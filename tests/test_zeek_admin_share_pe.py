"""Admin-share transfers require linked, client-directed executable file bytes."""
import importlib
import itertools

import pytest

from romulus.evidence.typed import RawRef, fv
from romulus.hunt.citations import COMPACT_CITATION_NOTE
from tests.fixtures import zeek_logs as zl
from tests.test_zeek_windows_protocols import every_shape

SMB = zl.SMB_FILES.with_(name=r"Temp\package.dat")
FILES = zl.FILES.with_(fuid=zl.FUID_SMB, uid=zl.UID_SMB, source="SMB", is_orig=True,
                      mime_type="application/octet-stream", **{"id.resp_h": zl.DC, "id.resp_p": 445})
PE = zl.PE.with_(id=zl.FUID_SMB)
SHAPES = ("malcolm", "elastic", "security_onion", "plain")


def detector():
    return importlib.import_module("romulus.detect.zeek_smb").AdminSharePeWrite()


def records(shape="plain", *, smb=SMB, files=FILES, pe=PE):
    return [every_shape(row)[shape] for row in (smb, files, pe)]


def run(batches):
    owner = detector()
    try:
        found = []
        for batch in batches:
            found.extend(owner.consume(batch))
        found.extend(owner.finalize())
        return found
    finally:
        owner.release_state()


@pytest.mark.parametrize("shape", SHAPES)
@pytest.mark.parametrize("order", list(itertools.permutations(range(3))))
def test_three_roles_join_immediately_in_every_order_and_shipper(shape, order):
    events = records(shape)
    owner = detector()
    try:
        assert list(owner.consume([events[order[0]]])) == []
        assert list(owner.consume([events[order[1]]])) == []
        [match] = list(owner.consume([events[order[2]]]))
        assert match.proposed_lane == "high"
        assert match.claim_type == "network_observation"
        assert {event.id for event in match.events} == {event.id for event in events}
        assert "sent" in match.claim and "administrative" in match.claim
        assert "completed" not in match.claim and "executed" not in match.claim
        assert "T1021.002" in " ".join(match.notes) and "T1570" in " ".join(match.notes)
        assert not list(owner.finalize())
    finally:
        owner.release_state()


def test_equivalent_shippers_have_identical_claim_lane_and_group_identity():
    decisions = []
    for shape in SHAPES:
        [match] = run([[event] for event in records(shape)])
        decisions.append((match.claim, match.proposed_lane, match.group_key))
    assert len(set(decisions)) == 1


@pytest.mark.parametrize("mime", ["application/x-dosexec", "application/vnd.microsoft.portable-executable"])
@pytest.mark.parametrize("shape", SHAPES)
def test_files_mime_can_supply_pe_evidence_without_a_pe_log(mime, shape):
    smb, files, _pe = records(shape, files=FILES.with_(mime_type=mime))
    [match] = run([[smb], [files]])
    assert match.proposed_lane == "high"
    assert {event.id for event in match.events} == {smb.id, files.id}


@pytest.mark.parametrize("share", [r"\\DC01\ADMIN$", r"\\DC01\IPC$", r"\\DC01\C$", r"\\DC01\z$"])
def test_all_requested_administrative_share_classes_are_supported(share):
    assert run([[event] for event in records(smb=SMB.with_(path=share))])


@pytest.mark.parametrize("change", [
    {"source": "HTTP"}, {"is_orig": False}, {"is_orig": None}, {"seen_bytes": 0},
    {"seen_bytes": None}, {"uid": "Cother"}, {"fuid": "Fother"},
    {"id.orig_h": "10.0.0.99"}, {"id.resp_h": "10.0.0.99"},
])
def test_files_must_prove_matching_smb_direction_bytes_uid_and_endpoints(change):
    assert run([[event] for event in records(files=FILES.with_(**change))]) == []


@pytest.mark.parametrize("index,field,value", [
    (0, "observer.name", "another-sensor"), (1, "observer.name", "another-sensor"),
    (2, "observer.name", "another-sensor"), (2, "file.fuid", "Fother"),
    (2, "pe.is_exe", False), (2, "pe.is_exe", None),
])
def test_sensor_fuid_and_pe_evidence_cannot_cross_join(index, field, value):
    events = records()
    events[index].fields[field] = fv(value, "test:independent-field")
    assert run([[event] for event in events]) == []


@pytest.mark.parametrize("change", [
    {"path": r"\\DC01\public"}, {"path": r"\\DC01\ADMIN$_backup"},
    {"id.orig_h": zl.DC}, {"id.orig_h": "127.0.0.1"}, {"id.resp_h": "::1"},
    {"fuid": None}, {"uid": None}, {"name": None},
])
def test_smb_must_name_a_remote_administrative_share_file(change):
    assert run([[event] for event in records(smb=SMB.with_(**change))]) == []


@pytest.mark.parametrize("action", ["SMB::FILE_OPEN", "SMB::FILE_WRITE"])
def test_even_explicit_write_plus_pe_needs_files_log_direction(action):
    smb, _files, pe = records(smb=SMB.with_(action=action))
    assert run([[smb], [pe]]) == []


def test_file_extension_alone_is_not_pe_evidence():
    smb, files, _ = records(smb=SMB.with_(name="Temp\\approved.exe"))
    assert run([[smb], [files]]) == []


@pytest.mark.parametrize("shape", SHAPES)
def test_old_singleton_endpoint_layout_and_carrying_uid_membership(shape):
    old = FILES.without("uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p").with_(
        conn_uids=["Cadjacent", zl.UID_SMB], tx_hosts=[zl.CLIENT], rx_hosts=[zl.DC])
    [match] = run([[event] for event in records(shape, files=old)])
    assert match.proposed_lane == "high"


@pytest.mark.parametrize("changes", [
    {"conn_uids": ["Cadjacent"]},
    {"tx_hosts": [zl.CLIENT, "10.0.0.99"]},
    {"rx_hosts": [zl.DC, "10.0.0.99"]},
    {"tx_hosts": []}, {"rx_hosts": []},
])
def test_ambiguous_or_inconsistent_old_layout_does_not_invent_endpoint_pairs(changes):
    old = FILES.without("uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p").with_(
        **{"conn_uids": [zl.UID_SMB], "tx_hosts": [zl.CLIENT], "rx_hosts": [zl.DC], **changes})
    assert run([[event] for event in records(files=old)]) == []


def test_present_carrying_uid_list_must_include_the_scalar_uid():
    events = records()
    events[1].fields["file.conn_uids"] = fv(["Cadjacent"], "test:conn_uids")
    assert run([[event] for event in events]) == []


def test_files_without_any_uid_can_join_by_sensor_fuid_and_proven_peers():
    row = FILES.without("uid")
    assert run([[event] for event in records(files=row)])


def test_missing_endpoints_are_named_partial_instead_of_inferred_from_smb():
    events = records(files=FILES.without("id.orig_h", "id.resp_h"))
    owner = detector()
    try:
        assert not [match for event in events for match in owner.consume([event])]
        assert any("endpoint" in reason.lower() for reason in owner.limit_reasons())
    finally:
        owner.release_state()


def test_default_logging_limit_is_always_exposed_in_positive_only_coverage():
    owner = detector()
    try:
        reason = owner.positive_only_reason.lower()
        assert not owner.assures_negative
        assert "files.log" in reason and "file_write" in reason and "default" in reason
        assert "full search" in reason
    finally:
        owner.release_state()


def test_duplicates_updates_and_fresh_replay_keep_one_stable_group():
    events = records()
    owner = detector()
    try:
        initial = [match for event in events for match in owner.consume([event])]
        assert len(initial) == 1
        assert not [match for _ in range(5) for event in events for match in owner.consume([event])]
        # A later files update has a new native identity but equivalent proof.
        updated = every_shape(FILES.with_(seen_bytes=99999))["plain"]
        assert not list(owner.consume([updated]))
        assert not list(owner.finalize())
    finally:
        owner.release_state()
    [replayed] = run([[event] for event in reversed(events)])
    assert replayed.group_key == initial[0].group_key


def test_reference_retention_is_bounded_and_explained_without_fabricating_refs():
    events = records()
    for event in events:
        event.raw = [RawRef(target="test", native_id=f"{event.id}-{n}") for n in range(20)]
    [match] = run([[event] for event in events])
    assert all(1 <= len(event.raw) <= 3 for event in match.events)
    assert all(COMPACT_CITATION_NOTE in event.caveats for event in match.events)
    assert any("reference" in note.lower() and "partial" in note.lower() for note in match.notes)
    assert all(ref.target == "test" for event in match.events for ref in event.raw)


def test_physical_schema_cap_is_named_partial_and_does_not_crash(tmp_path):
    from romulus.detect.bounded import StateBudget
    owner = detector()
    owner.spill_dir = tmp_path
    owner.budget = StateBudget(tmp_path, disk_total=1, reserve=0, reserve_floor=0)
    try:
        assert not list(owner.consume(records()))
        assert owner.capped or owner.limit_reasons()
    finally:
        owner.release_state()


def test_last_live_proof_can_publish_after_new_state_is_refused():
    owner = detector()
    smb, files, pe = records()
    try:
        assert not list(owner.consume([smb, files]))
        owner.state_budget().over_total = "synthetic no-growth condition"
        [match] = list(owner.consume([pe]))
        assert match.proposed_lane == "high"
        assert owner.limit_reasons()
    finally:
        owner.release_state()


def test_actual_publication_fetches_compact_sources_and_fresh_replay_does_not_duplicate():
    from romulus.hunt.publish import publish_match
    from romulus.store.repo import raw_id
    from tests.test_sweep import _repo

    sources = {}
    for row in (SMB, FILES, PE):
        native = zl.in_every_shape(row)["plain"]
        sources[native["_index"] + "/" + native["_id"]] = native["_source"]
    repository = _repo()
    identities = []
    for batch in (records(), list(reversed(records()))):
        owner = detector()
        try:
            [match] = [item for event in batch for item in owner.consume([event])]
            identities.append(match.group_key)
            publish_match(repository, "h1", owner, match, None, sources)
            assert not any(COMPACT_CITATION_NOTE in event.caveats for event in match.events)
            assert not any("not retrieved" in note.lower() for note in match.notes)
            raw = repository.raw_records([raw_id(ref.target, ref.native_id)
                                          for event in match.events for ref in event.raw])
            assert len(raw) == 3
        finally:
            owner.release_state()
    assert identities[0] == identities[1]
    [saved] = repository.candidates("h1")
    assert saved["lane"] == "high" and len(saved["event_ids"]) == 3


def test_many_equivalent_file_updates_retain_only_the_first_proof_and_facet():
    from tests.test_zeek_windows_protocols import normalize

    owner = detector()
    try:
        assert not list(owner.consume([records()[0]]))
        for index in range(100):
            native = zl.plain(FILES.with_(seen_bytes=index + 1), nid=f"update-{index}")
            assert not list(owner.consume([normalize(native)]))
        assert owner.rows.store().execute("SELECT COUNT(*) FROM smb_pe_files").fetchone()[0] == 1
        assert owner.rows.store().execute("SELECT COUNT(*) FROM smb_pe_proofs").fetchone()[0] == 2
        [match] = list(owner.consume([records()[2]]))
        assert match.proposed_lane == "high"
        assert owner.rows.store().execute("SELECT COUNT(*) FROM smb_pe_pending").fetchone()[0] == 0
    finally:
        owner.release_state()


@pytest.mark.parametrize("shape", ["elastic", "security_onion"])
def test_shipper_first_host_layout_preserves_a_partial_membership_caveat(shape):
    old = FILES.without("uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p").with_(
        conn_uids=[zl.UID_SMB], tx_hosts=[zl.CLIENT, "10.0.0.99"], rx_hosts=[zl.DC, "10.0.0.98"])
    events = records(shape, files=old)
    assert len(events[1].get("file.tx_hosts")) == 1
    owner = detector()
    try:
        [match] = [item for event in events for item in owner.consume([event])]
        assert match.proposed_lane == "high"
        assert any("old-layout" in note.lower() and "partial" in note.lower() for note in match.notes)
        cited_file = next(event for event in match.events if event.get("zeek.log") == "files")
        assert set(events[1].caveats) <= set(cited_file.caveats)
        assert any("old-layout" in reason.lower() for reason in owner.limit_reasons())
    finally:
        owner.release_state()
