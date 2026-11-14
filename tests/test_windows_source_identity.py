"""Source-scoped Windows record identities built from public schema shapes."""
from copy import deepcopy

import pytest

from romulus.evidence.normalize import normalize_hits
from romulus.evidence.windows import RecordIdContinuity, windows_record_key
from romulus.hunt.stage import EventStage
from tests.test_evtx_json import raw_hit, twin
from tests.test_nxlog_windows import nxlog_hit

NOTE = "clones without source identity cannot be told apart"


def _pair(metadata, *, shape="winlogbeat"):
    native = raw_hit()
    first = native if shape == "evtx" else twin(native)
    if shape == "nxlog":
        first = nxlog_hit(first)
    second = deepcopy(first)
    first["_id"], second["_id"] = "clone-a", "clone-b"
    for hit, source in zip((first, second), metadata, strict=True):
        hit["_source"].update(deepcopy(source))
    return first, second


@pytest.mark.parametrize("shape", ["winlogbeat", "evtx", "nxlog"])
@pytest.mark.parametrize("metadata", [
    ({"agent": {"type": "winlogbeat", "id": "sensor-a"}},
     {"agent": {"type": "winlogbeat", "id": "sensor-b"}}),
    ({"host": {"id": "machine-a"}}, {"host": {"id": "machine-b"}}),
    ({"log": {"file": {"path": "/exports/a/Security.evtx"}}},
     {"log": {"file": {"path": "/exports/b/Security.evtx"}}}),
    ({"host": {"ip": ["192.0.2.10"]}}, {"host": {"ip": ["192.0.2.11"]}}),
    # imaged after the agent first ran: the agent id and the machine GUID are shared, the addresses are not
    ({"agent": {"type": "winlogbeat", "id": "imaged"}, "host": {"id": "imaged-guid", "ip": ["172.20.64.10"]}},
     {"agent": {"type": "winlogbeat", "id": "imaged"}, "host": {"id": "imaged-guid", "ip": ["172.20.64.11"]}}),
])
def test_identical_clone_records_with_distinct_sources_survive_in_batch_and_on_disk(tmp_path, shape, metadata):
    first, second = _pair(metadata, shape=shape)
    events, skips, errors = normalize_hits([first, second])
    assert errors == [] and skips == {}
    assert len(events) == 2 and len({event.id for event in events}) == 2
    assert all(not any(NOTE in note for note in event.caveats) for event in events)
    separate = [normalize_hits([hit])[0][0] for hit in (first, second)]
    assert {event.id for event in separate} == {event.id for event in events}      # across batches as within one
    stage = EventStage(tmp_path)
    try:
        assert stage.unique_windows([separate[0]]) == ([separate[0]], [])
        assert stage.unique_windows([separate[1]]) == ([separate[1]], [])
    finally:
        stage.close()


@pytest.mark.parametrize("metadata", [
    {"agent": {"id": "same-source"}}, {"host": {"id": "same-host"}},
    {"log": {"file": {"path": "/exports/a.evtx"}}},
    {"host": {"ip": ["2001:db8::1", "192.0.2.3"]}},
])
def test_native_shipper_twins_with_the_same_source_still_collapse(metadata):
    native = raw_hit()
    shipped = twin(native)
    shipped["_id"] = "shipped"
    for hit in (native, shipped):
        for key, value in deepcopy(metadata).items():
            if isinstance(value, dict) and isinstance(hit["_source"].get(key), dict):
                hit["_source"][key].update(value)
            else:
                hit["_source"][key] = value
    events, skips, errors = normalize_hits([native, shipped])
    assert errors == [] and len(events) == 1
    assert sum(skips.values()) == 1
    assert {ref.native_id for ref in events[0].raw} == {"raw-1", "shipped"}


def test_source_less_copies_keep_legacy_key_and_explain_clone_ambiguity():
    first, second = _pair(({}, {}))
    events, skips, errors = normalize_hits([first, second])
    assert windows_record_key(first) == ("ws01.example.test", "security", "19")
    assert errors == [] and len(events) == 1 and sum(skips.values()) == 1
    assert any(NOTE in note for note in events[0].caveats)


def test_one_sided_source_does_not_invent_a_cross_clone_equivalence():
    first, second = _pair(({}, {"host": {"id": "clone-b"}}))
    events, skips, errors = normalize_hits([first, second])
    assert errors == [] and skips == {} and len(events) == 2
    assert len({event.id for event in events}) == 2


def test_stable_agent_identity_precedes_changing_file_and_ephemeral_id_while_addresses_agree():
    first, second = _pair((
        {"agent": {"type": "winlogbeat", "id": "stable", "ephemeral_id": "old"},
         "host": {"id": "host-a", "ip": ["192.0.2.1"]}, "log": {"file": {"path": "a.evtx"}}},
        {"agent": {"type": "winlogbeat", "id": "stable", "ephemeral_id": "new"},
         "host": {"id": "host-b", "ip": ["192.0.2.1"]}, "log": {"file": {"path": "b.evtx"}}},
    ))
    events, skips, errors = normalize_hits([first, second])
    assert errors == [] and len(events) == 1 and sum(skips.values()) == 1
    assert not any(NOTE in note for note in events[0].caveats)


CLONED = {"agent": {"type": "winlogbeat", "id": "imaged"}, "host": {"id": "imaged-guid"}}


def _cloned(*addresses):
    """The envelope of a machine imaged after its agent first ran, at the given addresses."""
    return {**CLONED, "host": {**CLONED["host"], "ip": list(addresses)}}


def test_copies_whose_host_addresses_differ_never_fold_whatever_their_identifiers_say():
    from romulus.evidence.windows import windows_source_identity

    first, second = _pair((_cloned("172.20.64.10"), _cloned("172.20.64.11")))
    events, skips, errors = normalize_hits([first, second])
    assert errors == [] and skips == {} and len(events) == 2
    assert all(not any(NOTE in note for note in event.caveats) for event in events)
    # the identity does not depend on the order the copies arrive in, or on the batch each arrives in
    turned, _, _ = normalize_hits([second, first])
    apart = [normalize_hits([hit])[0][0] for hit in (first, second)]
    assert {event.id for event in events} == {event.id for event in turned} == {event.id for event in apart}
    assert windows_record_key(first)[:3] == windows_record_key(second)[:3]
    assert windows_source_identity(first) != windows_source_identity(second)


def test_host_addresses_beside_an_identifier_are_canonical_and_order_independent():
    first, second = _pair((_cloned("2001:db8::1", "192.0.2.3", "192.0.2.3"),
                           _cloned("192.0.2.3", "2001:0db8:0:0:0:0:0:1")))
    events, skips, errors = normalize_hits([first, second])
    assert errors == [] and len(events) == 1 and sum(skips.values()) == 1


def test_an_address_set_on_one_copy_only_keeps_both_copies():
    first, second = _pair((CLONED, _cloned("172.20.64.10")))
    events, skips, errors = normalize_hits([first, second])
    assert errors == [] and skips == {} and len(events) == 2


def test_a_host_ip_value_that_is_no_address_adds_nothing_to_a_stable_identity():
    from romulus.evidence.windows import windows_source_identity

    first, second = _pair((_cloned("not an address"), _cloned("999.1.1.1")))
    assert windows_source_identity(first) == windows_source_identity(second)
    assert windows_source_identity(first) == windows_source_identity({"_source": CLONED})
    events, skips, errors = normalize_hits([first, second])
    assert errors == [] and len(events) == 1 and sum(skips.values()) == 1
    assert not any(NOTE in note for note in events[0].caveats)


def test_a_readdressed_host_keeps_one_record_id_sequence(tmp_path):
    from romulus.evidence.windows import windows_continuity_source

    first, second = _pair((_cloned("172.20.64.10"), _cloned("172.20.64.99")))
    second["_source"]["winlog"]["record_id"] = 20
    second["_source"]["winlog"]["event_data"]["CommandLine"] = "cmd.exe /c after-renewal"
    assert windows_continuity_source(first) == windows_continuity_source(second)
    continuity = RecordIdContinuity(tmp_path)
    try:
        assert continuity.observe("windows", [first, second]) == []
        assert continuity.state_count == 1
    finally:
        continuity.close()


def _two_sources(record_id=19):
    """One record as two pipelines deliver it: an EVTX export read from a file, and Winlogbeat on the machine."""
    export = raw_hit()
    export["_source"]["Event"]["System"]["EventRecordID"] = record_id
    shipped = twin(export)
    export["_id"], shipped["_id"] = f"export-{record_id}", f"shipped-{record_id}"
    export["_source"]["path"] = "/exports/ws01/Security.evtx"
    shipped["_source"]["agent"]["id"] = "agent-1"
    shipped["_source"]["host"] = {"id": "machine-1", "ip": ["192.0.2.10"]}
    return export, shipped


def _staged(stage, hits):
    """Normalize one batch and pass it through the stage's dedup, as the sweep does."""
    records = {}
    events, skips, errors = normalize_hits(hits, windows_records=records)
    assert errors == [] and skips == {}
    return events, *stage.unique_windows(events, records=records)


@pytest.mark.parametrize("together", [True, False])
def test_a_record_under_two_collection_sources_is_kept_twice_and_counted_once(tmp_path, together):
    export, shipped = _two_sources()
    stage = EventStage(tmp_path)
    try:
        delivered = []
        for batch in ([[export, shipped]] if together else [[export], [shipped]]):
            events, fresh, duplicates = _staged(stage, batch)
            assert fresh == events and duplicates == []
            delivered += fresh
        assert len({event.id for event in delivered}) == 2
        assert stage.windows_multi_source == 1
        # a third source of that record, and both copies delivered again, add nothing to the count
        third = deepcopy(shipped)
        third["_id"], third["_source"]["agent"]["id"] = "third", "agent-2"
        _events, fresh, duplicates = _staged(stage, [third, deepcopy(export), deepcopy(shipped)])
        assert len(fresh) == 1 and len(duplicates) == 2 and stage.windows_multi_source == 1
        # another record under two sources is the second record counted
        events, fresh, duplicates = _staged(stage, list(_two_sources(20)))
        assert fresh == events and duplicates == [] and stage.windows_multi_source == 2
        # the count keeps no row beyond each event's own
        assert stage.windows_db.execute("SELECT count(*) FROM windows_seen").fetchone()[0] == 5
    finally:
        stage.close()


def test_one_source_delivering_a_record_twice_is_a_duplicate_not_a_second_source(tmp_path):
    _export, shipped = _two_sources()
    again = deepcopy(shipped)
    again["_id"], again["_index"] = "again", "other-index"
    stage = EventStage(tmp_path)
    try:
        events, fresh, duplicates = _staged(stage, [shipped])
        assert fresh == events and duplicates == []
        events, fresh, duplicates = _staged(stage, [again])
        assert fresh == [] and duplicates == events
        assert stage.windows_multi_source == 0
    finally:
        stage.close()


def test_a_record_shipped_again_after_its_host_was_readdressed_is_kept_twice_and_counted(tmp_path):
    first, second = _pair((_cloned("172.20.64.10"), _cloned("172.20.64.99")))
    stage = EventStage(tmp_path)
    try:
        for hit in (first, second):
            events, fresh, duplicates = _staged(stage, [hit])
            assert fresh == events and duplicates == []
        assert stage.windows_multi_source == 1
    finally:
        stage.close()


def test_counting_records_under_several_sources_is_exact_and_adds_no_rows_at_volume(tmp_path):
    from datetime import UTC, datetime

    from romulus.evidence.typed import TypedEvent
    from romulus.evidence.windows import WINDOWS_NORMALIZER

    total, batch = 60_000, 2_000
    when = datetime(2026, 1, 2, tzinfo=UTC)
    stage = EventStage(tmp_path)
    try:
        for source in (1, 2, 3):
            for start in range(0, total, batch):
                # the first source ships every record, the second every other one, the third all of them again
                chosen = [record for record in range(start, start + batch) if source != 2 or record % 2 == 0]
                events = [TypedEvent(id=f"{record:012x}{source:012x}", family="process_exec", ts=when, host="ws01",
                                     fields={}, raw=[], normalizer=WINDOWS_NORMALIZER) for record in chosen]
                digests = {event.id: f"{record:020x}" for event, record in zip(events, chosen, strict=True)}
                fresh, duplicates = stage.unique_windows(events, records=digests)
                assert len(fresh) == len(events) and duplicates == []
        assert stage.windows_multi_source == total              # each record once, however many sources it has
        rows = stage.windows_db.execute("SELECT count(*) FROM windows_seen").fetchone()[0]
        assert rows == total * 2 + total // 2                   # one row per event and none for the count
    finally:
        stage.close()


def test_sweep_reports_records_under_two_sources_and_leaves_the_search_result_as_it_was(tmp_path, monkeypatch):
    from datetime import timedelta

    from romulus.evidence.windows_catalog import SYSMON, lookup_event_class
    from romulus.hunt import sweep as module
    from romulus.hunt.sweep import Sweep
    from romulus.report.manifest import _coverage_notes, _not_assessed
    from romulus.sources.models import Completeness, SearchOutcome, Window
    from tests.test_sweep import _repo
    from tests.test_windows_coverage import START, SYSMON_CHANNEL, WindowsProcessRule, _contract, _hit, _site

    shipped = [_hit(10), _hit(11)]
    exported = deepcopy(shipped)
    for record in exported:
        record["_id"] += "-export"
        record["_source"].pop("host")
        record["_source"]["log"] = {"file": {"path": "/exports/ws01/Sysmon.evtx"}}
    site = _site(tmp_path)

    def swept(records, directory):
        monkeypatch.setattr(module, "execute", lambda _client, intent, _contract: SearchOutcome(
            target=intent.target, fingerprint="synthetic", started_at=START, ended_at=START,
            completeness=Completeness.complete, total=len(records), total_relation="eq", returned=len(records),
            records=deepcopy(records)))
        contract = _contract()
        repo = _repo()
        directory.mkdir()
        sweep = Sweep(repo, None, "h1", Window(start=START, end=START + timedelta(minutes=30)),
                      {contract.target: contract}, site_facts=site, stage_dir=directory)
        sweep.pack = [WindowsProcessRule()]
        sweep._windows_inventory[contract.target] = {lookup_event_class(SYSMON_CHANNEL, SYSMON, 1).token}
        sweep._windows_inventory_reasons[contract.target] = []
        try:
            sweep.run_partition(contract.target, contract, [], sweep.window, est=len(records))
            [cell] = repo.rule_cells("h1")
            return cell, sweep.stats, contract.target
        finally:
            sweep.close_stage()

    alone, alone_stats, _target = swept(shipped, tmp_path / "one-source")
    cell, stats, target = swept(shipped + exported, tmp_path / "two-sources")
    assert alone_stats["events"] == 2 and stats["events"] == 4            # every copy is evaluated
    assert "Windows record seen under more than one collection source" not in alone_stats["skips"]
    assert stats["skips"]["Windows record seen under more than one collection source"] == 2
    assert (cell["state"], cell["detail"].get("reasons", [])) == (alone["state"], alone["detail"].get("reasons", []))
    # the count is a note about evaluated records, not data left unassessed
    assert _coverage_notes({"stats": stats}) == [{
        "target": target, "records": 2,
        "note": "2 Windows records were seen under more than one collection source; counts may include copies"}]
    assert not any("collection source" in row["reason"] for row in _not_assessed({}, {"stats": stats}))
    assert _coverage_notes({"stats": alone_stats}) == []


def test_ephemeral_id_alone_is_not_a_stable_source():
    first, second = _pair((
        {"agent": {"type": "winlogbeat", "ephemeral_id": "old"}},
        {"agent": {"type": "winlogbeat", "ephemeral_id": "new"}},
    ))
    events, skips, errors = normalize_hits([first, second])
    assert errors == [] and len(events) == 1 and sum(skips.values()) == 1
    assert any(NOTE in note for note in events[0].caveats)


@pytest.mark.parametrize("shape, field", [("evtx", "path"), ("evtx", "SourceFile"), ("nxlog", "FileName")])
def test_export_or_nxlog_file_metadata_scopes_identity_without_becoming_payload(shape, field):
    first, second = _pair(({field: "/exports/a.evtx"}, {field: "/exports/b.evtx"}), shape=shape)
    if field == "FileName":
        for hit in (first, second):
            hit["_source"]["SourceModuleType"] = "im_file"
    events, skips, errors = normalize_hits([first, second])
    assert errors == [] and skips == {} and len(events) == 2
    assert all("windows.event_data." + field not in event.fields for event in events)


def test_file_reindex_collapses_and_distinct_paths_do_not():
    first, second = _pair(({"path": "/exports/a.evtx"}, {"path": "/exports/a.evtx"}), shape="evtx")
    second["_index"] = "other-index"
    events, skips, errors = normalize_hits([first, second])
    assert errors == [] and len(events) == 1 and sum(skips.values()) == 1
    assert not any(NOTE in note for note in events[0].caveats)


def test_host_ip_identity_is_order_independent_and_canonical():
    first, second = _pair((
        {"host": {"ip": ["2001:db8::1", "192.0.2.3", "192.0.2.3"]}},
        {"host": {"ip": ["192.0.2.3", "2001:0db8:0:0:0:0:0:1"]}},
    ))
    events, skips, errors = normalize_hits([first, second])
    assert errors == [] and len(events) == 1 and sum(skips.values()) == 1
    assert not any(NOTE in note for note in events[0].caveats)


def test_flat_dotted_source_fields_match_nested_source_fields():
    first, second = _pair(({"host.id": "same-host"}, {"host": {"id": "same-host"}}))
    events, skips, errors = normalize_hits([first, second])
    assert errors == [] and len(events) == 1 and sum(skips.values()) == 1
    assert not any(NOTE in note for note in events[0].caveats)


def test_continuity_tracks_clones_independently_without_false_reuse(tmp_path):
    first, second = _pair(({"host": {"id": "machine-a"}}, {"host": {"id": "machine-b"}}))
    second["_source"]["winlog"]["event_data"]["CommandLine"] = "cmd.exe /c second-machine"
    next_records = [deepcopy(first), deepcopy(second)]
    for hit in next_records:
        hit["_source"]["winlog"]["record_id"] = 20
    continuity = RecordIdContinuity(tmp_path)
    try:
        reasons = continuity.observe("windows", [first, second, *next_records])
        assert reasons == []
        assert continuity.state_count == 2
        assert continuity.observe("windows", [*next_records]) == []
    finally:
        continuity.close()


def test_continuity_still_reports_reused_id_within_one_source(tmp_path):
    first, second = _pair(({"host": {"id": "machine-a"}}, {"host": {"id": "machine-a"}}))
    second["_source"]["winlog"]["event_data"]["CommandLine"] = "cmd.exe /c changed"
    continuity = RecordIdContinuity(tmp_path)
    try:
        reasons = continuity.observe("windows", [first, second])
        assert any("record_id reused" in note for note in reasons)
    finally:
        continuity.close()


def test_selective_continuity_projects_source_identity_and_does_not_mix_clone_sequences(tmp_path, monkeypatch):
    from datetime import timedelta

    from romulus.hunt import sweep as module
    from romulus.hunt.sweep import Sweep
    from romulus.sources.models import Completeness, SearchOutcome, Window
    from romulus.sources.profile import contract_from_types
    from tests.test_sweep import _repo
    from tests.test_windows_coverage import START, _continuity_bucket

    contract = contract_from_types("windows", {
        "@timestamp": "date", "winlog.computer_name": "keyword", "winlog.channel": "keyword",
        "winlog.record_id": "long", "winlog.event_id": "long", "host.id": "keyword",
    }, role="host", os_family="windows")
    buckets = []
    for source_id, minute in (("clone-a", 5), ("clone-b", 6)):
        for record_id in (10, 11):
            bucket = _continuity_bucket(record_id, minute + (record_id - 10) * 10)
            bucket["key"]["host.id"] = source_id
            buckets.append(bucket)
    seen = []

    def execute(_client, intent, _contract):
        seen.append(intent)
        return SearchOutcome(target=intent.target, fingerprint="synthetic", started_at=START, ended_at=START,
                             completeness=Completeness.complete, total=4, total_relation="eq", returned=4,
                             buckets=buckets)

    monkeypatch.setattr(module, "execute", execute)
    sweep = Sweep(_repo(), None, "h1", Window(start=START, end=START + timedelta(hours=1)),
                  {contract.target: contract}, stage_dir=tmp_path)
    try:
        _, reasons = sweep._selective_windows_continuity(contract.target, contract, sweep.window)
        assert "host.id" in seen[0].group_by
        assert not any("reused" in reason or "out of order" in reason for reason in reasons)
        assert sweep._windows_record_ids.state_count == 2
    finally:
        sweep.close_stage()


def test_source_less_normalized_event_makes_sweep_coverage_honestly_partial(tmp_path, monkeypatch):
    from datetime import timedelta

    from romulus.evidence.windows_catalog import SYSMON, lookup_event_class
    from romulus.hunt import sweep as module
    from romulus.hunt.sweep import Sweep
    from romulus.sources.models import Completeness, SearchOutcome, Window
    from tests.test_sweep import _repo
    from tests.test_windows_coverage import START, SYSMON_CHANNEL, WindowsProcessRule, _contract, _hit, _site

    records = [_hit(10), _hit(11)]
    for record in records:
        record["_source"].pop("host", None)
    monkeypatch.setattr(module, "execute", lambda _client, intent, _contract: SearchOutcome(
        target=intent.target, fingerprint="synthetic", started_at=START, ended_at=START,
        completeness=Completeness.complete, total=2, total_relation="eq", returned=2, records=records))
    contract = _contract()
    repo = _repo()
    sweep = Sweep(repo, None, "h1", Window(start=START, end=START + timedelta(minutes=30)),
                  {contract.target: contract}, site_facts=_site(tmp_path), stage_dir=tmp_path)
    sweep.pack = [WindowsProcessRule()]
    sweep._windows_inventory[contract.target] = {lookup_event_class(SYSMON_CHANNEL, SYSMON, 1).token}
    sweep._windows_inventory_reasons[contract.target] = []
    try:
        sweep.run_partition(contract.target, contract, [], sweep.window, est=2)
        cell = repo.rule_cells("h1")[0]
        assert cell["state"] == "evaluated_partial"
        assert any(NOTE in reason for reason in cell["detail"]["reasons"])
    finally:
        sweep.close_stage()


def test_nxlog_provider_filename_is_not_collection_identity():
    first, second = _pair(({"FileName": "a.evtx"}, {"FileName": "b.evtx"}), shape="nxlog")
    # im_msvistalog does not document a FileName envelope; provider data can use that name.
    from romulus.evidence.windows import windows_source_identity
    assert windows_source_identity(first) is None
    assert windows_source_identity(second) is None
    events, _, errors = normalize_hits([first, second])
    assert errors == []
    assert {event.get("windows.event_data.FileName") for event in events} == {"a.evtx", "b.evtx"}


def test_source_less_duplicate_partition_keeps_coverage_note(tmp_path, monkeypatch):
    from datetime import timedelta

    from romulus.evidence.windows_catalog import SYSMON, lookup_event_class
    from romulus.hunt import sweep as module
    from romulus.hunt.sweep import Sweep
    from romulus.sources.models import Completeness, SearchOutcome, Window
    from tests.test_sweep import _repo
    from tests.test_windows_coverage import START, SYSMON_CHANNEL, WindowsProcessRule, _contract, _hit, _site

    records = [_hit(10), _hit(11)]
    for record in records:
        record["_source"].pop("host", None)
    monkeypatch.setattr(module, "execute", lambda _client, intent, _contract: SearchOutcome(
        target=intent.target, fingerprint="synthetic", started_at=START, ended_at=START,
        completeness=Completeness.complete, total=2, total_relation="eq", returned=2, records=records))
    contract = _contract()
    repo = _repo()
    sweep = Sweep(repo, None, "h1", Window(start=START, end=START + timedelta(minutes=60)),
                  {contract.target: contract}, site_facts=_site(tmp_path), stage_dir=tmp_path)
    sweep.pack = [WindowsProcessRule()]
    sweep._windows_inventory[contract.target] = {lookup_event_class(SYSMON_CHANNEL, SYSMON, 1).token}
    sweep._windows_inventory_reasons[contract.target] = []
    try:
        for minute in (0, 30):
            window = Window(start=START + timedelta(minutes=minute), end=START + timedelta(minutes=minute + 30))
            sweep.run_partition(contract.target, contract, [], window, est=2)
        assert len(repo.rule_cells("h1")) == 2
        assert all(any(NOTE in reason for reason in cell["detail"]["reasons"])
                   for cell in repo.rule_cells("h1"))
        assert sweep.stats["events"] == 2
    finally:
        sweep.close_stage()


def test_pivot_reports_unresolved_clone_identity_for_source_less_events(monkeypatch):
    from romulus.hunt import pivot as module
    from romulus.hunt.pivot import PivotExecutor
    from tests.test_windows_script_pivot import (
        END,
        START,
        FakeClient,
        _complete_outcome,
        _contract,
        _intent,
        _repo,
    )

    record = twin(raw_hit())
    target = record["_index"]
    monkeypatch.setattr(module, "execute", lambda _client, intent, _contract, **_kw:
                        _complete_outcome(intent, record))
    executor = PivotExecutor(_repo(), FakeClient(), "h1", {target: _contract(target)})
    batch = executor.fetch_intents("finding", "identity", [_intent(target, START, END)], lambda _event: True,
                                   persist=False)
    assert batch.events
    assert all(cell.status == "partial" for cell in batch.coverage)
    assert any(NOTE in reason for cell in batch.coverage for reason in cell.reasons)


def test_selective_continuity_never_groups_by_host_addresses_and_leaves_an_address_only_group_unresolved(
        tmp_path, monkeypatch):
    from datetime import timedelta

    from romulus.hunt import sweep as module
    from romulus.hunt.sweep import Sweep
    from romulus.sources.models import Completeness, SearchOutcome, Window
    from romulus.sources.profile import contract_from_types
    from tests.test_sweep import _repo
    from tests.test_windows_coverage import START, SYSMON_CHANNEL, _continuity_bucket

    contract = contract_from_types("windows", {
        "@timestamp": "date", "winlog.computer_name": "keyword", "winlog.channel": "keyword",
        "winlog.record_id": "long", "winlog.event_id": "long", "host.ip": "ip",
    }, role="host", os_family="windows")
    buckets = [_continuity_bucket(10, 5), _continuity_bucket(11, 15)]
    for bucket in buckets:
        bucket["key"].pop("host.id", None)
    seen = []

    def execute(_client, intent, _contract):
        seen.append(intent)
        return SearchOutcome(target=intent.target, fingerprint="synthetic", started_at=START, ended_at=START,
                             completeness=Completeness.complete, total=2, total_relation="eq", returned=2,
                             buckets=buckets)

    monkeypatch.setattr(module, "execute", execute)
    sweep = Sweep(_repo(), None, "h1", Window(start=START, end=START + timedelta(hours=1)),
                  {contract.target: contract}, stage_dir=tmp_path)
    try:
        _, reasons = sweep._selective_windows_continuity(contract.target, contract, sweep.window)
        assert seen[0].group_by == ["@timestamp", "host.name", "event.channel", "winlog.record_id"]
        assert reasons == ["shipper gaps unresolved: no single-valued source identity on "
                           + SYSMON_CHANNEL + " for ws01.example.test"]
        assert sweep._windows_record_ids.state_count == 1
    finally:
        sweep.close_stage()


def test_selective_multivalued_source_metadata_is_unknown_not_a_false_continuity_gap(tmp_path, monkeypatch):
    from datetime import timedelta

    from romulus.hunt import sweep as module
    from romulus.hunt.sweep import Sweep
    from romulus.sources.models import Completeness, SearchOutcome, Window
    from romulus.sources.profile import contract_from_types
    from tests.test_sweep import _repo
    from tests.test_windows_coverage import START, _continuity_bucket

    contract = contract_from_types("windows", {
        "@timestamp": "date", "winlog.computer_name": "keyword", "winlog.channel": "keyword",
        "winlog.record_id": "long", "winlog.event_id": "long", "host.id": "keyword",
    }, role="host", os_family="windows")
    buckets = [_continuity_bucket(10, 5), _continuity_bucket(10, 5)]
    for bucket, machine in zip(buckets, ("machine-a", "machine-a-old"), strict=True):
        bucket["key"]["host.id"] = machine
    monkeypatch.setattr(module, "execute", lambda _client, intent, _contract: SearchOutcome(
        target=intent.target, fingerprint="synthetic", started_at=START, ended_at=START,
        completeness=Completeness.complete, total=1, total_relation="eq", returned=2, buckets=buckets))
    sweep = Sweep(_repo(), None, "h1", Window(start=START, end=START + timedelta(hours=1)),
                  {contract.target: contract}, stage_dir=tmp_path)
    try:
        _, reasons = sweep._selective_windows_continuity(contract.target, contract, sweep.window)
        assert reasons == ["shipper gaps unresolved: source identity metadata is multi-valued or not exact"]
        assert sweep._windows_record_ids is None
    finally:
        sweep.close_stage()
