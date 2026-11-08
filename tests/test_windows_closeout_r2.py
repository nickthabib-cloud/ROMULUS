"""Regression checks for direct replication publication and share-change deltas."""

from dataclasses import replace

import pytest

from romulus.detect.bounded import StateBudget
from romulus.detect.registry import bind_windows_site, fresh_direct_pack
from romulus.detect.windows_directory_events import DirectoryReplicationAccess
from romulus.detect.windows_share_events import ShareCreated
from romulus.evidence.typed import fv
from tests.test_windows_closeout import FACTS, logon, replication
from tests.windows_event_support import event, run


def direct_replication_rule(facts=FACTS):
    return next(
        rule
        for rule in bind_windows_site(fresh_direct_pack(), facts)
        if isinstance(rule, DirectoryReplicationAccess)
    )


@pytest.mark.parametrize("source,lane", [(None, "lead"), ("192.0.2.10", "lead"), ("198.51.100.7", "high")])
def test_direct_replication_publishes_without_finalize(source, lane):
    rule = direct_replication_rule()
    try:
        records = ([logon(source)] if source else []) + [replication()]
        (hit,) = list(rule.consume(records))
        assert hit.proposed_lane == lane
        assert any(ev.id == records[-1].id for ev in hit.events)
        assert list(rule.finalize()) == []
    finally:
        rule.close_spill()


def test_refused_replication_join_row_still_publishes_unresolved_lead():
    rule = DirectoryReplicationAccess()
    rule.site_facts = FACTS
    rule.budget = StateBudget(disk_total=64 * 1024, reserve=0)
    try:
        for i in range(200):
            list(rule.consume([logon(session=hex(10000 + i), native=f"fill-{i}")]))
        assert rule.capped > 0
        request = replication(native="refused-replication")
        (hit,) = list(rule.consume([request]))
        assert hit.proposed_lane == "lead"
        assert [ev.id for ev in hit.events] == [request.id]
        assert "source unresolved: join state refused at the disk ceiling" in " ".join(hit.notes)
        assert list(rule.finalize()) == []
    finally:
        rule.close_spill()


def test_duplicate_replication_join_row_is_not_reported_as_a_disk_refusal():
    rule = DirectoryReplicationAccess()
    rule.site_facts = FACTS
    request = replication()
    try:
        assert list(rule.consume([logon()])) == []
        assert len(list(rule.consume([request]))) == 1
        assert list(rule.consume([request])) == []
        assert not rule.capped
    finally:
        rule.close_spill()


def test_declared_workstation_cannot_override_an_undeclared_source_address():
    source = logon("198.51.100.7")
    source.fields["source.hostname"] = fv("sync01.example.test", "test")
    rule = DirectoryReplicationAccess()
    rule.site_facts = FACTS
    try:
        (hit,) = run(rule, [[source], [replication()]])
        assert hit.proposed_lane == "high"
        assert "undeclared host" in " ".join(hit.notes)
        assert {ev.id for ev in hit.events} == {source.id, replication().id}
    finally:
        rule.close_spill()


@pytest.mark.parametrize("addresses,has_ip", [((), True), (FACTS.directory_sync_addresses, False)])
def test_replication_hostname_fallback_names_its_client_reported_origin(addresses, has_ip):
    source = logon()
    source.fields["source.hostname"] = fv("sync01.example.test", "test")
    if not has_ip:
        source.fields.pop("source.ip")
    rule = DirectoryReplicationAccess()
    rule.site_facts = replace(FACTS, directory_sync_addresses=addresses)
    try:
        (hit,) = run(rule, [[source], [replication()]])
        assert hit.proposed_lane == "lead"
        assert "client-reported" in hit.claim
    finally:
        rule.close_spill()


@pytest.mark.parametrize("source", ["::1", "127.0.0.1"])
def test_replication_loopback_source_remains_high(source):
    rule = DirectoryReplicationAccess()
    rule.site_facts = FACTS
    try:
        (hit,) = run(rule, [[logon(source)], [replication()]])
        assert hit.proposed_lane == "high"
    finally:
        rule.close_spill()


def share_hit(change="modified", **fields):
    code = {"added": 5142, "modified": 5143, "deleted": 5144}[change]
    return ShareCreated().judge(
        event("share_change", code, **{"share.change": change, "share.name": "Finance", **fields})
    )[0]


@pytest.mark.parametrize("path", [r"D:\Shares\Finance", r"C:\Users\alice\share", r"C:\Windows\Tasks"])
def test_share_modification_does_not_raise_existing_broad_write_or_exposed_path(path):
    hit = share_hit(
        **{
            "share.local_path": path,
            "share.security_descriptor.old": "D:(A;;FA;;;WD)",
            "share.security_descriptor.new": "D:(A;;FA;;;WD)",
        }
    )
    assert hit.lane == "lead"


@pytest.mark.parametrize("trustee", ["WD", "AU", "DU", "AN", "S-1-1-0", "S-1-5-11", "S-1-5-7", "S-1-5-21-1-2-3-513"])
def test_share_modification_new_broad_write_ace_is_high(trustee):
    hit = share_hit(
        **{
            "share.security_descriptor.old": f"D:(A;;FR;;;{trustee})",
            "share.security_descriptor.new": f"D:(A;;FW;;;{trustee})",
        }
    )
    assert hit.lane == "high"


def test_share_modification_detects_a_new_broad_write_trustee():
    hit = share_hit(
        **{
            "share.security_descriptor.old": "D:(A;;FA;;;WD)",
            "share.security_descriptor.new": "D:(A;;FA;;;WD)(A;;FW;;;AU)",
        }
    )
    assert hit.lane == "high"


@pytest.mark.parametrize(
    "share,path",
    [
        (r"\\*\print$", r"C:\Windows\system32\spool\drivers"),
        ("print$", r"%SystemRoot%\System32\spool\drivers"),
        (r"\\*\SYSVOL", r"C:\Windows\SYSVOL\sysvol"),
        ("NETLOGON", r"%SystemRoot%\SYSVOL\sysvol\example.test\scripts"),
    ],
)
def test_os_share_path_table_keeps_share_creation_at_lead(share, path):
    hit = share_hit("added", **{"share.name": share, "share.local_path": path})
    assert hit.lane == "lead"


@pytest.mark.parametrize(
    "share,path",
    [("Data", r"C:\Windows\system32\spool\drivers"), ("print$", r"C:\Windows\Tasks"), ("SYSVOL", r"C:\Temp\SYSVOL")],
)
def test_os_share_exclusion_requires_both_name_and_exact_path_tree(share, path):
    assert share_hit("added", **{"share.name": share, "share.local_path": path}).lane == "high"


def test_os_share_path_exclusion_never_lowers_a_broad_write_ace():
    hit = share_hit(
        "added",
        **{
            "share.name": "print$",
            "share.local_path": r"C:\Windows\system32\spool\drivers",
            "share.security_descriptor.new": "D:(A;;FW;;;WD)",
        },
    )
    assert hit.lane == "high"

def test_share_modification_with_missing_old_descriptor_does_not_claim_a_new_grant():
    hit = share_hit(**{"share.security_descriptor.new": "D:(A;;FW;;;WD)"})
    assert hit.lane == "lead"


@pytest.mark.parametrize(
    "old,new,lane",
    [
        (r"D:\Shares\Data", r"C:\Windows\Tasks", "high"),
        (r"C:\Windows\Tasks", r"C:\Windows\Tasks", "lead"),
        (r"D:\Shares\Data", r"C:\Users\alice\share", "lead"),
    ],
)
def test_share_modification_requires_a_typed_change_to_a_system_path(old, new, lane):
    hit = share_hit(**{"share.local_path.old": old, "share.local_path.new": new})
    assert hit.lane == lane
    if lane == "high":
        assert {"share.local_path.old", "share.local_path.new"} <= {p.field for p in hit.predicate}


def test_refused_replication_join_row_retains_an_already_supported_high_source():
    rule = DirectoryReplicationAccess()
    rule.site_facts = FACTS
    rule.budget = StateBudget(disk_total=64 * 1024, reserve=0)
    try:
        list(rule.consume([logon(native="known-attacker")]))
        for i in range(200):
            list(rule.consume([logon(session=hex(10000 + i), native=f"fill-{i}")]))
        request = replication(native="refused-known-source")
        (hit,) = list(rule.consume([request]))
        assert hit.proposed_lane == "high"
        assert {ev.id for ev in hit.events} == {"known-attacker", request.id}
        assert "join state refused" in " ".join(hit.notes)
    finally:
        rule.close_spill()

@pytest.mark.parametrize(
    "old,new,lane",
    [
        ("D:(A;;FA;;;WD)", "D:(A;;FW;;;WD)", "lead"),
        ("D:(A;;FW;;;WD)", "D:(A;;FA;;;WD)", "high"),
        ("D:(A;;FW;;;S-1-1-0)", "D:(A;;FW;;;WD)", "lead"),
        ("D:(A;;0x00120116;;;AU)", "D:(A;;FW;;;AU)", "lead"),
        ("D:(A;;FW;;;AU)(A;;FR;;;WD)", "D:(A;;FR;;;WD)(A;;FW;;;AU)", "lead"),
        ("D:(A;IO;FW;;;WD)", "D:(A;;FW;;;WD)", "high"),
        ("-", "D:(A;;FW;;;WD)", "lead"),
        ("", "D:(A;;FW;;;WD)", "lead"),
    ],
)
def test_share_modification_compares_recorded_write_bits_without_acl_order_noise(old, new, lane):
    hit = share_hit(**{"share.security_descriptor.old": old, "share.security_descriptor.new": new})
    assert hit.lane == lane


@pytest.mark.parametrize("source,lane", [("192.0.2.10", "lead"), ("198.51.100.7", "high")])
def test_direct_late_logon_revises_the_source_without_finalize(source, lane):
    from tests.windows_process_support import stored

    rule = direct_replication_rule()
    request = replication()
    try:
        matches = list(rule.consume([request]))
        matches += list(rule.consume([logon(source)]))
        (hit,) = stored(matches)
        assert hit.proposed_lane == lane
        assert len(hit.events) == 2
        assert hit.revision_reason
    finally:
        rule.close_spill()


@pytest.mark.parametrize("order", ["logon-first", "access-first"])
def test_one_shot_publication_keeps_an_undeclared_source_high_in_either_batch_order(order):
    from romulus.hunt.publish import publish_match
    from tests.test_report import _repo_with_finding
    hunt = "h-" + order
    repo, _ = _repo_with_finding(hunt_id=hunt)
    repo.set_hunt_state(hunt, "running")
    rule = direct_replication_rule()
    access, sync = logon("198.51.100.7"), replication()
    events = [access, sync] if order == "logon-first" else [sync, access]
    raws = {"windows/" + e.id: {"message": e.id} for e in events}
    try:
        for match in rule.consume(events):
            publish_match(repo, hunt, rule, match, None, raws, source_case_id="case-1")
        assert [c["lane"] for c in repo.candidates(hunt) if c["rule_id"] == rule.id] == ["high"]
    finally:
        rule.close_spill()
