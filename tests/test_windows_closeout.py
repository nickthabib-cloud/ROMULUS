"""Share auditing and source-aware directory replication regressions."""

from dataclasses import replace

import pytest

from romulus.detect.windows_directory_events import DirectoryReplicationAccess
from romulus.evidence.windows import normalize_windows
from romulus.evidence.windows_catalog import SECURITY
from romulus.site import SiteFacts
from tests.windows_event_support import event, run
from tests.windows_fixtures import SHAPES, LogicalWindowsEvent, windows_hit

FACTS = SiteFacts(
    True,
    "test",
    {},
    (),
    ("dc01.example.test",),
    ("name:example\\syncsvc",),
    directory_sync_hosts=("sync01.example.test",),
    directory_sync_addresses=("192.0.2.10",),
)
RIGHT = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"


def native(code, data, shape="elastic_agent"):
    logical = LogicalWindowsEvent(
        "Security", SECURITY, code, "dc01.example.test", 1, "2026-01-02T03:00:00Z", data
    )
    return normalize_windows(windows_hit(logical, shape))


@pytest.mark.parametrize("shape", SHAPES)
@pytest.mark.parametrize("code,change", [(5142, "added"), (5143, "modified"), (5144, "deleted")])
def test_share_native_families_fields_and_actor(code, change, shape):
    ev = native(
        code,
        {
            "ShareName": "\\\\*\\Documents",
            "ShareLocalPath": "C:\\Documents",
            "SubjectUserName": "admin",
            "SubjectDomainName": "EXAMPLE",
            "OldSD": "D:(A;;FR;;;WD)",
            "NewSD": "D:(A;;FW;;;AU)",
        },
        shape,
    )
    assert ev.family == "share_change" and ev.get("share.change") == change
    assert ev.get("share.name") == "\\\\*\\Documents" and ev.get("share.local_path") == "C:\\Documents"
    assert ev.get("share.security_descriptor.old") == "D:(A;;FR;;;WD)"
    assert ev.get("share.security_descriptor.new") == "D:(A;;FW;;;AU)"
    assert ev.get("user.name") == "admin"


@pytest.mark.parametrize(
    "path,lane",
    [
        ("C:\\", "high"),
        ("C:\\Windows\\Tasks", "high"),
        ("%SystemRoot%\\Tasks", "high"),
        ("C:\\Users\\Public\\data", "high"),
        ("C:\\Temp\\data", "high"),
        ("C:\\Documents", "lead"),
        ("C:\\WindowsElsewhere", "lead"),
    ],
)
def test_share_change_path_lanes(path, lane):
    from romulus.detect.windows_share_events import ShareCreated

    (hit,) = ShareCreated().judge(
        event(
            "share_change", 5142, **{"share.change": "added", "share.name": "Data", "share.local_path": path}
        )
    )
    assert hit.lane == lane
    assert "share.local_path" in {p.field for p in hit.predicate}


@pytest.mark.parametrize(
    "sd,lane",
    [
        ("D:(A;;FW;;;WD)", "high"),
        ("D:(A;;GA;;;AU)", "high"),
        ("D:(A;;0x00000002;;;S-1-1-0)", "high"),
        ("D:(A;;FR;;;WD)", "lead"),
        ("D:(D;;FW;;;WD)", "lead"),
        ("D:(A;IO;FW;;;WD)", "lead"),
        ("D:(A;;FW;;;BA)", "lead"),
    ],
)
def test_share_descriptor_allow_write_not_deny_read_or_unrelated_trustee(sd, lane):
    from romulus.detect.windows_share_events import ShareCreated

    (hit,) = ShareCreated().judge(
        event(
            "share_change",
            5143,
            **{"share.change": "modified", "share.name": "Data", "share.security_descriptor.new": sd},
        )
    )
    assert hit.lane == lane


def test_deleted_share_is_context_and_missing_path_stays_lead():
    from romulus.detect.windows_share_events import ShareCreated

    (hit,) = ShareCreated().judge(
        event(
            "share_change",
            5144,
            **{"share.change": "deleted", "share.name": "Data", "share.local_path": "C:\\"},
        )
    )
    assert hit.lane == "context"
    assert ShareCreated().judge(event("share_access", 5145, **{"share.name": "C$"})) == []


@pytest.mark.parametrize("share", ["C$", "D$", "ADMIN$"])
@pytest.mark.parametrize("source,lane", [("192.0.2.10", "context"), ("192.0.2.99", "lead")])
def test_admin_share_connection_uses_source_site_declaration(share, source, lane):
    from romulus.detect.windows_share_events import AdminShareAccess

    rule = AdminShareAccess()
    rule.site_facts = replace(FACTS, management_hosts=("192.0.2.10",))
    (hit,) = rule.judge(event("share_access", 5140, **{"share.name": "\\\\*\\" + share, "source.ip": source}))
    assert hit.lane == lane
    assert rule.judge(event("share_access", 5145, **{"share.name": share, "source.ip": source})) == []


@pytest.mark.parametrize("share", ["IPC$", "AB$", "C$backup", "Data"])
def test_admin_share_connection_hard_negatives(share):
    from romulus.detect.windows_share_events import AdminShareAccess

    assert AdminShareAccess().judge(event("share_access", 5140, **{"share.name": share})) == []


def replication(session="0x1234", offset=60, host="dc01", native=None):
    return event(
        "directory_access",
        4662,
        host=host,
        offset=offset,
        native=native,
        **{
            "user.entity_id": "name:example\\syncsvc",
            "user.name": "syncsvc",
            "user.domain": "example",
            "windows.event_data.SubjectLogonId": session,
            "directory.object.server": "DS",
            "directory.object.dn": "DC=example,DC=test",
            "directory.access.access_mask": 256,
            "directory.rights.guids": [RIGHT],
        },
    )


def logon(source="192.0.2.99", session="0x1234", offset=0, host="dc01", native=None):
    return event(
        "auth",
        4624,
        host=host,
        offset=offset,
        native=native,
        **{"auth.session_id": session, "auth.target_account": "name:example\\syncsvc", "source.ip": source},
    )


@pytest.mark.parametrize("batches", [lambda a, b: [[a], [b]], lambda a, b: [[b], [a]]])
@pytest.mark.parametrize("source,lane", [("192.0.2.10", "lead"), ("192.0.2.99", "high")])
def test_declared_sync_account_source_join_out_of_order_and_late(batches, source, lane):
    rule = DirectoryReplicationAccess()
    rule.site_facts = FACTS
    a, b = logon(source), replication()
    hits = run(rule, batches(a, b))
    (hit,) = hits
    assert hit.proposed_lane == lane
    assert {e.id for e in hit.events} == {a.id, b.id}
    assert "undeclared host" in " ".join(hit.notes) if lane == "high" else True


@pytest.mark.parametrize(
    "other", [lambda: logon(host="dc02"), lambda: logon(session="0x9999"), lambda: logon(offset=120)]
)
def test_unresolved_sync_source_is_named_lead(other):
    rule = DirectoryReplicationAccess()
    rule.site_facts = FACTS
    (hit,) = run(rule, [[replication()], [other()]])
    assert hit.proposed_lane == "lead" and "source" in " ".join(hit.notes).lower()
    assert len(hit.events) == 1


def test_no_sync_source_declaration_keeps_lane_and_names_unchecked_host():
    rule = DirectoryReplicationAccess()
    rule.site_facts = replace(FACTS, directory_sync_hosts=(), directory_sync_addresses=())
    (hit,) = run(rule, [replication()])
    assert hit.proposed_lane == "lead" and "not checked" in " ".join(hit.notes)


def test_native_replication_actor_session_joins_native_logon_target():
    actor = {
        "SubjectUserSid": "S-1-5-21-1-2-3-1101",
        "SubjectUserName": "syncsvc",
        "SubjectDomainName": "EXAMPLE",
        "SubjectLogonId": "0x1234",
        "ObjectServer": "DS",
        "ObjectName": "DC=example,DC=test",
        "AccessMask": "0x100",
        "Properties": "{" + RIGHT + "}",
    }
    a = native(
        4624,
        {
            "TargetUserSid": "S-1-5-21-1-2-3-1101",
            "TargetUserName": "syncsvc",
            "TargetDomainName": "EXAMPLE",
            "TargetLogonId": "0x1234",
            "IpAddress": "192.0.2.99",
            "LogonType": "3",
        },
    )
    b = native(4662, actor)
    assert b.get("directory.actor_session_id") == "0x1234"
    rule = DirectoryReplicationAccess()
    rule.site_facts = FACTS
    (hit,) = run(rule, [[b], [a]])
    assert hit.proposed_lane == "high" and {e.id for e in hit.events} == {a.id, b.id}


def test_wrong_account_or_boot_cannot_supply_replication_source():
    from romulus.evidence.typed import fv

    for field, value in (("auth.target_account", "name:example\\other"), ("host.boot.id", "other-boot")):
        a, b = logon(), replication()
        b.fields["host.boot.id"] = fv("dc-boot", "test")
        a.fields[field] = fv(value, "test")
        rule = DirectoryReplicationAccess()
        rule.site_facts = FACTS
        (hit,) = run(rule, [[a], [b]])
        assert hit.proposed_lane == "lead" and len(hit.events) == 1


def test_declared_host_name_and_old_logon_remain_joinable_on_disk():
    from romulus.evidence.typed import fv

    a = logon(offset=-10 * 86400)
    a.fields["source.hostname"] = fv("sync01.example.test", "test")
    rule = DirectoryReplicationAccess()
    rule.site_facts = replace(FACTS, directory_sync_addresses=())
    (hit,) = run(rule, [[replication()], [a]])
    assert hit.proposed_lane == "lead" and len(hit.events) == 2
    assert "declared directory-sync source" in " ".join(hit.notes)


def test_known_undeclared_sync_source_publishes_high_immediately():
    rule = DirectoryReplicationAccess()
    rule.site_facts = FACTS
    assert list(rule.consume([logon()])) == []
    (high,) = list(rule.consume([replication()]))
    assert high.proposed_lane == "high"


def test_replication_source_rows_spill_across_ten_thousand_keys():
    rule = DirectoryReplicationAccess()
    rule.site_facts = FACTS
    rule.HOT = 4
    for start in range(0, 10000, 100):
        logons = [logon(session=hex(10000 + i), native=f"logon-{i}") for i in range(start, start + 100)]
        requests = [
            replication(session=hex(10000 + i), native=f"replication-{i}") for i in range(start, start + 100)
        ]
        list(rule.consume(requests))
        list(rule.consume(logons))
        rule.drain_staged()
        rule.drain_bounds()
    db = rule._sync_rows.store()
    assert db.execute("SELECT COUNT(*) FROM windows_rows").fetchone()[0] == 20000
    assert db.execute("SELECT COUNT(*) FROM windows_marks").fetchone()[0] == 10000
    assert all(not rows for _, rows in db._buffers.values())
    assert sum(group.records for _, group in rule.groups.items()) == 10000
    rule.close_spill()


def test_repeated_rights_in_one_logon_do_not_rescan_published_rows():
    rule = DirectoryReplicationAccess()
    rule.site_facts = FACTS
    list(rule.consume([logon()]))
    selects = []
    rule._sync_rows.store().db.set_trace_callback(
        lambda sql: selects.append(1) if "SELECT" in sql.upper() and "windows_marks" in sql else None
    )
    for i in range(100):
        list(rule.consume([replication(native=f"same-session-{i}", offset=60 + i)]))
    assert len(selects) <= 200
    rule.close_spill()


def test_sync_join_names_physical_disk_refusals():
    from romulus.detect.bounded import StateBudget

    rule = DirectoryReplicationAccess()
    rule.site_facts = FACTS
    rule.budget = StateBudget(disk_total=64 * 1024, reserve=0)
    for i in range(100):
        list(rule.consume([logon(session=hex(10000 + i), native=f"bounded-logon-{i}")]))
    assert rule.capped > 0
    assert any("disk" in reason.lower() or "byte" in reason.lower() for reason in rule.limit_reasons())
    rule.close_spill()


@pytest.mark.parametrize("path", ["\\??\\C:\\", "\\\\?\\C:\\", "\\Device\\HarddiskVolume3\\"])
def test_native_volume_root_share_paths_remain_high(path):
    from romulus.detect.windows_share_events import ShareCreated

    (hit,) = ShareCreated().judge(
        event(
            "share_change", 5142, **{"share.change": "added", "share.name": "Root", "share.local_path": path}
        )
    )
    assert hit.lane == "high"


def test_structured_descriptor_value_is_not_searched_as_serialized_text():
    from romulus.detect.windows_share_events import ShareCreated

    (hit,) = ShareCreated().judge(
        event(
            "share_change",
            5143,
            **{
                "share.change": "modified",
                "share.name": "Data",
                "share.security_descriptor.new": {"description": "(A;;FW;;;WD)"},
            },
        )
    )
    assert hit.lane == "lead"


def test_native_descriptor_field_never_types_a_non_string_as_sddl():
    ev = native(5143, {"ShareName": "Data", "NewSD": 42})
    assert not ev.has("share.security_descriptor.new")


def test_windows_share_rules_are_registered_once():
    from romulus.detect.registry import ALL_PLAYBOOKS

    ids = [rule.id for rule in ALL_PLAYBOOKS]
    assert ids.count("win.share_created") == 1
    assert ids.count("win.admin_share_access") == 1


@pytest.mark.parametrize("path", [r"C:\Temp", r"C:\Users\Public", "%TEMP%", "%USERPROFILE%"])
def test_share_writable_directory_roots_are_high(path):
    from romulus.detect.windows_share_events import ShareCreated

    (hit,) = ShareCreated().judge(
        event(
            "share_change", 5142, **{"share.change": "added", "share.name": "Data", "share.local_path": path}
        )
    )
    assert hit.lane == "high"


@pytest.mark.parametrize("latest_source,expected", [("192.0.2.10", "lead"), ("192.0.2.99", "high")])
def test_late_latest_dc_logon_revises_replication_source_in_place(latest_source, expected):
    early = logon(
        "192.0.2.99" if latest_source.endswith("10") else "192.0.2.10", offset=0, native="early-source"
    )
    latest = logon(latest_source, offset=50, native="latest-source")
    req = replication(offset=60)
    for batches in ([[early], [latest], [req]], [[early], [req], [latest]]):
        rule = DirectoryReplicationAccess()
        rule.site_facts = FACTS
        (hit,) = run(rule, batches)
        assert hit.proposed_lane == expected
        assert {ev.id for ev in hit.events} == {req.id, latest.id}


def test_late_source_corrections_remove_stale_high_aggregate_and_keep_citations():
    rule = DirectoryReplicationAccess()
    rule.site_facts = FACTS
    early = logon(offset=0, native="early-source")
    late = logon("192.0.2.10", offset=50, native="latest-source")
    requests = [replication(offset=60 + i, native=f"revision-request-{i}") for i in range(3)]
    hits = run(rule, [[early], requests, [late]])
    assert hits and all(hit.proposed_lane != "high" for hit in hits)
    assert all(any(ev.id == late.id for ev in hit.events) for hit in hits)
    assert any(hit.revision_reason for hit in hits)


def test_sync_aggregate_cites_the_logon_that_supports_its_lane():
    rule = DirectoryReplicationAccess()
    rule.site_facts = FACTS
    a = logon()
    reqs = [replication(offset=60 + i, native=f"cited-request-{i}") for i in range(3)]
    hits = run(rule, [[a], reqs])
    assert all(any(ev.id == a.id for ev in hit.events) for hit in hits)
