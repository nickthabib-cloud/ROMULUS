"""Authentication witness, state and interpretation regressions."""
import pytest

from romulus.detect import netdef
from romulus.detect.bounded import StateBudget
from romulus.detect.windows_auth_events import (
    WINDOWS_AUTH_EVENT_PLAYBOOKS,
    WindowsBruteForce,
    WindowsDistributedGuessing,
    WindowsExplicitCredentialFanout,
    WindowsExternalRdp,
    WindowsHashLogonShape,
    WindowsKerberoastDiversity,
    WindowsPasswordSpray,
)
from romulus.evidence.typed import fv
from tests.windows_event_support import START, event, run


def failed(n, *, account=None, source="203.0.113.5", host="ws01", offset=None):
    return event("auth", 4625, native=f"failure-{n}-{host}", host=host, offset=n if offset is None else offset,
                 outcome="failure", **{"source.ip": source, "auth.target_account": account or f"name:example\\u{n}"})


@pytest.mark.parametrize("rule,records", [
    (WindowsPasswordSpray, [failed(n) for n in range(20)]),
    (WindowsBruteForce, [failed(n, account="name:example\\alice") for n in range(20)]),
    (WindowsDistributedGuessing, [failed(n, account="name:example\\alice", source=f"203.0.113.{n+1}") for n in range(10)]),
])
def test_threshold_immediately_cites_every_counted_witness(rule, records):
    evaluator = rule()
    assert not evaluator.consume(records[:-1])
    matches = evaluator.consume(records[-1:])
    assert len(matches) == 1
    match = matches[0]
    assert {item.id for item in records} <= {item.id for item in match.events}
    assert match.proposed_lane == "lead" and "not proof" in match.claim
    assert not list(evaluator.finalize())
    evaluator.release_state()


def test_sliding_window_crosses_bucket_boundary_and_late_records_replay():
    offset = 600 - int(START.timestamp()) % 600 - 10
    records = [failed(n, offset=offset+n) for n in range(20)]
    assert run(WindowsPasswordSpray(), records)
    # Newest target first; no early timestamp can see its later witnesses until replay.
    matches = run(WindowsPasswordSpray(), [[item] for item in reversed(records)])
    assert matches and {item.id for item in records} <= {item.id for item in matches[-1].events}


def test_late_earlier_witnesses_revise_the_same_published_identity():
    records = [failed(n) for n in range(40)]
    chronological = run(WindowsPasswordSpray(), records)
    late = run(WindowsPasswordSpray(), [records[20:], records[:20]])
    canonical = lambda matches: [(item.group_key, item.claim, sorted(event.id for event in item.events)) for item in matches]
    assert canonical(late) == canonical(chronological)
    assert late[0].revision_reason


def test_duplicates_repetition_missing_fields_success_and_linux_are_not_spray():
    records = [failed(n, account="name:example\\alice") for n in range(30)]
    rule = WindowsPasswordSpray()
    assert not run(rule, [records, records])
    assert rule.rows.store().execute("SELECT count(*) FROM windows_rows").fetchone()[0] == 30
    rule.release_state()
    for change in ("success", "linux", "missing", "wide"):
        records = [failed(n, offset=n*601 if change == "wide" else n) for n in range(25)]
        for item in records:
            if change == "success":
                item.outcome = "success"
            elif change == "linux":
                item.fields["host.os.family"] = fv("linux", "test")
            elif change == "missing":
                item.fields.pop("auth.target_account")
        assert not run(WindowsPasswordSpray(), records)


def test_new_host_and_raw_copies_from_prior_batches_are_immediate():
    rule = WindowsPasswordSpray()
    matches = []
    for item in [failed(n) for n in range(20)] + [failed(50, host="ws02")]:
        rule.bind_raw({item.raw[0].key: {"marker": item.id}})
        matches.extend(rule.consume([item]))
    assert len(matches) == 2 and matches[0].group_key != matches[1].group_key
    assert "ws02" in matches[1].claim
    assert all(ref.key in match.raw_copies for match in matches for item in match.events for ref in item.raw)
    rule.release_state()


def test_repeated_value_on_an_early_host_is_not_suppressed_after_global_threshold():
    rule = WindowsPasswordSpray()
    assert not rule.consume([failed(0, host="early")])
    assert rule.consume([failed(n, host="other") for n in range(1, 20)])
    matches = rule.consume([failed(21, account="name:example\\u0", host="early")])
    assert len(matches) == 1 and "early" in matches[0].claim


@pytest.mark.parametrize("shape", ["elastic_agent", "winlogbeat_7", "winlogbeat_8"])
def test_native_4776_workstation_can_supply_a_clearly_labelled_source(shape):
    from romulus.evidence.windows import normalize_windows
    from romulus.evidence.windows_catalog import SECURITY
    from tests.windows_fixtures import LogicalWindowsEvent, windows_hit
    records = [normalize_windows(windows_hit(LogicalWindowsEvent("Security", SECURITY, 4776,
        "dc01.example.test", n+100, (START.replace(second=n)).isoformat().replace("+00:00", "Z"),
        {"TargetUserName": f"u{n}", "Workstation": "CLIENT01", "Status": "0xc000006a"}), shape))
        for n in range(20)]
    matches = run(WindowsPasswordSpray(), records)
    assert matches and "workstation" in matches[0].claim.casefold()


def test_budget_refusal_names_unassessed_correlation(tmp_path):
    rule = WindowsPasswordSpray()
    rule.budget = StateBudget(tmp_path, disk_total=1024*1024, reserve=0)
    rule.budget.force_full("test disk", lambda account: "windows_rows" in account.name)
    assert not rule.consume([failed(1)])
    assert rule.capped == 1 and rule.limit_reasons()
    rule.release_state()


def test_revising_a_marker_charges_only_its_size_change():
    rule = WindowsPasswordSpray()
    rule.rows.store()
    rule.rows.remember("key", "first")
    used = rule.rows.account.used
    rule.rows.remember("key", "other")
    assert rule.rows.account.used == used
    rule.release_state()


def test_sql_rows_reserve_a_store_floor_before_the_sweep_starts():
    from romulus.detect.bounded import live_stores
    rule = WindowsPasswordSpray()
    assert live_stores([rule]) == 4


@pytest.mark.parametrize("rule,code,field,count", [
    (WindowsExplicitCredentialFanout, 4648, "auth.target_server", 5),
    (WindowsKerberoastDiversity, 4769, "auth.service_name", 10),
])
def test_fanout_counts_distinct_targets(rule, code, field, count):
    records = [event("auth", code, offset=n, **{"user.entity_id": "sid:s-1-5-21-1-2-3-1100",
               "auth.target_account": "name:example\\alice", "source.ip": "203.0.113.5", field: f"target{n}"})
               for n in range(count)]
    assert run(rule(), records)
    for item in records:
        item.fields[field] = fv("same", "test")
    assert not run(rule(), records)


@pytest.mark.parametrize("fields,expected", [
    ({"auth.logon_type": 9, "auth.logon_process": "seclogo"}, True),
    ({"auth.logon_type": 3, "auth.package": "NTLM", "auth.key_length": 0}, True),
    ({"auth.logon_type": 3, "auth.package": "Kerberos", "auth.key_length": 0}, False),
    ({"auth.logon_type": 9, "auth.logon_process": "seclogo.exe"}, False),
    ({"auth.logon_type": 3, "auth.package": "NTLM", "auth.key_length": 0x100000000}, False),
    ({"auth.logon_type": 3, "auth.package": "NTLM", "auth.key_length": False}, False),
])
def test_hash_shapes_are_leads_with_hard_negatives(fields, expected):
    matches = run(WindowsHashLogonShape(), [event("auth", 4624, **fields)])
    assert bool(matches) == expected
    if matches:
        assert matches[0].proposed_lane == "lead" and "does not prove" in matches[0].claim


def test_rdp_uses_configured_networks_and_preserves_authentication_wording():
    assert WindowsExternalRdp.direction_dependent
    saved = netdef.current()
    try:
        netdef.install(netdef.SiteNetworks("configured", netdef.parse_networks(["203.0.113.0/24"], "test")))
        assert not run(WindowsExternalRdp(), [event("auth", 4624, **{"auth.logon_type": 10, "source.ip": "203.0.113.5"})])
        matches = run(WindowsExternalRdp(), [event("remote_access", 1149, **{
            "remote.action": "rdp_authentication", "source.ip": "198.51.100.5"})])
        assert len(matches) == 1 and "authentication record" in matches[0].claim
    finally:
        netdef.install(saved)


def test_large_single_key_has_disk_rows_without_unbounded_heap_lists():
    rule = WindowsBruteForce()
    for start in range(0, 5000, 100):
        rule.consume([failed(n, account="name:example\\alice", offset=n//10) for n in range(start, start+100)])
        rule.drain_staged()
    assert rule.rows.store().execute("SELECT count(*) FROM windows_rows").fetchone()[0] == 5000
    assert not rule._pending and not rule.groups
    rule.release_state()


def test_metadata_and_attack_ids_are_current():
    from romulus.catalog.attack import load_attack_bundle
    bundle = load_attack_bundle()
    assert len(WINDOWS_AUTH_EVENT_PLAYBOOKS) == 7
    for rule in WINDOWS_AUTH_EVENT_PLAYBOOKS:
        assert not rule.assures_negative and rule.benign and rule.research and rule.windows_event_classes
        assert rule.attack and all(not bundle.technique(item).revoked for item in rule.attack)
