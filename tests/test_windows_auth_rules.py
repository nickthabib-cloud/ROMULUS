"""Native authentication witness, state and interpretation regressions."""
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
from romulus.evidence.windows_catalog import RDP_RCM_CHANNEL, RDP_RCM_PROVIDER
from tests.test_windows_c_burst_review import START, bind, failure, native_event
from tests.windows_process_support import run


@pytest.mark.parametrize("rule,records,count", [
    (WindowsPasswordSpray, [failure(n) for n in range(20)], 2),
    (WindowsBruteForce, [failure(n, account="alice") for n in range(20)], 1),
    (WindowsDistributedGuessing, [failure(n, account="alice", source=f"203.0.113.{n+1}") for n in range(10)], 1),
])
def test_threshold_immediately_cites_every_counted_witness(rule, records, count):
    evaluator = bind(rule(), records)
    assert not evaluator.consume(records[:-1])
    evaluator.drain_staged()
    matches = evaluator.consume(records[-1:])
    assert len(matches) == count
    for match in matches:
        assert {item.id for item in records} <= {item.id for item in match.events}
        assert match.proposed_lane == "lead" and "not proof" in match.claim
    assert not list(evaluator.finalize())
    evaluator.release_state()


def test_sliding_window_crosses_bucket_boundary_and_late_records_replay():
    offset = 600 - int(START.timestamp()) % 600 - 10
    records = [failure(n, offset=offset+n) for n in range(20)]
    assert run(WindowsPasswordSpray(), records)
    matches = run(WindowsPasswordSpray(), [[item] for item in reversed(records)])
    assert matches and {item.id for item in records} <= {item.id for item in matches[-1].events}


def test_late_earlier_witnesses_revise_the_same_published_identity():
    records = [failure(n) for n in range(40)]
    chronological = run(WindowsPasswordSpray(), records)
    late = run(WindowsPasswordSpray(), [records[20:], records[:20]])
    canonical = lambda matches: [(item.group_key, item.claim, sorted(event.id for event in item.events)) for item in matches]
    assert canonical(late) == canonical(chronological)
    assert late[0].revision_reason


def test_duplicates_repetition_missing_fields_success_and_wide_records_are_not_spray():
    records = [failure(n, account="alice") for n in range(30)]
    rule = WindowsPasswordSpray()
    assert not run(rule, [records, records])
    assert rule.rows.store().execute("SELECT count(DISTINCT id) FROM windows_all").fetchone()[0] == 30
    rule.release_state()
    for change in ("success", "missing", "wide"):
        records = [native_event(4776, {"TargetUserName": f"u{n}" if change != "missing" else "-",
                                      "Workstation": "CLIENT01", "Status": "0x0" if change == "success" else "0xc000006a"},
                                offset=n*601 if change == "wide" else n) for n in range(25)]
        assert not run(WindowsPasswordSpray(), records)


def test_new_host_is_retained_at_the_final_source_checkpoint():
    records = [failure(n) for n in range(20)] + [failure(50, host="ws02.example.test")]
    rule = bind(WindowsPasswordSpray(), records)
    matches = []
    for item in records:
        matches.extend(rule.consume([item]))
        rule.drain_staged()
    source = [match for match in matches if "for IP " in match.claim]
    assert len(source) == 1
    [final] = [match for match in rule.finalize() if "for IP " in match.claim]
    assert final.group_key == source[0].group_key and final.proposed_lane == "lead"
    assert {item.id for item in final.events} == {item.id for item in records}
    assert "ws02" in final.claim and "21 records" in final.claim
    assert not list(rule.finalize())
    rule.release_state()


def test_repeated_value_on_an_early_host_is_not_suppressed_after_global_threshold():
    records = [failure(0, host="early.example.test"),
               *[failure(n, host="other.example.test") for n in range(1, 20)],
               failure(21, account="u0", host="early.example.test")]
    rule = bind(WindowsPasswordSpray(), records)
    assert not rule.consume(records[:1])
    assert rule.consume(records[1:-1])
    assert not rule.consume(records[-1:])
    [final] = list(rule.finalize())
    assert final.proposed_lane == "lead" and "early" in final.claim
    assert {item.id for item in final.events} == {item.id for item in records}
    assert "21 records" in final.claim and "20 distinct recorded target accounts" in final.claim
    assert not list(rule.finalize())
    rule.release_state()


@pytest.mark.parametrize("shape", ["elastic_agent", "winlogbeat_7", "winlogbeat_8"])
def test_native_4776_workstation_can_supply_a_clearly_labelled_source(shape):
    records = [native_event(4776, {"TargetUserName": f"u{n}", "Workstation": "CLIENT01", "Status": "0xc000006a"},
                            offset=n, shape=shape) for n in range(20)]
    matches = run(WindowsPasswordSpray(), records)
    assert matches and "workstation" in matches[0].claim.casefold()


def test_budget_refusal_names_unassessed_correlation(tmp_path):
    rule = WindowsPasswordSpray()
    rule.budget = StateBudget(tmp_path, disk_total=1024*1024, reserve=0)
    rule.budget.force_full("test disk", lambda account: "windows_rows" in account.name)
    assert not rule.consume([failure(1)])
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


@pytest.mark.parametrize("rule,code,native_field,count", [
    (WindowsExplicitCredentialFanout, 4648, "TargetServerName", 5),
    (WindowsKerberoastDiversity, 4769, "ServiceName", 10),
])
def test_fanout_counts_distinct_targets(rule, code, native_field, count):
    def records(same=False):
        return [native_event(code, {"SubjectUserSid": "S-1-5-21-1-2-3-1100", "TargetUserName": "alice",
                                   "TargetDomainName": "EXAMPLE", "IpAddress": "203.0.113.5", "Status": "0x0",
                                   native_field: "same" if same else f"target{n}"}, offset=n) for n in range(count)]
    assert run(rule(), records())
    assert not run(rule(), records(True))


@pytest.mark.parametrize("fields,expected", [
    ({"LogonType": "9", "LogonProcessName": "seclogo"}, True),
    ({"LogonType": "3", "AuthenticationPackageName": "NTLM", "KeyLength": "0"}, True),
    ({"LogonType": "3", "AuthenticationPackageName": "Kerberos", "KeyLength": "0"}, False),
    ({"LogonType": "9", "LogonProcessName": "seclogo.exe"}, False),
    ({"LogonType": "3", "AuthenticationPackageName": "NTLM", "KeyLength": "4294967296"}, False),
])
def test_hash_shapes_are_leads_with_hard_negatives(fields, expected):
    matches = run(WindowsHashLogonShape(), [native_event(4624, fields)])
    assert bool(matches) == expected
    if matches:
        assert matches[0].proposed_lane == "lead" and "does not prove" in matches[0].claim


def test_rdp_uses_configured_networks_and_preserves_authentication_wording():
    assert WindowsExternalRdp.direction_dependent
    saved = netdef.current()
    try:
        netdef.install(netdef.SiteNetworks("configured", netdef.parse_networks(["203.0.113.0/24"], "test")))
        assert not run(WindowsExternalRdp(), [native_event(4624, {"LogonType": "10", "IpAddress": "203.0.113.5"})])
        matches = run(WindowsExternalRdp(), [native_event(1149, {"Param1": "alice", "Param2": "EXAMPLE",
                                        "Param3": "198.51.100.5"}, channel=RDP_RCM_CHANNEL, provider=RDP_RCM_PROVIDER)])
        assert len(matches) == 1 and "authentication record" in matches[0].claim
    finally:
        netdef.install(saved)


def test_large_single_key_has_disk_rows_without_unbounded_heap_lists():
    rule = WindowsBruteForce()
    for start in range(0, 5000, 100):
        records = [failure(n, account="alice", offset=n//10) for n in range(start, start+100)]
        rule.consume(records)
        rule.drain_staged()
    assert rule.rows.store().execute("SELECT count(*) FROM windows_all").fetchone()[0] == 5000
    assert not rule._pending and not rule.groups
    rule.release_state()


def test_metadata_and_attack_ids_are_current():
    from romulus.catalog.attack import load_attack_bundle
    bundle = load_attack_bundle()
    assert len(WINDOWS_AUTH_EVENT_PLAYBOOKS) == 7
    for rule in WINDOWS_AUTH_EVENT_PLAYBOOKS:
        assert rule.version == ("6" if hasattr(rule, "citation_fields") else "4") and not rule.assures_negative and rule.benign and rule.research and rule.windows_event_classes
        if hasattr(rule, "citation_fields"):
            assert "doublings and finalization" in rule.card["lanes"]
        assert rule.attack and all(not bundle.technique(item).revoked for item in rule.attack)
