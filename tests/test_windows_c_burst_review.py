"""Native-record regressions for authentication concentration and compact citation state."""
import hashlib
import json
from datetime import UTC, datetime, timedelta

import pytest

from romulus.detect.bounded import StateBudget
from romulus.detect.windows_auth_events import (
    WindowsBruteForce,
    WindowsExternalRdp,
    WindowsHashLogonShape,
    WindowsKerberoastDiversity,
    WindowsPasswordSpray,
)
from romulus.evidence.windows import normalize_windows
from romulus.evidence.windows_catalog import RDP_LSM_CHANNEL, RDP_LSM_PROVIDER, SECURITY
from tests.windows_fixtures import LogicalWindowsEvent, windows_hit
from tests.windows_process_support import run

START = datetime(2026, 1, 2, 3, tzinfo=UTC)


def native_event(code, data, *, host="ws01.example.test", offset=0, record=None,
                 channel="Security", provider=SECURITY, shape="winlogbeat_8"):
    if record is None:
        material = json.dumps([code, data, host, offset, channel, provider], sort_keys=True)
        record = int(hashlib.sha256(material.encode()).hexdigest()[:12], 16)
    logical = LogicalWindowsEvent(channel, provider, code, host, record,
                                  (START+timedelta(seconds=offset)).isoformat().replace("+00:00", "Z"), data)
    return normalize_windows(windows_hit(logical, shape))


def failure(n, *, source="203.0.113.5", account=None, host="ws01.example.test", offset=None, shape="winlogbeat_8"):
    record = int(hashlib.sha256(json.dumps([n, source, account, host, offset]).encode()).hexdigest()[:12], 16)
    return native_event(4625, {"TargetUserName": account or f"u{n}", "TargetDomainName": "EXAMPLE",
                              "IpAddress": source or "-", "Status": "0xc000006a", "LogonType": "3"},
                        host=host, offset=n if offset is None else offset, shape=shape, record=record)


def ticket(n, *, principal="alice", service=None, offset=None, extra=None):
    return native_event(4769, {"TargetUserName": principal+"@EXAMPLE.TEST", "TargetDomainName": "EXAMPLE.TEST",
                              "ServiceName": service or f"mssql/db{n}", "IpAddress": "203.0.113.5",
                              "TicketEncryptionType": "0x12", "Status": "0x0", **(extra or {})},
                        offset=n if offset is None else offset, record=100000+n)


def bind(rule, records):
    by_id = {event.id: event for event in records}
    rule.bind_loader(lambda ids: [by_id[key] for key in ids if key in by_id])
    return rule


@pytest.mark.parametrize("shape", ["winlogbeat_7", "winlogbeat_8", "elastic_agent"])
def test_sourceless_spray_and_brute_force_preserve_reporting_host_without_source_attribution(shape):
    records = [failure(n, source=None, shape=shape) for n in range(50)]
    matches = run(WindowsPasswordSpray(), records)
    assert matches and all(match.proposed_lane == "lead" for match in matches)
    assert any("source unresolved, reported by ws01.example.test" in match.claim for match in matches)
    assert all("not proof" in match.claim for match in matches)
    repeated = [failure(n, source=None, account="alice", shape=shape) for n in range(20)]
    brute = run(WindowsBruteForce(), repeated)
    assert brute and all("One source" not in match.claim and "source unresolved" in match.claim for match in brute)


def test_rotating_sources_cannot_defeat_reporting_host_short_window():
    records = [failure(n, source=f"198.51.100.{n+1}") for n in range(30)]
    matches = run(WindowsPasswordSpray(), records)
    assert len(matches) == 1 and "reporting host ws01.example.test" in matches[0].claim
    assert "unrelated" in matches[0].claim
    assert len(matches[0].events) >= 20


@pytest.mark.parametrize("rotating", [False, True])
def test_daily_distinct_account_breadth_finds_slow_and_rotating_source_sprays(rotating):
    records = [failure(n, offset=n*61, source=f"198.51.{n//250}.{n%250+1}" if rotating else "203.0.113.5")
               for n in range(2000)]
    rule = WindowsPasswordSpray()
    matches = run(rule, [records[n:n+100] for n in range(0, len(records), 100)])
    daily = [match for match in matches if "hunt span" in match.claim]
    assert len(daily) == (1 if rotating else 2)  # One folded finding per concentration key across days.
    assert daily and all(len(match.events) == 100 for match in daily)
    assert any("reporting host" in match.claim for match in daily)
    if not rotating:
        assert any("recorded source IP 203.0.113.5" in match.claim for match in daily)
    assert all(any("fleet size" in note and "central DCs" in note for note in match.notes) for match in daily)
    assert not rule.limits
    rule.release_state()


def test_daily_threshold_requires_distinct_accounts_and_does_not_cross_utc_days():
    rule = WindowsPasswordSpray()
    records = [failure(n, account="alice", offset=n*61) for n in range(150)]
    assert not any("UTC day" in match.claim for match in run(rule, records))
    rule.release_state()
    records = [failure(n, offset=n*61+(86400 if n >= 50 else 0)) for n in range(99)]
    assert not run(WindowsPasswordSpray(), records)


def test_kerberos_rows_are_compact_and_expire_to_replayable_disk_archive():
    records = [ticket(n, service=f"host/s{n%7}", offset=n) for n in range(1000)]
    rule = bind(WindowsKerberoastDiversity(), records)
    for start in range(0, len(records), 100):
        assert not rule.consume(records[start:start+100])
        rule.drain_staged()
    db = rule.rows.store()
    assert [row[1] for row in db.execute("PRAGMA table_info(windows_rows)")] == ["k", "id", "ts", "value", "host"]
    assert db.execute("SELECT count(*) FROM windows_rows").fetchone()[0] <= 301
    assert db.execute("SELECT count(*) FROM windows_archive").fetchone()[0] >= 699
    assert rule.rows.account.used < 600*len(records)
    assert not list(rule.finalize())
    assert not rule._pending and not rule._batch and not rule.groups
    rule.release_state()


def test_archive_preserves_late_witnesses_and_cross_bucket_windows():
    # Most witnesses have expired from the active five-minute set before the last three arrive.
    attack = [ticket(n, principal="old", offset=10+n) for n in range(10)]
    future = [ticket(1000+n, principal="other", service="host/same", offset=10000+n) for n in range(30)]
    rule = WindowsKerberoastDiversity()
    matches = run(rule, [attack[:7], future, attack[7:]])
    found = [match for match in matches if "name:example.test\\old" in match.claim]
    assert found and {event.id for event in attack} <= {event.id for event in found[-1].events}
    assert not rule.limits
    rule.release_state()


def test_shared_budget_flood_cannot_take_another_rules_guaranteed_floor(tmp_path):
    budget = StateBudget(tmp_path, disk_total=8*2**20, reserve=0)
    budget.plan(70)
    noisy, roast = WindowsBruteForce(), WindowsKerberoastDiversity()
    for rule in (noisy, roast):
        rule.budget = budget
    # Over 25,000 native records force the noisy rule's own budget into honest refusal.
    for start in range(0, 25000, 100):
        noisy.consume([failure(n, account="alice", offset=n*601) for n in range(start, start+100)])
        noisy.drain_staged()
    attack = [ticket(90000+n) for n in range(10)]
    matches = run(roast, attack)
    assert noisy.capped > 0 and noisy.limit_reasons()
    assert matches and roast.capped == 0
    assert all(event.id in {item.id for item in matches[0].events} for event in attack)
    noisy.release_state()
    roast.release_state()


def test_original_two_megabyte_kerberos_flood_keeps_room_for_later_positive(tmp_path):
    budget = StateBudget(tmp_path, disk_total=2*2**20, reserve=0)
    budget.plan(70)
    rule = WindowsKerberoastDiversity()
    rule.budget = budget
    for start in range(0, 4000, 100):
        records = [ticket(n, principal=f"u{n%50}", service=f"host/s{n%7}") for n in range(start, start+100)]
        assert not rule.consume(records)
        rule.drain_staged()
    assert rule.rows.account.used < budget.pool and not budget.full
    attack = [ticket(90000+n, principal="late", offset=9000+n) for n in range(10)]
    assert run(rule, attack)
    assert rule.capped == 0 and not rule.limits
    rule.release_state()


def test_refused_parallel_indexes_count_one_unassessed_input_record(tmp_path):
    rule = WindowsPasswordSpray()
    rule.budget = StateBudget(tmp_path, disk_total=2*2**20, reserve=0)
    rule.budget.force_full("injected disk limit", lambda account: "windows_rows" in account.name)
    event = failure(1)
    for key in ("source", "reporter", "daily-source", "daily-reporter"):
        assert not rule.rows.put(key, event, "account")
    assert rule.capped == 1 and rule.limits["windows_row_refused"].records == 1
    rule.release_state()


def test_hash_shape_folds_session_and_guid_instances_but_separates_content_and_hosts():
    def logon(n, *, package="NTLM", kind="3", host="ws01.example.test"):
        return native_event(4624, {"TargetUserName": "alice", "TargetDomainName": "EXAMPLE", "LogonType": kind,
                                  "AuthenticationPackageName": package, "LogonProcessName": "seclogo",
                                  "KeyLength": "0", "TargetLogonId": hex(n+100),
                                  "LogonGuid": f"{{00000000-0000-0000-0000-{n:012x}}}"}, record=n+100, host=host)
    records = [logon(1), logon(2), logon(3, kind="9"), logon(4, host="ws02.example.test")]
    rule = WindowsHashLogonShape()
    out = rule.consume(records)
    assert len(rule.groups) == 2
    assert sorted(group.records for _, group in rule.groups.items()) == [1, 3]
    # First records on both hosts publish immediately; the first repeat also publishes the fleet fold.
    assert len(out) == 4 and any("ws02" in match.claim for match in out)
    result = run(bind(rule, records), [])
    assert len({match.group_key for match in [*out, *result] if match.group_key}) == 1
    assert any(field.field == "auth.session_key" for match in out for field in match.predicate)
    rule.release_state()


def test_native_lsm_local_console_is_not_an_unresolved_rdp_source():
    event = native_event(21, {"User": "EXAMPLE\\alice", "SessionID": "2", "Address": "LOCAL"},
                         channel=RDP_LSM_CHANNEL, provider=RDP_LSM_PROVIDER)
    assert not run(WindowsExternalRdp(), [event])


def test_retired_tgt_context_has_no_evaluator_or_correlation_rows():
    from romulus.detect import windows_correlations
    assert not hasattr(windows_correlations, "KerberosTgtContext")
    assert {rule.id for rule in windows_correlations.WINDOWS_CORRELATION_PLAYBOOKS} == {"win.created_then_privileged"}
