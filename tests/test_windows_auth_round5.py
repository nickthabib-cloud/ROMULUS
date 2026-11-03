"""Bounded revisions retain first/latest witnesses and truthful episode totals."""
import json

import pytest

from romulus.detect.bounded import StateExhausted
from romulus.detect.windows_auth_events import WindowsBruteForce, WindowsPasswordSpray
from romulus.hunt.publish import publish_match
from tests.test_candidate_revision import _audits
from tests.test_sweep import _repo
from tests.test_windows_c_burst_review import failure


def drive(rule, repo, events):
    for match in rule.consume(events):
        publish(repo, rule, match)


def publish(repo, rule, match):
    raw = {ref.key: {"fixture": event.id} for event in match.events for ref in event.raw}
    publish_match(repo, "h1", rule, match, None, raw)


def test_continuous_episode_revises_at_doublings_and_finalize_with_bounded_citations():
    repo, rule = _repo(), WindowsBruteForce()
    events = [failure(n, account="service", offset=n*30) for n in range(2880)]
    for start in range(0, len(events), 100):
        drive(rule, repo, events[start:start+100])
    [before] = repo.candidates("h1")
    assert before["gate_results"]["_revision"]["count"] == 7
    for match in rule.finalize():
        publish(repo, rule, match)
    [candidate] = repo.candidates("h1")
    assert candidate["gate_results"]["_revision"]["count"] == 8
    assert set(candidate["event_ids"]) == {event.id for event in events[:20]+events[-20:]}
    assert "144 non-overlapping qualifying windows" in candidate["claim"]
    assert "1 episode" in candidate["claim"] and "2880 records" in candidate["claim"]
    assert "1 distinct" in candidate["claim"]
    assert sum(len(json.dumps(row["detail"])) for row in _audits(repo)) < 100_000
    for audit in _audits(repo):
        assert "event_ids" not in audit["detail"]["previous"]
        assert audit["detail"]["citations"]["previous"]["count"] <= 40
    rule.release_state()


def test_authentication_hosts_outside_first_latest_citations_remain_paged_and_named():
    repo, rule = _repo(), WindowsPasswordSpray()
    events = ([failure(n) for n in range(20)] +
              [failure(20+n, host=f"middle{n:03}.example.test") for n in range(121)] +
              [failure(141+n) for n in range(20)])
    drive(rule, repo, events)
    for match in rule.finalize():
        publish(repo, rule, match)
    [source] = [row for row in repo.candidates("h1") if "for IP " in row["claim"]]
    assert set(source["event_ids"]) == {event.id for event in events[:20]+events[-20:]}
    assert "122 reporting hosts" in source["claim"]
    assert source["gate_results"]["_fleet_hosts_complete"]
    members, after = [], ""
    while True:
        page, after = repo.candidate_hosts(source["id"], after=after)
        assert len(page) <= 50
        members.extend(page)
        if not after:
            break
    expected = {}
    for event in events:
        expected.setdefault(event.host, event.id)
    assert {row["host"]: row["first_event_id"] for row in members} == expected
    assert not list(rule.finalize())
    rule.release_state()


def test_daily_host_first_witness_revises_when_an_earlier_record_arrives_late():
    repo, rule = _repo(), WindowsPasswordSpray()
    events = [failure(n) for n in range(100)]
    drive(rule, repo, events)
    for match in rule.finalize():
        publish(repo, rule, match)
    before = {row["id"] for row in repo.candidates("h1") if row["group_key"].startswith("windows-daily-auth:")}
    assert len(before) == 2
    earlier = failure(200, account="u0", offset=-1)
    drive(rule, repo, [earlier])
    for match in rule.finalize():
        publish(repo, rule, match)
    daily = [row for row in repo.candidates("h1") if row["group_key"].startswith("windows-daily-auth:")]
    assert {row["id"] for row in daily} == before
    for row in daily:
        [host], after = repo.candidate_hosts(row["id"])
        assert host["first_event_id"] == earlier.id and not after
    assert not list(rule.finalize())
    rule.release_state()


def test_expiry_failure_does_not_refuse_an_already_committed_record(monkeypatch):
    rule = WindowsBruteForce()
    first = failure(0, account="service", offset=0)
    latest = failure(1, account="service", offset=1000)
    assert rule.rows.put("key", first, "service")
    original = rule.rows._write
    def write(statement, rows):
        if statement.startswith("INSERT OR IGNORE INTO windows_archive"):
            raise StateExhausted("injected archive move full")
        return original(statement, rows)
    monkeypatch.setattr(rule.rows, "_write", write)
    with rule.rows.batch():
        assert rule.rows.put("key", latest, "service")
    assert rule.rows.count("key") == 2
    assert not rule.capped and "windows_expiry" in rule.limits
    rule.release_state()


def test_burst_admission_and_page_checks_are_bounded_per_batch(monkeypatch):
    rule = WindowsBruteForce()
    rows = rule.rows
    spill = rows.store()
    checks = []
    original = rule.state_budget().new_key_reason
    def admission(account):
        checks.append(account.name)
        return original(account)
    monkeypatch.setattr(rule.state_budget(), "new_key_reason", admission)
    statements = []
    spill.db.set_trace_callback(statements.append)
    rule.consume([failure(n, account="service", offset=n*30) for n in range(100)])
    assert len(checks) <= 4
    assert sum("PRAGMA max_page_count=" in statement for statement in statements) <= 2
    assert sum("PRAGMA page_count" in statement for statement in statements) <= 6
    rule.release_state()


def test_authentication_state_reclaims_optional_citations_before_refusing_records(tmp_path, monkeypatch):
    from tests.test_windows_c_round4 import dns
    from tests.test_windows_c_round5 import _feed, _native_sweep
    _, sweep = _native_sweep(tmp_path, monkeypatch)
    rule = WindowsBruteForce()
    rule.budget, rule.spill_dir = sweep.budget, tmp_path
    rule.consume([failure(99999, account="warmup", offset=0)])
    pairs = [dns(n, f"priority{n}.c2.test", pad=3500) for n in range(18)]
    _feed(sweep, pairs, monkeypatch)
    stage = sweep._event_stage()
    assert stage.db.execute("SELECT COUNT(*) FROM raw").fetchone()[0] == 18
    for start in range(0, 2000, 50):
        rule.consume([failure(n, account=f"unique{n}", offset=n*601+1000) for n in range(start, start+50)])
        assert not rule.capped
        if stage.db.execute("SELECT COUNT(*) FROM raw").fetchone()[0] == 0:
            break
    else:
        pytest.fail("probe did not reach citation reclamation")
    matches = rule.consume([failure(50000+n, account="late", offset=3000000+n) for n in range(20)])
    assert matches and not rule.capped
    assert sweep.budget.physical_used <= sweep.budget.disk_total
    rule.release_state()
    sweep.close_stage()


@pytest.mark.slow
def test_twenty_one_day_continuous_episode_keeps_logarithmic_revisions():
    repo, rule = _repo(), WindowsBruteForce()
    for start in range(0, 21*2880, 240):
        drive(rule, repo, [failure(n, account="service", offset=n*30) for n in range(start, start+240)])
    for match in rule.finalize():
        publish(repo, rule, match)
    [candidate] = repo.candidates("h1")
    assert candidate["gate_results"]["_revision"]["count"] == 12
    assert len(candidate["event_ids"]) == 40
    assert "3024 non-overlapping qualifying windows" in candidate["claim"]
    assert "60480 records" in candidate["claim"] and "1 episode" in candidate["claim"]
    assert sum(len(json.dumps(row["detail"])) for row in _audits(repo)) < 150_000
    rule.release_state()


def test_quiet_gap_revises_immediately_and_final_replay_is_idempotent():
    repo, rule = _repo(), WindowsBruteForce()
    first = [failure(n, account="service", offset=n) for n in range(20)]
    latest = [failure(100+n, account="service", offset=7*86400+n) for n in range(20)]
    drive(rule, repo, first)
    assert len(repo.candidates("h1")) == 1
    drive(rule, repo, latest)
    [candidate] = repo.candidates("h1")
    assert "2 episodes" in candidate["claim"]
    assert set(candidate["event_ids"]) == {event.id for event in first+latest}
    for match in rule.finalize():
        publish(repo, rule, match)
    count = len(_audits(repo))
    for match in rule.finalize():
        publish(repo, rule, match)
    assert len(_audits(repo)) == count
    rule.release_state()


def test_one_source_account_key_has_one_episode_across_reporting_hosts():
    repo, rule = _repo(), WindowsBruteForce()
    records = [failure(n, account="service", host=f"dc{n%2}.example.test", offset=n*20) for n in range(60)]
    drive(rule, repo, records)
    for match in rule.finalize():
        publish(repo, rule, match)
    [candidate] = repo.candidates("h1")
    assert "3 non-overlapping qualifying windows" in candidate["claim"]
    assert "1 episode" in candidate["claim"] and "1 distinct recorded target accounts" in candidate["claim"]
    assert len(candidate["event_ids"]) == 40
    rule.release_state()


def test_late_earlier_episode_is_replayed_after_an_earlier_finalize():
    repo, rule = _repo(), WindowsBruteForce()
    later = [failure(n, account="service", offset=86400+n) for n in range(20)]
    earlier = [failure(100+n, account="service", offset=n) for n in range(20)]
    drive(rule, repo, later)
    for match in rule.finalize():
        publish(repo, rule, match)
    drive(rule, repo, earlier)
    for match in rule.finalize():
        publish(repo, rule, match)
    [candidate] = repo.candidates("h1")
    assert "2 episodes" in candidate["claim"]
    assert earlier[0].ts.isoformat() in candidate["claim"]
    assert set(candidate["event_ids"]) == {event.id for event in earlier+later}
    rule.release_state()


def test_overlapping_latest_window_updates_witnesses_and_full_totals():
    repo, rule = _repo(), WindowsBruteForce()
    records = [failure(n, account="service", offset=n) for n in range(30)]
    drive(rule, repo, records)
    for match in rule.finalize():
        publish(repo, rule, match)
    [candidate] = repo.candidates("h1")
    assert "30 records" in candidate["claim"] and records[-1].ts.isoformat() in candidate["claim"]
    assert set(candidate["event_ids"]) == {event.id for event in records}
    rule.release_state()


def test_late_overlap_replays_first_window_without_dropping_later_witnesses():
    repo, rule = _repo(), WindowsBruteForce()
    later = [failure(n, account="service", offset=100+n) for n in range(20)]
    earlier = [failure(100+n, account="service", offset=90+n) for n in range(10)]
    drive(rule, repo, later)
    drive(rule, repo, earlier)
    for match in rule.finalize():
        publish(repo, rule, match)
    [candidate] = repo.candidates("h1")
    assert "30 records" in candidate["claim"] and earlier[0].ts.isoformat() in candidate["claim"]
    assert later[-1].ts.isoformat() in candidate["claim"]
    assert set(candidate["event_ids"]) == {event.id for event in earlier+later}
    rule.release_state()


def test_overlapping_qualifying_windows_bridge_episode_boundary():
    repo, rule = _repo(), WindowsBruteForce()
    offsets = [*range(20), *([619]*19), 1219]
    records = [failure(n, account="service", offset=offset) for n, offset in enumerate(offsets)]
    drive(rule, repo, records)
    for match in rule.finalize():
        publish(repo, rule, match)
    [candidate] = repo.candidates("h1")
    assert "1 episode" in candidate["claim"] and "2 non-overlapping qualifying windows" in candidate["claim"]
    assert records[-1].ts.isoformat() in candidate["claim"]
    rule.release_state()
