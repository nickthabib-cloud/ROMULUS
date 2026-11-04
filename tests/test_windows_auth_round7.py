"""Repeated distinct values and quiet gaps retain useful authentication publication."""
import json

import pytest

from romulus.detect.bounded import StateExhausted
from romulus.detect.windows_auth_events import WindowsBruteForce, WindowsPasswordSpray
from tests.test_sweep import _repo
from tests.test_windows_auth_round5 import drive, publish
from tests.test_windows_c_burst_review import failure


def test_refused_replay_state_cannot_replace_a_newer_published_window(monkeypatch):
    repo, rule = _repo(), WindowsBruteForce()
    try:
        first = [failure(n, account="service", offset=n) for n in range(25)]
        later = [failure(100+n, account="service", offset=3600+n) for n in range(25)]
        drive(rule, repo, first)
        drive(rule, repo, later)
        [before] = repo.candidates("h1")
        write = rule.rows._write
        refused = []
        def fail_later_replay(statement, rows):
            if statement == "INSERT OR REPLACE INTO windows_marks VALUES(?,?)":
                for key, value in rows:
                    if key.startswith("replay:") and json.loads(value)["latest_end"] > first[-1].ts.timestamp():
                        refused.append(key)
                        raise StateExhausted("injected physical replay-state write refusal")
            return write(statement, rows)
        monkeypatch.setattr(rule.rows, "_write", fail_later_replay)
        for match in rule.finalize():
            publish(repo, rule, match)
        assert refused
        [after] = repo.candidates("h1")
        assert after["claim"] == before["claim"]
        assert after["event_ids"] == before["event_ids"]
    finally:
        rule.release_state()


def test_negative_scan_hints_do_not_spend_disk_capacity_on_one_off_keys():
    rule = WindowsPasswordSpray()
    try:
        records = [failure(n, source=f"198.51.100.{n+1}", account="stale", offset=n)
                   for n in range(192)]
        assert not rule.consume(records)
        assert not list(rule.rows.markers("checked:"))
        assert len(rule._checked) <= 128
        assert all(len(key) <= 512 for key in rule._checked)
        assert not list(rule.finalize())
    finally:
        rule.release_state()


def test_late_value_after_negative_hint_eviction_still_publishes_immediately(monkeypatch):
    results = []
    for full_scan in (False, True):
        rule = WindowsPasswordSpray()
        if full_scan:
            monkeypatch.setattr(rule.rows, "prior_value", lambda *args, **kwargs: False)
        try:
            first = [failure(n, account=f"u{n}", offset=1000+n/100) for n in range(19)]
            assert not rule.consume(first)
            # Unrelated source/reporter keys evict the initial key's optional scan hint.
            churn = [failure(100+n, account="churn", offset=2000+n, host=f"host{n}",
                             source=f"10.2.0.{n+1}") for n in range(160)]
            assert not rule.consume(churn)
            late = failure(1000, account="newlate", offset=999)
            assert not rule.consume([late])
            repeated = failure(1001, account="u0", offset=1001)
            immediate = rule.consume([repeated])
            assert len(immediate) == 2
            assert all(late.id in {event.id for event in match.events} for match in immediate)
            final = list(rule.finalize())
            results.append([[(match.group_key, match.claim, match.proposed_lane, match.ts,
                              [event.id for event in match.events], match.predicate)
                             for match in matches] for matches in (immediate, final)])
        finally:
            rule.release_state()
    assert results[0] == results[1]


@pytest.mark.parametrize("batch_size", [1, 50])
def test_unqualified_repeated_suffix_does_not_rescan_a_previously_qualified_key(monkeypatch, batch_size):
    repo, rule = _repo(), WindowsPasswordSpray()
    try:
        drive(rule, repo, [failure(n, account=f"user{n}", offset=n) for n in range(25)])
        drive(rule, repo, [failure(100, account="stale", offset=1000)])
        calls = []
        original = rule.rows.witnesses
        def witnesses(*args, **kwargs):
            calls.append(args[0])
            return original(*args, **kwargs)
        monkeypatch.setattr(rule.rows, "witnesses", witnesses)
        repeated = [failure(101+n, account="stale", offset=1001+n/20) for n in range(200)]
        for start in range(0, len(repeated), batch_size):
            drive(rule, repo, repeated[start:start+batch_size])
        assert len(calls) <= 2
        newcomers = [failure(1000+n, account=f"new{n}", offset=1020+n) for n in range(19)]
        matches = rule.consume(newcomers)
        assert matches and all(match.proposed_lane == "lead" for match in matches)
        for match in matches:
            publish(repo, rule, match)
        for match in rule.finalize():
            publish(repo, rule, match)
        rows = repo.candidates("h1")
        assert rows and all("2 episodes" in row["claim"] for row in rows)
        assert all({event.id for event in newcomers} <= set(row["event_ids"]) for row in rows)
    finally:
        rule.release_state()


def test_subthreshold_records_between_episodes_do_not_count_as_a_quiet_day():
    rule = WindowsBruteForce()
    try:
        for episode in range(9):
            rule.consume([failure(25*episode+n, account="service", offset=episode*3600+n*2)
                          for n in range(25)])
        # The key stays active hourly, although these isolated failures do not qualify.
        for hour in range(9, 40):
            assert not rule.consume([failure(1000+hour, account="service", offset=hour*3600)])
        assert not rule.consume([failure(2000+n, account="service", offset=40*3600+n*2) for n in range(25)])
    finally:
        rule.release_state()


def test_distinct_skip_matches_full_scans_with_late_values_and_equal_timestamps(monkeypatch):
    initial = [failure(n, account=f"initial{n}", offset=n) for n in range(25)]
    suffix = [failure(100+n, account="stale", offset=1000+n/20) for n in range(80)]
    # Late insertions can increase the last evaluated window even if the next value repeats.
    late = [failure(300+n, account=f"late{n}", offset=1001+n/100) for n in range(19)]
    same_time = [failure(500+n, account=f"same{n}", offset=1010, host=f"host{n%2}") for n in range(22)]
    batches = [initial, suffix, late, [failure(600, account="stale", offset=1005)], same_time, suffix[:2]]
    results = []
    for full_scan in (False, True):
        repo, rule = _repo(), WindowsPasswordSpray()
        if full_scan:
            monkeypatch.setattr(rule.rows, "prior_value", lambda *args, **kwargs: False)
        emissions = []
        try:
            for batch in batches:
                matches = rule.consume(batch)
                emissions.extend((m.group_key, m.claim, [e.id for e in m.events]) for m in matches)
                for match in matches:
                    publish(repo, rule, match)
            for match in rule.finalize():
                publish(repo, rule, match)
            fields = ("id", "group_key", "claim", "lane", "event_ids", "predicate_fields", "gate_results")
            candidates = [{key: row[key] for key in fields} for row in repo.candidates("h1")]
            for row in candidates:
                for summary in row["gate_results"].get("_revision", {}).get("summaries", []):
                    summary.pop("at", None)  # Wall-clock audit time is not a detector outcome.
            results.append((emissions, candidates))
        finally:
            rule.release_state()
    assert results[0] == results[1]


@pytest.mark.parametrize("gap", [86399, 86400, 7*86400])
def test_ninth_prior_episode_rearms_only_after_a_full_day_of_quiet(gap):
    repo, rule = _repo(), WindowsBruteForce()
    try:
        for episode in range(9):
            drive(rule, repo, [failure(25*episode+n, account="service", offset=episode*3600+n*2)
                               for n in range(25)])
        late = [failure(1000+n, account="service", offset=8*3600+48+gap+n*2) for n in range(25)]
        matches = rule.consume(late)
        assert len(matches) == int(gap >= 86400)
        for match in matches:
            assert "10 episodes" in match.claim
            publish(repo, rule, match)
        # Another close episode remains on the ordinary doubling schedule.
        close = [failure(2000+n, account="service", offset=8*3600+48+gap+3600+n*2) for n in range(25)]
        assert not rule.consume(close)
        for match in rule.finalize():
            publish(repo, rule, match)
        [candidate] = repo.candidates("h1")
        assert "11 episodes" in candidate["claim"]
        assert {event.id for event in close[-20:]} <= set(candidate["event_ids"])
    finally:
        rule.release_state()
