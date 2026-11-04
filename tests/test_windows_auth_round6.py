"""Authentication checkpoints keep useful evidence with bounded publication and query work."""
import json
import sqlite3

from romulus.detect.bounded import StateExhausted
from romulus.detect.windows_auth_events import WindowsBruteForce, WindowsPasswordSpray
from tests.test_candidate_revision import _audits
from tests.test_sweep import _repo
from tests.test_windows_auth_round5 import drive, publish
from tests.test_windows_c_burst_review import failure


def test_separate_episodes_after_eight_publish_at_episode_doublings_and_finalize():
    repo, rule = _repo(), WindowsBruteForce()
    first, latest = [], []
    publications = []
    for episode in range(33):
        events = [failure(episode*25+n, account="service", offset=episode*3600+n*2) for n in range(25)]
        if not first:
            first = events[:20]
        latest = events[-20:]
        matches = rule.consume(events)
        publications.append(len(matches))
        for match in matches:
            publish(repo, rule, match)
    assert publications[:8] == [1]*8
    assert [index+1 for index, count in enumerate(publications[8:], 8) if count] == [16, 32]
    for match in rule.finalize():
        publish(repo, rule, match)
    [candidate] = repo.candidates("h1")
    assert "33 episodes" in candidate["claim"] and "825 records" in candidate["claim"]
    assert set(candidate["event_ids"]) == {event.id for event in first+latest}
    assert len(_audits(repo)) == 10
    assert sum(len(json.dumps(row["detail"])) for row in _audits(repo)) < 100_000
    assert not list(rule.finalize())
    rule.release_state()


def test_native_spray_latest_witness_query_stops_after_twenty_distinct_values(monkeypatch):
    repo, rule = _repo(), WindowsPasswordSpray()
    events = [failure(n, account=f"account{n%300}", offset=n/100) for n in range(800)]
    drive(rule, repo, events)
    latest = failure(800, account="account200", offset=8)
    query_steps = []
    original = rule.rows.witnesses

    def measured(*args, **kwargs):
        count = 0

        def step():
            nonlocal count
            count += 100
            return 0

        rule.rows.store().db.set_progress_handler(step, 100)
        try:
            result = original(*args, **kwargs)
            query_steps.append(count)
            return result
        finally:
            rule.rows.store().db.set_progress_handler(None, 0)

    monkeypatch.setattr(rule.rows, "witnesses", measured)
    drive(rule, repo, [latest])
    assert query_steps and max(query_steps) < 5000
    for match in rule.finalize():
        publish(repo, rule, match)
    [source] = [row for row in repo.candidates("h1") if "for IP " in row["claim"]]
    assert set(source["event_ids"]) == {e.id for e in events[:20]+events[-19:]+[latest]}
    rule.release_state()


def test_auth_record_survives_multiple_progressive_full_retries(monkeypatch):
    rule = WindowsBruteForce()
    rows = rule.rows
    spill = rows.store()
    original = rows._write
    failures = []

    def write(statement, batch, **kwargs):
        if statement.startswith("INSERT INTO windows_refs") and len(failures) < 2:
            failures.append(1)
            spill.db.rollback()
            rows._symbol_cache.clear()
            rows._symbol_bytes = 0
            try:
                raise sqlite3.OperationalError("database or disk is full")
            except sqlite3.OperationalError as cause:
                raise StateExhausted("injected physical FULL") from cause
        return original(statement, batch, **kwargs)

    monkeypatch.setattr(rows, "_write", write)
    steps = []
    monkeypatch.setattr(rule.state_budget(), "reclaim_citations_step", lambda: steps.append(1) or True)
    events = [failure(n, account="service") for n in range(20)]
    matches = rule.consume(events)
    assert matches and {event.id for event in matches[0].events} == {event.id for event in events}
    assert len(steps) == 2 and not rule.capped
    rule.release_state()


def test_auth_schema_survives_multiple_progressive_full_retries(monkeypatch):
    rule = WindowsBruteForce()
    rows = rule.rows
    original = rows._schema
    attempts, steps = [], []

    def interrupted(spill):
        attempts.append(1)
        if len(attempts) <= 2:
            spill.db.execute("SAVEPOINT auth_schema")
            spill.db.execute("CREATE TABLE windows_symbols(id INTEGER PRIMARY KEY,value TEXT UNIQUE)")
            raise sqlite3.OperationalError("database or disk is full")
        return original(spill)

    monkeypatch.setattr(rows, "_schema", interrupted)
    monkeypatch.setattr(rule.state_budget(), "reclaim_citations_step", lambda: steps.append(1) or True)
    events = [failure(n, account="service") for n in range(20)]
    matches = rule.consume(events)
    assert matches and {event.id for event in matches[0].events} == {event.id for event in events}
    assert len(attempts) == 3 and len(steps) == 2 and not rule.capped
    rule.release_state()
