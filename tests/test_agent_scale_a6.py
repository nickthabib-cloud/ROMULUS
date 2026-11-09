"""Graph projections and indexed overlap preserve results at bounded read sizes."""
import hashlib
import json
import random
import time

import pytest
from sqlalchemy import event, func, select

from romulus.report.incidents import build_incident_graph
from romulus.store import schema as t
from romulus.store.repo import ID_CHUNK
from tests.test_agent_store_r2 import NOW, _candidate, _repo
from tests.test_incident_grouping import _finding, _link


def _insert(repo, rows):
    with repo.engine.begin() as c:
        c.execute(t.candidate.insert(), [r | {"created_at": NOW} for r in rows])


def test_graph_bulk_projection_preserves_context_attack_fallback_and_agent(monkeypatch):
    repo = _repo()
    _insert(repo, [
        _candidate("anchor", events=["a", "shared"]) | {"context_event_ids": ["shared"]},
        _candidate("subject", events=["s", "shared"]) | {
            "context_event_ids": ["shared"], "gate_results": {"_attack": ["T1003"]}},
        _candidate("fallback", events=[]),
        _candidate("agent", provenance="agent", events=["s", "shared"]),
    ])
    links = [_link("context", "anchor", ["shared"]), _link("cited", "subject", ["fallback-event"])]
    monkeypatch.setattr(repo, "expansion_links", lambda _: links)
    monkeypatch.setattr(repo, "candidate", lambda _: pytest.fail("full candidate was materialized"))
    findings = [_finding(cid, []) for cid in ("anchor", "subject", "fallback", "agent")]
    findings[2]["citations"] = [{"event_id": "fallback-event"}]
    graph = build_incident_graph(repo, "h1", findings)
    assert next(link for link in graph["links"] if link["id"] == "context")["target_finding_ids"] == []
    assert next(link for link in graph["links"] if link["id"] == "cited")["target_finding_ids"] == ["fallback"]
    assert sorted(tuple(i["finding_ids"]) for i in graph["incidents"]) == [("anchor",), ("fallback", "subject")]
    incident = next(i for i in graph["incidents"] if "subject" in i["finding_ids"])
    assert "T1003" in str(incident)
    assert all("agent" not in i["finding_ids"] for i in graph["incidents"])
    assert hashlib.sha256(json.dumps(graph, sort_keys=True, separators=(",", ":")).encode()).hexdigest() == (
        "d5cb44a64a067607b94281deab4375e505c4e141a118a76b06a685764af31d8a")


def test_graph_twenty_thousand_findings_reads_zero_full_candidates(monkeypatch):
    repo = _repo()
    for start in range(0, 20_000, 500):
        _insert(repo, [_candidate(f"f{i:05}") for i in range(start, start + 500)])
    monkeypatch.setattr(repo, "candidate", lambda _: pytest.fail("full candidate read"))
    monkeypatch.setattr(repo, "candidates_by_ids", lambda *a, **k: pytest.fail("full candidates read"))
    statements = []

    def observed(c, cursor, statement, params, context, many):
        if statement.startswith("SELECT") and "FROM candidate" in statement:
            statements.append((statement, params))
            assert "candidate.claim" not in statement and "candidate.predicate_fields" not in statement
            assert len(params) <= ID_CHUNK + 1  # JSON path plus id chunk.

    event.listen(repo.engine, "before_cursor_execute", observed)
    graph = build_incident_graph(repo, "h1", [_finding(f"f{i:05}", []) for i in range(20_000)])
    event.remove(repo.engine, "before_cursor_execute", observed)
    assert len(graph["incidents"]) == 20_000
    assert len(statements) == (20_000 + ID_CHUNK - 1) // ID_CHUNK


def _legacy(repo, cites, lanes, size=500):
    after = ""
    while True:
        events = func.json_each(t.candidate.c.event_ids).table_valued("value")
        overlap = select(1).select_from(events).where(events.c.value.in_(cites)).exists()
        query = select(t.candidate).where(t.candidate.c.hunt_id == "h1", t.candidate.c.lane.in_(lanes),
                                         t.candidate.c.id > after, overlap).order_by(t.candidate.c.id).limit(size)
        with repo.engine.connect() as c:
            rows = [dict(row) for row in c.execute(query).mappings()]
        if not rows:
            return
        yield rows
        after = rows[-1]["id"]
        if len(rows) < size:
            return


def test_random_index_lookup_matches_json_each_order_and_cite_ownership():
    rng = random.Random(738)
    repo = _repo()
    lanes = ["urgent", "high", "lead", "context", "suppressed"]
    _insert(repo, [_candidate(f"f{i:04}", lane=rng.choice(lanes), events=rng.sample(
        [f"e{n}" for n in range(70)], rng.randrange(0, 8))) for i in range(350)])
    for _ in range(35):
        cites = rng.sample([f"e{n}" for n in range(80)], rng.randrange(1, 20))
        selected_lanes = rng.sample(lanes, rng.randrange(1, 6))
        expected = [row["id"] for page in _legacy(repo, cites, selected_lanes, 17) for row in page]
        actual = [row["id"] for page in repo.candidate_duplicate_batches("h1", cites, selected_lanes, 17)
                  for row in page]
        assert actual == expected
    cited = [f"e{n}" for n in range(ID_CHUNK + 15)]
    assert [r["id"] for p in repo.candidate_duplicate_batches("h1", cited, lanes, 23) for r in p] == [
        r["id"] for p in _legacy(repo, cited, lanes, 23) for r in p]
    assert repo.agent_alias_target_hunts("E", "e1", hunt_id="h1") == ["h1"]
    assert repo.agent_alias_target_hunts("E", "missing", hunt_id="h1") == []


def test_hundred_thousand_overlapping_candidates_remain_bounded_and_equal():
    repo = _repo()
    for start in range(0, 100_000, 500):
        _insert(repo, [_candidate(f"f{i:06}", events=["common"]) for i in range(start, start + 500)])
    def measure(batches):
        started = time.perf_counter()
        count = peak = 0
        for rows in batches:
            peak = max(peak, len(rows))
            count += len(rows)
            assert all("missing" not in row["event_ids"] for row in rows)
        return count, peak, time.perf_counter() - started
    before = measure(_legacy(repo, ["common", "missing"], ["high", "lead"]))
    after = measure(repo.candidate_duplicate_batches("h1", ["common", "missing"], ["high", "lead"]))
    assert before[:2] == after[:2] == (100_000, 500)
    print(f"100k overlap: json_each={before[2]:.6f}s index={after[2]:.6f}s peak={after[1]} count={after[0]}")
