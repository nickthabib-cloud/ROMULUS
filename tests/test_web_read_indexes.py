"""The workspace's per-page reads seek indexes: lane counts by provenance, a hunt's remote model calls, and one rule's
findings in importance order, including a rare rule in a large hunt. Plans are shown before and after the migration."""
import json
import sqlite3

import pytest
from alembic import command
from sqlalchemy import event

from romulus.store import schema as t
from romulus.store.db import make_engine
from romulus.store.repo import Repo
from romulus.web.finding_order import finding_page
from tests.test_local_content_migration import config

NAMES = {"ix_candidate_hunt_provenance_lane", "ix_candidate_rule_order", "ix_model_call_hunt_egress"}
LANE_COUNTS = "SELECT provenance, lane, count(*) FROM candidate WHERE hunt_id = ? GROUP BY provenance, lane"
REMOTE_CALL = "SELECT id FROM model_call WHERE hunt_id = ? AND egress = 'remote' LIMIT 1"
LANES = ("urgent", "high", "lead", "context", "suppressed")


def _plan(connection, sql, params=("h1",)):
    return " | ".join(str(row[-1]) for row in connection.exec_driver_sql("EXPLAIN QUERY PLAN " + sql, params))


def _store(path, count, rare_every):
    """A migrated store holding hunt h1 with `count` findings; every `rare_every`-th has the rare rule."""
    engine = make_engine(path)
    with engine.begin() as connection:
        command.upgrade(config(connection), "0041")
    Repo(engine).create_hunt("h1", {}, "d", "test")
    raw = sqlite3.connect(path)
    empty = json.dumps([])
    raw.executemany(
        "INSERT INTO candidate (id, hunt_id, rule_id, rule_version, claim, claim_type, event_ids, predicate_fields,"
        " entities, ts, severity, confidence, lane, priority, priority_reasons, gate_results, benign_alternatives,"
        " next_checks, group_key, provenance, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        ((f"c{i:06}", "h1", "rule.rare" if i % rare_every == 0 else f"rule.common{i % 7}", "1", "claim",
          "observed_action", empty, empty, empty, f"2030-01-01 {i % 24:02}:00:00.000000", "high", "high",
          LANES[i % 5], float(i % 100), empty, "{}", empty, empty, f"g{i}",
          "agent" if i % 11 == 0 else "deterministic", "2030-01-01 00:00:00.000000") for i in range(count)))
    raw.commit()
    raw.close()
    return engine


def test_plans_before_and_after_the_migration_and_round_trip(tmp_path):
    engine = _store(tmp_path / "plans.sqlite", 2_000, 50)
    with engine.connect() as connection:
        before = {"lanes": _plan(connection, LANE_COUNTS), "calls": _plan(connection, REMOTE_CALL)}
    # before: lane counts read the table and sort the groups; the remote-call lookup scans every hunt's calls
    assert "ix_candidate_hunt_provenance_lane" not in before["lanes"] and "TEMP B-TREE" in before["lanes"]
    assert "SCAN model_call" in before["calls"]
    with engine.begin() as connection:
        command.upgrade(config(connection), "0042")
    with engine.connect() as connection:
        after = {"lanes": _plan(connection, LANE_COUNTS), "calls": _plan(connection, REMOTE_CALL)}
    assert "USING COVERING INDEX ix_candidate_hunt_provenance_lane (hunt_id=?)" in after["lanes"]
    assert "TEMP B-TREE" not in after["lanes"]
    assert "USING INDEX ix_model_call_hunt_egress (hunt_id=? AND egress=?)" in after["calls"]
    for version in ("0041", "0042"):
        with engine.begin() as connection:
            (command.downgrade if version == "0041" else command.upgrade)(config(connection), version)
            indexes = set(connection.exec_driver_sql("SELECT name FROM sqlite_master WHERE type='index'").scalars())
            assert (NAMES <= indexes) if version == "0042" else not NAMES & indexes
            assert connection.exec_driver_sql("PRAGMA quick_check").scalar() == "ok"
    engine.dispose()


def _rule_pages(repo):
    """Every page of the rare rule's findings, with the statements each page ran."""
    statements, seen, cursor = [], [], ""
    listener = lambda _c, _x, sql, params, *_: statements.append((sql, params))
    event.listen(repo.engine, "before_cursor_execute", listener)
    try:
        while True:
            rows, _, cursor = finding_page(repo, "h1", after=cursor,
                                           predicates=(t.candidate.c.rule_id == "rule.rare",))
            seen += [row["id"] for row in rows]
            if not cursor:
                break
    finally:
        event.remove(repo.engine, "before_cursor_execute", listener)
    return seen, statements


def _steps(path, statements):
    """SQLite virtual-machine steps the statements take: a measure of the rows each one visits."""
    raw = sqlite3.connect(path)
    steps = 0

    def tick():
        nonlocal steps
        steps += 1
    raw.set_progress_handler(tick, 100)
    for sql, params in statements:
        raw.execute(sql, params).fetchall()
    raw.close()
    return steps * 100


@pytest.mark.slow
def test_a_rare_rule_in_a_large_hunt_seeks_its_own_index(tmp_path):
    path = tmp_path / "large.sqlite"
    engine = _store(path, 100_000, 1_000)
    repo = Repo(engine)
    seen_before, before = _rule_pages(repo)
    with engine.connect() as connection:
        plans_before = [_plan(connection, sql, params) for sql, params in before]
    # without the rule index a page walks the hunt's order index and tests every row for the rule
    assert all("ix_candidate_rule_order" not in plan for plan in plans_before)
    cost_before = _steps(path, before)
    with engine.begin() as connection:
        command.upgrade(config(connection), "0042")
    seen_after, after = _rule_pages(repo)
    assert seen_after == seen_before and len(seen_after) == 100
    with engine.connect() as connection:
        plans_after = [_plan(connection, sql, params) for sql, params in after]
    assert plans_after and all("ix_candidate_rule_order (hunt_id=? AND rule_id=?" in plan
                                for plan in plans_after)
    assert all("TEMP B-TREE" not in plan for plan in plans_after)
    # the same pages now visit about the rare rule's rows, not the hunt's
    assert _steps(path, after) * 20 < cost_before
    engine.dispose()
