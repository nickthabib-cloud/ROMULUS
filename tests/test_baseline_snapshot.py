"""Deterministic baseline snapshot planning and frozen membership."""
from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta

from sqlalchemy import insert, select

from romulus.baseline.snapshot import SnapshotPlanner
from romulus.baseline.spec import SPEC_BY_ID
from romulus.store import schema as t
from romulus.store.db import make_engine, migrate
from romulus.store.repo import Repo

START = datetime(2026, 1, 8, tzinfo=UTC)


def _repo(hunt_id="hunt"):
    repo = Repo(make_engine(":memory:"))
    migrate(repo.engine)
    repo.create_hunt(hunt_id, {}, "digest", "test")
    return repo


def _segment(repo, segment_id, start, end, *, origin="lookback", created=START, target="host"):
    repo.save_baseline_segment({
        "id": segment_id, "site": "site", "target": target, "spec_id": "bl.exec_path",
        "spec_version": "1", "key_version": "1", "normalizer": "fixture@1",
        "start": start, "end": end, "bucket": "day", "origin": origin,
        "source_hunt_id": None, "built_by_hunt_id": None, "exclusion_digest": "none",
        "excluded_keys": [], "hunted": int(origin == "hunt"), "events_total": 0,
        "status": "active", "created_at": created,
    }, [], [])


def _freeze(repo, hunt_id="hunt", **overrides):
    values = {
        "hunt_id": hunt_id, "window_start": START, "lookback": timedelta(hours=4),
        "min_live_hours": 2, "site": "site", "targets": ["host"],
        "specs": [SPEC_BY_ID["bl.exec_path"]],
    }
    values.update(overrides)
    return SnapshotPlanner(repo).freeze(**values)


def test_cover_prefers_hunt_then_newest_then_id_without_overlap():
    repo = _repo()
    _segment(repo, "lookback-new", START - timedelta(hours=2), START, created=START + timedelta(hours=2))
    _segment(repo, "hunt-old", START - timedelta(hours=2), START, origin="hunt", created=START)
    _segment(repo, "hunt-z", START - timedelta(hours=4), START - timedelta(hours=2),
             origin="hunt", created=START)
    _segment(repo, "hunt-a", START - timedelta(hours=4), START - timedelta(hours=2),
             origin="hunt", created=START)

    snapshot = _freeze(repo)

    assert snapshot["segment_ids"] == ["hunt-a", "hunt-old"]
    assert snapshot["status"] == "resolved"


def test_gaps_stop_effective_span_and_before_first_record_is_absent():
    repo = _repo()
    _segment(repo, "latest", START - timedelta(hours=1), START)
    _segment(repo, "older", START - timedelta(hours=4), START - timedelta(hours=2))

    snapshot = _freeze(repo, min_live_hours=1)
    coverage = snapshot["coverage"]["host|bl.exec_path"]

    assert coverage["effective_hours"] == 1
    assert coverage["effective_start"] == (START - timedelta(hours=1)).isoformat()
    assert coverage["gaps"] == [{
        "start": (START - timedelta(hours=2)).isoformat(),
        "end": (START - timedelta(hours=1)).isoformat(),
        "reason": "no complete segment",
    }]
    assert coverage["status"] == "shortened"

    absent_repo = _repo("absent")
    _segment(absent_repo, "only", START - timedelta(hours=2), START)
    absent = _freeze(absent_repo, "absent", min_live_hours=2)
    absent_coverage = absent["coverage"]["host|bl.exec_path"]
    assert absent_coverage["effective_hours"] == 2
    assert absent_coverage["status"] == "shortened"
    assert absent_coverage["absent_before"] == (START - timedelta(hours=2)).isoformat()


def test_min_live_hours_and_resume_write_once():
    repo = _repo()
    _segment(repo, "one", START - timedelta(hours=1), START)
    first = _freeze(repo, min_live_hours=2)
    _segment(repo, "better", START - timedelta(hours=4), START, origin="hunt",
             created=START + timedelta(days=1))

    resumed = _freeze(repo, min_live_hours=2)

    assert first == resumed
    assert resumed["status"] == "unresolved"
    with repo.engine.connect() as connection:
        members = connection.execute(select(t.baseline_snapshot_segment)).mappings().all()
    assert [row["segment_id"] for row in members] == ["one"]


def test_twin_plans_have_identical_digest():
    outputs = []
    for hunt_id in ("hunt-a", "hunt-b"):
        repo = _repo(hunt_id)
        _segment(repo, "segment", START - timedelta(hours=4), START)
        outputs.append(_freeze(repo, hunt_id)["digest"])
    assert outputs[0] == outputs[1]


def test_planner_filters_a_store_of_ten_thousand_segments_in_bounded_time():
    repo = _repo()
    rows = []
    for index in range(10_000):
        start = START - timedelta(hours=index + 1)
        rows.append({
            "id": f"segment-{index:05d}", "site": "site", "target": "host",
            "spec_id": "bl.exec_path", "spec_version": "1", "key_version": "1",
            "normalizer": "fixture@1", "start": start, "end": start + timedelta(hours=1),
            "bucket": "day", "origin": "lookback", "source_hunt_id": None,
            "built_by_hunt_id": None, "exclusion_digest": "none", "excluded_keys": [],
            "hunted": 0, "events_total": 0, "rows_digest": "0:0:0", "status": "active",
            "created_at": START,
        })
    with repo.engine.begin() as connection:
        connection.execute(insert(t.baseline_segment), rows)

    before = time.perf_counter()
    snapshot = _freeze(repo, lookback=timedelta(hours=168), min_live_hours=48)
    elapsed = time.perf_counter() - before

    assert snapshot["status"] == "resolved"
    assert len(snapshot["segment_ids"]) == 168
    assert elapsed < 5
