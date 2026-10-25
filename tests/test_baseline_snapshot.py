"""Deterministic baseline snapshot planning and frozen membership."""
from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta

from sqlalchemy import insert, select

from romulus.baseline.lookback import HistoryGap, LookbackBudget, LookbackWriter
from romulus.baseline.snapshot import SnapshotPlanner
from romulus.baseline.spec import SPEC_BY_ID
from romulus.evidence.typed import fv
from romulus.store import schema as t
from romulus.store.db import make_engine, migrate
from romulus.store.repo import Repo
from tests.test_baseline_lookback import START as LOOKBACK_START
from tests.test_baseline_lookback import FakeHistory, _event

START = datetime(2026, 1, 8, tzinfo=UTC)


def _lookback_repo(hunt_id="h1"):
    repo = Repo(make_engine(":memory:"))
    migrate(repo.engine)
    repo.create_hunt(hunt_id, {}, "digest", "test")
    return repo


def _repo(hunt_id="hunt"):
    repo = Repo(make_engine(":memory:"))
    migrate(repo.engine)
    repo.create_hunt(hunt_id, {}, "digest", "test")
    return repo


def _segment(repo, segment_id, start, end, *, origin="lookback", created=START, target="host", events=1):
    repo.save_baseline_segment({
        "id": segment_id, "site": "site", "target": target, "spec_id": "bl.exec_path",
        "spec_version": "1", "key_version": "1", "normalizer": "fixture@1",
        "start": start, "end": end, "bucket": "day", "origin": origin,
        "source_hunt_id": None, "built_by_hunt_id": None, "exclusion_digest": "none",
        "excluded_keys": [], "hunted": int(origin == "hunt"), "events_total": events,
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


def test_cover_claims_the_in_span_hours_of_a_segment_straddling_history_start():
    repo = _repo()
    _segment(repo, "straddling", START - timedelta(hours=6), START - timedelta(hours=2), origin="hunt")
    _segment(repo, "latest", START - timedelta(hours=2), START, origin="hunt")

    snapshot = _freeze(repo)
    coverage = snapshot["coverage"]["host|bl.exec_path"]

    assert snapshot["segment_ids"] == ["latest", "straddling"]
    assert coverage["gaps"] == []
    assert coverage["effective_start"] == (START - timedelta(hours=4)).isoformat()
    assert coverage["effective_hours"] == 4
    assert coverage["status"] == "resolved"


def test_gaps_stop_effective_span_and_carry_their_reason():
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
        "state": "missing", "reason": "no complete segment",
    }]
    assert coverage["absent_before"] is None
    assert coverage["status"] == "gap_shortened"
    assert snapshot["status"] == "gap_shortened"


def test_missing_segments_before_the_first_one_are_gaps_never_absence():
    repo = _repo()
    _segment(repo, "only", START - timedelta(hours=2), START)
    snapshot = _freeze(repo, min_live_hours=2)
    coverage = snapshot["coverage"]["host|bl.exec_path"]
    assert coverage["absent_before"] is None
    assert coverage["gaps"] == [{
        "start": (START - timedelta(hours=4)).isoformat(),
        "end": (START - timedelta(hours=2)).isoformat(),
        "state": "missing", "reason": "no complete segment",
    }]
    assert coverage["effective_hours"] == 2 and coverage["status"] == "gap_shortened"


def test_complete_empty_segments_are_the_evidence_of_absence():
    repo = _repo()
    _segment(repo, "empty", START - timedelta(hours=4), START - timedelta(hours=2), events=0)
    _segment(repo, "records", START - timedelta(hours=2), START)
    snapshot = _freeze(repo, min_live_hours=2)
    coverage = snapshot["coverage"]["host|bl.exec_path"]
    assert coverage["gaps"] == []
    assert coverage["absent_before"] == (START - timedelta(hours=2)).isoformat()
    assert coverage["effective_start"] == (START - timedelta(hours=2)).isoformat()
    # Shortened only by evidenced absence, never by a gap.
    assert coverage["effective_hours"] == 2 and coverage["status"] == "shortened"
    assert snapshot["status"] == "shortened"


def test_complete_span_without_records_is_absent_never_resolved():
    repo = _repo()
    _segment(repo, "empty", START - timedelta(hours=4), START, events=0)
    snapshot = _freeze(repo, min_live_hours=2)
    coverage = snapshot["coverage"]["host|bl.exec_path"]
    assert coverage["status"] == "absent" and coverage["effective_hours"] == 0
    assert coverage["absent_before"] == START.isoformat()
    assert snapshot["status"] == "unresolved"


def test_history_gap_reasons_reach_the_snapshot():
    repo = _repo()
    _segment(repo, "latest", START - timedelta(hours=2), START)
    gaps = [
        HistoryGap("host", START - timedelta(hours=4), START - timedelta(hours=3), "omitted_budget",
                   "lookback query or wall-clock budget exhausted", ("bl.exec_path",)),
        HistoryGap("host", START - timedelta(hours=3), START - timedelta(hours=2), "failed",
                   "shard failure", ("bl.exec_path",)),
        HistoryGap("other", START - timedelta(hours=3), START - timedelta(hours=2), "failed",
                   "elsewhere", ("bl.exec_path",)),
    ]
    snapshot = _freeze(repo, min_live_hours=2, history_gaps=gaps)
    assert snapshot["coverage"]["host|bl.exec_path"]["gaps"] == [
        {"start": (START - timedelta(hours=4)).isoformat(), "end": (START - timedelta(hours=3)).isoformat(),
         "state": "omitted_budget", "reason": "lookback query or wall-clock budget exhausted"},
        {"start": (START - timedelta(hours=3)).isoformat(), "end": (START - timedelta(hours=2)).isoformat(),
         "state": "failed", "reason": "shard failure"},
    ]


def test_scope_series_from_two_specs_over_one_event_has_one_row_per_hour():
    specs = [SPEC_BY_ID["bl.exec_path"], SPEC_BY_ID["bl.cmd_shape"]]
    event = _event(1, LOOKBACK_START - timedelta(minutes=30))
    event.fields["process.argv"] = fv(["ls", "-l"], "fixture")
    repo = _lookback_repo("h")
    result = LookbackWriter(
        repo, FakeHistory([event]), site="site", specs=specs, normalizer="fixture@1",
        budget=LookbackBudget(queries=10, records=10, seconds=60), now=lambda: LOOKBACK_START,
    ).fill(hunt_id="h", targets=["t"], start=LOOKBACK_START - timedelta(hours=1), end=LOOKBACK_START)
    assert result.gaps == ()
    SnapshotPlanner(repo).freeze(
        hunt_id="h", window_start=LOOKBACK_START, lookback=timedelta(hours=1), min_live_hours=1,
        site="site", targets=["t"], specs=specs,
    )
    for spec in specs:
        rows = repo.baseline_scope_series("host", "host:web01", "h", spec.id)
        assert [(row["hour"], row["events"]) for row in rows] == [(LOOKBACK_START - timedelta(hours=1), 1)]
        assert repo.baseline_peer_scopes("host", "h", spec.id) == 1


def test_budget_truncated_lookback_is_gaps_and_empty_source_is_absent():
    spec = SPEC_BY_ID["bl.exec_path"]
    hours = 72
    events = [_event(index, LOOKBACK_START - timedelta(hours=index, minutes=30)) for index in range(hours)]
    repo = _lookback_repo()
    result = LookbackWriter(
        repo, FakeHistory(events), site="site", specs=[spec], normalizer="fixture@1",
        budget=LookbackBudget(queries=100, records=10**6, seconds=600), now=lambda: LOOKBACK_START,
    ).fill(hunt_id="h1", targets=["host-index"], start=LOOKBACK_START - timedelta(hours=hours),
           end=LOOKBACK_START)
    assert result.complete == 50
    snapshot = SnapshotPlanner(repo).freeze(
        hunt_id="h1", window_start=LOOKBACK_START, lookback=timedelta(hours=hours), min_live_hours=48,
        site="site", targets=["host-index"], specs=[spec], history_gaps=result.gaps,
    )
    coverage = snapshot["coverage"]["host-index|bl.exec_path"]
    assert coverage["absent_before"] is None
    assert coverage["effective_hours"] == 50 and coverage["status"] == "gap_shortened"
    assert [(gap["state"], gap["start"], gap["end"]) for gap in coverage["gaps"]] == [(
        "omitted_budget", (LOOKBACK_START - timedelta(hours=hours)).isoformat(),
        (LOOKBACK_START - timedelta(hours=50)).isoformat(),
    )]

    empty = _lookback_repo("h2")
    LookbackWriter(
        empty, FakeHistory([]), site="site", specs=[spec], normalizer="fixture@1",
        budget=LookbackBudget(queries=1000, records=10**6, seconds=600), now=lambda: LOOKBACK_START,
    ).fill(hunt_id="h2", targets=["host-index"], start=LOOKBACK_START - timedelta(hours=hours),
           end=LOOKBACK_START)
    nothing = SnapshotPlanner(empty).freeze(
        hunt_id="h2", window_start=LOOKBACK_START, lookback=timedelta(hours=hours), min_live_hours=48,
        site="site", targets=["host-index"], specs=[spec],
    )
    assert nothing["status"] == "unresolved"
    assert nothing["coverage"]["host-index|bl.exec_path"]["status"] == "absent"


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
    for index, hunt_id in enumerate(("hunt-a", "hunt-b")):
        repo = _repo(hunt_id)
        _segment(repo, "segment", START - timedelta(hours=4), START,
                 created=START + timedelta(days=index))
        outputs.append(_freeze(repo, hunt_id)["digest"])
    assert outputs[0] == outputs[1]


def test_external_destination_cover_requires_the_same_network_digest():
    ext = SPEC_BY_ID["bl.ext_dest"]

    def build(network_digest):
        repo = _repo()
        repo.save_baseline_segment({
            "id": "ext", "site": "site", "target": "network", "spec_id": ext.id,
            "spec_version": ext.version, "key_version": ext.key_version,
            "normalizer": "fixture@1", "start": START - timedelta(hours=2), "end": START,
            "bucket": "day", "origin": "lookback", "source_hunt_id": None,
            "built_by_hunt_id": None, "exclusion_digest": "none",
            "network_digest": "network-a", "excluded_keys": [], "hunted": 0,
            "events_total": 1, "status": "active", "created_at": START,
        }, [], [])
        return SnapshotPlanner(repo).freeze(
            hunt_id="hunt", window_start=START, lookback=timedelta(hours=2),
            min_live_hours=1, site="site", targets=["network"], specs=[ext],
            network_digest=network_digest,
        )

    assert build("network-a")["segment_ids"] == ["ext"]
    mismatched = build("network-b")
    assert mismatched["segment_ids"] == []
    assert mismatched["coverage"]["network|bl.ext_dest"]["status"] == "unresolved"


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
            "hunted": 0, "events_total": 1, "events_basis": 2, "first_event_hour": start,
            "rows_digest": "0:0:0", "status": "active", "created_at": START,
        })
    with repo.engine.begin() as connection:
        connection.execute(insert(t.baseline_segment), rows)

    before = time.perf_counter()
    snapshot = _freeze(repo, lookback=timedelta(hours=168), min_live_hours=48)
    elapsed = time.perf_counter() - before

    assert snapshot["status"] == "resolved"
    assert len(snapshot["segment_ids"]) == 168
    assert elapsed < 5
