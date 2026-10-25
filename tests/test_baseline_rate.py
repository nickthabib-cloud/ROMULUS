"""Hourly service-account rate thresholds and publication semantics."""
from __future__ import annotations

import random
import tracemalloc
from dataclasses import asdict
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import inspect

from romulus.baseline import playbook as playbook_module
from romulus.baseline import rate as rate_module
from romulus.baseline.spec import SPEC_BY_ID, KeyContext
from romulus.evidence.typed import Outcome, RawRef, TypedEvent, fv
from romulus.hunt.baseline_stage import SnapshotView, _write_rollup
from romulus.sources.models import Window
from romulus.store.db import make_engine, migrate
from romulus.store.repo import Repo

T0 = datetime(2026, 1, 1, tzinfo=UTC)


def test_rate_threshold_uses_sample_sigma_and_published_defaults():
    result = rate_module.threshold([0, 0, 2, 2])

    assert result.n == 4
    assert result.mean == 1.0
    assert result.sigma == 1.154701
    assert result.value == 5.618802
    assert (result.min_count, result.k, result.z) == (5.0, 3.0, 4.0)


def test_rate_threshold_is_exactly_order_independent_over_shuffled_series():
    series = [0, 1, 2, 3, 5, 8, 13, 21, 34, 55] * 6
    expected = rate_module.threshold(series)
    rng = random.Random(1729)

    for _ in range(100):
        shuffled = list(series)
        rng.shuffle(shuffled)
        assert rate_module.threshold(shuffled) == expected


@pytest.mark.parametrize("series", ([], [1]))
def test_sample_sigma_requires_two_history_hours(series):
    with pytest.raises(ValueError, match="at least two"):
        rate_module.threshold(series)


def test_service_rate_playbook_is_registered_positive_only_and_lead_capped():
    playbook = playbook_module.ServiceExecRateBaseline()

    assert playbook_module.BASELINE_PLAYBOOKS[-1] is playbook_module.ServiceExecRateBaseline
    assert playbook.id == "bl.svc_exec_rate"
    assert playbook.spec.measure == "rate" and playbook.spec.bucket == "hour"
    assert playbook.assures_negative is False
    assert playbook.lane == "lead" and playbook.severity == "info"


def test_service_rate_projects_uid_without_making_it_required_for_configured_names():
    spec = SPEC_BY_ID["bl.svc_exec_rate"]

    assert spec.required_fields["process_exec"] == ("process.user",)
    assert spec.optional_fields["process_exec"] == ("process.uid",)


def _rate_segment(segment_id: str, start: datetime, end: datetime, *, target="host-index") -> dict:
    return {
        "id": segment_id, "site": "site", "target": target, "spec_id": "bl.svc_exec_rate",
        "spec_version": "1", "key_version": "1", "normalizer": "fixture@1",
        "start": start, "end": end, "bucket": "hour", "origin": "lookback",
        "source_hunt_id": None, "built_by_hunt_id": None, "exclusion_digest": "none",
        "excluded_keys": [], "hunted": 0, "events_total": 1, "status": "active", "created_at": end,
    }


def _rate_hour(segment_id: str, hour: datetime, events: int, *, scope="host_account:web-svc") -> dict:
    return {
        "segment_id": segment_id, "scope_kind": "host_account", "scope": scope,
        "hour": hour, "events": events,
    }


def test_history_scope_series_is_keyset_paged_instead_of_collected():
    repo = Repo(make_engine(":memory:"))
    migrate(repo.engine)
    end = T0 + timedelta(hours=211)
    repo.save_baseline_segment(
        _rate_segment("history", T0, end), (),
        (_rate_hour("history", T0 + timedelta(hours=index), index % 7) for index in range(211)),
    )
    repo.create_hunt("hunt", {}, "digest", "test")
    repo.save_baseline_snapshot({
        "hunt_id": "hunt", "plan": {}, "store_cut": {}, "segment_ids": ["history"],
        "coverage": {}, "status": "resolved", "digest": "snapshot",
    })

    series = repo.baseline_scope_series(
        "host_account", "host_account:web-svc", "hunt", "bl.svc_exec_rate", page_size=17,
    )

    assert not isinstance(series, list)
    rows = list(series)
    assert len(rows) == 211
    assert (rows[0]["hour"], rows[-1]["hour"]) == (T0, end - timedelta(hours=1))


def test_window_scope_series_sums_partitions_and_targets_by_hour_with_keyset_pages():
    repo = Repo(make_engine(":memory:"))
    migrate(repo.engine)
    repo.create_hunt("hunt", {}, "digest", "test")
    for target, partition, rows in (
        ("host-a", "p1", [_rate_hour("unused", T0, 2)]),
        ("host-a", "p2", [_rate_hour("unused", T0, 3), _rate_hour("unused", T0 + timedelta(hours=1), 4)]),
        ("host-b", "p1", [_rate_hour("unused", T0, 5)]),
    ):
        repo.save_baseline_window_cell("hunt", {
            "rule_id": "bl.svc_exec_rate", "version": "1", "target": target,
            "partition": partition, "state": "evaluated_complete", "matched": 0,
            "evaluated": sum(row["events"] for row in rows), "detail": {},
        }, (), scope_hours=rows)

    rows = list(repo.baseline_window_scope_series(
        "hunt", "bl.svc_exec_rate", "host_account", "host_account:web-svc",
        span=(T0, T0 + timedelta(hours=2)), page_size=1,
    ))

    assert [(row["hour"], row["events"]) for row in rows] == [
        (T0, 10), (T0 + timedelta(hours=1), 4),
    ]
    indexes = {row["name"] for row in inspect(repo.engine).get_indexes("baseline_window_scope_hour")}
    assert "ix_baseline_window_scope_rate" in indexes


def _rate_event(event_id: str, ts: datetime, *, user="web-svc", uid=100) -> TypedEvent:
    return TypedEvent(
        id=event_id, family="process_exec", ts=ts, host="web01", outcome=Outcome.success,
        fields={
            "process.user": fv(user, "fixture:process.user"),
            "process.uid": fv(uid, "fixture:process.uid"),
        },
        raw=[RawRef(target="host-index", native_id=f"raw-{event_id}")], normalizer="fixture@1",
    )


def _pending_observation(hunt_id: str, row: dict) -> dict:
    return {
        "hunt_id": hunt_id, "spec_id": "bl.svc_exec_rate", "spec_version": "1", **row,
        "history_count": None, "history_decayed": None, "peer_scopes_with_key": None,
        "peer_scopes": None, "threshold": None, "mean": None, "sigma": None,
        "n_hours": None, "verdict": "unresolved", "reason": "baseline judgement pending",
        "candidate_id": None,
    }


def _rate_view(*, history_hours=48, history_values=None, window_counts=(5,),
               window_start=T0 + timedelta(days=10), edge_minutes=0,
               window_state="evaluated_complete", history_status=None, hunt_id="hunt"):
    history_values = {0: 1} if history_values is None else history_values
    start = window_start + timedelta(minutes=edge_minutes)
    window = Window(start=start, end=start + timedelta(hours=len(window_counts)))
    history_start = window.start.replace(minute=0, second=0, microsecond=0) - timedelta(hours=history_hours)
    history_end = window.start.replace(minute=0, second=0, microsecond=0)
    repo = Repo(make_engine(":memory:"))
    migrate(repo.engine)
    manifest = {
        "targets": ["host-index"],
        "baseline": {
            "thresholds": {"rate": {"min_count": 5, "k": 3, "z": 4}},
        },
    }
    repo.create_hunt(hunt_id, manifest, "digest", "test")
    scope = "host_account:{\"account\":\"web-svc\",\"host\":\"web01\"}"
    history_rows = [
        _rate_hour("history", history_start + timedelta(hours=index), value, scope=scope)
        for index, value in sorted(history_values.items())
    ]
    repo.save_baseline_segment(
        _rate_segment("history", history_start, history_end), (), history_rows,
    )
    status = history_status or ("resolved" if history_hours >= 48 else "unresolved")
    gaps = ([{
        "start": (history_start + timedelta(hours=1)).isoformat(),
        "end": (history_start + timedelta(hours=2)).isoformat(),
        "state": "partial", "reason": "shard failure",
    }] if status == "gap_shortened" else [])
    snapshot_row = {
        "hunt_id": hunt_id,
        "plan": {
            "history_start": history_start.isoformat(), "window_start": history_end.isoformat(),
            "targets": ["host-index"], "specs": [{"id": "bl.svc_exec_rate", "version": "1",
                                                    "key_version": "1"}],
        },
        "store_cut": {}, "segment_ids": ["history"],
        "coverage": {"host-index|bl.svc_exec_rate": {
            "effective_start": history_start.isoformat(), "effective_hours": history_hours,
            "gaps": gaps, "absent_before": None, "status": status, "segment_ids": ["history"],
        }},
        "status": status, "digest": "snapshot-rate",
    }
    repo.save_baseline_snapshot(snapshot_row)

    events: list[TypedEvent] = []
    for hour_index, count in enumerate(window_counts):
        hour = window.start + timedelta(hours=hour_index)
        events.extend(
            _rate_event(f"window-{hour_index:02d}-{index:03d}", hour + timedelta(minutes=1, seconds=index))
            for index in range(count)
        )
    repo.save_evidence(
        hunt_id, events,
        {ref.key: {"message": event.id} for event in events for ref in event.raw}, None,
    )
    playbook = playbook_module.ServiceExecRateBaseline()
    playbook.begin_cell("window", (window.start, window.end), KeyContext())
    playbook.consume(events)
    cell = playbook.finish_cell()
    repo.save_baseline_window_cell(hunt_id, {
        "rule_id": playbook.id, "version": playbook.version, "target": "host-index",
        "partition": window.key(), "state": window_state, "matched": 0,
        "evaluated": len(events), "detail": {"reasons": [] if window_state == "evaluated_complete"
                                               else ["source result cap reached"]},
    }, (_pending_observation(hunt_id, row) for row in cell.observations),
        counts=cell.counts, scope_hours=cell.scope_hours)
    snapshot = repo.baseline_snapshot(hunt_id)
    assert snapshot is not None
    view = SnapshotView(
        repo, hunt_id, window, snapshot, min_live_hours=48, networks_configured=True,
    )
    return repo, playbook, view, scope


def test_live_history_hours_without_events_are_zeroes_in_the_threshold_series():
    repo, playbook, view, _scope = _rate_view(history_values={0: 1}, window_counts=(5,))

    matches = list(playbook.judge(view))

    row = next(repo.baseline_observations("hunt"))
    assert len(matches) == 1
    assert (row["n_hours"], row["history_count"]) == (48, 1)
    assert (row["mean"], row["sigma"], row["threshold"]) == (0.020833, 0.144338, 5.0)
    assert row["verdict"] == "over_threshold"
    assert "min_count 5" in matches[0].claim
    assert "mean × k (0.020833 × 3)" in matches[0].claim
    assert "mean + z × sample sigma (0.020833 + 4 × 0.144338)" in matches[0].claim
    assert "n=48" in matches[0].claim and "Seasonality is not modelled" in matches[0].claim


def test_a_scope_silent_in_history_is_unresolved_instead_of_becoming_a_zero_rate():
    repo, playbook, view, _scope = _rate_view(history_values={}, window_counts=(12,))

    assert list(playbook.judge(view)) == []
    row = next(repo.baseline_observations("hunt"))
    assert row["verdict"] == "unresolved" and row["reason"] == "scope is silent in history"


@pytest.mark.parametrize(("history_hours", "verdict", "leads"), [
    (47, "unresolved", 0),
    (48, "over_threshold", 1),
])
def test_rate_warmup_requires_48_live_complete_hours(history_hours, verdict, leads):
    repo, playbook, view, _scope = _rate_view(
        history_hours=history_hours, history_values={0: 1}, window_counts=(5,),
    )

    assert len(list(playbook.judge(view))) == leads
    assert next(repo.baseline_observations("hunt"))["verdict"] == verdict


@pytest.mark.parametrize(("counts", "reported"), [
    ((5, 7, 9), (5, 7, 9)),
    ((4, 5, 3), (5,)),
])
def test_one_grouped_lead_lists_every_and_only_window_hour_at_or_above_threshold(counts, reported):
    _repo, playbook, view, _scope = _rate_view(
        history_values={index: 1 for index in range(48)}, window_counts=counts,
    )

    matches = list(playbook.judge(view))

    assert len(matches) == 1
    for hour_index, count in enumerate(counts):
        hour = (view.window.start + timedelta(hours=hour_index)).isoformat()
        assert (f"{hour} count {count}" in matches[0].claim) is (count in reported)
    assert matches[0].group_key.startswith("baseline:bl.svc_exec_rate:host_account:")


def test_fractional_window_edges_are_not_measured_and_are_stated_in_the_lead():
    repo, playbook, view, _scope = _rate_view(
        history_values={index: 1 for index in range(48)},
        window_counts=(20, 5, 1, 20), edge_minutes=30,
    )

    matches = list(playbook.judge(view))

    assert len(matches) == 1
    claim = matches[0].claim
    assert "edge fractions" in claim and "not assessed" in claim
    floor = view.window.start.replace(minute=0, second=0, microsecond=0)
    assert f"{floor.isoformat()} count 20" not in claim
    assert f"{(floor + timedelta(hours=1)).isoformat()} count 5" in claim
    assert f"{(floor + timedelta(hours=3)).isoformat()} count 20" in claim
    assert next(repo.baseline_observations("hunt"))["window_count"] == 46


def test_a_window_with_only_fractional_hours_is_unresolved_and_not_measured():
    repo, playbook, view, _scope = _rate_view(
        history_values={index: 1 for index in range(48)}, window_counts=(20,), edge_minutes=30,
    )

    assert list(playbook.judge(view)) == []
    row = next(repo.baseline_observations("hunt"))
    assert row["verdict"] == "unresolved"
    assert "no complete whole hour" in row["reason"] and "not assessed" in row["reason"]


@pytest.mark.parametrize(("window_state", "history_status", "reason"), [
    ("evaluated_partial", None, "window coverage is partial"),
    ("evaluated_complete", "gap_shortened", "history gap"),
])
def test_partial_window_or_history_never_publishes_or_writes_a_complete_negative(
        window_state, history_status, reason):
    repo, playbook, view, _scope = _rate_view(
        history_values={index: 1 for index in range(48)}, window_counts=(20,),
        window_state=window_state, history_status=history_status,
    )

    assert list(playbook.judge(view)) == []
    row = next(repo.baseline_observations("hunt"))
    assert row["verdict"] == "unresolved" and reason in row["reason"]
    _write_rollup(repo, "hunt", playbook, view.spec_stats[playbook.id], view.snapshot, None)
    rollup = next(cell for cell in repo.rule_cells("hunt", rule_id=playbook.id)
                  if cell["target"] == "*" and cell["partition"] == "window")
    assert rollup["state"] == "positive_only_partial"


def test_twins_with_the_same_snapshot_are_canonical_identical():
    products = []
    for hunt_id in ("twin-a", "twin-b"):
        repo, playbook, view, _scope = _rate_view(
            history_values={index: index % 3 for index in range(48)}, window_counts=(9, 1, 10),
            hunt_id=hunt_id,
        )
        matches = list(playbook.judge(view))
        row = next(repo.baseline_observations(hunt_id))
        products.append({
            "match": {
                **asdict(matches[0]),
                "events": [event.model_dump(mode="json") for event in matches[0].events],
            },
            "observation": {key: value for key, value in row.items() if key != "hunt_id"},
        })

    assert products[0] == products[1]


@pytest.mark.slow
def test_many_scopes_over_two_weeks_are_judged_one_scope_at_a_time_with_bounded_memory():
    scope_count = 5_000
    history_start = T0
    history_end = T0 + timedelta(days=14)
    window = Window(start=history_end, end=history_end + timedelta(hours=1))

    class StreamingRepo:
        def __init__(self):
            self.written = 0
            self.max_batch = 0

        def get_hunt(self, _hunt_id):
            return {"manifest": {"baseline": {"thresholds": {"rate": {
                "min_count": 5, "k": 3, "z": 4,
            }}}}}

        def rule_cells(self, _hunt_id, *, rule_id=None):
            assert rule_id == "bl.svc_exec_rate"
            return [{
                "target": "host-index", "partition": window.key(), "state": "evaluated_complete",
            }]

        def baseline_observations_for_spec(self, _hunt_id, _spec_id, _version):
            for index in range(scope_count):
                scope = f"host_account:scope-{index:05d}"
                yield {
                    "hunt_id": "hunt", "spec_id": "bl.svc_exec_rate", "spec_version": "1",
                    "scope_kind": "host_account", "scope": scope, "key_id": f"key-{index}",
                    "key_digest": f"digest-{index:05d}", "key": {}, "window_count": 1,
                    "first_ts": window.start, "last_ts": window.start, "first_event_id": None,
                    "first_event_refs": [], "history_count": None, "history_decayed": None,
                    "peer_scopes_with_key": None, "peer_scopes": None, "threshold": None,
                    "mean": None, "sigma": None, "n_hours": None, "verdict": "unresolved",
                    "reason": "pending", "candidate_id": None,
                }

        def baseline_scope_series(self, _kind, _scope, _hunt_id, _spec_id, _span):
            return iter(({"segment_id": "history", "hour": history_start, "events": 1},))

        def baseline_window_scope_series(self, *_args, **_kwargs):
            return iter(({"hour": window.start, "events": 1},))

        def upsert_baseline_observations(self, rows):
            batch = list(rows)
            self.written += len(batch)
            self.max_batch = max(self.max_batch, len(batch))

    repo = StreamingRepo()
    snapshot = {
        "plan": {"history_start": history_start.isoformat(), "window_start": history_end.isoformat()},
        "coverage": {"host-index|bl.svc_exec_rate": {
            "effective_start": history_start.isoformat(), "effective_hours": 14 * 24,
            "gaps": [], "status": "resolved",
        }},
        "digest": "snapshot-rate", "status": "resolved",
    }
    view = SnapshotView(repo, "hunt", window, snapshot, min_live_hours=48, networks_configured=True)

    tracemalloc.start()
    assert list(playbook_module.ServiceExecRateBaseline().judge(view)) == []
    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    assert repo.written == scope_count and repo.max_batch == 1
    assert view.spec_stats["bl.svc_exec_rate"]["within_threshold"] == scope_count
    assert peak < 32 * 1024 * 1024
