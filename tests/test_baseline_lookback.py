"""Bounded, resumable source-history baseline construction."""
from __future__ import annotations

import threading
import time
from datetime import UTC, datetime, timedelta

import pytest

from romulus.baseline import CarryInStore, HistoryFetch, HistoryPartition, KeyContext
from romulus.baseline.count import KeyCounter
from romulus.baseline.lookback import LookbackBudget, LookbackWriter, segment_content_id
from romulus.baseline.spec import SPEC_BY_ID
from romulus.evidence.typed import Outcome, RawRef, TypedEvent, fv
from romulus.store.db import make_engine, migrate
from romulus.store.repo import Repo

START = datetime(2026, 2, 1, tzinfo=UTC)
SPEC = SPEC_BY_ID["bl.exec_path"]


def _event(index: int, ts: datetime, host: str = "web01") -> TypedEvent:
    return TypedEvent(
        id=f"event-{index}", family="process_exec", ts=ts, host=host, outcome=Outcome.success,
        fields={
            "process.executable": fv(f"/bin/tool{index % 3}", "fixture"),
            "process.exec_file.path": fv(f"/bin/tool{index % 3}", "fixture"),
            "process.user": fv("svc", "fixture"),
        },
        raw=[RawRef(target="host-index", native_id=str(index))], normalizer="fixture@1",
    )


class FakeHistory:
    def __init__(self, events=(), outcomes=None):
        self.events = tuple(events)
        self.outcomes = list(outcomes or [])
        self.plans: list[tuple[str, datetime]] = []
        self.fetches: list[HistoryPartition] = []

    def plan(self, target, start, end):
        self.plans.append((target, start))
        return [HistoryPartition(target, start, end, len(self.events), f"{target}:{start.isoformat()}")]

    def fetch(self, partition):
        self.fetches.append(partition)
        if self.outcomes:
            return self.outcomes.pop(0)
        events = tuple(event for event in self.events if partition.start <= event.ts < partition.end)
        return HistoryFetch(events, "complete", (), len(events))


def _repo(path=":memory:") -> Repo:
    repo = Repo(make_engine(path))
    migrate(repo.engine)
    return repo


def _writer(repo, source, **budget):
    return LookbackWriter(
        repo, source, site="site", specs=[SPEC], normalizer="fixture@1",
        budget=LookbackBudget(**({"queries": 100, "records": 1000, "seconds": 60} | budget)),
    )


def test_fill_is_newest_first_per_target_and_round_robins_targets():
    repo, source = _repo(), FakeHistory()
    writer = _writer(repo, source)

    result = writer.fill(
        hunt_id="build-a", targets=["z", "a"], start=START - timedelta(hours=2), end=START,
    )

    assert source.plans == [
        ("a", START - timedelta(hours=1)), ("z", START - timedelta(hours=1)),
        ("a", START - timedelta(hours=2)), ("z", START - timedelta(hours=2)),
    ]
    assert result.complete == 4 and result.gaps == ()
    assert len(repo.baseline_segments(statuses=["active"])) == 4


@pytest.mark.parametrize(
    ("fetch", "state", "reason"),
    [
        (HistoryFetch((), "failed", ("elasticsearch unavailable",), 0), "failed", "elasticsearch unavailable"),
        (HistoryFetch((), "partial", ("cap:100<total:101",), 100), "partial", "cap:"),
        (HistoryFetch((), "partial", ("timeout",), 0), "partial", "timeout"),
    ],
)
def test_failed_capped_or_timed_out_fetch_writes_no_segment(fetch, state, reason):
    repo = _repo()
    result = _writer(repo, FakeHistory(outcomes=[fetch])).fill(
        hunt_id="build", targets=["host"], start=START - timedelta(hours=1), end=START,
    )
    assert repo.baseline_segments() == []
    assert len(result.gaps) == 1
    assert result.gaps[0].state == state and reason in result.gaps[0].reason


def test_budget_exhaustion_is_visible_and_resume_skips_completed_hours():
    repo, first_source = _repo(), FakeHistory()
    first = _writer(repo, first_source, queries=2).fill(
        hunt_id="build", targets=["a", "b"], start=START - timedelta(hours=1), end=START,
    )
    assert first.complete == 1
    assert [(gap.target, gap.state) for gap in first.gaps] == [("b", "omitted_budget")]

    resumed_source = FakeHistory()
    resumed = _writer(repo, resumed_source).fill(
        hunt_id="build", targets=["a", "b"], start=START - timedelta(hours=1), end=START,
    )
    assert resumed.complete == 1 and resumed.gaps == ()
    assert [target for target, _ in resumed_source.plans] == ["b"]


def test_lookback_counts_equal_direct_key_counter_counts():
    events = [_event(1, START - timedelta(minutes=50)), _event(2, START - timedelta(minutes=40))]
    repo, source = _repo(), FakeHistory(events)
    result = _writer(repo, source).fill(
        hunt_id="build", targets=["host-index"], start=START - timedelta(hours=1), end=START,
    )
    assert result.gaps == ()
    segment = repo.baseline_segments(statuses=["active"])[0]
    stored = [{k: v for k, v in row.items() if k != "segment_id"}
              for row in repo.baseline_counts(segment["id"])]
    direct = KeyCounter("direct", SPEC)
    for event in events:
        direct.consume(event, KeyContext())
    expected = [{k: v for k, v in row.items() if k != "segment_id"} for row in direct.count_rows()]
    assert result.complete == 1 and stored == expected


def test_segment_identity_is_content_derived_and_revoked_rewrite_is_usable():
    common = {
        "site": "site", "target": "host", "spec": SPEC, "start": START - timedelta(hours=1), "end": START,
        "normalizer": "fixture@1", "exclusion_digest": "x", "excluded_keys": ["b", "a"],
    }
    assert segment_content_id(**common, built_by_hunt_id="hunt-a") == segment_content_id(
        **{**common, "excluded_keys": ["a", "b"]}, built_by_hunt_id="hunt-b",
    )
    repo, source = _repo(), FakeHistory()
    writer = _writer(repo, source)
    writer.fill(hunt_id="hunt-a", targets=["host"], start=START - timedelta(hours=1), end=START)
    original = repo.baseline_segments()[0]
    repo.set_baseline_segment_status(original["id"], "revoked")
    writer.fill(hunt_id="hunt-b", targets=["host"], start=START - timedelta(hours=1), end=START)
    rows = repo.baseline_segments()
    assert [row["status"] for row in rows] == ["revoked", "active"]
    assert rows[1]["id"] == f"{rows[0]['id']}-r1"


def test_building_segment_is_invisible_and_stale_cleanup_removes_its_rows():
    repo = _repo()
    row = _writer(repo, FakeHistory()).segment_row(
        hunt_id="build", target="host", spec=SPEC,
        start=START - timedelta(hours=1), end=START, events_total=1,
    )
    assert repo.begin_baseline_segment(row)
    count = KeyCounter(row["id"], SPEC)
    count.consume(_event(1, START - timedelta(minutes=1)), KeyContext())
    repo.append_baseline_segment_rows(row["id"], count.count_rows(), count.scope_hour_rows())
    assert repo.baseline_segments_for_cover(
        site="site", target="host", spec_id=SPEC.id, spec_version=SPEC.version,
        key_version=SPEC.key_version, start=START - timedelta(hours=1), end=START,
    ) == []
    assert repo.cleanup_baseline_building(before=START + timedelta(days=1)) == 1
    assert repo.baseline_segments() == [] and list(repo.baseline_counts(row["id"])) == []


def test_complete_lookback_fetch_records_parent_carry_on_disk():
    repo = _repo()
    repo.create_hunt("build", {}, "d", "test")
    event = _event(1, START - timedelta(minutes=1))
    event.fields.update({
        "process.pid": fv(42, "fixture"), "process.ppid": fv(1, "fixture"),
        "host.boot.id": fv("boot-a", "fixture"),
    })
    carry = CarryInStore(repo, "build")
    writer = LookbackWriter(
        repo, FakeHistory([event]), site="site", specs=[SPEC], normalizer="fixture@1",
        budget=LookbackBudget(queries=10, records=10, seconds=10), parent_carry=carry,
    )
    writer.fill(hunt_id="build", targets=["host-index"], start=START - timedelta(hours=1), end=START)
    assert carry.lookup("web01", 42, START.timestamp(), "boot-a")[1] == "/bin/tool1"


@pytest.mark.slow
def test_million_row_build_uses_short_transactions_and_allows_a_concurrent_writer(tmp_path):
    path = tmp_path / "concurrent.db"
    repo, other = _repo(path), Repo(make_engine(path))
    writer = _writer(repo, FakeHistory())
    row = writer.segment_row(
        hunt_id="build", target="host", spec=SPEC,
        start=START - timedelta(hours=1), end=START, events_total=1_000_000,
    )
    assert repo.begin_baseline_segment(row)
    stopped = threading.Event()
    waits: list[float] = []

    def concurrent_writes():
        index = 0
        while not stopped.is_set():
            before = time.perf_counter()
            other.create_hunt(f"concurrent-{index}", {}, "d", "test")
            waits.append(time.perf_counter() - before)
            index += 1

    thread = threading.Thread(target=concurrent_writes)
    thread.start()

    def counts():
        for index in range(1_000_000):
            yield {
                "segment_id": row["id"], "scope_kind": "host", "scope": f"host:{index % 1000}",
                "key_id": f"key-{index}", "key_digest": f"digest-{index}", "key": {"n": index},
                "bucket": START.replace(hour=0) - timedelta(days=1), "count": 1,
                "first_ts": START - timedelta(minutes=1), "last_ts": START - timedelta(minutes=1),
            }

    try:
        max_lock = repo.append_baseline_segment_rows(row["id"], counts(), (), chunk_size=5000)
        repo.finalize_baseline_segment(row["id"])
    finally:
        stopped.set()
        thread.join(timeout=35)
    print(f"million-row building max lock {max_lock:.3f}s; concurrent max wait {max(waits):.3f}s")
    assert waits and max_lock < 3 and max(waits) < 30
    assert repo.baseline_segments(statuses=["active"])[0]["status"] == "active"
