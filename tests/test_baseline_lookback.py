"""Bounded, resumable source-history baseline construction."""
from __future__ import annotations

import threading
import time
from datetime import UTC, datetime, timedelta

import pytest

from romulus.baseline import CarryInStore, HistoryFetch, HistoryPartition, HistoryPlan, KeyContext
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

    def plan(self, target, start, end, *, query_budget):
        self.plans.append((target, start))
        if query_budget < 1:
            return HistoryPlan((), 0, "partial", ("planning query budget exhausted",))
        expected = sum(start <= event.ts < end for event in self.events)
        return HistoryPlan((
            HistoryPartition(target, start, end, expected, f"{target}:{start.isoformat()}"),
        ), 1, "complete", ())

    def fetch(self, partition, *, record_budget=None, query_budget=None, deadline=None):
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
        now=lambda: START,
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


def test_exact_record_budget_omits_before_fetching_partition():
    repo, source = _repo(), FakeHistory([_event(1, START - timedelta(minutes=1))])
    result = _writer(repo, source, records=0).fill(
        hunt_id="build", targets=["host"], start=START - timedelta(hours=1), end=START,
    )
    assert source.fetches == []
    assert result.records == 0 and result.gaps[0].state == "omitted_budget"


def test_wall_budget_is_rechecked_after_a_slow_source_call():
    class Clock:
        value = 0.0

        def __call__(self):
            return self.value

    class SlowPlan(FakeHistory):
        def plan(self, target, start, end, *, query_budget):
            result = super().plan(target, start, end, query_budget=query_budget)
            clock.value = 11.0
            return result

    clock = Clock()
    repo, source = _repo(), SlowPlan()
    writer = LookbackWriter(
        repo, source, site="site", specs=[SPEC], normalizer="fixture@1",
        budget=LookbackBudget(queries=10, records=10, seconds=10), clock=clock, now=lambda: START,
    )

    result = writer.fill(
        hunt_id="build", targets=["host"], start=START - timedelta(hours=1), end=START,
    )

    assert source.fetches == [] and repo.baseline_segments() == []
    assert result.gaps[0].state == "omitted_budget"


def test_wall_budget_is_rechecked_after_a_slow_fetch():
    class Clock:
        value = 0.0

        def __call__(self):
            return self.value

    class SlowFetch(FakeHistory):
        def fetch(self, partition, *, record_budget=None, query_budget=None, deadline=None):
            result = super().fetch(
                partition, record_budget=record_budget, query_budget=query_budget, deadline=deadline,
            )
            clock.value = 11.0
            return result

    clock = Clock()
    repo, source = _repo(), SlowFetch([_event(1, START - timedelta(minutes=1))])
    writer = LookbackWriter(
        repo, source, site="site", specs=[SPEC], normalizer="fixture@1",
        budget=LookbackBudget(queries=10, records=10, seconds=10), clock=clock, now=lambda: START,
    )

    result = writer.fill(
        hunt_id="build", targets=["host"], start=START - timedelta(hours=1), end=START,
    )

    assert len(source.fetches) == 1 and repo.baseline_segments() == []
    assert result.records == 1 and result.gaps[0].state == "omitted_budget"


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


def test_resume_reclaims_its_own_crashed_build_immediately():
    repo = _repo()
    writer = _writer(repo, FakeHistory([_event(1, START - timedelta(minutes=1))]))
    row = writer.segment_row(
        hunt_id="build", target="host", spec=SPEC,
        start=START - timedelta(hours=1), end=START, events_total=1,
    )
    assert repo.begin_baseline_segment(row)
    partial = KeyCounter(row["id"], SPEC)
    partial.consume(_event(99, START - timedelta(minutes=1)), KeyContext())
    repo.append_baseline_segment_rows(row["id"], partial.count_rows(), partial.scope_hour_rows())

    result = writer.fill(
        hunt_id="build", targets=["host"], start=START - timedelta(hours=1), end=START,
    )

    assert result.complete == 1 and result.gaps == ()
    segments = repo.baseline_segments()
    assert len(segments) == 1 and segments[0]["status"] == "active"
    assert len(list(repo.baseline_counts(row["id"]))) == 2


def test_fresh_building_segment_is_not_cleaned_by_a_concurrent_writer():
    repo = _repo()
    writer = _writer(repo, FakeHistory())
    row = writer.segment_row(
        hunt_id="build", target="host", spec=SPEC,
        start=START - timedelta(hours=1), end=START, events_total=0,
    )
    assert repo.begin_baseline_segment(row)
    contender = _writer(repo, FakeHistory()).fill(
        hunt_id="other-builder", targets=["host"], start=START - timedelta(hours=1), end=START,
    )
    assert contender.complete == 0
    assert repo.baseline_segments()[0]["status"] == "building"


def test_unresolved_exec_pair_pending_never_becomes_an_empty_complete_segment():
    repo = _repo()
    child = TypedEvent(
        id="child", family="process_exec", ts=START - timedelta(minutes=1), host="web01",
        fields={"process.executable": fv("/bin/sh", "fixture"), "process.ppid": fv(99, "fixture")},
        raw=[], normalizer="fixture@1",
    )
    writer = LookbackWriter(
        repo, FakeHistory([child]), site="site", specs=[SPEC_BY_ID["bl.exec_pair"]],
        normalizer="fixture@1", budget=LookbackBudget(queries=10, records=10, seconds=10),
        now=lambda: START,
    )
    result = writer.fill(
        hunt_id="build", targets=["host-index"], start=START - timedelta(hours=1), end=START,
    )
    assert repo.baseline_segments(statuses=["active"]) == []
    assert result.gaps[0].state == "partial" and "parent exec before history" in result.gaps[0].reason


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
        now=lambda: START,
    )
    writer.fill(hunt_id="build", targets=["host-index"], start=START - timedelta(hours=1), end=START)
    assert carry.lookup("web01", 42, START.timestamp(), "boot-a")[1] == "/bin/tool1"


def test_parent_in_an_earlier_hour_is_explicit_then_resolves_on_resume():
    repo = _repo()
    repo.create_hunt("build", {}, "d", "test")
    parent = TypedEvent(
        id="parent", family="process_exec", ts=START - timedelta(minutes=90), host="web01",
        fields={
            "process.pid": fv(10, "fixture"), "process.ppid": fv(1, "fixture"),
            "process.executable": fv("/usr/sbin/parent", "fixture"),
            "host.boot.id": fv("boot-a", "fixture"),
        }, raw=[], normalizer="fixture@1",
    )
    child = TypedEvent(
        id="child", family="process_exec", ts=START - timedelta(minutes=30), host="web01",
        fields={
            "process.pid": fv(11, "fixture"), "process.ppid": fv(10, "fixture"),
            "process.executable": fv("/bin/sh", "fixture"),
            "host.boot.id": fv("boot-a", "fixture"),
        }, raw=[], normalizer="fixture@1",
    )
    carry = CarryInStore(repo, "build")

    def run():
        return LookbackWriter(
            repo, FakeHistory([parent, child]), site="site", specs=[SPEC_BY_ID["bl.exec_pair"]],
            normalizer="fixture@1", budget=LookbackBudget(queries=20, records=20, seconds=10),
            parent_carry=carry, now=lambda: START,
        ).fill(hunt_id="build", targets=["host-index"], start=START - timedelta(hours=2), end=START)

    first = run()
    assert any(gap.start == START - timedelta(hours=1) and gap.state == "partial" for gap in first.gaps)
    second = run()
    active = repo.baseline_segments(statuses=["active"])
    assert second.complete == 1
    assert any(row["start"] == START - timedelta(hours=1) for row in active)


def test_exec_pair_writer_matches_direct_counter_with_same_hour_parent():
    repo = _repo()
    repo.create_hunt("build", {}, "d", "test")
    parent = TypedEvent(
        id="parent", family="process_exec", ts=START - timedelta(minutes=2), host="web01",
        fields={
            "process.pid": fv(10, "fixture"), "process.ppid": fv(1, "fixture"),
            "process.executable": fv("/usr/sbin/parent", "fixture"),
            "host.boot.id": fv("boot-a", "fixture"),
        }, raw=[], normalizer="fixture@1",
    )
    child = TypedEvent(
        id="child", family="process_exec", ts=START - timedelta(minutes=1), host="web01",
        fields={
            "process.pid": fv(11, "fixture"), "process.ppid": fv(10, "fixture"),
            "process.executable": fv("/bin/sh", "fixture"),
            "host.boot.id": fv("boot-a", "fixture"),
        }, raw=[], normalizer="fixture@1",
    )
    carry = CarryInStore(repo, "build")
    carry.observe_events([parent])
    result = LookbackWriter(
        repo, FakeHistory([child]), site="site", specs=[SPEC_BY_ID["bl.exec_pair"]],
        normalizer="fixture@1", budget=LookbackBudget(queries=10, records=10, seconds=10),
        parent_carry=carry, now=lambda: START,
    ).fill(hunt_id="build", targets=["host-index"], start=START - timedelta(hours=1), end=START)

    segment = repo.baseline_segments(statuses=["active"])[0]
    stored = [{key: value for key, value in row.items() if key != "segment_id"}
              for row in repo.baseline_counts(segment["id"])]
    direct = KeyCounter("direct", SPEC_BY_ID["bl.exec_pair"])
    direct.consume(child, KeyContext(pid_table=carry))
    expected = [{key: value for key, value in row.items() if key != "segment_id"}
                for row in direct.count_rows()]
    assert result.complete == 1 and stored == expected


def test_exec_pair_resolves_children_before_three_pid_reuses_are_compacted():
    repo = _repo()
    repo.create_hunt("build", {}, "d", "test")
    events = []
    for index, executable in enumerate(("/p1", "/p3", "/p5"), start=1):
        events.append(TypedEvent(
            id=f"parent-{index}", family="process_exec",
            ts=START - timedelta(minutes=10) + timedelta(seconds=index * 2), host="web01",
            fields={
                "process.pid": fv(10, "fixture"), "process.ppid": fv(1, "fixture"),
                "process.executable": fv(executable, "fixture"),
                "host.boot.id": fv("boot-a", "fixture"),
            }, raw=[], normalizer="fixture@1",
        ))
        events.append(TypedEvent(
            id=f"child-{index}", family="process_exec",
            ts=events[-1].ts + timedelta(seconds=1), host="web01",
            fields={
                "process.pid": fv(20 + index, "fixture"), "process.ppid": fv(10, "fixture"),
                "process.executable": fv("/bin/sh", "fixture"),
                "host.boot.id": fv("boot-a", "fixture"),
            }, raw=[], normalizer="fixture@1",
        ))
    carry = CarryInStore(repo, "build")
    result = LookbackWriter(
        repo, FakeHistory(events), site="site", specs=[SPEC_BY_ID["bl.exec_pair"]],
        normalizer="fixture@1", budget=LookbackBudget(queries=10, records=20, seconds=10),
        parent_carry=carry, now=lambda: START,
    ).fill(hunt_id="build", targets=["host-index"], start=START - timedelta(hours=1), end=START)

    assert result.complete == 0
    # PID 1 parents remain explicitly unresolved, but all three child generations were resolved rather than
    # adding a "parent exec before history" omission after carry compaction.
    assert "parent pid 1/2 out of scope" in result.gaps[0].reason
    assert "parent exec before history" not in result.gaps[0].reason


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
