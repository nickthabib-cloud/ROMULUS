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
    assert repo.begin_baseline_segment(row) == "begun"
    contender = _writer(repo, FakeHistory()).fill(
        hunt_id="other-builder", targets=["host"], start=START - timedelta(hours=1), end=START,
    )
    assert contender.complete == 0
    assert repo.baseline_segments()[0]["status"] == "building"
    # Never skipped silently: the hour is a gap for this hunt, with the reason.
    assert [(gap.start, gap.state, gap.reason) for gap in contender.gaps] == [
        (START - timedelta(hours=1), "partial", "bl.exec_path: being built by another hunt"),
    ]


def test_segment_another_hunt_finished_meanwhile_counts_as_built():
    repo = _repo()
    first = _writer(repo, FakeHistory())
    row = first.segment_row(
        hunt_id="first", target="host", spec=SPEC, start=START - timedelta(hours=1), end=START, events_total=0,
    )
    assert repo.begin_baseline_segment(row) == "begun"
    repo.finalize_baseline_segment(row["id"])
    late = {**row, "built_by_hunt_id": "second", "status": "building"}
    assert repo.begin_baseline_segment(late, reclaim_owner=True) == "active"


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
    # The carry is per target, and answers only inside the hours the writer observed completely.
    at = (START - timedelta(seconds=1)).timestamp()
    assert carry.for_target("host-index").lookup("web01", 42, at, "boot-a")[1] == "/bin/tool1"
    assert carry.for_target("host-index").lookup("web01", 42, START.timestamp(), "boot-a") is None


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
    carry = CarryInStore(repo, "build", "host-index")
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


def _exec(index, ts, pid, ppid, executable, *, host="web01", boot="boot-a"):
    return TypedEvent(
        id=f"e{index}", family="process_exec", ts=ts, host=host, outcome=Outcome.success,
        fields={
            "process.pid": fv(pid, "fixture"), "process.ppid": fv(ppid, "fixture"),
            "process.executable": fv(executable, "fixture"), "host.boot.id": fv(boot, "fixture"),
        }, raw=[], normalizer="fixture@1",
    )


def _pair_writer(repo, source, carry):
    return LookbackWriter(
        repo, source, site="site", specs=[SPEC_BY_ID["bl.exec_pair"]], normalizer="fixture@1",
        budget=LookbackBudget(queries=50, records=50, seconds=60), parent_carry=carry, now=lambda: START,
    )


def _pair_keys(repo):
    return sorted(
        (segment["start"], row["key"]["parent_executable"], row["key"]["child_executable"])
        for segment in repo.baseline_segments(statuses=["active"])
        for row in repo.baseline_counts(segment["id"])
    )


F_HOUR, G_HOUR, H_HOUR = (START - timedelta(hours=n) for n in (3, 2, 1))


def test_parent_across_a_failed_hour_is_unresolved_never_the_older_generation():
    events = [
        _exec(1, F_HOUR + timedelta(minutes=10), 10, 500, "/old"),
        _exec(2, G_HOUR + timedelta(minutes=10), 10, 500, "/true_parent"),
        _exec(3, H_HOUR + timedelta(minutes=10), 11, 10, "/bin/sh"),
    ]

    class FailingG(FakeHistory):
        def fetch(self, partition, **kwargs):
            if partition.start == G_HOUR:
                return HistoryFetch((), "failed", ("shard failure",), 0)
            return super().fetch(partition, **kwargs)

    repo = _repo()
    repo.create_hunt("build", {}, "d", "test")
    carry = CarryInStore(repo, "build")
    for _ in range(2):
        result = _pair_writer(repo, FailingG(events), carry).fill(
            hunt_id="build", targets=["host-index"], start=F_HOUR, end=START,
        )
    assert ("/old", "/bin/sh") not in [(parent, child) for _, parent, child in _pair_keys(repo)]
    child_gap = [gap for gap in result.gaps if gap.start == H_HOUR]
    assert child_gap and child_gap[0].state == "partial"
    assert "e3: parent exec in an unobserved hour" in child_gap[0].reason


def test_parent_across_an_hour_another_hunt_built_is_unresolved_never_the_older_generation():
    repo = _repo()
    repo.create_hunt("A", {}, "d", "test")
    repo.create_hunt("B", {}, "d", "test")
    true_parent = _exec(2, G_HOUR + timedelta(minutes=10), 10, 500, "/true_parent")
    carry_a = CarryInStore(repo, "A", "host-index")
    carry_a.observe_events([_exec(0, START - timedelta(hours=4), 500, 1, "/usr/sbin/sshd")])
    carry_a.mark_observed(START - timedelta(hours=4), G_HOUR)
    built = _pair_writer(repo, FakeHistory([true_parent]), carry_a).fill(
        hunt_id="A", targets=["host-index"], start=G_HOUR, end=H_HOUR,
    )
    assert built.complete == 1

    events = [
        _exec(1, F_HOUR + timedelta(minutes=10), 10, 1, "/old"), true_parent,
        _exec(3, H_HOUR + timedelta(minutes=10), 11, 10, "/bin/sh"),
    ]
    carry_b = CarryInStore(repo, "B")
    for _ in range(2):
        source = FakeHistory(events)
        result = _pair_writer(repo, source, carry_b).fill(
            hunt_id="B", targets=["host-index"], start=F_HOUR, end=START,
        )
    # Hunt B skipped G because hunt A's segment covers it, so B's carry never saw /true_parent.
    assert G_HOUR not in [start for _, start in source.plans]
    assert ("/old", "/bin/sh") not in [(parent, child) for _, parent, child in _pair_keys(repo)]
    child_gap = [gap for gap in result.gaps if gap.start == H_HOUR]
    assert child_gap and "e3: parent exec in an unobserved hour" in child_gap[0].reason


def test_partially_fetched_hour_breaks_parent_continuity():
    events = [
        _exec(1, F_HOUR + timedelta(minutes=10), 10, 500, "/old"),
        _exec(2, G_HOUR + timedelta(minutes=5), 12, 500, "/unrelated"),
        _exec(3, G_HOUR + timedelta(minutes=40), 10, 500, "/true_parent"),
        _exec(4, H_HOUR + timedelta(minutes=10), 11, 10, "/bin/sh"),
    ]

    class SplitG(FakeHistory):
        """G has two partitions; the first is fed to the carry, the second (holding the parent) is capped."""

        def plan(self, target, start, end, *, query_budget):
            if start != G_HOUR:
                return super().plan(target, start, end, query_budget=query_budget)
            middle = start + timedelta(minutes=30)
            return HistoryPlan((
                HistoryPartition(target, start, middle, 1, "g1"),
                HistoryPartition(target, middle, end, 1, "g2"),
            ), 1, "complete", ())

        def fetch(self, partition, **kwargs):
            if partition.identity == "g2":
                return HistoryFetch((), "partial", ("cap:0<total:1",), 0)
            return super().fetch(partition, **kwargs)

    repo = _repo()
    repo.create_hunt("build", {}, "d", "test")
    carry = CarryInStore(repo, "build")
    for _ in range(2):
        result = _pair_writer(repo, SplitG(events), carry).fill(
            hunt_id="build", targets=["host-index"], start=F_HOUR, end=START,
        )
    assert ("/old", "/bin/sh") not in [(parent, child) for _, parent, child in _pair_keys(repo)]
    child_gap = [gap for gap in result.gaps if gap.start == H_HOUR]
    assert child_gap and "e4: parent exec in an unobserved hour" in child_gap[0].reason


def test_parent_resolves_across_continuously_observed_hours():
    events = [
        _exec(1, F_HOUR + timedelta(minutes=10), 10, 500, "/usr/sbin/parent"),
        _exec(2, G_HOUR + timedelta(minutes=10), 12, 500, "/unrelated"),
        _exec(3, H_HOUR + timedelta(minutes=10), 11, 10, "/bin/sh"),
    ]
    repo = _repo()
    repo.create_hunt("build", {}, "d", "test")
    carry = CarryInStore(repo, "build")
    for _ in range(2):
        _pair_writer(repo, FakeHistory(events), carry).fill(
            hunt_id="build", targets=["host-index"], start=F_HOUR, end=START,
        )
    assert (H_HOUR, "/usr/sbin/parent", "/bin/sh") in _pair_keys(repo)


def _building_with_rows(repo, rows, *, hunt_id="build"):
    row = _writer(repo, FakeHistory()).segment_row(
        hunt_id=hunt_id, target="host", spec=SPEC,
        start=START - timedelta(hours=1), end=START, events_total=rows,
    )
    assert repo.begin_baseline_segment(row)

    def counts():
        for index in range(rows):
            yield {
                "segment_id": row["id"], "scope_kind": "host", "scope": f"host:{index % 1000}",
                "key_id": f"key-{index}", "key_digest": f"digest-{index}", "key": {"n": index},
                "bucket": START.replace(hour=0) - timedelta(days=1), "count": 1,
                "first_ts": START - timedelta(minutes=1), "last_ts": START - timedelta(minutes=1),
            }

    repo.append_baseline_segment_rows(row["id"], counts(), (), chunk_size=5000)
    return row


def test_cleanup_and_reclaim_delete_child_rows_in_bounded_transactions(monkeypatch):
    from romulus.store import repo as repo_module

    monkeypatch.setattr(repo_module, "BASELINE_DELETE_CHUNK", 7)
    repo = _repo()
    statements: list[str] = []
    real = repo_module.write_txn

    class Counting:
        def __init__(self, engine):
            self.inner = real(engine)

        def __enter__(self):
            statements.append("txn")
            return self.inner.__enter__()

        def __exit__(self, *exc):
            return self.inner.__exit__(*exc)

    row = _building_with_rows(repo, 50)
    monkeypatch.setattr(repo_module, "write_txn", Counting)
    assert repo.cleanup_baseline_building(before=START + timedelta(days=1)) == 1
    # 50 child rows in chunks of 7 need at least 8 delete transactions besides the claim and the parent.
    assert len(statements) >= 10
    assert repo.baseline_segments() == [] and list(repo.baseline_counts(row["id"])) == []

    monkeypatch.setattr(repo_module, "write_txn", real)
    row = _building_with_rows(repo, 50)
    statements.clear()
    monkeypatch.setattr(repo_module, "write_txn", Counting)
    assert repo.begin_baseline_segment(row, reclaim_owner=True) == "begun"
    assert len(statements) >= 9
    assert list(repo.baseline_counts(row["id"])) == []
    assert repo.baseline_segments()[0]["status"] == "building"


def test_a_build_claimed_by_cleanup_is_not_reclaimed_by_its_owner():
    from romulus.store import repo as repo_module

    repo = _repo()
    row = _building_with_rows(repo, 3)
    with repo_module.write_txn(repo.engine) as connection:
        connection.execute(repo_module.t.baseline_segment.update().where(
            repo_module.t.baseline_segment.c.id == row["id"],
        ).values(built_by_hunt_id=repo_module.CLEANUP_OWNER))
    # A cleaner holds the row: the owner's resume must neither delete under it nor raise.
    assert repo.begin_baseline_segment(row, reclaim_owner=True) == "building_elsewhere"
    assert len(list(repo.baseline_counts(row["id"]))) == 3


@pytest.mark.slow
def test_cleanup_of_a_million_row_crashed_build_never_holds_the_write_lock_for_a_second(tmp_path):
    path = tmp_path / "cleanup.db"
    repo, other = _repo(path), Repo(make_engine(path))
    row = _building_with_rows(repo, 1_000_000)
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
    try:
        started = time.perf_counter()
        removed = repo.cleanup_baseline_building(before=START + timedelta(days=1))
        elapsed = time.perf_counter() - started
    finally:
        stopped.set()
        thread.join(timeout=35)
    print(f"cleanup of a crashed million-row build {elapsed:.1f}s; concurrent max wait {max(waits):.3f}s")
    assert removed == 1 and list(repo.baseline_counts(row["id"])) == []
    assert waits and max(waits) < 1


def test_work_beyond_the_target_hour_cap_is_returned_as_gaps(monkeypatch):
    from romulus.baseline import lookback as module

    monkeypatch.setattr(module, "MAX_WORK_ITEMS", 5)
    repo, source = _repo(), FakeHistory()
    result = _writer(repo, source).fill(
        hunt_id="build", targets=["b", "a"], start=START - timedelta(hours=4), end=START,
    )
    # Whole newest-first rounds fit the cap (two hours of both targets); the older hours are explicit gaps.
    assert result.complete == 4
    assert sorted(source.plans) == sorted(
        (target, START - timedelta(hours=offset)) for target in ("a", "b") for offset in (1, 2)
    )
    assert [(gap.target, gap.start, gap.end, gap.state) for gap in result.gaps] == [
        ("a", START - timedelta(hours=4), START - timedelta(hours=2), "omitted_budget"),
        ("b", START - timedelta(hours=4), START - timedelta(hours=2), "omitted_budget"),
    ]
    assert "target-hour cap 5" in result.gaps[0].reason


def test_event_stamped_outside_its_retrieval_hour_counts_in_that_hour_and_never_makes_a_recurring_gap():
    hour = START - timedelta(hours=1)
    # The source retrieves by its own time field; these records' typed times lie just outside the hour
    # the source returned them for (shipping delay, clock skew).
    early, late = _event(1, hour - timedelta(seconds=5)), _event(2, START + timedelta(seconds=5))

    class Skewed(FakeHistory):
        def plan(self, target, start, end, *, query_budget):
            self.plans.append((target, start))
            return HistoryPlan((HistoryPartition(target, start, end, 2, "skewed"),), 1, "complete", ())

        def fetch(self, partition, **kwargs):
            self.fetches.append(partition)
            return HistoryFetch((early, late), "complete", (), 2)

    repo = _repo()
    first = _writer(repo, Skewed()).fill(hunt_id="build", targets=["host"], start=hour, end=START)
    assert first.gaps == () and first.complete == 1
    segment = repo.baseline_segments(statuses=["active"])[0]
    rows = list(repo.baseline_counts(segment["id"]))
    # Each record counts once, in the hour it was retrieved for; its times are clamped into that hour.
    direct = KeyCounter("direct", SPEC)
    for event in (early, late):
        direct.consume(event, KeyContext())
    assert sum(row["count"] for row in rows) == sum(row["count"] for row in direct.count_rows())
    assert min(row["first_ts"] for row in rows) == hour
    assert max(row["last_ts"] for row in rows) < START
    assert {row["hour"] for row in repo.baseline_scope_hours(segment["id"])} == {hour}
    again = Skewed()
    _writer(repo, again).fill(hunt_id="build", targets=["host"], start=hour, end=START)
    assert again.plans == []


def test_an_hour_inside_a_multi_hour_segment_is_covered():
    repo, source = _repo(), FakeHistory()
    row = _writer(repo, source).segment_row(
        hunt_id="hunt", target="host", spec=SPEC, start=START - timedelta(hours=3), end=START, events_total=0,
    )
    assert repo.save_baseline_segment({**row, "status": "active"}, [], [])
    result = _writer(repo, source).fill(
        hunt_id="build", targets=["host"], start=START - timedelta(hours=4), end=START,
    )
    assert source.plans == [("host", START - timedelta(hours=4))]
    assert result.gaps == ()
