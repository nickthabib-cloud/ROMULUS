"""Coverage reasons stay bounded however many records fail: classes with exact counts and a few example ids, stored
once, never one entry per record copied into every row."""
from __future__ import annotations

from datetime import timedelta

from romulus.baseline.count import KeyCounter
from romulus.baseline.snapshot import SnapshotPlanner
from romulus.baseline.spec import SPEC_BY_ID
from romulus.hunt.baseline_stage import _coverage_failure
from tests.test_baseline_carry_hours import PAIR, START, H, _exec, _repo, _resolve


def test_per_record_reasons_fold_into_classes_with_exact_counts_and_bounded_examples():
    from romulus.baseline.reasons import EXAMPLES, ReasonTally

    tally = ReasonTally()
    for index in range(10_000):
        tally.add(f"event-{index:05d}: parent exec in an unobserved hour")
    tally.add("count row cap 5 exceeded")

    summary = tally.summary()

    assert summary == (
        "count row cap 5 exceeded",
        ("parent exec in an unobserved hour (10000 record(s): event-00000, event-00001, event-00002, event-00003, "
         f"event-00004 and {10_000 - EXAMPLES} more)"),
    )


def test_reason_classes_are_capped_with_a_stated_remainder():
    from romulus.baseline.reasons import CLASSES, summarize

    summary = summarize(f"reason class {index:03d}" for index in range(CLASSES + 7))

    assert len(summary) == CLASSES + 1 and summary[-1] == "and 7 more reason class(es)"


def test_a_counter_holds_bounded_reasons_however_many_records_fail():
    counter = KeyCounter("cell", SPEC_BY_ID["bl.exec_path"])
    for index in range(50_000):
        counter.mark_partial(f"e{index}: process.exec_file.path is absent", START, "web01")

    assert counter.partial
    assert counter.reasons == (
        "process.exec_file.path is absent (50000 record(s): e0, e1, e2, e3, e4 and 49995 more)",)


def _history_with_failing_children(children: int):
    """Exec-pair children in one history hour whose parent was never exec'd: one unresolved reason each."""
    t = START - 2 * H
    return [_exec(f"child-{index:05d}", t + timedelta(milliseconds=index), 20_000 + index, 999, "/bin/sh",
                  serial=index) for index in range(children)]


def _reason_sizes(store, hunt_id, gaps):
    snapshot = SnapshotPlanner(store).freeze(
        hunt_id=hunt_id, window_start=START, lookback=6 * H, min_live_hours=1, site="site",
        targets=["host-index"], specs=[PAIR], history_gaps=gaps,
    )
    coverage = [snapshot["coverage"]["host-index|bl.exec_pair"]]
    gap_reasons = [gap["reason"] for gap in coverage[0]["gaps"]]
    return len(_coverage_failure(coverage, 1) or ""), max(map(len, gap_reasons), default=0), gap_reasons


def test_coverage_reasons_stay_bounded_and_flat_across_consecutive_hunts():
    events = _history_with_failing_children(3_000)
    store = _repo()
    sizes = []
    for hunt_id in ("hunt-1", "hunt-2", "hunt-3"):
        _out, _source, result = _resolve(store, hunt_id, events, [], hours=6)
        failure, gap, gap_reasons = _reason_sizes(store, hunt_id, result.gaps)
        sizes.append((failure, gap))
        assert len(result.gaps) == 1 and "(3000 record(s): " in result.gaps[0].reason
    # the reason copied into each observation row and the per-hour gap reason are short and do not grow
    assert sizes[0] == sizes[1] == sizes[2]
    assert sizes[0][0] < 400 and sizes[0][1] < 400
    assert any("3000 record(s)" in reason for reason in gap_reasons)
