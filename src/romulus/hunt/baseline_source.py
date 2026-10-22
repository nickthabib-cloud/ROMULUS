"""Hunt-layer adapter from source retrieval to the baseline HistorySource protocol."""
from __future__ import annotations

import time
from collections.abc import Callable
from datetime import datetime

from romulus.baseline.protocol import HistoryFetch, HistoryPartition, HistoryPlan
from romulus.evidence.normalize import BootIntervals, normalize_hits
from romulus.hunt.sweep import HOST_DATASETS, MIN_SPLIT, PARTITION_MAX_DOCS, plan_partitions
from romulus.sources.execute import execute
from romulus.sources.models import Completeness, Predicate, SearchIntent, Window
from romulus.sources.profile import FieldContract

# A recursively split hour has at most 720 five-second leaves under sweep's current minimum. This defensive
# ceiling leaves ample headroom if that physical planner changes while preventing hostile plan materialization.
MAX_HISTORY_PARTITIONS = 10_000


class HuntHistorySource:
    """Exact source adapter shared with sweep planning and normalization.

    Boot placement uses one boot-interval map per planned hour, never one map across the lookback. History is
    read newest-first and a segment is written as soon as its hour completes, so a map shared across hours
    would let an older hour's records re-place (or refuse) boots already placed in a newer hour whose segment
    is written. With a map per hour, an event's boot rests only on records of its own hour; an event the hour
    cannot place keeps an unknown boot (never guessed). When a later partition of the same hour refuses a
    placement made from an earlier one (a sweep conflict), the hour's fetch is partial, so no segment is built
    from the hour.
    """

    def __init__(self, client, contracts: dict[str, FieldContract], *,
                 boots: Callable[[], BootIntervals] = BootIntervals,
                 clock: Callable[[], float] = time.monotonic):
        self.client, self.contracts = client, contracts
        self._new_boots = boots
        self.boots = boots()
        self.clock = clock

    @staticmethod
    def _filters(target: str) -> list[Predicate]:
        return ([Predicate(field="event.dataset", op="in", value=HOST_DATASETS)]
                if "host" in target else [])

    def plan(self, target: str, start: datetime, end: datetime, *, query_budget: int) -> HistoryPlan:
        # Every hour is planned before its partitions are fetched: start this hour's boot map.
        self.boots = self._new_boots()
        contract, filters = self.contracts[target], self._filters(target)
        planned: list[HistoryPartition] = []
        queries = 0

        class _BudgetExhausted(Exception):
            pass

        class _PartitionCapExceeded(Exception):
            pass

        def add(window: Window) -> None:
            nonlocal queries
            if queries >= query_budget:
                raise _BudgetExhausted
            queries += 1
            for part, count in plan_partitions(self.client, target, contract, window, filters):
                if count > PARTITION_MAX_DOCS and (part.end - part.start) > MIN_SPLIT * 2:
                    mid = part.start + (part.end - part.start) / 2
                    add(Window(start=part.start, end=mid))
                    add(Window(start=mid, end=part.end))
                else:
                    if len(planned) >= MAX_HISTORY_PARTITIONS:
                        raise _PartitionCapExceeded
                    planned.append(HistoryPartition(target, part.start, part.end, count, part.key()))

        try:
            add(Window(start=start, end=end))
        except _BudgetExhausted:
            return HistoryPlan((), queries, "partial", ("planning query budget exhausted",))
        except _PartitionCapExceeded:
            return HistoryPlan((), queries, "partial", (
                f"history partition cap {MAX_HISTORY_PARTITIONS} exceeded",
            ))
        except Exception as error:  # noqa: BLE001 - a source planning error is an explicit coverage result
            return HistoryPlan((), queries, "failed", (f"partition planning failed: {error}"[:300],))
        return HistoryPlan(
            tuple(sorted(planned, key=lambda item: (item.start, item.end, item.identity))),
            queries, "complete", (),
        )

    def fetch(self, partition: HistoryPartition, *, record_budget: int | None = None,
              query_budget: int | None = None, deadline: float | None = None) -> HistoryFetch:
        if partition.expected_records == 0:
            return HistoryFetch((), "complete", (), 0, 0)
        if record_budget is not None and record_budget < partition.expected_records:
            return HistoryFetch((), "partial", ("lookback record budget exhausted",), 0, 0)
        contract = self.contracts[partition.target]
        cap = min(2_000_000, max(PARTITION_MAX_DOCS, int(partition.expected_records * 1.2) + 1000))
        if record_budget is not None:
            cap = min(cap, max(0, record_budget))
        queries = 0

        def reserve_query() -> bool:
            nonlocal queries
            if query_budget is not None and queries >= query_budget:
                return False
            queries += 1
            return True

        outcome = execute(self.client, SearchIntent(
            kind="raw", target=partition.target,
            window=Window(start=partition.start, end=partition.end),
            filters=self._filters(partition.target), max_records=cap, purpose="baseline lookback",
        ), contract, on_query=reserve_query, deadline=deadline, clock=self.clock)
        reasons = list(outcome.reasons)
        if outcome.error:
            reasons.append(outcome.error)
        if outcome.completeness == Completeness.failed:
            return HistoryFetch(
                (), "failed", tuple(reasons or ["source fetch failed"]), outcome.returned, queries,
            )
        events, skips, errors = normalize_hits(outcome.records, self.boots)
        unsupported = sum(value for key, value in skips.items()
                          if key.startswith(("dataset:", "suricata event_type")))
        if errors:
            reasons.append(f"normalization_errors={len(errors)}")
        if unsupported:
            reasons.append(f"unsupported_records={unsupported}")
        conflicted = sorted(self.boots.conflicts)
        if conflicted:
            reasons.append(f"boot placement conflict on {len(conflicted)} host(s): {', '.join(conflicted[:5])}")
        if (outcome.completeness != Completeness.complete or outcome.total_relation != "eq"
                or outcome.returned != partition.expected_records or errors or unsupported or conflicted):
            if outcome.returned != partition.expected_records:
                reasons.append(
                    f"exact-count mismatch: planned {partition.expected_records}, received {outcome.returned}",
                )
            return HistoryFetch(tuple(events), "partial", tuple(reasons or ["incomplete retrieval"]),
                                outcome.returned, queries)
        return HistoryFetch(tuple(events), "complete", (), outcome.returned, queries)
