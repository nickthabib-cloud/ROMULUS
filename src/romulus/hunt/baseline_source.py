"""Hunt-layer adapter from source retrieval to the baseline HistorySource protocol."""
from __future__ import annotations

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
    """Exact source adapter shared with sweep planning and normalization."""

    def __init__(self, client, contracts: dict[str, FieldContract], *,
                 boots: BootIntervals | None = None):
        self.client, self.contracts = client, contracts
        self.boots = boots or BootIntervals()

    @staticmethod
    def _filters(target: str) -> list[Predicate]:
        return ([Predicate(field="event.dataset", op="in", value=HOST_DATASETS)]
                if "host" in target else [])

    def plan(self, target: str, start: datetime, end: datetime, *, query_budget: int) -> HistoryPlan:
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

    def fetch(self, partition: HistoryPartition, *, record_budget: int | None = None) -> HistoryFetch:
        contract = self.contracts[partition.target]
        cap = min(2_000_000, max(PARTITION_MAX_DOCS, int(partition.expected_records * 1.2) + 1000))
        if record_budget is not None:
            cap = min(cap, max(0, record_budget))
        outcome = execute(self.client, SearchIntent(
            kind="raw", target=partition.target,
            window=Window(start=partition.start, end=partition.end),
            filters=self._filters(partition.target), max_records=cap, purpose="baseline lookback",
        ), contract)
        reasons = list(outcome.reasons)
        if outcome.error:
            reasons.append(outcome.error)
        if outcome.completeness == Completeness.failed:
            return HistoryFetch((), "failed", tuple(reasons or ["source fetch failed"]), outcome.returned)
        events, skips, errors = normalize_hits(outcome.records, self.boots)
        unsupported = sum(value for key, value in skips.items()
                          if key.startswith(("dataset:", "suricata event_type")))
        if errors:
            reasons.append(f"normalization_errors={len(errors)}")
        if unsupported:
            reasons.append(f"unsupported_records={unsupported}")
        if (outcome.completeness != Completeness.complete or outcome.total_relation != "eq"
                or outcome.returned != partition.expected_records or errors or unsupported):
            if outcome.returned != partition.expected_records:
                reasons.append(
                    f"exact-count mismatch: planned {partition.expected_records}, received {outcome.returned}",
                )
            return HistoryFetch(tuple(events), "partial", tuple(reasons or ["incomplete retrieval"]),
                                outcome.returned)
        return HistoryFetch(tuple(events), "complete", (), outcome.returned)
