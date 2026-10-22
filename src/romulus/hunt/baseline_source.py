"""Hunt-layer adapter from source retrieval to the baseline HistorySource protocol."""
from __future__ import annotations

from datetime import datetime

from romulus.baseline.protocol import HistoryFetch, HistoryPartition
from romulus.evidence.normalize import BootIntervals, normalize_hits
from romulus.hunt.sweep import HOST_DATASETS, MIN_SPLIT, PARTITION_MAX_DOCS, plan_partitions
from romulus.sources.execute import execute
from romulus.sources.models import Completeness, Predicate, SearchIntent, Window
from romulus.sources.profile import FieldContract


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

    def plan(self, target: str, start: datetime, end: datetime) -> list[HistoryPartition]:
        contract, filters = self.contracts[target], self._filters(target)
        planned: list[HistoryPartition] = []

        def add(window: Window) -> None:
            for part, count in plan_partitions(self.client, target, contract, window, filters):
                if count > PARTITION_MAX_DOCS and (part.end - part.start) > MIN_SPLIT * 2:
                    mid = part.start + (part.end - part.start) / 2
                    add(Window(start=part.start, end=mid))
                    add(Window(start=mid, end=part.end))
                else:
                    planned.append(HistoryPartition(target, part.start, part.end, count, part.key()))

        add(Window(start=start, end=end))
        return sorted(planned, key=lambda item: (item.start, item.end, item.identity))

    def fetch(self, partition: HistoryPartition) -> HistoryFetch:
        contract = self.contracts[partition.target]
        cap = min(2_000_000, max(PARTITION_MAX_DOCS, int(partition.expected_records * 1.2) + 1000))
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
