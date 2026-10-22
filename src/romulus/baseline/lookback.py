"""Exact, budgeted construction of immutable baseline history segments."""
from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal

from romulus.baseline.carry import CarryInStore
from romulus.baseline.count import KeyCounter
from romulus.baseline.protocol import HistorySource
from romulus.baseline.spec import BaselineSpec, KeyContext
from romulus.store.repo import Repo

_HOUR = timedelta(hours=1)


@dataclass(frozen=True)
class LookbackBudget:
    """Hard per-run bounds; defaults are supplied by the hunt manifest in S5."""

    queries: int
    records: int
    seconds: float

    def __post_init__(self) -> None:
        if self.queries < 1 or self.records < 0 or self.seconds <= 0:
            raise ValueError("lookback budgets require queries>0, records>=0 and seconds>0")


@dataclass(frozen=True)
class HistoryGap:
    target: str
    start: datetime
    end: datetime
    state: Literal["partial", "failed", "omitted_budget"]
    reason: str
    spec_ids: tuple[str, ...]


@dataclass(frozen=True)
class LookbackResult:
    complete: int
    gaps: tuple[HistoryGap, ...]
    queries: int
    records: int
    max_write_seconds: float


def _canonical(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def segment_content_id(*, site: str, target: str, spec: BaselineSpec, start: datetime,
                       end: datetime, normalizer: str, exclusion_digest: str,
                       excluded_keys: list[str], built_by_hunt_id: str | None = None) -> str:
    """Stable base id; build ownership is provenance, and exclusion order carries no meaning.

    A permanently revoked base id is advanced by ``Repo.usable_baseline_segment_id`` to ``-rN``. That suffix
    is the only state-derived part of identity and prevents a revoked row from creating a permanent hole.
    """
    del built_by_hunt_id
    material = {
        "site": site, "target": target, "spec_id": spec.id, "spec_version": spec.version,
        "key_version": spec.key_version, "start": start.astimezone(UTC).isoformat(),
        "end": end.astimezone(UTC).isoformat(), "bucket": spec.bucket, "normalizer": normalizer,
        "exclusion_digest": exclusion_digest, "excluded_keys": sorted(set(excluded_keys)),
        "origin": "lookback",
    }
    return "bls-" + hashlib.sha256(_canonical(material).encode()).hexdigest()[:32]


class LookbackWriter:
    """Fill hour gaps without ever turning partial retrieval into a segment."""

    def __init__(self, repo: Repo, source: HistorySource, *, site: str,
                 specs: list[BaselineSpec], normalizer: str, budget: LookbackBudget,
                 context: KeyContext | None = None,
                 parent_carry: CarryInStore | None = None,
                 clock: Callable[[], float] = time.monotonic):
        self.repo, self.source, self.site = repo, source, site
        self.specs = tuple(sorted(specs, key=lambda item: item.id))
        self.normalizer, self.budget = normalizer, budget
        self.context, self.clock = context or KeyContext(), clock
        self.parent_carry = parent_carry

    def segment_row(self, *, hunt_id: str, target: str, spec: BaselineSpec,
                    start: datetime, end: datetime, events_total: int,
                    exclusion_digest: str = "none", excluded_keys: list[str] | None = None) -> dict:
        excluded_keys = sorted(set(excluded_keys or []))
        base_id = segment_content_id(
            site=self.site, target=target, spec=spec, start=start, end=end,
            normalizer=self.normalizer, exclusion_digest=exclusion_digest,
            excluded_keys=excluded_keys, built_by_hunt_id=hunt_id,
        )
        return {
            "id": self.repo.usable_baseline_segment_id(base_id), "site": self.site, "target": target,
            "spec_id": spec.id, "spec_version": spec.version, "key_version": spec.key_version,
            "normalizer": self.normalizer, "start": start, "end": end, "bucket": spec.bucket,
            "origin": "lookback", "source_hunt_id": None, "built_by_hunt_id": hunt_id,
            "exclusion_digest": exclusion_digest, "excluded_keys": excluded_keys, "hunted": 0,
            "events_total": events_total, "status": "building", "created_at": start,
        }

    def _covered(self, target: str, spec: BaselineSpec, start: datetime, end: datetime) -> bool:
        return bool(self.repo.baseline_segments_for_cover(
            site=self.site, target=target, spec_id=spec.id, spec_version=spec.version,
            key_version=spec.key_version, start=start, end=end,
        ))

    def fill(self, *, hunt_id: str, targets: list[str], start: datetime, end: datetime) -> LookbackResult:
        start, end = start.astimezone(UTC), end.astimezone(UTC)
        if start >= end or any((value.minute, value.second, value.microsecond) != (0, 0, 0)
                               for value in (start, end)):
            raise ValueError("lookback fill requires a nonempty hour-aligned interval")
        self.repo.cleanup_baseline_building(before=end)
        begun = self.clock()
        queries = records = complete = 0
        longest = 0.0
        gaps: list[HistoryGap] = []
        hours = int((end - start) / _HOUR)
        # One newest hour from every target before moving older: round-robin without target starvation.
        work = [(target, end - offset * _HOUR, end - (offset - 1) * _HOUR)
                for offset in range(1, hours + 1) for target in sorted(set(targets))]
        for target, hour_start, hour_end in work:
            missing = tuple(spec for spec in self.specs if not self._covered(target, spec, hour_start, hour_end))
            if not missing:
                continue
            if self.clock() - begun >= self.budget.seconds or queries >= self.budget.queries:
                gaps.append(HistoryGap(
                    target, hour_start, hour_end, "omitted_budget", "lookback query or wall-clock budget exhausted",
                    tuple(spec.id for spec in missing),
                ))
                continue
            try:
                partitions = list(self.source.plan(target, hour_start, hour_end))
                queries += 1
            except Exception as error:  # noqa: BLE001 - source failure is a coverage fact
                gaps.append(HistoryGap(
                    target, hour_start, hour_end, "failed", f"partition planning failed: {error}"[:300],
                    tuple(spec.id for spec in missing),
                ))
                continue
            counters = {spec.id: KeyCounter("pending", spec) for spec in missing}
            events_total = 0
            failure: tuple[str, str] | None = None
            for partition in sorted(partitions, key=lambda item: (item.start, item.end, item.identity)):
                if self.clock() - begun >= self.budget.seconds or queries >= self.budget.queries:
                    failure = ("omitted_budget", "lookback query or wall-clock budget exhausted")
                    break
                try:
                    fetched = self.source.fetch(partition)
                    queries += 1
                except Exception as error:  # noqa: BLE001 - adapter error is a coverage fact
                    failure = ("failed", f"partition fetch failed: {error}"[:300])
                    break
                if fetched.completeness != "complete":
                    failure = (
                        "failed" if fetched.completeness == "failed" else "partial",
                        "; ".join(fetched.reasons) or fetched.completeness,
                    )
                    break
                if fetched.record_count != partition.expected_records:
                    failure = ("partial", (
                        f"exact-count mismatch: planned {partition.expected_records}, "
                        f"received {fetched.record_count}"
                    ))
                    break
                if records + fetched.record_count > self.budget.records:
                    failure = ("omitted_budget", "lookback record budget exhausted")
                    break
                records += fetched.record_count
                events_total += len(fetched.events)
                if self.parent_carry is not None:
                    self.parent_carry.observe_events(fetched.events)
                for event in sorted(fetched.events, key=lambda item: (item.ts, item.id)):
                    for counter in counters.values():
                        counter.consume(event, self.context)
            if failure is not None:
                gaps.append(HistoryGap(
                    target, hour_start, hour_end, failure[0], failure[1], tuple(counter for counter in counters),
                ))
                continue
            partial = tuple(sorted(spec_id for spec_id, counter in counters.items() if counter.partial))
            if partial:
                reason = "; ".join(
                    f"{spec_id}: {item}" for spec_id in partial for item in counters[spec_id].reasons
                )
                gaps.append(HistoryGap(target, hour_start, hour_end, "partial", reason, partial))
            built = 0
            for spec in missing:
                counter = counters[spec.id]
                if counter.partial:
                    continue
                row = self.segment_row(
                    hunt_id=hunt_id, target=target, spec=spec, start=hour_start, end=hour_end,
                    events_total=events_total,
                )
                counter.bind_segment(row["id"])
                try:
                    if not self.repo.begin_baseline_segment(row):
                        continue
                    longest = max(longest, self.repo.append_baseline_segment_rows(
                        row["id"], counter.count_rows(), counter.scope_hour_rows(),
                    ))
                    self.repo.finalize_baseline_segment(row["id"])
                    built += 1
                except Exception as error:  # noqa: BLE001 - abandoned building row is recovered next run
                    gaps.append(HistoryGap(
                        target, hour_start, hour_end, "failed", f"segment build failed: {error}"[:300],
                        (spec.id,),
                    ))
            if built == len(missing) and not partial:
                complete += 1
        return LookbackResult(complete, tuple(gaps), queries, records, longest)
