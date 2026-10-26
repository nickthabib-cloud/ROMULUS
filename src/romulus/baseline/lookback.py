"""Exact, budgeted construction of immutable baseline history segments."""
from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal

from romulus.baseline.carry import (
    BEFORE_HISTORY,
    CarryHourBuilder,
    CarryInStore,
    HourParents,
    PendingResolver,
    load_carry_hour,
    save_carry_hour,
)
from romulus.baseline.count import KeyCounter
from romulus.baseline.playbook import BASELINE_PLAYBOOKS
from romulus.baseline.protocol import HistorySource
from romulus.baseline.spec import BaselineSpec, KeyContext, Pending, exec_serial
from romulus.evidence.typed import TypedEvent
from romulus.store.db import utcnow
from romulus.store.repo import BASELINE_EVENTS_BASIS, Repo

_HOUR = timedelta(hours=1)
# A normal source can produce at most 720 five-second leaves in one hour. The defensive partition cap leaves
# more than an order of magnitude of headroom; the target-hour cap bounds the returned coverage ledger itself.
MAX_WORK_ITEMS = 100_000
MAX_PARTITIONS_PER_HOUR = 10_000


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
    # partial and failed: the source did not deliver the hour. unresolved: it did, but the hour's keys cannot be
    # stated (a missing field, a parent before history, a closed bucket, a segment another hunt is building).
    state: Literal["partial", "failed", "omitted_budget", "unresolved"]
    reason: str
    spec_ids: tuple[str, ...]


@dataclass(frozen=True)
class LookbackResult:
    complete: int
    gaps: tuple[HistoryGap, ...]
    queries: int
    records: int
    max_write_seconds: float
    # kept carry hours removed after the fill: past the retention horizon, and the oldest over the disk budget
    carry_hours_pruned: int = 0
    carry_hours_trimmed: int = 0


# Carry input is kept for the longest configured lookback plus this margin, measured back from a target's newest kept
# hour: a later hunt whose window starts up to a day before that hour (a re-run, or overlapping daily hunts) still
# finds the input for its whole history. Older hours are read again when a hunt needs them.
CARRY_RETENTION_MARGIN = timedelta(hours=24)
# Estimated bytes of kept carry input across the store; over it, the oldest hours go first.
DEFAULT_CARRY_BUDGET_BYTES = 4_000_000_000


def _canonical(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


_PLAYBOOK_BY_SPEC = {playbook.spec.id: playbook for playbook in BASELINE_PLAYBOOKS}


def spec_records(spec: BaselineSpec) -> Callable[[list[TypedEvent]], list[TypedEvent]]:
    """The records one spec counts in a retrieved hour: exactly what the sweep gives the spec's playbook (its
    families, in its OS scope). Both writers count and total the same records, so a segment's events_total and
    keys do not depend on which writer read the hour."""
    playbook = _PLAYBOOK_BY_SPEC.get(spec.id)
    if playbook is None:
        return lambda events: [event for event in events if event.family in spec.families]
    return playbook().scope_partition


def exclusion_digest(keys: list[str]) -> str:
    """Canonical digest of a segment's sorted cited-key exclusions."""
    keys = sorted(set(keys))
    return "none" if not keys else hashlib.sha256(_canonical(keys).encode()).hexdigest()


def segment_content_id(*, site: str, target: str, spec: BaselineSpec, start: datetime,
                       end: datetime, normalizer: str, exclusion_digest: str,
                       excluded_keys: list[str], built_by_hunt_id: str | None = None,
                       network_digest: str | None = None,
                       origin: Literal["lookback", "hunt"] = "lookback") -> str:
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
        "origin": origin, "events_basis": BASELINE_EVENTS_BASIS,
    }
    if spec.requires_configured_networks:
        material["network_digest"] = network_digest
    return "bls-" + hashlib.sha256(_canonical(material).encode()).hexdigest()[:32]


class LookbackWriter:
    """Fill hour gaps without ever turning partial retrieval into a segment."""

    def __init__(self, repo: Repo, source: HistorySource, *, site: str,
                 specs: list[BaselineSpec], normalizer: str, budget: LookbackBudget,
                 context: KeyContext | None = None,
                 parent_carry: CarryInStore | None = None,
                 network_digest: str | None = None,
                 applicable_specs: dict[str, set[str]] | None = None,
                 clock: Callable[[], float] = time.monotonic,
                 now: Callable[[], datetime] = utcnow,
                 carry_retention: timedelta | None = None,
                 carry_budget_bytes: int = DEFAULT_CARRY_BUDGET_BYTES):
        self.repo, self.source, self.site = repo, source, site
        # the longest lookback any hunt of the site configures (default: this fill's span)
        self.carry_retention = carry_retention
        self.carry_budget_bytes = carry_budget_bytes
        self.specs = tuple(sorted(specs, key=lambda item: item.id))
        self.normalizer, self.budget = normalizer, budget
        self.context, self.clock = context or KeyContext(), clock
        self.parent_carry = parent_carry
        self.network_digest = network_digest
        self.applicable_specs = applicable_specs
        self.now = now

    def segment_row(self, *, hunt_id: str, target: str, spec: BaselineSpec,
                    start: datetime, end: datetime, events_total: int,
                    exclusion_digest: str = "none", excluded_keys: list[str] | None = None) -> dict:
        excluded_keys = sorted(set(excluded_keys or []))
        base_id = segment_content_id(
            site=self.site, target=target, spec=spec, start=start, end=end,
            normalizer=self.normalizer, exclusion_digest=exclusion_digest,
            excluded_keys=excluded_keys, built_by_hunt_id=hunt_id,
            network_digest=self.network_digest,
        )
        return {
            "id": self.repo.usable_baseline_segment_id(base_id), "site": self.site, "target": target,
            "spec_id": spec.id, "spec_version": spec.version, "key_version": spec.key_version,
            "normalizer": self.normalizer, "start": start, "end": end, "bucket": spec.bucket,
            "origin": "lookback", "source_hunt_id": None, "built_by_hunt_id": hunt_id,
            "exclusion_digest": exclusion_digest, "excluded_keys": excluded_keys, "hunted": 0,
            "network_digest": self.network_digest if spec.requires_configured_networks else None,
            "events_total": events_total, "events_basis": BASELINE_EVENTS_BASIS,
            "first_event_hour": start if events_total else None,
            "status": "building", "created_at": self.now(),
        }

    def _keeps_carry(self, target: str) -> bool:
        """Whether this target's hours matter to the parent carry: exec pairs resolve against it."""
        return self.parent_carry is not None and any(
            spec.id == "bl.exec_pair" and (self.applicable_specs is None
                                           or spec.id in self.applicable_specs.get(target, set()))
            for spec in self.specs
        )

    def _covered(self, target: str, spec: BaselineSpec, start: datetime, end: datetime) -> bool:
        """An hour is covered by any active segment containing it, hourly or wider."""
        return self.repo.baseline_segment_covers(
            site=self.site, target=target, spec_id=spec.id, spec_version=spec.version,
            key_version=spec.key_version, start=start, end=end,
            network_digest=self.network_digest if spec.requires_configured_networks else None,
        )

    def _write_segment(self, hunt_id: str, target: str, spec: BaselineSpec, start: datetime, end: datetime,
                       events_total: int, counter: KeyCounter, gaps: list[HistoryGap]) -> tuple[int, float]:
        """Write one complete hour's segment; (1 when the store holds it, longest write in seconds)."""
        excluded_keys = self.repo.baseline_exclusion_keys(
            site=self.site, target=target, spec_id=spec.id, spec_version=spec.version,
            key_version=spec.key_version, start=start, end=end,
        )
        excluded = set(excluded_keys)
        row = self.segment_row(
            hunt_id=hunt_id, target=target, spec=spec, start=start, end=end, events_total=events_total,
            exclusion_digest=exclusion_digest(excluded_keys), excluded_keys=excluded_keys,
        )
        counter.bind_segment(row["id"])
        try:
            state = self.repo.begin_baseline_segment(row, reclaim_owner=True)
            if state == "active":
                return 1, 0.0  # another hunt finished the identical segment since the cover check
            if state != "begun":
                # Never skipped silently: the hour is not in the store for this hunt yet.
                gaps.append(HistoryGap(
                    target, start, end, "unresolved",
                    f"{spec.id}: " + ("being built by another hunt" if state == "building_elsewhere"
                                      else f"segment {row['id']} is {state}"),
                    (spec.id,),
                ))
                return 0, 0.0
            seconds = self.repo.append_baseline_segment_rows(
                row["id"],
                (item for item in counter.count_rows() if item["key_digest"] not in excluded),
                counter.scope_hour_rows(),
            )
            self.repo.finalize_baseline_segment(row["id"])
            return 1, seconds
        except Exception as error:  # noqa: BLE001 - abandoned building row is recovered next run
            gaps.append(HistoryGap(
                target, start, end, "failed", f"segment build failed: {error}"[:300], (spec.id,),
            ))
            return 0, 0.0

    def fill(self, *, hunt_id: str, targets: list[str], start: datetime, end: datetime) -> LookbackResult:
        start, end = start.astimezone(UTC), end.astimezone(UTC)
        if start >= end or any((value.minute, value.second, value.microsecond) != (0, 0, 0)
                               for value in (start, end)):
            raise ValueError("lookback fill requires a nonempty hour-aligned interval")
        self.repo.cleanup_baseline_building(before=self.now() - _HOUR)
        # Hours staged by an interrupted fill hold no segment, so this fill reads them again.
        self.repo.clear_baseline_history_stage(hunt_id)
        begun = self.clock()
        queries = records = complete = 0
        longest = 0.0
        gaps: list[HistoryGap] = []
        # (target, hour) -> how many of its specs wait for post-fill resolution before the hour is complete
        waiting: dict[tuple[str, datetime], int] = {}
        hours = int((end - start) / _HOUR)
        ordered_targets = tuple(sorted(set(targets)))
        # Only whole newest-first rounds within the target-hour cap are worked. Older hours become one
        # omitted gap per target, so the returned ledger stays bounded and nothing is dropped silently.
        worked = min(hours, MAX_WORK_ITEMS // max(1, len(ordered_targets)))
        omitted = [
            HistoryGap(target, start, end - worked * _HOUR, "omitted_budget",
                       f"lookback target-hour cap {MAX_WORK_ITEMS} exceeded",
                       tuple(spec.id for spec in self.specs
                             if self.applicable_specs is None
                             or spec.id in self.applicable_specs.get(target, set())))
            for target in ordered_targets
        ] if worked < hours else []
        # One newest hour from every target before moving older: round-robin without target starvation.
        work = (
            (target, end - offset * _HOUR, end - (offset - 1) * _HOUR)
            for offset in range(1, worked + 1) for target in ordered_targets
        )
        for target, hour_start, hour_end in work:
            missing = tuple(
                spec for spec in self.specs
                if (self.applicable_specs is None
                    or spec.id in self.applicable_specs.get(target, set()))
                and not self._covered(target, spec, hour_start, hour_end)
            )
            keeps_carry = self._keeps_carry(target)
            if not missing:
                if not keeps_carry:
                    continue
                # Every spec's segments cover the hour, but its execs still belong to the parent carry, or a
                # parent exec'd before it could never be vouched for. The hour's persisted carry input feeds the
                # carry exactly as reading it would; an hour without one is read again for the carry alone.
                stored = load_carry_hour(self.repo, site=self.site, target=target, hour=hour_start,
                                         normalizer=self.normalizer)
                if stored is not None:
                    carry = self.parent_carry.for_target(target, horizon=end)
                    if carry.replay_hour(stored):
                        carry.mark_observed(hour_start, hour_end)
                    continue

            def gap(state: str, reason: str, target=target, hour_start=hour_start, hour_end=hour_end,
                    missing=missing) -> None:
                # An hour read for the carry alone leaves no spec's history short; it only stays unobserved.
                if missing:
                    gaps.append(HistoryGap(target, hour_start, hour_end, state, reason,
                                           tuple(spec.id for spec in missing)))

            if self.clock() - begun >= self.budget.seconds or queries >= self.budget.queries:
                gap("omitted_budget", "lookback query or wall-clock budget exhausted")
                continue
            try:
                planned = self.source.plan(
                    target, hour_start, hour_end, query_budget=self.budget.queries - queries,
                )
                queries += planned.query_count
            except Exception as error:  # noqa: BLE001 - source failure is a coverage fact
                queries = min(self.budget.queries, queries + 1)
                gap("failed", f"partition planning failed: {error}"[:300])
                continue
            if planned.completeness != "complete":
                gap(planned.completeness if planned.completeness in {"failed", "omitted_budget"} else "partial",
                    "; ".join(planned.reasons) or planned.completeness)
                continue
            if len(planned.partitions) > MAX_PARTITIONS_PER_HOUR:
                gap("omitted_budget", f"history partition cap {MAX_PARTITIONS_PER_HOUR} exceeded")
                continue
            if self.clock() - begun >= self.budget.seconds:
                gap("omitted_budget", "lookback wall-clock budget exhausted")
                continue
            counters = {spec.id: KeyCounter("pending", spec, span=(hour_start, hour_end)) for spec in missing}
            scopes = {spec.id: spec_records(spec) for spec in missing}
            # The horizon is the end of the history being filled: a child resolves only while observation runs
            # unbroken from its parent's exec through every later history hour.
            carry = (self.parent_carry.for_target(target, horizon=end)
                     if self.parent_carry is not None else None)
            carry_input = CarryHourBuilder((hour_start, hour_end)) if carry is not None else None
            hour_parents = HourParents()
            hour_context = KeyContext(
                pid_table=hour_parents,
                service_accounts=self.context.service_accounts,
                system_uid_range=self.context.system_uid_range,
                is_internal=self.context.is_internal,
            )
            failure: tuple[str, str] | None = None
            for partition in planned.partitions:
                if self.clock() - begun >= self.budget.seconds or queries >= self.budget.queries:
                    failure = ("omitted_budget", "lookback query or wall-clock budget exhausted")
                    break
                if records + partition.expected_records > self.budget.records:
                    failure = ("omitted_budget", "lookback record budget exhausted")
                    break
                try:
                    fetched = self.source.fetch(
                        partition, record_budget=self.budget.records - records,
                        query_budget=self.budget.queries - queries,
                        deadline=begun + self.budget.seconds,
                    )
                    queries += fetched.query_count
                except Exception as error:  # noqa: BLE001 - adapter error is a coverage fact
                    failure = ("failed", f"partition fetch failed: {error}"[:300])
                    break
                records += fetched.record_count
                if self.clock() - begun >= self.budget.seconds:
                    failure = ("omitted_budget", "lookback wall-clock budget exhausted")
                    break
                if fetched.completeness != "complete":
                    failure = (
                        fetched.completeness if fetched.completeness in {"failed", "omitted_budget"} else "partial",
                        "; ".join(fetched.reasons) or fetched.completeness,
                    )
                    break
                if fetched.record_count != partition.expected_records:
                    failure = ("partial", (
                        f"exact-count mismatch: planned {partition.expected_records}, "
                        f"received {fetched.record_count}"
                    ))
                    break
                if carry_input is not None:
                    carry_input.add(fetched.events)
                # Time, then the audit serial, orders one instant's execs (a shebang's env, then its interpreter).
                ordered_events = sorted(fetched.events, key=lambda item: (
                    item.ts, -1 if exec_serial(item) is None else exec_serial(item), item.id,
                ))
                for event in ordered_events:
                    hour_parents.add(event)
                for spec_id, counter in counters.items():
                    for event in scopes[spec_id](ordered_events):
                        counter.consume(event, hour_context)
            if failure is not None:
                # An incomplete hour feeds the carry nothing and never joins its observed ledger, so no parent
                # continuity runs through it; its records are reread by a later hunt.
                gap(failure[0], failure[1])
                continue
            # Every partition of the hour was fetched completely: its carry input is kept beside its segments and
            # fed to the carry, and the hour joins the continuity ledger before its children are resolved against
            # it. Failed, partial and budget-omitted hours never do, and so break parent continuity; neither does an
            # hour with an exec of no host, which could be any host's.
            if carry is not None and carry_input is not None:
                hour_input = carry_input.finish()
                if keeps_carry:
                    save_carry_hour(self.repo, site=self.site, target=target, hour=hour_start,
                                    normalizer=self.normalizer, carry=hour_input)
                if carry.replay_hour(hour_input):
                    carry.mark_observed(hour_start, hour_end)
            if not missing:
                continue
            # Children whose parent is not in their own hour wait for the whole fill: their parent may sit in an
            # older hour that newest-first filling has not read yet. Their hour is staged compactly and becomes a
            # segment only after every older hour has fed the carry.
            deferred: set[str] = set()
            stage_failures: list[HistoryGap] = []
            for counter in counters.values():
                if not counter.pendings or counter.partial:
                    continue
                if carry is None:
                    counter.take_pendings()
                    counter.mark_partial(BEFORE_HISTORY)
                    continue
                try:
                    self.repo.stage_baseline_history_cell(
                        hunt_id, {"target": target, "spec_id": counter.spec.id, "start": hour_start,
                                  "end": hour_end, "events_total": counter.events_counted},
                        counter.count_rows(), counter.scope_hour_rows(),
                        (asdict(pending) for pending in counter.take_pendings()),
                    )
                except Exception as error:  # noqa: BLE001 - a staging write failure is a coverage fact
                    stage_failures.append(HistoryGap(
                        target, hour_start, hour_end, "failed", f"history stage failed: {error}"[:300],
                        (counter.spec.id,),
                    ))
                    continue
                deferred.add(counter.spec.id)
            partial = tuple(sorted(spec_id for spec_id, counter in counters.items() if counter.partial))
            if partial:
                reason = "; ".join(
                    f"{spec_id}: {item}" for spec_id in partial for item in counters[spec_id].reasons
                )
                gaps.append(HistoryGap(target, hour_start, hour_end, "unresolved", reason, partial))
            gaps.extend(stage_failures)
            unstaged = {gap.spec_ids[0] for gap in stage_failures}
            built = 0
            for spec in missing:
                counter = counters[spec.id]
                if counter.partial or spec.id in deferred or spec.id in unstaged:
                    continue
                written, seconds = self._write_segment(hunt_id, target, spec, hour_start, hour_end,
                                                       counter.events_counted, counter, gaps)
                built += written
                longest = max(longest, seconds)
            if not partial and built + len(deferred) == len(missing):
                if deferred:
                    waiting[(target, hour_start)] = len(deferred)
                else:
                    complete += 1
        # Every hour the budget allowed has fed the carry: resolve the waiting children and write their hours.
        for cell in self.repo.baseline_history_cells(hunt_id):
            spec = next((item for item in self.specs if item.id == cell["spec_id"]), None)
            if spec is None or self.parent_carry is None:
                self.repo.drop_baseline_history_cell(hunt_id, cell["target"], cell["spec_id"], cell["start"])
                continue
            hour_start, hour_end = cell["start"], cell["end"]
            counter = KeyCounter("pending", spec, span=(hour_start, hour_end))
            counter.restore(
                (_count_row(row) for row in self.repo.baseline_history_rows(
                    hunt_id, cell["target"], spec.id, hour_start, "count")),
                (_scope_hour_row(row) for row in self.repo.baseline_history_rows(
                    hunt_id, cell["target"], spec.id, hour_start, "scope_hour")),
            )
            resolver = PendingResolver(self.parent_carry.for_target(cell["target"], horizon=end), spec)
            for body in self.repo.baseline_history_rows(hunt_id, cell["target"], spec.id, hour_start, "pending"):
                pending = _pending(body)
                resolution = resolver.resolve(pending)
                if resolution.reason is not None:
                    counter.mark_partial(f"{pending.event_id}: {resolution.reason}")
                else:
                    counter.add_keys(pending.ts, resolution.keys)
            written = 0
            if counter.partial:
                gaps.append(HistoryGap(
                    cell["target"], hour_start, hour_end, "unresolved",
                    "; ".join(f"{spec.id}: {item}" for item in counter.reasons), (spec.id,),
                ))
            else:
                written, seconds = self._write_segment(hunt_id, cell["target"], spec, hour_start, hour_end,
                                                       int(cell["events_total"]), counter, gaps)
                longest = max(longest, seconds)
            self.repo.drop_baseline_history_cell(hunt_id, cell["target"], spec.id, hour_start)
            key = (cell["target"], hour_start)
            if key in waiting:
                waiting[key] = waiting[key] - 1 if written else -len(self.specs)
                if waiting[key] == 0:
                    complete += 1
        pruned, trimmed = self._bound_carry(ordered_targets, end - start)
        return LookbackResult(complete, (*gaps, *omitted), queries, records, longest, pruned, trimmed)

    def _bound_carry(self, targets: tuple[str, ...], span: timedelta) -> tuple[int, int]:
        """Hold kept carry input to the retention horizon and the disk budget, after this fill has replayed what it
        needed. Each delete is a few whole hours in a short transaction (an hour's rows go with it), and a reader
        loads an hour in one transaction, so a concurrent hunt sees an hour whole or not at all and then reads it
        again, under its budget, or leaves it unobserved. Removal never changes what any hunt resolves wrongly:
        a removed hour is re-read input identical to what was kept."""
        if self.parent_carry is None:
            return 0, 0
        retention = max(span, self.carry_retention or span) + CARRY_RETENTION_MARGIN
        pruned = 0
        for target in targets:
            if not self._keeps_carry(target):
                continue
            newest = self.repo.baseline_carry_newest_hour(site=self.site, target=target)
            if newest is not None:
                pruned += self.repo.prune_baseline_carry_hours(
                    site=self.site, target=target, before=newest + _HOUR - retention,
                )[0]
        trimmed = self.repo.trim_baseline_carry(self.carry_budget_bytes)[0]
        return pruned, trimmed


def _count_row(body: dict) -> dict:
    return {**body, **{name: datetime.fromisoformat(body[name]) for name in ("bucket", "first_ts", "last_ts")}}


def _scope_hour_row(body: dict) -> dict:
    return {**body, "hour": datetime.fromisoformat(body["hour"])}


def _pending(body: dict) -> Pending:
    return Pending(**{**body, "ts": datetime.fromisoformat(body["ts"]),
                      "raw_refs": tuple(tuple(ref) for ref in body.get("raw_refs") or ())})
