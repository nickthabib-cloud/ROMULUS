"""Hunt-layer execution of validated, source-neutral investigator pivots."""
from __future__ import annotations

import re
from collections import deque
from datetime import UTC, datetime, timedelta
from time import perf_counter

from romulus.agent.models import EntityRef, PivotCoverage, PivotResult, PivotTimeRange
from romulus.agent.tools import (
    AuthActivityRequest,
    EntityTimelineRequest,
    IdsAlertsRequest,
    ProcessTreeRequest,
    ToolRequest,
)
from romulus.detect.registry import fresh_direct_pack
from romulus.evidence.normalize import normalize_hits
from romulus.evidence.typed import TypedEvent
from romulus.hunt.publish import publish_match
from romulus.sources.es import ElasticClient, SourceError
from romulus.sources.execute import execute
from romulus.sources.models import Completeness, Predicate, SearchIntent, SearchOutcome, Window
from romulus.sources.profile import FieldContract
from romulus.store.db import digest
from romulus.store.repo import Repo

MAX_PIVOT_RECORDS = 10_000
MAX_EVENT_SUMMARIES = 50
MAX_SUMMARY_FIELDS = 16
MAX_PIVOT_PARTITIONS = 16
MIN_PIVOT_SPLIT = timedelta(seconds=5)
HOST_TIMELINE_DATASETS = ["linux.audit", "systemd.journal", "apache.access", "apache.error"]
NETWORK_TIMELINE_DATASETS = [
    "suricata.eve.alert", "suricata.eve.flow", "suricata.eve.netflow", "suricata.eve.dns",
    "suricata.eve.http", "suricata.eve.fileinfo", "suricata.eve.tls", "suricata.eve.ssh",
]
SURICATA_ALERT_DATASET = "suricata.eve.alert"
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
_ISO_NANOS = re.compile(
    r"^(?P<base>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(?P<fraction>\d{1,9}))?"
    r"(?P<zone>Z|[+-]\d{2}:\d{2})$"
)


def _is_network(target: str, contract: FieldContract | None = None) -> bool:
    return "network" in target.lower() or bool(contract and contract.time_field == "firstPacket")


def _supports(contract: FieldContract, field: str, op: str = "eq") -> bool:
    return contract.supports(field, op)


def _event_entities(event: TypedEvent) -> list[EntityRef]:
    return [EntityRef(kind=kind, value=value, role=role) for kind, value, role in event.entities()]


def _summary(event: TypedEvent) -> dict:
    fields = {
        name: field.value
        for name, field in sorted(event.fields.items())[:MAX_SUMMARY_FIELDS]
    }
    return {
        "id": event.id, "family": event.family, "ts": event.ts.isoformat(), "host": event.host,
        "outcome": str(event.outcome), "fields": fields, "caveats": event.caveats[:5],
    }


def _is_capped(reasons: list[str]) -> bool:
    return any(reason.startswith("cap:") for reason in reasons)


def _non_cap_reasons(reasons: list[str]) -> list[str]:
    return [
        reason for reason in reasons
        if not reason.startswith(("cap:", "pivot_partition_limit:", "pivot_min_split:"))
    ]


def _source_value(source: dict, path: str):
    value = source
    for part in path.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def _datetime_ns(value: datetime) -> int | None:
    if value.tzinfo is None:
        return None
    delta = value.astimezone(UTC) - _EPOCH
    return ((delta.days * 86_400 + delta.seconds) * 1_000_000_000
            + value.astimezone(UTC).microsecond * 1_000)


def _time_ns(value: datetime | str) -> int | None:
    if isinstance(value, datetime):
        return _datetime_ns(value)
    match = _ISO_NANOS.fullmatch(str(value))
    if match:
        zone = "+00:00" if match.group("zone") == "Z" else match.group("zone")
        base = datetime.fromisoformat(match.group("base") + zone).astimezone(UTC)
        delta = base - _EPOCH
        fraction = (match.group("fraction") or "").ljust(9, "0")
        return (delta.days * 86_400 + delta.seconds) * 1_000_000_000 + int(fraction or "0")
    try:
        return _datetime_ns(datetime.fromisoformat(str(value)))
    except (TypeError, ValueError):
        return None


def _ns_text(value: int) -> str:
    seconds, nanos = divmod(value, 1_000_000_000)
    base = _EPOCH + timedelta(seconds=seconds)
    return f"{base:%Y-%m-%dT%H:%M:%S}.{nanos:09d}Z"


def _record_boundary(record: dict, contract: FieldContract) -> int | None:
    sort = record.get("_sort")
    value = sort[0] if isinstance(sort, list) and sort else None
    if not isinstance(value, str):
        value = _source_value(record.get("_source") or {}, contract.time_field)
    if value is None:
        return None
    return _time_ns(value)


def _range(start: datetime | str | int, end: datetime | str | int, reason: str, *, start_inclusive: bool = True,
           end_inclusive: bool = False) -> PivotTimeRange:
    def text(value: datetime | str | int) -> str:
        nanoseconds = value if isinstance(value, int) else _time_ns(value)
        return _ns_text(nanoseconds) if nanoseconds is not None else str(value)

    return PivotTimeRange(
        start=text(start), end=text(end),
        start_inclusive=start_inclusive,
        end_inclusive=end_inclusive, reason=reason,
    )


def _anchor_neighborhood(events: list[TypedEvent], anchor_ts: datetime | None,
                         limit: int = 4) -> list[TypedEvent]:
    if anchor_ts is None:
        return []
    return sorted(
        events, key=lambda event: (abs((event.ts - anchor_ts).total_seconds()), event.ts, event.id),
    )[:limit]


def _time_spread(events: list[TypedEvent], limit: int,
                 anchor_ts: datetime | None = None) -> list[TypedEvent]:
    ordered = sorted(events, key=lambda event: (event.ts, event.id))
    if len(ordered) <= limit:
        return ordered
    reserved = _anchor_neighborhood(ordered, anchor_ts, min(4, limit))
    chosen = {event.id: event for event in reserved}
    spread_limit = max(1, limit - len(chosen))
    if spread_limit == 1:
        spread = [ordered[0]]
    else:
        spread = [
            ordered[index * (len(ordered) - 1) // (spread_limit - 1)]
            for index in range(spread_limit)
        ]
    chosen.update({event.id: event for event in spread})
    if len(chosen) < limit:
        for event in ordered:
            chosen.setdefault(event.id, event)
            if len(chosen) == limit:
                break
    return sorted(chosen.values(), key=lambda event: (event.ts, event.id))[:limit]


def _merge_intervals(intervals: list[tuple[int, int]], start: int, end: int) -> list[tuple[int, int]]:
    merged: list[tuple[int, int]] = []
    for left, right in sorted((max(start, left), min(end, right)) for left, right in intervals):
        if left >= right:
            continue
        if merged and left <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], right))
        else:
            merged.append((left, right))
    return merged


def _uncovered(covered: list[tuple[int, int]], start: int, end: int) -> list[tuple[int, int]]:
    gaps = []
    cursor = start
    for left, right in covered:
        if cursor < left:
            gaps.append((cursor, left))
        cursor = max(cursor, right)
    if cursor < end:
        gaps.append((cursor, end))
    return gaps


def _safe_sample_interval(outcome: SearchOutcome, intent: SearchIntent,
                          contract: FieldContract) -> tuple[int, int] | None:
    """Return only the half-open interval proven exhaustive by one ordered PIT query."""
    start = _datetime_ns(intent.window.start)
    end = _datetime_ns(intent.window.end)
    if start is None or end is None:
        return None
    if outcome.completeness == Completeness.complete and not outcome.reasons:
        if (outcome.total_relation == "eq" and outcome.total is not None
                and outcome.returned == len(outcome.records) == outcome.total):
            return start, end
        return None
    if (outcome.completeness == Completeness.failed or not _is_capped(outcome.reasons)
            or _non_cap_reasons(outcome.reasons) or outcome.total_relation != "eq"
            or outcome.total is None or outcome.returned != len(outcome.records)
            or outcome.returned != intent.max_records or outcome.total <= outcome.returned):
        return None
    bounds = [boundary for record in outcome.records
              if (boundary := _record_boundary(record, contract)) is not None]
    if len(bounds) != len(outcome.records):
        return None
    if intent.order == "asc":
        boundary = min(end, max(bounds))
        return (start, boundary) if start < boundary else None
    boundary = max(start, min(bounds) + 1)
    return (boundary, end) if boundary < end else None


def _coalesce_coverage(segments: list[PivotCoverage]) -> list[PivotCoverage]:
    merged: list[PivotCoverage] = []
    for segment in sorted(segments, key=lambda item: (item.target, item.dataset or "", item.start, item.end)):
        if (merged and merged[-1].target == segment.target and merged[-1].end == segment.start
                and merged[-1].dataset == segment.dataset
                and merged[-1].status == segment.status and merged[-1].reasons == segment.reasons):
            previous = merged[-1]
            total = previous.total + segment.total if previous.total is not None and segment.total is not None else None
            merged[-1] = previous.model_copy(update={
                "end": segment.end,
                "returned": previous.returned + segment.returned,
                "total": total,
                "covered_ranges": previous.covered_ranges + segment.covered_ranges,
                "unresolved_ranges": previous.unresolved_ranges + segment.unresolved_ranges,
            })
        else:
            merged.append(segment)
    return merged


class PivotExecutor:
    """Translate accepted tools to safe intents, then normalize and directly detect results."""

    def __init__(self, repo: Repo, client: ElasticClient, hunt_id: str,
                 contracts: dict[str, FieldContract], heartbeat=None, owner_token: str | None = None):
        self.repo = repo
        self.client = client
        self.hunt_id = hunt_id
        self.contracts = contracts
        self.heartbeat = heartbeat or (lambda: None)
        self.owner_token = owner_token

    def _execute(self, intent: SearchIntent, contract: FieldContract, *, pit=None) -> SearchOutcome:
        self.heartbeat()
        outcome = (execute(self.client, intent, contract) if pit is None
                   else execute(self.client, intent, contract, pit=pit))
        self.heartbeat()
        return outcome

    def _intents(self, request: ToolRequest) -> list[SearchIntent]:
        args = request.arguments
        window = Window(start=args.start, end=args.end)
        intents: list[SearchIntent] = []
        for target, contract in self.contracts.items():
            network = _is_network(target, contract)
            filters: list[Predicate] = []
            any_of: list[list[Predicate]] = []

            if isinstance(request, EntityTimelineRequest):
                entity = args.entity
                if entity.kind == "ip" and network:
                    if not (_supports(contract, "event.dataset", "in")
                            and _supports(contract, "source.ip") and _supports(contract, "destination.ip")):
                        continue
                    filters = [Predicate(field="event.dataset", op="in", value=NETWORK_TIMELINE_DATASETS)]
                    any_of = [
                        [Predicate(field="source.ip", op="eq", value=entity.value)],
                        [Predicate(field="destination.ip", op="eq", value=entity.value)],
                    ]
                elif entity.kind == "ip" and not network:
                    if not _supports(contract, "event.dataset"):
                        continue
                    for dataset in HOST_TIMELINE_DATASETS:
                        dataset_filters = [Predicate(field="event.dataset", op="eq", value=dataset)]
                        dataset_any_of: list[list[Predicate]] = []
                        if dataset.startswith("apache."):
                            for field in ("source.ip", "destination.ip"):
                                if _supports(contract, field):
                                    dataset_any_of.append([
                                        Predicate(field=field, op="eq", value=entity.value),
                                    ])
                        intents.append(SearchIntent(
                            kind="raw", target=target, window=window,
                            filters=dataset_filters, any_of=dataset_any_of,
                            max_records=MAX_PIVOT_RECORDS,
                            purpose=f"agent:{request.tool}:{dataset}",
                        ))
                    continue
                elif (entity.kind == "host" and not network
                      and _supports(contract, "event.dataset", "in") and _supports(contract, "host.name")):
                    filters = [
                        Predicate(field="event.dataset", op="in", value=HOST_TIMELINE_DATASETS),
                        Predicate(field="host.name", op="eq", value=entity.value),
                    ]
                else:
                    continue
            elif isinstance(request, AuthActivityRequest):
                if network or not _supports(contract, "event.dataset"):
                    continue
                filters = [Predicate(field="event.dataset", op="eq", value="systemd.journal")]
                if args.entity.kind == "host":
                    if not _supports(contract, "host.name"):
                        continue
                    filters.append(Predicate(field="host.name", op="eq", value=args.entity.value))
            elif isinstance(request, ProcessTreeRequest):
                if network or not (_supports(contract, "event.dataset") and _supports(contract, "host.name")):
                    continue
                filters = [
                    Predicate(field="event.dataset", op="eq", value="linux.audit"),
                    Predicate(field="host.name", op="eq", value=args.host),
                ]
            elif isinstance(request, IdsAlertsRequest):
                if not network or not _supports(contract, "event.dataset"):
                    continue
                if args.entity.kind != "ip":
                    continue
                filters = [Predicate(field="event.dataset", op="eq", value=SURICATA_ALERT_DATASET)]
                if not (_supports(contract, "source.ip") and _supports(contract, "destination.ip")):
                    continue
                any_of = [
                    [Predicate(field="source.ip", op="eq", value=args.entity.value)],
                    [Predicate(field="destination.ip", op="eq", value=args.entity.value)],
                ]

            intents.append(SearchIntent(
                kind="raw", target=target, window=window, filters=filters, any_of=any_of,
                max_records=MAX_PIVOT_RECORDS, purpose=f"agent:{request.tool}",
            ))
        return intents

    @staticmethod
    def _intent_dataset(intent: SearchIntent) -> str | None:
        for predicate in intent.filters:
            if predicate.field == "event.dataset" and predicate.op == "eq" and isinstance(predicate.value, str):
                return predicate.value
        return None

    def _unsearchable_ip_coverage(self, request: ToolRequest) -> list[PivotCoverage]:
        if not isinstance(request, EntityTimelineRequest) or request.arguments.entity.kind != "ip":
            return []
        args = request.arguments
        unresolved: list[PivotCoverage] = []
        for target, contract in self.contracts.items():
            if _is_network(target, contract):
                continue
            if _supports(contract, "event.dataset"):
                continue
            for dataset in HOST_TIMELINE_DATASETS:
                reason = f"dataset_unsearchable:{dataset}:event.dataset predicate unavailable"
                unresolved.append(PivotCoverage(
                    target=target, dataset=dataset, start=args.start, end=args.end,
                    status="partial", reasons=[reason], returned=0, total=None,
                    unresolved_ranges=[_range(args.start, args.end, reason)],
                ))
        return unresolved

    def _execute_partitions(self, intent: SearchIntent, contract: FieldContract,
                            anchor_ts: datetime | None = None):
        """Breadth-first capped-window splitting keeps late activity represented within a fixed leaf budget."""
        pending = deque([intent])
        leaves = []
        while pending:
            current = pending.popleft()
            outcome = self._execute(current, contract)
            if _is_capped(outcome.reasons) and (current.window.end - current.window.start) > MIN_PIVOT_SPLIT * 2:
                projected_leaves = len(leaves) + len(pending) + 2
                if projected_leaves <= MAX_PIVOT_PARTITIONS:
                    midpoint = current.window.start + (current.window.end - current.window.start) / 2
                    pending.append(current.model_copy(update={
                        "window": Window(start=current.window.start, end=midpoint),
                    }))
                    pending.append(current.model_copy(update={
                        "window": Window(start=midpoint, end=current.window.end),
                    }))
                    continue
                outcome = outcome.model_copy(update={
                    "reasons": sorted(set(outcome.reasons + [f"pivot_partition_limit:{MAX_PIVOT_PARTITIONS}"])),
                })
            elif _is_capped(outcome.reasons):
                outcome = outcome.model_copy(update={
                    "reasons": sorted(set(outcome.reasons + [f"pivot_min_split:{int(MIN_PIVOT_SPLIT.total_seconds())}s"])),
                })
            if _is_capped(outcome.reasons):
                outcome, covered_ranges, unresolved_ranges = self._sample_terminal(
                    current, outcome, contract, anchor_ts,
                )
            elif outcome.completeness == Completeness.complete:
                covered_ranges = [_range(
                    current.window.start, current.window.end, "source retrieval complete",
                )]
                unresolved_ranges = []
            else:
                covered_ranges = []
                unresolved_ranges = [_range(
                    current.window.start, current.window.end,
                    "; ".join(outcome.reasons or [outcome.error or "source retrieval incomplete"]),
                )]
            leaves.append((current, outcome, covered_ranges, unresolved_ranges))
        return leaves

    def _sample_terminal(self, intent: SearchIntent, initial: SearchOutcome,
                         contract: FieldContract, anchor_ts: datetime | None):
        """Sample a dense leaf in both directions and around its anchor on one PIT snapshot."""
        planning_reasons = [
            reason for reason in initial.reasons
            if reason.startswith(("pivot_partition_limit:", "pivot_min_split:"))
        ]
        attempts: list[tuple[SearchIntent, SearchOutcome]] = []
        anchor_sampled = False
        try:
            with self.client.point_in_time(intent.target) as pit:
                head_intent = intent.model_copy(update={"order": "asc"})
                head = self._execute(head_intent, contract, pit=pit)
                attempts.append((head_intent, head))
                if (head.completeness == Completeness.complete and not head.reasons
                        and _safe_sample_interval(head, head_intent, contract) is not None):
                    return head, [_range(
                        intent.window.start, intent.window.end,
                        "shared-PIT ascending retrieval completed the full attempted range",
                    )], []

                tail_intent = intent.model_copy(update={"order": "desc"})
                tail = self._execute(tail_intent, contract, pit=pit)
                attempts.append((tail_intent, tail))
                if (tail.completeness == Completeness.complete and not tail.reasons
                        and _safe_sample_interval(tail, tail_intent, contract) is not None):
                    return tail, [_range(
                        intent.window.start, intent.window.end,
                        "shared-PIT descending retrieval completed the full attempted range",
                    )], []

                if (anchor_ts is not None
                        and intent.window.start < anchor_ts < intent.window.end):
                    anchor_sampled = True
                    before = intent.model_copy(update={
                        "window": Window(start=intent.window.start, end=anchor_ts),
                        "order": "desc",
                    })
                    after = intent.model_copy(update={
                        "window": Window(start=anchor_ts, end=intent.window.end),
                        "order": "asc",
                    })
                    attempts.append((before, self._execute(before, contract, pit=pit)))
                    attempts.append((after, self._execute(after, contract, pit=pit)))
        except SourceError as exc:
            reasons = sorted(set(initial.reasons + planning_reasons + [
                "pivot_shared_pit_error", "source_error",
            ]))
            fallback = initial.model_copy(update={
                "reasons": reasons,
                "error": initial.error or str(exc),
            })
            interval = _safe_sample_interval(initial, intent, contract)
            covered_intervals = [] if interval is None else [interval]
            start = _datetime_ns(intent.window.start)
            end = _datetime_ns(intent.window.end)
            covered = [_range(left, right, "ascending retrieval established this half-open range")
                       for left, right in covered_intervals]
            unresolved = [] if start is None or end is None else [
                _range(left, right, "shared PIT could not be opened; remaining range is unresolved")
                for left, right in _uncovered(covered_intervals, start, end)
            ]
            return fallback, covered, unresolved

        records = {}
        for _sample_intent, outcome in attempts:
            for record in outcome.records:
                index_id = (record.get("_index"), record.get("_id"))
                key = index_id if all(index_id) else ("__missing_record_identity__", len(records))
                records[key] = record
        unique_records = list(records.values())

        full_outcomes = [outcome for sample_intent, outcome in attempts
                         if sample_intent.window == intent.window]
        exact_totals = {
            outcome.total for outcome in full_outcomes
            if (outcome.completeness != Completeness.failed
                and outcome.total is not None and outcome.total_relation == "eq"
                and not _non_cap_reasons(outcome.reasons)
                and outcome.returned == len(outcome.records))
        }
        totals_match = len(exact_totals) <= 1
        total = next(iter(exact_totals)) if len(exact_totals) == 1 else None
        full_non_cap = {
            reason for outcome in full_outcomes for reason in _non_cap_reasons(outcome.reasons)
        }
        if (total is not None and totals_match and len(unique_records) == total
                and not full_non_cap):
            complete = full_outcomes[0].model_copy(update={
                "completeness": Completeness.complete,
                "reasons": [],
                "total": total,
                "total_relation": "eq",
                "returned": len(unique_records),
                "records": unique_records,
                "error": None,
            })
            return complete, [_range(
                intent.window.start, intent.window.end,
                "shared-PIT samples retrieved every record in the exact total",
            )], []

        source_reasons = [reason for _sample_intent, outcome in attempts for reason in outcome.reasons]
        reasons = source_reasons + planning_reasons + ["pivot_head_tail_sample"]
        if anchor_sampled:
            reasons.append("pivot_anchor_sample")
        if not totals_match:
            reasons.append("head_tail_total_mismatch")
        errors = [outcome.error for _sample_intent, outcome in attempts if outcome.error]
        all_failed = all(outcome.completeness == Completeness.failed
                         for _sample_intent, outcome in attempts)
        combined = full_outcomes[0].model_copy(update={
            "completeness": Completeness.failed if all_failed else Completeness.partial,
            "reasons": sorted(set(reasons)),
            "total": total,
            "total_relation": "eq" if total is not None else "unknown",
            "returned": len(unique_records),
            "records": unique_records,
            "error": errors[0] if errors else None,
        })

        start = _datetime_ns(intent.window.start)
        end = _datetime_ns(intent.window.end)
        if start is None or end is None:
            return combined, [], [_range(
                intent.window.start, intent.window.end,
                "attempted range could not be represented at nanosecond precision",
            )]
        intervals = [
            interval for sample_intent, outcome in attempts
            if (interval := _safe_sample_interval(outcome, sample_intent, contract)) is not None
        ]
        covered_intervals = _merge_intervals(intervals, start, end)
        if covered_intervals == [(start, end)]:
            covered_intervals = []
            reasons.append("coverage_count_inconsistency")
            combined = combined.model_copy(update={"reasons": sorted(set(reasons))})
        unresolved_intervals = _uncovered(covered_intervals, start, end)
        covered = [
            _range(left, right, "shared-PIT ordered retrieval established this half-open range")
            for left, right in covered_intervals
        ]
        unresolved_reason = "; ".join(sorted(set(reasons))) or "retrieval incomplete"
        unresolved = [
            _range(left, right, unresolved_reason)
            for left, right in unresolved_intervals
        ]
        return combined, covered, unresolved

    @staticmethod
    def _retain(request: ToolRequest, event: TypedEvent) -> bool:
        args = request.arguments
        if isinstance(request, EntityTimelineRequest):
            entity = args.entity
            return any(item.kind == entity.kind and item.value == entity.value for item in _event_entities(event))
        if isinstance(request, AuthActivityRequest):
            if event.family not in {"auth", "privilege_use"}:
                return False
            entity = args.entity
            return (event.host == entity.value if entity.kind == "host" else
                    any(item.kind == "account" and item.value == entity.value for item in _event_entities(event)))
        if isinstance(request, ProcessTreeRequest):
            return (event.family == "process_exec" and event.host == args.host
                    and args.process_id in {event.get("process.pid"), event.get("process.ppid")})
        if isinstance(request, IdsAlertsRequest):
            if event.family != "net_alert":
                return False
            entity = args.entity
            return (event.host == entity.value if entity.kind == "host" else
                    any(item.kind == "ip" and item.value == entity.value for item in _event_entities(event)))
        return False

    def run(self, case_id: str, request: ToolRequest, *,
            anchor_ts: datetime | None = None) -> PivotResult:
        started = perf_counter()
        if anchor_ts is not None:
            if anchor_ts.tzinfo is None:
                raise ValueError("pivot anchor must be timezone-aware")
            anchor_ts = anchor_ts.astimezone(UTC)
        if isinstance(request, IdsAlertsRequest) and request.arguments.entity.kind != "ip":
            return PivotResult(status="unsupported", reasons=[
                "ids_alerts requires an IP entity; network host.name identifies the observer sensor",
            ])
        intents = self._intents(request)
        planning_coverage = self._unsearchable_ip_coverage(request)
        if not intents:
            if planning_coverage:
                return PivotResult(
                    status="partial", coverage=planning_coverage,
                    reasons=sorted({reason for cell in planning_coverage for reason in cell.reasons}),
                )
            return PivotResult(status="unsupported", reasons=["no compatible source contract"])

        task_ids: list[str] = []
        retained: list[TypedEvent] = []
        raw_sources: dict[str, dict] = {}
        reasons: list[str] = [reason for cell in planning_coverage for reason in cell.reasons]
        coverage: list[PivotCoverage] = list(planning_coverage)
        successful_outcomes = 0
        incomplete = bool(planning_coverage)

        for intent in intents:
            fingerprint = digest({
                "case_id": case_id,
                "tool": request.model_dump(mode="json"),
                "intent": intent.model_dump(mode="json"),
                "anchor_ts": anchor_ts.isoformat() if anchor_ts is not None else None,
            })
            task_id = "t-" + fingerprint[:20]
            task_ids.append(task_id)
            task_input = intent.model_dump(mode="json")
            task_input["anchor_ts"] = anchor_ts.isoformat() if anchor_ts is not None else None
            self.repo.upsert_task(
                task_id, self.hunt_id, "pivot", case_id, task_input, fingerprint,
                owner_token=self.owner_token,
            )
            self.repo.update_task(task_id, "leased", attempt=True, owner_token=self.owner_token)
            target_coverage: list[PivotCoverage] = []
            target_reasons: list[str] = []
            target_total = 0
            target_total_known = True
            target_returned = 0
            target_error = None
            target_successes = 0
            for leaf_intent, outcome, covered_ranges, unresolved_ranges in self._execute_partitions(
                    intent, self.contracts[intent.target], anchor_ts):
                leaf_reasons = list(outcome.reasons)
                if outcome.completeness == Completeness.failed:
                    incomplete = True
                    target_error = target_error or outcome.error
                    leaf_reasons.extend(outcome.reasons or [outcome.error or "source execution failed"])
                    status = "failed"
                    errors = []
                    selected = []
                    sources = {}
                else:
                    successful_outcomes += 1
                    target_successes += 1
                    events, _skips, errors = normalize_hits(outcome.records)
                    if errors:
                        leaf_reasons.append(f"normalization_errors:{len(errors)}")
                        covered_ranges = []
                        unresolved_ranges = [_range(
                            leaf_intent.window.start, leaf_intent.window.end,
                            f"normalization_errors:{len(errors)}",
                        )]
                    selected = [event for event in events if self._retain(request, event)]
                    sources = {
                        f"{record['_index']}/{record['_id']}": record["_source"]
                        for record in outcome.records
                    }
                    raw_sources.update(sources)
                    self.repo.save_evidence(
                        self.hunt_id, selected, sources, task_id, owner_token=self.owner_token,
                    )
                    retained.extend(selected)
                    status = "complete" if outcome.completeness == Completeness.complete and not errors else "partial"
                incomplete |= status != "complete"
                reasons.extend(leaf_reasons)
                target_reasons.extend(leaf_reasons)
                target_returned += outcome.returned
                if outcome.total is None:
                    target_total_known = False
                else:
                    target_total += outcome.total
                target_coverage.append(PivotCoverage(
                    target=intent.target,
                    dataset=self._intent_dataset(intent),
                    start=leaf_intent.window.start.astimezone(UTC),
                    end=leaf_intent.window.end.astimezone(UTC),
                    status=status, reasons=sorted(set(leaf_reasons)), returned=outcome.returned,
                    total=outcome.total, covered_ranges=covered_ranges,
                    unresolved_ranges=unresolved_ranges,
                ))

            target_coverage = _coalesce_coverage(target_coverage)
            coverage.extend(target_coverage)
            outcome_digest = {
                "completeness": "failed" if target_successes == 0 else (
                    "partial" if any(segment.status != "complete" for segment in target_coverage) else "complete"
                ),
                "reasons": sorted(set(target_reasons)),
                "total": target_total if target_total_known else None,
                "returned": target_returned,
                "coverage": [segment.model_dump(mode="json") for segment in target_coverage],
            }
            if target_successes == 0:
                self.repo.update_task(
                    task_id, "failed", outcome=outcome_digest, error=target_error,
                    owner_token=self.owner_token,
                )
                continue
            self.repo.update_task(
                task_id, "executed", outcome=outcome_digest, owner_token=self.owner_token,
            )
            self.repo.update_task(task_id, "evaluated", owner_token=self.owner_token)

        candidate_ids: list[str] = []
        for playbook in fresh_direct_pack():
            for match in playbook.consume(retained):
                row = publish_match(
                    self.repo, self.hunt_id, playbook, match, task_ids[0] if task_ids else None,
                    raw_sources, source_case_id=case_id, owner_token=self.owner_token,
                )
                if row is not None:
                    candidate_ids.append(row["id"])

        unique_events = {event.id: event for event in retained}
        anchor_events = _anchor_neighborhood(list(unique_events.values()), anchor_ts)
        sampled_events = _time_spread(
            list(unique_events.values()), MAX_EVENT_SUMMARIES, anchor_ts,
        )
        unique_entities = {
            (entity.kind, entity.value, entity.role): entity
            for event in unique_events.values() for entity in _event_entities(event)
        }
        if successful_outcomes == 0:
            status = "failed"
        elif incomplete:
            status = "partial"
        else:
            status = "complete"
        duration_ms = int((perf_counter() - started) * 1000)
        return PivotResult(
            status=status,
            task_ids=task_ids,
            event_ids=[event.id for event in sampled_events],
            candidate_ids=candidate_ids,
            entities=list(unique_entities.values()),
            event_summaries=[_summary(event) for event in sampled_events],
            anchor_event_ids=[event.id for event in anchor_events],
            matched_event_count=len(unique_events),
            coverage=_coalesce_coverage(coverage),
            reasons=sorted(set(reasons)),
            duration_ms=duration_ms,
        )
