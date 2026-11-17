"""Hunt-layer execution of validated, source-neutral investigator pivots."""
from __future__ import annotations

import difflib
import ipaddress
import json
import math
import re
import tempfile
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from functools import wraps
from pathlib import Path
from time import perf_counter

from romulus.agent.models import EntityRef, PivotCoverage, PivotResult, PivotTimeRange
from romulus.agent.refusals import reason as refusal_reason
from romulus.agent.tools import (
    MAX_SEARCH_VALUES,
    SEARCH_OPS,
    AuthActivityRequest,
    EntityTimelineRequest,
    IdsAlertsRequest,
    ProcessTreeArgs,
    ProcessTreeRequest,
    SearchCondition,
    SearchEventsRequest,
    ToolRequest,
)
from romulus.detect.bounded import StateBudget
from romulus.detect.host import ExecLineage
from romulus.detect.registry import bind_windows_site, fresh_direct_pack
from romulus.evidence.auditd import AuditParseError, AuditRecord, parse_record
from romulus.evidence.linux_catalog import (
    AUDIT_RECORD,
    LINUX_LOGICAL_DATASETS,
    LOGICAL_FAMILIES,
    logical_of,
    match_shape,
)
from romulus.evidence.normalize import (
    AUDIT_LOGIN_TYPES,
    ELASTIC_DATASET,
    audit_host,
    audit_record_of,
    is_elastic_suricata,
    normalize_hits,
)
from romulus.evidence.typed import TypedEvent
from romulus.evidence.windows import windows_identity_reasons
from romulus.evidence.windows_catalog import (
    WINDOWS_CHANNELS,
    WINDOWS_HOST_DATASETS,
    channels_for_families,
    datasets_for_families,
)
from romulus.evidence.windows_reassembly import ScriptBlockAssembler
from romulus.evidence.zeek import zeek_record
from romulus.evidence.zeek_catalog import ELASTIC, MALCOLM, SECURITY_ONION, ZEEK_LOGS
from romulus.hunt.publish import publish_match
from romulus.hunt.windows_filters import nxlog_windows_group
from romulus.site import SiteFacts, absent_site_facts
from romulus.sources.compile import (
    _CASELESS_WINDOWS_NATIVES,
    _WINDOWS_COMPUTER_NATIVES,
    CompileError,
    _intent_os_family,
    compile_es,
    time_unit,
    utf16_length,
)
from romulus.sources.es import ElasticClient, SourceError
from romulus.sources.execute import execute
from romulus.sources.models import Completeness, Predicate, SearchIntent, SearchOutcome, Window
from romulus.sources.profile import LIMITED_KINDS, FieldContract
from romulus.store.db import digest
from romulus.store.repo import AGENT_HUNT_BUDGET_CAP, AGENT_SESSION_SHARE_CAP, Repo

MAX_PIVOT_RECORDS = 10_000
MAX_EVENT_SUMMARIES = 50
MAX_SUMMARY_FIELDS = 16
MAX_PIVOT_PARTITIONS = 16
MIN_PIVOT_SPLIT = timedelta(seconds=5)
# The logical Linux datasets: a source query names them, and the compiler selects each one's shipper shapes.
HOST_TIMELINE_DATASETS = list(LINUX_LOGICAL_DATASETS)
SURICATA_TIMELINE_DATASETS = [
    "suricata.eve.alert", "suricata.eve.flow", "suricata.eve.netflow", "suricata.eve.dns",
    "suricata.eve.http", "suricata.eve.fileinfo", "suricata.eve.tls", "suricata.eve.ssh",
]
# Zeek logs as the shippers that prefix them name them in event.dataset (Elastic's zeek.<stream>, Security Onion's
# zeek.<log>), from the catalog. Malcolm's and Security Onion's bare log names collide with other datasets, so those
# rows are selected by their shipper field as well (`zeek_source_groups`).
ZEEK_LOGS_BY_TOKEN = {log.token: log for log in ZEEK_LOGS}
_PREFIXED_SHAPES = (ELASTIC, SECURITY_ONION)


def _prefixed(logs) -> list[str]:
    return sorted({f"zeek.{name}" for log in logs for shape in _PREFIXED_SHAPES for name in log.names.get(shape, ())})


ZEEK_TIMELINE_DATASETS = _prefixed(ZEEK_LOGS)
NETWORK_TIMELINE_DATASETS = [*SURICATA_TIMELINE_DATASETS, *ZEEK_TIMELINE_DATASETS]
SURICATA_ALERT_DATASET = "suricata.eve.alert"
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
_ISO_NANOS = re.compile(
    r"^(?P<base>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(?P<fraction>\d{1,9}))?"
    r"(?P<zone>Z|[+-]\d{2}:\d{2})$"
)
_SURICATA_FAMILY = {
    "alert": "net_alert",
    "flow": "net_flow",
    "netflow": "net_flow",
    "dns": "dns_query",
    "http": "http_tx",
    "fileinfo": "file_transfer",
    "tls": "tls_session",
    "ssh": "ssh_session",
}
# Each catalogued Zeek log's family, by Zeek's own log name.
_ZEEK_FAMILY = {log.name: log.family for log in ZEEK_LOGS}


def zeek_capable(contract: FieldContract) -> bool:
    """Whether the target's mapping holds fields only a Zeek shipper writes (a zeek.* object, Security Onion's
    log.id.uid, plain Zeek JSON's _path): only then does a network pivot name Zeek's datasets, so a target with
    none keeps the intents it always had."""
    return any(name.startswith("zeek.") or name in ("log.id.uid", "_path") for name in contract.fields)


def zeek_source_groups(contract: FieldContract, logs=None) -> list[list[Predicate]]:
    """Predicate groups (any one selects a record) for the rows of the given Zeek logs (all when None), one per
    shipper layout the target can be searched by: the prefixed dataset names, Malcolm's provider with bare names,
    Security Onion's module with bare names. Empty when the target can run none of them: the caller then retrieves
    without a dataset predicate and normalization decides, never a negative."""
    logs = list(ZEEK_LOGS if logs is None else logs)
    groups: list[list[Predicate]] = []
    prefixed = _prefixed(logs)
    if prefixed and _supports(contract, "event.dataset", "in"):
        groups.append([Predicate(field="event.dataset", op="in", value=prefixed)])
    if prefixed and _supports(contract, "data_stream.dataset", "in"):
        groups.append([Predicate(field="data_stream.dataset", op="in", value=prefixed)])
    for marker, value, shape in (("event.provider", "zeek", MALCOLM), ("event.module", "zeek", SECURITY_ONION)):
        bare = sorted({name for log in logs for name in log.names.get(shape, ())})
        if bare and _supports(contract, marker) and _supports(contract, "event.dataset", "in"):
            groups.append([Predicate(field=marker, op="eq", value=value),
                           Predicate(field="event.dataset", op="in", value=bare)])
    return groups


@dataclass
class PivotEventBatch:
    """Typed source results for a deterministic link fetch, before playbook evaluation."""

    status: str
    task_ids: list[str]
    events: list[TypedEvent]
    raw_sources: dict[str, dict]
    coverage: list[PivotCoverage]
    reasons: list[str]
    duration_ms: int
    task_by_event: dict[str, str] = field(default_factory=dict)


def _is_network(target: str, contract: FieldContract | None = None) -> bool:
    del target
    return bool(contract and contract.role == "network")


def _host_datasets(
    contract: FieldContract,
    families: set[str] | None = None,
    *,
    os_family: str | None = None,
) -> tuple[str, ...]:
    family = os_family or contract.os_family
    if family == "windows":
        return datasets_for_families(families) if families else WINDOWS_HOST_DATASETS
    if families:
        # every logical dataset whose records can give one of the families
        selected = set()
        for dataset, fed in LOGICAL_FAMILIES.items():
            requested = families
            # Lineage needs process identity. Text scheduler observations have no PID/PPID;
            # preserve these datasets when another requested family can contribute.
            if "process_exec" in families and dataset in {"systemd.journal", "linux.syslog", "linux.text"}:
                requested = families - {"process_observed"}
            if fed & requested:
                selected.add(dataset)
        return tuple(dataset for dataset in HOST_TIMELINE_DATASETS if dataset in selected)
    return tuple(HOST_TIMELINE_DATASETS)


def _supports(contract: FieldContract, field: str, op: str = "eq") -> bool:
    return contract.supports(field, op)


def _windows_source_groups(
    contract: FieldContract, families: set[str] | None = None,
) -> list[list[Predicate]]:
    if contract.ecar and all(contract.supports(name, "exists") for name in ("ecar.object", "ecar.action")):
        return [[Predicate(field="ecar.object", op="exists"), Predicate(field="ecar.action", op="exists")]]
    datasets = datasets_for_families(families) if families else WINDOWS_HOST_DATASETS
    channels = channels_for_families(families) if families else WINDOWS_CHANNELS
    groups: list[list[Predicate]] = []
    if datasets and _supports(contract, "event.dataset", "in"):
        groups.append([Predicate(field="event.dataset", op="in", value=list(datasets))])
    if channels and _supports(contract, "event.channel", "in"):
        groups.append([Predicate(field="event.channel", op="in", value=list(channels))])
    flat = nxlog_windows_group(contract) if datasets or channels else None
    if flat is not None:
        # NXLog's flat records name no dataset and may spell a channel in any case: selected by their shape, which
        # also selects them where neither a dataset nor a channel is searchable (Channel mapped as text alone)
        groups.append(flat)
    from romulus.hunt.windows_filters import evtx_json_windows_group

    evtx = evtx_json_windows_group(contract) if datasets or channels else None
    if evtx is not None:
        groups.append(evtx)
    return groups


def _and_any_of(left: list[list[Predicate]], right: list[list[Predicate]]) -> list[list[Predicate]]:
    """Return disjunctive normal form for (OR left) AND (OR right)."""
    if not left:
        return right
    if not right:
        return left
    return [[*a, *b] for a in left for b in right]


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


def _script_metadata_reasons(events: list[TypedEvent]) -> list[str]:
    count = sum(
        any("script block part metadata is incomplete or invalid" in caveat for caveat in event.caveats)
        for event in events
    )
    reasons = ([f"PowerShell script-block part metadata incomplete or invalid for {count} event(s)"]
               if count else [])
    reasons.extend(sorted({
        caveat for event in events if event.get("script.truncated")
        for caveat in event.caveats if "joined text capped" in caveat
    }))
    return reasons


def _with_script_blocks(method):
    @wraps(method)
    def wrapped(self, *args, **kwargs):
        settings = getattr(self.client, "settings", None)
        root = self.stage_dir or getattr(settings, "stage_path", None)
        if root is not None:
            Path(root).mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="romulus-pivot-scripts-", dir=root) as directory:
            budget = StateBudget(
                directory, disk_total=int(getattr(settings, "state_disk_gb", 0) * 2**30) or None,
                reserve_floor=int(getattr(settings, "state_disk_reserve_gb", 2) * 2**30),
            )
            assembler = self._script_blocks = ScriptBlockAssembler(directory, budget=budget)
            try:
                return method(self, *args, **kwargs)
            finally:
                assembler.close()
                del self._script_blocks
    return wrapped


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


def _raw_identity(record: dict) -> tuple[str, str]:
    return str(record.get("_index", "")), str(record.get("_id", ""))


class _AuditParses:
    """Each audit record's parse, made once and shared by every step of one pivot leaf that reads it (grouping, the
    raw-family prefilter, normalization). Keyed by the record object, so it lives only as long as the leaf's
    records: one instance per `_normalize_pivot_records` call, never shared between leaves."""

    def __init__(self) -> None:
        self._by_record: dict[int, AuditRecord | AuditParseError] = {}

    def __call__(self, record: dict, raw: str) -> AuditRecord:
        found = self._by_record.get(id(record))
        if found is None:
            try:
                found = parse_record(raw)
            except AuditParseError as error:
                found = error
            self._by_record[id(record)] = found
        if isinstance(found, AuditParseError):
            raise type(found)(*found.args)
        return found


def _logical_inventory(datasets) -> set[str]:
    """An inventory's dataset names, each Linux shipper name replaced by its logical dataset."""
    return {logical_of(str(name)) or str(name) for name in datasets}


def _audit_identity(record: dict, parse: _AuditParses | None = None) -> tuple | None:
    """Return an audit event identity only when its authoritative record parses (a raw line, or a record a shipper
    parsed into fields). An Auditbeat event document is an event by itself and has none."""
    source = record.get("_source") or {}
    try:
        parsed = audit_record_of(record, parse)
    except AuditParseError:
        return None
    if parsed is None:
        return None
    return (audit_host(source, parsed), parsed.ts, parsed.serial)


def _normalization_groups(records: list[dict], parse: _AuditParses | None = None) -> list[list[dict]]:
    """Keep multi-record audit events atomic; every other hit is independent."""
    groups: dict[tuple, list[dict]] = {}
    order: list[tuple] = []
    for record in records:
        audit = _audit_identity(record, parse)
        key = ("audit", *audit) if audit is not None else ("raw", *_raw_identity(record))
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(record)
    return [groups[key] for key in order]


def _audit_types(records: list[dict], parse: _AuditParses | None = None) -> set[str] | None:
    types: set[str] = set()
    for record in records:
        try:
            parsed = audit_record_of(record, parse)
        except AuditParseError:
            return None
        if parsed is None:
            return None
        types.add(parsed.type)
    return types


def _prefilter_raw(records: list[dict], families: set[str], parse: _AuditParses | None = None) -> list[dict]:
    """Discard only groups whose authoritative type cannot produce a requested family."""
    selected: list[dict] = []
    for group in _normalization_groups(records, parse):
        source = group[0].get("_source") or {}
        dataset = _source_value(source, "event.dataset") or ""
        linux = match_shape(source)
        if linux is not None and linux[1].shape == AUDIT_RECORD:
            types = _audit_types(group, parse)
            if types is None:
                selected.extend(group)
            elif ((families == {"process_exec"} and "EXECVE" not in types)
                  or (families == {"net_socket"} and "SOCKADDR" not in types)):
                continue
            else:
                selected.extend(group)
            continue
        if dataset.startswith("suricata.eve"):
            raw = _source_value(source, "event.original") or source.get("message")
            try:
                event_type = json.loads(raw or "").get("event_type")
            except (json.JSONDecodeError, AttributeError, TypeError):
                if not is_elastic_suricata(source):
                    selected.extend(group)
                    continue
                # Filebeat or the Agent indexed the parsed record without its line: its type is a parsed field
                event_type = _source_value(source, "suricata.eve.event_type")
            family = _SURICATA_FAMILY.get(event_type)
            if family is None or family in families:
                selected.extend(group)
            continue
        zeek = zeek_record(source)
        if zeek is not None and zeek.log is not None and _ZEEK_FAMILY[zeek.log.name] not in families:
            continue                    # a catalogued Zeek log of another family; anything unread stays
        selected.extend(group)
    return selected


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
    if isinstance(value, int) and not isinstance(value, bool):
        # OpenSearch returns the time sort value as the field's own epoch number
        return value if time_unit(contract) == "ns" else value * 1_000_000
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


# The most physical queries `_sample_terminal` spends on one capped leaf (head, tail, before, after).
MAX_SAMPLE_QUERIES = 4


# The AI agent's source-query caps, each stopping with its own reason so a result, the run page and the audit tell
# them apart: the hunt's total, one session's share of it, and one tool call's slice of that share.
AGENT_HUNT_BUDGET = AGENT_HUNT_BUDGET_CAP
AGENT_SESSION_SHARE = AGENT_SESSION_SHARE_CAP
AGENT_CALL_SLICE = "agent_call_source_query_slice"
# one planned source's part of what its call may still spend (the rest divided by the sources still to search)
AGENT_SOURCE_SHARE = "agent_call_source_share"
AGENT_QUERY_CAPS = (AGENT_HUNT_BUDGET, AGENT_SESSION_SHARE, AGENT_CALL_SLICE, AGENT_SOURCE_SHARE)
_AGENT_CAP_EXPLAINED = {
    AGENT_HUNT_BUDGET: "the hunt's AI-agent source-query budget is spent",
    AGENT_SESSION_SHARE: "this session's share of the hunt's source-query budget is spent",
    AGENT_CALL_SLICE: "this tool call's slice of the session's source queries is spent",
    AGENT_SOURCE_SHARE: "this source's part of the tool call's source queries is spent",
}

# A host lookup refused for budget is not an answer: it is retried when budget allows.
HOST_LOOKUP_BUDGET = "source query budget exhausted"
NO_HOST_RECORD = "no host record carries host.ip"      # a complete lookup: no host claims the address
HOST_AMBIGUOUS = "victim host ambiguous"               # a complete lookup: several hosts claim the address


def _nxlog_mixed_coverage(contracts: dict[str, FieldContract], request: ToolRequest) -> list[PivotCoverage]:
    """A Linux target that also holds NXLog's flat Windows records: pivots select its Linux datasets only (its
    contract carries no Windows names for the flat records' values), so that shape is listed as not searched."""
    args = request.arguments
    reason = ("shape_not_searched:windows.nxlog:NXLog flat Windows records on a Linux target are not selected by "
              "pivots")
    return [PivotCoverage(target=target, dataset="windows.nxlog", start=args.start, end=args.end,
                          status="partial", reasons=[reason], returned=0, total=None,
                          unresolved_ranges=[_range(args.start, args.end, reason)])
            for target, contract in contracts.items()
            if contract.nxlog_mixed and not _is_network(target, contract)]


TEXT_HOST_QUERY_REASON = "text lines may carry their host only in the syslog header"


def _text_host_coverage(contracts, dataset_inventory, intents, *, header_host=False) -> list[PivotCoverage]:
    """Keep host-name pushdowns honest when typed hosts can come from unindexed text headers.

    Indexed matches remain useful, but neither their absence nor an exhaustive backend response proves that
    every matching typed host was searched. One bounded coverage cell per target/window names that omission.
    """
    gaps = {}
    for intent in intents:
        predicates = [*intent.filters, *(item for group in intent.any_of for item in group)]
        if not any(item.field == "host.name" and item.op in {"eq", "in"} for item in predicates):
            continue
        contract = contracts[intent.target]
        if _is_network(intent.target, contract):
            continue
        if contract.text_missing_host_records == 0:
            continue
        selected = PivotExecutor._intent_datasets(intent)
        if not header_host and selected and not selected.intersection({"linux.text", "linux.syslog"}):
            continue
        if not header_host and contract.os_family == "windows" and all(
            any(item.field == "event.channel" and item.op in {"eq", "in", "exists"}
                for item in [*intent.filters, *group]) for group in (intent.any_of or [[]])
        ):
            # A Windows channel selector excludes text even when no dataset field is mapped.
            continue
        inventory = dataset_inventory.get(intent.target)
        text_possible = (contract.linux_text_mixed is not False
                         or (contract.text_missing_host_records or 0) > 0
                         or bool({"linux.text", "linux.syslog"}.intersection(_logical_inventory(inventory or ()))))
        if not inventory and (not selected or selected.intersection({"linux.text", "linux.syslog"})):
            # An unknown datasetless count can leave text out of the usable inventory.
            payload = any(contract.spec(name, os_family="linux") is not None
                          for name in ("message", "event.original"))
            selector = any(contract.spec(name, os_family="linux") is not None
                           for name in ("event.dataset", "data_stream.dataset", "input.type", "log.file.path"))
            text_possible = text_possible or (payload and selector)
        if not (header_host or text_possible):
            continue
        key = (intent.target, intent.window.start, intent.window.end)
        gaps.setdefault(key, PivotCoverage(
            target=intent.target, dataset="linux.text", start=intent.window.start, end=intent.window.end,
            status="partial", reasons=[TEXT_HOST_QUERY_REASON], returned=0, total=None,
            unresolved_ranges=[_range(intent.window.start, intent.window.end, TEXT_HOST_QUERY_REASON)],
        ))
    return list(gaps.values())


def _link_task_kind(executor) -> str:
    """Keep borrowed executor methods compatible while separating agent link work."""
    return "agent_follow_link" if getattr(executor, "source_query_scope", None) == "agent" else "expansion_link"


# The agent's typed search (search_events). One search may name every target of its scope and has no entity to
# narrow it, and everything it keeps is persisted (evidence, its result's page items, its reach link), so it keeps
# far fewer rows than an entity pivot: a dense window is split into at most SEARCH_PARTITIONS leaves, each leaf
# query keeps at most SEARCH_LEAF_RECORDS, so one target keeps at most SEARCH_PARTITIONS leaves x (head, tail and the
# two anchor samples) x that many rows, from at most 2 x SEARCH_PARTITIONS - 1 + SEARCH_PARTITIONS x
# MAX_SAMPLE_QUERIES queries; once MAX_SEARCH_RECORDS rows were kept the targets not yet searched are named as not
# evaluated. Whatever a hunt's size, one search keeps at most MAX_SEARCH_RECORDS + MAX_SEARCH_TARGET_RECORDS rows: about
# ten such searches fit the hunt's agent page items, and one search's reach link stays far below the incident
# graph's payload ceiling. A capped search is partial and names what it did not read, never a no-match.
SEARCH_LEAF_RECORDS = 1_000
SEARCH_PARTITIONS = 4
MAX_SEARCH_TARGET_RECORDS = SEARCH_PARTITIONS * MAX_SAMPLE_QUERIES * SEARCH_LEAF_RECORDS
MAX_SEARCH_RECORDS = 5_000
SEARCH_PURPOSE = "agent:search_events"
# How many similar searchable fields a refusal or a not-evaluated reason names, and how many targets a refusal lists.
SEARCH_SIMILAR_FIELDS = 20
SEARCH_REASON_SIMILAR = 5
SEARCH_REFUSAL_TARGETS = 10
# The query clauses a compiled agent search may contain. Every value the model wrote reaches the source as the value
# of one of them (term, terms, prefix, range; a wildcard only in the compiler's escaped exact-value form). Never a
# phrase (it matches inside longer text: a mention, not the value), query_string, regexp, script or match.
SEARCH_CLAUSES = frozenset({"bool", "term", "terms", "prefix", "range", "wildcard", "exists"})
_STRING_KINDS = frozenset({"keyword", "constant_keyword", "wildcard", "flattened"})
_INTEGER_KINDS = frozenset({"long", "integer", "short"})
_INTEGER_TEXT = re.compile(r"[+-]?[0-9]{1,19}")
_NAME_TOKENS = re.compile(r"[._]")


def _text(value, limit: int = 200) -> str:
    text = " ".join(str(value).split())
    return text if len(text) <= limit else f"{text[:limit]}…"


def _scoped(contract: FieldContract, scope: str) -> bool:
    return scope == "all" or (scope == "network") == _is_network(contract.target, contract)


def search_values(kind: str, op: str, values: list[str]) -> list:
    """The condition's values as the field's native type takes them, else ValueError. A string field takes each value
    exactly as written; an address, number, time or boolean must parse as one (a time with its UTC offset)."""
    base = kind.split(":", 1)[0]
    out: list = []
    for text in values:
        if base in _STRING_KINDS:
            out.append(text)
        elif base == "ip":
            out.append(str(ipaddress.ip_network(text, strict=False)) if op == "cidr"
                       else str(ipaddress.ip_address(text)))
        elif base in _INTEGER_KINDS:
            if not _INTEGER_TEXT.fullmatch(text):
                raise ValueError(f"a {base} field takes whole numbers")
            out.append(int(text))
        elif base in {"double", "float"}:
            number = float(text)
            if not math.isfinite(number):
                raise ValueError(f"a {base} field takes finite numbers")
            out.append(number)
        elif base == "date":
            moment = datetime.fromisoformat(text)
            if moment.tzinfo is None:
                raise ValueError("a date value needs its UTC offset")
            out.append(moment.astimezone(UTC).isoformat())
        elif base == "boolean":
            if text not in ("true", "false"):
                raise ValueError("a boolean field takes true or false")
            out.append(text == "true")
        else:
            raise ValueError(f"values of a {kind} field are not searchable")
    return out


# Fields the compiler matches by a special equality form (sources.compile._pred_exact): the stored spelling differs
# from the typed value (case, a canonical account prefix, a short host name), so each value of an `in` is sent as that
# form, and a prefix of the typed value cannot be matched on the stored one.
_CANONICAL_ACCOUNTS = frozenset({"user.entity_id", "auth.target_account"})
_CASELESS_FIELDS = frozenset({"event.channel", "event.provider", "object.type"})
# How many hosts, addresses, accounts and domains one search result lists, and how many distinct reasons for records
# no normalizer read it names before counting the rest together.
MAX_SEARCH_ENTITIES = 1_000
MAX_SEARCH_SKIP_REASONS = 10
_ENTITY_ORDER = {"host": 0, "ip": 1, "account": 2, "domain": 3}


# The special equality forms, and what each sends in place of the typed value.
_SPECIAL_FORMS = {"account": "a canonical sid: or name: account form", "host": "a short host name",
                  "caseless": "a case-folded name"}


def _special_form(field_name: str, spec) -> str | None:
    natives = set(spec.natives or (spec.native,))
    if field_name in _CANONICAL_ACCOUNTS:
        return "account"
    if field_name == "host.name" and natives & _WINDOWS_COMPUTER_NATIVES:
        return "host"
    if field_name in _CASELESS_FIELDS and natives & _CASELESS_WINDOWS_NATIVES:
        return "caseless"
    return None


@dataclass(frozen=True)
class SearchCheck:
    """A condition the compiler sends as a special equality form, which the source matches as a superset of the
    typed value: a case-insensitive name, a host's short name in any domain, an account's short name in any domain.
    A hit is re-checked on the event's typed field with the compiler's own semantics; an event without that typed
    field is kept. Every other condition is the source's exact term, terms, prefix or range: never re-checked."""

    field: str
    form: str
    values: tuple


@dataclass
class _PlannedCondition:
    filters: list[Predicate]
    groups: list[list[Predicate]]          # alternatives (an `in` sent as one special equality form per value)
    check: SearchCheck | None
    caveats: list[str]                     # what the source cannot see for this condition


def _plan_condition(contract: FieldContract, condition: SearchCondition,
                    os_family: str | None) -> tuple[_PlannedCondition | None, str | None]:
    """One condition planned on this target, or why the target cannot evaluate it."""
    field_name, op = condition.field, condition.op
    if field_name == contract.time_field:
        return None, f"field {field_name} is the time field: set start and end instead"
    spec = contract.spec(field_name, os_family=os_family)
    if spec is None:
        return None, f"field {field_name} / op {op} not supported: no such field"
    variants = (spec, *spec.alternatives)
    if any(op not in variant.ops for variant in variants):
        supported = sorted(set.intersection(*(set(variant.ops) for variant in variants)) & set(SEARCH_OPS))
        return None, (f"field {field_name} / op {op} not supported: this {spec.type} field takes "
                      f"{', '.join(supported) or 'no search operation'}")
    special = _special_form(field_name, spec)
    if special is not None and op == "prefix":
        return None, (f"field {field_name} / op prefix refused: its typed value is {_SPECIAL_FORMS[special]}, which "
                      "a prefix of the stored value cannot match")

    def kind(variant) -> str:
        # equality on analyzed text is compiled against its keyword subfields: its values are strings
        return "keyword" if variant.exact and op in {"eq", "in"} else variant.type

    for variant in variants:
        limit = variant.exact_limit if variant.exact and op in {"eq", "in"} else None
        if limit is not None and any(utf16_length(value) > limit for value in condition.values):
            # the subfield keeps no longer value, and a phrase on the text would match it inside longer text
            return None, (f"field {field_name} / op {op}: a value longer than {limit} characters is not kept "
                          "exactly by this source and cannot be matched exactly")
    try:
        parsed = search_values(kind(spec), op, condition.values)
        for variant in spec.alternatives:
            search_values(kind(variant), op, condition.values)
    except ValueError as error:
        return None, f"field {field_name} / op {op}: value not valid for a {spec.type} field ({error})"
    caveats: list[str] = []
    # A keyword-like native indexes no value longer than its ignore_above (UTF-16 code units, as utf16_length counts
    # them); a limit the mapping did not give is finite and unknown.
    natives = [(variant, native) for variant in variants for native in (variant.natives or (variant.native,))
               if not variant.exact and variant.type.split(":", 1)[0] in LIMITED_KINDS]
    beyond = []
    for _variant, native in natives:
        known, limit = contract.index_limit(native)
        if op == "prefix" and (not known or limit is not None):
            caveats.append(f"{field_name}: values longer than {limit if known else 'an unknown limit of'} characters "
                           f"are not indexed in {native}, so a prefix cannot see them")
        elif op in {"eq", "in"} and not known:
            caveats.append(f"{field_name}: the index length limit of {native} is unknown; a longer stored value is "
                           "not indexed")
        elif op in {"eq", "in"} and limit is not None and any(utf16_length(value) > limit
                                                              for value in condition.values):
            beyond.append((native, limit))
    if natives and len(beyond) == len(natives):
        native, limit = beyond[0]
        return None, (f"field {field_name} / op {op}: a value longer than {limit} characters is not indexed by "
                      f"{native}")
    caveats.extend(f"{field_name}: a value longer than {limit} characters is not indexed in {native}"
                   for native, limit in beyond)
    value = parsed if op == "in" else parsed[0]
    if special is not None and op == "in":
        # each value in the compiler's special equality form, any one of them
        filters, groups = [], [[Predicate(field=field_name, op="eq", value=item)] for item in parsed]
    else:
        filters, groups = [Predicate(field=field_name, op=op, value=value)], []
    check = SearchCheck(field_name, special, tuple(condition.values)) if special is not None else None
    return _PlannedCondition(filters, groups, check, list(dict.fromkeys(caveats))), None


def _short_host(value) -> str:
    return str(value).strip().rstrip(".").split(".", 1)[0].casefold()


# Each canonical account field's typed name and domain on the same record: a record whose canonical account is its
# sid still names the account, and a search by name is checked on that name and domain.
_ACCOUNT_PAIRS = {"user.entity_id": ("user.name", "user.domain"),
                  "auth.target_account": ("account.name", "account.domain")}


def _same_domain(left: str, right: str) -> bool:
    """Whether two domain spellings can name one domain, without case. Two spellings of the same style (both NetBIOS,
    or both FQDN) must be equal. A NetBIOS name and an FQDN never refute each other: a forest's NetBIOS name need not
    be the FQDN's first label (CONTOSO and ad.contoso.com), and the record cannot tell which pairs belong together."""
    left, right = left.strip().rstrip(".").casefold(), right.strip().rstrip(".").casefold()
    return left == right or ("." in left) != ("." in right)


def _name_matches(name: str, domain: str | None, typed_name, typed_domain) -> bool:
    """A searched account name (with its domain, when it gave one) against a typed name and domain, without case; a
    domain either side does not give cannot refute it."""
    if str(typed_name).strip().casefold() != name.strip().casefold():
        return False
    return domain is None or typed_domain in (None, "") or _same_domain(domain, str(typed_domain))


def _split_account(body: str) -> tuple[str | None, str]:
    domain, separator, name = body.rpartition("\\")
    return (domain if separator and domain else None), name


def _account_holds(check: SearchCheck, typed, event: TypedEvent) -> bool:
    """Whether a typed canonical account meets any searched account. A sid search is checked on a typed sid; a typed
    name cannot refute it (the compiler matched the sid itself). A name search is checked on a typed name, or, when
    the typed account is a sid, on the same record's typed name and domain; when those are absent it is kept."""
    text = str(typed)
    typed_kind, _, typed_body = text.partition(":")
    typed_kind = typed_kind.casefold()
    for value in check.values:
        kind, _, body = value.partition(":")
        kind = kind.casefold()
        if kind == "sid":
            if typed_kind != "sid" or text.casefold() == value.casefold():
                return True
            continue
        domain, name = _split_account(body)
        if typed_kind == "name":
            typed_domain, typed_name = _split_account(typed_body)
            if _name_matches(name, domain, typed_name, typed_domain):
                return True
            continue
        name_field, domain_field = _ACCOUNT_PAIRS.get(check.field, (None, None))
        typed_name = event.get(name_field) if name_field else None
        if typed_name is None or _name_matches(name, domain, typed_name,
                                               event.get(domain_field) if domain_field else None):
            return True
    return False


def _special_holds(check: SearchCheck, typed, event: TypedEvent) -> bool:
    """Whether a typed value meets the condition as the compiler's special form means it: a name without case, a host
    by its short name, an account by its canonical form (_account_holds)."""
    text = str(typed)
    if check.form == "host":
        return _short_host(text) in {_short_host(value) for value in check.values}
    if check.form == "account":
        return _account_holds(check, typed, event)
    return text.casefold() in {value.casefold() for value in check.values}


def _search_keeps(checks: list[SearchCheck], event: TypedEvent) -> bool:
    """Whether a source match survives the special-form re-checks: kept unless the event's typed value of such a
    field is present and refutes it. A refuted row is a superset row, discarded and counted, never a match."""
    for check in checks:
        value = event.get(check.field)
        if value is None:
            continue
        values = value if isinstance(value, list) else [value]
        if values and not any(_special_holds(check, item, event) for item in values):
            return False
    return True


def _unsafe_clause(node) -> str | None:
    """The first clause type outside SEARCH_CLAUSES in a compiled query, else None."""
    if isinstance(node, list):
        return next((found for item in node if (found := _unsafe_clause(item)) is not None), None)
    if not isinstance(node, dict):
        return None
    for kind, body in node.items():
        if kind not in SEARCH_CLAUSES:
            return kind
        if kind == "bool":
            for key, value in body.items():
                if key in {"filter", "must", "should", "must_not"}:
                    found = _unsafe_clause(value)
                    if found is not None:
                        return found
    return None


def _similar_fields(contracts: list[FieldContract], field_name: str) -> tuple[list[dict], int]:
    """Up to SEARCH_SIMILAR_FIELDS searchable typed fields of these contracts whose names share a word with, or read
    like, `field_name`, with the agent search ops each takes; and how many searchable fields there are in all."""
    wanted = {token for token in _NAME_TOKENS.split(field_name.lower()) if token}
    matcher = difflib.SequenceMatcher(b=field_name.lower(), autojunk=False)
    found: dict[str, dict] = {}
    searchable: set[str] = set()
    for contract in contracts:
        for name, spec in contract.fields.items():
            ops = set(spec.ops).intersection(SEARCH_OPS)
            if not ops or name == contract.time_field:
                continue
            searchable.add(name)
            entry = found.get(name)
            if entry is None:
                overlap = len(wanted.intersection(_NAME_TOKENS.split(name.lower())))
                matcher.set_seq1(name.lower())
                ratio = matcher.ratio()
                if not overlap and ratio < 0.6:
                    continue
                entry = found[name] = {"field": name, "ops": set(), "rank": (-overlap, -ratio, name)}
            entry["ops"].update(ops)
    ranked = sorted(found.values(), key=lambda item: item["rank"])[:SEARCH_SIMILAR_FIELDS]
    return [{"field": _text(item["field"], 128), "ops": sorted(item["ops"])} for item in ranked], len(searchable)


@dataclass
class SearchPlan:
    """An agent search planned over the targets of its scope: an intent for each target that can evaluate every
    condition, a coverage cell naming each one that cannot, and a refusal when none can; with how each target's hits
    are confirmed, and what the source could not see (zero hits is never a confirmed absence)."""

    intents: list[SearchIntent]
    coverage: list[PivotCoverage]
    refusal: dict | None = None
    checks: dict[str, list[SearchCheck]] = field(default_factory=dict)
    caveats: list[str] = field(default_factory=list)


class PivotExecutor:
    """Translate accepted tools to safe intents, then normalize and directly detect results."""

    def __init__(self, repo: Repo, client: ElasticClient, hunt_id: str,
                 contracts: dict[str, FieldContract], heartbeat=None, owner_token: str | None = None,
                 source_query_budget: int | None = None,
                 source_query_scope: str | None = None,
                 dataset_inventory: dict[str, set[str] | list[str] | tuple[str, ...]] | None = None,
                 optimize_normalization: bool = True,
                 site_facts: SiteFacts | None = None, stage_dir=None):
        self.repo = repo
        self.client = client
        self.hunt_id = hunt_id
        self.contracts = contracts
        self.heartbeat = heartbeat or (lambda: None)
        self.owner_token = owner_token
        self.source_query_budget = source_query_budget
        self.source_query_scope = source_query_scope
        self.source_queries = 0
        # The AI agent's shares (configure_agent_shares): None leaves only the hunt total. `session_spent` and
        # `call_spent` count this executor's own reservations; `source_queries` mirrors the hunt-wide count, which
        # concurrent sessions also raise.
        self.session_id: str | None = None
        self.session_purpose: str | None = None
        self.session_share: int | None = None
        self.call_slice: int | None = None
        self.session_spent = 0
        self.call_spent = 0
        self._call_floor = 0
        self._intent_ceiling: int | None = None
        self._intent_share: int | None = None
        self._caps_recorded: set[str] = set()
        # a Linux shipper's dataset names are inventoried under the logical dataset that reads them
        self.dataset_inventory = {
            target: tuple(sorted(_logical_inventory(datasets)))
            for target, datasets in (dataset_inventory or {}).items()
        }
        self.optimize_normalization = optimize_normalization
        self.raw_family_prefilter = optimize_normalization
        self.site_facts = site_facts or absent_site_facts()
        self.stage_dir = stage_dir

    def process_termination_attested(self, host: str | None) -> bool:
        return bool(host) and self.site_facts.attests(
            host, "audit_policy", subcategory="Process Termination", outcome="success",
        )

    def system_log_attested(self, host: str | None) -> bool:
        return bool(host) and self.site_facts.attests(host, "system_event_log")

    def _normalize_pivot_records(
        self, records: list[dict], raw_families: set[str] | None, contract=None, surrogate_free: bool = False,
    ) -> tuple[list[TypedEvent], list[tuple[str, str]]]:
        prefilter = self.optimize_normalization and raw_families
        # one call per leaf: an audit event takes its boot id from a journald copy in the same batch, and nothing
        # (the batch, its audit parses) outlives the leaf, so memory stays bounded by the per-leaf record cap
        parse = _AuditParses()
        selected = _prefilter_raw(records, raw_families, parse) if prefilter else records
        events, _skips, errors = normalize_hits(selected, audit_parse=parse, contract=contract,
                                                surrogate_free=surrogate_free)
        script_blocks = getattr(self, "_script_blocks", None)
        if script_blocks is not None and any(event.family == "script_block" for event in events):
            raw_sources = {
                f"{record['_index']}/{record['_id']}": record["_source"] for record in selected
            }
            events = script_blocks.consume(events, raw_sources)
        return events, errors

    def _agent_budgeted(self) -> bool:
        return getattr(self, "source_query_scope", None) == "agent" and self.source_query_budget is not None

    def configure_agent_shares(self, *, session_id: str | None, purpose: str | None,
                               session_share: int | None, call_slice: int | None) -> None:
        """Bound this executor's AI-agent session: at most `session_share` source queries in all, and at most
        `call_slice` in one tool call (begin_call starts one). The hunt total still bounds both."""
        self.session_id, self.session_purpose = session_id, purpose
        self.session_share, self.call_slice = session_share, call_slice
        self.session_spent = 0
        self.begin_call()

    def begin_call(self) -> None:
        """Start one tool call's slice."""
        self.call_spent = 0
        self._call_floor = 0
        self._intent_ceiling = None
        self._intent_share = None
        self._caps_recorded = set()

    def _call_limit(self) -> int | None:
        """The current call's slice: the configured slice, raised to one query for each source the call plans (the
        session's share and the hunt total still bound it)."""
        if self.call_slice is None:
            return None
        return max(self.call_slice, getattr(self, "_call_floor", 0))

    def _agent_plan_call(self, intents: list[SearchIntent], *, rotate: bool = True) -> list[SearchIntent]:
        """Before an agent call runs its planned sources: its slice covers one query for each, and when even that
        cannot be spent (the session's share or the hunt total has less left than there are sources), the sources
        start at a place set by the hunt's persisted spend, so successive calls (and sessions) reach the ones an
        earlier call left unsearched. Every source the call does not reach is still named as not searched."""
        if not self._agent_budgeted() or not intents:
            return intents
        self._call_floor = max(getattr(self, "_call_floor", 0), len(intents))
        available = self.agent_available()
        if available is None or not 0 < available[0] < len(intents):
            return intents
        if not rotate or any(intent.purpose == "expansion:host-witness" for intent in intents):
            return intents              # a witness probe stops at its first hit: its order is its meaning
        start = self.source_queries % len(intents)
        return [*intents[start:], *intents[:start]]

    def _agent_cap(self, kind: str) -> str:
        limit = {AGENT_HUNT_BUDGET: self.source_query_budget, AGENT_SESSION_SHARE: self.session_share,
                 AGENT_CALL_SLICE: self._call_limit(),
                 AGENT_SOURCE_SHARE: getattr(self, "_intent_share", None)}[kind]
        reason = f"{kind}:{limit}"
        if kind not in self._caps_recorded:
            # once per cap and call: the audit says which cap stopped the agent, and where
            self._caps_recorded.add(kind)
            self.repo.audit("system", "agent.source_query_cap", self.hunt_id, {
                "cap": kind, "limit": limit, "session_id": self.session_id, "purpose": self.session_purpose,
                "session_spent": self.session_spent, "call_spent": self.call_spent,
            }, owner_token=self.owner_token)
        return reason

    def agent_available(self) -> tuple[int, str | None] | None:
        """How many source queries the AI agent may still spend in the current tool call, and when none, the reason of
        the cap that stops it (the hunt total first, then the session's share, then the call's slice). None outside
        the agent's budget. The hunt total is read from its persisted spend."""
        if not self._agent_budgeted():
            return None
        self.source_queries = self.repo.agent_source_queries(self.hunt_id)
        limits = [(self.source_query_budget - self.source_queries, AGENT_HUNT_BUDGET)]
        if self.session_share is not None:
            limits.append((self.session_share - self.session_spent, AGENT_SESSION_SHARE))
        if self.call_slice is not None:
            limits.append((self._call_limit() - self.call_spent, AGENT_CALL_SLICE))
        for left, kind in limits:
            if left <= 0:
                return 0, self._agent_cap(kind)
        return min(left for left, _kind in limits), None

    def _agent_room(self) -> tuple[int, str] | None:
        """The queries the current agent intent may still spend, from this executor's counters (no store read), and
        the kind of the cap that binds; None outside the agent's budget."""
        if not self._agent_budgeted():
            return None
        limits = [(self.source_query_budget - self.source_queries, AGENT_HUNT_BUDGET)]
        if self.session_share is not None:
            limits.append((self.session_share - self.session_spent, AGENT_SESSION_SHARE))
        if self.call_slice is not None:
            limits.append((self._call_limit() - self.call_spent, AGENT_CALL_SLICE))
        if self._intent_ceiling is not None:
            limits.append((self._intent_ceiling - self.call_spent, AGENT_SOURCE_SHARE))
        left, kind = min(limits, key=lambda item: item[0])
        return max(0, left), kind

    def _intent_allowance(self, intents_left: int) -> tuple[int, str | None] | None:
        """Before an agent intent's task: its fair part of what the call may still spend (the rest divided by the
        intents left, so one dense source cannot starve the others), or (0, reason) when nothing is left."""
        available = self.agent_available()
        if available is None:
            return None
        left, reason = available
        if left > 0:
            self._intent_share = max(1, left // max(1, intents_left))
            self._intent_ceiling = self.call_spent + self._intent_share
        return left, reason

    def _agent_reserve(self, spend_task_id: str | None) -> str | None:
        """Reserve one agent source query, or return the reason of the cap that refuses it."""
        if self.source_queries >= self.source_query_budget:
            return self._agent_cap(AGENT_HUNT_BUDGET)
        if self.session_share is not None and self.session_spent >= self.session_share:
            return self._agent_cap(AGENT_SESSION_SHARE)
        if self.call_slice is not None and self.call_spent >= self._call_limit():
            return self._agent_cap(AGENT_CALL_SLICE)
        if self._intent_ceiling is not None and self.call_spent >= self._intent_ceiling:
            return self._agent_cap(AGENT_SOURCE_SHARE)
        reserved = self.repo.reserve_agent_source_query(
            self.hunt_id, self.source_query_budget, spend_task_id, owner_token=self.owner_token,
            session_id=self.session_id, purpose=self.session_purpose,
        )
        if reserved is None:
            self.source_queries = self.source_query_budget
            return self._agent_cap(AGENT_HUNT_BUDGET)
        self.source_queries = reserved
        self.session_spent += 1
        self.call_spent += 1
        return None

    def _execute(
        self, intent: SearchIntent, contract: FieldContract, *, pit=None,
        spend_task_id: str | None = None, physical_query_limit: int | None = None,
    ) -> SearchOutcome:
        def temporal(outcome):
            if intent.kind == "raw" and contract.temporal_gaps and outcome.completeness != Completeness.failed:
                return outcome.model_copy(update={"completeness": Completeness.partial,
                    "reasons": sorted({*outcome.reasons, *contract.temporal_gaps})})
            return outcome
        agent = self._agent_budgeted()
        if physical_query_limit is not None:
            ceiling = physical_query_limit
            if self.source_query_budget is not None:
                ceiling = min(ceiling, self.source_query_budget)
            refused: list[str] = []

            def spend():
                if self.source_queries >= ceiling:
                    return False
                if agent:
                    # every physical page the agent reads is reserved under its caps, as any other agent query is
                    refusal = self._agent_reserve(spend_task_id)
                    if refusal is not None:
                        refused.append(refusal)
                        return False
                else:
                    self.source_queries += 1
                    if spend_task_id is not None:
                        self.repo.record_task_source_query(spend_task_id, owner_token=self.owner_token)
                self.heartbeat()
                return True
            options = {}
            if timing := getattr(self, "zeek_deadline", None):
                options.update(deadline=timing[0], clock=timing[1])
            outcome = temporal(execute(self.client, intent, contract, pit=pit, on_query=spend, **options))
            if refused:
                outcome = outcome.model_copy(update={"reasons": sorted({*outcome.reasons, *refused})})
            return outcome

        def budget_outcome(reason: str | None = None) -> SearchOutcome:
            now = datetime.now(UTC)
            prefix = self.source_query_scope or "expansion"
            reason = reason or f"{prefix}_source_query_budget:{self.source_query_budget}"
            return SearchOutcome(
                target=intent.target, fingerprint=digest(intent.model_dump(mode="json")),
                started_at=now, ended_at=now, completeness=Completeness.failed,
                reasons=[reason], error=reason,
            )
        if agent:
            refusal = self._agent_reserve(spend_task_id)
            if refusal is not None:
                return budget_outcome(refusal)
        elif self.source_query_budget is not None and self.source_queries >= self.source_query_budget:
            return budget_outcome()
        elif spend_task_id is not None:
            self.repo.record_task_source_query(spend_task_id, owner_token=self.owner_token)
            self.source_queries += 1
        else:
            self.source_queries += 1
        self.heartbeat()
        outcome = (execute(self.client, intent, contract) if pit is None
                   else execute(self.client, intent, contract, pit=pit))
        self.heartbeat()
        return temporal(outcome)

    def _intents(self, request: ToolRequest) -> list[SearchIntent]:
        if isinstance(request, SearchEventsRequest):
            # planned on its own: never the unfiltered fall-through below
            return self.plan_search(request).intents
        args = request.arguments
        window = Window(start=args.start, end=args.end)
        intents: list[SearchIntent] = []
        dataset_inventory = getattr(self, "dataset_inventory", {})
        for target, contract in self.contracts.items():
            network = _is_network(target, contract)
            filters: list[Predicate] = []
            any_of: list[list[Predicate]] = []

            if isinstance(request, EntityTimelineRequest):
                entity = args.entity
                if entity.kind == "ip" and contract.time_field == "firstPacket":
                    if not (_supports(contract, "source.ip") and _supports(contract, "destination.ip")):
                        continue
                    any_of = [
                        [Predicate(field="source.ip", op="eq", value=entity.value)],
                        [Predicate(field="destination.ip", op="eq", value=entity.value)],
                    ]
                elif entity.kind == "ip" and network:
                    if not (_supports(contract, "event.dataset", "in")
                            and _supports(contract, "source.ip") and _supports(contract, "destination.ip")):
                        continue
                    ip_groups = [
                        [Predicate(field="source.ip", op="eq", value=entity.value)],
                        [Predicate(field="destination.ip", op="eq", value=entity.value)],
                    ]
                    inventoried = dataset_inventory.get(target)
                    if inventoried is not None:
                        for dataset in inventoried:
                            if dataset in ZEEK_LOGS_BY_TOKEN:
                                # a dispatch token: the log's rows in every layout the target can be searched by
                                intents.append(SearchIntent(
                                    kind="raw", target=target, window=window,
                                    any_of=_and_any_of(
                                        zeek_source_groups(contract, [ZEEK_LOGS_BY_TOKEN[dataset]]), ip_groups),
                                    max_records=MAX_PIVOT_RECORDS,
                                    purpose=f"agent:{request.tool}:{dataset}",
                                ))
                                continue
                            if dataset not in NETWORK_TIMELINE_DATASETS and dataset != ELASTIC_DATASET:
                                continue
                            intents.append(SearchIntent(
                                kind="raw", target=target, window=window,
                                filters=[Predicate(field="event.dataset", op="eq", value=dataset)],
                                any_of=ip_groups,
                                max_records=MAX_PIVOT_RECORDS,
                                purpose=f"agent:{request.tool}:{dataset}",
                            ))
                        continue
                    if zeek_capable(contract):
                        # Suricata's datasets or any Zeek layout the target can be searched by
                        intents.append(SearchIntent(
                            kind="raw", target=target, window=window,
                            any_of=_and_any_of(
                                [[Predicate(field="event.dataset", op="in", value=NETWORK_TIMELINE_DATASETS)],
                                 *(group for group in zeek_source_groups(contract)
                                   if group[0].field != "event.dataset")], ip_groups),
                            max_records=MAX_PIVOT_RECORDS, purpose=f"agent:{request.tool}",
                        ))
                        continue
                    filters = [Predicate(field="event.dataset", op="in", value=SURICATA_TIMELINE_DATASETS)]
                    any_of = ip_groups
                elif entity.kind == "ip" and not network:
                    ip_groups = [
                        [Predicate(field=field, op="eq", value=entity.value)]
                        for field in ("source.ip", "destination.ip") if _supports(contract, field)
                    ]
                    if contract.os_family == "windows":
                        source_groups = _windows_source_groups(contract)
                        if not source_groups or not ip_groups:
                            continue
                        intents.append(SearchIntent(
                            kind="raw", target=target, window=window,
                            any_of=_and_any_of(source_groups, ip_groups),
                            max_records=MAX_PIVOT_RECORDS,
                            purpose=f"agent:{request.tool}:windows-events",
                        ))
                        continue
                    if not _supports(contract, "event.dataset"):
                        continue
                    supported_datasets = _host_datasets(contract)
                    datasets = dataset_inventory.get(target, supported_datasets)
                    for dataset in datasets:
                        if dataset not in supported_datasets:
                            continue
                        dataset_filters = [Predicate(field="event.dataset", op="eq", value=dataset)]
                        dataset_any_of = ip_groups
                        if target in dataset_inventory and not dataset_any_of:
                            continue
                        intents.append(SearchIntent(
                            kind="raw", target=target, window=window,
                            filters=dataset_filters, any_of=dataset_any_of,
                            max_records=MAX_PIVOT_RECORDS,
                            purpose=f"agent:{request.tool}:{dataset}",
                        ))
                    continue
                elif entity.kind == "host" and not network and _supports(contract, "host.name"):
                    if contract.os_family == "windows":
                        any_of = _windows_source_groups(contract)
                        if not any_of:
                            continue
                        filters = [Predicate(field="host.name", op="eq", value=entity.value)]
                    elif _supports(contract, "event.dataset", "in"):
                        filters = [
                            Predicate(field="event.dataset", op="in", value=list(_host_datasets(contract))),
                            Predicate(field="host.name", op="eq", value=entity.value),
                        ]
                    else:
                        continue
                else:
                    continue
            elif isinstance(request, AuthActivityRequest):
                if network:
                    continue
                if args.entity.kind == "host" and not _supports(contract, "host.name"):
                    continue
                if contract.os_family == "windows":
                    source_groups = _windows_source_groups(contract, {"auth"})
                    if not source_groups:
                        continue
                    auth_filters = []
                    if args.entity.kind == "host":
                        auth_filters.append(Predicate(field="host.name", op="eq", value=args.entity.value))
                    intents.append(SearchIntent(
                        kind="raw", target=target, window=window, filters=auth_filters,
                        any_of=source_groups, max_records=MAX_PIVOT_RECORDS,
                        purpose=f"agent:{request.tool}:windows-events",
                    ))
                    continue
                if not _supports(contract, "event.dataset"):
                    continue
                # the logical datasets other than the audit records that carry login lines (journal, syslog)
                auth_datasets = tuple(dataset for dataset in LINUX_LOGICAL_DATASETS
                                      if dataset != "linux.audit" and "auth" in LOGICAL_FAMILIES[dataset])
                for dataset in auth_datasets:
                    auth_filters = [Predicate(field="event.dataset", op="eq", value=dataset)]
                    if args.entity.kind == "host":
                        auth_filters.append(Predicate(field="host.name", op="eq", value=args.entity.value))
                    intents.append(SearchIntent(
                        kind="raw", target=target, window=window, filters=auth_filters,
                        max_records=MAX_PIVOT_RECORDS, purpose=f"agent:{request.tool}:{dataset}",
                    ))
                continue
            elif isinstance(request, ProcessTreeRequest):
                if network or not _supports(contract, "host.name"):
                    continue
                families = (
                    {"process_exec", "process_termination", "system_state"}
                    if contract.os_family == "windows" else {"process_exec"}
                )
                if contract.os_family == "windows":
                    source_groups = _windows_source_groups(contract, families)
                    if source_groups:
                        intents.append(SearchIntent(
                            kind="raw", target=target, window=window,
                            filters=[Predicate(field="host.name", op="eq", value=args.host)],
                            any_of=source_groups, max_records=MAX_PIVOT_RECORDS,
                            purpose=f"agent:{request.tool}:windows-events",
                        ))
                    continue
                if not _supports(contract, "event.dataset"):
                    continue
                for dataset in _host_datasets(contract, families):
                    intents.append(SearchIntent(
                        kind="raw", target=target, window=window,
                        filters=[
                            Predicate(field="event.dataset", op="eq", value=dataset),
                            Predicate(field="host.name", op="eq", value=args.host),
                        ],
                        max_records=MAX_PIVOT_RECORDS, purpose=f"agent:{request.tool}:{dataset}",
                    ))
                continue
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
                if zeek_capable(contract):
                    # Zeek's notice, weird, signature and intel rows are the sensor's alerts too
                    alerts = [log for log in ZEEK_LOGS if log.family == "net_alert"]
                    any_of = _and_any_of([filters, *zeek_source_groups(contract, alerts)], any_of)
                    filters = []

            intents.append(SearchIntent(
                kind="raw", target=target, window=window, filters=filters, any_of=any_of,
                max_records=MAX_PIVOT_RECORDS, purpose=f"agent:{request.tool}",
            ))
        return intents

    def plan(self, request: ToolRequest) -> tuple[list[SearchIntent], list[PivotCoverage]]:
        """Plan executable intents and every known unresolved dataset cell together."""
        if isinstance(request, SearchEventsRequest):
            planned = self.plan_search(request)
            return planned.intents, planned.coverage
        intents = self._intents(request)
        return intents, [*self._unsearchable_ip_coverage(request, intents),
                         *_nxlog_mixed_coverage(self.contracts, request),
                         *_text_host_coverage(self.contracts, self.dataset_inventory, intents)]

    def plan_search(self, request: SearchEventsRequest) -> SearchPlan:
        """Plan an agent search over every target of its scope, without any source query. A target evaluates the
        search only when its contract takes every condition (field, op and each value's type) and the compiled
        query holds only literal-value clauses; a condition is never dropped, so a target that cannot take one is a
        coverage cell naming what it could not evaluate, never zero hits. When no target can, the plan is a refusal
        naming the searchable fields that resemble each condition's."""
        args = request.arguments
        window = Window(start=args.start, end=args.end)
        flavor = getattr(getattr(self.client, "settings", None), "es_flavor", "elasticsearch")
        targets = [contract for _target, contract in sorted(self.contracts.items())
                   if contract is not None and _scoped(contract, args.scope)]
        intents: list[SearchIntent] = []
        # (target, problem, the condition's field when one); a target without a contract cannot be searched
        skipped: list[tuple[str, str, str | None]] = [
            (target, "no field contract for this target", None)
            for target, contract in sorted(self.contracts.items()) if contract is None]
        checks: dict[str, list[SearchCheck]] = {}
        caveats: list[str] = []
        for contract in targets:
            # a condition naming logical Linux datasets selects the Linux layout's fields, as the compiler does
            provisional = SearchIntent(kind="raw", target=contract.target, window=window, filters=[
                Predicate(field=item.field, op=item.op, value=item.values if item.op == "in" else item.values[0])
                for item in args.conditions])
            os_family = _intent_os_family(provisional)
            planned: list[_PlannedCondition] = []
            problem = field_name = None
            for condition in args.conditions:
                item, problem = _plan_condition(contract, condition, os_family)
                if item is None:
                    field_name = condition.field
                    break
                planned.append(item)
            if problem is None:
                any_of: list[list[Predicate]] = []
                for item in planned:
                    any_of = _and_any_of(any_of, item.groups)
                if len(any_of) > MAX_SEARCH_VALUES:
                    problem = (f"the special equality forms of these conditions' values need {len(any_of)} "
                               f"alternatives (at most {MAX_SEARCH_VALUES}): split the search")
            if problem is None:
                intent = SearchIntent(kind="raw", target=contract.target, window=window,
                                      filters=[predicate for item in planned for predicate in item.filters],
                                      any_of=any_of, max_records=SEARCH_LEAF_RECORDS, purpose=SEARCH_PURPOSE)
                try:
                    unsafe = _unsafe_clause(compile_es(intent, contract, flavor).body["query"])
                except (CompileError, ValueError, TypeError) as error:
                    problem = f"the conditions cannot be compiled exactly for this source ({_text(error)})"
                else:
                    if unsafe is not None:
                        problem = f"the conditions compile to a {unsafe} clause, which agent search does not send"
            if problem is None:
                intents.append(intent)
                checks[contract.target] = [item.check for item in planned if item.check is not None]
                caveats.extend(caveat for item in planned for caveat in item.caveats)
            else:
                skipped.append((contract.target, problem, field_name))
        coverage = []
        for target, problem, field_name in skipped:
            reason = f"not evaluated: {target}: {problem}"
            if field_name is not None and self.contracts.get(target) is not None:
                similar, _count = _similar_fields([self.contracts[target]], field_name)
                if similar:
                    reason += "; similar searchable fields: " + ", ".join(
                        item["field"] for item in similar[:SEARCH_REASON_SIMILAR])
            coverage.append(PivotCoverage(
                target=target, dataset=None, start=args.start, end=args.end, status="partial",
                reasons=[reason], returned=0, total=None,
                unresolved_ranges=[_range(args.start, args.end, reason)],
            ))
        if not intents:
            return SearchPlan([], coverage, self._search_refusal(request, targets, skipped))
        scoped = {contract.target: contract for contract in targets}
        coverage.extend(_nxlog_mixed_coverage(scoped, request))
        coverage.extend(_text_host_coverage(scoped, self.dataset_inventory, intents))
        for intent in intents:
            coverage.extend(self._text_parsed_coverage(scoped[intent.target], args))
        return SearchPlan(intents, coverage, checks=checks, caveats=list(dict.fromkeys(caveats)))

    def _text_parsed_coverage(self, contract: FieldContract, args) -> list[PivotCoverage]:
        """A target that maps a text payload (message, event.original) can hold records whose typed fields are
        parsed from that text (a journal, syslog or auth line, an access log, a Suricata EVE line its shipper did not
        parse), under a dataset of any name; a field search cannot read them. Every dataset in its inventory is named
        in such a cell, except those whose records are always field-structured (Windows event logs, Zeek logs,
        Arkime sessions, Suricata records its shipper parsed), or the whole target when its inventory is unknown."""
        if contract.ecar or not any(name in contract.fields for name in ("message", "event.original")):
            return []
        inventory = self.dataset_inventory.get(contract.target)
        if contract.os_family == "windows" and not _is_network(contract.target, contract):
            datasets = ["linux.text"] if contract.linux_text_mixed is not False else []
        elif inventory is None:
            datasets = [None]
        else:
            parsed_suricata = "suricata.eve.event_type" in contract.fields

            def structured(name: str) -> bool:
                return (name in WINDOWS_HOST_DATASETS or name.startswith(("windows.", "zeek.", "arkime."))
                        or name in ZEEK_LOGS_BY_TOKEN or (parsed_suricata and name.startswith("suricata.")))

            datasets = sorted(name for name in inventory if not structured(name))
        cells = []
        for dataset in datasets:
            reason = (f"dataset_text_parsed:{dataset or 'inventory unknown'}: typed fields of these records are "
                      "parsed from their text, which a field search cannot read")
            cells.append(PivotCoverage(
                target=contract.target, dataset=dataset, start=args.start, end=args.end, status="partial",
                reasons=[reason], returned=0, total=None, unresolved_ranges=[_range(args.start, args.end, reason)],
            ))
        return cells

    def search_item_bound(self, request: SearchEventsRequest) -> int:
        """The most page items one search's result can hold."""
        targets = sum(1 for contract in self.contracts.values()
                      if contract is None or _scoped(contract, request.arguments.scope))
        rows = MAX_SEARCH_RECORDS + MAX_SEARCH_TARGET_RECORDS
        # its kept rows, the direct-detection findings they can raise (each cites at least one of them), its listed
        # entities, and a few coverage cells and reasons for every target of its scope
        return 2 * rows + MAX_SEARCH_ENTITIES + 2 * (SEARCH_PARTITIONS + 8) * targets + MAX_SEARCH_SKIP_REASONS + 64

    def search_refusal(self, request: SearchEventsRequest) -> dict | None:
        """The refusal an agent search gets before any source query, or None when some target can evaluate it."""
        return self.plan_search(request).refusal

    @staticmethod
    def _search_refusal(request: SearchEventsRequest, targets: list[FieldContract],
                        skipped: list[tuple[str, str, str | None]]) -> dict:
        scope = request.arguments.scope
        if not targets:
            return {"code": "scope_has_no_source", "message": (
                f"this hunt has no {scope} source to search; scope host searches endpoint and host logs, network "
                "searches network logs and sessions, all searches both"),
                "reasons": [refusal_reason("scope", "no_source")]}
        failing = {field_name for _target, _problem, field_name in skipped if field_name is not None}
        conditions = []
        for condition in request.arguments.conditions:
            if condition.field not in failing:
                continue
            similar, count = _similar_fields(targets, condition.field)
            conditions.append({"field": condition.field, "op": condition.op, "similar_fields": similar,
                               "searchable_field_count": count})
        problems = [{"target": target, "problem": _text(problem)} for target, problem, _field in skipped]
        return {
            "code": "search_unsupported",
            "message": (f"no {scope} source can evaluate every condition, so nothing was searched; each target's "
                        "problem is listed, and similar_fields names searchable typed fields that resemble each "
                        "condition's field, with the operations each takes"),
            "reasons": [refusal_reason("conditions[].field", "unsupported_field") if failing
                        else refusal_reason("conditions", "not_compilable")],
            "conditions": conditions,
            "targets": problems[:SEARCH_REFUSAL_TARGETS],
            "targets_omitted": max(0, len(problems) - SEARCH_REFUSAL_TARGETS),
        }

    @staticmethod
    def _intent_dataset(intent: SearchIntent) -> str | None:
        for predicate in intent.filters:
            if predicate.field == "event.dataset" and predicate.op == "eq" and isinstance(predicate.value, str):
                return predicate.value
        if any(predicate.field == "event.channel" for group in intent.any_of for predicate in group):
            return "windows.events"
        return None

    @staticmethod
    def _intent_datasets(intent: SearchIntent) -> set[str]:
        """Datasets an intent searches, including dataset alternatives in ``any_of``."""
        datasets: set[str] = set()
        predicates = [*intent.filters, *(predicate for group in intent.any_of for predicate in group)]
        for predicate in predicates:
            if predicate.field != "event.dataset":
                continue
            if predicate.op == "eq" and isinstance(predicate.value, str):
                datasets.add(predicate.value)
            elif predicate.op == "in" and isinstance(predicate.value, (list, tuple, set, frozenset)):
                datasets.update(value for value in predicate.value if isinstance(value, str))
        return datasets

    @staticmethod
    def _ip_normalization_reasons(intent: SearchIntent, records: list[dict]) -> list[str]:
        if (PivotExecutor._intent_dataset(intent) != "linux.audit"
                or "entity_timeline" not in intent.purpose):
            return []
        reasons = set()
        for record in records:
            try:
                audit = audit_record_of(record)
            except AuditParseError:
                continue
            if audit is None:
                continue
            address = audit.fields.get("addr")
            if (audit.type.startswith(("USER_", "CRED_"))
                    and audit.type not in AUDIT_LOGIN_TYPES
                    and address not in {None, "", "?", "(null)", "(none)", "0.0.0.0", "::"}):
                reasons.add(f"audit_address_type_not_normalized:{audit.type}")
        return sorted(reasons)

    def _unsearchable_ip_coverage(
        self, request: ToolRequest, intents: list[SearchIntent] | None = None,
    ) -> list[PivotCoverage]:
        if not isinstance(request, EntityTimelineRequest) or request.arguments.entity.kind != "ip":
            return []
        args = request.arguments
        unresolved: list[PivotCoverage] = []
        intents = intents or []
        planned = {
            (intent.target, dataset)
            for intent in intents
            for dataset in PivotExecutor._intent_datasets(intent)
        }
        # a Zeek log planned by its dispatch token (its rows selected per shipper layout)
        planned.update((intent.target, intent.purpose.split(":", 2)[2]) for intent in intents
                       if intent.purpose.count(":") >= 2 and intent.purpose.split(":", 2)[2] in ZEEK_LOGS_BY_TOKEN)
        for target, contract in self.contracts.items():
            inventoried = self.dataset_inventory.get(target)
            if inventoried is not None:
                if contract.time_field == "firstPacket":
                    if any(intent.target == target for intent in intents):
                        continue
                    reason = "key not pushable; full-dataset scan refused"
                    unresolved.append(PivotCoverage(
                        target=target, dataset=None, start=args.start, end=args.end,
                        status="partial", reasons=[reason], returned=0, total=None,
                        unresolved_ranges=[_range(args.start, args.end, reason)],
                    ))
                    continue
                normalized = set([*NETWORK_TIMELINE_DATASETS, ELASTIC_DATASET, *ZEEK_LOGS_BY_TOKEN]
                                 if _is_network(target, contract) else _host_datasets(contract))
                for dataset in inventoried:
                    if (target, dataset) in planned:
                        continue
                    reason = (f"dataset_not_normalized:{dataset}" if dataset not in normalized
                              else f"dataset_unsearchable:{dataset}:IP predicate unavailable")
                    unresolved.append(PivotCoverage(
                        target=target, dataset=dataset, start=args.start, end=args.end,
                        status="partial", reasons=[reason], returned=0, total=None,
                        unresolved_ranges=[_range(args.start, args.end, reason)],
                    ))
                continue
            if _is_network(target, contract):
                continue
            if (_supports(contract, "event.dataset")
                    or (contract.os_family == "windows" and _supports(contract, "event.channel"))):
                continue
            for dataset in _host_datasets(contract):
                reason = f"dataset_unsearchable:{dataset}:event.dataset predicate unavailable"
                unresolved.append(PivotCoverage(
                    target=target, dataset=dataset, start=args.start, end=args.end,
                    status="partial", reasons=[reason], returned=0, total=None,
                    unresolved_ranges=[_range(args.start, args.end, reason)],
                ))
        return unresolved

    def resolve_host_ip(self, owner: str, ip: str, start: datetime, end: datetime,
                        query_cap: int | None = None) -> tuple[str | None, str | None]:
        """Resolve a network endpoint to one host identity from typed host records: the `host.name` values of
        records whose `host.ip` equals the address, over the hunt window. Returns (host, None) for exactly one
        name, else (None, reason). The lookup is a budgeted, durable task: a resumed hunt reuses its outcome.
        A new lookup is refused when its queries would take the executor past `query_cap`."""
        targets = [(target, contract) for target, contract in sorted(self.contracts.items())
                   if not _is_network(target, contract) and _supports(contract, "host.ip")
                   and (contract.spec("host.name") is not None and contract.spec("host.name").aggregatable)]
        if not targets:
            return None, f"victim host unknown for {ip}: no host source has a searchable host.ip field"
        fingerprint_input = {
            "hunt": self.hunt_id,
            "source_query_scope": getattr(self, "source_query_scope", None) or "expansion",
            "resolve_host_ip": ip,
            "start": start.isoformat(),
            "end": end.isoformat(),
            "targets": [target for target, _ in targets],
        }
        # Mixed hunts include the typed identity model in the task key even when only a Linux target exposes
        # a searchable host.ip field.
        windows_identity = any(
            contract.os_family == "windows"
            or bool(set(self.dataset_inventory.get(target, ())).intersection(WINDOWS_HOST_DATASETS))
            for target, contract in self.contracts.items()
        )
        if windows_identity:
            fingerprint_input["host_identity"] = "typed-v2"
        fingerprint = digest(fingerprint_input)
        task_id = "t-" + fingerprint[:20]
        prior = self.repo.task(task_id)
        if prior and prior["state"] == "evaluated" and isinstance(prior.get("outcome"), dict):
            return prior["outcome"].get("host"), prior["outcome"].get("reason")
        if query_cap is not None and self.source_queries + len(targets) > query_cap:
            return None, f"victim host not resolved for {ip}: {HOST_LOOKUP_BUDGET}"
        intent_record = {"resolve_host_ip": ip, "targets": [target for target, _ in targets]}
        if windows_identity:
            intent_record["host_identity"] = "typed-v2"
        self.repo.upsert_task(task_id, self.hunt_id, _link_task_kind(self), "host-resolution", intent_record,
                              fingerprint, owner_token=self.owner_token)
        self.repo.update_task(task_id, "leased", attempt=True, owner_token=self.owner_token)
        identities: dict[tuple[str, str], str] = {}
        incomplete: list[str] = []
        for target, contract in targets:
            intent = SearchIntent(kind="aggregate", target=target, window=Window(start=start, end=end),
                                  filters=[Predicate(field="host.ip", op="eq", value=ip)], group_by=["host.name"],
                                  purpose="expansion:resolve_host_ip")
            outcome = self._execute(intent, contract, spend_task_id=task_id)
            if outcome.completeness != Completeness.complete:
                incomplete.append(f"{target}: {'; '.join(outcome.reasons or [outcome.error or 'incomplete'])}")
            for bucket in outcome.buckets:
                name = bucket["key"].get("host.name")
                if name in (None, ""):
                    continue
                # Windows contracts aggregate their native computer-name field, which commonly carries an FQDN,
                # while normalization deliberately uses the lower-case short name as the typed host identity.
                # Resolve to that same identity before links, anchors and scheduling consume it.
                resolved = str(name)
                if contract.os_family == "windows":
                    native = resolved.strip().rstrip(".").casefold()
                    resolved = native.split(".", 1)[0]
                else:
                    native = resolved
                if resolved:
                    identities[(contract.os_family or "unknown", native)] = resolved
        if incomplete:
            host, reason = None, f"victim host unresolved for {ip}: host lookup incomplete ({'; '.join(incomplete)})"
        elif len(identities) == 1:
            host, reason = next(iter(identities.values())), None
        elif not identities:
            host, reason = None, f"victim host unknown for {ip}: {NO_HOST_RECORD} {ip}"
        else:
            native_names = sorted(native for _os_family, native in identities)
            host, reason = None, f"{HOST_AMBIGUOUS} for {ip}: {native_names[:5]}"
        # An incomplete lookup (timeout, shard failure, budget) is not a final answer: it stays retryable.
        self.repo.update_task(task_id, "partial" if incomplete else "evaluated",
                              outcome={"host": host, "reason": reason}, owner_token=self.owner_token)
        return host, reason

    def _execute_partitions(
        self,
        intent: SearchIntent,
        contract: FieldContract,
        anchor_ts: datetime | None = None,
        *,
        fetch_query_start: int | None = None,
        query_cap: int | None = None,
        spend_task_id: str | None = None,
        record_cap: int | None = None,
        max_partitions: int | None = None,
    ):
        """Breadth-first capped-window splitting keeps late activity represented within a fixed leaf budget."""
        if record_cap is not None:
            # Dependent joins share a physical row budget across hops: splitting a
            # capped parent would fetch its rows again and consume that budget twice.
            cap = min(intent.max_records, record_cap)
            cap = cap if cap <= 2000 else cap // 2000 * 2000
            bounded = intent.model_copy(update={"max_records": cap})
            ceiling = (fetch_query_start + query_cap if query_cap is not None and fetch_query_start is not None
                       else self.source_queries + 128)
            outcome = self._execute(bounded, contract, spend_task_id=spend_task_id, physical_query_limit=ceiling)
            if intent.purpose == "expansion:host-witness" and outcome.completeness == Completeness.partial:
                # This query establishes existence, not complete host history.
                # Truncating its sample does not make the lease hypothesis partial.
                reasons = [reason for reason in outcome.reasons if not reason.startswith("cap:")]
                if not reasons and outcome.returned:
                    outcome = outcome.model_copy(update={"completeness":Completeness.complete,"reasons":[]})
            reason = "; ".join(outcome.reasons or [outcome.error or "source retrieval incomplete"])
            complete = outcome.completeness == Completeness.complete
            return [(bounded, outcome,
                     [_range(intent.window.start, intent.window.end,
                             "bounded host activity existence probe" if intent.purpose == "expansion:host-witness"
                             else "source retrieval complete")] if complete else [],
                     [] if complete else [_range(intent.window.start, intent.window.end, reason)])]
        partitions = max_partitions or MAX_PIVOT_PARTITIONS
        pending = deque([intent])
        leaves = []
        while pending:
            current = pending.popleft()
            if (query_cap is not None and fetch_query_start is not None
                    and self.source_queries - fetch_query_start >= query_cap):
                now = datetime.now(UTC)
                reason = f"expansion_link_query_cap:{query_cap}"
                outcome = SearchOutcome(
                    target=current.target, fingerprint=digest(current.model_dump(mode="json")),
                    started_at=now, ended_at=now, completeness=Completeness.partial,
                    reasons=[reason], returned=0,
                )
                leaves.append((current, outcome, [], [
                    _range(current.window.start, current.window.end, reason),
                ]))
                continue
            outcome = self._execute(current, contract, spend_task_id=spend_task_id)
            room = self._agent_room()
            if _is_capped(outcome.reasons) and (current.window.end - current.window.start) > MIN_PIVOT_SPLIT * 2:
                projected_leaves = len(leaves) + len(pending) + 2
                # the agent splits only when its queries left can read every resulting window: a split it cannot
                # finish would discard this window's records for halves it never reads
                affordable = room is None or room[0] >= len(pending) + 2
                if projected_leaves <= partitions and affordable:
                    midpoint = current.window.start + (current.window.end - current.window.start) / 2
                    pending.append(current.model_copy(update={
                        "window": Window(start=current.window.start, end=midpoint),
                    }))
                    pending.append(current.model_copy(update={
                        "window": Window(start=midpoint, end=current.window.end),
                    }))
                    continue
                limit = (f"pivot_partition_limit:{partitions}" if projected_leaves > partitions
                         else self._agent_cap(room[1]))
                outcome = outcome.model_copy(update={
                    "reasons": sorted(set(outcome.reasons + [limit])),
                })
            elif _is_capped(outcome.reasons):
                outcome = outcome.model_copy(update={
                    "reasons": sorted(set(outcome.reasons + [f"pivot_min_split:{int(MIN_PIVOT_SPLIT.total_seconds())}s"])),
                })
            # The cap is hard: a capped leaf is sampled only when every sampling query fits under it.
            if (_is_capped(outcome.reasons) and query_cap is not None and fetch_query_start is not None
                    and self.source_queries - fetch_query_start + MAX_SAMPLE_QUERIES > query_cap):
                reason = f"expansion_link_query_cap:{query_cap}"
                outcome = outcome.model_copy(update={
                    "reasons": sorted(set(outcome.reasons + [reason])),
                })
                covered_ranges = []
                unresolved_ranges = [_range(current.window.start, current.window.end, reason)]
            elif _is_capped(outcome.reasons) and room is not None and room[0] < MAX_SAMPLE_QUERIES:
                # the agent's queries left cannot sample this leaf: its capped records are kept, the window unresolved
                reason = self._agent_cap(room[1])
                outcome = outcome.model_copy(update={"reasons": sorted(set(outcome.reasons + [reason]))})
                covered_ranges = []
                unresolved_ranges = [_range(current.window.start, current.window.end, reason)]
            elif _is_capped(outcome.reasons):
                outcome, covered_ranges, unresolved_ranges = self._sample_terminal(
                    current, outcome, contract, anchor_ts, spend_task_id=spend_task_id,
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

    def save_batch_selection(self, batch: PivotEventBatch, events: list[TypedEvent]) -> None:
        """Persist only the final events selected from a fetched link batch."""
        self._save_selected_events(events, batch.raw_sources, batch.task_by_event, batch.task_ids)

    def _save_selected_events(
        self,
        events: list[TypedEvent],
        raw_sources: dict[str, dict],
        task_by_event: dict[str, str],
        task_ids: list[str],
    ) -> None:
        fallback_task = task_ids[0] if len(task_ids) == 1 else None
        grouped: dict[str | None, dict[str, TypedEvent]] = {}
        for event in events:
            task_id = task_by_event.get(event.id, fallback_task)
            grouped.setdefault(task_id, {}).setdefault(event.id, event)
        for task_id, selected in grouped.items():
            self.repo.save_evidence(
                self.hunt_id, selected.values(), raw_sources, task_id, owner_token=self.owner_token,
            )

    @_with_script_blocks
    def fetch_intents(
        self,
        owner: str,
        fetch_key: str,
        intents: list[SearchIntent],
        retain: Callable[[TypedEvent], bool],
        *,
        anchor_ts: datetime | None = None,
        query_cap: int | None = None,
        planning_coverage: list[PivotCoverage] | None = None,
        raw_families: set[str] | None = None,
        persist: bool = True,
        max_total_records: int | None = None,
    ) -> PivotEventBatch:
        """Execute deterministic typed link intents without evaluating any playbook."""
        if anchor_ts is not None:
            # SQLite drops timezone metadata; persisted hunt timestamps are defined as UTC.
            anchor_ts = (anchor_ts.replace(tzinfo=UTC) if anchor_ts.tzinfo is None
                         else anchor_ts.astimezone(UTC))
        started = perf_counter()
        task_ids: list[str] = []
        retained: dict[str, TypedEvent] = {}
        task_by_event: dict[str, str] = {}
        raw_sources: dict[str, dict] = {}
        script_blocks = self._script_blocks
        coverage: list[PivotCoverage] = list(planning_coverage or [])
        reasons: list[str] = [reason for cell in coverage for reason in cell.reasons]
        successful = 0
        incomplete = bool(coverage)
        # a dependent join's sources share one row bound in their planned order: they are never rotated
        intents = self._agent_plan_call(list(intents), rotate=max_total_records is None)
        fetch_query_start = self.source_queries
        fetched_records = 0
        for position, intent in enumerate(intents):
            if intent.purpose == "expansion:host-witness" and retained:
                break
            if max_total_records is not None and fetched_records >= max_total_records:
                reasons.append(f"Zeek link shared fetched-row limit {max_total_records} reached; remaining sources unresolved")
                incomplete = True
                break
            if max_total_records is not None and query_cap is not None and self.source_queries-fetch_query_start >= query_cap:
                reasons.append(f"expansion_link_query_cap:{query_cap}; remaining sources unresolved")
                incomplete = True
                break
            allowance = self._intent_allowance(len(intents) - position)
            if allowance is not None and allowance[0] == 0:
                # the agent's query cap is reached: this source is named as not searched, and gets no task
                incomplete = True
                reasons.append(allowance[1])
                coverage.append(self._unsearched_cell(intent, allowance[1]))
                continue
            fingerprint = digest({
                "source_query_scope": self.source_query_scope or "expansion",
                "fetch_key": fetch_key,
                "intent": intent.model_dump(mode="json"),
            })
            task_id = "t-" + fingerprint[:20]
            task_ids.append(task_id)
            self.repo.upsert_task(
                task_id, self.hunt_id, _link_task_kind(self), owner,
                intent.model_dump(mode="json"), fingerprint, owner_token=self.owner_token,
            )
            self.repo.update_task(task_id, "leased", attempt=True, owner_token=self.owner_token)
            task_coverage: list[PivotCoverage] = []
            task_reasons: list[str] = []
            task_error = None
            task_successes = 0
            for leaf_intent, outcome, covered_ranges, unresolved_ranges in self._execute_partitions(
                    intent, self.contracts[intent.target], anchor_ts,
                    fetch_query_start=fetch_query_start, query_cap=query_cap,
                    spend_task_id=task_id,
                    record_cap=None if max_total_records is None else max_total_records-fetched_records):
                fetched_records += outcome.returned
                leaf_reasons = list(outcome.reasons)
                selected: list[TypedEvent] = []
                if outcome.completeness == Completeness.failed:
                    task_error = task_error or outcome.error
                    leaf_reasons.extend(outcome.reasons or [outcome.error or "source execution failed"])
                    status = "failed"
                else:
                    successful += 1
                    task_successes += 1
                    sources = {
                        f"{record['_index']}/{record['_id']}": record["_source"]
                        for record in outcome.records
                    }
                    contract=self.contracts[intent.target]
                    events, errors = (self._normalize_pivot_records(outcome.records,raw_families,contract,
                                                                    getattr(outcome, "surrogate_free", False))
                                      if contract.zeek_sensor else
                                      self._normalize_pivot_records(outcome.records,raw_families,
                                                                    surrogate_free=getattr(outcome, "surrogate_free", False)))
                    sources.update(script_blocks.sources_for(events))
                    normalization_reasons = [
                        *self._ip_normalization_reasons(leaf_intent, outcome.records),
                        *_script_metadata_reasons(events),
                        *windows_identity_reasons(events),
                    ]
                    if script_blocks.refusal_reason:
                        normalization_reasons.append(
                            "PowerShell script-block reassembly partial: " + script_blocks.refusal_reason
                        )
                    leaf_reasons.extend(normalization_reasons)
                    if errors or normalization_reasons:
                        if errors:
                            leaf_reasons.append(f"normalization_errors:{len(errors)}")
                        covered_ranges = []
                        unresolved_ranges = [_range(
                            leaf_intent.window.start, leaf_intent.window.end,
                            "; ".join(sorted(set(normalization_reasons + (
                                [f"normalization_errors:{len(errors)}"] if errors else []
                            )))),
                        )]
                    selected = [event for event in events if retain(event)]
                    raw_sources.update(sources)
                    for event in selected:
                        task_by_event.setdefault(event.id, task_id)
                    if persist:
                        self.repo.save_evidence(
                            self.hunt_id, selected, sources, task_id, owner_token=self.owner_token,
                        )
                    retained.update({event.id: event for event in selected})
                    status = ("complete" if outcome.completeness == Completeness.complete
                              and not errors and not normalization_reasons else "partial")
                incomplete |= status != "complete"
                reasons.extend(leaf_reasons)
                task_reasons.extend(leaf_reasons)
                task_coverage.append(PivotCoverage(
                    target=intent.target, dataset=self._intent_dataset(intent),
                    start=leaf_intent.window.start.astimezone(UTC),
                    end=leaf_intent.window.end.astimezone(UTC), status=status,
                    reasons=sorted(set(leaf_reasons)), returned=outcome.returned, total=outcome.total,
                    covered_ranges=covered_ranges, unresolved_ranges=unresolved_ranges,
                ))
            task_coverage = _coalesce_coverage(task_coverage)
            coverage.extend(task_coverage)
            outcome_digest = {
                "completeness": "failed" if task_successes == 0 else (
                    "partial" if any(cell.status != "complete" for cell in task_coverage) else "complete"
                ),
                "reasons": sorted(set(task_reasons)),
                "coverage": [cell.model_dump(mode="json") for cell in task_coverage],
                # records the source returned for this task, so evaluation can count expansion's retrieval cost
                "returned": sum(cell.returned or 0 for cell in task_coverage),
            }
            if task_successes == 0:
                self.repo.update_task(
                    task_id, "failed", outcome=outcome_digest, error=task_error,
                    owner_token=self.owner_token,
                )
            else:
                self.repo.update_task(task_id, "evaluated", outcome=outcome_digest, owner_token=self.owner_token)
        unfinished = 0
        final_script_reasons: set[str] = set()
        fallback_task = task_ids[0] if task_ids else ""
        for event in script_blocks.finalize():
            unfinished += 1
            final_script_reasons.update(_script_metadata_reasons([event]))
            sources = script_blocks.sources_for([event])
            if not retain(event):
                continue
            raw_sources.update(sources)
            retained.setdefault(event.id, event)
            if fallback_task:
                task_by_event.setdefault(event.id, fallback_task)
        if unfinished:
            reason = f"PowerShell script-block reassembly incomplete for {unfinished} block(s)"
            if final_script_reasons:
                reason += "; " + "; ".join(sorted(final_script_reasons))
            incomplete = True
            reasons.append(reason)
            coverage = [cell.model_copy(update={
                "status": "partial", "reasons": sorted(set(cell.reasons + [reason])),
                "covered_ranges": [],
                "unresolved_ranges": [_range(cell.start, cell.end, reason)],
            }) for cell in coverage]
        self._intent_ceiling = None
        status = "failed" if successful == 0 else "partial" if incomplete else "complete"
        return PivotEventBatch(
            status=status, task_ids=task_ids,
            events=sorted(retained.values(), key=lambda event: (event.ts, event.id)),
            raw_sources=raw_sources, coverage=_coalesce_coverage(coverage),
            reasons=sorted(set(reasons)), duration_ms=int((perf_counter() - started) * 1000),
            task_by_event=task_by_event,
        )

    def _sample_terminal(
        self, intent: SearchIntent, initial: SearchOutcome,
        contract: FieldContract, anchor_ts: datetime | None,
        *, spend_task_id: str | None = None,
    ):
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
                head = self._execute(
                    head_intent, contract, pit=pit, spend_task_id=spend_task_id,
                )
                attempts.append((head_intent, head))
                if (head.completeness == Completeness.complete and not head.reasons
                        and _safe_sample_interval(head, head_intent, contract) is not None):
                    return head, [_range(
                        intent.window.start, intent.window.end,
                        "shared-PIT ascending retrieval completed the full attempted range",
                    )], []

                tail_intent = intent.model_copy(update={"order": "desc"})
                tail = self._execute(
                    tail_intent, contract, pit=pit, spend_task_id=spend_task_id,
                )
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
                    attempts.append((before, self._execute(
                        before, contract, pit=pit, spend_task_id=spend_task_id,
                    )))
                    attempts.append((after, self._execute(
                        after, contract, pit=pit, spend_task_id=spend_task_id,
                    )))
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
        if isinstance(request, SearchEventsRequest):
            # the source matched the typed conditions on the contract's native fields: every record it returned is
            # the search's answer (a record no normalizer read is named by the search, never dropped silently)
            return True
        args = request.arguments
        windows_host = event.get("host.os.family") == "windows" or event.normalizer.startswith("windows-")

        def same_host(left: object, right: object) -> bool:
            left_text = str(left or "").strip().rstrip(".")
            right_text = str(right or "").strip().rstrip(".")
            if windows_host:
                return left_text.split(".", 1)[0].casefold() == right_text.split(".", 1)[0].casefold()
            return left_text == right_text

        if isinstance(request, EntityTimelineRequest):
            entity = args.entity
            return any(
                item.kind == entity.kind
                and (same_host(item.value, entity.value) if entity.kind == "host" else item.value == entity.value)
                for item in _event_entities(event)
            )
        if isinstance(request, AuthActivityRequest):
            if event.family not in {"auth", "privilege_use"}:
                return False
            entity = args.entity
            return (same_host(event.host, entity.value) if entity.kind == "host" else
                    any(item.kind == "account" and item.value == entity.value for item in _event_entities(event)))
        if isinstance(request, ProcessTreeRequest):
            if not same_host(event.host, args.host):
                return False
            if event.get("host.os.family") == "windows":
                return event.family in {"process_exec", "process_termination", "system_state"}
            return (event.family == "process_exec"
                    and args.process_id in {event.get("process.pid"), event.get("process.ppid")})
        if isinstance(request, IdsAlertsRequest):
            if event.family != "net_alert":
                return False
            entity = args.entity
            return (same_host(event.host, entity.value) if entity.kind == "host" else
                    any(item.kind == "ip" and item.value == entity.value for item in _event_entities(event)))
        return False

    @staticmethod
    def _select_windows_process_tree(
        events: list[TypedEvent], args: ProcessTreeArgs, anchor_ts: datetime | None,
        termination_attested: bool = False,
    ) -> tuple[list[TypedEvent], str | None]:
        candidates = sorted(
            (event for event in events
             if str(event.host or "").strip().rstrip(".").split(".", 1)[0].casefold()
             == str(args.host).strip().rstrip(".").split(".", 1)[0].casefold()),
            key=lambda event: (event.ts, event.id),
        )
        roots = [
            event for event in candidates
            if event.family == "process_exec" and event.get("process.pid") == args.process_id
        ]
        pivot_time = anchor_ts or (roots[0].ts if roots else args.start)
        prior_roots = [event for event in roots if event.ts <= pivot_time]
        root = None
        if prior_roots:
            lineage = ExecLineage()
            by_id = {}
            for event in prior_roots:
                lineage.observe(event)
                by_id[event.id] = event
            # Ask just after the anchor instant: every root at that instant is eligible, while ExecLineage orders
            # records only inside one audit or (computer, channel) record-id sequence and refuses differing images
            # across incomparable sequences.
            latest = lineage.latest(
                prior_roots[0].host,
                args.process_id,
                math.nextafter(pivot_time.timestamp(), math.inf),
            )
            if latest is None:
                return [], "process_tree root at anchor instant is ambiguous"
            root = by_id.get(latest.event_id)
        root_guid = root.get("process.guid") if root is not None else None
        if root_guid:
            guids = {str(root_guid).casefold()}
            selected: dict[str, TypedEvent] = {}
            changed = True
            while changed:
                changed = False
                for event in candidates:
                    if event.family != "process_exec":
                        continue
                    guid = str(event.get("process.guid") or "").casefold()
                    parent = str(event.get("process.parent.guid") or "").casefold()
                    if guid in guids or parent in guids:
                        selected[event.id] = event
                        if guid and guid not in guids:
                            guids.add(guid)
                            changed = True
            return list(selected.values()), None
        fences = [
            event for event in candidates
            if event.get("process.fence") == "boot"
            or (event.get("process.fence") == "termination" and event.get("process.pid") == args.process_id)
        ]
        if not fences:
            selected = [
                event for event in candidates
                if event.family == "process_exec"
                and args.process_id in {event.get("process.pid"), event.get("process.ppid")}
            ]
            reason = None if termination_attested else "process_tree PID fence evidence unavailable"
            return selected, reason
        lower, upper = args.start, args.end
        for fence in fences:
            if fence.ts <= pivot_time:
                lower = max(lower, fence.ts)
            else:
                upper = min(upper, fence.ts)
        return [
            event for event in candidates
            if event.family == "process_exec" and lower <= event.ts < upper
            and args.process_id in {event.get("process.pid"), event.get("process.ppid")}
        ], None

    @staticmethod
    def _select_process_tree_by_os(
        events: list[TypedEvent], args: ProcessTreeArgs, anchor_ts: datetime | None,
        termination_attested: bool = False,
    ) -> tuple[list[TypedEvent], str | None]:
        """Fence only Windows PID lineage; mixed-source Linux results keep Linux semantics."""
        windows = [event for event in events if event.get("host.os.family") == "windows"
                   or event.normalizer.startswith("windows-")]
        if not windows:
            return events, None
        windows_objects = {id(event) for event in windows}
        other = [event for event in events if id(event) not in windows_objects]
        selected, reason = PivotExecutor._select_windows_process_tree(
            windows, args, anchor_ts, termination_attested,
        )
        return [*other, *selected], reason

    @staticmethod
    def _unsearched_cell(intent: SearchIntent, reason: str) -> PivotCoverage:
        """A planned source the agent's query cap left unsearched: no task ran for it, and its whole window is
        unresolved (never zero hits)."""
        return PivotCoverage(
            target=intent.target, dataset=PivotExecutor._intent_dataset(intent), start=intent.window.start,
            end=intent.window.end, status="failed", reasons=[reason], returned=0, total=None,
            unresolved_ranges=[_range(intent.window.start, intent.window.end, reason)],
        )

    def _nothing_left(self, intents: list[SearchIntent], reason: str, started: float) -> PivotResult:
        """The result of a pivot the agent's query cap leaves nothing to spend on: failed, with the cap's reason, one
        unresolved cell for each planned source, and no task."""
        kind = reason.split(":", 1)[0]
        explained = (f"{_AGENT_CAP_EXPLAINED.get(kind, 'the source-query budget is spent')}: nothing was searched, "
                     "and no record was found or ruled out; rely on the results already returned")
        return PivotResult(
            status="failed", coverage=_coalesce_coverage([self._unsearched_cell(intent, reason) for intent in intents]),
            reasons=[reason, explained], duration_ms=int((perf_counter() - started) * 1000),
        )

    @_with_script_blocks
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
        search = isinstance(request, SearchEventsRequest)
        search_plan = self.plan_search(request) if search else None
        intents, planning_coverage = ((search_plan.intents, search_plan.coverage) if search_plan is not None
                                      else self.plan(request))
        if not intents:
            if planning_coverage:
                return PivotResult(
                    status="partial", coverage=planning_coverage,
                    reasons=sorted({reason for cell in planning_coverage for reason in cell.reasons}),
                )
            return PivotResult(status="unsupported", reasons=["no compatible source contract"])
        intents = self._agent_plan_call(intents)
        available = self.agent_available()
        if available is not None and available[0] == 0:
            # nothing can be searched: one result naming each planned source, and no task for any of them
            return self._nothing_left(intents, available[1], started)

        task_ids: list[str] = []
        retained: list[TypedEvent] = []
        task_by_event: dict[str, str] = {}
        raw_sources: dict[str, dict] = {}
        script_blocks = self._script_blocks
        reasons: list[str] = [reason for cell in planning_coverage for reason in cell.reasons]
        coverage: list[PivotCoverage] = list(planning_coverage)
        successful_outcomes = 0
        incomplete = bool(planning_coverage)
        search_fetched = discarded = 0
        skip_reasons: dict[str, int] = {}

        for position, intent in enumerate(intents):
            if search and search_fetched >= MAX_SEARCH_RECORDS:
                # the search's shared row bound: each target not yet searched is named, never counted as no match
                reason = f"search_record_limit:{MAX_SEARCH_RECORDS}: not evaluated: {intent.target}"
                incomplete = True
                reasons.append(reason)
                coverage.append(PivotCoverage(
                    target=intent.target, dataset=None, start=intent.window.start, end=intent.window.end,
                    status="partial", reasons=[reason], returned=0, total=None,
                    unresolved_ranges=[_range(intent.window.start, intent.window.end, reason)],
                ))
                continue
            allowance = self._intent_allowance(len(intents) - position)
            if allowance is not None and allowance[0] == 0:
                # the agent's query cap is reached: this source is named as not searched, and gets no task
                incomplete = True
                reasons.append(allowance[1])
                coverage.append(self._unsearched_cell(intent, allowance[1]))
                continue
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
                    intent, self.contracts[intent.target], anchor_ts,
                    spend_task_id=task_id, max_partitions=SEARCH_PARTITIONS if search else None):
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
                    sources = {
                        f"{record['_index']}/{record['_id']}": record["_source"]
                        for record in outcome.records
                    }
                    search_fetched += outcome.returned
                    contract = self.contracts[intent.target]
                    # a plain Zeek target's records are read through its contract, as a link fetch reads them
                    options = {"contract": contract} if search and contract.zeek_sensor else {}
                    events, skips, errors = normalize_hits(outcome.records,
                                                           surrogate_free=getattr(outcome, "surrogate_free", False),
                                                           **options)
                    if any(event.family == "script_block" for event in events):
                        events = script_blocks.consume(events, sources)
                        sources.update(script_blocks.sources_for(events))
                    normalization_reasons = [
                        *self._ip_normalization_reasons(leaf_intent, outcome.records),
                        *_script_metadata_reasons(events),
                        *windows_identity_reasons(events),
                        # a matched record no normalizer read is a match the search cannot show: named, not dropped
                        *(self._skip_reasons(skips, skip_reasons) if search else []),
                    ]
                    if script_blocks.refusal_reason:
                        normalization_reasons.append(
                            "PowerShell script-block reassembly partial: " + script_blocks.refusal_reason
                        )
                    leaf_reasons.extend(normalization_reasons)
                    if errors or normalization_reasons:
                        if errors:
                            leaf_reasons.append(f"normalization_errors:{len(errors)}")
                        covered_ranges = []
                        unresolved_ranges = [_range(
                            leaf_intent.window.start, leaf_intent.window.end,
                            "; ".join(sorted(set(normalization_reasons + (
                                [f"normalization_errors:{len(errors)}"] if errors else []
                            )))),
                        )]
                    if search:
                        selected = [event for event in events
                                    if _search_keeps(search_plan.checks[intent.target], event)]
                        discarded += len(events) - len(selected)
                    else:
                        selected = [event for event in events if self._retain(request, event)]
                    raw_sources.update(sources)
                    for event in selected:
                        task_by_event.setdefault(event.id, task_id)
                    retained.extend(selected)
                    status = ("complete" if outcome.completeness == Completeness.complete
                              and not errors and not normalization_reasons else "partial")
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

        unfinished = 0
        final_script_reasons: set[str] = set()
        fallback_task = task_ids[0] if task_ids else ""
        for event in script_blocks.finalize():
            unfinished += 1
            final_script_reasons.update(_script_metadata_reasons([event]))
            sources = script_blocks.sources_for([event])
            if search:
                if not any(_search_keeps(checks, event) for checks in search_plan.checks.values()):
                    discarded += 1
                    continue
            elif not self._retain(request, event):
                continue
            retained.append(event)
            raw_sources.update(sources)
            if fallback_task:
                task_by_event.setdefault(event.id, fallback_task)
        if unfinished:
            reason = f"PowerShell script-block reassembly incomplete for {unfinished} block(s)"
            if final_script_reasons:
                reason += "; " + "; ".join(sorted(final_script_reasons))
            incomplete = True
            reasons.append(reason)
            coverage = [cell.model_copy(update={
                "status": "partial", "reasons": sorted(set(cell.reasons + [reason])),
                "covered_ranges": [],
                "unresolved_ranges": [_range(cell.start, cell.end, reason)],
            }) for cell in coverage]

        if isinstance(request, ProcessTreeRequest):
            retained, fence_reason = self._select_process_tree_by_os(
                retained, request.arguments, anchor_ts,
                self.process_termination_attested(request.arguments.host),
            )
            if fence_reason:
                incomplete = True
                reasons.append(fence_reason)
                coverage = [cell.model_copy(update={
                    "status": "partial",
                    "reasons": sorted(set(cell.reasons + [fence_reason])),
                    "covered_ranges": [],
                    "unresolved_ranges": [_range(cell.start, cell.end, fence_reason)],
                }) for cell in coverage]

        self._save_selected_events(retained, raw_sources, task_by_event, task_ids)

        candidate_ids: list[str] = []
        for playbook in bind_windows_site(fresh_direct_pack(), self.site_facts):
            for match in playbook.consume(retained):
                row = publish_match(
                    self.repo, self.hunt_id, playbook, match, task_ids[0] if task_ids else None,
                    raw_sources, source_case_id=case_id, owner_token=self.owner_token, zeek_context=retained,
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
        if search and len(unique_entities) > MAX_SEARCH_ENTITIES:
            # hosts first, then addresses, accounts and domains: the rest are counted, and each matched record
            # still names its own
            kept = sorted(unique_entities, key=lambda key: (_ENTITY_ORDER.get(key[0], 9), key))[:MAX_SEARCH_ENTITIES]
            reasons.append(f"search_entities_listed:{MAX_SEARCH_ENTITIES}:of:{len(unique_entities)}")
            unique_entities = {key: unique_entities[key] for key in kept}
        self._intent_ceiling = None
        # nothing searched is failed, whatever stopped it (a budget's own reason says it was a bounded stop); zero
        # hits from what was searched is never an absence either way
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
            reach_event_ids=sorted(unique_events),
            candidate_ids=candidate_ids,
            entities=list(unique_entities.values()),
            event_summaries=[_summary(event) for event in sampled_events],
            anchor_event_ids=[event.id for event in anchor_events],
            matched_event_count=len(unique_events),
            coverage=_coalesce_coverage(coverage),
            reasons=sorted(set(reasons)),
            duration_ms=duration_ms,
            zero_caveats=search_plan.caveats if search_plan is not None else [],
            discarded=discarded,
        )

    @staticmethod
    def _skip_reasons(skips: dict[str, int], seen: dict[str, int]) -> list[str]:
        """Reasons naming the matched records no normalizer read: at most MAX_SEARCH_SKIP_REASONS distinct ones in
        one search, the rest counted together."""
        out = []
        for why, count in sorted(skips.items()):
            if not count:
                continue
            if why in seen or len(seen) < MAX_SEARCH_SKIP_REASONS:
                seen[why] = seen.get(why, 0) + count
                out.append(f"records_not_normalized:{count}:{_text(why)}")
            else:
                out.append(f"records_not_normalized:{count}:other reasons past the first {MAX_SEARCH_SKIP_REASONS}")
        return out
