"""Typed deterministic link fetchers for post-sweep expansion."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from romulus.agent.models import PivotCoverage
from romulus.agent.tools import EntityTimelineArgs, EntityTimelineRequest
from romulus.detect.correlation import PidTable
from romulus.evidence.typed import TypedEvent
from romulus.hunt.pivot import MAX_PIVOT_RECORDS, PivotExecutor, _is_network, _range, _supports
from romulus.sources.models import Predicate, SearchIntent, Window
from romulus.store.db import digest

LinkType = Literal[
    "process_lineage", "login_session", "network_flow", "flow_host_side",
    "source_ip", "account", "host_after_anchor",
]
LinkStrength = Literal["observed", "inferred"]
# Links that look only forward from the anchor: they fetch [anchor, window end), and say so.
FORWARD_LINKS = frozenset({"source_ip", "account", "host_after_anchor"})
# A flow key (community ID, 5-tuple) is time-free: port reuse and fixed-port UDP (123, 514) can join different
# flows far apart in time, so a flow join is observed only close to the anchor.
OBSERVED_FLOW_SPAN = timedelta(minutes=10)

UNUSABLE_TEXT_KEYS = {"", "-1", "4294967295", "(null)", "(none)", "unset", "(unknown)"}
# Links that need a host identity: they search one host's own records.
HOST_SIDE_LINKS = frozenset({"process_lineage", "login_session", "host_after_anchor"})


def usable_key(value: Any) -> bool:
    """Return whether a typed pivot key is meaningful and safe to use."""
    if value is None or isinstance(value, bool):
        return False
    if isinstance(value, int) and value in {-1, 4294967295}:
        return False
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in UNUSABLE_TEXT_KEYS:
            return False
        try:
            address = ip_address(normalized)
        except ValueError:
            return True
        return not (address.is_unspecified or address.is_loopback)
    return True


class LinkWindow(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    label: str
    start: datetime
    end: datetime


class LinkAnchor(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    finding_id: str
    ts: datetime
    host: str | None = None                  # a host identity from typed records; never an IP
    victim_ip: str | None = None             # set when `host` was resolved (or not) from a network endpoint
    host_reason: str | None = None           # why no host identity is available for victim_ip
    event_ids: list[str] = Field(default_factory=list)
    events: list[TypedEvent] = Field(default_factory=list)


class LinkResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    anchor_id: str
    link_type: LinkType
    window: LinkWindow
    strength: LinkStrength
    key: dict[str, Any]
    status: Literal["complete", "partial", "failed", "unsupported"]
    event_ids: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    task_ids: list[str] = Field(default_factory=list)
    coverage: list[PivotCoverage] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
    duration_ms: int = 0
    query_spend: int = 0


def _value(anchor: LinkAnchor, field: str):
    for event in sorted(anchor.events, key=lambda item: (item.ts, item.id)):
        if event.has(field):
            return event.get(field)
    return None


def _victim(anchor: LinkAnchor) -> dict:
    return {"victim_ip": anchor.victim_ip} if anchor.victim_ip else {}


def _host_reason(anchor: LinkAnchor) -> str | None:
    """Why a host-side link cannot run for this anchor, or None when it has a usable host identity."""
    if usable_key(anchor.host):
        return None
    return anchor.host_reason or "required typed key is unusable"


def _tuple(event: TypedEvent) -> tuple | None:
    values = (
        event.get("network.transport"), event.get("source.ip"), event.get("source.port"),
        event.get("destination.ip"), event.get("destination.port"),
    )
    return values if all(value is not None for value in values) else None


def _tuple_matches(left: tuple, right: tuple) -> bool:
    transport, src, sport, dst, dport = left
    rtransport, rsrc, rsport, rdst, rdport = right
    return transport == rtransport and (
        (src, sport, dst, dport) == (rsrc, rsport, rdst, rdport)
        or (src, sport, dst, dport) == (rdst, rdport, rsrc, rsport)
    )


class LinkFetcher:
    """Fetch each `(anchor, link, window)` once and keep typed-key semantics local and explicit."""

    def __init__(self, executor: PivotExecutor, hunt_start: datetime, hunt_end: datetime):
        self.executor = executor
        self.hunt_start = hunt_start.astimezone(UTC)
        self.hunt_end = hunt_end.astimezone(UTC)
        self._cache: dict[str, LinkResult] = {}
        self._hosts: dict[str, tuple[str | None, str | None]] = {}

    def resolve_host(self, owner: str, ip: str) -> tuple[str | None, str | None]:
        """A network endpoint's host identity from typed host records (`host.ip`), or why there is none.
        Exactly one host name resolves; none or several is a reason, never a guess."""
        if ip not in self._hosts:
            resolver = getattr(self.executor, "resolve_host_ip", None)
            self._hosts[ip] = (resolver(owner, ip, self.hunt_start, self.hunt_end) if resolver is not None
                               else (None, f"victim host unknown for {ip}: host resolution is unavailable"))
        return self._hosts[ip]

    def fetch(
        self,
        anchor: LinkAnchor,
        link_type: LinkType,
        window: LinkWindow,
        *,
        query_cap: int | None = None,
    ) -> LinkResult:
        key, strength, intents, retain, select, unsupported_reason, planning_coverage = self._plan(
            anchor, link_type, window,
        )
        fetch_key = self._fetch_key(anchor, link_type, window, key)
        if fetch_key in self._cache:
            return self._cache[fetch_key]
        if link_type in FORWARD_LINKS:          # persist the window actually searched
            anchor_ts = anchor.ts.astimezone(UTC) if anchor.ts.tzinfo else anchor.ts.replace(tzinfo=UTC)
            window = LinkWindow(label=window.label, start=max(anchor_ts, window.start), end=window.end)
        if not intents:
            if unsupported_reason:
                result = LinkResult(
                    id="link-" + fetch_key[:20], anchor_id=anchor.finding_id,
                    link_type=link_type, window=window, strength=strength, key=key,
                    status="unsupported", coverage=planning_coverage,
                    reasons=[unsupported_reason],
                )
                self._cache[fetch_key] = result
                return result
            if planning_coverage:
                reasons = sorted({reason for cell in planning_coverage for reason in cell.reasons})
                result = LinkResult(
                    id="link-" + fetch_key[:20], anchor_id=anchor.finding_id, link_type=link_type,
                    window=window, strength=strength, key=key, status="partial",
                    coverage=planning_coverage, reasons=reasons,
                )
                self._cache[fetch_key] = result
                return result
            result = LinkResult(
                id="link-" + fetch_key[:20], anchor_id=anchor.finding_id, link_type=link_type,
                window=window, strength=strength, key=key, status="unsupported",
                reasons=["required typed key or compatible source contract is unavailable"],
            )
            self._cache[fetch_key] = result
            return result
        query_start = getattr(self.executor, "source_queries", 0)
        batch = self.executor.fetch_intents(
            anchor.finding_id, fetch_key, intents, retain, anchor_ts=anchor.ts, query_cap=query_cap,
            planning_coverage=planning_coverage,
        )
        linked = select(batch.events)
        linked = sorted(
            (event for event in linked if event.id not in set(anchor.event_ids)),
            key=lambda event: (event.ts, event.id),
        )
        result = LinkResult(
            id="link-" + fetch_key[:20], anchor_id=anchor.finding_id, link_type=link_type,
            window=window, strength=strength, key=key, status=batch.status,
            event_ids=[event.id for event in linked],
            evidence_ids=sorted(set(anchor.event_ids + [event.id for event in linked])),
            task_ids=batch.task_ids, coverage=batch.coverage, reasons=batch.reasons,
            duration_ms=batch.duration_ms,
            query_spend=getattr(self.executor, "source_queries", query_start) - query_start,
        )
        self._cache[fetch_key] = result
        return result

    @staticmethod
    def _fetch_key(anchor: LinkAnchor, link_type: LinkType, window: LinkWindow, key: dict) -> str:
        return digest({
            "anchor": anchor.finding_id, "link": link_type,
            "window": window.model_dump(mode="json"), "key": key,
        })

    def result_id(self, anchor: LinkAnchor, link_type: LinkType, window: LinkWindow) -> str:
        key, *_rest = self._plan(anchor, link_type, window)
        return "link-" + self._fetch_key(anchor, link_type, window, key)[:20]

    def _plan(self, anchor: LinkAnchor, link_type: LinkType, window: LinkWindow):
        handlers = {
            "process_lineage": self._lineage,
            "login_session": self._session,
            "network_flow": self._flow,
            "flow_host_side": self._flow_host_side,
            "source_ip": self._source_ip,
            "account": self._account,
            "host_after_anchor": self._host_after,
        }
        return handlers[link_type](anchor, window)

    def _host_intents(self, window: LinkWindow, datasets: tuple[str, ...], host: str | None = None):
        intents = []
        for target, contract in sorted(self.executor.contracts.items()):
            if _is_network(target, contract) or not _supports(contract, "event.dataset"):
                continue
            for dataset in datasets:
                filters = [Predicate(field="event.dataset", op="eq", value=dataset)]
                if host is not None:
                    if not _supports(contract, "host.name"):
                        continue
                    filters.append(Predicate(field="host.name", op="eq", value=host))
                intents.append(SearchIntent(
                    kind="raw", target=target, window=Window(start=window.start, end=window.end),
                    filters=filters, max_records=MAX_PIVOT_RECORDS,
                    purpose=f"expansion:{dataset}",
                ))
        return intents

    def _endpoint_intents(self, window: LinkWindow, endpoints: list[list]):
        """Audit socket records on any host whose remote endpoint is one of these (ip, port) pairs."""
        intents = []
        for target, contract in sorted(self.executor.contracts.items()):
            if (_is_network(target, contract) or not _supports(contract, "event.dataset")
                    or not all(_supports(contract, field) for field in ("destination.ip", "destination.port"))):
                continue
            intents.append(SearchIntent(
                kind="raw", target=target, window=Window(start=window.start, end=window.end),
                filters=[Predicate(field="event.dataset", op="eq", value="linux.audit")],
                any_of=[[Predicate(field="destination.ip", op="eq", value=ip),
                         Predicate(field="destination.port", op="eq", value=port)] for ip, port in endpoints],
                max_records=MAX_PIVOT_RECORDS, purpose="expansion:flow_host_side",
            ))
        return intents

    def _lineage(self, anchor: LinkAnchor, window: LinkWindow):
        pid = _value(anchor, "process.pid")
        boot_id = _value(anchor, "host.boot.id")
        key = {"host": anchor.host, "pid": pid, "host.boot.id": boot_id, **_victim(anchor)}
        intents = self._host_intents(window, ("linux.audit",), anchor.host) if isinstance(pid, int) else []

        def select(events):
            all_events = {event.id: event for event in anchor.events + events
                          if event.family == "process_exec" and event.host == anchor.host
                          and (boot_id is None or event.get("host.boot.id") == boot_id)}
            root = next((event for event in anchor.events if event.get("process.pid") == pid), None)
            if root is None:
                return []
            table = PidTable()
            by_raw = {}
            for event in all_events.values():
                table.add(event)
                for raw in event.raw:
                    by_raw[raw.native_id] = event
            root_entry = table.lookup(anchor.host or "", pid, root.ts.timestamp())
            if root_entry is None:
                return []
            root_raws = {root_entry[3]}
            related: dict[str, TypedEvent] = {}
            root_parent = root.get("process.ppid")
            root_session = root.get("process.session_id")
            # An exec does not create a new process. Treat later exec records for the same
            # pid/process boundary as continuations so their descendants remain in lineage.
            for candidate in sorted(all_events.values(), key=lambda item: (item.ts, item.id)):
                if candidate.id == root.id or candidate.ts < root.ts:
                    continue
                if (candidate.get("process.pid") != pid
                        or candidate.get("process.ppid") != root_parent
                        or (root_session is not None
                            and candidate.get("process.session_id") != root_session)):
                    continue
                continuation = table.lookup(anchor.host or "", pid, candidate.ts.timestamp())
                if continuation is not None:
                    root_raws.add(continuation[3])
                    related[candidate.id] = candidate
            parent, when = root.get("process.ppid"), root.ts.timestamp()
            for _ in range(32):
                if not isinstance(parent, int) or parent in (0, 1):
                    break
                entry = table.lookup(anchor.host or "", parent, when)
                if entry is None:
                    break
                ancestor = by_raw.get(entry[3])
                if ancestor is None:
                    break
                related[ancestor.id] = ancestor
                parent, when = ancestor.get("process.ppid"), ancestor.ts.timestamp()
            for candidate in sorted(all_events.values(), key=lambda item: (item.ts, item.id)):
                if candidate.ts < root.ts or candidate.id == root.id:
                    continue
                parent, when = candidate.get("process.ppid"), candidate.ts.timestamp()
                for _ in range(32):
                    if not isinstance(parent, int) or parent in (0, 1):
                        break
                    entry = table.lookup(anchor.host or "", parent, when)
                    if entry is None:
                        break
                    if entry[3] in root_raws:
                        related[candidate.id] = candidate
                        break
                    ancestor = by_raw.get(entry[3])
                    if ancestor is None:
                        break
                    parent, when = ancestor.get("process.ppid"), ancestor.ts.timestamp()
            return list(related.values())

        reason = _host_reason(anchor) or (None if usable_key(pid) else "required typed key is unusable")
        return (key, "observed", intents if reason is None else [],
                lambda event: event.family == "process_exec", select, reason, [])

    def _session(self, anchor: LinkAnchor, window: LinkWindow):
        session_id, auid = _value(anchor, "process.session_id"), _value(anchor, "process.auid")
        boot_id = _value(anchor, "host.boot.id")
        key = {"host": anchor.host, "process.session_id": session_id, "process.auid": auid,
               "host.boot.id": boot_id, **_victim(anchor)}
        reason = _host_reason(anchor) or (None if usable_key(session_id) else "required typed key is unusable")
        intents = self._host_intents(window, ("linux.audit",), anchor.host) if reason is None else []

        def matches(event):
            return (event.host == anchor.host and event.get("process.session_id") == session_id
                    and (auid is None or event.get("process.auid") == auid)
                    and (boot_id is None or event.get("host.boot.id") == boot_id))

        return (key, "observed", intents, matches,
                lambda events: [event for event in events if matches(event)], reason, [])

    def _flow(self, anchor: LinkAnchor, window: LinkWindow):
        community_id = _value(anchor, "network.community_id")
        five_tuple = next((_tuple(event) for event in anchor.events if _tuple(event) is not None), None)
        key = ({"network.community_id": community_id} if community_id else
               {"five_tuple": list(five_tuple) if five_tuple else None})
        intents = []
        for target, contract in sorted(self.executor.contracts.items()):
            if not _is_network(target, contract):
                continue
            filters = []
            any_of = []
            if community_id and _supports(contract, "network.community_id"):
                filters.append(Predicate(field="network.community_id", op="eq", value=community_id))
            elif five_tuple and all(_supports(contract, field) for field in (
                    "source.ip", "source.port", "destination.ip", "destination.port")):
                transport, src, sport, dst, dport = five_tuple
                any_of = [
                    [Predicate(field="source.ip", op="eq", value=src),
                     Predicate(field="source.port", op="eq", value=sport),
                     Predicate(field="destination.ip", op="eq", value=dst),
                     Predicate(field="destination.port", op="eq", value=dport)],
                    [Predicate(field="source.ip", op="eq", value=dst),
                     Predicate(field="source.port", op="eq", value=dport),
                     Predicate(field="destination.ip", op="eq", value=src),
                     Predicate(field="destination.port", op="eq", value=sport)],
                ]
                if transport and _supports(contract, "network.transport"):
                    filters.append(Predicate(field="network.transport", op="eq", value=transport))
            else:
                continue
            intents.append(SearchIntent(
                kind="raw", target=target, window=Window(start=window.start, end=window.end),
                filters=filters, any_of=any_of, max_records=MAX_PIVOT_RECORDS,
                purpose="expansion:network_flow",
            ))
        def matches(event):
            if event.family not in {"net_flow", "net_alert", "net_session"}:
                return False
            if community_id:
                candidate_community = event.get("network.community_id")
                if candidate_community is not None:
                    return candidate_community == community_id
            candidate_tuple = _tuple(event)
            return bool(five_tuple and candidate_tuple and _tuple_matches(five_tuple, candidate_tuple))

        reason = None if usable_key(community_id) or (five_tuple and all(usable_key(item) for item in five_tuple)) else "required typed key is unusable"
        strength = "observed" if window.end - window.start <= OBSERVED_FLOW_SPAN else "inferred"
        return (key, strength, intents if reason is None else [], matches,
                lambda events: [event for event in events if matches(event)], reason, [])

    def _flow_host_side(self, anchor: LinkAnchor, window: LinkWindow):
        """Kernel socket records whose remote endpoint is one side of the flow. With a host identity, that host's
        records; without one (a network-only anchor), every host's, found by the endpoint itself as a pushable
        predicate, so the host comes from the matching records rather than from a guess."""
        five_tuple = next((_tuple(event) for event in anchor.events if _tuple(event) is not None), None)
        endpoints = [] if five_tuple is None else [
            [five_tuple[1], five_tuple[2]], [five_tuple[3], five_tuple[4]],
        ]
        any_host = anchor.host is None
        key = {"host.name": anchor.host, "flow_endpoints": endpoints, "actor": "inferred",
               **({"any_host": True} if any_host else {})}
        reason = None
        if (not endpoints
                or not all(usable_key(component) for endpoint in endpoints for component in endpoint)
                or (not any_host and not usable_key(anchor.host))):
            reason = "required typed key is unusable"
        if reason is not None:
            intents = []
        elif any_host:
            intents = self._endpoint_intents(window, endpoints)
            if not intents:
                reason = "key not pushable; full-dataset scan refused"
        else:
            intents = self._host_intents(window, ("linux.audit",), anchor.host)

        def matches(event):
            return (event.family == "net_socket" and (any_host or event.host == anchor.host)
                    and [event.get("destination.ip"), event.get("destination.port")] in endpoints)

        return (key, "inferred", intents, matches,
                lambda events: [event for event in events if matches(event)], reason, [])

    def _source_ip(self, anchor: LinkAnchor, window: LinkWindow):
        source_ip = _value(anchor, "source.ip")
        key = {"source.ip": source_ip, "actor": "inferred"}
        if not usable_key(source_ip):
            return (key, "inferred", [], lambda _event: False, lambda _events: [],
                    "required typed key is unusable", [])
        request = EntityTimelineRequest(tool="entity_timeline", arguments=EntityTimelineArgs(
            entity={"kind": "ip", "value": str(source_ip), "role": "src"},
            start=max(anchor.ts, window.start), end=window.end,
        ))
        if hasattr(self.executor, "plan"):
            all_intents, planning_coverage = self.executor.plan(request)
        else:
            all_intents, planning_coverage = self.executor._intents(request), []
        intents = [intent for intent in all_intents if any(
            predicate.field in {"source.ip", "destination.ip"}
            for group in intent.any_of for predicate in group
        )]
        # A planned intent without an IP predicate is refused, never run as a dataset scan; the dataset it
        # would have covered is unresolved for this address, not silently absent (review minor).
        planning_coverage = list(planning_coverage)
        covered = {(cell.target, cell.dataset) for cell in planning_coverage}
        for intent in all_intents:
            if intent in intents:
                continue
            dataset = PivotExecutor._intent_dataset(intent)
            if (intent.target, dataset) in covered:
                continue
            covered.add((intent.target, dataset))
            unresolved = f"dataset_unsearchable:{dataset}:IP predicate unavailable"
            planning_coverage.append(PivotCoverage(
                target=intent.target, dataset=dataset, start=intent.window.start, end=intent.window.end,
                status="partial", reasons=[unresolved], returned=0, total=None,
                unresolved_ranges=[_range(intent.window.start, intent.window.end, unresolved)],
            ))
        matches = lambda event: event.ts >= anchor.ts and event.get("source.ip") == source_ip
        reason = None if intents else "key not pushable; full-dataset scan refused"
        return (key, "inferred", intents, matches,
                lambda events: [event for event in events if matches(event)], reason,
                planning_coverage)

    def _account(self, anchor: LinkAnchor, window: LinkWindow):
        field = "user.name" if _value(anchor, "user.name") is not None else "process.auid"
        account = _value(anchor, field)
        key = {field: account, "actor": "inferred"}
        if not usable_key(account):
            return (key, "inferred", [], lambda _event: False, lambda _events: [],
                    "required typed key is unusable", [])
        forward = LinkWindow(label=window.label, start=max(anchor.ts, window.start), end=window.end)
        intents = []
        for target, contract in sorted(self.executor.contracts.items()):
            if _is_network(target, contract) or not _supports(contract, field):
                continue
            intents.append(SearchIntent(
                kind="raw", target=target, window=Window(start=forward.start, end=forward.end),
                filters=[Predicate(field=field, op="eq", value=account)],
                max_records=MAX_PIVOT_RECORDS, purpose="expansion:account",
            ))

        def matches(event):
            return (event.ts >= anchor.ts and event.host != anchor.host
                    and event.get(field) == account)

        reason = None if intents else "key not pushable; full-dataset scan refused"
        return (key, "inferred", intents, matches,
                lambda events: [event for event in events if matches(event)], reason, [])

    def _host_after(self, anchor: LinkAnchor, window: LinkWindow):
        key = {"host.name": anchor.host, "time_relation": "after", "actor": "inferred", **_victim(anchor)}
        reason = _host_reason(anchor)
        if reason:
            return (key, "inferred", [], lambda _event: False, lambda _events: [], reason, [])
        request = EntityTimelineRequest(tool="entity_timeline", arguments=EntityTimelineArgs(
            entity={"kind": "host", "value": anchor.host, "role": "host"},
            start=max(anchor.ts, window.start), end=window.end,
        ))
        intents = self.executor._intents(request)
        matches = lambda event: event.host == anchor.host and event.ts >= anchor.ts
        reason = None if intents else "key not pushable; full-dataset scan refused"
        return (key, "inferred", intents, matches,
                lambda events: [event for event in events if matches(event)], reason, [])
