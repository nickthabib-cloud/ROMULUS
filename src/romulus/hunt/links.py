"""Typed deterministic link fetchers for post-sweep expansion."""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from romulus.agent.models import PivotCoverage
from romulus.agent.tools import EntityTimelineArgs, EntityTimelineRequest
from romulus.detect.correlation import PidTable
from romulus.evidence.typed import TypedEvent
from romulus.hunt.pivot import MAX_PIVOT_RECORDS, PivotExecutor, _is_network, _supports
from romulus.sources.models import Predicate, SearchIntent, Window
from romulus.store.db import digest

LinkType = Literal[
    "process_lineage", "login_session", "network_flow", "source_ip", "account", "host_after_anchor",
]
LinkStrength = Literal["observed", "inferred"]


class LinkWindow(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    label: str
    start: datetime
    end: datetime


class LinkAnchor(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    finding_id: str
    ts: datetime
    host: str | None = None
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


def _value(anchor: LinkAnchor, field: str):
    for event in sorted(anchor.events, key=lambda item: (item.ts, item.id)):
        if event.has(field):
            return event.get(field)
    return None


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

    def fetch(self, anchor: LinkAnchor, link_type: LinkType, window: LinkWindow) -> LinkResult:
        key, strength, intents, retain, select = self._plan(anchor, link_type, window)
        fetch_key = digest({
            "anchor": anchor.finding_id, "link": link_type, "window": window.model_dump(mode="json"), "key": key,
        })
        if fetch_key in self._cache:
            return self._cache[fetch_key]
        if not intents:
            result = LinkResult(
                id="link-" + fetch_key[:20], anchor_id=anchor.finding_id, link_type=link_type,
                window=window, strength=strength, key=key, status="unsupported",
                reasons=["required typed key or compatible source contract is unavailable"],
            )
            self._cache[fetch_key] = result
            return result
        batch = self.executor.fetch_intents(
            anchor.finding_id, fetch_key, intents, retain, anchor_ts=anchor.ts,
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
        )
        self._cache[fetch_key] = result
        return result

    def _plan(self, anchor: LinkAnchor, link_type: LinkType, window: LinkWindow):
        handlers = {
            "process_lineage": self._lineage,
            "login_session": self._session,
            "network_flow": self._flow,
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

    def _lineage(self, anchor: LinkAnchor, window: LinkWindow):
        pid = _value(anchor, "process.pid")
        key = {"host": anchor.host, "pid": pid}
        intents = self._host_intents(window, ("linux.audit",), anchor.host) if isinstance(pid, int) else []

        def select(events):
            all_events = {event.id: event for event in anchor.events + events
                          if event.family == "process_exec" and event.host == anchor.host}
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
            root_raw = root_entry[3]
            related: dict[str, TypedEvent] = {}
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
                    if entry[3] == root_raw:
                        related[candidate.id] = candidate
                        break
                    ancestor = by_raw.get(entry[3])
                    if ancestor is None:
                        break
                    parent, when = ancestor.get("process.ppid"), ancestor.ts.timestamp()
            return list(related.values())

        return key, "observed", intents, lambda event: event.family == "process_exec", select

    def _session(self, anchor: LinkAnchor, window: LinkWindow):
        session_id, auid = _value(anchor, "process.session_id"), _value(anchor, "process.auid")
        key = {"host": anchor.host, "process.session_id": session_id, "process.auid": auid}
        intents = self._host_intents(window, ("linux.audit",), anchor.host) if session_id is not None else []

        def matches(event):
            return (event.host == anchor.host and event.get("process.session_id") == session_id
                    and (auid is None or event.get("process.auid") == auid))

        return key, "observed", intents, matches, lambda events: [event for event in events if matches(event)]

    def _flow(self, anchor: LinkAnchor, window: LinkWindow):
        community_id = _value(anchor, "network.community_id")
        five_tuple = next((_tuple(event) for event in anchor.events if _tuple(event) is not None), None)
        key = ({"network.community_id": community_id, "host_side": "inferred"} if community_id else
               {"five_tuple": list(five_tuple) if five_tuple else None, "host_side": "inferred"})
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
        if anchor.host and five_tuple:
            intents.extend(self._host_intents(window, ("linux.audit",), anchor.host))

        def matches(event):
            if community_id:
                candidate_community = event.get("network.community_id")
                if candidate_community is not None:
                    return candidate_community == community_id
                if event.family != "net_socket":
                    return False
            candidate_tuple = _tuple(event)
            if five_tuple and candidate_tuple and _tuple_matches(five_tuple, candidate_tuple):
                return True
            if event.family == "net_socket" and five_tuple:
                _transport, src, sport, dst, dport = five_tuple
                return ((event.get("destination.ip"), event.get("destination.port")) in {
                    (src, sport), (dst, dport),
                })
            return False

        return key, "observed", intents, matches, lambda events: [event for event in events if matches(event)]

    def _source_ip(self, anchor: LinkAnchor, window: LinkWindow):
        source_ip = _value(anchor, "source.ip")
        key = {"source.ip": source_ip, "actor": "inferred"}
        if source_ip is None:
            return key, "inferred", [], lambda _event: False, lambda _events: []
        request = EntityTimelineRequest(tool="entity_timeline", arguments=EntityTimelineArgs(
            entity={"kind": "ip", "value": str(source_ip), "role": "src"},
            start=max(anchor.ts, window.start), end=window.end,
        ))
        intents = self.executor._intents(request)
        matches = lambda event: event.ts >= anchor.ts and event.get("source.ip") == source_ip
        return key, "inferred", intents, matches, lambda events: [event for event in events if matches(event)]

    def _account(self, anchor: LinkAnchor, window: LinkWindow):
        field = "user.name" if _value(anchor, "user.name") is not None else "process.auid"
        account = _value(anchor, field)
        key = {field: account, "actor": "inferred"}
        intents = self._host_intents(window, ("linux.audit", "systemd.journal")) if account is not None else []

        def matches(event):
            return (event.ts >= anchor.ts and event.host != anchor.host
                    and event.get(field) == account)

        return key, "inferred", intents, matches, lambda events: [event for event in events if matches(event)]

    def _host_after(self, anchor: LinkAnchor, window: LinkWindow):
        key = {"host.name": anchor.host, "time_relation": "after", "actor": "inferred"}
        if not anchor.host:
            return key, "inferred", [], lambda _event: False, lambda _events: []
        request = EntityTimelineRequest(tool="entity_timeline", arguments=EntityTimelineArgs(
            entity={"kind": "host", "value": anchor.host, "role": "host"},
            start=max(anchor.ts, window.start), end=window.end,
        ))
        intents = self.executor._intents(request)
        matches = lambda event: event.host == anchor.host and event.ts >= anchor.ts
        return key, "inferred", intents, matches, lambda events: [event for event in events if matches(event)]
