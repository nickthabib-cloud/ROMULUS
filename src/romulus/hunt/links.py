"""Typed deterministic link fetchers for post-sweep expansion."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from typing import Any, Literal, NamedTuple

from pydantic import BaseModel, ConfigDict, Field

from romulus.agent.models import PivotCoverage
from romulus.agent.tools import EntityTimelineArgs, EntityTimelineRequest
from romulus.detect.correlation import PidTable, boot_of, boots_conflict
from romulus.evidence.normalize import BootIntervals
from romulus.evidence.typed import TypedEvent
from romulus.hunt.pivot import (
    HOST_LOOKUP_BUDGET,
    MAX_PIVOT_RECORDS,
    PivotExecutor,
    _is_network,
    _range,
    _supports,
)
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
RAW_FAMILIES_BY_LINK = {
    "process_lineage": {"process_exec"},
    "network_flow": {"net_flow", "net_alert", "net_session"},
    "flow_host_side": {"net_socket"},
}


def is_agent_reach(link_type: str | None, strength: str | None) -> bool:
    """Agent-requested reaches are hypotheses, never deterministic expansion work."""
    return strength == "agent_hypothesis" or bool(link_type and link_type.startswith("agent_"))


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


class Selection(NamedTuple):
    """A link's typed selection over the records it retrieved, with every step it could not decide. A link whose
    selection left a step unknown is partial, whatever its retrieval was: its negative is not complete."""
    events: list[TypedEvent]
    unresolved: list[str]


# Distinct undecided steps a selection names; the rest are counted in one more reason.
MAX_UNRESOLVED_REASONS = 8


def _unresolved(reasons: list[str]) -> list[str]:
    distinct = sorted(set(reasons))
    if len(distinct) <= MAX_UNRESOLVED_REASONS:
        return distinct
    return [*distinct[:MAX_UNRESOLVED_REASONS],
            f"and {len(distinct) - MAX_UNRESOLVED_REASONS} more undecided step(s)"]


def _serial(event: TypedEvent) -> int | None:
    value = event.get("audit.serial")
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _order(event: TypedEvent) -> tuple:
    return event.ts, _serial(event) is None, _serial(event) or 0, event.id


def _after(event: TypedEvent, root: TypedEvent) -> bool | None:
    """Whether `event` happened after `root`: by time, then by audit serial at one instant; None when they share an
    instant and a serial is missing (their order is unknown)."""
    if event.ts != root.ts:
        return event.ts > root.ts
    left, right = _serial(event), _serial(root)
    return None if left is None or right is None else left > right


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


def _boot(anchor: LinkAnchor) -> str | None:
    """The anchor's recorded boot id (its earliest record that carries one), or None."""
    value = _value(anchor, "host.boot.id")
    return None if value in (None, "") else str(value)


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


def _same_process_as(exec_event: TypedEvent, record: TypedEvent) -> bool:
    """Whether an exec of a record's pid can be the record's own process: it ran the program the record names
    (where both name one), the parent agrees (unless the record's process was reparented to init) and the login
    session agrees where both carry one."""
    program, exec_program = record.get("process.executable"), exec_event.get("process.executable")
    parent, exec_parent = record.get("process.ppid"), exec_event.get("process.ppid")
    session, exec_session = record.get("process.session_id"), exec_event.get("process.session_id")
    program_agrees = program is None or exec_program is None or exec_program == program
    parent_agrees = parent is None or parent in (0, 1) or exec_parent == parent
    session_agrees = session is None or exec_session is None or exec_session == session
    return program_agrees and parent_agrees and session_agrees


class LinkFetcher:
    """Fetch each `(anchor, link, window)` once and keep typed-key semantics local and explicit."""

    def __init__(self, executor: PivotExecutor, hunt_start: datetime, hunt_end: datetime,
                 boots: BootIntervals | None = None):
        self.executor = executor
        self.hunt_start = hunt_start.astimezone(UTC)
        self.hunt_end = hunt_end.astimezone(UTC)
        # The hunt's boot-interval map: fetched audit records without a boot id take the boot it places their time
        # in, so lineage and session filters can tell a reused pid or session id after a reboot.
        self.boots = boots if boots is not None else BootIntervals()
        self._cache: dict[str, LinkResult] = {}
        self._hosts: dict[str, tuple[str | None, str | None]] = {}

    def resolve_host(self, owner: str, ip: str, query_cap: int | None = None) -> tuple[str | None, str | None]:
        """A network endpoint's host identity from typed host records (`host.ip`), or why there is none.
        Exactly one host name resolves; none or several is a reason, never a guess. A lookup refused because it
        would pass `query_cap` is not remembered, so a later anchor with budget can still make it."""
        if ip in self._hosts:
            return self._hosts[ip]
        resolver = getattr(self.executor, "resolve_host_ip", None)
        if resolver is None:
            result = (None, f"victim host unknown for {ip}: host resolution is unavailable")
        else:
            result = resolver(owner, ip, self.hunt_start, self.hunt_end, query_cap=query_cap)
            if result[0] is None and (result[1] or "").endswith(HOST_LOOKUP_BUDGET):
                return result
        self._hosts[ip] = result
        return result

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

        def placed(event: TypedEvent) -> bool:
            # The executor stores what `retain` keeps, so each record's boot is placed before it is stored and
            # before `select` filters by boot. Link fetches carry no journald copies of their own.
            self.boots.fill([event])
            return retain(event)

        fetch_options = {
            "anchor_ts": anchor.ts,
            "query_cap": query_cap,
            "planning_coverage": planning_coverage,
        }
        if getattr(self.executor, "raw_family_prefilter", False):
            fetch_options["raw_families"] = RAW_FAMILIES_BY_LINK.get(link_type)
        batch = self.executor.fetch_intents(
            anchor.finding_id, fetch_key, intents, placed, **fetch_options,
        )
        selected = select(batch.events)
        if not isinstance(selected, Selection):
            selected = Selection(list(selected), [])
        anchored = set(anchor.event_ids)
        linked = sorted(
            (event for event in selected.events if event.id not in anchored),
            key=lambda event: (event.ts, event.id),
        )
        # A step the selection could not decide (an ambiguous or missing lineage record) leaves the link partial
        # with that reason: complete retrieval never makes an undecided selection a complete negative.
        status, reasons = batch.status, list(batch.reasons)
        if selected.unresolved:
            status = "partial" if status == "complete" else status
            reasons += [reason for reason in _unresolved(selected.unresolved) if reason not in reasons]
        result = LinkResult(
            id="link-" + fetch_key[:20], anchor_id=anchor.finding_id, link_type=link_type,
            window=window, strength=strength, key=key, status=status,
            event_ids=[event.id for event in linked],
            evidence_ids=sorted(set(anchor.event_ids + [event.id for event in linked])),
            task_ids=batch.task_ids, coverage=batch.coverage, reasons=reasons,
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
        boot_id = _boot(anchor)
        key = {"host": anchor.host, "pid": pid, "host.boot.id": boot_id, **_victim(anchor)}
        intents = self._host_intents(window, ("linux.audit",), anchor.host) if isinstance(pid, int) else []

        def select(events):
            """The anchored process's exec images (the programs it ran in place), its recorded ancestors and its
            recorded descendants. Execs of one instant are ordered by audit serial; a step that cannot be decided
            (execs of different programs at one instant without serials, or the anchor's own image not
            retrieved) is named in the selection, so the link is partial rather than an empty complete."""
            # A record of another boot is another process. The link retrieves audit records without their journald
            # copies; their boot comes from the hunt's boot-interval map. One the map cannot place (a gap between
            # boots, near a boot's edge) is kept: a pid reused after a reboot cannot be excluded for it.
            all_events = {event.id: event for event in anchor.events + events
                          if event.family == "process_exec" and event.host == anchor.host
                          and not boots_conflict(boot_id, boot_of(event))}
            root = next((event for event in anchor.events if event.get("process.pid") == pid), None)
            if root is None:
                return Selection([], [f"lineage undecided: no anchor record carries pid {pid}"])
            host = anchor.host or ""
            root_boot = boot_of(root) or boot_id
            table = PidTable()
            for event in all_events.values():
                table.add(event)
            unknown: list[str] = []

            # The process of the anchor record: an exec record is its own image; any other record (a file read, a
            # socket) is the pid's image at that record's (time, serial), counting an exec at its own serial.
            own = all_events.get(root.id)
            if own is None:
                found = table.image(host, pid, root.ts.timestamp(), root_boot, serial=_serial(root), inclusive=True)
                own = all_events.get(found.record.event_id) if found.record is not None else None
                if own is None:
                    unknown.append(found.why or (
                        f"lineage incomplete: no exec record of pid {pid} on {host} at or before "
                        f"{root.ts.isoformat()} was retrieved, so its images and descendants cannot be identified"))
                elif not _same_process_as(own, root):
                    # The pid's latest exec belongs to another process: this one forked without exec, or the pid
                    # was reused. Its own record's parent and session stand; its images cannot be identified.
                    unknown.append(
                        f"lineage incomplete: the latest exec of pid {pid} on {host} before {root.ts.isoformat()} "
                        f"({own.get('process.executable')}) has another parent or session than the record, so the "
                        f"record's process forked without exec or the pid was reused; its images cannot be identified")
                    own = None
            process = own or root
            parent_pid, session = process.get("process.ppid"), process.get("process.session_id")

            def same_process(event: TypedEvent) -> bool:
                # An exec does not create a process: an exec of this pid that kept its parent and session (and boot)
                # is the same process running another program.
                return (event.get("process.pid") == pid and event.get("process.ppid") == parent_pid
                        and (session is None or event.get("process.session_id") == session)
                        and not boots_conflict(root_boot, boot_of(event)))

            images: dict[str, TypedEvent] = {}
            if own is not None:
                images[own.id] = own
                current = own                   # the images it replaced, each strictly before the next
                for _ in range(32):
                    found = table.image(host, pid, current.ts.timestamp(), root_boot, serial=_serial(current),
                                        strict=True, exclude=current.id)
                    prior = all_events.get(found.record.event_id) if found.record is not None else None
                    if prior is None:
                        if found.why:
                            unknown.append(found.why)
                        break
                    if prior.id in images or not same_process(prior):
                        break                   # a different process held the pid before
                    images[prior.id] = prior
                    current = prior
            for candidate in sorted(all_events.values(), key=_order):
                # Later images, and images at the same instant whose order is unknown: the same process either way.
                if candidate.id not in images and same_process(candidate) and _after(candidate, process) is not False:
                    images[candidate.id] = candidate

            related: dict[str, TypedEvent] = dict(images)
            first = min(images.values(), key=_order) if images else root
            # With no image, the ancestors start from the record's own parent at the record's (time, serial).
            first_ts = first.ts.timestamp()
            # Ancestors: the parent's image when the process first execed (strictly before it), then up the chain.
            parent, when, serial, boot = first.get("process.ppid"), first_ts, _serial(first), root_boot
            for _ in range(32):
                if not isinstance(parent, int) or parent in (0, 1):
                    break
                found = table.image(host, parent, when, boot, serial=serial)
                ancestor = all_events.get(found.record.event_id) if found.record is not None else None
                if ancestor is None:
                    if found.why:
                        unknown.append(found.why)
                    break                       # an ancestor whose exec was not retrieved ends the chain
                if ancestor.id in related:
                    break
                related[ancestor.id] = ancestor
                parent, when, serial = found.record.ppid, found.record.ts, found.record.serial
                boot = boot or found.record.boot
            # Descendants: a record whose parent chain reaches one of the process's images.
            for candidate in sorted(all_events.values(), key=_order):
                if candidate.id in related or candidate.ts < first.ts:
                    continue
                parent, when, serial = candidate.get("process.ppid"), candidate.ts.timestamp(), _serial(candidate)
                boot = boot_of(candidate)
                for _ in range(32):
                    if not isinstance(parent, int) or parent in (0, 1):
                        break
                    found = table.image(host, parent, when, boot, serial=serial)
                    if found.record is None:
                        # Undecided only where the unordered execs could be the process's or its descendants'
                        # (not before its first image, where no chain reaches it).
                        if found.why and found.at is not None and found.at >= first_ts:
                            unknown.append(found.why)
                        break
                    if found.record.event_id in images:
                        related[candidate.id] = candidate
                        break
                    if found.record.ts < first_ts or found.record.event_id not in all_events:
                        break                   # older than the process: this chain never reaches it
                    parent, when, serial = found.record.ppid, found.record.ts, found.record.serial
                    boot = boot or found.record.boot
            return Selection(list(related.values()), unknown)

        reason = _host_reason(anchor) or (None if usable_key(pid) else "required typed key is unusable")
        return (key, "observed", intents if reason is None else [],
                lambda event: event.family == "process_exec", select, reason, [])

    def _session(self, anchor: LinkAnchor, window: LinkWindow):
        session_id, auid = _value(anchor, "process.session_id"), _value(anchor, "process.auid")
        boot_id = _boot(anchor)
        key = {"host": anchor.host, "process.session_id": session_id, "process.auid": auid,
               "host.boot.id": boot_id, **_victim(anchor)}
        reason = _host_reason(anchor) or (None if usable_key(session_id) else "required typed key is unusable")
        intents = self._host_intents(window, ("linux.audit",), anchor.host) if reason is None else []

        def matches(event):
            return (event.host == anchor.host and event.get("process.session_id") == session_id
                    and (auid is None or event.get("process.auid") == auid)
                    and not boots_conflict(boot_id, boot_of(event)))

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
        # would have covered is unresolved for this address, not silently absent.
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
