"""Typed deterministic link fetchers for post-sweep expansion."""
from __future__ import annotations

import ntpath
import re
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from typing import Any, Literal, NamedTuple

from pydantic import BaseModel, ConfigDict, Field

from romulus.agent.models import PivotCoverage
from romulus.agent.tools import EntityTimelineArgs, EntityTimelineRequest
from romulus.detect.correlation import PidTable, boot_of, boots_conflict
from romulus.detect.host import exec_order
from romulus.evidence.normalize import BootIntervals
from romulus.evidence.typed import TypedEvent, event_os_family
from romulus.evidence.windows_catalog import WINDOWS_HOST_DATASETS
from romulus.hunt.pivot import (
    HOST_LOOKUP_BUDGET,
    HOST_TIMELINE_DATASETS,
    MAX_PIVOT_RECORDS,
    PivotExecutor,
    _and_any_of,
    _host_datasets,
    _is_network,
    _range,
    _supports,
    _windows_source_groups,
)
from romulus.sources.models import Predicate, SearchIntent, Window
from romulus.store.db import digest

LinkType = Literal[
    "process_lineage", "login_session", "network_flow", "flow_host_side",
    "source_ip", "account", "host_after_anchor", "process_activity",
    "process_session", "kerberos_logon", "remote_logon_source", "service_process",
]
LinkStrength = Literal["observed", "inferred"]
WINDOWS_LINK_TYPES = frozenset({
    "process_activity", "process_session", "kerberos_logon", "remote_logon_source", "service_process",
})
# Links that look only forward from the anchor: they fetch [anchor, window end), and say so.
FORWARD_LINKS = frozenset({"source_ip", "account", "host_after_anchor", "service_process"})
# A flow key (community ID, 5-tuple) is time-free: port reuse and fixed-port UDP (123, 514) can join different
# flows far apart in time, so a flow join is observed only close to the anchor.
OBSERVED_FLOW_SPAN = timedelta(minutes=10)

UNUSABLE_TEXT_KEYS = {"", "-1", "4294967295", "(null)", "(none)", "unset", "(unknown)"}
_GENERIC_WINDOWS_SIDS = {
    "sid:s-1-0-0", "sid:s-1-1-0", "sid:s-1-5-7", "sid:s-1-5-11",
    "sid:s-1-5-18", "sid:s-1-5-19", "sid:s-1-5-20",
}
_GENERIC_WINDOWS_SID_PREFIXES = (
    "sid:s-1-5-32-",  # built-in local groups
    "sid:s-1-5-80-",  # service identities
    "sid:s-1-5-90-",  # window manager identities
)
# Links that need a host identity: they search one host's own records.
HOST_SIDE_LINKS = frozenset({"process_lineage", "login_session", "host_after_anchor"})
RAW_FAMILIES_BY_LINK = {
    "process_lineage": {"process_exec", "process_observed"},
    "network_flow": {"net_flow", "net_alert", "net_session"},
    "flow_host_side": {"net_socket"},
    "process_activity": {
        "process_exec", "net_socket", "file_change", "registry_change", "image_load",
        "process_access", "pipe_event", "dns_lookup", "remote_thread",
    },
    "process_session": {"auth", "system_state"},
    "kerberos_logon": {"auth"},
    "service_process": {"process_exec"},
}

_PROCESS_ACTIVITY_FAMILIES = RAW_FAMILIES_BY_LINK["process_activity"]
_ZERO_GUID = "00000000-0000-0000-0000-000000000000"
_WINDOWS_SESSION_SENTINELS = {"", "0", "0x0", "0x3e4", "0x3e5", "0x3e7"}
_REMOTE_LOGON_CODES = {4624, 4778, 1149, 5140, 5145}
_REMOTE_ADDRESS_CAVEAT = (
    "Address-to-host attribution is inferred: NAT, VPN, proxy paths, and DHCP changes can make the "
    "observed source address belong to another host at the logon time."
)
_REMOTE_WORKSTATION_CAVEAT = (
    "Workstation-name attribution is weaker than address evidence and uses only the canonical first DNS label."
)


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


def _event_code(event: TypedEvent) -> int | None:
    value = event.get("event.code")
    if isinstance(value, bool):
        return None
    try:
        return int(str(value), 10)
    except (TypeError, ValueError):
        return None


def _canonical_guid(value: Any) -> str | None:
    text = str(value or "").strip().strip("{}").casefold()
    if not re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", text):
        return None
    return None if text == _ZERO_GUID else text


def _guid_query_values(guid: str) -> list[str]:
    """Native Windows GUID keywords occur with or without braces and with either hex case."""
    upper = guid.upper()
    return [guid, upper, "{" + guid + "}", "{" + upper + "}"]


def _session_id(value: Any) -> str | None:
    text = str(value or "").strip().casefold()
    if not text:
        return None
    try:
        numeric = int(text, 16 if text.startswith("0x") else 10)
    except ValueError:
        return text if text not in _WINDOWS_SESSION_SENTINELS else None
    canonical = f"0x{numeric:x}"
    return canonical if canonical not in _WINDOWS_SESSION_SENTINELS else None


def _first_label(value: Any) -> str | None:
    text = str(value or "").strip().rstrip(".").casefold()
    if text in {"", "-"}:
        return None
    return text.split(".", 1)[0]


def _windows_path_key(value: Any) -> str | None:
    text = str(value or "").strip().strip('"').replace("/", "\\")
    if not text:
        return None
    if text.startswith(("\\\\?\\", "\\??\\")):
        text = text[4:]
        if text.casefold().startswith("unc\\"):
            text = "\\\\" + text[4:]
    return ntpath.normpath(text).casefold()


def _service_binary(value: Any) -> tuple[str | None, str | None]:
    """Parse only service command lines whose executable boundary Windows recorded unambiguously."""
    text = str(value or "").strip()
    if not text:
        return None, "required service image path is unusable"
    if text.startswith('"'):
        closing = text.find('"', 1)
        if closing < 2:
            return None, "quoted service image path has no closing quote"
        binary = text[1:closing]
    else:
        first = text.split(maxsplit=1)[0]
        if len(first) != len(text) and not re.search(r"\.(?:exe|com|bat|cmd)$", first, re.IGNORECASE):
            return None, "unquoted service image path with spaces is ambiguous"
        binary = first
    if ntpath.basename(binary).casefold() == "svchost.exe":
        return None, "svchost service groups are not attributed to one service"
    if _windows_path_key(binary) is None:
        return None, "required service image path is unusable"
    return binary, None


def _portable_windows_account(value: Any) -> bool:
    normalized = str(value or "").strip().casefold()
    return (usable_key(value) and normalized not in _GENERIC_WINDOWS_SIDS
            and normalized not in {"name:", "name:-"} and not normalized.endswith("\\-")
            and not normalized.startswith(_GENERIC_WINDOWS_SID_PREFIXES))


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
    link_key: dict[str, Any] = Field(default_factory=dict)


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


def _relative_event_order(left: TypedEvent, right: TypedEvent) -> int | None:
    """Order two events by time, then by a token valid in their shared source sequence."""
    if left.ts != right.ts:
        return -1 if left.ts < right.ts else 1
    left_order, left_domain = exec_order(left)
    right_order, right_domain = exec_order(right)
    if (left_order is None or right_order is None or left_domain is None
            or left_domain != right_domain or (left_order == right_order and left.id != right.id)):
        return None
    return (left_order > right_order) - (left_order < right_order)


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


def _os_family(anchor: LinkAnchor) -> str | None:
    families = {event_os_family(event) for event in anchor.events}
    families.discard("unknown")
    return next(iter(families)) if len(families) == 1 else None


def _victim(anchor: LinkAnchor) -> dict:
    return {"victim_ip": anchor.victim_ip} if anchor.victim_ip else {}


def _host_reason(anchor: LinkAnchor) -> str | None:
    """Why a host-side link cannot run for this anchor, or None when it has a usable host identity."""
    if usable_key(anchor.host):
        return None
    return anchor.host_reason or "required typed key is unusable"


def _target_has_host_os(executor, target: str, contract, os_family: str) -> bool:
    """Use a target's inventoried datasets when it contains both Linux and Windows records."""
    inventory = getattr(executor, "dataset_inventory", {}).get(target)
    # A valid host contract can have an empty inventory when the shipper omits event.dataset (notably raw
    # Winlogbeat records).  In that case the contract is the only observed OS classification; an empty set must
    # not disable every host link for the target.
    if not inventory:
        return contract.os_family == os_family
    datasets = set(inventory)
    if os_family == "windows":
        return bool(datasets.intersection(WINDOWS_HOST_DATASETS))
    if os_family == "linux":
        return bool(datasets.intersection(HOST_TIMELINE_DATASETS))
    return False


COMPUTED_COMMUNITY_ID = "#computed:community_id_v1"


def written_community_id(event: TypedEvent):
    """The record's community id when its sensor wrote it, None when ROMULUS computed it from the 5-tuple: a computed
    id is in no backend document, so it can never be a query key (the 5-tuple is)."""
    field = event.fields.get("network.community_id")
    if field is None or field.value in (None, "") or field.origin.endswith(COMPUTED_COMMUNITY_ID):
        return None
    return field.value


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
        # Forward links hash the requested symmetric window and persist the clipped searched window.
        # Service-process links plan from installation time so they do not query pre-install process starts.
        plan_window = self._effective_window(anchor, link_type, window) if link_type == "service_process" else window
        key, strength, intents, retain, select, unsupported_reason, planning_coverage = self._plan(
            anchor, link_type, plan_window,
        )
        fetch_key = self._fetch_key(anchor, link_type, plan_window, key)
        if fetch_key in self._cache:
            return self._cache[fetch_key]
        window = self._effective_window(anchor, link_type, window)
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
            # Place boot identity before final selection. Persistence happens only after `select`, and link
            # fetches carry no journald copies of their own.
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
            anchor.finding_id, fetch_key, intents, placed, persist=False, **fetch_options,
        )
        selected = select(batch.events)
        if not isinstance(selected, Selection):
            selected = Selection(list(selected), [])
        anchored = set(anchor.event_ids)
        linked = sorted(
            (event for event in selected.events if event.id not in anchored),
            key=lambda event: (event.ts, event.id),
        )
        save_selection = getattr(self.executor, "save_batch_selection", None)
        if save_selection is not None:
            save_selection(batch, linked)
        # A step the selection could not decide (an ambiguous or missing lineage record) leaves the link partial
        # with that reason: complete retrieval never makes an undecided selection a complete negative.
        status, reasons = batch.status, list(batch.reasons)
        if selected.unresolved:
            status = "partial" if status == "complete" else status
            reasons += [reason for reason in _unresolved(selected.unresolved) if reason not in reasons]
        if link_type == "remote_logon_source":
            advisory = (_REMOTE_ADDRESS_CAVEAT if key.get("source.ip")
                        else _REMOTE_WORKSTATION_CAVEAT)
            if advisory not in reasons:
                reasons.append(advisory)
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
        payload = {
            "anchor": anchor.finding_id, "link": link_type,
            "window": window.model_dump(mode="json"), "key": key,
        }
        if link_type in WINDOWS_LINK_TYPES:
            payload["anchor_host"] = anchor.host
        return digest(payload)

    @staticmethod
    def _effective_window(anchor: LinkAnchor, link_type: LinkType, window: LinkWindow) -> LinkWindow:
        if link_type not in FORWARD_LINKS:
            return window
        anchor_ts = anchor.ts.astimezone(UTC) if anchor.ts.tzinfo else anchor.ts.replace(tzinfo=UTC)
        return LinkWindow(label=window.label, start=max(anchor_ts, window.start), end=window.end)

    def result_id(self, anchor: LinkAnchor, link_type: LinkType, window: LinkWindow) -> str:
        plan_window = self._effective_window(anchor, link_type, window) if link_type == "service_process" else window
        key, *_rest = self._plan(anchor, link_type, plan_window)
        return "link-" + self._fetch_key(anchor, link_type, plan_window, key)[:20]

    def _plan(self, anchor: LinkAnchor, link_type: LinkType, window: LinkWindow):
        handlers = {
            "process_lineage": self._lineage,
            "login_session": self._session,
            "network_flow": self._flow,
            "flow_host_side": self._flow_host_side,
            "source_ip": self._source_ip,
            "account": self._account,
            "host_after_anchor": self._host_after,
            "process_activity": self._process_activity,
            "process_session": self._process_session,
            "kerberos_logon": self._kerberos_logon,
            "remote_logon_source": self._remote_logon_source,
            "service_process": self._service_process,
        }
        return handlers[link_type](anchor, window)

    def _host_intents(self, window: LinkWindow, families: set[str] | None, host: str | None = None,
                      os_family: str | None = None):
        intents = []
        for target, contract in sorted(self.executor.contracts.items()):
            if _is_network(target, contract):
                continue
            use_windows = os_family in (None, "windows") and _target_has_host_os(
                self.executor, target, contract, "windows",
            )
            use_linux = os_family in (None, "linux") and _target_has_host_os(
                self.executor, target, contract, "linux",
            )
            if use_windows:
                source_groups = _windows_source_groups(contract, families)
                if source_groups:
                    filters = []
                    if host is not None and not _supports(contract, "host.name"):
                        source_groups = []
                    elif host is not None:
                        native_hosts = [
                            candidate for candidate in contract.hosts
                            if _first_label(candidate) == _first_label(host)
                        ] or [host]
                        if len(native_hosts) > 1 and _supports(contract, "host.name", "in"):
                            filters.append(Predicate(field="host.name", op="in", value=native_hosts))
                        else:
                            filters.append(Predicate(field="host.name", op="eq", value=native_hosts[0]))
                    if source_groups:
                        intents.append(SearchIntent(
                            kind="raw", target=target, window=Window(start=window.start, end=window.end),
                            filters=filters, any_of=source_groups, max_records=MAX_PIVOT_RECORDS,
                            purpose="expansion:windows-events",
                        ))
            if not use_linux or not _supports(contract, "event.dataset"):
                continue
            inventoried = getattr(self.executor, "dataset_inventory", {}).get(target)
            for dataset in _host_datasets(contract, families, os_family="linux"):
                if inventoried is not None and dataset not in inventoried:
                    continue
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
        """Typed host socket records whose remote endpoint is one of these (ip, port) pairs."""
        intents = []
        for target, contract in sorted(self.executor.contracts.items()):
            if (_is_network(target, contract)
                    or not all(_supports(contract, field) for field in ("destination.ip", "destination.port"))):
                continue
            endpoint_groups = [
                [Predicate(field="destination.ip", op="eq", value=ip),
                 Predicate(field="destination.port", op="eq", value=port)]
                for ip, port in endpoints
            ]
            if _target_has_host_os(self.executor, target, contract, "windows"):
                source_groups = _windows_source_groups(contract, {"net_socket"})
                if source_groups:
                    intents.append(SearchIntent(
                        kind="raw", target=target, window=Window(start=window.start, end=window.end),
                        any_of=_and_any_of(source_groups, endpoint_groups),
                        max_records=MAX_PIVOT_RECORDS, purpose="expansion:flow_host_side",
                    ))
            if (not _target_has_host_os(self.executor, target, contract, "linux")
                    or not _supports(contract, "event.dataset")):
                continue
            inventoried = getattr(self.executor, "dataset_inventory", {}).get(target)
            for dataset in _host_datasets(contract, {"net_socket"}, os_family="linux"):
                if inventoried is not None and dataset not in inventoried:
                    continue
                intents.append(SearchIntent(
                    kind="raw", target=target, window=Window(start=window.start, end=window.end),
                    filters=[Predicate(field="event.dataset", op="eq", value=dataset)],
                    any_of=endpoint_groups,
                    max_records=MAX_PIVOT_RECORDS, purpose="expansion:flow_host_side",
                ))
        return intents

    def _windows_field_intents(
        self,
        window: LinkWindow,
        families: set[str],
        field_values: dict[str, list[Any]],
        *,
        host: str | None = None,
        purpose: str,
    ) -> list[SearchIntent]:
        """Push a normalized Windows key through its native aliases without an unkeyed dataset scan."""
        intents = []
        for target, contract in sorted(self.executor.contracts.items()):
            if (_is_network(target, contract)
                    or not _target_has_host_os(self.executor, target, contract, "windows")):
                continue
            source_groups = _windows_source_groups(contract, families)
            if not source_groups:
                continue
            filters = []
            if host is not None:
                if not _supports(contract, "host.name"):
                    continue
                native_hosts = [
                    candidate for candidate in contract.hosts
                    if _first_label(candidate) == _first_label(host)
                ] or [host]
                if len(native_hosts) > 1 and _supports(contract, "host.name", "in"):
                    filters.append(Predicate(field="host.name", op="in", value=native_hosts))
                else:
                    filters.append(Predicate(field="host.name", op="eq", value=native_hosts[0]))
            key_groups: list[list[Predicate]] = []
            for field, raw_values in field_values.items():
                values = list(dict.fromkeys(value for value in raw_values if value is not None))
                if not values:
                    continue
                if len(values) > 1 and _supports(contract, field, "in"):
                    key_groups.append([Predicate(field=field, op="in", value=values)])
                elif _supports(contract, field):
                    key_groups.extend([[Predicate(field=field, op="eq", value=value)] for value in values])
            if not key_groups:
                continue
            intents.append(SearchIntent(
                kind="raw", target=target, window=Window(start=window.start, end=window.end),
                filters=filters, any_of=_and_any_of(source_groups, key_groups),
                max_records=MAX_PIVOT_RECORDS, purpose=purpose,
            ))
        return intents

    def _windows_host_identity_intents(
        self, window: LinkWindow, label: str,
    ) -> tuple[list[SearchIntent], set[str], list[PivotCoverage]]:
        """Plan exact host predicates from complete inventories matching one canonical first label."""
        intents: list[SearchIntent] = []
        matched_hosts: set[str] = set()
        incomplete: list[PivotCoverage] = []
        for target, contract in sorted(self.executor.contracts.items()):
            if (_is_network(target, contract)
                    or not _target_has_host_os(self.executor, target, contract, "windows")):
                continue
            if not contract.host_inventory_complete:
                reason = "workstation host inventory is incomplete"
                incomplete.append(PivotCoverage(
                    target=target, dataset="windows", start=window.start, end=window.end,
                    status="partial", reasons=[reason], returned=0, total=None,
                    unresolved_ranges=[_range(window.start, window.end, reason)],
                ))
            if not _supports(contract, "host.name"):
                continue
            source_groups = _windows_source_groups(contract)
            if not source_groups:
                continue
            for host in contract.hosts:
                if _first_label(host) != label:
                    continue
                matched_hosts.add(host.casefold())
                intents.append(SearchIntent(
                    kind="raw", target=target, window=Window(start=window.start, end=window.end),
                    filters=[Predicate(field="host.name", op="eq", value=host)],
                    any_of=source_groups, max_records=MAX_PIVOT_RECORDS,
                    purpose="expansion:remote_logon_workstation",
                ))
        return intents, matched_hosts, incomplete

    def _lineage(self, anchor: LinkAnchor, window: LinkWindow):
        pid = _value(anchor, "process.pid")
        process_guid = _value(anchor, "process.guid")
        os_family = _os_family(anchor)
        boot_id = _boot(anchor)
        key = {"host": anchor.host, "pid": pid, "host.boot.id": boot_id, **_victim(anchor)}
        if usable_key(process_guid):
            key["process.guid"] = process_guid
        process_key = usable_key(process_guid) or isinstance(pid, int)
        families = ({"process_exec", "process_termination", "system_state"}
                    if os_family == "windows" else {"process_exec", "process_observed"})
        intents = self._host_intents(window, families, anchor.host, os_family) if process_key else []

        def select(events):
            """The anchored process's exec images, ancestors and descendants.

            Linux execs at one instant are ordered by audit serial and leave an undecided step when their order
            cannot be established. Windows uses ProcessGuid where present, or a pid bounded by termination and boot
            fences; Windows same-instant image ordering is handled by the shared ExecLineage at its lookup seams.
            """
            if os_family == "windows":
                roots = {str(process_guid).casefold()} if usable_key(process_guid) else set()
                related: dict[str, TypedEvent] = {}
                candidates = sorted(anchor.events + events, key=lambda item: (item.ts, item.id))
                if roots:
                    changed = True
                    while changed:
                        changed = False
                        for candidate in candidates:
                            if candidate.family != "process_exec" or candidate.host != anchor.host:
                                continue
                            guid = str(candidate.get("process.guid") or "").casefold()
                            parent = str(candidate.get("process.parent.guid") or "").casefold()
                            if guid in roots or parent in roots:
                                if guid and guid not in roots:
                                    roots.add(guid)
                                    changed = True
                                if candidate.id not in {event.id for event in anchor.events}:
                                    related[candidate.id] = candidate
                    return Selection(list(related.values()), [])
                # PID fallback is bounded by the closest termination/boot fence around the anchor.
                lower_fences: list[TypedEvent] = []
                upper_fences: list[TypedEvent] = []
                unresolved: list[str] = []
                anchored = set(anchor.event_ids)
                anchor_records = [
                    candidate for candidate in anchor.events
                    if candidate.ts == anchor.ts and candidate.get("process.pid") == pid
                ]
                anchor_record = next(
                    (candidate for candidate in anchor_records if candidate.id in anchored),
                    anchor_records[0] if len(anchor_records) == 1 else None,
                )
                for candidate in candidates:
                    fence = candidate.get("process.fence")
                    same_pid = candidate.get("process.pid") == pid
                    if fence == "boot" or (fence == "termination" and same_pid):
                        if candidate.ts < anchor.ts:
                            lower_fences.append(candidate)
                            continue
                        if candidate.ts > anchor.ts:
                            upper_fences.append(candidate)
                            continue
                        relative = (_relative_event_order(candidate, anchor_record)
                                    if anchor_record is not None else None)
                        if relative is None:
                            unresolved.append(
                                f"lineage undecided: Windows PID {fence} at the anchor instant cannot be ordered "
                                "without record_id in the same computer/channel"
                            )
                        elif relative <= 0:
                            lower_fences.append(candidate)
                        else:
                            upper_fences.append(candidate)

                def inside_fences(candidate: TypedEvent) -> bool:
                    if not (window.start <= candidate.ts < window.end):
                        return False
                    for fence in lower_fences:
                        relative = _relative_event_order(candidate, fence)
                        if relative is None:
                            unresolved.append(
                                "lineage undecided: a process event and its same-instant Windows PID fence "
                                "cannot be ordered outside one computer/channel record_id sequence"
                            )
                        elif relative <= 0:
                            return False
                    for fence in upper_fences:
                        relative = _relative_event_order(candidate, fence)
                        if relative is None:
                            unresolved.append(
                                "lineage undecided: a process event and its same-instant Windows PID fence "
                                "cannot be ordered outside one computer/channel record_id sequence"
                            )
                        elif relative >= 0:
                            return False
                    return True

                return Selection([
                    candidate for candidate in candidates
                    if candidate.family == "process_exec" and candidate.host == anchor.host
                    and (candidate.get("process.pid") == pid or candidate.get("process.ppid") == pid)
                    and candidate.id not in anchored and inside_fences(candidate)
                ], unresolved)
            # A record of another boot is another process. The link retrieves audit records without their journald
            # copies; their boot comes from the hunt's boot-interval map. One the map cannot place (a gap between
            # boots, near a boot's edge) is kept: a pid reused after a reboot cannot be excluded for it.
            all_events = {event.id: event for event in anchor.events + events
                          if event.family in {"process_exec", "process_observed"} and event.host == anchor.host
                          and not boots_conflict(boot_id, boot_of(event))}
            root = next((event for event in anchor.events if event.get("process.pid") == pid), None)
            if root is None:
                return Selection([], [f"lineage undecided: no anchor record carries pid {pid}"])
            host = anchor.host or ""
            root_boot = boot_of(root) or boot_id
            table = PidTable(observing=True)
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
                view = table.execs.view(host, parent, when, serial, boot, inclusive=False)
                ancestor = all_events.get(view.named.entry.event_id) if view.image is not None else None
                if ancestor is None:
                    if view.why:
                        unknown.append(view.why)
                    break                       # an ancestor whose exec was not retrieved ends the chain
                lineage_events = [all_events.get(step.entry.event_id) for step in view.span]
                if ancestor.id in related:
                    break
                related.update({event.id: event for event in lineage_events if event is not None})
                first_step = view.first
                parent, when, serial = first_step.ppid, first_step.ts, first_step.serial
                boot = boot or first_step.boot
            # Descendants: a record whose parent chain reaches one of the process's images.
            for candidate in sorted(all_events.values(), key=_order):
                if candidate.id in related or candidate.ts < first.ts:
                    continue
                parent, when, serial = candidate.get("process.ppid"), candidate.ts.timestamp(), _serial(candidate)
                boot = boot_of(candidate)
                for _ in range(32):
                    if not isinstance(parent, int) or parent in (0, 1):
                        break
                    view = table.execs.view(host, parent, when, serial, boot, inclusive=False)
                    if view.image is None:
                        # Undecided only where the unordered execs could be the process's or its descendants'
                        # (not before its first image, where no chain reaches it).
                        if view.why:
                            unknown.append(view.why)
                        break
                    span_ids = {step.entry.event_id for step in view.span}
                    if span_ids & images.keys():
                        related[candidate.id] = candidate
                        break
                    named = view.named
                    if named.ts < first_ts or named.entry.event_id not in all_events:
                        break                   # older than the process: this chain never reaches it
                    first_step = view.first
                    parent, when, serial = first_step.ppid, first_step.ts, first_step.serial
                    boot = boot or first_step.boot
            return Selection(list(related.values()), unknown)

        reason = _host_reason(anchor) or (None if process_key else "required typed key is unusable")
        pid_fallback = os_family == "windows" and not usable_key(process_guid)
        strength = ("observed" if not pid_fallback
                    or self.executor.process_termination_attested(anchor.host) else "inferred")
        return (key, strength, intents if reason is None else [],
                lambda event: event.family in families, select, reason, [])

    def _session(self, anchor: LinkAnchor, window: LinkWindow):
        os_family = _os_family(anchor)
        session_field = "auth.session_key" if os_family == "windows" else "process.session_id"
        session_id, auid = _value(anchor, session_field), _value(anchor, "process.auid")
        boot_id = _boot(anchor)
        key = {"host": anchor.host, session_field: session_id, **_victim(anchor)}
        if os_family != "windows":
            key.update({"process.auid": auid, "host.boot.id": boot_id})
        reason = _host_reason(anchor) or (None if usable_key(session_id) else "required typed key is unusable")
        session_families = {"auth", "system_state"} if os_family == "windows" else {"process_exec"}
        intents = self._host_intents(window, session_families, anchor.host, os_family) if reason is None else []

        def matches(event):
            if os_family == "windows":
                return event.host == anchor.host and event.get("auth.session_key") == session_id
            return (event.host == anchor.host and event.get(session_field) == session_id
                    and (auid is None or event.get("process.auid") == auid)
                    and not boots_conflict(boot_id, boot_of(event)))

        def select(events):
            if os_family != "windows":
                return [event for event in events if matches(event)]
            candidates = sorted(anchor.events + events, key=lambda item: (item.ts, item.id))
            lower, upper = window.start, window.end
            for event in candidates:
                if event.host != anchor.host or event.get("process.fence") != "boot":
                    continue
                if event.ts <= anchor.ts:
                    lower = max(lower, event.ts)
                elif event.ts < upper:
                    upper = event.ts
            return [event for event in candidates if lower <= event.ts < upper and matches(event)]

        strength = ("observed" if os_family != "windows"
                    or self.executor.system_log_attested(anchor.host) else "inferred")
        retain = (lambda event: event.family in session_families) if os_family == "windows" else matches
        return (key, strength, intents, retain,
                select, reason, [])

    def _flow(self, anchor: LinkAnchor, window: LinkWindow):
        community_id = next((cid for event in sorted(anchor.events, key=lambda item: (item.ts, item.id))
                             if (cid := written_community_id(event)) is not None), None)
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
            intents = self._host_intents(window, {"net_socket"}, anchor.host, _os_family(anchor))

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
        os_family = _os_family(anchor)
        fields = (["auth.target_account", "user.entity_id"] if os_family == "windows" else [
            "user.name" if _value(anchor, "user.name") is not None else "process.auid"
        ])
        field = next((name for name in fields if _value(anchor, name) is not None), fields[-1])
        account = _value(anchor, field)
        key = {field: account, "actor": "inferred"}
        if os_family == "windows" and not _portable_windows_account(account):
            return (key, "inferred", [], lambda _event: False, lambda _events: [],
                    "cross-host account identity is well-known or machine-generic", [])
        if not usable_key(account):
            return (key, "inferred", [], lambda _event: False, lambda _events: [],
                    "required typed key is unusable", [])
        forward = LinkWindow(label=window.label, start=max(anchor.ts, window.start), end=window.end)
        intents = []
        for target, contract in sorted(self.executor.contracts.items()):
            if _is_network(target, contract):
                continue
            if os_family not in {"linux", "windows"} or not _target_has_host_os(
                self.executor, target, contract, os_family,
            ):
                continue
            windows_groups = _windows_source_groups(contract) if os_family == "windows" else []
            inventoried = getattr(self.executor, "dataset_inventory", {}).get(target)
            mixed_linux = os_family == "linux" and inventoried is not None and bool(
                set(inventoried).intersection(WINDOWS_HOST_DATASETS)
            )
            for query_field in fields:
                if not _supports(contract, query_field):
                    continue
                if os_family == "windows":
                    if windows_groups:
                        intents.append(SearchIntent(
                            kind="raw", target=target,
                            window=Window(start=forward.start, end=forward.end),
                            filters=[Predicate(field=query_field, op="eq", value=account)],
                            any_of=windows_groups,
                            max_records=MAX_PIVOT_RECORDS, purpose="expansion:account",
                        ))
                    continue
                datasets = _host_datasets(contract, os_family="linux") if mixed_linux else (None,)
                for dataset in datasets:
                    filters = [Predicate(field=query_field, op="eq", value=account)]
                    if dataset is not None:
                        filters.insert(0, Predicate(field="event.dataset", op="eq", value=dataset))
                    intents.append(SearchIntent(
                        kind="raw", target=target,
                        window=Window(start=forward.start, end=forward.end), filters=filters,
                        max_records=MAX_PIVOT_RECORDS, purpose="expansion:account",
                    ))

        def matches(event):
            values = {event.get(name) for name in fields}
            return event.ts >= anchor.ts and event.host != anchor.host and account in values

        reason = None if intents else "key not pushable; full-dataset scan refused"
        return (key, "inferred", intents, matches,
                lambda events: [event for event in events if matches(event)], reason, [])

    def _host_after(self, anchor: LinkAnchor, window: LinkWindow):
        key = {"host.name": anchor.host, "time_relation": "after", "actor": "inferred", **_victim(anchor)}
        reason = _host_reason(anchor)
        if reason:
            return (key, "inferred", [], lambda _event: False, lambda _events: [], reason, [])
        os_family = _os_family(anchor)
        if os_family == "windows":
            intents = self._host_intents(window, None, anchor.host, "windows")
        else:
            request = EntityTimelineRequest(tool="entity_timeline", arguments=EntityTimelineArgs(
                entity={"kind": "host", "value": anchor.host, "role": "host"},
                start=max(anchor.ts, window.start), end=window.end,
            ))
            planned = self.executor.plan(request)[0] if hasattr(self.executor, "plan") else self.executor._intents(
                request,
            )
            inventories = getattr(self.executor, "dataset_inventory", {})
            has_mixed_target = any(
                bool(set(datasets).intersection(WINDOWS_HOST_DATASETS))
                and bool(set(datasets).intersection(HOST_TIMELINE_DATASETS))
                for datasets in inventories.values()
            )
            if not has_mixed_target:
                intents = [
                    intent for intent in planned
                    if os_family is None or self.executor.contracts[intent.target].os_family == os_family
                ]
            else:
                intents = []
                for intent in planned:
                    contract = self.executor.contracts[intent.target]
                    if os_family is not None and not _target_has_host_os(
                        self.executor, intent.target, contract, os_family,
                    ):
                        continue
                    inventory = inventories.get(intent.target)
                    if os_family == "linux" and inventory is not None:
                        dataset = PivotExecutor._intent_dataset(intent)
                        if dataset not in HOST_TIMELINE_DATASETS:
                            continue
                    intents.append(intent)
                # A mixed target whose profile is Windows needs explicit native Linux dataset intents because one
                # target-level OS label cannot produce both native host plans.
                if os_family == "linux":
                    for intent in self._host_intents(window, None, anchor.host, "linux"):
                        contract = self.executor.contracts[intent.target]
                        inventory = inventories.get(intent.target)
                        mixed = inventory is not None and bool(set(inventory).intersection(WINDOWS_HOST_DATASETS))
                        if mixed and contract.os_family != "linux" and intent not in intents:
                            intents.append(intent)
        matches = lambda event: event.host == anchor.host and event.ts >= anchor.ts
        reason = None if intents else "key not pushable; full-dataset scan refused"
        return (key, "inferred", intents, matches,
                lambda events: [event for event in events if matches(event)], reason, [])

    def _process_activity(self, anchor: LinkAnchor, window: LinkWindow):
        guid = _canonical_guid(anchor.link_key.get("process.guid")) or next((
            _canonical_guid(_value(anchor, field))
            for field in ("process.guid", "source.guid", "target.guid")
            if _canonical_guid(_value(anchor, field)) is not None
        ), None)
        boot_id = _boot(anchor)
        key = {"host.name": anchor.host, "process.guid": guid}
        if boot_id:
            key["host.boot.id"] = boot_id
        reason = _host_reason(anchor) or (None if guid else "required nonzero process GUID is unusable")
        intents = [] if reason else self._windows_field_intents(
            window, _PROCESS_ACTIVITY_FAMILIES,
            {
                "process.guid": _guid_query_values(guid),
                "source.guid": _guid_query_values(guid),
                "target.guid": _guid_query_values(guid),
            },
            host=anchor.host, purpose="expansion:process_activity",
        )
        if reason is None and not intents:
            reason = "key not pushable; full-dataset scan refused"

        def matches(event: TypedEvent) -> bool:
            if event.family not in _PROCESS_ACTIVITY_FAMILIES or event.host != anchor.host:
                return False
            event_boot = event.get("host.boot.id")
            if boot_id and event_boot and str(event_boot) != boot_id:
                return False
            # ParentProcessGuid names another process and is deliberately never a process-activity key.
            return any(
                _canonical_guid(event.get(field)) == guid
                for field in ("process.guid", "source.guid", "target.guid")
            )

        return (key, "observed", intents, matches,
                lambda events: [event for event in events if matches(event)], reason, [])

    def _process_session(self, anchor: LinkAnchor, window: LinkWindow):
        subject_session = _session_id(
            _value(anchor, "process.subject_session_id")
            or _value(anchor, "windows.event_data.SubjectLogonId")
        )
        target_session = _session_id(
            _value(anchor, "process.target_session_id")
            or _value(anchor, "windows.event_data.TargetLogonId")
            or _value(anchor, "process.session_id")
        )
        session = _session_id(anchor.link_key.get("process.session_id")) or subject_session or target_session
        boot_id = _boot(anchor)
        key = {"host.name": anchor.host, "process.session_id": session}
        if subject_session:
            key["process.subject_session_id"] = subject_session
        if target_session:
            key["process.target_session_id"] = target_session
        if boot_id:
            key["host.boot.id"] = boot_id
        reason = _host_reason(anchor) or (
            None if session else "required process logon session key is unusable"
        )
        # Logon ids may be decimal or variably padded hexadecimal in the native field. Fetch the bounded host
        # auth class and compare the canonical numeric session id locally rather than missing another spelling.
        auth_intents = ([] if reason else
                        self._host_intents(window, {"auth"}, anchor.host, "windows"))
        if reason is None and not auth_intents:
            reason = "key not pushable; full-dataset scan refused"
        intents = [] if reason else [
            *auth_intents, *self._host_intents(window, {"system_state"}, anchor.host, "windows"),
        ]

        def retain(event: TypedEvent) -> bool:
            return event.host == anchor.host and (
                event.family == "system_state"
                or (event.family == "auth" and _session_id(event.get("auth.session_id")) == session)
            )

        def select(events):
            candidates = sorted(anchor.events + list(events), key=lambda item: (item.ts, item.id))
            lower, upper = window.start, window.end
            saw_fence = False
            for event in candidates:
                if event.host != anchor.host or event.get("process.fence") != "boot":
                    continue
                saw_fence = True
                if event.ts <= anchor.ts:
                    lower = max(lower, event.ts)
                elif event.ts < upper:
                    upper = event.ts
            selected = []
            for event in candidates:
                event_boot = event.get("host.boot.id")
                if (
                    event.id not in anchor.event_ids
                    and lower <= event.ts < upper
                    and event.host == anchor.host
                    and event.family == "auth"
                    and _event_code(event) == 4624
                    and _session_id(event.get("auth.session_id")) == session
                    and not (boot_id and str(event_boot or "") != boot_id)
                ):
                    selected.append(event)
            attested = getattr(self.executor, "system_log_attested", lambda _host: False)(anchor.host)
            unresolved = []
            if not boot_id and not saw_fence and not attested:
                unresolved.append("process session same-boot boundary is unavailable")
            return Selection(selected, unresolved)

        return key, "observed", intents, retain, select, reason, []

    def _kerberos_logon(self, anchor: LinkAnchor, window: LinkWindow):
        code = anchor.link_key.get("event.code")
        if code not in {4624, 4769}:
            code = next((_event_code(event) for event in anchor.events if _event_code(event) in {4624, 4769}), None)
        guid = _canonical_guid(anchor.link_key.get("auth.logon_guid")) or next((
            _canonical_guid(event.get("auth.logon_guid")) for event in anchor.events
            if _canonical_guid(event.get("auth.logon_guid")) is not None
        ), None)
        key = {"auth.logon_guid": guid, "event.code": code}
        reason = None
        if code not in {4624, 4769}:
            reason = "anchor is not a 4624 logon or 4769 service-ticket event"
        elif guid is None:
            reason = "required nonzero logon GUID is unusable"
        intents = [] if reason else self._windows_field_intents(
            window, {"auth"}, {"auth.logon_guid": _guid_query_values(guid)},
            purpose="expansion:kerberos_logon",
        )
        if reason is None and not intents:
            reason = "key not pushable; full-dataset scan refused"
        expected = 4624 if code == 4769 else 4769

        def matches(event: TypedEvent) -> bool:
            return (
                event.family == "auth" and event.host != anchor.host
                and _event_code(event) == expected
                and _canonical_guid(event.get("auth.logon_guid")) == guid
            )

        return (key, "observed", intents, matches,
                lambda events: [event for event in events if matches(event)], reason, [])

    def _remote_logon_source(self, anchor: LinkAnchor, window: LinkWindow):
        code = anchor.link_key.get("event.code")
        if code is None:
            code = next((_event_code(event) for event in anchor.events if _event_code(event) is not None), None)
        logon_type = anchor.link_key.get("auth.logon_type")
        if logon_type is None:
            logon_type = next((event.get("auth.logon_type") for event in anchor.events
                               if event.get("auth.logon_type") is not None), None)
        try:
            logon_type = int(logon_type) if logon_type is not None else None
        except (TypeError, ValueError):
            logon_type = None
        eligible = code in _REMOTE_LOGON_CODES and (code != 4624 or logon_type in {3, 10})
        source_ip = anchor.link_key.get("source.ip")
        if not usable_key(source_ip):
            source_ip = next((event.get("source.ip") for event in anchor.events
                              if usable_key(event.get("source.ip"))), None)
        workstation = anchor.link_key.get("source.hostname")
        if not usable_key(workstation):
            workstation = next((
            event.get(field) for event in anchor.events
            for field in ("source.hostname", "source.workstation", "auth.workstation")
            if _first_label(event.get(field)) is not None
            ), None)
        label = _first_label(workstation)
        key: dict[str, Any] = {"event.code": code, "actor": "inferred"}
        if not eligible:
            return (key, "inferred", [], lambda _event: False, lambda _events: [],
                    "anchor is not an eligible remote logon or share event", [])

        if source_ip is not None:
            key.update({"source.ip": source_ip, "identity_strength": "observed_address_holder"})
            intents = self._windows_field_intents(
                window, {"net_socket"}, {"source.ip": [source_ip]},
                purpose="expansion:remote_logon_source_ip",
            )
            reason = None if intents else "source address is not pushable to Sysmon network evidence"

            def retain(event: TypedEvent) -> bool:
                return event.family == "net_socket" and event.get("source.ip") == source_ip and bool(event.host)

            def select(events):
                matches = [event for event in events if retain(event)]
                hosts = {
                    str(event.get("host.full_name") or event.host).strip().rstrip(".").casefold()
                    for event in matches if event.get("host.full_name") or event.host
                }
                if len(hosts) > 1:
                    return Selection([], [
                        ("remote source address was observed on multiple hosts; NAT, VPN, proxy, or DHCP "
                         "changes prevent unique attribution")
                    ])
                return Selection(matches, [])

            return key, "inferred", intents, retain, select, reason, []

        if label is None:
            return (key, "inferred", [], lambda _event: False, lambda _events: [],
                    "remote event has no usable source address or workstation name", [])
        key.update({"source.hostname": workstation, "canonical_label": label,
                    "identity_strength": "workstation_first_label"})
        intents, known_hosts, incomplete = self._windows_host_identity_intents(window, label)
        reason = None
        if incomplete:
            reason = None
        elif len(known_hosts) != 1 or not intents:
            reason = "workstation first label is not uniquely present in source inventory"

        def retain(event: TypedEvent) -> bool:
            return bool(event.host) and _first_label(event.host) == label

        def select(events):
            matches = [event for event in events if retain(event)]
            hosts = {str(event.host).casefold() for event in matches}
            if len(hosts) > 1:
                return Selection([], ["workstation first label maps to multiple hosts"])
            return Selection(matches, [])

        return key, "inferred", intents if reason is None else [], retain, select, reason, incomplete

    def _service_process(self, anchor: LinkAnchor, window: LinkWindow):
        code = anchor.link_key.get("event.code")
        if code is None:
            code = next((_event_code(event) for event in anchor.events if _event_code(event) is not None), None)
        raw_path = anchor.link_key.get("service.image_path") or _value(anchor, "service.image_path")
        binary, parse_reason = _service_binary(raw_path)
        binary_key = _windows_path_key(binary)
        key = {
            "host.name": anchor.host, "service.image_path": raw_path,
            "service.binary_key": binary_key, "process.parent": "services.exe", "actor": "inferred",
        }
        reason = _host_reason(anchor)
        if reason is None and code not in {4697, 7045}:
            reason = "anchor is not a service-install event"
        if reason is None:
            reason = parse_reason
        # Native Windows path keywords are case-sensitive while Windows path identity is not. Fetch the
        # host's bounded process class and compare the normalized key locally rather than risking a false negative.
        intents = ([] if reason else
                   self._host_intents(window, {"process_exec"}, anchor.host, "windows"))
        if reason is None and not intents:
            reason = "compatible Windows process source is unavailable"

        def matches(event: TypedEvent) -> bool:
            executable = _windows_path_key(
                event.get("process.executable_key") or event.get("process.executable")
            )
            parent = _windows_path_key(
                event.get("process.parent.executable_key") or event.get("process.parent.executable")
            )
            return (
                event.family == "process_exec" and event.host == anchor.host and event.ts >= anchor.ts
                and executable == binary_key and ntpath.basename(str(parent or "")).casefold() == "services.exe"
            )

        return (key, "inferred", intents, matches,
                lambda events: [event for event in events if matches(event)], reason, [])
