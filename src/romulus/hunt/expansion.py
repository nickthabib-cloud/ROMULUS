"""Crash-safe deterministic post-sweep expansion over typed links."""
from __future__ import annotations

import ipaddress
import json
import time
from collections import OrderedDict, defaultdict, deque
from collections.abc import Callable
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from datetime import UTC, datetime, timedelta

from romulus.agent.models import PivotCoverage
from romulus.decide.policy import LANE_ORDER
from romulus.detect import netdef
from romulus.detect.correlation import routable_remote
from romulus.detect.host import bind_lineage_citation_loader, is_internal
from romulus.detect.netdef import DIRECTION_ASSUMED_REASON
from romulus.detect.registry import bind_windows_site, fresh_direct_pack, rule_kind
from romulus.evidence.typed import TypedEvent, event_os_family
from romulus.evidence.windows_catalog import WINDOWS_HOST_DATASETS
from romulus.hunt.context import finalize_context
from romulus.hunt.expansion_plan import TIER_PLAN, WINDOWS_TIER_ADDITIONS
from romulus.hunt.links import (
    HOST_SIDE_LINKS,
    WINDOWS_LINK_TYPES,
    LinkAnchor,
    LinkFetcher,
    LinkResult,
    LinkType,
    LinkWindow,
    _canonical_guid,
    _event_code,
    _first_label,
    _session_id,
    effective_link_window,
    is_agent_reach,
    usable_key,
    written_community_id,
)
from romulus.hunt.pivot import HOST_AMBIGUOUS, HOST_LOOKUP_BUDGET, NO_HOST_RECORD
from romulus.hunt.publish import (
    LineageCitationFetcher,
    mark_hypothesis_relation,
    publish_match,
    subject_event_ids,
)
from romulus.hunt.rank import PASS_BEFORE_EXPANSION as RANK_PASS_SEEDS
from romulus.hunt.sweep import stored_boot_intervals
from romulus.hunt.windows_context import publish_windows_link_context
from romulus.hunt.zeek_links import FETCH_QUERIES as ZEEK_FETCH_QUERIES
from romulus.hunt.zeek_links import ZEEK_LINK_TYPES
from romulus.hunt.zeek_links import event_keys as zeek_event_keys
from romulus.sources.models import Window
from romulus.store.db import digest
from romulus.store.repo import Repo

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
DEFAULT_MAX_DEPTH = 3
DEFAULT_MAX_SOURCE_QUERIES = 180
MAX_ANCHOR_KEYS = 8
WINDOWS_DROPPED_SCOPE_EXAMPLES = 3
# The source queries each anchor brings to the expansion budget: every link of its plan fetched twice at the
# two-query floor of a physical fetch. The budget is shared, so an anchor with several keys draws on what one with
# fewer did not use.
PER_ANCHOR_SOURCE_QUERIES = 4 * sum(len(link_types) for _tier, link_types, _label in TIER_PLAN)
WINDOWS_PER_ANCHOR_SOURCE_QUERIES = PER_ANCHOR_SOURCE_QUERIES + 4 * sum(
    len(link_types) for _tier, link_types, _label in WINDOWS_TIER_ADDITIONS
)
NETWORK_FAMILIES = {"net_alert", "net_flow", "net_session", "dns_query", "http_tx",
                    "file_transfer", "tls_session", "ssh_session"}
_WINDOWS_TIER_LINKS = {
    (tier, label): links for tier, links, label in WINDOWS_TIER_ADDITIONS
}

# A sweep partition cell in one of these states evaluated every record of the rule's families in that partition; any
# other state (partial, failed, planned, split, not applicable, unsupported) leaves its records to expansion's own
# judgement.
SWEPT_COMPLETE = frozenset({"matched", "positive_only", "evaluated_complete", "no_match_complete"})
# Rules whose sweep coverage index is held while expansion runs (the least recently used is dropped and read again).
SWEPT_RULES_HELD = 8
# Task ids whose kind (a sweep read of this hunt or not) is held while expansion runs.
SWEEP_TASKS_HELD = 4096
# Reader-lineage lookups for hash reads whose only open question is their lineage. A provisioning or upgrade run
# reads the hash files from a handful of debconf, dpkg-preconfigure or service processes; 16 distinct readers per
# anchor covers such a run with room, while each lookup spends the expansion's shared source-query budget at its
# two-query floor, so one anchor's lookups never take more than a few links' worth. Past the cap a read stays high.
LINEAGE_FETCHES_PER_ANCHOR = 16
LINEAGE_FETCH_QUERY_CAP = 2
# Reader processes whose fetched lineage is held for the rest of the run (least recently used dropped).
LINEAGE_CACHE_HELD = 1024


def _cell_span(partition: str) -> tuple[datetime, datetime] | None:
    """A sweep partition key's (start, end); None for a link, window or other non-time partition."""
    start, sep, end = str(partition).partition("/")
    if not sep:
        return None
    try:
        return _utc(datetime.fromisoformat(start)), _utc(datetime.fromisoformat(end))
    except ValueError:
        return None


def _target_names(target: str, index: str) -> bool:
    """Whether a record read from `index` belongs to a configured sweep target: the target's own name or one of its
    comma-separated index patterns, with no exclusion pattern matching it. An alias cannot be resolved here, so its
    records are not placed (expansion judges them itself)."""
    from fnmatch import fnmatchcase
    parts = [part.strip() for part in str(target).split(",") if part.strip()]
    if any(part.startswith("-") and fnmatchcase(index, part[1:]) for part in parts):
        return False
    return any(not part.startswith("-") and fnmatchcase(index, part) for part in parts)


def _retain_smallest[T](mapping: dict[str, T], token: str, value: T, limit: int, *, rank=None) -> bool:
    """Keep the lexicographically first unique tokens in fixed space; return whether one fell outside it."""
    if token in mapping:
        return False
    if len(mapping) < limit:
        mapping[token] = value
        return False
    rank = rank or (lambda item, _value: item)
    largest = max(mapping, key=lambda item: rank(item, mapping[item]))
    if rank(token, value) < rank(largest, mapping[largest]):
        del mapping[largest]
        mapping[token] = value
    return True


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def expansion_windows(ts: datetime, hunt_window: Window) -> list[LinkWindow]:
    """The investigator's named windows, clipped to immutable hunt scope."""
    ts, start, end = _utc(ts), _utc(hunt_window.start), _utc(hunt_window.end)
    out = []
    for label, delta in (("anchor ±5 min", timedelta(minutes=5)),
                         ("anchor ±30 min", timedelta(minutes=30)),
                         ("anchor ±2 h", timedelta(hours=2))):
        window_start, window_end = max(start, ts - delta), min(end, ts + delta)
        if window_start < window_end:
            out.append(LinkWindow(label=label, start=window_start, end=window_end))
    return out


RESERVED_REASON = "source query budget reserved for discovered anchors"
# Within each tier of the expansion plan the most severe lane is served first. An anchor the budget stopped while a
# more severe anchor existed says where its queries went.
BUDGET_TO_SEVERE_REASON = "source query budget given to more severe anchors"
# Under the default internal-network definition, the endpoints it reads as outside are looked up to learn whether
# they are site hosts. Those fallback lookups together may spend at most this share of the expansion budget, so a
# network full of internet endpoints cannot starve the links themselves.
FALLBACK_LOOKUP_SHARE = 0.10
FALLBACK_CAP_REASON = "fallback lookup cap reached"
# Extra seeds are the evidence ranking's Reported findings beyond the rule estimate's whose entity carries a confirmed
# finding: expansion widens around a compromise the hunt has confirmed. An entity reported only for its tactic or rule
# breadth (a busy server's benign activity spans tactics) seeds nothing more than the rule estimate gives it: anchoring
# every lead there multiplies link work and correlation items without reaching more of an intrusion.
# Extra seeds anchored at a time: at most what
# the queries left could start, and never more than this, so a hunt with thousands of Reported findings writes
# anchors only as its budget can reach them. A hundred anchors at two queries a fetch is more than any leftover
# share of the default budget.
EXTRA_SEED_PAGE = 100
EXTRA_SEEDS_NOT_ANCHORED_REASON = "Reported-set seeds not anchored: budget"
EXTRA_SEEDS_NOT_ANCHORED_WALL_CLOCK = "Reported-set seeds not anchored: wall-clock budget"


# Cited records the planning cache may hold across all its anchors' plans. Beyond it the least recently planned anchor
# is dropped and planned again from the store when it is next needed, exactly as an uncached plan would be, so the
# cache bounds memory without changing a result; at a few KB per typed record this is a few hundred MB at most.
PLAN_CACHE_EVENTS = 100_000


def fallback_lookup_cap(max_source_queries: int) -> int:
    """Source queries all fallback lookups of a hunt may spend: FALLBACK_LOOKUP_SHARE of the budget, at least 1."""
    return max(1, int(max_source_queries * FALLBACK_LOOKUP_SHARE))


def _slot_groups_after(slots) -> list[int]:
    """For each slot, the budget groups left from it on. One anchor's Zeek variants of a link type share one query
    budget, so they divide the remaining queries as one slot: counted apart, a many-key anchor would cut every slot's
    cap below one physical fetch and starve the anchors after it."""
    seen, counts = set(), [0] * len(slots)
    for index in range(len(slots) - 1, -1, -1):
        slot = slots[index]
        seen.add((slot.row["id"], slot.link_type) if slot.link_type in ZEEK_LINK_TYPES else ("slot", index))
        counts[index] = len(seen)
    return counts


@dataclass
class _LinkPlan:
    variants: list[LinkAnchor]
    notes: tuple[str, ...]
    planned_query_cap: int
    planned_budget: int
    retryable: bool
    planned_lookups: int = 0         # the hunt's resolved lookups when planned: a refused plan retries when they grow
    slots: dict[str, list[_PlannedSlot]] = dataclass_field(default_factory=dict)


@dataclass
class _AnchorPlan:
    row: dict
    candidate: dict
    events: list[TypedEvent]
    anchor: LinkAnchor
    windows: dict[str, LinkWindow]
    links: dict[LinkType, _LinkPlan] = dataclass_field(default_factory=dict)


@dataclass
class _PlannedSlot:
    row: dict
    candidate: dict
    anchor: LinkAnchor
    link_type: LinkType
    window: LinkWindow
    stored: dict | None
    done: bool = False

def _curated_first(items, lane_of, imported):
    """Reorder peers inside each lane's existing positions, only when an imported peer is present."""
    grouped = defaultdict(list)
    any_imported = False
    for item in items:
        is_imported = imported(item)
        any_imported |= is_imported
        grouped[lane_of(item)].append((is_imported, item))
    if not any_imported:
        return items
    lanes = {lane: iter([item for flag, item in peers if not flag] +
                        [item for flag, item in peers if flag]) for lane, peers in grouped.items()}
    return [next(lanes[lane_of(item)]) for item in items]


class ExpansionEngine:
    def __init__(
        self, repo: Repo, hunt_id: str, hunt_window: Window, fetcher: LinkFetcher,
        *, max_depth: int = DEFAULT_MAX_DEPTH,
        max_source_queries: int = DEFAULT_MAX_SOURCE_QUERIES,
        per_anchor_source_queries: int | None = None,
        wall_clock_seconds: float = 7200,
        owner_token: str | None = None,
        clock: Callable[[], float] = time.monotonic,
        heartbeat: Callable[[], None] = lambda: None,
        after_link: Callable[[LinkResult], None] | None = None,
    ):
        self.repo, self.hunt_id, self.window, self.fetcher = repo, hunt_id, hunt_window, fetcher
        # Without per-anchor shares, max_source_queries is the expansion's fixed total; with them, each anchor that
        # can still be expanded brings per_anchor_source_queries and max_source_queries is the ceiling on the sum.
        self.max_depth, self.max_source_queries = max_depth, max_source_queries
        self.per_anchor_source_queries = per_anchor_source_queries
        self.budget = max_source_queries if per_anchor_source_queries is None else 0
        self.wall_clock_seconds, self.owner_token = wall_clock_seconds, owner_token
        self.clock, self.heartbeat, self.after_link = clock, heartbeat, after_link
        self.started = clock()
        # The sweep's boot-interval map (recorded with the hunt, so a resumed run uses the same one), shared with
        # the fetcher unless it was given its own.
        given = getattr(fetcher, "boots", None)
        self.boots = given if given else stored_boot_intervals(repo, hunt_id)
        if given is not None and not given:
            fetcher.boots = self.boots
        # address -> (host, reason) for fallback lookups already made in this hunt, and the queries they spent;
        # rebuilt from the durable lookup tasks on first use, so a resumed hunt neither repeats nor re-spends
        self._fallback: dict[str, tuple[str | None, str | None]] | None = None
        self._fallback_queries = 0
        # anchor id -> its hunt-independent identity, the last tie-break of the anchor order
        self._identities: dict[str, str] = {}
        # The evidence ranking's extra seeds: findings in its pass-1 Reported set that the rule estimate (urgent and
        # high) would not have seeded. They are anchored only once every anchor the rule estimate seeds is finished
        # or stopped, so those keep the budget share and order they always had, and then one page at a time, in rank
        # order, only while source queries and wall-clock time remain: the extra seeds spend only what is left, and
        # the ones never reached are counted, not anchored. `_extra_scores` holds the pass-1 rank of extra anchors
        # (bounded by the anchors themselves), which orders them within their tier.
        self._ranked = False
        self._extra_scores: dict[str, float] = {}
        self._extras_open = False
        self._extras_done = False
        self._extra_after = 0               # rank position of the last Reported finding looked at
        self._extras_stopped = EXTRA_SEEDS_NOT_ANCHORED_REASON   # why the remaining extra seeds were not anchored
        hunt = repo.get_hunt(hunt_id) if hasattr(repo, 'get_hunt') else None
        self._imported_rule_ids = {'sigma.' + row['id'] for row in ((hunt or {}).get('manifest', {}).get(
            'sigma_rules') or {}).get('applied', [])}
        # Planning inputs live only for this run, least recently used first, holding at most PLAN_CACHE_EVENTS cited
        # records in all; variants share those event objects.
        self._plans: OrderedDict[str, _AnchorPlan] = OrderedDict()
        self._plan_events = 0
        # rule id -> its sweep partition cells (target, start, end, complete), for SWEPT_RULES_HELD rules at most
        self._swept_cells: OrderedDict[str, dict] = OrderedDict()
        self._sweep_tasks: OrderedDict[str, bool] = OrderedDict()
        # records inside a complete sweep cell that the sweep did not store, so judged here as any unswept record
        self.unproven_swept = 0
        # Reader-lineage lookups: (host, boot, pid) -> (lineage record ids, why unavailable), the most recent
        # LINEAGE_CACHE_HELD; lookups made per anchor; queries spent since the run loop last counted them.
        self._lineage_cache: OrderedDict[tuple, tuple[list[str], str | None]] = OrderedDict()
        self._lineage_fetches: dict[str, int] = defaultdict(int)
        self._lineage_spend = 0
        self._query_count = 0

    def _events(self, ids: list[str]) -> list[TypedEvent]:
        """Stored records, with the boot the hunt's map places them in when they carry none (a sweep record read
        near its partition's end, before later observations, may have been stored without one)."""
        rows = self.repo.citation_events(self.hunt_id, ids)
        events = [TypedEvent.model_validate(row["event"]) for row in rows]
        self.boots.fill(events, rederive=True)
        return sorted(events, key=lambda event: (event.ts, event.id))

    @staticmethod
    def _anchor_host(events: list[TypedEvent]) -> str | None:
        """The host identity of a host-attributed anchor. A network-only anchor has none: its `host` is the
        sensor, and its internal endpoint is an address, not a host name (see `_victim_ips`)."""
        return next(
            (event.host for event in events if event.family not in NETWORK_FAMILIES and event.host), None,
        )

    @staticmethod
    def _victim_ips(events: list[TypedEvent]) -> list[str]:
        """Internal endpoint addresses of a network anchor, in address order."""
        internal = set()
        for event in events:
            for field in ("source.ip", "destination.ip"):
                try:
                    address = ipaddress.ip_address(str(event.get(field)))
                except ValueError:
                    continue
                if is_internal(address) and usable_key(str(address)):
                    internal.add(address)
        return [str(address) for address in sorted(internal, key=lambda a: (a.version, int(a)))]

    @staticmethod
    def _undecided_ips(events: list[TypedEvent]) -> list[str]:
        """Under the default internal-network definition, the routable endpoints it reads as outside the site: on a
        site in public space they may be the site's own hosts, so host resolution decides. Empty under a
        configured definition, which says where the site is."""
        if netdef.current().configured:
            return []
        found = set()
        for event in events:
            for field in ("source.ip", "destination.ip"):
                try:
                    address = ipaddress.ip_address(str(event.get(field)))
                except ValueError:
                    continue
                if not is_internal(address) and routable_remote(str(address)) and usable_key(str(address)):
                    found.add(address)
        return [str(address) for address in sorted(found, key=lambda a: (a.version, int(a)))]

    def _fallback_map(self) -> dict[str, tuple[str | None, str | None]]:
        """Fallback lookups this hunt already made, rebuilt once from its durable lookup tasks: an address the
        default reads as outside, with the verdict (a host, no host, ambiguous, or why it is unresolved)."""
        if self._fallback is None:
            self._fallback, self._fallback_queries = {}, 0
            executor = getattr(self.fetcher, "executor", None)
            contracts = getattr(executor, "contracts", {}) or {}
            inventories = getattr(executor, "dataset_inventory", {}) or {}
            requires_typed_host_identity = any(
                getattr(contract, "os_family", None) == "windows" for contract in contracts.values()
            ) or any(set(datasets).intersection(WINDOWS_HOST_DATASETS) for datasets in inventories.values())
            for task in self.repo.host_resolution_tasks(self.hunt_id):
                intent = task.get("intent") or {}
                if requires_typed_host_identity and intent.get("host_identity") != "typed-v2":
                    continue
                ip = intent.get("resolve_host_ip")
                spent = int(task.get("source_queries") or 0)
                try:
                    address = ipaddress.ip_address(str(ip))
                except ValueError:
                    continue
                if is_internal(address) or not routable_remote(str(address)) or ip in self._fallback:
                    continue                            # an internal endpoint's lookup is not a fallback
                outcome = task.get("outcome") or {}
                if task["state"] in ("evaluated", "partial") and isinstance(outcome, dict):
                    self._fallback[ip] = (outcome.get("host"), outcome.get("reason"))
                elif spent:
                    self._fallback[ip] = (None, f"victim host unresolved for {ip}: an earlier lookup did not finish")
                else:
                    continue                            # planned but never queried: not looked up yet
                self._fallback_queries += spent
        return self._fallback

    def _fallback_spent(self) -> int:
        self._fallback_map()
        return self._fallback_queries

    def _fallback_lookup(self, finding_id: str, ip: str, query_cap: int | None) -> tuple[str | None, str | None]:
        """Look up an endpoint the default reads as outside at most once per hunt, while the hunt's fallback
        lookups stay within fallback_lookup_cap(budget) source queries and the anchor's own `query_cap`. A lookup
        refused for the cap or the budget is not remembered, so it is stated now and may be made later."""
        known = self._fallback_map()
        if ip in known:
            return known[ip]
        remaining = fallback_lookup_cap(self.budget) - self._fallback_queries
        if remaining <= 0:
            return None, f"victim host not looked up for {ip}: {FALLBACK_CAP_REASON}"
        before = getattr(getattr(self.fetcher, "executor", None), "source_queries", None)
        cap = before + remaining if isinstance(before, int) else None
        effective = query_cap if cap is None else cap if query_cap is None else min(query_cap, cap)
        host, reason = self.fetcher.resolve_host(finding_id, ip, query_cap=effective)
        if host is None and (reason or "").endswith(HOST_LOOKUP_BUDGET):
            if cap is not None and (query_cap is None or cap < query_cap):
                reason = f"victim host not looked up for {ip}: {FALLBACK_CAP_REASON}"
            return host, reason
        after = getattr(getattr(self.fetcher, "executor", None), "source_queries", None)
        self._fallback_queries += after - before if isinstance(before, int) and isinstance(after, int) else 1
        known[ip] = (host, reason)
        return host, reason

    def _victim_variants(self, finding_id: str, variants: list[LinkAnchor], events: list[TypedEvent],
                         query_cap: int | None = None) -> tuple[list[LinkAnchor], list[str], list[str]]:
        """Host-side links of a network anchor run once per victim endpoint, each against the host that endpoint
        resolves to; an internal endpoint that resolves to no single host carries the reason instead.
        Under the default definition, the endpoints it reads as outside are resolved too: one that resolves to a
        host is a victim, one that no host record carries is not, and one that cannot be resolved (no host
        source, an incomplete lookup, or the budget) is named with the direction assumption, in the returned
        notes for the anchor and, when no victim is left, in the links' reason.
        A lookup not yet made (in this run or a resumed one) is made only while it fits under `query_cap`,
        the anchor's share of the query budget, checked against the live query count before each lookup.
        Returns (variants, endpoints beyond MAX_ANCHOR_KEYS, notes)."""
        ips, undecided = self._victim_ips(events), self._undecided_ips(events)
        if not ips and not undecided:
            return variants, [], []
        resolve = getattr(self.fetcher, "resolve_host", None)

        def lookup(ip: str) -> tuple[str | None, str | None]:
            if resolve is None:
                return None, f"victim host unknown for {ip}: host resolution is unavailable"
            return resolve(finding_id, ip, query_cap=query_cap)

        victims = [(ip, *lookup(ip)) for ip in ips]
        unresolved = []
        for ip in undecided:
            host, reason = self._fallback_lookup(finding_id, ip, query_cap) if resolve else lookup(ip)
            if host is not None or (reason or "").startswith(HOST_AMBIGUOUS):
                victims.append((ip, host, reason))      # host records claim the address: it is the site's
            elif NO_HOST_RECORD not in (reason or ""):
                unresolved.append(reason or f"victim host unknown for {ip}")
        note = (f"endpoints outside the default internal ranges not resolved to a site host "
                f"({'; '.join(unresolved)}); {DIRECTION_ASSUMED_REASON}")
        notes = [note] if unresolved else []
        out = [variant.model_copy(update={"host": host, "victim_ip": ip, "host_reason": reason})
               for variant in variants for ip, host, reason in victims]
        if not out:
            out = [variant.model_copy(update={"host_reason": notes[0]}) for variant in variants] if notes else variants
        return out[:MAX_ANCHOR_KEYS], [item.victim_ip for item in out[MAX_ANCHOR_KEYS:]], notes

    @staticmethod
    def _event_link_keys(event: TypedEvent, link_type: LinkType) -> list[dict]:
        if link_type in ZEEK_LINK_TYPES:
            return zeek_event_keys(event, link_type)
        if link_type == "process_lineage" and usable_key(event.get("process.pid")):
            return [{"process.pid": event.get("process.pid")}]
        if link_type == "login_session" and usable_key(event.get("process.session_id")):
            return [{
                "process.session_id": event.get("process.session_id"),
                "process.auid": event.get("process.auid") if usable_key(event.get("process.auid")) else None,
            }]
        if link_type in {"network_flow", "flow_host_side"}:
            community_id = written_community_id(event)
            flow_tuple = [event.get(field) for field in (
                "network.transport", "source.ip", "source.port",
                "destination.ip", "destination.port",
            )]
            if usable_key(community_id):
                return [{"network.community_id": community_id}]
            if all(usable_key(value) for value in flow_tuple):
                return [{"five_tuple": flow_tuple}]
        if link_type == "source_ip" and usable_key(event.get("source.ip")):
            return [{"source.ip": event.get("source.ip")}]
        if link_type == "account":
            if usable_key(event.get("user.name")):
                return [{"user.name": event.get("user.name")}]
            if usable_key(event.get("process.auid")):
                return [{"process.auid": event.get("process.auid")}]
        if link_type == "process_activity":
            return [
                {"process.guid": guid}
                for field in ("process.guid", "source.guid", "target.guid")
                if (guid := _canonical_guid(event.get(field))) is not None
            ]
        if link_type == "process_session":
            return [
                {"process.session_id": session}
                for field in (
                    "process.subject_session_id", "windows.event_data.SubjectLogonId",
                    "process.target_session_id", "windows.event_data.TargetLogonId",
                    "process.session_id",
                )
                if (session := _session_id(event.get(field))) is not None
            ]
        if link_type == "kerberos_logon":
            code = _event_code(event)
            guid = _canonical_guid(event.get("auth.logon_guid"))
            return [{"event.code": code, "auth.logon_guid": guid}] if code in {4624, 4769} and guid else []
        if link_type == "remote_logon_source":
            code = _event_code(event)
            logon_type = event.get("auth.logon_type")
            try:
                logon_type = int(logon_type) if logon_type is not None else None
            except (TypeError, ValueError):
                logon_type = None
            eligible = code in {4624, 4778, 1149, 5140, 5145} and (
                code != 4624 or logon_type in {3, 10}
            )
            if eligible and usable_key(event.get("source.ip")):
                return [{
                    "event.code": code, "auth.logon_type": logon_type,
                    "source.ip": event.get("source.ip"),
                }]
            if eligible:
                workstation = next((
                    event.get(field) for field in (
                        "source.hostname", "source.workstation", "auth.workstation",
                    ) if _first_label(event.get(field)) is not None
                ), None)
                if workstation is not None:
                    return [{
                        "event.code": code, "auth.logon_type": logon_type,
                        "source.hostname": workstation,
                    }]
        if link_type == "service_process":
            code = _event_code(event)
            image_path = event.get("service.image_path")
            if code in {4697, 7045} and usable_key(image_path):
                return [{"event.code": code, "service.image_path": image_path}]
        return []

    @staticmethod
    def _link_anchors(anchor: LinkAnchor, link_type: LinkType) -> tuple[list[LinkAnchor], list[dict]]:
        keyed: dict[str, tuple[dict, TypedEvent, str | None, datetime]] = {}
        windows_link = link_type in WINDOWS_LINK_TYPES
        zeek_link = link_type in ZEEK_LINK_TYPES
        limit = 1000 if zeek_link else MAX_ANCHOR_KEYS
        overflow = False
        for event in anchor.events:
            event_ts = _utc(event.ts)
            # A network record's host is its observer, not the endpoint host. Preserve the resolved/unknown
            # victim identity on those variants; host-attributed records use the host that wrote the key.
            event_host = anchor.host if event.family in NETWORK_FAMILIES else event.host or anchor.host
            for key in ExpansionEngine._event_link_keys(event, link_type):
                token = json.dumps(
                    {"key": key, "host": event_host, "window_anchor": event_ts.isoformat()}
                    if windows_link else key,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                value = (key, event, event_host, event_ts)
                if windows_link:
                    overflow |= _retain_smallest(
                        keyed, token, value, MAX_ANCHOR_KEYS + WINDOWS_DROPPED_SCOPE_EXAMPLES,
                        rank=lambda token, value: (abs(value[3] - _utc(anchor.ts)), token),
                    )
                elif zeek_link:
                    overflow |= _retain_smallest(keyed, token, value, limit + WINDOWS_DROPPED_SCOPE_EXAMPLES,
                                                 rank=lambda token, value: token)
                else:
                    keyed.setdefault(token, value)
        if not keyed:
            return [anchor], []
        tokens = sorted(keyed, key=lambda token: (
            (abs(keyed[token][3] - _utc(anchor.ts)), token) if windows_link else (timedelta(0), token)
        ))
        ordered = [keyed[token] for token in tokens]
        kept, dropped = ordered[:limit], ordered[limit:]
        if windows_link:
            variants = [
                anchor.model_copy(update={
                    "ts": event_ts,
                    "host": event_host,
                    "events": [event],
                    "link_key": key,
                })
                for key, event, event_host, event_ts in kept
            ]
        else:
            variants = [
                anchor.model_copy(update={"events": [event], **({"link_key": key} if zeek_link else {})})
                for key, event, _event_host, _event_ts in kept
            ]
        dropped_keys = [key for key, _event, _host, _ts in dropped]
        if overflow:
            dropped_keys.append({"additional_scopes": True})
        return variants, dropped_keys

    def _anchor_plan(self, row: dict, *, candidate: dict | None = None,
                     events: list[TypedEvent] | None = None) -> _AnchorPlan:
        plan = self._plans.get(row["id"])
        if plan is not None:
            self._plans.move_to_end(row["id"])
            return plan
        candidate = candidate or self.repo.candidate(row["candidate_id"])
        subject = subject_event_ids(candidate)
        events = events if events is not None else self._events(subject)
        candidate_ts = _utc(candidate["ts"])
        plan = _AnchorPlan(
            row=row, candidate=candidate, events=events,
            anchor=LinkAnchor(
                finding_id=candidate["id"], ts=candidate_ts, host=row["host"],
                event_ids=subject, events=events,
            ),
            windows={window.label: window for window in expansion_windows(candidate_ts, self.window)},
        )
        self._plans[row["id"]] = plan
        self._plan_events += len(events)
        while self._plan_events > PLAN_CACHE_EVENTS and len(self._plans) > 1:
            _evicted, dropped = self._plans.popitem(last=False)
            self._plan_events -= len(dropped.events)
        return plan

    def _seed_candidates(self, candidates, existing_rows: list[dict], *, ranked: bool = False) -> list[dict]:
        """Anchor the given candidates: those the rule estimate seeds (urgent or high), or with `ranked` the evidence
        ranking's extra seeds whatever their lane."""
        existing = {row["candidate_id"] for row in existing_rows}
        depths = {row["id"]: row["depth"] for row in existing_rows}
        added = []
        for candidate in candidates:
            if candidate.get("provenance") == "agent":
                continue
            if candidate["id"] in existing or (not ranked and candidate["lane"] not in {"urgent", "high"}):
                continue
            # Agent-published discoveries remain case contributions. A resume must not silently
            # promote them into deterministic expansion roots with a different reach contract.
            if candidate.get("source_case_id") is not None:
                continue
            # A context finding is already the product of a link from an anchor; expanding it again would
            # refetch the same session or lineage at depth + 1 and drain the reserve.
            if rule_kind(candidate["rule_id"]) == "context":
                continue
            parent = candidate.get("source_anchor_id")
            depth = depths.get(parent, -1) + 1 if parent else 0
            events = self._events(subject_event_ids(candidate))
            host = self._anchor_host(events)
            row = {
                "id": candidate["id"], "hunt_id": self.hunt_id, "candidate_id": candidate["id"],
                "depth": depth, "parent_anchor_id": parent, "host": host, "lane": candidate["lane"],
                "severity": candidate["severity"], "ts": candidate["ts"], "status": "pending", "reasons": [],
            }
            if candidate["ts"] is None:
                row.update(status="unexpanded", reasons=["observation time unavailable"])
            if not self.repo.save_expansion_anchor(row, owner_token=self.owner_token):
                continue
            existing.add(candidate["id"])
            depths[candidate["id"]] = depth
            added.append(row)
            if candidate["ts"] is not None:
                self._anchor_plan(row, candidate=candidate, events=events)
        return added

    def _seed_anchors(self) -> list[dict]:
        rows = self.repo.expansion_anchors(self.hunt_id)
        return self._seed_candidates(self.repo.candidates(self.hunt_id, ["urgent", "high"]), rows)

    def _is_extra(self, row: dict) -> bool:
        """A root the evidence ranking added: the rule estimate roots only urgent and high findings."""
        return self._ranked and row["depth"] == 0 and row["lane"] not in {"urgent", "high"}

    def _prepare_extra_seeds(self) -> None:
        if not hasattr(self.repo, "has_rank_pass") or not self.repo.has_rank_pass(self.hunt_id, RANK_PASS_SEEDS):
            return          # no pass-1 ranking: the rule estimate's seeds alone
        self._ranked = True
        # extra anchors an earlier run of this hunt made keep their rank order
        earlier = [row["id"] for row in self.repo.expansion_anchors(self.hunt_id) if self._is_extra(row)]
        for candidate_id, rank in self.repo.finding_ranks_for(self.hunt_id, RANK_PASS_SEEDS, earlier).items():
            self._extra_scores[candidate_id] = float(rank["score"])

    def _anchor_extra_seeds(self, query_count: int, all_rows: list[dict], blocked: dict) -> bool:
        """When every rule-estimate anchor is finished or stopped: anchor the next page of extra seeds, as many as
        the source queries a root may still spend could start (each fetch takes at least two), while such queries
        and wall-clock time remain. A page whose anchors had nothing to fetch spends nothing; the next page follows
        while queries remain, so the extras never reached are those the budget could not reach. True when the run
        loop has new work."""
        if not self._ranked or self._extras_done:
            return False
        opened, self._extras_open = not self._extras_open, True
        deferred = opened and any(self._is_extra(row) and row["status"] == "pending"
                                  for row in self.repo.expansion_anchors(self.hunt_id))
        if self.clock() - self.started >= self.wall_clock_seconds:
            self._extras_stopped = EXTRA_SEEDS_NOT_ANCHORED_WALL_CLOCK
            return deferred
        # With per-anchor shares each anchored extra brings its own share, up to the ceiling; with a fixed total the
        # extras are roots, so they may spend only what the root cap (the reserve for discovered anchors kept back)
        # still allows.
        cap = (self.max_source_queries if self.per_anchor_source_queries is not None
               else self._root_cap(all_rows, set(blocked), LANE_ORDER["lead"]))
        remaining = cap - query_count
        if remaining < 2:
            self._extras_stopped = EXTRA_SEEDS_NOT_ANCHORED_REASON
            return deferred
        want = min(EXTRA_SEED_PAGE, remaining // 2)
        rows = self.repo.expansion_anchors(self.hunt_id)
        anchored = 0
        while anchored < want:
            page = self.repo.finding_ranks_page(self.hunt_id, RANK_PASS_SEEDS, after_position=self._extra_after,
                                                limit=EXTRA_SEED_PAGE, reported=True, confirmed_entity=True)
            if not page:
                self._extras_done = True
                break
            candidates = {row["id"]: row for row in self.repo.candidates_by_ids(
                self.hunt_id, [item["candidate_id"] for item in page])}
            for item in page:
                self._extra_after = item["position"]
                candidate = candidates.get(item["candidate_id"])
                if candidate is None or candidate["lane"] in {"urgent", "high"}:
                    continue
                added = self._seed_candidates([candidate], rows, ranked=True)
                if added:
                    self._extra_scores[candidate["id"]] = float(item["score"])
                    rows.extend(added)
                    anchored += 1
                if anchored >= want:
                    break
        return anchored > 0 or deferred

    def _extras_not_anchored(self) -> int:
        """Extra seeds past the last one looked at (Reported, on an entity with a confirmed finding) that expansion
        could have anchored."""
        if not self._ranked or self._extras_done:
            return 0
        counts = self.repo.finding_rank_counts(self.hunt_id, RANK_PASS_SEEDS, after_position=self._extra_after,
                                               reported=True, exclude_lanes=("urgent", "high"), confirmed_entity=True)
        return sum(count for rule_id, count in counts.items() if rule_kind(rule_id) != "context")

    def _identity(self, row: dict) -> str:
        """The anchor's rule and evidence, which are the same in every hunt over the same records. A candidate id also
        carries its hunt's id, so ordering ties by it would give two runs of one hunt different anchor orders, and a
        budget cut inside a tier would then fall on different links."""
        if row["id"] not in self._identities:
            plan = self._plans.get(row["id"])
            candidate = plan.candidate if plan is not None else self.repo.candidate(row["candidate_id"])
            self._identities[row["id"]] = digest({
                "rule_id": candidate["rule_id"],
                "evidence": candidate.get("group_key") or sorted(subject_event_ids(candidate)),
            })
        return self._identities[row["id"]]

    def _anchor_priority(self, row: dict) -> tuple:
        return (
            LANE_ORDER.get(row["lane"], 9), -self._extra_scores.get(row["id"], 0.0),
            SEVERITY_ORDER.get(row["severity"], 9),
            row["ts"] is None, _utc(row["ts"]) if row["ts"] is not None else None,
            self._identity(row), row["id"],
        )

    def _is_imported(self, row: dict) -> bool:
        if not self._imported_rule_ids:
            return False
        plan = self._plans.get(row['id'])
        candidate = plan.candidate if plan is not None else self.repo.candidate(row['candidate_id'])
        return candidate['rule_id'] in self._imported_rule_ids

    def _ordered_anchors(self, rows: list[dict]) -> list[dict]:
        """Round-robin hosts while retaining deterministic priority within each host."""
        by_host: dict[str, deque[dict]] = defaultdict(deque)
        for row in sorted(rows, key=self._anchor_priority):
            by_host[row["host"] or ""].append(row)
        hosts = sorted(by_host, key=lambda host: self._anchor_priority(by_host[host][0]))
        ordered = []
        while any(by_host.values()):
            for host in hosts:
                if by_host[host]:
                    ordered.append(by_host[host].popleft())
        if self._imported_rule_ids:
            ordered = _curated_first(ordered, lambda row: row['lane'], self._is_imported)
        return ordered

    def _budget_for(self, all_rows: list[dict]) -> int:
        """The source queries the expansion may have spent by now: its fixed total, or one share for every anchor that
        can still be expanded (roots and discovered anchors alike, whichever run recorded them), up to the ceiling."""
        if self.per_anchor_source_queries is None:
            return self.max_source_queries
        shares = 0
        for row in all_rows:
            if row["depth"] >= self.max_depth or row["ts"] is None:
                continue
            share = self.per_anchor_source_queries
            # The default manifest reserves the portable/Linux plan. Windows anchors add the same four-query
            # allowance for each additional planned link; an explicit non-default setting remains authoritative.
            if share == PER_ANCHOR_SOURCE_QUERIES:
                is_windows = row.get("_windows_anchor")
                if is_windows is None:
                    is_windows = any(
                        event_os_family(event) == "windows" for event in self._anchor_plan(row).events
                    )
                    row["_windows_anchor"] = is_windows
                if is_windows:
                    share = WINDOWS_PER_ANCHOR_SOURCE_QUERIES
                is_zeek = row.get("_zeek_anchor")
                if is_zeek is None:
                    is_zeek = any(event.get("observer.product") == "zeek" for event in self._anchor_plan(row).events)
                    row["_zeek_anchor"] = is_zeek
                if is_zeek:
                    share += 4 * len(ZEEK_LINK_TYPES)
            shares += share
        return min(self.max_source_queries, shares)

    def _root_cap(self, all_rows: list[dict], blocked: set[str], lane_rank: int) -> int:
        """Queries a root anchor may reach, given the most severe lane with work. A fifth of the total (the fixed
        total, or with per-anchor shares the ceiling) is a reserve for anchors discovered by expansion. With shares,
        roots spend freely below the rest, since every discovered anchor brings its own share; the reserve keeps a
        discovered anchor's queries when shares reach the ceiling. It holds back roots only for a discovered anchor
        at least as severe; a less severe one waits behind them. With none waiting, half of the reserve is released
        to roots, but only when the other half still covers one fetch (two queries), so a discovered anchor of that
        lane is never starved."""
        budget = self.budget
        total = budget if self.per_anchor_source_queries is None else self.max_source_queries
        root_budget = total - max(1, (total + 4) // 5) if total else 0
        reserve = total - root_budget
        if self.per_anchor_source_queries is not None and budget <= root_budget:
            return budget
        children = [row for row in all_rows if 0 < row["depth"] < self.max_depth and row["status"] == "pending"
                    and row["id"] not in blocked]
        if any(LANE_ORDER.get(row["lane"], 9) <= lane_rank for row in children):
            return min(budget, root_budget)
        if children:
            return budget
        return min(budget, root_budget + (reserve // 2 if reserve - reserve // 2 >= 2 else 0))

    @staticmethod
    def _add_reason(anchor_reasons: dict[str, list[str]], anchor_id: str, reason: str) -> None:
        if reason not in anchor_reasons[anchor_id]:
            anchor_reasons[anchor_id].append(reason)

    @staticmethod
    def _retryable_victim_plan(variants: list[LinkAnchor], notes: list[str]) -> bool:
        reasons = [*(variant.host_reason or "" for variant in variants), *notes]
        return any("budget" in reason or FALLBACK_CAP_REASON in reason for reason in reasons)

    def _link_plan(self, plan: _AnchorPlan, link_type: LinkType,
                   anchor_reasons: dict[str, list[str]], root_cap: int) -> _LinkPlan:
        query_cap = root_cap if plan.row["depth"] == 0 else self.max_source_queries
        cached = plan.links.get(link_type)
        lookups = len(self._fallback or {})
        if cached is not None and not (
            cached.retryable
            and (query_cap > cached.planned_query_cap or self.budget > cached.planned_budget
                 or lookups > cached.planned_lookups)
        ):
            return cached

        if link_type in WINDOWS_LINK_TYPES:
            # Windows scopes depend on the tier's effective window. Keep only the anchor here; the tier planner
            # streams its cited events into a fixed-size scope buffer instead of caching every raw variant.
            variants, dropped = [plan.anchor], []
        else:
            variants, dropped = self._link_anchors(plan.anchor, link_type)
        notes: list[str] = []
        if link_type in HOST_SIDE_LINKS and not plan.anchor.host:
            variants, dropped_ips, notes = self._victim_variants(
                plan.candidate["id"], variants, plan.events, query_cap=query_cap,
            )
            for note in notes:
                self._add_reason(anchor_reasons, plan.row["id"], note)
            if dropped_ips:
                self._add_reason(
                    anchor_reasons, plan.row["id"],
                    "keys_not_expanded:" + json.dumps(
                        [{"victim_ip": ip} for ip in dropped_ips],
                        sort_keys=True, separators=(",", ":"),
                    ),
                )
        if dropped:
            if link_type in ZEEK_LINK_TYPES:
                self._add_reason(anchor_reasons,plan.row["id"],
                                 "Zeek link hop-key limit 1000 reached; remaining anchor keys unresolved")
            self._add_reason(
                anchor_reasons, plan.row["id"],
                "keys_not_expanded:" + json.dumps(dropped, sort_keys=True, separators=(",", ":")),
            )
        planned = _LinkPlan(
            variants=variants, notes=tuple(notes), planned_query_cap=query_cap, planned_budget=self.budget,
            retryable=self._retryable_victim_plan(variants, notes), planned_lookups=len(self._fallback or {}),
        )
        plan.links[link_type] = planned
        return planned

    def _windows_scoped_variants(
        self, anchor: LinkAnchor, link_type: LinkType, window_label: str,
    ) -> tuple[list[tuple[LinkAnchor, LinkWindow]], dict | None]:
        limit = MAX_ANCHOR_KEYS + WINDOWS_DROPPED_SCOPE_EXAMPLES
        scopes: dict[str, tuple[dict, TypedEvent, str | None, datetime, LinkWindow]] = {}
        overflow = False
        saw_key = False
        for event in anchor.events:
            keys = self._event_link_keys(event, link_type)
            if not keys:
                continue
            saw_key = True
            event_ts = _utc(event.ts)
            windows = {item.label: item for item in expansion_windows(event_ts, self.window)}
            window = windows.get(window_label)
            if window is None:
                continue
            window = effective_link_window(event_ts, link_type, window)
            if window.start >= window.end:
                continue
            event_host = anchor.host if event.family in NETWORK_FAMILIES else event.host or anchor.host
            for key in keys:
                token = json.dumps(
                    {
                        "key": key,
                        "host": event_host,
                        "window": window.model_dump(mode="json"),
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
                value = (key, event, event_host, event_ts, window)
                existing = scopes.get(token)
                if existing is not None:
                    if (abs(event_ts - _utc(anchor.ts)), event_ts, event.id) < (
                        abs(existing[3] - _utc(anchor.ts)), existing[3], existing[1].id,
                    ):
                        scopes[token] = value
                    continue
                overflow |= _retain_smallest(
                    scopes, token, value, limit,
                    rank=lambda token, value: (abs(value[3] - _utc(anchor.ts)), token),
                )
        if not saw_key:
            windows = {item.label: item for item in expansion_windows(anchor.ts, self.window)}
            window = windows.get(window_label)
            if window is not None:
                window = effective_link_window(anchor.ts, link_type, window)
                if window.start >= window.end:
                    window = None
            return ([(anchor, window)] if window is not None else []), None

        ordered = sorted(scopes.items(), key=lambda item: (abs(item[1][3] - _utc(anchor.ts)), item[0]))
        kept, dropped = ordered[:MAX_ANCHOR_KEYS], ordered[MAX_ANCHOR_KEYS:]
        scoped = [
            (
                anchor.model_copy(update={
                    "ts": event_ts,
                    "host": event_host,
                    "events": [event],
                    "link_key": key,
                }),
                window,
            )
            for _token, (key, event, event_host, event_ts, window) in kept
        ]
        if not dropped:
            return scoped, None
        examples = [{
            "host": str(host)[:128],
            "key": {name: str(value)[:128] for name, value in key.items()},
            "window": window.model_dump(mode="json"),
        } for _token, (key, _event, host, _ts, window) in dropped]
        return scoped, {
            "limit": MAX_ANCHOR_KEYS,
            "window_label": window_label,
            "dropped_at_least": len(examples) + int(overflow),
            "examples": examples,
            "more": overflow,
        }

    def _planned_slots(self, plan: _AnchorPlan, link_type: LinkType, window_label: str,
                       anchor_reasons: dict[str, list[str]], root_cap: int) -> list[_PlannedSlot]:
        link_plan = self._link_plan(plan, link_type, anchor_reasons, root_cap)
        cached = link_plan.slots.get(window_label)
        if cached is not None:
            return cached
        slots = []
        windows_link = link_type in WINDOWS_LINK_TYPES
        if windows_link:
            scoped, dropped = self._windows_scoped_variants(plan.anchor, link_type, window_label)
            if dropped is not None:
                self._add_reason(
                    anchor_reasons,
                    plan.row["id"],
                    "keys_not_expanded:" + json.dumps(dropped, sort_keys=True, separators=(",", ":")),
                )
        else:
            # Preserve the portable expansion identity and window contract byte-for-byte.
            window = plan.windows[window_label]
            scoped = [(variant, window) for variant in link_plan.variants]
        for variant, window in scoped:
            if hasattr(self.fetcher, "result_id"):
                stored = self.repo.expansion_link(self.fetcher.result_id(variant, link_type, window))
            else:
                stored = self.repo.expansion_link_for(
                    plan.candidate["id"], link_type, window.label, window.start, window.end,
                )
            done = bool(stored and stored["evaluated"])
            # an evaluated link needs nothing more from its stored row, which can carry thousands of record ids
            slots.append(_PlannedSlot(
                row=plan.row, candidate=plan.candidate, anchor=variant, link_type=link_type,
                window=window, stored=None if done else stored, done=done,
            ))
        link_plan.slots[window_label] = slots
        return slots

    def _tier_slots(self, ordered: list[dict], anchor_reasons: dict[str, list[str]],
                    root_cap: int) -> list[_PlannedSlot]:
        """The unevaluated slots of the lowest unfinished tier, assembled from per-anchor plans."""
        for tier, link_types, window_label in TIER_PLAN:
            tier_slots = []
            windows_links = _WINDOWS_TIER_LINKS.get((tier, window_label), ())
            zeek_links = ("zeek_uid", "zeek_file", "certificate") if tier == "T1" else (
                ("address_host",) if tier == "T2" else ())
            for link_type in (*link_types, *windows_links, *zeek_links):
                for anchor_row in ordered:
                    plan = self._anchor_plan(anchor_row)
                    if link_type in zeek_links and not any(zeek_event_keys(event, link_type) for event in plan.events):
                        continue
                    if link_type in windows_links and not any(
                        event_os_family(event) == "windows" for event in plan.events
                    ):
                        continue
                    tier_slots.extend(
                        slot for slot in self._planned_slots(
                            plan, link_type, window_label, anchor_reasons, root_cap,
                        ) if not slot.done
                    )
            if tier_slots:
                if self._imported_rule_ids:
                    tier_slots = _curated_first(tier_slots, lambda slot: slot.row['lane'],
                        lambda slot: slot.candidate['rule_id'] in self._imported_rule_ids)
                return tier_slots
        return []

    @staticmethod
    def _stored_result(row: dict) -> LinkResult:
        return LinkResult(
            id=row["id"], anchor_id=row["anchor_id"], link_type=row["link_type"],
            window=LinkWindow(label=row["window_label"], start=_utc(row["window_start"]),
                              end=_utc(row["window_end"])),
            strength=row["strength"], key=row["key"], status=row["status"], event_ids=row["event_ids"],
            evidence_ids=row["evidence_ids"], task_ids=row["task_ids"],
            coverage=[PivotCoverage.model_validate(item) for item in row["coverage"]],
            reasons=row["reasons"], duration_ms=row["duration_ms"],
            query_spend=row["query_spend"],
        )

    def _persist_link(self, result: LinkResult) -> None:
        self.repo.save_expansion_link({
            "id": result.id, "hunt_id": self.hunt_id, "anchor_id": result.anchor_id,
            "link_type": result.link_type, "window_label": result.window.label,
            "window_start": result.window.start, "window_end": result.window.end,
            "strength": result.strength, "key": result.key, "status": result.status,
            "event_ids": result.event_ids, "evidence_ids": result.evidence_ids,
            "task_ids": result.task_ids,
            "coverage": [item.model_dump(mode="json") for item in result.coverage],
            "reasons": result.reasons, "duration_ms": result.duration_ms,
            "query_spend": result.query_spend, "evaluated": 0,
            "zeek_budget": result.zeek_budget,
        }, owner_token=self.owner_token)

    def _evaluate(self, candidate: dict, result: LinkResult) -> list[dict]:
        if result.link_type == "address_host":
            # The small sample establishes that a lease's hostname has telemetry.
            # Dedicated host links own activity searches and their direct findings.
            self.repo.mark_expansion_link_evaluated(result.id, owner_token=self.owner_token)
            return []
        # Per link, only the direct (sweep) pack runs: a strong indicator among the linked records is published
        # immediately. Context rules are judged once, after expansion ends, by finalize_context.
        events = self._events(result.event_ids)
        published = []
        reach = {"anchor_id": candidate["id"], "link_id": result.id, "link_type": result.link_type,
                 "strength": result.strength}

        def publish(playbook, match, sweep_group=None, defer=True):
            # The finding stands on its own cited records and keeps its machine lane. Only its relation to the
            # anchor may be a hypothesis.
            mark_hypothesis_relation(match, anchor_id=candidate["id"], link_type=result.link_type,
                                     link_id=result.id, strength=result.strength)
            if sweep_group is not None:
                # an earlier fold of this link may have revised the group: fold into what is stored now
                sweep_group = self.repo.candidate(sweep_group["id"]) or sweep_group
            row = publish_match(
                self.repo, self.hunt_id, playbook, match, result.task_ids[0] if result.task_ids else None, {},
                source_anchor_id=candidate["id"], source_link_id=result.id, owner_token=self.owner_token,
                zeek_context=events, zeek_context_ids=result.evidence_ids, context_reach=dict(reach),
                sweep_group=sweep_group, defer_to_sweep=defer,
            )
            if row is not None:
                published.append(row)

        for playbook in self._direct_pack():
            rule_events, context, notes = events, frozenset(), {}
            if hasattr(playbook, "lineage_missing"):
                # Hash reads whose only open question is their reader's lineage: fetch it and judge them with it.
                rule_events, context, notes = self._with_reader_lineage(playbook.id, candidate["id"], events)
                playbook.observe_only = context
            matches = playbook.consume(rule_events)
            if not matches:
                continue
            for match in matches:
                match.notes.extend(notes.get(match.group_key, []))
            # The rule ran once over every record of the link, as without the sweep check. A match whose every
            # subject record the sweep is proven to have judged, and for which the sweep published a group, only adds
            # this reach to that group at the sweep's lane; every other match is published as before (failing toward
            # high), including one the sweep could not have made because it never saw its records together.
            per_record = hasattr(playbook, "match_each")
            if per_record:
                subjects = [event for event in rule_events if event.id not in context]
            else:
                wanted = {event.id for match in matches for event in match.events if event.id not in match.context_ids}
                subjects = [event for event in rule_events if event.id in wanted]
            proven = self._swept_ids(playbook, subjects)
            if not proven:
                for match in matches:
                    publish(playbook, match)
                continue
            if not per_record:
                for match in matches:
                    subject = {event.id for event in match.events if event.id not in match.context_ids}
                    group = self._sweep_group(playbook, match) if subject and subject <= proven else None
                    # the sweep's lane stands unless the reach's own judgment of these records is higher
                    publish(playbook, match, sweep_group=group,
                            defer=group is None or not self._higher(match, group))
                continue
            # A rule that folds records per typed shape places each proven record in the group the sweep published
            # for it (records the sweep split across lanes are never merged); the rest are judged here as before.
            folds, folded = self._swept_folds(playbook, rule_events, proven)
            if not folded:
                for match in matches:
                    publish(playbook, match)
                continue
            for group, defer, match in folds:
                publish(playbook, match, sweep_group=group, defer=defer)
            for match in self._judge(playbook.id, rule_events,
                                     lambda event, folded=folded, context=context:
                                     event.id not in folded and event.id not in context):
                match.notes.extend(notes.get(match.group_key, []))
                publish(self._rule(playbook.id), match)
        published.extend(publish_windows_link_context(self.repo, self.hunt_id, candidate, result, events,
                                                      owner_token=self.owner_token))
        self.repo.mark_expansion_link_evaluated(result.id, owner_token=self.owner_token)
        return published

    def _direct_pack(self) -> list:
        pack = bind_windows_site(fresh_direct_pack(), getattr(getattr(self.fetcher, "executor", None), "site_facts", None))
        # The same verified re-read of cited lineage records the sweep's pack has, so a finding found here can rest
        # on its lineage exactly as one found in the sweep can.
        executor = getattr(self.fetcher, "executor", None)
        if getattr(executor, "client", None) is not None and getattr(executor, "contracts", None):
            bind_lineage_citation_loader(pack, LineageCitationFetcher(executor.client, executor.contracts).load)
        return pack

    def _rule(self, rule_id: str):
        """A fresh evaluator of one rule, set up as the direct pack sets it up."""
        return next(playbook for playbook in self._direct_pack() if playbook.id == rule_id)

    def _judge(self, rule_id: str, events: list[TypedEvent], judged) -> list:
        """A fresh evaluator's matches over only the records `judged` accepts. A rule that reads other records as
        context (`observe_only`) still reads them; otherwise records of its own families it may not judge are left
        out."""
        rule = self._rule(rule_id)
        if hasattr(rule, "observe_only"):
            rule.observe_only = frozenset(event.id for event in events if not judged(event))
            return rule.consume(events)
        own = set(rule.families) - set(rule.context_families)
        return rule.consume([event for event in events if event.family not in own or judged(event)])

    def _with_reader_lineage(self, rule_id: str, anchor_id: str, events: list[TypedEvent]):
        """(the link's records plus fetched reader lineage, the ids of the fetched records (context only), notes per
        high group key for reads whose lineage stayed unavailable). Only a read the rule says lacks nothing but its
        lineage (`lineage_missing`: a packaged root Perl or Python, no login marker) is looked up, once per reader
        process."""
        probe = self._rule(rule_id)
        probe.observe_only = frozenset(event.id for event in events)
        probe.consume(events)                           # lineage only
        held = {event.id for event in events}
        added: dict[str, TypedEvent] = {}
        notes: dict[str, list[str]] = defaultdict(list)
        readers: dict[tuple, TypedEvent] = {}
        for event in events:
            if probe.lineage_missing(event):
                readers.setdefault((event.host, event.get("host.boot.id"), event.get("process.pid")), event)
        for key, event in readers.items():
            ids, why = self._reader_lineage(anchor_id, key, event)
            if why is not None:
                group = json.dumps([event.host, str(event.get("process.executable")), str(event.get("file.path")),
                                    "high"])
                note = (f"Lineage for the reader (pid {key[2]} on {key[0]}) was not available to expansion: {why}; "
                        "the read stays high.")
                if note not in notes[group]:
                    notes[group].append(note)
                continue
            added.update((record.id, record) for record in self._events([i for i in ids if i not in held]))
        if not added:
            return events, frozenset(), notes
        merged = sorted([*events, *added.values()], key=lambda record: (record.ts, record.id))
        return merged, frozenset(added), notes

    def _reader_lineage(self, anchor_id: str, key: tuple, event: TypedEvent) -> tuple[list[str], str | None]:
        """(the stored ids of the reader's process-lineage records, why they are unavailable or None)."""
        cached = self._lineage_cache.get(key)
        if cached is not None:
            self._lineage_cache.move_to_end(key)
            return cached
        if self._lineage_fetches[anchor_id] >= LINEAGE_FETCHES_PER_ANCHOR:
            return [], f"this anchor's {LINEAGE_FETCHES_PER_ANCHOR} reader-lineage lookups are spent"
        if (reason := self._budget_reason(self._query_count + self._lineage_spend)) is not None:
            return [], reason
        fetch = getattr(self.fetcher, "fetch", None)
        if fetch is None:
            return [], "no lineage fetcher is available"
        windows = expansion_windows(event.ts, self.window)
        if not windows:
            return [], "the read is outside the hunt window"
        self._lineage_fetches[anchor_id] += 1
        link_anchor = LinkAnchor(finding_id=anchor_id, ts=event.ts, host=event.host, event_ids=[event.id],
                                 events=[event])
        result = fetch(link_anchor, "process_lineage", windows[-1], query_cap=LINEAGE_FETCH_QUERY_CAP)
        self._lineage_spend += result.query_spend
        found = ((list(result.event_ids), None) if result.status == "complete" else
                 ([], f"the lineage lookup was {result.status}"
                      + (f" ({'; '.join(result.reasons)[:200]})" if result.reasons else "")))
        self._lineage_cache[key] = found
        while len(self._lineage_cache) > LINEAGE_CACHE_HELD:
            self._lineage_cache.popitem(last=False)
        return found

    def _swept_folds(self, playbook, events: list[TypedEvent], swept: set[str]):
        """([(the sweep's candidate, one match of the records this reach adds to it)], the ids of those records) for a
        rule that judges records one at a time (`match_each`): each proven record goes to the group the sweep
        published for it, so records the sweep split across lanes are never merged. A record whose group is not
        decidable, or that the sweep put in no group, is not placed (the caller judges it as before)."""
        from dataclasses import replace
        rule = self._rule(playbook.id)
        citing = self._sweep_citing(playbook.id, swept)
        by_id = {event.id: event for event in events}
        missing = getattr(rule, "lineage_missing", None)
        placed: dict[tuple[str, bool], tuple[dict, list]] = {}
        folded: set[str] = set()
        for match in rule.match_each(events, swept):
            subject = [event.id for event in match.events if event.id not in match.context_ids]
            groups = {citing[event_id]["id"]: citing[event_id] for event_id in subject if event_id in citing}
            if len(groups) == 1 and len(subject) == sum(event_id in citing for event_id in subject):
                group = next(iter(groups.values()))
                # The sweep's lane stands unless this reach's own judgment is higher for a reason other than a
                # lineage it does not hold (a record it holds and the sweep did not, such as a script rewrite).
                defer = (not self._higher(match, group)
                         or (missing is not None
                             and any(missing(by_id[event_id]) for event_id in subject if event_id in by_id)))
                placed.setdefault((group["id"], defer), (group, []))[1].append(match)
                folded.update(subject)
        out = []
        for (_group_id, defer), (group, matches) in placed.items():
            matches.sort(key=lambda match: (match.ts, match.events[0].id))
            records = list({event.id: event for match in matches for event in match.events
                            if event.id not in match.context_ids}.values())
            first, last = matches[0], matches[-1]
            base = first if defer else min(matches, key=lambda match: LANE_ORDER.get(match.proposed_lane, 9))
            out.append((group, defer, replace(
                base, events=records, context_ids=set(),
                predicate=[p for match in matches for p in match.predicate],
                raw_copies={key: value for match in matches for key, value in match.raw_copies.items()},
                aggregate_summary={"count": len(records), "peak": len(records), "episodes": 1,
                                   "first": first.ts.timestamp(), "last": last.ts.timestamp()})))
        return out, folded

    def _higher(self, match, group: dict) -> bool:
        """Whether a match's own decided lane is above the lane of the sweep's group."""
        from romulus.decide.policy import decide
        return LANE_ORDER.get(decide(match, self.hunt_id).lane, 9) < LANE_ORDER.get(group["lane"], 9)

    def _cells(self, rule_id: str) -> dict[str, list[tuple[datetime, datetime, bool]]]:
        """The rule's sweep partition cells per target, ordered by start, as (start, end, complete). Split, window and
        link cells are not partitions a record was read in. Held for SWEPT_RULES_HELD rules (the least recently used
        is dropped and read again when needed)."""
        cells = self._swept_cells.get(rule_id)
        if cells is None:
            cells = defaultdict(list)
            for row in self.repo.rule_cells(self.hunt_id, rule_id=rule_id):
                span = _cell_span(row["partition"]) if row["state"] != "split" else None
                target = str(row["target"])
                if span is not None and target != "*" and ":" not in target.split(",")[0]:
                    cells[target].append((span[0], span[1], row["state"] in SWEPT_COMPLETE))
            cells = {target: sorted(rows) for target, rows in cells.items()}
            self._swept_cells[rule_id] = cells
            while len(self._swept_cells) > SWEPT_RULES_HELD:
                self._swept_cells.popitem(last=False)
        else:
            self._swept_cells.move_to_end(rule_id)
        return cells

    def _swept_ids(self, playbook, events: list[TypedEvent]) -> set[str]:
        """The records of this link the sweep is proven to have judged for this rule: each of its raw records was read
        from a sweep target, in a partition whose cell for the rule is complete (no covering cell partial), and was
        stored in this hunt by a sweep task. Bounded by the link's own records."""
        from bisect import bisect_right
        own = set(playbook.families) - set(playbook.context_families)
        candidates = [event for event in events if event.family in own and event.raw]
        if not candidates:
            return set()
        cells = self._cells(playbook.id)
        out = set()
        for event in candidates:
            ts = _utc(event.ts)
            covering = []
            for ref in event.raw:
                found = []
                for target, rows in cells.items():
                    if not _target_names(target, ref.target):
                        continue
                    # leaf partitions of a target do not overlap: the one starting last at or before ts
                    at = bisect_right(rows, (ts, datetime.max.replace(tzinfo=UTC), True)) - 1
                    if at >= 0 and rows[at][0] <= ts < rows[at][1]:
                        found.append(rows[at][2])
                covering.append(bool(found) and all(found))
            if covering and all(covering):
                out.add(event.id)
        proven = self._stored_by_sweep([event for event in candidates if event.id in out])
        # A complete cell does not prove its records were read: a record ingested after the sweep read the partition
        # sits inside it unseen. Only a record the sweep itself stored is known to have been judged by it.
        self.unproven_swept += len(out) - len(proven)
        return proven

    def _stored_by_sweep(self, events: list[TypedEvent]) -> set[str]:
        """The records whose every raw copy was first stored in this hunt by a sweep task (a sweep stores the records
        its findings cite, not every record it reads)."""
        from romulus.store.repo import raw_id
        wanted = {raw_id(ref.target, ref.native_id) for event in events for ref in event.raw}
        first_task: dict[str, str | None] = {}
        ordered = sorted(wanted)
        for start in range(0, len(ordered), 500):
            for row in self.repo.raw_records(ordered[start:start + 500]):
                first_task[row["id"]] = row.get("first_task_id")
        out = set()
        for event in events:
            tasks = [first_task.get(raw_id(ref.target, ref.native_id)) for ref in event.raw]
            if tasks and all(task is not None and self._sweep_task(task) for task in tasks):
                out.add(event.id)
        return out

    def _sweep_task(self, task_id: str) -> bool:
        """Whether a task is one of this hunt's sweep partition reads (held for SWEEP_TASKS_HELD task ids)."""
        known = self._sweep_tasks.get(task_id)
        if known is None:
            row = self.repo.task(task_id)
            known = bool(row) and row["kind"] == "sweep" and row["hunt_id"] == self.hunt_id
            self._sweep_tasks[task_id] = known
            while len(self._sweep_tasks) > SWEEP_TASKS_HELD:
                self._sweep_tasks.popitem(last=False)
        else:
            self._sweep_tasks.move_to_end(task_id)
        return known

    def _sweep_group(self, playbook, match) -> dict | None:
        """The candidate the sweep published under this match's own group (or, without a group key, for its exact
        records); None when the sweep published none, so the match is published as before."""
        from romulus.decide.policy import candidate_group_id, candidate_id
        cid = (candidate_group_id(playbook.id, match.group_key, self.hunt_id) if match.group_key
               else candidate_id(match, self.hunt_id))
        row = self.repo.candidate(cid)
        if (row is None or row.get("source_case_id") is not None or row.get("source_anchor_id") is not None
                or row["lane"] == "context"):
            return None
        return row

    def _sweep_citing(self, rule_id: str, ids: set[str]) -> dict[str, dict]:
        """record id -> the one sweep-published candidate of this rule that cites it, for the given records (a record
        two of them cite is left out: its group is not decidable). A read-only scan of the rule's sweep candidates
        that keeps only the wanted records."""
        from sqlalchemy import select

        from romulus.store import schema as tables
        if not ids:
            return {}
        query = select(tables.candidate.c.id, tables.candidate.c.event_ids).where(
            tables.candidate.c.hunt_id == self.hunt_id, tables.candidate.c.rule_id == rule_id,
            tables.candidate.c.source_case_id.is_(None), tables.candidate.c.source_anchor_id.is_(None),
            tables.candidate.c.lane != "context")
        owners: dict[str, set[str]] = defaultdict(set)
        with self.repo.engine.connect() as connection:
            for candidate_id, event_ids in connection.execute(query):
                for event_id in set(event_ids or ()) & ids:
                    owners[event_id].add(candidate_id)
        rows: dict[str, dict] = {}
        out = {}
        for event_id, candidates in owners.items():
            if len(candidates) != 1:
                continue
            cid = next(iter(candidates))
            if cid not in rows:
                rows[cid] = self.repo.candidate(cid)
            if rows[cid] is not None:
                out[event_id] = rows[cid]
        return out

    def _budget_reason(self, query_count: int) -> str | None:
        if query_count >= self.budget:
            return "source query budget exhausted"
        if self.clock() - self.started >= self.wall_clock_seconds:
            return "expansion wall-clock budget exhausted"
        return None

    def run(self) -> dict:
        self._prepare_extra_seeds()
        self._seed_anchors()
        all_rows = self.repo.expansion_anchors(self.hunt_id)
        query_count = self.repo.expansion_source_queries(self.hunt_id)
        executor = getattr(self.fetcher, "executor", None)
        if executor is not None and hasattr(executor, "source_queries"):
            executor.source_queries = query_count
        anchor_reasons: dict[str, list[str]] = defaultdict(list)
        # One existing blocked-anchor entry also records the typed cause; diagnostic text is never a cause.
        blocked_anchors: dict[str, bool] = {}
        stop_reason = "fixpoint"
        source_failed = False
        # anchor id -> (the query limit it was stopped under, the reasons that stop added). The limit grows when the
        # reserve is released or a discovered anchor brings its share; the anchor then spends again.
        budget_blocked: dict[str, tuple[int, list[str]]] = {}
        while True:
            self.budget = self._budget_for(all_rows)
            eligible = []
            for row in all_rows:
                if row["status"] != "pending" or row["id"] in blocked_anchors:
                    continue
                if not self._extras_open and self._is_extra(row):
                    continue        # an extra seed anchored by an earlier run waits for the rule estimate's anchors
                if row["depth"] >= self.max_depth:
                    reason = f"maximum expansion depth {self.max_depth} reached"
                    anchor_reasons[row["id"]].append(reason)
                    blocked_anchors[row['id']] = False
                    stop_reason = "depth_limit"
                    continue
                plan = self._anchor_plan(row)
                candidate_ts = _utc(plan.candidate["ts"])
                if not (_utc(self.window.start) <= candidate_ts < _utc(self.window.end)):
                    self._add_reason(anchor_reasons, row["id"], "anchor outside the hunt window")
                    blocked_anchors[row['id']] = False
                    continue
                eligible.append(row)
            # Always choose the globally lowest unfinished tier, so every anchor, and a newly discovered one, gets its
            # narrow links before any anchor widens its window. Within the tier the most severe lane goes first, so
            # when the budget runs out inside a tier it is the less severe anchors' links that wait.
            ranks = sorted({LANE_ORDER.get(row["lane"], 9) for row in eligible})
            ordered = [anchor_row for rank in ranks
                       for anchor_row in self._ordered_anchors(
                           [row for row in eligible if LANE_ORDER.get(row["lane"], 9) == rank])]
            if not ranks:
                if self._anchor_extra_seeds(query_count, all_rows, blocked_anchors):
                    all_rows = self.repo.expansion_anchors(self.hunt_id)
                    continue
                break               # every pending anchor is stopped, and only a newly found anchor grows the budget
            root_cap = self._root_cap(all_rows, blocked_anchors, ranks[0])
            depths = {row["id"]: row["depth"] for row in all_rows}
            released = False
            for anchor_id, (limit, added) in list(budget_blocked.items()):
                if (root_cap if depths[anchor_id] == 0 else self.budget) > limit:
                    del budget_blocked[anchor_id]
                    blocked_anchors.pop(anchor_id, None)
                    for reason in added:
                        anchor_reasons[anchor_id].remove(reason)
                    released = True
            if released:
                continue
            slots = self._tier_slots(ordered, anchor_reasons, root_cap)
            if not slots:
                if self._anchor_extra_seeds(query_count, all_rows, blocked_anchors):
                    all_rows = self.repo.expansion_anchors(self.hunt_id)
                    continue
                break
            spent = getattr(getattr(self.fetcher, "executor", None), "source_queries", None)
            if isinstance(spent, int):
                query_count = max(query_count, spent)
            made_progress = False
            known_anchor_ids = {row["id"] for row in all_rows}
            groups_after = _slot_groups_after(slots)
            for slot_index, slot in enumerate(slots):
                anchor_row, candidate, anchor = slot.row, slot.candidate, slot.anchor
                link_type, window, stored = slot.link_type, slot.window, slot.stored
                if stored:
                    budget_reason = None
                else:
                    budget_reason = self._budget_reason(query_count)
                if budget_reason:
                    stop_reason = "budget"
                    added = [budget_reason]
                    if budget_reason == "source query budget exhausted" and any(
                            LANE_ORDER.get(row["lane"], 9) < LANE_ORDER.get(anchor_row["lane"], 9)
                            for row in all_rows):
                        added.append(BUDGET_TO_SEVERE_REASON)
                    anchor_reasons[anchor_row["id"]].extend(added)
                    if budget_reason == "source query budget exhausted":
                        budget_blocked[anchor_row["id"]] = (self.budget, added)
                    blocked_anchors[anchor_row['id']] = True
                    continue
                allowed_budget = root_cap if anchor_row["depth"] == 0 and not stored else self.budget
                remaining = allowed_budget - query_count
                # Every physical fetch is budgeted for at least two queries (a Zeek join, which opens its own point
                # in time, for three). Do not let that floor cross the root-anchor reserve or the global cap.
                floor = ZEEK_FETCH_QUERIES if link_type in ZEEK_LINK_TYPES else 2
                if not stored and remaining < floor:
                    stop_reason = "budget"
                    reason = (RESERVED_REASON if anchor_row["depth"] == 0 and root_cap < self.budget
                              else "source query budget exhausted")
                    budget_blocked[anchor_row["id"]] = (allowed_budget, [reason])
                    anchor_reasons[anchor_row["id"]].append(reason)
                    blocked_anchors[anchor_row['id']] = True
                    continue
                query_cap = min(12, max(floor, remaining // max(1, groups_after[slot_index])))
                self.heartbeat()
                if link_type in ZEEK_LINK_TYPES:
                    self.fetcher.executor.zeek_deadline = (self.started + self.wall_clock_seconds, self.clock)
                result = self._stored_result(stored) if stored else self.fetcher.fetch(
                    anchor, link_type, window, query_cap=query_cap,
                )
                if not stored:
                    self._persist_link(result)
                    actual_queries = getattr(getattr(self.fetcher, "executor", None), "source_queries", None)
                    query_count = (actual_queries if actual_queries is not None
                                   else query_count + result.query_spend)
                self._query_count = query_count
                published = self._evaluate(candidate, result)
                spent, self._lineage_spend = self._lineage_spend, 0
                if spent:
                    # reader-lineage lookups made while judging the link spend the same source-query budget
                    actual_queries = getattr(getattr(self.fetcher, "executor", None), "source_queries", None)
                    query_count = actual_queries if actual_queries is not None else query_count + spent
                slot.done, slot.stored = True, None
                made_progress = True
                if result.status != "complete":
                    anchor_reasons[anchor_row["id"]].extend(
                        result.reasons or [f"{link_type} {result.status}"],
                    )
                if result.status == "failed":
                    stop_reason = "source_failure"
                    source_failed = True
                if self.after_link:
                    self.after_link(result)
                    added = self._seed_anchors()
                elif published:
                    # Direct discoveries are the only production source of anchors during expansion. Seed just
                    # those rows; the optional callback is a test/integration hook and uses the full scan above.
                    current = [*all_rows]
                    added = []
                    for published_row in published:
                        stored_candidate = self.repo.candidate(published_row["id"])
                        if stored_candidate is not None:
                            newly_added = self._seed_candidates([stored_candidate], current)
                            current.extend(newly_added)
                            added.extend(newly_added)
                else:
                    added = []
                if added:
                    all_rows = self.repo.expansion_anchors(self.hunt_id)
                if {row["id"] for row in added} - known_anchor_ids:
                    break
            if not made_progress:
                continue

        final_links = [
            link for link in self.repo.expansion_links(self.hunt_id)
            if not is_agent_reach(link["link_type"], link["strength"])
        ]
        imported_consumers = self.repo.expansion_rule_consumers(
            self.hunt_id, self._imported_rule_ids) if self._imported_rule_ids else 0
        for row in self.repo.expansion_anchors(self.hunt_id):
            # Only anchors this run worked are finalized: those still pending. An anchor a previous run finalized
            # (resume re-runs expansion) was never scheduled here, so its recorded status and reasons stand; above
            # all, an unexpanded or partial anchor is never upgraded to complete. Budget-stopped anchors are left
            # as recorded rather than re-attempted: the source-query and wall-clock budgets are hunt-wide and
            # persist across a resume, so the budget that stopped them is still spent.
            if row["status"] != "pending":
                continue
            links = [link for link in final_links if link["anchor_id"] == row["id"]]
            reasons = sorted(set(anchor_reasons[row["id"]] + [
                reason for link in links if link["status"] != "complete"
                for reason in (link["reasons"] or [f"{link['link_type']} {link['status']}"])
            ]))
            if imported_consumers and not self._is_imported(row) and blocked_anchors.get(row['id'], False):
                reasons.append(f'budget spent on {imported_consumers} imported-rule anchors')
            if row["id"] in blocked_anchors:
                status = "expanded_partial" if links else "unexpanded"
            else:
                status = "expanded_partial" if reasons else "expanded_complete"
            self.repo.update_expansion_anchor(row["id"], status, reasons, owner_token=self.owner_token)
        # One deterministic context pass over every evaluated link, whatever the stop reason, and again on a
        # resumed run (this call re-runs it over all links, which is idempotent).
        finalize_context(self.repo, self.hunt_id, owner_token=self.owner_token)
        anchors = self.repo.expansion_anchors(self.hunt_id)
        if source_failed and stop_reason != "source_failure":
            stop_reason = f"{stop_reason}; source_failure"
        status = ("completed" if not source_failed and stop_reason in {"fixpoint", "depth_limit", "budget"}
                  else "partial")
        # Expansion is complete only when every anchor is, whichever run recorded it. Status and stop reason
        # come from the anchor rows, so a resumed run that reached a fixpoint over its own work still reports the
        # anchors an earlier run left unexpanded or partial, and why.
        unfinished = [row for row in anchors if row["status"] in {"unexpanded", "expanded_partial"}]
        if unfinished:
            status = "partial"
            kinds = sorted({"keys not expanded" if reason.startswith("keys_not_expanded:") else reason
                            for row in unfinished for reason in row["reasons"]})
            shown = "; ".join(kinds[:5]) + (f"; +{len(kinds) - 5} more" if len(kinds) > 5 else "")
            unexpanded_count = sum(row["status"] == "unexpanded" for row in unfinished)
            accounting = (f"anchors not fully expanded: {unexpanded_count} unexpanded, "
                          f"{len(unfinished) - unexpanded_count} partial" + (f" ({shown})" if shown else ""))
            stop_reason = accounting if stop_reason == "fixpoint" else f"{stop_reason}; {accounting}"
        not_anchored = self._extras_not_anchored()
        if not_anchored:
            stop_reason = f"{stop_reason}; {not_anchored} {self._extras_stopped}"
        summary = {
            "status": status,
            "stop_reason": stop_reason, "anchors": len(anchors),
            "expanded_complete": sum(row["status"] == "expanded_complete" for row in anchors),
            "expanded_partial": sum(row["status"] == "expanded_partial" for row in anchors),
            "unexpanded": [row["id"] for row in anchors if row["status"] == "unexpanded"],
            "source_queries": query_count,
            **({"reported_seeds_not_anchored": {"count": not_anchored, "reason": self._extras_stopped}}
               if not_anchored else {}),
            # the budget the expansion ran under, so a reader can tell a cut by the ceiling from one by the shares
            "budget": {
                "per_anchor_source_queries": self.per_anchor_source_queries,
                "max_source_queries": self.max_source_queries,
                "source_query_budget": self._budget_for(anchors),
                "ceiling_reached": self._budget_for(anchors) >= self.max_source_queries,
            },
        }
        self.repo.audit("system", "hunt.expansion_summary", self.hunt_id, summary,
                        owner_token=self.owner_token)
        return summary
