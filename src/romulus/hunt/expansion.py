"""Crash-safe deterministic post-sweep expansion over typed links."""
from __future__ import annotations

import ipaddress
import json
import time
from collections import defaultdict, deque
from collections.abc import Callable
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from datetime import UTC, datetime, timedelta

from romulus.agent.models import PivotCoverage
from romulus.decide.policy import LANE_ORDER
from romulus.detect import netdef
from romulus.detect.correlation import routable_remote
from romulus.detect.host import is_internal
from romulus.detect.netdef import DIRECTION_ASSUMED_REASON
from romulus.detect.registry import fresh_direct_pack, rule_kind
from romulus.evidence.typed import TypedEvent
from romulus.hunt.context import finalize_context
from romulus.hunt.expansion_plan import TIER_PLAN
from romulus.hunt.links import (
    HOST_SIDE_LINKS,
    LinkAnchor,
    LinkFetcher,
    LinkResult,
    LinkType,
    LinkWindow,
    is_agent_reach,
    usable_key,
)
from romulus.hunt.pivot import HOST_AMBIGUOUS, HOST_LOOKUP_BUDGET, NO_HOST_RECORD
from romulus.hunt.publish import mark_hypothesis_relation, publish_match
from romulus.hunt.sweep import stored_boot_intervals
from romulus.sources.models import Window
from romulus.store.db import digest
from romulus.store.repo import Repo

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
DEFAULT_MAX_DEPTH = 3
DEFAULT_MAX_SOURCE_QUERIES = 180
MAX_ANCHOR_KEYS = 8
# The source queries each anchor brings to the expansion budget: every link of its plan fetched twice at the
# two-query floor of a physical fetch. The budget is shared, so an anchor with several keys draws on what one with
# fewer did not use.
PER_ANCHOR_SOURCE_QUERIES = 4 * sum(len(link_types) for _tier, link_types, _label in TIER_PLAN)
NETWORK_FAMILIES = {"net_alert", "net_flow", "net_session", "dns_query", "http_tx",
                    "file_transfer", "tls_session", "ssh_session"}


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


def fallback_lookup_cap(max_source_queries: int) -> int:
    """Source queries all fallback lookups of a hunt may spend: FALLBACK_LOOKUP_SHARE of the budget, at least 1."""
    return max(1, int(max_source_queries * FALLBACK_LOOKUP_SHARE))


@dataclass
class _LinkPlan:
    variants: list[LinkAnchor]
    planned_query_cap: int
    planned_budget: int
    retryable: bool
    generation: int = 0
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
        # Planning inputs live only for this run. Candidate citations are already bounded by the detector citation
        # limits; variants share those event objects, so this is O(anchors * cited records), not O(link slots).
        self._plans: dict[str, _AnchorPlan] = {}

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
            for task in self.repo.host_resolution_tasks(self.hunt_id):
                ip = (task.get("intent") or {}).get("resolve_host_ip")
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
    def _link_anchors(anchor: LinkAnchor, link_type: LinkType) -> tuple[list[LinkAnchor], list[dict]]:
        keyed: dict[str, tuple[dict, TypedEvent]] = {}
        for event in anchor.events:
            key: dict | None = None
            if link_type == "process_lineage" and usable_key(event.get("process.pid")):
                key = {"process.pid": event.get("process.pid")}
            elif link_type == "login_session" and usable_key(event.get("process.session_id")):
                key = {
                    "process.session_id": event.get("process.session_id"),
                    "process.auid": event.get("process.auid") if usable_key(event.get("process.auid")) else None,
                }
            elif link_type in {"network_flow", "flow_host_side"}:
                community_id = event.get("network.community_id")
                flow_tuple = [event.get(field) for field in (
                    "network.transport", "source.ip", "source.port",
                    "destination.ip", "destination.port",
                )]
                if usable_key(community_id):
                    key = {"network.community_id": community_id}
                elif all(usable_key(value) for value in flow_tuple):
                    key = {"five_tuple": flow_tuple}
            elif link_type == "source_ip" and usable_key(event.get("source.ip")):
                key = {"source.ip": event.get("source.ip")}
            elif link_type == "account":
                if usable_key(event.get("user.name")):
                    key = {"user.name": event.get("user.name")}
                elif usable_key(event.get("process.auid")):
                    key = {"process.auid": event.get("process.auid")}
            if key is not None:
                keyed.setdefault(json.dumps(key, sort_keys=True, separators=(",", ":")), (key, event))
        if not keyed:
            return [anchor], []
        ordered = [keyed[token] for token in sorted(keyed)]
        kept, dropped = ordered[:MAX_ANCHOR_KEYS], ordered[MAX_ANCHOR_KEYS:]
        variants = [anchor.model_copy(update={"events": [event]}) for _key, event in kept]
        return variants, [key for key, _event in dropped]

    def _anchor_plan(self, row: dict, *, candidate: dict | None = None,
                     events: list[TypedEvent] | None = None) -> _AnchorPlan:
        plan = self._plans.get(row["id"])
        if plan is not None:
            return plan
        candidate = candidate or self.repo.candidate(row["candidate_id"])
        events = events if events is not None else self._events(candidate["event_ids"])
        candidate_ts = _utc(candidate["ts"])
        plan = _AnchorPlan(
            row=row, candidate=candidate, events=events,
            anchor=LinkAnchor(
                finding_id=candidate["id"], ts=candidate_ts, host=row["host"],
                event_ids=candidate["event_ids"], events=events,
            ),
            windows={window.label: window for window in expansion_windows(candidate_ts, self.window)},
        )
        self._plans[row["id"]] = plan
        return plan

    def _seed_candidates(self, candidates: list[dict], existing_rows: list[dict]) -> list[dict]:
        existing = {row["candidate_id"] for row in existing_rows}
        depths = {row["id"]: row["depth"] for row in existing_rows}
        added = []
        for candidate in candidates:
            if candidate["id"] in existing or candidate["lane"] not in {"urgent", "high"}:
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
            events = self._events(candidate["event_ids"])
            host = self._anchor_host(events)
            row = {
                "id": candidate["id"], "hunt_id": self.hunt_id, "candidate_id": candidate["id"],
                "depth": depth, "parent_anchor_id": parent, "host": host, "lane": candidate["lane"],
                "severity": candidate["severity"], "ts": candidate["ts"], "status": "pending", "reasons": [],
            }
            if not self.repo.save_expansion_anchor(row, owner_token=self.owner_token):
                continue
            existing.add(candidate["id"])
            depths[candidate["id"]] = depth
            added.append(row)
            self._anchor_plan(row, candidate=candidate, events=events)
        return added

    def _seed_anchors(self) -> list[dict]:
        rows = self.repo.expansion_anchors(self.hunt_id)
        return self._seed_candidates(self.repo.candidates(self.hunt_id, ["urgent", "high"]), rows)

    def _identity(self, row: dict) -> str:
        """The anchor's rule and evidence, which are the same in every hunt over the same records. A candidate id also
        carries its hunt's id, so ordering ties by it would give two runs of one hunt different anchor orders, and a
        budget cut inside a tier would then fall on different links."""
        if row["id"] not in self._identities:
            plan = self._plans.get(row["id"])
            candidate = plan.candidate if plan is not None else self.repo.candidate(row["candidate_id"])
            self._identities[row["id"]] = digest({
                "rule_id": candidate["rule_id"],
                "evidence": candidate.get("group_key") or sorted(candidate["event_ids"]),
            })
        return self._identities[row["id"]]

    def _anchor_priority(self, row: dict) -> tuple:
        return (
            LANE_ORDER.get(row["lane"], 9), SEVERITY_ORDER.get(row["severity"], 9),
            _utc(row["ts"]), self._identity(row), row["id"],
        )

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
        return ordered

    def _budget_for(self, all_rows: list[dict]) -> int:
        """The source queries the expansion may have spent by now: its fixed total, or one share for every anchor that
        can still be expanded (roots and discovered anchors alike, whichever run recorded them), up to the ceiling."""
        if self.per_anchor_source_queries is None:
            return self.max_source_queries
        expandable = sum(1 for row in all_rows if row["depth"] < self.max_depth)
        return min(self.max_source_queries, self.per_anchor_source_queries * expandable)

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
        if cached is not None and not (
            cached.retryable
            and (query_cap > cached.planned_query_cap or self.budget > cached.planned_budget)
        ):
            return cached

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
            self._add_reason(
                anchor_reasons, plan.row["id"],
                "keys_not_expanded:" + json.dumps(dropped, sort_keys=True, separators=(",", ":")),
            )
        planned = _LinkPlan(
            variants=variants, planned_query_cap=query_cap, planned_budget=self.budget,
            retryable=self._retryable_victim_plan(variants, notes),
            generation=(cached.generation + 1 if cached is not None else 0),
        )
        plan.links[link_type] = planned
        return planned

    def _planned_slots(self, plan: _AnchorPlan, link_type: LinkType, window_label: str,
                       anchor_reasons: dict[str, list[str]], root_cap: int) -> list[_PlannedSlot]:
        link_plan = self._link_plan(plan, link_type, anchor_reasons, root_cap)
        cached = link_plan.slots.get(window_label)
        if cached is not None:
            return cached
        window = plan.windows[window_label]
        slots = []
        for variant in link_plan.variants:
            if hasattr(self.fetcher, "result_id"):
                stored = self.repo.expansion_link(self.fetcher.result_id(variant, link_type, window))
            else:
                stored = self.repo.expansion_link_for(
                    plan.candidate["id"], link_type, window.label, window.start, window.end,
                )
            slots.append(_PlannedSlot(
                row=plan.row, candidate=plan.candidate, anchor=variant, link_type=link_type,
                window=window, stored=stored, done=bool(stored and stored["evaluated"]),
            ))
        link_plan.slots[window_label] = slots
        return slots

    def _tier_slots(self, ordered: list[dict], anchor_reasons: dict[str, list[str]],
                    root_cap: int) -> list[_PlannedSlot]:
        """The unevaluated slots of the lowest unfinished tier, assembled from per-anchor plans."""
        for _tier, link_types, window_label in TIER_PLAN:
            tier_slots = []
            for link_type in link_types:
                for anchor_row in ordered:
                    plan = self._anchor_plan(anchor_row)
                    tier_slots.extend(
                        slot for slot in self._planned_slots(
                            plan, link_type, window_label, anchor_reasons, root_cap,
                        ) if not slot.done
                    )
            if tier_slots:
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
        }, owner_token=self.owner_token)

    def _evaluate(self, candidate: dict, result: LinkResult) -> list[dict]:
        # Per link, only the direct (sweep) pack runs: a strong indicator among the linked records is published
        # immediately. Context rules are judged once, after expansion ends, by finalize_context.
        events = self._events(result.event_ids)
        published = []
        for playbook in fresh_direct_pack():
            for match in playbook.consume(events):
                # The finding stands on its own cited records and keeps its machine lane. Only its relation to
                # the anchor may be a hypothesis.
                mark_hypothesis_relation(
                    match, anchor_id=candidate["id"], link_type=result.link_type,
                    link_id=result.id, strength=result.strength,
                )
                row = publish_match(
                    self.repo, self.hunt_id, playbook, match, result.task_ids[0] if result.task_ids else None, {},
                    source_anchor_id=candidate["id"], source_link_id=result.id, owner_token=self.owner_token,
                )
                if row is not None:
                    published.append(row)
        self.repo.mark_expansion_link_evaluated(result.id, owner_token=self.owner_token)
        return published

    def _budget_reason(self, query_count: int) -> str | None:
        if query_count >= self.budget:
            return "source query budget exhausted"
        if self.clock() - self.started >= self.wall_clock_seconds:
            return "expansion wall-clock budget exhausted"
        return None

    def run(self) -> dict:
        self._seed_anchors()
        all_rows = self.repo.expansion_anchors(self.hunt_id)
        query_count = self.repo.expansion_source_queries(self.hunt_id)
        executor = getattr(self.fetcher, "executor", None)
        if executor is not None and hasattr(executor, "source_queries"):
            executor.source_queries = query_count
        anchor_reasons: dict[str, list[str]] = defaultdict(list)
        blocked_anchors: set[str] = set()
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
                if row["depth"] >= self.max_depth:
                    reason = f"maximum expansion depth {self.max_depth} reached"
                    anchor_reasons[row["id"]].append(reason)
                    blocked_anchors.add(row["id"])
                    stop_reason = "depth_limit"
                    continue
                plan = self._anchor_plan(row)
                candidate_ts = _utc(plan.candidate["ts"])
                if not (_utc(self.window.start) <= candidate_ts < _utc(self.window.end)):
                    self._add_reason(anchor_reasons, row["id"], "anchor outside the hunt window")
                    blocked_anchors.add(row["id"])
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
                break               # every pending anchor is stopped, and only a newly found anchor grows the budget
            root_cap = self._root_cap(all_rows, blocked_anchors, ranks[0])
            depths = {row["id"]: row["depth"] for row in all_rows}
            released = False
            for anchor_id, (limit, added) in list(budget_blocked.items()):
                if (root_cap if depths[anchor_id] == 0 else self.budget) > limit:
                    del budget_blocked[anchor_id]
                    blocked_anchors.discard(anchor_id)
                    for reason in added:
                        anchor_reasons[anchor_id].remove(reason)
                    released = True
            if released:
                continue
            slots = self._tier_slots(ordered, anchor_reasons, root_cap)
            if not slots:
                break
            spent = getattr(getattr(self.fetcher, "executor", None), "source_queries", None)
            if isinstance(spent, int):
                query_count = max(query_count, spent)
            made_progress = False
            known_anchor_ids = {row["id"] for row in all_rows}
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
                    blocked_anchors.add(anchor_row["id"])
                    continue
                allowed_budget = root_cap if anchor_row["depth"] == 0 and not stored else self.budget
                remaining = allowed_budget - query_count
                # Every physical fetch is budgeted for at least two queries. Do not
                # let that floor cross the root-anchor reserve or the global cap.
                if not stored and remaining < 2:
                    stop_reason = "budget"
                    reason = (RESERVED_REASON if anchor_row["depth"] == 0 and root_cap < self.budget
                              else "source query budget exhausted")
                    budget_blocked[anchor_row["id"]] = (allowed_budget, [reason])
                    anchor_reasons[anchor_row["id"]].append(reason)
                    blocked_anchors.add(anchor_row["id"])
                    continue
                remaining_slots = len(slots) - slot_index
                query_cap = min(12, max(2, remaining // max(1, remaining_slots)))
                self.heartbeat()
                result = self._stored_result(stored) if stored else self.fetcher.fetch(
                    anchor, link_type, window, query_cap=query_cap,
                )
                if not stored:
                    self._persist_link(result)
                    actual_queries = getattr(getattr(self.fetcher, "executor", None), "source_queries", None)
                    query_count = (actual_queries if actual_queries is not None
                                   else query_count + result.query_spend)
                published = self._evaluate(candidate, result)
                slot.done = True
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
        summary = {
            "status": status,
            "stop_reason": stop_reason, "anchors": len(anchors),
            "expanded_complete": sum(row["status"] == "expanded_complete" for row in anchors),
            "expanded_partial": sum(row["status"] == "expanded_partial" for row in anchors),
            "unexpanded": [row["id"] for row in anchors if row["status"] == "unexpanded"],
            "source_queries": query_count,
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
