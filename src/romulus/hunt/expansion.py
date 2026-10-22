"""Crash-safe deterministic post-sweep expansion over typed links."""
from __future__ import annotations

import ipaddress
import json
import time
from collections import defaultdict, deque
from collections.abc import Callable
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
from romulus.hunt.links import (
    HOST_SIDE_LINKS,
    LinkAnchor,
    LinkFetcher,
    LinkResult,
    LinkType,
    LinkWindow,
    usable_key,
)
from romulus.hunt.pivot import HOST_AMBIGUOUS, NO_HOST_RECORD
from romulus.hunt.publish import publish_match
from romulus.hunt.sweep import stored_boot_intervals
from romulus.sources.models import Window
from romulus.store.repo import Repo

TIER_PLAN: tuple[tuple[str, tuple[LinkType, ...], str], ...] = (
    ("T1", ("login_session", "process_lineage", "network_flow"), "anchor ±5 min"),
    ("T2", ("host_after_anchor", "flow_host_side"), "anchor ±5 min"),
    ("T3", ("login_session", "process_lineage", "network_flow", "host_after_anchor",
            "flow_host_side"), "anchor ±30 min"),
    ("T4", ("source_ip", "account"), "anchor ±5 min"),
    ("T5", ("login_session", "process_lineage", "network_flow", "host_after_anchor",
            "flow_host_side", "source_ip", "account"), "anchor ±2 h"),
)
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
DEFAULT_MAX_DEPTH = 3
DEFAULT_MAX_SOURCE_QUERIES = 180
MAX_ANCHOR_KEYS = 8
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

class ExpansionEngine:
    def __init__(
        self, repo: Repo, hunt_id: str, hunt_window: Window, fetcher: LinkFetcher,
        *, max_depth: int = DEFAULT_MAX_DEPTH,
        max_source_queries: int = DEFAULT_MAX_SOURCE_QUERIES,
        wall_clock_seconds: float = 7200,
        owner_token: str | None = None,
        clock: Callable[[], float] = time.monotonic,
        heartbeat: Callable[[], None] = lambda: None,
        after_link: Callable[[LinkResult], None] | None = None,
    ):
        self.repo, self.hunt_id, self.window, self.fetcher = repo, hunt_id, hunt_window, fetcher
        self.max_depth, self.max_source_queries = max_depth, max_source_queries
        self.wall_clock_seconds, self.owner_token = wall_clock_seconds, owner_token
        self.clock, self.heartbeat, self.after_link = clock, heartbeat, after_link
        self.started = clock()
        # The sweep's boot-interval map (recorded with the hunt, so a resumed run uses the same one), shared with
        # the fetcher unless it was given its own.
        given = getattr(fetcher, "boots", None)
        self.boots = given if given else stored_boot_intervals(repo, hunt_id)
        if given is not None and not given:
            fetcher.boots = self.boots

    def _events(self, ids: list[str]) -> list[TypedEvent]:
        """Stored records, with the boot the hunt's map places them in when they carry none (a sweep record read
        near its partition's end, before later observations, may have been stored without one)."""
        rows = self.repo.events_by_ids(ids)
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
            host, reason = lookup(ip)
            if host is not None or (reason or "").startswith(HOST_AMBIGUOUS):
                victims.append((ip, host, reason))      # host records claim the address: it is the site's
            elif NO_HOST_RECORD not in (reason or ""):
                unresolved.append(reason or f"victim host unknown for {ip}")
        notes = ([f"endpoints outside the default internal ranges not resolved to a site host "
                  f"({'; '.join(unresolved)}); {DIRECTION_ASSUMED_REASON}"] if unresolved else [])
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

    def _seed_anchors(self) -> None:
        existing = {row["candidate_id"] for row in self.repo.expansion_anchors(self.hunt_id)}
        depths = {row["id"]: row["depth"] for row in self.repo.expansion_anchors(self.hunt_id)}
        for candidate in self.repo.candidates(self.hunt_id, ["urgent", "high"]):
            if candidate["id"] in existing:
                continue
            # A context finding is already the product of a link from an anchor; expanding it again would
            # refetch the same session or lineage at depth + 1 and drain the reserve.
            if rule_kind(candidate["rule_id"]) == "context":
                continue
            parent = candidate.get("source_anchor_id")
            depth = depths.get(parent, -1) + 1 if parent else 0
            events = self._events(candidate["event_ids"])
            host = self._anchor_host(events)
            self.repo.save_expansion_anchor({
                "id": candidate["id"], "hunt_id": self.hunt_id, "candidate_id": candidate["id"],
                "depth": depth, "parent_anchor_id": parent, "host": host, "lane": candidate["lane"],
                "severity": candidate["severity"], "ts": candidate["ts"], "status": "pending", "reasons": [],
            }, owner_token=self.owner_token)
            existing.add(candidate["id"])
            depths[candidate["id"]] = depth

    @staticmethod
    def _anchor_priority(row: dict) -> tuple:
        return (
            LANE_ORDER.get(row["lane"], 9), SEVERITY_ORDER.get(row["severity"], 9),
            _utc(row["ts"]), row["id"],
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

    def _evaluate(self, candidate: dict, anchor_events: list[TypedEvent], result: LinkResult) -> None:
        # Per link, only the direct (sweep) pack runs: a strong indicator among the linked records is published
        # immediately. Context rules are judged once, after expansion ends, by finalize_context.
        events = self._events(result.event_ids)
        for playbook in fresh_direct_pack():
            for match in playbook.consume(events):
                if result.strength == "inferred":
                    # The finding stands on its own cited records and keeps its own lane (strong indicators are
                    # reported on their own). Only its relation to the anchor is inferred.
                    match.claim += (f" Its relation to {candidate['id']} rests on inferred {result.link_type} link "
                                    f"{result.id} and is a hypothesis; the actor is not proven identical.")
                    match.notes.append("reached through an inferred expansion link: the relation to the anchor "
                                       "is a hypothesis, the finding itself is not")
                publish_match(
                    self.repo, self.hunt_id, playbook, match, result.task_ids[0] if result.task_ids else None, {},
                    source_anchor_id=candidate["id"], source_link_id=result.id, owner_token=self.owner_token,
                )
        self.repo.mark_expansion_link_evaluated(result.id, owner_token=self.owner_token)

    def _budget_reason(self, query_count: int) -> str | None:
        if query_count >= self.max_source_queries:
            return "source query budget exhausted"
        if self.clock() - self.started >= self.wall_clock_seconds:
            return "hunt wall-clock budget exhausted"
        return None

    def run(self) -> dict:
        self._seed_anchors()
        query_count = self.repo.expansion_source_queries(self.hunt_id)
        executor = getattr(self.fetcher, "executor", None)
        if executor is not None and hasattr(executor, "source_queries"):
            executor.source_queries = query_count
        anchor_reasons: dict[str, list[str]] = defaultdict(list)
        blocked_anchors: set[str] = set()
        root_budget = self.max_source_queries - max(1, (self.max_source_queries + 4) // 5)
        if self.max_source_queries == 0:
            root_budget = 0
        stop_reason = "fixpoint"
        source_failed = False
        reserve = self.max_source_queries - root_budget
        reserve_blocked: dict[str, int] = {}     # root anchor id -> the root cap it was blocked under
        while True:
            self._seed_anchors()
            all_rows = self.repo.expansion_anchors(self.hunt_id)
            # The reserve exists for anchors discovered by expansion. While none that can still expand is
            # waiting, half of it is released to root anchors, but only when the other half still covers one
            # fetch (two queries), so a discovered anchor is never starved.
            children_waiting = any(0 < row["depth"] < self.max_depth and row["status"] == "pending"
                                   and row["id"] not in blocked_anchors for row in all_rows)
            releasable = reserve // 2 if reserve - reserve // 2 >= 2 else 0
            root_cap = root_budget if children_waiting else root_budget + releasable
            for anchor_id, blocked_cap in list(reserve_blocked.items()):
                if root_cap > blocked_cap:       # the reserve was released since: the root may spend again
                    del reserve_blocked[anchor_id]
                    blocked_anchors.discard(anchor_id)
                    anchor_reasons[anchor_id] = [r for r in anchor_reasons[anchor_id] if r != RESERVED_REASON]
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
                eligible.append(row)
            ordered = self._ordered_anchors(eligible)
            slots = []
            # Always choose the globally lowest unfinished tier. A newly discovered
            # anchor therefore receives T1 before any surviving T2+ work continues.
            for _tier, link_types, window_label in TIER_PLAN:
                tier_slots = []
                for link_type in link_types:
                    for anchor_row in ordered:
                        candidate = self.repo.candidate(anchor_row["candidate_id"])
                        candidate_ts = _utc(candidate["ts"])
                        anchor_events = self._events(candidate["event_ids"])
                        base_anchor = LinkAnchor(
                            finding_id=candidate["id"], ts=candidate_ts, host=anchor_row["host"],
                            event_ids=candidate["event_ids"], events=anchor_events,
                        )
                        window = next(
                            item for item in expansion_windows(candidate_ts, self.window)
                            if item.label == window_label
                        )
                        variants, dropped = self._link_anchors(base_anchor, link_type)
                        if link_type in HOST_SIDE_LINKS and not base_anchor.host:
                            cap = root_cap if anchor_row["depth"] == 0 else self.max_source_queries
                            variants, dropped_ips, notes = self._victim_variants(
                                candidate["id"], variants, anchor_events, query_cap=cap)
                            anchor_reasons[anchor_row["id"]].extend(
                                note for note in notes if note not in anchor_reasons[anchor_row["id"]])
                            if dropped_ips:
                                anchor_reasons[anchor_row["id"]].append(
                                    "keys_not_expanded:" + json.dumps(
                                        [{"victim_ip": ip} for ip in dropped_ips],
                                        sort_keys=True, separators=(",", ":")))
                        if dropped:
                            anchor_reasons[anchor_row["id"]].append(
                                "keys_not_expanded:" + json.dumps(
                                    dropped, sort_keys=True, separators=(",", ":"),
                                ),
                            )
                        for variant in variants:
                            if hasattr(self.fetcher, "result_id"):
                                stored = self.repo.expansion_link(
                                    self.fetcher.result_id(variant, link_type, window),
                                )
                            else:
                                stored = self.repo.expansion_link_for(
                                    candidate["id"], link_type, window.label, window.start, window.end,
                                )
                            if not (stored and stored["evaluated"]):
                                tier_slots.append((
                                    anchor_row, candidate, variant, link_type, window, stored,
                                ))
                if tier_slots:
                    slots = tier_slots
                    break
            if not slots:
                break
            spent = getattr(getattr(self.fetcher, "executor", None), "source_queries", None)
            if isinstance(spent, int):
                query_count = max(query_count, spent)
            made_progress = False
            known_anchor_ids = {row["id"] for row in all_rows}
            for slot_index, (anchor_row, candidate, anchor, link_type, window, stored) in enumerate(slots):
                if stored:
                    budget_reason = None
                else:
                    budget_reason = self._budget_reason(query_count)
                if budget_reason:
                    stop_reason = "budget"
                    anchor_reasons[anchor_row["id"]].append(budget_reason)
                    blocked_anchors.add(anchor_row["id"])
                    continue
                if stored:
                    remaining = self.max_source_queries - query_count
                else:
                    allowed_budget = self.max_source_queries
                    if anchor_row["depth"] == 0:
                        allowed_budget = root_cap
                    remaining = allowed_budget - query_count
                # Every physical fetch is budgeted for at least two queries. Do not
                # let that floor cross the root-anchor reserve or the global cap.
                if not stored and remaining < 2:
                    stop_reason = "budget"
                    reason = RESERVED_REASON if anchor_row["depth"] == 0 else "source query budget exhausted"
                    if anchor_row["depth"] == 0:
                        reserve_blocked[anchor_row["id"]] = root_cap
                    anchor_reasons[anchor_row["id"]].append(reason)
                    blocked_anchors.add(anchor_row["id"])
                    continue
                remaining_slots = len(slots) - slot_index
                query_cap = min(12, max(2, remaining // max(1, remaining_slots)))
                self.heartbeat()
                anchor_events = self._events(candidate["event_ids"])
                result = self._stored_result(stored) if stored else self.fetcher.fetch(
                    anchor, link_type, window, query_cap=query_cap,
                )
                if not stored:
                    self._persist_link(result)
                    actual_queries = getattr(getattr(self.fetcher, "executor", None), "source_queries", None)
                    query_count = (actual_queries if actual_queries is not None
                                   else query_count + result.query_spend)
                self._evaluate(candidate, anchor_events, result)
                made_progress = True
                if result.status != "complete":
                    anchor_reasons[anchor_row["id"]].extend(
                        result.reasons or [f"{link_type} {result.status}"],
                    )
                if result.status == "failed":
                    stop_reason = "source_failure"
                    source_failed = True
                self._seed_anchors()
                if self.after_link:
                    self.after_link(result)
                if {row["id"] for row in self.repo.expansion_anchors(self.hunt_id)} - known_anchor_ids:
                    break
            if not made_progress:
                continue

        final_links = self.repo.expansion_links(self.hunt_id)
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
        }
        self.repo.audit("system", "hunt.expansion_summary", self.hunt_id, summary,
                        owner_token=self.owner_token)
        return summary
