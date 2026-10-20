"""Crash-safe deterministic post-sweep expansion over typed links."""
from __future__ import annotations

import time
from collections import defaultdict, deque
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from romulus.agent.models import PivotCoverage
from romulus.decide.policy import LANE_ORDER
from romulus.detect.base import ContextAnchor, ContextLink
from romulus.detect.registry import fresh_direct_pack
from romulus.evidence.typed import TypedEvent
from romulus.hunt.context import evaluate_context
from romulus.hunt.links import LinkAnchor, LinkFetcher, LinkResult, LinkType, LinkWindow
from romulus.hunt.publish import publish_match
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


def _anchor_class(rule_id: str) -> str:
    lowered = rule_id.lower()
    if "ssh" in lowered or "remote_login" in lowered:
        return "remote_login"
    if "web" in lowered or "interpreter" in lowered:
        return "web_shell"
    if "credential" in lowered:
        return "credential_access"
    return "execution"


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

    def _events(self, ids: list[str]) -> list[TypedEvent]:
        rows = self.repo.events_by_ids(ids)
        events = [TypedEvent.model_validate(row["event"]) for row in rows]
        return sorted(events, key=lambda event: (event.ts, event.id))

    def _seed_anchors(self) -> None:
        existing = {row["candidate_id"] for row in self.repo.expansion_anchors(self.hunt_id)}
        depths = {row["id"]: row["depth"] for row in self.repo.expansion_anchors(self.hunt_id)}
        for candidate in self.repo.candidates(self.hunt_id, ["urgent", "high"]):
            if candidate["id"] in existing:
                continue
            parent = candidate.get("source_anchor_id")
            depth = depths.get(parent, -1) + 1 if parent else 0
            events = self._events(candidate["event_ids"])
            host = next((event.host for event in events if event.host), None)
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
            "reasons": result.reasons, "duration_ms": result.duration_ms, "evaluated": 0,
        }, owner_token=self.owner_token)

    def _evaluate(self, candidate: dict, anchor_events: list[TypedEvent], result: LinkResult) -> None:
        # Every coverage cell evaluates every event. Publication owns cross-window deduplication.
        events = self._events(result.event_ids)
        for playbook in fresh_direct_pack():
            for match in playbook.consume(events):
                publish_match(
                    self.repo, self.hunt_id, playbook, match, result.task_ids[0] if result.task_ids else None, {},
                    source_anchor_id=candidate["id"], source_link_id=result.id, owner_token=self.owner_token,
                )
        context_anchor = ContextAnchor(
            id=candidate["id"], anchor_class=_anchor_class(candidate["rule_id"]), lane=candidate["lane"],
            claim=candidate["claim"], events=anchor_events,
        )
        context_link = ContextLink(
            id=result.id, link_type=result.link_type, strength=result.strength, key=result.key,
            evidence_events=self._events(result.evidence_ids), status=result.status, reasons=result.reasons,
        )
        for evaluated in evaluate_context(self.repo, self.hunt_id, context_anchor, context_link, events):
            publish_match(
                self.repo, self.hunt_id, evaluated.playbook, evaluated.match,
                result.task_ids[0] if result.task_ids else None, {},
                source_anchor_id=candidate["id"], source_link_id=result.id, owner_token=self.owner_token,
                context_reach={
                    "anchor_id": candidate["id"], "link_id": result.id,
                    "link_type": result.link_type, "strength": result.strength,
                },
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
        existing_links = self.repo.expansion_links(self.hunt_id)
        query_count = len({task for row in existing_links for task in row["task_ids"]})
        anchor_reasons: dict[str, list[str]] = defaultdict(list)
        blocked_anchors: set[str] = set()
        root_budget = self.max_source_queries - max(1, (self.max_source_queries + 4) // 5)
        if self.max_source_queries == 0:
            root_budget = 0
        stop_reason = "fixpoint"
        for _tier, link_types, window_label in TIER_PLAN:
            while True:
                self._seed_anchors()
                all_rows = self.repo.expansion_anchors(self.hunt_id)
                eligible = []
                for row in all_rows:
                    if row["status"] != "pending" or row["id"] in blocked_anchors:
                        continue
                    if row["depth"] > self.max_depth:
                        reason = f"maximum expansion depth {self.max_depth} exceeded"
                        anchor_reasons[row["id"]].append(reason)
                        blocked_anchors.add(row["id"])
                        stop_reason = "depth_limit"
                        continue
                    eligible.append(row)
                ordered = self._ordered_anchors(eligible)
                slots = []
                for link_type in link_types:
                    for anchor_row in ordered:
                        candidate = self.repo.candidate(anchor_row["candidate_id"])
                        candidate_ts = _utc(candidate["ts"])
                        window = next(
                            item for item in expansion_windows(candidate_ts, self.window)
                            if item.label == window_label
                        )
                        stored = self.repo.expansion_link_for(
                            candidate["id"], link_type, window.label, window.start, window.end,
                        )
                        if not (stored and stored["evaluated"]):
                            slots.append((anchor_row, candidate, link_type, window, stored))
                if not slots:
                    break
                made_progress = False
                for slot_index, (anchor_row, candidate, link_type, window, stored) in enumerate(slots):
                    budget_reason = self._budget_reason(query_count)
                    if budget_reason:
                        stop_reason = "budget"
                        anchor_reasons[anchor_row["id"]].append(budget_reason)
                        blocked_anchors.add(anchor_row["id"])
                        continue
                    allowed_budget = self.max_source_queries
                    if anchor_row["depth"] == 0:
                        allowed_budget = root_budget
                    remaining = allowed_budget - query_count
                    if remaining <= 0:
                        stop_reason = "budget"
                        reason = ("source query budget reserved for discovered anchors"
                                  if anchor_row["depth"] == 0 else "source query budget exhausted")
                        anchor_reasons[anchor_row["id"]].append(reason)
                        blocked_anchors.add(anchor_row["id"])
                        continue
                    remaining_slots = len(slots) - slot_index
                    query_cap = min(12, max(2, remaining // max(1, remaining_slots)))
                    self.heartbeat()
                    anchor_events = self._events(candidate["event_ids"])
                    anchor = LinkAnchor(
                        finding_id=candidate["id"], ts=_utc(candidate["ts"]), host=anchor_row["host"],
                        event_ids=candidate["event_ids"], events=anchor_events,
                    )
                    result = self._stored_result(stored) if stored else self.fetcher.fetch(
                        anchor, link_type, window, query_cap=query_cap,
                    )
                    if not stored:
                        self._persist_link(result)
                        actual_queries = getattr(getattr(self.fetcher, "executor", None), "source_queries", None)
                        query_count = (actual_queries if actual_queries is not None
                                       else query_count + len(set(result.task_ids)))
                    self._evaluate(candidate, anchor_events, result)
                    made_progress = True
                    if result.status != "complete":
                        anchor_reasons[anchor_row["id"]].extend(
                            result.reasons or [f"{link_type} {result.status}"],
                        )
                    if result.status == "failed":
                        stop_reason = "source_failure"
                    self._seed_anchors()
                    if self.after_link:
                        self.after_link(result)
                if not made_progress:
                    break

        final_links = self.repo.expansion_links(self.hunt_id)
        for row in self.repo.expansion_anchors(self.hunt_id):
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
        anchors = self.repo.expansion_anchors(self.hunt_id)
        summary = {
            "status": "completed" if stop_reason in {"fixpoint", "depth_limit", "budget"} else "partial",
            "stop_reason": stop_reason, "anchors": len(anchors),
            "expanded_complete": sum(row["status"] == "expanded_complete" for row in anchors),
            "expanded_partial": sum(row["status"] == "expanded_partial" for row in anchors),
            "unexpanded": [row["id"] for row in anchors if row["status"] == "unexpanded"],
            "source_queries": query_count,
        }
        self.repo.audit("system", "hunt.expansion_summary", self.hunt_id, summary,
                        owner_token=self.owner_token)
        return summary
