"""Crash-safe deterministic post-sweep expansion over typed links."""
from __future__ import annotations

import time
from collections import Counter
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

LINK_ORDER: tuple[LinkType, ...] = (
    "login_session", "process_lineage", "network_flow", "source_ip", "account", "host_after_anchor",
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

    def _next_anchor(self, expanded_hosts: Counter) -> dict | None:
        pending = [row for row in self.repo.expansion_anchors(self.hunt_id) if row["status"] == "pending"]
        if not pending:
            return None
        return min(pending, key=lambda row: (
            expanded_hosts[row["host"] or ""], LANE_ORDER.get(row["lane"], 9),
            SEVERITY_ORDER.get(row["severity"], 9), _utc(row["ts"]), row["id"],
        ))

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
        # Named windows are nested. Evaluate each linked record once per anchor/link type while still
        # retaining every window's independent coverage row.
        already_seen = {
            event_id
            for row in self.repo.expansion_links(self.hunt_id)
            if row["anchor_id"] == result.anchor_id and row["link_type"] == result.link_type
            and row["id"] != result.id and row["evaluated"]
            for event_id in row["event_ids"]
        }
        events = self._events([event_id for event_id in result.event_ids if event_id not in already_seen])
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
        expanded_hosts = Counter(row["host"] or "" for row in self.repo.expansion_anchors(self.hunt_id)
                                 if row["status"].startswith("expanded_"))
        stop_reason = "fixpoint"
        while (anchor_row := self._next_anchor(expanded_hosts)) is not None:
            budget_reason = self._budget_reason(query_count)
            if budget_reason:
                stop_reason = "budget"
                for row in self.repo.expansion_anchors(self.hunt_id):
                    if row["status"] == "pending":
                        self.repo.update_expansion_anchor(row["id"], "unexpanded", [budget_reason],
                                                          owner_token=self.owner_token)
                break
            if anchor_row["depth"] > self.max_depth:
                stop_reason = "depth_limit"
                self.repo.update_expansion_anchor(anchor_row["id"], "unexpanded", [
                    f"maximum expansion depth {self.max_depth} exceeded",
                ], owner_token=self.owner_token)
                continue
            self.heartbeat()
            candidate = self.repo.candidate(anchor_row["candidate_id"])
            anchor_events = self._events(candidate["event_ids"])
            candidate_ts = _utc(candidate["ts"])
            anchor = LinkAnchor(
                finding_id=candidate["id"], ts=candidate_ts, host=anchor_row["host"],
                event_ids=candidate["event_ids"], events=anchor_events,
            )
            reasons = []
            for link_type in LINK_ORDER:
                for window in expansion_windows(candidate_ts, self.window):
                    budget_reason = self._budget_reason(query_count)
                    if budget_reason:
                        stop_reason = "budget"
                        reasons.append(budget_reason)
                        break
                    stored = self.repo.expansion_link_for(
                        anchor.finding_id, link_type, window.label, window.start, window.end,
                    )
                    if stored and stored["evaluated"]:
                        if stored["status"] != "complete":
                            reasons.extend(stored["reasons"] or [f"{link_type} {stored['status']}"])
                        continue
                    result = self._stored_result(stored) if stored else self.fetcher.fetch(anchor, link_type, window)
                    if not stored:
                        self._persist_link(result)
                        actual_queries = getattr(getattr(self.fetcher, "executor", None), "source_queries", None)
                        query_count = actual_queries if actual_queries is not None else query_count + len(set(result.task_ids))
                    self._evaluate(candidate, anchor_events, result)
                    if result.status != "complete":
                        reasons.extend(result.reasons or [f"{link_type} {result.status}"])
                    if result.status == "failed":
                        stop_reason = "source_failure"
                    self._seed_anchors()
                    if self.after_link:
                        self.after_link(result)
                if reasons and reasons[-1] in {"source query budget exhausted", "hunt wall-clock budget exhausted"}:
                    break
            if stop_reason == "budget" and any("budget exhausted" in reason for reason in reasons):
                self.repo.update_expansion_anchor(anchor_row["id"], "unexpanded", sorted(set(reasons)),
                                                  owner_token=self.owner_token)
                for row in self.repo.expansion_anchors(self.hunt_id):
                    if row["status"] == "pending":
                        self.repo.update_expansion_anchor(row["id"], "unexpanded", [reasons[-1]],
                                                          owner_token=self.owner_token)
                break
            status = "expanded_partial" if reasons else "expanded_complete"
            self.repo.update_expansion_anchor(anchor_row["id"], status, sorted(set(reasons)),
                                              owner_token=self.owner_token)
            expanded_hosts[anchor_row["host"] or ""] += 1
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
