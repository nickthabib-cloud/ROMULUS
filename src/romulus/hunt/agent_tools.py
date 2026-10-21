"""Hunt-layer construction and execution boundary for model-facing pivot tools."""
from __future__ import annotations

from datetime import UTC, datetime

from romulus.agent.models import EntityRef, PivotResult
from romulus.agent.toolbox import Toolbox
from romulus.config import Settings
from romulus.detect.registry import fresh_direct_pack
from romulus.evidence.typed import TypedEvent
from romulus.hunt.context import finalize_context
from romulus.hunt.expansion import ExpansionEngine, expansion_windows
from romulus.hunt.links import LinkAnchor, LinkFetcher, LinkResult
from romulus.hunt.pivot import PivotExecutor
from romulus.hunt.publish import publish_match
from romulus.sources.models import Window
from romulus.store.db import digest
from romulus.store.repo import Repo

_PIVOT_LINK_TYPES = {
    "entity_timeline": "host_after_anchor",
    "auth_activity": "login_session",
    "process_tree": "process_lineage",
    "ids_alerts": "source_ip",
}
_EVENT_DIGEST_LIMIT = 50


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


class HuntToolExecutor:
    """Own source access, direct detection, reach persistence, and safe context re-finalization."""

    def __init__(self, repo: Repo, hunt_id: str, pivot: PivotExecutor, fetcher: LinkFetcher,
                 hunt_start: datetime, hunt_end: datetime, *, owner_token: str | None = None):
        self.repo = repo
        self.hunt_id = hunt_id
        self.pivot = pivot
        self.fetcher = fetcher
        self.window = Window(start=_utc(hunt_start), end=_utc(hunt_end))
        self.owner_token = owner_token

    def _events(self, ids: list[str]) -> list[TypedEvent]:
        rows = self.repo.events_by_ids(ids)
        return sorted((TypedEvent.model_validate(row["event"]) for row in rows),
                      key=lambda event: (event.ts, event.id))

    def _ensure_anchor(self, candidate: dict, events: list[TypedEvent]) -> None:
        if any(row["id"] == candidate["id"] for row in self.repo.expansion_anchors(self.hunt_id)):
            return
        self.repo.save_expansion_anchor({
            "id": candidate["id"], "hunt_id": self.hunt_id, "candidate_id": candidate["id"],
            "depth": 0, "parent_anchor_id": None, "host": ExpansionEngine._anchor_host(events),
            "lane": candidate["lane"], "severity": candidate["severity"], "ts": candidate["ts"],
            "status": "expanded_partial",
            "reasons": ["agent evaluated a requested reach; the deterministic tier plan was not rerun"],
        }, owner_token=self.owner_token)

    def _save_reach(self, candidate: dict, event_ids: list[str], *, link_id: str, link_type: str,
                    start: datetime, end: datetime, status: str, coverage: list,
                    reasons: list[str], task_ids: list[str], duration_ms: int,
                    query_spend: int, key: dict) -> None:
        if not event_ids:
            return
        anchor_events = self._events(candidate["event_ids"])
        self._ensure_anchor(candidate, anchor_events)
        self.repo.save_expansion_link({
            "id": link_id, "hunt_id": self.hunt_id, "anchor_id": candidate["id"],
            "link_type": link_type, "window_label": "agent requested",
            "window_start": start, "window_end": end, "strength": "inferred", "key": key,
            "status": status, "event_ids": sorted(set(event_ids)),
            "evidence_ids": sorted(set(candidate["event_ids"] + event_ids)),
            "task_ids": task_ids, "coverage": [item.model_dump(mode="json") for item in coverage],
            "reasons": sorted(set(reasons)), "duration_ms": duration_ms,
            "query_spend": query_spend, "evaluated": 0,
        }, owner_token=self.owner_token)
        self.repo.mark_expansion_link_evaluated(link_id, owner_token=self.owner_token)

    def run(self, session_id: str, anchor_id: str, request, *, anchor_ts: datetime) -> PivotResult:
        candidate = self.repo.candidate(anchor_id)
        if candidate is None or candidate["hunt_id"] != self.hunt_id:
            return PivotResult(status="unsupported", reasons=["anchor finding is not in this hunt"])
        query_start = int(getattr(self.pivot, "source_queries", 0))
        result = self.pivot.run(session_id, request, anchor_ts=anchor_ts)
        reach_ids = list(getattr(result, "reach_event_ids", []) or result.event_ids)
        link_type = _PIVOT_LINK_TYPES[request.tool]
        link_id = "agent-link-" + digest({
            "hunt_id": self.hunt_id, "anchor_id": anchor_id,
            "request": request.model_dump(mode="json"),
        })[:20]
        self._save_reach(
            candidate, reach_ids, link_id=link_id, link_type=link_type,
            start=request.arguments.start, end=request.arguments.end, status=result.status,
            coverage=result.coverage, reasons=result.reasons, task_ids=result.task_ids,
            duration_ms=result.duration_ms,
            query_spend=max(0, int(getattr(self.pivot, "source_queries", query_start)) - query_start),
            key={"agent_tool": request.tool},
        )
        # Safe and idempotent: the finalizer recomputes context only from persisted, evaluated reaches.
        finalize_context(self.repo, self.hunt_id, owner_token=self.owner_token)
        return result

    def _publish_direct(self, session_id: str, candidate: dict, result: LinkResult,
                        events: list[TypedEvent]) -> list[str]:
        candidate_ids = []
        for playbook in fresh_direct_pack():
            for match in playbook.consume(events):
                row = publish_match(
                    self.repo, self.hunt_id, playbook, match,
                    result.task_ids[0] if result.task_ids else None, {},
                    source_case_id=session_id, source_anchor_id=candidate["id"],
                    source_link_id=result.id, owner_token=self.owner_token,
                )
                if row is not None:
                    candidate_ids.append(row["id"])
        return candidate_ids

    @staticmethod
    def _summary(event: TypedEvent) -> dict:
        return {
            "id": event.id, "family": event.family, "ts": event.ts.isoformat(), "host": event.host,
            "outcome": str(event.outcome),
            "fields": {name: field.value for name, field in sorted(event.fields.items())[:16]},
            "caveats": event.caveats[:5],
        }

    def follow_link(self, session_id: str, anchor_id: str, link_type: str,
                    window_label: str | None) -> PivotResult:
        candidate = self.repo.candidate(anchor_id)
        if candidate is None or candidate["hunt_id"] != self.hunt_id:
            return PivotResult(status="unsupported", reasons=["anchor finding is not in this hunt"])
        anchor_events = self._events(candidate["event_ids"])
        anchor = LinkAnchor(
            finding_id=candidate["id"], ts=_utc(candidate["ts"]),
            host=ExpansionEngine._anchor_host(anchor_events),
            event_ids=candidate["event_ids"], events=anchor_events,
        )
        windows = expansion_windows(anchor.ts, self.window)
        label = window_label or "anchor ±5 min"
        window = next(item for item in windows if item.label == label)
        used = int(getattr(self.fetcher.executor, "source_queries", 0))
        maximum = getattr(self.fetcher.executor, "source_query_budget", None)
        remaining = max(0, int(maximum) - used) if isinstance(maximum, int) else 12
        result = self.fetcher.fetch(anchor, link_type, window, query_cap=min(12, remaining))
        self._ensure_anchor(candidate, anchor_events)
        self.repo.save_expansion_link({
            "id": result.id, "hunt_id": self.hunt_id, "anchor_id": candidate["id"],
            "link_type": result.link_type, "window_label": result.window.label,
            "window_start": result.window.start, "window_end": result.window.end,
            "strength": result.strength, "key": result.key, "status": result.status,
            "event_ids": result.event_ids, "evidence_ids": result.evidence_ids,
            "task_ids": result.task_ids,
            "coverage": [item.model_dump(mode="json") for item in result.coverage],
            "reasons": result.reasons, "duration_ms": result.duration_ms,
            "query_spend": result.query_spend, "evaluated": 0,
        }, owner_token=self.owner_token)
        events = self._events(result.event_ids)
        candidate_ids = self._publish_direct(session_id, candidate, result, events)
        self.repo.mark_expansion_link_evaluated(result.id, owner_token=self.owner_token)
        finalize_context(self.repo, self.hunt_id, owner_token=self.owner_token)
        entities = {
            (kind, value, role): EntityRef(kind=kind, value=value, role=role)
            for event in events for kind, value, role in event.entities()
            if kind in {"host", "account", "ip", "domain"}
        }
        sampled = events[:_EVENT_DIGEST_LIMIT]
        return PivotResult(
            status=result.status, task_ids=result.task_ids,
            event_ids=[event.id for event in sampled], reach_event_ids=[event.id for event in events],
            candidate_ids=candidate_ids, entities=list(entities.values()),
            event_summaries=[self._summary(event) for event in sampled],
            anchor_event_ids=candidate["event_ids"], matched_event_count=len(events),
            coverage=result.coverage, reasons=result.reasons, duration_ms=result.duration_ms,
        )


def build_agent_toolbox(settings: Settings, repo: Repo, hunt_id: str, *, client, contracts: dict,
                        session_id: str, owner_token: str | None = None) -> Toolbox:
    """Construct source-capable ports in the hunt layer and inject only their protocol into agent code."""
    hunt = repo.get_hunt(hunt_id)
    if hunt is None:
        raise KeyError(hunt_id)
    manifest = hunt.get("manifest") or {}
    window = manifest.get("window") or {}
    start = _utc(datetime.fromisoformat(str(window["start"])))
    end = _utc(datetime.fromisoformat(str(window["end"])))
    inventory = {
        target: tuple(sorted((profile or {}).get("datasets") or []))
        for target, profile in (manifest.get("source_profiles") or {}).items()
    }
    pivot = PivotExecutor(
        repo, client, hunt_id, contracts, owner_token=owner_token,
        source_query_budget=settings.agent_max_source_queries, source_query_scope="agent",
        dataset_inventory=inventory,
    )
    pivot.source_queries = repo.agent_source_queries(hunt_id)
    fetcher = LinkFetcher(pivot, start, end)
    executor = HuntToolExecutor(repo, hunt_id, pivot, fetcher, start, end, owner_token=owner_token)
    return Toolbox(repo, hunt_id, executor=executor, session_id=session_id)
