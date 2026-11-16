"""Hunt-layer construction and execution boundary for model-facing pivot tools."""
from __future__ import annotations

from datetime import UTC, datetime

from romulus.agent.models import EntityRef, PivotResult
from romulus.agent.toolbox import FOLLOW_LINK_KINDS, Toolbox
from romulus.agent.tools import SearchEventsRequest
from romulus.config import Settings
from romulus.detect.registry import bind_windows_site, fresh_direct_pack
from romulus.evidence.typed import TypedEvent
from romulus.hunt.expansion import ExpansionEngine, expansion_windows
from romulus.hunt.links import LinkAnchor, LinkFetcher, LinkResult
from romulus.hunt.manifest import inventory_usable
from romulus.hunt.pivot import PivotExecutor
from romulus.hunt.publish import mark_hypothesis_relation, publish_match
from romulus.site import ensure_site_unchanged
from romulus.sources.models import Window
from romulus.store.db import digest
from romulus.store.repo import Repo

_PIVOT_LINK_TYPES = {
    "entity_timeline": "agent_entity_timeline",
    "auth_activity": "agent_auth_activity",
    "process_tree": "agent_process_tree",
    "ids_alerts": "agent_ids_alerts",
    "search_events": "agent_search_events",
}
_AGENT_HYPOTHESIS = "agent_hypothesis"
_EVENT_DIGEST_LIMIT = 50
# anchors whose followable link kinds one session's executor remembers (each costs one read of the anchor's records)
_FOLLOWABLE_CACHE = 256


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


class HuntToolExecutor:
    """Own source access, direct detection, and agent-hypothesis reach persistence."""

    def __init__(self, repo: Repo, hunt_id: str, pivot: PivotExecutor, fetcher: LinkFetcher,
                 hunt_start: datetime, hunt_end: datetime, *, owner_token: str | None = None,
                 packet_sources: tuple[str, ...] = (), uncontracted_targets: tuple[str, ...] = ()):
        self.repo = repo
        self.hunt_id = hunt_id
        self.pivot = pivot
        self.fetcher = fetcher
        self.window = Window(start=_utc(hunt_start), end=_utc(hunt_end))
        self.owner_token = owner_token
        # packet sources the hunt can read (packet captures, the Arkime viewer): a typed search never reaches them
        self.packet_sources = tuple(packet_sources)
        # hunt targets with no field contract in this run: no search can read them, whatever its scope
        self.uncontracted_targets = tuple(uncontracted_targets)
        self._followable: dict[str, tuple[str, ...]] = {}

    def _events(self, ids: list[str]) -> list[TypedEvent]:
        rows = self.repo.citation_events(self.hunt_id, ids)
        return sorted((TypedEvent.model_validate(row["event"]) for row in rows),
                      key=lambda event: (event.ts, event.id))

    def _save_reach(self, candidate: dict, event_ids: list[str], *, link_id: str, link_type: str,
                    start: datetime, end: datetime, status: str, coverage: list,
                    reasons: list[str], task_ids: list[str], duration_ms: int,
                    query_spend: int, key: dict) -> None:
        if not event_ids:
            return
        self.repo.save_expansion_link({
            "id": link_id, "hunt_id": self.hunt_id, "anchor_id": candidate["id"],
            "link_type": link_type, "window_label": "agent requested",
            "window_start": start, "window_end": end, "strength": _AGENT_HYPOTHESIS, "key": key,
            "status": status, "event_ids": sorted(set(event_ids)),
            "evidence_ids": sorted(set(candidate["event_ids"] + event_ids)),
            "task_ids": task_ids, "coverage": [item.model_dump(mode="json") for item in coverage],
            "reasons": sorted(set(reasons)), "duration_ms": duration_ms,
            "query_spend": query_spend, "evaluated": 0,
        }, owner_token=self.owner_token)
        self.repo.mark_expansion_link_evaluated(link_id, owner_token=self.owner_token)

    def search_refusal(self, request: SearchEventsRequest) -> dict | None:
        """Why an agent search cannot run on this hunt's sources, decided without any source query; None when some
        target of its scope can evaluate every condition."""
        return self.pivot.search_refusal(request)

    def run(self, session_id: str, anchor_id: str, request, *, anchor_ts: datetime | None) -> PivotResult:
        link_type = _PIVOT_LINK_TYPES.get(request.tool)
        if link_type is None:
            # a tool this boundary cannot record reach for is refused before any source query
            return PivotResult(status="unsupported", reasons=[f"tool {request.tool} has no agent reach link type"])
        candidate = self.repo.candidate(anchor_id)
        if candidate is None or candidate["hunt_id"] != self.hunt_id:
            return PivotResult(status="unsupported", reasons=["anchor finding is not in this hunt"])
        if candidate["ts"] is None or anchor_ts is None:
            return PivotResult(status="partial", reasons=[
                "anchor observation time unavailable; time-based pivot was not evaluated",
            ])
        query_start = int(getattr(self.pivot, "source_queries", 0))
        link_key = {"agent_tool": request.tool}
        if request.tool == "auth_activity":
            link_key["entity"] = request.arguments.entity.model_dump(mode="json")
        if isinstance(request, SearchEventsRequest):
            link_key["search"] = request.arguments.model_dump(mode="json", include={"scope", "conditions"})
        result = self.pivot.run(session_id, request, anchor_ts=anchor_ts)
        if isinstance(request, SearchEventsRequest):
            packets = self.packet_sources if request.arguments.scope != "host" else ()
            unsearched = [*(f"{name}: not searched (scope unsupported for agent search)" for name in packets),
                          *(f"{target}: not searched (no field contract for this target)"
                            for target in self.uncontracted_targets)]
            if unsearched:
                result = result.model_copy(update={"not_searched": unsearched})
        reach_ids = list(getattr(result, "reach_event_ids", []) or result.event_ids)
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
            key=link_key,
        )
        return result

    def _publish_direct(self, session_id: str, candidate: dict, result: LinkResult,
                        events: list[TypedEvent]) -> list[str]:
        candidate_ids = []
        for playbook in bind_windows_site(fresh_direct_pack(), getattr(self.pivot, "site_facts", None)):
            for match in playbook.consume(events):
                mark_hypothesis_relation(
                    match, anchor_id=candidate["id"], link_type=result.link_type,
                    link_id=result.id, strength=result.strength,
                )
                row = publish_match(
                    self.repo, self.hunt_id, playbook, match,
                    result.task_ids[0] if result.task_ids else None, {},
                    source_case_id=session_id, source_anchor_id=candidate["id"],
                    source_link_id=result.id, owner_token=self.owner_token, zeek_context=events, zeek_context_ids=result.evidence_ids,
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

    def _link_anchor(self, candidate: dict) -> LinkAnchor:
        anchor_events = self._events(candidate["event_ids"])
        return LinkAnchor(
            finding_id=candidate["id"], ts=_utc(candidate["ts"]),
            host=ExpansionEngine._anchor_host(anchor_events),
            event_ids=candidate["event_ids"], events=anchor_events,
        )

    def _link_window(self, anchor: LinkAnchor, window_label: str | None):
        label = window_label or "anchor ±5 min"
        return next(item for item in expansion_windows(anchor.ts, self.window) if item.label == label)

    def followable_links(self, anchor_id: str) -> tuple[str, ...]:
        """The follow_link kinds the anchor finding's cited records carry a usable typed key for, decided by the
        link planner itself without a source query. A finding without an observation time gets every kind:
        follow_link then answers each with its own partial result."""
        cached = self._followable.get(anchor_id)
        if cached is not None:
            return cached
        candidate = self.repo.candidate(anchor_id)
        decide = getattr(self.fetcher, "followable", None)
        if candidate is None or candidate["hunt_id"] != self.hunt_id:
            kinds: tuple[str, ...] = ()
        elif candidate["ts"] is None or decide is None:
            kinds = FOLLOW_LINK_KINDS       # a fetcher that cannot say lets every kind through to follow_link
        else:
            anchor = self._link_anchor(candidate)
            window = self._link_window(anchor, None)
            kinds = tuple(kind for kind in FOLLOW_LINK_KINDS if decide(anchor, kind, window))
        if len(self._followable) >= _FOLLOWABLE_CACHE:
            self._followable.pop(next(iter(self._followable)))
        self._followable[anchor_id] = kinds
        return kinds

    def follow_link(self, session_id: str, anchor_id: str, link_type: str,
                    window_label: str | None) -> PivotResult:
        candidate = self.repo.candidate(anchor_id)
        if candidate is None or candidate["hunt_id"] != self.hunt_id:
            return PivotResult(status="unsupported", reasons=["anchor finding is not in this hunt"])
        if candidate["ts"] is None:
            return PivotResult(status="partial", reasons=[
                "anchor observation time unavailable; time-based link was not evaluated",
            ])
        anchor = self._link_anchor(candidate)
        window = self._link_window(anchor, window_label)
        used = int(getattr(self.fetcher.executor, "source_queries", 0))
        maximum = getattr(self.fetcher.executor, "source_query_budget", None)
        remaining = max(0, int(maximum) - used) if isinstance(maximum, int) else 12
        result = self.fetcher.fetch(anchor, link_type, window, query_cap=min(12, remaining))
        agent_link_id = "agent-link-" + digest({
            "hunt_id": self.hunt_id, "anchor_id": candidate["id"], "source_link_id": result.id,
        })[:20]
        agent_result = result.model_copy(update={
            "id": agent_link_id,
            "link_type": f"agent_follow_{result.link_type}",
            "strength": _AGENT_HYPOTHESIS,
            "key": {"agent_tool": "follow_link", "requested_link_type": result.link_type,
                    "source_key": result.key},
        })
        self.repo.save_expansion_link({
            "id": agent_result.id, "hunt_id": self.hunt_id, "anchor_id": candidate["id"],
            "link_type": agent_result.link_type, "window_label": agent_result.window.label,
            "window_start": result.window.start, "window_end": result.window.end,
            "strength": agent_result.strength, "key": agent_result.key, "status": result.status,
            "event_ids": result.event_ids, "evidence_ids": result.evidence_ids,
            "task_ids": result.task_ids,
            "coverage": [item.model_dump(mode="json") for item in result.coverage],
            "reasons": result.reasons, "duration_ms": result.duration_ms,
            "query_spend": result.query_spend, "evaluated": 0,
        }, owner_token=self.owner_token)
        events = self._events(result.event_ids)
        candidate_ids = self._publish_direct(session_id, candidate, agent_result, events)
        self.repo.mark_expansion_link_evaluated(agent_result.id, owner_token=self.owner_token)
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
                        session_id: str, owner_token: str | None = None, heartbeat=None) -> Toolbox:
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
        if inventory_usable(profile)
    }
    pivot = PivotExecutor(
        repo, client, hunt_id, contracts, owner_token=owner_token, heartbeat=heartbeat,
        source_query_budget=settings.agent_max_source_queries, source_query_scope="agent",
        dataset_inventory=inventory,
        site_facts=ensure_site_unchanged(settings.home, manifest.get("site")),
    )
    pivot.source_queries = repo.agent_source_queries(hunt_id)
    fetcher = LinkFetcher(pivot, start, end)
    # The packet stage reads the captures behind each Arkime session target (the viewer, then TShark); a typed
    # search reads the session records alone, so those captures are named as not searched.
    packet_sources = tuple(f"packet captures behind {target} (Arkime viewer and TShark)"
                           for target, contract in sorted(contracts.items())
                           if contract is not None and getattr(contract, "time_field", "") == "firstPacket")
    uncontracted = tuple(sorted({str(target) for target in manifest.get("targets") or []
                                 if contracts.get(target) is None}))
    executor = HuntToolExecutor(repo, hunt_id, pivot, fetcher, start, end, owner_token=owner_token,
                                packet_sources=packet_sources, uncontracted_targets=uncontracted)
    return Toolbox(repo, hunt_id, executor=executor, session_id=session_id, owner_token=owner_token)
