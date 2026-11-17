"""Hunt-layer construction and execution boundary for model-facing pivot tools."""
from __future__ import annotations

import re
from datetime import UTC, datetime
from math import ceil

from romulus.agent.models import EntityRef, PivotCoverage, PivotResult
from romulus.agent.toolbox import FOLLOW_LINK_KINDS, Toolbox
from romulus.agent.tools import QuerySourceRequest, SearchEventsRequest
from romulus.config import Settings
from romulus.detect.registry import bind_windows_site, fresh_direct_pack
from romulus.evidence.typed import TypedEvent
from romulus.hunt.agent_query import SourceQueryRunner, query_refusal
from romulus.hunt.expansion import ExpansionEngine, expansion_windows
from romulus.hunt.links import LinkAnchor, LinkFetcher, LinkResult
from romulus.hunt.manifest import inventory_usable
from romulus.hunt.pivot import MAX_SEARCH_ENTITIES, PivotExecutor
from romulus.hunt.publish import mark_hypothesis_relation, publish_match
from romulus.site import ensure_site_unchanged
from romulus.sources.agent_query import MAX_QUERY_HITS
from romulus.sources.models import Window
from romulus.sources.packets import ArkimeSessionSearch
from romulus.sources.profile import AGGREGATABLE, LIMITED_KINDS, SHARDS_UNANSWERED
from romulus.store.db import digest
from romulus.store.repo import Repo

# An Arkime session target's viewer is a source of its own: its name is this prefix and the target's.
ARKIME_SOURCE_PREFIX = "arkime:"
KEYWORD_LIKE = frozenset({"keyword", "constant_keyword", "wildcard", "flattened"})
# What a listing passes to the model from a source's mapping or the viewer's field list: names a mapping can take
# from telemetry (dynamic mapping), so only strict names of bounded length are shown and the rest only counted.
LISTED_NAME = re.compile(r"^[A-Za-z0-9_@.\-]{1,256}$")
LISTED_LABEL = re.compile(r"^[A-Za-z0-9_ .\-]{1,64}$")
LISTED_SOURCE = re.compile(r"^[A-Za-z0-9_.+:@\-]{1,300}$")
ANALYZED_TEXT = frozenset({"text", "match_only_text"})

_PIVOT_LINK_TYPES = {
    "entity_timeline": "agent_entity_timeline",
    "auth_activity": "agent_auth_activity",
    "process_tree": "agent_process_tree",
    "ids_alerts": "agent_ids_alerts",
    "search_events": "agent_search_events",
    "query_source": "agent_query_source",
}
_AGENT_HYPOTHESIS = "agent_hypothesis"
_EVENT_DIGEST_LIMIT = 50
# anchors whose followable link kinds one session's executor remembers (each costs one read of the anchor's records)
_FOLLOWABLE_CACHE = 256
# A follow_link fetch spends at most this many source queries (the deterministic link planner's own bound).
_FOLLOW_LINK_QUERIES = 12

# How the hunt's AI-agent source queries (AGENT_MAX_SOURCE_QUERIES) are shared, so that no session or tool call
# starves the rest. Each share is derived when a session starts, from the spend persisted so far, so a resumed hunt
# never gets a fresh budget and what one session leaves unused flows to the sessions after it.
# - orient reads the whole dossier to open hypotheses: all orient sessions together take at most this part of the
#   total, which leaves most of it for following the hypotheses' leads;
ORIENT_SHARE = 0.20
# - an investigate session takes the remaining queries divided by the open hypotheses that can still be given a
#   session (its own included); the assessment reads no source, so nothing is held back for it;
# - one tool call spends at most this part of its session's share, and never less than the floor (one pivot can fan
#   out over many indices and time partitions), and never more than the share; a call's slice is raised to one query
#   for each source it plans (PivotExecutor._agent_plan_call), within what the session's share has left.
CALL_SLICE_SHARE = 0.10
CALL_SLICE_FLOOR = 32
# out-of-window packet sources named together in one summary line
_OUTSIDE_NAMES = 5


def _label(value, limit: int = 64) -> str | None:
    """A short descriptive text from a profile (a type, a group, a note), shown only when it is plain."""
    if not isinstance(value, str):
        return None
    if limit > 64:
        text = " ".join(value.split())[:limit]
        return text if all(ch.isprintable() for ch in text) else None
    return value if LISTED_LABEL.fullmatch(value) else None


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def agent_query_shares(settings: Settings, repo: Repo, hunt_id: str, session: dict | None) -> tuple[int | None,
                                                                                                    int | None]:
    """(session share, call slice) of the hunt's AI-agent source queries for one session (see ORIENT_SHARE); (None,
    None) for a session of another purpose, which the hunt total alone bounds."""
    purpose = (session or {}).get("purpose")
    total = settings.agent_max_source_queries
    remaining = max(0, total - repo.agent_source_queries(hunt_id))
    if purpose == "orient":
        orient_left = max(0, ceil(total * ORIENT_SHARE) - repo.agent_purpose_source_queries(hunt_id, "orient"))
        share = min(remaining, orient_left)
    elif purpose == "investigate":
        own = session.get("hypothesis_id")
        planned = {row["id"] for row in repo.agent_hypotheses(hunt_id)
                   if row["status"] == "open"
                   and int(row.get("sessions_run") or 0) < settings.agent_max_sessions_per_hypothesis}
        share = ceil(remaining / max(1, len(planned | ({own} if own else set()))))
    else:
        return None, None
    return share, min(share, max(CALL_SLICE_FLOOR, ceil(share * CALL_SLICE_SHARE)))


def packet_span(profile: dict | None) -> tuple[datetime, datetime] | None:
    """The times of every packet behind an Arkime session index, as profiled when the hunt started: its earliest
    first packet to its latest last packet. None unless both are known from a complete inventory search."""
    profile = profile or {}
    if any(SHARDS_UNANSWERED in str(note) for note in profile.get("notes") or []):
        return None
    bounds = []
    for key in ("time_min", "packet_time_max"):
        try:
            value = datetime.fromisoformat(str(profile.get(key)))
        except (TypeError, ValueError):
            return None
        if value.tzinfo is None:
            return None
        bounds.append(value.astimezone(UTC))
    return (bounds[0], bounds[1]) if bounds[0] <= bounds[1] else None


def _outside(span: tuple[datetime, datetime] | None, start: datetime, end: datetime) -> bool:
    """Whether a known span cannot overlap the half-open window [start, end)."""
    return span is not None and (span[1] < _utc(start) or span[0] >= _utc(end))


class HuntToolExecutor:
    """Own source access, direct detection, and agent-hypothesis reach persistence."""

    def __init__(self, repo: Repo, hunt_id: str, pivot: PivotExecutor, fetcher: LinkFetcher,
                 hunt_start: datetime, hunt_end: datetime, *, owner_token: str | None = None,
                 packet_sources: tuple[str, ...] = (), uncontracted_targets: tuple[str, ...] = (),
                 packet_spans: dict[str, tuple[datetime, datetime]] | None = None,
                 settings: Settings | None = None, arkime_search=None):
        self.repo = repo
        self.hunt_id = hunt_id
        self.pivot = pivot
        self.fetcher = fetcher
        self.window = Window(start=_utc(hunt_start), end=_utc(hunt_end))
        self.owner_token = owner_token
        # packet sources the hunt can read (packet captures, the Arkime viewer): a typed search never reaches them
        self.packet_sources = tuple(packet_sources)
        # each packet source's known packet times (packet_span); one without a known span is always named
        self.packet_spans = dict(packet_spans or {})
        # hunt targets with no field contract in this run: no search can read them, whatever its scope
        self.uncontracted_targets = tuple(uncontracted_targets)
        self._followable: dict[str, tuple[str, ...]] = {}
        self._profile_cache: dict[str, dict] | None = None
        self._sources: dict[str, tuple[str, str]] | None = None
        self.sources_not_listed = 0
        # the agent's own source queries (query_source): secrets are redacted from what they keep, with these settings
        self.settings = settings
        self.queries = SourceQueryRunner(pivot, settings, arkime_search)

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

    def search_fields(self) -> dict:
        """The typed fields an agent search can name on this hunt's targets (PivotExecutor.search_vocabulary), how
        many targets each role has, and how many sources no typed search reads; no source query."""
        targets = {"host": 0, "network": 0}
        for contract in self.pivot.contracts.values():
            if contract is not None:
                targets["network" if contract.role == "network" else "host"] += 1
        return {"fields": self.pivot.search_vocabulary(), "targets": targets,
                "packet_sources": len(self.packet_sources), "uncontracted": len(self.uncontracted_targets)}

    def _profiles(self) -> dict[str, dict]:
        if self._profile_cache is None:
            self._profile_cache = self.repo.source_profiles(self.hunt_id)
        return self._profile_cache

    def source_table(self) -> dict[str, tuple[str, str]]:
        """Every source the agent can name, by its exact name: (kind, target). Each target with a field contract (an
        Elasticsearch or OpenSearch index or data stream) is a source of kind index; each Arkime session target's
        viewer is a source of kind arkime_viewer named arkime:<target>, unless an index already has that name. A name
        is only ever looked up here, never parsed."""
        if self._sources is None:
            table: dict[str, tuple[str, str]] = {}
            for target, contract in sorted(self.pivot.contracts.items()):
                if contract is not None:
                    table[target] = ("index", target)
            for target, contract in sorted(self.pivot.contracts.items()):
                if contract is not None and contract.time_field == "firstPacket":
                    table.setdefault(ARKIME_SOURCE_PREFIX + target, ("arkime_viewer", target))
            # a name the agent could not write back is not a source it can name: counted, never shown
            self.sources_not_listed = sum(1 for name in table if not LISTED_SOURCE.fullmatch(name))
            self._sources = {name: entry for name, entry in table.items() if LISTED_SOURCE.fullmatch(name)}
        return self._sources

    def search_sources(self) -> list[dict]:
        """The hunt's sources (source_table) with each one's kind, role, time field and field count. No source
        query."""
        out = []
        for name, (kind, target) in sorted(self.source_table().items()):
            contract = self.pivot.contracts[target]
            if kind == "index":
                out.append({"source": name, "kind": kind, "role": "network" if contract.role == "network" else "host",
                            "time_field": contract.time_field, "fields": len(self._native_table(target))})
            else:
                profile = self._profiles().get(target) or {}
                out.append({"source": name, "kind": kind, "role": "network", "time_field": contract.time_field,
                            "fields": len(profile.get("arkime_fields") or [])})
        return out

    def _native_table(self, target: str) -> dict[str, str]:
        """A target's native fields and their mapped types: from its profile, else its contract's direct fields."""
        profile = self._profiles().get(target) or {}
        types = profile.get("field_types")
        if isinstance(types, dict) and types:
            return {str(name): str(kind) for name, kind in types.items()}
        contract = self.pivot.contracts.get(target)
        if contract is None:
            return {}
        table = contract.linux_fields or contract.fields
        return {name: spec.type for name, spec in table.items() if tuple(spec.natives or (spec.native,)) == (name,)}

    def native_fields(self, source: str) -> dict | None:
        """One source's own fields: an index's mapped fields (type, keyword-like or text, indexed, aggregatable,
        ignore_above), or an Arkime viewer's expression fields as profiled when the hunt started. None for a name
        that is not one of the hunt's sources. No source query."""
        found = self.source_table().get(source)
        if found is None:
            return None
        kind, target = found
        contract = self.pivot.contracts[target]
        if kind == "arkime_viewer":
            profile = self._profiles().get(target) or {}
            fields, hidden = [], 0
            for item in profile.get("arkime_fields") or []:
                name = item.get("field") if isinstance(item, dict) else None
                if not isinstance(name, str) or not LISTED_NAME.fullmatch(name):
                    hidden += 1
                    continue
                fields.append({"field": name, "type": _label(item.get("type")), "group": _label(item.get("group")),
                               "db_field": item.get("db_field") if isinstance(item.get("db_field"), str)
                               and LISTED_NAME.fullmatch(item["db_field"]) else None})
            note = profile.get("arkime_fields_note")
            if "arkime_fields" not in profile:
                note = ("the viewer's expression fields were not profiled for this hunt; its expressions still take "
                        "the viewer's own field names")
            return {"fields": fields, "note": _label(note, 300), "names_not_listed": hidden}
        fields, hidden = [], 0
        for name, mapped in self._native_table(target).items():
            if not LISTED_NAME.fullmatch(name):
                hidden += 1
                continue
            base, _, qualifier = mapped.partition(":")
            item = {"field": name, "type": base,
                    "kind": ("keyword" if base in KEYWORD_LIKE else "text" if base in ANALYZED_TEXT else "other"),
                    "indexed": qualifier not in ("not_indexed", "doc_values_only"),
                    "aggregatable": mapped in AGGREGATABLE}
            if base in LIMITED_KINDS:
                known, limit = contract.index_limit(name)
                item["ignore_above"] = limit if known and limit is not None else ("none" if known else "unknown")
            fields.append(item)
        return {"fields": fields, "note": None, "names_not_listed": hidden}

    def search_sources_hidden(self) -> int:
        """How many of the hunt's sources have a name no listing shows (and no query can name)."""
        self.source_table()
        return self.sources_not_listed

    def query_refusal(self, request: QuerySourceRequest) -> dict | None:
        """Why the agent's own query cannot be sent (hunt.agent_query.query_refusal), decided without any source
        query; None when it can."""
        found = self.source_table().get(request.arguments.source)
        return query_refusal(request, found[0] if found else None)

    def search_item_bound(self, request) -> int:
        """The most page items one search's or query's result can hold (PivotExecutor.search_item_bound), plus a
        search's named unsearched sources."""
        if isinstance(request, QuerySourceRequest):
            # its returned rows, the findings they can raise, its listed entities, one coverage cell and its reasons
            return 2 * MAX_QUERY_HITS + MAX_SEARCH_ENTITIES + 64
        return self.pivot.search_item_bound(request) + len(self.packet_sources) + len(self.uncontracted_targets)

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
        begin = getattr(self.pivot, "begin_call", None)
        if begin is not None:
            begin()
        query_start = self._spent()
        link_key = {"agent_tool": request.tool}
        if request.tool == "auth_activity":
            link_key["entity"] = request.arguments.entity.model_dump(mode="json")
        if isinstance(request, SearchEventsRequest):
            link_key["search"] = request.arguments.model_dump(mode="json", include={"scope", "conditions"})
        if isinstance(request, QuerySourceRequest):
            link_key["query"] = request.arguments.model_dump(mode="json", include={
                "source", "query", "expression", "aggs", "sort", "size"})
            kind, target = self.source_table().get(request.arguments.source, (None, None))
            if kind is None:
                result = PivotResult(status="unsupported", reasons=["the source is not one of this hunt's sources"])
            else:
                result = self.queries.run(session_id, request, kind=kind, target=target)
        else:
            result = self.pivot.run(session_id, request, anchor_ts=anchor_ts)
        if isinstance(request, SearchEventsRequest):
            # matched records no normalizer read: the first ones are kept as raw records the agent can cite as text
            self.queries.keep_search_unread(session_id, request, result)
            packets = self.packet_sources if request.arguments.scope != "host" else ()
            # a capture whose every packet is known to fall outside the search window is no gap: counted in one
            # summary line, never listed as not searched
            outside = [name for name in packets
                       if _outside(self.packet_spans.get(name), request.arguments.start, request.arguments.end)]
            excluded = set(outside)
            packets = tuple(name for name in packets if name not in excluded)
            if outside:
                named = ", ".join(outside[:_OUTSIDE_NAMES]) + (
                    f", and {len(outside) - _OUTSIDE_NAMES} more" if len(outside) > _OUTSIDE_NAMES else "")
                result = result.model_copy(update={"reasons": sorted({*result.reasons, (
                    f"{len(outside)} packet source(s) not listed as not searched: every packet behind them, as "
                    f"profiled when the hunt started, is outside the search window ({named})")})})
            unsearched = [*(f"{name}: not searched (scope unsupported for agent search)" for name in packets),
                          *(f"{target}: not searched (no field contract for this target)"
                            for target in self.uncontracted_targets)]
            if unsearched:
                # a source the search could not read makes it partial everywhere its outcome is kept: the tool
                # result, its coverage, and the reach link
                gaps = [PivotCoverage(target=item.split(":", 1)[0], dataset=None, start=request.arguments.start,
                                      end=request.arguments.end, status="partial", reasons=[item], returned=0,
                                      total=None)
                        for item in unsearched]
                result = result.model_copy(update={
                    "not_searched": unsearched, "coverage": [*result.coverage, *gaps],
                    "reasons": sorted({*result.reasons, *unsearched}),
                    "status": "partial" if result.status == "complete" else result.status,
                })
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
            query_spend=max(0, self._spent() - query_start),
            key=link_key,
        )
        return result

    def _spent(self, executor=None) -> int:
        """The queries this session's executor reserved itself (concurrent sessions raise the hunt-wide count too)."""
        executor = executor if executor is not None else self.pivot
        budgeted = getattr(executor, "_agent_budgeted", None)
        if budgeted is not None and budgeted():
            return int(executor.session_spent)
        return int(getattr(executor, "source_queries", 0))

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
        executor = self.fetcher.executor
        begin = getattr(executor, "begin_call", None)
        if begin is not None:
            begin()
        available = executor.agent_available() if getattr(executor, "agent_available", None) else None
        if available is not None:
            if available[0] == 0:
                # nothing can be fetched: one result with the cap's reason, and no task
                return PivotResult(status="failed", anchor_event_ids=candidate["event_ids"], reasons=[
                    available[1], "the agent's source-query cap is reached: the link was not followed, and no record "
                    "was found or ruled out; rely on the results already returned"])
            remaining = available[0]
        else:
            used = int(getattr(executor, "source_queries", 0))
            maximum = getattr(executor, "source_query_budget", None)
            remaining = max(0, int(maximum) - used) if isinstance(maximum, int) else _FOLLOW_LINK_QUERIES
        result = self.fetcher.fetch(anchor, link_type, window, query_cap=min(_FOLLOW_LINK_QUERIES, remaining))
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
    session = repo.agent_session(hunt_id, session_id)
    share, call_slice = agent_query_shares(settings, repo, hunt_id, session)
    pivot.configure_agent_shares(session_id=session_id, purpose=(session or {}).get("purpose"),
                                 session_share=share, call_slice=call_slice)
    fetcher = LinkFetcher(pivot, start, end)
    # The packet stage reads the captures behind each Arkime session target (the viewer, then TShark); a typed
    # search reads the session records alone, so those captures are named as not searched.
    packet_targets = {f"packet captures behind {target} (Arkime viewer and TShark)": target
                      for target, contract in sorted(contracts.items())
                      if contract is not None and getattr(contract, "time_field", "") == "firstPacket"}
    profiles = repo.source_profiles(hunt_id) if packet_targets else {}
    spans = {name: span for name, target in packet_targets.items()
             if (span := packet_span(profiles.get(target))) is not None}
    uncontracted = tuple(sorted({str(target) for target in manifest.get("targets") or []
                                 if contracts.get(target) is None}))
    executor = HuntToolExecutor(repo, hunt_id, pivot, fetcher, start, end, owner_token=owner_token,
                                packet_sources=tuple(packet_targets), uncontracted_targets=uncontracted,
                                packet_spans=spans, settings=settings,
                                arkime_search=ArkimeSessionSearch(settings) if packet_targets else None)
    return Toolbox(repo, hunt_id, executor=executor, session_id=session_id, owner_token=owner_token)
