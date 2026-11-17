"""The AI agent's own source queries (query_source), run in the hunt layer.

The agent names one of the hunt's sources (hunt.agent_tools.HuntToolExecutor.source_table) and writes a Query DSL
query for an index, or an Arkime expression for an Arkime viewer. sources.agent_query decides what may be sent and
builds the body; this module checks the request before any source query (query_refusal), spends the agent's source
queries under the same caps as its other pivots, reads the source through the existing clients only, keeps every
returned record a normalizer reads as citable evidence (direct detection runs on them, as on any pivot), and keeps a
bounded, redacted preview of the rows and aggregations. Zero hits is never an absence; shard failures, timeouts,
caps and rows past the size are named.
"""
from __future__ import annotations

import json
from fnmatch import fnmatchcase
from time import perf_counter

from romulus.agent.models import PivotCoverage, PivotResult
from romulus.agent.provider.base import redact_value
from romulus.agent.refusals import reason as refusal_reason
from romulus.agent.tools import QuerySourceRequest
from romulus.config import Settings, redact_text
from romulus.detect.registry import bind_windows_site, fresh_direct_pack
from romulus.evidence.normalize import normalize_hits
from romulus.hunt.pivot import (
    _AGENT_CAP_EXPLAINED,
    MAX_EVENT_SUMMARIES,
    MAX_SEARCH_ENTITIES,
    PivotExecutor,
    _event_entities,
    _range,
    _summary,
    _time_spread,
)
from romulus.hunt.publish import publish_match
from romulus.sources.agent_query import (
    MAX_QUERY_HITS,
    QueryRefused,
    aggregation_caveats,
    bound_aggregations,
    es_body,
    validate_es_query,
    validate_expression,
    window_seconds,
)
from romulus.sources.compile import build_query
from romulus.sources.es import SourceError, WriteAttemptBlocked, last_response_surrogate_free
from romulus.sources.models import SearchIntent, Window
from romulus.sources.packets import SESSION_ID
from romulus.store.db import digest

QUERY_PURPOSE = "agent:query_source"
ZERO_STATEMENT = "nothing matched this query in this source; this is not a confirmed absence"
# what a stored result keeps of the rows and aggregations (both untrusted telemetry, redacted before they are kept)
MAX_PREVIEW_ROWS = 20
MAX_ROW_BYTES = 2_048
MAX_STORED_TELEMETRY_BYTES = 65_536
MAX_ERROR_CHARS = 600
MAX_REASONS = 20


def _bounded(text: str, limit: int = MAX_ERROR_CHARS) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= limit else f"{text[:limit]}…[{len(text) - limit} chars omitted]"


def query_refusal(request: QuerySourceRequest, kind: str | None) -> dict | None:
    """Why the agent's query cannot be sent to the named source, decided without any source query; None when it can.
    `kind` is the source's kind from the hunt's source table (None: not one of the hunt's sources)."""
    args = request.arguments

    def refused(path: str, code: str, message: str) -> dict:
        return {"code": "query_refused", "message": message, "reasons": [refusal_reason(path, code)]}

    if kind is None:
        return refused("source", "unknown_source",
                       "that is not one of this hunt's sources; list_search_fields listing=sources names them")
    try:
        if kind == "arkime_viewer":
            if args.expression is None:
                return refused("expression", "expression_required",
                               "an Arkime viewer source takes an expression (the viewer's own query language)")
            validate_expression(args.expression)
        else:
            if args.expression is not None:
                return refused("expression", "expression_not_accepted",
                               "an index source takes a Query DSL query and aggregations, not an Arkime expression")
            validate_es_query(args.query, args.aggs, args.sort, args.size, args.source_fields,
                              window_seconds=window_seconds(args.start, args.end))
    except QueryRefused as error:
        return refused(error.path, error.code, f"{error.path}: {error}")
    return None


class SourceQueryRunner:
    """Run one validated agent query on one hunt source, through the pivot executor's client, budget and evidence
    store."""

    def __init__(self, pivot: PivotExecutor, settings: Settings | None, arkime_search=None):
        self.pivot = pivot
        self.settings = settings
        self.arkime_search = arkime_search

    # ---- helpers ------------------------------------------------------------------------------------------------
    def _redact(self, value):
        return redact_value(value, self.settings) if self.settings is not None else value

    def _redact_text(self, text: str) -> str:
        return redact_text(text, self.settings) if self.settings is not None else text

    def _spend(self, task_id: str) -> str | None:
        """Reserve one source query for this task under the agent's caps; the reason of the cap that refuses it."""
        pivot = self.pivot
        if pivot._agent_budgeted():
            return pivot._agent_reserve(task_id)
        if pivot.source_query_budget is not None and pivot.source_queries >= pivot.source_query_budget:
            return f"{pivot.source_query_scope or 'expansion'}_source_query_budget:{pivot.source_query_budget}"
        pivot.source_queries += 1
        pivot.repo.record_task_source_query(task_id, owner_token=pivot.owner_token)
        return None

    def _cell(self, target: str, args, status: str, reasons: list[str], returned: int,
              total: int | None) -> PivotCoverage:
        unresolved = [] if status == "complete" else [
            _range(args.start, args.end, "; ".join(reasons[:3]) or "query result incomplete")]
        return PivotCoverage(target=target, dataset=None, start=args.start, end=args.end, status=status,
                             reasons=sorted(set(reasons))[:MAX_REASONS], returned=returned, total=total,
                             unresolved_ranges=unresolved)

    def _failed(self, target, args, reasons, started, *, task_ids=(), query: dict | None = None) -> PivotResult:
        return PivotResult(status="failed", task_ids=list(task_ids), reasons=sorted(set(reasons)),
                           coverage=[self._cell(target, args, "failed", reasons, 0, None)],
                           duration_ms=int((perf_counter() - started) * 1000),
                           query={"negative": "unresolved", "statement": ZERO_STATEMENT, **(query or {})})

    def _search(self, target: str, body: dict) -> tuple[dict | None, str | None, str | None]:
        """(response, query error, source error): a 400 answer is the query's own error, which the model can
        correct; anything else that fails (authorization, a missing index, a timeout, an overloaded or failed source)
        is a source failure, unresolved."""
        try:
            return self.pivot.client.search(target, body), None, None
        except WriteAttemptBlocked as exc:
            return None, _bounded(self._redact_text(f"refused before sending: {exc}")), None
        except SourceError as exc:
            status = getattr(exc, "status", None)
            text = _bounded(self._redact_text(str(exc)))
            if status == 400:
                return None, text, None
            return None, None, text

    # ---- the run ------------------------------------------------------------------------------------------------
    def run(self, case_id: str, request: QuerySourceRequest, *, kind: str, target: str) -> PivotResult:
        started = perf_counter()
        args = request.arguments
        pivot = self.pivot
        contract = pivot.contracts[target]
        refusal = query_refusal(request, kind)
        if refusal is not None:      # the toolbox refuses first; a direct caller is refused here too
            return self._failed(target, args, [refusal["message"]], started,
                                query={"query_error": refusal["message"]})
        available = pivot.agent_available()
        if available is not None and available[0] == 0:
            cap = available[1]
            explained = (f"{_AGENT_CAP_EXPLAINED.get(cap.split(':', 1)[0], 'the source-query budget is spent')}: "
                         "nothing was queried, and no record was found or ruled out")
            return self._failed(target, args, [cap, explained], started)
        fingerprint = digest({"case_id": case_id, "tool": request.model_dump(mode="json")})
        task_id = "t-" + fingerprint[:20]
        pivot.repo.upsert_task(task_id, pivot.hunt_id, "pivot", case_id, {
            "purpose": QUERY_PURPOSE, "source": args.source, "target": target,
            "start": args.start.isoformat(), "end": args.end.isoformat(), "request_digest": fingerprint,
        }, fingerprint, owner_token=pivot.owner_token)
        pivot.repo.update_task(task_id, "leased", attempt=True, owner_token=pivot.owner_token)
        window = Window(start=args.start, end=args.end)
        window_clause = build_query(SearchIntent(kind="raw", target=target, window=window), contract)["bool"]["filter"][0]
        reasons: list[str] = []
        viewer: dict | None = None
        if kind == "arkime_viewer":
            ids, viewer, stop = self._viewer_ids(task_id, args)
            if stop is not None:
                return self._finish_failed(task_id, target, args, started, stop)
            if not ids:
                return self._finish(task_id, target, args, started, response=None, reasons=viewer["reasons"],
                                    viewer=viewer)
            body = es_body({"ids": {"values": ids}}, None, None, min(len(ids), MAX_QUERY_HITS),
                           window_clause=window_clause, time_field=contract.time_field)
            reasons.extend(viewer["reasons"])
        else:
            body = es_body(args.query, args.aggs, args.sort, args.size, window_clause=window_clause,
                           time_field=contract.time_field)
        cap = self._spend(task_id)
        if cap is not None:
            return self._finish_failed(task_id, target, args, started, {
                "reasons": [cap, "the agent's source-query cap is reached: the source was not queried"]},
                viewer=viewer)
        response, query_error, source_error = self._search(target, body)
        if query_error is not None:
            return self._finish_failed(task_id, target, args, started, {
                "reasons": [f"the source refused the query: {query_error}"], "query_error": query_error},
                viewer=viewer)
        if source_error is not None:
            return self._finish_failed(task_id, target, args, started, {
                "reasons": [f"the source query failed (timed out or the source failed): {source_error}"]},
                viewer=viewer)
        return self._finish(task_id, target, args, started, response=response, reasons=reasons, viewer=viewer,
                            case_id=case_id, requested_ids=len(viewer["ids"]) if viewer else None)

    def _viewer_ids(self, task_id: str, args) -> tuple[list[str], dict, dict | None]:
        """The session ids the viewer's expression search returns, spending one source query. Arkime's session id
        is the session record's _id in its index (the packet stage fetches packets by that _id)."""
        if self.arkime_search is None:
            return [], {}, {"reasons": ["no Arkime viewer client is configured for agent queries"]}
        cap = self._spend(task_id)
        if cap is not None:
            return [], {}, {"reasons": [cap, "the agent's source-query cap is reached: the viewer was not queried"]}
        found = self.arkime_search.search(args.expression, args.start, args.end, MAX_QUERY_HITS)
        if found.query_error is not None:
            text = _bounded(self._redact_text(found.query_error))
            return [], {}, {"reasons": [f"the viewer refused the expression: {text}"], "query_error": text}
        if found.error is not None:
            return [], {}, {"reasons": [f"the viewer search failed: {_bounded(self._redact_text(found.error))}"]}
        # the viewer can name a session as <n>@<id> (the session's _id after a cluster ordinal); the index knows the _id
        ids = [item for item in dict.fromkeys(_session_record_id(raw) for raw in found.ids)
               if item is not None and SESSION_ID.fullmatch(item)]
        reasons = []
        unusable = len(found.ids) - len(ids)
        if unusable:
            reasons.append(f"{unusable} viewer result(s) without a usable session id were not read")
        if found.matched is None:
            reasons.append("the viewer did not say how many sessions matched")
        elif found.matched > len(found.ids):
            reasons.append(f"the viewer matched {found.matched} sessions; the first {len(found.ids)} were read")
        return ids, {"ids": ids, "matched": found.matched, "reasons": reasons}, None

    def _finish_failed(self, task_id, target, args, started, stop: dict, viewer=None) -> PivotResult:
        self.pivot.repo.update_task(task_id, "failed", outcome={"completeness": "failed", "reasons": stop["reasons"]},
                                    error=stop["reasons"][0], owner_token=self.pivot.owner_token)
        query = {key: stop[key] for key in ("query_error",) if key in stop}
        if viewer:
            query["viewer"] = {"matched": viewer.get("matched"), "ids_read": len(viewer.get("ids") or [])}
        return self._failed(target, args, stop["reasons"], started, task_ids=[task_id], query=query)

    def _finish(self, task_id: str, target: str, args, started: float, *, response: dict | None,
                reasons: list[str], viewer: dict | None, case_id: str | None = None,
                requested_ids: int | None = None) -> PivotResult:
        pivot = self.pivot
        contract = pivot.contracts[target]
        reasons = list(reasons)
        hits_block = (response or {}).get("hits") or {}
        records = [hit for hit in hits_block.get("hits") or []
                   if isinstance(hit, dict) and isinstance(hit.get("_id"), str)
                   and isinstance(hit.get("_source"), dict) and isinstance(hit.get("_index"), str)]
        total_block = hits_block.get("total")
        total = total_block.get("value") if isinstance(total_block, dict) else total_block
        relation = total_block.get("relation", "eq") if isinstance(total_block, dict) else "eq"
        total = int(total) if isinstance(total, int) and not isinstance(total, bool) else None
        if response is not None and response.get("timed_out"):
            reasons.append("the source timed out: its answer holds what it read before the timeout")
        if response is not None and response.get("terminated_early"):
            reasons.append("the source stopped early at its per-shard document cap: counts and aggregations are "
                           "partial")
        if relation != "eq":
            reasons.append(f"more than {total} records matched (the count stops there)")
        if total is not None and total > len(records) and args.size > 0:
            reasons.append(f"{total}{'+' if relation != 'eq' else ''} records matched; the first {len(records)} "
                           "were returned (size)")
        if response is not None and response.get("aggregations") is not None:
            # a top N with other values left out is not the whole answer
            reasons.extend(aggregation_caveats(response["aggregations"]))
        if response is not None and contract.temporal_gaps:
            # what the source's own clock or query time cannot show, as every pivot on this source names it
            reasons.extend(contract.temporal_gaps)
        if requested_ids is not None and len(records) < requested_ids:
            reasons.append(f"{requested_ids - len(records)} viewer session(s) are not records of this source in the "
                           "window: not shown")
        options = {"contract": contract} if contract.zeek_sensor else {}
        events, skips, errors = normalize_hits(records, surrogate_free=last_response_surrogate_free(), **options)
        skipped = sum(count for count in skips.values() if count)
        if skipped:
            reasons.append(f"{skipped} returned record(s) no normalizer reads: shown in the preview, not citable")
        if errors:
            reasons.append(f"normalization_errors:{len(errors)}")
        raw_sources = {f"{record['_index']}/{record['_id']}": record["_source"] for record in records}
        pivot._save_selected_events(events, raw_sources, {event.id: task_id for event in events}, [task_id])
        candidate_ids: list[str] = []
        for playbook in bind_windows_site(fresh_direct_pack(), pivot.site_facts):
            for match in playbook.consume(events):
                row = publish_match(pivot.repo, pivot.hunt_id, playbook, match, task_id, raw_sources,
                                    source_case_id=case_id, owner_token=pivot.owner_token, zeek_context=events)
                if row is not None:
                    candidate_ids.append(row["id"])
        unique = {event.id: event for event in events}
        entities = {(entity.kind, entity.value, entity.role): entity
                    for event in unique.values() for entity in _event_entities(event)}
        if len(entities) > MAX_SEARCH_ENTITIES:
            reasons.append(f"query_entities_listed:{MAX_SEARCH_ENTITIES}:of:{len(entities)}")
            entities = {key: entities[key] for key in sorted(entities)[:MAX_SEARCH_ENTITIES]}
        status = "complete" if not reasons else "partial"
        found = bool(records) or bool(total)
        telemetry, cut = self._telemetry(records, (response or {}).get("aggregations"), unique, args)
        if cut:
            reasons.append(cut)
            status = "partial"
        sampled = _time_spread(list(unique.values()), MAX_EVENT_SUMMARIES, None)
        pivot.repo.update_task(task_id, "executed", outcome={
            "completeness": status, "reasons": sorted(set(reasons))[:MAX_REASONS], "total": total,
            "returned": len(records)}, owner_token=pivot.owner_token)
        pivot.repo.update_task(task_id, "evaluated", owner_token=pivot.owner_token)
        query = {"negative": "matches_found" if found else "unresolved",
                 "statement": None if found else ZERO_STATEMENT,
                 "total": {"value": total, "relation": relation}, "returned": len(records),
                 "telemetry_json": telemetry}
        if viewer is not None:
            query["viewer"] = {"matched": viewer.get("matched"), "ids_read": len(viewer.get("ids") or [])}
        return PivotResult(
            status=status, task_ids=[task_id], event_ids=[event.id for event in sampled],
            reach_event_ids=sorted(unique), candidate_ids=candidate_ids, entities=list(entities.values()),
            event_summaries=[_summary(event) for event in sampled], matched_event_count=len(unique),
            coverage=[self._cell(target, args, status, reasons, len(records), total)],
            reasons=sorted(set(reasons)), duration_ms=int((perf_counter() - started) * 1000), query=query)

    def _telemetry(self, records: list[dict], aggregations, events: dict, args) -> tuple[str, str | None]:
        """The redacted, bounded JSON text of the rows (at most MAX_PREVIEW_ROWS, each cut to MAX_ROW_BYTES, showing
        the fields the model asked for) and the aggregations (bucket lists cut and counted), at most
        MAX_STORED_TELEMETRY_BYTES; and why anything was cut."""
        by_record: dict[str, list[str]] = {}
        for event in events.values():
            for ref in event.raw:
                by_record.setdefault(f"{ref.target}/{ref.native_id}", []).append(event.id)
        rows = []
        for record in records[:MAX_PREVIEW_ROWS]:
            source = record["_source"]
            if args.source_fields:
                source = _select(source, args.source_fields)
            text = json.dumps(self._redact(source), ensure_ascii=False, sort_keys=True, default=str)
            # whether a normalizer read this row: its evidence alias is then in the result's evidence
            row = {"index": record["_index"], "id": record["_id"],
                   "citable": bool(by_record.get(f"{record['_index']}/{record['_id']}"))}
            if len(text.encode("utf-8")) > MAX_ROW_BYTES:
                row["source_text"] = text.encode("utf-8")[:MAX_ROW_BYTES].decode("utf-8", errors="ignore")
                row["source_cut"] = True
            else:
                row["source"] = json.loads(text)
            rows.append(row)
        notes = []
        if len(records) > MAX_PREVIEW_ROWS:
            beyond = records[MAX_PREVIEW_ROWS:]
            cited = sum(1 for record in beyond if by_record.get(f"{record['_index']}/{record['_id']}"))
            notes.append(f"{len(beyond)} returned row(s) are not in the preview; {cited} of them were normalized and "
                         f"are in evidence, {len(beyond) - cited} were not and are not citable")
        bounded, buckets_cut = bound_aggregations(self._redact(aggregations)) if aggregations is not None else (None, 0)
        if buckets_cut:
            notes.append(f"{buckets_cut} aggregation bucket(s) not shown")
        body = {"rows": rows, "aggregations": bounded}
        text = json.dumps(body, ensure_ascii=False, sort_keys=True, default=str)
        if len(text.encode("utf-8")) > MAX_STORED_TELEMETRY_BYTES:
            text = text.encode("utf-8")[:MAX_STORED_TELEMETRY_BYTES].decode("utf-8", errors="ignore")
            notes.append(f"the rows and aggregations were cut at {MAX_STORED_TELEMETRY_BYTES} bytes")
        return text, "; ".join(notes) or None


def _session_record_id(raw) -> str | None:
    """The session record's _id in its index for an id the Arkime viewer returned: the viewer may prefix it with a
    numeric ordinal and @ (3@241118-AbC… names the record 241118-AbC…)."""
    if not isinstance(raw, str):
        return None
    ordinal, separator, rest = raw.partition("@")
    return rest if separator and ordinal.isdigit() and rest else raw


def _select(source: dict, patterns: list[str]) -> dict:
    """The fields of a record whose dotted names match any of the patterns."""
    out: dict = {}

    def walk(node, prefix: str) -> None:
        if isinstance(node, dict) and node:
            for key, child in node.items():
                walk(child, f"{prefix}{key}.")
            return
        name = prefix[:-1]
        if any(fnmatchcase(name, pattern) for pattern in patterns):
            out[name] = node

    walk(source, "")
    return out

