"""Bounded read models and live activity for the AI investigation views."""
from __future__ import annotations

import json
import sqlite3
import tempfile
from collections import defaultdict
from pathlib import Path
from urllib.parse import quote, urlencode

from sqlalchemy import func, select, tuple_

from romulus.report.manifest import _ai_assessment
from romulus.store import schema as t

PAGE_SIZE = 50


def clip(value, limit=600):
    value = str(value or "")
    return value if len(value) <= limit else value[:limit] + " … [truncated]"


def json_text(value, limit=2048):
    # iterencode stops before serializing an arbitrarily large persisted value.
    chunks, size = [], 0
    for chunk in json.JSONEncoder(ensure_ascii=False, sort_keys=True, default=str).iterencode(value):
        encoded = chunk.encode("utf-8")
        room = limit - size
        chunks.append(encoded[:room].decode("utf-8", errors="ignore"))
        size += len(encoded)
        if size > limit:
            return "".join(chunks) + " … [truncated]"
    return "".join(chunks)


def href(hunt_id, suffix=""):
    return "/hunts/" + quote(hunt_id, safe="") + suffix


def page_rows(repo, table, hunt_id, *, after="", limit=PAGE_SIZE, predicates=(), columns=None):
    """ID-keyset pagination with an exact remaining count; no offset or full-table Python read."""
    where = (table.c.hunt_id == hunt_id, *predicates, table.c.id > after)
    with repo.engine.connect() as connection:
        rows = [dict(row) for row in connection.execute(select(*(columns or (table,))).where(*where)
            .order_by(table.c.id).limit(limit)).mappings()]
        remaining = int(connection.execute(select(func.count()).select_from(table).where(
            table.c.hunt_id == hunt_id, *predicates, table.c.id > (rows[-1]["id"] if rows else after)
        )).scalar_one()) if rows else 0
    return rows, remaining, rows[-1]["id"] if rows and remaining else None


def counts(repo, hunt_id):
    tables = {"hypotheses": t.agent_hypothesis, "findings": t.candidate, "links": t.agent_link,
              "notes": t.agent_note, "requests": t.agent_rule_request}
    with repo.engine.connect() as connection:
        return {name: int(connection.execute(select(func.count()).select_from(table).where(
            table.c.hunt_id == hunt_id, *([table.c.provenance == "agent"] if name == "findings" else [])
        )).scalar_one()) for name, table in tables.items()}


def resolved_cite(repo, hunt_id, cite):
    if not isinstance(cite, dict):
        return {"label": "unresolved cite", "url": None}
    kind = cite.get("kind") or cite.get("target_kind")
    row_id = cite.get("id") or cite.get("target_id")
    if not isinstance(row_id, str) or len(row_id) > 512:
        return {"label": "unresolved cite", "url": None}
    with repo.engine.connect() as connection:
        if kind in {"F", "finding"}:
            found = connection.execute(select(t.candidate.c.id).where(
                t.candidate.c.hunt_id == hunt_id, t.candidate.c.id == row_id)).scalar_one_or_none()
            if found:
                return {"label": clip(found, 160), "url": "/findings/" + quote(found, safe="")}
        elif kind in {"E", "evidence"}:
            candidate = connection.execute(select(t.candidate_event.c.candidate_id).where(
                t.candidate_event.c.hunt_id == hunt_id, t.candidate_event.c.event_id == row_id
            ).order_by(t.candidate_event.c.candidate_id).limit(1)).scalar_one_or_none()
            if candidate and repo.citation_events(hunt_id, [row_id]):
                return {"label": clip(row_id, 160), "url": "/findings/" + quote(candidate, safe="")
                        + "?" + urlencode({"event": row_id}) + "#evidence-" + quote(row_id, safe="")}
    return {"label": "unresolved cite", "url": None}


def cites_view(repo, hunt_id, cites, limit=20):
    return [resolved_cite(repo, hunt_id, cite) for cite in (cites or [])[:limit]]


def assessment_view(repo, hunt_id):
    assessment = _ai_assessment(repo, hunt_id, stored_only=True)
    if not assessment:
        return None
    result = {**assessment, "header": clip(assessment["header"], 1000), "sections": []}
    body = assessment.get("body") or {}
    sections = [(name, body.get(name, [])) for name in
                ("overall", "key_steps", "alternatives", "gaps", "next_checks")]
    sections.append(("confidence reasons", (body.get("confidence") or {}).get("reasons", [])))
    for name, items in sections:
        sentences = []
        for item in items[:30]:
            sentence = item.get("sentence", item)
            sentences.append({"text": clip(sentence.get("text"), 2000), "kind": clip(sentence.get("kind"), 50),
                              "cites": cites_view(repo, hunt_id, sentence.get("cites")),
                              "cites_more": max(0, len(sentence.get("cites") or []) - 20)})
        if sentences:
            result["sections"].append({"name": name.replace("_", " "), "sentences": sentences,
                                       "more": max(0, len(items) - 30)})
    confidence = body.get("confidence") or {}
    result["confidence"] = clip(confidence.get("overall"), 100)
    result["checker_text"] = json_text(assessment.get("checker") or {})
    return result


def panel(repo, hunt, usage):
    run = repo.agent_run(hunt["id"])
    if run is None:
        return None
    configured = hunt["manifest"].get("ai_agent") or {}
    provider = run.get("provider") or configured
    reason = str(run.get("reason") or "")
    limit_items = [clip(item.strip(), 200) for item in reason.split(";")[:100]
                   if item.strip().startswith(("cap:", "budget:"))]
    summary = repo.latest_audit(hunt["id"], "hunt.ai_agent_summary")
    limit_items.extend(clip(item, 200) for item in ((summary or {}).get("detail") or {}).get("limits_hit", [])[:100])
    return {"run": run, "state": "interrupted (lease expired)" if run["state"] == "running"
            and not repo.agent_lease_live(hunt["id"]) else run["state"],
            "reason": clip(reason, 2000), "provider": clip(provider.get("provider"), 200),
            "model": clip(provider.get("model") or provider.get("model_requested"), 300),
            "usage": usage, "budgets": configured.get("budgets") or provider.get("budgets") or {},
            "source_queries": repo.agent_source_queries(hunt["id"]),
            "wall_seconds": repo.agent_elapsed_ms(hunt["id"]) / 1000,
            "limits": sorted(set(limit_items)), "counts": counts(repo, hunt["id"]),
            "assessment": assessment_view(repo, hunt["id"]),
            "refusal": repo.agent_reassessment_refusal(hunt["id"])}


def hypotheses_page(repo, hunt_id, after=""):
    rows, remaining, cursor = page_rows(repo, t.agent_hypothesis, hunt_id, after=after)
    ids = [row["id"] for row in rows]
    totals = defaultdict(dict)
    with repo.engine.connect() as connection:
        for hid, role, count in connection.execute(select(t.agent_hypothesis_cite.c.hypothesis_id,
                t.agent_hypothesis_cite.c.role, func.count()).where(t.agent_hypothesis_cite.c.hunt_id == hunt_id,
                t.agent_hypothesis_cite.c.hypothesis_id.in_(ids)).group_by(
                    t.agent_hypothesis_cite.c.hypothesis_id, t.agent_hypothesis_cite.c.role)):
            totals[hid][role] = count
        for row in rows:
            row["cite_counts"] = totals[row["id"]]
            row["statement"] = clip(row["statement"], 300)
            entity_ids = row.get("entity_ids") or []
            row["entity_names"] = [clip(value, 200) for value in connection.execute(select(t.entity.c.value).where(
                t.entity.c.hunt_id == hunt_id, t.entity.c.id.in_(entity_ids[:50])).limit(50)).scalars()]
            row["entities_more"] = max(0, len(entity_ids) - 50)
    return rows, remaining, cursor


def validate_hypothesis_links(repo, hunt_id, rows):
    ids = {row.get("agent_hypothesis_id") for row in rows if row.get("agent_hypothesis_id")}
    with repo.engine.connect() as connection:
        found = set(connection.execute(select(t.agent_hypothesis.c.id).where(
            t.agent_hypothesis.c.hunt_id == hunt_id, t.agent_hypothesis.c.id.in_(ids))).scalars())
    for row in rows:
        if row.get("agent_hypothesis_id") not in found:
            row["agent_hypothesis_id"] = None


def hypothesis_cites(repo, hunt_id, hid, after=""):
    try:
        cursor = json.loads(after) if after else ["", "", ""]
        if not isinstance(cursor, list) or len(cursor) != 3 or any(not isinstance(value, str) for value in cursor):
            raise ValueError("Invalid cite cursor")
    except (ValueError, TypeError) as error:
        raise ValueError("Invalid cite cursor") from error
    table = t.agent_hypothesis_cite
    key = tuple_(table.c.role, table.c.target_kind, table.c.target_id)
    where = (table.c.hunt_id == hunt_id, table.c.hypothesis_id == hid, key > tuple(cursor))
    with repo.engine.connect() as connection:
        rows = [dict(row) for row in connection.execute(select(table).where(*where)
            .order_by(table.c.role, table.c.target_kind, table.c.target_id).limit(PAGE_SIZE)).mappings()]
        last = [rows[-1][name] for name in ("role", "target_kind", "target_id")] if rows else cursor
        more = int(connection.execute(select(func.count()).select_from(table).where(
            table.c.hunt_id == hunt_id, table.c.hypothesis_id == hid, key > tuple(last))).scalar_one())
    return [{**row, "resolved": resolved_cite(repo, hunt_id, row)} for row in rows], more, json.dumps(last)


def _event(name, payload):
    return "event: " + name + "\ndata: " + json.dumps(payload, default=str) + "\n\n"


async def live_events(repo, request, hunt_id, sleep):
    # Finding IDs outlive every memory bound: retain connection-local revision state on disk.
    with tempfile.TemporaryDirectory(prefix="romulus-stream-") as scratch:
        seen = sqlite3.connect(Path(scratch) / "seen.sqlite")
        seen.execute("PRAGMA cache_size=-256")
        seen.execute("CREATE TABLE seen (id TEXT PRIMARY KEY)")
        cursor, end_seq, last_run = 0, None, None
        try:
            while not await request.is_disconnected():
                hunt = repo.get_hunt(hunt_id)
                if hunt is None:
                    yield _event("end", {})
                    return
                run = repo.agent_run(hunt_id)
                terminal = hunt["execution_state"] not in {"planned", "running"} and (
                    not run or run["state"] not in {"pending", "running"})
                if terminal and end_seq is None:
                    end_seq = repo.agent_change_max_seq(hunt_id)
                changes = repo.agent_change_page(hunt_id, after_seq=cursor, limit=200)
                grouped = defaultdict(list)
                for change in changes:
                    grouped[change["kind"]].append(change["row_id"])
                rows = {kind: repo.agent_change_rows(hunt_id, kind, list(dict.fromkeys(ids)))
                        for kind, ids in grouped.items()}
                emitted = set()
                for change in changes:
                    kind, row_id = change["kind"], change["row_id"]
                    if (kind, row_id) in emitted:
                        continue
                    emitted.add((kind, row_id))
                    row = rows[kind].get(row_id)
                    if not row:
                        continue
                    if kind == "finding":
                        if row["lane"] not in {"urgent", "high", "lead"}:
                            continue
                        revised = seen.execute("SELECT 1 FROM seen WHERE id=?", (row_id,)).fetchone() is not None
                        seen.execute("INSERT OR IGNORE INTO seen VALUES (?)", (row_id,))
                        payload = {"id": row_id, "lane": row["lane"], "rule": row["rule_id"],
                                   "claim": row["claim"][:300], "ts": str(row["ts"]), "revised": revised}
                        if row.get("provenance") == "agent":
                            payload["provenance"] = "agent"
                        yield _event("finding", payload)
                        if row.get("provenance") == "agent":
                            yield _event("agent_finding", payload)
                    elif kind == "run":
                        current_run = (row["state"], clip(row.get("reason"), 600))
                        if current_run != last_run:
                            last_run = current_run
                            yield _event("agent_run", {"state": current_run[0], "reason": current_run[1]})
                    elif kind == "hypothesis":
                        yield _event("hypothesis", {"id": row_id, "status": row["status"],
                            "confidence": row["confidence"], "statement": row["statement"][:300]})
                    elif kind == "session":
                        yield _event("session", {key: row[key] for key in ("id", "purpose", "state", "tool_calls")})
                    elif kind == "tool_call":
                        yield _event("tool_call", {"session": row["session_id"], "seq": row["seq"],
                                                   "name": clip(row["name"], 100), "status": row["status"]})
                if changes:
                    cursor = changes[-1]["seq"]
                    seen.commit()
                # Deletion may have raced the bounded reads above.
                if repo.get_hunt(hunt_id) is None:
                    yield _event("end", {})
                    return
                yield _event("state", {"state": hunt["execution_state"], "lanes": repo.lane_counts(hunt_id)})
                if end_seq is not None and cursor >= end_seq:
                    yield _event("end", {})
                    return
                if len(changes) < 200:
                    await sleep(2)
        finally:
            seen.close()
