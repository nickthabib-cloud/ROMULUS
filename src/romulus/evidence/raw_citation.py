"""Raw records the AI agent can cite: a source record that no normalizer read.

A record the agent's own source query returns, and that no normalizer turns into a typed event, can still be cited
the way an analyst cites a log line. It is kept as text: its source reference (index and record id, or the Arkime
session id), its time when the source's time field holds one, the cleaned and redacted record bounded per record (cut
and marked past the bound), a digest of the record as the source returned it, and where it came from (the agent
session, the task and the query). Nothing is extracted from it: it has no typed fields and no detection rule ran on
it, so it shows only that a record with this text exists. A command line or an address inside it is a mention, never
an action.
"""
from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime

from romulus.store.cleaning import clean_source
from romulus.store.db import digest

RAW_LABEL = "raw record, not normalized: no typed fields were extracted and no detection rule ran on it"
RAW_LABEL_PLURAL = ("raw records, not normalized: no typed fields were extracted and no detection rule ran on them; "
                    "each shows only that a record with this text exists, not that an action happened")
# what one stored raw record keeps of its (cleaned, redacted) source text, and of the query that returned it
MAX_RAW_TEXT_BYTES = 16_384
MAX_RAW_QUERY_CHARS = 2_000
MAX_TIME_TEXT = 64
RAW_ID_PREFIX = "rr-"
# the admission-gate key an AI finding lists its cited raw record ids under (never in its typed event ids)
RAW_GATE = "_agent_raw_records"
SOURCE_KINDS = ("index", "arkime_session")


def raw_record_id(hunt_id: str, target: str, native_id: str) -> str:
    """One stable id per hunt and source record: the same record returned again keeps its row and alias."""
    material = json.dumps([hunt_id, target, native_id], separators=(",", ":"))
    return RAW_ID_PREFIX + hashlib.sha256(material.encode()).hexdigest()[:24]


def _bounded_bytes(text: str, limit: int) -> tuple[str, bool]:
    encoded = text.encode("utf-8")
    if len(encoded) <= limit:
        return text, False
    return encoded[:limit].decode("utf-8", errors="ignore"), True


def _field(source: dict, name: str):
    """A dotted field's value, nested or flat (both spellings occur in shipped records)."""
    if name in source:
        return source[name]
    node = source
    for part in name.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def record_time(source: dict, time_field: str | None) -> tuple[datetime | None, str | None]:
    """(time in UTC, the value as the record holds it, bounded) from the source's time field; (None, None) when the
    record has none. A value that is not an RFC 3339 time or epoch milliseconds keeps its text and no time."""
    if not time_field:
        return None, None
    value = _field(source, time_field)
    if isinstance(value, list) and len(value) == 1:
        value = value[0]
    if value is None or isinstance(value, (dict, list, bool)):
        return None, None
    text = str(value)[:MAX_TIME_TEXT]
    moment = None
    if isinstance(value, (int, float)):
        try:
            moment = datetime.fromtimestamp(value / 1000, tz=UTC)
        except (OverflowError, OSError, ValueError):
            moment = None
    elif isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00").replace("z", "+00:00"))
        except ValueError:
            parsed = None
        if parsed is not None:
            moment = parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)
    return moment, text


def build_raw_record(hunt_id: str, hit: dict, *, source_kind: str, time_field: str | None, session_id: str | None,
                     task_id: str | None, query_digest: str, query_text: str, redact, flagged) -> dict:
    """The stored row for one returned record (`hit` has _index, _id and _source). `redact` removes configured
    secrets from a JSON-like value; `flagged` says whether a value carries instruction-shaped text. The digest is of
    the record as the source returned it; the text kept is cleaned (recognized credentials masked) and redacted."""
    if source_kind not in SOURCE_KINDS:
        raise ValueError(f"unknown raw record source kind {source_kind}")
    source = hit["_source"]
    full = json.dumps(redact(clean_source(source)), ensure_ascii=False, sort_keys=True, default=str)
    text, cut = _bounded_bytes(full, MAX_RAW_TEXT_BYTES)
    ts, time_text = record_time(source, time_field)
    query = query_text if len(query_text) <= MAX_RAW_QUERY_CHARS else query_text[:MAX_RAW_QUERY_CHARS] + "…"
    return {
        "id": raw_record_id(hunt_id, hit["_index"], hit["_id"]), "hunt_id": hunt_id,
        "target": hit["_index"], "native_id": hit["_id"], "source_kind": source_kind,
        "ts": ts, "time_field": time_field, "time_text": time_text,
        "text": text, "text_cut": cut, "text_bytes": len(full.encode("utf-8")),
        "digest": digest(source), "session_id": session_id, "task_id": task_id,
        "query_digest": query_digest, "query": query, "suspicious_content": bool(flagged(full)),
    }


def raw_record_view(row: dict, *, text: bool = True) -> dict:
    """What every renderer shows of a stored raw record: its label, source reference, time, digest, provenance and
    (with `text`) the bounded text, marked when it was cut. The text is untrusted telemetry: a renderer escapes it."""
    ts = row.get("ts")
    if isinstance(ts, datetime):
        ts = (ts.replace(tzinfo=UTC) if ts.tzinfo is None else ts.astimezone(UTC)).isoformat().replace("+00:00", "Z")
    view = {
        "id": row["id"], "kind": "raw_record", "label": RAW_LABEL,
        "source_kind": row["source_kind"], "target": row["target"], "native_id": row["native_id"],
        "time": ts, "time_field": row.get("time_field"), "time_text": row.get("time_text"),
        "digest": row["digest"], "text_bytes": row["text_bytes"], "text_cut": bool(row["text_cut"]),
        "session_id": row.get("session_id"), "task_id": row.get("task_id"), "query_digest": row["query_digest"],
        "suspicious_content": bool(row.get("suspicious_content")),
    }
    if text:
        # the redacted query that returned it, and the record's text: both untrusted, both escaped by renderers
        view["query"] = row.get("query") or ""
        view["text"] = row["text"]
        if row["text_cut"]:
            view["text_note"] = (f"cut at {MAX_RAW_TEXT_BYTES} bytes of {row['text_bytes']}; the source keeps the "
                                 "whole record")
    return view
