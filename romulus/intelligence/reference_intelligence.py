"""Bounded, score-neutral consumers for capability reference intelligence."""
from __future__ import annotations

import copy
from collections.abc import Iterable
from typing import Any


def _basename(value: Any) -> str:
    text = str(value or "").strip().lower().replace("\\", "/")
    return text.rsplit("/", 1)[-1]


def compile_capability_index(records: Iterable[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Index validated capability references by exact executable basename."""
    result: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        if not isinstance(record, dict) or record.get("record_type") != "source_capability_reference":
            continue
        executable = _basename((record.get("source_metadata") or {}).get("executable"))
        if not executable:
            for observable in record.get("observables", []) or []:
                if not isinstance(observable, dict) or observable.get("role") != "process.name":
                    continue
                values = observable.get("values") or []
                executable = _basename(values[0]) if values else ""
                if executable:
                    break
        if executable:
            result.setdefault(executable, []).append(record)
    return {key: sorted(value, key=lambda row: str(row.get("id", ""))) for key, value in sorted(result.items())}


def _nested(value: dict[str, Any], path: str) -> Any:
    current: Any = value
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _event_executables(event: dict[str, Any]) -> set[str]:
    values: set[str] = set()
    raw = event.get("raw") if isinstance(event.get("raw"), dict) else {}
    for field in ("process.name", "process.executable", "winlog.event_data.Image", "exe"):
        for source in (raw, event):
            observed = _nested(source, field)
            if observed is None and isinstance(source, dict):
                observed = source.get(field)
            for item in observed if isinstance(observed, list) else [observed]:
                name = _basename(item)
                if name:
                    values.add(name)
    return values


def attach_capability_context(
    candidates: list[dict[str, Any]],
    evidence: list[dict[str, Any]],
    index: dict[str, list[dict[str, Any]]],
    limit: int = 5,
) -> list[dict[str, Any]]:
    """Attach cited reference context without changing detection or scoring fields."""
    bounded = max(0, min(int(limit), 20))
    by_id = {str(row.get("evidence_id")): row for row in evidence if row.get("evidence_id")}
    enriched: list[dict[str, Any]] = []
    for source_candidate in candidates:
        candidate = copy.deepcopy(source_candidate)
        matches: dict[str, dict[str, Any]] = {}
        for evidence_id in candidate.get("evidence_ids", []) or []:
            event = by_id.get(str(evidence_id))
            if not event:
                continue
            for executable in sorted(_event_executables(event)):
                for reference in index.get(executable, []):
                    reference_id = str(reference.get("id") or "")
                    if not reference_id:
                        continue
                    context = matches.setdefault(reference_id, {
                        "reference_id": reference_id,
                        "title": reference.get("title"),
                        "executable": executable,
                        "function": (reference.get("source_metadata") or {}).get("function"),
                        "sources": list(reference.get("source_refs") or []),
                        "source_url": reference.get("source_url"),
                        "attack_techniques": list(reference.get("attack_techniques") or []),
                        "evidence_ids": [],
                    })
                    if evidence_id not in context["evidence_ids"]:
                        context["evidence_ids"].append(evidence_id)
        candidate["capability_context"] = sorted(matches.values(), key=lambda row: row["reference_id"])[:bounded]
        enriched.append(candidate)
    return enriched
