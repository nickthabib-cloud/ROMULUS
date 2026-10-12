"""Persistent, deterministic scheduling primitives for evidence searches."""

from __future__ import annotations

import copy
import hashlib
import json
from collections.abc import Mapping, MutableMapping
from typing import Any


_SOURCES = {"elasticsearch", "arkime", "tshark"}
_SOURCE_FAMILIES = {"host", "network"}
_PHASES = {"discovery", "investigation"}
_ORIGINS = {
    "behavior_catalog",
    "trusted_indicator",
    "directed_survey",
    "candidate_follow_up",
    "model_proposal",
    "coverage_frontier",
}
_OWNER_FIELDS = (
    "candidate_ids",
    "follow_up_ids",
    "hypothesis_ids",
    "anchor_evidence_ids",
)
_HISTORY_LIMIT = 500


def initialize_scheduler(state: MutableMapping[str, Any]) -> None:
    """Add scheduler collections to a serializable hunt state in place."""

    if not isinstance(state, MutableMapping):
        raise TypeError("scheduler state must be a mutable mapping")
    defaults = {
        "search_tasks": {},
        "search_queue": [],
        "search_outcomes": [],
        "scheduler_history": [],
    }
    for field, default in defaults.items():
        if field not in state:
            state[field] = copy.deepcopy(default)
        elif not isinstance(state[field], type(default)):
            raise ValueError(f"scheduler state field {field!r} has the wrong type")


def _normalized(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _normalized(value[key]) for key in sorted(value, key=str)}
    if isinstance(value, (list, tuple)):
        return [_normalized(item) for item in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise ValueError(f"search task values must be JSON-serializable, got {type(value).__name__}")


def _required_text(proposal: Mapping[str, Any], field: str) -> str:
    value = proposal.get(field)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"search task requires non-empty {field}")
    return value.strip()


def _validated_execution(proposal: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(proposal, Mapping):
        raise TypeError("search task proposal must be a mapping")

    source = _required_text(proposal, "source").lower()
    source_family = _required_text(proposal, "source_family").lower()
    phase = _required_text(proposal, "phase").lower()
    origin = _required_text(proposal, "origin").lower()
    if source not in _SOURCES:
        raise ValueError(f"unsupported search source: {source}")
    if source_family not in _SOURCE_FAMILIES:
        raise ValueError(f"unsupported search source family: {source_family}")
    if phase not in _PHASES:
        raise ValueError(f"unsupported search phase: {phase}")
    if origin not in _ORIGINS:
        raise ValueError(f"unsupported search origin: {origin}")

    targets = proposal.get("source_targets")
    if not isinstance(targets, (list, tuple)) or not targets:
        raise ValueError("search task requires at least one source target")
    normalized_targets = sorted({_required_list_text(item, "source_targets") for item in targets})

    query_spec = proposal.get("query_spec")
    time_range = proposal.get("time_range")
    if not isinstance(query_spec, Mapping) or not query_spec:
        raise ValueError("search task requires a non-empty query_spec mapping")
    if not isinstance(time_range, Mapping) or not time_range:
        raise ValueError("search task requires a non-empty time_range mapping")

    return {
        "source": source,
        "source_family": source_family,
        "source_targets": normalized_targets,
        "phase": phase,
        "origin": origin,
        "query_spec": _normalized(query_spec),
        "time_range": _normalized(time_range),
    }


def _required_list_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"search task {field} entries must be non-empty strings")
    return value.strip()


def _fingerprint_payload(proposal: Mapping[str, Any]) -> dict[str, Any]:
    execution = _validated_execution(proposal)
    return {
        "source": execution["source"],
        "source_family": execution["source_family"],
        "source_targets": execution["source_targets"],
        "query_spec": execution["query_spec"],
        "time_range": execution["time_range"],
    }


def execution_fingerprint(proposal: Mapping[str, Any]) -> str:
    """Return the stable identity of what will actually execute."""

    canonical = json.dumps(
        _fingerprint_payload(proposal),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest().upper()


def _priority_for(proposal: Mapping[str, Any], origin: str) -> tuple[int, int]:
    if origin == "trusted_indicator":
        return 1, 1000
    if origin == "candidate_follow_up":
        candidate_priority = str(proposal.get("candidate_priority") or "").strip().lower()
        if proposal.get("trusted_indicator_match") or candidate_priority == "critical":
            return 1, 900
        if candidate_priority == "high":
            return 2, 700
        if candidate_priority in {"medium", "low"}:
            return 5, 100
        return 3, 500
    if origin == "behavior_catalog":
        return 2, 800
    if origin == "directed_survey":
        return 3, 600
    if origin == "model_proposal":
        return 3, 300
    return 4, 200


def _owners(proposal: Mapping[str, Any], field: str) -> list[str]:
    values = proposal.get(field, [])
    if values is None:
        return []
    if not isinstance(values, (list, tuple)):
        raise ValueError(f"search task {field} must be a list")
    merged: list[str] = []
    for value in values:
        item = _required_list_text(value, field)
        if item not in merged:
            merged.append(item)
    return merged


def _append_history(state: MutableMapping[str, Any], event: dict[str, Any]) -> None:
    history = state["scheduler_history"]
    history.append(event)
    if len(history) > _HISTORY_LIMIT:
        del history[:-_HISTORY_LIMIT]


def register_search_task(
    state: MutableMapping[str, Any], proposal: Mapping[str, Any]
) -> tuple[str, bool]:
    """Register a search once, merging every owner of duplicate execution."""

    initialize_scheduler(state)
    execution = _validated_execution(proposal)
    fingerprint = execution_fingerprint(proposal)
    task_id = f"ST-{fingerprint[:16]}"
    owners = {field: _owners(proposal, field) for field in _OWNER_FIELDS}
    tier, score = _priority_for(proposal, execution["origin"])

    existing = state["search_tasks"].get(task_id)
    if existing is not None:
        if existing.get("execution_fingerprint") != fingerprint:
            raise ValueError(f"search task ID collision for {task_id}")
        for field, values in owners.items():
            for value in values:
                if value not in existing[field]:
                    existing[field].append(value)
        if execution["origin"] not in existing["origins"]:
            existing["origins"].append(execution["origin"])
        if (tier, -score) < (
            int(existing["priority_tier"]),
            -int(existing["priority_score"]),
        ):
            existing["priority_tier"] = tier
            existing["priority_score"] = score
        _append_history(
            state,
            {
                "event": "task_merged",
                "task_id": task_id,
                "origin": execution["origin"],
                "owner_count": sum(len(existing[field]) for field in _OWNER_FIELDS),
            },
        )
        return task_id, False

    created_sequence = max(
        (int(task.get("created_sequence", 0)) for task in state["search_tasks"].values()),
        default=0,
    ) + 1
    intent = proposal.get("intent", "")
    task = {
        "task_id": task_id,
        "execution_fingerprint": fingerprint,
        **execution,
        "intent": str(intent).strip()[:500],
        **owners,
        "origins": [execution["origin"]],
        "priority_tier": tier,
        "priority_score": score,
        "status": "queued",
        "attempt_count": 0,
        "created_sequence": created_sequence,
        "last_attempt_at": None,
    }
    state["search_tasks"][task_id] = task
    state["search_queue"].append(task_id)
    _append_history(
        state,
        {
            "event": "task_registered",
            "task_id": task_id,
            "origin": execution["origin"],
            "source_family": execution["source_family"],
            "phase": execution["phase"],
        },
    )
    return task_id, True
