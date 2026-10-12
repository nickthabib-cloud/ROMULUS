"""Persistent, deterministic scheduling primitives for evidence searches."""

from __future__ import annotations

import copy
import hashlib
import json
from collections.abc import Callable, Mapping, MutableMapping
from datetime import datetime, timezone
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
_OUTCOME_LIMIT = 1000
_TERMINAL_STATUSES = {"completed", "partial", "failed", "skipped", "budget_limited"}


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
    time_range = execution["time_range"]
    start = time_range.get("start", time_range.get("gte"))
    end = time_range.get("end", time_range.get("lte"))
    if (start is None) != (end is None):
        raise ValueError("search task time range requires both start and end bounds")
    if start is None:
        effective_time = {"unbounded": True}
    else:
        def canonical(value: Any, field: str) -> tuple[datetime, str]:
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"search task time range {field} must be an ISO-8601 string")
            try:
                parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
            except ValueError as exc:
                raise ValueError(f"search task time range {field} is not valid ISO-8601") from exc
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            utc = parsed.astimezone(timezone.utc)
            return utc, utc.isoformat(timespec="microseconds").replace("+00:00", "Z")

        start_value, canonical_start = canonical(start, "start")
        end_value, canonical_end = canonical(end, "end")
        if start_value > end_value:
            raise ValueError("search task time range is reversed")
        effective_time = {"start": canonical_start, "end": canonical_end}
    return {
        "source": execution["source"],
        "source_targets": execution["source_targets"],
        "query_spec": execution["query_spec"],
        "time_range": effective_time,
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
        return 2, 600
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
    effective_proposal = dict(proposal)
    policy = state.get("sampling_policy")
    if isinstance(policy, Mapping):
        query_spec = dict(proposal.get("query_spec") or {})
        query_spec["sampling"] = _normalized(policy)
        effective_proposal["query_spec"] = query_spec
    execution = _validated_execution(effective_proposal)
    fingerprint = execution_fingerprint(effective_proposal)
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


def _family_attempt_counts(state: Mapping[str, Any]) -> dict[str, int]:
    counts = {"host": 0, "network": 0}
    for outcome in state.get("search_outcomes", []):
        if not isinstance(outcome, Mapping):
            continue
        family = outcome.get("source_family")
        if family in counts and outcome.get("status") != "interrupted":
            counts[family] += 1
    return counts


def _selection_key(task: Mapping[str, Any], attempts: Mapping[str, int]) -> tuple[int, int, int, int, str]:
    return (
        int(task.get("priority_tier", 99)),
        int(attempts.get(str(task.get("source_family")), 0)),
        -int(task.get("priority_score", 0)),
        int(task.get("created_sequence", 0)),
        str(task.get("task_id", "")),
    )


def select_search_tasks(
    state: MutableMapping[str, Any], *, phase: str, limit: int = 3
) -> list[dict[str, Any]]:
    """Select runnable tasks deterministically without starting them."""

    initialize_scheduler(state)
    normalized_phase = str(phase).strip().lower()
    if normalized_phase not in _PHASES:
        raise ValueError(f"unsupported search phase: {phase}")
    if limit <= 0:
        return []

    queue_ids = list(dict.fromkeys(str(task_id) for task_id in state["search_queue"]))
    runnable = [
        state["search_tasks"][task_id]
        for task_id in queue_ids
        if task_id in state["search_tasks"]
        and state["search_tasks"][task_id].get("phase") == normalized_phase
        and state["search_tasks"][task_id].get("status") in {"queued", "interrupted"}
    ]
    source_health = state.get("source_health", {})
    if isinstance(source_health, Mapping):
        runnable = [
            task for task in runnable if source_health.get(task.get("source_family"), True) is not False
        ]
    attempts = _family_attempt_counts(state)
    ordered = sorted(runnable, key=lambda item: _selection_key(item, attempts))

    if normalized_phase != "discovery":
        return [copy.deepcopy(task) for task in ordered[:limit]]

    best_by_family: dict[str, dict[str, Any]] = {}
    for task in ordered:
        best_by_family.setdefault(str(task["source_family"]), task)
    reserved = sorted(best_by_family.values(), key=lambda item: _selection_key(item, attempts))
    selected = reserved[:limit]
    selected_ids = {str(task["task_id"]) for task in selected}
    if len(selected) < limit:
        selected.extend(
            task for task in ordered if task["task_id"] not in selected_ids
        )
        selected = selected[:limit]

    served = {str(task["source_family"]) for task in selected}
    unserved = sorted(set(best_by_family) - served)
    if unserved:
        _append_history(
            state,
            {
                "event": "discovery_budget_gap",
                "phase": "discovery",
                "limit": int(limit),
                "unserved_families": unserved,
            },
        )
    return [copy.deepcopy(task) for task in selected]


def _timestamp(now: str | None = None) -> str:
    if now is not None:
        value = str(now).strip()
        if not value:
            raise ValueError("scheduler timestamp cannot be empty")
        return value
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def begin_search_task(
    state: MutableMapping[str, Any], task_id: str, *, now: str | None = None
) -> dict[str, Any]:
    """Mark one queued task running immediately before source execution."""

    initialize_scheduler(state)
    task = state["search_tasks"].get(task_id)
    if task is None:
        raise KeyError(f"unknown search task: {task_id}")
    if task.get("status") not in {"queued", "interrupted"}:
        raise ValueError(f"search task {task_id} is not runnable from {task.get('status')}")
    task["status"] = "running"
    task["attempt_count"] = int(task.get("attempt_count", 0)) + 1
    task["last_attempt_at"] = _timestamp(now)
    state["search_queue"] = [queued for queued in state["search_queue"] if queued != task_id]
    _append_history(
        state,
        {
            "event": "task_started",
            "task_id": task_id,
            "attempt_count": task["attempt_count"],
        },
    )
    return copy.deepcopy(task)


def outcome_resolves(outcome: Mapping[str, Any]) -> bool:
    """Return whether an outcome conclusively tested its owners."""

    if not isinstance(outcome, Mapping) or outcome.get("status") != "completed":
        return False
    matched_total = outcome.get("matched_total")
    if isinstance(matched_total, bool) or not isinstance(matched_total, int) or matched_total < 0:
        return False
    return not any(
        (
            outcome.get("capped"),
            outcome.get("timed_out"),
            outcome.get("shard_failures"),
            outcome.get("incomplete"),
        )
    )


def _bounded_outcome_value(value: Any, *, limit: int = 500) -> Any:
    if isinstance(value, str):
        return value[:limit]
    if value is None or isinstance(value, (int, float, bool)):
        return value
    return None


def _normalized_sampling(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, Mapping):
        return None
    result: dict[str, Any] = {}
    for field in ("version", "requested_strata", "covered_strata", "backfilled"):
        item = value.get(field)
        if isinstance(item, int) and not isinstance(item, bool) and item >= 0:
            result[field] = item
    for field, limit in (("strategy", 64), ("fallback_reason", 120), ("bounds_source", 64)):
        item = value.get(field)
        if isinstance(item, str) and item.strip():
            result[field] = item.strip()[:limit]
    retained = value.get("retained_by_stratum")
    if isinstance(retained, (list, tuple)):
        result["retained_by_stratum"] = [
            int(item) for item in retained[:24]
            if isinstance(item, int) and not isinstance(item, bool) and item >= 0
        ]
    return result or None


def _append_outcome(state: MutableMapping[str, Any], outcome: dict[str, Any]) -> None:
    state["search_outcomes"].append(outcome)
    if len(state["search_outcomes"]) > _OUTCOME_LIMIT:
        del state["search_outcomes"][:-_OUTCOME_LIMIT]


def _normalized_outcome(
    task: Mapping[str, Any], outcome: Mapping[str, Any], recorded_at: str
) -> dict[str, Any]:
    status = str(outcome.get("status") or "").strip().lower()
    if status not in _TERMINAL_STATUSES:
        raise ValueError(f"unsupported terminal search outcome: {status or '<empty>'}")
    matched = outcome.get("matched_total")
    returned = outcome.get("returned_total", outcome.get("returned"))
    normalized: dict[str, Any] = {
        "outcome_id": "SO-"
        + hashlib.sha256(
            f"{task['task_id']}:{task.get('attempt_count', 0)}".encode("utf-8")
        ).hexdigest()[:16].upper(),
        "task_id": task["task_id"],
        "execution_fingerprint": task["execution_fingerprint"],
        "source": task["source"],
        "source_family": task["source_family"],
        "phase": task["phase"],
        "status": status,
        "attempt_count": int(task.get("attempt_count", 0)),
        "recorded_at": recorded_at,
        "matched_total": matched if isinstance(matched, int) and not isinstance(matched, bool) else None,
        "returned_total": returned if isinstance(returned, int) and not isinstance(returned, bool) else None,
        "capped": bool(outcome.get("capped", False)),
        "timed_out": bool(outcome.get("timed_out", False)),
        "shard_failures": (
            len(outcome["shard_failures"])
            if isinstance(outcome.get("shard_failures"), (list, tuple))
            else int(outcome.get("shard_failures", 0) or 0)
        ),
        "incomplete": bool(outcome.get("incomplete", False)),
    }
    for field in ("artifact_id", "reason", "error_kind"):
        value = _bounded_outcome_value(outcome.get(field))
        if value is not None:
            normalized[field] = value
    evidence_ids = outcome.get("evidence_ids")
    if isinstance(evidence_ids, (list, tuple)):
        normalized["evidence_ids"] = [
            _required_list_text(value, "evidence_ids") for value in evidence_ids[:100]
        ]
    time_range = outcome.get("time_range")
    if isinstance(time_range, Mapping):
        normalized["time_range"] = _normalized(time_range)
    sampling = _normalized_sampling(outcome.get("sampling"))
    if sampling is not None:
        normalized["sampling"] = sampling
    if outcome.get("possible_duplicate_execution"):
        normalized["possible_duplicate_execution"] = True
    return normalized


def record_search_outcome(
    state: MutableMapping[str, Any],
    task_id: str,
    outcome: Mapping[str, Any],
    *,
    now: str | None = None,
) -> dict[str, Any]:
    """Record the authoritative terminal outcome for exactly one task attempt."""

    initialize_scheduler(state)
    task = state["search_tasks"].get(task_id)
    if task is None:
        raise KeyError(f"unknown search task: {task_id}")
    if task.get("status") in _TERMINAL_STATUSES:
        prior = next(
            (
                item
                for item in reversed(state["search_outcomes"])
                if item.get("task_id") == task_id
                and item.get("attempt_count") == task.get("attempt_count")
            ),
            None,
        )
        if prior is None:
            raise ValueError(f"terminal search task {task_id} has no recorded outcome")
        return copy.deepcopy(prior)
    if task.get("status") != "running":
        raise ValueError(f"search task {task_id} has not been started")
    normalized = _normalized_outcome(task, outcome, _timestamp(now))
    _append_outcome(state, normalized)
    task["status"] = normalized["status"]
    task["last_outcome_id"] = normalized["outcome_id"]
    state["search_queue"] = [queued for queued in state["search_queue"] if queued != task_id]
    _append_history(
        state,
        {
            "event": "task_finished",
            "task_id": task_id,
            "status": normalized["status"],
            "resolves": outcome_resolves(normalized),
        },
    )
    return copy.deepcopy(normalized)


def record_unexecuted_outcome(
    state: MutableMapping[str, Any],
    task_id: str,
    *,
    reason: str,
    now: str | None = None,
) -> dict[str, Any]:
    """Terminalize queued work without pretending a source call was attempted."""

    initialize_scheduler(state)
    task = state["search_tasks"].get(task_id)
    if task is None:
        raise KeyError(f"unknown search task: {task_id}")
    if task.get("status") in _TERMINAL_STATUSES:
        prior = next((item for item in reversed(state["search_outcomes"])
            if item.get("task_id") == task_id), None)
        if prior is None:
            raise ValueError(f"terminal search task {task_id} has no recorded outcome")
        return copy.deepcopy(prior)
    if task.get("status") not in {"queued", "interrupted"}:
        raise ValueError(f"search task {task_id} cannot be finalized from {task.get('status')}")
    normalized = _normalized_outcome(task, {
        "status": "budget_limited",
        "reason": str(reason or "resource_limit")[:300],
        "matched_total": None,
        "returned_total": None,
        "incomplete": True,
        "time_range": task.get("time_range", {}),
    }, _timestamp(now))
    _append_outcome(state, normalized)
    task["status"] = normalized["status"]
    task["last_outcome_id"] = normalized["outcome_id"]
    state["search_queue"] = [queued for queued in state["search_queue"] if queued != task_id]
    _append_history(state, {"event": "task_not_executed", "task_id": task_id,
        "status": "budget_limited", "reason": normalized.get("reason")})
    return copy.deepcopy(normalized)


def recover_interrupted_tasks(state: MutableMapping[str, Any]) -> list[str]:
    """Requeue a persisted running task once, then stop rather than loop."""

    initialize_scheduler(state)
    requeued: list[str] = []
    running = sorted(
        (task for task in state["search_tasks"].values() if task.get("status") == "running"),
        key=lambda item: (int(item.get("created_sequence", 0)), str(item.get("task_id", ""))),
    )
    for task in running:
        task_id = str(task["task_id"])
        interruption_count = int(task.get("interruption_count", 0)) + 1
        task["interruption_count"] = interruption_count
        interrupted = {
            "outcome_id": "SO-"
            + hashlib.sha256(
                f"{task_id}:{task.get('attempt_count', 0)}:interrupted".encode("utf-8")
            ).hexdigest()[:16].upper(),
            "task_id": task_id,
            "execution_fingerprint": task["execution_fingerprint"],
            "source": task["source"],
            "source_family": task["source_family"],
            "phase": task["phase"],
            "attempt_count": int(task.get("attempt_count", 0)),
            "recorded_at": _timestamp(),
            "matched_total": None,
            "returned_total": None,
            "capped": False,
            "timed_out": False,
            "shard_failures": 0,
            "incomplete": True,
            "possible_duplicate_execution": True,
        }
        if interruption_count == 1:
            interrupted.update({"status": "interrupted", "reason": "process_interrupted"})
            _append_outcome(state, interrupted)
            task["status"] = "interrupted"
            if task_id not in state["search_queue"]:
                state["search_queue"].append(task_id)
            requeued.append(task_id)
            event = "task_requeued_after_interruption"
        else:
            interrupted.update({"status": "skipped", "reason": "repeated_interruption"})
            _append_outcome(state, interrupted)
            task["status"] = "skipped"
            task["last_outcome_id"] = interrupted["outcome_id"]
            state["search_queue"] = [queued for queued in state["search_queue"] if queued != task_id]
            event = "task_stopped_after_repeated_interruption"
        _append_history(
            state,
            {
                "event": event,
                "task_id": task_id,
                "attempt_count": int(task.get("attempt_count", 0)),
                "possible_duplicate_execution": True,
            },
        )
    return requeued


def _legacy_result_by_id(state: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    results: dict[str, Mapping[str, Any]] = {}
    coverage = state.get("coverage", {})
    if isinstance(coverage, Mapping):
        for item in coverage.get("model_search_results", []):
            if isinstance(item, Mapping) and item.get("search_id"):
                results[str(item["search_id"])] = item
    for item in state.get("pivot_results", []):
        if isinstance(item, Mapping) and item.get("lead_id"):
            results[str(item["lead_id"])] = item
    return results


def _legacy_proposal(state: Mapping[str, Any], lead: Mapping[str, Any]) -> dict[str, Any]:
    legacy_source = str(lead.get("source") or "host").lower()
    family = "network" if legacy_source in {"network", "arkime", "tshark"} else "host"
    source = legacy_source if legacy_source in _SOURCES else (
        "arkime" if family == "network" else "elasticsearch"
    )
    if source == "elasticsearch":
        targets = [str(value) for value in state.get("es_indices", []) if str(value).strip()]
    else:
        targets = [str(value) for value in lead.get("source_targets", []) if str(value).strip()]
    if not targets:
        targets = [f"legacy-{family}"]
    selectors = {
        key: copy.deepcopy(lead[key])
        for key in (
            "terms",
            "ips",
            "hostnames",
            "ports",
            "protocols",
            "event_codes",
            "index_class",
        )
        if lead.get(key)
    }
    selectors["legacy_lead_id"] = str(lead.get("id"))
    time_range = lead.get("time_range")
    if not isinstance(time_range, Mapping) or not time_range:
        time_range = {"legacy_scope": "unknown"}
    return {
        "source": source,
        "source_family": family,
        "source_targets": targets,
        "phase": "investigation",
        "origin": "coverage_frontier",
        "intent": str(lead.get("intent") or lead.get("why") or "legacy search"),
        "query_spec": selectors,
        "time_range": time_range,
        "candidate_ids": [lead["candidate_id"]] if lead.get("candidate_id") else [],
        "follow_up_ids": [lead["follow_up_id"]] if lead.get("follow_up_id") else [],
        "hypothesis_ids": [lead["hypothesis_id"]] if lead.get("hypothesis_id") else [],
        "anchor_evidence_ids": list(lead.get("anchor_evidence_ids", [])),
    }


def migrate_legacy_search_state(
    state: MutableMapping[str, Any],
    *,
    compile_pending: Callable[[Mapping[str, Any]], list[Mapping[str, Any]]] | None = None,
) -> None:
    """Convert legacy attempted-lead markers into conservative terminal outcomes."""

    initialize_scheduler(state)
    if state.get("scheduler_migration_version") == 1:
        return
    completed = {str(value) for value in state.get("completed_leads", [])}
    leads = {
        str(item.get("id")): item
        for item in state.get("lead_catalog", [])
        if isinstance(item, Mapping) and item.get("id")
    }
    results = _legacy_result_by_id(state)
    for legacy_id in sorted(set(leads) | completed):
        lead = leads.get(legacy_id) or {
            "id": legacy_id, "source": "host", "intent": "unknown legacy search"
        }
        if legacy_id not in completed and compile_pending is not None:
            try:
                proposals = compile_pending(lead)
            except (TypeError, ValueError, json.JSONDecodeError):
                proposals = []
            if proposals:
                for proposal in proposals:
                    task_id, _ = register_search_task(state, proposal)
                    state["search_tasks"][task_id]["legacy_lead_id"] = legacy_id
                continue
        task_id, _ = register_search_task(state, _legacy_proposal(state, lead))
        task = state["search_tasks"][task_id]
        task["legacy_lead_id"] = legacy_id
        if legacy_id not in completed:
            begin_search_task(state, task_id)
            record_search_outcome(state, task_id, {
                "status": "skipped",
                "reason": "legacy_pending_not_executable",
                "matched_total": None,
                "returned_total": None,
                "incomplete": True,
            })
            continue
        if task.get("status") in _TERMINAL_STATUSES:
            continue
        begin_search_task(state, task_id)
        legacy_result = results.get(legacy_id)
        if legacy_result is None:
            normalized = {
                "status": "skipped",
                "reason": "legacy_attempt_unknown",
                "matched_total": None,
                "returned_total": None,
                "incomplete": True,
            }
        else:
            status_text = str(legacy_result.get("status") or "completed").lower()
            if any(token in status_text for token in ("fail", "error", "reject")):
                status = "failed"
            elif legacy_result.get("capped") or any(
                token in status_text for token in ("partial", "timeout", "cap reached")
            ):
                status = "partial"
            else:
                status = "completed"
            returned = legacy_result.get("returned_total", legacy_result.get("returned", 0))
            matched = legacy_result.get("matched_total")
            completeness_known=(isinstance(matched,int) and not isinstance(matched,bool)
                and all(key in legacy_result for key in ("capped","timed_out","shard_failures")))
            reason="legacy_result_migrated"
            incomplete=False
            if status=="completed" and (not completeness_known or legacy_result.get("timed_out")
                    or legacy_result.get("shard_failures")):
                status="partial"
                reason=("legacy_completeness_unknown" if not completeness_known
                    else "legacy_result_incomplete")
                incomplete=True
            normalized = {
                "status": status,
                "matched_total": matched,
                "returned_total": returned,
                "capped": bool(legacy_result.get("capped", False)),
                "timed_out": bool(legacy_result.get("timed_out", False)),
                "shard_failures": legacy_result.get("shard_failures", 0),
                "incomplete": incomplete,
                "reason": reason,
            }
        record_search_outcome(state, task_id, normalized)
    state["scheduler_migration_version"] = 1
