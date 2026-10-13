"""Build the bounded, evidence-grounded case file shown to reasoning models.

The case file is a deliberately narrow projection of hunt state.  It is pure,
deterministic, JSON-safe, and excludes source-native query bodies and secrets.
"""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
from typing import Any


_RAW_FIELDS = (
    "message",
    "event.original",
    "event.action",
    "event.dataset",
    "event.code",
    "process.name",
    "process.command_line",
    "process.executable",
    "host.name",
    "host.ip",
    "user.name",
    "source.ip",
    "source.port",
    "destination.ip",
    "destination.port",
    "http.uri",
    "dns.host",
    "network.protocol",
)
_PRIORITY = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}
_CLOSED_FOLLOW_UP = {"completed", "closed", "resolved", "not_applicable"}


def build_case_file(
    state: Mapping[str, Any],
    *,
    evidence_limit: int = 24,
    candidate_limit: int = 12,
    hypothesis_limit: int = 16,
    timeline_limit: int = 24,
    outcome_limit: int = 30,
) -> dict[str, Any]:
    """Return a bounded reasoning view of already-admitted hunt state."""
    source = state if isinstance(state, Mapping) else {}
    evidence_limit = _limit(evidence_limit)
    candidate_limit = _limit(candidate_limit)
    hypothesis_limit = _limit(hypothesis_limit)
    timeline_limit = _limit(timeline_limit)
    outcome_limit = _limit(outcome_limit)

    evidence_index = _evidence_index(source)
    candidates, anchor_ids = _select_candidates(
        source.get("candidate_leads"), evidence_index, candidate_limit, evidence_limit
    )
    evidence = _select_evidence(evidence_index, anchor_ids, evidence_limit)
    visible_evidence_ids = {row["evidence_id"] for row in evidence}
    visible_candidate_ids = {row["candidate_id"] for row in candidates}
    hypotheses = _hypotheses(
        source.get("hypotheses"), visible_candidate_ids, visible_evidence_ids, hypothesis_limit
    )

    case_file = {
        "version": 1,
        "mission": _mission(source),
        "candidates": candidates,
        "hypotheses": hypotheses,
        "evidence": evidence,
        "timeline": _timeline(evidence, timeline_limit),
        "path_fragments": _path_fragments(
            source.get("investigation_graph"), visible_evidence_ids, limit=min(12, timeline_limit)
        ),
        "completed_searches": _completed_searches(
            source.get("search_outcomes"), source.get("search_tasks"), visible_evidence_ids, outcome_limit
        ),
        "unresolved_follow_ups": _unresolved_follow_ups(candidates),
        "source_status": _source_status(source),
        "coverage_gaps": _coverage_gaps(source.get("coverage"), limit=30),
        "novelty": _novelty(source.get("progress_history")),
    }
    return case_file


def visible_case_ids(case_file: Mapping[str, Any]) -> dict[str, set[str]]:
    """Return every grounding identifier actually visible in a case file."""
    visible = {
        "candidate": set(),
        "evidence": set(),
        "hypothesis": set(),
        "follow_up": set(),
        "task": set(),
        "proposal": set(),
    }
    singular = {
        "candidate_id": "candidate",
        "evidence_id": "evidence",
        "hypothesis_id": "hypothesis",
        "hypothesis_ref": "hypothesis",
        "follow_up_id": "follow_up",
        "task_id": "task",
        "proposal_id": "proposal",
    }
    plural = {
        "candidate_ids": "candidate",
        "evidence_ids": "evidence",
        "anchor_evidence_ids": "evidence",
        "hypothesis_ids": "hypothesis",
        "follow_up_ids": "follow_up",
        "task_ids": "task",
        "unresolved_task_ids": "task",
        "proposal_ids": "proposal",
    }

    def visit(value: Any) -> None:
        if isinstance(value, Mapping):
            for key, child in value.items():
                if key in singular:
                    identifier = _text(child, 120)
                    if identifier:
                        visible[singular[key]].add(identifier)
                elif key in plural:
                    visible[plural[key]].update(_strings(child, 120, 100))
                visit(child)
        elif isinstance(value, (list, tuple)):
            for child in value:
                visit(child)

    visit(case_file)
    return visible


def _mission(state: Mapping[str, Any]) -> dict[str, Any]:
    coverage = _mapping(state.get("coverage"))
    return {
        "hunt_id": _text(state.get("hunt_id"), 100),
        "objective": _text(state.get("objective"), 1200),
        "mode": _text(state.get("mission_mode"), 40),
        "time_scope": _text(coverage.get("time_scope") or state.get("scheduler_mission_time_range"), 300),
    }


def _evidence_index(state: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}
    for section in ("host", "network", "evidence"):
        for raw in _rows(state.get(section)):
            evidence_id = _text(raw.get("evidence_id") or raw.get("id") or raw.get("_id"), 120)
            if not evidence_id or evidence_id in index:
                continue
            raw_fields = _mapping(raw.get("raw"))
            provenance = _mapping(raw.get("provenance"))
            index[evidence_id] = {
                "evidence_id": evidence_id,
                "source": _text(raw.get("source") or section, 80),
                "asset": _text(raw.get("asset"), 160),
                "observed_at": _text(raw.get("observed_at"), 80),
                "observation": _text(raw.get("observation"), 360),
                "retrieval_context": _text(
                    provenance.get("lead_id")
                    or provenance.get("search_id")
                    or provenance.get("task_id")
                    or "broad source collection",
                    120,
                ),
                "raw": {
                    key: _safe_value(raw_fields[key], 240)
                    for key in _RAW_FIELDS
                    if key in raw_fields
                },
            }
    return index


def _candidate_sort(row: Mapping[str, Any]) -> tuple[Any, ...]:
    tier = _text(row.get("priority_tier"), 40).lower()
    score = _number(row.get("priority_score"), 0)
    return (-_PRIORITY.get(tier, -1), -score, _text(row.get("candidate_id"), 120))


def _select_candidates(
    raw_candidates: Any,
    evidence_index: Mapping[str, dict[str, Any]],
    candidate_limit: int,
    evidence_limit: int,
) -> tuple[list[dict[str, Any]], list[str]]:
    selected: list[dict[str, Any]] = []
    anchor_ids: list[str] = []
    used_ids: set[str] = set()
    for raw in sorted(_rows(raw_candidates), key=_candidate_sort):
        if len(selected) >= candidate_limit:
            break
        candidate_id = _text(raw.get("candidate_id"), 120)
        if not candidate_id or candidate_id in used_ids:
            continue
        owned = [item for item in _strings(raw.get("evidence_ids"), 120, 100) if item in evidence_index]
        owned = list(dict.fromkeys(owned))
        # A reasoning-visible lead is never separated from all evidence records it owns.
        missing_owned = [item for item in _strings(raw.get("evidence_ids"), 120, 100) if item not in evidence_index]
        new_anchor_ids = [item for item in owned if item not in anchor_ids]
        if not owned or missing_owned or len(anchor_ids) + len(new_anchor_ids) > evidence_limit:
            continue
        compact = {
            "candidate_id": candidate_id,
            "kind": _text(raw.get("kind"), 80),
            "title": _text(raw.get("title"), 240),
            "description": _text(raw.get("description"), 360),
            "priority_tier": _text(raw.get("priority_tier"), 40),
            "priority_score": _number(raw.get("priority_score"), 0),
            "disposition": _text(raw.get("disposition"), 60),
            "evidence_ids": owned,
            "assets": _strings(raw.get("assets") or raw.get("affected_assets"), 160, 20),
            "attack_techniques": _strings(raw.get("attack_techniques"), 40, 20),
            "score_reasons": _strings(raw.get("score_reasons"), 200, 12),
            "benign_explanations": _strings(raw.get("benign_explanations"), 240, 8),
            "follow_ups": _follow_ups(raw, candidate_id),
        }
        selected.append(compact)
        used_ids.add(candidate_id)
        anchor_ids.extend(new_anchor_ids)
    return selected, anchor_ids


def _follow_ups(candidate: Mapping[str, Any], candidate_id: str) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    rows = _rows(candidate.get("follow_ups"))
    if rows:
        for raw in rows[:20]:
            follow_up_id = _text(raw.get("follow_up_id"), 120)
            if not follow_up_id:
                continue
            normalized.append({
                "follow_up_id": follow_up_id,
                "intent": _text(raw.get("intent"), 300),
                "status": _text(raw.get("status") or "pending", 60),
            })
        return normalized

    legacy = candidate.get("follow_up")
    if isinstance(legacy, str):
        legacy = [legacy]
    if isinstance(legacy, (list, tuple)):
        for value in legacy[:20]:
            intent = _text(value, 300)
            if not intent:
                continue
            digest = hashlib.sha256(f"{candidate_id}\0{intent}".encode("utf-8")).hexdigest()[:12].upper()
            normalized.append({
                "follow_up_id": f"LEGACY-FU-{digest}",
                "intent": intent,
                "status": "pending",
            })
    return normalized


def _select_evidence(
    evidence_index: Mapping[str, dict[str, Any]], anchor_ids: list[str], limit: int
) -> list[dict[str, Any]]:
    chosen_ids = list(dict.fromkeys(anchor_ids))[:limit]
    remaining = [row for key, row in evidence_index.items() if key not in set(chosen_ids)]
    remaining.sort(key=lambda row: (row.get("observed_at", ""), row["evidence_id"]), reverse=True)
    chosen_ids.extend(row["evidence_id"] for row in remaining[: max(0, limit - len(chosen_ids))])
    return [dict(evidence_index[identifier]) for identifier in chosen_ids]


def _hypotheses(
    raw_hypotheses: Any,
    visible_candidate_ids: set[str],
    visible_evidence_ids: set[str],
    limit: int,
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw in _rows(raw_hypotheses):
        hypothesis_id = _text(raw.get("hypothesis_id"), 120)
        candidate_id = _text(raw.get("candidate_id"), 120)
        if not candidate_id:
            candidate_id = next(iter(_strings(raw.get("basis_candidate_ids"), 120, 4)), "")
        if not hypothesis_id or hypothesis_id in seen:
            continue
        if candidate_id and candidate_id not in visible_candidate_ids:
            continue
        cited = _strings(
            raw.get("candidate_evidence_ids") or raw.get("basis_evidence_ids")
            or raw.get("evidence_ids"), 120, 100
        )
        if cited and not set(cited).issubset(visible_evidence_ids):
            continue
        assessment = raw.get("model_assessment") or raw.get("deterministic_assessment")
        compact_assessment = None
        if isinstance(assessment, Mapping):
            assessment_evidence = [
                item for item in _strings(assessment.get("evidence_ids"), 120, 20)
                if item in visible_evidence_ids
            ]
            compact_assessment = {
                "status": _text(assessment.get("status"), 60),
                "evidence_ids": assessment_evidence,
                "rationale": _text(assessment.get("rationale"), 300),
            }
        out.append({
            "hypothesis_id": hypothesis_id,
            "candidate_id": candidate_id,
            "title": _text(raw.get("title"), 240),
            "technique_id": _text(raw.get("technique_id"), 60),
            "status": _text(raw.get("status"), 60),
            "priority": _number(raw.get("priority"), 0),
            "rationale": _text(raw.get("rationale"), 360),
            "evidence_ids": cited,
            "expected_host": _strings(raw.get("expected_host"), 240, 8),
            "expected_network": _strings(raw.get("expected_network"), 240, 8),
            "falsifying_observations": _strings(raw.get("falsifying_observations"), 240, 8),
            "benign_explanations": _strings(raw.get("benign_explanations"), 240, 8),
            "analytic_goal": _text(raw.get("analytic_goal"), 360),
            "anchor_entities": _strings(raw.get("anchor_entities"), 200, 24),
            "candidate_assets": _strings(raw.get("candidate_assets"), 160, 20),
            "ips": _strings(raw.get("ips"), 80, 8),
            "hostnames": _strings(raw.get("hostnames"), 255, 8),
            "assessment": compact_assessment,
        })
        seen.add(hypothesis_id)
        if len(out) >= limit:
            break
    return out


def _timeline(evidence: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    ordered = sorted(evidence, key=lambda row: (row.get("observed_at", ""), row["evidence_id"]))
    return [{
        "observed_at": row.get("observed_at", ""),
        "evidence_id": row["evidence_id"],
        "source": row.get("source", ""),
        "asset": row.get("asset", ""),
        "observation": row.get("observation", ""),
    } for row in ordered[:limit]]


def _path_fragments(graph: Any, visible_evidence_ids: set[str], limit: int) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for raw in _rows(_mapping(graph).get("paths")):
        steps = []
        for step in _rows(raw.get("steps"))[:24]:
            evidence_ids = [
                item for item in _strings(step.get("evidence_ids"), 120, 20)
                if item in visible_evidence_ids
            ]
            if not evidence_ids:
                continue
            entities = [{
                "entity_type": _text(entity.get("entity_type"), 80),
                "value": _text(entity.get("value"), 160),
            } for entity in _rows(step.get("entities"))[:12]]
            steps.append({
                "sequence": _number(step.get("sequence"), len(steps) + 1),
                "activity_type": _text(step.get("activity_type"), 100),
                "label": _text(step.get("label"), 300),
                "observed_at": _text(step.get("observed_at"), 80),
                "evidence_ids": evidence_ids,
                "entities": entities,
            })
        if not steps:
            continue
        relationships = [{
            "from_sequence": _number(row.get("from_sequence"), 0),
            "to_sequence": _number(row.get("to_sequence"), 0),
            "relationship": _text(row.get("relationship"), 160),
        } for row in _rows(raw.get("relationships"))[:24]]
        out.append({
            "path_id": _text(raw.get("path_id"), 120),
            "finding_id": _text(raw.get("finding_id"), 120),
            "title": _text(raw.get("title"), 240),
            "confidence": _text(raw.get("confidence"), 60),
            "steps": steps,
            "relationships": relationships,
            "gaps": _strings(raw.get("gaps"), 300, 12),
            "caveats": _strings(raw.get("caveats"), 300, 12),
        })
        if len(out) >= limit:
            break
    return out


def _task_index(raw_tasks: Any) -> dict[str, Mapping[str, Any]]:
    if isinstance(raw_tasks, Mapping):
        rows = [value for value in raw_tasks.values() if isinstance(value, Mapping)]
    else:
        rows = _rows(raw_tasks)
    return {
        task_id: row
        for row in rows
        if (task_id := _text(row.get("task_id"), 120))
    }


def _completed_searches(
    raw_outcomes: Any,
    raw_tasks: Any,
    visible_evidence_ids: set[str],
    limit: int,
) -> list[dict[str, Any]]:
    tasks = _task_index(raw_tasks)
    outcomes = _rows(raw_outcomes)[-limit:] if limit else []
    out = []
    for outcome in outcomes:
        task_id = _text(outcome.get("task_id"), 120)
        task = tasks.get(task_id, {})
        sampling = _mapping(outcome.get("sampling"))
        out.append({
            "task_id": task_id,
            "status": _text(outcome.get("status") or task.get("status"), 60),
            "source": _text(outcome.get("source") or task.get("source"), 80),
            "source_family": _text(outcome.get("source_family") or task.get("source_family"), 80),
            "phase": _text(outcome.get("phase") or task.get("phase"), 80),
            "intent": _text(task.get("intent") or outcome.get("intent"), 300),
            "candidate_ids": _strings(task.get("candidate_ids"), 120, 20),
            "follow_up_ids": _strings(task.get("follow_up_ids"), 120, 20),
            "hypothesis_ids": _strings(task.get("hypothesis_ids"), 120, 20),
            "evidence_ids": [
                item for item in _strings(outcome.get("evidence_ids"), 120, 100)
                if item in visible_evidence_ids
            ],
            "returned_total": _number(outcome.get("returned_total"), 0),
            "matched_total": _number(outcome.get("matched_total"), 0),
            "total_relation": _text(outcome.get("total_relation"), 40),
            "capped": bool(outcome.get("capped")),
            "timed_out": bool(outcome.get("timed_out")),
            "shard_failures": _number(outcome.get("shard_failures"), 0),
            "incomplete": bool(outcome.get("incomplete")),
            "error_kind": _text(outcome.get("error_kind"), 100),
            "reason": _text(outcome.get("reason"), 300),
            "sampling": {
                key: _safe_value(sampling[key], 160)
                for key in (
                    "version", "strategy", "requested_strata", "covered_strata",
                    "retained_by_stratum", "matched_by_stratum", "fallback_reason",
                )
                if key in sampling
            },
        })
    return out


def _unresolved_follow_ups(candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for candidate in candidates:
        for follow_up in candidate.get("follow_ups", []):
            status = _text(follow_up.get("status") or "pending", 60)
            if status.lower() in _CLOSED_FOLLOW_UP:
                continue
            out.append({
                "candidate_id": candidate["candidate_id"],
                "follow_up_id": follow_up["follow_up_id"],
                "intent": follow_up.get("intent", ""),
                "status": status,
            })
    return out[:40]


def _source_status(state: Mapping[str, Any]) -> dict[str, Any]:
    coverage = _mapping(state.get("coverage"))
    health = _mapping(state.get("source_health"))
    errors = [{
        "source": _text(row.get("source"), 80),
        "source_family": _text(row.get("source_family"), 80),
        "error_kind": _text(row.get("error_kind") or row.get("kind"), 100),
        "detail": _text(row.get("detail") or row.get("reason"), 300),
    } for row in _rows(state.get("source_errors"))[-20:]]
    return {
        "health": {str(key)[:80]: bool(value) for key, value in sorted(health.items(), key=lambda item: str(item[0]))},
        "coverage": {
            key: _text(coverage.get(key), 300)
            for key in ("host", "network")
            if coverage.get(key) is not None
        },
        "errors": errors,
    }


def _coverage_gaps(raw_coverage: Any, limit: int) -> list[dict[str, Any]]:
    coverage = _mapping(raw_coverage)
    gaps = []
    for row in _rows(coverage.get("scheduler_gaps")):
        gaps.append({
            "kind": "scheduler",
            "phase": _text(row.get("phase"), 80),
            "reason": _text(row.get("reason"), 160),
            "source": _text(row.get("source"), 80),
            "source_family": _text(row.get("source_family"), 80),
            "task_id": _text(row.get("task_id"), 120),
            "task_ids": _strings(row.get("task_ids") or row.get("budget_limited_task_ids"), 120, 40),
            "task_count": _number(row.get("task_count") or row.get("budget_limited_task_count"), 0),
        })
    hypothesis_coverage = _mapping(coverage.get("hypothesis_coverage"))
    for row in _rows(hypothesis_coverage.get("rows")):
        if bool(row.get("closed")):
            continue
        gaps.append({
            "kind": "hypothesis",
            "reason": "unresolved_hypothesis_coverage",
            "hypothesis_id": _text(row.get("hypothesis_id"), 120),
            "task_ids": _strings(row.get("unresolved_task_ids"), 120, 40),
        })
    for row in _rows(hypothesis_coverage.get("candidate_rows")):
        if bool(row.get("closed")):
            continue
        gaps.append({
            "kind": "candidate",
            "reason": "unresolved_candidate_coverage",
            "candidate_id": _text(row.get("candidate_id"), 120),
            "follow_up_ids": _strings(row.get("unfinished_follow_up_ids"), 120, 40),
            "task_ids": _strings(row.get("unresolved_task_ids"), 120, 40),
        })
    return gaps[:limit]


def _novelty(raw_history: Any) -> dict[str, Any]:
    history = _rows(raw_history)
    if not history:
        return {}
    latest = history[-1]
    signals = _mapping(latest.get("signals"))
    changed = _mapping(latest.get("changed_ids"))
    return {
        "stage": _text(latest.get("stage"), 80),
        "material_progress": bool(latest.get("material_progress")),
        "signals": {
            str(key)[:80]: _safe_value(value, 120)
            for key, value in sorted(signals.items(), key=lambda item: str(item[0]))
        },
        "changed_ids": {
            str(key)[:80]: _strings(value, 120, 40)
            for key, value in sorted(changed.items(), key=lambda item: str(item[0]))
        },
        "stagnant_cycles": _number(latest.get("stagnant_cycles"), 0),
    }


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _rows(value: Any) -> list[Mapping[str, Any]]:
    if not isinstance(value, (list, tuple)):
        return []
    return [row for row in value if isinstance(row, Mapping)]


def _limit(value: Any) -> int:
    try:
        return max(0, min(100, int(value)))
    except (TypeError, ValueError):
        return 0


def _text(value: Any, limit: int) -> str:
    if value is None:
        return ""
    if isinstance(value, (str, int, float, bool)):
        return str(value)[:limit]
    return ""


def _strings(value: Any, item_limit: int, count_limit: int) -> list[str]:
    if isinstance(value, (str, int, float, bool)):
        value = [value]
    if not isinstance(value, (list, tuple, set)):
        return []
    result = []
    for item in value:
        text = _text(item, item_limit)
        if text and text not in result:
            result.append(text)
        if len(result) >= count_limit:
            break
    return result


def _number(value: Any, default: int | float) -> int | float:
    if isinstance(value, bool):
        return default
    if isinstance(value, (int, float)):
        return value
    try:
        return float(str(value))
    except (TypeError, ValueError):
        return default


def _safe_value(value: Any, text_limit: int) -> Any:
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return value[:text_limit]
    if isinstance(value, (list, tuple)):
        return [_safe_value(item, text_limit) for item in value[:40]]
    return _text(value, text_limit)


__all__ = ["build_case_file", "visible_case_ids"]
