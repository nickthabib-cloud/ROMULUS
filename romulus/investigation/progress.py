"""Deterministic investigation-progress and stopping primitives."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, MutableMapping
from typing import Any

from .scheduler import outcome_resolves


def _text(value: Any) -> str:
    return str(value or "").strip()


def _sorted_ids(values: Any) -> list[str]:
    if isinstance(values, (str, bytes, Mapping)) or not isinstance(values, Iterable):
        values = []
    return sorted({_text(value) for value in values if _text(value)})


def snapshot_progress(state: Mapping[str, Any]) -> dict[str, Any]:
    """Return the stable investigation facts that can constitute progress."""

    evidence_ids = _sorted_ids(
        item.get("evidence_id")
        for item in list(state.get("host", []) or []) + list(state.get("network", []) or [])
        if isinstance(item, Mapping)
    )

    candidate_states: dict[str, dict[str, Any]] = {}
    for candidate in state.get("candidate_leads", []) or []:
        if not isinstance(candidate, Mapping):
            continue
        candidate_id = _text(candidate.get("candidate_id"))
        if not candidate_id or candidate_id in candidate_states:
            continue
        follow_ups = []
        for follow_up in candidate.get("follow_ups", []) or []:
            if not isinstance(follow_up, Mapping):
                continue
            follow_up_id = _text(follow_up.get("follow_up_id"))
            if follow_up_id:
                follow_ups.append(f"{follow_up_id}:{_text(follow_up.get('status')) or 'pending'}")
        candidate_states[candidate_id] = {
            "disposition": _text(candidate.get("disposition")) or "observed",
            "follow_ups": sorted(set(follow_ups)),
        }
    candidate_states = {key: candidate_states[key] for key in sorted(candidate_states)}

    tasks = state.get("search_tasks", {})
    search_fingerprints = _sorted_ids(
        task.get("execution_fingerprint")
        for task in tasks.values() if isinstance(task, Mapping)
    ) if isinstance(tasks, Mapping) else []

    resolving_task_ids = _sorted_ids(
        outcome.get("task_id")
        for outcome in state.get("search_outcomes", []) or []
        if isinstance(outcome, Mapping) and outcome_resolves(outcome)
    )

    hypothesis_states: dict[str, dict[str, Any]] = {}
    for hypothesis in state.get("hypotheses", []) or []:
        if not isinstance(hypothesis, Mapping):
            continue
        hypothesis_id = _text(hypothesis.get("hypothesis_id"))
        if not hypothesis_id or hypothesis_id in hypothesis_states:
            continue
        assessment = hypothesis.get("model_assessment")
        if not isinstance(assessment, Mapping):
            assessment = hypothesis.get("deterministic_assessment")
        if not isinstance(assessment, Mapping):
            assessment = {}
        hypothesis_states[hypothesis_id] = {
            "status": _text(hypothesis.get("status")) or "untested",
            "assessment": _text(assessment.get("status")) or "unassessed",
            "evidence_ids": _sorted_ids(assessment.get("evidence_ids", [])),
        }
    hypothesis_states = {key: hypothesis_states[key] for key in sorted(hypothesis_states)}

    graph = state.get("investigation_graph", {})
    if not isinstance(graph, Mapping):
        graph = {}
    graph_node_ids = _sorted_ids(
        item.get("node_id") for item in graph.get("nodes", []) or [] if isinstance(item, Mapping)
    )
    graph_edge_ids = _sorted_ids(
        item.get("edge_id") for item in graph.get("edges", []) or [] if isinstance(item, Mapping)
    )
    path_ids = _sorted_ids(
        item.get("path_id") for item in graph.get("paths", []) or [] if isinstance(item, Mapping)
    )

    open_gaps: set[str] = set()
    coverage = state.get("coverage", {})
    ledger = coverage.get("hypothesis_coverage", {}) if isinstance(coverage, Mapping) else {}
    if isinstance(ledger, Mapping):
        for hypothesis_id in ledger.get("untested_hypotheses", []) or []:
            if _text(hypothesis_id):
                open_gaps.add(f"hypothesis:{_text(hypothesis_id)}")
        for row in ledger.get("rows", []) or []:
            if not isinstance(row, Mapping) or row.get("closed"):
                continue
            if _text(row.get("hypothesis_id")):
                open_gaps.add(f"hypothesis:{_text(row.get('hypothesis_id'))}")
            for task_id in row.get("unresolved_task_ids", []) or []:
                if _text(task_id):
                    open_gaps.add(f"task:{_text(task_id)}")
        for candidate_id in ledger.get("open_candidate_ids", []) or []:
            if _text(candidate_id):
                open_gaps.add(f"candidate:{_text(candidate_id)}")
        for row in ledger.get("candidate_rows", []) or []:
            if not isinstance(row, Mapping) or row.get("closed"):
                continue
            if _text(row.get("candidate_id")):
                open_gaps.add(f"candidate:{_text(row.get('candidate_id'))}")
            for follow_up_id in row.get("unfinished_follow_up_ids", []) or []:
                if _text(follow_up_id):
                    open_gaps.add(f"follow_up:{_text(follow_up_id)}")
            for task_id in row.get("unresolved_task_ids", []) or []:
                if _text(task_id):
                    open_gaps.add(f"task:{_text(task_id)}")

    return {
        "evidence_ids": evidence_ids,
        "candidate_states": candidate_states,
        "search_fingerprints": search_fingerprints,
        "resolving_task_ids": resolving_task_ids,
        "hypothesis_states": hypothesis_states,
        "graph_node_ids": graph_node_ids,
        "graph_edge_ids": graph_edge_ids,
        "path_ids": path_ids,
        "open_gap_ids": sorted(open_gaps),
    }


def compare_progress(previous: Mapping[str, Any], current: Mapping[str, Any]) -> dict[str, Any]:
    """Classify only newly admitted or newly resolved stable investigation facts."""

    signals: dict[str, int] = {}
    changed_ids: dict[str, list[str]] = {}

    def additions(field: str, signal: str) -> None:
        added = sorted(set(current.get(field, []) or []) - set(previous.get(field, []) or []))
        if added:
            signals[signal] = len(added)
            changed_ids[signal] = added[:100]

    additions("evidence_ids", "new_evidence")
    additions("search_fingerprints", "new_search_fingerprints")
    additions("resolving_task_ids", "new_resolving_outcomes")
    additions("graph_node_ids", "new_graph_nodes")
    additions("graph_edge_ids", "new_graph_edges")
    additions("path_ids", "new_paths")

    previous_candidates = previous.get("candidate_states", {})
    current_candidates = current.get("candidate_states", {})
    if not isinstance(previous_candidates, Mapping):
        previous_candidates = {}
    if not isinstance(current_candidates, Mapping):
        current_candidates = {}
    new_candidates = sorted(set(current_candidates) - set(previous_candidates))
    candidate_updates = sorted(
        key for key in set(current_candidates) & set(previous_candidates)
        if current_candidates[key] != previous_candidates[key]
    )
    if new_candidates:
        signals["new_candidates"] = len(new_candidates)
        changed_ids["new_candidates"] = new_candidates[:100]
    if candidate_updates:
        signals["candidate_updates"] = len(candidate_updates)
        changed_ids["candidate_updates"] = candidate_updates[:100]

    previous_hypotheses = previous.get("hypothesis_states", {})
    current_hypotheses = current.get("hypothesis_states", {})
    if not isinstance(previous_hypotheses, Mapping):
        previous_hypotheses = {}
    if not isinstance(current_hypotheses, Mapping):
        current_hypotheses = {}
    hypothesis_updates = sorted(
        key for key in current_hypotheses
        if key not in previous_hypotheses or current_hypotheses[key] != previous_hypotheses[key]
    )
    if hypothesis_updates:
        signals["hypothesis_updates"] = len(hypothesis_updates)
        changed_ids["hypothesis_updates"] = hypothesis_updates[:100]

    closed_gaps = sorted(
        set(previous.get("open_gap_ids", []) or []) - set(current.get("open_gap_ids", []) or [])
    )
    if closed_gaps:
        signals["closed_coverage_gaps"] = len(closed_gaps)
        changed_ids["closed_coverage_gaps"] = closed_gaps[:100]

    return {
        "material_progress": bool(signals),
        "signals": signals,
        "changed_ids": changed_ids,
    }


def _totals_from_history(history: Any) -> dict[str, Any]:
    entries = [entry for entry in history if isinstance(entry, Mapping)] if isinstance(history, list) else []
    signal_totals: dict[str, int] = {}
    productive_cycles = 0
    max_stagnant_cycles_seen = 0
    for entry in entries:
        if entry.get("material_progress") is True:
            productive_cycles += 1
        stagnant = entry.get("stagnant_cycles", 0)
        if isinstance(stagnant, int) and not isinstance(stagnant, bool):
            max_stagnant_cycles_seen = max(max_stagnant_cycles_seen, max(0, stagnant))
        signals = entry.get("signals", {})
        if not isinstance(signals, Mapping):
            continue
        for name, count in signals.items():
            if isinstance(count, int) and not isinstance(count, bool) and count > 0:
                signal_totals[str(name)] = signal_totals.get(str(name), 0) + count
    return {
        "cycles_recorded": len(entries),
        "productive_cycles": productive_cycles,
        "stagnant_cycles_recorded": len(entries) - productive_cycles,
        "max_stagnant_cycles_seen": max_stagnant_cycles_seen,
        "signal_totals": dict(sorted(signal_totals.items())),
    }


def _normalized_totals(value: Any, history: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        return _totals_from_history(history)
    fallback = _totals_from_history(history)
    normalized: dict[str, Any] = {}
    for field in ("cycles_recorded", "productive_cycles", "stagnant_cycles_recorded",
                  "max_stagnant_cycles_seen"):
        count = value.get(field, fallback[field])
        normalized[field] = max(0, count) if isinstance(count, int) and not isinstance(count, bool) else fallback[field]
    signals = value.get("signal_totals", fallback["signal_totals"])
    normalized["signal_totals"] = dict(sorted(
        (str(name), count) for name, count in signals.items()
        if isinstance(count, int) and not isinstance(count, bool) and count > 0
    )) if isinstance(signals, Mapping) else fallback["signal_totals"]
    return normalized


def initialize_progress(state: MutableMapping[str, Any]) -> None:
    """Add progress bookkeeping to new or legacy state without inventing a cycle."""

    if not isinstance(state.get("progress_baseline"), Mapping):
        state["progress_baseline"] = snapshot_progress(state)
    if not isinstance(state.get("progress_history"), list):
        state["progress_history"] = []
    state["progress_totals"] = _normalized_totals(
        state.get("progress_totals"), state["progress_history"]
    )

    stagnant_cycles = state.get("stagnant_cycles", 0)
    if not isinstance(stagnant_cycles, int) or isinstance(stagnant_cycles, bool):
        stagnant_cycles = 0
    state["stagnant_cycles"] = max(0, stagnant_cycles)


def record_progress(
    state: MutableMapping[str, Any],
    stage: str,
    history_limit: int = 100,
) -> dict[str, Any]:
    """Record one deterministic cycle against the preceding stable snapshot."""

    if not isinstance(history_limit, int) or isinstance(history_limit, bool) or history_limit < 1:
        raise ValueError("history_limit must be a positive integer")

    had_baseline = isinstance(state.get("progress_baseline"), Mapping)
    initialize_progress(state)
    if not had_baseline:
        return {
            "stage": _text(stage) or "unknown",
            "material_progress": False,
            "signals": {},
            "changed_ids": {},
            "stagnant_cycles": state["stagnant_cycles"],
            "initial_baseline": True,
        }

    current = snapshot_progress(state)
    assessment = compare_progress(state["progress_baseline"], current)
    stagnant_cycles = 0 if assessment["material_progress"] else state["stagnant_cycles"] + 1
    entry = {
        "stage": _text(stage) or "unknown",
        "material_progress": assessment["material_progress"],
        "signals": assessment["signals"],
        "changed_ids": assessment["changed_ids"],
        "stagnant_cycles": stagnant_cycles,
        "initial_baseline": False,
    }

    history = state["progress_history"]
    history.append(entry)
    state["progress_history"] = history[-history_limit:]
    totals = state["progress_totals"]
    totals["cycles_recorded"] += 1
    cycle_field = "productive_cycles" if assessment["material_progress"] else "stagnant_cycles_recorded"
    totals[cycle_field] += 1
    totals["max_stagnant_cycles_seen"] = max(totals["max_stagnant_cycles_seen"], stagnant_cycles)
    for name, count in assessment["signals"].items():
        totals["signal_totals"][name] = totals["signal_totals"].get(name, 0) + count
    totals["signal_totals"] = dict(sorted(totals["signal_totals"].items()))
    state["progress_baseline"] = current
    state["stagnant_cycles"] = stagnant_cycles
    return entry


def summarize_progress(state: Mapping[str, Any]) -> dict[str, Any]:
    """Summarize the bounded ledger for reporting without retaining model prose."""

    history = state.get("progress_history", [])
    if not isinstance(history, list):
        history = []
    entries = [entry for entry in history if isinstance(entry, Mapping)]

    totals = _normalized_totals(state.get("progress_totals"), history)

    current_stagnant = state.get("stagnant_cycles", 0)
    if not isinstance(current_stagnant, int) or isinstance(current_stagnant, bool):
        current_stagnant = 0
    last = entries[-1] if entries else {}
    last_signals = last.get("signals", {}) if isinstance(last, Mapping) else {}
    if not isinstance(last_signals, Mapping):
        last_signals = {}

    return {
        "cycles_recorded": totals["cycles_recorded"],
        "productive_cycles": totals["productive_cycles"],
        "stagnant_cycles_recorded": totals["stagnant_cycles_recorded"],
        "current_stagnant_cycles": max(0, current_stagnant),
        "max_stagnant_cycles_seen": totals["max_stagnant_cycles_seen"],
        "signal_totals": totals["signal_totals"],
        "last_stage": _text(last.get("stage")) or None,
        "last_material_signals": dict(last_signals) if last.get("material_progress") else {},
        "final_stop_basis": _text(state.get("termination_reason")) or None,
    }


def decide_next_action(
    *,
    hard_limit_reason: str | None,
    reasoning_limit_reason: str | None,
    coverage_closed: bool,
    queued_priority_tier: int | None,
    grounded: bool,
    can_reason: bool,
    just_reasoned: bool,
    stagnant_cycles: int,
    max_stagnant_cycles: int,
) -> dict[str, str]:
    """Choose the next hunt action from facts, limits, and queue priority alone."""

    if hard_limit_reason:
        return {"action": "report", "termination_reason": hard_limit_reason}
    if coverage_closed:
        return {"action": "report", "termination_reason": "coverage_closure_reached"}

    has_queued_work = (
        isinstance(queued_priority_tier, int)
        and not isinstance(queued_priority_tier, bool)
        and queued_priority_tier > 0
    )
    high_value_work = has_queued_work and queued_priority_tier <= 2
    if high_value_work:
        return {"action": "pivot"}

    valid_stagnation_limit = (
        max_stagnant_cycles
        if isinstance(max_stagnant_cycles, int)
        and not isinstance(max_stagnant_cycles, bool)
        and max_stagnant_cycles > 0
        else 1
    )
    valid_stagnant_cycles = (
        max(0, stagnant_cycles)
        if isinstance(stagnant_cycles, int) and not isinstance(stagnant_cycles, bool)
        else 0
    )
    if valid_stagnant_cycles >= valid_stagnation_limit:
        return {"action": "report", "termination_reason": "no_productive_frontier"}

    if grounded and can_reason and not just_reasoned:
        return {"action": "reason"}
    if has_queued_work:
        return {"action": "pivot"}
    if reasoning_limit_reason:
        return {"action": "report", "termination_reason": reasoning_limit_reason}
    return {"action": "report", "termination_reason": "no_productive_frontier"}
