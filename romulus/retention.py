"""Safe, hunt-scoped post-report retention policies."""
from __future__ import annotations

from copy import deepcopy
import hashlib
from pathlib import Path
from typing import Any
import zipfile

from .models import utc_now
from .store import Store


class RetentionError(RuntimeError):
    """Raised before cleanup when retention preconditions are not satisfied."""


def apply_retention(
    store: Store, state: dict[str, Any], policy: str = "compact", *, automatic: bool = False,
) -> dict[str, Any]:
    """Apply a retention policy without changing the investigation conclusion.

    Automatic compaction is limited to completed hunts.  Calling this function
    explicitly with ``automatic=False`` finalizes a reported partial hunt.
    """
    if policy not in {"compact", "full"}:
        raise RetentionError(f"Unsupported retention policy: {policy}")
    working = deepcopy(state)
    hunt_id = str(working.get("hunt_id") or "")
    if not hunt_id:
        raise RetentionError("Investigation ID is required for retention")
    existing = working.get("retention") if isinstance(working.get("retention"), dict) else {}
    if policy == "compact" and existing.get("status") == "completed":
        _verify_reports(hunt_id, working.get("report_paths", []))
        return working
    if policy == "full":
        working["retention"] = {"policy":"full","status":"retained","updated_at":utc_now()}
        store.save_state(hunt_id,working)
        return working
    if automatic and working.get("status") != "completed":
        working["retention"] = {
            "policy":"compact","status":"resumable","updated_at":utc_now(),
            "reason":"Automatic compaction is limited to completed hunts.",
        }
        store.save_state(hunt_id,working)
        return working

    reports = _verify_reports(hunt_id, working.get("report_paths", []))
    retained_ids = _cited_evidence_ids(working)
    compact_state = _compact_state(working, retained_ids)
    compact_state["retention"] = {
        "policy":"compact","status":"in_progress","finalized_at":utc_now(),
        "reports_verified":reports,
    }
    database_stats: dict[str, Any] = {}
    try:
        database_stats = store.compact_investigation(hunt_id,compact_state,retained_ids)
        log_stats = store.remove_hunt_log_records(hunt_id)
        checkpoint_stats = store.prune_checkpoints(hunt_id,keep=0,compact=True)
        compact_state["retention"].update({
            "status":"completed",**database_stats,**log_stats,**checkpoint_stats,
        })
        store.save_state(hunt_id,compact_state)
        return compact_state
    except Exception as exc:
        # Some cleanup stages are necessarily separate from the operational
        # database transaction.  The operation is idempotent, and an explicit
        # incomplete marker allows a later retry without changing the outcome.
        fallback = compact_state if database_stats else working
        fallback["retention"] = {
            "policy":"compact","status":"incomplete","finalized_at":utc_now(),
            "reports_verified":reports,"error_type":type(exc).__name__,**database_stats,
        }
        store.save_state(hunt_id,fallback)
        return fallback


def _verify_reports(hunt_id: str, report_paths: Any) -> list[dict[str, Any]]:
    paths=[Path(str(value)) for value in report_paths or []]
    docx_paths=[path for path in paths if path.suffix.lower()==".docx"]
    text_paths=[path for path in paths if path.suffix.lower()==".txt"]
    if not docx_paths or not text_paths:
        raise RetentionError("Both DOCX and TXT reports are required before compaction")
    verified=[]
    for path in docx_paths[:1]+text_paths[:1]:
        if hunt_id not in path.name or not path.is_file() or path.stat().st_size<=0:
            raise RetentionError("A hunt-scoped report is missing or empty")
        if path.suffix.lower()==".docx":
            if not zipfile.is_zipfile(path):
                raise RetentionError("The DOCX report cannot be reopened")
            with zipfile.ZipFile(path) as package:
                if "word/document.xml" not in package.namelist():
                    raise RetentionError("The DOCX report has no document body")
                package.read("word/document.xml")
        else:
            if not path.read_text(encoding="utf-8").strip():
                raise RetentionError("The TXT report cannot be reopened")
        verified.append({
            "path":str(path),"size_bytes":path.stat().st_size,
            "sha256":hashlib.sha256(path.read_bytes()).hexdigest(),
        })
    return verified


def _cited_evidence_ids(state: dict[str, Any]) -> set[str]:
    cited={
        str(evidence_id) for finding in state.get("findings",[]) or []
        for evidence_id in (finding.get("evidence_ids") or []) if str(evidence_id).strip()
    }
    for candidate in state.get("candidate_leads",[]) or []:
        if not candidate.get("customer_visible"): continue
        cited.update(str(value) for value in candidate.get("evidence_ids",[]) or [] if str(value).strip())
    for path in (state.get("investigation_graph") or {}).get("paths",[]) or []:
        for step in path.get("steps",[]) or []:
            cited.update(str(value) for value in step.get("evidence_ids",[]) or [] if str(value).strip())
        for relationship in path.get("relationships",[]) or []:
            cited.update(str(value) for value in relationship.get("evidence_ids",[]) or [] if str(value).strip())
    return cited


def _compact_state(state: dict[str, Any], retained_ids: set[str]) -> dict[str, Any]:
    keys=(
        "hunt_id","objective","status","outcome","termination_reason","mission_mode","mode","retention_policy",
        "started_at","resumed_at","finished_at","duration_ms","summary","report_paths",
        "tool_calls","depth",
    )
    compact={key:deepcopy(state[key]) for key in keys if key in state}
    compact["manifest_version"]=1
    compact["findings"]=deepcopy(state.get("findings",[]) or [])
    compact["candidate_leads"]=[
        deepcopy(candidate) for candidate in state.get("candidate_leads",[]) or []
        if candidate.get("customer_visible")
    ]
    compact["coverage"]=_compact_coverage(state.get("coverage",{}))
    compact["source_errors"]=[{
        key:error.get(key) for key in ("tool","stage","error","status_code") if error.get(key) is not None
    } for error in state.get("source_errors",[]) or []]
    compact["investigation_graph"]=_compact_graph(state.get("investigation_graph",{}),retained_ids)
    return compact


def _compact_coverage(coverage: Any) -> dict[str, Any]:
    if not isinstance(coverage,dict): return {}
    keys=(
        "time_scope","host","network","network_sources","source_error_count",
        "coverage_closure_ready","tool_calls_used","tool_call_limit","depth_used","depth_limit",
        "minimum_reasoning_rounds","termination_reason","behavior_candidates","analyst_model",
    )
    return {key:deepcopy(coverage[key]) for key in keys if key in coverage}


def _compact_graph(graph: Any, retained_ids: set[str]) -> dict[str, Any]:
    if not isinstance(graph,dict):
        return {"version":1,"nodes":[],"edges":[],"paths":[],"summary":{}}
    retained_paths=[]
    for path in graph.get("paths",[]) or []:
        step_ids={
            str(value) for step in path.get("steps",[]) or []
            for value in step.get("evidence_ids",[]) or []
        }
        if step_ids and step_ids<=retained_ids:
            retained_paths.append(deepcopy(path))
    base_node_ids=set()
    for node in graph.get("nodes",[]) or []:
        evidence_id=node.get("evidence_id")
        evidence_ids=set(str(value) for value in node.get("evidence_ids",[]) or [])
        if evidence_id in retained_ids or evidence_ids & retained_ids:
            base_node_ids.add(node.get("node_id"))
    retained_edges=[]; entity_node_ids=set()
    for edge in graph.get("edges",[]) or []:
        source,target=edge.get("source"),edge.get("target")
        if source in base_node_ids and str(target).startswith("entity:"):
            entity_node_ids.add(target)
        if source in base_node_ids and target in base_node_ids:
            retained_edges.append(deepcopy(edge))
    kept_node_ids=base_node_ids|entity_node_ids
    for edge in graph.get("edges",[]) or []:
        if edge.get("source") in base_node_ids and edge.get("target") in entity_node_ids:
            retained_edges.append(deepcopy(edge))
    nodes=[deepcopy(node) for node in graph.get("nodes",[]) or [] if node.get("node_id") in kept_node_ids]
    unique_edges={edge.get("edge_id"):edge for edge in retained_edges if edge.get("edge_id")}
    edges=sorted(unique_edges.values(),key=lambda edge:str(edge.get("edge_id")))
    nodes.sort(key=lambda node:str(node.get("node_id")))
    summary={
        "evidence_nodes":sum(node.get("node_type")=="evidence" for node in nodes),
        "activity_nodes":sum(node.get("node_type")=="activity" for node in nodes),
        "entity_nodes":sum(node.get("node_type")=="entity" for node in nodes),
        "observed_edges":sum(edge.get("basis")=="observed" for edge in edges),
        "inferred_edges":sum(edge.get("basis")=="inferred" for edge in edges),
    }
    return {"version":graph.get("version",1),"nodes":nodes,"edges":edges,"paths":retained_paths,"summary":summary}
