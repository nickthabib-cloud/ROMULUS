"""Safe, hunt-scoped post-report retention policies."""
from __future__ import annotations

from copy import deepcopy
import hashlib
from pathlib import Path
import re
from typing import Any

from .models import utc_now
from .store import Store


class RetentionError(RuntimeError):
    """Raised before cleanup when retention preconditions are not satisfied."""


def is_retention_finalized(state: dict[str, Any]) -> bool:
    """Recognize both current and pre-finalized-field terminal retention states."""
    existing=state.get("retention") if isinstance(state.get("retention"),dict) else {}
    return existing.get("finalized") is True or (
        existing.get("policy")=="compact" and existing.get("status")=="completed"
    )


def validate_retention_transition(
    state: dict[str, Any], policy: str, *, automatic: bool = False, finalize: bool = False,
) -> None:
    """Fail before reports or retained state can be rewritten by an illegal transition."""
    if policy not in {"compact", "full"}:
        raise RetentionError(f"Unsupported retention policy: {policy}")
    if not str(state.get("hunt_id") or ""):
        raise RetentionError("Investigation ID is required for retention")
    hunt_status=str(state.get("status") or "")
    if hunt_status not in {"completed","partial"}:
        raise RetentionError("Only completed or partial hunts can enter retention")
    existing=state.get("retention") if isinstance(state.get("retention"),dict) else {}
    compact_started=(existing.get("policy")=="compact" and existing.get("status") in {"in_progress","incomplete","completed"})
    if compact_started and policy!="compact":
        raise RetentionError("Compact retention is irreversible and cannot be relabelled full")
    if hunt_status=="partial" and not automatic and not finalize and not is_retention_finalized(state):
        raise RetentionError("A partial hunt must be explicitly finalized before retention")


def apply_retention(
    store: Store, state: dict[str, Any], policy: str = "compact", *, automatic: bool = False,
    finalize: bool = False,
) -> dict[str, Any]:
    """Apply a retention policy without changing the investigation conclusion.

    Automatic finalization is limited to completed hunts.  Calling this function
    explicitly with ``automatic=False`` finalizes a reported partial hunt.
    """
    working = deepcopy(state)
    validate_retention_transition(working,policy,automatic=automatic,finalize=finalize)
    hunt_id = str(working.get("hunt_id") or "")
    hunt_status=str(working.get("status") or "")
    existing = working.get("retention") if isinstance(working.get("retention"), dict) else {}
    if policy == "compact" and existing.get("status") == "completed":
        _verify_reports(hunt_id, working.get("report_paths", []))
        working["retention_policy"]="compact"
        working["retention"]["finalized"]=True
        store.save_state(hunt_id,working)
        return working
    working["retention_policy"]=policy
    if hunt_status=="partial" and automatic:
        working["retention"] = {
            "policy":policy,"status":"resumable","finalized":False,"updated_at":utc_now(),
            "reason":"Automatic finalization is limited to completed hunts.",
        }
        store.save_state(hunt_id,working)
        return working
    reports = _verify_reports(hunt_id, working.get("report_paths", []))
    if policy == "full":
        working["retention"] = {
            "policy":"full","status":"retained","finalized":True,"updated_at":utc_now(),
            "reports_verified":reports,
        }
        store.save_state(hunt_id,working)
        return working

    retained_ids = _cited_evidence_ids(working)
    compact_state = _compact_state(working, retained_ids)
    compact_state["retention"] = {
        "policy":"compact","status":"in_progress","finalized":True,"finalized_at":utc_now(),
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
            "policy":"compact","status":"incomplete","finalized":True,"finalized_at":utc_now(),
            "reports_verified":reports,"error_type":type(exc).__name__,**database_stats,
        }
        store.save_state(hunt_id,fallback)
        return fallback


def _verify_reports(hunt_id: str, report_paths: Any) -> list[dict[str, Any]]:
    paths=[Path(str(value)) for value in report_paths or []]
    docx_paths=[path for path in paths if path.suffix.lower()==".docx"]
    text_paths=[path for path in paths if path.suffix.lower()==".txt"]
    if len(docx_paths)!=1 or len(text_paths)!=1:
        raise RetentionError("Exactly one DOCX and one TXT report are required before compaction")
    docx_path,text_path=docx_paths[0],text_paths[0]
    if docx_path.stem!=text_path.stem:
        raise RetentionError("The DOCX and TXT reports do not belong to the same generation")
    verified=[]
    for path in (docx_path,text_path):
        if not path.name.startswith(f"{hunt_id}-") or not path.is_file() or path.stat().st_size<=0:
            raise RetentionError("A hunt-scoped report is missing or empty")
        if path.suffix.lower()==".docx":
            try:
                from docx import Document
                document=Document(path)
                text="\n".join(
                    [paragraph.text for paragraph in document.paragraphs]
                    +[cell.text for table in document.tables for row in table.rows for cell in row.cells]
                    +[paragraph.text for section in document.sections for paragraph in section.header.paragraphs]
                    +[paragraph.text for section in document.sections for paragraph in section.footer.paragraphs]
                )
            except Exception as exc:
                raise RetentionError("The DOCX report cannot be reopened by the Word parser") from exc
            identity=re.compile(rf"(?<![A-Za-z0-9-]){re.escape(hunt_id)}(?![A-Za-z0-9-])")
            if not identity.search(text):
                raise RetentionError("The DOCX report does not identify this hunt")
        else:
            try: text=path.read_text(encoding="utf-8")
            except (OSError,UnicodeError) as exc:
                raise RetentionError("The TXT report cannot be reopened") from exc
            if not text.strip():
                raise RetentionError("The TXT report cannot be reopened")
            if f"Investigation: {hunt_id}" not in {line.strip() for line in text.splitlines()}:
                raise RetentionError("The TXT report does not identify this hunt")
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
    compact["coverage"]["scheduler_summary"]=_scheduler_summary(state)
    compact["coverage"]["sampling_summary"]=_sampling_summary(state)
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


def _scheduler_summary(state: dict[str, Any]) -> dict[str, Any]:
    tasks=list(state.get("search_tasks",{}).values()) if isinstance(state.get("search_tasks"),dict) else []
    outcomes={item.get("task_id"):item for item in state.get("search_outcomes",[]) or []
        if isinstance(item,dict) and item.get("task_id")}
    def counts(values):
        result={}
        for value in values:
            key=str(value or "unknown"); result[key]=result.get(key,0)+1
        return dict(sorted(result.items()))
    def resolves(outcome):
        return bool(isinstance(outcome,dict) and outcome.get("status")=="completed"
            and isinstance(outcome.get("matched_total"),int) and not isinstance(outcome.get("matched_total"),bool)
            and not any((outcome.get("capped"),outcome.get("timed_out"),outcome.get("shard_failures"),outcome.get("incomplete"))))
    history=state.get("scheduler_history",[]) or []
    fairness=[deepcopy(item) for item in history if isinstance(item,dict) and "budget_gap" in str(item.get("event"))][-20:]
    fairness.extend(deepcopy(item) for item in (state.get("coverage",{}).get("scheduler_gaps",[]) or [])[-20:])
    return {"tasks_total":len(tasks),
        "by_origin":counts(origin for task in tasks for origin in (task.get("origins") or [task.get("origin")])),
        "by_source":counts(task.get("source") for task in tasks),
        "by_status":counts(task.get("status") for task in tasks),
        "duplicate_merges_avoided":sum(item.get("event")=="task_merged" for item in history if isinstance(item,dict)),
        "unresolved_task_count":sum(not resolves(outcomes.get(task.get("task_id"))) for task in tasks),
        "source_fairness_gaps":fairness[:40]}


def _sampling_summary(state: dict[str, Any]) -> dict[str, Any]:
    outcomes=[item for item in state.get("search_outcomes",[]) or [] if isinstance(item,dict)]
    summaries=[item["sampling"] for item in outcomes if isinstance(item.get("sampling"),dict)]
    def counts(values):
        result={}
        for value in values:
            key=str(value or "unknown"); result[key]=result.get(key,0)+1
        return dict(sorted(result.items()))
    def integer_total(field):
        return sum(int(item.get(field,0)) for item in summaries
            if isinstance(item.get(field),int) and not isinstance(item.get(field),bool))
    retained=sum(sum(int(value) for value in item.get("retained_by_stratum",[])[:24]
        if isinstance(value,int) and not isinstance(value,bool) and value>=0) for item in summaries)
    fallbacks=counts(item.get("fallback_reason") for item in summaries if item.get("fallback_reason"))
    return {"tasks_with_sampling":len(summaries),
        "by_strategy":counts(item.get("strategy") for item in summaries),
        "requested_strata":integer_total("requested_strata"),
        "covered_strata":integer_total("covered_strata"),
        "retained_records":retained,"fallbacks":fallbacks}


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
