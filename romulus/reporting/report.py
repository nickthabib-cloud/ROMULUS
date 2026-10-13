"""Professional DOCX and portable plain-text report generation."""
from pathlib import Path
from datetime import datetime, timezone
from typing import Any
from ..intelligence.knowledge import TECHNIQUES, ATTACK_RELEASE, ATTACK_RELEASE_DATE, ATTACK_DOMAIN
from ..investigation.classification import unresolved_anomalous_candidates
from .report_items import build_report_items

def generate_report(state: dict[str, Any], output_dir: Path) -> list[Path]:
    output_dir.mkdir(parents=True,exist_ok=True)
    hid=state.get("hunt_id","UNKNOWN"); stamp=datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    anomalies=unresolved_anomalous_candidates(state.get("candidate_leads",[]) or [])
    finalized=state.get("status")=="completed" or bool(state.get("finalized_at"))
    anomaly_expected=bool(finalized and anomalies)
    state["report_manifest"]={"generation_stamp":stamp,"anomaly_expected":anomaly_expected}
    state=_xml_safe(state)
    text_path=output_dir/f"{hid}-{stamp}.txt"; docx_path=output_dir/f"{hid}-{stamp}.docx"
    content=_content(state)
    text_path.write_text(content,encoding="utf-8")
    try: _docx(state,docx_path)
    except ImportError as e: raise RuntimeError("python-docx is required to generate the Word deliverable") from e
    paths=[docx_path,text_path]
    if anomaly_expected:
        anomaly_dir=output_dir/"anomalous"; anomaly_dir.mkdir(parents=True,exist_ok=True)
        anomaly_path=anomaly_dir/f"{hid}-anomalous-leads-{stamp}.txt"
        anomaly_path.write_text(_anomaly_content(state,unresolved_anomalous_candidates(
            state.get("candidate_leads",[]) or [])),encoding="utf-8")
        paths.append(anomaly_path)
    return paths

def _xml_safe(value):
    """Remove characters forbidden by XML 1.0 from telemetry-derived text."""
    if isinstance(value,str):
        return "".join(ch for ch in value if ch in "\t\n\r" or 0x20<=ord(ch)<=0xD7FF or 0xE000<=ord(ch)<=0xFFFD or 0x10000<=ord(ch)<=0x10FFFF)
    if isinstance(value,dict):
        return {_xml_safe(key):_xml_safe(item) for key,item in value.items()}
    if isinstance(value,list):
        return [_xml_safe(item) for item in value]
    if isinstance(value,tuple):
        return tuple(_xml_safe(item) for item in value)
    return value

def _join_text(values, separator=", "):
    """Format model-derived lists defensively; structured output can still contain nulls."""
    if values is None: return ""
    if isinstance(values,str): return values
    if not isinstance(values,(list,tuple,set)): return str(values)
    return separator.join(str(value) for value in values if value is not None and str(value).strip())

def _event_reference(event):
    """Keep report citations useful without repeating large query DSL per event."""
    provenance=event.get("provenance",{}) if isinstance(event.get("provenance"),dict) else {}
    parts=[str(event.get("source") or "unknown")]
    retrieval=provenance.get("search_id") or provenance.get("lead_id")
    if retrieval: parts.append(f"search={retrieval}")
    for key in ("index","document_id","session_id","pcap"):
        value=provenance.get(key)
        if value is not None: parts.append(f"{key}={value}")
    raw=event.get("raw",{}) if isinstance(event.get("raw"),dict) else {}
    frame=raw.get("frame.number")
    if frame is not None: parts.append(f"frame={frame}")
    return "; ".join(parts)

def _bounded_report_events(state, key, limit=175):
    rows=list(state.get(key,[])); cited=set()
    for item in build_report_items(state): cited.update(item.get("evidence_ids",[]) or [])
    for finding in state.get("findings",[]): cited.update(finding.get("evidence_ids",[]) or [])
    for hypothesis in state.get("hypotheses",[]): cited.update(hypothesis.get("evidence_ids",[]) or [])
    chosen=[row for row in rows if row.get("evidence_id") in cited]
    chosen_ids={row.get("evidence_id") for row in chosen}
    remaining=[row for row in rows if row.get("evidence_id") not in chosen_ids]
    slots=max(0,limit-len(chosen))
    if slots and remaining:
        step=max(1,len(remaining)//slots)
        chosen.extend(remaining[::step][:slots])
    return sorted(chosen[:max(limit,len(chosen))],key=lambda row:str(row.get("observed_at") or ""))

def _analytic_lines(summary):
    if not isinstance(summary,dict): return []
    lines=[]; scope=summary.get("scope",{}); quality=summary.get("telemetry_quality",{})
    lines.append(f"- Scope: host={scope.get('host_events',0)}, network={scope.get('network_events',0)}, first={scope.get('first_observed')}, last={scope.get('last_observed')}.")
    lines.append(f"- Data quality: timestamps={quality.get('timestamp_coverage_pct')}%, host entities={quality.get('host_entity_coverage_pct')}%, network endpoints={quality.get('network_endpoint_coverage_pct')}%.")
    for observation in summary.get("behavioral_observations",[])[:12]:
        lines.append(f"- {observation.get('analytic')}: observations={observation.get('observations')}; sample evidence={_join_text(observation.get('sample_evidence_ids'))}. {observation.get('note','')}")
    for fanout in summary.get("network_profile",{}).get("high_fanout",[])[:8]:
        lines.append(f"- Fan-out candidate {fanout.get('source')}: {fanout.get('unique_destinations')} destinations / {fanout.get('unique_destination_ports')} ports; sample={_join_text(fanout.get('sample_evidence_ids'))}.")
    for periodic in summary.get("network_profile",{}).get("periodic_edge_candidates",[])[:8]:
        lines.append(f"- Periodicity candidate {periodic.get('source')} → {periodic.get('destination')}:{periodic.get('port')}: {periodic.get('observations')} observations, mean {periodic.get('mean_interval_seconds')}s, CV {periodic.get('interval_cv')}; sample={_join_text(periodic.get('sample_evidence_ids'))}.")
    return lines

def _candidate_line(candidate):
    return (
        f"- {candidate.get('candidate_id')} {candidate.get('title')} "
        f"[{candidate.get('classification','legacy-unclassified')} / {candidate.get('investigation_status','legacy-status')} / "
        f"{candidate.get('priority_tier')} / score {candidate.get('priority_score')} / {candidate.get('disposition')}]; "
        f"kind={candidate.get('kind')}; evidence={_join_text(candidate.get('evidence_ids')) or 'none'}; "
        f"ATT&CK={_join_text(candidate.get('attack_techniques')) or 'unmapped'}; "
        f"score basis={_join_text(candidate.get('score_reasons'), '; ') or 'not recorded'}; "
        f"benign context={_join_text(candidate.get('benign_explanations'), '; ') or 'none supplied'}; "
        f"follow-up={_join_text(candidate.get('follow_up'), '; ') or 'none supplied'}."
    )


def _report_item_lines(item):
    lines=[
        f"- {item.get('item_id')} {item.get('title')} "
        f"[{str(item.get('classification') or '').upper()} / {item.get('investigation_status')} / confidence {item.get('confidence')}]: "
        f"{item.get('observation')}",
        f"  Why it matters: {item.get('why_it_matters')}",
        f"  Evidence: {_join_text(item.get('evidence_ids')) or 'none cited'}",
        f"  Assets: {_join_text(item.get('assets')) or 'none recorded'}; "
        f"first={item.get('first_observed') or 'not recorded'}; last={item.get('last_observed') or 'not recorded'}; "
        f"ATT&CK={_join_text(item.get('attack_techniques')) or 'unmapped'}.",
        f"  Follow-up results: {_join_text(item.get('follow_up_results'), '; ') or 'none recorded'}",
        f"  Benign alternatives: {_join_text(item.get('benign_alternatives'), '; ') or 'none recorded'}",
        f"  Coverage gaps: {_join_text(item.get('coverage_gaps'), '; ') or 'none recorded'}",
        f"  Recommended actions: {_join_text(item.get('recommended_actions'), '; ') or 'analyst review'}",
    ]
    return lines


def _anomaly_content(state, candidates):
    hunt_id=str(state.get("hunt_id") or "UNKNOWN")
    coverage=state.get("coverage",{}) if isinstance(state.get("coverage"),dict) else {}
    evidence_index={
        str(row.get("evidence_id")):row
        for row in list(state.get("host",[]) or [])+list(state.get("network",[]) or [])
        if isinstance(row,dict) and row.get("evidence_id")
    }
    tasks=state.get("search_tasks",{}) if isinstance(state.get("search_tasks"),dict) else {}
    outcomes={
        str(row.get("task_id")):row for row in state.get("search_outcomes",[]) or []
        if isinstance(row,dict) and row.get("task_id")
    }
    lines=[
        "ROMULUS ANOMALOUS LEAD QUEUE",
        f"Investigation: {hunt_id}",
        f"Hunt window: {coverage.get('time_scope') or 'not recorded'}",
        "Warning: Each entry is an anomalous lead, not a conclusion. Validate it before escalation or action.",
    ]
    for candidate in candidates:
        candidate_id=str(candidate.get("candidate_id") or "unknown")
        owned=list(dict.fromkeys(str(value) for value in candidate.get("evidence_ids",[]) if value))[:12]
        lines += [
            "",
            f"LEAD {candidate_id}: {_bounded_text(candidate.get('title'),240) or 'Untitled anomaly'}",
            f"Status: {candidate.get('investigation_status') or 'new'}",
            "Why unusual: "+(_bounded_text(candidate.get("classification_reason"),500)
                or _bounded_text(candidate.get("description"),500)
                or "The deterministic behavior did not meet the suspicious-report policy without additional context."),
            "Observed facts:",
        ]
        facts=0
        for evidence_id in owned:
            event=evidence_index.get(evidence_id,{})
            provenance=event.get("provenance",{}) if isinstance(event.get("provenance"),dict) else {}
            provenance_bits=[
                f"{key}={_bounded_text(provenance.get(key),160)}"
                for key in ("search_id","lead_id","index","document_id","session_id","pcap")
                if provenance.get(key) is not None
            ]
            lines.append(
                f"- {evidence_id}: {_bounded_text(event.get('observation'),500) or 'Owned evidence record'}; "
                f"source={_bounded_text(event.get('source'),80) or 'unknown'}; "
                f"time={_bounded_text(event.get('observed_at'),80) or 'not recorded'}; "
                f"asset={_bounded_text(event.get('asset'),160) or 'not recorded'}; "
                f"provenance={'; '.join(provenance_bits) or 'compact provenance unavailable'}."
            )
            facts+=1
        if not facts: lines.append("- No owned evidence fact was available in the bounded retained state.")
        lines.append("Performed searches and outcomes:")
        relevant=[]
        for task_id,task in sorted(tasks.items()):
            if not isinstance(task,dict) or candidate_id not in (task.get("candidate_ids") or []): continue
            outcome=outcomes.get(str(task_id),{})
            relevant.append(
                f"- {task_id}: intent={_bounded_text(task.get('intent'),300) or 'not recorded'}; "
                f"status={outcome.get('status') or task.get('status') or 'not recorded'}; "
                f"returned={outcome.get('returned_total','not recorded')}; matched={outcome.get('matched_total','not recorded')}; "
                f"capped={bool(outcome.get('capped'))}; timed_out={bool(outcome.get('timed_out'))}; "
                f"result={_bounded_text(outcome.get('reason') or outcome.get('error_kind'),240) or 'no additional detail'}."
            )
        lines += relevant or ["- No candidate-owned search outcome was recorded."]
        lines.append("Benign alternatives: "+(
            _join_text(_bounded_values(candidate.get("benign_explanations"),300),"; ")
            or "none recorded"))
        lines.append("Coverage gaps: "+(
            _join_text(_bounded_values(candidate.get("telemetry_gaps"),300),"; ")
            or "none recorded"))
        pivots=[
            _bounded_text(row.get("intent"),300) for row in candidate.get("follow_ups",[]) or []
            if isinstance(row,dict) and row.get("intent")
        ] or _bounded_values(candidate.get("follow_up"),300)
        lines.append("Next pivot: "+(_join_text(pivots,"; ") or "Analyst review of the cited evidence and adjacent activity."))
    return "\n".join(lines)+"\n"


def _bounded_text(value,limit):
    if value is None: return ""
    return " ".join(str(value).split())[:max(0,int(limit))]


def _bounded_values(value,limit):
    values=value if isinstance(value,(list,tuple,set)) else [value]
    return [_bounded_text(item,limit) for item in values if _bounded_text(item,limit)]


def _supported_paths(state):
    paths=list((state.get("investigation_graph") or {}).get("paths",[]) or [])
    referenced={
        path_id for finding in state.get("findings",[]) or []
        for path_id in (finding.get("attack_path_ids") or [])
    }
    if referenced:
        paths=[path for path in paths if path.get("path_id") in referenced]
    return sorted(paths,key=lambda path:(str(path.get("finding_id") or ""),int(path.get("segment_index") or 0),str(path.get("path_id") or "")))


def _path_entities(step):
    values=[]
    for entity in step.get("entities",[]) or []:
        value=entity.get("value")
        if value: values.append(f"{entity.get('entity_type','entity')}={value}")
    return _join_text(values)


def _scheduler_lines(state):
    tasks=list(state.get("search_tasks",{}).values()) if isinstance(state.get("search_tasks"),dict) else []
    outcomes={item.get("task_id"):item for item in state.get("search_outcomes",[]) or []
        if isinstance(item,dict) and item.get("task_id")}
    lines=[]
    terminal_resolved={"completed"}
    ordered=sorted(tasks,key=lambda item:(
        1 if (outcomes.get(item.get("task_id"),{}).get("status") or item.get("status")) in terminal_resolved else 0,
        int(item.get("created_sequence",0)),str(item.get("task_id",""))))
    selected=ordered[:250]
    lines.append(f"Scheduler task appendix: shown={len(selected)}; total={len(tasks)}; omitted={max(0,len(tasks)-len(selected))}.")
    for task in selected:
        outcome=outcomes.get(task.get("task_id"),{})
        sampling=outcome.get("sampling") if isinstance(outcome.get("sampling"),dict) else {}
        retained=sampling.get("retained_by_stratum")
        matched_by=sampling.get("matched_by_stratum")
        retained_total=sum(value for value in retained if isinstance(value,int) and not isinstance(value,bool)) if isinstance(retained,list) else 0
        sampling_text=(f"sampling={sampling.get('strategy')}; strata={sampling.get('covered_strata')}/{sampling.get('requested_strata')}; "
            f"sampled_records={retained_total}; retained_by_stratum={_join_text(retained) or 'not recorded'}; "
            f"matched_by_stratum={_join_text(matched_by) or 'not recorded'}; "
            f"sampling_fallback={sampling.get('fallback_reason') or 'none'}; "
            if sampling else "sampling=not recorded; ")
        owners=[]
        for key,label in (("candidate_ids","candidates"),("follow_up_ids","follow-ups"),("hypothesis_ids","hypotheses")):
            if task.get(key): owners.append(f"{label}={_join_text(task.get(key))}")
        scope=(outcome.get("time_range") or task.get("time_range") or {}).get("scope","not recorded")
        lines.append(f"- {task.get('task_id')} {task.get('source')}/{task.get('source_family')} {task.get('phase')}; "
            f"origins={_join_text(task.get('origins') or [task.get('origin')])}; intent={task.get('intent')}; "
            f"owners={'; '.join(owners) or 'none'}; status={outcome.get('status') or task.get('status')}; "
            f"returned={outcome.get('returned_total')}; matched={outcome.get('matched_total')}; scope={scope}; "
            f"capped={bool(outcome.get('capped'))}; timed_out={bool(outcome.get('timed_out'))}; "
            f"shard_failures={outcome.get('shard_failures',0)}; incomplete={bool(outcome.get('incomplete'))}; "
            f"{sampling_text}error={outcome.get('error_kind') or outcome.get('reason') or 'none'}.")
    gaps=[item for item in state.get("scheduler_history",[]) or []
        if isinstance(item,dict) and "budget_gap" in str(item.get("event"))]
    gaps.extend(state.get("coverage",{}).get("scheduler_gaps",[]) or [])
    if gaps:
        lines.append("Unresolved scheduler/source-fairness gaps:")
        for gap in gaps[-40:]:
            task_ids=gap.get("budget_limited_task_ids") or gap.get("queued_task_ids") or []
            total=gap.get("budget_limited_task_count")
            total=int(total) if isinstance(total,int) else len(task_ids)
            lines.append(f"- phase={gap.get('phase')}; event={gap.get('event')}; reason={gap.get('reason')}; "
                f"unserved={_join_text(gap.get('unserved_families')) or 'none'}; "
                f"budget-limited={_join_text(task_ids) or 'none'}; total={total}; omitted={max(0,total-len(task_ids))}.")
    return lines


def _content(s):
    host_events=_bounded_report_events(s,"host"); network_events=_bounded_report_events(s,"network")
    report_items=build_report_items(s)
    coverage=s.get("coverage",{}) if isinstance(s.get("coverage"),dict) else {}
    progress=coverage.get("progress_summary",{}) if isinstance(coverage.get("progress_summary"),dict) else {}
    lines=[f"ROMULUS INVESTIGATION REPORT — {s.get('status','partial').upper()}",f"Investigation: {s.get('hunt_id','')}",f"Generated: {datetime.now(timezone.utc).isoformat(timespec='seconds')}","", "EXECUTIVE SUMMARY",s.get("summary") or "Investigation summary unavailable.",
        f"Outcome: {s.get('outcome','not recorded')}",f"Termination reason: {s.get('termination_reason','not recorded')}",
        f"Elapsed: {s.get('duration_ms','not recorded')} ms",
        f"Tool calls: {s.get('tool_calls',0)} / {s.get('coverage',{}).get('tool_call_limit','not recorded')}; analyst rounds: {s.get('depth',0)} / {s.get('coverage',{}).get('depth_limit','not recorded')}",
        f"Safety backstops: runtime={coverage.get('runtime_seconds_used','not recorded')} / {coverage.get('runtime_seconds_limit','not recorded')} seconds; tool calls={s.get('tool_calls',0)} / {coverage.get('tool_call_limit','not recorded')}; analyst rounds={s.get('depth',0)} / {coverage.get('depth_limit','not recorded')}",
        f"Progress stop basis: {progress.get('final_stop_basis') or s.get('termination_reason','not recorded')}",
        f"Progress cycles: {progress.get('cycles_recorded',0)} recorded; {progress.get('productive_cycles',0)} productive; {progress.get('stagnant_cycles_recorded',0)} stagnant",
        f"Stagnation: current={progress.get('current_stagnant_cycles',coverage.get('stagnant_cycles',0))}; maximum observed={progress.get('max_stagnant_cycles_seen',0)}; configured stop threshold={coverage.get('max_stagnant_cycles','not recorded')}",
        f"ATT&CK knowledge baseline: {ATTACK_DOMAIN} {ATTACK_RELEASE} ({ATTACK_RELEASE_DATE})","", "OBJECTIVE AND SCOPE",s.get("objective",""),"", "DATA SOURCES AND COVERAGE"]
    aggregate_keys={"progress_summary","runtime_seconds_used","runtime_seconds_limit",
        "max_stagnant_cycles","stagnant_cycles","reasoning_summary"}
    lines += [f"- {k}: {v}" for k,v in coverage.items() if k not in
        {"search_fields","analytic_summary","hypothesis_coverage","recent_search_artifacts"}|aggregate_keys]
    lines += ["", "INVESTIGATOR AND CRITIC COVERAGE"]+_reasoning_coverage_lines(s)
    lines += ["", "REASONING AND INVESTIGATION STAGES"]
    for stage in s.get("stage_history",[]): lines.append(f"- {stage.get('timestamp')} {stage.get('stage')}: {stage.get('status')}; details={stage.get('details')}.")
    for stage in s.get("reasoning_history",[]):
        searches=[x.get("intent",x.get("id","")) for x in stage.get("selected_searches",[]) if isinstance(x,dict)]
        lines.append(f"- {stage.get('stage')}: {stage.get('basis')}; round={stage.get('round','n/a')}; next searches={_join_text(searches, '; ') or _join_text(stage.get('selected_leads')) or 'none'}; evidence considered={stage.get('evidence_count',0)}.")
        if stage.get("reasoning"): lines.append(f"  Analyst reasoning: {stage.get('reasoning')}")
        if stage.get("created_hypothesis_ids"): lines.append(f"  New follow-up hypotheses: {_join_text(stage.get('created_hypothesis_ids'))}")
    for run in s.get("tool_runs",[]): lines.append(f"- {run.get('reasoning_stage')}: {run.get('tool')} [{run.get('result_status')}], returned={run.get('result_count',0)}, matched total={run.get('source_total')}, window={run.get('time_range')}, duration={run.get('duration_ms')} ms, error={run.get('error') or 'none'}.")
    lines += ["", "HYPOTHESES"]
    for h in s.get("hypotheses",[]):
        t=TECHNIQUES.get(h.get("technique_id"),{}); lines.append(f"- {h.get('title')} ({h.get('technique_id') or 'unmapped'} {t.get('name','')}): {h.get('status')}; confidence {h.get('confidence')}. {h.get('rationale')}")
        lines.append(f"  Expected host evidence: {_join_text(h.get('expected_host'))}; network: {_join_text(h.get('expected_network'))}. Benign explanations: {_join_text(h.get('benign_explanations'))}.")
        assessment=h.get("model_assessment") or h.get("deterministic_assessment")
        if assessment: lines.append(f"  Evidence assessment: {assessment.get('status')}; rationale={assessment.get('rationale')}; cited events={_join_text(assessment.get('evidence_ids'))}.")
    lines += ["", "HYPOTHESIS AND ANALYTIC COVERAGE"]
    ledger=s.get("coverage",{}).get("hypothesis_coverage",{})
    for row in ledger.get("rows",[]):
        lines.append(f"- {row.get('hypothesis_id')} / {row.get('technique_id')}: priority={row.get('priority')}; analytics attempted={row.get('executed_analytics')}/{row.get('planned_analytics')}; resolved={row.get('resolved_analytics')}; sources={_join_text(row.get('sources')) or 'none'}; returned={row.get('returned')}; assessment={row.get('assessment')}; gaps={_join_text(row.get('telemetry_gaps')) or 'none'}.")
    lines += ["", "UNIFIED SEARCH SCHEDULER"]+(_scheduler_lines(s) or ["No scheduler tasks were recorded."])
    lines += ["", "DETERMINISTIC BEHAVIORAL ANALYTICS"]+(_analytic_lines(s.get("analytic_summary",{})) or ["No analytic summary was produced."])
    for classification,label in (("malicious","MALICIOUS BEHAVIOR"),("suspicious","SUSPICIOUS BEHAVIOR")):
        lines += ["",label]
        selected=[item for item in report_items if item.get("classification")==classification]
        if not selected:
            lines.append(f"No {classification} report items were recorded.")
        for item in selected:
            lines += _report_item_lines(item)
    paths=_supported_paths(s)
    lines += ["", "SUPPORTED ATTACK PATHS"]
    if not paths: lines.append("No evidence-supported multi-record path was derived from the cited findings.")
    for path in paths:
        lines.append(f"- {path.get('path_id')} {path.get('title')} — segment {path.get('segment_index',1)} of {path.get('segment_count',1)}; relationship confidence={path.get('confidence','not assessed')}.")
        for step in path.get("steps",[]):
            lines.append(f"  {step.get('sequence')}. {step.get('observed_at') or 'time unavailable'} {step.get('activity_type')}: {step.get('label')} Evidence={_join_text(step.get('evidence_ids'))}; entities={_path_entities(step) or 'none recorded'}.")
        for relationship in path.get("relationships",[]):
            lines.append(f"  Link {relationship.get('source_sequence')}→{relationship.get('target_sequence')}: {relationship.get('relationship')} [{relationship.get('basis')} / {relationship.get('confidence')}]; reasons={_join_text(relationship.get('reasons'), '; ') or 'not recorded'}.")
        for caveat in path.get("caveats",[]): lines.append(f"  Caveat: {caveat}")
        for gap in path.get("gaps",[]): lines.append(f"  Gap: {gap}")
    lines += ["", f"HOST ANALYSIS — {len(host_events)} representative/cited records of {len(s.get('host',[]))}"]+[f"- {e.get('evidence_id')} {e.get('observed_at')} {e.get('asset')}: {e.get('observation')} [{_event_reference(e)}]" for e in host_events]
    lines += ["", f"NETWORK ANALYSIS — {len(network_events)} representative/cited records of {len(s.get('network',[]))}"]+[f"- {e.get('evidence_id')} {e.get('observed_at')} {e.get('asset')}: {e.get('observation')} [{_event_reference(e)}]" for e in network_events]
    lines += ["", "CROSS-DOMAIN CORRELATION"]
    lines += [f"- Host {c.get('host_ref')} ↔ network {c.get('network_ref')}; reasons={_join_text(c.get('reasons'), '; ') or ('shared IP '+str(c.get('ip')))}; direction={c.get('direction','unresolved')}; score={c.get('score','not scored')}; time delta {c.get('delta_seconds')} seconds. Caveat: {c.get('caveat')}" for c in s.get("correlations",[])] or ["No corroborated cross-domain correlation was made."]
    lines += ["", "ATT&CK MAPPING"]+[f"- {h.get('technique_id')} {TECHNIQUES.get(h.get('technique_id'),{}).get('name','')}: {h.get('status')}" for h in s.get("hypotheses",[])]
    lines += ["", "SEARCH RESULT ARTIFACTS"]
    lines += [f"- {a.get('artifact_id')} {a.get('stage')} via {a.get('tool')}: status={a.get('result_status')}; returned={a.get('returned')}; matched={a.get('matched_total')}; scope={a.get('scope')}; error={a.get('error_reason') or 'none'}." for a in s.get("search_artifacts",[])[:250]] or ["No search artifacts were recorded."]
    lines += ["", "BOUNDED EVIDENCE TIMELINE"]
    timeline=sorted(host_events+network_events,key=lambda e:e.get("observed_at","") or "")
    lines += [f"- {e.get('observed_at')} {e.get('source')}: {e.get('observation')} ({e.get('evidence_id')})" for e in timeline]
    lines += ["", "SOURCE ERRORS AND LIMITATIONS"]
    errors=s.get("source_errors",[])
    lines += [f"- {e.get('tool')} at {e.get('stage')}: {e.get('error')}; {e.get('reason')} (HTTP {e.get('status_code')})" if e.get("status_code") else f"- {e.get('tool')} at {e.get('stage')}: {e.get('error')}; {e.get('reason') or 'no additional detail'}" for e in errors] or ["No source errors were recorded."]
    if s.get("error"): lines.append(s["error"])
    lines += ["This assessment covers only the evidence sources and time period recorded above. Searches and reports are bounded; lack of findings does not establish that the environment is secure.","", "CONCLUSIONS AND RECOMMENDED FOLLOW-UP",s.get("summary") or "", "", "TECHNICAL CANDIDATE WORKING LIST"]
    lines += [_candidate_line(item) for item in s.get("candidate_leads",[])] or ["No catalog candidates were recorded."]
    if s.get("retention_policy")=="compact" and (s.get("status")=="completed" or s.get("finalized_at")):
        retention_note=("This finalized investigation uses compact retention. After both reports are verified, per-hunt working audit records and uncited raw evidence are scheduled for removal; "
            "structured findings, supported paths, and their cited evidence remain in the compact investigation record.")
    else:
        retention_note="Exact compiled queries remain in tool_audit.jsonl and complete raw evidence remains in SQLite unless the hunt is explicitly finalized with compact retention."
    lines += ["", "TECHNICAL EVIDENCE APPENDIX", f"The human-readable evidence manifest is bounded to {len(host_events)} host and {len(network_events)} network records. Stable citations and search-result IDs appear above. {retention_note}"]
    return "\n".join(lines)


def _reasoning_coverage_lines(state):
    coverage=state.get("coverage",{}) if isinstance(state.get("coverage"),dict) else {}
    summary=coverage.get("reasoning_summary")
    if not isinstance(summary,dict):
        return ["No grounded investigator/critic aggregate was recorded for this investigation."]

    def count(key):
        try: return max(0,int(summary.get(key,0)))
        except (TypeError,ValueError): return 0

    lines=[
        f"- Calls: investigator={count('investigator_calls')}; critic={count('critic_calls')}; unavailable passes={count('unavailable_passes')}.",
    ]
    labels=(("Hypotheses","hypotheses"),("Assessments","assessments"),
        ("Searches","searches"),("Findings","findings"))
    for label,key in labels:
        lines.append(f"- {label}: proposed={count('proposed_'+key)}; admitted={count('admitted_'+key)}; rejected={count('rejected_'+key)}.")

    rejection_counts={}
    for stage in state.get("reasoning_history",[]) or []:
        if not isinstance(stage,dict): continue
        grounded=stage.get("grounded_reasoning")
        admission=grounded.get("admission") if isinstance(grounded,dict) else None
        for rejection in admission.get("rejections",[]) if isinstance(admission,dict) else []:
            if not isinstance(rejection,dict): continue
            reasons=rejection.get("reason_codes",[])
            if not isinstance(reasons,list): continue
            for reason in reasons:
                if not isinstance(reason,str) or not reason.strip(): continue
                code=reason.strip()[:120]
                rejection_counts[code]=rejection_counts.get(code,0)+1
    if rejection_counts:
        lines.append("- Rejection reasons: "+"; ".join(
            f"{key}={rejection_counts[key]}" for key in sorted(rejection_counts))+".")
    else:
        lines.append("- Rejection reasons: none recorded.")
    gap=summary.get("last_gap")
    lines.append(f"- Availability gaps: {str(gap)[:160] if gap else 'none recorded'}.")
    return lines

def _docx(s,path):
    from docx import Document
    from docx.shared import Inches,Pt,RGBColor
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    from docx.enum.table import WD_TABLE_ALIGNMENT, WD_CELL_VERTICAL_ALIGNMENT
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn
    navy="18324A"; blue="245B83"; pale_blue="EAF2F8"; pale_gray="F3F5F7"; white="FFFFFF"; amber="C77800"; green="2F6B4F"

    def shade(cell,fill):
        properties=cell._tc.get_or_add_tcPr(); element=properties.find(qn("w:shd"))
        if element is None:
            element=OxmlElement("w:shd"); properties.append(element)
        element.set(qn("w:fill"),fill)

    def set_cell_text(cell,text,bold=False,color=None,size=9):
        cell.text=""; paragraph=cell.paragraphs[0]; run=paragraph.add_run(str(text or "Not recorded"))
        run.bold=bold; run.font.size=Pt(size)
        if color: run.font.color.rgb=RGBColor.from_string(color)
        cell.vertical_alignment=WD_CELL_VERTICAL_ALIGNMENT.CENTER

    def mark_header(row):
        row._tr.get_or_add_trPr().append(OxmlElement("w:tblHeader"))

    def format_table(table,header=True):
        table.alignment=WD_TABLE_ALIGNMENT.CENTER
        for row_index,row in enumerate(table.rows):
            for cell in row.cells:
                properties=cell._tc.get_or_add_tcPr()
                borders=properties.find(qn("w:tcBorders"))
                if borders is None:
                    borders=OxmlElement("w:tcBorders"); properties.append(borders)
                for edge in ("top","left","bottom","right","insideH","insideV"):
                    border=borders.find(qn(f"w:{edge}"))
                    if border is None:
                        border=OxmlElement(f"w:{edge}"); borders.append(border)
                    border.set(qn("w:val"),"single"); border.set(qn("w:sz"),"4"); border.set(qn("w:color"),"D9D9D9")
                margins=properties.find(qn("w:tcMar"))
                if margins is None:
                    margins=OxmlElement("w:tcMar"); properties.append(margins)
                for side in ("top","left","bottom","right"):
                    margin=margins.find(qn(f"w:{side}"))
                    if margin is None:
                        margin=OxmlElement(f"w:{side}"); margins.append(margin)
                    margin.set(qn("w:w"),"90"); margin.set(qn("w:type"),"dxa")
                if header and row_index==0:
                    shade(cell,navy)
                elif row_index%2==0:
                    shade(cell,pale_gray)

    def heading(title):
        paragraph=doc.add_heading(title,level=1); paragraph.paragraph_format.space_before=Pt(13); paragraph.paragraph_format.space_after=Pt(5)
        return paragraph

    def para(value,style=None):
        paragraph=doc.add_paragraph(str(value or "Not recorded."),style=style)
        paragraph.paragraph_format.space_after=Pt(5)
        return paragraph

    def friendly(value):
        return str(value or "Not recorded").replace("_"," ").strip().capitalize()

    findings=list(s.get("findings",[]) or [])
    report_items=build_report_items(s)
    errors=list(s.get("source_errors",[]) or [])
    sampled_outcomes=[item for item in s.get("search_outcomes",[]) or []
        if isinstance(item,dict) and (item.get("capped") or
            isinstance(item.get("sampling"),dict) and item["sampling"].get("strategy") not in {None,"exhaustive"})]
    representative_strategies={"time_stratified","rank_stratified","time_stratified_reservoir","deterministic_reservoir"}
    representative_outcomes=[item for item in sampled_outcomes
        if item.get("sampling",{}).get("strategy") in representative_strategies
        and not item.get("sampling",{}).get("fallback_reason")]
    fallback_outcomes=[item for item in sampled_outcomes if item not in representative_outcomes]
    confidence_order={"not assessed":0,"low":1,"moderate":2,"high":3}
    confidence_values=[]
    for item in report_items:
        value=str(item.get("confidence") or "not assessed").lower()
        if value.isdigit(): value="high" if int(value)>=90 else "moderate" if int(value)>=60 else "low"
        confidence_values.append(value)
    overall_confidence=max(confidence_values,key=lambda value:confidence_order.get(value,0),default="low")
    if any(item.get("classification")=="malicious" for item in report_items):
        verdict="Malicious Activity Identified"
    elif report_items:
        verdict="Suspicious Activity Identified"
    elif s.get("status")!="completed" or errors:
        verdict="Inconclusive"
    else:
        verdict="No Significant Findings"
    priority=("Critical" if any(item.get("classification")=="malicious" for item in report_items)
        else "High" if report_items else "Informational")

    cited_ids={evidence for item in report_items for evidence in (item.get("evidence_ids") or [])}
    assets=[]
    for item in report_items: assets.extend(str(value) for value in item.get("assets",[]) if value)
    for event in list(s.get("host",[]) or [])+list(s.get("network",[]) or []):
        if event.get("evidence_id") in cited_ids and event.get("asset"): assets.append(str(event["asset"]))
    assets=list(dict.fromkeys(assets))

    actions=[str(value).strip() for item in report_items
        for value in item.get("recommended_actions",[]) if str(value).strip()]
    actions=list(dict.fromkeys(actions))[:6]
    if not actions:
        actions=["Review the hunt scope and retain the report with the investigation record."]

    attack_rows=[]; seen_techniques=set()
    technique_inputs=[]
    for item in report_items: technique_inputs.extend(item.get("attack_techniques") or [])
    for hypothesis in s.get("hypotheses",[]) or []:
        if str(hypothesis.get("status") or "").lower() in {"supported","suspected","observed"}:
            technique_inputs.append(hypothesis.get("technique_id"))
    for technique_id in technique_inputs:
        if not technique_id or technique_id in seen_techniques or technique_id not in TECHNIQUES: continue
        seen_techniques.add(technique_id); technique=TECHNIQUES[technique_id]
        attack_rows.append((technique_id,technique.get("name") or "Not recorded",technique.get("tactic") or "Not recorded"))

    doc=Document(); section=doc.sections[0]
    section.top_margin=Inches(.6); section.bottom_margin=Inches(.6); section.left_margin=Inches(.72); section.right_margin=Inches(.72)
    header=section.header.paragraphs[0]; header.text="ROMULUS  |  DEFENSIVE THREAT HUNT"; header.style=doc.styles["Header"]
    header.runs[0].font.color.rgb=RGBColor(0,0,0); header.runs[0].font.size=Pt(8); header.runs[0].bold=True
    footer=section.footer.paragraphs[0]; footer.alignment=WD_ALIGN_PARAGRAPH.CENTER
    footer.add_run(f"{s.get('hunt_id','UNKNOWN')}  •  UNMARKED  •  Page ").font.size=Pt(8)
    field=OxmlElement("w:fldSimple"); field.set(qn("w:instr"),"PAGE"); footer._p.append(field)

    styles=doc.styles; styles["Normal"].font.name="Aptos"; styles["Normal"].font.size=Pt(9.5); styles["Normal"].font.color.rgb=RGBColor.from_string(navy)
    styles["Title"].font.name="Aptos Display"; styles["Title"].font.size=Pt(25); styles["Title"].font.bold=True; styles["Title"].font.color.rgb=RGBColor(0,0,0)
    styles["Heading 1"].font.name="Aptos Display"; styles["Heading 1"].font.size=Pt(15); styles["Heading 1"].font.bold=True; styles["Heading 1"].font.color.rgb=RGBColor(0,0,0)
    styles["Heading 2"].font.name="Aptos"; styles["Heading 2"].font.size=Pt(11); styles["Heading 2"].font.bold=True; styles["Heading 2"].font.color.rgb=RGBColor(0,0,0)

    title_properties=styles["Title"].element.get_or_add_pPr(); title_border=title_properties.find(qn("w:pBdr"))
    if title_border is not None: title_properties.remove(title_border)
    title=doc.add_paragraph(style="Title"); title.alignment=WD_ALIGN_PARAGRAPH.LEFT; title.add_run("Threat Hunt Report")
    subtitle=doc.add_paragraph(); subtitle.paragraph_format.space_after=Pt(12)
    run=subtitle.add_run("ROMULUS autonomous investigation  •  "); run.bold=True; run.font.color.rgb=RGBColor.from_string(blue)
    subtitle.add_run(f"{s.get('hunt_id','UNKNOWN')}  •  {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")

    assessment=doc.add_paragraph(); assessment.paragraph_format.space_after=Pt(12)
    label=assessment.add_run("Assessment  "); label.bold=True
    value=assessment.add_run(verdict); value.bold=True; value.font.color.rgb=RGBColor.from_string(amber if verdict!="No Significant Findings" else green)
    assessment.add_run(f"    Confidence  {overall_confidence.title()}    Priority  {priority}")

    heading("Executive Summary"); para(s.get("summary") or "No investigation summary was recorded.")
    heading("Assessment at a Glance")
    glance=doc.add_table(rows=0,cols=2); glance.style="Light Shading Accent 1"; glance.alignment=WD_TABLE_ALIGNMENT.CENTER
    glance_items=(
        ("Objective",s.get("objective") or "Not recorded"),
        ("Hunt window",s.get("coverage",{}).get("time_scope") or "Not recorded"),
        ("Affected assets",", ".join(assets) if assets else "No affected assets identified"),
        ("Reportable behavior count",str(len(report_items))),
    )
    for label,value in glance_items:
        cells=glance.add_row().cells; set_cell_text(cells[0],label,True,navy); set_cell_text(cells[1],value)
    format_table(glance,header=False)

    heading("What We Found")
    if not report_items:
        para("No reportable suspicious activity met the finding threshold in the telemetry and time range examined.")
    for classification,label in (("malicious","Malicious Behavior"),("suspicious","Suspicious Behavior")):
        doc.add_heading(label,level=2)
        selected=[item for item in report_items if item.get("classification")==classification]
        if not selected: para(f"No {classification} report items were recorded.")
        for item in selected:
            doc.add_heading(str(item.get("title") or "Evidence-backed behavior"),level=2)
            meta=doc.add_paragraph(
                f"{friendly(item.get('classification'))}  •  {friendly(item.get('investigation_status'))}  •  "
                f"{friendly(item.get('confidence'))} confidence"
            )
            meta.runs[0].bold=True; meta.runs[0].font.color.rgb=RGBColor.from_string(blue)
            para(str(item.get("observation") or "No compact observation was recorded."))
            para("Why it matters: "+str(item.get("why_it_matters") or "Not recorded."))
            para("Evidence: "+(_join_text(item.get("evidence_ids")) or "None cited."))
            para("Assets and time: "+(_join_text(item.get("assets")) or "No assets recorded")+
                f"; {item.get('first_observed') or 'time unavailable'} through {item.get('last_observed') or 'time unavailable'}.")
            if item.get("follow_up_results"): para("Follow-up results: "+_join_text(item.get("follow_up_results"),"; "))
            if item.get("benign_alternatives"): para("Possible benign explanation: "+_join_text(item.get("benign_alternatives"),"; "))
            if item.get("coverage_gaps"): para("Limitations: "+_join_text(item.get("coverage_gaps"),"; "))
            if item.get("recommended_actions"): para("Recommended action: "+_join_text(item.get("recommended_actions"),"; "))

    heading("Supported Attack Path")
    supported_paths=_supported_paths(s)
    if not supported_paths:
        para("No evidence-supported multi-record path was derived from the cited findings.")
    for supported_path in supported_paths:
        segment=f" — segment {supported_path.get('segment_index',1)} of {supported_path.get('segment_count',1)}" if int(supported_path.get("segment_count") or 1)>1 else ""
        doc.add_heading(str(supported_path.get("title") or "Evidence-supported activity")+segment,level=2)
        for step in supported_path.get("steps",[]):
            entities=_path_entities(step)
            detail=f"{step.get('sequence')}. {step.get('observed_at') or 'Time unavailable'} — {friendly(step.get('activity_type'))}: {step.get('label')}. Evidence: {_join_text(step.get('evidence_ids'))}."
            if entities: detail+=f" Entities: {entities}."
            para(detail)
        caveats=list(supported_path.get("caveats",[]) or [])+list(supported_path.get("gaps",[]) or [])
        if caveats: para("Limitations: "+_join_text(caveats," "))

    heading("Scope and Coverage")
    scope=doc.add_table(rows=1,cols=2); scope.style="Light Shading Accent 1"; scope.alignment=WD_TABLE_ALIGNMENT.CENTER
    set_cell_text(scope.rows[0].cells[0],"Telemetry",True,white); set_cell_text(scope.rows[0].cells[1],"Coverage result",True,white)
    shade(scope.rows[0].cells[0],navy); shade(scope.rows[0].cells[1],navy); mark_header(scope.rows[0])
    coverage=s.get("coverage",{}) or {}
    for label,key in (("Host telemetry","host"),("Network telemetry","network")):
        cells=scope.add_row().cells; set_cell_text(cells[0],label,True); set_cell_text(cells[1],coverage.get(key) or "Not recorded")
    limitations=[]
    if errors: limitations.append(f"{len(errors)} source error(s) limited the investigation.")
    if representative_outcomes:
        limitations.append(f"{len(representative_outcomes)} search result set(s) used a bounded representative sample; capped searches remain incomplete coverage.")
    if fallback_outcomes:
        limitations.append(f"{len(fallback_outcomes)} search result set(s) used incomplete, nonrepresentative bounded retrieval because complete representative sampling was unavailable.")
    if s.get("termination_reason")=="no_productive_frontier":
        limitations.append("The investigation ended because no further productive evidence pivot was available. Unresolved coverage remains a limitation.")
    if not limitations: limitations.append("No source errors or sampled-result limitations were recorded.")
    cells=scope.add_row().cells; set_cell_text(cells[0],"Collection limitations",True)
    set_cell_text(cells[1]," ".join(limitations)+" See the technical TXT report for details.")
    format_table(scope)
    para("This assessment applies only to the specified time range and the telemetry listed above. No finding is not proof that the environment is free of malicious activity.")

    heading("MITRE ATT&CK Context")
    if attack_rows:
        attack=doc.add_table(rows=1,cols=3); attack.style="Light Shading Accent 1"; attack.alignment=WD_TABLE_ALIGNMENT.CENTER
        for index,label in enumerate(("Technique","Name","Tactic")):
            set_cell_text(attack.rows[0].cells[index],label,True,white); shade(attack.rows[0].cells[index],navy)
        mark_header(attack.rows[0])
        for technique_id,name,tactic in attack_rows:
            cells=attack.add_row().cells
            for index,value in enumerate((technique_id,name,tactic)): set_cell_text(cells[index],value,index==0)
        format_table(attack)
        para(f"Technique names are mapped to MITRE ATT&CK {ATTACK_RELEASE} ({ATTACK_RELEASE_DATE}).")
    else:
        para("No supported finding was mapped to a MITRE ATT&CK technique.")

    assessment_heading=heading("Assessment and Confidence"); assessment_heading.paragraph_format.page_break_before=True
    para(f"Overall assessment: {verdict}. Overall confidence: {overall_confidence.title()}.")
    confidence_bases=[str(item.get("why_it_matters") or "").strip() for item in report_items]
    confidence_bases=[item for item in confidence_bases if item]
    if confidence_bases: para("Confidence basis: "+" ".join(confidence_bases))
    para("Malicious classification is limited to the strict trusted-indicator admission gate. Analyst validation is still required before containment or remediation.")

    heading("Recommended Actions")
    for index,action in enumerate(actions,1): para(f"{index}. {action}")

    divider=doc.add_paragraph(); divider.paragraph_format.space_before=Pt(12)
    run=divider.add_run("Technical record"); run.bold=True; run.font.color.rgb=RGBColor.from_string(blue)
    divider.add_run("  The corresponding TXT report contains search history, hypotheses, tool activity, evidence references, source errors, and the complete candidate working list.")
    doc.save(path)
