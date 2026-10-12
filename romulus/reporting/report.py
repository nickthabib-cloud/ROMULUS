"""Professional DOCX and portable plain-text report generation."""
from pathlib import Path
from datetime import datetime, timezone
from typing import Any
from ..intelligence.knowledge import TECHNIQUES, ATTACK_RELEASE, ATTACK_RELEASE_DATE, ATTACK_DOMAIN

def generate_report(state: dict[str, Any], output_dir: Path) -> list[Path]:
    output_dir.mkdir(parents=True,exist_ok=True)
    state=_xml_safe(state)
    hid=state.get("hunt_id","UNKNOWN"); stamp=datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    text_path=output_dir/f"{hid}-{stamp}.txt"; docx_path=output_dir/f"{hid}-{stamp}.docx"
    content=_content(state)
    text_path.write_text(content,encoding="utf-8")
    try: _docx(state,docx_path)
    except ImportError as e: raise RuntimeError("python-docx is required to generate the Word deliverable") from e
    return [docx_path,text_path]

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

def _content(s):
    host_events=_bounded_report_events(s,"host"); network_events=_bounded_report_events(s,"network")
    lines=[f"ROMULUS INVESTIGATION REPORT — {s.get('status','partial').upper()}",f"Investigation: {s.get('hunt_id','')}",f"Generated: {datetime.now(timezone.utc).isoformat(timespec='seconds')}","", "EXECUTIVE SUMMARY",s.get("summary") or "Investigation summary unavailable.",
        f"Outcome: {s.get('outcome','not recorded')}",f"Termination reason: {s.get('termination_reason','not recorded')}",
        f"Elapsed: {s.get('duration_ms','not recorded')} ms",
        f"Tool calls: {s.get('tool_calls',0)} / {s.get('coverage',{}).get('tool_call_limit','not recorded')}; analyst rounds: {s.get('depth',0)} / {s.get('coverage',{}).get('depth_limit','not recorded')}",
        f"ATT&CK knowledge baseline: {ATTACK_DOMAIN} {ATTACK_RELEASE} ({ATTACK_RELEASE_DATE})","", "OBJECTIVE AND SCOPE",s.get("objective",""),"", "DATA SOURCES AND COVERAGE"]
    lines += [f"- {k}: {v}" for k,v in s.get("coverage",{}).items() if k not in {"search_fields","analytic_summary","hypothesis_coverage","recent_search_artifacts"}]
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
        if h.get("model_assessment"): lines.append(f"  Evidence assessment: {h['model_assessment'].get('status')}; rationale={h['model_assessment'].get('rationale')}; cited events={_join_text(h['model_assessment'].get('evidence_ids'))}.")
    lines += ["", "HYPOTHESIS AND ANALYTIC COVERAGE"]
    ledger=s.get("coverage",{}).get("hypothesis_coverage",{})
    for row in ledger.get("rows",[]):
        lines.append(f"- {row.get('hypothesis_id')} / {row.get('technique_id')}: priority={row.get('priority')}; analytics={row.get('executed_analytics')}/{row.get('planned_analytics')}; sources={_join_text(row.get('sources')) or 'none'}; returned={row.get('returned')}; assessment={row.get('assessment')}; gaps={_join_text(row.get('telemetry_gaps')) or 'none'}.")
    lines += ["", "DETERMINISTIC BEHAVIORAL ANALYTICS"]+(_analytic_lines(s.get("analytic_summary",{})) or ["No analytic summary was produced."])
    lines += ["", "SIGNIFICANT FINDINGS"]
    if not s.get("findings"): lines.append("No significant findings recorded.")
    for f in s.get("findings",[]): lines += [f"- {f.get('finding_id')} {f.get('title')} [{f.get('status')} / {f.get('confidence')}]: {f.get('observation')}","  Analysis: "+str(f.get("interpretation") or ""),"  Evidence: "+_join_text(f.get("evidence_ids")),"  Alternatives: "+_join_text(f.get("alternatives"),"; "),"  Follow-up: "+_join_text(f.get("follow_up"),"; ")]
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
    lines += ["This assessment covers only the evidence sources and time period recorded above. Searches and reports are bounded; lack of findings does not establish that the environment is secure.","", "CONCLUSIONS AND RECOMMENDED FOLLOW-UP",s.get("summary") or "", "", "TECHNICAL EVIDENCE APPENDIX", f"The human-readable evidence manifest is bounded to {len(host_events)} host and {len(network_events)} network records. Stable citations and search-result IDs appear above. Exact compiled queries remain in tool_audit.jsonl and complete raw evidence remains in SQLite."]
    return "\n".join(lines)

def _docx(s,path):
    from docx import Document
    from docx.shared import Inches,Pt,RGBColor
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    from docx.enum.section import WD_SECTION
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn
    host_events=_bounded_report_events(s,"host"); network_events=_bounded_report_events(s,"network")
    doc=Document(); section=doc.sections[0]; section.header.paragraphs[0].text="ROMULUS | Defensive Threat Hunt"
    footer=section.footer.paragraphs[0]; footer.add_run(f"Investigation {s.get('hunt_id','')} | Generated in UTC | Page ")
    field=OxmlElement("w:fldSimple"); field.set(qn("w:instr"),"PAGE"); footer._p.append(field)
    styles=doc.styles; styles["Normal"].font.name="Aptos"; styles["Normal"].font.size=Pt(9)
    p=doc.add_paragraph(); p.alignment=WD_ALIGN_PARAGRAPH.CENTER; p.add_run("ROMULUS\n").bold=True
    r=p.add_run("THREAT HUNT INVESTIGATION REPORT\n"); r.font.size=Pt(20); r.font.color.rgb=RGBColor(31,78,121)
    p.add_run(f"\n{str(s.get('status','partial')).upper()}\n\nInvestigation {s.get('hunt_id','')}\n{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    doc.add_page_break()
    def heading(title): doc.add_heading(title,level=1)
    def para(value): doc.add_paragraph(str(value or "Not recorded."))
    heading("Executive Summary"); para(s.get("summary")); para(f"Outcome: {s.get('outcome','not recorded')}. Termination: {s.get('termination_reason','not recorded')}. Elapsed: {s.get('duration_ms','not recorded')} ms. Tool calls: {s.get('tool_calls',0)} / {s.get('coverage',{}).get('tool_call_limit','not recorded')}. Analyst rounds: {s.get('depth',0)} / {s.get('coverage',{}).get('depth_limit','not recorded')}.")
    para(f"ATT&CK knowledge baseline: {ATTACK_DOMAIN} {ATTACK_RELEASE} ({ATTACK_RELEASE_DATE}).")
    heading("Investigation Objective and Scope"); para(s.get("objective"))
    heading("Data Sources Examined")
    table=doc.add_table(rows=1,cols=2); table.style="Light Shading Accent 1"; table.rows[0].cells[0].text="Source"; table.rows[0].cells[1].text="Coverage"
    for k,v in s.get("coverage",{}).items():
        if k in {"search_fields","analytic_summary","hypothesis_coverage","recent_search_artifacts"}: continue
        row=table.add_row().cells; row[0].text=str(k); row[1].text=str(v)
    heading("Reasoning and Investigation Stages")
    for stage in s.get("stage_history",[]): para(f"{stage.get('timestamp')} {stage.get('stage')}: {stage.get('status')}; details: {stage.get('details')}.")
    for stage in s.get("reasoning_history",[]):
        searches=[x.get("intent",x.get("id","")) for x in stage.get("selected_searches",[]) if isinstance(x,dict)]
        para(f"{stage.get('stage')}: {stage.get('basis')}; round {stage.get('round','n/a')}; next searches: {_join_text(searches, '; ') or _join_text(stage.get('selected_leads')) or 'none'}; evidence considered: {stage.get('evidence_count',0)}.")
        if stage.get("reasoning"): para("Analyst reasoning: "+str(stage.get("reasoning")))
        if stage.get("created_hypothesis_ids"): para("New follow-up hypotheses: "+_join_text(stage.get("created_hypothesis_ids")))
    for run in s.get("tool_runs",[]): para(f"{run.get('reasoning_stage')} — {run.get('tool')} [{run.get('result_status')}], returned {run.get('result_count',0)}, matched total {run.get('source_total')}, window {run.get('time_range')}, duration {run.get('duration_ms')} ms, error {run.get('error') or 'none'}.")
    heading("Methodology and Hypotheses")
    for h in s.get("hypotheses",[]):
        para(f"{h.get('title')} — {h.get('technique_id') or 'unmapped'} ({h.get('status')}, {h.get('confidence')} confidence). {h.get('rationale')} Expected host: {_join_text(h.get('expected_host'))}. Expected network: {_join_text(h.get('expected_network'))}. Benign alternatives: {_join_text(h.get('benign_explanations'))}.")
        if h.get("model_assessment"): para(f"Evidence assessment: {h['model_assessment'].get('status')}. {h['model_assessment'].get('rationale')} Evidence IDs: {_join_text(h['model_assessment'].get('evidence_ids'))}.")
    heading("Hypothesis and Analytic Coverage")
    ledger=s.get("coverage",{}).get("hypothesis_coverage",{})
    for row in ledger.get("rows",[]):
        para(f"{row.get('hypothesis_id')} / {row.get('technique_id')}: priority {row.get('priority')}; analytics {row.get('executed_analytics')}/{row.get('planned_analytics')}; sources {_join_text(row.get('sources')) or 'none'}; returned {row.get('returned')}; assessment {row.get('assessment')}; gaps {_join_text(row.get('telemetry_gaps')) or 'none'}.")
    heading("Deterministic Behavioral Analytics")
    for line in _analytic_lines(s.get("analytic_summary",{})) or ["No analytic summary was produced."]: para(line.removeprefix("- "))
    heading("Significant Findings")
    if not s.get("findings"): para("No significant findings recorded in the evidence examined.")
    for f in s.get("findings",[]):
        para(f"{f.get('finding_id')} — {f.get('title')} [{f.get('status')}; confidence {f.get('confidence')}]")
        para("Observed behavior: "+str(f.get("observation") or "")); para("Analysis: "+str(f.get("interpretation") or "")); para("Evidence references: "+_join_text(f.get("evidence_ids")))
        para("Confidence basis: "+str(f.get("confidence_justification") or "")); para("Alternative explanations: "+_join_text(f.get("alternatives"),"; ")); para("Follow-up: "+_join_text(f.get("follow_up"),"; "))
    for title,key,events in (("Host Analysis","host",host_events),("Network Analysis","network",network_events)):
        heading(title)
        para(f"Showing {len(events)} representative/cited records of {len(s.get(key,[]))} retained records.")
        if not events: para("No events returned or source unavailable.")
        for e in events: para(f"{e.get('evidence_id')} | {e.get('observed_at')} | {e.get('source')} | {e.get('asset')}\nObservation: {e.get('observation')}\nReference: {_event_reference(e)}")
    heading("Cross-Domain Correlation")
    for c in s.get("correlations",[]): para(f"{c.get('host_ref')} and {c.get('network_ref')} correlate within {c.get('delta_seconds')} seconds; reasons: {_join_text(c.get('reasons'), '; ') or ('shared IP '+str(c.get('ip')))}; direction {c.get('direction','unresolved')}; score {c.get('score','not scored')}. {c.get('caveat')}")
    if not s.get("correlations"): para("No correlation was established.")
    heading("Bounded Evidence Timeline")
    for e in sorted(host_events+network_events,key=lambda x:x.get("observed_at","") or ""): para(f"{e.get('observed_at')} — {e.get('observation')} [{e.get('evidence_id')}]")
    heading("ATT&CK Technique Mapping")
    for h in s.get("hypotheses",[]):
        t=TECHNIQUES.get(h.get("technique_id"),{}); para(f"{h.get('technique_id')} {t.get('name','')} ({t.get('tactic','')}); assessment: {h.get('status')}. Reference: {t.get('url','')}")
    heading("Search Result Artifacts")
    for artifact in s.get("search_artifacts",[])[:250]:
        para(f"{artifact.get('artifact_id')} — {artifact.get('stage')} via {artifact.get('tool')}; status {artifact.get('result_status')}; returned {artifact.get('returned')}; matched {artifact.get('matched_total')}; scope {artifact.get('scope')}; error {artifact.get('error_reason') or 'none'}.")
    heading("Source Errors, Confidence, Missing Telemetry, and Limitations")
    errors=s.get("source_errors",[])
    if errors:
        for error in errors: para(f"{error.get('tool')} at {error.get('stage')}: {error.get('error')}; {error.get('reason') or ''}"+(f" (HTTP {error.get('status_code')})" if error.get("status_code") else ""))
    else: para("No source errors were recorded.")
    para(s.get("error","")); para("Packet scans drain the complete filtered capture under a per-call timeout and retain a bounded number of matches; other search results also have configured result caps. IP/time proximity is a lead and does not by itself establish identity, process attribution, or maliciousness. Consider NAT, DHCP, and clock skew. An isolated SYN is not proof of a completed connection. Absence of findings does not prove absence of compromise.")
    heading("Conclusions and Recommended Follow-up"); para(s.get("summary"))
    heading("Technical Evidence Appendix")
    para(f"This readable manifest is bounded to {len(host_events)} host and {len(network_events)} network records. Stable evidence and search-result references are listed above. Exact compiled queries remain in tool_audit.jsonl; complete raw evidence remains in SQLite.")
    for sec in doc.sections:
        sec.top_margin=Inches(.65); sec.bottom_margin=Inches(.65)
    doc.save(path)
