"""Technical Markdown report rendered strictly from a ReportManifest."""
from __future__ import annotations

import json
import re

BANNER = "UNCLASSIFIED // FOR TRAINING USE"
_MD_SPECIAL = re.compile(r"([\\`*_{}\[\]<>#|])")
_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f\x1b\u061c\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]")


def esc(text) -> str:
    """Inline-safe text: strip control/ANSI chars, escape Markdown/HTML metacharacters."""
    return _MD_SPECIAL.sub(r"\\\1", _CTRL.sub("", str(text)))


def cell(text) -> str:
    """A table cell: inline-safe and on one line, so a newline cannot end the row."""
    return " ".join(esc(text).split())


def fence(text: str, lang: str = "text") -> str:
    """Fence longer than any backtick run in the content, so telemetry cannot close it."""
    text = _CTRL.sub("", text)
    longest = max((len(m) for m in re.findall(r"`+", text)), default=0)
    f = "`" * max(3, longest + 1)
    return f"{f}{lang}\n{text}\n{f}"


def _anchor(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_-]+", "-", value)


def outcome_sentence(m: dict) -> str:
    n = len(m["findings"])
    urgent_high = sum(1 for f in m["findings"] if f["lane"] in ("urgent", "high"))
    partial = m["execution_state"] != "completed_within_scope"
    if n:
        s = (f"ROMULUS reports {urgent_high} urgent/high finding(s) and {n - urgent_high} investigative lead(s) "
             f"for review.")
    else:
        s = ("ROMULUS found no qualifying behavior in what it searched, listed below. That does not mean nothing "
             "is there.")
    if partial:
        s += f" The hunt is {m['execution_state']}: some sources, windows or tasks were not fully searched."
    unresolved = {rule for gap in (m.get("coverage") or {}).get("gaps") or [] for rule in gap["rules"]}
    if unresolved:
        s += f" {len(unresolved)} rule(s) searched only part of their scope; see Coverage gaps."
    return s


def _ai_agent_cell(m: dict) -> str:
    ai = m.get("ai_agent") or {}
    phase, configured = ai.get("phase") or {}, ai.get("configured") or {}
    text = f"{phase.get('status', 'unknown')}: {phase.get('reason', '')}".rstrip(": ")
    if configured.get("model"):
        text += f" (provider {configured.get('provider')}, model {configured.get('model')}, "                 f"{configured.get('egress') or 'unknown'} endpoint)"
    return text


def _internal_networks_cell(m: dict) -> str:
    """Which addresses the hunt treated as the site's, in one line."""
    view = m.get("internal_networks") or {}
    return str(view.get("line") or view.get("summary") or "Internal networks: not recorded").removeprefix("Internal networks: ")


def render(m: dict, banner: str = BANNER) -> str:
    h = m["hunt"]
    graph = m.get("incident_graph") or {"incidents": [], "links": [], "nodes": [], "edges": []}
    link_strength = {link["id"]: link["style"] for link in graph["links"]}
    link_strength.update({
        link["id"]: link["strength"]
        for link in (m.get("investigations") or {}).get("link_accounting", [])
    })
    out = [banner, "", f"# ROMULUS technical report: hunt `{h['id']}`", "",
           f"Revision {m['revision']['number']} (`{m['revision']['id']}`)"
           + (f", supersedes `{m['revision']['supersedes']}`" if m["revision"]["supersedes"] else ""), "",
           "## Outcome", "", outcome_sentence(m), "",
           "| Item | Value |", "|---|---|",
           f"| Execution state | {esc(m['execution_state'])} |",
           f"| Detection result | {esc(m['detection_result'])} |",
           f"| Window (UTC, half-open) | {esc(h['window']['start'])} → {esc(h['window']['end'])} |",
           f"| Sources | {esc(', '.join(h['targets']))} |",
           f"| Internal networks | {cell(_internal_networks_cell(m))} |",
           f"| Lane counts | {esc(json.dumps(m['lane_counts'], sort_keys=True))} |",
           f"| Model investigator | {esc(m['agent'].get('status'))}: {esc(m['agent'].get('stop_reason', ''))} |",
           f"| AI agent | {cell(_ai_agent_cell(m))} |",
           f"| Stop reason | {esc(m['stop_reason'])} |",
           f"| Broken citations | {m['integrity']['broken_citations']} |",
           f"| Broken investigation citations | {m['integrity'].get('broken_investigation_citations', 0)} |", ""]
    for egress in m.get("banners") or []:
        out += [f"> **Model egress:** {cell(egress)}", ""]
    if (m.get("internal_networks") or {}).get("warning"):
        out += [f"> **Internal networks:** {cell(m['internal_networks']['warning'])}", ""]
    if not m["integrity"]["finalizable"]:
        out += [("> **Degraded report:** one or more citations could not be resolved to retained evidence. "
                 "Those findings are listed with the broken citation marked."), ""]

    out += ["## Findings and leads", "", "Ranked: urgent, then high, then investigative leads; by priority within a lane.", "",
            "| # | Lane | Severity | Confidence | Time (UTC) | Rule | Claim |", "|---|---|---|---|---|---|---|"]
    for i, f in enumerate(m["findings"], 1):
        claim = f["claim"] if len(f["claim"]) <= 140 else f["claim"][:139] + "…"
        out.append(f"| [{i}](#f-{f['id']}) | {f['lane']} | {f['severity']} | {f['confidence']} | "
                   f"{esc(f['observed_at'][:19])} | {esc(f['rule_id'])} | {esc(claim)} |")
    out.append("")

    for i, f in enumerate(m["findings"], 1):
        out += [f'<a id="f-{f["id"]}"></a>', "", f"### {i}. {esc(f['rule_id'])} ({f['lane']})", "",
                f"**Claim.** {esc(f['claim'])}", "",
                f"- Finding ID: `{f['id']}` · rule version {esc(f['rule_version'])} · claim type {esc(f['claim_type'])}",
                f"- Observed at: {esc(f['observed_at'])} UTC",
                (f"- Severity **{f['severity']}**, confidence **{f['confidence']}**, priority {f['priority']:.0f} "
                 f"({esc('; '.join(f['priority_reasons']))})"),
                f"- Analyst status: {esc(f['analyst_status'])}",
                f"- Entities: {esc(', '.join(f'{k}:{v} ({r})' for k, v, r in f['entities']))}", ""]
        if f.get("source_case_id"):
            out += [(f"- Investigator chain: [case `{esc(f['source_case_id'])}`]"
                     f"(#case-{_anchor(f['source_case_id'])})"), ""]
        if f.get("source_anchor_id"):
            strength = link_strength.get(f.get("source_link_id"), "unknown-strength")
            out += [(f"- Expansion chain: anchor `{esc(f['source_anchor_id'])}` via {esc(strength)} link "
                     f"`{esc(f.get('source_link_id') or '')}`"), ""]
        out += ["**Predicate fields (what the claim rests on)**", "", "| Field | Value | Origin |", "|---|---|---|"]
        for p in f["predicate_fields"]:
            v = json.dumps(p["value"], ensure_ascii=False)
            v = v if len(v) <= 200 else v[:199] + "…"
            out.append(f"| {esc(p['field'])} | {esc(v)} | {esc(p['origin'])} |")
        out += ["", "**Admission gates**", "", ", ".join(f"{esc(k)}: {esc(v)}" for k, v in f["gates"].items()), ""]
        if f["notes"]:
            out += ["**Notes**", ""] + [f"- {esc(n)}" for n in f["notes"]] + [""]
        out += ["**Benign alternatives to rule out**", ""] + [f"- {esc(b)}" for b in f["benign_alternatives"]] + [""]
        out += ["**Recommended next checks**", ""] + [f"- {esc(c)}" for c in f["next_checks"]] + [""]
        out += ["**Citations**", "", "| Event | Source | Native ID | Digest | Status |", "|---|---|---|---|---|"]
        for c in f["citations"][:25]:
            out.append(f"| {esc(c['event_id'])} | {esc(c.get('target', ''))} | {esc(c.get('native_id', ''))} | "
                       f"{esc(c.get('digest', '')[:16])}… | {esc(c['status'])} |")
        if len(f["citations"]) > 25:
            out.append(f"| … | {len(f['citations']) - 25} more citations in the JSON manifest | | | |")
        out.append("")

    out += ["## Incidents", "",
            ("Incidents are connected only by observed typed links. Inferred links remain visible hypotheses and "
             "never merge incident counts."), "",
            "| Incident | Entry point | Findings | Hosts | Accounts | ATT&CK tactics | Observed edges | Inferred edges |",
            "|---|---|---:|---|---|---|---:|---:|"]
    for incident in graph["incidents"]:
        out.append(
            f"| {esc(incident['id'])} | {esc(incident['entry_point'])} | {len(incident['finding_ids'])} | "
            f"{esc(', '.join(incident['hosts']) or 'none')} | {esc(', '.join(incident['accounts']) or 'none')} | "
            f"{esc(', '.join(incident['attack_tactics']) or 'none')} | {incident['observed_edges']} | "
            f"{incident['inferred_edges']} |"
        )
    if not graph["incidents"]:
        out.append("| none | none | 0 | none | none | none | 0 | 0 |")
    multi = [incident for incident in graph["incidents"] if len(incident["finding_ids"]) > 1]
    out += ["", "**Incident narratives**", "",
            ("Template narratives built from typed fields only. Inferred links are hypotheses; gaps say what is "
             "not known."), ""]
    for incident in multi:
        out.append(f"- `{esc(incident['id'])}`")
        for sentence in incident.get("narrative", []):
            cites = " ".join(f"[{esc(c)}](#f-{c})" for c in sentence["cites"][:12])
            tag = "" if sentence["kind"] == "observed" else f"*{esc(sentence['kind'])}:* "
            out.append(f"  - {tag}{esc(sentence['text'])}" + (f" ({cites})" if cites else ""))
    if not multi:
        out.append("- No incident has more than one finding.")
    analyst = m.get("analyst_links") or []
    if analyst:
        out += ["", "**Analyst-asserted links (not proven)**", "",
                "| From | To | Relation | By | Note |", "|---|---|---|---|---|"]
        out += [f"| [{esc(a['from_finding'])}](#f-{a['from_finding']}) | [{esc(a['to_finding'])}](#f-{a['to_finding']}) "
                f"| {cell(a['relation'])} | {cell(a['actor'])} | {cell(a.get('note') or '')} |" for a in analyst]
    out += ["", "**Attack-path timelines**", ""]
    for incident in graph["incidents"]:
        timeline = " → ".join(f"[{esc(item)}](#f-{item})" for item in incident["timeline"])
        out += [f"- `{esc(incident['id'])}`: {timeline}",
                f"  - Open ends: {esc(json.dumps(incident['open_ends'], sort_keys=True))}"]
    if not graph["incidents"]:
        out.append("- No reportable findings or leads formed an incident.")
    out += ["", "**Expansion links**", "",
            "| Link | Anchor | Targets | Type | Style | Status | Key | Evidence |",
            "|---|---|---|---|---|---|---|---|"]
    for link in graph["links"]:
        out.append(
            f"| {esc(link['id'])} | {esc(link['anchor_finding_id'])} | "
            f"{esc(', '.join(link['target_finding_ids']) or 'none')} | {esc(link['link_type'])} | "
            f"{esc(link['style'])} | {esc(link['status'])} | "
            f"{esc(json.dumps(link['key'], ensure_ascii=False, sort_keys=True))} | "
            f"{esc(', '.join(link['evidence_ids']) or 'none')} |"
        )
    if not graph["links"]:
        out.append("| none | none | none | none | none | none | none | none |")
    out.append("")

    investigations = m.get("investigations") or {
        "summary": {}, "seed_partition": {}, "cases": [], "unworked_seed_ids": [],
        "model_contribution": {}, "incomplete_case_ids": [], "analyst_flags": [],
    }
    inv_summary = investigations["summary"]
    partitions = investigations["seed_partition"]
    contributions = investigations["model_contribution"]
    expansion_accounting = investigations.get("anchor_accounting")
    intro = (("Deterministic expansion records every anchor and link without model judgment.")
             if expansion_accounting else
             ("Model conclusions are recorded as cited analyst guidance. They remain separate from deterministic "
              "machine claims, lanes, and coverage results."))
    out += [
        "## Investigations", "", intro, "",
        "| Item | Value |", "|---|---|",
        f"| Status | {esc(inv_summary.get('status', 'unknown'))} |",
        f"| Agent mode | {esc(inv_summary.get('mode', 'model'))} |",
        f"| Cases | {inv_summary.get('cases', 0)} |",
        f"| Model calls | {contributions.get('model_calls', 0)} |",
        f"| Pivot steps | {contributions.get('pivot_steps', 0)} |",
        f"| Partial pivot steps | {inv_summary.get('partial_pivots', 0)} |",
        f"| Rejected pivot proposals | {max(0, contributions.get('pivot_proposals', 0) - contributions.get('pivot_steps', 0))} |",
        f"| Pivot-discovered candidates | {contributions.get('contributed_candidates', inv_summary.get('contributed_candidates', 0))} |",
        f"| Unworked seeds | {inv_summary.get('unworked_count', 0)} |",
        f"| Analyst flags | {inv_summary.get('analyst_flags', 0)} |",
        f"| Deterministic fallbacks | {inv_summary.get('deterministic_fallbacks', 0)} |",
        f"| Constraint defects | {inv_summary.get('constraint_defects', 0)} |",
        f"| Menu options hidden by cap | {inv_summary.get('menu_hidden_options', 0)} |", "",
    ]
    if expansion_accounting:
        out += ["**Anchor accounting**", "",
                f"- Expanded complete: {esc(', '.join(expansion_accounting['expanded_complete']) or 'none')}",
                f"- Expanded partial: {esc(', '.join(expansion_accounting['expanded_partial']) or 'none')}",
                f"- Unexpanded: {esc(', '.join(expansion_accounting['unexpanded']) or 'none')}",
                f"- Pending: {esc(', '.join(expansion_accounting['pending']) or 'none')}", ""]
        for anchor in expansion_accounting["anchors"]:
            out.append(
                f"- `{esc(anchor['id'])}` depth {anchor['depth']} · **{esc(anchor['status'])}** · "
                f"{esc('; '.join(anchor['reasons']) or 'no gaps')}"
            )
        out.append("")
    else:
        out += ["**Seed accounting**", "",
                f"- Concluded: {esc(', '.join(partitions.get('concluded', [])) or 'none')}",
                f"- Assigned but unfinished: {esc(', '.join(partitions.get('assigned_unfinished', [])) or 'none')}",
                f"- Unassigned: {esc(', '.join(partitions.get('unassigned', [])) or 'none')}", ""]
    analyst_flags = investigations.get("analyst_flags") or []
    if analyst_flags:
        out += ["**Analyst review required**", ""]
        for flag in analyst_flags:
            out.append(
                f"- Case {esc(flag.get('case_id', 'unknown'))}: {esc(flag.get('message', ''))}"
            )
        out.append("")
    for case in investigations["cases"]:
        out += [
            f'<a id="case-{_anchor(case["id"])}"></a>', "",
            f"### Case {esc(case['id'])}: {esc(case['title'])}", "",
            f"- Status: **{esc(case['status'])}** · steps {case['steps_used']}/{case['step_budget']}",
            f"- Seeds: {esc(', '.join(case['seed_candidate_ids']) or 'none (spawned case)')}",
            f"- Entities: {esc(json.dumps(case['entities'], ensure_ascii=False, sort_keys=True))}",
            f"- Hypotheses: {esc('; '.join(case['hypotheses']) or 'none')}",
            (f"- Menu cap: {case.get('menu_cap', {}).get('hidden_options', 0)} hidden option(s) across "
             f"{case.get('menu_cap', {}).get('steps_capped', 0)} capped step(s)"),
        ]
        chosen_options = case.get("chosen_options") or []
        if chosen_options:
            out += ["", "**Chosen option chain**", ""]
            for choice in chosen_options:
                suffix = " · deterministic fallback" if choice.get("deterministic_fallback") else ""
                out.append(
                    f"- Step {choice['n']}: `{esc(choice['id'])}` — {esc(choice['description'])}{suffix}"
                )
                if choice.get("fallback_note"):
                    out.append(f"  - Fallback note: {esc(choice['fallback_note'])}")
        contributed = case.get("contributed_candidate_ids") or []
        if contributed:
            links = ", ".join(f"[{esc(candidate)}](#f-{candidate})" for candidate in contributed)
            out.append(f"- Pivot-discovered machine candidates: {links}")
        conclusion = case.get("conclusion")
        if conclusion:
            out += ["", "**Model conclusion (separate from machine decision)**", "",
                    f"- Conclusion: {esc(conclusion.get('model_conclusion', ''))}",
                    f"- Reasoning: {esc(conclusion.get('reasoning', ''))}",
                    f"- Cited evidence: {esc(', '.join(conclusion.get('evidence_ids') or []) or 'none')}",
                    f"- Benign alternatives: {esc('; '.join(conclusion.get('benign_alternatives') or []) or 'none')}",
                    "- This is a model assessment; it does not alter any deterministic claim or lane."]
        out += ["", "**Pivot chain**", ""]
        if not case["pivot_steps"]:
            out.append("- No pivot steps recorded.")
        for step in case["pivot_steps"]:
            result = step.get("result") or {}
            out += [
                (f"- Step {step['n']}: `{esc(step.get('tool') or 'unknown')}` · "
                 f"{'accepted' if step['accepted'] else 'rejected'}"),
                f"  - Hypothesis: {esc(step.get('hypothesis') or '')}",
                f"  - Cited evidence: {esc(', '.join(step.get('evidence_ids') or []) or 'none')}",
                f"  - Arguments: {esc(json.dumps(step.get('arguments') or {}, ensure_ascii=False, sort_keys=True))}",
                f"  - Result: {esc(json.dumps(result, ensure_ascii=False, sort_keys=True))}",
            ]
            coverage = result.get("coverage") or []
            if coverage:
                out.append("  - Covered/partial ranges (UTC; outer bounds are attempted ranges):")
                for segment in coverage:
                    reasons = "; ".join(segment.get("reasons") or []) or "none"
                    out.append(
                        f"    - {esc(segment.get('target', 'unknown'))}: "
                        f"{esc(segment.get('start', ''))} → {esc(segment.get('end', ''))} · "
                        f"**{esc(segment.get('status', 'unknown'))}** · "
                        f"returned {segment.get('returned', 0)}/{esc(segment.get('total'))} · "
                        f"reasons: {esc(reasons)}"
                    )
                    covered = segment.get("covered_ranges") or []
                    if covered:
                        out.append("      - Fully covered subranges:")
                        for item in covered:
                            left = "[" if item.get("start_inclusive", True) else "("
                            right = "]" if item.get("end_inclusive", False) else ")"
                            out.append(
                                f"        - {left}{esc(item.get('start', ''))}, "
                                f"{esc(item.get('end', ''))}{right}: {esc(item.get('reason', ''))}"
                            )
                    unresolved = segment.get("unresolved_ranges") or []
                    if unresolved:
                        out.append("      - Unresolved subranges:")
                        for item in unresolved:
                            left = "[" if item.get("start_inclusive", True) else "("
                            right = "]" if item.get("end_inclusive", False) else ")"
                            out.append(
                                f"        - {left}{esc(item.get('start', ''))}, "
                                f"{esc(item.get('end', ''))}{right}: {esc(item.get('reason', ''))}"
                            )
            if step.get("rejection"):
                out.append(f"  - Rejection: {esc(step['rejection'])}")
        out.append("")

    out += ["## Coverage", "",
            ("What each rule searched. ROMULUS reports what it finds and never claims that nothing is there. "
             "`searched in full` says every partition in scope was evaluated and none matched; it is a statement "
             "about the search, not about the network. `searched in part` means at least one partition was partial, "
             "failed, or had records missing required fields: those blind spots are listed under Coverage gaps. "
             "`not assessable by design` marks rules that identify behaviour from text (argv, script content, log "
             "messages, self-reported user agents): they flag what they find and cannot show absence. Each rule row "
             "states what, if any, complementary assurance exists."), "",
            "| Rule | Records evaluated | Search result | Cell states |", "|---|---|---|---|"]
    for r in m["coverage"]["rules"]:
        out.append(f"| {esc(r['rule_id'])} | {r['records_evaluated']} | {esc(r['search_result'])} | "
                   f"{esc(json.dumps(r['states'], sort_keys=True))} |")
    baseline = m["coverage"].get("baseline") or {}
    baseline_specs = baseline.get("specs") or []
    if baseline_specs:
        out += ["", "### Baseline snapshot", "",
                (f"Snapshot digest: `{esc(baseline.get('snapshot_digest') or 'not frozen')}`; "
                 f"snapshot status: **{esc(baseline.get('snapshot_status', 'unknown'))}**; "
                 f"stage status: **{esc(baseline.get('stage_status', 'unknown'))}**."), "",
                "| Spec | Status | Unresolved observations | Verdict counts |",
                "|---|---|---:|---|"]
        for spec in baseline_specs:
            out.append(
                f"| {esc(spec['id'])} | {esc(spec['status'])} | {spec['unresolved_count']} | "
                f"{esc(json.dumps(spec['verdicts'], sort_keys=True))} |"
            )
    gaps = m["coverage"].get("gaps") or []
    out += ["", "### Coverage gaps", "",
            ("Every source partition or link where at least one rule was not fully searched, and why. These are the "
             "hunt's blind spots."), "",
            "| Target | Partition | Rules left unresolved | Reasons |", "|---|---|---|---|"]
    for gap in gaps:
        rules = gap["rules"]
        named = (f"every rule evaluated there ({len(rules)})" if gap.get("every_rule_there")
                 else ", ".join(f"{rule} ({state})" for rule, state in rules.items()))
        out.append(f"| {cell(gap['target'])} | {cell(gap['partition'])} | {cell(named)} | "
                   f"{cell('; '.join(gap['reasons']))} |")
    if not gaps:
        out.append("| none | none | none | none |")
    unassessed = m["coverage"].get("not_assessed") or []
    out += ["", "### Data not assessed", "",
            "Data in scope that no rule evaluated. It was not searched and is not counted as evaluated.", "",
            "| Target | Dataset | Records | Count scope | Reason |", "|---|---|---|---|---|"]
    for item in unassessed:
        records = "unknown" if item.get("records") is None else item["records"]
        out.append(f"| {cell(item['target'])} | {cell(item.get('dataset') or 'any')} | {cell(records)} | "
                   f"{cell(item['count_scope'])} | {cell(item['reason'])} |")
    if not unassessed:
        out.append("| none | none | 0 | none | none |")
    out += ["", (f"Context-only items (not listed above): {m['context_items']}. They remain in the JSON manifest "
                 "and the database."), "",
            "## Versions", "", fence(json.dumps(m["versions"], indent=2, sort_keys=True), "json"), "", banner, ""]
    return "\n".join(out)
