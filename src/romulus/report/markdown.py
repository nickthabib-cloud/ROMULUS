"""Technical Markdown report rendered strictly from a ReportManifest."""
from __future__ import annotations

import json
import re

BANNER = "UNCLASSIFIED // FOR TRAINING USE"
_MD_SPECIAL = re.compile(r"([\\`*_{}\[\]<>#|])")
_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f\x1b]")


def esc(text) -> str:
    """Inline-safe text: strip control/ANSI chars, escape Markdown/HTML metacharacters."""
    return _MD_SPECIAL.sub(r"\\\1", _CTRL.sub("", str(text)))


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
        s = ("No qualifying behavior was observed in the assessed scope listed below. This is not a statement "
             "that the environment is clean.")
    if partial:
        s += f" The hunt is {m['execution_state']}: some sources, windows or tasks were not fully assessed."
    return s


def render(m: dict, banner: str = BANNER) -> str:
    h = m["hunt"]
    out = [banner, "", f"# ROMULUS technical report: hunt `{h['id']}`", "",
           f"Revision {m['revision']['number']} (`{m['revision']['id']}`)"
           + (f", supersedes `{m['revision']['supersedes']}`" if m["revision"]["supersedes"] else ""), "",
           "## Outcome", "", outcome_sentence(m), "",
           "| Item | Value |", "|---|---|",
           f"| Execution state | {esc(m['execution_state'])} |",
           f"| Detection result | {esc(m['detection_result'])} |",
           f"| Window (UTC, half-open) | {esc(h['window']['start'])} → {esc(h['window']['end'])} |",
           f"| Sources | {esc(', '.join(h['targets']))} |",
           f"| Lane counts | {esc(json.dumps(m['lane_counts'], sort_keys=True))} |",
           f"| Model investigator | {esc(m['agent'].get('status'))}: {esc(m['agent'].get('stop_reason', ''))} |",
           f"| Stop reason | {esc(m['stop_reason'])} |",
           f"| Broken citations | {m['integrity']['broken_citations']} |", ""]
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

    investigations = m.get("investigations") or {
        "summary": {}, "seed_partition": {}, "cases": [], "unworked_seed_ids": [],
        "model_contribution": {}, "incomplete_case_ids": [], "analyst_flags": [],
    }
    inv_summary = investigations["summary"]
    partitions = investigations["seed_partition"]
    contributions = investigations["model_contribution"]
    out += [
        "## Investigations", "",
        ("Model conclusions are recorded as cited analyst guidance. They remain separate from deterministic "
         "machine claims, lanes, and coverage results."), "",
        "| Item | Value |", "|---|---|",
        f"| Status | {esc(inv_summary.get('status', 'unknown'))} |",
        f"| Cases | {inv_summary.get('cases', 0)} |",
        f"| Model calls | {contributions.get('model_calls', 0)} |",
        f"| Pivot steps | {contributions.get('pivot_steps', 0)} |",
        f"| Partial pivot steps | {inv_summary.get('partial_pivots', 0)} |",
        f"| Rejected pivot proposals | {max(0, contributions.get('pivot_proposals', 0) - contributions.get('pivot_steps', 0))} |",
        f"| Pivot-discovered candidates | {contributions.get('contributed_candidates', inv_summary.get('contributed_candidates', 0))} |",
        f"| Unworked seeds | {inv_summary.get('unworked_count', 0)} |",
        f"| Analyst flags | {inv_summary.get('analyst_flags', 0)} |", "",
        "**Seed accounting**", "",
        f"- Concluded: {esc(', '.join(partitions.get('concluded', [])) or 'none')}",
        f"- Assigned but unfinished: {esc(', '.join(partitions.get('assigned_unfinished', [])) or 'none')}",
        f"- Unassigned: {esc(', '.join(partitions.get('unassigned', [])) or 'none')}", "",
    ]
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
        ]
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
            ("A negative statement applies only where a rule's coverage is `complete`. `unresolved` means at least one "
             "partition was partial, failed, or had records missing required fields."), "",
            "| Rule | Records evaluated | Negative claim | Cell states |", "|---|---|---|---|"]
    for r in m["coverage"]["rules"]:
        out.append(f"| {esc(r['rule_id'])} | {r['records_evaluated']} | {esc(r['negative_claim'])} | "
                   f"{esc(json.dumps(r['states'], sort_keys=True))} |")
    out += ["", (f"Context-only items (not listed above): {m['context_items']}. They remain in the JSON manifest "
                 "and the database."), "",
            "## Versions", "", fence(json.dumps(m["versions"], indent=2, sort_keys=True), "json"), "", banner, ""]
    return "\n".join(out)
