"""Render an aggregate result (dict) to Markdown, compare two results, and guard against label leaks."""
from __future__ import annotations

import json
from collections import Counter

from eval.funnel import STAGES


class LeakError(RuntimeError):
    pass


def leak_check(text: str, forbidden: set[str]) -> None:
    """Refuse output that contains any opportunity id or evidence locator from the gold inventory."""
    found = sorted(f for f in forbidden if f in text)
    if found:
        raise LeakError(f"aggregate output contains {len(found)} gold identifier(s); refusing to write")


def _w(x: dict | str | None) -> str:
    if not isinstance(x, dict):
        return str(x)
    if x.get("n", 0) == 0:
        return "n/a (0/0)"
    return f"{x['p']:.2f} ({x['k']}/{x['n']}; 95% CI {x['lo']:.2f}–{x['hi']:.2f})"


def _p(x: dict) -> str:
    if x["n_reviewed"] == 0:
        return "n/a (0 reviewed)"
    base = f"{x['tp']}/{x['n_reviewed']} reviewed"
    if x["p"] is not None:
        return f"{x['p']:.2f} ({base})"
    return f"{x['p_lower']:.2f}–{x['p_upper']:.2f} ({base}; {x['unadjudicated']} unadjudicated)"


def render(r: dict) -> str:
    h, rec, fl = r["hunt"], r["recall"], r["false_leads"]
    L = [f"# Evaluation result: {r['run_id']}", "",
         (f"Dataset `{r['dataset']}` ({r['mode']} set). Gold inventory {r['gold']['version']}. Scored "
         f"{r['scored_utc']} by `eval-custodian` with `eval.score` (matching rule PROTOCOL §6, pre-registered "
         "2026-10-19). Aggregate only."), ""]
    if r.get("notes"):
        L += ["## Caveats", ""] + [f"- {n}" for n in r["notes"]] + [""]
    L += ["## Run identity", "", "| Item | Value |", "|---|---|",
          f"| Hunt | `{h['id']}` ({h['execution_state']}, {h['detection_result']}) |",
          f"| Window | {h['window']} |",
          f"| Mode | {'model-off' if h['model_off'] else 'model-on'} (agent status: {h['agent_status']}) |",
          f"| Rule pack / normalizer / policy | {h['pack']} / {h['normalizer']} / {h['policy']} |",
          f"| Model config | {h['model']} |",
          f"| Config digest | `{h['config_digest']}` |",
          f"| Hunt manifest digest | `{h['manifest_digest']}` |",
          f"| Scorer commit | {r['scorer']['commit']} |",
          "| Gold file digests | " + ", ".join(f"{k} `{v[:12]}`" for k, v in sorted(r['gold']['files_sha256'].items())) + " |",
          ""]
    L += ["## Recall (Tier A)", "",
          ("Denominator: observable opportunities. Reported = urgent + high lanes; surfaced adds lead. "
          "Wilson 95% intervals; with n this small they are wide."), "",
          "| Slice | Reported | Surfaced |", "|---|---|---|",
          f"| All observable | {_w(rec['reported']['all_observable'])} | {_w(rec['surfaced']['all_observable'])} |",
          f"| Critical + high | {_w(rec['reported']['critical_high'])} | {_w(rec['surfaced']['critical_high'])} |"]
    for k in rec["reported"]["by_severity"]:
        L.append(f"| Severity {k} | {_w(rec['reported']['by_severity'][k])} | {_w(rec['surfaced']['by_severity'][k])} |")
    for k in rec["reported"]["by_time_position"]:
        L.append(f"| Position {k} | {_w(rec['reported']['by_time_position'][k])} | "
                 f"{_w(rec['surfaced']['by_time_position'][k])} |")
    for k in rec["reported"]["by_source"]:
        L.append(f"| Source {k} | {_w(rec['reported']['by_source'][k])} | {_w(rec['surfaced']['by_source'][k])} |")
    if r["mode"] == "dev":
        for k in rec["reported"]["by_class"]:
            L.append(f"| Class {k} | {_w(rec['reported']['by_class'][k])} | {_w(rec['surfaced']['by_class'][k])} |")
    L += ["", f"- Derived opportunities, reported: {_w(rec['derived'])}.",
          f"- Inferable-only opportunities, surfaced: {_w(rec['inferable_only']['surfaced'])}.",
          (f"- Not observable: {rec['not_observable']['count']} ({rec['not_observable']['reasons']}); "
          f"hit anyway: {rec['not_observable']['hit_anyway']}."),
          f"- Observable opportunities found only in the context lane (mentioned, not counted): {rec['mentioned_only']}.",
          f"- Suppression misses: {rec['suppression_misses']}.",
          (f"- Tier B only (right entity and time, no proving record cited): {r['matching']['tier_b_only_opps']} "
          "observable opportunities."),
          (f"- Locator-match anomalies (proving record cited, entity or time check failed): "
          f"{r['matching']['anomalies']} item–opportunity pairs, for custodian review."), ""]
    f = r["funnel"]
    L += ["## Miss funnel", "", f"Misses (observable, not reported): {f['misses']}. Basis: {f['replay']}.", "",
          "| Furthest stage | Count |", "|---|---|"]
    L += [f"| {s} | {f['by_stage'].get(s, 0)} |" for s in STAGES if s != "reported"]
    if r["mode"] == "dev" and f.get("by_stage_class"):
        L += ["", "| Stage | Behavior class | Count |", "|---|---|---|"]
        for k, n in f["by_stage_class"].items():
            s, c = k.split("|", 1)
            L.append(f"| {s} | {c} | {n} |")
    if f.get("notes"):
        L += ["", "Notes: " + "; ".join(f"{k} ({v})" for k, v in f["notes"].items())]
    p = r["precision"]
    L += ["", "## Precision at review ranks", "",
          f"Review order: {p['order_basis']}. TP = Tier A hit on any opportunity or adjudicated `true_unlisted`.", "",
          f"- P@10: {_p(p['p10'])}; duplicates in top 10: {p['p10']['duplicates_in_top']}.",
          f"- P@20: {_p(p['p20'])}; duplicates in top 20: {p['p20']['duplicates_in_top']}.",
          f"- Surfaced items: {p['surfaced_total']}. Verdicts: {fl['verdicts']}.", "",
          ] + _by_rule_lines(p.get("by_rule")) + [
          "## False leads per review hour", "",
          (f"Review time {fl['basis']}: {fl['minutes_per_item']} min per surfaced item, "
          f"{fl['review_hours_modeled']} h for {fl['surfaced']} items."), "",
          f"- False leads: {fl['false']}; unadjudicated: {fl['unadjudicated']}.",
          "- Per hour: " + (f"{fl['per_hour']}" if fl["per_hour"] is not None else
                            f"{fl['per_hour_lower']}–{fl['per_hour_upper']} (bounds; unadjudicated items remain)"), ""]
    c = r["citations"]
    L += ["## Citation validity (automated part)", "", f"Reported items: {c['reported_items']}; citations: {c['citations']}.", "",
          f"- Retained copy present with matching digest: {_w(c['retained_digest_match'])}.",
          f"- Source record present with matching digest: {_w(c['source_digest_match'])}.",
          f"- Predicate-field origin inside the cited records: {_w(c['predicate_origin_in_citations'])}.",
          (f"- Predicate value equals the cited typed-event field: {_w(c['predicate_value_matches_typed_event'])} "
          f"({c['predicate_value_unverifiable']} not checkable: field not on the typed event)."),
          f"- Items passing every automated check: {_w(c['items_all_checks_pass'])}.",
          f"- Remaining manual review: {c['manual_remaining']}.", ""]
    t, co = r["timing"], r["cost"]
    L += ["## Time and cost", "", f"Basis: {t['basis']}.", "",
          (f"- Time to first actionable finding: {t['time_to_first_actionable_s']} s; first reported item: "
          f"{t['time_to_first_reported_s']} s; total hunt: {t['total_hunt_s']} s."),
          (f"- Tasks: {co['tasks']} {co['task_kinds']}; records returned: {co['records_returned']}; records swept: "
          f"{co['records_swept']}; typed events: {co['typed_events']}; partitions: {co['partitions']}."),
          (f"- Model calls: {co['model_calls']}; prompt/completion tokens: {co['prompt_tokens']}/"
          f"{co['completion_tokens']}; model time: {co['model_ms']} ms."),
          (f"- ES requests: {co['es_requests']}; bytes: {co['bytes_fetched']}; Arkime calls: {co['arkime_calls']}; "
          f"TShark CPU: {co['tshark_cpu_s']}."), "",
          "## Coverage-claim accuracy", "",
          (f"- Rules whose report negative claim is 'complete': {r['coverage_claims']['rules_claiming_complete']}; "
          f"no_match_complete cells: {r['coverage_claims']['complete_negative_cells']}; candidate false complete "
          f"negatives (gold action records of a claimed technique inside the cell): "
          f"{r['coverage_claims']['candidate_false_complete_negatives']} ({r['coverage_claims']['adjudication']})."), "",
          ] + agent_section(r.get("agent")) + [
          "## Comparisons", "", "| Comparison | Status |", "|---|---|"]
    for k, v in r["comparisons"].items():
        L.append(f"| {k} | {v} |")
    if r.get("data_gaps"):
        L += ["", "## Product data the scorer needed but the store lacks", ""] + [f"- {g}" for g in r["data_gaps"]]
    L.append("")
    return "\n".join(L)


def _by_rule_lines(br: dict | None) -> list[str]:
    if not br:
        return []
    L = ["", "| Rule (surfaced items) | n | Tier A hit | true_unlisted | benign | unsupported | unadjudicated |",
         "|---|---|---|---|---|---|---|"]
    for rule, v in br.items():
        L.append(f"| {rule} | {v.get('n', 0)} | {v.get('tier_a_hit', 0)} | {v.get('true_unlisted', 0)} | "
                 f"{v.get('benign', 0)} | {v.get('unsupported', 0)} | {v.get('unadjudicated', 0)} |")
    return L + [""]


def agent_section(a: dict | None) -> list[str]:
    if not a or not a.get("present"):
        return ["## Agent", "", "No agent activity in this hunt (model-off or disabled).", ""]
    p, s, mc, ai, pr = a["pivots"], a["seeds"], a["model_calls"], a["agent_items"], a["pivot_reach"]
    return [
        "## Agent effectiveness", "",
        f"- Status: {a['status']} ({a['stop_reason']}).",
        f"- Cases: {a['cases']} {a['cases_by_status']}; steps used {a['steps_used']} of {a['step_budget']} budgeted.",
        f"- Decisions (excluding seeds): {a['decisions']}.",
        f"- Rejection reasons: {a['rejection_reasons']}.",
        (f"- Pivots: {p['proposed']} proposed, {p['executed']} executed ({p['complete']} complete, {p['partial']} "
        f"partial, {p['failed']} failed), {p['rejected']} rejected, duplicates blocked {p['duplicates_blocked']}; "
        f"tools executed {p['tools_executed']}."),
        (f"- Fallback-parked cases: {a['fallback_parked']}; analyst flags: {a['analyst_flags']}; conclusions: "
        f"{a['conclusions']}; accepted escalations: {a['escalations_accepted']}."),
        (f"- Seeds: {s['total']} total; concluded {s['concluded']}; assigned but unfinished {s['assigned_unfinished']}; "
        f"unassigned {s['unassigned']}; unworked {s['unworked']}."),
        (f"- Model calls: {mc['total']} {mc['by_status']}; prompt/completion tokens {mc['prompt_tokens']}/"
        f"{mc['completion_tokens']}; model time {mc['model_ms']} ms."),
        (f"- Agent-produced items: {ai['total']} {ai['by_lane']}; Tier A opportunities {ai['tier_a_opps']}; "
        f"Tier B opportunities {ai['tier_b_opps']}."),
        (f"- Pivot reach (retrieved a gold action/outcome record): {pr['locator_level_opps']} observable "
        f"opportunities {pr['locator_level_by_class']}; of these not otherwise surfaced: "
        f"{pr['locator_level_not_otherwise_surfaced']}."),
        f"- Pivot reach at entity + window level: {pr['entity_window_opps']} {pr['entity_window_by_class']}.",
        (f"- Executed pivots that retrieved at least one gold action/outcome record: "
         f"{pr.get('executed_pivots_retrieving_gold', 'n/a')} of {p['executed']}."),
        f"- Note: {pr['note']}.", ""] + _v2_lines(a)


def _v2_lines(a: dict) -> list[str]:
    out = []
    m = a.get("menu")
    if m:
        out += [(f"- Menu decisions: {m['menus']}; options chosen by kind {m['options_chosen_by_kind']}; median menu "
                 f"size {m['menu_size_median']}; hidden options {m['hidden_options_total']}; text truncated "
                 f"{m['text_truncated']}."),
                (f"- Constraint defects: {m['constraint_defects']}; model errors: {m['model_errors']}; deterministic "
                 f"fallbacks: {m['deterministic_fallbacks']}; model attempts {m['model_attempts']}.")]
    cg = a.get("conclusions_vs_gold")
    if cg:
        out += [f"- Concluded cases by status and gold: {cg['cases_by_status_and_gold']}.",
                (f"- Escalated and parked/closed-seed candidates by verdict (Tier A hit, or the custodian adjudication): "
                 f"{cg.get('concluded_candidates_by_verdict')}."),
                (f"- Escalations landing on gold: {cg['escalations_on_gold_opps']} opportunities "
                 f"{cg['escalations_on_gold_by_class']}; of these, not reported by the sweep (lead lane only): "
                 f"{cg['escalated_gold_opps_not_reported_by_sweep']}."),
                f"- Closed cases holding gold: {cg['closed_cases_holding_gold'] or 'none'}.",
                (f"- Concluded seeds hitting gold: {cg['seeds_concluded_with_gold']} opportunities "
                 f"{cg['seeds_concluded_with_gold_by_class']}; unworked seeds hitting gold: "
                 f"{cg['seeds_unworked_with_gold_by_class']}."),
                f"- Note: {cg['note']}.", ""]
    return out


def ablation(off: dict, on: dict, off_priv: dict, on_priv: dict, classes: dict[str, str]) -> str:
    """Model-on vs model-off (§8 item 10). classes: opp id -> behavior class (used for counts only)."""
    def only(a, b, key):
        sa = {o for o, v in a["per_opportunity"].items() if v[key]}
        sb = {o for o, v in b["per_opportunity"].items() if v[key]}
        d = sa - sb
        return len(d), dict(sorted(Counter(classes[o] for o in d).items()))
    L = [compare(off, on, "model-off", "model-on"), "",
         "| Delta (on minus off) | Value |", "|---|---|"]
    for name, path in (("Time to first actionable (s)", ("timing", "time_to_first_actionable_s")),
                       ("Time to first reported (s)", ("timing", "time_to_first_reported_s")),
                       ("Total hunt (s)", ("timing", "total_hunt_s")), ("Model calls", ("cost", "model_calls")),
                       ("Prompt tokens", ("cost", "prompt_tokens")), ("Completion tokens", ("cost", "completion_tokens")),
                       ("Model time (ms)", ("cost", "model_ms")), ("Tasks", ("cost", "tasks")),
                       ("Records returned", ("cost", "records_returned"))):
        va, vb = off[path[0]][path[1]], on[path[0]][path[1]]
        try:
            L.append(f"| {name} | {round(vb - va, 1)} ({va} → {vb}) |")
        except TypeError:
            L.append(f"| {name} | n/a ({va} → {vb}) |")
    L += ["", "| Opportunities hit only in one run | Count | By class |", "|---|---|---|"]
    for lane in ("reported", "surfaced"):
        n, c = only(on_priv, off_priv, lane)
        L.append(f"| {lane}, model-on only | {n} | {c} |")
        n, c = only(off_priv, on_priv, lane)
        L.append(f"| {lane}, model-off only | {n} | {c} |")
    return "\n".join(L)


def ablation_n(base: tuple, others: list[tuple], classes: dict[str, str]) -> str:
    """N-way ablation: base = (label, result, private); others likewise. Deltas and only-in sets vs the base."""
    bl, b, bp = base
    L = [compare_n([(bl, b)] + [(lab, r) for lab, r, _ in others]), "",
         "| Delta vs " + bl + " | " + " | ".join(lab for lab, _, _ in others) + " |",
         "|---|" + "---|" * len(others)]
    for name, path in (("Time to first actionable (s)", ("timing", "time_to_first_actionable_s")),
                       ("Total hunt (s)", ("timing", "total_hunt_s")), ("Model calls", ("cost", "model_calls")),
                       ("Prompt tokens", ("cost", "prompt_tokens")), ("Completion tokens", ("cost", "completion_tokens")),
                       ("Model time (ms)", ("cost", "model_ms")), ("Tasks", ("cost", "tasks")),
                       ("Records returned", ("cost", "records_returned"))):
        cells = []
        for _lab, r, _ in others:
            va, vb = b[path[0]][path[1]], r[path[0]][path[1]]
            try:
                cells.append(f"{round(vb - va, 1)} ({va} → {vb})")
            except TypeError:
                cells.append(f"n/a ({va} → {vb})")
        L.append(f"| {name} | " + " | ".join(cells) + " |")

    def only(a, c, key):
        sa = {o for o, v in a["per_opportunity"].items() if v[key]}
        sc = {o for o, v in c["per_opportunity"].items() if v[key]}
        d = sa - sc
        return len(d), dict(sorted(Counter(classes[o] for o in d).items()))
    L += ["", "| Opportunities hit only in one run | Count | By class |", "|---|---|---|"]
    for lab, _r, p in others:
        for lane in ("reported", "surfaced"):
            n, c = only(p, bp, lane)
            L.append(f"| {lane}, {lab} only (not {bl}) | {n} | {c} |")
            n, c = only(bp, p, lane)
            L.append(f"| {lane}, {bl} only (not {lab}) | {n} | {c} |")
    return chr(10).join(L)


def compare(a: dict, b: dict, la: str, lb: str) -> str:
    return compare_n([(la, a), (lb, b)])


def compare_n(runs: list[tuple]) -> str:
    def g(r, path):
        x = r
        for p in path:
            x = x.get(p) if isinstance(x, dict) else None
            if x is None:
                return None
        return x
    rows = [("Recall reported, all observable", ("recall", "reported", "all_observable")),
            ("Recall reported, critical+high", ("recall", "reported", "critical_high")),
            ("Recall surfaced, all observable", ("recall", "surfaced", "all_observable")),
            ("Recall surfaced, critical+high", ("recall", "surfaced", "critical_high"))]
    for src in ("host_index", "network_index", "arkime", "pcap"):
        rows.append((f"Recall reported, source {src}", ("recall", "reported", "by_source", src)))
    for pos in ("middle", "late"):
        rows.append((f"Recall reported, position {pos}", ("recall", "reported", "by_time_position", pos)))
    rows += [("P@10", ("precision", "p10")), ("P@20", ("precision", "p20")),
             ("Citation items passing all automated checks", ("citations", "items_all_checks_pass"))]
    L = ["| Metric | " + " | ".join(lab for lab, _ in runs) + " |", "|---|" + "---|" * len(runs)]
    for name, path in rows:
        vals = [g(r, path) for _, r in runs]
        fmt = _p if isinstance(vals[0], dict) and "n_reviewed" in vals[0] else _w
        L.append(f"| {name} | " + " | ".join(fmt(v) if v is not None else "n/a" for v in vals) + " |")
    scal = [("Surfaced items", ("precision", "surfaced_total")), ("False leads", ("false_leads", "false")),
            ("False leads per hour (modeled)", ("false_leads", "per_hour")),
            ("Unadjudicated surfaced items", ("false_leads", "unadjudicated")),
            ("Funnel misses", ("funnel", "misses")),
            ("Candidate false complete negatives", ("coverage_claims", "candidate_false_complete_negatives")),
            ("Time to first actionable (s)", ("timing", "time_to_first_actionable_s")),
            ("Time to first reported (s)", ("timing", "time_to_first_reported_s")),
            ("Total hunt (s)", ("timing", "total_hunt_s")), ("Tasks", ("cost", "tasks")),
            ("Records returned", ("cost", "records_returned")), ("Model calls", ("cost", "model_calls")),
            ("Prompt / completion tokens", None), ("Model time (ms)", ("cost", "model_ms")),
            ("Review order basis", ("precision", "order_basis"))]
    for name, path in scal:
        if path is None:
            L.append(f"| {name} | " + " | ".join(f"{r['cost']['prompt_tokens']} / {r['cost']['completion_tokens']}"
                                                 for _, r in runs) + " |")
        else:
            L.append(f"| {name} | " + " | ".join(str(g(r, path)) for _, r in runs) + " |")
    return chr(10).join(L)


def dumps(r: dict) -> str:
    return json.dumps(r, indent=1, sort_keys=True, default=str)
