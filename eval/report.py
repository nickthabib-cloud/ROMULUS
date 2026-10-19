"""Render an aggregate result (dict) to Markdown, compare two results, and guard against label leaks."""
from __future__ import annotations

import json

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
          "## Comparisons", "", "| Comparison | Status |", "|---|---|"]
    for k, v in r["comparisons"].items():
        L.append(f"| {k} | {v} |")
    if r.get("data_gaps"):
        L += ["", "## Product data the scorer needed but the store lacks", ""] + [f"- {g}" for g in r["data_gaps"]]
    L.append("")
    return "\n".join(L)


def compare(a: dict, b: dict, la: str, lb: str) -> str:
    def g(r, path):
        x = r
        for p in path:
            x = x[p]
        return x
    rows = [("Recall reported, all observable", ("recall", "reported", "all_observable")),
            ("Recall reported, critical+high", ("recall", "reported", "critical_high")),
            ("Recall surfaced, all observable", ("recall", "surfaced", "all_observable")),
            ("P@10", ("precision", "p10")), ("P@20", ("precision", "p20"))]
    L = [f"| Metric | {la} | {lb} |", "|---|---|---|"]
    for name, path in rows:
        va, vb = g(a, path), g(b, path)
        fmt = _p if "k" in va and "n_reviewed" in va else _w
        L.append(f"| {name} | {fmt(va)} | {fmt(vb)} |")
    L.append(f"| Surfaced items | {a['precision']['surfaced_total']} | {b['precision']['surfaced_total']} |")
    L.append(f"| Time to first actionable (s) | {a['timing']['time_to_first_actionable_s']} | "
             f"{b['timing']['time_to_first_actionable_s']} |")
    L.append(f"| Total hunt (s) | {a['timing']['total_hunt_s']} | {b['timing']['total_hunt_s']} |")
    L.append(f"| Model calls | {a['cost']['model_calls']} | {b['cost']['model_calls']} |")
    return "\n".join(L)


def dumps(r: dict) -> str:
    return json.dumps(r, indent=1, sort_keys=True, default=str)
