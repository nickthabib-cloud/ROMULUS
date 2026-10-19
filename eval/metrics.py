"""PROTOCOL §8 metrics. Every proportion carries its denominator and a Wilson 95% interval."""
from __future__ import annotations

import hashlib
import json
import math
from collections import Counter, defaultdict
from pathlib import Path

from eval.gold import SOURCES, Gold, parse_ts
from eval.hunt import MENTIONED_LANES, REPORTED_LANES, SURFACED_LANES, Hunt, Item
from eval.match import ItemMatch

REVIEW_MINUTES_PER_ITEM = 5.0          # pre-registered modeled review cost (PROTOCOL §8.4)
VERDICTS = {"true_unlisted": True, "benign": False, "unsupported": False}
SEVERITIES = ("critical", "high", "medium", "low")
POSITIONS = ("early", "middle", "late")


def wilson(k: int, n: int, z: float = 1.96) -> dict:
    if n == 0:
        return {"k": k, "n": n, "p": None, "lo": None, "hi": None}
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return {"k": k, "n": n, "p": round(p, 4), "lo": round(max(0.0, c - h), 4), "hi": round(min(1.0, c + h), 4)}


def item_signature(item: Item) -> str:
    """Hunt-independent identity of an item (candidate ids differ between hunts)."""
    keys = sorted("|".join(map(str, k)) for k in item.keys)
    return hashlib.sha256(json.dumps([item.rule_id, keys]).encode()).hexdigest()


def load_adjudications(path: str | Path | None) -> dict[str, dict]:
    if not path or not Path(path).exists():
        return {}
    out = {}
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if line.strip():
            r = json.loads(line)
            if r["verdict"] not in VERDICTS:
                raise ValueError(f"bad verdict {r['verdict']!r}")
            out[r["signature"]] = r
    return out


# --------------------------------------------------------------------------------------------- recall
def hit_sets(matches: list[ItemMatch]) -> dict[str, dict[str, set[str]]]:
    """lane set -> {opp_id: sources}; plus suppression and mentioned."""
    out = {"reported": defaultdict(set), "surfaced": defaultdict(set), "mentioned": defaultdict(set),
           "suppressed": defaultdict(set)}
    for m in matches:
        lane = m.item.lane
        for oid in m.tier_a:
            srcs = m.tier_a_sources.get(oid, set())
            if lane in REPORTED_LANES:
                out["reported"][oid] |= srcs
            if lane in SURFACED_LANES:
                out["surfaced"][oid] |= srcs
            if lane in MENTIONED_LANES:
                out["mentioned"][oid] |= srcs
            if lane in ("suppressed", "benign"):
                out["suppressed"][oid] |= srcs
    return out


def recall(gold: Gold, hits: dict[str, dict[str, set[str]]]) -> dict:
    obs = [o for o in gold.opportunities.values() if o.observability == "observable"]
    res: dict = {}
    for lane_set in ("reported", "surfaced"):
        h = hits[lane_set]
        r = {"all_observable": wilson(sum(o.opp_id in h for o in obs), len(obs)),
             "critical_high": wilson(sum(o.opp_id in h for o in obs if o.critical_high),
                                     sum(o.critical_high for o in obs))}
        r["by_severity"] = {s: wilson(sum(o.opp_id in h for o in obs if o.severity == s),
                                      sum(o.severity == s for o in obs)) for s in SEVERITIES}
        classes = sorted({o.behavior_class for o in obs})
        r["by_class"] = {c: wilson(sum(o.opp_id in h for o in obs if o.behavior_class == c),
                                   sum(o.behavior_class == c for o in obs)) for c in classes}
        r["by_time_position"] = {p: wilson(sum(o.opp_id in h for o in obs if o.time_position == p),
                                           sum(o.time_position == p for o in obs)) for p in POSITIONS}
        r["by_source"] = {}
        for s in SOURCES:
            den = [o for o in obs if o.source_status.get(s) == "direct"]
            r["by_source"][s] = wilson(sum(s in h.get(o.opp_id, set()) for o in den), len(den))
        res[lane_set] = r
    inf = [o for o in gold.opportunities.values() if o.observability == "inferable_only"]
    nob = [o for o in gold.opportunities.values() if o.observability == "not_observable"]
    res["inferable_only"] = {"surfaced": wilson(sum(o.opp_id in hits["surfaced"] for o in inf), len(inf))}
    res["not_observable"] = {"count": len(nob),
                             "reasons": dict(Counter(o.not_observable_reason or "unknown" for o in nob)),
                             "hit_anyway": sum(o.opp_id in hits["surfaced"] for o in nob)}
    res["mentioned_only"] = sum(1 for o in obs if o.opp_id in hits["mentioned"] and o.opp_id not in hits["surfaced"])
    res["suppression_misses"] = sum(1 for o in obs if o.opp_id in hits["suppressed"] and o.opp_id not in hits["surfaced"])
    res["derived"] = wilson(sum(o.opp_id in hits["reported"] for o in obs if o.derived), sum(o.derived for o in obs))
    return res


# --------------------------------------------------------------------------------------------- precision
def review_list(hunt: Hunt, matches: list[ItemMatch]) -> tuple[list[ItemMatch], str]:
    surfaced = [m for m in matches if m.item.lane in SURFACED_LANES]
    by_id = {m.item.id: m for m in surfaced}
    if hunt.report_order and set(hunt.report_order) == set(by_id):
        return [by_id[i] for i in hunt.report_order], "report manifest order (latest revision)"
    surfaced.sort(key=lambda m: m.item.review_sort)
    return surfaced, "replicated manifest sort (lane, -priority, ts)" + (
        "; latest manifest revision lists a different item set" if hunt.report_order else "; no manifest revision")


def classify(ordered: list[ItemMatch], adj: dict[str, dict]) -> list[dict]:
    seen: set[str] = set()
    out = []
    for m in ordered:
        sig = item_signature(m.item)
        if m.tier_a:
            verdict, tp = "tier_a_hit", True
            dup = m.tier_a <= seen
            seen |= m.tier_a
        elif sig in adj:
            verdict, tp, dup = adj[sig]["verdict"], VERDICTS[adj[sig]["verdict"]], False
        else:
            verdict, tp, dup = "unadjudicated", None, False
        out.append({"lane": m.item.lane, "rule_id": m.item.rule_id, "verdict": verdict, "tp": tp, "duplicate": dup,
                    "signature": sig, "item_id": m.item.id})
    return out


def precision_at(rows: list[dict], k: int) -> dict:
    top = rows[:k]
    n = len(top)
    tp = sum(r["tp"] is True for r in top)
    un = sum(r["tp"] is None for r in top)
    return {"k": k, "n_reviewed": n, "tp": tp, "unadjudicated": un,
            "p": round(tp / n, 4) if n and not un else None,
            "p_lower": round(tp / n, 4) if n else None, "p_upper": round((tp + un) / n, 4) if n else None,
            "duplicates_in_top": sum(r["duplicate"] for r in top)}


def false_leads(rows: list[dict]) -> dict:
    n = len(rows)
    fp = sum(r["tp"] is False for r in rows)
    un = sum(r["tp"] is None for r in rows)
    hours = n * REVIEW_MINUTES_PER_ITEM / 60.0
    return {"surfaced": n, "false": fp, "unadjudicated": un, "review_hours_modeled": round(hours, 2),
            "minutes_per_item": REVIEW_MINUTES_PER_ITEM, "basis": "modeled (pre-registered default)",
            "per_hour": round(fp / hours, 2) if hours and not un else None,
            "per_hour_lower": round(fp / hours, 2) if hours else None,
            "per_hour_upper": round((fp + un) / hours, 2) if hours else None,
            "verdicts": dict(Counter(r["verdict"] for r in rows))}


# --------------------------------------------------------------------------------------------- citations
def citation_validity(matches: list[ItemMatch], source_check: dict | None = None) -> dict:
    """Automated part of §8.5 over Reported items. source_check: locator key -> bool (digest matched in source)."""
    rep = [m.item for m in matches if m.item.lane in REPORTED_LANES]
    total = retained = in_source_ok = in_source_checked = 0
    pf_total = pf_origin_ok = pf_value_ok = pf_value_unverifiable = 0
    items_ok = 0
    for it in rep:
        cited_native = {c["native_id"] for c in it.locators}
        ok_item = it.missing_events == 0 and bool(it.locators)
        for c in it.locators:
            total += 1
            retained += c["retained"] and c["digest_ok"]
            ok_item &= bool(c["retained"] and c["digest_ok"])
            if source_check is not None and c["key"] in source_check:
                in_source_checked += 1
                in_source_ok += bool(source_check[c["key"]])
                ok_item &= bool(source_check[c["key"]])
        for pf in it.predicate_fields:
            if not isinstance(pf, dict):
                continue
            pf_total += 1
            origin = str(pf.get("origin") or "")
            if origin.split(":", 1)[0] in cited_native:
                pf_origin_ok += 1
            else:
                ok_item = False
            vals = [f.get(pf.get("field"), {}).get("value") for f in it.event_fields if pf.get("field") in f]
            if not vals:
                pf_value_unverifiable += 1
            elif pf.get("value") in vals:
                pf_value_ok += 1
            else:
                ok_item = False
        items_ok += ok_item
    return {"reported_items": len(rep), "citations": total,
            "retained_digest_match": wilson(retained, total),
            "source_digest_match": wilson(in_source_ok, in_source_checked) if source_check is not None else "not run",
            "predicate_fields": pf_total, "predicate_origin_in_citations": wilson(pf_origin_ok, pf_total),
            "predicate_value_matches_typed_event": wilson(pf_value_ok, pf_total - pf_value_unverifiable),
            "predicate_value_unverifiable": pf_value_unverifiable,
            "items_all_checks_pass": wilson(items_ok, len(rep)),
            "manual_remaining": "claim wording vs evidence for every Reported item, plus a 20-lead random sample "
                                "(PROTOCOL §8.5); unsupported-claim count pending that review"}


# --------------------------------------------------------------------------------------------- time, cost
def timing(hunt: Hunt, gold: Gold, matches: list[ItemMatch]) -> dict:
    st = hunt.started_at
    rep = [m for m in matches if m.item.lane in REPORTED_LANES and m.item.created_at]

    def delta(ms):
        return round((min(m.item.created_at for m in ms) - st).total_seconds(), 1) if ms and st else None
    actionable = [m for m in rep if any(gold.opportunities[o].critical_high for o in m.tier_a)]
    return {"time_to_first_actionable_s": delta(actionable), "time_to_first_reported_s": delta(rep),
            "total_hunt_s": round((hunt.ended_at - st).total_seconds(), 1) if hunt.ended_at and st else None,
            "basis": "candidate.created_at minus hunt.started_at (wall clock)"}


def cost(hunt: Hunt) -> dict:
    sweep = next((a["detail"] for a in reversed(hunt.audit) if a["action"] == "hunt.sweep_summary"), None) or {}
    stats = sweep.get("stats") or {}
    returned = sum(int((t.get("outcome") or {}).get("returned") or 0) for t in hunt.tasks)
    calls = hunt.model_calls
    return {"tasks": len(hunt.tasks), "task_kinds": dict(Counter(t["kind"] for t in hunt.tasks)),
            "records_returned": returned, "records_swept": stats.get("records"), "typed_events": stats.get("events"),
            "partitions": stats.get("partitions"), "model_calls": len(calls),
            "prompt_tokens": sum(int(c.get("prompt_eval_count") or 0) for c in calls),
            "completion_tokens": sum(int(c.get("eval_count") or 0) for c in calls),
            "model_ms": sum(int(c.get("duration_ms") or 0) for c in calls),
            "es_requests": "not recorded", "bytes_fetched": "not recorded",
            "arkime_calls": 0 if not any(str((t.get("intent") or {}).get("target", "")).startswith("arkime")
                                         for t in hunt.tasks) else "see tasks",
            "tshark_cpu_s": "not recorded"}


# --------------------------------------------------------------------------------------------- coverage claims
def _base(t: str) -> str:
    return t.split(":")[-1].split(".")[0]


def coverage_claims(hunt: Hunt, gold: Gold) -> dict:
    """§8.8: cells in state no_match_complete (the only complete-negative cell state; evaluated_complete means
    the partition was fully evaluated, not that nothing matched) whose partition holds gold action/outcome
    records of a technique the rule claims. Also counts the report's rule-level 'complete' negative claims."""
    pack = {p["id"]: p for p in (hunt.manifest.get("pack") or {}).get("playbooks", [])}
    complete = [c for c in hunt.rule_cells if c["state"] == "no_match_complete"]
    cand = set()
    for c in complete:
        rule = pack.get(c["rule_id"])
        if not rule or "/" not in c["partition"]:
            continue
        p0, p1 = c["partition"].split("/", 1)
        t0, t1 = parse_ts(p0), parse_ts(p1)
        techs = {_base(a) for a in rule.get("attack", [])}
        for (oid, _src), rows in gold.es_rows.items():
            if not techs & {_base(a) for a in gold.opportunities[oid].attack}:
                continue
            if any(key[1] == c["target"] and role in ("action", "outcome") and ts and t0 <= ts < t1
                   for key, role, ts, _ds in rows):
                cand.add((c["rule_id"], oid))
    rules_complete = (sum(1 for r in hunt.report_coverage if r.get("negative_claim") == "complete")
                      if hunt.report_coverage is not None else "no report revision")
    return {"complete_negative_cells": len(complete), "rules_claiming_complete": rules_complete,
            "candidate_false_complete_negatives": len(cand),
            "adjudication": "pending custodian review" if cand else "none needed"}
