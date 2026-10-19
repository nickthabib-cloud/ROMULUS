"""Agent effectiveness (PROTOCOL §8 item 10): what the model-driven investigator did and what it reached.

Class-level aggregates only. Per-opportunity reach goes to the private output.
"""
from __future__ import annotations

import json
import re
from collections import Counter
from datetime import timedelta

from eval.gold import DIRECT_ROLES, Gold
from eval.hunt import Hunt
from eval.match import ItemMatch
from eval.metrics import item_signature

TIER_B_SLACK = timedelta(minutes=10)


def _reason_class(text: str | None) -> str:
    """Rejection text reduced to its category (ids and values stripped)."""
    if not text:
        return "unspecified"
    parts = []
    for clause in str(text).split(";"):
        c = clause.strip().split(":", 1)[0]
        c = re.sub(r"\b(step|steps)\s+\d+\b", r"\1 N", c)
        c = re.sub(r"'[^']*'|\"[^\"]*\"|\b[0-9a-f]{8,}\b|\d+", "…", c).strip()
        if c:
            parts.append(c)
    return "; ".join(sorted(set(parts))) or "unspecified"


def _summary(case: dict) -> dict:
    s = case.get("summary")
    if not s:
        return {}
    try:
        v = json.loads(s)
        return v if isinstance(v, dict) else {}
    except (TypeError, json.JSONDecodeError):
        return {"model_conclusion": "legacy_summary"}


def effectiveness(hunt: Hunt, gold: Gold, matches: list[ItemMatch], hits: dict,
                  adjudications: dict | None = None) -> tuple[dict, dict]:
    agent = next((a["detail"] for a in reversed(hunt.audit) if a["action"] == "hunt.agent_summary"), None) or {}
    steps = hunt.case_steps
    decisions = Counter()
    rejections = Counter()
    for s in steps:
        d = s["decision"] or {}
        act = d.get("action", "unknown")
        if act == "seed":
            continue
        decisions[f"{act}:{'accepted' if s['accepted'] else 'rejected'}"] += 1
        if not s["accepted"]:
            rejections[_reason_class(s.get("rejection"))] += 1
    piv = hunt.pivots
    executed = [p for p in piv if p["executed"]]
    calls = hunt.model_calls
    agent_items = [m for m in matches if m.item.source_case_id]
    # pivot reach: locator level (a retrieved record is gold action/outcome evidence) and Tier B (entity + window)
    reach_a: set[str] = set()
    reach_b: set[str] = set()
    for p in executed:
        for k in p["keys"]:
            for oid, role, _src in gold.evidence.get(k, ()):
                if role in DIRECT_ROLES and gold.opportunities[oid].observability == "observable":
                    reach_a.add(oid)
        for oid, o in gold.opportunities.items():
            if o.observability != "observable" or o.start is None or not p["start"] or not p["end"]:
                continue
            if p["entities"] & gold.expand(o.entities) and p["start"] <= o.end + TIER_B_SLACK \
                    and o.start - TIER_B_SLACK <= p["end"]:
                reach_b.add(oid)
    surfaced = set(hits["surfaced"])
    def cls(ids):
        return dict(sorted(Counter(gold.opportunities[i].behavior_class for i in ids).items()))
    conclusions = Counter((_summary(c).get("model_conclusion") or "none") for c in hunt.cases)
    flags = sum(1 for c in hunt.cases if _summary(c).get("analyst_flag"))
    out = {
        "present": bool(hunt.cases or calls),
        "status": agent.get("status", "unknown"), "stop_reason": agent.get("stop_reason"),
        "cases": len(hunt.cases), "cases_by_status": dict(Counter(c["status"] for c in hunt.cases)),
        "steps_used": sum(int(c.get("steps_used") or 0) for c in hunt.cases),
        "step_budget": sum(int(c.get("step_budget") or 0) for c in hunt.cases),
        "decisions": dict(sorted(decisions.items())), "rejection_reasons": dict(rejections.most_common()),
        "pivots": {"proposed": len(piv), "executed": len(executed),
                   "complete": sum(p["status"] == "complete" for p in executed),
                   "partial": sum(p["status"] == "partial" for p in executed),
                   "failed": sum(p["status"] == "failed" for p in executed),
                   "rejected": sum(not p["accepted"] for p in piv),
                   "duplicates_blocked": agent.get("duplicate_pivots_blocked"),
                   "tools_executed": dict(Counter(p["tool"] for p in executed))},
        "fallback_parked": sum(c["status"] == "fallback_parked" for c in hunt.cases),
        "analyst_flags": flags, "conclusions": dict(conclusions),
        "escalations_accepted": decisions.get("escalate:accepted", 0),
        "seeds": {"total": agent.get("seed_count"),
                  "concluded": _n(agent.get("concluded_seed_ids")),
                  "assigned_unfinished": _n(agent.get("assigned_unfinished_seed_ids")),
                  "unassigned": _n(agent.get("unassigned_seed_ids")),
                  "unworked": agent.get("unworked_count", _n(agent.get("unworked_seed_ids")))},
        "model_calls": {"total": len(calls), "by_status": dict(Counter(c["status"] for c in calls)),
                        "prompt_tokens": sum(int(c.get("prompt_eval_count") or 0) for c in calls),
                        "completion_tokens": sum(int(c.get("eval_count") or 0) for c in calls),
                        "model_ms": sum(int(c.get("duration_ms") or 0) for c in calls)},
        "agent_items": {"total": len(agent_items), "by_lane": dict(Counter(m.item.lane for m in agent_items)),
                        "tier_a_opps": len({o for m in agent_items for o in m.tier_a}),
                        "tier_b_opps": len({o for m in agent_items for o in m.tier_b})},
        "pivot_reach": {"locator_level_opps": len(reach_a), "locator_level_by_class": cls(reach_a),
                        "locator_level_not_otherwise_surfaced": cls(reach_a - surfaced),
                        "entity_window_opps": len(reach_b), "entity_window_by_class": cls(reach_b),
                        "note": "a pivot retrieving a gold record is reach, not a finding; only an admitted item counts "
                                "toward recall"},
    }
    out["pivot_reach"]["executed_pivots_retrieving_gold"] = sum(
        1 for p in executed if any(role in DIRECT_ROLES for k in p["keys"] for _o, role, _s in gold.evidence.get(k, ())))
    v2, v2_private = _menu_and_conclusions(hunt, gold, matches, hits, agent, adjudications or {})
    out.update(v2)
    private = {"pivot_reach_locator": sorted(reach_a), "pivot_reach_entity_window": sorted(reach_b),
               "agent_item_hits": sorted({o for m in agent_items for o in m.tier_a}), **v2_private}
    return out, private


def _option_kind(decision: dict) -> str:
    act = decision.get("action", "unknown")
    return f"pivot:{decision.get('tool')}" if act == "pivot" else act


def _menu_and_conclusions(hunt: Hunt, gold: Gold, matches: list[ItemMatch], hits: dict, agent: dict,
                          adjudications: dict):
    """Investigator v2 (menu-driven) fields, and the gold quality of case conclusions and concluded seeds."""
    by_item = {m.item.id: m for m in matches}
    menu_steps = [s for s in hunt.case_steps if "chosen_option" in (s["decision"] or {})]
    chosen = Counter()
    sizes, hidden, truncated, fallbacks, attempts = [], 0, 0, 0, Counter()
    for s in menu_steps:
        d = s["decision"]
        menu = {o.get("id"): o for o in d.get("menu") or []}
        opt = menu.get(d.get("chosen_option"))
        chosen[_option_kind((opt or {}).get("decision") or d)] += 1
        sizes.append(len(menu))
        hidden += int(d.get("menu_hidden_count") or 0)
        truncated += bool(d.get("text_truncated"))
        fallbacks += bool(d.get("deterministic_fallback"))
        attempts[str(d.get("model_attempt"))] += 1
    defects = sum(1 for s in hunt.case_steps if (s["decision"] or {}).get("action") == "constraint_defect")
    model_errors = sum(1 for s in hunt.case_steps if (s["decision"] or {}).get("action") == "model_error")

    def gold_opps(cids):
        return {o for c in cids if c in by_item for o in by_item[c].tier_a}

    def cls(ids):
        return dict(sorted(Counter(gold.opportunities[i].behavior_class for i in ids).items()))
    # case conclusions vs gold
    concl = Counter()
    verdicts = Counter()

    def verdict(cid):
        m = by_item.get(cid)
        if m is None:
            return "missing"
        if m.tier_a:
            return "tier_a_hit"
        return (adjudications.get(item_signature(m.item)) or {}).get("verdict") or f"unadjudicated_{m.item.lane}"
    esc_gold, esc_only_lead = set(), set()
    concluded_benign_on_gold = set()
    for case in hunt.cases:
        st = case["status"]
        if st not in ("escalated", "parked", "closed"):
            continue
        steps = [s for s in hunt.case_steps if s["case_id"] == case["id"]]
        seeds = next(((s["decision"] or {}).get("seed_candidate_ids") or [] for s in steps
                      if (s["decision"] or {}).get("action") == "seed"), [])
        escalated = [(s["decision"] or {}).get("candidate_id") for s in steps
                     if (s["decision"] or {}).get("action") == "escalate" and s["accepted"]]
        opps = gold_opps(seeds + [c for c in escalated if c])
        for c in escalated:
            verdicts[f"escalated:{verdict(c)}"] += 1
        if st in ("parked", "closed"):
            for c in seeds:
                verdicts[f"{st}_seed:{verdict(c)}"] += 1
        concl[f"{st}:{'gold' if opps else 'no_gold'}"] += 1
        if st == "escalated":
            eo = gold_opps([c for c in escalated if c])
            esc_gold |= eo
            esc_only_lead |= {o for o in eo if o not in hits["reported"]}
        if st == "closed" and opps:
            concluded_benign_on_gold |= opps
    seeds_concluded = [c for c in (agent.get("concluded_seed_ids") or []) if isinstance(c, str)]
    seeds_unworked = [c for c in (agent.get("unworked_seed_ids") or []) if isinstance(c, str)]
    out = {"menu": {"menus": len(menu_steps), "options_chosen_by_kind": dict(chosen.most_common()),
                    "menu_size_median": sorted(sizes)[len(sizes) // 2] if sizes else None,
                    "hidden_options_total": hidden, "text_truncated": truncated,
                    "deterministic_fallbacks": fallbacks, "model_attempts": dict(attempts),
                    "constraint_defects": defects, "model_errors": model_errors} if menu_steps else None,
           "conclusions_vs_gold": {
               "cases_by_status_and_gold": dict(sorted(concl.items())),
               "concluded_candidates_by_verdict": dict(sorted(verdicts.items())),
               "escalations_on_gold_opps": len(esc_gold), "escalations_on_gold_by_class": cls(esc_gold),
               "escalated_gold_opps_not_reported_by_sweep": cls(esc_only_lead),
               "closed_cases_holding_gold": cls(concluded_benign_on_gold),
               "seeds_concluded_with_gold": len(gold_opps(seeds_concluded)),
               "seeds_concluded_with_gold_by_class": cls(gold_opps(seeds_concluded)),
               "seeds_unworked_with_gold_by_class": cls(gold_opps(seeds_unworked)),
               "note": "escalation cannot change a candidate's lane; it marks the case escalated. Gold is judged on "
                       "the seed and escalated candidates' Tier A hits"}}
    private = {"escalated_gold_opps": sorted(esc_gold), "seed_concluded_gold_opps": sorted(gold_opps(seeds_concluded))}
    return out, private


def _n(v) -> int | None:
    if v is None:
        return None
    return len(v) if isinstance(v, list) else int(v)
