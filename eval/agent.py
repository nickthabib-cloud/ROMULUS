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


def effectiveness(hunt: Hunt, gold: Gold, matches: list[ItemMatch], hits: dict) -> tuple[dict, dict]:
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
    private = {"pivot_reach_locator": sorted(reach_a), "pivot_reach_entity_window": sorted(reach_b),
               "agent_item_hits": sorted({o for m in agent_items for o in m.tier_a})}
    return out, private


def _n(v) -> int | None:
    if v is None:
        return None
    return len(v) if isinstance(v, list) else int(v)
