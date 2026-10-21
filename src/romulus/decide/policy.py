"""Canonical FindingDecision policy shared by every interface (spec section 10)."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from romulus.detect.base import Match
from romulus.evidence.typed import Outcome

POLICY_VERSION = "decide@1"
LANE_ORDER = {"urgent": 0, "high": 1, "lead": 2, "context": 3, "suppressed": 4}
SEV_WEIGHT = {"critical": 40, "high": 30, "medium": 20, "low": 10, "info": 0}
CONF_WEIGHT = {"high": 20, "medium": 10, "low": 0}


@dataclass
class Decision:
    candidate_id: str
    admitted: bool
    lane: str
    severity: str
    confidence: str
    priority: float
    priority_reasons: list[str]
    gates: dict[str, str]                    # gate -> pass | fail:<why> | n/a
    notes: list[str] = field(default_factory=list)


def candidate_id(m: Match, hunt_id: str) -> str:
    """Stable identity within a hunt: hunt + rule + exact evidence (or documented aggregate group key).
    Scoped to the hunt so re-hunting the same data creates that hunt's own candidates."""
    ident = m.group_key or "|".join(sorted(r.key for e in m.events for r in e.raw))
    return hashlib.sha256(f"{hunt_id}|{m.playbook_id}|{ident}".encode()).hexdigest()[:20]


def decide(m: Match, hunt_id: str) -> Decision:
    gates: dict[str, str] = {}
    notes: list[str] = []
    gates["observation"] = "pass" if m.events else "fail:no events"
    gates["provenance"] = "pass" if m.events and all(e.raw for e in m.events) else "fail:missing raw reference"
    gates["predicate_fields"] = "pass" if m.predicate and all(p.origin for p in m.predicate) \
        else "fail:predicate lacks field lineage"
    gates["entity_time"] = "pass" if m.events and m.events[0].host or m.entities else "fail:no affected entity"
    # A mention (a tool or indicator named in text) is never an action finding. It is still kept visible when it
    # is associated with an attack: admitted, capped at lead, and worded as a mention by its rule.
    gates["claim_type"] = "pass" if m.claim_type != "mention" else "pass:mention (capped at lead, not an action)"

    lane = m.proposed_lane
    if m.claim_type == "mention" and lane in ("urgent", "high"):
        lane = "lead"
        notes.append("lane capped at lead: a mention is not an action")
    confidence = m.confidence
    # Outcome semantics: a direct action claim whose exec outcome is unknown/failed is downgraded.
    if m.claim_type == "observed_action":
        outcomes = {e.outcome for e in m.events}
        if Outcome.failure in outcomes:
            gates["outcome"] = "pass:failed operation (worded as attempt)"
            if lane in ("urgent", "high"):
                lane = "lead"
                notes.append("lane lowered: the recorded operation failed")
            confidence = "medium" if confidence == "high" else confidence
        elif Outcome.unknown in outcomes:
            gates["outcome"] = "pass:outcome unknown (stated in claim)"
            if lane == "urgent":
                lane = "high"
                notes.append("lane lowered from urgent: outcome unknown")
        else:
            gates["outcome"] = "pass"
    else:
        gates["outcome"] = "n/a"
    for e in m.events:
        if e.caveats:
            notes.extend(sorted(set(e.caveats)))
            break
    admitted = all(not v.startswith("fail") for v in gates.values())
    if not admitted:
        lane = "context"

    reasons = [f"severity {m.severity} (+{SEV_WEIGHT[m.severity]})", f"confidence {confidence} (+{CONF_WEIGHT[confidence]})"]
    score = SEV_WEIGHT[m.severity] + CONF_WEIGHT[confidence]
    if m.claim_type == "observed_action":
        score += 10
        reasons.append("direct observed action (+10)")
    if lane == "urgent":
        score += 20
        reasons.append("urgent lane (+20)")
    return Decision(candidate_id=candidate_id(m, hunt_id), admitted=admitted, lane=lane, severity=m.severity,
                    confidence=confidence, priority=float(score), priority_reasons=reasons, gates=gates,
                    notes=notes + m.notes)
