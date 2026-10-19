"""PROTOCOL §6 matching rule: Tier A (strict), Tier B (loose), and locator-match anomalies."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta

from eval.gold import DIRECT_ROLES, Gold, Opportunity
from eval.hunt import Item

TIER_A_SLACK = timedelta(seconds=120)
TIER_B_SLACK = timedelta(minutes=10)


@dataclass
class ItemMatch:
    item: Item
    tier_a: set[str] = field(default_factory=set)          # opp ids
    tier_a_sources: dict[str, set[str]] = field(default_factory=dict)   # opp id -> sources whose locator matched
    tier_b: set[str] = field(default_factory=set)
    anomalies: list[tuple[str, str]] = field(default_factory=list)       # (opp id, reason)
    context_only: set[str] = field(default_factory=set)     # opps where only context-role locators matched


def _overlap(a0, a1, b0, b1) -> bool:
    if None in (a0, a1, b0, b1):
        return False
    return a0 <= b1 and b0 <= a1


def ok_roles(opp: Opportunity) -> frozenset[str]:
    return DIRECT_ROLES | {"indirect"} if opp.observability == "inferable_only" else DIRECT_ROLES


def match_item(item: Item, gold: Gold) -> ItemMatch:
    m = ItemMatch(item=item)
    # locator hits per opportunity
    hits: dict[str, list[tuple[str, str]]] = {}
    for key in item.keys:
        for oid, role, src in gold.evidence.get(key, ()):
            hits.setdefault(oid, []).append((role, src))
    for oid, opp in gold.opportunities.items():
        ents_ok = bool(item.entities & gold.expand(opp.entities))
        roles = ok_roles(opp)
        good = [(r, s) for r, s in hits.get(oid, []) if r in roles]
        if opp.start is not None and opp.end is not None:
            time_a = _overlap(item.t_min, item.t_max, opp.start - TIER_A_SLACK, opp.end + TIER_A_SLACK)
            time_b = _overlap(item.t_min, item.t_max, opp.start - TIER_B_SLACK, opp.end + TIER_B_SLACK)
        else:
            time_a = time_b = False
        if good:
            if ents_ok and time_a:
                m.tier_a.add(oid)
                m.tier_a_sources[oid] = {s for _, s in good}
            else:
                why = [w for w, bad in (("entity", not ents_ok), ("time", not time_a)) if bad]
                m.anomalies.append((oid, "locator matched but " + "+".join(why) + " check failed"))
        elif ents_ok and time_b:
            m.tier_b.add(oid)
            if hits.get(oid):
                m.context_only.add(oid)
    return m


def match_all(items: list[Item], gold: Gold) -> list[ItemMatch]:
    return [match_item(i, gold) for i in items]
