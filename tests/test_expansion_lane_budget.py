"""Expansion runs every anchor's narrow links before any anchor widens, and serves the most severe lane first within
each tier of the plan: urgent, then high, then lead.

An urgent anchor's wide windows must never take the queries every high anchor needs for its first ±5 min links (a
hunt that did that left all its high anchors unexpanded), and a benign high anchor found later must never take the
queries an urgent anchor's links of the same tier need.
"""
from datetime import timedelta

import pytest

from romulus.hunt.expansion import ExpansionEngine
from romulus.hunt.expansion_plan import TIER_PLAN
from tests.test_expansion_engine import (
    T0,
    WINDOW,
    ScriptedFetcher,
    add_anchor,
    event,
    repo_with_anchor,
    stable_state,
)

LINKS_PER_ANCHOR = sum(len(link_types) for _tier, link_types, _label in TIER_PLAN)


class SteadyFetcher(ScriptedFetcher):
    """Each fetch spends two source queries (within its cap), durably recorded like a real fetch's task."""

    def __init__(self, repo, *, crash_after=None):
        super().__init__(repo)
        self.executor = type("Counter", (), {"source_queries": 0})()
        self.crash_after = crash_after

    def result_id(self, anchor, link_type, window):
        return f"L-{anchor.finding_id}-{link_type}-{window.label}"

    def fetch(self, anchor, link_type, window, *, query_cap=None):
        if self.crash_after is not None and len(self.calls) >= self.crash_after:
            raise RuntimeError("simulated crash")
        spent = min(2, query_cap or 0)
        self.executor.source_queries += spent
        task_id = f"T-{anchor.finding_id}-{link_type}-{window.label}"
        self.repo.upsert_task(task_id, "h1", "expansion_link", anchor.finding_id,
                              {"link_type": link_type, "window": window.label}, f"fp-{task_id}")
        for _ in range(spent):
            self.repo.record_task_source_query(task_id)
        result = super().fetch(anchor, link_type, window, query_cap=query_cap)
        result.id = self.result_id(anchor, link_type, window)
        result.query_spend = spent
        result.task_ids = [task_id]
        return result


def set_lane(repo, candidate_id, lane, severity="high", source_anchor_id=None):
    from romulus.store import schema as tables
    with repo.engine.begin() as connection:
        connection.execute(tables.candidate.update().where(tables.candidate.c.id == candidate_id).values(
            lane=lane, severity=severity, source_anchor_id=source_anchor_id))


def urgent_and_later_highs(*, highs=2, leads=1):
    """One urgent anchor on web1, then high anchors (earlier in time, on other hosts) and lead candidates."""
    repo = repo_with_anchor(candidate_id="F-urgent")
    for index in range(highs):
        candidate = f"F-high-{index}"
        add_anchor(repo, candidate, f"cam{index}", ts=T0 - timedelta(minutes=10 + index))
        set_lane(repo, candidate, "high")
    for index in range(leads):
        candidate = f"F-lead-{index}"
        add_anchor(repo, candidate, f"lead{index}", ts=T0 - timedelta(minutes=20 + index))
        set_lane(repo, candidate, "lead", severity="medium")
    return repo


def links_of(repo, anchor_id):
    return [row for row in repo.expansion_links("h1") if row["anchor_id"] == anchor_id]


def anchors(repo):
    return {row["id"]: row for row in repo.expansion_anchors("h1")}


def test_every_anchor_gets_its_narrow_links_before_any_anchor_widens_and_urgent_goes_first_in_each_tier():
    repo = urgent_and_later_highs()
    fetcher = SteadyFetcher(repo)

    ExpansionEngine(repo, "h1", WINDOW, fetcher, max_source_queries=60).run()

    labels = [call[2] for call in fetcher.calls]
    first_wide = labels.index("anchor ±30 min")
    assert {call[0] for call in fetcher.calls[:first_wide]} == {"F-urgent", "F-high-0", "F-high-1"}
    narrow = TIER_PLAN[0][1] + TIER_PLAN[1][1]
    for link_type in narrow:                       # within a narrow link type, the urgent anchor is served first
        served = [call[0] for call in fetcher.calls[:first_wide] if call[1] == link_type]
        assert served[0] == "F-urgent"
    rows = anchors(repo)
    assert "F-lead-0" not in rows                                  # a lead candidate is not an expansion anchor


def test_a_high_anchor_discovered_later_never_takes_the_urgent_anchors_links_of_the_same_tier():
    repo = urgent_and_later_highs(highs=0, leads=0)
    fetcher = SteadyFetcher(repo)
    inserted = False

    def discover_high(_result):
        nonlocal inserted
        if inserted:
            return
        inserted = True
        add_anchor(repo, "F-found", "cam9", ts=T0 + timedelta(minutes=1))
        set_lane(repo, "F-found", "high", source_anchor_id="F-urgent")

    ExpansionEngine(repo, "h1", WINDOW, fetcher, max_source_queries=60, after_link=discover_high).run()

    t1 = [(call[0], call[1]) for call in fetcher.calls if call[2] == "anchor ±5 min" and call[1] in TIER_PLAN[0][1]]
    for link_type in TIER_PLAN[0][1]:
        served = [anchor for anchor, kind in t1 if kind == link_type]
        assert served[0] == "F-urgent"
    urgent_narrow = {(call[1], call[2]) for call in fetcher.calls
                     if call[0] == "F-urgent" and call[2] == "anchor ±5 min"}
    assert urgent_narrow >= {(kind, "anchor ±5 min") for kind in TIER_PLAN[0][1] + TIER_PLAN[1][1]}
    assert "F-found" in [call[0] for call in fetcher.calls]       # it still runs, its narrow links first


def test_a_more_severe_anchor_discovered_later_gets_its_narrow_links_before_the_lower_lane_continues():
    repo = urgent_and_later_highs(highs=1, leads=0)
    set_lane(repo, "F-urgent", "high")                            # two high roots, no urgent yet
    fetcher = SteadyFetcher(repo)
    inserted = False

    def discover_urgent(_result):
        nonlocal inserted
        if inserted:
            return
        inserted = True
        add_anchor(repo, "F-critical", "web7", ts=T0 + timedelta(minutes=1))
        set_lane(repo, "F-critical", "urgent", severity="critical", source_anchor_id="F-urgent")

    ExpansionEngine(repo, "h1", WINDOW, fetcher, max_source_queries=200, after_link=discover_urgent).run()

    order = [(call[0], call[1], call[2]) for call in fetcher.calls]
    first = [anchor for anchor, *_ in order].index("F-critical")
    assert first == 1                                              # right after the link that found it
    assert order[first] == ("F-critical", TIER_PLAN[0][1][0], "anchor ±5 min")


def test_under_a_tight_budget_the_narrow_links_of_every_anchor_come_before_the_urgent_anchors_wide_ones():
    repo = urgent_and_later_highs(highs=0, leads=0)
    fetcher = SteadyFetcher(repo)
    inserted = False

    def discover_high(_result):
        nonlocal inserted
        if inserted:
            return
        inserted = True
        add_anchor(repo, "F-found", "cam9", ts=T0 + timedelta(minutes=1))
        set_lane(repo, "F-found", "high", source_anchor_id="F-urgent")

    summary = ExpansionEngine(repo, "h1", WINDOW, fetcher, max_source_queries=20,
                              after_link=discover_high).run()

    assert summary["source_queries"] <= 20
    found = [call for call in fetcher.calls if call[0] == "F-found"]
    assert found and all(call[2] == "anchor ±5 min" for call in found)   # the high anchor got narrow links
    assert not any(call[0] == "F-urgent" and call[2] == "anchor ±30 min"
                   for call in fetcher.calls[:fetcher.calls.index(found[0])])
    rows = anchors(repo)
    assert rows["F-urgent"]["status"] in {"expanded_partial", "expanded_complete"}
    assert any("budget" in reason for row in rows.values() for reason in row["reasons"])


def test_within_a_lane_a_discovered_anchor_still_gets_its_first_tier_before_surviving_deeper_tiers():
    repo = urgent_and_later_highs(highs=0, leads=0)
    fetcher = SteadyFetcher(repo)
    inserted = False

    def discover_urgent(result):
        nonlocal inserted
        if inserted or result.link_type != "host_after_anchor" or result.window.label != "anchor ±5 min":
            return
        inserted = True
        add_anchor(repo, "F-child", "web2", ts=T0 + timedelta(minutes=1))
        set_lane(repo, "F-child", "urgent", severity="critical", source_anchor_id="F-urgent")

    ExpansionEngine(repo, "h1", WINDOW, fetcher, after_link=discover_urgent).run()

    order = [(call[0], call[1], call[2]) for call in fetcher.calls]
    child_t1 = order.index(("F-child", "login_session", "anchor ±5 min"))
    assert all(anchor_id == "F-urgent" for anchor_id, *_ in order[:child_t1])
    assert ("F-urgent", "login_session", "anchor ±30 min") in order[child_t1:]


def tied_anchors(names):
    """An urgent anchor and two high anchors on one host at the same instant, whose candidate ids are `names`: a
    candidate id carries its hunt's id, so two runs of one hunt name the same two findings differently."""
    repo = repo_with_anchor(candidate_id="F-urgent")
    for evidence, rule_id in (("tie-a", "corr.process_network_link"), ("tie-b", "host.interpreter_external_connection")):
        record = event(f"{evidence}-event", host="cam1", ts=T0 - timedelta(minutes=10))
        repo.save_evidence("h1", [record], {}, None)
        repo.save_candidate({
            "id": names[evidence], "hunt_id": "h1", "rule_id": rule_id, "rule_version": "1", "claim": "tied",
            "claim_type": "observed_action", "event_ids": [record.id], "predicate_fields": [],
            "entities": [["host", "cam1", "host"]], "ts": record.ts, "severity": "high", "confidence": "high",
            "lane": "high", "priority": 40.0, "priority_reasons": [], "gate_results": {}, "benign_alternatives": [],
            "next_checks": [], "source_case_id": None, "source_anchor_id": None, "source_link_id": None,
        })
    return repo


def test_anchors_tied_on_lane_severity_and_time_are_ordered_the_same_in_every_run_of_a_hunt():
    outcomes = []
    for names in ({"tie-a": "F-1", "tie-b": "F-2"}, {"tie-a": "F-2", "tie-b": "F-1"}):
        evidence_of = {name: evidence for evidence, name in names.items()} | {"F-urgent": "urgent"}
        repo = tied_anchors(names)
        fetcher = SteadyFetcher(repo)
        ExpansionEngine(repo, "h1", WINDOW, fetcher, max_source_queries=16).run()
        rows = anchors(repo)
        cut = [evidence_of[anchor_id] for anchor_id, row in rows.items()
               if any("budget" in reason for reason in row["reasons"])]
        outcomes.append(([(evidence_of[call[0]], call[1], call[2]) for call in fetcher.calls], sorted(cut)))
    assert outcomes[0][1]                                          # the budget cut falls among the tied anchors
    assert outcomes[0] == outcomes[1]


def test_lane_ordered_expansion_is_deterministic():
    outcomes = []
    for _ in range(2):
        repo = urgent_and_later_highs(highs=3)
        fetcher = SteadyFetcher(repo)
        summary = ExpansionEngine(repo, "h1", WINDOW, fetcher, max_source_queries=70).run()
        outcomes.append((stable_state(repo), summary, fetcher.calls))
    assert outcomes[0] == outcomes[1]


@pytest.mark.parametrize("crash_after", [5, LINKS_PER_ANCHOR + 3])
def test_a_resumed_lane_ordered_expansion_ends_where_an_uninterrupted_one_does(crash_after):
    uninterrupted = urgent_and_later_highs(highs=2)
    expected = ExpansionEngine(uninterrupted, "h1", WINDOW, SteadyFetcher(uninterrupted),
                               max_source_queries=60).run()

    repo = urgent_and_later_highs(highs=2)
    with pytest.raises(RuntimeError, match="simulated crash"):
        ExpansionEngine(repo, "h1", WINDOW, SteadyFetcher(repo, crash_after=crash_after),
                        max_source_queries=60).run()
    resumed = SteadyFetcher(repo)
    summary = ExpansionEngine(repo, "h1", WINDOW, resumed, max_source_queries=60).run()

    assert stable_state(repo) == stable_state(uninterrupted)
    assert summary == expected
