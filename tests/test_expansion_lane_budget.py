"""Expansion serves its query budget by severity: urgent anchors first, then high, then lead.

A benign anchor that appears later in a lower or equal lane (a newly configured network turning CCTV connects into
high findings) must never take the queries an urgent anchor's remaining tiers need. Within a lane the tier-major,
per-host fair order stays: a discovered anchor still gets its first tier before surviving deeper tiers there.
"""
from datetime import timedelta

import pytest

from romulus.hunt.expansion import BUDGET_TO_SEVERE_REASON, ExpansionEngine
from romulus.hunt.expansion_plan import TIER_PLAN
from tests.test_expansion_engine import (
    T0,
    WINDOW,
    ScriptedFetcher,
    add_anchor,
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


def test_the_urgent_anchors_tiers_all_run_before_any_high_anchor_spends():
    repo = urgent_and_later_highs()
    fetcher = SteadyFetcher(repo)

    ExpansionEngine(repo, "h1", WINDOW, fetcher, max_source_queries=60).run()

    order = [call[0] for call in fetcher.calls]
    assert order[:LINKS_PER_ANCHOR] == ["F-urgent"] * LINKS_PER_ANCHOR
    assert len(links_of(repo, "F-urgent")) == LINKS_PER_ANCHOR
    rows = anchors(repo)
    assert rows["F-urgent"]["status"] == "expanded_complete" and rows["F-urgent"]["reasons"] == []
    # the highs share what is left, tier by tier and host by host, and say why they stopped
    assert {call[0] for call in fetcher.calls[LINKS_PER_ANCHOR:]} == {"F-high-0", "F-high-1"}
    for anchor_id in ("F-high-0", "F-high-1"):
        assert rows[anchor_id]["status"] == "expanded_partial"
        assert any("budget" in reason for reason in rows[anchor_id]["reasons"])
    assert "F-lead-0" not in rows                                  # a lead candidate is not an expansion anchor


def test_a_lower_lane_anchor_discovered_later_never_takes_the_urgent_anchors_remaining_tiers():
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

    order = [call[0] for call in fetcher.calls]
    assert order[:LINKS_PER_ANCHOR] == ["F-urgent"] * LINKS_PER_ANCHOR
    assert anchors(repo)["F-urgent"]["status"] == "expanded_complete"
    assert "F-found" in order                                      # it still runs, from what is left


def test_a_more_severe_anchor_discovered_later_is_served_before_the_lower_lane_continues():
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

    order = [call[0] for call in fetcher.calls]
    first = order.index("F-critical")
    assert first == 1                                              # right after the link that found it
    assert order[first:first + LINKS_PER_ANCHOR] == ["F-critical"] * LINKS_PER_ANCHOR


def test_an_urgent_root_waiting_for_the_reserve_gets_it_before_a_less_severe_discovered_anchor():
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

    assert summary["source_queries"] == 20
    assert [call[0] for call in fetcher.calls] == ["F-urgent"] * 10       # all 20 queries, 2 per fetch
    rows = anchors(repo)
    assert rows["F-found"]["status"] == "unexpanded"
    assert BUDGET_TO_SEVERE_REASON in rows["F-found"]["reasons"]


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
    if crash_after <= LINKS_PER_ANCHOR:
        assert resumed.calls[0][0] == "F-urgent"                   # the urgent anchor's tiers resume first
