"""Mission-scale planning behavior for deterministic expansion."""
from collections import Counter
from datetime import timedelta

from romulus.hunt.expansion import ExpansionEngine
from tests.test_expansion_engine import T0, WINDOW, add_anchor, repo_with_anchor
from tests.test_expansion_lane_budget import SteadyFetcher, set_lane


class _CountingEngine(ExpansionEngine):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.event_reads = Counter()

    def _events(self, ids):
        self.event_reads[tuple(ids)] += 1
        return super()._events(ids)


def test_anchor_planning_inputs_are_read_once_when_discoveries_replan_the_tier():
    repo = repo_with_anchor(candidate_id="F-root")
    for index in range(8):
        candidate_id = f"F-root-{index}"
        add_anchor(repo, candidate_id, f"host{index % 3}", ts=T0 + timedelta(seconds=index))
        set_lane(repo, candidate_id, "high")
    fetcher = SteadyFetcher(repo)
    discoveries = iter(range(3))

    def discover(_result):
        try:
            index = next(discoveries)
        except StopIteration:
            return
        candidate_id = f"F-found-{index}"
        add_anchor(repo, candidate_id, f"found{index}", ts=T0 + timedelta(minutes=index + 1))
        set_lane(repo, candidate_id, "high", source_anchor_id="F-root")

    engine = _CountingEngine(
        repo, "h1", WINDOW, fetcher, max_source_queries=1_000,
        per_anchor_source_queries=100, after_link=discover,
    )
    engine.run()

    anchor_event_ids = {
        tuple(repo.candidate(row["candidate_id"])["event_ids"])
        for row in repo.expansion_anchors("h1")
    }
    assert anchor_event_ids
    assert all(engine.event_reads[event_ids] == 1 for event_ids in anchor_event_ids)


def test_anchor_outside_the_hunt_window_is_unexpanded_with_an_explicit_reason():
    repo = repo_with_anchor(candidate_id="F-outside")
    candidate = repo.candidate("F-outside")
    outside = WINDOW.start - timedelta(minutes=10)
    from romulus.store import schema as tables

    with repo.engine.begin() as connection:
        connection.execute(tables.candidate.update().where(
            tables.candidate.c.id == candidate["id"],
        ).values(ts=outside))

    summary = ExpansionEngine(repo, "h1", WINDOW, SteadyFetcher(repo)).run()

    [anchor] = repo.expansion_anchors("h1")
    assert anchor["status"] == "unexpanded"
    assert anchor["reasons"] == ["anchor outside the hunt window"]
    assert summary["unexpanded"] == ["F-outside"]
