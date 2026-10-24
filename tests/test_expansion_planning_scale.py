"""Mission-scale planning behavior for deterministic expansion."""
import random
from collections import Counter
from datetime import timedelta

import pytest

from romulus.hunt.expansion import PER_ANCHOR_SOURCE_QUERIES, ExpansionEngine
from romulus.store import schema as tables
from tests.expansion_reference import ReferenceExpansionEngine
from tests.test_expansion_engine import T0, WINDOW, add_anchor, repo_with_anchor, stable_state
from tests.test_expansion_lane_budget import SteadyFetcher, set_lane
from tests.test_expansion_victim_host import _fetcher, network_anchor_repo


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
    with repo.engine.begin() as connection:
        connection.execute(tables.candidate.update().where(
            tables.candidate.c.id == candidate["id"],
        ).values(ts=outside))

    summary = ExpansionEngine(repo, "h1", WINDOW, SteadyFetcher(repo)).run()

    [anchor] = repo.expansion_anchors("h1")
    assert anchor["status"] == "unexpanded"
    assert anchor["reasons"] == ["anchor outside the hunt window"]
    assert summary["unexpanded"] == ["F-outside"]


def test_network_anchor_plan_keeps_victim_variants_and_their_notes():
    repo = network_anchor_repo()
    engine = ExpansionEngine(repo, "h1", WINDOW, _fetcher(repo), max_depth=1)

    engine.run()

    host_plans = [
        plan for link_type, plan in engine._plans["F-net"].links.items()
        if link_type in {"login_session", "process_lineage", "host_after_anchor"}
    ]
    assert host_plans and all(plan.variants for plan in host_plans)
    assert any(plan.notes for plan in host_plans)


def _random_repo(seed: int, count: int = 16):
    rng = random.Random(seed)
    repo = repo_with_anchor(candidate_id="F-000")
    specs = []
    for index in range(count):
        candidate_id = f"F-{index:03d}"
        host = f"host{rng.randrange(4)}"
        ts = T0 + timedelta(seconds=rng.choice((0, 0, 1, 2, 5)))
        lane = rng.choice(("urgent", "high", "lead"))
        severity = rng.choice(("critical", "high", "medium"))
        rule_id = rng.choice(("host.web_shell", "corr.process_network_link"))
        if index:
            add_anchor(repo, candidate_id, host, ts=ts)
        else:
            host = "web1"
            ts = T0
        with repo.engine.begin() as connection:
            connection.execute(tables.candidate.update().where(
                tables.candidate.c.id == candidate_id,
            ).values(lane=lane, severity=severity, rule_id=rule_id,
                     group_key=f"group-{rng.randrange(6)}", ts=ts))
        specs.append((candidate_id, host, ts, lane, severity))
    for candidate_id, host, ts, lane, severity in specs:
        repo.save_expansion_anchor({
            "id": candidate_id, "hunt_id": "h1", "candidate_id": candidate_id,
            "depth": 0, "parent_anchor_id": None, "host": host, "lane": lane,
            "severity": severity, "ts": ts, "status": "pending", "reasons": [],
        })
    return repo


def _discoveries(repo, fetcher, seed):
    rng = random.Random(seed + 1000)
    planned = {
        trigger: (
            f"F-found-{index}", f"found{rng.randrange(3)}",
            rng.choice(("urgent", "high")), rng.choice(("critical", "high")),
        )
        for index, trigger in enumerate((1, 4, 9, 17))
    }

    def after_link(_result):
        spec = planned.get(len(fetcher.calls))
        if spec is None:
            return
        candidate_id, host, lane, severity = spec
        add_anchor(repo, candidate_id, host, ts=T0 + timedelta(minutes=len(fetcher.calls)))
        set_lane(repo, candidate_id, lane, severity=severity, source_anchor_id="F-000")

    return after_link


@pytest.mark.parametrize(("seed", "budget"), [
    (7, {"max_source_queries": 70}),
    (11, {"max_source_queries": 100, "per_anchor_source_queries": 12}),
    (29, {"max_source_queries": 1_000, "per_anchor_source_queries": PER_ANCHOR_SOURCE_QUERIES}),
])
def test_randomized_plans_equal_the_previous_planner(seed, budget):
    def run(engine_cls):
        repo = _random_repo(seed)
        fetcher = SteadyFetcher(repo)
        summary = engine_cls(
            repo, "h1", WINDOW, fetcher, after_link=_discoveries(repo, fetcher, seed), **budget,
        ).run()
        return stable_state(repo), summary, fetcher.calls

    assert run(ExpansionEngine) == run(ReferenceExpansionEngine)


def _resume_run(crash_after=None):
    repo = _random_repo(43, count=20)

    def callback(result):
        evaluated = sum(link["evaluated"] for link in repo.expansion_links("h1"))
        for index, threshold in enumerate((1, 5, 12)):
            candidate_id = f"F-resume-found-{index}"
            if evaluated < threshold or repo.candidate(candidate_id) is not None:
                continue
            add_anchor(repo, candidate_id, f"resume{index}", ts=result.window.start + timedelta(seconds=index))
            set_lane(repo, candidate_id, "urgent" if index == 2 else "high",
                     severity="critical" if index == 2 else "high", source_anchor_id="F-000")

    kwargs = {
        "max_source_queries": 700,
        "per_anchor_source_queries": PER_ANCHOR_SOURCE_QUERIES,
    }
    if crash_after is not None:
        with pytest.raises(RuntimeError, match="simulated crash"):
            fetcher = SteadyFetcher(repo, crash_after=crash_after)
            ExpansionEngine(repo, "h1", WINDOW, fetcher, after_link=callback, **kwargs).run()
    fetcher = SteadyFetcher(repo)
    summary = ExpansionEngine(repo, "h1", WINDOW, fetcher, after_link=callback, **kwargs).run()
    return stable_state(repo), summary


def test_discovery_planning_resumes_deterministically_at_several_crash_points():
    expected = _resume_run()
    assert _resume_run() == expected
    for crash_after in (2, 8, 25, 80):
        assert _resume_run(crash_after) == expected
