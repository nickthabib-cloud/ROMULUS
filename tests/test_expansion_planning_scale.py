"""Mission-scale planning behavior for deterministic expansion."""
import hashlib
import random
from collections import Counter
from datetime import timedelta

import pytest

from romulus.hunt import expansion as expansion_module
from romulus.hunt.expansion import PER_ANCHOR_SOURCE_QUERIES, ExpansionEngine
from romulus.store import schema as tables
from tests.expansion_reference import ReferenceExpansionEngine
from tests.test_expansion_engine import (
    T0,
    WINDOW,
    ScriptedFetcher,
    add_anchor,
    event,
    repo_with_anchor,
    stable_state,
)
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



class _PublishingFetcher(ScriptedFetcher):
    """Spends two queries per fetch; about one link in five returns a fresh credential read, which the direct pack
    publishes as a finding that becomes a discovered anchor: the production discovery path, with no after_link."""

    def __init__(self, repo, seed, crash_after=None):
        super().__init__(repo)
        self.executor = type("Counter", (), {"source_queries": 0})()
        self.seed, self.crash_after = seed, crash_after

    def result_id(self, anchor, link_type, window):
        return f"L-{anchor.finding_id}-{link_type}-{window.label}"

    def fetch(self, anchor, link_type, window, *, query_cap=None):
        if self.crash_after is not None and len(self.calls) >= self.crash_after:
            raise RuntimeError("simulated crash")
        key = f"{self.seed}|{anchor.finding_id}|{link_type}|{window.label}"
        draw = int(hashlib.sha256(key.encode()).hexdigest(), 16)
        spent = min(2, query_cap or 0)
        self.executor.source_queries += spent
        task_id = f"T-{key}"
        self.repo.upsert_task(task_id, "h1", "expansion_link", anchor.finding_id, {"k": key}, f"fp-{task_id}")
        for _ in range(spent):
            self.repo.record_task_source_query(task_id)
        self.linked = None
        if draw % 5 == 0:
            read = event(f"cred-{draw % 10**12}", host=f"h{draw % 4}", ts=T0 + timedelta(seconds=draw % 600),
                         argv=["/usr/bin/cat", "/etc/shadow"])
            self.repo.save_evidence("h1", [read], {}, None)
            self.linked, self.linked_type = read, link_type
        result = super().fetch(anchor, link_type, window, query_cap=query_cap)
        result.id = self.result_id(anchor, link_type, window)
        result.query_spend = spent
        result.task_ids = [task_id]
        return result


def _published_run(engine_cls, seed, budget, crash_after=None):
    repo = _random_repo(seed, count=10)
    if crash_after is not None:
        with pytest.raises(RuntimeError, match="simulated crash"):
            engine_cls(repo, "h1", WINDOW, _PublishingFetcher(repo, seed, crash_after), **budget).run()
    fetcher = _PublishingFetcher(repo, seed)
    summary = engine_cls(repo, "h1", WINDOW, fetcher, **budget).run()
    return stable_state(repo), summary, fetcher.calls


@pytest.mark.parametrize("cache_events", [expansion_module.PLAN_CACHE_EVENTS, 1])
@pytest.mark.parametrize(("seed", "budget"), [
    (0, {"max_source_queries": 60}),
    (3, {"max_source_queries": 200}),
    (5, {"max_source_queries": 150, "per_anchor_source_queries": 12}),
    (8, {"max_source_queries": 2_000, "per_anchor_source_queries": PER_ANCHOR_SOURCE_QUERIES}),
])
def test_anchors_published_by_links_plan_as_the_previous_planner_did(seed, budget, cache_events, monkeypatch):
    """With a cache too small to hold one plan, every plan is evicted and rebuilt from the store: no result changes."""
    monkeypatch.setattr(expansion_module, "PLAN_CACHE_EVENTS", cache_events)
    expected = _published_run(ReferenceExpansionEngine, seed, budget)
    assert len(expected[0]["anchors"]) > 10                       # links published discovered anchors
    assert _published_run(ExpansionEngine, seed, budget) == expected
    for crash_after in (3, 17):
        assert _published_run(ExpansionEngine, seed, budget, crash_after)[:2] == expected[:2]


def test_a_tiny_plan_cache_evicts_and_holds_no_evaluated_links_row(monkeypatch):
    monkeypatch.setattr(expansion_module, "PLAN_CACHE_EVENTS", 1)
    repo = _random_repo(43, count=20)
    with pytest.raises(RuntimeError, match="simulated crash"):
        ExpansionEngine(repo, "h1", WINDOW, SteadyFetcher(repo, crash_after=30)).run()
    engine = ExpansionEngine(repo, "h1", WINDOW, SteadyFetcher(repo))
    engine.run()

    assert len(engine._plans) == 1 and engine._plan_events <= max(1, len(engine._plans[next(iter(engine._plans))].events))
    slots = [slot for plan in engine._plans.values() for link in plan.links.values()
             for window_slots in link.slots.values() for slot in window_slots]
    assert slots and all(slot.stored is None for slot in slots if slot.done)
