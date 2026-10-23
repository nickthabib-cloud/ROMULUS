"""The expansion budget grows with the anchors to follow, so a hunt with many findings is not held to a lab-sized
total: each anchor that can still be expanded brings its own share of source queries, a ceiling bounds the sum, and
the expansion phase has its own wall clock. When the ceiling binds, the narrow links of every anchor still come
first, the most severe lane first within each tier, and every cut is stated.
"""
from datetime import UTC, datetime, timedelta

import pytest

from romulus.config import Settings
from romulus.hunt import run as hunt_run
from romulus.hunt.expansion import PER_ANCHOR_SOURCE_QUERIES, ExpansionEngine
from romulus.hunt.expansion_plan import TIER_PLAN
from tests.test_expansion_engine import T0, WINDOW, add_anchor, repo_with_anchor, stable_state
from tests.test_expansion_lane_budget import SteadyFetcher, set_lane

LINKS_PER_ANCHOR = sum(len(link_types) for _tier, link_types, _label in TIER_PLAN)
NARROW = {(kind, "anchor ±5 min") for kind in TIER_PLAN[0][1]}


def many_anchors(count, *, hosts=50):
    """One urgent anchor and `count` - 1 high anchors over `hosts` hosts, spread over the hunt window."""
    repo = repo_with_anchor(candidate_id="F-0000")
    for index in range(1, count):
        candidate = f"F-{index:04d}"
        add_anchor(repo, candidate, f"host{index % hosts}", ts=T0 + timedelta(seconds=7 * index))
        set_lane(repo, candidate, "high")
    return repo


def links_by_anchor(fetcher):
    out = {}
    for anchor_id, link_type, label, *_ in fetcher.calls:
        out.setdefault(anchor_id, set()).add((link_type, label))
    return out


def test_every_anchor_runs_its_whole_plan_while_the_shares_are_below_the_ceiling():
    repo = many_anchors(40)
    fetcher = SteadyFetcher(repo)

    summary = ExpansionEngine(repo, "h1", WINDOW, fetcher, max_source_queries=100_000,
                              per_anchor_source_queries=PER_ANCHOR_SOURCE_QUERIES).run()

    served = links_by_anchor(fetcher)
    assert len(served) == 40
    assert all(len(links) == LINKS_PER_ANCHOR for links in served.values())   # T4 and the wide windows included
    assert summary["source_queries"] == 40 * LINKS_PER_ANCHOR * 2
    assert not any("budget" in reason for row in repo.expansion_anchors("h1") for reason in row["reasons"])


def test_the_same_anchors_under_a_fixed_total_stop_in_the_narrow_tiers():
    repo = many_anchors(40)
    fetcher = SteadyFetcher(repo)

    ExpansionEngine(repo, "h1", WINDOW, fetcher, max_source_queries=180).run()

    assert not any(label != "anchor ±5 min" for _anchor, _kind, label, *_ in fetcher.calls)


@pytest.mark.slow
def test_at_mission_scale_the_ceiling_cuts_wide_links_first_and_states_every_cut():
    count, ceiling = 600, 6_000
    repo = many_anchors(count, hosts=120)
    fetcher = SteadyFetcher(repo)

    summary = ExpansionEngine(repo, "h1", WINDOW, fetcher, max_source_queries=ceiling,
                              per_anchor_source_queries=PER_ANCHOR_SOURCE_QUERIES).run()

    assert summary["source_queries"] <= ceiling
    served = links_by_anchor(fetcher)
    assert len(served) == count                                            # no anchor is left unexpanded
    assert all(links >= NARROW for links in served.values())               # every anchor's first tier ran
    keys = [(kind, label) for _anchor, kind, label, *_ in fetcher.calls]
    last_first_tier = max(index for index, key in enumerate(keys) if key in NARROW)
    assert all(label != "anchor ±30 min" for _kind, label in keys[:last_first_tier])   # narrow before wide
    rows = repo.expansion_anchors("h1")
    assert summary["unexpanded"] == []
    assert all(row["status"] in {"expanded_partial", "expanded_complete"} for row in rows)
    cut = [row for row in rows if len(served[row["id"]]) < LINKS_PER_ANCHOR]
    assert cut and all(any("budget" in reason for reason in row["reasons"]) for row in cut)


def test_a_discovered_anchor_brings_its_own_share_after_the_roots_spent_theirs():
    repo = many_anchors(2)
    fetcher = SteadyFetcher(repo)
    found = False

    def discover(result):
        nonlocal found
        if found or len(fetcher.calls) < 12:
            return
        found = True
        add_anchor(repo, "F-found", "web9", ts=T0 + timedelta(minutes=2))
        set_lane(repo, "F-found", "high", source_anchor_id="F-0000")

    ExpansionEngine(repo, "h1", WINDOW, fetcher, max_source_queries=100_000, per_anchor_source_queries=12,
                    after_link=discover).run()

    served = links_by_anchor(fetcher)
    assert served["F-found"] >= NARROW                       # the roots' 24 queries were spent; its own 12 were not
    assert sum(1 for call in fetcher.calls if call[0] == "F-found") >= len(NARROW)


def test_a_per_anchor_expansion_is_deterministic_and_resumes_to_the_same_end():
    def run(crash_after=None):
        repo = many_anchors(30, hosts=7)
        kwargs = {"max_source_queries": 900, "per_anchor_source_queries": PER_ANCHOR_SOURCE_QUERIES}
        if crash_after is not None:
            with pytest.raises(RuntimeError, match="simulated crash"):
                ExpansionEngine(repo, "h1", WINDOW, SteadyFetcher(repo, crash_after=crash_after), **kwargs).run()
        summary = ExpansionEngine(repo, "h1", WINDOW, SteadyFetcher(repo), **kwargs).run()
        return stable_state(repo), summary

    expected = run()
    assert run() == expected
    for crash_after in (5, 90, 300):
        assert run(crash_after) == expected


class _Profile:
    def __init__(self, target):
        self.target = target

    def model_dump(self, mode=None):
        return {"id": f"p-{self.target}", "target": self.target, "kind": "index", "backend_version": "test",
                "doc_count": 1, "datasets": {}}


class _Client:
    def __init__(self, settings):
        pass

    def resolve(self, pattern):
        return [pattern]


def test_a_new_hunt_records_per_anchor_shares_the_ceiling_and_expansions_own_wall_clock(tmp_path, monkeypatch):
    monkeypatch.setattr(hunt_run, "ElasticClient", _Client)
    monkeypatch.setattr(hunt_run, "build_profile", lambda client, target: (_Profile(target), None))
    settings = Settings(home=tmp_path, agent_mode="off", es_index_patterns="logs-host",
                        expansion_max_source_queries=5_000, expansion_wall_clock_minutes=45)
    hunt_id = hunt_run.create_hunt(settings, T0, T0 + timedelta(hours=1), "test")

    expansion = hunt_run.open_repo(settings).get_hunt(hunt_id)["manifest"]["expansion"]
    assert expansion == {"enabled": True, "max_depth": 3, "per_anchor_source_queries": PER_ANCHOR_SOURCE_QUERIES,
                         "max_source_queries": 5_000, "wall_clock_minutes": 45}


@pytest.mark.parametrize("recorded", ["per_anchor", "fixed"])
def test_expansion_runs_under_the_budget_its_hunt_recorded(tmp_path, monkeypatch, recorded):
    seen = {}

    class Engine:
        def __init__(self, *args, **kwargs):
            seen.update(kwargs)

        def run(self):
            return {"status": "completed"}

    monkeypatch.setattr(hunt_run, "ExpansionEngine", Engine)
    monkeypatch.setattr(hunt_run, "PivotExecutor", lambda *args, **kwargs: seen.setdefault("executor", kwargs))
    settings = Settings(home=tmp_path, agent_mode="off")
    repo = hunt_run.open_repo(settings)
    config = ({"enabled": True, "max_depth": 3, "per_anchor_source_queries": 76, "max_source_queries": 5_000,
               "wall_clock_minutes": 45} if recorded == "per_anchor" else
              {"enabled": True, "max_depth": 3, "max_source_queries": 180})
    long_ago = datetime.now(UTC) - timedelta(hours=5)               # a sweep that ran for hours
    hunt = {"id": "h1", "started_at": long_ago,
            "manifest": {"expansion": config, "budgets": {"wall_clock_minutes": 120}, "source_profiles": {}}}

    hunt_run._run_expansion(settings, repo, None, hunt, {}, WINDOW, "owner")

    if recorded == "per_anchor":
        assert seen["per_anchor_source_queries"] == 76 and seen["max_source_queries"] == 5_000
        assert seen["wall_clock_seconds"] == 45 * 60                 # its own clock: the long sweep took none
        assert seen["executor"]["source_query_budget"] == 5_000
    else:
        assert seen["per_anchor_source_queries"] is None and seen["max_source_queries"] == 180
        assert seen["wall_clock_seconds"] == 0                       # the hunt-wide clock, as such hunts recorded
