"""Deterministic expansion controller: accounting, budgets and resume."""
import copy
from datetime import UTC, datetime, timedelta

import pytest

from romulus.agent.models import PivotCoverage
from romulus.evidence.typed import Outcome, RawRef, TypedEvent, fv
from romulus.hunt import run as hunt_run
from romulus.hunt.expansion import ExpansionEngine
from romulus.hunt.links import LinkResult
from romulus.report.manifest import build_manifest
from romulus.sources.models import Window
from romulus.store.db import make_engine, migrate
from romulus.store.repo import Repo

T0 = datetime(2024, 11, 18, 14, 0, tzinfo=UTC)
WINDOW = Window(start=T0 - timedelta(hours=1), end=T0 + timedelta(hours=3))


def event(event_id: str, *, host="web1", ts=T0, argv=None):
    fields = {"process.executable": fv((argv or ["/bin/sh"])[0], f"{event_id}:exe")}
    if argv is not None:
        fields["process.argv"] = fv(argv, f"{event_id}:argv")
    return TypedEvent(
        id=event_id, family="process_exec", ts=ts, host=host, outcome=Outcome.success,
        fields=fields, raw=[RawRef(target="host-x", native_id=event_id, digest="d")],
        normalizer="test@1",
    )


def repo_with_anchor(*, host="web1", candidate_id="F-anchor"):
    engine = make_engine(":memory:")
    migrate(engine)
    repo = Repo(engine)
    repo.create_hunt("h1", {
        "window": {"start": WINDOW.start.isoformat(), "end": WINDOW.end.isoformat()},
        "style": "broad", "hypothesis": "", "original_input": {}, "targets": [],
        "pack": {"version": "test", "playbooks": []}, "normalizer": "test", "policy": "test",
        "model": {}, "romulus_version": "test", "agent_mode": "off",
        "budgets": {"wall_clock_minutes": 120},
    }, "digest", "test")
    anchor = event("anchor-event", host=host)
    repo.save_evidence("h1", [anchor], {}, None)
    repo.save_candidate({
        "id": candidate_id, "hunt_id": "h1", "rule_id": "host.web_shell",
        "rule_version": "1", "claim": "web service spawned a shell",
        "claim_type": "observed_action", "event_ids": [anchor.id],
        "predicate_fields": [], "entities": [["host", host, "host"]], "ts": anchor.ts,
        "severity": "critical", "confidence": "high", "lane": "urgent", "priority": 100.0,
        "priority_reasons": [], "gate_results": {}, "benign_alternatives": [], "next_checks": [],
        "source_case_id": None, "source_anchor_id": None, "source_link_id": None,
    })
    return repo


class ScriptedFetcher:
    def __init__(self, repo, *, linked=None, strength="observed"):
        self.repo = repo
        self.linked = linked
        self.strength = strength
        self.calls = []

    def fetch(self, anchor, link_type, window, *, query_cap=None):
        assert anchor.ts.tzinfo is not None and anchor.ts.utcoffset() == timedelta(0)
        self.calls.append((anchor.finding_id, link_type, window.label))
        event_ids = [self.linked.id] if self.linked is not None and link_type == "host_after_anchor" else []
        return LinkResult(
            id=f"L-{anchor.finding_id}-{link_type}-{window.label}", anchor_id=anchor.finding_id,
            link_type=link_type, window=window, strength=self.strength,
            key={"host": anchor.host, "type": link_type}, status="complete",
            event_ids=event_ids, evidence_ids=sorted(anchor.event_ids + event_ids),
            task_ids=[f"T-{len(self.calls)}"], coverage=[PivotCoverage(
                target="host-x", dataset="linux.audit", start=window.start, end=window.end,
                status="complete", returned=len(event_ids), total=len(event_ids),
            )],
        )


class BudgetedFetcher(ScriptedFetcher):
    def __init__(self, repo):
        super().__init__(repo)
        self.executor = type("Counter", (), {"source_queries": 0})()
        self.query_caps = []

    def fetch(self, anchor, link_type, window, *, query_cap=None):
        self.query_caps.append(query_cap)
        self.executor.source_queries += query_cap or 0
        return super().fetch(anchor, link_type, window, query_cap=query_cap)


def add_anchor(repo, candidate_id, host, *, ts=T0):
    anchor = event(f"{candidate_id}-event", host=host, ts=ts)
    repo.save_evidence("h1", [anchor], {}, None)
    repo.save_candidate({
        "id": candidate_id, "hunt_id": "h1", "rule_id": "host.web_shell",
        "rule_version": "1", "claim": "web service spawned a shell",
        "claim_type": "observed_action", "event_ids": [anchor.id],
        "predicate_fields": [], "entities": [["host", host, "host"]], "ts": anchor.ts,
        "severity": "critical", "confidence": "high", "lane": "urgent", "priority": 100.0,
        "priority_reasons": [], "gate_results": {}, "benign_alternatives": [], "next_checks": [],
        "source_case_id": None, "source_anchor_id": None, "source_link_id": None,
    })


def stable_state(repo):
    return {
        "anchors": [{k: row[k] for k in ("id", "candidate_id", "depth", "parent_anchor_id", "status", "reasons")}
                    for row in repo.expansion_anchors("h1")],
        "links": [{k: row[k] for k in ("id", "anchor_id", "link_type", "window_label", "strength",
                                                     "status", "event_ids", "evaluated")}
                  for row in repo.expansion_links("h1")],
    }


def without_timing(manifest):
    cleaned = copy.deepcopy(manifest)
    cleaned["hunt"]["started_at"] = None
    cleaned["hunt"]["ended_at"] = None
    for finding in cleaned["findings"]:
        for disposition in finding["disposition_history"]:
            disposition["at"] = None
    return cleaned


def test_two_runs_have_identical_deterministic_expansion_state():
    states = []
    manifests = []
    for _ in range(2):
        repo = repo_with_anchor()
        result = ExpansionEngine(repo, "h1", WINDOW, ScriptedFetcher(repo)).run()
        assert result["stop_reason"] == "fixpoint"
        states.append(stable_state(repo))
        manifests.append(build_manifest(repo, "h1", "test"))

    assert states[0] == states[1]
    assert without_timing(manifests[0]) == without_timing(manifests[1])


def test_budget_exhaustion_lists_every_unworked_anchor():
    repo = repo_with_anchor()

    result = ExpansionEngine(
        repo, "h1", WINDOW, ScriptedFetcher(repo), max_source_queries=0,
    ).run()

    assert result["stop_reason"] == "budget"
    assert result["unexpanded"] == ["F-anchor"]
    anchor = repo.expansion_anchors("h1")[0]
    assert anchor["status"] == "unexpanded"
    assert "source query budget exhausted" in anchor["reasons"]


def test_tier_scheduler_gives_each_host_a_fetch_before_dense_anchor_can_starve_it():
    repo = repo_with_anchor(host="web1", candidate_id="F-one")
    add_anchor(repo, "F-two", "web2", ts=T0 + timedelta(seconds=1))
    fetcher = BudgetedFetcher(repo)

    ExpansionEngine(repo, "h1", WINDOW, fetcher, max_source_queries=8).run()

    assert [call[0] for call in fetcher.calls[:2]] == ["F-one", "F-two"]
    assert fetcher.query_caps[:2] == [2, 2]


def test_resume_continues_after_crash_without_repeating_evaluated_links():
    repo = repo_with_anchor()
    first_fetcher = ScriptedFetcher(repo)
    calls = 0

    def crash_after_first(_link):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("simulated crash")

    with pytest.raises(RuntimeError, match="simulated crash"):
        ExpansionEngine(repo, "h1", WINDOW, first_fetcher, after_link=crash_after_first).run()
    first_key = first_fetcher.calls[0]
    assert repo.expansion_links("h1")[0]["evaluated"] == 1

    resumed_fetcher = ScriptedFetcher(repo)
    result = ExpansionEngine(repo, "h1", WINDOW, resumed_fetcher).run()

    assert result["stop_reason"] == "fixpoint"
    assert first_key not in resumed_fetcher.calls
    assert repo.expansion_anchors("h1")[0]["status"] == "expanded_complete"


def test_inferred_link_context_candidate_is_lead_and_keeps_provenance():
    repo = repo_with_anchor()
    discovery = event("discovery", ts=T0 + timedelta(minutes=1), argv=["whoami"])
    repo.save_evidence("h1", [discovery], {}, None)
    fetcher = ScriptedFetcher(repo, linked=discovery, strength="inferred")

    ExpansionEngine(repo, "h1", WINDOW, fetcher).run()

    candidates = [row for row in repo.candidates("h1") if row["id"] != "F-anchor"]
    assert len(candidates) == 1
    assert candidates[0]["lane"] == "lead"
    assert candidates[0]["source_anchor_id"] == "F-anchor"
    assert candidates[0]["source_link_id"].startswith("L-F-anchor-host_after_anchor")


def test_resume_runs_expansion_before_optional_agent_without_rerunning_sweep(tmp_path, monkeypatch):
    settings = __import__("romulus.config", fromlist=["Settings"]).Settings(home=tmp_path, agent_mode="model")
    repo = hunt_run.open_repo(settings)
    repo.create_hunt("h1", {
        "window": {"start": WINDOW.start.isoformat(), "end": WINDOW.end.isoformat()},
        "targets": [], "source_profiles": {}, "agent_mode": "model", "expansion": {"enabled": True},
        "budgets": {"wall_clock_minutes": 120},
    }, "digest", "test")
    repo.claim_hunt("h1", 1, now=T0 - timedelta(hours=2))
    repo.audit("system", "hunt.sweep_summary", "h1", {"finished": True, "complete": True, "stats": {}})
    repo.set_hunt_state("h1", "partial", stop_reason="interrupted expansion")
    order = []
    monkeypatch.setattr(hunt_run, "_contracts", lambda *_args: {})
    monkeypatch.setattr(hunt_run, "_run_expansion", lambda *_args, **_kwargs: order.append("expansion") or {
        "status": "completed", "stop_reason": "fixpoint", "unexpanded": [],
    })
    monkeypatch.setattr(hunt_run, "_run_investigator", lambda *_args, **_kwargs: order.append("agent") or {
        "status": "completed", "partial": False, "stop_reason": "done", "unworked_count": 0,
    })

    hunt_run.resume_hunt(settings, "h1")

    assert order == ["expansion", "agent"]
