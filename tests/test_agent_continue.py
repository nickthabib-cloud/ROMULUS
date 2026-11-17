"""A continued agent run (after a stop, an interruption or added budget) carries on where the last one ended: it does
not orient again, reserves for the assessment in proportion to what it has left, assesses once at its end (or not at
all when it could investigate nothing), and is audited with its earlier end reasons kept in the run's history."""
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from threading import Lock

from romulus.agent import hunt_budget
from romulus.agent.investigate import (
    NO_NEW_INVESTIGATION,
    ORIENT_SHARE_LIMIT,
    ORIENT_TOKEN_SHARE,
    STOPPED_REASON,
    _BudgetGate,
    continuation_plan,
    orient_completed,
    run_agent_phase,
)
from romulus.agent.provider import AgentBudget, BudgetLimits
from romulus.agent.provider.base import ChatProvider, ToolCall, Usage
from romulus.agent.toolbox import Toolbox
from romulus.config import Settings
from romulus.hunt import controls
from romulus.hunt import run as hunt_run
from romulus.store.db import make_engine, migrate, utcnow
from romulus.store.repo import Repo
from romulus.web import agent_views
from tests.agent_scripted import ScriptedProvider, response

BODY = {"overall": [{"text": "The persisted finding is available for review.", "cites": [], "kind": "hypothesis"}],
        "key_steps": [], "narrative": [], "confidence": {"overall": "low", "reasons": []},
        "alternatives": [], "gaps": [], "next_checks": []}


def _finish(summary="The review of this lead is complete."):
    return [ToolCall("f", "finish_session", {"summary": summary}, "{}")]


def _hunt(tmp_path, s, **overrides):
    engine = make_engine(tmp_path / "db.sqlite")
    migrate(engine)
    repo = Repo(engine)
    choice = hunt_budget.choose(s, "standard", overrides, role="lead", chosen_by="web:alice")
    window = {"start": "2024-11-18T10:00:00+00:00", "end": "2024-11-18T11:00:00+00:00"}
    repo.create_hunt("h1", {"window": window, "targets": [], "ai_agent": {
        "requested": True, "budgets": hunt_budget.pinned_block(choice)}}, "d", "cli:web:alice")
    repo.set_hunt_state("h1", "running")
    repo.set_hunt_state("h1", "completed_within_scope", detection_result="leads_only", stop_reason="scope")
    for index in range(2):
        repo.save_candidate({
            "id": f"c{index}", "hunt_id": "h1", "rule_id": "host.test", "rule_version": "1",
            "claim": f"deterministic finding {index}", "claim_type": "observed_action", "event_ids": [],
            "context_event_ids": [], "predicate_fields": [], "entities": [["host", f"ws-{index}", "host"]],
            "ts": datetime.now(UTC), "severity": "high", "confidence": "high", "lane": "high", "priority": 2.0,
            "priority_reasons": [], "gate_results": {}, "benign_alternatives": [], "next_checks": [],
            "group_key": f"c{index}", "source_case_id": None, "source_anchor_id": None, "source_link_id": None})
    return repo


def _run(s, repo, provider, **kwargs):
    return run_agent_phase(s, repo, "h1", provider=provider, toolbox_factory=lambda _s: Toolbox(repo, "h1"),
                           clock=lambda: 0.0, **kwargs)


def _opens():
    return [ToolCall("o1", "open_hypothesis", {"statement": "Review the first incident hypothesis"}, "{}"),
            ToolCall("o2", "open_hypothesis", {"statement": "Review an alternate incident hypothesis"}, "{}"),
            ToolCall("of", "finish_session", {"summary": "The initial review is complete."}, "{}")]


def test_a_continuation_after_an_extension_skips_orient_and_works_the_open_hypotheses(tmp_path):
    s = Settings(home=tmp_path, agent_triage="off")
    repo = _hunt(tmp_path, s, max_calls=2)
    first = ScriptedProvider([response(tool_calls=_opens()), response(parsed=BODY)])
    result = _run(s, repo, first)
    assert result.state == "partial" and "budget:calls" in result.reason
    open_before = [row for row in repo.agent_hypotheses("h1") if row["status"] == "open"]
    assert open_before and all(row["sessions_run"] == 0 for row in open_before)
    assert continuation_plan(s, repo, "h1") == {"starting_phase": "investigate"}

    controls.extend_budget(s, repo, "h1", actor="web:alice", role="analyst", amounts={"max_calls": 10})
    later = ScriptedProvider([response(tool_calls=_finish()) for _ in open_before] + [response(parsed=BODY)])
    result = _run(s, repo, later)
    purposes = [row["purpose"] for row in repo.agent_sessions("h1")]
    assert purposes.count("orient") == 1                              # no second orient
    assert purposes.count("investigate") == len(open_before)          # every open hypothesis got its session
    assert purposes.count("assess") == 2                              # once per run
    assert all(row["sessions_run"] == 1 for row in repo.agent_hypotheses("h1") if row["status"] == "open")
    assert len(later.requests) == len(open_before) + 1


def test_an_orient_interrupted_before_storing_hypotheses_orients_again(tmp_path):
    s = Settings(home=tmp_path, agent_triage="off")
    repo = _hunt(tmp_path, s)
    repo.save_agent_session({"id": "as-old", "hunt_id": "h1", "hypothesis_id": None, "purpose": "orient",
                             "state": "interrupted", "tool_calls": 0, "summary": "", "started_at": utcnow(),
                             "ended_at": utcnow()})
    assert not orient_completed(repo, "h1")
    assert continuation_plan(s, repo, "h1") == {"starting_phase": "orient"}
    provider = ScriptedProvider([response(tool_calls=_opens())] + [response(tool_calls=_finish())] * 4
                                + [response(parsed=BODY)])
    _run(s, repo, provider)
    orients = [row for row in repo.agent_sessions("h1") if row["purpose"] == "orient"]
    assert [row["state"] for row in orients] == ["interrupted", "finished"]
    # once it stored its hypotheses, orient is done, though its first session was interrupted
    assert orient_completed(repo, "h1") and continuation_plan(s, repo, "h1")["starting_phase"] != "orient"


def test_the_assessment_hold_is_a_share_of_what_the_run_has_left(tmp_path):
    limits = BudgetLimits(100, 1_000_000, 36_000, 0.0, 0.0, 0.0)
    fresh = _BudgetGate(AgentBudget(limits, clock=lambda: 0.0), Settings(home=tmp_path))
    assert fresh._reserve_for_assess(4096, 1024)[:2] == (15, 150_000)
    continued = _BudgetGate(AgentBudget(limits, calls=90, budget_tokens=900_000, clock=lambda: 0.0),
                            Settings(home=tmp_path))
    continued.base = (90, 900_000, 0.0, 0.0)             # a continuation given 10 more calls and 100,000 tokens
    calls, tokens, _cost, _wall = continued._reserve_for_assess(4096, 1024)
    assert calls == 2 and tokens == 15_000               # never less than the assessment's own worst case
    assert tokens >= limits.worst_tokens(4096, 1024)


def test_an_extension_too_small_to_investigate_is_said_plainly_and_not_spent_on_a_reassessment(tmp_path):
    s = Settings(home=tmp_path, agent_triage="off")
    repo = _hunt(tmp_path, s, max_calls=2)
    _run(s, repo, ScriptedProvider([response(tool_calls=_opens()), response(parsed=BODY)]))
    revision = repo.agent_assessments("h1")[-1]["revision"]
    assert repo.agent_assessments("h1")[-1]["source"] == "agent"
    controls.extend_budget(s, repo, "h1", actor="web:alice", role="analyst", amounts={"max_calls": 1})
    provider = ScriptedProvider([])                      # nothing may be asked
    result = _run(s, repo, provider)
    assert provider.requests == []
    assert NO_NEW_INVESTIGATION in result.reason and "budget:calls" in result.reason
    assert repo.agent_assessments("h1")[-1]["revision"] == revision     # the stored assessment stands
    assert all(row["sessions_run"] == 0 for row in repo.agent_hypotheses("h1"))   # no session used up


def test_an_agent_only_resume_is_audited_with_its_reason_and_starting_phase(tmp_path, monkeypatch):
    s = Settings(home=tmp_path, agent_triage="off")
    repo = _hunt(tmp_path, s, max_calls=2)
    _run(s, repo, ScriptedProvider([response(tool_calls=_opens()), response(parsed=BODY)]))
    monkeypatch.setattr(hunt_run, "open_repo", lambda _s: repo)
    for name in ("ensure_site_unchanged", "install_for_hunt"):
        monkeypatch.setattr(hunt_run, name, lambda *_a, **_k: None)
    monkeypatch.setattr(hunt_run, "ElasticClient", lambda *_a, **_k: object())
    monkeypatch.setattr(hunt_run, "_contracts", lambda *_a, **_k: {})
    monkeypatch.setattr(hunt_run, "_ai_agent_phase", lambda *_a, **_k: {"status": "partial"})
    monkeypatch.setattr(hunt_run, "recorded_agent_model", lambda *_a: "")
    controls.extend_budget(s, repo, "h1", actor="web:alice", role="analyst", amounts={"max_calls": 5})
    hunt_run.resume_hunt(s, "h1", continue_agent=True, actor="cli:web:alice")
    audit = repo.latest_audit("h1", "hunt.agent_resume")
    assert audit["actor"] == "cli:web:alice"
    assert audit["detail"]["reason"] == "extension" and audit["detail"]["starting_phase"] == "investigate"

    # an agent the analyst stopped: the resume says the stop was cleared
    repo.release_agent_lease("h1")                       # the stand-in phase above holds it
    run = repo.agent_run("h1")
    repo.save_agent_run({**{key: run[key] for key in ("hunt_id", "prompt_digests", "provider", "started_at")},
                         "state": "partial", "reason": STOPPED_REASON, "ended_at": utcnow() + timedelta(hours=1)})
    hunt_run.resume_hunt(s, "h1", continue_agent=True, actor="cli:web:bob")
    assert repo.latest_audit("h1", "hunt.agent_resume")["detail"]["reason"] == "stop_cleared"


def test_a_stop_reason_survives_the_next_run_in_the_run_history(tmp_path):
    s = Settings(home=tmp_path, agent_triage="off")
    repo = _hunt(tmp_path, s)
    stop = {"detail": None}
    provider = ScriptedProvider([response(tool_calls=_opens())])

    def chat(request, original=provider.chat):
        result = original(request)
        stop["detail"] = "requested by web:alice"
        return result
    provider.chat = chat
    first = _run(s, repo, provider, stop=lambda: stop["detail"])
    assert STOPPED_REASON in first.reason
    repo.audit("cli:web:alice", "hunt.agent_resume", "h1", {"reason": "stop_cleared", "starting_phase": "investigate"})
    later = ScriptedProvider([response(tool_calls=_finish())] * 2 + [response(parsed=BODY)])
    second = _run(s, repo, later)
    assert STOPPED_REASON not in (second.reason or "")
    history = agent_views.run_history(repo, "h1")["rows"]
    assert [row["kind"] for row in history] == ["run ended", "continued", "run ended"]
    assert STOPPED_REASON in history[0]["why"] and history[1]["who"] == "cli:web:alice"
    assert repo.agent_run("h1")["reason"] != history[0]["why"]


class _HeavyOrient(ChatProvider):
    """Orient calls that each charge a large prompt (the dossier) and never finish; investigate and assess are cheap."""
    name, model, sends_sampling = "scripted", "scripted-model", False

    def __init__(self, prompt_tokens):
        self.prompt_tokens, self.requests, self.lock, self.opened = prompt_tokens, [], Lock(), 0

    def describe(self):
        return {"provider": self.name, "model_requested": self.model, "endpoint_host": "scripted", "egress": "local"}

    def context_tokens(self):
        return 1_000_000

    def output_limit(self, _request):
        return 1024

    def chat(self, request):
        with self.lock:
            self.requests.append(request)
            system = str(request.messages[0]["content"])
            if request.response_schema is not None:
                return response(parsed=BODY)
            if "Dossier index page" in str(request.messages[1]["content"]):
                self.opened += 1
                result = response(tool_calls=[ToolCall(f"o{self.opened}", "open_hypothesis", {
                    "statement": f"Review incident hypothesis number {self.opened}"}, "{}")])
                return replace(result, usage=Usage(prompt_tokens=self.prompt_tokens, completion_tokens=500))
            assert system
            return response(tool_calls=_finish())


def test_the_quick_profile_leaves_investigation_a_real_share(tmp_path):
    s = Settings(home=tmp_path, agent_triage="off")
    quick = hunt_budget.profile_limits(s, "quick")
    repo = _hunt(tmp_path, s, **{key: quick[key] for key in hunt_budget.LIMITS})
    # each orient call charges a tenth of the quick token budget: unbounded, orient would spend it all
    provider = _HeavyOrient(quick["max_tokens"] // 10)
    result = _run(s, repo, provider)
    sessions = repo.agent_sessions("h1")
    orient = [row for row in sessions if row["purpose"] == "orient"]
    investigate = [row for row in sessions if row["purpose"] == "investigate"]
    assert len(orient) == 1 and ORIENT_SHARE_LIMIT in result.limits_hit
    orient_spent = repo.agent_usage("h1", purposes=("orient",))["budget_tokens"]
    assert orient_spent <= quick["max_tokens"] * ORIENT_TOKEN_SHARE + quick["max_tokens"] // 10
    assert investigate and all(row["tool_calls"] >= 1 for row in investigate)        # investigation ran
    assert any(row["purpose"] == "assess" for row in sessions)
