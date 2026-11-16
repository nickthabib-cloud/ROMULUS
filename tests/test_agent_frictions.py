"""Agent controller frictions: the budget reservation, over-long session summaries, link kinds the model is offered,
incident reads by alias, per-session tool-call allowances, and fallback-model attribution."""
from __future__ import annotations

import threading
import time
from datetime import UTC, datetime

import pytest

from romulus.agent.admission import SUMMARY_MAX_CHARS, SUMMARY_TRUNCATED, truncated_summary
from romulus.agent.assessment import run_assessment
from romulus.agent.investigate import (
    TOOL_CALL_EXTRA_FACTOR,
    _BudgetGate,
    _prompt_set,
    _run_session,
    _tool_call_allowance,
)
from romulus.agent.models import PivotResult
from romulus.agent.provider import AgentBudget, BudgetExhausted, BudgetLimits, record_call
from romulus.agent.provider.base import ChatRequest, ToolCall
from romulus.agent.toolbox import FOLLOW_LINK_KINDS, Toolbox
from romulus.config import Settings
from romulus.hunt.links import LinkFetcher
from romulus.report.manifest import _ai_agent, _ai_assessment
from romulus.store.db import make_engine, migrate
from romulus.store.repo import Repo
from tests.agent_scripted import ScriptedProvider, response
from tests.test_agent_toolbox import _repo as toolbox_repo
from tests.test_expansion_links import T0, T1, FakePivot, anchor, cases, event, window

BODY = {"overall": [], "key_steps": [], "narrative": [], "confidence": {"overall": "low", "reasons": []},
        "alternatives": [], "gaps": [], "next_checks": []}


def _hunt(tmp_path, name="frictions"):
    engine = make_engine(tmp_path / f"{name}.sqlite")
    migrate(engine)
    repo = Repo(engine)
    repo.create_hunt("h1", {"window": {}, "targets": [], "ai_agent": {"requested": True}}, "d", "test")
    repo.set_hunt_state("h1", "running")
    repo.set_hunt_state("h1", "completed_within_scope", detection_result="leads_only", stop_reason="scope")
    return engine, repo


# ---- the budget reservation -------------------------------------------------------------------------------------

def _weighted_limits(*, fallback: bool) -> BudgetLimits:
    # a 2M weighted token budget, cache writes counted at 1.25, the refusal fallback on
    return BudgetLimits(200, 2_000_000, 3600, 0.0, 0.0, 0.0, model="m", refusal_fallback=fallback,
                        cache_read_token_weight=0.1, cache_write_token_weight=1.25)


def test_the_fallback_attempt_is_reserved_only_when_the_fallback_is_on(tmp_path):
    on = BudgetLimits.from_settings(Settings(home=tmp_path, agent_provider="anthropic"))
    off = BudgetLimits.from_settings(Settings(home=tmp_path, agent_provider="anthropic",
                                              agent_refusal_fallback="off"))
    other = BudgetLimits.from_settings(Settings(home=tmp_path, agent_provider="openai_compatible"))
    assert (on.attempts_reserved, off.attempts_reserved, other.attempts_reserved) == (2, 1, 1)
    assert on.worst_tokens(1000, 100) == 2 * off.worst_tokens(1000, 100) == 2 * (1250 + 100)
    assert other.worst_tokens(1000, 100) == 1100


def test_a_call_waits_for_a_sibling_reservation_instead_of_stopping_at_half_the_budget(tmp_path):
    limits = _weighted_limits(fallback=True)
    budget = AgentBudget(limits, calls=20, tokens=3_000_000, budget_tokens=1_040_000, clock=lambda: 0.0)
    gate = _BudgetGate(budget, Settings(home=tmp_path))
    prompt, output = 90_000, 64_096
    worst = limits.worst_tokens(prompt, output)
    hold = 300_000                                   # 15% of the budget kept for the assessment
    # 52% spent: this call's worst case beside a sibling's in flight and the hold is over the limit, alone it fits
    assert budget.budget_tokens + 2 * worst + hold > limits.max_tokens
    assert budget.budget_tokens + worst + hold <= limits.max_tokens
    sibling = gate.reserve(prompt, output, "investigate")
    got: list = []
    errors: list = []

    def second():
        try:
            got.append(gate.reserve(prompt, output, "investigate"))
        except BudgetExhausted as exc:      # a stop caused only by the sibling's transient reservation
            errors.append(exc)
    thread = threading.Thread(target=second)
    thread.start()
    deadline = time.monotonic() + 10
    while not gate.queue and time.monotonic() < deadline:
        time.sleep(0.01)
    time.sleep(0.05)
    assert gate.queue and not got and not errors          # waiting, not stopped
    gate.settle(sibling, result=response())               # the sibling settles far below its worst case
    thread.join(10)
    assert not errors and len(got) == 1
    assert gate.tokens == worst and gate.calls == 1
    gate.settle(got[0], result=response())
    assert gate.tokens == 0 and not gate.queue


def test_a_call_that_cannot_fit_even_alone_stops_and_says_what_was_spent_reserved_and_held(tmp_path):
    limits = _weighted_limits(fallback=True)
    budget = AgentBudget(limits, calls=20, tokens=3_000_000, budget_tokens=1_400_000, clock=lambda: 0.0)
    gate = _BudgetGate(budget, Settings(home=tmp_path))
    worst = limits.worst_tokens(90_000, 64_096)
    with pytest.raises(BudgetExhausted) as stopped:
        gate.reserve(90_000, 64_096, "investigate")
    detail = str(stopped.value)
    assert stopped.value.budget == "tokens"
    assert "1400000 of 2000000 budget tokens" in detail
    assert f"{worst} reserved for this call's worst case" in detail
    assert "300000 held for the assessment" in detail
    assert gate.tokens == 0 and gate.calls == 0 and not gate.queue


def test_a_budget_stop_records_its_numbers_in_the_session_summary(tmp_path):
    engine, repo = _hunt(tmp_path)
    settings = Settings(home=tmp_path, agent_max_tokens=1000)
    budget = AgentBudget.from_usage(BudgetLimits.from_settings(settings), repo.agent_usage("h1"), clock=lambda: 0.0)
    outcome = _run_session(settings, repo, "h1", ScriptedProvider([]), _BudgetGate(budget, settings),
                           lambda session: Toolbox(repo, "h1", session_id=session), _prompt_set(), purpose="orient")
    assert outcome["state"] == "budget" and outcome["reason"] == "budget:tokens"
    stored = repo.agent_sessions("h1")[-1]["summary"]
    assert stored.startswith("Budget stop: tokens budget reached:") and "of 1000 budget tokens" in stored
    engine.dispose()


# ---- finish_session summaries over the limit ---------------------------------------------------------------------

def test_a_truncated_summary_ends_at_a_sentence_and_says_it_was_cut():
    text = ("The session read the anchor's records. " * 80).strip()
    cut = truncated_summary(text)
    assert len(cut) <= SUMMARY_MAX_CHARS and cut.endswith(SUMMARY_TRUNCATED)
    assert cut[:-len(SUMMARY_TRUNCATED)].rstrip().endswith("records.")
    assert truncated_summary("x" * 5000).endswith(SUMMARY_TRUNCATED)       # no boundary at all: cut mid-word
    assert len(truncated_summary("x" * 5000)) <= SUMMARY_MAX_CHARS
    short = "A summary inside the limit."
    assert truncated_summary(short) == short


def test_an_over_long_summary_is_refused_once_with_its_length_then_kept_cut_to_fit(tmp_path):
    engine, repo = _hunt(tmp_path)
    settings = Settings(home=tmp_path)
    secret = "telemetry-value-7f3a"
    long_summary = (f"Examined {secret} closely. " + "The lead stays open for the next session. " * 60).strip()
    too_long = ToolCall("f1", "finish_session", {"summary": long_summary}, "{}")
    provider = ScriptedProvider([response(tool_calls=[too_long]), response(tool_calls=[too_long])])
    budget = AgentBudget.from_usage(BudgetLimits.from_settings(settings), repo.agent_usage("h1"), clock=lambda: 0.0)

    outcome = _run_session(settings, repo, "h1", provider, _BudgetGate(budget, settings),
                           lambda session: Toolbox(repo, "h1", session_id=session), _prompt_set(), purpose="orient")

    refusal = provider.requests[1].messages[-1]["content"]
    assert f"summary has {len(long_summary)} characters" in refusal and f"at most {SUMMARY_MAX_CHARS}" in refusal
    assert secret not in refusal                         # numbers only, never the summary's text
    assert outcome["state"] == "finished"
    assert outcome["summary"].endswith(SUMMARY_TRUNCATED) and len(outcome["summary"]) <= SUMMARY_MAX_CHARS
    rows = repo.agent_tool_calls("h1")
    assert [row["status"] for row in rows] == ["refused", "complete"]
    assert repo.agent_refusal_counts("h1")["by_tool"]["finish_session"] == {
        "summary: string_too_long": 1, "summary: truncated_by_product": 1}
    engine.dispose()


def test_after_the_context_wrap_up_an_over_long_summary_is_kept_at_once(tmp_path):
    engine, repo = _hunt(tmp_path, "context-wrap")
    settings = Settings(home=tmp_path)
    too_long = ToolCall("f1", "finish_session", {"summary": "The lead stays open. " * 200}, "{}")
    # a context window this small puts the first request past 85%: the controller asks for the wrap-up at once
    provider = ScriptedProvider([response(tool_calls=[too_long])], context=2000, output=64)
    budget = AgentBudget.from_usage(BudgetLimits.from_settings(settings), repo.agent_usage("h1"), clock=lambda: 0.0)

    outcome = _run_session(settings, repo, "h1", provider, _BudgetGate(budget, settings),
                           lambda session: Toolbox(repo, "h1", session_id=session), _prompt_set(),
                           purpose="investigate", hypothesis=_open_hypothesis(repo))

    assert "Context is nearly full" in provider.requests[0].messages[-1]["content"]
    assert outcome["state"] == "context_full" and outcome["summary"].endswith(SUMMARY_TRUNCATED)
    assert repo.agent_refusal_counts("h1")["by_tool"]["finish_session"] == {"summary: truncated_by_product": 1}
    engine.dispose()


def _open_hypothesis(repo):
    now = datetime.now(UTC)
    repo.save_agent_hypothesis({"id": "hyp-w", "hunt_id": "h1", "statement": "Review the wrap-up hypothesis here",
                                "techniques": [], "entity_ids": [], "status": "open", "confidence": "low",
                                "questions": ["q"], "created_session_id": None, "sessions_run": 0,
                                "created_at": now, "updated_at": now})
    return repo.agent_hypotheses("h1")[0]


# ---- follow_link offers only kinds the executor can follow ---------------------------------------------------------

class _Executor:
    def __init__(self, followable):
        self.followable = tuple(followable)
        self.followed: list[str] = []

    def run(self, *args, **kwargs):
        raise AssertionError("no pivot is run here")

    def follow_link(self, session_id, anchor_id, link_type, window_label):
        self.followed.append(link_type)
        return PivotResult(status="complete")

    def followable_links(self, anchor_id):
        return self.followable


def test_follow_link_states_its_kinds_and_get_finding_lists_the_followable_ones():
    toolbox = Toolbox(toolbox_repo(2), "h1", executor=_Executor(["login_session", "process_lineage"]),
                      session_id="s1")
    tool = next(tool for tool in toolbox.provider_tools() if tool.name == "follow_link")
    assert all(kind in tool.description for kind in FOLLOW_LINK_KINDS)
    assert set(tool.parameters["properties"]["link_type"]["enum"]) == set(FOLLOW_LINK_KINDS)
    finding = toolbox.execute("get_finding", {"finding": "F1"})["data"]["finding"]
    # in the tool's own order
    assert finding["follow_link_kinds"] == ["process_lineage", "login_session"]
    # without an executor that can say, nothing is claimed
    assert "follow_link_kinds" not in Toolbox(toolbox_repo(2), "h1").execute(
        "get_finding", {"finding": "F1"})["data"]["finding"]


def test_an_unfollowable_kind_is_a_typed_refusal_before_any_source_work():
    executor = _Executor(["process_lineage"])
    toolbox = Toolbox(toolbox_repo(2), "h1", executor=executor, session_id="s1")
    toolbox.execute("get_finding", {"finding": "F1"})

    refused = toolbox.execute("follow_link", {"anchor": "F1", "link_type": "network_flow"})

    assert refused["status"] == "refused" and executor.followed == []
    error = refused["data"]["error"]
    assert error["code"] == "link_not_followable" and error["reasons"] == ["link_type: not_followable"]
    assert error["follow_link_kinds"] == ["process_lineage"]
    assert toolbox.execute("follow_link", {"anchor": "F1", "link_type": "process_lineage"})["status"] == "complete"
    assert executor.followed == ["process_lineage"]


def test_the_planner_says_followable_exactly_when_fetch_would_not_answer_unsupported():
    anchors = [anchor(kind, pair[0]) for kind, pair in cases().items()]
    anchors.append(anchor("bare", event("bare", "process_exec", host=None)))
    for item in anchors:
        for kind in FOLLOW_LINK_KINDS:
            planning = FakePivot([])
            followable = LinkFetcher(planning, T0, T1).followable(item, kind, window())
            assert planning.calls == []                       # planning issues no source query
            fetched = LinkFetcher(FakePivot([]), T0, T1).fetch(item, kind, window())
            assert followable == (fetched.status != "unsupported"), (item.finding_id, kind)


def test_the_hunt_executor_asks_the_link_planner_and_refuses_without_source_work():
    from romulus.hunt.agent_tools import HuntToolExecutor
    repo = toolbox_repo(2)                        # process records with an account and a host, but no process ID
    pivot = FakePivot([])
    pivot.source_queries = 0
    executor = HuntToolExecutor(repo, "h1", pivot, LinkFetcher(pivot, T0, T0 + (T1 - T0) * 6), T0,
                                T0 + (T1 - T0) * 6)
    toolbox = Toolbox(repo, "h1", executor=executor, session_id="s1")
    kinds = toolbox.execute("get_finding", {"finding": "F1"})["data"]["finding"]["follow_link_kinds"]
    assert "process_lineage" not in kinds and "account" in kinds
    assert kinds == list(executor.followable_links("finding-00"))

    refused = toolbox.execute("follow_link", {"anchor": "F1", "link_type": "process_lineage"})

    assert refused["data"]["error"]["reasons"] == ["link_type: not_followable"]
    assert pivot.calls == [] and pivot.source_queries == 0
    assert not [row for row in repo.expansion_links("h1") if row["link_type"].startswith("agent_follow_")]


def test_the_dossier_marks_tiers_and_links_follow_link_cannot_follow():
    from romulus.agent.aliases import AliasBook
    from romulus.agent.dossier import _expansion
    repo = toolbox_repo(2)
    repo.save_expansion_anchor({
        "id": "finding-01", "hunt_id": "h1", "candidate_id": "finding-01", "depth": 0, "parent_anchor_id": None,
        "host": "web01", "lane": "high", "severity": "high", "ts": T0, "status": "pending", "reasons": [],
    })
    repo.save_expansion_link({
        "id": "link-2", "hunt_id": "h1", "anchor_id": "finding-01", "link_type": "network_flow",
        "window_label": "anchor ±5 min", "window_start": T0, "window_end": T1, "strength": "observed",
        "key": {}, "status": "unsupported", "event_ids": [], "evidence_ids": [], "task_ids": [], "coverage": [],
        "reasons": ["required typed key is unusable"], "duration_ms": 1, "query_spend": 0, "evaluated": 1,
    })
    aliases = AliasBook(repo, "h1")
    plain = _expansion(repo, "h1", aliases)
    assert all("followable" not in item for item in plain["link_tiers_not_reached"])
    assert [item["followable"] for item in plain["partial_links"]] == [False]
    marked = _expansion(repo, "h1", aliases, lambda finding: ["process_lineage"])
    assert marked["link_tiers_not_reached"]                      # nothing is dropped
    assert {item["link_type"] for item in marked["link_tiers_not_reached"] if item["followable"]} == {
        "process_lineage"}


# ---- get_incident by alias -----------------------------------------------------------------------------------------

def test_get_incident_takes_an_issued_incident_alias_without_list_incidents_first():
    toolbox = Toolbox(toolbox_repo(2), "h1")
    schema = next(tool for tool in toolbox.provider_tools() if tool.name == "get_incident").parameters
    incident = schema["properties"]["incident"]
    assert incident["pattern"] == "^[FIENL][1-9][0-9]*$" and "incident alias (I...)" in incident["description"]
    alias = toolbox.aliases.alias_for("I", toolbox._incident_graph()[0]["incidents"][0]["id"])

    detail = toolbox.execute("get_incident", {"incident": alias, "page": 1})

    assert detail["status"] == "complete" and set(detail["data"]["incident"]["members"]) == {"F1", "F2"}
    refused = toolbox.execute("get_incident", {"incident": "3", "page": 1})       # a list position is not an alias
    assert refused["status"] == "refused" and refused["data"]["error"]["code"] == "invalid_arguments"


def test_get_incident_reads_the_aliases_the_dossier_and_the_controller_issue():
    from romulus.agent.admission import AgentAdmission
    from romulus.agent.dossier import build_dossier
    from romulus.agent.investigate import _controller_open_hypotheses
    repo = toolbox_repo(2)
    dossier_alias = build_dossier(repo, "h1", token_budget=24_000).page(1)["incidents"][0]["alias"]
    admission = AgentAdmission(Settings(home="."), repo, "h1", "orient-1", purpose="orient")
    _controller_open_hypotheses(Settings(home="."), repo, "h1", "orient-1", admission)
    statement = repo.agent_hypotheses("h1")[0]["statement"]
    assert statement.startswith(f"Investigate incident {dossier_alias}:")
    toolbox = Toolbox(repo, "h1")         # a fresh session: list_incidents was never called

    detail = toolbox.execute("get_incident", {"incident": dossier_alias, "page": 1})

    assert detail["status"] == "complete" and set(detail["data"]["incident"]["members"]) == {"F1", "F2"}


# ---- the per-session tool-call allowance ---------------------------------------------------------------------------

def test_the_tool_call_allowance_scales_with_reads_and_stays_bounded(tmp_path):
    settings = Settings(home=tmp_path, agent_max_tool_calls_per_session=25)
    assert _tool_call_allowance(settings, reads=0) == 25
    assert _tool_call_allowance(settings, reads=7) == 32
    assert _tool_call_allowance(settings, reads=10_000) == 25 * (1 + TOOL_CALL_EXTRA_FACTOR)
    assert _tool_call_allowance(settings, reads=-3) == 25


def test_an_investigate_session_gets_one_read_per_finding_its_hypothesis_cites(tmp_path):
    engine, repo = _hunt(tmp_path, "allowance")
    now = datetime.now(UTC)
    repo.save_agent_hypothesis({"id": "hyp-1", "hunt_id": "h1", "statement": "Review the cited findings here",
                                "techniques": [], "entity_ids": [], "status": "open", "confidence": "low",
                                "questions": ["q"], "created_session_id": None, "sessions_run": 0,
                                "created_at": now, "updated_at": now})
    from romulus.store import schema as tables
    from tests.test_agent_controller_r2 import _candidate
    with repo.engine.begin() as connection:
        connection.execute(tables.candidate.insert(), [{**_candidate(index), "id": f"c{index}"} for index in range(3)])
        connection.execute(tables.agent_hypothesis_cite.insert(), [
            {"hunt_id": "h1", "hypothesis_id": "hyp-1", "role": "support", "target_kind": "finding",
             "target_id": f"c{index}"} for index in range(3)])
    settings = Settings(home=tmp_path, agent_max_tool_calls_per_session=4)
    budget = AgentBudget.from_usage(BudgetLimits.from_settings(settings), repo.agent_usage("h1"), clock=lambda: 0.0)
    finish = ToolCall("f", "finish_session", {"summary": "The bounded session is complete."}, "{}")
    outcome = _run_session(settings, repo, "h1", ScriptedProvider([response(tool_calls=[finish])]),
                           _BudgetGate(budget, settings), lambda session: Toolbox(repo, "h1", session_id=session),
                           _prompt_set(), purpose="investigate", hypothesis=repo.agent_hypotheses("h1")[0])
    assert outcome["state"] == "finished", (outcome["reason"], outcome["summary"])
    assert outcome["tool_call_limit"] == 4 + 3
    engine.dispose()


# ---- fallback attribution ------------------------------------------------------------------------------------------

def _served_by_fallback(result, category="cyber"):
    result.model_reported = "claude-fallback-model"
    result.details = {"stop_reason": "end_turn", "model": "claude-fallback-model",
                      "fallback": {"served_by": "claude-fallback-model", "category": category,
                                   "switches": [{"from": "scripted-model", "to": "claude-fallback-model",
                                                 "category": category}]}}
    return result


def test_a_fallback_written_assessment_says_so_and_the_manifest_counts_fallbacks_and_refusals(tmp_path):
    engine, repo = _hunt(tmp_path, "fallback")
    provider = ScriptedProvider([_served_by_fallback(response(parsed=BODY))])
    limits = BudgetLimits(10, 100_000, 600, 0, 0, 0)
    budget = AgentBudget.from_usage(limits, repo.agent_usage("h1"), clock=lambda: 0.0)
    assert run_assessment(Settings(home=tmp_path), repo, "h1", provider, budget, clock=lambda: 0.0) is not None
    # an investigate call the fallback served outright (no category), and a triage call left declined
    outright = response()
    outright.model_reported = "claude-fallback-model"
    outright.details = {"fallback": {"served_by": "claude-fallback-model", "switches": [], "category": None}}
    record_call(repo, provider, hunt_id="h1", purpose="investigate", request=ChatRequest(messages=[]),
                result=outright, limits=limits)
    declined = response(status="refused", error="declined")
    declined.details = {"stop_reason": "refusal", "refusal": {"category": "cyber", "explanation": "text"}}
    record_call(repo, provider, hunt_id="h1", purpose="agent.triage", request=ChatRequest(messages=[]),
                result=declined, limits=limits)

    header = _ai_assessment(repo, "h1")["header"]
    assert ("Written by fallback model claude-fallback-model after the configured model scripted-model declined "
            "(category: cyber).") in header
    # the other agent calls a fallback model wrote are named in the header too
    assert "Agent calls behind it: 2 agent call(s) (assess 1, investigate 1) were written by fallback" in header
    fallbacks = _ai_agent(repo, "h1", {"ai_agent": {"provider": "scripted"}})["usage"]["fallbacks"]
    assert fallbacks["calls"] == 2 and fallbacks["by_purpose"] == {"assess": 1, "investigate": 1}
    assert fallbacks["by_category"] == {"cyber": 1, "unknown": 1}
    assert fallbacks["models"] == {"claude-fallback-model": 2}
    assert fallbacks["refusals"] == 1 and fallbacks["refusals_by_category"] == {"cyber": 1}
    assert "written by fallback model(s) claude-fallback-model" in fallbacks["note"]
    assert "text" not in str(fallbacks)                       # never the refusal's explanation
    engine.dispose()


def test_an_ordinary_assessment_header_and_usage_keep_their_shape(tmp_path):
    engine, repo = _hunt(tmp_path, "ordinary")
    provider = ScriptedProvider([response(parsed=BODY)])
    budget = AgentBudget.from_usage(BudgetLimits(10, 100_000, 600, 0, 0, 0), repo.agent_usage("h1"),
                                    clock=lambda: 0.0)
    run_assessment(Settings(home=tmp_path), repo, "h1", provider, budget, clock=lambda: 0.0)
    assert _ai_assessment(repo, "h1")["header"] == (
        "AI-generated hypothesis from the cited evidence. Not confirmed by an analyst. Model: "
        "scripted/scripted-model.")
    assert "fallbacks" not in _ai_agent(repo, "h1", {"ai_agent": {}})["usage"]
    assert "fallback" not in repo.agent_assessments("h1")[-1]["model"]
    engine.dispose()
