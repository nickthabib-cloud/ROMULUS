"""Regression coverage for bounded controller failures and scheduler inputs."""
import json
from datetime import UTC, datetime, timedelta
from threading import Barrier, Lock

import pytest

from romulus.agent.investigate import (
    _BudgetGate,
    _priority,
    _prompt_set,
    _run_session,
    _touched_entities,
    run_agent_phase,
)
from romulus.agent.provider import AgentBudget, BudgetLimits, ProviderUnavailable, record_failure
from romulus.agent.provider.base import ChatRequest, ToolCall, estimate_tokens, parse_tool_arguments
from romulus.agent.toolbox import Toolbox
from romulus.config import Settings
from romulus.store import schema as tables
from romulus.store.db import make_engine, migrate
from romulus.store.repo import Repo
from tests.agent_scripted import ScriptedProvider, response

ASSESSMENT = {"overall": [], "key_steps": [], "confidence": {"overall": "low", "reasons": []},
              "alternatives": [], "gaps": [], "next_checks": []}


@pytest.fixture
def agent_repo(tmp_path):
    engine = make_engine(tmp_path / "controller.sqlite")
    migrate(engine)
    repo = Repo(engine)
    repo.create_hunt("h1", {"window": {}, "targets": [], "ai_agent": {"requested": True}}, "d", "test")
    # Failure injection begins after the deterministic run has durably finished.
    with engine.begin() as connection:
        connection.execute(tables.hunt.update().where(tables.hunt.c.id == "h1").values(
            execution_state="completed_within_scope", detection_result="leads_only"))
    yield repo
    engine.dispose()


def _candidate(index):
    return {"id": f"c{index:06d}", "hunt_id": "h1", "rule_id": f"host.rule{index % 40}", "rule_version": "1",
            "claim": f"process execution of tool{index} on host ws{index % 50} by account u{index % 30}",
            "claim_type": "observed_action", "event_ids": [], "context_event_ids": [], "predicate_fields": [],
            "entities": [["host", f"ws{index % 50}", "host"]],
            "ts": datetime(2024, 11, 18, 10, tzinfo=UTC) + timedelta(seconds=index),
            "severity": "high", "confidence": "high", "lane": ("urgent", "high", "lead")[index % 3],
            "priority": 2.0, "priority_reasons": [], "gate_results": {}, "benign_alternatives": [],
            "next_checks": [], "group_key": f"c{index}", "source_case_id": None,
            "source_anchor_id": None, "source_link_id": None, "created_at": datetime.now(UTC)}


def _hypothesis(repo, index=0):
    now = datetime.now(UTC) + timedelta(microseconds=index)
    row = {"id": f"hyp-{index}", "hunt_id": "h1", "statement": f"Review hypothesis number {index} here",
           "techniques": [], "entity_ids": [], "status": "open", "confidence": "low", "questions": ["q"],
           "created_session_id": None, "sessions_run": 0, "created_at": now, "updated_at": now}
    repo.save_agent_hypothesis(row)
    return row


def _finish():
    return response(tool_calls=[ToolCall("f", "finish_session", {"summary": "The bounded session is complete."}, "{}")])


def _run(repo, tmp_path, provider, **settings):
    return run_agent_phase(Settings(home=tmp_path, **settings), repo, "h1", provider=provider,
                           toolbox_factory=lambda sid: Toolbox(repo, "h1", session_id=sid), clock=lambda: 0.0)


@pytest.mark.parametrize("findings", [600, 20_000])
def test_orient_initial_request_accounts_for_tool_schemas(agent_repo, tmp_path, findings):
    repo = agent_repo
    with repo.engine.begin() as connection:
        connection.execute(tables.candidate.insert(), [_candidate(index) for index in range(findings)])
    settings = Settings(home=tmp_path)
    provider = ScriptedProvider([_finish()], context=32_000, output=1024)
    gate = _BudgetGate(AgentBudget.from_usage(BudgetLimits.from_settings(settings), {}, clock=lambda: 0.0), settings)
    outcome = _run_session(settings, repo, "h1", provider, gate,
                           lambda sid: Toolbox(repo, "h1", session_id=sid), _prompt_set(), purpose="orient")
    request = provider.requests[0]
    assert estimate_tokens(request.prompt_text()) + provider.output_limit(request) < int(32_000 * 0.85)
    assert not any("Context is nearly full" in str(message.get("content")) for message in request.messages)
    assert outcome["state"] == "finished"


class _AttemptBoundExceeded(BaseException):
    """Stop a broken retry loop promptly without relying on timing assertions."""


@pytest.mark.parametrize("lease_lost", [False, True])
def test_session_start_write_failure_is_bounded(agent_repo, tmp_path, monkeypatch, lease_lost):
    repo = agent_repo
    _hypothesis(repo)
    candidate = _candidate(0)
    candidate["lane"] = "lead"
    with repo.engine.begin() as connection:
        connection.execute(tables.candidate.insert().values(**candidate))
    attempts = []

    def fail_write(*args, **kwargs):
        attempts.append(1)
        if len(attempts) > 2:
            raise _AttemptBoundExceeded("controller retried a failed scheduling round")
        raise RuntimeError("hunt h1 lease ownership lost" if lease_lost else "session database unavailable")

    monkeypatch.setattr(repo, "save_agent_session", fail_write)
    result = _run(repo, tmp_path, ScriptedProvider([]))
    assert len(attempts) == (1 if lease_lost else 2)
    assert result.reason == "lease_lost" if lease_lost else result.state == "failed"
    assert repo.get_hunt("h1")["execution_state"] == "completed_within_scope"
    assert repo.get_hunt("h1")["detection_result"] == "leads_only"


def test_budget_round_with_none_reason_still_assesses(agent_repo, tmp_path):
    repo = agent_repo
    _hypothesis(repo, 0)
    _hypothesis(repo, 1)
    result = _run(repo, tmp_path, ScriptedProvider([_finish(), response(parsed=ASSESSMENT)]),
                  agent_max_calls=2, agent_concurrency=2)
    assert result.state == "partial" and "budget:calls" in result.reason
    assert sorted(row["state"] for row in repo.agent_sessions("h1", purpose="investigate")) == ["budget", "finished"]
    assert repo.agent_sessions("h1", purpose="assess")[-1]["state"] == "finished"


def test_scheduler_touches_only_typed_entity_aliases(agent_repo):
    repo = agent_repo
    now = datetime.now(UTC)
    with repo.engine.begin() as connection:
        connection.execute(tables.agent_alias.insert(), [
            {"hunt_id": "h1", "alias": "N1", "kind": "N", "target_id": "entity-1", "created_at": now},
            {"hunt_id": "h1", "alias": "N12", "kind": "N", "target_id": "entity-12", "created_at": now},
        ])
        connection.execute(tables.agent_session.insert().values(
            id="s1", hunt_id="h1", purpose="orient", state="finished", tool_calls=2, summary="done", started_at=now))
    for seq, (name, arguments) in enumerate([
        ("entity_profile", {"entity": "N12"}),
        ("finish_session", {"summary": "N1 occurs only inside model prose, not an entity argument."}),
    ]):
        repo.save_agent_tool_call({"id": f"tc{seq}", "hunt_id": "h1", "session_id": "s1", "seq": seq,
                                  "name": name, "arguments": arguments, "status": "complete",
                                  "result_digest": "d", "created_at": now})
    assert _touched_entities(repo, "h1") == {"entity-12"}


def test_scheduler_priority_fetches_only_cited_finding_ids(agent_repo, monkeypatch):
    repo = agent_repo
    hypothesis = _hypothesis(repo)
    with repo.engine.begin() as connection:
        connection.execute(tables.candidate.insert().values(**_candidate(0)))
        connection.execute(tables.agent_hypothesis_cite.insert().values(
            hypothesis_id="hyp-0", hunt_id="h1", role="support", target_kind="finding", target_id="c000000"))
    queried = []
    original = repo.candidates_by_ids

    def selective(ids, **kwargs):
        queried.append(list(ids))
        return original(ids, **kwargs)

    monkeypatch.setattr(repo, "candidates_by_ids", selective)
    monkeypatch.setattr(repo, "candidates", lambda *_args, **_kwargs: pytest.fail("scheduler loaded the whole hunt"))
    assert _priority(repo, "h1", hypothesis, set())[0] == -3
    assert queried == [["c000000"]]


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_preparsed_tool_arguments_reject_nonfinite_numbers(value):
    parsed = parse_tool_arguments("c1", "tool", {"nested": [{"number": value}]})
    assert parsed.arguments is None and parsed.error


def test_record_failure_retains_attempt_duration(agent_repo):
    provider = ScriptedProvider([])
    error = ProviderUnavailable("offline")
    error.duration_ms = 3456
    record_failure(agent_repo, provider, hunt_id="h1", purpose="assess", request=ChatRequest(messages=[]),
                   error=error, limits=BudgetLimits.from_settings(Settings()))
    assert agent_repo.model_calls("h1")[0]["duration_ms"] == 3456


@pytest.mark.parametrize("lose_at", [1, 3, 4])
def test_heartbeat_lease_loss_stops_before_more_calls(agent_repo, tmp_path, monkeypatch, lose_at):
    repo = agent_repo
    _hypothesis(repo)
    checks = []
    finalized = []

    def heartbeat():
        checks.append(1)
        if len(checks) == lose_at:
            raise RuntimeError("hunt h1 lease ownership lost")

    monkeypatch.setattr(repo, "finalize_agent_run", lambda *_args, **_kwargs: finalized.append(1), raising=False)
    provider = ScriptedProvider([_finish()])
    result = run_agent_phase(Settings(home=tmp_path), repo, "h1", provider=provider,
                             toolbox_factory=lambda sid: Toolbox(repo, "h1", session_id=sid),
                             clock=lambda: 0.0, heartbeat=heartbeat)
    assert result.reason == "lease_lost"
    assert len(provider.requests) <= 1 and not finalized
    assert not repo.agent_sessions("h1", purpose="assess")


def test_no_progress_round_is_not_rescheduled(agent_repo, tmp_path, monkeypatch):
    from romulus.agent import investigate
    repo = agent_repo
    _hypothesis(repo)
    attempts = []

    def no_progress(*args, **kwargs):
        attempts.append(1)
        if len(attempts) > 1:
            raise _AttemptBoundExceeded("controller repeated a round with no durable progress")
        return {"state": "finished", "reason": None}

    monkeypatch.setattr(investigate, "_run_session", no_progress)
    result = _run(repo, tmp_path, ScriptedProvider([response(parsed=ASSESSMENT)]))
    assert len(attempts) == 1 and result.state == "partial"
    assert "no_progress" in result.reason
    assert repo.agent_sessions("h1", purpose="assess")[-1]["state"] == "finished"


class _SimulatedCrash(BaseException):
    pass


@pytest.mark.parametrize("purpose", ["orient", "assess"])
def test_crash_in_model_call_recovers_running_session(agent_repo, tmp_path, purpose):
    repo = agent_repo
    if purpose == "orient":
        with repo.engine.begin() as connection:
            connection.execute(tables.candidate.insert().values(**_candidate(0)))
    with pytest.raises(_SimulatedCrash):
        _run(repo, tmp_path, ScriptedProvider([_SimulatedCrash()]))
    assert repo.agent_run("h1")["state"] == "running"
    assert repo.agent_sessions("h1")[-1]["purpose"] == purpose
    assert repo.agent_sessions("h1")[-1]["state"] == "running"
    replies = [_finish(), _finish(), response(parsed=ASSESSMENT)] if purpose == "orient" else [response(parsed=ASSESSMENT)]
    result = _run(repo, tmp_path, ScriptedProvider(replies))
    assert result.state == "completed"
    assert repo.agent_sessions("h1")[0]["state"] == "interrupted"
    assert repo.agent_sessions("h1")[-1]["purpose"] == "assess"


def test_concurrent_rounds_never_run_two_sessions_for_one_hypothesis(agent_repo, tmp_path):
    repo = agent_repo
    _hypothesis(repo, 0)
    _hypothesis(repo, 1)
    barrier = Barrier(2)
    lock = Lock()
    active = set()
    seen = []

    def reply(request):
        hypothesis = json.loads(request.messages[1]["content"])["hypothesis"]["alias"]
        with lock:
            assert hypothesis not in active
            active.add(hypothesis)
            seen.append(hypothesis)
        barrier.wait(timeout=10)
        with lock:
            active.remove(hypothesis)
        return _finish()

    result = _run(repo, tmp_path, ScriptedProvider([reply] * 4 + [response(parsed=ASSESSMENT)]),
                  agent_concurrency=2, agent_max_sessions_per_hypothesis=2)
    assert result.state == "completed"
    assert len(seen) == 4 and len(set(seen[:2])) == 2 and len(set(seen[2:])) == 2


def test_skip_retains_latest_agent_assessment(agent_repo, tmp_path):
    from romulus.agent.investigate import skip_agent_phase
    repo = agent_repo
    repo.save_agent_assessment({"id": "existing", "hunt_id": "h1", "revision": 1, "source": "agent",
                                "model": {}, "body": ASSESSMENT, "checker": {}, "created_at": datetime.now(UTC)})
    skip_agent_phase(Settings(home=tmp_path), repo, "h1", "provider_not_ready")
    assert [(row["revision"], row["source"]) for row in repo.agent_assessments("h1")] == [(1, "agent")]


@pytest.mark.parametrize("source", ["agent", "template"])
def test_crash_before_terminal_transaction_recovers_without_more_model_calls(agent_repo, tmp_path, monkeypatch, source):
    repo = agent_repo
    original = repo.finalize_agent_run

    def crash(*args, **kwargs):
        raise _SimulatedCrash()

    monkeypatch.setattr(repo, "finalize_agent_run", crash)
    replies = [response(parsed=ASSESSMENT)] if source == "agent" else [response(content="bad"), response(content="bad")]
    with pytest.raises(_SimulatedCrash):
        _run(repo, tmp_path, ScriptedProvider(replies))
    assert repo.agent_run("h1")["state"] == "running"
    assert repo.agent_assessments("h1")[-1]["source"] == source
    monkeypatch.setattr(repo, "finalize_agent_run", original)
    provider = ScriptedProvider([])
    result = _run(repo, tmp_path, provider)
    assert result.state == "partial" and result.reason == "recovered_finished_sessions"
    assert not provider.requests
    assert repo.agent_run("h1")["state"] == result.state


@pytest.mark.parametrize("budget", ["wall-clock", "cost"])
def test_wall_and_cost_exhaustion_use_the_template_without_a_model_call(agent_repo, tmp_path, budget):
    repo = agent_repo
    _hypothesis(repo)
    settings = {"agent_max_cost_usd": 0.000001, "agent_price_input_per_mtok": 1.0} if budget == "cost" else {}
    ticks = iter([0.0])
    provider = ScriptedProvider([])
    result = run_agent_phase(Settings(home=tmp_path, **settings), repo, "h1", provider=provider,
                             toolbox_factory=lambda sid: Toolbox(repo, "h1", session_id=sid),
                             clock=(lambda: next(ticks, 4000.0)) if budget == "wall-clock" else lambda: 0.0)
    assert result.state == "partial" and f"budget:{budget}" in result.reason
    assert not provider.requests
    assert repo.agent_assessments("h1")[-1]["source"] == "template"


def test_recovery_keeps_caps_honestly_partial_after_a_finalization_crash(agent_repo, tmp_path, monkeypatch):
    repo = agent_repo
    with repo.engine.begin() as connection:
        connection.execute(tables.candidate.insert().values(**_candidate(0)))
    original = repo.finalize_agent_run
    terminal = []

    def crash(hunt_id, values, **kwargs):
        terminal.append(values)
        raise _SimulatedCrash()

    monkeypatch.setattr(repo, "finalize_agent_run", crash)
    opens = response(tool_calls=[
        ToolCall("o1", "open_hypothesis", {"statement": "Review the first incident hypothesis"}, "{}"),
        ToolCall("o2", "open_hypothesis", {"statement": "Review an alternate incident hypothesis"}, "{}"),
        ToolCall("f", "finish_session", {"summary": "The bounded session is complete."}, "{}"),
    ])
    with pytest.raises(_SimulatedCrash):
        _run(repo, tmp_path, ScriptedProvider([opens, _finish(), response(parsed=ASSESSMENT)]),
             agent_max_initial_hypotheses=1, agent_max_hypotheses=1)
    assert terminal[0]["state"] == "partial"
    assert all(row["state"] == "finished" for row in repo.agent_sessions("h1"))
    monkeypatch.setattr(repo, "finalize_agent_run", original)
    provider = ScriptedProvider([])
    result = _run(repo, tmp_path, provider)
    assert result.state == "partial" and result.reason == "recovered_finished_sessions"
    assert not provider.requests
