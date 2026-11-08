"""Tests for the persisted, hypothesis-driven agent phase."""
import json
from datetime import UTC, datetime, timedelta

import pytest
from alembic import command
from sqlalchemy import inspect

from romulus.agent.admission import AgentAdmission
from romulus.agent.aliases import AliasBook
from romulus.agent.assessment import _assessment_input, check_assessment, run_assessment
from romulus.agent.claims import CLAIM_KIND_FAMILIES, REGISTERED_EVENT_FAMILIES
from romulus.agent.investigate import _BudgetGate, _prompt_set, _run_session, run_agent_phase
from romulus.agent.provider import AgentBudget, BudgetLimits, ProviderUnavailable
from romulus.agent.provider.base import ToolCall, estimate_tokens
from romulus.agent.toolbox import Toolbox
from romulus.config import Settings
from romulus.evidence.normalize import BOOT_FILL_FAMILIES
from romulus.evidence.typed import NETWORK_OBSERVER_FAMILIES
from romulus.evidence.windows_catalog import EVENT_CLASSES
from romulus.evidence.zeek_catalog import ZEEK_LOGS
from romulus.store import schema as tables
from romulus.store.db import make_engine, migrate
from romulus.store.repo import Repo
from tests.agent_scripted import ScriptedProvider, response
from tests.test_local_content_migration import config


def test_claim_family_table_covers_every_registered_event_family():
    registered = ({row.family for row in EVENT_CLASSES} | {row.family for row in ZEEK_LOGS}
                  | NETWORK_OBSERVER_FAMILIES | BOOT_FILL_FAMILIES)
    assert registered <= REGISTERED_EVENT_FAMILIES
    assert REGISTERED_EVENT_FAMILIES <= set(CLAIM_KIND_FAMILIES)
    assert all("mention" in CLAIM_KIND_FAMILIES[family] for family in registered)


def test_agent_phase_migration_round_trips_a_populated_database(tmp_path):
    engine = make_engine(tmp_path / "agent-migration.sqlite")
    with engine.begin() as connection:
        command.upgrade(config(connection), "0034")
        connection.execute(tables.hunt.insert().values(
            id="h1", created_at=datetime.now(UTC), created_by="test", manifest={},
            manifest_digest="d", execution_state="planned",
        ))
        connection.execute(tables.agent_alias.insert().values(
            hunt_id="h1", alias="F1", kind="F", target_id="legacy-finding", created_at=datetime.now(UTC),
        ))
        connection.exec_driver_sql(
            "INSERT INTO candidate (id,hunt_id,rule_id,rule_version,claim,claim_type,event_ids,context_event_ids,"
            "predicate_fields,entities,ts,severity,confidence,lane,priority,priority_reasons,gate_results,"
            "benign_alternatives,next_checks,group_key,source_case_id,source_anchor_id,source_link_id,created_at) "
            "VALUES ('c1','h1','host.test','1','legacy candidate','observed_action','[]','[]','[]','[]',NULL,"
            "'high','high','high',1.0,'[]','{}','[]','[]','g1',NULL,NULL,NULL,'2026-01-01')",
        )
        connection.exec_driver_sql(
            "INSERT INTO model_call (id,hunt_id,purpose,model,options,prompt_digest,status,at) "
            "VALUES ('mc1','h1','triage','legacy-model','{}','p','ok','2026-01-01')",
        )

    with engine.begin() as connection:
        command.upgrade(config(connection), "0035")
        inspector = inspect(connection)
        expected = {
            "agent_run", "agent_hypothesis", "agent_hypothesis_event", "agent_hypothesis_cite",
            "agent_session", "agent_tool_call", "agent_link", "agent_note", "agent_rule_request",
            "agent_assessment",
        }
        assert expected <= set(inspector.get_table_names())
        assert {column["name"] for column in inspector.get_columns("agent_session")} >= {
            "id", "hunt_id", "hypothesis_id", "purpose", "state", "tool_calls", "summary",
        }
        assert {column["name"] for column in inspector.get_columns("candidate")} >= {
            "provenance", "agent_hypothesis_id",
        }
        assert connection.exec_driver_sql(
            "SELECT kind || ':' || alias || ':' || target_id FROM agent_alias WHERE hunt_id='h1'",
        ).scalar_one() == "F:F1:legacy-finding"
        assert connection.exec_driver_sql(
            "SELECT provenance || ':' || claim FROM candidate WHERE id='c1'",
        ).scalar_one() == "deterministic:legacy candidate"
        assert connection.exec_driver_sql(
            "SELECT model || ':' || COALESCE(session_id,'none') FROM model_call WHERE id='mc1'",
        ).scalar_one() == "legacy-model:none"
        connection.exec_driver_sql(
            "INSERT INTO agent_alias(hunt_id,alias,kind,target_id,created_at) "
            "VALUES ('h1','H1','H','hyp-1','2026-01-01')",
        )
        connection.exec_driver_sql("DELETE FROM agent_alias WHERE kind='H'")
        assert connection.exec_driver_sql("PRAGMA foreign_key_check").all() == []
        assert connection.exec_driver_sql("PRAGMA quick_check").scalar_one() == "ok"

    with engine.begin() as connection:
        command.downgrade(config(connection), "0034")
        assert "agent_run" not in inspect(connection).get_table_names()
        assert connection.exec_driver_sql("SELECT alias FROM agent_alias WHERE kind='F'").scalar_one() == "F1"
        assert connection.exec_driver_sql("SELECT claim FROM candidate WHERE id='c1'").scalar_one() == "legacy candidate"
        assert connection.exec_driver_sql("SELECT model FROM model_call WHERE id='mc1'").scalar_one() == "legacy-model"
        assert connection.exec_driver_sql("PRAGMA foreign_key_check").all() == []
        assert connection.exec_driver_sql("PRAGMA quick_check").scalar_one() == "ok"

    with engine.begin() as connection:
        command.upgrade(config(connection), "0035")
        assert "agent_assessment" in inspect(connection).get_table_names()
        assert connection.exec_driver_sql("PRAGMA foreign_key_check").all() == []
        assert connection.exec_driver_sql("PRAGMA quick_check").scalar_one() == "ok"
    engine.dispose()


def test_scripted_orient_investigate_and_assess_keeps_deterministic_rows(tmp_path):
    engine = make_engine(tmp_path / "scripted-agent.sqlite")
    migrate(engine)
    repo = Repo(engine)
    repo.create_hunt("h1", {"window": {}, "targets": [], "ai_agent": {"requested": True}}, "d", "test")
    repo.save_candidate({
        "id": "c1", "hunt_id": "h1", "rule_id": "host.test", "rule_version": "1",
        "claim": "a deterministic process execution finding", "claim_type": "observed_action",
        "event_ids": [], "context_event_ids": [], "predicate_fields": [],
        "entities": [["host", "workstation-1", "host"]], "ts": datetime.now(UTC),
        "severity": "high", "confidence": "high", "lane": "high", "priority": 2.0,
        "priority_reasons": [], "gate_results": {}, "benign_alternatives": [], "next_checks": [],
        "group_key": "c1", "source_case_id": None, "source_anchor_id": None, "source_link_id": None,
    })
    deterministic_before = repo.candidates("h1")
    opens = [
        ToolCall("o1", "open_hypothesis", {"statement": "Review the first incident hypothesis"}, "{}"),
        ToolCall("o2", "open_hypothesis", {"statement": "Review an alternate incident hypothesis"}, "{}"),
        ToolCall("of", "finish_session", {"summary": "The initial review is complete."}, "{}"),
    ]
    finish = [ToolCall("f", "finish_session", {"summary": "The evidence review is complete."}, "{}")]
    assessment = {"overall": [{"text": "The persisted finding is available for review.", "cites": [],
                                "kind": "hypothesis"}],
                  "key_steps": [], "confidence": {"overall": "low", "reasons": []},
                  "alternatives": [], "gaps": [], "next_checks": []}
    provider = ScriptedProvider([response(tool_calls=opens), response(tool_calls=finish),
                                 response(tool_calls=finish), response(parsed=assessment)])
    settings = Settings(home=tmp_path)

    result = run_agent_phase(settings, repo, "h1", provider=provider,
                             toolbox_factory=lambda _session: Toolbox(repo, "h1"), clock=lambda: 0.0)

    sessions = repo.agent_sessions("h1")
    assert result.state == "completed", (result.as_dict(), sessions, repo.agent_assessments("h1"))
    orient_tool_names = {tool.name for tool in provider.requests[0].tools}
    assert "open_hypothesis" in orient_tool_names and "finish_session" in orient_tool_names
    assert not orient_tool_names.intersection({"update_hypothesis", "propose_finding", "propose_link",
                                               "add_note", "request_rule"})
    assert [row["purpose"] for row in sessions] == ["orient", "investigate", "investigate", "assess"]
    assert all(row["state"] == "finished" for row in sessions)
    assert len(repo.agent_hypotheses("h1")) == 2
    assert repo.candidates("h1") == deterministic_before
    assert repo.agent_run("h1")["state"] == "completed"
    assert len(provider.requests) == 4
    engine.dispose()


def test_assessment_checker_removes_uncited_unknown_and_absence_text_and_downgrades_agent_cites(tmp_path):
    engine = make_engine(tmp_path / "assessment-checker.sqlite")
    migrate(engine)
    repo = Repo(engine)
    repo.create_hunt("h1", {"window": {}, "targets": []}, "d", "test")
    for candidate_id, provenance in (("det", "deterministic"), ("ai", "agent")):
        repo.save_candidate({
            "id": candidate_id, "hunt_id": "h1", "rule_id": "host.test", "rule_version": "1",
            "claim": f"A {provenance} process execution finding", "claim_type": "observed_action",
            "event_ids": [], "context_event_ids": [], "predicate_fields": [], "entities": [],
            "ts": None, "severity": "high", "confidence": "high", "lane": "high", "priority": 2.0,
            "priority_reasons": [], "gate_results": {}, "benign_alternatives": [], "next_checks": [],
            "group_key": candidate_id, "source_case_id": None, "source_anchor_id": None,
            "source_link_id": None, "provenance": provenance,
        })
    aliases = AliasBook(repo, "h1")
    deterministic_alias = aliases.alias_for("F", "det")
    agent_alias = aliases.alias_for("F", "ai")
    body = {"overall": [
        {"text": "This sentence has no support.", "cites": [], "kind": "inferred"},
        {"text": "This alias is unknown.", "cites": ["F999"], "kind": "inferred"},
        {"text": "The host is clean.", "cites": [deterministic_alias], "kind": "observed"},
        {"text": "The agent proposal suggests a possible execution path.", "cites": [agent_alias],
         "kind": "observed"}],
        "key_steps": [], "confidence": {"overall": "low", "reasons": []}, "alternatives": [],
        "gaps": [{"text": "No auditd records from host B were in the index after 14:00.",
                  "cites": [deterministic_alias], "kind": "inferred"}], "next_checks": []}

    checked, counts = check_assessment(repo, "h1", body)

    assert checked["overall"] == [{"text": "The agent proposal suggests a possible execution path.",
                                    "cites": ["ai"], "kind": "inferred"}]
    assert checked["gaps"][0]["text"].startswith("No auditd records")
    assert checked["gaps"][0]["cites"] == ["det"]
    assert counts == {"removed_uncited": 1, "removed_unknown_alias": 1,
                      "downgraded_observed": 1, "removed_absence_claim": 1}
    engine.dispose()


def test_reassessment_appends_revision_and_preserves_the_first(tmp_path):
    engine = make_engine(tmp_path / "assessment-revisions.sqlite")
    migrate(engine)
    repo = Repo(engine)
    repo.create_hunt("h1", {"window": {}, "targets": []}, "d", "test")
    first_body = {"overall": [], "key_steps": [], "confidence": {"overall": "low", "reasons": []},
                  "alternatives": [], "gaps": [], "next_checks": []}
    first = {"id": "aa-first", "hunt_id": "h1", "revision": 1, "source": "template", "model": {},
             "body": first_body, "checker": {}, "created_at": datetime.now(UTC)}
    repo.save_agent_assessment(first)
    provider = ScriptedProvider([response(parsed=first_body)])
    limits = BudgetLimits(10, 100_000, 600, 0, 0, 0)
    budget = AgentBudget.from_usage(limits, repo.agent_usage("h1"), clock=lambda: 0.0)

    result = run_assessment(Settings(home=tmp_path), repo, "h1", provider, budget, clock=lambda: 0.0)

    rows = repo.agent_assessments("h1")
    assert result["revision"] == 2
    assert [row["revision"] for row in rows] == [1, 2]
    assert rows[0]["body"] == first_body
    assert rows[0]["source"] == "template"
    assert rows[1]["source"] == "agent"
    engine.dispose()


def test_interrupted_investigation_is_retried_without_repeating_deterministic_work(tmp_path):
    engine = make_engine(tmp_path / "interrupted-agent.sqlite")
    migrate(engine)
    repo = Repo(engine)
    repo.create_hunt("h1", {"window": {}, "targets": [], "ai_agent": {"requested": True}}, "d", "test")
    started = datetime.now(UTC) - timedelta(minutes=1)
    repo.save_agent_hypothesis({
        "id": "hyp-1", "hunt_id": "h1", "statement": "Review the interrupted investigation hypothesis",
        "techniques": [], "entity_ids": [], "status": "open", "confidence": "low", "questions": [],
        "created_session_id": "as-crashed", "sessions_run": 1, "created_at": started, "updated_at": started,
    })
    repo.save_agent_session({"id": "as-crashed", "hunt_id": "h1", "hypothesis_id": "hyp-1",
                             "purpose": "investigate", "state": "running", "tool_calls": 2,
                             "summary": "", "started_at": started, "ended_at": None})
    repo.save_agent_run({"hunt_id": "h1", "state": "running", "reason": None, "prompt_digests": {},
                         "provider": {}, "started_at": started, "ended_at": None})
    body = {"overall": [], "key_steps": [], "confidence": {"overall": "low", "reasons": []},
            "alternatives": [], "gaps": [], "next_checks": []}
    provider = ScriptedProvider([response(tool_calls=[ToolCall(
        "finish", "finish_session", {"summary": "The resumed investigation is complete."}, "{}")]),
        response(parsed=body)])

    result = run_agent_phase(Settings(home=tmp_path), repo, "h1", provider=provider,
                             toolbox_factory=lambda session: Toolbox(repo, "h1", session_id=session),
                             clock=lambda: 0.0)

    sessions = repo.agent_sessions("h1")
    assert [row["state"] for row in sessions] == ["interrupted", "finished", "finished"]
    assert [row["purpose"] for row in sessions] == ["investigate", "investigate", "assess"]
    assert repo.agent_hypotheses("h1")[0]["sessions_run"] == 1
    assert result.state == "completed"
    assert len(provider.requests) == 2
    engine.dispose()


def test_resume_after_new_investigation_replaces_a_stale_agent_assessment(tmp_path):
    engine = make_engine(tmp_path / "stale-agent-assessment.sqlite")
    migrate(engine)
    repo = Repo(engine)
    repo.create_hunt("h1", {"window": {}, "targets": [], "ai_agent": {"requested": True}}, "d", "test")
    now = datetime.now(UTC)
    repo.save_agent_session({"id": "as-orient", "hunt_id": "h1", "hypothesis_id": None, "purpose": "orient",
                             "state": "finished", "tool_calls": 1, "summary": "Initial review finished.",
                             "started_at": now, "ended_at": now})
    repo.save_agent_hypothesis({
        "id": "hyp-pending", "hunt_id": "h1", "statement": "Continue the pending investigation after resume",
        "techniques": [], "entity_ids": [], "status": "open", "confidence": "low",
        "questions": ["collect more evidence"], "created_session_id": "as-orient", "sessions_run": 0,
        "created_at": now, "updated_at": now,
    })
    old_body = {"overall": [], "key_steps": [], "confidence": {"overall": "low", "reasons": []},
                "alternatives": [], "gaps": [], "next_checks": []}
    repo.save_agent_assessment({"id": "aa-stale", "hunt_id": "h1", "revision": 1, "source": "agent",
                                "model": {"provider": "scripted"}, "body": old_body, "checker": {},
                                "created_at": now})
    repo.save_agent_run({"hunt_id": "h1", "state": "partial", "reason": "provider_unavailable",
                         "prompt_digests": {}, "provider": {}, "started_at": now, "ended_at": now})
    hypothesis_alias = AliasBook(repo, "h1").alias_for("H", "hyp-pending")
    body = {"overall": [], "key_steps": [], "confidence": {"overall": "medium", "reasons": []},
            "alternatives": [], "gaps": [], "next_checks": []}
    provider = ScriptedProvider([
        response(tool_calls=[ToolCall("updated", "update_hypothesis",
                                      {"hypothesis": hypothesis_alias, "note": "Reviewed after resume.",
                                       "questions": []}, "{}"),
                               ToolCall("finished", "finish_session",
                                        {"summary": "The resumed investigation is complete."}, "{}")]),
        response(parsed=body),
    ])

    result = run_agent_phase(Settings(home=tmp_path), repo, "h1", provider=provider,
                             toolbox_factory=lambda session: Toolbox(repo, "h1", session_id=session),
                             clock=lambda: 0.0)

    assessments = repo.agent_assessments("h1")
    assert result.state == "completed"
    assert [row["revision"] for row in assessments] == [1, 2]
    assert assessments[0]["id"] == "aa-stale" and assessments[0]["body"] == old_body
    assert assessments[1]["source"] == "agent" and assessments[1]["body"] == body
    assert [row["purpose"] for row in repo.agent_sessions("h1")].count("assess") == 1
    assert len(provider.requests) == 2
    engine.dispose()


def test_two_consecutive_provider_outages_are_billed_then_assess_runs(tmp_path):
    engine = make_engine(tmp_path / "agent-outages.sqlite")
    migrate(engine)
    repo = Repo(engine)
    repo.create_hunt("h1", {"window": {}, "targets": [], "ai_agent": {"requested": True}}, "d", "test")
    repo.save_candidate({
        "id": "c1", "hunt_id": "h1", "rule_id": "host.test", "rule_version": "1",
        "claim": "A deterministic finding for controller-generated investigation", "claim_type": "observed_action",
        "event_ids": [], "context_event_ids": [], "predicate_fields": [], "entities": [], "ts": None,
        "severity": "high", "confidence": "high", "lane": "high", "priority": 2.0,
        "priority_reasons": [], "gate_results": {}, "benign_alternatives": [], "next_checks": [],
        "group_key": "c1", "source_case_id": None, "source_anchor_id": None, "source_link_id": None,
    })
    def outage():
        error = ProviderUnavailable("endpoint unavailable")
        error.billed = [{"model": "scripted-model", "prompt": 100, "completion": 20}]
        return error
    body = {"overall": [], "key_steps": [], "confidence": {"overall": "low", "reasons": []},
            "alternatives": [], "gaps": [], "next_checks": []}
    provider = ScriptedProvider([outage(), outage(), response(parsed=body)])

    result = run_agent_phase(Settings(home=tmp_path), repo, "h1", provider=provider,
                             toolbox_factory=lambda session: Toolbox(repo, "h1", session_id=session),
                             clock=lambda: 0.0)

    calls = repo.model_calls("h1")
    assert [row["status"] for row in calls] == ["error", "error", "ok"]
    assert all(row["options"]["billed_failure"] == "ProviderUnavailable" for row in calls[:2])
    assert repo.agent_usage("h1")["calls"] == 3
    assert [row["state"] for row in repo.agent_sessions("h1")] == ["failed", "failed", "finished"]
    assert result.state == "partial" and result.reason == "provider_unavailable"
    engine.dispose()


def test_assessment_schema_failure_gets_one_retry_then_a_template(tmp_path):
    engine = make_engine(tmp_path / "assessment-retry.sqlite")
    migrate(engine)
    repo = Repo(engine)
    repo.create_hunt("h1", {"window": {}, "targets": [], "ai_agent": {"requested": True}}, "d", "test")
    invalid = response(parsed={"overall": "not a list"})
    provider = ScriptedProvider([invalid, invalid])
    result = run_agent_phase(Settings(home=tmp_path), repo, "h1", provider=provider,
                             toolbox_factory=lambda session: Toolbox(repo, "h1", session_id=session),
                             clock=lambda: 0.0)
    rows = repo.agent_assessments("h1")
    assert len(provider.requests) == 2
    assert result.state == "partial" and result.reason == "assessment_not_produced"
    assert len(rows) == 1 and rows[0]["source"] == "template"
    assert rows[0]["body"]["overall"][0]["text"].startswith("No qualifying behavior was reported")
    assert repo.agent_sessions("h1", purpose="assess")[-1]["state"] == "failed"
    engine.dispose()


@pytest.mark.parametrize("mode, expected", [
    ("capped", "capped"), ("context_full", "context_full"),
    ("no_tool_call_twice", "failed"), ("refused", "refused"),
])
def test_session_stop_conditions_are_persisted_and_do_not_skip_assessment(tmp_path, mode, expected):
    engine = make_engine(tmp_path / f"agent-stop-{mode}.sqlite")
    migrate(engine)
    repo = Repo(engine)
    repo.create_hunt("h1", {"window": {}, "targets": [], "ai_agent": {"requested": True}}, "d", "test")
    repo.save_candidate({
        "id": "c1", "hunt_id": "h1", "rule_id": "host.test", "rule_version": "1",
        "claim": "A deterministic finding for the session stop test", "claim_type": "observed_action",
        "event_ids": [], "context_event_ids": [], "predicate_fields": [], "entities": [], "ts": None,
        "severity": "high", "confidence": "high", "lane": "high", "priority": 2.0,
        "priority_reasons": [], "gate_results": {}, "benign_alternatives": [], "next_checks": [],
        "group_key": "c1", "source_case_id": None, "source_anchor_id": None, "source_link_id": None,
    })
    opened = ToolCall("open", "open_hypothesis", {"statement": "Review this bounded stop-condition hypothesis"}, "{}")
    finish = ToolCall("finish", "finish_session", {"summary": "The bounded review session is complete."}, "{}")
    body = {"overall": [], "key_steps": [], "confidence": {"overall": "low", "reasons": []},
            "alternatives": [], "gaps": [], "next_checks": []}
    settings = Settings(home=tmp_path, agent_max_tool_calls_per_session=1 if mode == "capped" else 25)
    if mode == "capped":
        provider = ScriptedProvider([response(tool_calls=[opened]),
                                     response(tool_calls=[ToolCall("again", "open_hypothesis",
                                                                   {"statement": "Another bounded hypothesis"}, "{}")]),
                                     response(tool_calls=[finish]), response(parsed=body)])
    elif mode == "context_full":
        provider = ScriptedProvider([response(tool_calls=[finish]), response(tool_calls=[finish]),
                                     response(parsed=body)], context=1)
    elif mode == "no_tool_call_twice":
        provider = ScriptedProvider([response(content="A text-only response."), response(content="Still no tool call."),
                                     response(tool_calls=[finish]), response(parsed=body)])
    else:
        provider = ScriptedProvider([response(status="refused", error="model declined"),
                                     response(tool_calls=[finish]), response(parsed=body)])

    result = run_agent_phase(settings, repo, "h1", provider=provider,
                             toolbox_factory=lambda session: Toolbox(repo, "h1", session_id=session),
                             clock=lambda: 0.0)

    sessions = repo.agent_sessions("h1")
    assert sessions[0]["purpose"] == "orient" and sessions[0]["state"] == expected
    assessment_state = "context_full" if mode == "context_full" else "finished"
    assert sessions[-1]["purpose"] == "assess" and sessions[-1]["state"] == assessment_state
    assert result.state == "partial"
    assert len(repo.agent_assessments("h1")) == 1
    engine.dispose()


def test_invalid_tool_arguments_consume_the_per_session_call_budget(tmp_path):
    engine = make_engine(tmp_path / "agent-invalid-tool-budget.sqlite")
    migrate(engine)
    repo = Repo(engine)
    repo.create_hunt("h1", {"window": {}, "targets": [], "ai_agent": {"requested": True}}, "d", "test")
    settings = Settings(home=tmp_path, agent_max_tool_calls_per_session=1)
    invalid = ToolCall("bad", "open_hypothesis", None, "{", error="tool arguments were not valid JSON")
    second = ToolCall("again", "open_hypothesis", {"statement": "A bounded hypothesis after the cap"}, "{}")
    provider = ScriptedProvider([response(tool_calls=[invalid]), response(tool_calls=[second])])
    limits = BudgetLimits.from_settings(settings)
    budget = AgentBudget.from_usage(limits, repo.agent_usage("h1"), clock=lambda: 0.0)

    outcome = _run_session(settings, repo, "h1", provider, _BudgetGate(budget, settings),
                            lambda session: Toolbox(repo, "h1", session_id=session), _prompt_set(), purpose="orient")

    sessions = repo.agent_sessions("h1")
    calls = repo.agent_tool_calls("h1")
    assert outcome["state"] == "capped"
    assert sessions[-1]["tool_calls"] == 1
    assert [row["status"] for row in calls] == ["refused", "refused"]
    assert repo.agent_hypotheses("h1") == []
    engine.dispose()


def test_investigation_reserve_exhaustion_goes_to_assess_with_budget_reason(tmp_path):
    engine = make_engine(tmp_path / "agent-investigate-budget.sqlite")
    migrate(engine)
    repo = Repo(engine)
    repo.create_hunt("h1", {"window": {}, "targets": [], "ai_agent": {"requested": True}}, "d", "test")
    repo.save_candidate({
        "id": "c1", "hunt_id": "h1", "rule_id": "host.test", "rule_version": "1",
        "claim": "A deterministic finding for an investigation budget test", "claim_type": "observed_action",
        "event_ids": [], "context_event_ids": [], "predicate_fields": [], "entities": [], "ts": None,
        "severity": "high", "confidence": "high", "lane": "high", "priority": 2.0,
        "priority_reasons": [], "gate_results": {}, "benign_alternatives": [], "next_checks": [],
        "group_key": "c1", "source_case_id": None, "source_anchor_id": None, "source_link_id": None,
    })
    opened = ToolCall("open", "open_hypothesis", {"statement": "Review the call-budget hypothesis"}, "{}")
    finish = ToolCall("finish", "finish_session", {"summary": "The initial review is complete."}, "{}")
    body = {"overall": [], "key_steps": [], "confidence": {"overall": "low", "reasons": []},
            "alternatives": [], "gaps": [], "next_checks": []}
    provider = ScriptedProvider([response(tool_calls=[opened, finish]), response(parsed=body)])

    result = run_agent_phase(Settings(home=tmp_path, agent_max_calls=2), repo, "h1", provider=provider,
                             toolbox_factory=lambda session: Toolbox(repo, "h1", session_id=session),
                             clock=lambda: 0.0)

    sessions = repo.agent_sessions("h1")
    assert [row["state"] for row in sessions] == ["finished", "budget", "finished"]
    assert "budget:calls" in result.reason
    assert len(provider.requests) == 2
    assert result.state == "partial" and "budget:calls" in result.reason
    engine.dispose()


def test_assessment_budget_exhaustion_stores_a_reasoned_template(tmp_path):
    engine = make_engine(tmp_path / "agent-assess-budget.sqlite")
    migrate(engine)
    repo = Repo(engine)
    repo.create_hunt("h1", {"window": {}, "targets": [], "ai_agent": {"requested": True}}, "d", "test")
    provider = ScriptedProvider([response(parsed={"overall": "invalid"})])

    result = run_agent_phase(Settings(home=tmp_path, agent_max_calls=1), repo, "h1", provider=provider,
                             toolbox_factory=lambda session: Toolbox(repo, "h1", session_id=session),
                             clock=lambda: 0.0)

    assess = repo.agent_sessions("h1", purpose="assess")[-1]
    assessment = repo.agent_assessments("h1")[-1]
    assert assess["state"] == "budget" and assess["summary"] == "budget:calls"
    assert result.state == "partial" and result.reason == "budget:calls"
    assert assessment["source"] == "template"
    assert assessment["body"]["overall"][0]["text"].startswith("No qualifying behavior was reported")
    engine.dispose()


def test_assessment_input_trims_all_sections_and_refuses_an_oversized_prompt(tmp_path):
    engine = make_engine(tmp_path / "agent-assessment-context.sqlite")
    migrate(engine)
    repo = Repo(engine)
    repo.create_hunt("h1", {"window": {}, "targets": [], "ai_agent": {"requested": True}}, "d", "test")
    now = datetime.now(UTC)
    for index in range(20):
        repo.save_agent_hypothesis({
            "id": f"hyp-context-{index:02d}", "hunt_id": "h1",
            "statement": f"Review this active hypothesis and its bounded evidence. {index} " + ("x" * 500),
            "techniques": [], "entity_ids": [], "status": "open", "confidence": "low", "questions": [],
            "created_session_id": None, "sessions_run": 0, "created_at": now + timedelta(microseconds=index),
            "updated_at": now,
        })

    context = _assessment_input(repo, "h1", token_budget=80)
    serialized = json.dumps(context["data"], sort_keys=True, ensure_ascii=False, default=str)
    assert estimate_tokens(serialized) <= 80
    assert context["data"]["omitted"]["other_hypotheses"] > 0
    assert "remain in the report" in context["data"]["omitted"]["message"]

    body = {"overall": [], "key_steps": [], "confidence": {"overall": "low", "reasons": []},
            "alternatives": [], "gaps": [], "next_checks": []}
    provider = ScriptedProvider([response(parsed=body)], context=64, output=32)
    budget = AgentBudget.from_usage(BudgetLimits.from_settings(Settings(home=tmp_path)), repo.agent_usage("h1"),
                                    clock=lambda: 0.0)
    assert run_assessment(Settings(home=tmp_path), repo, "h1", provider, budget, clock=lambda: 0.0) is None
    assert provider.requests == []
    assessment_session = repo.agent_sessions("h1", purpose="assess")[-1]
    assert assessment_session["state"] == "context_full"
    assert "exceeds 85%" in assessment_session["summary"]
    engine.dispose()


def test_mission_scale_40_hypotheses_four_sessions_and_25_tools_stays_within_caps(tmp_path):
    engine = make_engine(tmp_path / "agent-scale.sqlite")
    migrate(engine)
    repo = Repo(engine)
    repo.create_hunt("h1", {"window": {}, "targets": [], "ai_agent": {"requested": True}}, "d", "test")
    now = datetime.now(UTC)
    for index in range(40):
        repo.save_agent_hypothesis({
            "id": f"hyp-{index:02d}", "hunt_id": "h1",
            "statement": f"Review bounded scale hypothesis {index:02d}", "techniques": [], "entity_ids": [],
            "status": "open", "confidence": "low", "questions": ["continue evidence review"],
            "created_session_id": None, "sessions_run": 0,
            "created_at": now + timedelta(microseconds=index), "updated_at": now,
        })

    body = {"overall": [], "key_steps": [], "confidence": {"overall": "low", "reasons": []},
            "alternatives": [], "gaps": [], "next_checks": []}

    def scripted(request):
        if request.response_schema is not None:
            return response(parsed=body)
        user = next(message["content"] for message in request.messages if message.get("role") == "user"
                    and message.get("content", "").startswith("{"))
        hypothesis = json.loads(user)["hypothesis"]
        alias = hypothesis["alias"]
        if any("Tool-call limit reached" in str(message.get("content", "")) for message in request.messages):
            return response(tool_calls=[ToolCall("finish", "finish_session",
                                                 {"summary": "The bounded scale session is complete."}, "{}")])
        questions = [] if len(hypothesis["previous_sessions"]) >= 3 else ["continue evidence review"]
        return response(tool_calls=[ToolCall(f"update-{index}", "update_hypothesis",
                                             {"hypothesis": alias, "note": f"Recorded bounded review {index}.",
                                              "questions": questions}, "{}") for index in range(25)])

    settings = Settings(home=tmp_path, agent_max_calls=400, agent_max_tokens=50_000_000,
                        agent_max_wall_seconds=10_000, agent_max_tool_calls_per_session=25,
                        agent_max_hypotheses=40, agent_max_sessions_per_hypothesis=4,
                        agent_concurrency=2, agent_context_tokens=100_000,
                        agent_assess_reserve_fraction=0.0)
    provider = ScriptedProvider([scripted] * 400, context=100_000, output=1024)

    result = run_agent_phase(settings, repo, "h1", provider=provider,
                             toolbox_factory=lambda session: Toolbox(repo, "h1", session_id=session),
                             clock=lambda: 0.0)

    sessions = repo.agent_sessions("h1")
    investigation = [row for row in sessions if row["purpose"] == "investigate"]
    calls_by_session = {}
    for row in repo.agent_tool_calls("h1"):
        calls_by_session[row["session_id"]] = calls_by_session.get(row["session_id"], 0) + 1
    assert result.state == "completed"
    assert len(repo.agent_hypotheses("h1")) == 40
    assert all(row["sessions_run"] == 4 and not row["questions"] for row in repo.agent_hypotheses("h1"))
    assert len(investigation) == 160 and all(row["state"] == "finished" for row in investigation)
    assert len(provider.requests) == 321
    assert len(calls_by_session) == 160 and set(calls_by_session.values()) == {26}
    assert len(repo.agent_hypothesis_events("hyp-00")) == 100
    assert len(repo.agent_tool_calls("h1")) == 160 * (25 + 1)
    assert len(repo.agent_links("h1")) <= settings.agent_max_links
    assert len(repo.agent_notes("h1")) <= settings.agent_max_notes
    assert len(repo.agent_rule_requests("h1")) <= 50
    repo.save_agent_session({"id": "as-cap", "hunt_id": "h1", "hypothesis_id": None,
                             "purpose": "investigate", "state": "running", "tool_calls": 0,
                             "summary": "", "started_at": datetime.now(UTC), "ended_at": None})
    admission = AgentAdmission(settings, repo, "h1", "as-cap")
    toolbox = Toolbox(repo, "h1", session_id="as-cap")
    admission.register(toolbox)
    refused = toolbox.execute("open_hypothesis", {"statement": "One more bounded hypothesis is refused"})
    assert refused["status"] == "refused"
    assert refused["errors"] == ["hypothesis limit reached; update an existing one"]
    assert "cap:hypotheses" in admission.limits_hit
    engine.dispose()


def test_agent_reassess_cli_publishes_a_new_report_revision(tmp_path, monkeypatch, capsys):
    from types import SimpleNamespace

    from romulus import cli
    from romulus.agent import provider as provider_port
    from romulus.hunt import run as hunt_run
    from romulus.report import manifest as report_manifest

    settings = Settings(home=tmp_path)
    repo = hunt_run.open_repo(settings)
    repo.create_hunt("h1", {"window": {}, "targets": [], "ai_agent": {"requested": False}}, "d", "test")
    body = {"overall": [], "key_steps": [], "confidence": {"overall": "low", "reasons": []},
            "alternatives": [], "gaps": [], "next_checks": []}
    repo.save_agent_assessment({"id": "aa-first", "hunt_id": "h1", "revision": 1, "source": "template",
                                "model": {}, "body": body, "checker": {}, "created_at": datetime.now(UTC)})
    monkeypatch.setattr(cli, "load_settings", lambda _path: settings)
    monkeypatch.setattr(provider_port, "agent_readiness", lambda _settings: SimpleNamespace(ready=True))
    monkeypatch.setattr(provider_port, "build_provider", lambda *_a, **_kw:
                        ScriptedProvider([response(parsed=body)]))
    monkeypatch.setattr(report_manifest, "publish_revision", lambda *_a, **_kw: {"revision": {"number": 2}})

    assert cli.main(["agent", "reassess", "h1"]) == 0
    output = capsys.readouterr().out
    assert '"assessment_revision": 2' in output
    assert '"report_revision": 2' in output
    assert [row["revision"] for row in repo.agent_assessments("h1")] == [1, 2]
