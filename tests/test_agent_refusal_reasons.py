"""Refused model output is recorded by field path and error type, never by the values it held."""
from __future__ import annotations

import json
import logging
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from romulus.agent.admission import FinishSessionArgs, OpenHypothesisArgs
from romulus.agent.investigate import run_agent_phase
from romulus.agent.provider.base import ToolCall, parse_tool_arguments
from romulus.agent.provider.claude_messages import instance_problems
from romulus.agent.refusals import (
    bounded,
    field_path,
    is_reason,
    reason,
    tool_result_reasons,
    validation_reasons,
)
from romulus.agent.toolbox import Toolbox
from romulus.agent.triage import DROP_REASONS
from romulus.config import Settings
from romulus.store.db import make_engine, migrate, utcnow
from romulus.store.repo import Repo
from tests.agent_scripted import ScriptedProvider, response
from tests.test_web_agent_a6 import run_row, setup  # noqa: F401 - the web fixture

SENTINEL = "SENTINELzq9telemetry"


def test_a_validation_error_becomes_paths_and_types_without_input_or_unknown_keys():
    try:
        OpenHypothesisArgs.model_validate({"statement": SENTINEL[:5], "entities": ["bad " + SENTINEL],
                                           SENTINEL: SENTINEL, "questions": [""]})
    except ValidationError as exc:
        reasons = validation_reasons(exc.errors())
    assert reasons == ["statement: string_too_short", "entities[]: string_pattern_mismatch",
                       "questions[]: string_too_short", "*: extra_forbidden"]
    assert SENTINEL not in json.dumps(reasons) and all(is_reason(item) for item in reasons)
    try:
        FinishSessionArgs.model_validate({"summary": "short"})
    except ValidationError as exc:
        assert validation_reasons(exc.errors()) == ["summary: string_too_short"]


def test_paths_and_types_outside_the_allowed_shapes_cannot_carry_text():
    assert field_path(("a", 3, "b c", SENTINEL + "!")) == "a[].?.?"
    assert reason("x y", "Bad Type") == "?: invalid"
    assert not is_reason(f"$: {SENTINEL} value") and not is_reason("statement: has 'quotes'")
    assert bounded([f"statement: {SENTINEL}!"]) == ["?: invalid"]
    many = bounded(f"f{n}: missing" for n in range(40))
    assert len(many) == 20 and many[-1] == "$: more_reasons_omitted"
    assert tool_result_reasons({"status": "complete"}) is None
    assert tool_result_reasons({"status": "refused", "data": {"error": {"code": "unknown_cursor"}}}) == [
        "$: unknown_cursor"]


def test_the_adapter_schema_check_names_fields_never_values_or_invented_keys():
    schema = {"type": "object", "additionalProperties": False, "required": ["summary", "cites"],
              "properties": {"summary": {"type": "string"},
                             "cites": {"type": "array", "items": {"type": "string", "pattern": "^E[0-9]+$"}},
                             "kind": {"type": "string", "enum": ["a", "b"]}}}
    problems = instance_problems({"summary": 7, "cites": [SENTINEL, "E1", SENTINEL], "kind": SENTINEL,
                                  SENTINEL: 1}, schema)
    assert bounded(problems) == ["*: unexpected_property", "summary: type_mismatch", "cites[]: pattern_mismatch",
                                 "kind: enum_mismatch"]
    assert SENTINEL not in json.dumps(problems)
    assert instance_problems({"cites": []}, schema) == ["summary: missing"]
    bad_json = parse_tool_arguments("t1", "finish_session", '{"summary": "' + SENTINEL)
    assert bad_json.problems == ("$: invalid_json",)


def _hunt(tmp_path) -> Repo:
    engine = make_engine(tmp_path / "refusals.sqlite")
    migrate(engine)
    repo = Repo(engine)
    repo.create_hunt("h1", {"window": {}, "targets": [], "ai_agent": {"requested": True}}, "d", "test")
    repo.set_hunt_state("h1", "running")
    repo.set_hunt_state("h1", "completed_within_scope", detection_result="leads_only", stop_reason="scope")
    repo.save_candidate({
        "id": "c1", "hunt_id": "h1", "rule_id": "host.test", "rule_version": "1",
        "claim": "a deterministic process execution finding", "claim_type": "observed_action",
        "event_ids": [], "context_event_ids": [], "predicate_fields": [],
        "entities": [["host", "workstation-1", "host"]], "ts": datetime.now(UTC),
        "severity": "high", "confidence": "high", "lane": "high", "priority": 2.0,
        "priority_reasons": [], "gate_results": {}, "benign_alternatives": [], "next_checks": [],
        "group_key": "c1", "source_case_id": None, "source_anchor_id": None, "source_link_id": None,
    })
    return repo


def test_refused_calls_record_reasons_on_their_rows_audit_and_logs_without_values(tmp_path, caplog):
    repo = _hunt(tmp_path)
    orient = [
        ToolCall("a", "finish_session", {"summary": SENTINEL[:6]}, "{}"),                       # too short
        ToolCall("b", "open_hypothesis", {"statement": "A hypothesis " + SENTINEL, SENTINEL: SENTINEL}, "{}"),
        ToolCall("c", "open_hypothesis", {"statement": "A hypothesis about " + SENTINEL, "entities": ["N999"]},
                 "{}"),                                                                     # never issued
        ToolCall("d", "open_hypothesis", None, '{"statement": 7, "x": "' + SENTINEL + '"}',
                 error="arguments do not match the tool's schema: statement: type_mismatch",
                 problems=("statement: type_mismatch", "*: unexpected_property")),
        ToolCall("e", "finish_session", {"summary": "The initial review found nothing to open."}, "{}"),
    ]
    finish = [ToolCall("f", "finish_session", {"summary": "The evidence review is complete."}, "{}")]
    invalid = response(parsed={"overall": SENTINEL, SENTINEL: [SENTINEL]})
    # orient, the controller's hypothesis for the finding's incident, and two assessment answers
    provider = ScriptedProvider([response(tool_calls=orient), response(tool_calls=finish), invalid, invalid])
    with caplog.at_level(logging.DEBUG):
        result = run_agent_phase(Settings(home=tmp_path), repo, "h1", provider=provider,
                                 toolbox_factory=lambda session: Toolbox(repo, "h1", session_id=session),
                                 clock=lambda: 0.0)
    rows = repo.agent_tool_calls("h1", session_id=repo.agent_sessions("h1", purpose="orient")[0]["id"])
    assert [row["refusal_reasons"] for row in rows] == [
        ["summary: string_too_short"], ["*: extra_forbidden"], ["entities[]: alias_not_issued"],
        ["statement: type_mismatch", "*: unexpected_property"], None]
    assess = [row for row in repo.model_calls(hunt_id="h1") if row["purpose"] == "assess"]
    assert len(assess) == 2 and all(not row["validation"]["ok"] for row in assess)
    assert assess[0]["validation"]["reasons"] == ["overall: list_type", "key_steps: missing", "narrative: missing", "confidence: missing",
                                                  "alternatives: missing", "gaps: missing",
                                                  "next_checks: missing", "*: extra_forbidden"]
    expected = {"assessment": {"*: extra_forbidden": 2, "alternatives: missing": 2, "confidence: missing": 2,
                               "gaps: missing": 2, "key_steps: missing": 2, "narrative: missing": 2, "next_checks: missing": 2,
                               "overall: list_type": 2},
                "finish_session": {"summary: string_too_short": 1},
                "open_hypothesis": {"*: extra_forbidden": 1, "*: unexpected_property": 1,
                                    "entities[]: alias_not_issued": 1, "statement: type_mismatch": 1}}
    assert repo.agent_refusal_counts("h1") == {"by_tool": expected}
    assert result.as_dict()["refusals"] == {"by_tool": expected}
    audit = repo.latest_audit("h1", "hunt.ai_agent_summary")["detail"]
    assert audit["refusals"] == {"by_tool": expected}
    # the values stay where the model's own output is kept by design (arguments, raw replies), and nowhere else
    stored = json.dumps([[row["refusal_reasons"] for row in rows], [row["validation"] for row in assess], audit],
                        default=str)
    assert SENTINEL not in stored and SENTINEL not in caplog.text
    # the retry message the model reads names fields and error types only
    retry = provider.requests[-1].messages[-1]["content"]
    assert "overall: list_type" in retry and SENTINEL not in retry


def test_an_assessment_check_that_fails_still_records_the_billed_call(tmp_path, monkeypatch):
    from romulus.agent import assessment
    from romulus.agent.provider import AgentBudget, BudgetLimits
    repo = _hunt(tmp_path)
    body = {"overall": [], "key_steps": [], "narrative": [], "confidence": {"overall": "low", "reasons": []}, "alternatives": [],
            "gaps": [], "next_checks": []}

    def broken(*_a, **_kw):
        raise RuntimeError("store unavailable")
    monkeypatch.setattr(assessment, "check_assessment", broken)
    settings = Settings(home=tmp_path)
    budget = AgentBudget(BudgetLimits.from_settings(settings), clock=lambda: 0.0)
    with pytest.raises(RuntimeError, match="store unavailable"):
        assessment.run_assessment(settings, repo, "h1", ScriptedProvider([response(parsed=body)]), budget)
    rows = [row for row in repo.model_calls(hunt_id="h1") if row["purpose"] == "assess"]
    assert len(rows) == 1 and rows[0]["validation"]["reasons"] == ["$: check_failed"]


def test_triage_drop_reasons_are_paths_and_types():
    assert all(is_reason(item) for item in DROP_REASONS.values())


def test_the_web_panel_shows_refusal_counts_by_tool_and_reason_without_values(setup):  # noqa: F811
    client, repo, _cid, _settings, _app, _password = setup
    run_row(repo)
    now = utcnow()
    repo.save_agent_session({"id": "as-1", "hunt_id": "h1", "hypothesis_id": None, "purpose": "orient",
                             "state": "finished", "tool_calls": 2, "summary": "", "started_at": now, "ended_at": now})
    for seq, (name, reasons) in enumerate((("finish_session", ["summary: string_too_short"]),
                                           ("finish_session", ["summary: string_too_short"]),
                                           ("open_hypothesis", ["*: extra_forbidden"])), 1):
        repo.save_agent_tool_call({"id": f"atc-{seq}", "hunt_id": "h1", "session_id": "as-1", "seq": seq,
                                   "name": name, "arguments": {"summary": SENTINEL, SENTINEL: SENTINEL},
                                   "arguments_truncated": False, "status": "refused", "result_digest": "d",
                                   "refusal_reasons": reasons, "model_call_id": None, "created_at": now})
    body = client.get("/hunts/h1/run").text
    assert "Refused model calls" in body
    assert "<td>finish_session</td><td><code>summary: string_too_short</code></td><td>2</td>" in body
    assert "<td>open_hypothesis</td><td><code>*: extra_forbidden</code></td><td>1</td>" in body
    assert SENTINEL not in body
