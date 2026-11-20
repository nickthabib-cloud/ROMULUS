"""The agent's secret guard: doctor's weak-secret warning, a guard trip that ends its session cleanly and is audited by
setting and part, redaction counts per setting, and their display on Run details. A sentinel secret value is checked
never to reach a stored row, the audit, a log line or a rendered page."""
import json
import logging

import pytest
from sqlalchemy import select

from romulus.agent.assessment import run_assessment
from romulus.agent.investigate import _BudgetGate, _prompt_set, _run_session, run_agent_phase
from romulus.agent.provider import (
    SECRET_GUARD_ACTION,
    AgentBudget,
    BudgetLimits,
    ChatRequest,
    HistoryError,
    SecretGuardTripped,
    record_call,
)
from romulus.agent.provider.base import ToolCall, redact_messages
from romulus.agent.toolbox import Toolbox
from romulus.config import Settings, redact_counted
from romulus.doctor import check_secret_strength
from romulus.store import schema as t
from romulus.store.db import make_engine, migrate, utcnow
from romulus.store.repo import Repo
from tests import test_web_agent_a6
from tests.agent_scripted import ScriptedProvider, response

# a made-up value: no product source, template or test fixture holds it
SENTINEL = "Qv7-sentinel-Zr41"
DICTIONARY_WORD = "telescopes"
RANDOM_32 = "q7Zx3LmP9vRt2WbN8cKd4HfJ6sYg1QeA"
setup = test_web_agent_a6.setup


def _repo(tmp_path, name="guard"):
    engine = make_engine(tmp_path / f"{name}.sqlite")
    migrate(engine)
    repo = Repo(engine)
    repo.create_hunt("h1", {"window": {}, "targets": [], "ai_agent": {"requested": True}}, "d", "test")
    repo.set_hunt_state("h1", "running")
    repo.set_hunt_state("h1", "completed_within_scope", detection_result="leads_only", stop_reason="scope")
    return engine, repo


def _every_stored_value(engine) -> str:
    """Every row of every table, as text."""
    out = []
    with engine.connect() as connection:
        for table in t.metadata.sorted_tables:
            out += [json.dumps(dict(row), default=str) for row in connection.execute(select(table)).mappings()]
    return "\n".join(out)


# ---- doctor ----------------------------------------------------------------------------------------------------

def test_doctor_warns_about_a_dictionary_like_secret_by_name_only(tmp_path, caplog, capsys):
    caplog.set_level(logging.DEBUG)
    check = check_secret_strength(Settings(home=tmp_path, arkime_password=DICTIONARY_WORD), source_root=tmp_path)
    assert check.status == "warn"
    assert "ARKIME_PASSWORD (under 16 characters)" in check.detail
    assert "easier to guess" in check.detail and "before the AI model sees it" in check.detail
    assert "the session goes on rather than ending" in check.detail and "at a real site" in check.detail
    assert check.data == {"settings": ["ARKIME_PASSWORD"]}
    shown = check.detail + json.dumps(check.data) + caplog.text + "".join(capsys.readouterr())
    assert DICTIONARY_WORD not in shown.lower() and str(len(DICTIONARY_WORD)) not in check.detail


def test_doctor_warns_about_a_secret_the_product_source_holds_as_a_word(tmp_path):
    # mixed classes and enough characters for the entropy measure: only the source measure finds it
    value = "Lantern_Beacon_Q7x"
    (tmp_path / "page.html").write_text(f"<p>the {value.upper()} label</p>", encoding="utf-8")
    check = check_secret_strength(Settings(home=tmp_path, es_password=value), source_root=tmp_path)
    assert check.status == "warn" and check.data == {"settings": ["ES_PASSWORD"]} and value not in check.detail
    # part of a longer word is not a whole word
    (tmp_path / "page.html").write_text(f"<p>x{value}y</p>", encoding="utf-8")
    assert check_secret_strength(Settings(home=tmp_path, es_password=value), source_root=tmp_path).status == "ok"
    # the product's own package is the default source: a word from it is found
    assert check_secret_strength(Settings(home=tmp_path, es_password="check_secret_strength")).status == "warn"


def test_doctor_does_not_warn_about_a_random_32_character_secret(tmp_path):
    check = check_secret_strength(Settings(home=tmp_path, arkime_password=RANDOM_32, es_api_key=RANDOM_32[::-1]))
    assert check.status == "ok" and RANDOM_32 not in check.detail
    assert check_secret_strength(Settings(home=tmp_path)).status == "ok"


# ---- redaction counts --------------------------------------------------------------------------------------------

def test_redaction_counts_name_the_setting_and_count_only_what_a_request_adds():
    s = Settings(arkime_password=SENTINEL)
    counts: dict = {}
    assert redact_counted(f"a {SENTINEL} b {json.dumps(SENTINEL)}", s, counts) == 'a <redacted> b "<redacted>"'
    assert counts == {"ARKIME_PASSWORD": 2}
    history = [{"role": "system", "content": "hunt"}, {"role": "user", "content": f"rec {SENTINEL} {SENTINEL}"},
               {"role": "assistant", "content": f"seen {SENTINEL}"},
               {"role": "tool", "tool_call_id": "c1", "content": json.dumps({"url": f"/x?{SENTINEL}"})}]
    first: dict = {}
    redact_messages(history[:2], s, first)
    later: dict = {}
    sent = redact_messages(history, s, later)
    assert first == {"ARKIME_PASSWORD": 2} and later == {"ARKIME_PASSWORD": 1}
    assert SENTINEL not in json.dumps(sent)
    # the product's own instructions are redacted too but are not telemetry: never counted
    instructions: dict = {}
    sent = redact_messages([{"role": "system", "content": f"never {SENTINEL}"}, history[1]], s, instructions)
    assert instructions == {"ARKIME_PASSWORD": 2} and SENTINEL not in json.dumps(sent)


def test_redaction_counts_are_recorded_per_call_and_summed_in_usage(tmp_path, caplog):
    pytest.importorskip("anthropic")
    from tests.test_agent_provider_claude import (
        THINKING,
        TOOL,
        Endpoint,
        claude_settings,
        provider,
        reply,
        text,
        tool_use,
    )
    caplog.set_level(logging.DEBUG)
    engine, repo = _repo(tmp_path, "redactions")
    settings = claude_settings(arkime_password=SENTINEL)
    p, _ = provider(settings, Endpoint(reply([THINKING, text("Reading."), tool_use()], stop="tool_use"),
                                       reply([text("done")])))
    limits = BudgetLimits.from_settings(settings)
    first = ChatRequest([{"role": "user", "content": f"GET /reset?pw={SENTINEL} and {SENTINEL}"}], tools=[TOOL])
    result = p.chat(first)
    assert result.redactions == {"ARKIME_PASSWORD": 2}
    record_call(repo, p, hunt_id="h1", purpose="investigate", request=first, result=result, limits=limits,
                session_id=None)
    second = ChatRequest([*first.messages, result.assistant_message(),
                          {"role": "tool", "tool_call_id": "toolu_01", "content": f"user {SENTINEL} changed"}],
                         tools=[TOOL])
    result = p.chat(second)
    assert result.redactions == {"ARKIME_PASSWORD": 1}
    record_call(repo, p, hunt_id="h1", purpose="investigate", request=second, result=result, limits=limits)
    assert [row["options"].get("redactions") for row in repo.model_calls("h1")] == [
        {"ARKIME_PASSWORD": 2}, {"ARKIME_PASSWORD": 1}]
    assert repo.agent_usage("h1")["redactions"] == {"ARKIME_PASSWORD": 3}
    # a call without replacements adds nothing, and a hunt without any has no redactions key
    assert "redactions" not in Repo(_repo(tmp_path, "clean")[0]).agent_usage("h1")
    assert SENTINEL not in _every_stored_value(engine) and SENTINEL not in caplog.text
    engine.dispose()


# ---- a guard trip ------------------------------------------------------------------------------------------------

def test_a_guard_trip_ends_the_session_cleanly_keeps_its_writes_and_audits_names_only(tmp_path, caplog):
    pytest.importorskip("anthropic")
    from tests.test_agent_provider_claude import Endpoint, claude_settings, provider, reply, text, tool_use
    caplog.set_level(logging.DEBUG)
    engine, repo = _repo(tmp_path)
    settings = claude_settings(arkime_password=SENTINEL, home=tmp_path)
    # the model writes the secret's text in its own thinking and in a write: the signed turn can be neither redacted
    # nor sent again, and the write is run and stored with the text removed
    thinking = {"type": "thinking", "thinking": f"The account change set {SENTINEL} as the password.",
                "signature": "EqQBCkgIBhABGAIiQL+signature/A=="}
    opened = tool_use(json.dumps({"statement": f"Review the account change to {SENTINEL} on the web host",
                                  "techniques": [],
                                  "entities": [], "supporting": [], "questions": ["Who?"]}), name="open_hypothesis")
    endpoint = Endpoint(reply([thinking, text("Opening a hypothesis."), opened], stop="tool_use"),
                        reply([text("never sent")]))
    p, _ = provider(settings, endpoint)
    budget = AgentBudget.from_usage(BudgetLimits.from_settings(settings), repo.agent_usage("h1"), clock=lambda: 0.0)
    gate = _BudgetGate(budget, settings)

    outcome = _run_session(settings, repo, "h1", p, gate, lambda session: Toolbox(repo, "h1", session_id=session),
                           _prompt_set(), purpose="orient")

    assert len(endpoint.calls) == 1                        # the turn holding the secret was never sent back
    assert outcome["state"] == "secret_guard" and outcome["reason"] == "secret_guard"
    assert gate.tokens == 0 and gate.calls == 0            # the reservation was settled
    session = repo.agent_sessions("h1")[-1]
    assert session["state"] == "secret_guard" and session["ended_at"] is not None
    assert session["summary"].startswith("Secret guard:") and "ARKIME_PASSWORD" in session["summary"]
    assert "open_hypothesis: complete" in session["summary"]
    assert [row["statement"] for row in repo.agent_hypotheses("h1")] == [
        "Review the account change to <redacted> on the web host"]
    events = [row["detail"] for row in repo.audit_trail("h1", SECRET_GUARD_ACTION)[0]]
    assert events == [{"setting": "ARKIME_PASSWORD", "part": part, "session_id": session["id"],
                       "purpose": "orient", "message_index": 2}
                      for part in ("thinking", "tool_input_parsed", "tool_input_streamed")]
    assert repo.agent_secret_guard_counts("h1") == {"ARKIME_PASSWORD": 1}
    assert SENTINEL not in _every_stored_value(engine) and SENTINEL not in caplog.text
    engine.dispose()


@pytest.mark.parametrize("blocks, part", [
    (lambda s, text, tool_use: [text(f"the password is {s}"), tool_use()], "text"),
    (lambda s, text, tool_use: [text("Lead."), tool_use(json.dumps({"ok": True, "n": s}))], "tool_input_streamed"),
])
def test_the_trip_names_the_setting_and_part_and_is_still_a_history_error(blocks, part):
    pytest.importorskip("anthropic")
    from tests.test_agent_provider_claude import (
        THINKING,
        TOOL,
        Endpoint,
        claude_settings,
        provider,
        reply,
        text,
        tool_use,
    )
    settings = claude_settings(es_password=SENTINEL)
    first, _ = provider(settings, Endpoint(reply([THINKING, *blocks(SENTINEL, text, tool_use)], stop="tool_use")))
    message = first.chat(ChatRequest([{"role": "user", "content": "go"}], tools=[TOOL])).assistant_message()
    endpoint = Endpoint(reply([text("x")]))
    p, _ = provider(settings, endpoint)
    with pytest.raises(SecretGuardTripped) as exc:
        p.chat(ChatRequest([{"role": "user", "content": "go"}, message,
                            {"role": "tool", "tool_call_id": "toolu_01", "content": "ok"}], tools=[TOOL]))
    assert isinstance(exc.value, HistoryError) and endpoint.calls == []
    assert ("ES_PASSWORD", part) in exc.value.trips and exc.value.message_index == 1
    assert SENTINEL not in str(exc.value) and "ES_PASSWORD" in str(exc.value)


def test_after_a_trip_the_run_continues_its_other_sessions_and_the_assessment(tmp_path):
    engine, repo = _repo(tmp_path, "phase")
    repo.save_candidate({
        "id": "c1", "hunt_id": "h1", "rule_id": "host.test", "rule_version": "1",
        "claim": "a deterministic process execution finding", "claim_type": "observed_action",
        "event_ids": [], "context_event_ids": [], "predicate_fields": [], "entities": [], "ts": utcnow(),
        "severity": "high", "confidence": "high", "lane": "high", "priority": 2.0,
        "priority_reasons": [], "gate_results": {}, "benign_alternatives": [], "next_checks": [],
        "group_key": "c1", "source_case_id": None, "source_anchor_id": None, "source_link_id": None,
    })
    opens = [ToolCall("o1", "open_hypothesis", {"statement": "Review the first incident hypothesis"}, "{}"),
             ToolCall("o2", "open_hypothesis", {"statement": "Review an alternate incident hypothesis"}, "{}"),
             ToolCall("of", "finish_session", {"summary": "The initial review is complete."}, "{}")]
    read = [ToolCall("r1", "list_findings", {}, "{}")]
    finish = [ToolCall("f", "finish_session", {"summary": "The evidence review is complete."}, "{}")]
    body = {"overall": [], "key_steps": [], "narrative": [], "confidence": {"overall": "low", "reasons": []},
            "alternatives": [], "gaps": [], "next_checks": []}
    trip =SecretGuardTripped(3, [("ARKIME_PASSWORD", "text")])
    provider = ScriptedProvider([response(tool_calls=opens), response(tool_calls=read), trip,
                                 response(tool_calls=finish), response(parsed=body)])

    result = run_agent_phase(Settings(home=tmp_path, agent_concurrency=1), repo, "h1", provider=provider,
                             toolbox_factory=lambda session: Toolbox(repo, "h1", session_id=session),
                             clock=lambda: 0.0)

    sessions = repo.agent_sessions("h1")
    assert [(row["purpose"], row["state"]) for row in sessions] == [
        ("orient", "finished"), ("investigate", "secret_guard"), ("investigate", "finished"), ("assess", "finished")]
    assert result.state == "partial" and "secret_guard" in result.reason
    assert repo.agent_assessments("h1")[-1]["source"] == "agent"
    assert result.as_dict()["secret_guard"] == {"ARKIME_PASSWORD": 1}
    summary = repo.latest_audit("h1", "hunt.ai_agent_summary")["detail"]
    assert summary["secret_guard"] == {"ARKIME_PASSWORD": 1}
    engine.dispose()


def test_the_session_state_migration_round_trips(tmp_path):
    from alembic import command

    from tests.test_local_content_migration import config
    engine, repo = _repo(tmp_path, "migration")
    repo.save_agent_session({"id": "s1", "hunt_id": "h1", "hypothesis_id": None, "purpose": "orient",
                             "state": "secret_guard", "tool_calls": 0, "summary": "", "started_at": utcnow(),
                             "ended_at": utcnow()})
    with engine.begin() as connection:
        command.downgrade(config(connection), "0042")
    assert repo.agent_sessions("h1")[0]["state"] == "failed"
    with engine.begin() as connection:
        command.upgrade(config(connection), "head")
    repo.update_agent_session("s1", "h1", {"state": "secret_guard"})
    assert repo.agent_sessions("h1")[0]["state"] == "secret_guard"
    with engine.connect() as connection:
        assert connection.exec_driver_sql("PRAGMA foreign_key_check").all() == []
    engine.dispose()


# ---- Run details -------------------------------------------------------------------------------------------------

def test_run_details_show_redaction_and_guard_counts_by_setting_name(setup):
    client, repo, *_ = setup
    test_web_agent_a6.run_row(repo, state="partial", reason="secret_guard")
    assert 'id="secret-guard"' not in client.get("/hunts/h1/run").text
    repo.save_model_call({"id": "mc-r1", "hunt_id": "h1", "purpose": "investigate", "model": "m",
                          "options": {"redactions": {"ARKIME_PASSWORD": 23, "<b>bad</b>": 2}},
                          "prompt_digest": "d", "status": "ok", "provider": "scripted",
                          "endpoint_host": "scripted", "egress": "local", "model_reported": "m"})
    for session in ("as-1", "as-2"):
        for part in ("thinking", "text"):
            repo.audit("system", SECRET_GUARD_ACTION, "h1", {"setting": "ARKIME_PASSWORD", "part": part,
                                                             "session_id": session, "purpose": "investigate",
                                                             "message_index": 4})
    html = client.get("/hunts/h1/run").text
    block = html.split('id="secret-guard"', 1)[1].split("</section>", 1)[0]
    assert '<span class="mono">ARKIME_PASSWORD</span> 23 replacements' in block
    assert '<span class="mono">?</span> 2 replacements' in block and "<b>bad</b>" not in html
    assert '<span class="mono">ARKIME_PASSWORD</span> 2 sessions' in block
    assert "romulus doctor" in block


def test_after_a_real_trip_no_page_shows_the_secret_and_run_details_count_it(setup, caplog):
    pytest.importorskip("anthropic")
    from tests.test_agent_provider_claude import Endpoint, claude_settings, provider, reply, text, tool_use
    caplog.set_level(logging.DEBUG)
    client, repo, *_ = setup
    test_web_agent_a6.run_row(repo, state="partial", reason="secret_guard")
    settings = claude_settings(arkime_password=SENTINEL)
    thinking = {"type": "thinking", "thinking": f"The reset set {SENTINEL}.",
                "signature": "EqQBCkgIBhABGAIiQL+signature/A=="}
    opened = tool_use(json.dumps({"statement": f"Review the password reset to {SENTINEL} on the web host",
                                  "techniques": [], "entities": [], "supporting": [], "questions": ["Who?"]}),
                      name="open_hypothesis")
    endpoint = Endpoint(reply([thinking, text(f"Opening {SENTINEL}."), opened], stop="tool_use"), reply([text("x")]))
    p, _ = provider(settings, endpoint)
    budget = AgentBudget.from_usage(BudgetLimits.from_settings(settings), repo.agent_usage("h1"), clock=lambda: 0.0)
    # the dossier the model is shown holds the secret's text once (a finding's claim), so redaction counts it
    with repo.engine.begin() as connection:
        connection.execute(t.candidate.update().values(claim=f"Password reset to {SENTINEL} observed"))
    outcome = _run_session(settings, repo, "h1", p, _BudgetGate(budget, settings),
                           lambda session: Toolbox(repo, "h1", session_id=session), _prompt_set(), purpose="orient")
    assert outcome["state"] == "secret_guard" and len(endpoint.calls) == 1
    assert SENTINEL not in endpoint.calls[0].content.decode()
    assert repo.agent_usage("h1").get("redactions", {}).get("ARKIME_PASSWORD", 0) >= 1
    # the deterministic finding keeps its text: only what the model wrote is stored without it
    with repo.engine.begin() as connection:
        connection.execute(t.candidate.update().values(claim="Password reset observed"))
    pages = [client.get(f"/hunts/h1{suffix}").text for suffix in (
        "", "/run", "/findings", "/assessment", "/hypotheses", "/agent/notes", "/agent/findings")]
    hid = repo.agent_hypotheses("h1")[0]["id"]
    pages.append(client.get(f"/hunts/h1/hypotheses/{hid}").text)
    assert all(SENTINEL not in page for page in pages) and SENTINEL not in caplog.text
    block = pages[1].split('id="secret-guard"', 1)[1].split("</section>", 1)[0]
    assert '<span class="mono">ARKIME_PASSWORD</span> 1 session' in block and "replacement" in block


# ---- the assessment ----------------------------------------------------------------------------------------------

def _assess_with_claude(repo, tmp_path, *replies):
    from tests.test_agent_provider_claude import Endpoint, claude_settings, provider
    settings = claude_settings(arkime_password=SENTINEL, home=tmp_path)
    endpoint = Endpoint(*replies)
    p, _ = provider(settings, endpoint)
    budget = AgentBudget.from_usage(BudgetLimits.from_settings(settings), repo.agent_usage("h1"), clock=lambda: 0.0)
    return run_assessment(settings, repo, "h1", p, budget, clock=lambda: 0.0), endpoint


def test_an_assessment_retry_that_would_replay_the_secret_ends_in_secret_guard(setup, tmp_path, caplog):
    pytest.importorskip("anthropic")
    from tests.test_agent_provider_claude import reply, text
    caplog.set_level(logging.DEBUG)
    client, repo, *_ = setup
    test_web_agent_a6.run_row(repo, state="partial", reason="secret_guard")
    # an answer that fails validation and holds the secret's text: its retry would replay it
    broken = json.dumps({"overall": f"The reset set {SENTINEL}."})
    result, endpoint = _assess_with_claude(repo, tmp_path, reply([text(broken)]), reply([text("{}")]))
    assert result is None and len(endpoint.calls) == 1
    session = repo.agent_sessions("h1", purpose="assess")[-1]
    assert session["state"] == "secret_guard" and session["summary"].startswith("secret_guard: ")
    assert "ARKIME_PASSWORD" in session["summary"]
    events = [row["detail"] for row in repo.audit_trail("h1", SECRET_GUARD_ACTION)[0]]
    assert events == [{"setting": "ARKIME_PASSWORD", "part": "text", "session_id": session["id"],
                       "purpose": "assess", "message_index": 2}]
    pages = [client.get(f"/hunts/h1{suffix}").text for suffix in ("", "/run", "/assessment")]
    assert SENTINEL not in _every_stored_value(repo.engine) and SENTINEL not in caplog.text
    assert all(SENTINEL not in page for page in pages)


def test_a_stored_assessment_and_its_narrative_never_hold_the_secret(setup, tmp_path, caplog):
    pytest.importorskip("anthropic")
    from romulus.agent.aliases import AliasBook
    from romulus.report import markdown
    from romulus.report.manifest import build_manifest
    from tests.test_agent_provider_claude import reply, text
    caplog.set_level(logging.DEBUG)
    client, repo, *_ = setup
    test_web_agent_a6.run_row(repo)
    alias = AliasBook(repo, "h1").alias_for("E", "ev1")
    body = {"overall": [{"text": f"The account reset to {SENTINEL} is the lead.", "cites": [alias],
                         "kind": "hypothesis"}],
            "key_steps": [], "confidence": {"overall": "medium", "reasons": []},
            "narrative": [{"time_span": {"start": "", "end": ""}, "phase": "Credential Access", "sentences": [
                {"text": f"The recorded process set the password {SENTINEL} on web01.", "cites": [alias],
                 "kind": "observed"}]}],
            "alternatives": [], "gaps": [], "next_checks": []}
    result, endpoint = _assess_with_claude(repo, tmp_path, reply([text(json.dumps(body))]))
    assert result is not None and len(endpoint.calls) == 1
    stored = repo.agent_assessments("h1")[-1]["body"]
    assert stored["narrative"][0]["sentences"][0]["text"] == "The recorded process set the password <redacted> on web01."
    assert stored["overall"][0]["text"] == "The account reset to <redacted> is the lead."
    manifest = build_manifest(repo, "h1", "test")
    manifest["revision"] = {"number": 1, "id": "h1-r1", "supersedes": None}
    report = markdown.render(manifest)
    assert "<redacted>" in report or "\\<redacted\\>" in report
    pages = [client.get(f"/hunts/h1{suffix}").text for suffix in ("", "/assessment", "/run")]
    assert SENTINEL not in _every_stored_value(repo.engine) and SENTINEL not in caplog.text
    assert SENTINEL not in report and SENTINEL not in json.dumps(manifest, default=str)
    assert all(SENTINEL not in page for page in pages)


def test_an_assess_trip_stores_the_template_with_the_secret_guard_reason(tmp_path):
    engine, repo = _repo(tmp_path, "assess-trip")
    provider = ScriptedProvider([SecretGuardTripped(2, [("ES_PASSWORD", "text")])])
    result = run_agent_phase(Settings(home=tmp_path), repo, "h1", provider=provider,
                             toolbox_factory=lambda session: Toolbox(repo, "h1", session_id=session),
                             clock=lambda: 0.0)
    assert [(row["purpose"], row["state"]) for row in repo.agent_sessions("h1")] == [("assess", "secret_guard")]
    template = repo.agent_assessments("h1")[-1]
    assert template["source"] == "template"
    assert result.state == "partial" and "secret_guard" in result.reason
    assert result.as_dict()["secret_guard"] == {"ES_PASSWORD": 1}
    from romulus.agent.assessment import template_assessment
    assert "(secret_guard)" in template_assessment(repo, "h1", "secret_guard")["header"]
    engine.dispose()


# ---- the triage pass ---------------------------------------------------------------------------------------------

def _web_client(monkeypatch, tmp_path, repo):
    import secrets as random

    from fastapi.testclient import TestClient

    from romulus.web import app as web
    from romulus.web.auth import create_user
    monkeypatch.setattr(web, "open_repo", lambda _: repo)
    app = web.create_app(Settings(home=tmp_path, secret_key=random.token_urlsafe(32)), tmp_path / "settings.env")
    password = random.token_urlsafe(20)
    create_user(repo.engine, "lead", password, "lead")
    client = TestClient(app)
    client.post("/login", data={"username": "lead", "password": password})
    return client


def test_triage_verdicts_are_stored_exported_reported_and_shown_without_the_secret(tmp_path, monkeypatch, caplog):
    anthropic = pytest.importorskip("anthropic")
    httpx2 = pytest.importorskip("httpx2")
    assert anthropic
    from romulus.agent.triage import DATA_BEGIN, DATA_END, run_triage_pass
    from romulus.hunt.triage import write_export
    from romulus.report.manifest import build_manifest
    from romulus.report.markdown import render
    from tests import test_ai_triage
    from tests.test_agent_provider_claude import MODEL_INFO, claude_settings, provider, reply, text
    caplog.set_level(logging.DEBUG)
    engine = make_engine(tmp_path / "triage.sqlite")
    migrate(engine)
    repo = test_ai_triage._hunt(filler=12, repo=Repo(engine))
    requests = []

    def endpoint(request):
        if request.url.path.startswith("/v1/models"):
            return httpx2.Response(200, json=MODEL_INFO)
        requests.append(request.content.decode())
        body = json.loads(request.content)
        user = body["messages"][0]["content"]
        user = user if isinstance(user, str) else "".join(block.get("text", "") for block in user)
        cards = json.loads(user[user.index(DATA_BEGIN + "\n") + len(DATA_BEGIN) + 1:user.index("\n" + DATA_END)])
        # a label holding the secret's text is cleared (its verdict kept and counted); the others keep a plain
        # label, and every rationale holds the text
        answer = {"groups": [test_ai_triage.verdict(card, "likely_attack",
                                                    label=f"reset-{SENTINEL.lower()}" if i == 0 else "web-chain",
                                                    rationale=f"The account was set to {SENTINEL} here.")
                             for i, card in enumerate(cards["cards"])]}
        return httpx2.Response(200, headers={"content-type": "text/event-stream"},
                               content=reply([text(json.dumps(answer))]))

    settings = claude_settings(arkime_password=SENTINEL.lower(), es_password=SENTINEL, home=tmp_path,
                               stage_dir=tmp_path / "stage",
                               agent_triage_promote_per_lane=2, agent_triage_call_input_tokens=4000,
                               agent_triage_call_output_tokens=2048)
    p, _ = provider(settings, endpoint)
    summary = run_triage_pass(settings, repo, "h1", p)
    assert summary["dropped"] == {"redacted_incident_label": len(requests)}
    assert summary["groups"]["triaged"] == summary["groups"]["eligible"]          # no verdict was lost
    with engine.connect() as connection:
        rows = [dict(row) for row in connection.execute(select(t.ai_triage_group)).mappings()]
    with_verdict = [row for row in rows if row["rationale"]]
    assert with_verdict and all(row["rationale"] == "The account was set to <redacted> here." for row in with_verdict)
    assert {row["incident_label"] for row in with_verdict} == {"web-chain", None}
    assert sum(row["incident_label"] is None for row in with_verdict) == len(requests)
    written = repo.agent_usage("h1")["output_redactions"]
    assert written["ES_PASSWORD"] >= len(with_verdict) and written["ARKIME_PASSWORD"] == len(requests)
    write_export(repo, "h1", tmp_path / "order.json")
    manifest = build_manifest(repo, "h1", "test")
    report = render({**manifest, "revision": {"number": 1, "id": "r1", "supersedes": None}})
    assert "The account was set to" in report
    client = _web_client(monkeypatch, tmp_path, repo)
    page = client.get("/hunts/h1/triage").text
    assert "The account was set to &lt;redacted&gt; here." in page
    run = client.get("/hunts/h1/run").text
    assert '<span class="mono">ES_PASSWORD</span>' in run.split('id="secret-guard"', 1)[1]
    shown = [_every_stored_value(engine), (tmp_path / "order.json").read_text(encoding="utf-8"), report,
             json.dumps(manifest, default=str), page, run, caplog.text, *requests]
    assert all(SENTINEL not in item and SENTINEL.lower() not in item for item in shown)
    engine.dispose()


def test_no_write_tool_ever_receives_the_secret_and_no_stored_call_holds_it(tmp_path, caplog):
    caplog.set_level(logging.DEBUG)
    engine, repo = _repo(tmp_path, "writes")
    settings = Settings(home=tmp_path, arkime_password=SENTINEL)
    now = utcnow()
    repo.save_agent_hypothesis({"id": "hyp-1", "hunt_id": "h1", "statement": "Review the account change here",
                                "techniques": [], "entity_ids": [], "status": "open", "confidence": "low",
                                "questions": ["q"], "created_session_id": None, "sessions_run": 0,
                                "created_at": now, "updated_at": now})
    received: list = []

    class Spy(Toolbox):
        def execute(self, name, arguments):
            received.append((name, arguments))
            return super().execute(name, arguments)

    def writes(request):
        hypothesis = json.loads(request.messages[1]["content"])["hypothesis"]["alias"]
        said = f"The account was set to {SENTINEL} on web01."
        return response(tool_calls=[
            ToolCall("w1", "add_note", {"target": hypothesis, "text": said, "cites": []}, "{}"),
            ToolCall("w2", "update_hypothesis", {"hypothesis": hypothesis, "questions": [said], "note": said}, "{}"),
            ToolCall("w3", "propose_finding", {"claim": said, "claim_kind": "account_change", "cites": ["E1"],
                                               "lane": "lead", "rationale": said}, "{}"),
            ToolCall("w4", "propose_link", {"from": "F1", "to": "F2", "relation": "related", "cites": ["F1"],
                                            "rationale": said}, "{}"),
            ToolCall("w5", "request_rule", {"pattern_description": said, "cites": ["E1"]}, "{}"),
            ToolCall("w6", "finish_session", {"summary": said}, json.dumps({"summary": said}))])
    budget = AgentBudget.from_usage(BudgetLimits.from_settings(settings), repo.agent_usage("h1"), clock=lambda: 0.0)
    outcome = _run_session(settings, repo, "h1", ScriptedProvider([writes]), _BudgetGate(budget, settings),
                           lambda session: Spy(repo, "h1", session_id=session), _prompt_set(),
                           purpose="investigate", hypothesis=repo.agent_hypotheses("h1")[0])
    assert [name for name, _ in received] == ["add_note", "update_hypothesis", "propose_finding", "propose_link",
                                              "request_rule", "finish_session"]
    assert all(SENTINEL not in json.dumps(arguments) and "<redacted>" in json.dumps(arguments)
               for _, arguments in received)
    assert outcome["state"] == "finished" and outcome["summary"] == "The account was set to <redacted> on web01."
    assert repo.agent_notes("h1") and all("<redacted>" in row["text"] for row in repo.agent_notes("h1"))
    assert SENTINEL not in _every_stored_value(engine) and SENTINEL not in caplog.text
    engine.dispose()


def test_an_error_quoting_the_model_is_stored_redacted(tmp_path, caplog):
    pytest.importorskip("anthropic")
    from tests.test_agent_provider_claude import (
        TOOL,
        Endpoint,
        claude_settings,
        provider,
        reply,
        text,
        tool_use,
    )
    caplog.set_level(logging.DEBUG)
    engine, repo = _repo(tmp_path, "error")
    # the model calls a tool it was never offered, named after the secret: the error names the tool
    made_up = "x" + SENTINEL.replace("-", "_")
    secret = made_up[1:]
    settings = claude_settings(arkime_password=secret)
    p, _ = provider(settings, Endpoint(reply([text("Calling."), tool_use(name=made_up)], stop="tool_use")))
    request = ChatRequest([{"role": "user", "content": "go"}], tools=[TOOL])
    result = p.chat(request)
    assert result.status == "invalid_tool_call" and secret not in result.error and "<redacted>" in result.error
    record_call(repo, p, hunt_id="h1", purpose="investigate", request=request, result=result,
                limits=BudgetLimits.from_settings(settings))
    stored = repo.model_calls("h1")[0]
    assert any("<redacted>" in error for error in stored["validation"]["errors"])
    assert stored["options"]["output_redactions"] == {"ARKIME_PASSWORD": 1}       # the stored call's name
    assert secret not in _every_stored_value(engine) and secret not in caplog.text
    engine.dispose()


def test_a_redacted_triage_label_is_cleared_and_counted_and_its_verdict_kept():
    from romulus.agent.triage import validate
    item = {"group_id": "G1", "assessment": "likely_attack", "rationale": "Evidence on the card.", "cites": ["c1"]}
    verdicts, drops = validate({"groups": [{**item, "incident_label": "reset-<redacted>"},
                                           {**item, "group_id": "G2", "incident_label": "Not A Slug!"},
                                           {**item, "group_id": "G3", "incident_label": "web-chain"}]},
                               {"G1": ["c1"], "G2": ["c1"], "G3": ["c1"]})
    assert verdicts["G1"]["incident_label"] is None and verdicts["G1"]["assessment"] == "likely_attack"
    assert "G2" not in verdicts                               # a label malformed for any other reason still drops
    assert verdicts["G3"]["incident_label"] == "web-chain"
    assert drops == {"redacted_incident_label": 1, "bad_incident_label": 1}


def test_an_invented_tool_name_holding_the_secret_is_never_stored_and_trips_on_replay(setup, caplog):
    pytest.importorskip("anthropic")
    from tests.test_agent_provider_claude import (
        THINKING,
        Endpoint,
        claude_settings,
        provider,
        reply,
        text,
        tool_use,
    )
    caplog.set_level(logging.DEBUG)
    client, repo, *_ = setup
    test_web_agent_a6.run_row(repo, state="partial", reason="secret_guard")
    settings = claude_settings(arkime_password=SENTINEL)
    endpoint = Endpoint(reply([THINKING, text("Calling."), tool_use("{}", name=SENTINEL)], stop="tool_use"),
                        reply([text("never sent")]))
    p, _ = provider(settings, endpoint)
    budget = AgentBudget.from_usage(BudgetLimits.from_settings(settings), repo.agent_usage("h1"), clock=lambda: 0.0)
    outcome = _run_session(settings, repo, "h1", p, _BudgetGate(budget, settings),
                           lambda session: Toolbox(repo, "h1", session_id=session), _prompt_set(), purpose="orient")
    assert outcome["state"] == "secret_guard" and len(endpoint.calls) == 1
    events = [row["detail"] for row in repo.audit_trail("h1", SECRET_GUARD_ACTION)[0]]
    assert ("ARKIME_PASSWORD", "tool_name") in {(event["setting"], event["part"]) for event in events}
    assert [row["name"] for row in repo.agent_tool_calls("h1")] == ["?"]
    assert "?" in repo.agent_refusal_counts("h1")["by_tool"]
    assert "Session stopped after ?: " in outcome["summary"]
    pages = [client.get(f"/hunts/h1{suffix}").text for suffix in ("", "/run", "/hypotheses")]
    assert SENTINEL not in _every_stored_value(repo.engine) and SENTINEL not in caplog.text
    assert all(SENTINEL not in page for page in pages)
