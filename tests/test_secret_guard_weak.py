"""A weak configured secret (short, low-entropy or dictionary-like, by the rule doctor's secrets.strength warning uses)
is redacted where it stands as a word of its own, in a model reply as everywhere else, and never ends an agent
session: its text is replaced before the reply is validated, run, stored, shown or sent back, the replacements are
counted by setting and audited by name. A strong secret's text in a reply still ends the session at the guard. The
weak value is scanned for, as a word, in every stored row, request, log line, page and report."""
import json
import logging
import re

import pytest

from romulus.agent.assessment import run_assessment
from romulus.agent.investigate import _BudgetGate, _prompt_set, _run_session
from romulus.agent.provider import (
    SECRET_GUARD_ACTION,
    WEAK_SECRET_ACTION,
    AgentBudget,
    BudgetLimits,
    ChatRequest,
    SecretGuardTripped,
    record_call,
)
from romulus.agent.provider.base import PROVIDER_STATE
from romulus.agent.toolbox import Toolbox
from romulus.config import Settings, redact_counted, redact_text, weak_secret_names
from romulus.doctor import check_secret_lengths, check_secret_strength
from romulus.store.db import utcnow
from tests import test_web_agent_a6
from tests.test_secret_guard import SENTINEL, _every_stored_value, _repo

# made-up fixture values: a dictionary-like word (one character class) and a longer word that holds it
WEAK = "marmalade"
LONGER = "marmalades"
AS_WORD = re.compile(r"(?<![^\W\d_])" + WEAK + r"(?![^\W\d_])")
SIGNATURE = "EqQBCkgIBhABGAIiQL+signature/A=="
setup = test_web_agent_a6.setup


def _no_weak_word(*texts: str) -> bool:
    return not any(AS_WORD.search(text) for text in texts)


# ---- the classification ----------------------------------------------------------------------------------------

@pytest.mark.parametrize("values", [
    {"arkime_password": WEAK},                                            # one character class
    {"es_password": "es-pass-9876"},                                      # low entropy
    {"es_password": "q7Zx3LmP9vRt2WbN8cKd4HfJ6sYg1QeA"},                  # strong
    {"arkime_password": "Lantern_Beacon_Q7x"},                            # strong unless the source holds it
    {"arkime_password": WEAK, "es_api_key": "q7Zx3LmP9vRt2WbN8cKd4HfJ6sYg1QeA", "agent_api_key": "aaaaaaaaaaaa"},
])
def test_the_weak_secrets_are_the_ones_doctor_warns_about(tmp_path, values):
    s = Settings(home=tmp_path, **values)
    for root in (tmp_path, None):
        check = check_secret_strength(s, source_root=root)
        assert set((check.data or {}).get("settings", [])) == set(weak_secret_names(s, root))
    (tmp_path / "page.html").write_text("<p>the LANTERN_BEACON_Q7X label</p>", encoding="utf-8")
    check = check_secret_strength(s, source_root=tmp_path)
    assert set((check.data or {}).get("settings", [])) == set(weak_secret_names(s, tmp_path))
    assert ("ARKIME_PASSWORD" in weak_secret_names(s, tmp_path)) == ("arkime_password" in values)


def test_a_short_secret_is_weak_and_doctor_names_it_under_secrets_length(tmp_path):
    s = Settings(home=tmp_path, arkime_password="jam9")
    assert weak_secret_names(s) == {"ARKIME_PASSWORD"}
    assert check_secret_lengths(s).status == "warn" and check_secret_strength(s).status == "ok"


def test_the_doctor_message_says_weak_secrets_are_redacted_not_session_ending(tmp_path):
    detail = check_secret_strength(Settings(home=tmp_path, arkime_password=WEAK), source_root=tmp_path).detail
    assert "redacted wherever it appears as a word of its own" in detail
    assert "rather than ending AI sessions" in detail and "replace it with a long random value at a real site" \
        in detail.lower()
    assert WEAK not in detail.lower()


# ---- the matcher ------------------------------------------------------------------------------------------------

def test_a_weak_secret_is_matched_only_as_a_word_of_its_own_and_a_strong_one_anywhere():
    s = Settings(arkime_password=WEAK, es_password=SENTINEL)
    counts: dict = {}
    text = (f"{WEAK}; {LONGER}; un{WEAK}; pw_{WEAK}; {WEAK}42; ({WEAK}); {WEAK.upper()}; "
            f'{json.dumps({"v": WEAK})}; x{SENTINEL}y')
    assert redact_counted(text, s, counts) == (
        '<redacted>; marmalades; unmarmalade; pw_<redacted>; <redacted>42; (<redacted>); MARMALADE; '
        '{"v": "<redacted>"}; x<redacted>y')
    assert counts == {"ARKIME_PASSWORD": 5, "ES_PASSWORD": 1}


def test_a_strong_secret_holding_the_weak_word_is_replaced_whole():
    s = Settings(arkime_password=WEAK, es_password=f"Qv7-{WEAK}-Zr41")
    assert redact_text(f"set Qv7-{WEAK}-Zr41 and {WEAK}", s) == "set <redacted> and <redacted>"


# ---- a Claude endpoint whose replies are built from each request -----------------------------------------------

def _thinking(text: str) -> dict:
    return {"type": "thinking", "thinking": text, "signature": SIGNATURE}


def _endpoint(*steps):
    from tests.test_agent_provider_claude import Endpoint

    class Steps(Endpoint):
        """Each /v1/messages request is answered by the next step: reply bytes, or a function of the request body."""

        def __init__(self):
            super().__init__(b"")
            self.steps = list(steps)

        def __call__(self, request):
            if request.url.path == "/v1/messages":
                step = self.steps.pop(0) if len(self.steps) > 1 else self.steps[0]
                self.replies = [step(json.loads(request.content)) if callable(step) else step]
            return super().__call__(request)

    return Steps()


def _user_text(body: dict) -> str:
    content = body["messages"][0]["content"]
    return content if isinstance(content, str) else "".join(block.get("text", "") for block in content)


def _hypothesis(repo) -> dict:
    now = utcnow()
    repo.save_agent_hypothesis({"id": "hyp-1", "hunt_id": "h1", "statement": "Review the account change here",
                                "techniques": [], "entity_ids": [], "status": "open", "confidence": "low",
                                "questions": ["q"], "created_session_id": None, "sessions_run": 0,
                                "created_at": now, "updated_at": now})
    return repo.agent_hypotheses("h1")[0]


def _weak_session(repo, tmp_path):
    """An investigate session whose first reply writes the weak secret's text in its thinking, its text, a note and a
    proposed finding, and whose second reply finishes with it in the summary."""
    from tests.test_agent_provider_claude import claude_settings, provider, reply, text, tool_use
    said = f"The account was set to {WEAK} on web01; {LONGER} is another word."

    def first(body):
        alias = json.loads(_user_text(body))["hypothesis"]["alias"]
        return reply([_thinking(f"The reset set {WEAK}, not {LONGER}."), text(f"Checking {WEAK} and {LONGER}."),
                      tool_use(json.dumps({"target": alias, "text": said, "cites": []}), name="add_note"),
                      tool_use(json.dumps({"claim": said, "claim_kind": "account_change", "cites": ["E1"],
                                           "lane": "lead", "rationale": said}), name="propose_finding",
                               call_id="toolu_02")], stop="tool_use")

    finish = reply([text("Done."), tool_use(json.dumps({"summary": said}), name="finish_session", call_id="toolu_03")],
                   stop="tool_use")
    settings = claude_settings(arkime_password=WEAK, home=tmp_path)
    endpoint = _endpoint(first, finish)
    p, _ = provider(settings, endpoint)
    budget = AgentBudget.from_usage(BudgetLimits.from_settings(settings), repo.agent_usage("h1"), clock=lambda: 0.0)
    outcome = _run_session(settings, repo, "h1", p, _BudgetGate(budget, settings),
                           lambda session: Toolbox(repo, "h1", session_id=session), _prompt_set(),
                           purpose="investigate", hypothesis=_hypothesis(repo))
    return outcome, endpoint


def test_a_weak_secret_in_a_reply_is_redacted_everywhere_and_the_session_goes_on(tmp_path, caplog):
    pytest.importorskip("anthropic")
    caplog.set_level(logging.DEBUG)
    engine, repo = _repo(tmp_path, "weak")
    outcome, endpoint = _weak_session(repo, tmp_path)

    # the session went on past the reply that held the text, and finished on its own
    assert len(endpoint.calls) == 2
    assert outcome["state"] == "finished"
    assert outcome["summary"] == "The account was set to <redacted> on web01; marmalades is another word."
    # the conversation sent onward: the turn goes back without its signed thinking, its text and tool inputs scrubbed,
    # and the longer word is left as it is
    turn = next(m for m in endpoint.body(1)["messages"] if m["role"] == "assistant")
    assert [block["type"] for block in turn["content"]] == ["text", "tool_use", "tool_use"]
    assert turn["content"][0]["text"] == "Checking <redacted> and marmalades."
    assert turn["content"][1]["input"]["text"] == "The account was set to <redacted> on web01; marmalades is another word."
    assert turn["content"][2]["input"]["claim"] == turn["content"][1]["input"]["text"]
    # the tool arguments as run and stored, and the note written
    stored_calls = {row["name"]: row["arguments"] for row in repo.agent_tool_calls("h1")}
    assert stored_calls["add_note"]["text"] == "The account was set to <redacted> on web01; marmalades is another word."
    assert "<redacted>" in json.dumps(stored_calls["propose_finding"]) and LONGER in json.dumps(stored_calls)
    assert [row["text"] for row in repo.agent_notes("h1")] == [stored_calls["add_note"]["text"]]
    # the counts and the audit: by setting name, never a value, and no guard trip
    calls = repo.model_calls("h1")
    # thinking, text, the note, the finding's claim and rationale; then the summary
    assert calls[0]["options"]["output_redactions"] == {"ARKIME_PASSWORD": 5}
    assert repo.agent_usage("h1")["output_redactions"] == {"ARKIME_PASSWORD": 6}
    events = [row["detail"] for row in repo.audit_trail("h1", WEAK_SECRET_ACTION)[0]]
    session = repo.agent_sessions("h1")[-1]
    assert events == [{"setting": "ARKIME_PASSWORD", "replacements": 5, "model_call_id": calls[0]["id"],
                       "session_id": session["id"], "purpose": "investigate"},
                      {"setting": "ARKIME_PASSWORD", "replacements": 1, "model_call_id": calls[1]["id"],
                       "session_id": session["id"], "purpose": "investigate"}]
    assert repo.audit_trail("h1", SECRET_GUARD_ACTION)[0] == [] and repo.agent_secret_guard_counts("h1") == {}
    # the value never stands as a word anywhere it could have gone; the longer word is kept
    sent = [request.content.decode() for request in endpoint.calls[1:]]
    assert _no_weak_word(_every_stored_value(engine), caplog.text, *sent)
    assert LONGER in _every_stored_value(engine)
    engine.dispose()


def test_a_strong_secret_beside_a_weak_one_still_ends_the_session_and_names_only_the_strong_one(tmp_path, caplog):
    pytest.importorskip("anthropic")
    from tests.test_agent_provider_claude import claude_settings, provider, reply, text, tool_use
    caplog.set_level(logging.DEBUG)
    engine, repo = _repo(tmp_path, "strong")
    settings = claude_settings(arkime_password=WEAK, es_password=SENTINEL, home=tmp_path)
    opened = tool_use(json.dumps({"statement": f"Review the reset to {SENTINEL} and {WEAK} on the web host",
                                  "techniques": [], "entities": [], "supporting": [], "questions": ["Who?"]}),
                      name="open_hypothesis")
    endpoint = _endpoint(reply([_thinking("Opening."), text(f"Opening {WEAK}."), opened], stop="tool_use"),
                         reply([text("never sent")]))
    p, _ = provider(settings, endpoint)
    budget = AgentBudget.from_usage(BudgetLimits.from_settings(settings), repo.agent_usage("h1"), clock=lambda: 0.0)
    outcome = _run_session(settings, repo, "h1", p, _BudgetGate(budget, settings),
                           lambda session: Toolbox(repo, "h1", session_id=session), _prompt_set(), purpose="orient")
    assert outcome["state"] == "secret_guard" and len(endpoint.calls) == 1
    events = [row["detail"] for row in repo.audit_trail("h1", SECRET_GUARD_ACTION)[0]]
    assert {event["setting"] for event in events} == {"ES_PASSWORD"}
    assert repo.agent_secret_guard_counts("h1") == {"ES_PASSWORD": 1}
    assert [row["statement"] for row in repo.agent_hypotheses("h1")] == [
        "Review the reset to <redacted> and <redacted> on the web host"]
    stored = _every_stored_value(engine)
    assert SENTINEL not in stored and SENTINEL not in caplog.text and _no_weak_word(stored, caplog.text)
    engine.dispose()


# ---- the provider: tool arguments and replay ------------------------------------------------------------------

def test_tool_arguments_holding_a_weak_secret_are_redacted_before_validation_and_replay():
    pytest.importorskip("anthropic")
    from romulus.agent.provider.base import Tool
    from tests.test_agent_provider_claude import (
        TOOL,
        Endpoint,
        claude_settings,
        provider,
        reply,
        text,
        tool_use,
    )
    note = Tool("note", "x", {"type": "object", "properties": {"note": {"type": "string"}}, "required": ["note"],
                              "additionalProperties": False})
    settings = claude_settings(arkime_password=WEAK)
    for raw, parsed in ((json.dumps({"note": f"{WEAK} and {LONGER}"}), {"note": "<redacted> and marmalades"}),
                        (f'{{"note": "{WEAK} and {LONGER}"', None)):             # cut off: it does not parse
        endpoint = Endpoint(reply([_thinking(f"About {WEAK}."), text("Noting."), tool_use(raw, name="note")],
                                  stop="tool_use"), reply([text("ok")]))
        p, _ = provider(settings, endpoint)
        request = ChatRequest([{"role": "user", "content": "go"}], tools=[TOOL, note])
        result = p.chat(request)
        call = result.tool_calls[0]
        assert call.arguments == parsed and _no_weak_word(call.raw_arguments) and LONGER in call.raw_arguments
        assert (result.status == "ok") == (parsed is not None)
        message = result.assistant_message()
        assert _no_weak_word(json.dumps(message)) and "thinking" not in json.dumps(message[PROVIDER_STATE])
        assert result.reply_redactions == {"ARKIME_PASSWORD": 2}
        followed = p.chat(ChatRequest([*request.messages, message,
                                       {"role": "tool", "tool_call_id": "toolu_01", "content": "ok"}],
                                      tools=[TOOL, note]))
        assert followed.ok and len(endpoint.calls) == 2 and _no_weak_word(endpoint.calls[1].content.decode())


def test_a_reply_without_a_weak_secret_keeps_its_thinking_and_is_unchanged():
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
    p, _ = provider(claude_settings(arkime_password=WEAK),
                    Endpoint(reply([_thinking(f"About {LONGER}."), text(f"{LONGER}."), tool_use()], stop="tool_use")))
    result = p.chat(ChatRequest([{"role": "user", "content": "go"}], tools=[TOOL]))
    assert result.reply_redactions == {} and result.content == f"{LONGER}."
    assert [block["type"] for block in result.provider_state["content"]] == ["thinking", "text", "tool_use"]


def test_a_turn_from_elsewhere_holding_a_weak_secret_still_trips_the_backstop():
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
    first, _ = provider(claude_settings(), Endpoint(reply([_thinking(""), text(f"it is {WEAK}"), tool_use()],
                                                          stop="tool_use")))
    message = first.chat(ChatRequest([{"role": "user", "content": "go"}], tools=[TOOL])).assistant_message()
    endpoint = Endpoint(reply([text("x")]))
    p, _ = provider(claude_settings(arkime_password=WEAK), endpoint)
    with pytest.raises(SecretGuardTripped) as exc:
        p.chat(ChatRequest([{"role": "user", "content": "go"}, message,
                            {"role": "tool", "tool_call_id": "toolu_01", "content": "ok"}], tools=[TOOL]))
    assert exc.value.trips == (("ARKIME_PASSWORD", "text"),) and endpoint.calls == []


def test_the_openai_responses_adapter_redacts_a_weak_secret_in_text_reasoning_and_calls():
    respx = pytest.importorskip("respx")
    from tests.test_agent_provider_openai_responses import (
        API,
        LOOSE,
        TOOL,
        build,
        call,
        message,
        response,
        settings,
        streamed,
    )
    reasoning = {"type": "reasoning", "id": "rs_1", "encrypted_content": "gAAAA-encrypted-1",
                 "summary": [{"type": "summary_text", "text": f"The reset set {WEAK}."}]}
    first = response(reasoning, message(f"Checking {WEAK} and {LONGER}."),
                     call(name="search", arguments=json.dumps({"q": f"{WEAK} logins"})))
    with respx.mock(base_url=API, assert_all_called=False) as api:
        route = api.post("/responses").mock(side_effect=[streamed(first), streamed(response(message("done")))])
        p, _ = build(settings(arkime_password=WEAK))
        conversation = [{"role": "user", "content": "check"}]
        turn = p.chat(ChatRequest(conversation, tools=[TOOL, LOOSE]))
        assert turn.content == "Checking <redacted> and marmalades."
        assert turn.tool_calls[0].arguments == {"q": "<redacted> logins"}
        assert turn.reply_redactions == {"ARKIME_PASSWORD": 3}
        conversation += [turn.assistant_message(), {"role": "tool", "tool_call_id": "call_1", "content": "x"}]
        assert p.chat(ChatRequest(conversation, tools=[TOOL, LOOSE])).ok and len(route.calls) == 2
        replayed = json.loads(route.calls[1].request.content)["input"]
        assert replayed[1]["encrypted_content"] == "gAAAA-encrypted-1"
        assert replayed[1]["summary"][0]["text"] == "The reset set <redacted>."
        assert _no_weak_word(route.calls[1].request.content.decode())


# ---- the assessment and the report ------------------------------------------------------------------------------

def _assess(repo, tmp_path, *replies):
    from tests.test_agent_provider_claude import claude_settings, provider
    settings = claude_settings(arkime_password=WEAK, home=tmp_path)
    endpoint = _endpoint(*replies)
    p, _ = provider(settings, endpoint)
    budget = AgentBudget.from_usage(BudgetLimits.from_settings(settings), repo.agent_usage("h1"), clock=lambda: 0.0)
    return run_assessment(settings, repo, "h1", p, budget, clock=lambda: 0.0), endpoint


def test_an_assessment_holding_a_weak_secret_is_retried_stored_and_reported_without_it(setup, tmp_path, caplog):
    pytest.importorskip("anthropic")
    from romulus.agent.aliases import AliasBook
    from romulus.report import markdown
    from romulus.report.manifest import build_manifest
    from tests.test_agent_provider_claude import reply, text
    caplog.set_level(logging.DEBUG)
    client, repo, *_ = setup
    test_web_agent_a6.run_row(repo)
    alias = AliasBook(repo, "h1").alias_for("E", "ev1")
    # the first answer fails validation and holds the text: its retry replays it, and the session goes on
    broken = json.dumps({"overall": f"The reset set {WEAK}."})
    body = {"overall": [{"text": f"The account reset to {WEAK} is the lead; {LONGER} is not.", "cites": [alias],
                         "kind": "hypothesis"}],
            "key_steps": [], "confidence": {"overall": "medium", "reasons": []},
            "narrative": [{"time_span": {"start": "", "end": ""}, "phase": "Credential Access", "sentences": [
                {"text": f"The recorded process set the password {WEAK} on web01.", "cites": [alias],
                 "kind": "observed"}]}],
            "alternatives": [], "gaps": [], "next_checks": []}
    result, endpoint = _assess(repo, tmp_path, reply([text(broken)]), reply([text(json.dumps(body))]))
    assert result is not None and len(endpoint.calls) == 2
    assert _no_weak_word(endpoint.calls[1].content.decode())
    session = repo.agent_sessions("h1", purpose="assess")[-1]
    assert session["state"] == "finished"
    stored = repo.agent_assessments("h1")[-1]
    assert stored["source"] == "agent"
    assert stored["body"]["overall"][0]["text"] == "The account reset to <redacted> is the lead; marmalades is not."
    assert stored["body"]["narrative"][0]["sentences"][0]["text"] == (
        "The recorded process set the password <redacted> on web01.")
    assert repo.agent_secret_guard_counts("h1") == {}
    assert {row["detail"]["setting"] for row in repo.audit_trail("h1", WEAK_SECRET_ACTION)[0]} == {"ARKIME_PASSWORD"}
    manifest = build_manifest(repo, "h1", "test")
    manifest["revision"] = {"number": 1, "id": "h1-r1", "supersedes": None}
    report = markdown.render(manifest)
    assert LONGER in report
    pages = [client.get(f"/hunts/h1{suffix}").text for suffix in ("", "/assessment", "/run")]
    assert _no_weak_word(_every_stored_value(repo.engine), caplog.text, report, json.dumps(manifest, default=str),
                         *pages)


# ---- Run details --------------------------------------------------------------------------------------------------

def test_run_details_count_weak_secret_redactions_as_replacements_not_session_ends(setup, tmp_path):
    pytest.importorskip("anthropic")
    client, repo, *_ = setup
    test_web_agent_a6.run_row(repo)
    outcome, _ = _weak_session(repo, tmp_path)
    assert outcome["state"] == "finished"
    page = client.get("/hunts/h1/run").text
    block = page.split('id="secret-guard"', 1)[1].split("</section>", 1)[0]
    total = repo.agent_usage("h1")["output_redactions"]["ARKIME_PASSWORD"]
    assert f'<span class="mono">ARKIME_PASSWORD</span> {total} replacements' in block
    assert "sessions went on" in block and "Agent sessions ended" not in block
    assert _no_weak_word(page)


def test_record_call_merges_reply_redactions_and_audits_them_by_name(tmp_path):
    from tests.agent_scripted import ScriptedProvider, response
    engine, repo = _repo(tmp_path, "record")
    result = response(content="<redacted> seen")
    result.reply_redactions = {"ARKIME_PASSWORD": 2}
    request = ChatRequest([{"role": "user", "content": "go"}])
    call_id = record_call(repo, ScriptedProvider([]), hunt_id="h1", purpose="investigate", request=request,
                          result=result, limits=BudgetLimits.from_settings(Settings(home=tmp_path)),
                          session_id=None, settings=Settings(home=tmp_path, arkime_password=WEAK))
    assert repo.model_calls("h1")[0]["options"]["output_redactions"] == {"ARKIME_PASSWORD": 2}
    assert [row["detail"] for row in repo.audit_trail("h1", WEAK_SECRET_ACTION)[0]] == [
        {"setting": "ARKIME_PASSWORD", "replacements": 2, "model_call_id": call_id, "session_id": None,
         "purpose": "investigate"}]
    engine.dispose()
