"""The OpenAI Responses API adapter, tested against a respx-mocked endpoint.

No test reaches a real model or the network: every request to the API root is answered by respx, and name
resolution is injected.
"""
import json

import httpx
import pytest
import respx

from romulus.agent.provider import (
    AgentBudget,
    AgentNotReady,
    BudgetLimits,
    ChatRequest,
    HistoryError,
    ProviderUnavailable,
    Tool,
    agent_readiness,
    build_provider,
)
from romulus.agent.provider.openai_compatible import openai_strict_problems
from romulus.config import Settings
from romulus.doctor import check_agent

KEY = "sk-test-responses-0123456789abcdef"
SECRET = "es-password-0123456789"
API = "https://api.openai.com/v1"
MODEL = "gpt-test-2026-01-01"


def openai_dns(host: str) -> list[str]:
    return ["162.159.140.245"] if host == "api.openai.com" else []


TOOL = Tool("report_status", "Report status.", {
    "type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"], "additionalProperties": False,
})
LOOSE = Tool("search", "Search events.", {
    "type": "object", "properties": {"q": {"type": "string"}, "limit": {"type": "integer"}}, "required": ["q"],
    "additionalProperties": False,
})


def settings(**kw) -> Settings:
    base = {"agent_provider": "openai_responses", "agent_model": MODEL, "agent_api_key": KEY,
            "model_egress": "lab-public-data", "agent_thinking_tokens": 2000, "es_password": SECRET}
    return Settings(**{**base, **kw})


def build(s: Settings | None = None):
    sleeps: list[float] = []
    return build_provider(s or settings(), resolver=openai_dns, sleep=sleeps.append), sleeps


def ask(*messages, **kw) -> ChatRequest:
    return ChatRequest(list(messages) or [{"role": "system", "content": "You are a test."},
                                          {"role": "user", "content": "go"}], **kw)


# ---- reply builders ---------------------------------------------------------------------------------------------

def reasoning(n=1) -> dict:
    return {"type": "reasoning", "id": f"rs_{n}", "summary": [], "encrypted_content": f"gAAAA-encrypted-{n}"}


def call(name="report_status", arguments='{"ok": true}', call_id="call_1") -> dict:
    return {"type": "function_call", "id": f"fc_{call_id}", "call_id": call_id, "name": name,
            "arguments": arguments, "status": "completed"}


def message(text="", refusal=None) -> dict:
    parts = [{"type": "output_text", "text": text, "annotations": []}] if refusal is None else [
        {"type": "refusal", "refusal": refusal}]
    return {"type": "message", "id": "msg_1", "role": "assistant", "status": "completed", "content": parts}


def response(*output, status="completed", reason=None, usage=None, model=MODEL, error=None) -> dict:
    body = {"id": "resp_1", "object": "response", "status": status, "model": model, "output": list(output),
            "reasoning": {"effort": "high", "summary": None},
            "incomplete_details": {"reason": reason} if reason else None, "error": error}
    if usage is not False:
        body["usage"] = usage or {"input_tokens": 1200, "input_tokens_details": {"cached_tokens": 1000},
                                  "output_tokens": 300, "output_tokens_details": {"reasoning_tokens": 250},
                                  "total_tokens": 1500}
    return body


def sse(*events: dict) -> httpx.Response:
    text = "".join(f"event: {e['type']}\ndata: {json.dumps(e)}\n\n" for e in events)
    return httpx.Response(200, headers={"content-type": "text/event-stream"}, content=text.encode())


def streamed(body: dict) -> httpx.Response:
    """A streamed reply: created, an ignored delta, then the terminal event that carries the whole response."""
    terminal = {"completed": "response.completed", "incomplete": "response.incomplete",
                "failed": "response.failed"}[body["status"]]
    created = {**body, "status": "in_progress", "output": [], "usage": None}
    return sse({"type": "response.created", "sequence_number": 0, "response": created},
               {"type": "response.output_text.delta", "sequence_number": 1, "delta": "x"},
               {"type": terminal, "sequence_number": 2, "response": body})


@pytest.fixture
def api():
    with respx.mock(base_url=API, assert_all_called=False) as mock:
        yield mock


def sent(route, n=-1) -> dict:
    return json.loads(route.calls[n].request.content)


# ---- configuration ----------------------------------------------------------------------------------------------

def test_the_provider_defaults_to_the_openai_api_root_and_needs_the_egress_switch_and_a_key():
    ready = agent_readiness(settings(), openai_dns)
    assert ready.ready and ready.decision.host == "api.openai.com" and ready.decision.egress == "remote"
    blocked = agent_readiness(settings(model_egress=""), openai_dns)
    assert blocked.state == "blocked" and "ROMULUS_MODEL_EGRESS" in blocked.reason
    keyless = agent_readiness(settings(agent_api_key=""), openai_dns)
    assert keyless.state == "not_configured" and "AGENT_API_KEY" in keyless.reason
    with pytest.raises(AgentNotReady):
        build_provider(settings(model_egress=""), resolver=openai_dns)
    options = ready.provenance(settings())["options"]
    assert options == {"effort": "high", "max_output_tokens": 4096, "thinking_tokens": 2000}
    assert KEY not in json.dumps(ready.provenance(settings()))


# ---- request shape ------------------------------------------------------------------------------------------------

def test_request_shape_tools_reasoning_output_limit_storage_and_auth(api):
    route = api.post("/responses").mock(return_value=streamed(response(call())))
    p, _ = build()
    result = p.chat(ask(tools=[TOOL, LOOSE], tool_choice="required", max_output_tokens=500, temperature=0.2))
    assert result.ok, result.error
    body, request = sent(route), route.calls[-1].request
    assert request.headers["authorization"] == f"Bearer {KEY}"
    assert body["model"] == MODEL and body["stream"] is True
    assert body["max_output_tokens"] == 500 + 2000            # output plus room for reasoning
    assert body["reasoning"] == {"effort": "high", "summary": "auto"}
    assert body["store"] is False and body["include"] == ["reasoning.encrypted_content"]
    assert body["truncation"] == "disabled"
    assert "temperature" not in body and "top_p" not in body
    assert body["tool_choice"] == "required"
    assert body["tools"] == [
        {"type": "function", "name": "report_status", "description": "Report status.",
         "parameters": TOOL.parameters, "strict": True},
        # an optional property is outside strict mode: sent loose, checked here
        {"type": "function", "name": "search", "description": "Search events.", "parameters": LOOSE.parameters,
         "strict": False}]
    assert body["input"] == [{"role": "system", "content": "You are a test."}, {"role": "user", "content": "go"}]


@pytest.mark.parametrize("choice", ["auto", "required", "none"])
def test_tool_choice_is_sent_as_asked(api, choice):
    reply = response(call()) if choice != "none" else response(message("no tools"))
    route = api.post("/responses").mock(return_value=streamed(reply))
    p, _ = build()
    assert p.chat(ask(tools=[TOOL], tool_choice=choice)).ok
    assert sent(route)["tool_choice"] == choice


def test_a_response_schema_becomes_text_format_and_the_reply_is_parsed(api):
    route = api.post("/responses").mock(return_value=streamed(response(message('{"ok": true}'))))
    p, _ = build()
    result = p.chat(ask(response_schema=TOOL.parameters, schema_name="report_status"))
    assert result.ok and result.parsed == {"ok": True}
    assert sent(route)["text"] == {"format": {"type": "json_schema", "name": "report_status",
                                              "schema": TOOL.parameters, "strict": True}}


def test_a_reply_outside_the_response_schema_is_invalid_json(api):
    api.post("/responses").mock(return_value=streamed(response(message('{"ok": "yes"}'))))
    p, _ = build()
    result = p.chat(ask(response_schema=TOOL.parameters))
    assert result.status == "invalid_json" and "expected boolean" in result.error


def test_secrets_are_redacted_from_every_outgoing_message(api):
    route = api.post("/responses").mock(return_value=streamed(response(message("done"))))
    p, _ = build()
    p.chat(ask({"role": "user", "content": f"password {SECRET} and key {KEY}"}))
    raw = route.calls[-1].request.content.decode()
    assert SECRET not in raw and KEY not in raw and "<redacted>" in raw


# ---- the tool loop and history ------------------------------------------------------------------------------------

def test_a_multi_turn_tool_loop_replays_reasoning_and_calls_with_their_outputs(api):
    first = response(reasoning(1), call(arguments='{"ok": true}', call_id="call_a"))
    second = response(reasoning(2), message("all checked"))
    route = api.post("/responses").mock(side_effect=[streamed(first), streamed(second)])
    p, _ = build()
    conversation = [{"role": "system", "content": "You are a test."}, {"role": "user", "content": "check"}]
    turn = p.chat(ChatRequest(conversation, tools=[TOOL]))
    assert turn.ok and turn.finish_reason == "tool_calls"
    assert [(c.id, c.name, c.arguments) for c in turn.tool_calls] == [("call_a", "report_status", {"ok": True})]
    conversation += [turn.assistant_message(), {"role": "tool", "tool_call_id": "call_a", "content": "3 events"}]
    final = p.chat(ChatRequest(conversation, tools=[TOOL]))
    assert final.ok and final.content == "all checked" and final.finish_reason == "stop"
    assert sent(route)["input"] == [
        {"role": "system", "content": "You are a test."}, {"role": "user", "content": "check"},
        reasoning(1), call(arguments='{"ok": true}', call_id="call_a"),
        {"type": "function_call_output", "call_id": "call_a", "output": "3 events"}]


def test_a_changed_assistant_turn_or_foreign_state_is_refused_before_sending(api):
    route = api.post("/responses").mock(return_value=streamed(response(reasoning(), call())))
    p, _ = build()
    turn = p.chat(ask(tools=[TOOL]))
    edited = turn.assistant_message()
    edited["tool_calls"][0]["function"]["arguments"] = '{"ok": false}'
    with pytest.raises(HistoryError, match="changed"):
        p.chat(ask({"role": "user", "content": "go"}, edited, {"role": "tool", "tool_call_id": "call_1",
                                                                  "content": "x"}))
    foreign = {**turn.assistant_message(), "provider_state": {"provider": "anthropic", "content": []}}
    with pytest.raises(HistoryError, match="not written by this adapter"):
        p.chat(ask({"role": "user", "content": "go"}, foreign))
    odd = turn.assistant_message()
    odd["provider_state"]["output"].append({"type": "web_search_call", "id": "ws_1"})
    with pytest.raises(HistoryError, match="web_search_call"):
        p.chat(ask({"role": "user", "content": "go"}, odd))
    assert len(route.calls) == 1


def test_a_replayed_turn_holding_a_secret_is_never_sent(api):
    route = api.post("/responses").mock(return_value=streamed(response(message(f"the password is {SECRET}"))))
    p, _ = build()
    turn = p.chat(ask())
    with pytest.raises(HistoryError, match="secret"):
        p.chat(ask({"role": "user", "content": "go"}, turn.assistant_message(), {"role": "user", "content": "and?"}))
    assert len(route.calls) == 1


def test_history_from_another_provider_is_sent_from_its_text_and_calls(api):
    route = api.post("/responses").mock(return_value=streamed(response(message("ok"))))
    p, _ = build()
    assistant = {"role": "assistant", "content": "looking", "tool_calls": [
        {"id": "toolu_1", "type": "function", "function": {"name": "report_status", "arguments": {"ok": True}}}]}
    assert p.chat(ask({"role": "user", "content": "go"}, assistant,
                      {"role": "tool", "tool_call_id": "toolu_1", "content": "done"}, tools=[TOOL])).ok
    assert sent(route)["input"][1:] == [
        {"role": "assistant", "content": "looking"},
        {"type": "function_call", "call_id": "toolu_1", "name": "report_status", "arguments": '{"ok": true}'},
        {"type": "function_call_output", "call_id": "toolu_1", "output": "done"}]


# ---- reply checks ---------------------------------------------------------------------------------------------------

def test_a_required_tool_choice_answered_without_a_call_is_invalid(api):
    api.post("/responses").mock(return_value=streamed(response(reasoning(), message("I would rather not."))))
    p, _ = build()
    result = p.chat(ask(tools=[TOOL], tool_choice="required"))
    assert result.status == "invalid_tool_call" and "without the tool call required" in result.error


def test_a_tool_call_where_none_was_allowed_is_invalid(api):
    api.post("/responses").mock(return_value=streamed(response(call())))
    p, _ = build()
    assert p.chat(ask(tools=[TOOL], tool_choice="none")).status == "invalid_tool_call"


@pytest.mark.parametrize(("arguments", "error"), [
    ('{"ok": tru', "not valid JSON"),
    ('["ok"]', "not a JSON object"),
    ('{"ok": "yes"}', "do not match the tool's schema"),
])
def test_malformed_tool_arguments_are_invalid_tool_calls(api, arguments, error):
    api.post("/responses").mock(return_value=streamed(response(call(arguments=arguments))))
    p, _ = build()
    result = p.chat(ask(tools=[TOOL]))
    assert result.status == "invalid_tool_call" and error in result.error


def test_a_call_to_a_tool_that_was_not_offered_is_invalid(api):
    api.post("/responses").mock(return_value=streamed(response(call(name="run_shell", arguments="{}"))))
    p, _ = build()
    result = p.chat(ask(tools=[TOOL]))
    assert result.status == "invalid_tool_call" and "run_shell" in result.error


def test_a_refusal_is_refused_never_ok_and_carries_no_state_or_calls(api):
    api.post("/responses").mock(return_value=streamed(response(
        call(), message(refusal="I can't help with that."))))
    p, _ = build()
    result = p.chat(ask(tools=[TOOL]))
    assert result.status == "refused" and "I can't help with that." in result.error
    assert result.tool_calls == [] and result.provider_state is None
    assert result.details["refusal"] == ["I can't help with that."]


def test_a_content_filter_stop_is_refused(api):
    api.post("/responses").mock(return_value=streamed(response(message("partial"), status="incomplete",
                                                               reason="content_filter")))
    p, _ = build()
    assert p.chat(ask()).status == "refused"


def test_output_cut_at_the_limit_is_truncated_and_says_when_reasoning_used_it_all(api):
    api.post("/responses").mock(side_effect=[
        streamed(response(message('{"ok": true}'), status="incomplete", reason="max_output_tokens")),
        streamed(response(reasoning(), status="incomplete", reason="max_output_tokens"))])
    p, _ = build()
    cut = p.chat(ask(response_schema=TOOL.parameters))
    assert cut.status == "truncated_output" and cut.details["incomplete_reason"] == "max_output_tokens"
    empty = p.chat(ask())
    assert empty.status == "truncated_output" and "AGENT_THINKING_TOKENS" in empty.error


@pytest.mark.parametrize("status", ["in_progress", "cancelled", None])
def test_a_response_that_is_not_finished_is_an_error(api, status):
    body = response(message("x"))
    body["status"] = status
    api.post("/responses").mock(return_value=httpx.Response(200, json=body))
    p, _ = build()
    assert p.chat(ask()).status == "error"


def test_unexpected_output_items_are_an_error(api):
    api.post("/responses").mock(return_value=streamed(response({"type": "web_search_call", "id": "ws_1"},
                                                               message("x"))))
    p, _ = build()
    result = p.chat(ask())
    assert result.status == "error" and "web_search_call" in result.error and result.provider_state is None


@pytest.mark.parametrize("payload", [{"output": None, "status": "completed"}, {"status": "completed",
                                                                               "output": ["x"]}, ["x"]])
def test_malformed_replies_are_errors_not_crashes(api, payload):
    api.post("/responses").mock(return_value=httpx.Response(200, json=payload))
    p, _ = build()
    assert p.chat(ask()).status == "error"


@pytest.mark.parametrize("events", [
    [{"type": "response.created", "response": "not an object"}, {"type": "response.completed", "response": 3}],
    [{"type": "response.completed"}],
])
def test_malformed_stream_events_are_errors_not_crashes(api, events):
    api.post("/responses").mock(return_value=sse(*events))
    p, _ = build()
    assert p.chat(ask()).status == "error"


def test_a_stream_line_that_is_not_json_is_an_error(api):
    api.post("/responses").mock(return_value=httpx.Response(200, headers={"content-type": "text/event-stream"},
                                                            content=b"data: {not json\n\n"))
    p, _ = build()
    assert p.chat(ask()).status == "error"


def test_a_server_that_answers_without_streaming_is_read_whole(api):
    api.post("/responses").mock(return_value=httpx.Response(200, json=response(message("whole"))))
    p, _ = build()
    result = p.chat(ask())
    assert result.ok and result.content == "whole"


# ---- usage, cost and model pin ---------------------------------------------------------------------------------------

def test_usage_maps_cached_and_reasoning_tokens_and_cost_follows_it(api):
    usage = {"input_tokens": 10_000, "input_tokens_details": {"cached_tokens": 8_000, "cache_write_tokens": 500},
             "output_tokens": 2_000, "output_tokens_details": {"reasoning_tokens": 1_500}, "total_tokens": 12_000}
    api.post("/responses").mock(return_value=streamed(response(message("x"), usage=usage, model=MODEL + "-b")))
    s = settings(agent_price_input_per_mtok=2.0, agent_price_output_per_mtok=8.0,
                 agent_price_cache_read_per_mtok=0.2, agent_price_cache_write_per_mtok=2.5)
    p, _ = build(s)
    result = p.chat(ask())
    u = result.usage
    assert (u.prompt_tokens, u.completion_tokens, u.cache_read_tokens, u.cache_write_tokens) == (10_000, 2_000,
                                                                                                8_000, 500)
    assert result.details["reasoning_tokens"] == 1_500 and result.details["reasoning_effort"] == "high"
    assert result.model_reported == MODEL + "-b"
    charged = AgentBudget(BudgetLimits.from_settings(s), clock=lambda: 0.0).charge(result)
    assert (charged["prompt_tokens"], charged["completion_tokens"], charged["estimated"]) == (10_000, 2_000, False)
    # 1,500 uncached at 2.0, 8,000 cached at 0.2, 500 written at 2.5, 2,000 output (reasoning included) at 8.0
    assert charged["cost_usd"] == pytest.approx((1_500 * 2.0 + 8_000 * 0.2 + 500 * 2.5 + 2_000 * 8.0) / 1e6)


def test_missing_usage_is_charged_from_an_estimate(api):
    api.post("/responses").mock(return_value=streamed(response(message("x" * 320), usage=False)))
    p, _ = build()
    result = p.chat(ask())
    assert result.ok and not result.usage.reported
    assert AgentBudget(BudgetLimits.from_settings(settings()), clock=lambda: 0.0).charge(result)["estimated"]


def test_the_output_allowance_includes_reasoning_room_for_the_budget_check():
    p, _ = build()
    assert p.output_limit(ask(max_output_tokens=1000)) == 3000


# ---- context window ---------------------------------------------------------------------------------------------------

def test_a_prompt_too_large_for_the_context_is_never_sent(api):
    route = api.post("/responses").mock(return_value=streamed(response(message("x"))))
    p, _ = build(settings(agent_context_tokens=5000))
    assert p.chat(ask({"role": "user", "content": "x" * 10_000})).status == "too_large"
    assert route.calls == []


def test_a_prompt_at_the_context_ceiling_is_truncated_input(api):
    usage = {"input_tokens": 9_990, "output_tokens": 5, "input_tokens_details": {"cached_tokens": 0},
             "output_tokens_details": {"reasoning_tokens": 0}}
    api.post("/responses").mock(return_value=streamed(response(message("x"), usage=usage)))
    p, _ = build(settings(agent_context_tokens=10_000, agent_max_output_tokens=64, agent_thinking_tokens=1024))
    assert p.chat(ask()).status == "truncated_input"


def test_an_oversized_request_is_too_large(api):
    api.post("/responses").mock(return_value=httpx.Response(413, json={"error": {"message": "too big"}}))
    p, _ = build()
    assert p.chat(ask()).status == "too_large"


# ---- failures and retries -------------------------------------------------------------------------------------------

def test_a_429_is_retried_after_its_retry_after_then_succeeds(api):
    route = api.post("/responses").mock(side_effect=[
        httpx.Response(429, headers={"retry-after": "2"}, json={"error": {"message": "slow down"}}),
        streamed(response(message("ok")))])
    p, sleeps = build()
    result = p.chat(ask())
    assert result.ok and result.attempts == 2 and sleeps == [2.0] and len(route.calls) == 2


def test_an_outage_raises_after_three_retries(api):
    api.post("/responses").mock(return_value=httpx.Response(503, json={"error": {"message": f"down {KEY}"}}))
    p, sleeps = build()
    with pytest.raises(ProviderUnavailable) as exc:
        p.chat(ask())
    assert len(sleeps) == 3 and "after 4 attempts" in str(exc.value) and KEY not in str(exc.value)


def test_connection_errors_are_retried(api):
    api.post("/responses").mock(side_effect=[httpx.ConnectError("refused"), streamed(response(message("ok")))])
    p, sleeps = build()
    assert p.chat(ask()).ok and len(sleeps) == 1


def test_client_errors_are_not_retried_and_show_the_provider_message_whole_and_redacted(api):
    text = ("Function tools with reasoning_effort are not supported for this model in /v1/chat/completions. To use "
            "function tools, use /v1/responses or set reasoning_effort to 'none'. " + "More detail. " * 30
            + f"(key {KEY})")
    route = api.post("/responses").mock(return_value=httpx.Response(400, json={"error": {
        "message": text, "type": "invalid_request_error", "param": "tools", "code": None}}))
    p, sleeps = build()
    result = p.chat(ask())
    assert result.status == "error" and len(route.calls) == 1 and sleeps == []
    assert result.error == "HTTP 400: " + text.replace(KEY, "<redacted>")
    assert KEY not in result.raw


def test_a_failed_response_is_retried_only_for_transient_codes_and_each_attempt_is_billed(api):
    failed = response(status="failed", error={"code": "server_error", "message": "try again"},
                      usage={"input_tokens": 100, "output_tokens": 7})
    api.post("/responses").mock(side_effect=[streamed(failed), streamed(response(message("ok")))])
    p, sleeps = build()
    result = p.chat(ask())
    assert result.ok and result.attempts == 2 and len(sleeps) == 1
    assert [(b["prompt"], b["completion"]) for b in result.details["billed"]] == [(100, 7), (1200, 300)]
    charged = AgentBudget(BudgetLimits.from_settings(settings()), clock=lambda: 0.0).charge(result)
    assert (charged["prompt_tokens"], charged["completion_tokens"]) == (1300, 307)


def test_a_failed_response_with_a_lasting_cause_is_an_error(api):
    failed = response(status="failed", error={"code": "invalid_prompt", "message": "flagged"}, usage=False)
    route = api.post("/responses").mock(return_value=streamed(failed))
    p, _ = build()
    result = p.chat(ask())
    assert result.status == "error" and "invalid_prompt" in result.error and "flagged" in result.error
    assert len(route.calls) == 1 and result.details["billed"][0]["worst_case"] is True


def test_a_stream_error_event_is_an_error(api):
    created = {"type": "response.created", "response": {"model": MODEL, "status": "in_progress"}}
    api.post("/responses").mock(return_value=sse(created, {"type": "error", "code": "bad_thing",
                                                           "message": f"broke {KEY}"}))
    p, _ = build()
    result = p.chat(ask())
    assert result.status == "error" and "bad_thing" in result.error and KEY not in result.error


def test_a_stream_that_breaks_off_is_retried_and_charged_at_its_full_allowance(api):
    created = {"type": "response.created", "response": {"model": MODEL, "status": "in_progress"}}
    api.post("/responses").mock(side_effect=[sse(created), streamed(response(message("ok")))])
    p, sleeps = build()
    result = p.chat(ask(max_output_tokens=100))
    assert result.ok and len(sleeps) == 1
    broken = result.details["billed"][0]
    assert broken["worst_case"] is True and broken["completion"] == 100 + 2000
    assert broken["prompt"] == result.prompt_tokens_est


def test_with_a_cost_budget_a_stream_that_broke_off_is_not_retried(api):
    created = {"type": "response.created", "response": {"model": MODEL, "status": "in_progress"}}
    route = api.post("/responses").mock(return_value=sse(created))
    p, sleeps = build(settings(agent_max_cost_usd=5.0, agent_price_input_per_mtok=1.0,
                               agent_price_output_per_mtok=4.0))
    result = p.chat(ask())
    assert result.status == "error" and "not retried" in result.error and sleeps == [] and len(route.calls) == 1
    assert result.details["billed"][0]["worst_case"] is True


def test_an_outage_after_the_reply_began_carries_the_billed_attempts(api):
    created = {"type": "response.created", "response": {"model": MODEL, "status": "in_progress"}}
    api.post("/responses").mock(return_value=sse(created))
    p, _ = build()
    with pytest.raises(ProviderUnavailable) as exc:
        p.chat(ask())
    assert len(exc.value.billed) == 4 and all(b["worst_case"] for b in exc.value.billed)


def test_redirects_are_not_followed(api):
    api.post("/responses").mock(return_value=httpx.Response(307, headers={"location": "https://elsewhere.example/"}))
    p, _ = build()
    assert p.chat(ask()).status == "error"


# ---- doctor ----------------------------------------------------------------------------------------------------------

def _doctor_endpoint(api, *, models=(MODEL,), tool_reply=None, reported=MODEL):
    api.get("/models").mock(return_value=httpx.Response(200, json={"data": [{"id": m} for m in models]}))

    def answer(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        if body.get("tools"):
            return tool_reply or streamed(response(reasoning(), call(), model=reported))
        return streamed(response(reasoning(), message('{"ok": true}'), model=reported))
    api.post("/responses").mock(side_effect=answer)


def test_doctor_checks_reachability_model_tools_schema_usage_and_pin(api):
    _doctor_endpoint(api)
    checks = {c.name: c for c in check_agent(settings(), resolver=openai_dns)}
    assert checks["agent.provider"].detail == f"openai_responses model {MODEL} at api.openai.com"
    for name in ("agent.reachable", "agent.model", "agent.context", "agent.output", "agent.tool_calls",
                 "agent.json_schema", "agent.usage", "agent.model_pin"):
        assert checks[name].status == "ok", (name, checks[name].detail)
    assert checks["agent.egress"].status == "warn"


def test_doctor_shows_a_rejected_call_with_the_provider_message_whole_and_redacted(api):
    text = ("Function tools with reasoning_effort are not supported for this model in /v1/chat/completions. To use "
            "function tools, use /v1/responses or set reasoning_effort to 'none'. " + "x" * 400 + f" {KEY}")
    _doctor_endpoint(api, tool_reply=httpx.Response(400, json={"error": {"message": text,
                                                                         "type": "invalid_request_error"}}))
    checks = {c.name: c for c in check_agent(settings(), resolver=openai_dns)}
    detail = checks["agent.tool_calls"].detail
    assert checks["agent.tool_calls"].status == "fail"
    assert detail.endswith(text.replace(KEY, "<redacted>")) and KEY not in detail


def test_doctor_fails_a_missing_model_and_warns_on_a_different_reported_model(api):
    _doctor_endpoint(api, models=("other",), reported=MODEL + "-snapshot")
    checks = {c.name: c for c in check_agent(settings(), resolver=openai_dns)}
    assert checks["agent.model"].status == "fail"
    assert checks["agent.model_pin"].status == "warn" and MODEL + "-snapshot" in checks["agent.model_pin"].detail


def test_doctor_reports_a_rejected_key_and_makes_no_calls(api):
    api.get("/models").mock(return_value=httpx.Response(401, json={"error": {"message": "bad key"}}))
    route = api.post("/responses")
    checks = check_agent(settings(), resolver=openai_dns)
    assert checks[-1].name == "agent.reachable" and checks[-1].status == "fail" and route.calls == []


# ---- review fixes: silent reasoning, summaries, strict subset, refusals, state, usage, doctor ------------------------

CREATED = {"type": "response.created", "response": {"model": MODEL, "status": "in_progress"}}


class Stalled(httpx.SyncByteStream):
    """A stream that sends the created event, then nothing until the read times out."""

    def __iter__(self):
        yield f"event: response.created\ndata: {json.dumps(CREATED)}\n\n".encode()
        raise httpx.ReadTimeout("timed out")


def stalled(_request=None) -> httpx.Response:
    return httpx.Response(200, headers={"content-type": "text/event-stream"}, stream=Stalled())


def test_a_read_timeout_after_the_response_began_is_billed_once_and_never_retried(api):
    route = api.post("/responses").mock(side_effect=stalled)
    p, sleeps = build()
    result = p.chat(ask(max_output_tokens=100))
    assert result.status == "error" and len(route.calls) == 1 and sleeps == []
    assert "AGENT_TIMEOUT_SECONDS" in result.error and "not retried" in result.error
    assert result.details["billed"] == [{"model": MODEL, "prompt": result.prompt_tokens_est, "completion": 2100,
                                         "cache_read": 0, "cache_write": 0, "worst_case": True}]


def test_a_read_timeout_before_the_response_began_is_retried(api):
    route = api.post("/responses").mock(side_effect=[httpx.ReadTimeout("slow"), streamed(response(message("ok")))])
    p, sleeps = build()
    result = p.chat(ask())
    assert result.ok and len(route.calls) == 2 and len(sleeps) == 1 and "billed" in result.details
    assert len(result.details["billed"]) == 1


def test_reasoning_summary_events_keep_the_stream_alive_and_are_otherwise_ignored(api):
    summary = {"type": "response.reasoning_summary_text.delta", "item_id": "rs_1", "output_index": 0,
               "summary_index": 0, "delta": "Checking the status", "sequence_number": 1}
    done = response({**reasoning(), "summary": [{"type": "summary_text", "text": "Checking the status"}]},
                    message("ok"))
    api.post("/responses").mock(return_value=sse(CREATED, summary, {"type": "response.completed", "response": done}))
    p, _ = build()
    result = p.chat(ask())
    assert result.ok and result.provider_state["output"][0]["summary"][0]["text"] == "Checking the status"


def test_a_refused_reasoning_summary_is_dropped_for_good(api):
    refused = httpx.Response(400, json={"error": {"message": "Your organization must be verified to generate "
                                                             "reasoning summaries.", "param": "reasoning.summary"}})
    route = api.post("/responses").mock(side_effect=[refused, streamed(response(message("a"))),
                                                     streamed(response(message("b")))])
    p, sleeps = build()
    assert p.chat(ask()).ok and p.chat(ask()).ok and sleeps == []
    assert [sent(route, n)["reasoning"] for n in range(3)] == [
        {"effort": "high", "summary": "auto"}, {"effort": "high"}, {"effort": "high"}]


def test_another_parameters_summary_error_keeps_reasoning_summaries(api):
    other = httpx.Response(400, json={"error": {"message": "Missing required parameter: 'input[1].summary'.",
                                                "param": "input[1].summary"}})
    route = api.post("/responses").mock(side_effect=[other, streamed(response(message("b")))])
    p, _ = build()
    first = p.chat(ask())
    assert first.status == "error" and "input[1].summary" in first.error
    assert p.chat(ask()).ok
    assert [sent(route, n)["reasoning"] for n in range(2)] == [{"effort": "high", "summary": "auto"}] * 2


@pytest.mark.parametrize("code", ["bio_policy", "misalignment_policy_violation"])
def test_a_response_stopped_under_a_safety_policy_is_refused(api, code):
    failed = response(status="failed", error={"code": code, "message": "blocked"}, usage=False)
    api.post("/responses").mock(return_value=streamed(failed))
    p, _ = build()
    result = p.chat(ask())
    assert result.status == "refused" and code in result.error and result.provider_state is None


def test_a_stream_error_event_with_a_nested_error_object_is_read(api):
    api.post("/responses").mock(return_value=sse(CREATED, {"type": "error", "error": {"code": "invalid_prompt",
                                                                                      "message": "nested"}}))
    p, _ = build()
    result = p.chat(ask())
    assert result.status == "error" and "invalid_prompt" in result.error and "nested" in result.error


def test_malformed_usage_in_a_failed_response_is_an_error_not_a_crash(api):
    failed = {"status": "failed", "model": MODEL, "output": [], "error": {"code": "invalid_prompt", "message": "x"},
              "usage": {"input_tokens": 5, "output_tokens": 1, "input_tokens_details": "oops"}}
    api.post("/responses").mock(return_value=sse({"type": "response.failed", "response": failed}))
    p, _ = build()
    result = p.chat(ask())
    assert result.status == "error" and result.details["billed"][0]["prompt"] == 5


OBJ = {"type": "object", "additionalProperties": False}


@pytest.mark.parametrize(("schema", "problem"), [
    ({**OBJ, "properties": {"a": {"allOf": [{"type": "string"}]}}, "required": ["a"]}, "allOf"),
    ({**OBJ, "$defs": {"x": {"type": "string"}}, "properties": {"a": {"$ref": "#/$defs/x", "description": "d"}},
      "required": ["a"]}, "$ref must stand alone"),
    ({**OBJ, "properties": {"page": {"type": "integer", "default": 1}}, "required": ["page"]}, "default"),
    ({**OBJ, "properties": {"a": {"type": "string"}, "b": {"type": "string"}}, "required": ["a"]}, "required"),
    ({**OBJ, "properties": {"a": {"type": "string", "format": "uri"}}, "required": ["a"]}, "format"),
    ({"anyOf": [OBJ]}, "root"),
])
def test_a_schema_outside_the_openai_strict_subset_is_sent_loose(api, schema, problem):
    assert any(problem in p for p in openai_strict_problems(schema)), openai_strict_problems(schema)
    route = api.post("/responses").mock(return_value=streamed(response(message('{"a": "x"}'))))
    p, _ = build()
    assert p.chat(ask(tools=[Tool("loose", "x", schema)])).ok
    assert sent(route)["tools"][0]["strict"] is False


def test_the_openai_strict_subset_accepts_its_documented_keywords():
    schema = {**OBJ, "required": ["n", "ids", "when", "note", "ref"],
              "properties": {"n": {"type": "integer", "minimum": 1, "maximum": 9, "description": "d", "title": "N"},
                             "ids": {"type": "array", "items": {"type": "string", "pattern": "^[a-z]+$"},
                                     "minItems": 1, "maxItems": 20},
                             "when": {"type": "string", "format": "date-time"},
                             "note": {"anyOf": [{"type": "string"}, {"type": "null"}]},
                             "ref": {"$ref": "#/$defs/kind"}},
              "$defs": {"kind": {"type": "string", "enum": ["a", "b"]}}}
    assert openai_strict_problems(schema) == []


def test_a_response_schema_with_optional_properties_is_sent_loose_and_still_checked(api):
    schema = {**OBJ, "properties": {"ok": {"type": "boolean"}, "note": {"type": "string"}}, "required": ["ok"]}
    route = api.post("/responses").mock(side_effect=[streamed(response(message('{"ok": true}'))),
                                                     streamed(response(message('{"note": "x"}')))])
    p, _ = build()
    assert p.chat(ask(response_schema=schema)).ok
    assert sent(route)["text"]["format"]["strict"] is False
    assert p.chat(ask(response_schema=schema)).status == "invalid_json"


def test_stored_state_keeps_only_known_set_fields_so_later_turns_replay(api):
    first = response({"type": "reasoning", "id": "rs_1", "summary": [], "encrypted_content": "gAAA", "content": None,
                      "status": None},
                     {"type": "message", "id": "msg_1", "role": "assistant", "status": "completed", "phase": None,
                      "content": [{"type": "output_text", "text": "hi", "annotations": [], "newfield": 1}]})
    route = api.post("/responses").mock(side_effect=[streamed(first), streamed(response(message("again")))])
    p, _ = build()
    turn = p.chat(ask())
    assert p.chat(ask({"role": "user", "content": "go"}, turn.assistant_message(),
                      {"role": "user", "content": "more"})).ok
    assert sent(route)["input"][1:3] == [
        {"type": "reasoning", "id": "rs_1", "summary": [], "encrypted_content": "gAAA"},
        {"type": "message", "id": "msg_1", "role": "assistant", "status": "completed",
         "content": [{"type": "output_text", "text": "hi", "annotations": []}]}]


def test_json_escaped_and_masked_keys_are_redacted_from_errors(api):
    key = "sk-proj-local&key<0123456789>wxyz"
    backslash = chr(92)
    escaped = key.replace("&", backslash + "u0026").replace("<", backslash + "u003c").replace(">", backslash + "u003e")
    body = '{"error": {"message": "bad key ' + escaped + ', or Incorrect API key provided: sk-proj-****wxyz."}}'
    api.post("/responses").mock(return_value=httpx.Response(401, content=body.encode(),
                                                            headers={"content-type": "application/json"}))
    p, _ = build(settings(agent_api_key=key))
    result = p.chat(ask())
    assert key not in result.error and escaped not in result.raw and "sk-proj-****wxyz" not in result.error
    assert result.error == "HTTP 401: bad key <redacted>, or Incorrect API key provided: <redacted>."


def test_doctor_context_claims_follow_the_endpoint(api):
    _doctor_endpoint(api)
    checks = {c.name: c for c in check_agent(settings(), resolver=openai_dns)}
    assert checks["agent.context"].status == "ok" and "OpenAI refuses" in checks["agent.context"].detail
    other = "https://models.example/v1"
    with respx.mock(base_url=other, assert_all_called=False) as elsewhere:
        _doctor_endpoint(elsewhere)
        checks = {c.name: c for c in check_agent(settings(agent_base_url=other),
                                                 resolver=lambda host: ["198.51.100.9"])}
    assert checks["agent.context"].status == "warn" and "AGENT_CONTEXT_TOKENS" in checks["agent.context"].detail
    local = "http://10.0.0.5:8000/v1"
    with respx.mock(base_url=local, assert_all_called=False) as lan:
        _doctor_endpoint(lan)
        checks = check_agent(settings(agent_base_url=local, model_egress="", agent_api_key=""), resolver=lambda h: [])
    contexts = [c for c in checks if c.name == "agent.context"]
    assert [c.status for c in contexts] == ["warn"] and "local server" in contexts[0].detail


@pytest.mark.parametrize(("effort", "timeout", "warned"), [("high", 180, True), ("max", 599, True),
                                                           ("high", 600, False), ("medium", 180, False)])
def test_doctor_warns_when_the_read_timeout_is_short_for_long_reasoning(api, effort, timeout, warned):
    _doctor_endpoint(api)
    checks = {c.name: c for c in check_agent(settings(agent_effort=effort, agent_timeout_seconds=timeout),
                                             resolver=openai_dns)}
    assert ("agent.timeout" in checks) is warned
    if warned:
        assert checks["agent.timeout"].status == "warn" and "600" in checks["agent.timeout"].detail


def test_doctor_probes_with_the_real_output_cap_and_fails_a_model_whose_limit_is_lower(api):
    api.get("/models").mock(return_value=httpx.Response(200, json={"data": [{"id": MODEL}]}))
    route = api.post("/responses").mock(return_value=httpx.Response(400, json={"error": {
        "message": "max_output_tokens is too large: this model supports at most 32768 output tokens."}}))
    checks = {c.name: c for c in check_agent(settings(agent_max_output_tokens=8000), resolver=openai_dns)}
    assert sent(route, 0)["max_output_tokens"] == 8000 + 2000
    assert checks["agent.output"].status == "fail" and "at most 32768" in checks["agent.output"].detail
    assert checks["agent.tool_calls"].status == "fail"


def test_masked_key_pattern_never_spans_telemetry_and_stays_linear():
    import time

    from romulus.config import redact_text
    s = settings(agent_api_key="sk-proj-0123456789abcdefdata")
    record = '{"task":"task-runner","pw":"****","note":"metadata"}'
    assert redact_text(record, s) == record
    assert redact_text("key sk-proj-****data rejected", s) == "key <redacted> rejected"
    run = "disk-" * 16000 + "****" + "data"
    started = time.perf_counter()
    assert redact_text(run, s) == run
    assert time.perf_counter() - started < 1.0
