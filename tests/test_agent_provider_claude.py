"""The anthropic adapter (Claude Messages API through the official SDK), tested against a mocked endpoint.

The SDK sends every request through httpx2, so the endpoint is an httpx2 mock transport replying with the
Messages API's streaming (server-sent events) shapes; name resolution is injected. No test reaches the network,
and every key is fake. Skipped when the optional SDK is not installed.
"""
import json
import logging

import pytest
from pydantic import ValidationError

anthropic = pytest.importorskip("anthropic")
httpx2 = pytest.importorskip("httpx2")

from romulus.agent.provider import (
    PROVIDER_STATE,
    AgentBudget,
    BudgetLimits,
    ChatRequest,
    HistoryError,
    ProviderUnavailable,
    Tool,
    agent_readiness,
    build_provider,
    record_call,
)
from romulus.agent.provider.claude_messages import (
    FALLBACK_BETA,
    EgressViolation,
    instance_problems,
    strict_schema_problems,
)
from romulus.config import Settings, load_settings
from romulus.doctor import check_agent

KEY = "sk-ant-test-0123456789abcdefFAKE"
AMBIENT = "sk-ant-ambient-NOT-OURS-0000"
MODEL = "claude-opus-5-5"
HOST = "api.anthropic.com"
TOOL = Tool("report_status", "Report status.", {
    "type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"], "additionalProperties": False,
})
PIVOT = Tool("pivot", "Follow a lead.", {
    "type": "object", "properties": {"entity": {"type": "string"}, "limit": {"type": "integer", "enum": [10, 50]}},
    "required": ["entity"], "additionalProperties": False,
})


def resolver_for(table):
    def resolve(host):
        if host not in table:
            raise OSError("no such host")
        return table[host]
    return resolve


PUBLIC = resolver_for({HOST: ["198.51.100.20"], "gateway.example": ["198.51.100.21"]})


def claude_settings(**kw) -> Settings:
    base = {"agent_provider": "anthropic", "agent_model": MODEL, "agent_api_key": KEY,
            "model_egress": "lab-public-data", "agent_context_tokens": 1_000_000}
    return Settings(**{**base, **kw})


# ---- a streaming Messages API endpoint -----------------------------------------------------------------------

def sse(events: list[dict]) -> bytes:
    return "".join(f"event: {e['type']}\ndata: {json.dumps(e)}\n\n" for e in events).encode()


def reply(blocks: list[dict], *, stop="end_turn", model=MODEL, usage=None, stop_details=None, iterations=None,
          pings=True) -> bytes:
    """A streamed reply in the documented event order. A tool_use block's "raw" is its input JSON as streamed
    (split across deltas); a text block's text is streamed in two chunks."""
    usage = {"input_tokens": 120, "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0,
             "output_tokens": 30, **(usage or {})}
    events = [{"type": "message_start", "message": {
        "id": "msg_01", "type": "message", "role": "assistant", "model": model, "content": [],
        "stop_reason": None, "stop_sequence": None, "usage": {**usage, "output_tokens": 1}}}]
    if pings:
        events.append({"type": "ping"})
    for i, block in enumerate(blocks):
        kind = block["type"]
        if kind == "text":
            events.append({"type": "content_block_start", "index": i, "content_block": {"type": "text", "text": ""}})
            half = len(block["text"]) // 2
            for chunk in (block["text"][:half], block["text"][half:]):
                events.append({"type": "content_block_delta", "index": i,
                               "delta": {"type": "text_delta", "text": chunk}})
        elif kind == "thinking":
            events.append({"type": "content_block_start", "index": i,
                           "content_block": {"type": "thinking", "thinking": "", "signature": ""}})
            if block.get("thinking"):
                events.append({"type": "content_block_delta", "index": i,
                               "delta": {"type": "thinking_delta", "thinking": block["thinking"]}})
            events.append({"type": "content_block_delta", "index": i,
                           "delta": {"type": "signature_delta", "signature": block["signature"]}})
        elif kind == "tool_use":
            events.append({"type": "content_block_start", "index": i, "content_block": {
                "type": "tool_use", "id": block["id"], "name": block["name"], "input": {}}})
            raw = block["raw"]
            for chunk in (raw[:len(raw) // 2], raw[len(raw) // 2:]):
                if chunk:
                    events.append({"type": "content_block_delta", "index": i,
                                   "delta": {"type": "input_json_delta", "partial_json": chunk}})
        else:            # redacted_thinking, fallback: whole in the start event, no deltas
            events.append({"type": "content_block_start", "index": i, "content_block": block})
        events.append({"type": "content_block_stop", "index": i})
    delta_usage = {"output_tokens": usage["output_tokens"]}
    if iterations is not None:
        delta_usage["iterations"] = iterations
    events.append({"type": "message_delta", "delta": {"stop_reason": stop, "stop_sequence": None,
                                                      "stop_details": stop_details}, "usage": delta_usage})
    events.append({"type": "message_stop"})
    return sse(events)


def text(t):
    return {"type": "text", "text": t}


def tool_use(raw='{"ok": true}', name="report_status", call_id="toolu_01"):
    return {"type": "tool_use", "id": call_id, "name": name, "raw": raw}


THINKING = {"type": "thinking", "thinking": "", "signature": "EqQBCkgIBhABGAIiQL+signature/A=="}
REDACTED = {"type": "redacted_thinking", "data": "EmwKAhgBEgy3va3pzix/LafPsn4aDFIT2Xlxh0L5L8rLVyIwxtE3rA=="}
MODEL_INFO = {"type": "model", "id": MODEL, "display_name": "Claude Opus 5.5", "created_at": "2026-10-01T00:00:00Z",
              "lifecycle": "active", "max_input_tokens": 1_000_000, "max_tokens": 128_000}


class Endpoint:
    """Replays replies to /v1/messages in order (the last one repeats) and answers /v1/models/{id}; records
    every request."""

    def __init__(self, *replies, model_info=None):
        self.replies = list(replies)
        self.model_info = model_info if model_info is not None else MODEL_INFO
        self.requests: list = []

    def __call__(self, request):
        self.requests.append(request)
        if request.url.path.startswith("/v1/models"):
            if isinstance(self.model_info, httpx2.Response):
                return self.model_info
            return httpx2.Response(200, json=self.model_info)
        item = self.replies.pop(0) if len(self.replies) > 1 else self.replies[0]
        if isinstance(item, Exception):
            raise item
        if isinstance(item, httpx2.Response):
            return item
        return httpx2.Response(200, headers={"content-type": "text/event-stream"}, content=item)

    @property
    def calls(self):
        return [r for r in self.requests if r.url.path == "/v1/messages"]

    def body(self, n=-1) -> dict:
        return json.loads(self.calls[n].content)


def provider(settings: Settings, endpoint: Endpoint, resolver=PUBLIC):
    sleeps: list[float] = []
    p = build_provider(settings, transport=httpx2.MockTransport(endpoint), resolver=resolver, sleep=sleeps.append)
    return p, sleeps


def ask(**kw) -> ChatRequest:
    return ChatRequest([{"role": "system", "content": "You are a test."}, {"role": "user", "content": "go"}], **kw)


# ---- configuration and readiness ------------------------------------------------------------------------------

def test_anthropic_keys_load_and_are_validated(tmp_path):
    env = tmp_path / ".env"
    env.write_text("AGENT_PROVIDER=anthropic\nAGENT_MODEL=claude-opus-5-5\nAGENT_EFFORT=xhigh\n"
                   "AGENT_THINKING_TOKENS=32000\nAGENT_REFUSAL_FALLBACK=off\nAGENT_PRICE_CACHE_READ_PER_MTOK=0.2\n"
                   "AGENT_PRICE_CACHE_WRITE_PER_MTOK=5\n", encoding="utf-8")
    s = load_settings(env, environ={})
    assert (s.agent_provider, s.agent_effort, s.agent_thinking_tokens, s.agent_refusal_fallback) == (
        "anthropic", "xhigh", 32000, "off")
    assert (s.agent_price_cache_read_per_mtok, s.agent_price_cache_write_per_mtok) == (0.2, 5.0)
    assert Settings().agent_effort == "high" and Settings().agent_refusal_fallback == "default"
    for bad in ({"agent_effort": "extreme"}, {"agent_effort": "HIGH"}, {"agent_refusal_fallback": "on"},
                {"agent_thinking_tokens": 512}, {"agent_provider": "claude"}):
        with pytest.raises(ValidationError):
            Settings(**bad)


def test_the_documented_api_root_is_the_default_endpoint_and_is_remote():
    r = agent_readiness(claude_settings(), PUBLIC)
    assert r.ready and r.decision.host == HOST and r.decision.egress == "remote"
    blocked = agent_readiness(claude_settings(model_egress=""), PUBLIC)
    assert blocked.state == "blocked" and "ROMULUS_MODEL_EGRESS" in blocked.reason
    plain = agent_readiness(claude_settings(agent_base_url="http://gateway.example"), PUBLIC)
    assert plain.state == "blocked" and "https" in plain.reason


def test_the_key_is_required_and_comes_only_from_agent_api_key(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", AMBIENT)
    r = agent_readiness(claude_settings(agent_api_key=""), PUBLIC)
    assert r.state == "not_configured" and "AGENT_API_KEY" in r.reason


def test_a_priced_agent_needs_the_cache_read_price():
    r = agent_readiness(claude_settings(agent_price_input_per_mtok=4, agent_price_output_per_mtok=20), PUBLIC)
    assert r.state == "blocked" and "AGENT_PRICE_CACHE_READ_PER_MTOK" in r.reason
    assert agent_readiness(claude_settings(agent_price_input_per_mtok=4, agent_price_output_per_mtok=20,
                                           agent_price_cache_read_per_mtok=0.2, agent_max_cost_usd=5), PUBLIC).ready


def test_provenance_names_the_options_and_never_the_key():
    s = claude_settings(agent_effort="max")
    prov = agent_readiness(s, PUBLIC).provenance(s)
    assert prov["provider"] == "anthropic" and prov["endpoint_host"] == HOST
    assert prov["options"] == {"effort": "max", "max_output_tokens": 4096, "thinking_tokens": 60000,
                               "refusal_fallback": "default"}
    assert KEY not in json.dumps(prov)


# ---- the request ----------------------------------------------------------------------------------------------

def test_request_shape_strict_tools_schema_effort_thinking_caching_and_fallback():
    ep = Endpoint(reply([THINKING, tool_use()], stop="tool_use"))
    p, _ = provider(claude_settings(agent_thinking_tokens=20000), ep)
    result = p.chat(ask(tools=[TOOL, PIVOT], response_schema=TOOL.parameters, max_output_tokens=300,
                        temperature=0.2))
    req = ep.calls[0]
    assert (req.url.scheme, req.url.host, req.url.path) == ("https", HOST, "/v1/messages")
    assert req.headers["authorization"] == f"Bearer {KEY}" and "x-api-key" not in req.headers
    assert req.headers["anthropic-beta"] == FALLBACK_BETA and req.headers["anthropic-version"]
    body = ep.body()
    assert body["model"] == MODEL and body["stream"] is True
    assert body["max_tokens"] == 300 + 20000                      # room for thinking on top of the output
    assert body["thinking"] == {"type": "adaptive"}
    assert body["output_config"] == {"effort": "high", "format": {"type": "json_schema", "schema": TOOL.parameters}}
    assert body["fallbacks"] == "default"
    assert body["system"] == [{"type": "text", "text": "You are a test.", "cache_control": {"type": "ephemeral"}}]
    assert body["cache_control"] == {"type": "ephemeral"}
    assert [t["name"] for t in body["tools"]] == ["pivot", "report_status"]      # deterministic order
    assert all(t["strict"] is True and t["eager_input_streaming"] is True for t in body["tools"])
    assert "cache_control" not in body["tools"][-1]                # the breakpoint is on the system prompt
    assert body["tool_choice"] == {"type": "auto"}
    assert not {"temperature", "top_p", "top_k"} & set(body)       # never sampling parameters
    breakpoints = json.dumps(body).count('"cache_control"')
    assert breakpoints <= 4
    assert result.ok and result.finish_reason == "tool_calls" and result.tool_calls[0].arguments == {"ok": True}
    assert result.model_reported == MODEL


def test_without_a_system_prompt_the_breakpoint_closes_the_tool_list_and_fallback_off_sends_no_beta():
    ep = Endpoint(reply([tool_use()], stop="tool_use"))
    p, _ = provider(claude_settings(agent_refusal_fallback="off"), ep)
    p.chat(ChatRequest([{"role": "user", "content": "go"}], tools=[TOOL, PIVOT]))
    body = ep.body()
    assert "system" not in body and body["tools"][-1]["cache_control"] == {"type": "ephemeral"}
    assert "fallbacks" not in body and "anthropic-beta" not in ep.calls[0].headers


def test_translation_of_system_tool_calls_and_tool_results():
    first = Endpoint(reply([THINKING, text("Two leads."), tool_use(call_id="toolu_a"),
                            tool_use('{"entity": "web1"}', name="pivot", call_id="toolu_b")], stop="tool_use"))
    p, _ = provider(claude_settings(), first)
    history = [{"role": "system", "content": "You are a test."}, {"role": "user", "content": "go"}]
    result = p.chat(ChatRequest(history, tools=[TOOL, PIVOT]))
    assert result.ok and [c.name for c in result.tool_calls] == ["report_status", "pivot"]
    history += [result.assistant_message(),
                {"role": "tool", "tool_call_id": "toolu_a", "content": "noted"},
                {"role": "tool", "tool_call_id": "toolu_b", "content": "3 events", "is_error": False},
                {"role": "system", "content": "Budget: 5 calls left."}]
    second = Endpoint(reply([text("done")]))
    p2, _ = provider(claude_settings(), second)
    p2.chat(ChatRequest(history, tools=[TOOL, PIVOT]))
    body = second.body()
    assert body["system"][0]["text"] == "You are a test."
    roles = [m["role"] for m in body["messages"]]
    assert roles == ["user", "assistant", "user", "system"]          # both results in one user message
    assert body["messages"][2]["content"] == [
        {"type": "tool_result", "tool_use_id": "toolu_a", "content": "noted"},
        {"type": "tool_result", "tool_use_id": "toolu_b", "content": "3 events"}]
    assert body["messages"][3] == {"role": "system", "content": "Budget: 5 calls left."}
    assistant = body["messages"][1]["content"]
    assert [b["type"] for b in assistant] == ["thinking", "text", "tool_use", "tool_use"]
    assert assistant[3] == {"type": "tool_use", "id": "toolu_b", "name": "pivot", "input": {"entity": "web1"}}


def test_required_tool_choice_is_auto_plus_an_instruction_replayed_with_its_reply():
    ep = Endpoint(reply([THINKING, tool_use()], stop="tool_use"))
    p, _ = provider(claude_settings(), ep)
    history = [{"role": "user", "content": "check"}]
    result = p.chat(ChatRequest(history, tools=[TOOL], tool_choice="required"))
    body = ep.body()
    assert body["tool_choice"] == {"type": "auto"}
    instruction = body["messages"][-1]
    assert instruction["role"] == "system" and "report_status" in instruction["content"]
    assert result.ok
    history += [result.assistant_message(), {"role": "tool", "tool_call_id": "toolu_01", "content": "ok"}]
    p.chat(ChatRequest(history, tools=[TOOL]))
    replayed = ep.body()["messages"]
    # the instruction keeps its place ahead of the turn it produced: the history stays append-only
    assert replayed[1] == instruction and replayed[2]["role"] == "assistant"
    assert ep.body()["tool_choice"] == {"type": "auto"}


def test_a_required_tool_call_that_does_not_come_is_invalid():
    p, _ = provider(claude_settings(), Endpoint(reply([text("I would rather not.")])))
    result = p.chat(ask(tools=[TOOL], tool_choice="required"))
    assert result.status == "invalid_tool_call" and "without the tool call" in result.error


def test_none_tool_choice_is_passed_through():
    ep = Endpoint(reply([text("hi")]))
    p, _ = provider(claude_settings(), ep)
    p.chat(ask(tools=[TOOL], tool_choice="none"))
    assert ep.body()["tool_choice"] == {"type": "none"}


def test_requests_never_carry_sampling_parameters_and_records_say_so(tmp_path):
    from romulus.hunt import run as hunt_run
    ep = Endpoint(reply([text("hi")]))
    p, _ = provider(claude_settings(), ep)
    request = ask(temperature=0.0)
    result = p.chat(request)
    assert not {"temperature", "top_p", "top_k"} & set(ep.body())
    repo = hunt_run.open_repo(Settings(home=tmp_path))
    repo.create_hunt("h1", {"window": {}, "targets": []}, "digest", "test")
    call = record_call(repo, p, hunt_id="h1", purpose="agent.test", request=request, result=result,
                       limits=BudgetLimits.from_settings(claude_settings()))
    row = next(r for r in repo.model_calls(hunt_id="h1") if r["id"] == call)
    assert row["options"]["temperature"] is None


# ---- strict schemas ---------------------------------------------------------------------------------------------

@pytest.mark.parametrize(("schema", "problem"), [
    ({"type": "object", "properties": {"a": {"type": "string"}}, "required": ["a"]}, "additionalProperties"),
    ({"type": "object", "properties": {"a": {"type": "string", "minLength": 2}}, "required": ["a"],
      "additionalProperties": False}, "minLength"),
    ({"type": "object", "properties": {"n": {"type": "integer", "maximum": 9}}, "required": ["n"],
      "additionalProperties": False}, "maximum"),
    ({"type": "object", "properties": {"a": {"oneOf": [{"type": "string"}, {"type": "null"}]}}, "required": ["a"],
      "additionalProperties": False}, "anyOf"),
    ({"type": "object", "properties": {"a": {"type": "array", "items": {"type": "string"}, "minItems": 2}},
      "required": ["a"], "additionalProperties": False}, "minItems"),
    ({"type": "object", "properties": {"a": {"type": "string", "format": "ipv4-cidr"}}, "required": ["a"],
      "additionalProperties": False}, "format"),
    ({"type": "object", "properties": {"a": {"type": "string", "pattern": r"(a)\1"}}, "required": ["a"],
      "additionalProperties": False}, "pattern"),
    ({"type": "object", "properties": {"a": {"type": "object", "properties": {}, "required": [],
                                             "additionalProperties": True}}, "required": ["a"],
      "additionalProperties": False}, "additionalProperties"),
    ({"type": "object", "properties": {"node": {"$ref": "#/$defs/node"}}, "required": ["node"],
      "additionalProperties": False, "$defs": {"node": {"type": "object", "properties": {
          "child": {"$ref": "#/$defs/node"}}, "required": [], "additionalProperties": False}}}, "recursive"),
    ({"type": "object", "properties": {"a": {"$ref": "https://schemas.example/a.json"}}, "required": ["a"],
      "additionalProperties": False}, "$ref"),
    ({"type": "array", "items": {"type": "string"}}, "top level"),
])
def test_a_schema_outside_the_strict_subset_is_refused_before_sending(schema, problem):
    assert any(problem in p for p in strict_schema_problems(schema)), strict_schema_problems(schema)
    ep = Endpoint(reply([text("hi")]))
    p, _ = provider(claude_settings(), ep)
    result = p.chat(ask(tools=[Tool("bad", "Bad.", schema)]))
    assert result.status == "error" and "strict" in result.error and ep.calls == []
    result = p.chat(ask(response_schema=schema))
    assert result.status == "error" and ep.calls == []


def test_the_documented_subset_is_accepted():
    schema = {"type": "object", "additionalProperties": False, "required": ["kind", "ids"],
              "properties": {"kind": {"type": "string", "enum": ["host", "ip"], "description": "d", "default": "host"},
                             "ids": {"type": "array", "items": {"$ref": "#/$defs/id"}, "minItems": 1},
                             "when": {"type": "string", "format": "date-time"},
                             "note": {"anyOf": [{"type": "string", "pattern": "^[a-z]+$"}, {"type": "null"}]},
                             "fixed": {"const": 3}, "maybe": {"type": ["integer", "null"]}},
              "$defs": {"id": {"type": "string", "title": "id"}}}
    assert strict_schema_problems(schema) == []
    assert instance_problems({"kind": "ip", "ids": ["a"], "note": None, "fixed": 3, "maybe": 2}, schema) == []
    bad = instance_problems({"kind": "file", "ids": [], "fixed": True, "extra": 1}, schema)
    assert len(bad) == 4


def test_the_per_request_complexity_limits_are_checked():
    many = [Tool(f"t{n}", "x", TOOL.parameters) for n in range(21)]
    p, _ = provider(claude_settings(), Endpoint(reply([text("hi")])))
    assert "strict tools" in p.chat(ask(tools=many)).error
    optional = {"type": "object", "properties": {f"p{n}": {"type": "string"} for n in range(25)}, "required": [],
                "additionalProperties": False}
    assert "optional parameters" in p.chat(ask(tools=[Tool("wide", "x", optional)])).error


# ---- the reply: stop reasons, usage, tool inputs ------------------------------------------------------------

def test_end_turn_is_a_complete_answer_and_usage_counts_every_prompt_token():
    usage = {"input_tokens": 50, "cache_creation_input_tokens": 400, "cache_read_input_tokens": 3000,
             "output_tokens": 70}
    p, _ = provider(claude_settings(), Endpoint(reply([THINKING, text("All clear in what was searched.")],
                                                      usage=usage)))
    result = p.chat(ask())
    assert result.ok and result.finish_reason == "stop" and result.content == "All clear in what was searched."
    assert (result.usage.prompt_tokens, result.usage.completion_tokens) == (3450, 70)
    assert (result.usage.cache_read_tokens, result.usage.cache_write_tokens) == (3000, 400)
    assert result.details["stop_reason"] == "end_turn"


def test_the_truncation_check_sees_cached_prompt_tokens():
    usage = {"input_tokens": 10, "cache_creation_input_tokens": 0, "cache_read_input_tokens": 7980}
    p, _ = provider(claude_settings(agent_context_tokens=8000, agent_max_output_tokens=64,
                                    agent_thinking_tokens=1024), Endpoint(reply([text("x")], usage=usage)))
    assert p.chat(ask()).status == "truncated_input"


def test_max_tokens_is_truncated_output_even_when_thinking_used_all_of_it():
    p, _ = provider(claude_settings(), Endpoint(reply([THINKING], stop="max_tokens")))
    result = p.chat(ask())
    assert result.status == "truncated_output" and "AGENT_THINKING_TOKENS" in result.error
    p, _ = provider(claude_settings(), Endpoint(reply([text('{"ok": tr')], stop="max_tokens")))
    assert p.chat(ask(response_schema=TOOL.parameters)).status == "truncated_output"
    p, _ = provider(claude_settings(), Endpoint(reply([tool_use('{"ok": tr')], stop="max_tokens")))
    result = p.chat(ask(tools=[TOOL]))
    assert result.status == "truncated_output"


def test_a_refusal_is_refused_with_its_category_never_nothing_found():
    stop = {"type": "refusal", "category": "cyber", "explanation": "This looks like exploit development."}
    blocks = [THINKING, text("Partial analysis of the beacon"), tool_use()]
    p, _ = provider(claude_settings(), Endpoint(reply(blocks, stop="refusal", stop_details=stop)))
    result = p.chat(ask(tools=[TOOL]))
    assert result.status == "refused" and not result.ok
    assert "cyber" in result.error and result.details["refusal"]["category"] == "cyber"
    assert result.tool_calls == [] and result.provider_state is None   # never run, never replayed
    assert result.content == "Partial analysis of the beacon"            # kept for the record, status says why
    stop_none = {"type": "refusal", "category": None, "explanation": None}
    p, _ = provider(claude_settings(), Endpoint(reply([], stop="refusal", stop_details=stop_none)))
    result = p.chat(ask())
    assert result.status == "refused" and "none given" in result.error


@pytest.mark.parametrize("stop", ["pause_turn", "stop_sequence", "model_context_window_exceeded", "compaction",
                                  "a_reason_from_the_future"])
def test_any_other_stop_reason_is_an_error(stop):
    p, _ = provider(claude_settings(), Endpoint(reply([text("partial")], stop=stop)))
    result = p.chat(ask())
    assert result.status == "error" and stop in result.error


def test_tool_inputs_are_parsed_strictly_from_the_stream_and_checked_against_the_schema():
    p, _ = provider(claude_settings(), Endpoint(reply([tool_use('{"entity": "web1", "limit": 50}', name="pivot")],
                                                      stop="tool_use")))
    result = p.chat(ask(tools=[PIVOT]))
    assert result.ok and result.tool_calls[0].arguments == {"entity": "web1", "limit": 50}
    assert result.tool_calls[0].raw_arguments == '{"entity": "web1", "limit": 50}'
    # the SDK's tolerant parser returns the last two as complete objects; the port's strict parse does not
    for raw, why in (('{"entity": 5}', "schema"), ('{"entity": "a", "limit": 7}', "schema"),
                     ('{"entity": "a", "shell": "id"}', "schema"), ('["web1"]', "JSON object"),
                     ('{"entity": "web1"}garbage', "not valid JSON"), ('{"entity": "we', "not valid JSON")):
        p, _ = provider(claude_settings(), Endpoint(reply([tool_use(raw, name="pivot")], stop="tool_use")))
        result = p.chat(ask(tools=[PIVOT]))
        assert result.status == "invalid_tool_call" and why in result.error, raw
        assert result.tool_calls[0].arguments is None


def test_a_tool_input_the_sdk_cannot_parse_is_invalid_not_a_crash():
    p, _ = provider(claude_settings(), Endpoint(reply([tool_use('{"ok": xyz}')], stop="tool_use")))
    result = p.chat(ask(tools=[TOOL]))
    assert result.status == "invalid_tool_call" and result.tool_calls == []


def test_a_call_to_a_tool_not_offered_and_a_tool_stop_without_a_call_are_invalid():
    p, _ = provider(claude_settings(), Endpoint(reply([tool_use(name="run_shell")], stop="tool_use")))
    assert p.chat(ask(tools=[TOOL])).status == "invalid_tool_call"
    p, _ = provider(claude_settings(), Endpoint(reply([text("calling")], stop="tool_use")))
    assert p.chat(ask(tools=[TOOL])).status == "invalid_tool_call"


def test_schema_output_must_parse_and_match():
    for content, status in (('{"ok": true}', "ok"), ("not json", "invalid_json"), ('{"ok": "yes"}', "invalid_json")):
        p, _ = provider(claude_settings(), Endpoint(reply([text(content)])))
        assert p.chat(ask(response_schema=TOOL.parameters)).status == status, content


# ---- the refusal fallback and the model that answered --------------------------------------------------------

def test_the_model_that_answered_is_recorded_when_the_fallback_served(tmp_path):
    from romulus.hunt import run as hunt_run
    from romulus.report.manifest import _ai_agent
    switch = {"type": "fallback", "from": {"model": MODEL}, "to": {"model": "claude-opus-5"},
              "trigger": {"category": "cyber"}}
    iterations = [{"type": "message", "model": MODEL, "input_tokens": 120, "cache_creation_input_tokens": 0,
                   "cache_read_input_tokens": 0, "output_tokens": 0},
                  {"type": "fallback_message", "model": "claude-opus-5", "input_tokens": 120,
                   "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0, "output_tokens": 30}]
    blocks = [text("Looking at "), THINKING, switch, THINKING, text("the beacon."), tool_use()]
    ep = Endpoint(reply(blocks, stop="tool_use", model=MODEL, iterations=iterations))
    s = claude_settings(agent_price_input_per_mtok=4, agent_price_output_per_mtok=20,
                        agent_price_cache_read_per_mtok=0.2)
    p, _ = provider(s, ep)
    result = p.chat(ask(tools=[TOOL]))
    assert result.ok and result.model_reported == "claude-opus-5" and result.model_requested == MODEL
    assert result.details["fallback"] == {"served_by": "claude-opus-5",
                                          "switches": [{"from": MODEL, "to": "claude-opus-5"}]}
    # the declined model's thinking before the switch is dropped; its text carries over; the marker is not replayed
    kept = result.provider_state["content"]
    assert [b["type"] for b in kept] == ["text", "thinking", "text", "tool_use"]
    assert result.content == "Looking at the beacon."
    # every billed attempt is charged
    charged = AgentBudget(BudgetLimits.from_settings(s), clock=lambda: 0.0).charge(result)
    assert (charged["prompt_tokens"], charged["completion_tokens"]) == (240, 30)
    repo = hunt_run.open_repo(Settings(home=tmp_path))
    repo.create_hunt("h1", {"window": {}, "targets": []}, "digest", "test")
    call = record_call(repo, p, hunt_id="h1", purpose="agent.test", request=ask(tools=[TOOL]), result=result,
                       limits=BudgetLimits.from_settings(s))
    row = next(r for r in repo.model_calls(hunt_id="h1") if r["id"] == call)
    assert (row["model"], row["model_reported"]) == (MODEL, "claude-opus-5")
    assert row["options"]["provider_details"]["fallback"]["served_by"] == "claude-opus-5"
    shown = _ai_agent(repo, "h1", {"ai_agent": {"provider": "anthropic", "model": MODEL}})
    assert shown["usage"]["models_reported"] == [{"model": MODEL, "model_reported": "claude-opus-5", "calls": 1}]


# ---- thinking blocks round-trip, and history that cannot -----------------------------------------------------

def test_thinking_blocks_go_back_byte_for_byte_in_their_place():
    first = Endpoint(reply([THINKING, REDACTED, text("One lead."), tool_use()], stop="tool_use"))
    p, _ = provider(claude_settings(), first)
    history = [{"role": "user", "content": "go"}]
    result = p.chat(ChatRequest(history, tools=[TOOL]))
    message = result.assistant_message()
    assert message[PROVIDER_STATE]["content"][0] == THINKING and message[PROVIDER_STATE]["content"][1] == REDACTED
    history += [message, {"role": "tool", "tool_call_id": "toolu_01", "content": "ok"}]
    stored = json.loads(json.dumps(history))           # as a controller would persist and reload it
    second = Endpoint(reply([text("done")]))
    p2, _ = provider(claude_settings(), second)
    assert p2.chat(ChatRequest(stored, tools=[TOOL])).ok
    sent = second.body()["messages"][1]
    assert sent == {"role": "assistant", "content": [
        THINKING, REDACTED, {"type": "text", "text": "One lead."},
        {"type": "tool_use", "id": "toolu_01", "name": "report_status", "input": {"ok": True}}]}


def test_the_provider_state_is_never_redacted_and_never_reaches_other_adapters():
    signature_with_secret = {**THINKING, "signature": "abcdSECRETabcd"}
    first = Endpoint(reply([signature_with_secret, tool_use()], stop="tool_use"))
    s = claude_settings(es_password="SECRET")
    p, _ = provider(s, first)
    history = [{"role": "user", "content": "go"}]
    history += [p.chat(ChatRequest(history, tools=[TOOL])).assistant_message(),
                {"role": "tool", "tool_call_id": "toolu_01", "content": "result with SECRET"}]
    second = Endpoint(reply([text("done")]))
    p2, _ = provider(s, second)
    p2.chat(ChatRequest(history, tools=[TOOL]))
    body = second.body()
    assert body["messages"][1]["content"][0]["signature"] == "abcdSECRETabcd"     # replayed exactly
    assert body["messages"][2]["content"][0]["content"] == "result with <redacted>"
    # the openai_compatible adapter never forwards the field
    import httpx
    seen = []

    def openai(request):
        seen.append(json.loads(request.content))
        return httpx.Response(200, json={"model": "m", "choices": [{"message": {"content": "hi"},
                                                                     "finish_reason": "stop"}],
                                         "usage": {"prompt_tokens": 1, "completion_tokens": 1}})
    other = build_provider(Settings(agent_base_url="http://10.0.0.5/v1", agent_model="m"),
                           transport=httpx.MockTransport(openai), resolver=resolver_for({}))
    other.chat(ChatRequest(history, tools=[TOOL]))
    assert all(PROVIDER_STATE not in m for m in seen[0]["messages"])


def test_a_tool_call_turn_without_its_provider_state_raises_and_sends_nothing():
    ep = Endpoint(reply([text("x")]))
    p, _ = provider(claude_settings(), ep)
    foreign = [{"role": "user", "content": "go"},
               {"role": "assistant", "content": None, "tool_calls": [
                   {"id": "call_1", "type": "function", "function": {"name": "report_status",
                                                                      "arguments": '{"ok": true}'}}]},
               {"role": "tool", "tool_call_id": "call_1", "content": "ok"}]
    with pytest.raises(HistoryError, match="append-only"):
        p.chat(ChatRequest(foreign, tools=[TOOL]))
    assert ep.calls == []
    # a plain assistant reply without tool calls carries no signed turn to replay
    p.chat(ChatRequest([{"role": "user", "content": "a"}, {"role": "assistant", "content": "b"},
                        {"role": "user", "content": "c"}]))
    assert ep.body()["messages"][1] == {"role": "assistant", "content": "b"}


@pytest.mark.parametrize("edit", ["text", "arguments", "dropped_call", "foreign_state"])
def test_an_edited_turn_raises_and_sends_nothing(edit):
    first = Endpoint(reply([THINKING, text("Lead."), tool_use()], stop="tool_use"))
    p, _ = provider(claude_settings(), first)
    message = p.chat(ChatRequest([{"role": "user", "content": "go"}], tools=[TOOL])).assistant_message()
    if edit == "text":
        message["content"] = "Lead (summarised)."
    elif edit == "arguments":
        message["tool_calls"][0]["function"]["arguments"] = '{"ok": false}'
    elif edit == "dropped_call":
        message["tool_calls"] = []
    else:
        message[PROVIDER_STATE] = {"provider": "openai_compatible", "content": []}
    ep = Endpoint(reply([text("x")]))
    p2, _ = provider(claude_settings(), ep)
    with pytest.raises(HistoryError):
        p2.chat(ChatRequest([{"role": "user", "content": "go"}, message,
                             {"role": "tool", "tool_call_id": "toolu_01", "content": "ok"}], tools=[TOOL]))
    assert ep.calls == []


# ---- ambient SDK discovery is ignored ---------------------------------------------------------------------------

def test_ambient_sdk_configuration_is_ignored(monkeypatch, tmp_path, caplog):
    ambient = {
        "ANTHROPIC_API_KEY": AMBIENT, "ANTHROPIC_AUTH_TOKEN": AMBIENT + "-token",
        "ANTHROPIC_BASE_URL": "https://ambient.example", "ANTHROPIC_LOG": "debug",
        "ANTHROPIC_CUSTOM_HEADERS": f"x-api-key: {AMBIENT}\nAuthorization: Bearer {AMBIENT}\n"
                                    "anthropic-beta: ambient-beta-2099-01-01\nanthropic-version: 2023-06-01\n"
                                    "X-Ambient: 1",
        "ANTHROPIC_PROFILE": "ambient", "ANTHROPIC_CONFIG_DIR": str(tmp_path),
        "ANTHROPIC_FEDERATION_RULE_ID": "fdrl_ambient", "ANTHROPIC_ORGANIZATION_ID": "org_ambient",
        "ANTHROPIC_SERVICE_ACCOUNT_ID": "svac_ambient", "ANTHROPIC_IDENTITY_TOKEN": "eyJ.ambient.jwt",
        "ANTHROPIC_IDENTITY_TOKEN_FILE": str(tmp_path / "token"), "ANTHROPIC_WORKSPACE_ID": "wrkspc_ambient",
        "ANTHROPIC_OPEN_TELEMETRY_TRACES_CONTENT_MODE": "content",
        "HTTPS_PROXY": "http://proxy.corp.example:3128", "HTTP_PROXY": "http://proxy.corp.example:3128",
        "ALL_PROXY": "http://proxy.corp.example:3128",
    }
    for name, value in ambient.items():
        monkeypatch.setenv(name, value)
    caplog.set_level(logging.DEBUG)
    ep = Endpoint(reply([text("hi")]))
    p, _ = provider(claude_settings(), ep)
    assert p.chat(ask()).ok
    req = ep.calls[0]
    assert req.url.host == HOST
    assert req.headers["authorization"] == f"Bearer {KEY}"
    assert "x-api-key" not in req.headers and "x-ambient" not in req.headers
    assert req.headers["anthropic-beta"] == FALLBACK_BETA
    from anthropic._constants import ANTHROPIC_API_VERSION
    assert req.headers["anthropic-version"] == ANTHROPIC_API_VERSION
    assert AMBIENT not in str(req.headers)
    # no proxy: no mounts, and our pinned transport carries every request
    http = p.client._client
    assert http._mounts == {} and http._transport_for_url(req.url) is p.transport
    assert not [r for r in caplog.records if r.name.startswith(("anthropic", "httpx2"))
                and r.levelno < logging.WARNING]


def test_the_production_transport_uses_no_proxy(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.corp.example:3128")
    monkeypatch.setenv("ALL_PROXY", "http://proxy.corp.example:3128")
    p = build_provider(claude_settings(), resolver=PUBLIC)
    http = p.client._client
    assert http._mounts == {} and http.follow_redirects is False and http._trust_env is False
    assert type(p.transport.inner._pool).__name__ == "ConnectionPool"     # not an HTTP proxy pool
    assert p.client.max_retries == 0


def test_a_request_to_any_other_host_is_refused_by_the_transport():
    ep = Endpoint(reply([text("hi")]))
    p, _ = provider(claude_settings(), ep)
    with pytest.raises(EgressViolation):
        p.transport.handle_request(httpx2.Request("GET", "https://ambient.example/v1/models"))
    with pytest.raises(anthropic.APIConnectionError):
        p.client.with_options(base_url="https://ambient.example").models.retrieve(MODEL)
    assert ep.requests == []


# ---- errors, retries and secrets --------------------------------------------------------------------------------

def overloaded_event() -> bytes:
    return sse([{"type": "message_start", "message": {
        "id": "msg_01", "type": "message", "role": "assistant", "model": MODEL, "content": [], "stop_reason": None,
        "stop_sequence": None, "usage": {"input_tokens": 5, "output_tokens": 1}}},
        {"type": "error", "error": {"type": "overloaded_error", "message": "Overloaded"}}])


def test_one_retry_policy_the_ports():
    ep = Endpoint(httpx2.Response(529, json={"type": "error", "error": {"type": "overloaded_error",
                                                                         "message": "Overloaded"}}),
                  httpx2.Response(429, headers={"retry-after": "7"},
                                  json={"type": "error", "error": {"type": "rate_limit_error", "message": "slow"}}),
                  overloaded_event(), reply([text("hi")]))
    p, sleeps = provider(claude_settings(), ep)
    result = p.chat(ask())
    assert result.ok and result.attempts == 4 and len(ep.calls) == 4      # the SDK itself never retried
    assert sleeps == [2.0, 7.0, 8.0]


def test_an_outage_raises_after_three_retries_without_the_key():
    ep = Endpoint(httpx2.Response(503, text=f"down; key {KEY}"))
    p, sleeps = provider(claude_settings(), ep)
    with pytest.raises(ProviderUnavailable) as exc:
        p.chat(ask())
    assert len(ep.calls) == 4 and len(sleeps) == 3 and KEY not in str(exc.value)
    ep = Endpoint(httpx2.ConnectError("refused"))
    p, sleeps = provider(claude_settings(), ep)
    with pytest.raises(ProviderUnavailable):
        p.chat(ask())
    assert sleeps == [2.0, 4.0, 8.0]
    ep = Endpoint(httpx2.ReadTimeout("slow"))
    p, _ = provider(claude_settings(), ep)
    with pytest.raises(ProviderUnavailable):
        p.chat(ask())


def test_broken_streams_are_retried_or_errors_never_a_complete_answer():
    p, sleeps = provider(claude_settings(), Endpoint(b"", reply([text("hi")])))       # closed before it began
    assert p.chat(ask()).ok and sleeps == [2.0]
    started = reply([text("partial answer")]).split(b"event: message_delta")[0]       # cut before the stop
    p, _ = provider(claude_settings(), Endpoint(started))
    result = p.chat(ask())
    assert result.status == "error" and "finish reason" in result.error
    # events before message_start are ignored by the SDK: no reply began, so it is retried, then unavailable
    disordered = sse([{"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}},
                      {"type": "message_stop"}])
    ep = Endpoint(disordered)
    p, _ = provider(claude_settings(), ep)
    with pytest.raises(ProviderUnavailable):
        p.chat(ask())
    assert len(ep.calls) == 4


@pytest.mark.parametrize(("status", "kind", "outcome"), [
    (400, "invalid_request_error", "error"), (401, "authentication_error", "error"),
    (403, "permission_error", "error"), (404, "not_found_error", "error"), (413, "request_too_large", "too_large"),
    (307, None, "error"), (302, None, "error"),
])
def test_client_errors_and_redirects_are_not_retried_and_never_show_the_key(status, kind, outcome):
    if kind:
        response = httpx2.Response(status, json={"type": "error", "error": {"type": kind, "message": f"bad {KEY}"}})
    else:
        response = httpx2.Response(status, headers={"location": f"https://elsewhere.example/?k={KEY}"},
                                   text=f"moved {KEY}")
    ep = Endpoint(response)
    p, sleeps = provider(claude_settings(), ep)
    result = p.chat(ask())
    assert result.status == outcome and len(ep.requests) == 1 and sleeps == []
    for text_ in (result.error, result.raw, repr(result), repr(p), json.dumps(p.describe())):
        assert KEY not in text_


def test_the_key_never_appears_in_a_successful_result_or_reprs():
    ep = Endpoint(reply([text(f"echo {KEY}")]))
    p, _ = provider(claude_settings(), ep)
    result = p.chat(ask())
    assert KEY not in result.raw and KEY not in repr(p) and KEY not in repr(p.client.__dict__.get("_client"))


# ---- context window and doctor ----------------------------------------------------------------------------------

def test_the_context_window_comes_from_the_models_endpoint_when_unset():
    ep = Endpoint(reply([text("hi")]), model_info={**MODEL_INFO, "max_input_tokens": 30_000})
    p, _ = provider(claude_settings(agent_context_tokens=0, agent_thinking_tokens=20_000), ep)
    assert p.chat(ask()).ok
    assert p.context_tokens() == 30_000
    assert len([r for r in ep.requests if r.url.path.startswith("/v1/models")]) == 1     # asked once
    result = p.chat(ChatRequest([{"role": "user", "content": "x" * 40_000}]))
    assert result.status == "too_large" and len(ep.calls) == 1


def doctor_endpoint(model_info=None, tool_reply=None, schema_reply=None):
    def handle(request):
        if request.url.path.startswith("/v1/models"):
            info = model_info if model_info is not None else MODEL_INFO
            return info if isinstance(info, httpx2.Response) else httpx2.Response(200, json=info)
        body = json.loads(request.content)
        content = (tool_reply or reply([THINKING, tool_use()], stop="tool_use")) if body.get("tools") else (
            schema_reply or reply([text('{"ok": true}')]))
        return httpx2.Response(200, headers={"content-type": "text/event-stream"}, content=content)
    return httpx2.MockTransport(handle)


def test_doctor_confirms_model_window_output_tool_calls_schema_usage_and_pin():
    checks = {c.name: c for c in check_agent(claude_settings(agent_context_tokens=0), transport=doctor_endpoint(),
                                             resolver=PUBLIC)}
    assert checks["agent.provider"].status == "ok" and checks["agent.egress"].status == "warn"
    for name in ("agent.reachable", "agent.model", "agent.context", "agent.output", "agent.tool_calls",
                 "agent.json_schema", "agent.usage", "agent.model_pin"):
        assert checks[name].status == "ok", (name, checks[name].detail)
    assert "1000000" in checks["agent.context"].detail


@pytest.mark.parametrize(("info", "check", "words"), [
    ({**MODEL_INFO, "max_input_tokens": None}, "agent.context", "AGENT_CONTEXT_TOKENS"),
    ({**MODEL_INFO, "id": "claude-opus-5-5-20261001"}, "agent.model", "AGENT_MODEL=claude-opus-5-5-20261001"),
    ({**MODEL_INFO, "max_tokens": 32_000}, "agent.output", "AGENT_THINKING_TOKENS"),
    (httpx2.Response(404, json={"type": "error", "error": {"type": "not_found_error", "message": "model"}}),
     "agent.model", "404"),
    (httpx2.Response(401, json={"type": "error", "error": {"type": "authentication_error", "message": KEY}}),
     "agent.reachable", "rejected the key"),
])
def test_doctor_fails_clearly(info, check, words):
    checks = check_agent(claude_settings(agent_context_tokens=0), transport=doctor_endpoint(model_info=info),
                         resolver=PUBLIC)
    found = {c.name: c for c in checks}
    assert found[check].status == "fail" and words in found[check].detail
    assert all(KEY not in c.detail for c in checks)


def test_doctor_tool_probe_without_a_tool_call_is_invalid():
    checks = {c.name: c for c in check_agent(claude_settings(), resolver=PUBLIC,
                                             transport=doctor_endpoint(tool_reply=reply([text("no")])))}
    assert checks["agent.tool_calls"].status == "fail" and "invalid_tool_call" in checks["agent.tool_calls"].detail


# ---- budgets ------------------------------------------------------------------------------------------------------

def test_cache_reads_and_writes_are_priced_and_the_worst_case_never_undercounts():
    s = claude_settings(agent_price_input_per_mtok=4, agent_price_output_per_mtok=20,
                        agent_price_cache_read_per_mtok=0.2, agent_max_cost_usd=1)
    limits = BudgetLimits.from_settings(s)
    assert limits.price_cache_write_per_mtok == pytest.approx(5.0)       # 1.25 x input, the 5-minute write price
    usage = {"input_tokens": 1000, "cache_creation_input_tokens": 2000, "cache_read_input_tokens": 100_000,
             "output_tokens": 500}
    p, _ = provider(s, Endpoint(reply([text("hi")], usage=usage)))
    charged = AgentBudget(limits, clock=lambda: 0.0).charge(p.chat(ask()))
    assert charged["cost_usd"] == pytest.approx((1000 * 4 + 2000 * 5 + 100_000 * 0.2 + 500 * 20) / 1e6)
    assert limits.worst_cost(10_000, 1000) == pytest.approx((10_000 * 5 + 1000 * 20) / 1e6)
    other = BudgetLimits.from_settings(Settings(agent_price_input_per_mtok=2, agent_price_output_per_mtok=8))
    assert other.price_cache_write_per_mtok == 0 and other.worst_cost(1000, 100) == pytest.approx(
        (1000 * 2 + 100 * 8) / 1e6)


def test_the_output_limit_includes_thinking_for_budget_checks():
    p, _ = provider(claude_settings(agent_thinking_tokens=10_000), Endpoint(reply([text("hi")])))
    assert p.output_limit(ask(max_output_tokens=500)) == 10_500
