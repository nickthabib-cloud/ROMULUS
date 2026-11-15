"""Every real investigator tool can be offered through every model adapter.

The toolbox's argument models use JSON-schema keywords (bounds, defaults, array sizes) that some providers' strict
modes do not accept. An adapter must still send them, loose where strict mode cannot take them: a tool the adapter
refused would stop the agent on that provider. The requests each agent phase really sends must also stay inside the
Messages API's strict limits. No test reaches a real model: each endpoint is mocked.
"""
import json

import httpx
import httpx2
import pytest

from romulus.agent.provider import ChatRequest, build_provider
from romulus.agent.toolbox import Toolbox
from romulus.config import Settings

KEY = "sk-test-toolbox-0123456789abcdef"
REMOTE = ["198.51.100.30"]


def _tools(tmp_path):
    from romulus.hunt import run as hunt_run
    repo = hunt_run.open_repo(Settings(home=tmp_path))
    repo.create_hunt("h1", {"window": {}, "targets": []}, "digest", "test")
    return Toolbox(repo, "h1").provider_tools()


def _sse(events: list[dict]) -> bytes:
    return "".join(f"event: {e['type']}\ndata: {json.dumps(e)}\n\n" for e in events).encode()


def _openai_compatible(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json={"model": "m", "choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}],
                                     "usage": {"prompt_tokens": 10, "completion_tokens": 1}})


def _ollama(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json={"model": "m", "message": {"role": "assistant", "content": "ok"}, "done": True,
                                     "done_reason": "stop", "prompt_eval_count": 10, "eval_count": 1})


def _responses(request: httpx.Request) -> httpx.Response:
    done = {"status": "completed", "model": "m", "usage": {"input_tokens": 10, "output_tokens": 1},
            "output": [{"type": "message", "id": "msg_1", "role": "assistant", "status": "completed",
                        "content": [{"type": "output_text", "text": "ok", "annotations": []}]}]}
    return httpx.Response(200, headers={"content-type": "text/event-stream"},
                          content=_sse([{"type": "response.completed", "response": done}]))


def _messages(request) -> httpx2.Response:
    usage = {"input_tokens": 10, "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0, "output_tokens": 1}
    events = [{"type": "message_start", "message": {"id": "msg_1", "type": "message", "role": "assistant",
                                                    "model": "m", "content": [], "stop_reason": None,
                                                    "stop_sequence": None, "usage": usage}},
              {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}},
              {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "ok"}},
              {"type": "content_block_stop", "index": 0},
              {"type": "message_delta", "delta": {"stop_reason": "end_turn", "stop_sequence": None},
               "usage": {"output_tokens": 1}},
              {"type": "message_stop"}]
    return httpx2.Response(200, headers={"content-type": "text/event-stream"}, content=_sse(events))


ADAPTERS = {
    "openai_compatible": ({"agent_base_url": "http://10.0.0.5:8000/v1"}, httpx.MockTransport, _openai_compatible,
                          lambda body: [t["function"]["name"] for t in body["tools"]]),
    "ollama": ({"agent_base_url": "http://10.0.0.5:11434", "agent_context_tokens": 1_000_000}, httpx.MockTransport,
               _ollama, lambda body: [t["function"]["name"] for t in body["tools"]]),
    "openai_responses": ({"agent_api_key": KEY, "model_egress": "lab-public-data"}, httpx.MockTransport, _responses,
                         lambda body: [t["name"] for t in body["tools"]]),
    "anthropic": ({"agent_api_key": KEY, "model_egress": "lab-public-data", "agent_context_tokens": 1_000_000},
                  httpx2.MockTransport, _messages, lambda body: [t["name"] for t in body["tools"]]),
}


@pytest.mark.parametrize("adapter", sorted(ADAPTERS))
def test_every_toolbox_tool_can_be_sent_by_every_adapter(tmp_path, adapter):
    extra, transport, answer, names = ADAPTERS[adapter]
    tools = _tools(tmp_path)
    assert len(tools) >= 12
    sent: list = []

    def handle(request):
        sent.append(request)
        return answer(request)

    s = Settings(agent_provider=adapter, agent_model="m", **extra)
    p = build_provider(s, transport=transport(handle), resolver=lambda host: REMOTE, sleep=lambda _: None)
    result = p.chat(ChatRequest([{"role": "user", "content": "investigate"}], tools=tools))
    assert result.ok, result.error
    calls = [r for r in sent if r.method == "POST"]
    assert len(calls) == 1
    assert sorted(names(json.loads(calls[0].content))) == sorted(t.name for t in tools)


WRITE_TOOLS = {"open_hypothesis", "update_hypothesis", "propose_finding", "propose_link", "add_note",
               "request_rule", "finish_session"}
# what the first live agent-on hunt sent for investigate, which the API refused as too large a grammar: 15 strict
# tools, 15 union-typed and 0 optional parameters, 56 properties, 24 enum values. Orient, which compiled, sent 11
# strict tools, 14 unions, 38 properties.
REFUSED_INVESTIGATE = {"tools": 15, "union": 15, "properties": 56}


@pytest.mark.parametrize("purpose", ["orient", "investigate", "assess"])
def test_the_real_phase_requests_stay_inside_every_strict_limit(tmp_path, purpose):
    from romulus.agent.admission import AgentAdmission
    from romulus.agent.assessment import ASSESSMENT_SCHEMA
    from romulus.agent.provider.claude_messages import (
        GRAMMAR_BUDGET,
        MAX_OPTIONAL_PARAMETERS,
        MAX_STRICT_TOOLS,
        MAX_UNION_PARAMETERS,
        strict_schema_problems,
    )
    from romulus.hunt.run import open_repo

    repo = open_repo(Settings(home=tmp_path))
    repo.create_hunt("h1", {"window": {}, "targets": []}, "d", "test")
    if purpose == "assess":
        request = ChatRequest([{"role": "user", "content": "assess"}], response_schema=ASSESSMENT_SCHEMA)
        expected: set = set()
    else:
        toolbox = Toolbox(repo, "h1")
        AgentAdmission(Settings(home=tmp_path), repo, "h1", "as-test", purpose=purpose).register(toolbox)
        request = ChatRequest([{"role": "user", "content": purpose}], tools=toolbox.provider_tools())
        expected = {"open_hypothesis", "finish_session"} if purpose == "orient" else WRITE_TOOLS
        assert {t.name for t in request.tools if t.strict} == expected

    sent: list = []

    def handle(r):
        sent.append(r)
        return _messages(r)

    settings = Settings(agent_provider="anthropic", agent_model="m", agent_api_key=KEY,
                        model_egress="lab-public-data", agent_context_tokens=1_000_000)
    provider = build_provider(settings, transport=httpx2.MockTransport(handle), resolver=lambda _host: REMOTE)
    strict, problems = provider._strictness(request)
    assert not problems and set(strict) == expected       # every tool asking for strictness fits
    provider.chat(request)
    body = json.loads(next(r for r in sent if r.method == "POST").content)
    schemas = [t["input_schema"] for t in body.get("tools", []) if t["strict"]]
    assert {t["name"] for t in body.get("tools", []) if t["strict"]} == expected
    if purpose == "assess":
        schemas.append(body["output_config"]["format"]["schema"])
    counts: dict = {}
    for schema in schemas:
        assert strict_schema_problems(schema, counts) == []
    assert counts["optional"] <= MAX_OPTIONAL_PARAMETERS and counts["union"] <= MAX_UNION_PARAMETERS
    assert len(expected) <= min(MAX_STRICT_TOOLS, GRAMMAR_BUDGET["tools"])
    if purpose != "assess":
        for key in ("optional", "union", "properties", "enum"):
            assert counts[key] <= GRAMMAR_BUDGET[key], key
        assert counts["pattern"] == 0
        # well inside what was refused, on each measure
        assert len(expected) < REFUSED_INVESTIGATE["tools"] and counts["union"] < REFUSED_INVESTIGATE["union"]
        assert counts["properties"] < REFUSED_INVESTIGATE["properties"]
    # the budget would not have let the refused request through
    assert REFUSED_INVESTIGATE["tools"] > GRAMMAR_BUDGET["tools"]
    assert REFUSED_INVESTIGATE["union"] > GRAMMAR_BUDGET["union"]


def test_tool_arguments_that_are_not_a_json_object_are_refused():
    from romulus.agent.provider.base import parse_tool_arguments

    for raw, message in (("[]", "not a JSON object"), ("NaN", "non-finite JSON number"),
                         ("Infinity", "non-finite JSON number"), ("-Infinity", "non-finite JSON number")):
        parsed = parse_tool_arguments("call", "propose_finding", raw)
        assert parsed.arguments is None and message in parsed.error
