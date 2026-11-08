"""Every real investigator tool can be offered through every model adapter.

The toolbox's argument models use JSON-schema keywords (bounds, defaults, array sizes) that some providers' strict
modes do not accept. An adapter must still send them, loose where strict mode cannot take them: a tool the adapter
refused would stop the agent on that provider. No test reaches a real model: each endpoint is mocked.
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


def test_hypothesis_and_output_tool_schemas_are_strict_and_anthropic_stays_under_its_union_limit(tmp_path):
    from romulus.agent.admission import AgentAdmission
    from romulus.agent.provider.base import parse_tool_arguments
    from romulus.agent.provider.claude_messages import (
        MAX_OPTIONAL_PARAMETERS,
        MAX_STRICT_TOOLS,
        MAX_UNION_PARAMETERS,
        strict_schema_problems,
    )
    from romulus.hunt.run import open_repo

    repo = open_repo(Settings(home=tmp_path))
    repo.create_hunt("h1", {"window": {}, "targets": []}, "d", "test")
    toolbox = Toolbox(repo, "h1")
    AgentAdmission(Settings(home=tmp_path), repo, "h1", "as-test").register(toolbox)
    tools = toolbox.provider_tools()
    assert {"open_hypothesis", "update_hypothesis", "propose_finding", "propose_link", "add_note",
            "request_rule", "finish_session"} <= {tool.name for tool in tools}
    assert all(strict_schema_problems(tool.parameters) == [] for tool in tools)

    settings = Settings(agent_provider="anthropic", agent_model="m", agent_api_key=KEY,
                        model_egress="lab-public-data", agent_context_tokens=1_000_000)
    provider = build_provider(settings, transport=httpx2.MockTransport(_messages), resolver=lambda _host: REMOTE)
    strict, problems = provider._strictness(ChatRequest([{"role": "user", "content": "investigate"}], tools=tools))
    assert not problems
    counts = {"optional": 0, "union": 0}
    for tool in tools:
        if tool.name in strict:
            assert strict_schema_problems(tool.parameters, counts) == []
    assert len(strict) <= MAX_STRICT_TOOLS
    assert counts["optional"] <= MAX_OPTIONAL_PARAMETERS
    assert counts["union"] <= MAX_UNION_PARAMETERS
    assert {"propose_finding", "open_hypothesis", "finish_session"} <= strict

    for raw, message in (("[]", "not a JSON object"), ("NaN", "non-finite JSON number"),
                         ("Infinity", "non-finite JSON number"), ("-Infinity", "non-finite JSON number")):
        parsed = parse_tool_arguments("call", "propose_finding", raw)
        assert parsed.arguments is None and message in parsed.error
