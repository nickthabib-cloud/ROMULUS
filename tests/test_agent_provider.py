"""The AI agent's model-provider port, tested against mocked OpenAI-compatible and Ollama endpoints.

No test reaches a real model or the network: endpoints are httpx mock transports and name resolution is
injected.
"""
import json

import httpx
import pytest
from pydantic import ValidationError

from romulus.agent.provider import (
    AgentBudget,
    AgentNotReady,
    BudgetExhausted,
    BudgetLimits,
    ChatRequest,
    ProviderUnavailable,
    Tool,
    agent_readiness,
    build_provider,
    egress_banners,
    record_call,
)
from romulus.agent.provider.egress import EndpointError, classify
from romulus.config import Settings, load_settings
from romulus.doctor import check_agent

KEY = "sk-test-0123456789abcdef"
REMOTE = "https://api.model.example/v1"
LOCAL = "http://10.20.30.40:8000/v1"
TOOL = Tool("report_status", "Report status.", {
    "type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"], "additionalProperties": False,
})


def resolver_for(table: dict[str, list[str]]):
    def resolve(host: str) -> list[str]:
        if host not in table:
            raise OSError("no such host")
        return table[host]
    return resolve


PUBLIC = resolver_for({"api.model.example": ["198.51.100.7"]})


def remote_settings(**kw) -> Settings:
    base = {"agent_base_url": REMOTE, "agent_model": "model-2026-01-01", "agent_api_key": KEY,
            "model_egress": "lab-public-data"}
    return Settings(**{**base, **kw})


def local_settings(**kw) -> Settings:
    return Settings(**{"agent_base_url": LOCAL, "agent_model": "team-model", **kw})


def completion(*, content=None, tool_calls=None, finish="stop", usage=None, model="model-2026-01-01",
               refusal=None) -> dict:
    message = {"role": "assistant", "content": content}
    if tool_calls is not None:
        message["tool_calls"] = tool_calls
    if refusal is not None:
        message["refusal"] = refusal
    body = {"id": "c1", "model": model, "choices": [{"index": 0, "message": message, "finish_reason": finish}]}
    if usage is not False:
        body["usage"] = usage or {"prompt_tokens": 120, "completion_tokens": 30, "total_tokens": 150}
    return body


def tool_call(name="report_status", arguments='{"ok": true}', call_id="call_1") -> dict:
    return {"id": call_id, "type": "function", "function": {"name": name, "arguments": arguments}}


class Recorder:
    """A mock endpoint that replays responses in order and records every request."""

    def __init__(self, *responses):
        self.responses = list(responses)
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        item = self.responses.pop(0) if len(self.responses) > 1 else self.responses[0]
        if isinstance(item, Exception):
            raise item
        if isinstance(item, httpx.Response):
            return item
        return httpx.Response(200, json=item)

    def body(self, n=-1) -> dict:
        return json.loads(self.requests[n].content)


def provider(settings: Settings, recorder: Recorder, resolver=PUBLIC):
    sleeps: list[float] = []
    p = build_provider(settings, transport=httpx.MockTransport(recorder), resolver=resolver, sleep=sleeps.append)
    return p, sleeps


def ask(**kw) -> ChatRequest:
    return ChatRequest([{"role": "system", "content": "You are a test."}, {"role": "user", "content": "go"}], **kw)


# ---- configuration --------------------------------------------------------------------------------------

def test_agent_keys_load_from_the_env_file(tmp_path):
    env = tmp_path / ".env"
    env.write_text("AGENT_PROVIDER=ollama\nAGENT_BASE_URL=http://127.0.0.1:11434\nAGENT_MODEL=m\n"
                   "AGENT_MAX_CALLS=7\nAGENT_MAX_COST_USD=1.5\nROMULUS_MODEL_EGRESS=lab-public-data\n"
                   "MODEL_LOCAL_HOSTS=llm.enclave.example, 100.64.0.0/10\nAGENT_API_KEY=\n", encoding="utf-8")
    s = load_settings(env, environ={})
    assert (s.agent_provider, s.agent_base_url, s.agent_model, s.agent_max_calls) == (
        "ollama", "http://127.0.0.1:11434", "m", 7)
    assert s.agent_max_cost_usd == 1.5 and s.model_egress == "lab-public-data"
    assert s.model_local_hosts == ["llm.enclave.example", "100.64.0.0/10"]
    assert s.redacted()["agent_api_key"] == "<unset>"


@pytest.mark.parametrize("value", ["lab_public_data", "yes", "true", "LAB-PUBLIC-DATA"])
def test_a_misspelled_egress_switch_is_a_configuration_error(value):
    with pytest.raises(ValidationError):
        Settings(model_egress=value)


def test_the_api_key_is_a_secret_and_never_printed():
    s = remote_settings()
    assert KEY not in json.dumps(s.redacted())
    assert s.redacted()["agent_api_key"] == "<set>"


# ---- egress ---------------------------------------------------------------------------------------------

@pytest.mark.parametrize("url", [
    "http://localhost:8000/v1", "http://127.0.0.1:8000/v1", "http://10.1.2.3/v1", "http://172.16.0.9/v1",
    "http://172.31.255.1/v1", "http://192.168.36.1:11434", "http://[::1]:8000/v1", "http://[fd00::5]/v1",
    "http://[::ffff:10.0.0.1]/v1",
])
def test_loopback_and_private_endpoints_are_local(url):
    d = classify(url, [], "", resolver_for({}))
    assert (d.egress, d.allowed) == ("local", True)


@pytest.mark.parametrize("url", [
    "https://172.32.0.1/v1", "https://8.8.8.8/v1", "https://100.64.1.1/v1", "https://169.254.1.1/v1",
    "https://[2001:db8::1]/v1",
])
def test_other_addresses_are_remote_and_refused_without_the_switch(url):
    d = classify(url, [], "", resolver_for({}))
    assert (d.egress, d.allowed) == ("remote", False)
    assert "ROMULUS_MODEL_EGRESS=lab-public-data" in d.refusal


def test_a_name_is_local_only_when_every_address_is_local():
    resolve = resolver_for({"llm.lan": ["10.0.0.5", "192.168.1.5"], "mixed.lan": ["10.0.0.5", "198.51.100.1"]})
    assert classify("http://llm.lan/v1", [], "", resolve).egress == "local"
    assert classify("http://mixed.lan/v1", [], "", resolve).egress == "remote"


def test_a_name_that_does_not_resolve_is_remote():
    d = classify("http://nowhere.example/v1", [], "", resolver_for({}))
    assert (d.egress, d.allowed) == ("remote", False)
    assert "did not resolve" in d.basis


def test_model_local_hosts_accepts_names_addresses_and_networks():
    resolve = resolver_for({"gpu.enclave.example": ["100.64.3.4"]})
    assert classify("https://LLM.Enclave.Example./v1", ["llm.enclave.example"], "", resolve).egress == "local"
    assert classify("https://gpu.enclave.example/v1", ["100.64.0.0/10"], "", resolve).egress == "local"
    assert classify("https://100.64.9.9/v1", ["100.64.9.9"], "", resolve).egress == "local"
    assert classify("https://gpu.enclave.example/v1", ["100.65.0.0/16"], "", resolve).egress == "remote"


def test_the_switch_allows_a_remote_endpoint_only_over_https():
    assert classify(REMOTE, [], "lab-public-data", PUBLIC).allowed
    d = classify("http://api.model.example/v1", [], "lab-public-data", PUBLIC)
    assert not d.allowed and "https" in d.refusal


@pytest.mark.parametrize("url", ["ftp://10.0.0.1/v1", "https://user:pw@10.0.0.1/v1", "not a url", "http:///v1"])
def test_unusable_endpoint_urls_are_rejected(url):
    with pytest.raises(EndpointError):
        classify(url, [], "", resolver_for({}))


# ---- readiness --------------------------------------------------------------------------------------------

def test_no_endpoint_means_not_configured():
    r = agent_readiness(Settings(), resolver_for({}))
    assert r.state == "not_configured"
    assert r.message() == "agent not configured: AGENT_BASE_URL is empty"


def test_endpoint_without_model_is_not_configured():
    r = agent_readiness(Settings(agent_base_url=LOCAL), resolver_for({}))
    assert (r.state, r.reason) == ("not_configured", "AGENT_MODEL is empty")


def test_remote_endpoint_without_a_key_is_not_configured_so_adding_the_key_is_the_last_step():
    s = remote_settings(agent_api_key="")
    r = agent_readiness(s, PUBLIC)
    assert r.state == "not_configured"
    assert r.message().startswith("agent not configured: AGENT_API_KEY is empty")
    assert agent_readiness(s.model_copy(update={"agent_api_key": remote_settings().agent_api_key}), PUBLIC).ready


def test_remote_endpoint_without_the_switch_is_blocked_even_with_a_key():
    r = agent_readiness(remote_settings(model_egress=""), PUBLIC)
    assert r.state == "blocked" and "ROMULUS_MODEL_EGRESS" in r.reason
    with pytest.raises(AgentNotReady):
        build_provider(remote_settings(model_egress=""), resolver=PUBLIC)


def test_local_server_needs_no_key():
    assert agent_readiness(local_settings(), resolver_for({})).ready


def test_a_cost_budget_without_prices_is_blocked():
    r = agent_readiness(local_settings(agent_max_cost_usd=5.0), resolver_for({}))
    assert r.state == "blocked" and "AGENT_PRICE_INPUT_PER_MTOK" in r.reason


def test_provenance_carries_no_key_and_no_url_path():
    s = remote_settings(agent_base_url="https://api.model.example/v1/secret-path?token=abc")
    prov = agent_readiness(s, PUBLIC).provenance(s)
    text = json.dumps(prov)
    assert KEY not in text and "secret-path" not in text and "token=abc" not in text
    assert prov["endpoint_host"] == "api.model.example" and prov["egress"] == "remote"
    assert prov["budgets"]["max_calls"] == 200


# ---- OpenAI-compatible adapter ------------------------------------------------------------------------------

def test_request_shape_auth_tools_schema_and_output_limit():
    rec = Recorder(completion(tool_calls=[tool_call()], finish="tool_calls"))
    p, _ = provider(remote_settings(), rec)
    result = p.chat(ask(tools=[TOOL], tool_choice="required", response_schema=TOOL.parameters,
                        max_output_tokens=300, temperature=0.2))
    req = rec.requests[0]
    assert str(req.url) == "https://api.model.example/v1/chat/completions"
    assert req.headers["authorization"] == f"Bearer {KEY}"
    body = rec.body()
    assert body["model"] == "model-2026-01-01" and body["max_completion_tokens"] == 300
    assert body["tools"][0]["function"]["name"] == "report_status" and body["tool_choice"] == "required"
    assert body["response_format"]["json_schema"]["strict"] is True and body["temperature"] == 0.2
    assert result.ok and result.finish_reason == "tool_calls"
    assert result.tool_calls[0].arguments == {"ok": True}
    assert (result.usage.prompt_tokens, result.usage.completion_tokens) == (120, 30)
    assert result.model_reported == "model-2026-01-01"


def test_temperature_is_omitted_unless_asked_for():
    rec = Recorder(completion(content="hi"))
    p, _ = provider(remote_settings(), rec)
    p.chat(ask())
    assert "temperature" not in rec.body() and "tools" not in rec.body()


def test_secrets_are_redacted_from_every_outgoing_message():
    rec = Recorder(completion(content="ok"))
    s = remote_settings(es_password="es-pass-9876")
    p, _ = provider(s, rec)
    p.chat(ChatRequest([{"role": "user", "content": f"log line with {KEY} and es-pass-9876"},
                        {"role": "assistant", "content": None, "tool_calls": [
                            tool_call(arguments=json.dumps({"note": "es-pass-9876"}))]},
                        {"role": "tool", "tool_call_id": "call_1", "content": "es-pass-9876"}], tools=[TOOL]))
    sent = rec.requests[0].content.decode()
    assert "es-pass-9876" not in sent
    assert KEY not in sent
    assert "<redacted>" in sent


def test_output_cut_at_the_token_limit_is_truncated_even_when_it_parses():
    rec = Recorder(completion(content='{"ok": true}', finish="length"))
    p, _ = provider(remote_settings(), rec)
    result = p.chat(ask(response_schema=TOOL.parameters))
    assert (result.ok, result.status) == (False, "truncated_output")


def test_prompt_at_the_context_ceiling_is_truncated_input():
    rec = Recorder(completion(content="{}", usage={"prompt_tokens": 7990, "completion_tokens": 5}))
    p, _ = provider(remote_settings(agent_context_tokens=8000, agent_max_output_tokens=64), rec)
    assert p.chat(ask()).status == "truncated_input"


def test_a_prompt_too_large_for_the_context_is_never_sent():
    rec = Recorder(completion(content="{}"))
    p, _ = provider(remote_settings(agent_context_tokens=2048, agent_max_output_tokens=64), rec)
    result = p.chat(ChatRequest([{"role": "user", "content": "x" * 20000}]))
    assert result.status == "too_large" and rec.requests == []


@pytest.mark.parametrize(("kw", "status"), [
    ({"finish": "content_filter", "content": ""}, "refused"),
    ({"refusal": "I can't help with that.", "content": None}, "refused"),
    ({"finish": None, "content": "{}"}, "error"),
    ({"finish": "weird", "content": "{}"}, "error"),
])
def test_refusals_and_unverifiable_stops_are_not_ok(kw, status):
    rec = Recorder(completion(**kw))
    p, _ = provider(remote_settings(), rec)
    assert p.chat(ask()).status == status


@pytest.mark.parametrize("arguments", ['{"ok": tru', '["ok"]', '"ok"'])
def test_malformed_tool_arguments_are_invalid_tool_calls(arguments):
    rec = Recorder(completion(tool_calls=[tool_call(arguments=arguments)], finish="tool_calls"))
    p, _ = provider(remote_settings(), rec)
    result = p.chat(ask(tools=[TOOL]))
    assert result.status == "invalid_tool_call" and result.tool_calls[0].arguments is None


def test_a_call_to_a_tool_that_was_not_offered_is_invalid():
    rec = Recorder(completion(tool_calls=[tool_call(name="run_shell")], finish="tool_calls"))
    p, _ = provider(remote_settings(), rec)
    result = p.chat(ask(tools=[TOOL]))
    assert result.status == "invalid_tool_call" and "run_shell" in result.error
    rec2 = Recorder(completion(tool_calls=[tool_call()], finish="tool_calls"))
    p2, _ = provider(remote_settings(), rec2)
    assert p2.chat(ask()).status == "invalid_tool_call"


def test_schema_output_must_be_a_json_object():
    for content, status in (('{"ok": true}', "ok"), ("not json", "invalid_json"), ("[1]", "invalid_json")):
        p, _ = provider(remote_settings(), Recorder(completion(content=content)))
        result = p.chat(ask(response_schema=TOOL.parameters))
        assert result.status == status
    p, _ = provider(remote_settings(), Recorder(completion(content='{"ok": true}')))
    assert p.chat(ask(response_schema=TOOL.parameters)).parsed == {"ok": True}


def test_missing_usage_is_flagged_not_hidden():
    p, _ = provider(remote_settings(), Recorder(completion(content="hi", usage=False)))
    result = p.chat(ask())
    assert result.ok and not result.usage.reported


def test_servers_that_reject_max_completion_tokens_get_max_tokens():
    rec = Recorder(httpx.Response(400, json={"error": {"message": "Unrecognized request argument: max_completion_tokens"}}),
                   completion(content="hi"))
    p, _ = provider(local_settings(), rec, resolver_for({}))
    assert p.chat(ask(max_output_tokens=100)).ok
    assert "max_tokens" in rec.body(-1) and "max_completion_tokens" not in rec.body(-1)
    p.chat(ask())
    assert "max_tokens" in rec.body(-1)


def test_transient_failures_are_retried_with_backoff():
    rec = Recorder(httpx.Response(503), httpx.Response(429, headers={"retry-after": "7"}), completion(content="hi"))
    p, sleeps = provider(remote_settings(), rec)
    result = p.chat(ask())
    assert result.ok and result.attempts == 3
    assert sleeps == [2.0, 7.0]


def test_an_outage_raises_after_three_retries():
    rec = Recorder(httpx.Response(503, text=f"down; key {KEY}"))
    p, sleeps = provider(remote_settings(), rec)
    with pytest.raises(ProviderUnavailable) as exc:
        p.chat(ask())
    assert len(rec.requests) == 4 and len(sleeps) == 3
    assert KEY not in str(exc.value)


def test_connection_errors_raise_after_three_retries():
    rec = Recorder(httpx.ConnectError("refused"))
    p, sleeps = provider(remote_settings(), rec)
    with pytest.raises(ProviderUnavailable):
        p.chat(ask())
    assert len(rec.requests) == 4 and sleeps == [2.0, 4.0, 8.0]


def test_client_errors_are_not_retried_and_echoed_keys_are_redacted():
    rec = Recorder(httpx.Response(401, json={"error": {"message": f"bad key {KEY}"}}))
    p, sleeps = provider(remote_settings(), rec)
    result = p.chat(ask())
    assert result.status == "error" and len(rec.requests) == 1 and sleeps == []
    assert KEY not in result.error and KEY not in result.raw


def test_redirects_are_not_followed():
    rec = Recorder(httpx.Response(307, headers={"location": "https://elsewhere.example/v1/chat/completions"}))
    p, _ = provider(remote_settings(), rec)
    assert p.chat(ask()).status == "error"
    assert len(rec.requests) == 1


# ---- Ollama adapter ---------------------------------------------------------------------------------------

def ollama_reply(*, content="", tool_calls=None, done_reason="stop", prompt=50, out=10) -> dict:
    message = {"role": "assistant", "content": content}
    if tool_calls is not None:
        message["tool_calls"] = tool_calls
    return {"model": "small:8b", "message": message, "done": True, "done_reason": done_reason,
            "prompt_eval_count": prompt, "eval_count": out}


def ollama_settings(**kw) -> Settings:
    return Settings(**{"agent_provider": "ollama", "agent_base_url": "http://192.168.1.10:11434",
                       "agent_model": "small:8b", "ollama_num_ctx": 4096, **kw})


def test_ollama_request_has_explicit_context_tools_and_schema():
    rec = Recorder(ollama_reply(tool_calls=[{"function": {"name": "report_status", "arguments": {"ok": True}}}]))
    p, _ = provider(ollama_settings(), rec, resolver_for({}))
    result = p.chat(ChatRequest([
        {"role": "user", "content": "go"},
        {"role": "assistant", "content": None, "tool_calls": [tool_call()]},
        {"role": "tool", "tool_call_id": "call_1", "content": "{}"},
    ], tools=[TOOL], response_schema=TOOL.parameters, max_output_tokens=200))
    body = rec.body()
    assert str(rec.requests[0].url).endswith("/api/chat")
    assert body["options"]["num_ctx"] == 4096 and body["options"]["num_predict"] == 200
    assert body["format"] == TOOL.parameters and body["tools"][0]["function"]["name"] == "report_status"
    assert body["messages"][1]["tool_calls"][0]["function"]["arguments"] == {"ok": True}
    assert "tool_call_id" not in body["messages"][2]
    assert result.ok and result.tool_calls[0].arguments == {"ok": True}


def test_ollama_silent_truncation_is_detected():
    p, _ = provider(ollama_settings(), Recorder(ollama_reply(content="{}", prompt=4090)), resolver_for({}))
    assert p.chat(ask(max_output_tokens=64)).status == "truncated_input"
    p, _ = provider(ollama_settings(), Recorder(ollama_reply(content="{}", done_reason="length")), resolver_for({}))
    assert p.chat(ask(max_output_tokens=64)).status == "truncated_output"


def test_ollama_context_comes_from_agent_context_tokens_when_set():
    rec = Recorder(ollama_reply(content="hi"))
    p, _ = provider(ollama_settings(agent_context_tokens=16384), rec, resolver_for({}))
    p.chat(ask(max_output_tokens=64))
    assert rec.body()["options"]["num_ctx"] == 16384


# ---- budgets ----------------------------------------------------------------------------------------------

LIMITS = BudgetLimits(max_calls=3, max_tokens=1000, max_wall_seconds=60, max_cost_usd=0.01,
                      price_input_per_mtok=2.0, price_output_per_mtok=8.0)


def test_each_budget_is_checked_before_the_call():
    now = [0.0]
    b = AgentBudget(LIMITS, clock=lambda: now[0])
    b.check(100, 100)
    with pytest.raises(BudgetExhausted) as exc:
        b.check(500, 600)
    assert exc.value.budget == "tokens"
    b.calls = 3
    with pytest.raises(BudgetExhausted) as exc:
        b.check(1, 1)
    assert exc.value.budget == "calls"
    b.calls = 0
    b.check(1, 1)
    now[0] = 60.0
    with pytest.raises(BudgetExhausted) as exc:
        b.check(1, 1)
    assert exc.value.budget == "wall-clock"


def test_cost_budget_uses_the_worst_case_of_the_next_call():
    b = AgentBudget(LIMITS, cost_usd=0.0095, clock=lambda: 0.0)
    with pytest.raises(BudgetExhausted) as exc:
        b.check(100, 100)        # up to 0.0002 + 0.0008
    assert exc.value.budget == "cost"


def test_spending_continues_from_stored_usage_after_resume():
    b = AgentBudget.from_usage(LIMITS, {"calls": 2, "tokens": 900, "cost_usd": 0.001, "estimated": True},
                               wall_seconds_before=30.0, clock=lambda: 0.0)
    assert (b.calls, b.tokens, b.estimated) == (2, 900, True)
    with pytest.raises(BudgetExhausted):
        b.check(50, 100)


def test_unreported_usage_is_charged_from_an_estimate():
    p, _ = provider(remote_settings(), Recorder(completion(content="x" * 320, usage=False)))
    result = p.chat(ask())
    charged = AgentBudget(LIMITS, clock=lambda: 0.0).charge(result)
    assert charged["estimated"] and charged["completion_tokens"] >= 100 and charged["prompt_tokens"] > 0


# ---- call records, usage roll-up and banners -------------------------------------------------------------------

def _repo_with_hunt(tmp_path):
    from romulus.hunt import run as hunt_run
    repo = hunt_run.open_repo(Settings(home=tmp_path))
    repo.create_hunt("h1", {"window": {}, "targets": []}, "digest", "test")
    return repo


def test_every_call_is_recorded_with_provider_model_finish_usage_and_cost(tmp_path):
    repo = _repo_with_hunt(tmp_path)
    s = remote_settings(agent_price_input_per_mtok=2.0, agent_price_output_per_mtok=8.0)
    rec = Recorder(completion(tool_calls=[tool_call()], finish="tool_calls", model="model-2026-01-01-b"),
                   completion(content="hi", usage=False))
    p, _ = provider(s, rec)
    limits = BudgetLimits.from_settings(s)
    first = record_call(repo, p, hunt_id="h1", purpose="agent.orient", request=ask(tools=[TOOL]),
                        result=p.chat(ask(tools=[TOOL])), limits=limits)
    record_call(repo, p, hunt_id="h1", purpose="agent.assess", request=ask(), result=p.chat(ask()), limits=limits)
    row = next(r for r in repo.model_calls(hunt_id="h1") if r["id"] == first)
    assert (row["provider"], row["endpoint_host"], row["egress"]) == ("openai_compatible", "api.model.example",
                                                                      "remote")
    assert (row["model"], row["model_reported"], row["finish_reason"]) == (
        "model-2026-01-01", "model-2026-01-01-b", "tool_calls")
    assert (row["prompt_eval_count"], row["eval_count"]) == (120, 30)
    assert row["cost_usd_est"] == pytest.approx((120 * 2 + 30 * 8) / 1e6)
    assert row["parsed"]["tool_calls"][0]["name"] == "report_status"
    assert KEY not in json.dumps(row, default=str)
    usage = repo.agent_usage("h1")
    assert usage["calls"] == 2 and usage["estimated"] is True and usage["tokens"] > 150
    assert usage["remote_calls"] == [{"endpoint_host": "api.model.example", "model": "model-2026-01-01",
                                      "calls": 2}]
    assert egress_banners({"egress": "remote", "requested": True}, usage) == [
        "Telemetry excerpts were sent to api.model.example (model-2026-01-01) by the AI agent (2 model calls)."]


def test_legacy_investigator_calls_do_not_count_against_agent_budgets(tmp_path):
    repo = _repo_with_hunt(tmp_path)
    repo.save_model_call({"id": "mc-old", "hunt_id": "h1", "purpose": "triage", "model": "small",
                          "options": {}, "prompt_digest": "d", "status": "ok"})
    assert repo.agent_usage("h1")["calls"] == 0


def test_banners_for_configured_remote_and_local_endpoints():
    empty = {"remote_calls": []}
    configured = {"egress": "remote", "requested": True, "endpoint_host": "api.model.example", "model": "m"}
    assert "no telemetry was sent" in egress_banners(configured, empty)[0]
    assert egress_banners({**configured, "requested": False}, empty) == []
    assert egress_banners({**configured, "egress": "local"}, empty) == []
    assert egress_banners(None, empty) == []


# ---- doctor -------------------------------------------------------------------------------------------------

def test_doctor_says_agent_not_configured_cleanly():
    checks = check_agent(Settings(), resolver=resolver_for({}))
    assert [(c.name, c.status) for c in checks] == [("agent.provider", "ok")]
    assert "agent not configured: AGENT_BASE_URL is empty" in checks[0].detail


def test_doctor_with_a_missing_key_for_a_remote_endpoint_is_not_configured_not_failed():
    checks = check_agent(remote_settings(agent_api_key=""), resolver=PUBLIC)
    assert [(c.name, c.status) for c in checks] == [("agent.provider", "ok")]
    assert "AGENT_API_KEY is empty" in checks[0].detail


def test_doctor_fails_a_remote_endpoint_without_the_switch():
    checks = check_agent(remote_settings(model_egress=""), resolver=PUBLIC)
    assert checks[0].status == "fail" and "ROMULUS_MODEL_EGRESS" in checks[0].detail


def _probe_endpoint(models=("model-2026-01-01",), tool_ok=True, schema_ok=True, models_status=200):
    def handle(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/models"):
            return httpx.Response(models_status, json={"data": [{"id": m} for m in models]})
        body = json.loads(request.content)
        if body.get("tools"):
            args = '{"ok": true}' if tool_ok else '{"ok": fals'
            return httpx.Response(200, json=completion(tool_calls=[tool_call(arguments=args)], finish="tool_calls"))
        return httpx.Response(200, json=completion(content='{"ok": true}' if schema_ok else "nope"))
    return httpx.MockTransport(handle)


def test_doctor_checks_reachability_model_tools_schema_usage_and_egress():
    checks = {c.name: c for c in check_agent(remote_settings(), transport=_probe_endpoint(), resolver=PUBLIC)}
    assert checks["agent.provider"].status == "ok"
    assert checks["agent.egress"].status == "warn" and "telemetry excerpts will be sent" in checks["agent.egress"].detail
    for name in ("agent.reachable", "agent.model", "agent.tool_calls", "agent.json_schema", "agent.usage",
                 "agent.model_pin"):
        assert checks[name].status == "ok", (name, checks[name].detail)


def test_doctor_fails_missing_model_and_broken_tool_calls():
    checks = {c.name: c for c in check_agent(
        remote_settings(), transport=_probe_endpoint(models=("other",), tool_ok=False, schema_ok=False),
        resolver=PUBLIC)}
    assert checks["agent.model"].status == "fail"
    assert checks["agent.tool_calls"].status == "fail"
    assert checks["agent.json_schema"].status == "fail"


def test_doctor_reports_a_rejected_key():
    checks = check_agent(remote_settings(), transport=_probe_endpoint(models_status=401), resolver=PUBLIC)
    assert checks[-1].name == "agent.reachable" and checks[-1].status == "fail"


def test_doctor_local_endpoint_and_unneeded_switch():
    s = local_settings(agent_model="model-2026-01-01", model_egress="lab-public-data")
    checks = {c.name: c for c in check_agent(s, transport=_probe_endpoint(), resolver=resolver_for({}))}
    assert checks["agent.egress"].status == "warn" and "not needed" in checks["agent.egress"].detail
    s = local_settings(agent_model="model-2026-01-01")
    checks = {c.name: c for c in check_agent(s, transport=_probe_endpoint(), resolver=resolver_for({}))}
    assert checks["agent.egress"].status == "ok"


# ---- hunts: the deterministic result never depends on the agent's configuration ---------------------------------

def test_hunt_results_are_identical_whether_the_agent_is_unconfigured_blocked_or_ready(tmp_path, monkeypatch):
    from datetime import UTC, datetime, timedelta

    from romulus import cli
    from romulus.evidence.typed import RawRef, TypedEvent, fv
    from romulus.hunt import run as hunt_run
    from romulus.report.manifest import build_manifest, canonical_manifest
    from romulus.report.markdown import render

    start = datetime(2024, 11, 18, 14, 0, tzinfo=UTC)
    shell = TypedEvent(id="shell", family="process_exec", ts=start + timedelta(minutes=5), host="web1",
                       fields={"process.executable": fv("/bin/sh", "shell:exe"),
                               "process.argv": fv(["/bin/sh", "-c", "id"], "shell:argv")},
                       raw=[RawRef(target="host-x", native_id="shell", digest="d")], normalizer="test@1")

    class PublishingSweep:
        def __init__(self, repo, client, hunt_id, *args, **kwargs):
            self.repo, self.hunt_id = repo, hunt_id
            self.partial_reasons, self.stats = [], {"partitions": 1, "records": 1, "events": 1, "skips": {}}

        def run_target(self, _target):
            raise AssertionError("no targets")

        def finalize(self):
            self.repo.save_evidence(self.hunt_id, [shell], {}, None)
            self.repo.save_candidate({
                "id": f"{self.hunt_id}-c", "hunt_id": self.hunt_id, "rule_id": "host.web_shell", "rule_version": "1",
                "claim": "web service spawned a shell", "claim_type": "observed_action", "event_ids": [shell.id],
                "predicate_fields": [], "entities": [["host", "web1", "host"]], "ts": shell.ts,
                "severity": "critical", "confidence": "high", "lane": "urgent", "priority": 100.0,
                "priority_reasons": [], "gate_results": {}, "benign_alternatives": [], "next_checks": [],
                "group_key": "web1|shell", "source_case_id": None, "source_anchor_id": None,
                "source_link_id": None,
            })

    monkeypatch.setattr(hunt_run, "Sweep", PublishingSweep)
    configs = {
        "unconfigured": Settings(home=tmp_path),
        "no_key": remote_settings(home=tmp_path, agent_base_url="https://198.51.100.7/v1", agent_api_key=""),
        "blocked": remote_settings(home=tmp_path, agent_base_url="https://198.51.100.7/v1", model_egress=""),
        "ready": remote_settings(home=tmp_path, agent_base_url="https://198.51.100.7/v1"),
        "disabled": remote_settings(home=tmp_path, agent_base_url="https://198.51.100.7/v1", agent_default="off"),
    }
    results, canon, reports = {}, {}, {}
    for name, s in configs.items():
        repo = hunt_run.open_repo(s)
        manifest = {"window": {"start": start.isoformat(), "end": (start + timedelta(hours=1)).isoformat()},
                    "targets": [], "source_profiles": {}, "agent_mode": "off", "expansion": {"enabled": False},
                    "style": "broad", "original_input": {}, "pack": {"version": "p"}, "normalizer": "n",
                    "policy": "d", "model": {}, "romulus_version": "t",
                    "ai_agent": hunt_run.ai_agent_entry(s)}
        repo.create_hunt(f"h-{name}", manifest, "digest", "test")
        results[name] = hunt_run.run_hunt(s, f"h-{name}", expand=False)
        canon[name] = canonical_manifest(repo, f"h-{name}")
        reports[name] = build_manifest(repo, f"h-{name}", "test")

    statuses = {name: r["ai_agent"]["status"] for name, r in results.items()}
    assert statuses == {"unconfigured": "not_configured", "no_key": "not_configured", "blocked": "blocked",
                        "ready": "not_run", "disabled": "disabled"}
    assert results["unconfigured"]["ai_agent"]["reason"] == "agent not configured: AGENT_BASE_URL is empty"
    assert "AGENT_API_KEY is empty" in results["no_key"]["ai_agent"]["reason"]
    for name, r in results.items():
        assert (r["execution_state"], r["detection_result"], r["lanes"]) == (
            "completed_within_scope", "reportable_findings", {"urgent": 1}), name

    def findings(m):
        return [(f["rule_id"], f["lane"], f["claim"]) for f in m["findings"]]
    assert all(findings(c) == findings(canon["unconfigured"]) for c in canon.values())
    # only the configured remote endpoint that the hunt asked for carries a banner, and it says nothing was sent
    assert {n: bool(r["banners"]) for n, r in reports.items()} == {
        "unconfigured": False, "no_key": True, "blocked": True, "ready": True, "disabled": False}
    assert "no telemetry was sent" in reports["ready"]["banners"][0]
    md = render({**reports["ready"], "revision": {"number": 1, "id": "r1", "supersedes": None}})
    assert "> **Model egress:**" in md and r"| AI agent | not\_run" in md
    assert KEY not in json.dumps(reports["ready"], default=str)
    assert cli._ai_agent_line(results["unconfigured"]).startswith(
        "AI agent: not_configured (agent not configured: AGENT_BASE_URL is empty)")


def test_cli_no_agent_turns_the_ai_agent_off_for_the_hunt(monkeypatch, capsys, tmp_path):
    from romulus import cli
    from romulus.hunt import run as hunt_run

    seen = {}
    monkeypatch.setattr(cli, "load_settings", lambda _path: Settings(home=tmp_path))
    monkeypatch.setattr(hunt_run, "create_hunt", lambda *a, **kw: seen.update(kw) or "h1")
    monkeypatch.setattr(hunt_run, "run_hunt", lambda *a, **kw: {
        "execution_state": "completed_within_scope", "detection_result": "leads_only", "lanes": {}, "stats": {},
        "ai_agent": {"status": "disabled", "reason": "the AI agent was not requested for this hunt"}})
    assert cli.main(["hunt", "start", "--start", "2024-11-18T10:00:00", "--end", "2024-11-18T11:00:00",
                     "--no-agent"]) == 0
    assert seen["ai_agent"] is False
    assert "AI agent: disabled" in capsys.readouterr().out
