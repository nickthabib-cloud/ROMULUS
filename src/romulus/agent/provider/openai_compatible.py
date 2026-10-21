"""Adapter for any server that speaks the OpenAI Chat Completions API with tool calling and JSON-schema output.

It serves a team's own model server (vLLM, SGLang, llama.cpp server, LM Studio, TGI, Ollama's /v1) and, in a
lab on public data only, a hosted API. AGENT_BASE_URL is the API root that contains /chat/completions.
"""
from __future__ import annotations

import httpx

from romulus.agent.provider.base import (
    ChatProvider,
    ChatRequest,
    ChatResult,
    ProviderUnavailable,
    Tool,
    ToolCall,
    Usage,
    parse_tool_arguments,
)
from romulus.config import redact_text

PROBE_TOOL = Tool("report_status", "Report that the check succeeded.", {
    "type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"],
    "additionalProperties": False,
})
PROBE_SCHEMA = PROBE_TOOL.parameters
PROBE_MAX_OUTPUT = 512


def _int(value) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


class OpenAICompatibleProvider(ChatProvider):
    name = "openai_compatible"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # newer servers take max_completion_tokens; older ones only max_tokens (switched once, on rejection)
        self._max_param = "max_completion_tokens"

    def _headers(self) -> dict[str, str]:
        key = self.s.agent_api_key.get_secret_value()
        return {"Authorization": f"Bearer {key}"} if key else {}

    def _body(self, request: ChatRequest, messages: list[dict], max_out: int) -> dict:
        body: dict = {"model": self.model, "messages": messages, self._max_param: max_out}
        if request.tools:
            body["tools"] = [{"type": "function", "function": {
                "name": t.name, "description": t.description, "parameters": t.parameters,
            }} for t in request.tools]
            body["tool_choice"] = request.tool_choice
        if request.response_schema is not None:
            body["response_format"] = {"type": "json_schema", "json_schema": {
                "name": request.schema_name, "schema": request.response_schema, "strict": request.strict_schema,
            }}
        if request.temperature is not None:
            body["temperature"] = request.temperature
        return body

    def _chat(self, request: ChatRequest, messages: list[dict], max_out: int, est: int) -> ChatResult:
        body = self._body(request, messages, max_out)
        response, ms, attempts = self._post("/chat/completions", body)
        if response.status_code == 400 and self._max_param == "max_completion_tokens" \
                and "max_completion_tokens" in response.text:
            self._max_param = "max_tokens"
            body[self._max_param] = body.pop("max_completion_tokens")
            response, more_ms, more = self._post("/chat/completions", body)
            ms, attempts = ms + more_ms, attempts + more
        if response.status_code != 200:
            return self._http_error(response, est, ms, attempts)
        try:
            data = response.json()
            choice = data["choices"][0]
            message = choice.get("message") or {}
            calls: list[ToolCall] = []
            for n, call in enumerate(message.get("tool_calls") or []):
                function = call.get("function") or {}
                calls.append(parse_tool_arguments(str(call.get("id") or f"call_{n}"),
                                                  str(function.get("name") or ""), function.get("arguments", "")))
            usage = data.get("usage") or {}
            usage.get("prompt_tokens")
        except (ValueError, KeyError, IndexError, TypeError, AttributeError):
            return ChatResult("error", "", "", None, [], Usage(), est, self.model, "", ms,
                              redact_text(response.text[:2000], self.s), "response is not a chat completion",
                              attempts)
        content = message.get("content")
        return self._finish(
            finish_reason=choice.get("finish_reason"), content=content if isinstance(content, str) else "",
            tool_calls=calls, usage=Usage(_int(usage.get("prompt_tokens")), _int(usage.get("completion_tokens"))),
            est=est, model_reported=str(data.get("model") or ""), ms=ms, raw=response.text, attempts=attempts,
            request=request, refusal=message.get("refusal") or "",
        )

    def probe(self) -> list[tuple[str, str, str]]:
        out: list[tuple[str, str, str]] = []
        try:
            response = self.http.get("/models")
        except httpx.HTTPError as exc:
            return [("agent.reachable", "fail", f"{self.decision.host}: {exc.__class__.__name__}")]
        if response.status_code in (401, 403):
            return [("agent.reachable", "fail", f"{self.decision.host} rejected the key (HTTP {response.status_code})")]
        if response.status_code == 200:
            try:
                ids = sorted(str(m.get("id")) for m in response.json().get("data", []))
            except (ValueError, AttributeError, TypeError):
                ids = []
            out.append(("agent.reachable", "ok", f"{self.decision.host} lists {len(ids)} model(s)"))
            if ids and self.model not in ids:
                out.append(("agent.model", "fail", f"{self.model} is not among the models the server lists"))
            elif ids:
                out.append(("agent.model", "ok", f"{self.model} is listed"))
        else:
            out.append(("agent.reachable", "warn", (f"{self.decision.host} does not list models "
                                                   f"(HTTP {response.status_code}); checking by a call")))
        out += self._probe_calls()
        return out

    def _probe_calls(self) -> list[tuple[str, str, str]]:
        out = []
        user = [{"role": "user", "content": "This is a connectivity check. Call report_status with ok set to true."}]
        try:
            tool = self.chat(ChatRequest(user, tools=[PROBE_TOOL], tool_choice="required",
                                         max_output_tokens=PROBE_MAX_OUTPUT))
            schema = self.chat(ChatRequest(
                [{"role": "user", "content": "This is a connectivity check. Reply with ok set to true."}],
                response_schema=PROBE_SCHEMA, schema_name="report_status", max_output_tokens=PROBE_MAX_OUTPUT))
        except ProviderUnavailable as exc:
            return [("agent.tool_calls", "fail", str(exc))]
        good_tool = tool.ok and any(c.name == PROBE_TOOL.name and (c.arguments or {}).get("ok") is True
                                    for c in tool.tool_calls)
        out.append(("agent.tool_calls", "ok" if good_tool else "fail",
                    "tool calling works" if good_tool else f"no valid tool call: {tool.status} {tool.error}"[:300]))
        good_schema = schema.ok and (schema.parsed or {}).get("ok") is True
        out.append(("agent.json_schema", "ok" if good_schema else "fail",
                    "JSON-schema output works" if good_schema else f"{schema.status} {schema.error}"[:300]))
        out += usage_checks(self.model, (tool, schema))
        return out


def usage_checks(model: str, results) -> list[tuple[str, str, str]]:
    """Doctor checks shared by every adapter: usage reporting and model pinning."""
    out = []
    answered = [r for r in results if r.status != "error"]
    if answered and all(r.usage.reported for r in answered):
        out.append(("agent.usage", "ok", "token usage reported"))
    elif answered:
        out.append(("agent.usage", "warn", ("the server does not report token usage: budgets fall back to "
                                           "estimates and a cut-off prompt can be detected only by AGENT_CONTEXT_TOKENS")))
    reported = sorted({r.model_reported for r in answered if r.model_reported})
    if "latest" in model.lower():
        out.append(("agent.model_pin", "warn", f"{model} is a moving alias; pin a dated snapshot"))
    elif reported and reported != [model]:
        out.append(("agent.model_pin", "warn", (f"requested {model}, the server reports {', '.join(reported)}; "
                                               "pin the snapshot it reports")))
    elif reported:
        out.append(("agent.model_pin", "ok", f"the server reports {reported[0]}"))
    return out
