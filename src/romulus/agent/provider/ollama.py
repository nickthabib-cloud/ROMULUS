"""Adapter for Ollama's native chat API, for small local runs.

Ollama truncates prompts silently, so the context window is always explicit (AGENT_CONTEXT_TOKENS, else
OLLAMA_NUM_CTX) and a prompt that reaches it is reported as truncated.
"""
from __future__ import annotations

import json

import httpx

from romulus.agent.provider.base import (
    ChatProvider,
    ChatRequest,
    ChatResult,
    ProviderUnavailable,
    ToolCall,
    Usage,
    parse_tool_arguments,
)
from romulus.agent.provider.openai_compatible import PROBE_MAX_OUTPUT, PROBE_TOOL, usage_checks


def _ollama_messages(messages: list[dict]) -> list[dict]:
    """OpenAI-style messages to Ollama's: tool-call arguments are objects, and tool results name no call id."""
    out = []
    for m in messages:
        m = dict(m)
        if m.get("tool_calls"):
            calls = []
            for call in m["tool_calls"]:
                function = dict(call.get("function") or {})
                arguments = function.get("arguments")
                if isinstance(arguments, str):
                    try:
                        function["arguments"] = json.loads(arguments) if arguments.strip() else {}
                    except json.JSONDecodeError:
                        function["arguments"] = {}
                calls.append({"function": function})
            m["tool_calls"] = calls
        m.pop("tool_call_id", None)
        if m.get("content") is None:
            m["content"] = ""
        out.append(m)
    return out


class OllamaProvider(ChatProvider):
    name = "ollama"

    def context_tokens(self) -> int:
        return self.s.agent_context_tokens or self.s.ollama_num_ctx

    def _chat(self, request: ChatRequest, messages: list[dict], max_out: int, est: int) -> ChatResult:
        options: dict = {"num_ctx": self.context_tokens(), "num_predict": max_out, "seed": 7}
        if request.temperature is not None:
            options["temperature"] = request.temperature
        body: dict = {"model": self.model, "stream": False, "messages": _ollama_messages(messages),
                      "think": self.s.ollama_think, "keep_alive": self.s.ollama_keep_alive, "options": options}
        if request.tools:
            body["tools"] = [{"type": "function", "function": {
                "name": t.name, "description": t.description, "parameters": t.parameters,
            }} for t in request.tools]
        if request.response_schema is not None:
            body["format"] = request.response_schema
        response, ms, attempts = self._post("/api/chat", body)
        if response.status_code != 200:
            return self._http_error(response, est, ms, attempts)
        try:
            data = response.json()
            message = data.get("message") or {}
        except (ValueError, AttributeError):
            return ChatResult("error", "", "", None, [], Usage(), est, self.model, "", ms,
                              response.text[:2000], "response is not an Ollama chat reply", attempts)
        calls: list[ToolCall] = []
        for n, call in enumerate(message.get("tool_calls") or []):
            function = (call or {}).get("function") or {}
            calls.append(parse_tool_arguments(f"call_{n}", str(function.get("name") or ""),
                                              function.get("arguments", {})))
        prompt, completion = data.get("prompt_eval_count"), data.get("eval_count")
        # prompt_eval_count counts only non-cached tokens, so a low value is normal; a value at the
        # context ceiling means the prompt was cut. The shared check compares it with num_ctx.
        content = message.get("content")
        return self._finish(
            finish_reason=data.get("done_reason") if data.get("done") else None,
            content=content if isinstance(content, str) else "", tool_calls=calls,
            usage=Usage(prompt if isinstance(prompt, int) else None,
                        completion if isinstance(completion, int) else None),
            est=est, model_reported=str(data.get("model") or ""), ms=ms, raw=response.text, attempts=attempts,
            request=request,
        )

    def probe(self) -> list[tuple[str, str, str]]:
        out = []
        try:
            version = self.http.get("/api/version").json().get("version")
            tags = [m["name"] for m in self.http.get("/api/tags").json().get("models", [])]
        except (httpx.HTTPError, ValueError, KeyError, AttributeError) as exc:
            return [("agent.reachable", "fail", f"{self.decision.host}: {exc.__class__.__name__}")]
        out.append(("agent.reachable", "ok", f"Ollama {version}; {len(tags)} model(s)"))
        if self.model not in tags:
            return [*out, ("agent.model", "fail", f"{self.model} is not pulled")]
        try:
            show = self.http.post("/api/show", json={"model": self.model}).json()
        except (httpx.HTTPError, ValueError):
            show = {}
        limit = next((v for k, v in (show.get("model_info") or {}).items() if k.endswith(".context_length")), None)
        ctx = self.context_tokens()
        out.append(("agent.model", "ok" if limit is None or ctx <= limit else "fail",
                    f"num_ctx={ctx} model_max={limit}"))
        try:
            tool = self.chat(ChatRequest(
                [{"role": "user", "content": "This is a connectivity check. Call report_status with ok set to true."}],
                tools=[PROBE_TOOL], tool_choice="required", max_output_tokens=PROBE_MAX_OUTPUT))
        except ProviderUnavailable as exc:
            return [*out, ("agent.tool_calls", "fail", str(exc))]
        good = tool.ok and any(c.name == PROBE_TOOL.name and (c.arguments or {}).get("ok") is True
                               for c in tool.tool_calls)
        out.append(("agent.tool_calls", "ok" if good else "fail",
                    "tool calling works" if good else f"no valid tool call: {tool.status} {tool.error}"[:300]))
        return out + usage_checks(self.model, (tool,))
