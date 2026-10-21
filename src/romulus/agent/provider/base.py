"""The model-provider port: one chat interface for every adapter, with truncation, usage and finish-reason checks.

Requests and results use one shape whatever the server. Every adapter must report why generation stopped
and how many tokens it used, and must turn a cut-off prompt or output into an explicit non-ok status: a
truncated answer is never passed on as a complete one. Outgoing text is passed through secret redaction.
"""
from __future__ import annotations

import json
import time
from collections.abc import Callable
from dataclasses import dataclass, field

import httpx

from romulus.agent.provider.egress import EgressDecision
from romulus.config import Settings, redact_text

CHARS_PER_TOKEN = 3.2          # conservative for English + JSON + log text
TRUNCATION_MARGIN = 32
MAX_RETRIES = 3                # after the first attempt; then the provider is unavailable
RETRY_STATUSES = frozenset({408, 409, 429, 500, 502, 503, 504})
MAX_RETRY_AFTER_SECONDS = 60.0
STOP_REASONS = frozenset({"stop", "tool_calls", "function_call"})

# ok | too_large | truncated_input | truncated_output | refused | invalid_json | invalid_tool_call | error
STATUSES = ("ok", "too_large", "truncated_input", "truncated_output", "refused", "invalid_json",
            "invalid_tool_call", "error")


class ProviderUnavailable(RuntimeError):
    """The endpoint could not be reached, or kept failing, after the bounded retries."""


class AgentNotReady(RuntimeError):
    """The agent is not configured, or its configuration is refused (for example, egress)."""


def estimate_tokens(text: str) -> int:
    return int(len(text) / CHARS_PER_TOKEN) + 8


@dataclass(frozen=True)
class Tool:
    name: str
    description: str
    parameters: dict          # JSON schema of the arguments object


@dataclass(frozen=True)
class ToolCall:
    id: str
    name: str
    arguments: dict | None    # None when the arguments were not a JSON object
    raw_arguments: str
    error: str = ""

    def as_dict(self) -> dict:
        return {"id": self.id, "name": self.name, "arguments": self.arguments,
                "raw_arguments": self.raw_arguments, "error": self.error}


@dataclass(frozen=True)
class Usage:
    prompt_tokens: int | None = None
    completion_tokens: int | None = None

    @property
    def reported(self) -> bool:
        return self.prompt_tokens is not None and self.completion_tokens is not None


@dataclass
class ChatRequest:
    """OpenAI-style messages: {role, content}, assistant {tool_calls}, tool {tool_call_id, content}."""
    messages: list[dict]
    tools: list[Tool] = field(default_factory=list)
    tool_choice: str = "auto"                 # auto | required | none
    response_schema: dict | None = None       # JSON schema the reply must satisfy (no tools needed)
    schema_name: str = "romulus_output"
    strict_schema: bool = True
    max_output_tokens: int | None = None      # defaults to AGENT_MAX_OUTPUT_TOKENS
    temperature: float | None = None          # omitted when None: some models accept only their default

    def prompt_text(self) -> str:
        parts = [json.dumps(self.messages, sort_keys=True, default=str)]
        if self.tools:
            parts.append(json.dumps([t.__dict__ for t in self.tools], sort_keys=True))
        if self.response_schema is not None:
            parts.append(json.dumps(self.response_schema, sort_keys=True))
        return "\n".join(parts)


@dataclass
class ChatResult:
    status: str
    finish_reason: str
    content: str
    parsed: dict | None
    tool_calls: list[ToolCall]
    usage: Usage
    prompt_tokens_est: int
    model_requested: str
    model_reported: str
    duration_ms: int
    raw: str
    error: str = ""
    attempts: int = 1

    @property
    def ok(self) -> bool:
        return self.status == "ok"


def redact_messages(messages: list[dict], settings: Settings) -> list[dict]:
    """Copy of the messages with every configured secret removed from every string, at any depth."""
    def clean(value):
        if isinstance(value, str):
            return redact_text(value, settings)
        if isinstance(value, list):
            return [clean(v) for v in value]
        if isinstance(value, dict):
            return {k: clean(v) for k, v in value.items()}
        return value
    return [clean(m) for m in messages]


def parse_tool_arguments(call_id: str, name: str, raw) -> ToolCall:
    if isinstance(raw, dict):
        return ToolCall(call_id, name, raw, json.dumps(raw, sort_keys=True))
    text = raw if isinstance(raw, str) else json.dumps(raw)
    try:
        value = json.loads(text) if text.strip() else {}
    except json.JSONDecodeError as exc:
        return ToolCall(call_id, name, None, text, f"arguments are not valid JSON: {exc}")
    if not isinstance(value, dict):
        return ToolCall(call_id, name, None, text, "arguments are not a JSON object")
    return ToolCall(call_id, name, value, text)


class ChatProvider:
    """Shared request plumbing: egress decision, context pre-check, redaction, bounded retries."""
    name = ""

    def __init__(self, settings: Settings, decision: EgressDecision, transport: httpx.BaseTransport | None = None,
                 sleep: Callable[[float], None] = time.sleep):
        if not decision.allowed:
            raise AgentNotReady(decision.refusal)
        self.s = settings
        self.decision = decision
        self.model = settings.agent_model
        self.sleep = sleep
        self.http = httpx.Client(base_url=settings.agent_base_url.strip().rstrip("/"),
                                 timeout=settings.agent_timeout_seconds, transport=transport,
                                 headers=self._headers(), follow_redirects=False)

    # ---- adapter hooks --------------------------------------------------------------------------------
    def _headers(self) -> dict[str, str]:
        return {}

    def context_tokens(self) -> int:
        """The context window the adapter can verify against; 0 when only the server knows it."""
        return self.s.agent_context_tokens

    def _chat(self, request: ChatRequest, messages: list[dict], max_out: int, est: int) -> ChatResult:
        raise NotImplementedError

    def probe(self) -> list[tuple[str, str, str]]:
        """Doctor checks as (name, ok|warn|fail, detail). Sends no telemetry."""
        raise NotImplementedError

    # ---- the port -------------------------------------------------------------------------------------
    def describe(self) -> dict:
        return {"provider": self.name, "model": self.model, "endpoint_host": self.decision.host,
                "endpoint_scheme": self.decision.scheme, "egress": self.decision.egress,
                "egress_basis": self.decision.basis}

    def chat(self, request: ChatRequest) -> ChatResult:
        max_out = request.max_output_tokens or self.s.agent_max_output_tokens
        messages = redact_messages(request.messages, self.s)
        est = estimate_tokens(request.prompt_text())
        ctx = self.context_tokens()
        if ctx and est + max_out > ctx:
            return ChatResult("too_large", "", "", None, [], Usage(), est, self.model, "", 0, "",
                              f"prompt estimate {est} + {max_out} output exceeds the {ctx}-token context")
        return self._chat(request, messages, max_out, est)

    def _post(self, path: str, body: dict) -> tuple[httpx.Response, int, int]:
        """POST with up to MAX_RETRIES retries on transport errors and retryable statuses.
        Returns the final response, its duration in ms, and the number of attempts."""
        attempt = 0
        while True:
            attempt += 1
            t0 = time.monotonic()
            try:
                response = self.http.post(path, json=body)
            except httpx.TransportError as exc:
                if attempt > MAX_RETRIES:
                    raise ProviderUnavailable(redact_text(
                        f"{self.decision.host}: {exc.__class__.__name__}: {exc} after {attempt} attempts",
                        self.s)) from None
                self.sleep(2.0 ** attempt)
                continue
            ms = int((time.monotonic() - t0) * 1000)
            if response.status_code in RETRY_STATUSES:
                if attempt > MAX_RETRIES:
                    raise ProviderUnavailable(redact_text(
                        f"{self.decision.host}: HTTP {response.status_code} after {attempt} attempts: "
                        f"{response.text[:300]}", self.s))
                self.sleep(self._retry_after(response, attempt))
                continue
            return response, ms, attempt

    @staticmethod
    def _retry_after(response: httpx.Response, attempt: int) -> float:
        header = response.headers.get("retry-after", "")
        try:
            return min(max(float(header), 0.0), MAX_RETRY_AFTER_SECONDS)
        except ValueError:
            return 2.0 ** attempt

    def _http_error(self, response: httpx.Response, est: int, ms: int, attempts: int) -> ChatResult:
        body = redact_text(response.text[:2000], self.s)
        return ChatResult("error", "", "", None, [], Usage(), est, self.model, "", ms, body,
                          f"HTTP {response.status_code}: {body[:300]}", attempts)

    def _finish(self, *, finish_reason: str | None, content: str, tool_calls: list[ToolCall], usage: Usage,
                est: int, model_reported: str, ms: int, raw: str, attempts: int, request: ChatRequest,
                refusal: str = "") -> ChatResult:
        """Apply the completeness checks every adapter shares, in order of severity."""
        raw = redact_text(raw, self.s)

        def result(status: str, error: str = "", parsed: dict | None = None) -> ChatResult:
            return ChatResult(status, finish_reason or "", content, parsed, tool_calls, usage, est, self.model,
                              model_reported, ms, raw, error, attempts)

        ctx = self.context_tokens()
        if ctx and usage.prompt_tokens is not None and usage.prompt_tokens >= ctx - TRUNCATION_MARGIN:
            return result("truncated_input", f"prompt used {usage.prompt_tokens} of the {ctx}-token context: "
                                             "the server may have cut the prompt")
        if not finish_reason:
            return result("error", "the response has no finish reason, so a complete answer cannot be verified")
        if finish_reason == "length":
            return result("truncated_output", "output stopped at the token limit")
        if refusal or finish_reason == "content_filter":
            return result("refused", refusal or "the provider's content filter stopped the output")
        if finish_reason not in STOP_REASONS:
            return result("error", f"unexpected finish reason {finish_reason!r}")
        bad = [c for c in tool_calls if c.error]
        if bad:
            return result("invalid_tool_call", "; ".join(f"{c.name}: {c.error}" for c in bad))
        if tool_calls:
            unknown = sorted({c.name for c in tool_calls} - {t.name for t in request.tools})
            if unknown:
                return result("invalid_tool_call", f"unknown tool(s): {', '.join(unknown)}")
        if request.response_schema is not None and not tool_calls:
            try:
                parsed = json.loads(content)
            except json.JSONDecodeError as exc:
                return result("invalid_json", str(exc))
            if not isinstance(parsed, dict):
                return result("invalid_json", "the reply is not a JSON object")
            return result("ok", parsed=parsed)
        return result("ok")
