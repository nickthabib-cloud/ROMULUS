"""The model-provider port: one chat interface for every adapter, with truncation, usage and finish-reason checks.

Requests and results use one shape whatever the server. Every adapter must report why generation stopped
and how many tokens it used, and must turn a cut-off prompt or output into an explicit non-ok status: a
truncated answer is never passed on as a complete one. Outgoing text is passed through secret redaction.
"""
from __future__ import annotations

import json
import time
from collections.abc import Callable, Collection
from dataclasses import dataclass, field, replace
from typing import TypeVar

import httpx

from romulus.agent.provider.egress import EgressDecision
from romulus.config import (
    Settings,
    redact_counted,
    redact_text,
    secret_in,
    secret_settings,
    weak_secret_names,
)

CHARS_PER_TOKEN = 3.2          # conservative for English + JSON + log text
TRUNCATION_MARGIN = 32
MAX_RETRIES = 3                # after the first attempt; then the provider is unavailable
RETRY_STATUSES = frozenset({408, 409, 429, 500, 502, 503, 504})
MAX_RETRY_AFTER_SECONDS = 60.0
MAX_ERROR_MESSAGE = 2000       # a provider's own error message is shown whole up to this length
STOP_REASONS = frozenset({"stop", "tool_calls", "function_call"})
T = TypeVar("T")

# ok | too_large | truncated_input | truncated_output | refused | invalid_json | invalid_tool_call | error
STATUSES = ("ok", "too_large", "truncated_input", "truncated_output", "refused", "invalid_json",
            "invalid_tool_call", "error")

# The key of the opaque per-message field an adapter may need replayed with its own assistant turns (for
# example signed thinking blocks). The caller stores it with the message and sends it back unchanged; it is
# never redacted or interpreted outside the adapter that wrote it, and adapters that do not use it never see it.
PROVIDER_STATE = "provider_state"


class ProviderUnavailable(RuntimeError):
    """The endpoint could not be reached, or kept failing, after the bounded retries."""


class AgentNotReady(RuntimeError):
    """The agent is not configured, or its configuration is refused (for example, egress)."""


class HistoryError(ValueError):
    """The conversation cannot be sent as it is: for example, an assistant turn lacks the provider state its
    adapter must replay, or was changed after the model produced it. Nothing was sent."""


# The parts of a replayed assistant turn the secret guard reads: its text, its readable thinking or reasoning, a
# tool call's input as the model streamed it and as it was parsed, and a tool call's name.
SECRET_GUARD_PARTS = ("text", "thinking", "tool_input_streamed", "tool_input_parsed", "tool_name")


class SecretGuardTripped(HistoryError):
    """A replayed assistant turn holds the text of a configured secret: a strong one, unless the turn did not come
    from this port, since a reply has every weak secret's text replaced when it arrives. The turn is signed provider
    state, so it can be neither redacted nor sent: the session it belongs to cannot continue. `trips` names, for
    each match, the secret's setting (its environment name) and the part of the turn it was found in; it never
    holds the value or any text around it. Nothing was sent."""

    def __init__(self, message_index: int, trips: list[tuple[str, str]]):
        self.message_index = message_index
        self.trips = tuple(sorted(set(trips)))
        names = ", ".join(sorted({setting for setting, _ in self.trips}))
        parts = ", ".join(part for part in SECRET_GUARD_PARTS if part in {p for _, p in self.trips})
        super().__init__(f"assistant message {message_index} holds a configured secret ({names}; in its {parts}); "
                         "it is never sent")


def secret_trips(parts: list[tuple[str, str]], secrets: list[tuple[str, str]],
                 weak: Collection[str] = ()) -> list[tuple[str, str]]:
    """(setting, part) for every secret value found in a (part, text) list: names only. A strong secret is found
    wherever its text appears; a weak one (its setting in `weak`) only as a word of its own. A reply has every weak
    secret's text replaced when it arrives (ChatProvider.chat) unless it also holds a strong secret's, so a weak
    secret is named only beside a strong one's or in a turn that did not come from this port: where a strong secret
    is found, only the strong ones are named, since they are what end the session."""
    found = [(name, part) for name, value in secrets for part, text in parts
             if text and secret_in(text, value, name in weak)]
    strong = [trip for trip in found if trip[0] not in weak]
    return strong or found


class TransientFailure(Exception):
    """One attempt failed in a way worth retrying. `detail` and `suffix` frame the message reported when the
    retries run out; `retry_after` is the server's Retry-After header, if any."""

    def __init__(self, detail: str, *, retry_after: str | None = None, suffix: str = ""):
        super().__init__(detail)
        self.detail = detail
        self.retry_after = retry_after
        self.suffix = suffix


def estimate_tokens(text: str) -> int:
    return int(len(text) / CHARS_PER_TOKEN) + 8


# the documented API root for providers that have one; any other provider needs AGENT_BASE_URL
DEFAULT_BASE_URLS = {"anthropic": "https://api.anthropic.com", "openai_responses": "https://api.openai.com/v1"}


def endpoint_url(s: Settings) -> str:
    """AGENT_BASE_URL, or the provider's documented API root when it is unset."""
    return s.agent_base_url.strip() or DEFAULT_BASE_URLS.get(s.agent_provider, "")


def error_message(body: str, settings: Settings) -> str:
    """The provider's own message from an error body (`{"error": {"message": ...}}`, `{"error": "..."}` or
    `{"message": ...}`), whole up to MAX_ERROR_MESSAGE characters; else the start of the body. The body is
    redacted before it is cut, and the message again once decoded (JSON escapes can hide a secret's text)."""
    body = redact_text(body, settings)
    try:
        data = json.loads(body)
    except ValueError:
        return body[:300]
    found = data.get("error") if isinstance(data, dict) else None
    if isinstance(found, dict):
        found = found.get("message")
    elif not isinstance(found, str) and isinstance(data, dict):
        found = data.get("message")
    if not isinstance(found, str) or not found.strip():
        return body[:300]
    return redact_text(found, settings)[:MAX_ERROR_MESSAGE]


@dataclass(frozen=True)
class Tool:
    name: str
    description: str
    parameters: dict          # JSON schema of the arguments object: exactly what the caller's validator accepts
    # whether the caller wants the arguments' shape enforced by the server where it can (a strict mode); an
    # adapter may still send the tool loose, and the caller validates every call's arguments either way
    strict: bool = True


@dataclass(frozen=True)
class ToolCall:
    id: str
    name: str
    arguments: dict | None    # None when the arguments were not a JSON object
    raw_arguments: str
    error: str = ""
    # why the arguments were refused, as `<path>: <type>` reasons (romulus.agent.refusals): never a value
    problems: tuple[str, ...] = ()

    def as_dict(self) -> dict:
        return {"id": self.id, "name": self.name, "arguments": self.arguments,
                "raw_arguments": self.raw_arguments, "error": self.error}


@dataclass(frozen=True)
class Usage:
    prompt_tokens: int | None = None          # every prompt token, including any read from or written to a cache
    completion_tokens: int | None = None
    cache_read_tokens: int | None = None      # of prompt_tokens: read from the provider's prompt cache
    cache_write_tokens: int | None = None     # of prompt_tokens: written to it

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
    attempt_guard: Callable[[dict], bool] | None = field(default=None, repr=False, compare=False)

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
    provider_state: dict | None = None             # opaque; see PROVIDER_STATE and assistant_message()
    details: dict = field(default_factory=dict)    # provider-reported specifics (native stop reason, refusal, ...)
    # secret replacements outgoing redaction made in the text this call added to its conversation, by setting
    # (environment name): numbers only (see redact_messages)
    redactions: dict = field(default_factory=dict)
    # replacements of a weak secret's text in this reply itself, made when it arrived, by setting: numbers only (see
    # ChatProvider.chat)
    reply_redactions: dict = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.status == "ok"

    def assistant_message(self) -> dict:
        """This reply as the assistant message to append to the conversation, with the provider state its
        adapter needs to accept the conversation back. Append it unchanged: an edited or trimmed turn cannot be
        replayed to an adapter that uses provider state."""
        message: dict = {"role": "assistant", "content": self.content or None}
        if self.tool_calls:
            message["tool_calls"] = [{"id": c.id, "type": "function",
                                      "function": {"name": c.name, "arguments": c.raw_arguments}}
                                     for c in self.tool_calls]
        if self.provider_state is not None:
            message[PROVIDER_STATE] = self.provider_state
        return message


def redact_value(value, settings: Settings, counts: dict[str, int] | None = None):
    """Copy of a JSON-like value with every configured secret removed from every string, at any depth: what the
    model wrote, before it is run or stored. `counts` receives the replacements by setting (names only)."""
    if isinstance(value, str):
        return redact_counted(value, settings, counts)
    if isinstance(value, list):
        return [redact_value(v, settings, counts) for v in value]
    if isinstance(value, dict):
        return {k: redact_value(v, settings, counts) for k, v in value.items()}
    return value


def redact_messages(messages: list[dict], settings: Settings, counts: dict[str, int] | None = None) -> list[dict]:
    """Copy of the messages with every configured secret removed from every string, at any depth. The provider
    state is left as it is: it is the model's own earlier output, which must go back byte for byte (signatures
    cover it), and every prompt it was produced from was redacted.

    `counts` receives the replacements, by setting, made in the non-system messages after the last assistant turn:
    what this request adds to an append-only conversation. Earlier messages were counted by the call that first
    sent them, so the counts of a session's calls add up to what it hid once, however often its history is sent
    again. System messages are the product's own instructions, not telemetry, and are never counted."""
    last_assistant = max((i for i, m in enumerate(messages) if isinstance(m, dict) and m.get("role") == "assistant"),
                         default=-1)

    def clean(value, tally):
        if isinstance(value, str):
            return redact_counted(value, settings, tally)
        if isinstance(value, list):
            return [clean(v, tally) for v in value]
        if isinstance(value, dict):
            return {k: clean(v, tally) for k, v in value.items()}
        return value
    out = []
    for i, m in enumerate(messages):
        # system messages are the product's own instructions, not telemetry: redacted, never counted
        system = isinstance(m, dict) and m.get("role") == "system"
        tally = counts if i > last_assistant and not system else None
        out.append({k: v if k == PROVIDER_STATE else clean(v, tally) for k, v in m.items()} if isinstance(m, dict)
                   else clean(m, tally))
    return out


def _strings(value) -> list[str]:
    """Every string in a JSON-like value, keys included, at any depth."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for k, v in value.items() for s in (*_strings(k), *_strings(v))]
    if isinstance(value, list | tuple):
        return [s for v in value for s in _strings(v)]
    return []


def _scrub_json(value, scrub: Callable[[str], str]):
    """Copy of a JSON-like value with `scrub` applied to every string, keys included, at any depth."""
    if isinstance(value, str):
        return scrub(value)
    if isinstance(value, list):
        return [_scrub_json(v, scrub) for v in value]
    if isinstance(value, dict):
        return {scrub(k) if isinstance(k, str) else k: _scrub_json(v, scrub) for k, v in value.items()}
    return value


def _scrub_call(call: ToolCall, scrub: Callable[..., str]) -> ToolCall:
    """The tool call with `scrub` applied to its name and arguments, counted once. Parsed arguments are scrubbed as
    values and written out again as the raw arguments, so the two still agree; arguments that did not parse are
    scrubbed as text."""
    name = scrub(call.name)
    if call.arguments is None:
        arguments, raw = None, scrub(call.raw_arguments)
    else:
        arguments = _scrub_json(call.arguments, scrub)
        if arguments != call.arguments:
            raw = json.dumps(arguments)
        else:
            # the raw text can hold the secret where the parsed value does not (a repeated key): written out again
            raw = call.raw_arguments if scrub(call.raw_arguments) == call.raw_arguments else json.dumps(arguments)
    if name == call.name and arguments == call.arguments and raw == call.raw_arguments:
        return call
    return replace(call, name=name, arguments=arguments, raw_arguments=raw)


def parse_tool_arguments(call_id: str, name: str, raw) -> ToolCall:
    if isinstance(raw, dict):
        try:
            text = json.dumps(raw, sort_keys=True, allow_nan=False)
        except (TypeError, ValueError) as exc:
            return ToolCall(call_id, name, None, json.dumps(raw, sort_keys=True, default=str),
                            f"arguments are not valid JSON: {exc}", ("$: invalid_json",))
        return ToolCall(call_id, name, raw, text)
    text = raw if isinstance(raw, str) else json.dumps(raw)
    try:
        value = json.loads(text, parse_constant=lambda constant: (_ for _ in ()).throw(
            ValueError(f"non-finite JSON number {constant} is not allowed"))) if text.strip() else {}
    except (json.JSONDecodeError, ValueError) as exc:
        return ToolCall(call_id, name, None, text, f"arguments are not valid JSON: {exc}", ("$: invalid_json",))
    if not isinstance(value, dict):
        return ToolCall(call_id, name, None, text, "arguments are not a JSON object", ("$: not_an_object",))
    return ToolCall(call_id, name, value, text)


class ChatProvider:
    """Shared request plumbing: egress decision, context pre-check, redaction, bounded retries."""
    name = ""
    replays_provider_state = False   # adapters that read PROVIDER_STATE from assistant messages
    sends_sampling = True            # adapters that pass ChatRequest.temperature to the server

    def __init__(self, settings: Settings, decision: EgressDecision, transport=None,
                 sleep: Callable[[float], None] = time.sleep):
        if not decision.allowed:
            raise AgentNotReady(decision.refusal)
        self.s = settings
        self.decision = decision
        self.model = settings.agent_model
        self.sleep = sleep
        self.http = self._build_http(transport)

    # ---- adapter hooks --------------------------------------------------------------------------------
    def _build_http(self, transport: httpx.BaseTransport | None) -> httpx.Client | None:
        return httpx.Client(base_url=endpoint_url(self.s).rstrip("/"),
                            timeout=self.s.agent_timeout_seconds, transport=transport,
                            headers=self._headers(), follow_redirects=False,
                            # never through an environment proxy: its host was not classified for egress
                            trust_env=False)

    def _headers(self) -> dict[str, str]:
        return {}

    def context_tokens(self) -> int:
        """The context window the adapter can verify against; 0 when only the server knows it."""
        return self.s.agent_context_tokens

    def output_limit(self, request: ChatRequest) -> int:
        """The most output tokens one call with this request may produce: what the context check and the
        budget check must allow for."""
        return request.max_output_tokens or self.s.agent_max_output_tokens

    def model_output_limit(self) -> int:
        """The most output tokens the model's server reports one call may ask for; 0 when it reports none."""
        return 0

    def _chat(self, request: ChatRequest, messages: list[dict], max_out: int, est: int) -> ChatResult:
        raise NotImplementedError

    def probe(self) -> list[tuple[str, str, str]]:
        """Doctor checks as (name, ok|warn|fail, detail). Sends no telemetry."""
        raise NotImplementedError

    # ---- signed reasoning in replayed turns -----------------------------------------------------------------
    def without_reasoning(self, message: dict) -> dict:
        """`message` (an assistant turn this adapter returned) without the signed reasoning its provider state
        replays, for a turn whose earlier conversation changed (a compaction) or that the provider refused. Its text
        and tool calls stay. The default leaves the turn as it is: an adapter whose replayed reasoning is not bound to
        the earlier conversation, or that has none, has nothing to remove."""
        return message

    def reasoning_rejected(self, result: ChatResult) -> bool:
        """Whether the provider refused `result`'s request because a replayed reasoning block no longer matches the
        conversation it was produced in (removing the reasoning, `without_reasoning`, is the remedy)."""
        return False

    # ---- the port -------------------------------------------------------------------------------------
    def describe(self) -> dict:
        return {"provider": self.name, "model": self.model, "endpoint_host": self.decision.host,
                "endpoint_scheme": self.decision.scheme, "egress": self.decision.egress,
                "egress_basis": self.decision.basis}

    def chat(self, request: ChatRequest) -> ChatResult:
        max_out = self.output_limit(request)
        messages = request.messages
        if not self.replays_provider_state:
            messages = [{k: v for k, v in m.items() if k != PROVIDER_STATE} if isinstance(m, dict) else m
                        for m in messages]
        redactions: dict[str, int] = {}
        messages = redact_messages(messages, self.s, redactions)
        est = estimate_tokens(request.prompt_text())
        ctx = self.context_tokens()
        if ctx and est + max_out > ctx:
            # nothing was sent: no replacement reached the model
            return ChatResult("too_large", "", "", None, [], Usage(), est, self.model, "", 0, "",
                              f"prompt estimate {est} + {max_out} output exceeds the {ctx}-token context")
        result = self._chat(request, messages, max_out, est)
        result.redactions = dict(sorted(redactions.items()))
        if result.error:
            # an error can quote the model (a refusal's words, a tool name it made up): it is stored and shown
            result.error = redact_text(result.error, self.s)
        return self._without_weak_secrets(result)

    # ---- weak secrets in replies ----------------------------------------------------------------------------------
    def _without_weak_secrets(self, result: ChatResult) -> ChatResult:
        """`result` with every weak configured secret's text (config.weak_secret_names) replaced by the redaction
        marker wherever it stands as a word of its own: in the reply's text, its parsed answer, its tool calls' names
        and arguments, and the provider state its turn is replayed from (`_scrub_reply_state`). This happens before
        the reply is validated, run, stored, shown or appended to its conversation, so the session goes on and its
        turn never carries the text onward. `reply_redactions` counts the replacements by setting.

        A reply that also holds a strong secret's text is left as it is: its turn then ends the session at the secret
        guard, as any strong secret's does, and everything taken from it is redacted where it is run or stored."""
        secrets = secret_settings(self.s)
        if not secrets:
            return result
        weak = weak_secret_names(self.s)
        if not weak:
            return result
        texts = _strings([result.content, result.parsed, [call.as_dict() for call in result.tool_calls],
                          result.provider_state])
        if any(name not in weak and value in text for name, value in secrets for text in texts):
            return result
        counts: dict[str, int] = {}

        def scrub(text: str, counted: bool = True) -> str:
            return redact_counted(text, self.s, counts if counted else None, only=weak)

        content = scrub(result.content) if result.content else result.content
        calls = [_scrub_call(call, scrub) for call in result.tool_calls]
        parsed = _scrub_json(result.parsed, lambda text: scrub(text, False))
        state = result.provider_state
        if state is not None:
            state, replayed, calls = self._scrub_reply_state(state, scrub, calls, bool(counts))
            if replayed is not None:
                content = replayed
        if not counts:
            return result
        result.content, result.parsed, result.tool_calls, result.provider_state = content, parsed, calls, state
        result.reply_redactions = dict(sorted(counts.items()))
        return result

    def _scrub_reply_state(self, state: dict, scrub: Callable[..., str], calls: list[ToolCall],
                           changed: bool) -> tuple[dict, str | None, list[ToolCall]]:
        """The adapter's provider state with a weak secret's text replaced, consistent with the reply's scrubbed tool
        calls (`calls`), so that the turn replays: (state, the reply text the state now replays or None when it is
        unchanged, the calls). `scrub(text, counted=True)` replaces the text and counts it; text the reply's content
        or calls already counted is scrubbed uncounted. `changed` says whether the content or calls held any. An
        adapter whose state holds readable text must override this; the default leaves the state as it is."""
        return state, None, calls

    def _retrying(self, attempt_once: Callable[[], T], *, attempt_guard: Callable[[dict], bool] | None = None,
                  billed=None) -> tuple[T, int, int]:
        """Run `attempt_once`, retrying up to MAX_RETRIES times with backoff while it raises TransientFailure.
        Returns its value, the final attempt's duration in ms, and the number of attempts; raises
        ProviderUnavailable when the retries run out. The one retry policy every adapter uses."""
        attempt = 0
        started = time.monotonic()
        while True:
            attempt += 1
            t0 = time.monotonic()
            try:
                value = attempt_once()
            except TransientFailure as failure:
                billed_parts = list(billed() if callable(billed) else billed or [])
                retry_allowed = attempt <= MAX_RETRIES
                guard_allowed = True
                if attempt_guard is not None:
                    guard_allowed = bool(attempt_guard({"billed": billed_parts, "retry_available": retry_allowed}))
                if not retry_allowed or not guard_allowed:
                    reason = (f"{self.decision.host}: {failure.detail} after {attempt} attempts{failure.suffix}"
                              if not retry_allowed else
                              f"{self.decision.host}: retry stopped by the agent budget after {attempt} attempts")
                    unavailable = ProviderUnavailable(redact_text(
                        reason, self.s))
                    unavailable.billed = billed_parts
                    unavailable.duration_ms = int((time.monotonic() - started) * 1000)
                    unavailable.charged_by_guard = attempt_guard is not None
                    raise unavailable from None
                self.sleep(self._backoff(failure.retry_after, attempt))
                continue
            return value, int((time.monotonic() - t0) * 1000), attempt

    @staticmethod
    def _backoff(retry_after: str | None, attempt: int) -> float:
        """The server's Retry-After (capped), else exponential backoff."""
        try:
            return min(max(float(retry_after or ""), 0.0), MAX_RETRY_AFTER_SECONDS)
        except ValueError:
            return 2.0 ** attempt

    def _post(self, path: str, body: dict, *, attempt_guard: Callable[[dict], bool] | None = None,
              billed=None) -> tuple[httpx.Response, int, int]:
        """POST with up to MAX_RETRIES retries on transport errors and retryable statuses.
        Returns the final response, its duration in ms, and the number of attempts."""
        def once() -> httpx.Response:
            try:
                response = self.http.post(path, json=body)
            except httpx.TransportError as exc:
                raise TransientFailure(f"{exc.__class__.__name__}: {exc}") from None
            if response.status_code in RETRY_STATUSES:
                raise TransientFailure(f"HTTP {response.status_code}",
                                       suffix=f": {error_message(response.text, self.s)}",
                                       retry_after=response.headers.get("retry-after", ""))
            return response
        return self._retrying(once, attempt_guard=attempt_guard, billed=billed)

    def _http_error(self, response: httpx.Response, est: int, ms: int, attempts: int) -> ChatResult:
        body = redact_text(response.text, self.s)
        return ChatResult("error", "", "", None, [], Usage(), est, self.model, "", ms, body[:2000],
                          f"HTTP {response.status_code}: {error_message(response.text, self.s)}", attempts)

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
