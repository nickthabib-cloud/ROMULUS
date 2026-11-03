"""Adapter for the Claude Messages API, through Anthropic's official Python SDK (the optional romulus[anthropic]
install, imported only when this adapter is built).

AGENT_BASE_URL defaults to https://api.anthropic.com, a remote endpoint: telemetry may reach it only under
ROMULUS_MODEL_EGRESS=lab-public-data, over https. The SDK is given the key from AGENT_API_KEY, an HTTP client built
here (no environment proxy, no redirects, every request pinned to the classified host and stripped of headers the
environment would add) and no retries of its own, so the port's one retry policy applies. Credentials, endpoints,
headers, logging and tracing the SDK would otherwise read from the environment are not used.

Translation: leading system messages become the top-level system prompt and later ones mid-conversation system
messages; assistant tool calls become tool_use blocks; consecutive tool results go back in one user message. Tools
are sent strict, and a schema outside the strict subset the API documents is refused before anything is sent; a
response schema becomes output_config.format; sampling parameters are never sent. tool_choice "required" becomes
"auto" with an instruction to call a tool, and a reply without one is invalid_tool_call. Thinking is adaptive,
AGENT_EFFORT sets how much, and every call's max_tokens adds AGENT_THINKING_TOKENS of room for it. Calls stream
(large max_tokens values need it), tool inputs stream as generated, and so each tool input is parsed strictly from
the raw stream and checked against its schema here. The tools and system prompt form a cached prefix, and the
growing conversation is cached automatically.

Sessions must be append-only, or start fresh. Claude signs its thinking blocks, and they must go back unchanged, in
their original place in the turn that produced them, in a conversation whose earlier turns are unchanged. Each
reply's blocks travel in the provider state of its assistant message (ChatResult.assistant_message()). An assistant
turn with tool calls but no provider state (history from another provider, or a trimmed or rebuilt turn), or whose
text or tool calls no longer match it, raises HistoryError before anything is sent.
"""
from __future__ import annotations

import copy
import json
import logging
import os
import re
import time
from collections.abc import Callable

from romulus.agent.provider.base import (
    PROVIDER_STATE,
    RETRY_STATUSES,
    ChatProvider,
    ChatRequest,
    ChatResult,
    HistoryError,
    ToolCall,
    TransientFailure,
    Usage,
    endpoint_url,
    parse_tool_arguments,
)
from romulus.agent.provider.egress import EgressDecision
from romulus.agent.provider.openai_compatible import probe_calls
from romulus.config import Settings, redact_text

# the server-side refusal fallback, "default" form: the API picks the fallback model by refusal category
FALLBACK_BETA = "server-side-fallback-2026-07-01"
CACHE = {"type": "ephemeral"}            # five-minute cache entries
OVERLOADED = 529
RETRY_ERROR_TYPES = frozenset({"overloaded_error", "rate_limit_error", "api_error"})   # also sent mid-stream
STOP_REASONS = {"end_turn": "stop", "tool_use": "tool_calls", "max_tokens": "length"}  # the rest are not a reply

# the JSON-schema subset strict tools and structured outputs accept, and its per-request complexity limits
STRICT_TYPES = frozenset({"object", "array", "string", "integer", "number", "boolean", "null"})
STRICT_FORMATS = frozenset({"date-time", "time", "date", "duration", "email", "hostname", "uri", "ipv4", "ipv6",
                            "uuid"})
STRICT_KEYS = frozenset({"type", "properties", "required", "additionalProperties", "items", "enum", "const",
                         "anyOf", "allOf", "$ref", "description", "title", "default", "format", "minItems",
                         "pattern"})
DEF_KEYS = ("$defs", "$def", "definitions")
UNSUPPORTED_PATTERN = re.compile(r"\\[1-9]|\(\?<?[=!]|\\[bB]")   # backreferences, lookaround, word boundaries
MAX_STRICT_TOOLS = 20
MAX_OPTIONAL_PARAMETERS = 24
MAX_UNION_PARAMETERS = 16


class EgressViolation(Exception):
    """A request to a host other than the one classified for egress; it is never sent."""


class _Failed(Exception):
    """A call that ended without a usable reply and is not worth retrying."""

    def __init__(self, status: str, error: str):
        super().__init__(error)
        self.status = status
        self.error = error


def _import_sdk():
    import anthropic

    # ANTHROPIC_LOG turns on SDK debug logs of whole requests: telemetry has no place in logs
    for name in ("anthropic", "httpx2", "httpcore2"):
        logging.getLogger(name).setLevel(logging.WARNING)
    return anthropic


def _pinned_transport(httpx2, inner, *, target, authorization: str, betas: frozenset[str], api_version: str,
                      drop: frozenset[str]):
    """An httpx2 transport that refuses any request not addressed to `target` and fixes the headers that carry
    credentials and API options, whatever the SDK merged in from the environment."""
    expected = (target.scheme, target.host, target.port)
    drop = drop - {"authorization", "anthropic-version", "anthropic-beta"}      # set or filtered below

    class PinnedTransport(httpx2.BaseTransport):
        def __init__(self):
            self.inner = inner

        def handle_request(self, request):
            url = request.url
            if (url.scheme, url.host, url.port) != expected:
                raise EgressViolation(f"refused a request to {url.scheme}://{url.host}: only "
                                      f"{target.scheme}://{target.host} was classified for egress")
            headers = request.headers
            for name in drop | {"x-api-key"}:
                if name in headers:
                    del headers[name]
            headers["authorization"] = authorization
            headers["anthropic-version"] = api_version
            asked = [b.strip() for b in headers.get("anthropic-beta", "").split(",") if b.strip() in betas]
            if asked:
                headers["anthropic-beta"] = ",".join(asked)
            elif "anthropic-beta" in headers:
                del headers["anthropic-beta"]
            return self.inner.handle_request(request)

        def close(self):
            self.inner.close()

    return PinnedTransport()


def _text(message: dict) -> str:
    content = message.get("content")
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "".join(str(part.get("text", "")) for part in content if isinstance(part, dict))
    return str(content)


# ---- the strict schema subset --------------------------------------------------------------------------------

def _defs(schema: dict) -> dict[str, dict]:
    out = {}
    for key in DEF_KEYS:
        if isinstance(schema.get(key), dict):
            for name, sub in schema[key].items():
                out[f"#/{key}/{name}"] = sub
    return out


def _refs(node) -> set[str]:
    if isinstance(node, dict):
        found = {node["$ref"]} if isinstance(node.get("$ref"), str) else set()
        for key, value in node.items():
            if key not in DEF_KEYS:
                found |= _refs(value)
        return found
    if isinstance(node, list):
        return set().union(*(_refs(v) for v in node)) if node else set()
    return set()


def strict_schema_problems(schema, counts: dict | None = None) -> list[str]:
    """Why `schema` is outside the documented strict subset (empty when it is inside). `counts` accumulates
    optional and union parameters for the per-request limits."""
    counts = counts if counts is not None else {"optional": 0, "union": 0}
    problems: list[str] = []
    if not isinstance(schema, dict):
        return ["the schema is not a JSON object"]
    if schema.get("type") != "object":
        problems.append("$: the top level must be an object schema")
    defs = _defs(schema)

    def walk(node, path: str, top: bool = False) -> None:
        if not isinstance(node, dict):
            problems.append(f"{path}: not a schema object")
            return
        for key in node:
            if key not in STRICT_KEYS and not (top and key in DEF_KEYS):
                problems.append(f"{path}: '{key}' is not supported" + (" (use anyOf)" if key == "oneOf" else ""))
        kinds = node.get("type")
        if kinds is not None:
            listed = kinds if isinstance(kinds, list) else [kinds]
            if not listed or any(k not in STRICT_TYPES for k in listed):
                problems.append(f"{path}: type {kinds!r} is not supported")
            if isinstance(kinds, list) and len(kinds) > 1:
                counts["union"] += 1
            kinds = set(listed)
        else:
            kinds = set()
        if "object" in kinds:
            if node.get("additionalProperties") is not False:
                problems.append(f"{path}: objects must set additionalProperties to false")
            required = node.get("required")
            properties = node.get("properties", {})
            if not isinstance(required, list) or not isinstance(properties, dict):
                problems.append(f"{path}: objects must list their required properties")
            else:
                unknown = sorted(set(map(str, required)) - set(properties))
                if unknown:
                    problems.append(f"{path}: required names undeclared properties {unknown}")
                counts["optional"] += len(set(properties) - set(required))
                for name, sub in properties.items():
                    walk(sub, f"{path}.{name}")
        elif "additionalProperties" in node and node["additionalProperties"] is not False:
            problems.append(f"{path}: additionalProperties must be false")
        if "items" in node:
            walk(node["items"], f"{path}[]")
        if "minItems" in node and node["minItems"] not in (0, 1):
            problems.append(f"{path}: minItems other than 0 or 1 is not supported")
        if "enum" in node and (not isinstance(node["enum"], list) or any(
                isinstance(v, (dict, list)) for v in node["enum"])):
            problems.append(f"{path}: enum must list strings, numbers, booleans or nulls")
        if "format" in node and node["format"] not in STRICT_FORMATS:
            problems.append(f"{path}: format {node['format']!r} is not supported")
        if "pattern" in node and (not isinstance(node["pattern"], str)
                                  or UNSUPPORTED_PATTERN.search(node["pattern"])):
            problems.append(f"{path}: the pattern uses an unsupported regular-expression feature")
        for key in ("anyOf", "allOf"):
            if key in node:
                if not isinstance(node[key], list) or not node[key]:
                    problems.append(f"{path}: {key} must list schemas")
                    continue
                if key == "anyOf":
                    counts["union"] += 1
                for n, sub in enumerate(node[key]):
                    if key == "allOf" and isinstance(sub, dict) and "$ref" in sub:
                        problems.append(f"{path}.allOf[{n}]: allOf with $ref is not supported")
                    walk(sub, f"{path}.{key}[{n}]")
        if "$ref" in node and node["$ref"] not in defs:
            problems.append(f"{path}: $ref {node['$ref']!r} must name a definition in this schema")

    walk(schema, "$", top=True)
    for ref, sub in defs.items():
        walk(sub, ref)
    # recursion: a definition that reaches itself through $refs
    graph = {ref: _refs(sub) & set(defs) for ref, sub in defs.items()}
    for start, targets in graph.items():
        stack, seen = list(targets), set()
        while stack:
            ref = stack.pop()
            if ref == start:
                problems.append(f"{start}: recursive schemas are not supported")
                break
            if ref not in seen:
                seen.add(ref)
                stack.extend(graph.get(ref, ()))
    return problems


def _is_type(value, kind: str) -> bool:
    if kind == "integer":
        return (isinstance(value, int) and not isinstance(value, bool)) or (
            isinstance(value, float) and value.is_integer())
    if kind == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if kind == "null":
        return value is None
    python = {"string": str, "boolean": bool, "object": dict, "array": list}.get(kind)
    return python is not None and isinstance(value, python)


def _same(a, b) -> bool:
    return a == b and isinstance(a, bool) == isinstance(b, bool)


def instance_problems(value, schema: dict, root: dict | None = None, path: str = "$") -> list[str]:
    """Why `value` does not match `schema` (a schema inside the strict subset). String formats are left to the
    API's grammar and not checked here."""
    root = root if root is not None else schema
    if not isinstance(schema, dict):
        return []
    if "$ref" in schema:
        target = _defs(root).get(schema["$ref"])
        return instance_problems(value, target, root, path) if target is not None else [f"{path}: unknown $ref"]
    problems: list[str] = []
    if "anyOf" in schema and not any(not instance_problems(value, sub, root, path) for sub in schema["anyOf"]):
        problems.append(f"{path}: matches none of the allowed shapes")
    for sub in schema.get("allOf", []):
        problems += instance_problems(value, sub, root, path)
    if "const" in schema and not _same(value, schema["const"]):
        problems.append(f"{path}: must be {schema['const']!r}")
    if "enum" in schema and not any(_same(value, option) for option in schema["enum"]):
        problems.append(f"{path}: not one of the allowed values")
    kinds = schema.get("type")
    if kinds is not None:
        listed = kinds if isinstance(kinds, list) else [kinds]
        if not any(_is_type(value, k) for k in listed):
            return [*problems, f"{path}: expected {' or '.join(listed)}"]
    if isinstance(value, dict):
        properties = schema.get("properties", {})
        problems += [f"{path}: missing {name!r}" for name in schema.get("required", []) if name not in value]
        if schema.get("additionalProperties") is False:
            problems += [f"{path}: unexpected {name!r}" for name in value if name not in properties]
        for name, sub in properties.items():
            if name in value:
                problems += instance_problems(value[name], sub, root, f"{path}.{name}")
    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0):
            problems.append(f"{path}: needs at least {schema['minItems']} item(s)")
        if isinstance(schema.get("items"), dict):
            for n, item in enumerate(value):
                problems += instance_problems(item, schema["items"], root, f"{path}[{n}]")
    if isinstance(value, str) and isinstance(schema.get("pattern"), str):
        try:
            if not re.search(schema["pattern"], value):
                problems.append(f"{path}: does not match the pattern")
        except re.error:
            pass
    return problems


# ---- the adapter ---------------------------------------------------------------------------------------------

class ClaudeMessagesProvider(ChatProvider):
    name = "anthropic"
    replays_provider_state = True
    sends_sampling = False

    def __init__(self, settings: Settings, decision: EgressDecision, transport=None,
                 sleep: Callable[[float], None] = time.sleep):
        super().__init__(settings, decision, transport=transport, sleep=sleep)
        anthropic = _import_sdk()
        import httpx2
        from anthropic._constants import ANTHROPIC_API_VERSION

        self.sdk = anthropic
        self.httpx2 = httpx2
        self.base_url = endpoint_url(settings).rstrip("/")
        self.betas = (FALLBACK_BETA,) if settings.agent_refusal_fallback == "default" else ()
        self._window: int | None = None
        key = settings.agent_api_key.get_secret_value()
        # header names the SDK would merge in from ANTHROPIC_CUSTOM_HEADERS (credentials, API options, anything)
        drop = frozenset(line.split(":", 1)[0].strip().lower()
                         for line in os.environ.get("ANTHROPIC_CUSTOM_HEADERS", "").split("\n") if ":" in line)
        # an explicit transport: the SDK's default one would mount the environment's (or the registry's) proxies
        inner = transport if transport is not None else httpx2.HTTPTransport(trust_env=False)
        self.transport = _pinned_transport(httpx2, inner, target=httpx2.URL(self.base_url),
                                           authorization=f"Bearer {key}", betas=frozenset(self.betas),
                                           api_version=ANTHROPIC_API_VERSION, drop=drop)
        timeout = float(settings.agent_timeout_seconds)
        http = anthropic.DefaultHttpxClient(transport=self.transport, trust_env=False, follow_redirects=False,
                                            timeout=timeout)
        self.client = anthropic.Anthropic(api_key=key, base_url=self.base_url, http_client=http, max_retries=0,
                                          timeout=timeout, open_telemetry={"traces": False, "propagation": False})

    def _build_http(self, transport):
        return None     # the SDK's client carries every request

    def __repr__(self) -> str:
        return f"<ClaudeMessagesProvider {self.model} at {self.decision.host}>"

    # ---- sizes ----------------------------------------------------------------------------------------------
    def output_limit(self, request: ChatRequest) -> int:
        return super().output_limit(request) + self.s.agent_thinking_tokens

    def context_tokens(self) -> int:
        """AGENT_CONTEXT_TOKENS, else the window the models endpoint reports (asked once; 0 if unknown)."""
        if self.s.agent_context_tokens:
            return self.s.agent_context_tokens
        if self._window is None:
            self._window = 0
            try:
                self._window = int(self.client.models.retrieve(self.model).max_input_tokens or 0)
            except (self.sdk.APIError, self.httpx2.HTTPError, EgressViolation):
                pass        # the API still enforces the window; it rejects a prompt that does not fit
        return self._window

    # ---- one call -------------------------------------------------------------------------------------------
    def _chat(self, request: ChatRequest, messages: list[dict], max_out: int, est: int) -> ChatResult:
        def failed(status: str, error: str, ms: int = 0, attempts: int = 1) -> ChatResult:
            return ChatResult(status, "", "", None, [], Usage(), est, self.model, "", ms, "",
                              redact_text(error, self.s)[:2000], attempts)

        problems = self._schema_problems(request)
        if problems:
            return failed("error", "not sent: outside the strict JSON-schema subset the API accepts: "
                                   + "; ".join(problems[:10]))
        body, before = self._body(request, messages, max_out)
        raw_inputs: dict[int, str] = {}
        attempts = [0]

        def once():
            attempts[0] += 1
            raw_inputs.clear()
            return self._stream(body, raw_inputs)

        t0 = time.monotonic()
        try:
            message, ms, n = self._retrying(once)
        except _Failed as exc:
            return failed(exc.status, exc.error, int((time.monotonic() - t0) * 1000), attempts[0])
        return self._result(request, message, raw_inputs, before, est, ms, n)

    def _stream(self, body: dict, raw_inputs: dict[int, str]):
        """One streamed request and its final message, with each tool input's raw JSON as it arrived."""
        sdk, httpx2 = self.sdk, self.httpx2
        try:
            with self.client.beta.messages.stream(**body) as stream:
                for event in stream:
                    if event.type == "content_block_delta" and getattr(event.delta, "type", "") == "input_json_delta":
                        raw_inputs[event.index] = raw_inputs.get(event.index, "") + event.delta.partial_json
                try:
                    return stream.get_final_message()
                except AssertionError:
                    # the SDK has no message when the stream closed before it began (a dropped connection)
                    raise TransientFailure("the reply stream ended before the reply began") from None
        except sdk.APIStatusError as exc:
            code, kind = exc.status_code, exc.type or ""
            detail = redact_text(str(exc.message), self.s)[:300]
            if code in RETRY_STATUSES or code == OVERLOADED or (code < 300 and kind in RETRY_ERROR_TYPES):
                where = f"HTTP {code}" if code >= 300 else "stream error"
                raise TransientFailure(f"{where} {kind}".strip(), suffix=f": {detail}",
                                       retry_after=exc.response.headers.get("retry-after")) from None
            if code == 413:
                raise _Failed("too_large", f"HTTP 413 {kind}: {detail}") from None
            raise _Failed("error", f"HTTP {code} {kind}: {detail}".replace("  ", " ")) from None
        except sdk.APIConnectionError as exc:
            cause = exc.__cause__
            if isinstance(cause, EgressViolation):
                raise _Failed("error", str(cause)) from None
            raise TransientFailure(f"{exc.__class__.__name__}: {cause.__class__.__name__ if cause else exc}") from None
        except httpx2.TransportError as exc:
            raise TransientFailure(f"{exc.__class__.__name__}") from None
        except sdk.APIError as exc:          # e.g. a reply the SDK could not read as a message
            raise _Failed("error", f"{exc.__class__.__name__}: {exc}"[:600]) from None
        except ValueError as exc:
            if raw_inputs:
                # the SDK could not parse a tool input at all; there is no complete tool_use block to answer
                raise _Failed("invalid_tool_call", f"a tool input is not valid JSON: {exc}"[:600]) from None
            raise _Failed("error", f"the reply stream could not be read: {exc}"[:600]) from None
        except RuntimeError as exc:          # events out of order: not a reply the port can vouch for
            raise _Failed("error", f"the reply stream could not be read: {exc}"[:600]) from None

    # ---- request ----------------------------------------------------------------------------------------------
    def _schema_problems(self, request: ChatRequest) -> list[str]:
        counts = {"optional": 0, "union": 0}
        problems = [f"tool {t.name}: {p}" for t in request.tools for p in strict_schema_problems(t.parameters, counts)]
        if request.response_schema is not None:
            problems += [f"response schema: {p}" for p in strict_schema_problems(request.response_schema, counts)]
        if len(request.tools) > MAX_STRICT_TOOLS:
            problems.append(f"{len(request.tools)} strict tools (at most {MAX_STRICT_TOOLS})")
        if counts["optional"] > MAX_OPTIONAL_PARAMETERS:
            problems.append(f"{counts['optional']} optional parameters (at most {MAX_OPTIONAL_PARAMETERS})")
        if counts["union"] > MAX_UNION_PARAMETERS:
            problems.append(f"{counts['union']} union-typed parameters (at most {MAX_UNION_PARAMETERS})")
        return problems

    def _body(self, request: ChatRequest, messages: list[dict], max_out: int) -> tuple[dict, list[dict]]:
        """The stream() arguments, and the messages this call adds ahead of its reply (replayed with it)."""
        system, out = self._translate(request, messages)
        tools = [{"name": t.name, "description": t.description, "input_schema": t.parameters, "strict": True,
                  # inputs stream as generated; _tool_call parses and checks each one, as the API no longer does
                  "eager_input_streaming": True}
                 for t in sorted(request.tools, key=lambda t: t.name)]
        # one explicit cache breakpoint closes the stable prefix (tools, then the system prompt)
        if system:
            system[-1]["cache_control"] = dict(CACHE)
        elif tools:
            tools[-1]["cache_control"] = dict(CACHE)
        before: list[dict] = []
        if tools and request.tool_choice == "required":
            # this model rejects a forced tool choice; the instruction is replayed with the reply it produced
            names = ", ".join(t["name"] for t in tools)
            before = [{"role": "system", "content": f"Answer this turn by calling one of the provided tools "
                                                    f"({names}). A reply without a tool call is not accepted."}]
            out += copy.deepcopy(before)
        output_config: dict = {"effort": self.s.agent_effort}
        if request.response_schema is not None:
            output_config["format"] = {"type": "json_schema", "schema": request.response_schema}
        # never temperature, top_p or top_k: the API rejects sampling parameters
        body: dict = {"model": self.model, "max_tokens": max_out, "messages": out,
                      "thinking": {"type": "adaptive"}, "output_config": output_config,
                      # automatic caching of the conversation so far, behind the explicit breakpoint
                      "cache_control": dict(CACHE)}
        if system:
            body["system"] = system
        if tools:
            body["tools"] = tools
            body["tool_choice"] = {"type": "none" if request.tool_choice == "none" else "auto"}
        if self.betas:
            body["betas"] = list(self.betas)
            body["fallbacks"] = "default"
        return body, before

    def _translate(self, request: ChatRequest, messages: list[dict]) -> tuple[list[dict], list[dict]]:
        """Port messages to the top-level system blocks and Messages API messages. `messages` are the redacted
        ones; `request.messages` are the originals, against which replayed turns are checked."""
        system: list[dict] = []
        out: list[dict] = []
        results: list[dict] | None = None      # the open user message of tool results
        for n, (original, m) in enumerate(zip(request.messages, messages)):
            role = m.get("role")
            if role != "tool":
                results = None
            if role == "system":
                if out:
                    out.append({"role": "system", "content": _text(m)})     # a mid-conversation system message
                else:
                    system.append({"type": "text", "text": _text(m)})
            elif role == "user":
                content = m.get("content")
                out.append({"role": "user", "content": content if isinstance(content, str) else
                            [{"type": "text", "text": _text({"content": [part]})} for part in content or []]})
            elif role == "assistant":
                out += self._assistant(n, original, m)
            elif role == "tool":
                block = {"type": "tool_result", "tool_use_id": str(m.get("tool_call_id") or ""), "content": _text(m)}
                if m.get("is_error"):
                    block["is_error"] = True
                if results is None:
                    results = []
                    out.append({"role": "user", "content": results})
                results.append(block)
            else:
                raise HistoryError(f"message {n} has an unknown role {role!r}")
        return system, out

    def _assistant(self, n: int, original: dict, m: dict) -> list[dict]:
        state = original.get(PROVIDER_STATE)
        calls = original.get("tool_calls") or []
        if state is None:
            if calls:
                raise HistoryError(
                    f"assistant message {n} has tool calls but none of the thinking blocks Claude signed for that "
                    "turn: it was built by another provider, or trimmed or rebuilt. Append each reply as "
                    "ChatResult.assistant_message() returns it; sessions must be append-only or start fresh")
            return [{"role": "assistant", "content": _text(m)}]
        if not isinstance(state, dict) or state.get("provider") != self.name or not isinstance(
                state.get("content"), list):
            raise HistoryError(f"assistant message {n} carries provider state this adapter did not write")
        blocks = state["content"]
        stored_calls = [(b.get("id"), b.get("name"), b.get("input")) for b in blocks if b.get("type") == "tool_use"]
        given_calls = []
        for call in calls:
            function = call.get("function") or {}
            arguments = function.get("arguments")
            try:
                parsed = json.loads(arguments) if isinstance(arguments, str) else arguments
            except json.JSONDecodeError:
                parsed = arguments
            given_calls.append((call.get("id"), function.get("name"), parsed))
        stored_text = "".join(str(b.get("text", "")) for b in blocks if b.get("type") == "text")
        if given_calls != stored_calls or _text(original) != stored_text:
            raise HistoryError(f"assistant message {n} was changed after the model produced it; its signed "
                               "thinking no longer matches the turn. Sessions must be append-only or start fresh")
        before = state.get("before") or []
        return [*copy.deepcopy(before), {"role": "assistant", "content": copy.deepcopy(blocks)}]

    # ---- reply ------------------------------------------------------------------------------------------------
    def _result(self, request: ChatRequest, message, raw_inputs: dict[int, str], before: list[dict], est: int,
                ms: int, attempts: int) -> ChatResult:
        blocks = list(message.content or [])
        # after a fallback, only text from before the last switch carries over; the declined model's thinking and
        # tool calls are dropped, and the switch marker itself is an audit record the API ignores
        boundary = max((i for i, b in enumerate(blocks) if b.type == "fallback"), default=-1)
        kept: list[dict] = []
        texts: list[str] = []
        calls: list[ToolCall] = []
        for i, block in enumerate(blocks):
            if block.type == "fallback" or (i < boundary and block.type != "text"):
                continue
            kept.append(block.to_dict())
            if block.type == "text":
                texts.append(block.text)
            elif block.type == "tool_use":
                raw = raw_inputs.get(i)
                if raw is None:
                    raw = json.dumps(block.input) if block.input else ""
                calls.append(self._tool_call(block.id, block.name, raw, request))
        content = "".join(texts)
        native = message.stop_reason
        details: dict = {"stop_reason": native, "model": message.model}
        refusal = ""
        stop = message.stop_details
        if native == "refusal":
            category = getattr(stop, "category", None)
            details["refusal"] = {"category": category, "explanation": getattr(stop, "explanation", None),
                                  "recommended_model": getattr(stop, "recommended_model", None)}
            refusal = (f"the model declined to answer (category: {category or 'none given'})"
                       + (f": {stop.explanation}" if getattr(stop, "explanation", None) else ""))
            calls = []      # a refusal can cut a tool call off mid-input; never run one
        switches = [{"from": b.from_.model, "to": b.to.model} for b in blocks if b.type == "fallback"]
        usage = message.usage
        iterations = [it for it in (getattr(usage, "iterations", None) or [])
                      if it.type in ("message", "fallback_message")]
        if switches or any(it.type == "fallback_message" for it in iterations):
            details["fallback"] = {"served_by": message.model, "switches": switches}
        if len(iterations) > 1:
            # every attempt the API billed for this call, the declined ones included
            details["billed"] = {
                "prompt": sum(it.input_tokens + it.cache_creation_input_tokens + it.cache_read_input_tokens
                              for it in iterations),
                "completion": sum(it.output_tokens for it in iterations),
                "cache_read": sum(it.cache_read_input_tokens for it in iterations),
                "cache_write": sum(it.cache_creation_input_tokens for it in iterations)}
        if usage is not None:
            read, write = usage.cache_read_input_tokens or 0, usage.cache_creation_input_tokens or 0
            tokens = Usage(usage.input_tokens + read + write, usage.output_tokens, read, write)
        else:
            tokens = Usage()
        finish = "refusal" if native == "refusal" else STOP_REASONS.get(native, native) if native else None
        result = self._finish(finish_reason=finish, content=content, tool_calls=calls, usage=tokens, est=est,
                              model_reported=str(message.model or ""), ms=ms,
                              raw=json.dumps(message.to_dict(mode="json"), sort_keys=True), attempts=attempts,
                              request=request, refusal=refusal)
        if result.status == "truncated_output" and not content and not calls:
            result.error += ("; nothing was produced before the limit (thinking used it all): raise "
                             "AGENT_THINKING_TOKENS or lower AGENT_EFFORT")
        if result.ok and native == "tool_use" and not calls:
            result.status, result.error = "invalid_tool_call", "the reply stopped for a tool call but holds none"
        if result.ok and request.tool_choice == "required" and not calls:
            result.status, result.error = "invalid_tool_call", "the model answered without the tool call required"
        if result.ok and result.parsed is not None and request.response_schema is not None:
            problems = instance_problems(result.parsed, request.response_schema)
            if problems:
                result.status, result.parsed = "invalid_json", None
                result.error = "the reply does not match the requested schema: " + "; ".join(problems[:5])
        result.details = details
        if result.status != "refused":
            result.provider_state = {"provider": self.name, "model": message.model, "before": before,
                                     "content": kept}
        return result

    def _tool_call(self, call_id: str, name: str, raw: str, request: ChatRequest) -> ToolCall:
        """The port's argument parsing on the raw streamed JSON, then the tool's schema."""
        call = parse_tool_arguments(call_id, name, raw)
        tool = next((t for t in request.tools if t.name == name), None)
        if call.arguments is not None and tool is not None:
            problems = instance_problems(call.arguments, tool.parameters)
            if problems:
                return ToolCall(call_id, name, None, raw,
                                "arguments do not match the tool's schema: " + "; ".join(problems[:5]))
        return call

    # ---- doctor -----------------------------------------------------------------------------------------------
    def probe(self) -> list[tuple[str, str, str]]:
        sdk, host = self.sdk, self.decision.host
        try:
            info = self.client.models.retrieve(self.model)
        except (sdk.AuthenticationError, sdk.PermissionDeniedError) as exc:
            return [("agent.reachable", "fail", f"{host} rejected the key (HTTP {exc.status_code})")]
        except sdk.NotFoundError:
            return [("agent.reachable", "ok", f"{host} answered"),
                    ("agent.model", "fail", f"{self.model} is not a model this key can use (HTTP 404)")]
        except sdk.APIStatusError as exc:
            return [("agent.reachable", "fail", f"{host}: HTTP {exc.status_code} from the models endpoint")]
        except sdk.APIConnectionError as exc:
            cause = exc.__cause__
            reason = str(cause) if isinstance(cause, EgressViolation) else (
                cause.__class__.__name__ if cause else exc.__class__.__name__)
            return [("agent.reachable", "fail", f"{host}: {reason}")]
        out = [("agent.reachable", "ok", f"{host} answered the models endpoint")]
        if info.id != self.model:
            detail = f"{self.model} resolves to {info.id}: set AGENT_MODEL={info.id} to pin the exact model"
            out.append(("agent.model", "fail", detail))
        else:
            out.append(("agent.model", "ok", f"{info.id} is available ({info.display_name})"))
        window, configured = info.max_input_tokens, self.s.agent_context_tokens
        if not configured and window:
            self._window = int(window)
            out.append(("agent.context", "ok", f"context window {window} tokens, from the models endpoint"))
        elif not configured:
            detail = f"the models endpoint reports no context window for {self.model}: set AGENT_CONTEXT_TOKENS"
            out.append(("agent.context", "fail", detail))
        elif window and configured > window:
            detail = f"AGENT_CONTEXT_TOKENS={configured} exceeds the model's {window}-token context window"
            out.append(("agent.context", "fail", detail))
        else:
            out.append(("agent.context", "ok", f"AGENT_CONTEXT_TOKENS={configured}"))
        need = self.s.agent_max_output_tokens + self.s.agent_thinking_tokens
        if info.max_tokens and need > info.max_tokens:
            detail = (f"AGENT_MAX_OUTPUT_TOKENS + AGENT_THINKING_TOKENS = {need} exceeds the model's output "
                      f"limit of {info.max_tokens} tokens")
            out.append(("agent.output", "fail", detail))
        elif info.max_tokens:
            detail = f"max_tokens {need} per call (output limit {info.max_tokens}); effort {self.s.agent_effort}"
            out.append(("agent.output", "ok", detail))
        return out + probe_calls(self)
