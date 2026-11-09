"""Adapter for the Claude Messages API, through Anthropic's official Python SDK (the optional romulus[anthropic]
install, imported only when this adapter is built).

AGENT_BASE_URL defaults to https://api.anthropic.com, a remote endpoint: telemetry may reach it only under
ROMULUS_MODEL_EGRESS=lab-public-data, over https. The SDK is given the key from AGENT_API_KEY, an HTTP client built
here (no environment proxy, no redirects, every request pinned to the classified host and sent with an allowlist of
headers rebuilt from the request) and no retries of its own, so the port's one retry policy applies. Credentials,
endpoints, headers, logging and tracing the SDK would otherwise read from the environment are not used. Each call
reports every attempt the API billed, with the model that served it (a refusal-fallback answer, or an attempt that
broke off mid-reply at its full output allowance), so budgets price each attempt by its own model.

Translation: leading system messages become the top-level system prompt and later ones mid-conversation system
messages, placed where the API accepts them (after a user turn, last or before an assistant turn; anything else is a
HistoryError); assistant tool calls become tool_use blocks; consecutive tool results go back in one user message. A
tool is sent strict when its schema is inside the strict subset the API documents (and the request within its strict
limits), else not strict; a response schema becomes output_config.format and must be inside the subset, or the request
is refused before anything is sent; sampling parameters are never sent. tool_choice "required" becomes "auto" with an
instruction to call a tool, and a reply without one is invalid_tool_call. Thinking is adaptive, AGENT_EFFORT sets how
much, and every call's max_tokens adds AGENT_THINKING_TOKENS of room for it. Calls stream (large max_tokens values
need it), tool inputs stream as generated, and so each tool input is parsed strictly from the raw stream and, for a
strict tool, checked against its schema here (the caller validates every tool's arguments against its own model). The tools and system prompt form a cached prefix, and the
growing conversation is cached automatically.

Sessions must be append-only, or start fresh. Claude signs its thinking blocks, and they must go back unchanged, in
their original place in the turn that produced them, in a conversation whose earlier turns are unchanged. Each
reply's blocks travel in the provider state of its assistant message (ChatResult.assistant_message()), with the raw
tool inputs the model streamed and the tools a required-tool instruction named, which is rebuilt from those names.
Replay accepts only text, thinking, redacted-thinking and tool-use blocks with their known fields, as an assistant
turn. An assistant turn with tool calls but no provider state (history from another provider, or a trimmed or
rebuilt turn), a state that is malformed or holds anything else, a turn whose text or tool calls no longer match its
state, or one that holds a configured secret, raises HistoryError before anything is sent.
"""
from __future__ import annotations

import copy
import datetime
import ipaddress
import json
import logging
import os
import re
import time
from collections.abc import Callable

from pydantic import SecretStr

from romulus.agent.provider.base import (
    MAX_ERROR_MESSAGE,
    PROVIDER_STATE,
    RETRY_STATUSES,
    ChatProvider,
    ChatRequest,
    ChatResult,
    HistoryError,
    ProviderUnavailable,
    ToolCall,
    TransientFailure,
    Usage,
    endpoint_url,
    parse_tool_arguments,
)
from romulus.agent.provider.egress import EgressDecision
from romulus.agent.provider.openai_compatible import probe_calls
from romulus.config import MIN_SECRET_LENGTH, Settings, redact_text

# the server-side refusal fallback, "default" form: the API picks the fallback model by refusal category
FALLBACK_BETA = "server-side-fallback-2026-07-01"
CACHE = {"type": "ephemeral"}            # five-minute cache entries
OVERLOADED = 529
RETRY_ERROR_TYPES = frozenset({"overloaded_error", "rate_limit_error", "api_error"})   # also sent mid-stream
# the documented stop reasons that say what a reply is, in the port's words; any other is an error (stop_sequence
# included: no stop sequence is ever sent)
CLAUDE_STOP_REASONS = {"end_turn": "stop", "tool_use": "tool_calls", "max_tokens": "length", "refusal": "refusal"}

# what a reply may hold and an assistant turn may replay: these block types, with only these fields
BLOCK_KEYS = {"text": frozenset({"type", "text", "citations"}),
              "thinking": frozenset({"type", "thinking", "signature"}),
              "redacted_thinking": frozenset({"type", "data"}),
              "tool_use": frozenset({"type", "id", "name", "input", "caller"})}
STATE_KEYS = frozenset({"provider", "model", "content", "tool_inputs", "required_tools"})
# the SDK's per-request client metadata headers (the platform ones are read from the client itself)
STAINLESS_PER_REQUEST = ("x-stainless-timeout", "x-stainless-retry-count", "x-stainless-read-timeout",
                         "x-stainless-helper-method", "x-stainless-stream-helper")
TOOL_NAME = re.compile(r"[A-Za-z0-9_-]{1,128}")

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


# ---- conversation shape ---------------------------------------------------------------------------------------

def _instruction(names: list[str]) -> str:
    return (f"Answer this turn by calling one of the provided tools ({', '.join(names)}). "
            "A reply without a tool call is not accepted.")


def _require_tool(out: list[dict], n, names: list[str]) -> None:
    """Ask for a tool call in a system message after the last user turn: merged into a system message already
    there, else appended. Rebuilt the same way when the reply is replayed, so the history stays append-only."""
    text = _instruction(names)
    if out and out[-1]["role"] == "system":
        out[-1]["content"] = f"{out[-1]['content']}\n\n{text}"
    elif out and out[-1]["role"] == "user":
        out.append({"role": "system", "content": text, "_n": n})
    else:
        raise HistoryError(f"message {n}: a tool call can be required only after a user turn")


def _check_placement(out: list[dict]) -> None:
    """Mid-conversation system messages where the API accepts them: right after a user turn, and either last or
    right before an assistant turn. Drops the bookkeeping field."""
    for i, message in enumerate(out):
        if message["role"] != "system":
            continue
        n = message.pop("_n", "?")
        before = out[i - 1]["role"] if i else None
        after = out[i + 1]["role"] if i + 1 < len(out) else None
        if before != "user" or after not in (None, "assistant"):
            raise HistoryError(f"message {n}: a system message after the first turn must follow a user turn and "
                               "be the last message or come right before an assistant turn")


def _state_problem(state) -> str:
    """Why a provider state cannot be a reply this adapter stored (empty when it can)."""
    if not isinstance(state, dict) or state.get("provider") != "anthropic":
        return "it was not written by this adapter"
    if set(state) - STATE_KEYS:
        return f"unknown fields {sorted(set(state) - STATE_KEYS)}"
    blocks, inputs = state.get("content"), state.get("tool_inputs", {})
    if not isinstance(blocks, list) or not isinstance(inputs, dict) or not isinstance(state.get("model", ""), str):
        return "malformed"
    ids = []
    for block in blocks:
        kind = block.get("type") if isinstance(block, dict) else None
        if not isinstance(kind, str) or kind not in BLOCK_KEYS:
            return f"a {kind!r} block, which a reply to this adapter never holds"
        if set(block) - BLOCK_KEYS[kind]:
            return f"a {kind} block with unknown fields {sorted(set(block) - BLOCK_KEYS[kind])}"
        strings = {"text": ("text",), "thinking": ("thinking", "signature"), "redacted_thinking": ("data",),
                   "tool_use": ("id", "name")}[kind]
        if any(not isinstance(block.get(key), str) for key in strings) or block.get("citations") is not None:
            return f"a malformed {kind} block"
        if kind == "tool_use":
            if not isinstance(block.get("input"), dict) or block.get("caller") not in (None, {"type": "direct"}):
                return "a malformed tool_use block"
            ids.append(block["id"])
    if sorted(ids) != sorted(inputs) or not all(isinstance(v, str) for v in inputs.values()):
        return "tool inputs that do not match its tool calls"
    for block in blocks:
        if block["type"] == "tool_use" and _derived_input(inputs[block["id"]]) != block["input"]:
            return "a tool_use input that is not the one its raw streamed input gives"
    required = state.get("required_tools", [])
    if not isinstance(required, list) or not all(isinstance(r, str) and TOOL_NAME.fullmatch(r) for r in required):
        return "malformed required tools"
    return ""


def _derived_input(raw: str):
    """The input object a tool's raw streamed JSON gives: the JSON itself when it parses, else what the SDK's
    tolerant parser made of it when the reply arrived (None when it cannot make anything of it)."""
    if not raw.strip():
        return {}          # no input was streamed: the block keeps the empty input it started with
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        pass
    import jiter  # the SDK's own parser, with the mode it uses for tool input

    try:
        return jiter.from_json(raw.encode("utf-8"), partial_mode=True)
    except ValueError:
        return None


def _long_secrets(settings: Settings) -> list[str]:
    """Configured secrets long enough to tell apart from ordinary text (shorter ones doctor warns about)."""
    values = (getattr(settings, name) for name in type(settings).model_fields)
    return [v.get_secret_value() for v in values
            if isinstance(v, SecretStr) and len(v.get_secret_value()) >= MIN_SECRET_LENGTH]


def _same_arguments(given, stored_raw: str) -> bool:
    """The tool-call arguments of a message against the raw input the model streamed for it."""
    if isinstance(given, str):
        return given == stored_raw
    try:
        return given is not None and json.loads(stored_raw) == given
    except json.JSONDecodeError:
        return False


def _import_sdk():
    import anthropic

    # ANTHROPIC_LOG turns on SDK debug logs of whole requests: telemetry has no place in logs
    for name in ("anthropic", "httpx2", "httpcore2"):
        logging.getLogger(name).setLevel(logging.WARNING)
    return anthropic


def _pinned_transport(httpx2, inner, *, target, authorization: str, betas: frozenset[str], api_version: str,
                      user_agent: str, ambient: frozenset[str]):
    """An httpx2 transport that refuses any request not addressed to `target` and sends only the headers this
    adapter vouches for, rebuilt from the request itself: never the credentials, API options, client metadata or
    framing headers the SDK merges in from the environment (ANTHROPIC_CUSTOM_HEADERS, whose names are `ambient`)."""
    expected = (target.scheme, target.host, target.port)

    class PinnedTransport(httpx2.BaseTransport):
        def __init__(self):
            self.inner = inner
            self.platform: dict[str, str] = {}      # the SDK's own client metadata, set once the client exists

        def handle_request(self, request):
            url = request.url
            if (url.scheme, url.host, url.port) != expected:
                raise EgressViolation(f"refused a request to {url.scheme}://{url.host}: only "
                                      f"{target.scheme}://{target.host} was classified for egress")
            body = request.read()
            headers = [("host", url.netloc.decode("ascii")), ("accept", "application/json"),
                       ("accept-encoding", "gzip, deflate"), ("connection", "keep-alive"),
                       ("user-agent", user_agent), ("authorization", authorization),
                       ("anthropic-version", api_version)]
            asked = [b.strip() for b in request.headers.get("anthropic-beta", "").split(",") if b.strip() in betas]
            if asked:
                headers.append(("anthropic-beta", ",".join(dict.fromkeys(asked))))
            # the SDK's own client metadata: its platform values, and the per-request ones the environment did not name
            headers += list(self.platform.items())
            headers += [(name, request.headers[name]) for name in STAINLESS_PER_REQUEST
                        if name in request.headers and name not in ambient]
            if body or request.method == "POST":
                headers += [("content-type", "application/json"), ("content-length", str(len(body)))]
            request.headers = httpx2.Headers(headers)
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
        if "pattern" in node:
            if not isinstance(node["pattern"], str) or UNSUPPORTED_PATTERN.search(node["pattern"]):
                problems.append(f"{path}: the pattern uses an unsupported regular-expression feature")
            else:
                try:
                    re.compile(node["pattern"])
                except re.error as exc:
                    problems.append(f"{path}: the pattern is not a valid regular expression ({exc})")
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
    if kind == "integer":      # 5.0 and True are not integers
        return isinstance(value, int) and not isinstance(value, bool)
    if kind == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if kind == "null":
        return value is None
    python = {"string": str, "boolean": bool, "object": dict, "array": list}.get(kind)
    return python is not None and isinstance(value, python)


def _same(a, b) -> bool:
    return a == b and isinstance(a, bool) == isinstance(b, bool)


_OFFSET = r"(?:[Zz]|[+-]\d{2}:\d{2})"
_FORMATS = {      # ASCII only: \d must not match other scripts' digits
    "date-time": re.compile(rf"\d{{4}}-\d{{2}}-\d{{2}}[Tt ]\d{{2}}:\d{{2}}:\d{{2}}(?:\.\d+)?{_OFFSET}", re.ASCII),
    "time": re.compile(rf"\d{{2}}:\d{{2}}:\d{{2}}(?:\.\d+)?{_OFFSET}", re.ASCII),
    "date": re.compile(r"\d{4}-\d{2}-\d{2}", re.ASCII),
    "duration": re.compile(r"P(?=\d|T\d)(?:\d+Y)?(?:\d+M)?(?:\d+W)?(?:\d+D)?(?:T(?=\d)(?:\d+H)?(?:\d+M)?"
                           r"(?:\d+(?:\.\d+)?S)?)?", re.ASCII),
    "uuid": re.compile(r"[0-9A-Fa-f]{8}-(?:[0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}", re.ASCII),
    "uri": re.compile(r"[A-Za-z][A-Za-z0-9+.-]*:[^\s<>\"{}|\\^`]*", re.ASCII),
}
_LABEL = re.compile(r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)", re.ASCII)
_LEAP_SECOND = re.compile(r"(\d{2}:\d{2}):60", re.ASCII)


def _clock_ok(value: str, kind: str) -> bool:
    """An RFC 3339 date-time or full-time, a leap second (:60) included, which only 23:59 UTC can carry."""
    leap = _LEAP_SECOND.search(value)
    if leap:
        value = value[:leap.start()] + leap.group(1) + ":59" + value[leap.end():]
    value = value.replace("z", "Z").replace("t", "T").replace(" ", "T")
    if kind == "date-time":
        moment = datetime.datetime.fromisoformat(value)
    else:
        moment = datetime.datetime.combine(datetime.date(2000, 1, 1), datetime.time.fromisoformat(value))
    if leap:
        utc = moment.astimezone(datetime.UTC)
        return (utc.hour, utc.minute) == (23, 59)
    return True


def _hostname_ok(value: str) -> bool:
    return 0 < len(value.rstrip(".")) <= 253 and all(_LABEL.fullmatch(label) for label in value.rstrip(".").split("."))


def _format_ok(value: str, kind: str) -> bool:
    """The string formats the strict subset allows, checked as RFC 3339 / ISO 8601 / RFC 1123 / RFC 3986 define
    them (an unknown format is refused up front by strict_schema_problems)."""
    try:
        if kind in _FORMATS and not _FORMATS[kind].fullmatch(value):
            return False
        if kind in ("date-time", "time"):
            return _clock_ok(value, kind)
        if kind == "date":
            datetime.date.fromisoformat(value)
        elif kind == "ipv4":
            ipaddress.IPv4Address(value)
        elif kind == "ipv6":
            if "%" in value:        # a zone id names a local interface, not an address
                return False
            ipaddress.IPv6Address(value)
        elif kind == "hostname":
            return _hostname_ok(value)
        elif kind == "email":
            local, _, domain = value.rpartition("@")
            return bool(local) and len(local) <= 64 and not any(c.isspace() for c in local) and _hostname_ok(domain)
        elif kind not in _FORMATS:
            return False
        return True
    except ValueError:
        return False


def instance_problems(value, schema: dict, root: dict | None = None, path: str = "$") -> list[str]:
    """Why `value` does not match `schema` (a schema inside the strict subset, string formats included)."""
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
    if isinstance(value, str) and "pattern" in schema:
        try:
            if not re.search(schema["pattern"], value):
                problems.append(f"{path}: does not match the pattern")
        except (re.error, TypeError):       # refused up front by strict_schema_problems; never skipped here
            problems.append(f"{path}: the schema's pattern cannot be checked")
    if isinstance(value, str) and "format" in schema and not _format_ok(value, schema["format"]):
        problems.append(f"{path}: not a valid {schema['format']}")
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
        timeout = float(settings.agent_timeout_seconds)
        # an explicit transport: the SDK's default one would mount the environment's (or the registry's) proxies
        inner = transport if transport is not None else httpx2.HTTPTransport(trust_env=False)
        # the header names the SDK merges in from ANTHROPIC_CUSTOM_HEADERS: never copied to the wire
        ambient = frozenset(line.split(":", 1)[0].strip().lower()
                            for line in os.environ.get("ANTHROPIC_CUSTOM_HEADERS", "").split("\n") if ":" in line)
        self.transport = _pinned_transport(httpx2, inner, target=httpx2.URL(self.base_url),
                                           authorization=f"Bearer {key}", betas=frozenset(self.betas),
                                           api_version=ANTHROPIC_API_VERSION,
                                           user_agent=f"Anthropic/Python {anthropic.__version__}", ambient=ambient)
        http = anthropic.DefaultHttpxClient(transport=self.transport, trust_env=False, follow_redirects=False,
                                            timeout=timeout)
        self.client = anthropic.Anthropic(api_key=key, base_url=self.base_url, http_client=http, max_retries=0,
                                          timeout=timeout, open_telemetry={"traces": False, "propagation": False})
        self.transport.platform = {**{k.lower(): v for k, v in self.client.platform_headers().items()},
                                   "x-stainless-async": "false"}

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

        strict, problems = self._strictness(request)
        if problems:
            return failed("error", "not sent: the response schema is outside the strict JSON-schema subset the API "
                                   "accepts: " + "; ".join(problems[:10]))
        body, required = self._body(request, messages, max_out, strict)
        raw_inputs: dict[int, str] = {}
        attempts = [0]
        broken: list[dict] = []          # attempts that broke off after their reply began: billed all the same

        def once():
            attempts[0] += 1
            raw_inputs.clear()
            began: dict = {}
            try:
                return self._stream(body, raw_inputs, began)
            except (TransientFailure, _Failed) as exc:
                if not began:
                    raise
                broken.extend(self._broken_attempt(began, max_out))
                if isinstance(exc, TransientFailure) and self.s.agent_max_cost_usd and request.attempt_guard is None:
                    # a retry could be billed again in full, past what the budget checked before this call
                    raise _Failed("error", f"the reply broke off after it began and was billed ({exc.detail}); not "
                                           "retried, as a cost budget is set") from None
                raise

        t0 = time.monotonic()
        try:
            message, ms, n = self._retrying(once, attempt_guard=request.attempt_guard,
                                            billed=lambda: broken)
        except _Failed as exc:
            result = failed(exc.status, exc.error, int((time.monotonic() - t0) * 1000), attempts[0])
            if broken:
                result.details = {"billed": broken}
            return result
        except ProviderUnavailable as exc:
            exc.billed = broken      # for AgentBudget.charge_failure: the provider billed these attempts
            raise
        return self._result(request, message, raw_inputs, required, est, ms, n, broken, max_out)

    def _broken_attempt(self, began: dict, max_out: int) -> list[dict]:
        """The charge of an attempt whose reply began and then broke off: its reported prompt, and its output at the
        reported count when the stream got that far, else at the full allowance (never as an empty completion). After
        an in-stream switch to the fallback model, that model's hop is charged too: the same prompt written to its
        cold cache, and its full allowance."""
        usage = began.get("usage")
        read = getattr(usage, "cache_read_input_tokens", None) or 0
        write = getattr(usage, "cache_creation_input_tokens", None) or 0
        prompt = (getattr(usage, "input_tokens", None) or 0) + read + write
        output = began.get("output_tokens")
        parts = [{"model": began.get("model") or "", "prompt": prompt, "completion": output if output is not None
                  else max_out, "cache_read": read, "cache_write": write, "worst_case": output is None}]
        if began.get("switched_to"):
            parts.append({"model": began["switched_to"], "prompt": prompt, "completion": max_out, "cache_read": 0,
                          "cache_write": read + write, "worst_case": True})
        return parts

    def _stream(self, body: dict, raw_inputs: dict[int, str], began: dict):
        """One streamed request and its final message, with each tool input's raw JSON as it arrived. `began` gets
        the model and usage the reply started with, and the output count once the reply reports it."""
        sdk, httpx2 = self.sdk, self.httpx2
        try:
            with self.client.beta.messages.stream(**body) as stream:
                for event in stream:
                    if event.type == "content_block_delta" and getattr(event.delta, "type", "") == "input_json_delta":
                        raw_inputs[event.index] = raw_inputs.get(event.index, "") + event.delta.partial_json
                    elif event.type == "message_start":
                        began.update(model=event.message.model, usage=event.message.usage)
                    elif event.type == "message_delta":
                        began["output_tokens"] = event.usage.output_tokens
                    elif event.type == "content_block_start" and getattr(event.content_block, "type", "") == "fallback":
                        began["switched_to"] = event.content_block.to.model       # the fallback model now answers
                try:
                    message = stream.get_final_message()
                except AssertionError:
                    message = None
                if message is None:
                    # no message: the stream closed before the reply began (a dropped connection)
                    raise TransientFailure("the reply stream ended before the reply began")
                return message
        except sdk.APIStatusError as exc:
            code, kind = exc.status_code, exc.type or ""
            payload = exc.body if isinstance(exc.body, dict) else {}
            error = payload.get("error") if isinstance(payload.get("error"), dict) else {}
            message = error.get("message") if isinstance(error.get("message"), str) else str(exc.message)
            detail = redact_text(message, self.s)[:MAX_ERROR_MESSAGE]
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
    def _strictness(self, request: ChatRequest) -> tuple[frozenset[str], list[str]]:
        """Choose a bounded strict-tool prefix in stable output-first order.

        The response schema has no loose form, so its problems refuse the request. Tools after the provider's
        per-request union/optional limit remain available with local validation but are sent non-strict.
        """
        schema_counts = {"optional": 0, "union": 0}
        problems: list[str] = []
        if request.response_schema is not None:
            problems = [f"response schema: {p}"
                        for p in strict_schema_problems(request.response_schema, schema_counts)]
        counts = dict(schema_counts)
        strict = set()
        preferred = (
            "propose_finding", "propose_link", "add_note", "request_rule",
            "open_hypothesis", "update_hypothesis", "finish_session",
            "get_finding", "get_evidence", "get_incident",
            "list_findings", "list_coverage", "list_incidents", "entity_profile",
            "entity_timeline", "auth_activity", "process_tree", "ids_alerts", "follow_link",
        )
        order = {name: index for index, name in enumerate(preferred)}
        for t in sorted(request.tools, key=lambda item: (order.get(item.name, len(order)), item.name)):
            tool_counts = {"optional": 0, "union": 0}
            if not strict_schema_problems(t.parameters, tool_counts):
                proposed = {key: counts[key] + tool_counts[key] for key in counts}
                if (len(strict) >= MAX_STRICT_TOOLS or proposed["optional"] > MAX_OPTIONAL_PARAMETERS
                        or proposed["union"] > MAX_UNION_PARAMETERS):
                    break
                strict.add(t.name)
                counts = proposed
        if schema_counts["optional"] > MAX_OPTIONAL_PARAMETERS:
            problems.append(f"{schema_counts['optional']} optional parameters (at most {MAX_OPTIONAL_PARAMETERS})")
        if schema_counts["union"] > MAX_UNION_PARAMETERS:
            problems.append(f"{schema_counts['union']} union-typed parameters (at most {MAX_UNION_PARAMETERS})")
        return frozenset(strict), problems

    def _body(self, request: ChatRequest, messages: list[dict], max_out: int,
              strict: frozenset[str] = frozenset()) -> tuple[dict, list[str]]:
        """The stream() arguments, and the tools a required-tool instruction named (replayed with the reply)."""
        system, out = self._translate(request, messages)
        tools = [{"name": t.name, "description": t.description, "input_schema": t.parameters,
                  "strict": t.name in strict,
                  # inputs stream as generated; _tool_call parses each one, as the API no longer does
                  "eager_input_streaming": True}
                 for t in sorted(request.tools, key=lambda t: t.name)]
        # one explicit cache breakpoint closes the stable prefix (tools, then the system prompt)
        if system:
            system[-1]["cache_control"] = dict(CACHE)
        elif tools:
            tools[-1]["cache_control"] = dict(CACHE)
        required: list[str] = []
        if tools and request.tool_choice == "required":
            # this model rejects a forced tool choice; the instruction is rebuilt from these names on replay
            required = [t["name"] for t in tools]
            _require_tool(out, len(request.messages), required)
        _check_placement(out)
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
        return body, required

    def _translate(self, request: ChatRequest, messages: list[dict]) -> tuple[list[dict], list[dict]]:
        """Port messages to the top-level system blocks and Messages API messages. `messages` are the redacted
        ones; `request.messages` are the originals, against which replayed turns are checked."""
        system: list[dict] = []
        out: list[dict] = []
        results: list[dict] | None = None      # the open user message of tool results
        for n, (original, m) in enumerate(zip(request.messages, messages)):
            if not isinstance(m, dict):
                raise HistoryError(f"message {n} is not a message object")
            role = m.get("role")
            if role != "tool":
                results = None
            if role == "system":
                if out:
                    out.append({"role": "system", "content": _text(m), "_n": n})    # a mid-conversation one
                else:
                    system.append({"type": "text", "text": _text(m)})
            elif role == "user":
                content = m.get("content")
                out.append({"role": "user", "content": content if isinstance(content, str) else
                            [{"type": "text", "text": _text({"content": [part]})} for part in content or []]})
            elif role == "assistant":
                out += self._assistant(n, original, m, out)
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

    def _assistant(self, n: int, original: dict, m: dict, out: list[dict]) -> list[dict]:
        state = original.get(PROVIDER_STATE)
        calls = original.get("tool_calls") or []
        if state is None:
            if calls:
                raise HistoryError(
                    f"assistant message {n} has tool calls but none of the thinking blocks Claude signed for that "
                    "turn: it was built by another provider, or trimmed or rebuilt. Append each reply as "
                    "ChatResult.assistant_message() returns it; sessions must be append-only or start fresh")
            return [{"role": "assistant", "content": _text(m)}]
        problem = _state_problem(state)
        if problem:
            raise HistoryError(f"assistant message {n} carries provider state this adapter will not replay: {problem}")
        blocks, raw_inputs = state["content"], state.get("tool_inputs") or {}
        stored = [(b["id"], b["name"], raw_inputs.get(b["id"], "")) for b in blocks if b["type"] == "tool_use"]
        given = [(c.get("id"), (c.get("function") or {}).get("name"), (c.get("function") or {}).get("arguments"))
                 for c in calls if isinstance(c, dict)]
        same_calls = len(given) == len(stored) == len(calls) and all(
            g[:2] == s[:2] and _same_arguments(g[2], s[2]) for g, s in zip(given, stored, strict=True))
        stored_text = "".join(b["text"] for b in blocks if b["type"] == "text")
        if not same_calls or _text(original) != stored_text:
            raise HistoryError(f"assistant message {n} was changed after the model produced it; its signed "
                               "thinking no longer matches the turn. Sessions must be append-only or start fresh")
        replayed = ([b.get("text") or b.get("thinking") or "" for b in blocks] + [s[2] for s in stored]
                    + [json.dumps(b["input"]) for b in blocks if b["type"] == "tool_use"])
        if any(secret in text for secret in _long_secrets(self.s) for text in replayed):
            raise HistoryError(f"assistant message {n} holds a configured secret; it is never sent")
        if state.get("required_tools"):
            _require_tool(out, n, list(state["required_tools"]))
        return [{"role": "assistant", "content": copy.deepcopy(blocks)}]

    # ---- reply ------------------------------------------------------------------------------------------------
    def _result(self, request: ChatRequest, message, raw_inputs: dict[int, str], required: list[str], est: int,
                ms: int, attempts: int, broken: list[dict], max_out: int) -> ChatResult:
        blocks = list(message.content or [])
        # after a fallback, only text from before the last switch carries over; the declined model's thinking and
        # tool calls are dropped, and the switch marker itself is an audit record the API ignores
        boundary = max((i for i, b in enumerate(blocks) if b.type == "fallback"), default=-1)
        kept: list[dict] = []
        texts: list[str] = []
        calls: list[ToolCall] = []
        tool_inputs: dict[str, str] = {}
        foreign: list[str] = []
        for i, block in enumerate(blocks):
            if block.type == "fallback" or (i < boundary and block.type != "text"):
                continue
            if block.type not in BLOCK_KEYS:
                foreign.append(block.type)      # no server tools are offered: nothing else belongs in a reply
                continue
            kept.append({k: v for k, v in block.to_dict(warnings=False).items() if k in BLOCK_KEYS[block.type]})
            if block.type == "text":
                texts.append(block.text)
            elif block.type == "tool_use":
                raw = raw_inputs.get(i)
                if raw is None:
                    raw = json.dumps(block.input) if block.input else ""
                tool_inputs[block.id] = raw
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
        served_by_fallback = any(it.type == "fallback_message" for it in iterations)
        if switches or served_by_fallback:
            details["fallback"] = {"served_by": message.model, "switches": switches}
        read, write = (usage.cache_read_input_tokens or 0), (usage.cache_creation_input_tokens or 0)
        tokens = Usage(usage.input_tokens + read + write, usage.output_tokens, read, write)
        # every attempt the API billed for this call, each with the model that served it (the declined ones, and a
        # call the fallback model serves outright, included), after any attempt that broke off before this one
        attempts_billed = [{"model": it.model or ("" if served_by_fallback else message.model),
                            "prompt": it.input_tokens + it.cache_creation_input_tokens + it.cache_read_input_tokens,
                            "completion": it.output_tokens, "cache_read": it.cache_read_input_tokens,
                            "cache_write": it.cache_creation_input_tokens} for it in iterations] or [
            {"model": message.model, "prompt": tokens.prompt_tokens, "completion": tokens.completion_tokens,
             "cache_read": read, "cache_write": write}]
        if native is None:
            # the stream ended before it reported a stop or its output: charged as an attempt that broke off
            attempts_billed = self._broken_attempt(
                {"model": switches[0]["from"] if switches else message.model, "usage": usage,
                 "switched_to": switches[-1]["to"] if switches else None}, max_out)
        details["billed"] = [*broken, *attempts_billed]
        finish = CLAUDE_STOP_REASONS.get(native, native) if native else None
        result = self._finish(finish_reason=finish, content=content, tool_calls=calls, usage=tokens, est=est,
                              model_reported=str(message.model or ""), ms=ms,
                              raw=json.dumps(message.to_dict(mode="json"), sort_keys=True), attempts=attempts,
                              request=request, refusal=refusal)
        if native and native not in CLAUDE_STOP_REASONS and result.status != "truncated_input":
            # only the documented reasons say what the reply is; stop_sequence too, as none is ever sent
            result.status, result.error = "error", f"unexpected stop reason {native!r}: not a complete reply"
        if foreign and result.status in ("ok", "invalid_json", "invalid_tool_call"):
            result.status, result.error = "error", f"the reply holds unexpected content blocks: {sorted(set(foreign))}"
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
        if result.status != "refused" and not foreign:
            state: dict = {"provider": self.name, "model": message.model, "content": kept, "tool_inputs": tool_inputs}
            if required:
                state["required_tools"] = required
            result.provider_state = state
        return result

    def _tool_call(self, call_id: str, name: str, raw: str, request: ChatRequest) -> ToolCall:
        """The port's argument parsing on the raw streamed JSON, then the tool's schema."""
        call = parse_tool_arguments(call_id, name, raw)
        tool = next((t for t in request.tools if t.name == name), None)
        # a schema outside the subset was sent loose; the caller validates those arguments against its own model
        if call.arguments is not None and tool is not None and not strict_schema_problems(tool.parameters):
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
