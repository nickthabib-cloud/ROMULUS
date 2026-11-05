"""Adapter for the OpenAI Responses API (POST /responses), which reasoning models need for function tools.

AGENT_BASE_URL is the API root that contains /responses and defaults to https://api.openai.com/v1, a remote
endpoint: telemetry may reach it only under ROMULUS_MODEL_EGRESS=lab-public-data, over https. Requests go through the
port's HTTP client (no environment proxy, no redirects) with the key from AGENT_API_KEY, and the port's one retry
policy applies.

Translation: system, developer and user messages become input messages in place; assistant tool calls become
function_call items and tool results function_call_output items. Function tools are flat and sent strict when their
schema is inside the strict subset (every property required, no additional properties), else not strict; either way
each call's arguments are parsed here and, for a schema in that subset, checked against it. A response schema
becomes text.format. tool_choice auto, required and none are sent as they are, and a reply without the call a
required choice asked for is invalid_tool_call. Reasoning effort is AGENT_EFFORT, and each call's max_output_tokens
(which counts reasoning) adds AGENT_THINKING_TOKENS of room for it. Sampling parameters are never sent: reasoning
models refuse them. Truncation is disabled, so the server refuses a prompt larger than the context window instead
of dropping its start. Calls stream, so AGENT_TIMEOUT_SECONDS bounds each read rather than the whole reply, and the
reply is the response the terminal event carries.

Nothing is stored on the server (store=false): reasoning crosses turns as encrypted reasoning items. Each reply's
output items travel in the provider state of its assistant message (ChatResult.assistant_message()) and are replayed
unchanged in their place. An assistant turn without provider state (history from another provider) is sent from its
text and tool calls alone. A state that is malformed or holds anything else, a turn whose text or tool calls no
longer match its state, or one that holds a configured secret raises HistoryError before anything is sent.

Usage maps input_tokens (cached tokens included) to prompt tokens, output_tokens (reasoning included) to completion
tokens, and the cached and cache-write input details to the cache counts. An attempt that broke off after the
response began is charged as billed: its reported usage, else its prompt estimate and full output allowance.

Field names are checked against OpenAI's API reference, as the official SDK's generated types carry it, and guides:
- https://developers.openai.com/api/reference/resources/responses/methods/create
- https://github.com/openai/openai-python/blob/main/src/openai/types/responses/response_create_params.py
- https://github.com/openai/openai-python/blob/main/src/openai/types/responses/response.py (and response_usage.py,
  response_input_item_param.py, function_tool_param.py, response_reasoning_item.py, response_output_message.py,
  response_completed_event.py, response_failed_event.py, response_error_event.py)
- https://github.com/openai/openai-python/blob/main/src/openai/types/shared/reasoning.py
- https://developers.openai.com/api/docs/guides/reasoning (reasoning items without stored responses)
- https://developers.openai.com/api/docs/guides/function-calling
"""
from __future__ import annotations

import copy
import json
import time

import httpx

from romulus.agent.provider.base import (
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
    error_message,
    parse_tool_arguments,
)
from romulus.agent.provider.claude_messages import (
    _long_secrets,
    _same_arguments,
    _text,
    instance_problems,
    strict_schema_problems,
)
from romulus.agent.provider.openai_compatible import _int, probe_calls, probe_models
from romulus.config import redact_text

# the output items a reply may hold and an assistant turn may replay, with only these fields
ITEM_KEYS = {"reasoning": frozenset({"type", "id", "summary", "encrypted_content", "content", "status"}),
             "message": frozenset({"type", "id", "role", "status", "content", "phase"}),
             "function_call": frozenset({"type", "id", "call_id", "name", "arguments", "status"})}
PART_KEYS = {"output_text": frozenset({"type", "text", "annotations", "logprobs"}),
             "refusal": frozenset({"type", "refusal"})}
STATE_KEYS = frozenset({"provider", "model", "output"})
INCOMPLETE_REASONS = {"max_output_tokens": "length", "content_filter": "content_filter"}
# response error codes worth another attempt, whether in a failed response or a stream error event
TRANSIENT_CODES = frozenset({"server_error", "rate_limit_exceeded"})


class _Failed(Exception):
    """A call that ended without a usable reply and is not worth retrying."""

    def __init__(self, status: str, error: str, raw: str = ""):
        super().__init__(error)
        self.status = status
        self.error = error
        self.raw = raw


def _all_required(node) -> bool:
    """Whether every object in the schema requires each of its properties, as the API's strict mode needs."""
    if isinstance(node, list):
        return all(_all_required(v) for v in node)
    if not isinstance(node, dict):
        return True
    properties = node.get("properties")
    if isinstance(properties, dict) and set(node.get("required") or []) != set(properties):
        return False
    return all(_all_required(v) for v in node.values())


def strict_ok(schema) -> bool:
    return not strict_schema_problems(schema) and _all_required(schema)


def _state_problem(state) -> str:
    """Why a provider state cannot be a reply this adapter stored (empty when it can)."""
    if not isinstance(state, dict) or state.get("provider") != OpenAIResponsesProvider.name:
        return "it was not written by this adapter"
    if set(state) - STATE_KEYS:
        return f"unknown fields {sorted(set(state) - STATE_KEYS)}"
    items = state.get("output")
    if not isinstance(items, list) or not isinstance(state.get("model", ""), str):
        return "malformed"
    for item in items:
        kind = item.get("type") if isinstance(item, dict) else None
        if not isinstance(kind, str) or kind not in ITEM_KEYS:
            return f"a {kind!r} item, which a reply to this adapter never holds"
        if set(item) - ITEM_KEYS[kind]:
            return f"a {kind} item with unknown fields {sorted(set(item) - ITEM_KEYS[kind])}"
        if not isinstance(item.get("id", ""), str):
            return f"a malformed {kind} item"
        if kind == "function_call" and not all(isinstance(item.get(k), str) for k in ("call_id", "name", "arguments")):
            return "a malformed function_call item"
        if kind == "reasoning" and (not isinstance(item.get("summary", []), list)
                                    or not isinstance(item.get("encrypted_content") or "", str)):
            return "a malformed reasoning item"
        if kind == "message":
            parts = item.get("content")
            if item.get("role") != "assistant" or not isinstance(parts, list):
                return "a malformed message item"
            for part in parts:
                ptype = part.get("type") if isinstance(part, dict) else None
                if ptype not in PART_KEYS or set(part) - PART_KEYS[ptype] \
                        or not isinstance(part.get("text" if ptype == "output_text" else "refusal"), str):
                    return "a message item with a malformed content part"
    return ""


def _plain_texts(items: list[dict]) -> list[str]:
    """Every readable string a replayed reply carries (encrypted reasoning is opaque and never readable)."""
    out = []
    for item in items:
        if item["type"] == "function_call":
            out += [item["arguments"], item["name"]]
        elif item["type"] == "message":
            out += [p.get("text") or p.get("refusal") or "" for p in item["content"]]
        else:
            out += [str(p.get("text", "")) for key in ("summary", "content") for p in item.get(key) or []
                    if isinstance(p, dict)]
    return out


class OpenAIResponsesProvider(ChatProvider):
    name = "openai_responses"
    replays_provider_state = True
    sends_sampling = False

    def _headers(self) -> dict[str, str]:
        key = self.s.agent_api_key.get_secret_value()
        return {"Authorization": f"Bearer {key}"} if key else {}

    def output_limit(self, request: ChatRequest) -> int:
        return super().output_limit(request) + self.s.agent_thinking_tokens

    # ---- one call -------------------------------------------------------------------------------------------
    def _chat(self, request: ChatRequest, messages: list[dict], max_out: int, est: int) -> ChatResult:
        def failed(status: str, error: str, ms: int, attempts: int, raw: str = "") -> ChatResult:
            return ChatResult(status, "", "", None, [], Usage(), est, self.model, "", ms,
                              redact_text(raw, self.s)[:2000], redact_text(error, self.s), attempts)

        body = self._body(request, messages, max_out)
        attempts = [0]
        broken: list[dict] = []          # attempts that broke off after the response began: billed all the same

        def once():
            attempts[0] += 1
            began: dict = {}
            try:
                return self._stream(body, began)
            except (TransientFailure, _Failed) as exc:
                if not began:
                    raise
                broken.append(self._broken_attempt(began, est, max_out))
                if isinstance(exc, TransientFailure) and self.s.agent_max_cost_usd:
                    # a retry could be billed again in full, past what the budget checked before this call
                    raise _Failed("error", f"the reply broke off after it began and was billed ({exc.detail}); not "
                                           "retried, as a cost budget is set") from None
                raise

        t0 = time.monotonic()
        try:
            data, ms, n = self._retrying(once)
        except _Failed as exc:
            result = failed(exc.status, exc.error, int((time.monotonic() - t0) * 1000), attempts[0], exc.raw)
            if broken:
                result.details = {"billed": broken}
            return result
        except ProviderUnavailable as exc:
            exc.billed = broken      # for AgentBudget.charge_failure: the provider billed these attempts
            raise
        try:
            return self._result(request, data, est, ms, n, broken, max_out)
        except (KeyError, TypeError, AttributeError, ValueError):
            result = failed("error", "the reply is not a Responses API response", ms, n, json.dumps(data, default=str))
            if broken:
                result.details = {"billed": broken}
            return result

    def _broken_attempt(self, began: dict, est: int, max_out: int) -> dict:
        usage = began.get("usage") if isinstance(began.get("usage"), dict) else {}
        prompt, completion = _int(usage.get("input_tokens")), _int(usage.get("output_tokens"))
        details = usage.get("input_tokens_details") or {}
        return {"model": began.get("model") or "", "prompt": prompt if prompt is not None else est,
                "completion": completion if completion is not None else max_out,
                "cache_read": _int(details.get("cached_tokens")) or 0,
                "cache_write": _int(details.get("cache_write_tokens")) or 0,
                "worst_case": completion is None}

    def _stream(self, body: dict, began: dict) -> dict:
        """One streamed request and the response its terminal event carries. `began` gets the model once the
        response is created, and the usage of a response that failed."""
        try:
            with self.http.stream("POST", "/responses", json=body) as response:
                code = response.status_code
                if code != 200:
                    response.read()
                    text = redact_text(response.text, self.s)
                    if code in RETRY_STATUSES:
                        raise TransientFailure(f"HTTP {code}", suffix=f": {error_message(text)}",
                                               retry_after=response.headers.get("retry-after", ""))
                    raise _Failed("too_large" if code == 413 else "error", f"HTTP {code}: {error_message(text)}",
                                  text)
                if "text/event-stream" not in response.headers.get("content-type", ""):
                    response.read()        # a server that answered in one piece
                    try:
                        data = response.json()
                    except ValueError:
                        raise _Failed("error", "the reply is not a Responses API response", response.text) from None
                    return self._final({"type": "response.completed", "response": data}, began)
                return self._events(response, began)
        except httpx.TransportError as exc:
            raise TransientFailure(f"{exc.__class__.__name__}: {exc}") from None
        except httpx.HTTPError as exc:       # e.g. a body that cannot be decoded: not a reply worth another try
            raise _Failed("error", f"the reply could not be read: {exc.__class__.__name__}: {exc}"[:600]) from None

    def _events(self, response: httpx.Response, began: dict) -> dict:
        data: list[str] = []
        for line in response.iter_lines():
            if line.startswith("data:"):
                data.append(line[5:].removeprefix(" "))
            elif not line and data:
                found = self._event("\n".join(data), began)
                data = []
                if found is not None:
                    return found
        if data:
            found = self._event("\n".join(data), began)
            if found is not None:
                return found
        raise TransientFailure("the reply stream ended before the response completed")

    def _event(self, text: str, began: dict) -> dict | None:
        if text.strip() == "[DONE]":
            return None
        try:
            event = json.loads(text)
        except ValueError:
            raise _Failed("error", "the reply stream could not be read: an event is not JSON") from None
        if not isinstance(event, dict):
            raise _Failed("error", "the reply stream could not be read: an event is not an object")
        kind = event.get("type")
        if kind in ("response.created", "response.in_progress"):
            created = event.get("response")
            began["model"] = str((created.get("model") if isinstance(created, dict) else None)
                                 or began.get("model") or "")
            return None
        if kind == "error":
            raise self._failure(event.get("code"), event.get("message"))
        if kind in ("response.completed", "response.incomplete", "response.failed"):
            return self._final(event, began)
        return None

    def _final(self, event: dict, began: dict) -> dict:
        data = event.get("response")
        if not isinstance(data, dict):
            raise _Failed("error", f"the {event.get('type')} event carries no response")
        if event["type"] == "response.failed" or data.get("status") == "failed":
            began.setdefault("model", str(data.get("model") or ""))
            began["usage"] = data.get("usage")
            error = data.get("error") if isinstance(data.get("error"), dict) else {}
            raise self._failure(error.get("code"), error.get("message"))
        return data

    def _failure(self, code, message) -> Exception:
        detail = redact_text(str(message or "no message given"), self.s)
        if code in TRANSIENT_CODES:
            return TransientFailure(f"response error {code}", suffix=f": {detail}")
        return _Failed("error", f"the response failed ({code or 'no code given'}): {detail}")

    # ---- request ----------------------------------------------------------------------------------------------
    def _body(self, request: ChatRequest, messages: list[dict], max_out: int) -> dict:
        # never temperature or top_p: reasoning models refuse sampling parameters
        body: dict = {"model": self.model, "input": self._input(request, messages), "max_output_tokens": max_out,
                      "reasoning": {"effort": self.s.agent_effort}, "store": False,
                      # stateless reasoning: the encrypted items come back to be replayed with the turn
                      "include": ["reasoning.encrypted_content"], "truncation": "disabled", "stream": True}
        if request.tools:
            body["tools"] = [{"type": "function", "name": t.name, "description": t.description,
                              "parameters": t.parameters, "strict": strict_ok(t.parameters)} for t in request.tools]
            body["tool_choice"] = request.tool_choice
        if request.response_schema is not None:
            body["text"] = {"format": {"type": "json_schema", "name": request.schema_name,
                                       "schema": request.response_schema, "strict": request.strict_schema}}
        return body

    def _input(self, request: ChatRequest, messages: list[dict]) -> list[dict]:
        """Port messages as input items. `messages` are the redacted ones; `request.messages` are the originals,
        against which replayed turns are checked."""
        items: list[dict] = []
        for n, (original, m) in enumerate(zip(request.messages, messages)):
            if not isinstance(m, dict):
                raise HistoryError(f"message {n} is not a message object")
            role = m.get("role")
            if role in ("system", "developer", "user"):
                content = m.get("content")
                items.append({"role": role, "content": [{"type": "input_text", "text": _text({"content": [part]})}
                                                        for part in content] if isinstance(content, list)
                              else _text(m)})
            elif role == "assistant":
                items += self._assistant(n, original, m)
            elif role == "tool":
                items.append({"type": "function_call_output", "call_id": str(m.get("tool_call_id") or ""),
                              "output": _text(m)})
            else:
                raise HistoryError(f"message {n} has an unknown role {role!r}")
        return items

    def _assistant(self, n: int, original: dict, m: dict) -> list[dict]:
        state = original.get(PROVIDER_STATE)
        if state is None:
            out: list[dict] = []
            if _text(m):
                out.append({"role": "assistant", "content": _text(m)})
            for call in m.get("tool_calls") or []:
                if not isinstance(call, dict):
                    raise HistoryError(f"assistant message {n} has a tool call that is not an object")
                function = call.get("function") or {}
                arguments = function.get("arguments")
                out.append({"type": "function_call", "call_id": str(call.get("id") or ""),
                            "name": str(function.get("name") or ""),
                            "arguments": arguments if isinstance(arguments, str) else json.dumps(arguments or {})})
            return out
        problem = _state_problem(state)
        if problem:
            raise HistoryError(f"assistant message {n} carries provider state this adapter will not replay: {problem}")
        items = state["output"]
        calls = original.get("tool_calls") or []
        stored = [(i["call_id"], i["name"], i["arguments"]) for i in items if i["type"] == "function_call"]
        given = [(c.get("id"), (c.get("function") or {}).get("name"), (c.get("function") or {}).get("arguments"))
                 for c in calls if isinstance(c, dict)]
        same_calls = len(given) == len(stored) == len(calls) and all(
            g[:2] == s[:2] and _same_arguments(g[2], s[2]) for g, s in zip(given, stored, strict=True))
        stored_text = "".join(p["text"] for i in items if i["type"] == "message" for p in i["content"]
                              if p["type"] == "output_text")
        if not same_calls or _text(original) != stored_text:
            raise HistoryError(f"assistant message {n} was changed after the model produced it; its reasoning no "
                               "longer matches the turn. Sessions must be append-only or start fresh")
        if any(secret in text for secret in _long_secrets(self.s) for text in _plain_texts(items)):
            raise HistoryError(f"assistant message {n} holds a configured secret; it is never sent")
        return copy.deepcopy(items)

    # ---- reply ------------------------------------------------------------------------------------------------
    def _result(self, request: ChatRequest, data: dict, est: int, ms: int, attempts: int, broken: list[dict],
                max_out: int) -> ChatResult:
        kept: list[dict] = []
        texts: list[str] = []
        refusals: list[str] = []
        calls: list[ToolCall] = []
        foreign: list[str] = []
        for item in data["output"]:
            kind = item.get("type")
            if kind not in ITEM_KEYS:
                foreign.append(str(kind))      # no hosted tools are offered: nothing else belongs in a reply
                continue
            kept.append({k: v for k, v in item.items() if k in ITEM_KEYS[kind]})
            if kind == "message":
                for part in item.get("content") or []:
                    if part.get("type") == "output_text":
                        texts.append(str(part.get("text") or ""))
                    elif part.get("type") == "refusal":
                        refusals.append(str(part.get("refusal") or ""))
                    else:
                        foreign.append(f"message part {part.get('type')}")
            elif kind == "function_call":
                calls.append(self._tool_call(str(item.get("call_id") or ""), str(item.get("name") or ""),
                                             item.get("arguments", ""), request))
        content = "".join(texts)
        status = data.get("status")
        reason = (data.get("incomplete_details") or {}).get("reason")
        model = str(data.get("model") or "")
        if status == "completed":
            finish = "tool_calls" if calls else "stop"
        elif status == "incomplete":
            finish = INCOMPLETE_REASONS.get(reason, f"incomplete ({reason})")
        else:
            finish = f"status {status}" if status else None
        refusal = ""
        if refusals:
            refusal = "the model declined to answer: " + " ".join(r for r in refusals if r).strip()
            calls = []      # never run a tool call from a reply that refused
        usage = data.get("usage") if isinstance(data.get("usage"), dict) else {}
        inputs, outputs = usage.get("input_tokens_details") or {}, usage.get("output_tokens_details") or {}
        tokens = Usage(_int(usage.get("input_tokens")), _int(usage.get("output_tokens")),
                       _int(inputs.get("cached_tokens")), _int(inputs.get("cache_write_tokens")))
        details: dict = {"status": status, "model": model,
                         "reasoning_effort": (data.get("reasoning") or {}).get("effort"),
                         "reasoning_tokens": _int(outputs.get("reasoning_tokens"))}
        if reason:
            details["incomplete_reason"] = reason
        if refusals:
            details["refusal"] = refusals
        if tokens.reported:
            billed = [{"model": model, "prompt": tokens.prompt_tokens, "completion": tokens.completion_tokens,
                       "cache_read": tokens.cache_read_tokens or 0, "cache_write": tokens.cache_write_tokens or 0}]
        else:
            billed = [{"model": model, "prompt": est, "completion": max_out, "worst_case": True}] if broken else []
        if broken or billed:
            details["billed"] = [*broken, *billed]
        result = self._finish(finish_reason=finish, content=content, tool_calls=calls, usage=tokens, est=est,
                              model_reported=model, ms=ms, raw=json.dumps(data, sort_keys=True), attempts=attempts,
                              request=request, refusal=refusal)
        if foreign and result.status in ("ok", "invalid_json", "invalid_tool_call"):
            result.status, result.error = "error", f"the reply holds unexpected output: {sorted(set(foreign))}"
        if result.status == "truncated_output" and not content and not calls:
            result.error += ("; nothing was produced before the limit (reasoning used it all): raise "
                             "AGENT_THINKING_TOKENS or lower AGENT_EFFORT")
        if result.ok and request.tool_choice == "required" and not calls:
            result.status, result.error = "invalid_tool_call", "the model answered without the tool call required"
        if result.ok and request.tool_choice == "none" and calls:
            result.status, result.error = "invalid_tool_call", "the model called a tool where none was allowed"
        if result.ok and result.parsed is not None and request.response_schema is not None \
                and not strict_schema_problems(request.response_schema):
            problems = instance_problems(result.parsed, request.response_schema)
            if problems:
                result.status, result.parsed = "invalid_json", None
                result.error = "the reply does not match the requested schema: " + "; ".join(problems[:5])
        result.details = details
        if result.status != "refused" and not foreign:
            result.provider_state = {"provider": self.name, "model": model, "output": kept}
        return result

    def _tool_call(self, call_id: str, name: str, raw, request: ChatRequest) -> ToolCall:
        """The port's argument parsing, then the tool's schema when it is inside the strict subset."""
        call = parse_tool_arguments(call_id, name, raw)
        tool = next((t for t in request.tools if t.name == name), None)
        if call.arguments is not None and tool is not None and not strict_schema_problems(tool.parameters):
            problems = instance_problems(call.arguments, tool.parameters)
            if problems:
                return ToolCall(call_id, name, None, call.raw_arguments,
                                "arguments do not match the tool's schema: " + "; ".join(problems[:5]))
        return call

    # ---- doctor -----------------------------------------------------------------------------------------------
    def probe(self) -> list[tuple[str, str, str]]:
        out, reachable = probe_models(self)
        if not reachable:
            return out
        configured = self.s.agent_context_tokens
        out.append(("agent.context", "ok", f"AGENT_CONTEXT_TOKENS={configured}" if configured else
                    "truncation is disabled: the server refuses a prompt larger than the model's context window"))
        need = self.s.agent_max_output_tokens + self.s.agent_thinking_tokens
        out.append(("agent.output", "ok", (f"max_output_tokens {need} per call (AGENT_MAX_OUTPUT_TOKENS + "
                                           f"AGENT_THINKING_TOKENS); reasoning effort {self.s.agent_effort}")))
        return out + probe_calls(self)
