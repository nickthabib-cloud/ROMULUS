"""Deterministic provider responses for offline agent-controller tests."""
from __future__ import annotations

from collections import deque
from copy import deepcopy
from threading import Lock

from romulus.agent.provider.base import ChatProvider, ChatResult, Usage


class ScriptedProvider(ChatProvider):
    name = "scripted"
    model = "scripted-model"
    sends_sampling = False

    def __init__(self, results, *, context=100_000, output=1024):
        self.results = deque(results)
        self.requests = []
        self.context = context
        self.output = output
        self.lock = Lock()

    def describe(self):
        return {"provider": self.name, "model_requested": self.model, "endpoint_host": "scripted",
                "egress": "local"}

    def context_tokens(self):
        return self.context

    def output_limit(self, _request):
        return self.output

    def chat(self, request):
        with self.lock:
            self.requests.append(deepcopy(request))
            if not self.results:
                raise AssertionError("scripted provider ran out of responses")
            response = self.results.popleft()
        if callable(response):
            response = response(request)
        if isinstance(response, BaseException):
            raise response
        return response


def response(*, tool_calls=(), parsed=None, content="", status="ok", error=""):
    calls = list(tool_calls)
    return ChatResult(status=status, finish_reason="tool_calls" if calls else "stop", content=content,
                      parsed=parsed, tool_calls=calls, usage=Usage(prompt_tokens=100, completion_tokens=40),
                      prompt_tokens_est=100, model_requested="scripted-model", model_reported="scripted-model",
                      duration_ms=1, raw=content or "{}", error=error)
