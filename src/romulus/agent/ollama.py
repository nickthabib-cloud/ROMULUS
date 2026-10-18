"""Ollama chat client with JSON-schema structured output, explicit num_ctx and truncation checks."""
from __future__ import annotations

import json
import time
from dataclasses import dataclass

import httpx

from romulus.config import Settings

CHARS_PER_TOKEN = 3.2          # conservative for English + JSON + log text
TRUNCATION_MARGIN = 32


class ModelUnavailable(RuntimeError):
    pass


@dataclass
class ModelResult:
    ok: bool
    status: str                 # ok | invalid_json | truncated | too_large | error
    raw: str
    parsed: dict | None
    prompt_tokens_est: int
    prompt_eval_count: int | None
    eval_count: int | None
    duration_ms: int
    error: str = ""


def estimate_tokens(text: str) -> int:
    return int(len(text) / CHARS_PER_TOKEN) + 8


class OllamaClient:
    def __init__(self, s: Settings, transport: httpx.BaseTransport | None = None):
        self.s = s
        self.http = httpx.Client(base_url=s.ollama_url.rstrip("/"), timeout=s.ollama_timeout_seconds,
                                 transport=transport)

    def available(self) -> bool:
        try:
            return self.http.get("/api/version", timeout=5).status_code == 200
        except httpx.HTTPError:
            return False

    def chat_json(self, model: str, system: str, user: str, schema: dict, max_out: int = 900,
                  temperature: float = 0.1) -> ModelResult:
        est = estimate_tokens(system) + estimate_tokens(user)
        num_ctx = self.s.ollama_num_ctx
        if est + max_out > num_ctx:
            return ModelResult(False, "too_large", "", None, est, None, None, 0,
                               f"prompt estimate {est} + {max_out} output exceeds num_ctx {num_ctx}")
        body = {
            "model": model, "stream": False, "format": schema, "think": self.s.ollama_think,
            "keep_alive": self.s.ollama_keep_alive,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "options": {"num_ctx": num_ctx, "num_predict": max_out, "temperature": temperature, "seed": 7},
        }
        t0 = time.time()
        try:
            r = self.http.post("/api/chat", json=body)
        except httpx.HTTPError as e:
            raise ModelUnavailable(str(e)) from e
        ms = int((time.time() - t0) * 1000)
        if r.status_code != 200:
            return ModelResult(False, "error", r.text[:500], None, est, None, None, ms, f"HTTP {r.status_code}")
        d = r.json()
        raw = d.get("message", {}).get("content", "")
        pec, ec = d.get("prompt_eval_count"), d.get("eval_count")
        # prompt_eval_count counts only non-cached tokens, so a low value is normal; a value at the
        # context ceiling means Ollama silently truncated the prompt.
        if pec is not None and pec >= num_ctx - TRUNCATION_MARGIN:
            return ModelResult(False, "truncated", raw, None, est, pec, ec, ms,
                               f"prompt_eval_count {pec} reached num_ctx {num_ctx}: prompt was truncated")
        if d.get("done_reason") == "length":
            return ModelResult(False, "invalid_json", raw, None, est, pec, ec, ms, "output hit num_predict limit")
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as e:
            return ModelResult(False, "invalid_json", raw, None, est, pec, ec, ms, str(e))
        return ModelResult(True, "ok", raw, parsed, est, pec, ec, ms)
