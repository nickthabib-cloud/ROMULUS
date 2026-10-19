"""Run frozen bakeoff tasks against candidate models through the production model path.

Each call goes through ``OllamaClient.chat_json`` with the production decision schema and output budget,
then ``parse_decision_output``, ``validate_decision`` and the controller's duplicate-pivot check, exactly
as the investigator would. A capturing transport records Ollama's own timings (load, prompt eval, eval)
so token rates are real decode rates, not wall-clock estimates.

Seed 7 is production. Other seeds are written into the request by the transport, only to measure
run-to-run variance, and every result row records the seed it used.

A rejected first attempt is retried once, as the controller does. The retry brief is the frozen brief
with the validation errors inserted and re-rendered; the controller rebuilds from the store instead, so
retry rows are marked ``retry_approximate``.
"""
from __future__ import annotations

import json
import re
from collections.abc import Callable, Iterable
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
from pydantic import ValidationError

from romulus.agent.brief import BuiltBrief, _render
from romulus.agent.controller import Investigator
from romulus.agent.models import EntityRef, decision_schema, parse_decision_output
from romulus.agent.ollama import ModelUnavailable, OllamaClient
from romulus.agent.options import Menu
from romulus.agent.validate import ValidationResult, validate_decision
from romulus.bakeoff.export import MAX_OUT
from romulus.config import Settings

RESULT_SCHEMA = "bakeoff-result/1"
PRODUCTION_SEED = 7
_TELEMETRY = re.compile(r"<UNTRUSTED_TELEMETRY>\n(.*)\n</UNTRUSTED_TELEMETRY>\Z", re.DOTALL)
_TIMINGS = ("total_duration", "load_duration", "prompt_eval_count", "prompt_eval_duration", "eval_count",
            "eval_duration", "done_reason")


class CaptureTransport(httpx.BaseTransport):
    """Pass requests through; keep the last /api/chat timing fields; optionally override the seed."""

    def __init__(self, seed: int = PRODUCTION_SEED, inner: httpx.BaseTransport | None = None):
        self.seed = seed
        self.inner = inner or httpx.HTTPTransport()
        self.last: dict | None = None

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        is_chat = request.url.path.endswith("/api/chat")
        if is_chat and self.seed != PRODUCTION_SEED:
            body = json.loads(request.read())
            body.setdefault("options", {})["seed"] = self.seed
            headers = {k: v for k, v in request.headers.items() if k.lower() != "content-length"}
            request = httpx.Request(request.method, request.url, headers=headers, json=body)
        response = self.inner.handle_request(request)
        data = response.read()
        response.close()
        if is_chat:
            self.last = None
            try:
                payload = json.loads(data)
            except ValueError:
                payload = {}
            message = payload.get("message") or {}
            self.last = {key: payload.get(key) for key in _TIMINGS}
            self.last["thinking_chars"] = len(message.get("thinking") or "")
        headers = {k: v for k, v in response.headers.items()
                   if k.lower() not in {"content-length", "content-encoding", "transfer-encoding"}}
        return httpx.Response(response.status_code, headers=headers, content=data, request=request)

    def close(self) -> None:
        self.inner.close()


def brief_from_task(serialized: dict) -> BuiltBrief:
    return BuiltBrief(
        system=serialized["system"],
        user=serialized["user"],
        schema=dict(serialized.get("output_schema") or {}),
        menu=Menu.model_validate(serialized.get("menu") or {"options": [], "hidden_count": 0}),
        aliases=dict(serialized.get("aliases") or {}),
        token_estimate=serialized["token_estimate"],
        shrink_actions=list(serialized.get("shrink_actions") or []),
        known_candidates=dict(serialized.get("known_candidates") or {}),
        known_evidence_ids=set(serialized.get("known_evidence_ids") or []),
        known_entities=[EntityRef.model_validate(raw) for raw in serialized.get("known_entities") or []],
        injection_flags=list(serialized.get("injection_flags") or []),
        injection_evidence_ids=set(serialized.get("injection_evidence_ids") or []),
        known_process_ids={(str(host), int(pid)) for host, pid in serialized.get("known_process_ids") or []},
    )


def _window(task: dict) -> SimpleNamespace:
    return SimpleNamespace(start=datetime.fromisoformat(task["window"]["start"]),
                           end=datetime.fromisoformat(task["window"]["end"]))


def _duplicate(task: dict, request: Any) -> dict | None:
    """The controller's own duplicate-pivot check, over the task's frozen prior steps."""
    steps = task.get("prior_steps") or []
    shim = SimpleNamespace(repo=SimpleNamespace(case_steps=lambda _case_id: steps))
    return Investigator._executed_duplicate(shim, task["origin"]["case_id"], request)


def judge(task: dict, brief: BuiltBrief, parsed: dict | None) -> dict:
    """Schema and semantic validation exactly as the controller applies it."""
    out: dict[str, Any] = {"schema_valid": False, "validation_ok": False, "errors": [], "decision": None}
    try:
        decision = parse_decision_output(parsed)
    except ValidationError as exc:
        out["errors"] = [f"invalid decision schema: {exc}"]
        return out
    out["schema_valid"] = True
    out["decision"] = decision.model_dump(mode="json")
    validation: ValidationResult = validate_decision(decision, brief, _window(task))
    errors = list(validation.errors)
    if validation.ok and decision.action == "pivot":
        duplicate = _duplicate(task, validation.request)
        if duplicate is not None:
            errors = [
                (f"duplicate pivot: normalized request already executed at step {duplicate['n']}; "
                f"reuse prior_steps step {duplicate['n']} result_digest")
            ]
    out["validation_ok"] = not errors
    out["errors"] = errors
    return out


def retry_brief(brief: BuiltBrief, errors: list[str]) -> BuiltBrief | None:
    """Insert validation errors into the frozen brief's data and re-render it with the production renderer."""
    match = _TELEMETRY.search(brief.user)
    if match is None:
        return None
    data = json.loads(match.group(1))
    data["validation_retry_errors"] = list(errors)
    user, estimate = _render(brief.system, data, brief.schema)
    return BuiltBrief(**{**brief.__dict__, "user": user, "token_estimate": estimate})


def _rate(count: Any, duration_ns: Any) -> float | None:
    if not count or not duration_ns:
        return None
    return round(count / (duration_ns / 1e9), 2)


def _call(client: OllamaClient, transport: CaptureTransport, model: str, brief: BuiltBrief,
          max_out: int) -> tuple[dict, dict | None]:
    transport.last = None
    try:
        result = client.chat_json(model, brief.system, brief.user, brief.schema or decision_schema(), max_out=max_out)
    except ModelUnavailable as exc:
        return {"status": "unavailable", "error": str(exc), "duration_ms": None, "raw": ""}, None
    timings = transport.last or {}
    row = {
        "status": result.status,
        "error": result.error,
        "raw": result.raw,
        "duration_ms": result.duration_ms,
        "prompt_tokens_est": result.prompt_tokens_est,
        "prompt_eval_count": result.prompt_eval_count,
        "eval_count": result.eval_count,
        "load_ms": None if timings.get("load_duration") is None else timings["load_duration"] // 1_000_000,
        "prompt_eval_ms": None if timings.get("prompt_eval_duration") is None
        else timings["prompt_eval_duration"] // 1_000_000,
        "eval_ms": None if timings.get("eval_duration") is None else timings["eval_duration"] // 1_000_000,
        "decode_tokens_per_s": _rate(timings.get("eval_count"), timings.get("eval_duration")),
        "prompt_tokens_per_s": _rate(timings.get("prompt_eval_count"), timings.get("prompt_eval_duration")),
        "done_reason": timings.get("done_reason"),
        "thinking_chars": timings.get("thinking_chars", 0),
    }
    return row, result.parsed if result.ok else None


def model_info(client: OllamaClient, model: str) -> dict:
    """Name, digest, size and quantization from /api/tags; resident VRAM share from /api/ps if loaded."""
    info: dict[str, Any] = {"model": model}
    try:
        for entry in client.http.get("/api/tags", timeout=10).json().get("models") or []:
            if entry.get("name") == model or entry.get("model") == model:
                details = entry.get("details") or {}
                info.update(digest=entry.get("digest"), size_bytes=entry.get("size"),
                            parameter_size=details.get("parameter_size"),
                            quantization=details.get("quantization_level"), family=details.get("family"))
        for entry in client.http.get("/api/ps", timeout=10).json().get("models") or []:
            if entry.get("name") == model or entry.get("model") == model:
                info.update(loaded_size_bytes=entry.get("size"), loaded_vram_bytes=entry.get("size_vram"),
                            context_length=entry.get("context_length"))
    except (httpx.HTTPError, ValueError) as exc:
        info["error"] = str(exc)
    return info


def _key(row: dict) -> tuple:
    return row["task_id"], row["model"], row["num_ctx"], row["think"], row["seed"], row["max_out"]


def run_bakeoff(settings: Settings, tasks: list[dict], models: list[str], num_ctx_values: list[int],
                think_values: list[bool], seeds: list[int], out_path: str | Path, run_id: str,
                max_out: int = MAX_OUT, retry: bool = True, inner_transport: httpx.BaseTransport | None = None,
                progress: Callable[[str], None] | None = None) -> dict:
    """Append one result row per (task, model, num_ctx, think, seed); rows already in ``out_path`` are skipped."""
    out = Path(out_path)
    done: set[tuple] = set()
    if out.exists():
        for line in out.read_text(encoding="utf-8").splitlines():
            row = json.loads(line) if line.strip() else {}
            if row.get("kind") == "result" and row.get("attempt") == 1:
                done.add(_key(row))
    counts = {"calls": 0, "skipped_done": 0, "no_brief": 0}
    with out.open("a", encoding="utf-8", newline="\n") as handle:
        def emit(row: dict) -> None:
            handle.write(json.dumps(row, sort_keys=True, default=str) + "\n")
            handle.flush()

        for model in models:
            for num_ctx in num_ctx_values:
                for think in think_values:
                    for seed in seeds:
                        transport = CaptureTransport(seed, inner_transport)
                        config = settings.model_copy(update={
                            "ollama_model_triage": model, "ollama_num_ctx": num_ctx, "ollama_think": think,
                        })
                        client = OllamaClient(config, transport=transport)
                        config_rows = 0
                        for task in tasks:
                            base = {"kind": "result", "schema": RESULT_SCHEMA, "run_id": run_id,
                                    "task_id": task["task_id"], "model": model, "num_ctx": num_ctx,
                                    "think": think, "seed": seed, "max_out": max_out}
                            if _key(base) in done:
                                counts["skipped_done"] += 1
                                continue
                            serialized = (task.get("briefs") or {}).get(str(num_ctx))
                            if not serialized or "error" in serialized:
                                emit({**base, "attempt": 1, "status": "no_brief",
                                      "error": (serialized or {}).get("error", "no brief for this num_ctx")})
                                counts["no_brief"] += 1
                                continue
                            brief = brief_from_task(serialized)
                            call, parsed = _call(client, transport, model, brief, max_out)
                            counts["calls"] += 1
                            verdict = judge(task, brief, parsed) if parsed is not None else {
                                "schema_valid": False, "validation_ok": False, "errors": [call["error"]],
                                "decision": None}
                            emit({**base, **call, **verdict, "attempt": 1,
                                  "brief_token_estimate": brief.token_estimate})
                            config_rows += 1
                            if config_rows == 1:
                                emit({"kind": "model_info", "run_id": run_id, "num_ctx": num_ctx,
                                      "think": think, **model_info(client, model)})
                            if progress:
                                progress(f"{model} ctx={num_ctx} think={think} seed={seed} "
                                         f"{task['task_id']} -> {call['status']} ok={verdict['validation_ok']}")
                            if call["status"] == "unavailable":
                                return {**counts, "stopped": "model unavailable"}
                            if (retry and call["status"] in {"ok", "invalid_json"}
                                    and not verdict["validation_ok"]):
                                second = retry_brief(brief, verdict["errors"])
                                if second is None or second.token_estimate + max_out > num_ctx:
                                    emit({**base, "attempt": 2, "status": "no_retry_brief",
                                          "retry_approximate": True})
                                    continue
                                call2, parsed2 = _call(client, transport, model, second, max_out)
                                counts["calls"] += 1
                                verdict2 = judge(task, second, parsed2) if parsed2 is not None else {
                                    "schema_valid": False, "validation_ok": False, "errors": [call2["error"]],
                                    "decision": None}
                                emit({**base, **call2, **verdict2, "attempt": 2, "retry_approximate": True,
                                      "brief_token_estimate": second.token_estimate})
                        transport.close()
    return counts


def summarize(rows: Iterable[dict]) -> list[dict]:
    """Per-configuration validity, latency and decode rate. Decision accuracy is scored in ``eval/``."""
    groups: dict[tuple, dict[str, Any]] = {}
    for row in rows:
        if row.get("kind") != "result" or row.get("status") in {"no_brief", "no_retry_brief"}:
            continue
        key = (row["model"], row["num_ctx"], row["think"])
        group = groups.setdefault(key, {"first": [], "second": {}, "latency": [], "decode": []})
        if row["attempt"] == 1:
            group["first"].append(row)
            if row.get("duration_ms") is not None:
                group["latency"].append(row["duration_ms"])
            if row.get("decode_tokens_per_s"):
                group["decode"].append(row["decode_tokens_per_s"])
        else:
            group["second"][(row["task_id"], row["seed"])] = row

    def median(values: list[float]) -> float | None:
        if not values:
            return None
        ordered = sorted(values)
        mid = len(ordered) // 2
        return ordered[mid] if len(ordered) % 2 else (ordered[mid - 1] + ordered[mid]) / 2

    summary = []
    for (model, num_ctx, think), group in sorted(groups.items(), key=lambda item: tuple(map(str, item[0]))):
        first = group["first"]
        n = len(first)
        ok_first = sum(1 for row in first if row.get("validation_ok"))
        ok_with_retry = ok_first + sum(
            1 for row in first if not row.get("validation_ok")
            and (group["second"].get((row["task_id"], row["seed"])) or {}).get("validation_ok")
        )
        summary.append({
            "model": model, "num_ctx": num_ctx, "think": think, "n": n,
            "schema_valid": sum(1 for row in first if row.get("schema_valid")),
            "valid_first": ok_first, "valid_with_retry": ok_with_retry,
            "truncated": sum(1 for row in first if row.get("status") == "truncated"),
            "output_limit": sum(1 for row in first if row.get("done_reason") == "length"),
            "errors": sum(1 for row in first if row.get("status") in {"error", "too_large"}),
            "median_latency_ms": median(group["latency"]),
            "median_decode_tokens_per_s": median(group["decode"]),
        })
    return summary
