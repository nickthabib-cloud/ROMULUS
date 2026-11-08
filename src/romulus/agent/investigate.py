"""Persisted, bounded hypothesis investigation over the A2 read and pivot tools."""
from __future__ import annotations

import json
import math
import threading
import uuid
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from time import monotonic

from romulus.agent.admission import AgentAdmission
from romulus.agent.assessment import run_assessment, template_assessment
from romulus.agent.dossier import build_dossier
from romulus.agent.provider import (
    AgentBudget,
    BudgetExhausted,
    BudgetLimits,
    ChatRequest,
    ProviderUnavailable,
    charge_parts,
    parts_of,
    record_call,
    record_failure,
)
from romulus.agent.provider.base import estimate_tokens
from romulus.agent.toolbox import Toolbox
from romulus.config import Settings
from romulus.report.incidents import build_incident_graph
from romulus.store.db import digest, utcnow
from romulus.store.repo import Repo


@dataclass
class AgentPhaseResult:
    state: str
    reason: str | None
    prompt_digests: dict
    provider: dict
    sessions: list[dict] = field(default_factory=list)
    limits_hit: list[str] = field(default_factory=list)
    unworked: list[str] = field(default_factory=list)
    usage: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {"status": self.state, "reason": self.reason, "prompt_digests": self.prompt_digests,
                "provider": self.provider, "sessions": self.sessions, "limits_hit": self.limits_hit,
                "unworked": self.unworked, "usage": self.usage}


@dataclass
class _Reservation:
    prompt_est: int
    max_output: int
    tokens: int
    cost: float
    purpose: str
    retry_budget: str | None = None


class _BudgetGate:
    """Reserve worst-case concurrent calls so parallel sessions cannot race past hunt caps."""

    def __init__(self, budget: AgentBudget, settings: Settings):
        self.budget = budget
        self.settings = settings
        self.lock = threading.Lock()
        self.calls = 0
        self.tokens = 0
        self.cost = 0.0

    def _reserve_for_assess(self, prompt: int, output: int) -> tuple[int, int, float, float]:
        limits = self.budget.limits
        fraction = self.settings.agent_assess_reserve_fraction
        calls = max(1, math.ceil(limits.max_calls * fraction))
        tokens = max(math.ceil(limits.max_tokens * fraction),
                     limits.worst_tokens(min(max(prompt, 4096), 16_000), output))
        cost = max(limits.max_cost_usd * fraction,
                   limits.worst_cost(min(max(prompt, 4096), 16_000), output)) if limits.max_cost_usd else 0.0
        wall = max(limits.max_wall_seconds * fraction, min(limits.max_wall_seconds, 60.0))
        return calls, tokens, cost, wall

    def reserve(self, prompt: int, output: int, purpose: str) -> _Reservation:
        limits = self.budget.limits
        tokens = limits.worst_tokens(prompt, output)
        cost = limits.worst_cost(prompt, output)
        with self.lock:
            self.budget.check(prompt, output)
            after_calls = self.budget.calls + self.calls + 1
            after_tokens = self.budget.tokens + self.tokens + tokens
            after_cost = self.budget.cost_usd + self.cost + cost
            if purpose != "assess":
                reserve_calls, reserve_tokens, reserve_cost, reserve_wall = self._reserve_for_assess(prompt, output)
                if after_calls + reserve_calls > limits.max_calls:
                    raise BudgetExhausted("calls", "assessment reserve must remain available")
                if after_tokens + reserve_tokens > limits.max_tokens:
                    raise BudgetExhausted("tokens", "assessment reserve must remain available")
                if limits.max_cost_usd and after_cost + reserve_cost > limits.max_cost_usd:
                    raise BudgetExhausted("cost", "assessment reserve must remain available")
                if self.budget.wall_seconds() + reserve_wall >= limits.max_wall_seconds:
                    raise BudgetExhausted("wall-clock", "assessment reserve must remain available")
            self.calls += 1
            self.tokens += tokens
            self.cost += cost
        return _Reservation(prompt, output, tokens, cost, purpose)

    def settle(self, reservation: _Reservation, result=None, error: BaseException | None = None) -> None:
        with self.lock:
            self.calls -= 1
            self.tokens -= reservation.tokens
            self.cost -= reservation.cost
            if error is not None:
                self.budget.charge_failure(error)
            elif result is not None:
                self.budget.charge(result)

    def attempt_guard(self, reservation: _Reservation, billed: dict) -> bool:
        parts = parts_of(billed.get("billed"))
        if not billed.get("retry_available"):
            return True
        limits = self.budget.limits
        used = charge_parts(parts)
        extra_tokens = limits.worst_tokens(reservation.prompt_est, reservation.max_output)
        extra_cost = limits.worst_cost(reservation.prompt_est, reservation.max_output)
        with self.lock:
            tokens = self.budget.tokens + max(0, self.tokens - reservation.tokens) + used.prompt + used.completion + extra_tokens
            cost = self.budget.cost_usd + max(0.0, self.cost - reservation.cost) + limits.charge_cost(used) + extra_cost
            if tokens > limits.max_tokens:
                reservation.retry_budget = "tokens"
            elif limits.max_cost_usd and cost > limits.max_cost_usd:
                reservation.retry_budget = "cost"
            elif self.budget.wall_seconds() >= limits.max_wall_seconds:
                reservation.retry_budget = "wall-clock"
            return reservation.retry_budget is None


def _prompt(name: str) -> str:
    from importlib.resources import files
    return files("romulus.agent").joinpath("prompts", name).read_text(encoding="utf-8")


def _prompt_set() -> dict[str, str]:
    names = ("system.md", "orient.md", "investigate.md", "assess.md")
    return {name: _prompt(name) for name in names}


def _store_template(repo: Repo, hunt_id: str, reason: str, *, owner_token=None) -> dict:
    existing = repo.agent_assessments(hunt_id)
    if existing:
        latest = existing[-1]
        if latest.get("source") == "template":
            return latest
    template = template_assessment(repo, hunt_id, reason)
    revision = len(existing) + 1
    row = {"id": "aa-" + uuid.uuid4().hex[:20], "hunt_id": hunt_id, "revision": revision,
           "source": "template", "model": {}, "body": template["body"], "checker": {}, "created_at": utcnow()}
    repo.save_agent_assessment(row, owner_token=owner_token)
    return row


def skip_agent_phase(settings: Settings, repo: Repo, hunt_id: str, reason: str, *, provider: dict | None = None,
                     prompt_digests: dict | None = None, owner_token=None) -> AgentPhaseResult:
    """Record an off or unavailable phase without touching deterministic hunt state."""
    repo.save_agent_run({"hunt_id": hunt_id, "state": "skipped", "reason": reason[:500],
                         "prompt_digests": prompt_digests or {}, "provider": provider or {},
                         "started_at": None, "ended_at": utcnow()}, owner_token=owner_token)
    _store_template(repo, hunt_id, reason, owner_token=owner_token)
    return AgentPhaseResult("skipped", reason, prompt_digests or {}, provider or {},
                            usage=repo.agent_usage(hunt_id))


def fail_agent_phase(repo: Repo, hunt_id: str, reason: str, *, owner_token=None) -> dict:
    existing = repo.agent_run(hunt_id) or {}
    repo.save_agent_run({"hunt_id": hunt_id, "state": "failed", "reason": reason[:500],
                         "prompt_digests": existing.get("prompt_digests") or {},
                         "provider": existing.get("provider") or {},
                         "started_at": existing.get("started_at") or utcnow(), "ended_at": utcnow()},
                        owner_token=owner_token)
    _store_template(repo, hunt_id, reason, owner_token=owner_token)
    return AgentPhaseResult("failed", reason, existing.get("prompt_digests") or {},
                            existing.get("provider") or {}, usage=repo.agent_usage(hunt_id)).as_dict()


def _id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:20]}"


def _candidate_views(repo: Repo, hunt_id: str) -> list[dict]:
    return [{"id": row["id"], "lane": row["lane"], "rule_id": row["rule_id"],
             "observed_at": str(row["ts"]) if row["ts"] is not None else None,
             "entities": row.get("entities") or [], "event_ids": row.get("event_ids") or [],
             "citations": [], "source_link_id": row.get("source_link_id")}
            for row in repo.candidates(hunt_id, ["urgent", "high", "lead"])]


def _controller_open_hypotheses(settings, repo, hunt_id: str, session_id: str, admission: AgentAdmission) -> None:
    if repo.agent_hypotheses(hunt_id):
        return
    candidates = repo.candidates(hunt_id, ["urgent", "high", "lead"])
    if not candidates:
        return
    graph = build_incident_graph(repo, hunt_id, _candidate_views(repo, hunt_id))
    by_id = {row["id"]: row for row in candidates}
    lane_priority = {"urgent": 3, "high": 2, "lead": 1}
    ordered = sorted(graph["incidents"], key=lambda incident: (
        -max((lane_priority.get(by_id[item]["lane"], 0) for item in incident["finding_ids"] if item in by_id),
             default=0), incident["id"]))
    existing_support = {row["target_id"] for hypothesis in repo.agent_hypotheses(hunt_id)
                        for row in repo.agent_hypothesis_cites(hypothesis_id=hypothesis["id"])
                        if row["role"] == "support" and row["target_kind"] == "finding"}
    for incident in ordered:
        if len(repo.agent_hypotheses(hunt_id)) >= min(settings.agent_max_initial_hypotheses,
                                                      settings.agent_max_hypotheses):
            break
        top = min((by_id[item] for item in incident["finding_ids"] if item in by_id),
                  key=lambda row: (-lane_priority.get(row["lane"], 0), -float(row["priority"]), row["id"]))
        if top["id"] in existing_support:
            continue
        incident_alias = admission.aliases.alias_for("I", incident["id"])
        statement = f"Investigate incident {incident_alias}: {top['claim']}"
        if len(statement) < 10:
            statement = f"Investigate incident {incident_alias} and review its cited finding."
        try:
            admission.create_controller_hypothesis(statement, finding_id=top["id"], alias=incident_alias)
        except ValueError:
            break
        existing_support.add(top["id"])


def _hypothesis_context(repo: Repo, hunt_id: str, hypothesis: dict, summaries: list[dict]) -> dict:
    from romulus.agent.aliases import AliasBook
    aliases = AliasBook(repo, hunt_id)
    cites = repo.agent_hypothesis_cites(hypothesis_id=hypothesis["id"])
    mapped_cites = []
    kind_map = {"finding": "F", "evidence": "E", "link": "L", "agent_link": "A"}
    for cite in cites:
        mapped_cites.append({"role": cite["role"], "alias": aliases.alias_for(kind_map[cite["target_kind"]], cite["target_id"])})
    entities = [aliases.alias_for("N", item) for item in hypothesis.get("entity_ids") or []]
    body = {"alias": aliases.alias_for("H", hypothesis["id"]), "statement": hypothesis["statement"],
            "techniques": hypothesis["techniques"], "entities": entities, "status": hypothesis["status"],
            "confidence": hypothesis["confidence"], "questions": hypothesis["questions"], "cites": mapped_cites,
            "previous_sessions": summaries}
    return body


def _summaries(repo: Repo, hunt_id: str, hypothesis_id: str) -> list[dict]:
    sessions = [row for row in repo.agent_sessions(hunt_id, hypothesis_id=hypothesis_id, purpose="investigate")
                if row["state"] != "running"]
    rows = [{"state": row["state"], "summary": row.get("summary", ""), "started_at": str(row["started_at"])}
            for row in sessions]
    joined = json.dumps(rows, ensure_ascii=False, sort_keys=True)
    omitted = 0
    while len(joined) > 6000 and rows:
        rows.pop(0)
        omitted += 1
        joined = json.dumps(rows, ensure_ascii=False, sort_keys=True)
    return ([{"omitted_earlier_summaries": omitted, "message": f"{omitted} earlier summaries omitted."}] if omitted else []) + rows


def _touched_entities(repo: Repo, hunt_id: str) -> set[str]:
    alias_to_id = {row["alias"]: row["target_id"] for row in repo.agent_aliases(hunt_id) if row["kind"] == "N"}
    touched = set()
    for call in repo.agent_tool_calls(hunt_id):
        arguments = call.get("arguments")
        serialized = json.dumps(arguments, sort_keys=True, default=str)
        for alias, target_id in alias_to_id.items():
            if alias in serialized:
                touched.add(target_id)
    return touched


def _priority(repo: Repo, hunt_id: str, hypothesis: dict, touched: set[str]) -> tuple:
    supports = [row for row in repo.agent_hypothesis_cites(hypothesis_id=hypothesis["id"])
                if row["role"] == "support" and row["target_kind"] == "finding"]
    finding_ids = [row["target_id"] for row in supports]
    candidates = {row["id"]: row for row in repo.candidates(hunt_id) if row["id"] in finding_ids}
    lane = max(({"urgent": 3, "high": 2, "lead": 1}.get(row["lane"], 0) for row in candidates.values()), default=0)
    untouched = sum(item not in touched for item in hypothesis.get("entity_ids") or [])
    return (-lane, -len(hypothesis.get("questions") or []), -untouched,
            str(hypothesis["created_at"]), hypothesis["id"])


def _session_tools(toolbox: Toolbox) -> list:
    return toolbox.provider_tools()


def _deterministic_tool_summary(calls: list[tuple[str, str]], changes: list[dict]) -> str:
    recent = calls[-10:]
    steps = "; ".join(f"{name}: {status}" for name, status in recent) or "no tool calls"
    changed = f"; {len(changes)} hypothesis change(s) recorded" if changes else ""
    return f"Session stopped after {steps}{changed}."[:2000]


def _run_session(settings: Settings, repo: Repo, hunt_id: str, provider, budget_gate: _BudgetGate,
                 toolbox_factory: Callable[[str], Toolbox], prompts: dict[str, str],
                 *, purpose: str, hypothesis: dict | None = None, owner_token=None) -> dict:
    session_id = _id("as")
    now = utcnow()
    hypothesis_id = hypothesis["id"] if hypothesis else None
    repo.save_agent_session({"id": session_id, "hunt_id": hunt_id, "hypothesis_id": hypothesis_id,
                             "purpose": purpose, "state": "running", "tool_calls": 0, "summary": "",
                             "started_at": now, "ended_at": None}, owner_token=owner_token)
    if hypothesis_id:
        repo.increment_agent_hypothesis_sessions(hypothesis_id, hunt_id, owner_token=owner_token)
    toolbox = toolbox_factory(session_id)
    admission = AgentAdmission(settings, repo, hunt_id, session_id, hypothesis_id=hypothesis_id,
                               owner_token=owner_token, purpose=purpose)
    admission.register(toolbox)
    tools = _session_tools(toolbox)
    system_text = prompts["system.md"]
    if purpose == "orient":
        orientation = prompts["orient.md"]
        room = max(1, provider.context_tokens() - estimate_tokens(system_text + orientation) -
                   provider.output_limit(ChatRequest(messages=[])) - 512) if provider.context_tokens() else 24_000
        dossier = build_dossier(repo, hunt_id, token_budget=room)
        user = {"message": "Dossier index page 1 of " + str(len(dossier.pages)) +
                "; call list_findings for the rest.", "page": dossier.page(1)}
        messages = [{"role": "system", "content": system_text + "\n\n" + orientation},
                    {"role": "user", "content": json.dumps(user, sort_keys=True, ensure_ascii=False, default=str)}]
    else:
        context = _hypothesis_context(repo, hunt_id, hypothesis, _summaries(repo, hunt_id, hypothesis_id))
        dossier = build_dossier(repo, hunt_id, token_budget=1000)
        messages = [{"role": "system", "content": system_text + "\n\n" + prompts["investigate.md"]},
                    {"role": "user", "content": json.dumps({"dossier_header": {
                        "header": dossier.payload.get("header"), "scope": dossier.payload.get("scope")},
                        "hypothesis": context}, sort_keys=True, ensure_ascii=False, default=str)}]
    admission.issue_aliases("\n".join(str(message.get("content", "")) for message in messages))
    tool_history: list[tuple[str, str]] = []
    hypothesis_changes: list[dict] = []
    tool_count = 0
    no_tool_misses = 0
    wrap_up_sent = False
    context_wrap_sent = False
    call_seq = 0
    provider_unavailable = False

    def finish(state: str, final_summary: str, reason: str | None = None) -> dict:
        repo.update_agent_session(session_id, hunt_id, {"state": state, "summary": final_summary[:2000],
                                                         "tool_calls": tool_count, "ended_at": utcnow()},
                                  owner_token=owner_token)
        return {"id": session_id, "hypothesis_id": hypothesis_id, "purpose": purpose, "state": state,
                "summary": final_summary[:2000], "reason": reason,
                "provider_unavailable": provider_unavailable, "limits_hit": sorted(admission.limits_hit)}

    try:
        while True:
            request = ChatRequest(messages=messages, tools=tools, tool_choice="auto")
            prompt_est = estimate_tokens(request.prompt_text())
            ctx = provider.context_tokens()
            max_out = provider.output_limit(request)
            over_context = bool(ctx and prompt_est > ctx * 0.85)
            if over_context and context_wrap_sent:
                return finish("context_full", _deterministic_tool_summary(tool_history, hypothesis_changes),
                              "estimated prompt reached 85% of context")
            if over_context:
                messages.append({"role": "user", "content": "Context is nearly full. Call finish_session now "
                                "with a concise summary; no further investigation is needed in this session."})
                context_wrap_sent = True
                request = ChatRequest(messages=messages, tools=tools, tool_choice="auto")
                prompt_est = estimate_tokens(request.prompt_text())
                max_out = provider.output_limit(request)
            try:
                reservation = budget_gate.reserve(prompt_est, max_out, purpose)
            except BudgetExhausted as exc:
                if purpose == "assess":
                    return finish("budget", _deterministic_tool_summary(tool_history, hypothesis_changes),
                                  f"budget:{exc.budget}")
                return finish("budget", _deterministic_tool_summary(tool_history, hypothesis_changes),
                              f"budget:{exc.budget}")
            request.attempt_guard = lambda info, reservation=reservation: budget_gate.attempt_guard(reservation, info)
            try:
                result = provider.chat(request)
            except ProviderUnavailable as exc:
                budget_gate.settle(reservation, error=exc)
                record_failure(repo, provider, hunt_id=hunt_id, purpose=purpose, request=request, error=exc,
                               limits=budget_gate.budget.limits, session_id=session_id, owner_token=owner_token)
                provider_unavailable = True
                return finish("failed", _deterministic_tool_summary(tool_history, hypothesis_changes),
                              f"budget:{reservation.retry_budget}" if reservation.retry_budget else
                              "provider_unavailable")
            except Exception as exc:  # noqa: BLE001 - provider failures must end only this agent session.
                budget_gate.settle(reservation)
                return finish("failed", f"Provider call failed: {type(exc).__name__}: {exc}"[:2000],
                              "provider_error")
            budget_gate.settle(reservation, result=result)
            model_call_id = record_call(repo, provider, hunt_id=hunt_id, purpose=purpose, request=request,
                                        result=result, limits=budget_gate.budget.limits, session_id=session_id,
                                        owner_token=owner_token)
            if result.status in {"too_large", "truncated_input"}:
                return finish("context_full", result.error or "Provider reported an oversized or truncated input.",
                              "context_full")
            if result.status == "refused":
                return finish("refused", result.error or "Provider refused this session.", "refused")
            messages.append(result.assistant_message())
            if not result.tool_calls:
                if context_wrap_sent:
                    return finish("context_full", _deterministic_tool_summary(tool_history, hypothesis_changes),
                                  "context wrap-up did not finish the session")
                if wrap_up_sent:
                    return finish("capped", _deterministic_tool_summary(tool_history, hypothesis_changes),
                                  "tool-call wrap-up did not finish the session")
                no_tool_misses += 1
                if no_tool_misses == 1:
                    messages.append({"role": "user", "content": "Reply with a tool call; call finish_session to end."})
                    continue
                return finish("failed", _deterministic_tool_summary(tool_history, hypothesis_changes),
                              "no_tool_call_twice")
            no_tool_misses = 0
            if wrap_up_sent or context_wrap_sent:
                finish_call = next((call for call in result.tool_calls if call.name == "finish_session"), None)
                if finish_call is None:
                    for call in result.tool_calls:
                        call_seq += 1
                        raw = call.raw_arguments[:8192]
                        arguments = call.arguments if call.arguments is not None else raw
                        refused = {"status": "refused", "errors": ["tool-call limit reached; only finish_session is allowed"]}
                        repo.save_agent_tool_call({"id": _id("atc"), "hunt_id": hunt_id, "session_id": session_id,
                                                   "seq": call_seq, "name": call.name, "arguments": arguments,
                                                   "arguments_truncated": len(call.raw_arguments.encode()) > 8192,
                                                   "status": "refused", "result_digest": digest(refused),
                                                   "model_call_id": model_call_id, "created_at": utcnow()},
                                                  owner_token=owner_token)
                    if context_wrap_sent:
                        return finish("context_full", _deterministic_tool_summary(tool_history, hypothesis_changes),
                                      "context wrap-up did not finish the session")
                    return finish("capped", _deterministic_tool_summary(tool_history, hypothesis_changes),
                                  "tool-call limit reached")
                allowed_calls = [finish_call]
            else:
                allowed_calls = result.tool_calls
            if not wrap_up_sent and tool_count >= settings.agent_max_tool_calls_per_session:
                messages.append({"role": "user", "content": "Tool-call limit reached. Call finish_session now with a summary."})
                wrap_up_sent = True
                # This reply already used the final ordinary tool call. The single wrap-up call is next.
                continue
            for call in allowed_calls:
                call_seq += 1
                at_limit = tool_count >= settings.agent_max_tool_calls_per_session and not wrap_up_sent
                if at_limit:
                    tool_result = {"status": "refused", "errors": ["tool-call limit reached"]}
                else:
                    tool_count += 1
                    if call.error:
                        tool_result = {"status": "refused", "errors": [call.error]}
                    else:
                        tool_result = toolbox.execute(call.name, call.arguments)
                raw_args = call.raw_arguments.encode("utf-8")
                if call.arguments is not None:
                    stored_args = call.arguments
                    truncated = False
                else:
                    stored_args = raw_args[:8192].decode("utf-8", errors="replace")
                    truncated = len(raw_args) > 8192
                status = tool_result.get("status", "failed")
                admission.issue_aliases(tool_result)
                repo.save_agent_tool_call({"id": _id("atc"), "hunt_id": hunt_id, "session_id": session_id,
                                           "seq": call_seq, "name": call.name, "arguments": stored_args,
                                           "arguments_truncated": truncated, "status": status,
                                           "result_digest": digest(tool_result), "model_call_id": model_call_id,
                                           "created_at": utcnow()}, owner_token=owner_token)
                repo.update_agent_session(session_id, hunt_id, {"tool_calls": tool_count}, owner_token=owner_token)
                tool_history.append((call.name, status))
                if call.name == "update_hypothesis" and status == "complete":
                    hypothesis_changes.append(tool_result.get("data") or {})
                messages.append({"role": "tool", "tool_call_id": call.id,
                                 "content": json.dumps(tool_result, sort_keys=True, ensure_ascii=False, default=str)})
                if call.name == "finish_session" and status == "complete":
                    summary = str((tool_result.get("data") or {}).get("summary") or "Session finished.")
                    end_state = "context_full" if context_wrap_sent else "finished"
                    return finish(end_state, summary, "context_full" if context_wrap_sent else None)
            if not wrap_up_sent and tool_count >= settings.agent_max_tool_calls_per_session:
                messages.append({"role": "user", "content": "Tool-call limit reached. Call finish_session now with a summary."})
                wrap_up_sent = True
                continue
            if wrap_up_sent:
                return finish("capped", _deterministic_tool_summary(tool_history, hypothesis_changes),
                              "wrap_up_not_finished")
    except Exception as exc:  # noqa: BLE001 - controller faults must leave deterministic hunt results intact.
        return finish("failed", f"Controller error: {type(exc).__name__}: {exc}"[:2000], "controller_error")


def _unworked(repo: Repo, hunt_id: str) -> list[str]:
    return [row["id"] for row in repo.agent_hypotheses(hunt_id)
            if row["status"] == "open" and int(row.get("sessions_run") or 0) == 0]


def _has_open_questions(hypothesis: dict) -> bool:
    return bool(hypothesis.get("questions"))


def _next_hypotheses(settings: Settings, repo: Repo, hunt_id: str) -> list[dict]:
    rows = [row for row in repo.agent_hypotheses(hunt_id) if row["status"] == "open" and
            int(row.get("sessions_run") or 0) < settings.agent_max_sessions_per_hypothesis]
    if not rows:
        return []
    minimum = min(int(row.get("sessions_run") or 0) for row in rows)
    round_rows = [row for row in rows if int(row.get("sessions_run") or 0) == minimum]
    touched = _touched_entities(repo, hunt_id)
    return sorted(round_rows, key=lambda row: _priority(repo, hunt_id, row, touched))


def _investigation_done(repo: Repo, hunt_id: str) -> bool:
    open_rows = [row for row in repo.agent_hypotheses(hunt_id) if row["status"] == "open"]
    return not open_rows or all(int(row.get("sessions_run") or 0) >= 1 and not _has_open_questions(row)
                                for row in open_rows)


def _recover_running_sessions(repo: Repo, hunt_id: str, *, owner_token=None) -> None:
    for session in repo.agent_sessions(hunt_id):
        if session["state"] == "running":
            repo.interrupt_running_agent_session(session["id"], hunt_id, owner_token=owner_token)


def _budget(settings: Settings, manifest: dict, repo: Repo, hunt_id: str, clock) -> AgentBudget:
    config = ((manifest.get("ai_agent") or {}).get("budgets") or {})
    required = {"max_calls", "max_tokens", "max_wall_seconds"}
    limits = (BudgetLimits.from_dict(config, str((manifest.get("ai_agent") or {}).get("model") or ""))
              if required <= config.keys() else BudgetLimits.from_settings(settings))
    return AgentBudget.from_usage(limits, repo.agent_usage(hunt_id),
                                  wall_seconds_before=repo.agent_elapsed_ms(hunt_id) / 1000.0, clock=clock)


def run_agent_phase(settings: Settings, repo: Repo, hunt_id: str, *, provider,
                    toolbox_factory: Callable[[str], Toolbox], owner_token: str | None = None,
                    clock: Callable[[], float] = monotonic) -> AgentPhaseResult:
    """Run the persisted orient, investigate and assess phases without changing detection results."""
    hunt = repo.get_hunt(hunt_id)
    if hunt is None:
        raise KeyError(hunt_id)
    prompts = _prompt_set()
    prompt_digests = {name: digest(text) for name, text in prompts.items()}
    provider_data = provider.describe()
    existing = repo.agent_run(hunt_id)
    if existing and existing.get("state") == "completed" and repo.agent_assessments(hunt_id):
        return AgentPhaseResult("completed", existing.get("reason"), existing.get("prompt_digests") or {},
                                existing.get("provider") or provider_data, usage=repo.agent_usage(hunt_id))
    _recover_running_sessions(repo, hunt_id, owner_token=owner_token)
    budget = _budget(settings, hunt["manifest"], repo, hunt_id, clock)
    gate = _BudgetGate(budget, settings)
    start = existing.get("started_at") if existing and existing.get("started_at") else utcnow()
    repo.save_agent_run({"hunt_id": hunt_id, "state": "running", "reason": None,
                         "prompt_digests": prompt_digests,
                         "provider": {**provider_data, "models_reported": repo.agent_usage(hunt_id).get("models_reported", [])},
                         "started_at": start, "ended_at": None}, owner_token=owner_token)
    all_sessions = []
    limits_hit: set[str] = set()
    reasons: list[str] = []
    assessment_stale = False
    reportable_count = repo.candidate_count_lanes(hunt_id, ("urgent", "high", "lead"))
    orient_finished = any(row["purpose"] == "orient" and row["state"] == "finished"
                          for row in repo.agent_sessions(hunt_id))
    if reportable_count and not orient_finished:
        assessment_stale = True
        orient = _run_session(settings, repo, hunt_id, provider, gate, toolbox_factory, prompts,
                              purpose="orient", owner_token=owner_token)
        all_sessions.append(orient)
        limits_hit.update(orient.get("limits_hit") or [])
        if orient.get("reason"):
            reasons.append(orient["reason"])
        orient_rows = repo.agent_sessions(hunt_id, purpose="orient")
        latest_orient = orient_rows[-1] if orient_rows else None
        if latest_orient:
            admission = AgentAdmission(settings, repo, hunt_id, latest_orient["id"], owner_token=owner_token,
                                       purpose="orient")
            _controller_open_hypotheses(settings, repo, hunt_id, latest_orient["id"], admission)
            limits_hit.update(admission.limits_hit)

    consecutive_outages = 1 if reportable_count and not orient_finished and orient.get("provider_unavailable") else 0
    stop_scheduling = False
    while not stop_scheduling:
        batch = _next_hypotheses(settings, repo, hunt_id)
        if not batch:
            break
        room = batch[:settings.agent_concurrency]
        assessment_stale = True
        # Breadth-first round selection in _next_hypotheses means every selected hypothesis is distinct.
        completed = []
        with ThreadPoolExecutor(max_workers=len(room), thread_name_prefix="romulus-agent") as pool:
            futures = {pool.submit(_run_session, settings, repo, hunt_id, provider, gate, toolbox_factory, prompts,
                                   purpose="investigate", hypothesis=hypothesis, owner_token=owner_token): hypothesis
                       for hypothesis in room}
            for future in as_completed(futures):
                try:
                    outcome = future.result()
                except Exception as exc:  # noqa: BLE001 - isolate one session's controller fault.
                    outcome = {"state": "failed", "reason": f"controller_error: {type(exc).__name__}: {exc}"}
                completed.append(outcome)
                all_sessions.append(outcome)
                limits_hit.update(outcome.get("limits_hit") or [])
                if outcome.get("provider_unavailable"):
                    consecutive_outages += 1
                    if consecutive_outages >= 2:
                        stop_scheduling = True
                else:
                    consecutive_outages = 0
                if outcome.get("reason"):
                    reasons.append(outcome["reason"])
        if stop_scheduling:
            reasons.append("provider_unavailable")
        if any(row["reason"] and row["reason"].startswith("budget:") for row in completed):
            reasons.extend(row["reason"] for row in completed if row.get("reason", "").startswith("budget:"))
            break
        if _investigation_done(repo, hunt_id):
            break

    existing_assessments = repo.agent_assessments(hunt_id)
    if existing_assessments and existing_assessments[-1].get("source") == "agent" and not assessment_stale:
        assessment = {"revision": existing_assessments[-1]["revision"], "body": existing_assessments[-1]["body"]}
    else:
        try:
            assessment = run_assessment(settings, repo, hunt_id, provider, budget, owner_token=owner_token, clock=clock)
        except Exception as exc:  # noqa: BLE001 - assessment errors use the deterministic template.
            assessment = None
            reasons.append(f"assessment_error:{type(exc).__name__}")
    if assessment is None:
        assessment_sessions = repo.agent_sessions(hunt_id, purpose="assess")
        assessment_reason = ((assessment_sessions[-1].get("summary") or "") if assessment_sessions else "")
        if assessment_reason.startswith("budget:") or assessment_reason == "provider_unavailable":
            reasons.append(assessment_reason)
        elif assessment_reason.startswith("context_full"):
            reasons.append("context_full")
        reason = next((item for item in reasons if item.startswith("budget:")), None)
        if reason is None:
            reason = ("provider_unavailable" if "provider_unavailable" in reasons else
                      "context_full" if "context_full" in reasons else "assessment_not_produced")
        _store_template(repo, hunt_id, reason, owner_token=owner_token)
        reasons.append(reason)
    limits_hit.update(item for session in all_sessions for item in session.get("limits_hit", []))
    state = "partial" if limits_hit or reasons or assessment is None else "completed"
    if consecutive_outages >= 2:
        state = "partial"
    reason = "; ".join(dict.fromkeys([*sorted(limits_hit), *reasons])) or None
    usage = repo.agent_usage(hunt_id)
    provider_data = {**provider_data, "models_reported": usage.get("models_reported", [])}
    repo.save_agent_run({"hunt_id": hunt_id, "state": state, "reason": reason,
                         "prompt_digests": prompt_digests, "provider": provider_data,
                         "started_at": start, "ended_at": utcnow()}, owner_token=owner_token)
    return AgentPhaseResult(state, reason, prompt_digests, provider_data, all_sessions,
                            sorted(limits_hit), _unworked(repo, hunt_id), usage)
