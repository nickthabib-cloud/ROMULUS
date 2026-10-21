"""Model-provider port for the AI investigating agent: readiness, the adapter factory and call recording.

`agent_readiness` decides, without contacting the model, whether the agent can run: `not_configured`
(nothing to call; the hunt is deterministic only), `blocked` (the configuration is refused, for example a
remote endpoint without the egress switch), or `ready`. `build_provider` returns an adapter only when ready.
"""
from __future__ import annotations

import uuid
from collections.abc import Callable
from dataclasses import dataclass

import httpx

from romulus.agent.provider.base import (
    AgentNotReady,
    ChatProvider,
    ChatRequest,
    ChatResult,
    ProviderUnavailable,
    Tool,
    ToolCall,
    Usage,
)
from romulus.agent.provider.budget import AgentBudget, BudgetExhausted, BudgetLimits, charged_tokens
from romulus.agent.provider.egress import (
    EGRESS_SWITCH_VALUE,
    EgressDecision,
    EndpointError,
    Resolver,
    classify,
    system_resolver,
)
from romulus.config import Settings
from romulus.store.db import digest

__all__ = [
    "EGRESS_SWITCH_VALUE", "AgentBudget", "AgentNotReady", "AgentReadiness", "BudgetExhausted", "BudgetLimits",
    "ChatProvider", "ChatRequest", "ChatResult", "ProviderUnavailable", "Tool", "ToolCall", "Usage",
    "agent_readiness", "build_provider", "egress_banners", "record_call",
]


@dataclass(frozen=True)
class AgentReadiness:
    state: str                         # not_configured | blocked | ready
    reason: str
    provider: str
    model: str
    decision: EgressDecision | None = None

    @property
    def ready(self) -> bool:
        return self.state == "ready"

    def message(self) -> str:
        if self.state == "not_configured":
            return f"agent not configured: {self.reason}"
        if self.state == "blocked":
            return f"agent blocked: {self.reason}"
        egress = self.decision.egress if self.decision else "unknown"
        return f"agent ready: {self.provider} {self.model} at {self.decision.host if self.decision else '?'} ({egress})"

    def provenance(self, s: Settings) -> dict:
        """What the hunt manifest records: never the key, never a URL path or query."""
        d = self.decision
        return {"state": self.state, "reason": self.reason, "provider": self.provider, "model": self.model,
                "endpoint_host": d.host if d else None, "endpoint_scheme": d.scheme if d else None,
                "egress": d.egress if d else None, "egress_basis": d.basis if d else None,
                "egress_switch": s.model_egress or None,
                "budgets": {**BudgetLimits.from_settings(s).as_dict(),
                            "max_tool_calls_per_session": s.agent_max_tool_calls_per_session,
                            "concurrency": s.agent_concurrency}}


def agent_readiness(s: Settings, resolver: Resolver = system_resolver) -> AgentReadiness:
    provider, model = s.agent_provider, s.agent_model.strip()
    if not s.agent_base_url.strip():
        return AgentReadiness("not_configured", "AGENT_BASE_URL is empty", provider, model)
    if not model:
        return AgentReadiness("not_configured", "AGENT_MODEL is empty", provider, model)
    try:
        decision = classify(s.agent_base_url, s.model_local_hosts, s.model_egress, resolver)
    except EndpointError as exc:
        return AgentReadiness("blocked", str(exc), provider, model)
    if not decision.allowed:
        return AgentReadiness("blocked", decision.refusal, provider, model, decision)
    if decision.egress == "remote" and provider == "openai_compatible" and not s.agent_api_key.get_secret_value():
        return AgentReadiness("not_configured", "AGENT_API_KEY is empty (a remote endpoint needs a key)",
                              provider, model, decision)
    if s.agent_max_cost_usd and not (s.agent_price_input_per_mtok or s.agent_price_output_per_mtok):
        return AgentReadiness("blocked", "AGENT_MAX_COST_USD is set but AGENT_PRICE_INPUT_PER_MTOK and "
                                         "AGENT_PRICE_OUTPUT_PER_MTOK are not, so the cost cannot be estimated",
                              provider, model, decision)
    return AgentReadiness("ready", "", provider, model, decision)


def build_provider(s: Settings, *, transport: httpx.BaseTransport | None = None,
                   resolver: Resolver = system_resolver, sleep: Callable[[float], None] | None = None,
                   readiness: AgentReadiness | None = None) -> ChatProvider:
    readiness = readiness or agent_readiness(s, resolver)
    if not readiness.ready:
        raise AgentNotReady(readiness.message())
    from romulus.agent.provider.ollama import OllamaProvider
    from romulus.agent.provider.openai_compatible import OpenAICompatibleProvider
    cls = OllamaProvider if s.agent_provider == "ollama" else OpenAICompatibleProvider
    kwargs = {"transport": transport}
    if sleep is not None:
        kwargs["sleep"] = sleep
    return cls(s, readiness.decision, **kwargs)


def record_call(repo, provider: ChatProvider, *, hunt_id: str, purpose: str, request: ChatRequest,
                result: ChatResult, limits: BudgetLimits, call_id: str | None = None, case_id: str | None = None,
                validation: dict | None = None, owner_token: str | None = None) -> str:
    """Store one model call: prompt digest, provider and model (requested and reported), parameters, the raw
    response, finish reason, validation, usage and an estimated cost."""
    call_id = call_id or "mc-" + uuid.uuid4().hex[:20]
    prompt, completion, estimated = charged_tokens(result)
    described = provider.describe()
    repo.save_model_call({
        "id": call_id, "hunt_id": hunt_id, "case_id": case_id, "purpose": purpose, "model": provider.model,
        "options": {"tool_choice": request.tool_choice, "tools": [t.name for t in request.tools],
                    "schema": request.schema_name if request.response_schema is not None else None,
                    "max_output_tokens": request.max_output_tokens, "temperature": request.temperature,
                    "attempts": result.attempts, "usage_estimated": estimated},
        "prompt_digest": digest({"messages": request.messages, "tools": [t.__dict__ for t in request.tools],
                                 "schema": request.response_schema}),
        "prompt_tokens_est": result.prompt_tokens_est,
        "prompt_eval_count": result.usage.prompt_tokens, "eval_count": result.usage.completion_tokens,
        "duration_ms": result.duration_ms, "raw_response": result.raw,
        "parsed": {"content": result.parsed, "tool_calls": [c.as_dict() for c in result.tool_calls]},
        "validation": validation if validation is not None else {"ok": result.ok, "errors": [result.error] if result.error else []},
        "status": result.status,
        "provider": described["provider"], "endpoint_host": described["endpoint_host"],
        "egress": described["egress"], "model_reported": result.model_reported or None,
        "finish_reason": result.finish_reason or None,
        "cost_usd_est": limits.cost(prompt, completion) if limits.priced else None,
    }, owner_token=owner_token)
    return call_id


def egress_banners(configured: dict | None, usage: dict) -> list[str]:
    """Banners a hunt or report carries about remote model endpoints: one per remote host and model that
    actually received calls (from the stored call rows), else one for a configured remote endpoint."""
    banners = [f"Telemetry excerpts were sent to {r['endpoint_host']} ({r['model']}) by the AI agent "
               f"({r['calls']} model calls)." for r in usage.get("remote_calls") or []]
    if not banners and configured and configured.get("egress") == "remote" and configured.get("requested"):
        banners.append(f"The AI agent was configured to use the remote endpoint {configured.get('endpoint_host')} "
                       f"({configured.get('model')}); no telemetry was sent to it in this hunt.")
    return banners
