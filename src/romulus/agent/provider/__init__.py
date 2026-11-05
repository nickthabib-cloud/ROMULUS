"""Model-provider port for the AI investigating agent: readiness, the adapter factory and call recording.

`agent_readiness` decides, without contacting the model, whether the agent can run: `not_configured`
(nothing to call; the hunt is deterministic only), `blocked` (the configuration is refused, for example a
remote endpoint without the egress switch), or `ready`. `build_provider` returns an adapter only when ready.
The anthropic adapter's SDK is an optional install, imported only when that provider is built.
"""
from __future__ import annotations

import importlib.util
import uuid
from collections.abc import Callable
from dataclasses import dataclass

from romulus.agent.provider.base import (
    PROVIDER_STATE,
    AgentNotReady,
    ChatProvider,
    ChatRequest,
    ChatResult,
    HistoryError,
    ProviderUnavailable,
    Tool,
    ToolCall,
    Usage,
    endpoint_url,
)
from romulus.agent.provider.budget import AgentBudget, BudgetExhausted, BudgetLimits, charge_of
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

ANTHROPIC_EXTRA_HINT = "the anthropic provider needs its optional SDK: install romulus[anthropic]"
ANTHROPIC_MODULES = ("anthropic", "httpx2")

__all__ = [
    "EGRESS_SWITCH_VALUE", "PROVIDER_STATE", "AgentBudget", "AgentNotReady", "AgentReadiness", "BudgetExhausted",
    "BudgetLimits", "ChatProvider", "ChatRequest", "ChatResult", "HistoryError", "ProviderUnavailable", "Tool",
    "ToolCall", "Usage", "agent_readiness", "build_provider", "egress_banners", "record_call",
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
        out = {"state": self.state, "reason": self.reason, "provider": self.provider, "model": self.model,
               "endpoint_host": d.host if d else None, "endpoint_scheme": d.scheme if d else None,
               "egress": d.egress if d else None, "egress_basis": d.basis if d else None,
               "egress_switch": s.model_egress or None,
               "budgets": {**BudgetLimits.from_settings(s).as_dict(),
                           "max_tool_calls_per_session": s.agent_max_tool_calls_per_session,
                           "max_source_queries": s.agent_max_source_queries,
                           "concurrency": s.agent_concurrency}}
        if self.provider == "anthropic":
            out["options"] = {"effort": s.agent_effort, "max_output_tokens": s.agent_max_output_tokens,
                              "thinking_tokens": s.agent_thinking_tokens,
                              "refusal_fallback": s.agent_refusal_fallback}
        elif self.provider == "openai_responses":
            out["options"] = {"effort": s.agent_effort, "max_output_tokens": s.agent_max_output_tokens,
                              "thinking_tokens": s.agent_thinking_tokens}
        return out


def sdk_installed(*modules: str) -> bool:
    """Whether the optional SDK (by default anthropic and its HTTP library) can be imported, found without
    importing it."""
    for module in modules or ANTHROPIC_MODULES:
        try:
            if importlib.util.find_spec(module) is None:
                return False
        except (ImportError, ValueError):
            return False
    return True


def missing_prices(s: Settings) -> list[str]:
    """The prices a priced agent can be charged at that are not set above 0. A cost budget needs the input and
    output prices; a priced anthropic agent also needs the cache-read price (its prompt cache is always on) and,
    with the refusal fallback on, the fallback model's prices: without any one of them the cost is undercounted."""
    anthropic = s.agent_provider == "anthropic"
    fallback = anthropic and s.agent_refusal_fallback == "default"
    fallback_prices = [("AGENT_PRICE_FALLBACK_INPUT_PER_MTOK", s.agent_price_fallback_input_per_mtok),
                       ("AGENT_PRICE_FALLBACK_OUTPUT_PER_MTOK", s.agent_price_fallback_output_per_mtok),
                       ("AGENT_PRICE_FALLBACK_CACHE_READ_PER_MTOK", s.agent_price_fallback_cache_read_per_mtok)]
    priced = bool(s.agent_max_cost_usd or s.agent_price_input_per_mtok or s.agent_price_output_per_mtok
                  or (anthropic and (s.agent_price_cache_read_per_mtok or any(v for _, v in fallback_prices))))
    needed = []
    if s.agent_max_cost_usd or (anthropic and priced):
        needed += [("AGENT_PRICE_INPUT_PER_MTOK", s.agent_price_input_per_mtok),
                   ("AGENT_PRICE_OUTPUT_PER_MTOK", s.agent_price_output_per_mtok)]
    if anthropic and priced:
        needed.append(("AGENT_PRICE_CACHE_READ_PER_MTOK", s.agent_price_cache_read_per_mtok))
        if fallback:
            needed += fallback_prices
    return [name for name, value in needed if not value]


def agent_readiness(s: Settings, resolver: Resolver = system_resolver) -> AgentReadiness:
    provider, model = s.agent_provider, s.agent_model.strip()
    url = endpoint_url(s)
    if not url:
        return AgentReadiness("not_configured", "AGENT_BASE_URL is empty", provider, model)
    if not model:
        return AgentReadiness("not_configured", "AGENT_MODEL is empty", provider, model)
    if provider == "anthropic" and not sdk_installed():
        return AgentReadiness("not_configured", ANTHROPIC_EXTRA_HINT, provider, model)
    try:
        decision = classify(url, s.model_local_hosts, s.model_egress, resolver)
    except EndpointError as exc:
        return AgentReadiness("blocked", str(exc), provider, model)
    if not decision.allowed:
        return AgentReadiness("blocked", decision.refusal, provider, model, decision)
    if decision.egress == "remote" and provider in ("openai_compatible", "openai_responses")             and not s.agent_api_key.get_secret_value():
        return AgentReadiness("not_configured", "AGENT_API_KEY is empty (a remote endpoint needs a key)",
                              provider, model, decision)
    if provider == "anthropic" and not s.agent_api_key.get_secret_value():
        return AgentReadiness("not_configured", "AGENT_API_KEY is empty (the anthropic provider needs a key)",
                              provider, model, decision)
    missing = missing_prices(s)
    if missing:
        lead = "AGENT_MAX_COST_USD is set but " if s.agent_max_cost_usd else "the agent is priced but "
        return AgentReadiness("blocked", f"{lead}{', '.join(missing)} {'is' if len(missing) == 1 else 'are'} not "
                                         "set above 0: every price a call can be charged at is needed, or the cost "
                                         "cannot be estimated without undercounting", provider, model, decision)
    return AgentReadiness("ready", "", provider, model, decision)


def build_provider(s: Settings, *, transport=None, resolver: Resolver = system_resolver,
                   sleep: Callable[[float], None] | None = None,
                   readiness: AgentReadiness | None = None) -> ChatProvider:
    """The ready adapter. `transport` replaces the HTTP transport (tests): an httpx transport for the
    openai_compatible, openai_responses and ollama adapters, an httpx2 transport (the SDK's HTTP library) for
    anthropic."""
    readiness = readiness or agent_readiness(s, resolver)
    if not readiness.ready:
        raise AgentNotReady(readiness.message())
    kwargs = {"transport": transport}
    if sleep is not None:
        kwargs["sleep"] = sleep
    if s.agent_provider == "anthropic":
        try:
            from romulus.agent.provider.claude_messages import ClaudeMessagesProvider
            return ClaudeMessagesProvider(s, readiness.decision, **kwargs)
        except ImportError:      # the SDK, or part of it, is missing or broken
            raise AgentNotReady(f"agent not configured: {ANTHROPIC_EXTRA_HINT}") from None
    if s.agent_provider == "ollama":
        from romulus.agent.provider.ollama import OllamaProvider as cls
    elif s.agent_provider == "openai_responses":
        from romulus.agent.provider.openai_responses import OpenAIResponsesProvider as cls
    else:
        from romulus.agent.provider.openai_compatible import OpenAICompatibleProvider as cls
    return cls(s, readiness.decision, **kwargs)


def record_call(repo, provider: ChatProvider, *, hunt_id: str, purpose: str, request: ChatRequest,
                result: ChatResult, limits: BudgetLimits, call_id: str | None = None, case_id: str | None = None,
                validation: dict | None = None, owner_token: str | None = None) -> str:
    """Store one model call: prompt digest, provider and model (requested and reported), parameters, the raw
    response, finish reason, validation, usage and an estimated cost."""
    call_id = call_id or "mc-" + uuid.uuid4().hex[:20]
    charge = charge_of(result)
    described = provider.describe()
    options = {"tool_choice": request.tool_choice, "tools": [t.name for t in request.tools],
               "schema": request.schema_name if request.response_schema is not None else None,
               "max_output_tokens": request.max_output_tokens,
               # an adapter that never sends sampling parameters records none
               "temperature": request.temperature if provider.sends_sampling else None,
               "attempts": result.attempts, "usage_estimated": charge.estimated}
    if charge.cache_read or charge.cache_write:
        options.update(cache_read_tokens=charge.cache_read, cache_write_tokens=charge.cache_write)
    if charge.worst_case:
        options["usage_worst_case"] = True     # an attempt that broke off mid-reply, charged at its full allowance
    if result.details:
        options["provider_details"] = dict(result.details)
    repo.save_model_call({
        "id": call_id, "hunt_id": hunt_id, "case_id": case_id, "purpose": purpose, "model": provider.model,
        "options": options,
        "prompt_digest": digest({"messages": request.messages, "tools": [t.__dict__ for t in request.tools],
                                 "schema": request.response_schema}),
        "prompt_tokens_est": result.prompt_tokens_est,
        # what the call was charged: every attempt the provider billed for it, when it reports them
        "prompt_eval_count": None if charge.estimated else charge.prompt,
        "eval_count": None if charge.estimated else charge.completion,
        "duration_ms": result.duration_ms, "raw_response": result.raw,
        "parsed": {"content": result.parsed, "tool_calls": [c.as_dict() for c in result.tool_calls]},
        "validation": validation if validation is not None else {"ok": result.ok, "errors": [result.error] if result.error else []},
        "status": result.status,
        "provider": described["provider"], "endpoint_host": described["endpoint_host"],
        "egress": described["egress"], "model_reported": result.model_reported or None,
        "finish_reason": result.finish_reason or None,
        "cost_usd_est": limits.charge_cost(charge) if limits.priced else None,
    }, owner_token=owner_token)
    return call_id


def egress_banners(configured: dict | None, usage: dict) -> list[str]:
    """Banners a hunt or report carries about remote model endpoints: one per remote host and model that
    actually received calls (from the stored call rows), else one for a configured remote endpoint."""
    fallback = ((configured or {}).get("options") or {}).get("refusal_fallback") == "default"
    also = (" A call the provider's safety classifier declined may have been answered by its refusal-fallback "
            "model on the same host." if fallback else "")
    banners = [f"Telemetry excerpts were sent to {r['endpoint_host']} ({r['model']}) by the AI agent "
               f"({r['calls']} model calls).{also}" for r in usage.get("remote_calls") or []]
    if not banners and configured and configured.get("egress") == "remote" and configured.get("requested"):
        banners.append(f"The AI agent was configured to use the remote endpoint {configured.get('endpoint_host')} "
                       f"({configured.get('model')}); no telemetry was sent to it in this hunt.")
    return banners
