"""Token budgets count prompt tokens at their price weight: cache reads and writes against uncached input."""
from __future__ import annotations

import math

import pytest
from pydantic import ValidationError

from romulus.agent.provider import record_call, record_failure
from romulus.agent.provider.base import ChatRequest, ChatResult, ProviderUnavailable, Usage
from romulus.agent.provider.budget import AgentBudget, BudgetExhausted, BudgetLimits, Charge
from romulus.agent.triage import TriageBudget
from romulus.config import Settings, load_settings

MODEL = "claude-test-model"
# the usage of a live investigation that stopped on its token budget after two of eight hypotheses
LIVE_PROMPT, LIVE_READ, LIVE_WRITE, LIVE_OUTPUT = 1_595_635, 1_157_596, 437_963, 62_503


def anthropic(**kw) -> Settings:
    return Settings(**{"agent_provider": "anthropic", "agent_model": MODEL, **kw})


def result(prompt: int, completion: int, read: int = 0, write: int = 0, *, billed=None) -> ChatResult:
    details = {"billed": billed} if billed is not None else {}
    return ChatResult("ok", "stop", "done", None, [], Usage(prompt, completion, read, write), prompt, MODEL, MODEL,
                      5, "{}", details=details)


class FakeProvider:
    name = "anthropic"
    model = MODEL
    sends_sampling = False

    def describe(self) -> dict:
        return {"provider": self.name, "model": self.model, "endpoint_host": "api.example", "egress": "remote"}


def live_weighted() -> int:
    uncached = LIVE_PROMPT - LIVE_READ - LIVE_WRITE
    return math.ceil(uncached + LIVE_READ * 0.1 + LIVE_WRITE * 1.25) + LIVE_OUTPUT


def test_the_documented_defaults_weight_cache_reads_and_writes_for_the_anthropic_provider():
    limits = BudgetLimits.from_settings(anthropic())
    assert (limits.cache_read_token_weight, limits.cache_write_token_weight) == (0.1, 1.25)
    budget = AgentBudget(limits, clock=lambda: 0.0)
    charged = budget.charge(result(LIVE_PROMPT, LIVE_OUTPUT, LIVE_READ, LIVE_WRITE))
    # the raw counts are kept as they were; the budget holds the weighted total
    assert budget.tokens == LIVE_PROMPT + LIVE_OUTPUT == 1_658_138
    assert budget.budget_tokens == charged["budget_tokens"] == live_weighted() == 725_793
    assert charged["prompt_tokens"] == LIVE_PROMPT and charged["cache_read_tokens"] == LIVE_READ
    snapshot = budget.snapshot()
    assert (snapshot["tokens"], snapshot["budget_tokens"]) == (1_658_138, 725_793)
    # that run's next call fits the default 2,000,000 budget tokens; counted raw it would not
    budget.check(100_000, 64_096)
    assert budget.tokens + limits.worst_tokens(100_000, 64_096) > limits.max_tokens


@pytest.mark.parametrize("provider", ["openai_compatible", "ollama", "openai_responses"])
def test_other_providers_count_each_token_once_whatever_cache_counts_they_report(provider):
    limits = BudgetLimits.from_settings(Settings(agent_provider=provider, agent_model="m"))
    assert not limits.weighted and "cache_read_token_weight" not in limits.as_dict()
    budget = AgentBudget(limits, clock=lambda: 0.0)
    budget.charge(result(10_000, 500, read=8_000, write=1_000))
    assert budget.budget_tokens == budget.tokens == 10_500
    assert limits.worst_tokens(1000, 100) == 1100


def test_the_weights_are_settings_with_bounds_and_are_recorded_with_the_hunt(tmp_path):
    env = tmp_path / ".env"
    env.write_text("AGENT_PROVIDER=anthropic\nAGENT_CACHE_READ_TOKEN_WEIGHT=0.05\n"
                   "AGENT_CACHE_WRITE_TOKEN_WEIGHT=2\n", encoding="utf-8")
    s = load_settings(env, environ={})
    limits = BudgetLimits.from_settings(s)
    assert (limits.cache_read_token_weight, limits.cache_write_token_weight) == (0.05, 2.0)
    recorded = limits.as_dict()
    assert (recorded["cache_read_token_weight"], recorded["cache_write_token_weight"]) == (0.05, 2.0)
    rebuilt = BudgetLimits.from_dict(recorded, MODEL)
    assert (rebuilt.cache_read_token_weight, rebuilt.cache_write_token_weight) == (0.05, 2.0)
    # a hunt recorded without weights keeps counting each token once
    legacy = {k: v for k, v in recorded.items() if not k.endswith("_token_weight")}
    assert not BudgetLimits.from_dict(legacy, MODEL).weighted
    for bad in ({"agent_cache_read_token_weight": 0}, {"agent_cache_read_token_weight": 1.5},
                {"agent_cache_write_token_weight": 0.9}):
        with pytest.raises(ValidationError):
            Settings(**bad)


def test_the_pre_call_check_counts_the_whole_prompt_at_the_dearest_weight():
    limits = BudgetLimits.from_settings(anthropic(agent_refusal_fallback="off", agent_max_tokens=10_000))
    assert limits.worst_tokens(1000, 100) == 1250 + 100      # every prompt token may be a cache write
    budget = AgentBudget(limits, budget_tokens=10_000 - 1300, clock=lambda: 0.0)
    with pytest.raises(BudgetExhausted) as raised:            # an uncached prompt (1100) would have fit
        budget.check(1000, 100)
    assert raised.value.budget == "tokens" and "weighted by price" in raised.value.detail
    with_fallback = BudgetLimits.from_settings(anthropic())
    assert with_fallback.worst_tokens(1000, 100) == 2 * (1250 + 100)


def test_a_cost_cap_stays_a_separate_limit():
    limits = BudgetLimits.from_settings(anthropic(
        agent_refusal_fallback="off", agent_max_cost_usd=0.01, agent_price_input_per_mtok=1,
        agent_price_output_per_mtok=5, agent_price_cache_read_per_mtok=0.1))
    budget = AgentBudget(limits, clock=lambda: 0.0)
    budget.charge(result(1_000_000, 0, read=1_000_000))
    assert budget.budget_tokens == 100_000 and budget.cost_usd == pytest.approx(0.1)
    with pytest.raises(BudgetExhausted) as raised:
        budget.check(10, 10)
    assert raised.value.budget == "cost"


def test_attempts_from_several_models_are_weighted_attempt_by_attempt():
    limits = BudgetLimits.from_settings(anthropic())
    billed = [{"model": MODEL, "prompt": 1000, "completion": 10, "cache_read": 900, "cache_write": 0},
              {"model": "fallback", "prompt": 1000, "completion": 200, "cache_read": 0, "cache_write": 1000}]
    charge = AgentBudget(limits, clock=lambda: 0.0).charge(result(0, 0, billed=billed))
    assert charge["budget_tokens"] == math.ceil(100 + 90 + 1250) + 210
    assert limits.budget_tokens(Charge(1000, 10, 900, 0)) == 200


def _repo(tmp_path):
    from romulus.hunt import run as hunt_run
    repo = hunt_run.open_repo(Settings(home=tmp_path))
    repo.create_hunt("h1", {"window": {}, "targets": []}, "digest", "test")
    return repo


def test_call_rows_record_budget_tokens_and_a_resumed_budget_continues_from_them(tmp_path):
    from romulus.agent.investigate import _budget
    repo = _repo(tmp_path)
    settings = anthropic()
    limits = BudgetLimits.from_settings(settings)
    request = ChatRequest([{"role": "user", "content": "go"}])
    first = record_call(repo, FakeProvider(), hunt_id="h1", purpose="investigate", request=request,
                        result=result(LIVE_PROMPT, LIVE_OUTPUT, LIVE_READ, LIVE_WRITE), limits=limits)
    failure = ProviderUnavailable("down")
    failure.billed = [{"model": MODEL, "prompt": 2000, "completion": 100, "cache_read": 1000, "cache_write": 0}]
    record_failure(repo, FakeProvider(), hunt_id="h1", purpose="investigate", request=request, error=failure,
                   limits=limits)
    estimated = ChatResult("ok", "stop", "x" * 32, None, [], Usage(), 50, MODEL, MODEL, 1, "x" * 32)
    record_call(repo, FakeProvider(), hunt_id="h1", purpose="investigate", request=request, result=estimated,
                limits=limits)
    row = next(r for r in repo.model_calls(hunt_id="h1") if r["id"] == first)
    assert row["options"]["budget_tokens"] == live_weighted()
    assert (row["prompt_eval_count"], row["eval_count"]) == (LIVE_PROMPT, LIVE_OUTPUT)     # raw, as before
    usage = repo.agent_usage("h1")
    failure_weighted = math.ceil(1000 + 100) + 100
    estimated_raw = 50 + int(len("x" * 32) / 3.2) + 8
    assert usage["tokens"] == LIVE_PROMPT + LIVE_OUTPUT + 2100 + estimated_raw
    assert usage["budget_tokens"] == live_weighted() + failure_weighted + estimated_raw
    manifest = {"ai_agent": {"model": MODEL, "budgets": limits.as_dict()}}
    resumed = _budget(settings, manifest, repo, "h1", lambda: 0.0)
    assert resumed.limits.cache_read_token_weight == 0.1
    assert (resumed.tokens, resumed.budget_tokens) == (usage["tokens"], usage["budget_tokens"])


def test_the_triage_input_budget_counts_weighted_prompt_tokens():
    budget = TriageBudget.from_settings(anthropic(agent_refusal_fallback="off",
                                                  agent_triage_max_input_tokens=100_000), clock=lambda: 0.0)
    budget.charge(result(100_000, 1000, read=90_000))
    assert (budget.input_tokens, budget.budget_input_tokens) == (100_000, 19_000)
    snapshot = budget.snapshot()
    assert (snapshot["input_tokens"], snapshot["budget_input_tokens"]) == (100_000, 19_000)
    budget.check(60_000, 1000)              # 19,000 + 75,000 at the dearest weight fits
    with pytest.raises(BudgetExhausted) as raised:
        budget.check(70_000, 1000)          # 19,000 + 87,500 does not
    assert raised.value.budget == "input-tokens"
