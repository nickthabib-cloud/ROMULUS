"""The assess call's output allowance: a floor for adapters that add no thinking room, clamped to the model's
reported output limit, and the number the budget and the cost worst case reserve."""
import pytest

from romulus.agent import investigate
from romulus.agent.assessment import ASSESS_OUTPUT_FLOOR, assess_output, run_assessment
from romulus.agent.investigate import _BudgetGate
from romulus.agent.provider import AgentBudget, BudgetLimits, build_provider
from romulus.agent.provider.base import ToolCall, estimate_tokens
from romulus.agent.toolbox import Toolbox
from romulus.config import Settings
from tests.agent_scripted import ScriptedProvider, response
from tests.test_agent_provider_claude import MODEL_INFO, Endpoint, claude_settings, reply, text
from tests.test_agent_provider_claude import provider as claude_provider
from tests.test_agent_provider_toolbox_tools import ADAPTERS, REMOTE
from tests.test_report import _repo_with_finding

BODY = {"overall": [], "key_steps": [], "narrative": [], "confidence": {"overall": "low", "reasons": []},
        "alternatives": [], "gaps": [], "next_checks": []}


def _adapter(kind, **settings):
    extra, transport, answer, _names = ADAPTERS[kind]
    s = Settings(agent_provider=kind, agent_model="m", **{**extra, **settings})
    return s, build_provider(s, transport=transport(answer), resolver=lambda host: REMOTE, sleep=lambda _: None)


class NoThinkingRoom(ScriptedProvider):
    """A scripted adapter whose output limit is the request's, as the OpenAI-compatible and Ollama adapters'."""

    def __init__(self, results, settings, *, reported=0, **kwargs):
        super().__init__(results, **kwargs)
        self.s = settings
        self.reported = reported

    def output_limit(self, request):
        return request.max_output_tokens or self.s.agent_max_output_tokens

    def model_output_limit(self):
        return self.reported


@pytest.mark.parametrize("kind,expected", [("openai_compatible", ASSESS_OUTPUT_FLOOR), ("ollama", ASSESS_OUTPUT_FLOOR),
                                           ("openai_responses", None), ("anthropic", None)])
def test_each_adapter_kind_gets_the_floor_only_without_thinking_room(kind, expected):
    s, provider = _adapter(kind)
    allowance = assess_output(s, provider)
    assert allowance.max_output_tokens == expected
    # what the budget reserves is the adapter's output limit for that request
    if expected:
        assert allowance.limit == ASSESS_OUTPUT_FLOOR and "8192" in allowance.note
    else:      # thinking room is added to every call, as before: unchanged
        assert allowance.limit == s.agent_max_output_tokens + s.agent_thinking_tokens and not allowance.note
    # a configured allowance above the floor stands
    s, provider = _adapter(kind, agent_max_output_tokens=16_000)
    assert assess_output(s, provider).max_output_tokens is None
    assert assess_output(s, provider).limit == 16_000 + (s.agent_thinking_tokens if not expected else 0)


def test_the_floor_is_clamped_to_the_models_reported_output_limit():
    s = Settings()
    clamped = assess_output(s, NoThinkingRoom([], s, reported=6000))
    assert (clamped.max_output_tokens, clamped.limit) == (6000, 6000)
    assert "clamped to the model's reported 6000-token output limit" in clamped.note
    # below the configured allowance: the configured value stands (doctor reports that), and the clamp is stated
    low = assess_output(s, NoThinkingRoom([], s, reported=3000))
    assert (low.max_output_tokens, low.limit) == (None, 4096) and "clamped" in low.note
    assert assess_output(s, NoThinkingRoom([], s, reported=200_000)).max_output_tokens == ASSESS_OUTPUT_FLOOR


def test_the_claude_adapter_reads_the_models_output_limit_once_and_keeps_its_thinking_room():
    endpoint = Endpoint(reply([text("hi")]), model_info={**MODEL_INFO, "max_tokens": 64_000})
    provider, _ = claude_provider(claude_settings(), endpoint)
    assert provider.model_output_limit() == 64_000 == provider.model_output_limit()
    assert len([r for r in endpoint.requests if r.url.path.startswith("/v1/models")]) == 1
    allowance = assess_output(provider.s, provider)
    assert allowance.max_output_tokens is None
    assert allowance.limit == provider.s.agent_max_output_tokens + provider.s.agent_thinking_tokens


def test_the_assess_call_requests_and_budgets_the_effective_allowance(tmp_path):
    repo, _ = _repo_with_finding()
    s = Settings(home=tmp_path)
    provider = NoThinkingRoom([response(parsed=BODY)], s)
    budget = AgentBudget.from_usage(BudgetLimits(10, 1_000_000, 600, 0, 0, 0), repo.agent_usage("h1"),
                                    clock=lambda: 0.0)
    result = run_assessment(s, repo, "h1", provider, budget, clock=lambda: 0.0)
    assert provider.requests[0].max_output_tokens == ASSESS_OUTPUT_FLOOR
    assert result["output_allowance"]["limit"] == ASSESS_OUTPUT_FLOOR
    assert "8192" in repo.agent_sessions("h1", purpose="assess")[-1]["summary"]
    # a token budget that holds the configured allowance but not the floor stops the call before it is sent
    prompt = 0
    for request in provider.requests:
        prompt = estimate_tokens(request.prompt_text())
    tight = BudgetLimits(10, prompt + 6000, 600, 0, 0, 0)
    held = NoThinkingRoom([response(parsed=BODY)], s)
    assert run_assessment(s, repo, "h1", held, AgentBudget.from_usage(tight, {}, clock=lambda: 0.0),
                          clock=lambda: 0.0) is None
    assert held.requests == [] and repo.agent_sessions("h1", purpose="assess")[-1]["summary"] == "budget:tokens"
    # the cost worst case: a cost budget that covers the configured output but not the floor stops it too
    priced = BudgetLimits(10, 10_000_000, 600, 1.0, 0.0, 1_000_000 / 6000)      # $1 buys 6000 output tokens
    held = NoThinkingRoom([response(parsed=BODY)], s)
    assert run_assessment(s, repo, "h1", held, AgentBudget.from_usage(priced, {}, clock=lambda: 0.0),
                          clock=lambda: 0.0) is None
    assert held.requests == [] and repo.agent_sessions("h1", purpose="assess")[-1]["summary"] == "budget:cost"


def test_the_investigation_holds_the_effective_allowance_for_the_assessment(tmp_path, monkeypatch):
    s = Settings(home=tmp_path, agent_assess_reserve_fraction=0.0)
    limits = BudgetLimits(10, 10_000_000, 600, 100.0, 1.0, 10.0)
    gate = _BudgetGate(AgentBudget.from_usage(limits, {}, clock=lambda: 0.0), s, assess_output=ASSESS_OUTPUT_FLOOR)
    _calls, tokens, cost, _wall = gate._reserve_for_assess(5000, 1024)
    assert tokens == limits.worst_tokens(5000, ASSESS_OUTPUT_FLOOR) > limits.worst_tokens(5000, 1024)
    assert cost == limits.worst_cost(5000, ASSESS_OUTPUT_FLOOR)
    # the agent phase builds its gate with the assess call's own output limit
    seen = []

    class Recording(_BudgetGate):
        def __init__(self, budget, settings, assess_output=None):
            seen.append(assess_output)
            super().__init__(budget, settings, assess_output=assess_output)

    monkeypatch.setattr(investigate, "_BudgetGate", Recording)
    repo, _ = _repo_with_finding()
    finish = ToolCall("f", "finish_session", {"summary": "The initial review found nothing to open."}, "{}")
    provider = NoThinkingRoom([response(tool_calls=[finish]), response(parsed=BODY)], s)
    investigate.run_agent_phase(s, repo, "h1", provider=provider, clock=lambda: 0.0,
                                toolbox_factory=lambda session: Toolbox(repo, "h1", session_id=session))
    assert seen == [ASSESS_OUTPUT_FLOOR]
    assert provider.requests[-1].max_output_tokens == ASSESS_OUTPUT_FLOOR


def test_the_floor_is_capped_at_a_third_of_a_known_context_window(tmp_path):
    s, provider = _adapter("ollama", agent_context_tokens=0, ollama_num_ctx=16_384)
    allowance = assess_output(s, provider)
    assert (allowance.max_output_tokens, allowance.limit) == (16_384 // 3, 16_384 // 3)
    assert "capped at a third of the 16384-token context window (5461 tokens)" in allowance.note
    # at the default 8192-token window the cap is below the configured allowance, which stands; the cap is stated
    s, provider = _adapter("ollama", agent_context_tokens=0)
    allowance = assess_output(s, provider)
    assert allowance.max_output_tokens is None and allowance.limit == 4096 and "8192-token context" in allowance.note
    # and the assess session says so
    repo, _ = _repo_with_finding()
    s = Settings(home=tmp_path)
    scripted = NoThinkingRoom([response(parsed=BODY)], s, context=16_384)
    budget = AgentBudget.from_usage(BudgetLimits(10, 1_000_000, 600, 0, 0, 0), {}, clock=lambda: 0.0)
    assert run_assessment(s, repo, "h1", scripted, budget, clock=lambda: 0.0) is not None
    assert scripted.requests[0].max_output_tokens == 5461
    assert "a third of the 16384-token context window" in repo.agent_sessions("h1", purpose="assess")[-1]["summary"]
