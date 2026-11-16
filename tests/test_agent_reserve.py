"""The per-call budget reservation of an append-only session (its cached prefix at the read weight), and the separate
read and write tool-call allowances of a session."""
from __future__ import annotations

from datetime import UTC, datetime

import pytest

from romulus.agent import investigate
from romulus.agent.admission import truncation_marker
from romulus.agent.aliases import AliasBook
from romulus.agent.investigate import (
    _BudgetGate,
    _cache_basis,
    _CachedPrefix,
    _prompt_set,
    _run_session,
    _write_allowance,
)
from romulus.agent.provider import AgentBudget, BudgetExhausted, BudgetLimits
from romulus.agent.provider.base import ChatRequest, ToolCall, Usage
from romulus.agent.toolbox import Toolbox
from romulus.config import Settings
from romulus.store.db import make_engine, migrate
from romulus.store.repo import Repo
from tests.agent_scripted import ScriptedProvider, response

OUTPUT = 64_096                 # the output allowance plus the thinking allowance
HOLD = 300_000                  # 15% of the budget, held for the assessment


def _limits(*, fallback: bool = True) -> BudgetLimits:
    return BudgetLimits(400, 2_000_000, 36_000, 0.0, 0.0, 0.0, model="m", refusal_fallback=fallback,
                        cache_read_token_weight=0.1, cache_write_token_weight=1.25)


def _hunt(tmp_path, name):
    engine = make_engine(tmp_path / f"{name}.sqlite")
    migrate(engine)
    repo = Repo(engine)
    repo.create_hunt("h1", {"window": {}, "targets": [], "ai_agent": {"requested": True}}, "d", "test")
    repo.set_hunt_state("h1", "running")
    repo.set_hunt_state("h1", "completed_within_scope", detection_result="leads_only", stop_reason="scope")
    now = datetime.now(UTC)
    repo.save_agent_hypothesis({"id": "hyp-1", "hunt_id": "h1", "statement": "Review the session hypothesis here",
                                "techniques": [], "entity_ids": [], "status": "open", "confidence": "low",
                                "questions": ["q"], "created_session_id": None, "sessions_run": 0,
                                "created_at": now, "updated_at": now})
    return engine, repo


def _reply(tool_calls, *, prompt, read=0, write=0, completion=1000):
    result = response(tool_calls=tool_calls)
    result.usage = Usage(prompt, completion, read, write)
    return result


def _session(repo, tmp_path, provider, gate, settings=None):
    settings = settings or Settings(home=tmp_path)
    return _run_session(settings, repo, "h1", provider, gate, lambda session: Toolbox(repo, "h1", session_id=session),
                        _prompt_set(), purpose="investigate", hypothesis=repo.agent_hypotheses("h1")[0])


def _sized(monkeypatch, provider, sizes):
    """Prompt estimates by call: the session's prompt grows from call to call."""
    monkeypatch.setattr(investigate, "estimate_tokens",
                        lambda text: sizes[min(len(provider.requests), len(sizes) - 1)])


FINISH = ToolCall("f", "finish_session", {"summary": "The bounded session is complete."}, "{}")
READ = ToolCall("r", "list_findings", {"page": 1}, "{}")


# ---- the reservation -----------------------------------------------------------------------------------------------

def test_a_write_everything_reservation_at_half_the_budget_stops_the_session(tmp_path):
    limits = _limits()
    # a 228,158-token prompt estimate: written whole to the cache at 1.25, plus the output and thinking allowance,
    # once for the configured model and once more for the refusal fallback's attempt
    assert limits.worst_tokens(228_158, OUTPUT) == 2 * (285_198 + OUTPUT) == 698_588
    budget = AgentBudget(limits, calls=30, tokens=5_000_000, budget_tokens=1_076_687, clock=lambda: 0.0)
    gate = _BudgetGate(budget, Settings(home=tmp_path))
    with pytest.raises(BudgetExhausted) as stopped:
        gate.reserve(228_158, OUTPUT, "investigate")
    assert "1076687 of 2000000" in str(stopped.value) and "698588 reserved" in str(stopped.value)
    assert f"{HOLD} held for the assessment" in str(stopped.value)
    # with the previous call's 219,000-token cached prefix still alive, the same call fits and is reserved safely
    reservation = gate.reserve(228_158, OUTPUT, "investigate", prefix=_CachedPrefix(219_000, since=0.0))
    main = 21_900 + (228_158 - 219_000) * 1.25 + OUTPUT
    fallback = 285_198 + OUTPUT                     # the fallback model shares no cache: its prompt is written whole
    assert reservation.tokens == int(main + 0.5) + fallback and reservation.cached == 219_000
    assert budget.budget_tokens + reservation.tokens + HOLD <= limits.max_tokens


def test_the_fallback_attempt_is_reserved_only_when_the_fallback_is_on():
    on, off = _limits(), _limits(fallback=False)
    assert on.worst_tokens_cached(228_158, 219_000, OUTPUT) - off.worst_tokens_cached(228_158, 219_000, OUTPUT) == (
        285_198 + OUTPUT)
    # unweighted budgets (every other provider) count each token once, cached or not
    plain = BudgetLimits(400, 2_000_000, 36_000, 0.0, 0.0, 0.0)
    assert plain.worst_tokens_cached(1000, 900, 100) == plain.worst_tokens(1000, 100) == 1100


@pytest.mark.parametrize(("model", "fallback", "reserved"), [
    ("claude-haiku-5-5", "default", False),       # no server-side fallback: no attempt that can never happen
    ("claude-opus-5-5", "default", True), ("claude-fable-5-2", "default", True),
    ("claude-unknown-9", "default", True),        # unknown: the safe over-reservation
    ("claude-opus-5-5", "off", False),
])
def test_a_fallback_attempt_is_reserved_only_for_a_model_it_can_serve(tmp_path, model, fallback, reserved):
    settings = Settings(home=tmp_path, agent_provider="anthropic", agent_model=model,
                        agent_refusal_fallback=fallback)
    limits = BudgetLimits.from_settings(settings)
    assert limits.refusal_fallback is reserved
    assert limits.attempts_reserved == (2 if reserved else 1)
    single = limits.worst_tokens_cached(228_158, 219_000, OUTPUT)
    assert single == int(21_900 + (228_158 - 219_000) * 1.25 + 0.5) + OUTPUT + (285_198 + OUTPUT if reserved else 0)


def test_the_banner_mentions_a_fallback_answer_only_when_one_can_happen():
    from romulus.agent.provider import egress_banners
    usage = {"remote_calls": [{"endpoint_host": "api.example", "model": "m", "calls": 3}]}
    served = {"options": {"refusal_fallback": "default"}}
    unserved = {"options": {"refusal_fallback": "default", "refusal_fallback_served": False}}
    assert "refusal-fallback" in egress_banners(served, usage)[0]
    assert "refusal-fallback" not in egress_banners(unserved, usage)[0]


def _growing_session(monkeypatch, tmp_path, *, clock, spent=800_000, second=None, name="grow"):
    engine, repo = _hunt(tmp_path, name)
    first = _reply([READ], prompt=220_000, write=219_000, completion=3000)
    finished = second or _reply([FINISH], prompt=231_000, read=219_000, write=11_000, completion=500)
    provider = ScriptedProvider([first, finished], context=1_000_000, output=OUTPUT)
    _sized(monkeypatch, provider, [200_000, 228_158])
    budget = AgentBudget(_limits(), calls=30, tokens=5_000_000, budget_tokens=spent, clock=clock)
    gate = _BudgetGate(budget, Settings(home=tmp_path))
    reserved = []
    reserve = gate.reserve

    def spy(*args, **kwargs):
        reservation = reserve(*args, **kwargs)
        reserved.append(reservation)
        return reservation
    gate.reserve = spy
    return engine, repo, provider, gate, budget, reserved


def test_the_same_session_continues_and_its_charge_never_exceeds_the_reservation(monkeypatch, tmp_path):
    engine, repo, provider, gate, budget, reserved = _growing_session(monkeypatch, tmp_path, clock=lambda: 0.0)
    charged_before = []
    settle = gate.settle

    def watch(reservation, result=None, error=None):
        before = budget.budget_tokens
        settle(reservation, result=result, error=error)
        charged_before.append(budget.budget_tokens - before)
    gate.settle = watch

    outcome = _session(repo, tmp_path, provider, gate)

    assert outcome["state"] == "finished" and outcome["reservation_overruns"] == 0
    # after the first call's charge about 1.08M is spent, and the
    # second call's write-everything worst case would no longer fit beside the hold
    spent_at_second = 800_000 + charged_before[0]
    assert spent_at_second + _limits().worst_tokens(228_158, OUTPUT) + HOLD > 2_000_000
    assert reserved[1].cached == 219_000
    assert spent_at_second + reserved[1].tokens + HOLD <= 2_000_000
    for reservation, charged in zip(reserved, charged_before, strict=True):
        assert charged <= reservation.tokens
    engine.dispose()


def test_an_expired_cache_entry_is_reserved_as_a_write(monkeypatch, tmp_path):
    now = [0.0]
    engine, repo, provider, gate, _budget, reserved = _growing_session(
        monkeypatch, tmp_path, clock=lambda: now[0], name="expired")
    first = provider.results[0]

    def slow(_request):
        now[0] = investigate.CACHE_TRUST_SECONDS + 1      # tools and thinking outlast the cache entry
        return first
    provider.results[0] = slow

    outcome = _session(repo, tmp_path, provider, gate)

    # past the entry's life the whole prompt counts as written, and the session stops, saying so in numbers
    assert outcome["state"] == "budget" and outcome["reason"] == "budget:tokens"
    stored = repo.agent_sessions("h1")[-1]["summary"]
    assert "reserved for this call's worst case," in stored and "read weight" not in stored
    assert len(reserved) == 1
    engine.dispose()


def test_a_cache_entry_is_trusted_only_inside_its_life(tmp_path):
    now = [0.0]
    gate = _BudgetGate(AgentBudget(_limits(), clock=lambda: now[0]), Settings(home=tmp_path))
    prefix = _CachedPrefix(219_000, since=0.0)
    now[0] = investigate.CACHE_TRUST_SECONDS - 1
    assert gate.cached_tokens(prefix) == 219_000
    now[0] = investigate.CACHE_TRUST_SECONDS
    assert gate.cached_tokens(prefix) == 0
    assert investigate.CACHE_TRUST_SECONDS < investigate.CACHE_TTL_SECONDS == 300


def test_no_cached_prefix_is_assumed_after_a_fallback_answer_or_without_cache_use():
    request = ChatRequest(messages=[{"role": "user", "content": "x"}])
    plain = _reply([READ], prompt=1000, write=900)
    assert _cache_basis(plain, request, 900, 0.0)["cached"] == 900
    fallback = _reply([READ], prompt=1000, write=900)
    fallback.details = {"fallback": {"served_by": "other", "switches": [], "category": None}}
    assert _cache_basis(fallback, request, 900, 0.0) is None
    assert _cache_basis(_reply([READ], prompt=1000), request, 900, 0.0) is None


def test_a_charge_above_its_reservation_is_recorded_and_stops_the_session_honestly(monkeypatch, tmp_path):
    # the provider reports far more prompt than the cache basis allowed for: every token of it written
    missed = _reply([FINISH], prompt=800_000, write=800_000, completion=1000)
    engine, repo, provider, gate, budget, reserved = _growing_session(
        monkeypatch, tmp_path, clock=lambda: 0.0, spent=800_000, second=missed, name="overrun")

    outcome = _session(repo, tmp_path, provider, gate)

    assert reserved[1].overrun is not None and reserved[1].overrun[0] > reserved[1].overrun[1]
    assert outcome["state"] == "budget" and outcome["reason"] == "budget:tokens"
    assert outcome["reservation_overruns"] == 1
    stored = repo.agent_sessions("h1")[-1]["summary"]
    assert stored.startswith("Budget stop: tokens budget exceeded: a call was charged")
    assert f"{budget.budget_tokens} of 2000000 budget tokens are spent" in stored
    engine.dispose()


# ---- reads and writes ----------------------------------------------------------------------------------------------

def _alias(repo):
    return AliasBook(repo, "h1").alias_for("H", "hyp-1")


def _update(repo, note="Recorded what the read showed.", call_id="u"):
    return ToolCall(call_id, "update_hypothesis", {"hypothesis": _alias(repo), "note": note}, "{}")


def test_after_the_read_limit_the_session_still_records_and_finishes(tmp_path):
    engine, repo = _hunt(tmp_path, "reads")
    settings = Settings(home=tmp_path, agent_max_tool_calls_per_session=1)
    gate = _BudgetGate(AgentBudget(BudgetLimits.from_settings(settings), clock=lambda: 0.0), settings)
    provider = ScriptedProvider([response(tool_calls=[READ]),
                                 response(tool_calls=[ToolCall("r2", "list_findings", {"page": 1}, "{}"),
                                                      _update(repo)]),
                                 response(tool_calls=[FINISH])])

    outcome = _session(repo, tmp_path, provider, gate, settings)

    closing = provider.requests[1].messages[-1]["content"]
    assert closing.startswith("Tool-call limit reached for read tools")
    assert "update_hypothesis" in closing and "finish_session remain" in closing
    rows = [(row["name"], row["status"], row["refusal_reasons"]) for row in repo.agent_tool_calls("h1")]
    assert rows == [("list_findings", "complete", None), ("list_findings", "refused", ["$: tool_call_limit"]),
                    ("update_hypothesis", "complete", None), ("finish_session", "complete", None)]
    assert outcome["state"] == "finished"
    assert len(repo.agent_hypothesis_events("hyp-1")) == 1          # the recorded work is kept
    engine.dispose()


def test_writes_have_their_own_bounded_allowance(tmp_path):
    engine, repo = _hunt(tmp_path, "writes")
    settings = Settings(home=tmp_path, agent_max_tool_calls_per_session=1)
    allowance = _write_allowance(settings)
    assert allowance == 4
    gate = _BudgetGate(AgentBudget(BudgetLimits.from_settings(settings), clock=lambda: 0.0), settings)
    updates = [_update(repo, f"Recorded review step {index}.", f"u{index}") for index in range(allowance + 1)]
    provider = ScriptedProvider([response(tool_calls=updates), response(tool_calls=[FINISH])])

    outcome = _session(repo, tmp_path, provider, gate, settings)

    statuses = [row["status"] for row in repo.agent_tool_calls("h1")]
    assert statuses == ["complete"] * allowance + ["refused", "complete"]
    assert repo.agent_tool_calls("h1")[allowance]["refusal_reasons"] == ["$: write_call_limit"]
    assert provider.requests[1].messages[-1]["content"].startswith("Tool-call limit reached for write tools")
    assert outcome["state"] == "finished" and outcome["write_call_limit"] == allowance
    engine.dispose()


def test_an_over_long_hypothesis_note_is_refused_once_then_kept_cut_and_marked(tmp_path):
    engine, repo = _hunt(tmp_path, "note")
    settings = Settings(home=tmp_path)
    gate = _BudgetGate(AgentBudget(BudgetLimits.from_settings(settings), clock=lambda: 0.0), settings)
    secret = "value-91c2"
    note = (f"Saw {secret} in the record. " + "The lead stays open for review. " * 30).strip()
    provider = ScriptedProvider([response(tool_calls=[_update(repo, note, "u1")]),
                                 response(tool_calls=[_update(repo, note, "u2")]),
                                 response(tool_calls=[FINISH])])

    outcome = _session(repo, tmp_path, provider, gate, settings)

    refusal = provider.requests[1].messages[-1]["content"]
    assert f"note has {len(note)} characters" in refusal and "at most 600" in refusal and secret not in refusal
    assert outcome["state"] == "finished"
    assert repo.agent_refusal_counts("h1")["by_tool"]["update_hypothesis"] == {
        "note: string_too_long": 1, "note: truncated_by_product": 1}
    events = repo.agent_hypothesis_events("hyp-1")
    assert len(events) == 1
    stored = str(events[0])
    assert truncation_marker("note", 600) in stored
    engine.dispose()


def test_a_changed_prefix_is_reserved_as_a_write(monkeypatch, tmp_path):
    engine, repo, provider, gate, _budget, reserved = _growing_session(
        monkeypatch, tmp_path, clock=lambda: 0.0, spent=500_000, name="changed")
    basis = investigate._cache_basis

    def rewritten(result, request, prompt_est, started_at):
        recorded = basis(result, request, prompt_est, started_at)
        request.messages[1]["content"] += " "         # after the call, an earlier message is edited
        return recorded
    monkeypatch.setattr(investigate, "_cache_basis", rewritten)

    _session(repo, tmp_path, provider, gate)

    assert reserved[0].cached == 0 and reserved[1].cached == 0
    engine.dispose()


def test_a_turn_past_the_cache_lookback_is_reserved_as_a_write():
    parallel = [{"role": "assistant", "content": "", "provider_state": {"content": [
        {"type": "thinking"}, {"type": "text"}, *[{"type": "tool_use"}] * 30]}}, *[{"role": "tool"}] * 30]
    assert investigate._cache_positions(parallel) == 4          # a run of calls, and of results, is one position
    interleaved = [{"role": "assistant", "content": "", "provider_state": {"content": [
        {"type": "thinking"}, {"type": "tool_use"}] * 10}}, {"role": "user", "content": "x"}]
    assert investigate._cache_positions(interleaved) == 21 > investigate.CACHE_LOOKBACK_POSITIONS


def test_a_declined_attempt_and_the_fallback_answer_never_exceed_the_reservation():
    from romulus.agent.provider.budget import Part, charge_parts
    limits = _limits()
    reserved = limits.worst_tokens_cached(228_158, 219_000, OUTPUT)
    # the configured model reads the prefix, writes the growth, and declines at the end of its full allowance; the
    # fallback model then writes the whole prompt to its own cache and uses its full allowance
    declined = Part("m", 228_158, OUTPUT, cache_read=219_000, cache_write=228_158 - 219_000)
    answered = Part("fallback", 228_158, OUTPUT, cache_write=228_158)
    assert limits.budget_tokens(charge_parts((declined, answered))) <= reserved
    assert limits.budget_tokens(charge_parts((declined,))) <= _limits(fallback=False).worst_tokens_cached(
        228_158, 219_000, OUTPUT)


# ---- runaway sessions end in a bounded number of model calls ---------------------------------------------------------

def _forever(make):
    return [lambda _request, make=make: response(tool_calls=[make()])] * 50


def test_a_session_that_only_writes_ends_capped(tmp_path):
    engine, repo = _hunt(tmp_path, "only-writes")
    settings = Settings(home=tmp_path, agent_max_tool_calls_per_session=1)
    gate = _BudgetGate(AgentBudget(BudgetLimits.from_settings(settings), clock=lambda: 0.0), settings)
    provider = ScriptedProvider(_forever(lambda: _update(repo)))

    outcome = _session(repo, tmp_path, provider, gate, settings)

    assert outcome["state"] == "capped"
    assert len(provider.requests) == _write_allowance(settings) + 1       # the allowance, then one refused reply
    engine.dispose()


def test_a_session_that_only_reads_ends_capped(tmp_path):
    engine, repo = _hunt(tmp_path, "only-reads")
    settings = Settings(home=tmp_path, agent_max_tool_calls_per_session=2)
    gate = _BudgetGate(AgentBudget(BudgetLimits.from_settings(settings), clock=lambda: 0.0), settings)
    provider = ScriptedProvider(_forever(lambda: READ))

    outcome = _session(repo, tmp_path, provider, gate, settings)

    assert outcome["state"] == "capped" and len(provider.requests) == 3
    engine.dispose()


def test_a_session_whose_finish_keeps_being_refused_ends_capped(tmp_path):
    engine, repo = _hunt(tmp_path, "finish-loop")
    settings = Settings(home=tmp_path)
    gate = _BudgetGate(AgentBudget(BudgetLimits.from_settings(settings), clock=lambda: 0.0), settings)
    provider = ScriptedProvider(_forever(lambda: ToolCall("f", "finish_session", {"summary": "short"}, "{}")))

    outcome = _session(repo, tmp_path, provider, gate, settings)

    assert outcome["state"] == "capped" and outcome["reason"] == "finish_session refused 3 times"
    assert len(provider.requests) == investigate.FINISH_ATTEMPTS
    engine.dispose()


def test_an_over_long_agent_note_is_refused_once_then_kept_cut_and_marked(tmp_path):
    engine, repo = _hunt(tmp_path, "add-note")
    settings = Settings(home=tmp_path)
    gate = _BudgetGate(AgentBudget(BudgetLimits.from_settings(settings), clock=lambda: 0.0), settings)
    text = "The record repeats the earlier pattern. " * 40
    note = ToolCall("n", "add_note", {"target": _alias(repo), "text": text}, "{}")
    provider = ScriptedProvider([response(tool_calls=[note]), response(tool_calls=[note]),
                                 response(tool_calls=[FINISH])])

    outcome = _session(repo, tmp_path, provider, gate, settings)

    assert outcome["state"] == "finished"
    assert repo.agent_refusal_counts("h1")["by_tool"]["add_note"] == {
        "text: string_too_long": 1, "text: truncated_by_product": 1}
    stored = repo.agent_notes("h1")
    assert len(stored) == 1 and stored[0]["text"].endswith(truncation_marker("text", 1000))
    engine.dispose()
