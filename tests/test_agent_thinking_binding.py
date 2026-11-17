"""Signed reasoning stays valid across compaction: a provider that binds each thinking block to the conversation it
was produced in (Anthropic's preserved thinking) never receives a block whose earlier conversation changed, and a
refusal for one is recovered once instead of ending the session."""
from __future__ import annotations

import json

from romulus.agent import context
from romulus.agent.context import SessionResults
from romulus.agent.investigate import REASONING_REJECTED_REASON
from romulus.agent.provider.base import PROVIDER_STATE, ChatRequest, ToolCall, Usage, estimate_tokens
from romulus.agent.provider.claude_messages import NO_VISIBLE_REPLY, thinking_rejected, without_thinking
from tests.agent_scripted import ScriptedProvider, response
from tests.test_agent_context import _query_result, _run, _settings

REFUSAL = ("HTTP 400 invalid_request_error: messages.5.content.0: Invalid `signature` in `thinking` block. The block "
           "is bound to a different conversation. Remove the block, or set "
           "`thinking.block_binding.prefix_mismatch_behavior` to \"drop_block\".")


class ThinkingProvider(ScriptedProvider):
    """A scripted provider whose replies carry signed thinking, stripped and recognised as the Anthropic adapter
    does."""
    name = "anthropic"

    def without_reasoning(self, message):
        return without_thinking(message)

    def reasoning_rejected(self, result):
        return thinking_rejected(result)


def _signed(calls, n):
    """A reply with a thinking block and its tool calls in the adapter's provider state."""
    def answer(request):
        result = response(tool_calls=calls)
        prompt = estimate_tokens(request.prompt_text())
        result.usage = Usage(prompt, 200, max(0, prompt - 1000), min(prompt, 1000))
        result.provider_state = {"provider": "anthropic", "model": "m", "content": [
            {"type": "thinking", "thinking": f"reasoning {n}", "signature": f"sig-{n}"},
            *({"type": "tool_use", "id": c.id, "name": c.name, "input": c.arguments or {}} for c in calls)]}
        return result
    return answer


def _queries(count, *, refuse_at=(), finish=True):
    def script(anchor, _evidence, _hypothesis):
        query = {"anchor": anchor, "source": "net-a", "query": {"match_all": {}}}
        steps = [_signed([ToolCall(f"q{i}", "query_source", query, json.dumps(query))], i)
                 for i in range(1, count + 1)]
        if finish:
            steps.append(_signed([ToolCall("f1", "finish_session", {"summary": "Followed the lead to its end."},
                                           "{}")], 0))
        for at in sorted(refuse_at):
            steps.insert(at, response(status="error", error=REFUSAL))
        return steps
    return script


def _thinking(message) -> list[str]:
    state = message.get(PROVIDER_STATE) or {}
    return [b["signature"] for b in state.get("content") or [] if b.get("type") == "thinking"]


def _bare(messages):
    return [without_thinking(m) if m.get("role") == "assistant" else m for m in messages]


def _assert_every_block_bound(requests):
    """Every thinking block a request replays sits after exactly the conversation it was produced in: the request
    that produced it, compared without thinking (what the API binds it to)."""
    produced = {}
    for n, request in enumerate(requests):
        for j, message in enumerate(request.messages):
            for signature in _thinking(message):
                if signature not in produced:
                    # first replayed here: its producing request is the previous one, whose messages it follows
                    produced[signature] = _bare(requests[n - 1].messages)
                    assert _bare(request.messages[:j]) == produced[signature]
                assert _bare(request.messages[:j]) == produced[signature], (n, j, signature)


def test_a_compacting_session_never_replays_thinking_bound_to_a_changed_conversation(tmp_path, monkeypatch):
    monkeypatch.setattr(context, "COMPACT_AFTER_TOKENS", 10_000)
    _repo, provider, outcome, *_ = _run(tmp_path, _queries(14), provider_class=ThinkingProvider)
    assert outcome["state"] == "finished" and outcome["context"]["compactions"] >= 2
    assert outcome["context"]["reasoning_turns_stripped"] > 0
    _assert_every_block_bound(provider.requests)
    # reasoning is kept where it is still valid: before the first edit, and since the last compaction
    last = provider.requests[-1].messages
    kept = [n for n, m in enumerate(last) if _thinking(m)]
    assert kept and any(_thinking(m) for m in last[:5])
    # the strip keeps each turn's tool calls, and the text the replay check compares
    for message in last:
        if message.get("role") == "assistant":
            assert [b["type"] for b in message[PROVIDER_STATE]["content"] if b["type"] != "thinking"] == ["tool_use"]


def test_without_compaction_nothing_is_stripped(tmp_path):
    _repo, provider, outcome, *_ = _run(tmp_path, _queries(4), provider_class=ThinkingProvider)
    assert outcome["state"] == "finished" and "context" not in outcome
    assert [len(_thinking(m)) for m in provider.requests[-1].messages if m.get("role") == "assistant"] == [1] * 4


def test_a_binding_refusal_is_retried_once_without_thinking_and_the_session_goes_on(tmp_path):
    repo, provider, outcome, *_ = _run(tmp_path, _queries(4, refuse_at=[3]), provider_class=ThinkingProvider)
    assert outcome["state"] == "finished" and outcome["reasoning_retry"] is True
    statuses = [row["status"] for row in repo.model_calls("h1")]
    assert statuses == ["ok", "ok", "ok", "error", "ok", "ok"]
    # the retried request and every later one carry no thinking from before the refusal; later turns keep theirs
    retried = provider.requests[4].messages
    assert not any(_thinking(m) for m in retried)
    assert retried == _bare(provider.requests[3].messages)      # the same history, stripped, nothing appended
    _assert_every_block_bound(provider.requests[4:])
    assert _thinking(provider.requests[-1].messages[-2]) == ["sig-4"]


def test_a_second_binding_refusal_ends_the_session_under_its_own_reason(tmp_path):
    _repo, provider, outcome, *_ = _run(tmp_path, _queries(4, refuse_at=[2, 3]), provider_class=ThinkingProvider)
    assert outcome["state"] == "failed" and outcome["reason"] == REASONING_REJECTED_REASON
    assert outcome["reason"] != "no_tool_call_twice" and len(provider.requests) == 4


def test_another_providers_error_is_not_taken_for_a_binding_refusal():
    assert thinking_rejected(response(status="error", error=REFUSAL))
    assert not thinking_rejected(response(status="error", error="HTTP 400 invalid_request_error: max_tokens"))
    assert not thinking_rejected(response(content="bound to a different conversation"))
    assert ScriptedProvider([]).reasoning_rejected(response(status="error", error=REFUSAL)) is False


def test_the_strip_keeps_text_and_calls_and_never_leaves_an_empty_turn():
    turn = {"role": "assistant", "content": "Looking.", "tool_calls": [{"id": "t1"}], PROVIDER_STATE: {
        "provider": "anthropic", "content": [{"type": "thinking", "thinking": "x", "signature": "s"},
                                             {"type": "redacted_thinking", "data": "d"},
                                             {"type": "text", "text": "Looking."},
                                             {"type": "tool_use", "id": "t1", "name": "n", "input": {}}]}}
    stripped = without_thinking(turn)
    assert [b["type"] for b in stripped[PROVIDER_STATE]["content"]] == ["text", "tool_use"]
    assert stripped["content"] == "Looking." and stripped["tool_calls"] == turn["tool_calls"]
    assert without_thinking(stripped) is stripped                         # repeating it changes nothing
    alone = {"role": "assistant", "content": None, PROVIDER_STATE: {
        "provider": "anthropic", "content": [{"type": "thinking", "thinking": "x", "signature": "s"}]}}
    emptied = without_thinking(alone)
    assert emptied[PROVIDER_STATE]["content"] == [{"type": "text", "text": NO_VISIBLE_REPLY}]
    assert emptied["content"] == NO_VISIBLE_REPLY
    assert without_thinking({"role": "assistant", "content": "plain"}) == {"role": "assistant", "content": "plain"}


# ---- the Anthropic request body after a compaction --------------------------------------------------------------

def test_the_anthropic_body_after_a_compaction_carries_no_stale_signed_thinking(monkeypatch, tmp_path):
    from tests.test_agent_provider_claude import (
        PIVOT,
        THINKING,
        TOOL,
        Endpoint,
        claude_settings,
        provider,
        reply,
        text,
        tool_use,
    )
    monkeypatch.setattr(context, "COMPACT_AFTER_TOKENS", 1)
    monkeypatch.setattr(context, "KEEP_FULL_RESULTS", 1)
    results = SessionResults(_settings(tmp_path))
    signed = [{**THINKING, "signature": f"{THINKING['signature']}{n}"} for n in range(3)]
    endpoint = Endpoint(*(reply([signed[n], text(f"step {n}"), tool_use(call_id=f"toolu_{n}")], stop="tool_use")
                          for n in range(3)), reply([text("done")]))
    p, _ = provider(claude_settings(), endpoint)
    messages = [{"role": "system", "content": "You are a test."}, {"role": "user", "content": "go"}]
    for n in range(3):
        turn = p.chat(ChatRequest(list(messages), tools=[TOOL, PIVOT]))
        assert turn.ok, turn.error
        messages.append(turn.assistant_message())
        handle, content = results.enter(n + 1, "query_source", {}, _query_result(n + 1, "E1"), {"E1"})
        messages.append({"role": "tool", "tool_call_id": f"toolu_{n}", "content": content})
        results.track(len(messages) - 1, handle)
    assert results.compact(messages, p.without_reasoning) == 2
    p.chat(ChatRequest(list(messages), tools=[TOOL, PIVOT]))
    before, after = endpoint.body(2), endpoint.body(3)
    assistants = [m for m in after["messages"] if m["role"] == "assistant"]
    # the first turn precedes the edit (the first stubbed result) and keeps its signed thinking; the turns after it
    # go out without theirs, as a run from the end; text and tool calls stay
    assert [[b["type"] for b in m["content"]] for m in assistants] == [
        ["thinking", "text", "tool_use"], ["text", "tool_use"], ["text", "tool_use"]]
    assert assistants[0] == next(m for m in before["messages"] if m["role"] == "assistant")
    assert [b.get("text") for m in assistants for b in m["content"] if b["type"] == "text"] == [
        "step 0", "step 1", "step 2"]
    assert json.dumps(after).count('"cache_control"') == 2
