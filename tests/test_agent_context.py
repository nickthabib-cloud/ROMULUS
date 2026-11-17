"""A session's bounded working context: large tool results are stored whole and paged, older ones are compacted to
stubs in batches, the stubs keep every alias citable, and the conversation stays append-only between compactions so
the provider's prompt cache keeps reading its prefix."""
from __future__ import annotations

import json
from datetime import UTC, datetime

from romulus.agent import context
from romulus.agent.aliases import AliasBook
from romulus.agent.context import (
    SessionResults,
    compact_threshold,
    prompt_composition,
    result_token_cap,
    session_tag,
)
from romulus.agent.investigate import _BudgetGate, _prompt_set, _run_session
from romulus.agent.provider import AgentBudget, BudgetLimits
from romulus.agent.provider.base import ChatRequest, ToolCall, Usage, estimate_tokens
from romulus.agent.toolbox import (
    QUERY_SOURCE_DESCRIPTION,
    QuerySourceToolArgs,
    RegisteredTool,
    Toolbox,
    _result,
)
from romulus.config import Settings, redact_text
from tests.agent_scripted import ScriptedProvider, response
from tests.test_report import _repo_with_finding

SECRET = "es-password-0123456789"
CALLS = 40
ROW_BYTES = 12_000          # one query_source chunk of rows and aggregations


def _settings(tmp_path, **kw) -> Settings:
    return Settings(**{"home": tmp_path, "es_password": SECRET, "agent_max_tool_calls_per_session": CALLS + 10, **kw})


def _hunt():
    repo, finding_id = _repo_with_finding()
    now = datetime.now(UTC)
    repo.save_agent_hypothesis({"id": "hyp-1", "hunt_id": "h1", "statement": "Review the session hypothesis here",
                                "techniques": [], "entity_ids": [], "status": "open", "confidence": "low",
                                "questions": ["q"], "created_session_id": None, "sessions_run": 0,
                                "created_at": now, "updated_at": now})
    book = AliasBook(repo, "h1")
    return repo, book.alias_for("F", finding_id), book.alias_for("E", "ev1"), book.alias_for("H", "hyp-1")


def _rows(n: int) -> str:
    """A query's rows as their JSON text, about ROW_BYTES long, holding a configured secret once."""
    rows, size, i = [], 0, 0
    while size < ROW_BYTES:
        row = {"_id": f"r{n}-{i}", "process.command_line": f"powershell -enc AAAA{i:05d} --pw {SECRET if i == 3 else 'x'}",
               "host.name": f"ws{i % 7:02d}", "user.name": f"user{i % 5}"}
        rows.append(row)
        size += len(json.dumps(row))
        i += 1
    return json.dumps(rows, sort_keys=True)


def _query_result(n: int, evidence: str) -> dict:
    cursor = "P" + f"{n:020d}"
    return _result("complete", counts={"returned": 1, "total": 40}, data={"result": {
        "evidence": [evidence], "candidates": [], "entities": [], "event_summaries": [], "coverage": [],
        "reasons": [], "task_count": 1, "duration_ms": 5, "page": 1, "cursor": cursor, "raw_evidence": [],
        "search": {"tool": "query_source", "source": "net-a", "negative": "matches_found", "statement": None,
                   "total": 40, "returned": 20, "repeated": False,
                   "rows_and_aggregations": {"encoding": "json", "text": _rows(n), "chunk_index": 1,
                                             "chunk_count": 2, "omitted": True,
                                             "fetch": f"query_source page=1 cursor={cursor} chunk_index=2"}}}},
        more=False)


def _toolbox_factory(repo, evidence, produced: list, rows_per_result: int = 1):
    def make(session):
        toolbox = Toolbox(repo, "h1", session_id=session)

        def query(_args):
            result = _query_result(len(produced) + 1, evidence)
            if rows_per_result > 1:
                result["data"]["result"]["search"]["rows_and_aggregations"]["text"] = "".join(
                    _rows(i) for i in range(rows_per_result))
            produced.append(result)
            return produced[-1]
        # the same name, arguments and description: the tool definitions sent are the real ones
        toolbox.registry["query_source"] = RegisteredTool("query_source", QUERY_SOURCE_DESCRIPTION,
                                                          QuerySourceToolArgs, query)
        return toolbox
    return make


def _cached_reply(calls):
    """A reply whose usage says the prompt was read from the cache but for its last 1,000 tokens."""
    def answer(request):
        prompt = estimate_tokens(request.prompt_text())
        result = response(tool_calls=calls(request) if callable(calls) else calls)
        result.usage = Usage(prompt, 200, max(0, prompt - 1000), min(prompt, 1000))
        return result
    return answer


def _handle_of(request, call_id: str) -> str:
    """The handle the model was shown for the result of `call_id`: its stub's, or its first page's."""
    content = json.loads(next(m["content"] for m in request.messages if m.get("tool_call_id") == call_id))
    # a result shown whole and never compacted names no handle: a guess, which the session refuses
    return content.get("handle") or (content.get("paged") or {}).get("handle") or "R1"


def _get_result(call_id: str, of: str, page: int):
    """A get_result call for the result of call `of`, by the handle the conversation names (handles are per session)."""
    return lambda request: [ToolCall(call_id, "get_result", {"handle": _handle_of(request, of), "page": page}, "{}")]


def _script(anchor, evidence, hypothesis):
    query = {"anchor": anchor, "source": "net-a", "query": {"wildcard": {"process.command_line": {"value": "*-enc*"}}}}
    steps = [[ToolCall(f"q{i}", "query_source", query, json.dumps(query))] for i in range(1, CALLS + 1)]
    steps.append(_get_result("g1", "q1", 1))
    update = {"hypothesis": hypothesis, "add_support": [evidence], "note": "Encoded PowerShell seen on the host."}
    steps.append([ToolCall("u1", "update_hypothesis", update, json.dumps(update))])
    steps.append([ToolCall("f1", "finish_session", {"summary": "Followed the encoded PowerShell lead."}, "{}")])
    return [_cached_reply(calls) for calls in steps]


def _run(tmp_path, script=None, *, settings=None, stop=None, before_reserve=None, rows_per_result=1):
    """Run one investigate session over the scripted replies (`script(anchor, evidence, hypothesis)`, by default
    CALLS queries, a re-read, a citation and the finish). `stop()` is the analyst's stop request; `before_reserve(n)`
    runs before the n-th reservation (from 0)."""
    repo, anchor, evidence, hypothesis = _hunt()
    settings = settings or _settings(tmp_path)
    provider = ScriptedProvider((script or _script)(anchor, evidence, hypothesis), context=1_000_000, output=4096)
    limits = BudgetLimits(400, 100_000_000, 36_000, 0.0, 0.0, 0.0, model="m",
                          cache_read_token_weight=0.1, cache_write_token_weight=1.25)
    gate = _BudgetGate(AgentBudget(limits, clock=lambda: 0.0), settings, stop=stop)
    reserved = []
    reserve = gate.reserve

    def spy(prompt, output, purpose, *, prefix=None):
        if before_reserve is not None:
            before_reserve(len(reserved))
        reserved.append(prefix)
        return reserve(prompt, output, purpose, prefix=prefix)
    gate.reserve = spy
    produced: list = []
    outcome = _run_session(settings, repo, "h1", provider, gate,
                           _toolbox_factory(repo, evidence, produced, rows_per_result),
                           _prompt_set(), purpose="investigate", hypothesis=repo.agent_hypotheses("h1")[0])
    sizes = [estimate_tokens(request.prompt_text()) for request in provider.requests]
    return repo, provider, outcome, sizes, produced, reserved, evidence, settings


def _is_prefix(before: list[dict], after: list[dict]) -> bool:
    return len(before) <= len(after) and after[:len(before)] == before


def test_prompts_stay_bounded_across_a_forty_call_session_with_large_query_results(tmp_path, monkeypatch):
    # before: no compaction (the threshold never reached), as the session ran until now
    monkeypatch.setattr(context, "COMPACT_AFTER_TOKENS", 10 ** 12)
    _repo, _provider, before_outcome, before, *_ = _run(tmp_path / "before")
    monkeypatch.undo()
    _repo, provider, outcome, after, *_ = _run(tmp_path / "after")

    assert before_outcome["state"] == outcome["state"] == "finished"
    assert len(before) == len(after) == CALLS + 3
    # without compaction every call re-sends every earlier result: the prompt grows by a result per call
    assert before[-1] > 150_000 and before[-1] > 5 * before[5]
    # with it the prompt stays bounded: the full results are at most the kept ones plus one batch
    ceiling = before[0] + context.COMPACT_AFTER_TOKENS + (context.KEEP_FULL_RESULTS + 2) * 5_000 + CALLS * 400
    assert max(after) <= ceiling < before[-1] / 2
    assert outcome["context"]["compactions"] >= 3
    last = prompt_composition(provider.requests[-1].messages, provider.requests[-1].tools)
    assert last["stubs"] > 0 and last["tool_results"].get("query_source", 0) <= (
        context.COMPACT_AFTER_TOKENS + context.KEEP_FULL_RESULTS * 5_000)


def test_the_profile_script_reads_each_calls_prompt_and_cache_use_from_the_store(tmp_path):
    from scripts.agent_prompt_profile import profile
    repo, _provider, _outcome, sizes, *_ = _run(tmp_path)
    [session] = profile(repo, "h1")
    calls = session["calls"]
    assert [call["prompt"] for call in calls] == sizes
    assert calls[0]["tools"] == ["query_source"] and calls[-1]["tools"] == ["finish_session"]
    assert all(call["cache_read"] + call["cache_write"] == call["prompt"] for call in calls)


def test_the_conversation_is_append_only_between_compactions_and_a_compaction_is_reserved_uncached(tmp_path):
    _repo, provider, outcome, _sizes, _produced, reserved, *_ = _run(tmp_path)
    requests = [request.messages for request in provider.requests]
    rewritten = [i for i in range(1, len(requests)) if not _is_prefix(requests[i - 1], requests[i])]
    # every request extends the previous one, except the first after each compaction
    assert len(rewritten) == outcome["context"]["compactions"] >= 1
    for i in rewritten:
        old, new = requests[i - 1], requests[i]
        changed = [n for n in range(len(old)) if old[n] != new[n]]
        # only tool results' content changed; the model's turns and every tool_call_id are as they were
        assert changed and all(old[n]["role"] == new[n]["role"] == "tool" for n in changed)
        assert all(old[n]["tool_call_id"] == new[n]["tool_call_id"] for n in changed)
        # the cached prefix of the previous request is no longer this one's: reserved as written to the cache
        assert reserved[i] is None
        # the call after it extends the compacted conversation again and is reserved at the read weight
        if i + 1 < len(requests) and i + 1 not in rewritten:
            assert reserved[i + 1] is not None
    # a stub once written never changes: every later request carries it unchanged
    first = rewritten[0]
    stubbed = [n for n in range(len(requests[first - 1])) if requests[first - 1][n] != requests[first][n]]
    for later in requests[first:]:
        assert [later[n] for n in stubbed] == [requests[first][n] for n in stubbed]


def test_a_stub_keeps_the_leads_and_the_compacted_result_is_reread_redacted(tmp_path):
    repo, provider, _outcome, _sizes, produced, _reserved, evidence, settings = _run(tmp_path)
    final = provider.requests[-1].messages
    stub = json.loads(next(m["content"] for m in final if m.get("tool_call_id") == "q1"))
    # handles are per session: the call's number and the session's tag
    handle = "R1-" + session_tag(repo.agent_sessions("h1")[0]["id"])
    assert stub["handle"] == handle and stub["tool"] == "query_source" and stub["status"] == "complete"
    assert stub["aliases"] == [evidence] and stub["kept"] == {"evidence": 1, "raw_records": 0}
    assert stub["negative"] == "matches_found" and stub["total"] == 40 and stub["cursor"] == "P" + "0" * 19 + "1"
    assert stub["next_chunk"].endswith("chunk_index=2") and "wildcard" in stub["arguments"]
    # no telemetry text in a stub
    assert "powershell" not in json.dumps(stub) and SECRET not in json.dumps(stub)
    # the re-read is the stored result's own text, with the secret removed
    reread = json.loads(next(m["content"] for m in final if m.get("tool_call_id") == "g1"))
    expected = redact_text(json.dumps(produced[0], sort_keys=True, ensure_ascii=False, default=str), settings)
    assert reread["status"] == "complete" and reread["data"]["handle"] == handle
    assert reread["data"]["page"] == 1 and expected.startswith(reread["data"]["text"])
    assert len(reread["data"]["text"]) > len(expected) / 2
    assert SECRET not in reread["data"]["text"] and "powershell" in reread["data"]["text"]
    # the alias the first result issued, compacted long before, is cited after the compactions
    calls = {row["seq"]: row for row in repo.agent_tool_calls("h1")}
    update = next(row for row in calls.values() if row["name"] == "update_hypothesis")
    assert update["status"] == "complete"
    cited = [row for row in repo.agent_hypothesis_cites(hypothesis_id="hyp-1") if row["role"] == "support"]
    assert [row["target_id"] for row in cited if row["target_kind"] == "evidence"] == ["ev1"]


def test_an_oversized_result_enters_as_its_envelope_and_first_page_and_is_paged_whole(tmp_path):
    settings = _settings(tmp_path)
    results = SessionResults(settings, context_tokens=1_000_000)
    big = _query_result(1, "E1")
    big["data"]["result"]["search"]["rows_and_aggregations"]["text"] = "".join(_rows(i) for i in range(9))
    handle, content = results.enter(7, "query_source", {"anchor": "F1"}, big, {"E1"})
    assert handle == "R7"
    assert len(content) <= results.cap_chars and estimate_tokens(content) <= result_token_cap(1_000_000) + 100
    shown = json.loads(content)
    assert shown["status"] == "complete" and shown["aliases"] == ["E1"] and shown["more"] is False
    assert shown["paged"]["page"] == 1 and shown["paged"]["next"] == "get_result handle=R7 page=2"
    assert SECRET not in content
    toolbox = Toolbox(_repo_with_finding()[0], "h1")
    toolbox.results = results
    pages = []
    page = 1
    while True:
        read = toolbox.execute("get_result", {"handle": "R7", "page": page})
        assert read["status"] == "complete" and len(json.dumps(read)) <= results.cap_chars * 1.3
        pages.append(read["data"]["text"])
        if not read["more"]:
            break
        page += 1
    assert page == shown["paged"]["pages"] > 1
    whole = "".join(pages)
    assert whole == redact_text(json.dumps(big, sort_keys=True, ensure_ascii=False), settings)
    assert pages[0] == shown["paged"]["text"]
    # the secrets removed before it entered are counted for the call that sends it, once
    assert results.take_redactions() == {"ES_PASSWORD": 9} and results.take_redactions() == {}
    refused = toolbox.execute("get_result", {"handle": "R7", "page": page + 1})
    assert refused["status"] == "refused" and refused["data"]["error"]["code"] == "page_out_of_range"
    assert toolbox.execute("get_result", {"handle": "R99"})["data"]["error"]["code"] == "unknown_handle"
    results.close()


def test_a_result_that_fits_enters_exactly_as_before_and_is_not_counted_twice(tmp_path):
    results = SessionResults(_settings(tmp_path), context_tokens=0)
    small = _query_result(1, "E1")
    handle, content = results.enter(1, "query_source", {}, small, {"E1"})
    assert content == json.dumps(small, sort_keys=True, ensure_ascii=False, default=str)
    # the provider redacts and counts what it sends: nothing is counted here
    assert results.take_redactions() == {}
    assert results.page(handle, 1)["text"] == redact_text(content, results.settings)
    results.close()


def test_the_result_cap_is_a_share_of_the_context_within_bounds():
    assert result_token_cap(0) == context.RESULT_TOKEN_CAP
    assert result_token_cap(1_000_000) == context.RESULT_TOKEN_CAP
    assert result_token_cap(100_000) == 5_000
    assert result_token_cap(8_000) == context.MIN_RESULT_TOKENS


def test_compaction_never_stubs_unseen_results_writes_or_small_results(tmp_path, monkeypatch):
    monkeypatch.setattr(context, "COMPACT_AFTER_TOKENS", 1)
    monkeypatch.setattr(context, "KEEP_FULL_RESULTS", 0)
    results = SessionResults(_settings(tmp_path))
    messages = [{"role": "system", "content": "s"}, {"role": "user", "content": "u"}]

    def add(tool, result, call_id):
        handle, content = results.enter(len(messages), tool, {}, result, set())
        messages.append({"role": "tool", "tool_call_id": call_id, "content": content})
        results.track(len(messages) - 1, handle)
    messages.append({"role": "assistant", "content": None, "tool_calls": []})
    add("query_source", _query_result(1, "E1"), "a")
    add("update_hypothesis", {"status": "complete", "data": {"hypothesis": "H1", "pad": "x" * 5000}}, "b")
    add("list_findings", {"status": "complete", "data": {}}, "c")
    messages.append({"role": "assistant", "content": None, "tool_calls": []})
    add("query_source", _query_result(2, "E1"), "d")        # not yet sent: never stubbed
    assert results.compact(messages) == 1
    assert json.loads(messages[3]["content"])["handle"] == "R3"
    assert "pad" in messages[4]["content"] and json.loads(messages[5]["content"])["status"] == "complete"
    assert "powershell" in messages[7]["content"]
    assert results.compact(messages) == 0        # nothing more to stub until it has been sent
    results.close()


# ---- the providers' cache breakpoints over a compacted conversation ------------------------------------------------

def _compacting(monkeypatch, tmp_path):
    monkeypatch.setattr(context, "COMPACT_AFTER_TOKENS", 1)
    monkeypatch.setattr(context, "KEEP_FULL_RESULTS", 1)
    return SessionResults(_settings(tmp_path))


def test_the_anthropic_breakpoints_are_unchanged_by_compaction(monkeypatch, tmp_path):
    from tests.test_agent_provider_claude import (
        PIVOT,
        TOOL,
        Endpoint,
        claude_settings,
        provider,
        reply,
        text,
        tool_use,
    )
    results = _compacting(monkeypatch, tmp_path)
    endpoint = Endpoint(reply([text("one"), tool_use(call_id="toolu_a")], stop="tool_use"),
                        reply([text("two"), tool_use(call_id="toolu_b")], stop="tool_use"),
                        reply([text("done")]))
    p, _ = provider(claude_settings(), endpoint)
    messages = [{"role": "system", "content": "You are a test."}, {"role": "user", "content": "go"}]
    for n, call_id in enumerate(("toolu_a", "toolu_b")):
        turn = p.chat(ChatRequest(list(messages), tools=[TOOL, PIVOT]))
        messages.append(turn.assistant_message())
        handle, content = results.enter(n + 1, "query_source", {}, _query_result(n + 1, "E1"), {"E1"})
        messages.append({"role": "tool", "tool_call_id": call_id, "content": content})
        results.track(len(messages) - 1, handle)
    assert results.compact(messages) == 1
    p.chat(ChatRequest(list(messages), tools=[TOOL, PIVOT]))
    before, after = endpoint.body(1), endpoint.body(2)
    for body in (before, after):
        # one breakpoint closes the system prompt, and the conversation is cached automatically behind it
        assert body["system"][-1]["cache_control"] == {"type": "ephemeral"}
        assert body["cache_control"] == {"type": "ephemeral"}
        assert json.dumps(body).count('"cache_control"') == 2
        assert body["tools"] == before["tools"] and body["system"] == before["system"]
    # the model's turns are replayed byte for byte; only the compacted tool result's content changed
    assert after["messages"][1] == before["messages"][1]
    stubbed = after["messages"][2]["content"][0]
    assert stubbed["tool_use_id"] == "toolu_a" and json.loads(stubbed["content"])["handle"] == "R1"


def test_the_responses_input_changes_only_in_the_compacted_output(monkeypatch, tmp_path):
    import respx

    from tests.test_agent_provider_openai_responses import API, TOOL, build, call, reasoning, sent, streamed
    from tests.test_agent_provider_openai_responses import response as reply
    results = _compacting(monkeypatch, tmp_path)
    with respx.mock(base_url=API, assert_all_called=False) as api:
        route = api.post("/responses").mock(side_effect=[
            streamed(reply(reasoning(1), call(call_id="call_a"))), streamed(reply(reasoning(2), call(call_id="call_b"))),
            streamed(reply(reasoning(3), call(call_id="call_c")))])
        p, _ = build()
        messages = [{"role": "system", "content": "You are a test."}, {"role": "user", "content": "go"}]
        for n, call_id in enumerate(("call_a", "call_b")):
            turn = p.chat(ChatRequest(list(messages), tools=[TOOL]))
            assert turn.ok, turn.error
            messages.append(turn.assistant_message())
            handle, content = results.enter(n + 1, "query_source", {}, _query_result(n + 1, "E1"), {"E1"})
            messages.append({"role": "tool", "tool_call_id": call_id, "content": content})
            results.track(len(messages) - 1, handle)
        assert results.compact(messages) == 1
        assert p.chat(ChatRequest(list(messages), tools=[TOOL])).ok
        before, after = sent(route, 1)["input"], sent(route, 2)["input"]
    assert len(before) == len(after) - 3
    changed = [n for n in range(len(before)) if before[n] != after[n]]
    assert len(changed) == 1 and after[changed[0]]["type"] == "function_call_output"
    assert after[changed[0]]["call_id"] == "call_a" and json.loads(after[changed[0]]["output"])["handle"] == "R1"
    assert SECRET not in json.dumps(after)


def test_every_session_offers_get_result_with_the_same_definition():
    repo, *_ = _hunt()
    a, b = Toolbox(repo, "h1", session_id="s1"), Toolbox(repo, "h1", session_id="s2")
    assert "get_result" in a.registry
    assert [t for t in a.provider_tools() if t.name == "get_result"] == [
        t for t in b.provider_tools() if t.name == "get_result"]
    assert a.execute("get_result", {"handle": "R1"})["status"] == "unsupported"
    assert a.execute("get_result", {"handle": "E1"})["status"] == "refused"


# ---- a compacting session ends as it did before: budget, secret guard, analyst stop ---------------------------------

def _queries_then_finish(count: int, *, fail_at: int | None = None, error: BaseException | None = None):
    def script(anchor, _evidence, _hypothesis):
        query = {"anchor": anchor, "source": "net-a", "query": {"match_all": {}}}
        steps = [_cached_reply([ToolCall(f"q{i}", "query_source", query, json.dumps(query))])
                 for i in range(1, count + 1)]
        steps.append(_cached_reply([ToolCall("f1", "finish_session", {"summary": "Followed the lead to its end."},
                                             "{}")]))
        if fail_at is not None:
            steps[fail_at] = error
        return steps
    return script


STOP_AT = 9     # a call after the first compaction (results of about 5,700 tokens, threshold 10,000)


def test_a_budget_stop_after_a_compaction_ends_the_session_as_before(tmp_path, monkeypatch):
    from romulus.agent.provider import BudgetExhausted
    monkeypatch.setattr(context, "COMPACT_AFTER_TOKENS", 10_000)

    def exhaust(n):
        if n == STOP_AT:
            raise BudgetExhausted("tokens", "1 of 1 budget tokens spent")
    _repo, provider, outcome, *_ = _run(tmp_path, _queries_then_finish(12), before_reserve=exhaust)
    assert outcome["context"]["compactions"] >= 1 and len(provider.requests) == STOP_AT
    assert outcome["state"] == "budget" and outcome["reason"] == "budget:tokens"
    assert outcome["summary"].startswith("Budget stop: ")


def test_a_secret_guard_trip_after_a_compaction_ends_the_session_as_before(tmp_path, monkeypatch):
    from romulus.agent.investigate import SECRET_GUARD_REASON
    from romulus.agent.provider import SecretGuardTripped
    monkeypatch.setattr(context, "COMPACT_AFTER_TOKENS", 10_000)
    tripped = SecretGuardTripped(3, [("ES_PASSWORD", "text")])
    repo, provider, outcome, *_ = _run(tmp_path, _queries_then_finish(12, fail_at=STOP_AT, error=tripped))
    assert outcome["context"]["compactions"] >= 1 and len(provider.requests) == STOP_AT + 1
    assert outcome["state"] == "secret_guard" and outcome["reason"] == SECRET_GUARD_REASON
    assert repo.agent_secret_guard_counts("h1")


def test_an_analyst_stop_after_a_compaction_ends_the_session_as_before(tmp_path, monkeypatch):
    from romulus.agent.investigate import STOPPED_REASON
    monkeypatch.setattr(context, "COMPACT_AFTER_TOKENS", 10_000)
    asked = []

    def ask(n):
        if n == STOP_AT:
            asked.append("lead-1 at 12:00")
    _repo, provider, outcome, *_ = _run(tmp_path, _queries_then_finish(12), before_reserve=ask,
                                        stop=lambda: asked[0] if asked else None)
    assert outcome["context"]["compactions"] >= 1 and len(provider.requests) == STOP_AT
    assert outcome["state"] == "interrupted" and outcome["reason"] == STOPPED_REASON
    assert outcome["summary"].startswith("Stopped by analyst (lead-1 at 12:00).")


# ---- a session paging an oversized result ------------------------------------------------------------------------

def test_a_session_pages_an_oversized_result_counts_its_secrets_and_bounds_rereads(tmp_path, monkeypatch):
    monkeypatch.setattr(context, "COMPACT_AFTER_TOKENS", 1)
    monkeypatch.setattr(context, "KEEP_FULL_RESULTS", 1)

    def script(anchor, _evidence, _hypothesis):
        query = {"anchor": anchor, "source": "net-a", "query": {"match_all": {}}}
        steps = [[ToolCall("q1", "query_source", query, json.dumps(query))]]
        # a model that keeps re-reading: thirty pages asked for, with an allowance of three
        steps += [_get_result(f"g{n}", "q1", min(n, 4)) for n in range(1, 31)]
        steps.append([ToolCall("f1", "finish_session", {"summary": "Paged through the large result."}, "{}")])
        return [_cached_reply(calls) for calls in steps]
    settings = _settings(tmp_path, agent_max_tool_calls_per_session=3)
    repo, provider, outcome, _sizes, *_ = _run(tmp_path, script, settings=settings, rows_per_result=9)
    entered = provider.requests[1].messages[-1]["content"]
    first = json.loads(entered)
    handle = first["paged"]["handle"]
    assert first["paged"]["page"] == 1 and first["paged"]["pages"] >= 4 and first["aliases"]
    assert len(entered) <= SessionResults(settings, context_tokens=1_000_000).cap_chars
    # the secrets removed before the paged result entered are counted once, for the call that sent it
    calls = repo.model_calls("h1")
    assert calls[1]["options"]["redactions"] == {"ES_PASSWORD": 9}
    assert all("redactions" not in call["options"] for n, call in enumerate(calls) if n != 1)
    # re-reads have their own allowance (the session's reads), spend no source read, and close like the others: the
    # model is told, and a reply that makes only a refused re-read ends the session capped
    assert "Tool-call limit reached for re-read tools" in provider.requests[4].messages[-1]["content"]
    assert len(provider.requests) == 5
    assert outcome["state"] == "capped" and outcome["reason"] == (
        "tool-call limit reached and the reply used no remaining tool")
    rows = sorted(repo.agent_tool_calls("h1"), key=lambda row: row["seq"])
    assert [(row["name"], row["status"]) for row in rows] == [
        ("query_source", "complete"), ("get_result", "complete"), ("get_result", "complete"),
        ("get_result", "complete"), ("get_result", "refused")]
    assert rows[4]["refusal_reasons"] == ["$: reread_call_limit"]
    # a re-read page is compacted like a result, to a stub that names the same page
    final = provider.requests[-1].messages
    stub = json.loads(next(m["content"] for m in final if m.get("tool_call_id") == "g1"))
    assert stub == {"compacted": f"a re-read of {handle} page 1; get_result handle={handle} page=1 shows it again",
                    "handle": handle, "page": 1, "pages": first["paged"]["pages"], "tool": "get_result",
                    "of_tool": "query_source"}
    assert SECRET not in json.dumps([m.get("content") for m in final])


def test_text_heavy_in_escapes_never_makes_a_page_larger_than_the_cap(tmp_path):
    settings = _settings(tmp_path)
    results = SessionResults(settings, context_tokens=1_000_000)
    heavy = _query_result(1, "E1")
    heavy["data"]["result"]["search"]["rows_and_aggregations"]["text"] = json.dumps(
        [{"path": "C:\\Windows\\System32\\" + "\\\"q\\\"" * 40 + f"{i}"} for i in range(900)])
    handle, content = results.enter(1, "query_source", {}, heavy, {"E1"})
    pages = json.loads(content)["paged"]["pages"]
    assert pages > 1 and len(content) <= results.cap_chars
    texts = [results.page(handle, n)["text"] for n in range(1, pages + 1)]
    assert all(len(json.dumps(text, ensure_ascii=False)) <= results.page_chars for text in texts)
    assert "".join(texts) == redact_text(json.dumps(heavy, sort_keys=True, ensure_ascii=False), settings)
    results.close()


def test_a_reread_of_a_result_that_fits_is_paged_within_the_cap_too(tmp_path):
    settings = _settings(tmp_path)
    results = SessionResults(settings, context_tokens=1_000_000)
    heavy = {"status": "complete", "data": {"rows": "\\\"" * (results.cap_chars // 4 - 50)}}
    handle, content = results.enter(1, "query_source", {}, heavy, set())
    # it fits, so it enters whole as before; escaped again inside a re-read it would be about twice the cap
    assert content == json.dumps(heavy, sort_keys=True, ensure_ascii=False) and len(content) <= results.cap_chars
    pages = results.entries[handle].pages
    assert pages >= 2
    texts = [results.page(handle, n) for n in range(1, pages + 1)]
    assert all(len(json.dumps(page, ensure_ascii=False)) <= results.cap_chars for page in texts)
    assert "".join(page["text"] for page in texts) == content
    results.close()


def test_the_compaction_threshold_is_at_most_a_quarter_of_a_small_context(tmp_path):
    assert compact_threshold(0) == compact_threshold(1_000_000) == context.COMPACT_AFTER_TOKENS
    assert compact_threshold(32_000) == 8_000
    results = SessionResults(_settings(tmp_path), context_tokens=32_000)
    messages = [{"role": "system", "content": "s"}, {"role": "user", "content": "u"},
                {"role": "assistant", "content": None, "tool_calls": []}]
    for n in range(1, 11):     # ten paged results of about 2,000 tokens: 12,000 stale tokens past the kept four
        handle, content = results.enter(n, "query_source", {}, _query_result(n, "E1"), {"E1"})
        messages.append({"role": "tool", "tool_call_id": f"c{n}", "content": content})
        results.track(len(messages) - 1, handle)
    messages.append({"role": "assistant", "content": None, "tool_calls": []})
    assert results.compact(messages) == 6
    results.close()


def test_a_lone_surrogate_is_stored_and_read_back_unchanged(tmp_path):
    results = SessionResults(_settings(tmp_path))
    odd = {"status": "complete", "data": {"text": "before \ud800 after " + "x" * 50_000}}
    handle, content = results.enter(1, "query_source", {}, odd, set())
    text = json.dumps(odd, sort_keys=True, ensure_ascii=False)
    pages = [results.page(handle, n)["text"] for n in range(1, results.entries[handle].pages + 1)]
    assert "".join(pages) == text and "\ud800" in pages[0]
    assert json.loads(content)["paged"]["text"] == pages[0]
    results.close()


def test_a_paged_envelope_and_a_stub_keep_where_the_safety_flags_are(tmp_path):
    results = SessionResults(_settings(tmp_path))
    flagged = _query_result(1, "E1")
    flagged["data"]["safety_flags"] = [{"code": "A7", "path": f"$.data.result.rows[{i}]", "detections": ["x"],
                                        "reason": "untrusted data contains instruction-shaped content"}
                                       for i in range(12)]
    flagged["data"]["result"]["search"]["rows_and_aggregations"]["text"] = "".join(_rows(i) for i in range(4))
    handle, content = results.enter(1, "query_source", {}, flagged, {"E1"})
    shown = json.loads(content)
    assert "paged" in shown and shown["safety_flags"] == 12
    assert shown["safety_flag_paths"] == [f"$.data.result.rows[{i}]" for i in range(10)]
    assert json.loads(results.entries[handle].stub)["safety_flag_paths"] == shown["safety_flag_paths"]
    results.close()


def test_handles_are_per_session(tmp_path):
    settings = _settings(tmp_path)
    one, two = (SessionResults(settings, tag=session_tag(name)) for name in ("as-one", "as-two"))
    handle, _content = one.enter(1, "query_source", {}, _query_result(1, "E1"), {"E1"})
    other, _content = two.enter(1, "query_source", {}, _query_result(1, "E1"), {"E1"})
    assert handle != other and handle.startswith("R1-") and other.startswith("R1-")
    toolbox = Toolbox(_repo_with_finding()[0], "h1")
    toolbox.results = two
    assert toolbox.execute("get_result", {"handle": other})["status"] == "complete"
    for foreign in (handle, "R1"):
        refused = toolbox.execute("get_result", {"handle": foreign})
        assert refused["status"] == "refused" and refused["data"]["error"]["code"] == "unknown_handle"
        assert "handles are per session" in refused["data"]["error"]["message"]
        assert other.split("-")[1] in refused["data"]["error"]["message"]
    one.close()
    two.close()
