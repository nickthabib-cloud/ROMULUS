"""A session's bounded working context: tool results kept whole on the side, older ones compacted to stubs.

A tool result stays in the session's conversation for every later call of that session, so without a bound the
model's prompt grows with everything it has ever read, and the token budget goes to re-reading old results instead of
investigating. `SessionResults` keeps it bounded:

- Every tool result is stored whole on the side, under a handle (``R<n>``), with every configured secret's text
  already removed. ``get_result handle=R<n> page=<p>`` re-reads it in pages, from that redacted text, so a page cut
  never splits a secret and nothing re-sent was ever unredacted.
- A result larger than one page enters the conversation as its envelope (status, counts, what to read next, the
  aliases it issued) and its first page; the rest is paged through ``get_result``.
- Once the results the model has already been sent, older than the latest `KEEP_FULL_RESULTS`, add up to more than
  `COMPACT_AFTER_TOKENS`, all of them are replaced by stubs at once. Between compactions the conversation is
  append-only, so the provider's prompt cache keeps reading its prefix; a stub, once written, never changes, so the
  stubs of earlier compactions stay part of every later prefix.

A stub names the tool, the arguments it was called with, its status, counts, negative statement, the cursor and the
next chunk it offered, and every citable alias the result issued: aliases stay issued to the session, so a compacted
result's aliases stay citable. It holds no telemetry text. The model's own turns and the results of the tools that
record its work are never compacted: they are its working memory.
"""
from __future__ import annotations

import json
import re
import tempfile
from dataclasses import dataclass, field

from romulus.agent.admission import collect_issued_aliases
from romulus.agent.provider.base import CHARS_PER_TOKEN, PROVIDER_STATE, estimate_tokens, redact_value
from romulus.config import Settings, redact_counted, redact_text

# The latest tool results kept in full at a compaction (of those a stub would replace: write results and short ones
# are never stubbed and not counted here). A reply often makes two to four calls at once, and the next step usually
# compares the newest results with each other; older ones are re-read on demand through their handle.
KEEP_FULL_RESULTS = 4
# A compaction runs once the full results older than the kept ones reach this many estimated tokens. Each compaction
# changes the conversation from its first newly stubbed result on, so the provider writes that tail to its cache again
# once (about 1.25 times the input price) instead of reading it (about 0.1 times); in between, every call re-reads the
# stale results (0.1 times each). Over a session of forty large query results (about 5,700 tokens each) the weighted
# prompt cost is lowest between 32,000 and 48,000 (a compaction every 6 to 9 calls), and rises on either side (more
# rewrites below, more stale re-reads above); the lower end also keeps the largest prompt lower. With a provider that
# bills cached input at the full price, compaction is pure saving, and this threshold only keeps it batched.
COMPACT_AFTER_TOKENS = 32_000
# The most estimated tokens one tool result may add to the conversation: the smaller of this and RESULT_CONTEXT_SHARE
# of the model's context, never under MIN_RESULT_TOKENS. It fits a query_source chunk (12 KB of rows and aggregations)
# and a search page's telemetry allowance (24 KB) with their envelopes in one page; larger content is paged.
RESULT_TOKEN_CAP = 10_000
RESULT_CONTEXT_SHARE = 0.05
MIN_RESULT_TOKENS = 2_000
# Results shorter than this many characters are never stubbed: a stub would not be much shorter.
STUB_MIN_CHARS = 1_600
# The share of a result's character allowance one page of its text takes, measured as it is shown (escaped inside the
# tool message's JSON): the rest is the page envelope (status, counts, up to STUB_ALIASES aliases, the next call).
PAGE_SHARE = 0.75
# How many aliases a stub or a paged envelope lists by name; the rest are counted, and the handle shows them.
STUB_ALIASES = 200
# How many characters of the call's arguments a stub repeats (the call itself stays in the model's own turn).
STUB_ARGUMENT_CHARS = 400
# The stored results of a session stay in memory up to this many bytes and overflow to a temporary file past it:
# nothing a session read is dropped to bound memory. A session's results are bounded by its tool-call allowance.
STORE_MEMORY_BYTES = 8 * 1024 * 1024
# The tools that record the session's work: their results are never stubbed.
NEVER_COMPACTED = frozenset({"open_hypothesis", "update_hypothesis", "propose_finding", "propose_link", "add_note",
                             "request_rule", "finish_session"})
HANDLE_PATTERN = r"^R[1-9][0-9]*$"
_ALIAS_ORDER = re.compile(r"^([A-Z])([0-9]+)$")


def result_token_cap(context_tokens: int) -> int:
    """The most estimated tokens one tool result may add to the conversation, for a model with this context."""
    if not context_tokens:
        return RESULT_TOKEN_CAP
    return max(MIN_RESULT_TOKENS, min(RESULT_TOKEN_CAP, int(context_tokens * RESULT_CONTEXT_SHARE)))


def _alias_key(alias: str) -> tuple:
    match = _ALIAS_ORDER.match(alias)
    return (match.group(1), int(match.group(2))) if match else (alias, 0)


def _bounded(text: str, limit: int) -> str:
    return text if len(text) <= limit else f"{text[:limit]}…[{len(text) - limit} chars omitted]"


@dataclass
class _Entry:
    handle: str
    tool: str
    arguments: str              # the call's arguments as JSON text, secrets removed, bounded
    offset: int                 # where the redacted result text starts in the store, in bytes
    length: int                 # its length in bytes
    chars: int                  # its length in characters
    bounds: list[int]           # where each page of its text starts, in characters, and where the last one ends
    stub: str                  # the stub that replaces it at a compaction (computed once: it never changes)
    envelope: dict = field(default_factory=dict)

    @property
    def pages(self) -> int:
        return len(self.bounds) - 1


def _shown_length(text: str) -> int:
    """How many characters `text` takes as a JSON string inside a tool message (its escapes counted)."""
    return len(json.dumps(text, ensure_ascii=False))


def _page_bounds(text: str, budget: int) -> list[int]:
    """Where each page of `text` starts, and where the last ends: each page as long as fits in `budget` characters
    once escaped as a JSON string, so text heavy in quotes and backslashes never makes a page larger."""
    bounds, start = [0], 0
    while start < len(text):
        low, high = start + 1, min(len(text), start + budget)
        if _shown_length(text[start:high]) <= budget:
            low = high
        else:
            while low < high:      # the longest prefix that fits (one character always does)
                middle = (low + high + 1) // 2
                if _shown_length(text[start:middle]) <= budget:
                    low = middle
                else:
                    high = middle - 1
        bounds.append(low)
        start = low
    return bounds if len(bounds) > 1 else [0, 0]


@dataclass
class _Slot:
    """A tool message in the conversation that a compaction may stub."""
    index: int                  # its position in the session's messages
    handle: str
    tool: str
    stub: str
    tokens: int                 # its content's estimated tokens while it is in full
    stubbed: bool = False


class SessionResults:
    """One session's tool results: stored whole, entered bounded, re-read by handle, compacted in batches."""

    def __init__(self, settings: Settings, *, context_tokens: int = 0):
        self.settings = settings
        self.cap_tokens = result_token_cap(context_tokens)
        self.cap_chars = int(self.cap_tokens * CHARS_PER_TOKEN)
        self.page_chars = max(1_000, int(self.cap_chars * PAGE_SHARE))
        # open for the session's life: the session closes it (close()) however it ends
        self.store = tempfile.SpooledTemporaryFile(max_size=STORE_MEMORY_BYTES, mode="w+b")  # noqa: SIM115
        self.entries: dict[str, _Entry] = {}
        self.slots: list[_Slot] = []
        # secret replacements made in results entered already redacted (paged ones), by setting: added to the counts
        # of the call that sends them, as the provider counts what it redacts itself
        self.pending_redactions: dict[str, int] = {}
        self.compactions = 0
        self.stubbed = 0

    def close(self) -> None:
        self.store.close()

    # ---- entering a result ------------------------------------------------------------------------------------
    def enter(self, seq: int, tool: str, arguments, result: dict, aliases: set[str]) -> tuple[str, str]:
        """Store `result` (the result of call `seq` of the session, run as `tool` with `arguments`, which issued
        `aliases`) and return its handle and the content its tool message carries: the result's JSON as before when
        it fits one page, else its envelope and first page."""
        handle = f"R{seq}"
        text = json.dumps(result, sort_keys=True, ensure_ascii=False, default=str)
        counts: dict[str, int] = {}
        redacted = redact_counted(text, self.settings, counts)
        encoded = redacted.encode("utf-8")
        self.store.seek(0, 2)
        offset = self.store.tell()
        self.store.write(encoded)
        shown = redact_value(json.loads(json.dumps(result, default=str)), self.settings)
        fits = len(text) <= self.cap_chars
        bounds = [0, len(redacted)] if fits else _page_bounds(redacted, self.page_chars)
        argument_text = _bounded(redact_text(json.dumps(arguments, sort_keys=True, ensure_ascii=False, default=str),
                                             self.settings), STUB_ARGUMENT_CHARS)
        envelope = self._envelope(tool, shown, sorted(aliases, key=_alias_key))
        entry = _Entry(handle, tool, argument_text, offset, len(encoded), len(redacted), bounds, "", envelope)
        pages = entry.pages
        entry.stub = json.dumps(self._stub(entry), sort_keys=True, ensure_ascii=False)
        self.entries[handle] = entry
        if fits:
            return handle, text
        for name, count in counts.items():
            self.pending_redactions[name] = self.pending_redactions.get(name, 0) + count
        paged = {**envelope, "paged": {
            "handle": handle, "page": 1, "pages": pages, "encoding": "json", "text": redacted[:bounds[1]],
            "message": (f"This result is larger than one page: this is page 1 of {pages} of its JSON text. Read the "
                        f"rest with get_result handle={handle} page=2 (and so on). The aliases it issued are listed "
                        "above and are citable now."),
            "next": f"get_result handle={handle} page=2"}}
        return handle, json.dumps(paged, sort_keys=True, ensure_ascii=False)

    def track(self, index: int, handle: str) -> None:
        """Record that the tool message at `index` of the conversation carries the result `handle`."""
        entry = self.entries[handle]
        self.slots.append(_Slot(index, handle, entry.tool, entry.stub, 0))

    def track_reread(self, index: int, handle: str, page: int, content: str) -> None:
        """Record a get_result page at `index`: compacted like a result, to a stub pointing at the same page."""
        entry = self.entries.get(handle)
        if entry is None:
            return
        stub = json.dumps({"compacted": (f"a re-read of {handle} page {page}; get_result handle={handle} "
                                         f"page={page} shows it again"),
                           "handle": handle, "page": page, "pages": entry.pages, "tool": "get_result",
                           "of_tool": entry.tool}, sort_keys=True, ensure_ascii=False)
        self.slots.append(_Slot(index, handle, "get_result", stub, estimate_tokens(content)))

    def take_redactions(self) -> dict[str, int]:
        counts, self.pending_redactions = self.pending_redactions, {}
        return counts

    # ---- reading a result again -------------------------------------------------------------------------------
    def page(self, handle: str, page: int) -> dict:
        """One page of a stored result's redacted JSON text, with the call that reads the next."""
        entry = self.entries.get(handle)
        if entry is None:
            return {"error": {"code": "unknown_handle",
                              "message": f"no result {handle} in this session; handles are R<n>, as stubs name them"}}
        if page > entry.pages:
            return {"error": {"code": "page_out_of_range",
                              "message": f"result {handle} has {entry.pages} page(s)"}}
        self.store.seek(entry.offset)
        text = self.store.read(entry.length).decode("utf-8")
        part = text[entry.bounds[page - 1]:entry.bounds[page]]
        return {"handle": handle, "tool": entry.tool, "arguments": entry.arguments, "page": page,
                "pages": entry.pages, "encoding": "json", "text": part,
                "next": f"get_result handle={handle} page={page + 1}" if page < entry.pages else None}

    # ---- compaction -------------------------------------------------------------------------------------------
    def compact(self, messages: list[dict]) -> int:
        """Stub, in `messages`, every full tool result the model has been sent that is older than the latest
        KEEP_FULL_RESULTS, once those add up to COMPACT_AFTER_TOKENS; returns how many were stubbed (0: unchanged).
        Only tool messages' content changes: the model's turns, their provider state and every tool_call_id stay."""
        last_assistant = max((i for i, m in enumerate(messages) if m.get("role") == "assistant"), default=-1)
        # the full results a stub would replace: the results of the tools that record the session's work, and
        # results too short to gain from a stub, stay as they are and are not counted among the kept ones
        full = [slot for slot in self.slots if not slot.stubbed and slot.tool not in NEVER_COMPACTED
                and len(str(messages[slot.index].get("content") or "")) >= STUB_MIN_CHARS]
        for slot in full:
            if not slot.tokens:
                slot.tokens = estimate_tokens(str(messages[slot.index].get("content") or ""))
        kept = {id(slot) for slot in full[-KEEP_FULL_RESULTS:]} if KEEP_FULL_RESULTS else set()
        # a result the model has not been sent yet (after its last turn) is never stubbed
        candidates = [slot for slot in full if id(slot) not in kept and slot.index < last_assistant]
        if sum(slot.tokens for slot in candidates) < COMPACT_AFTER_TOKENS:
            return 0
        for slot in candidates:
            message = messages[slot.index]
            if message.get("role") != "tool":
                raise ValueError(f"message {slot.index} is not a tool result")
            messages[slot.index] = {**message, "content": slot.stub}
            slot.stubbed = True
        self.compactions += 1
        self.stubbed += len(candidates)
        return len(candidates)

    # ---- what a stub and an envelope say ----------------------------------------------------------------------
    @staticmethod
    def _envelope(tool: str, result: dict, aliases: list[str]) -> dict:
        """The typed fields of a result that say what it found and what to read next: never telemetry text."""
        out: dict = {"tool": tool, "status": result.get("status"), "counts": result.get("counts"),
                     "more": result.get("more")}
        coverage = result.get("coverage")
        if isinstance(coverage, dict):
            out["coverage"] = {"status": coverage.get("status"), "gaps": len(coverage.get("gaps") or [])}
        data = result.get("data") if isinstance(result.get("data"), dict) else {}
        error = data.get("error")
        if isinstance(error, dict) and isinstance(error.get("code"), str):
            out["error_code"] = error["code"]
        if data.get("safety_flags"):
            out["safety_flags"] = len(data["safety_flags"])
        inner = data.get("result") if isinstance(data.get("result"), dict) else {}
        if inner.get("cursor"):
            out["cursor"] = inner["cursor"]
        search = inner.get("search") if isinstance(inner.get("search"), dict) else None
        if search is not None:
            for key in ("negative", "statement", "total", "returned", "discarded", "source", "repeated",
                        "gaps_and_caveats_omitted"):
                if search.get(key) is not None:
                    out[key] = search[key]
            if search.get("gaps_and_caveats"):
                out["gaps_and_caveats"] = len(search["gaps_and_caveats"])
            chunk = search.get("rows_and_aggregations")
            if isinstance(chunk, dict) and chunk.get("fetch"):
                out["next_chunk"] = chunk["fetch"]
        if "evidence" in inner or "raw_evidence" in inner:
            out["kept"] = {"evidence": len(inner.get("evidence") or []),
                           "raw_records": len(inner.get("raw_evidence") or [])}
        out["aliases"] = aliases[:STUB_ALIASES]
        if len(aliases) > STUB_ALIASES:
            out["aliases_not_listed"] = len(aliases) - STUB_ALIASES
        return out

    @staticmethod
    def _stub(entry: _Entry) -> dict:
        return {**entry.envelope, "handle": entry.handle, "pages": entry.pages, "arguments": entry.arguments,
                "compacted": (f"This result was compacted to save context. Its aliases above stay citable; "
                              f"get_result handle={entry.handle} page=1 re-reads it in full "
                              f"({entry.pages} page(s)).")}


def issued_in(result: dict, tool: str, issued: set[str]) -> set[str]:
    """The aliases `result` of `tool` issued to the session (those in its trusted fields the session now holds)."""
    return {alias for alias in collect_issued_aliases(result, source="tool", tool_name=tool) if alias in issued}


def _is_stub(content) -> bool:
    try:
        value = json.loads(content) if isinstance(content, str) and content.startswith("{") else None
    except ValueError:
        return False
    return isinstance(value, dict) and "compacted" in value and "handle" in value


def prompt_composition(messages: list[dict], tools: list | None = None) -> dict:
    """Estimated tokens of one request by part: the system prompt, the opening context (dossier and hypothesis),
    tool definitions, tool results by tool (stubs apart), the model's own turns (their provider state apart) and the
    controller's later messages. Used to measure how a session's prompts grow."""
    out: dict = {"system": 0, "context": 0, "tool_definitions": 0, "tool_results": {}, "stubs": 0,
                 "model_turns": 0, "model_state": 0, "controller": 0}
    names: dict[str, str] = {}
    seen_user = False
    for message in messages:
        role = message.get("role")
        if role == "assistant":
            for call in message.get("tool_calls") or []:
                names[call.get("id")] = (call.get("function") or {}).get("name", "?")
            state = message.get(PROVIDER_STATE)
            out["model_state"] += estimate_tokens(json.dumps(state, sort_keys=True, default=str)) if state else 0
            out["model_turns"] += estimate_tokens(json.dumps(
                {k: v for k, v in message.items() if k != PROVIDER_STATE}, sort_keys=True, default=str))
        elif role == "tool":
            tokens = estimate_tokens(json.dumps(message, sort_keys=True, default=str))
            if _is_stub(message.get("content")):
                out["stubs"] += tokens
            else:
                name = names.get(message.get("tool_call_id"), "?")
                out["tool_results"][name] = out["tool_results"].get(name, 0) + tokens
        elif role == "system":
            out["system"] += estimate_tokens(json.dumps(message, sort_keys=True, default=str))
        elif not seen_user:
            seen_user = True
            out["context"] += estimate_tokens(json.dumps(message, sort_keys=True, default=str))
        else:
            out["controller"] += estimate_tokens(json.dumps(message, sort_keys=True, default=str))
    if tools:
        out["tool_definitions"] = estimate_tokens(json.dumps([t.__dict__ for t in tools], sort_keys=True))
    out["tool_results_total"] = sum(out["tool_results"].values())
    out["total"] = (out["system"] + out["context"] + out["tool_definitions"] + out["tool_results_total"]
                    + out["stubs"] + out["model_turns"] + out["model_state"] + out["controller"])
    return out
