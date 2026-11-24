"""The AI agent's packet reads (read_session), run in the hunt layer.

The agent names one Arkime session it has already seen in this hunt, only by an alias ROMULUS issued: the evidence of
an Arkime session record (a net_session event), a packet-content event (http_body, tcp_stream), or a raw record of an
Arkime session returned by its own viewer query. The model never supplies a session id, a path, a filter, a port, a
URL or a byte range. `SessionReader.refusal` decides, before any source query, whether the record names a session of
this hunt's Arkime sources that can overlap the hunt window.

A read then:

1. answers from the packet content this hunt already holds for the session (what the packet stage, or an earlier read,
   kept): its events and findings are returned and nothing is fetched again;
2. otherwise re-reads the session's own record from the hunt's Arkime session index by its id (a typed `ids` query)
   and every saved document of a long session by typed equality on its endpoints and first packet, checks that it
   overlaps the hunt window, and reserves one read under the hunt's session-read caps;
3. fetches the session's packets once through the packet stage's own fetcher (every segment, merged in packet order,
   byte capped), and runs the stage's own fixed TShark extraction on them: the HTTP rebuild (`http_body` events) for a
   session Arkime saw HTTP in, and the cleartext stream analysis (one `tcp_stream` event, with its interactive-shell
   indicators) for any TCP session. The stream filter is built only from the session record's typed endpoints;
4. saves the extracted events as citable evidence (E aliases), runs the packet rules over them and publishes their
   matches through the normal admission path as findings reached by the agent; and
5. returns bounded previews of what was read: response headers' typed values and body excerpts, and the conversation's
   first turns, each line made safe to show (`detect.packets.show`) after recognised credentials are masked. Packet
   content is untrusted telemetry: it is never an instruction, and only the typed events are citable.

Every way a read can lose content (a cap, a failed or truncated fetch, a TShark run that failed, an unparseable frame,
a response TShark could not rebuild) makes the result partial with its reason, in the result and its coverage cell.
Nothing rebuilt is never a negative. Work files live in a private directory under the hunt home, removed afterwards.
"""
from __future__ import annotations

import json
import logging
import re
import shutil
import tempfile
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from time import perf_counter

from romulus.agent.models import PivotCoverage, PivotResult
from romulus.config import Settings, redact_text
from romulus.decide.policy import candidate_id as decided_candidate_id
from romulus.detect.packets import PASSWORD_PROMPT, _clean, _text, show
from romulus.detect.registry import bind_windows_site, fresh_direct_pack
from romulus.detect.web_attacks import _credential_name, _redact_uri
from romulus.evidence.typed import TypedEvent
from romulus.evidence.zeek_credentials import strip_uri_userinfo
from romulus.hunt import packets as stage
from romulus.hunt.expansion import _target_names
from romulus.hunt.pivot import (
    _AGENT_CAP_EXPLAINED,
    MAX_EVENT_SUMMARIES,
    MAX_SEARCH_ENTITIES,
    _event_entities,
    _range,
    _summary,
    _time_spread,
)
from romulus.hunt.publish import publish_match
from romulus.hunt.stage import PCAP_PREFIX
from romulus.sources.es import SourceError, WriteAttemptBlocked
from romulus.sources.models import Window
from romulus.sources.packets import SESSION_ID, ArkimePackets, PacketError, stream_key
from romulus.store.db import digest

log = logging.getLogger("romulus.agent_session")

READ_PURPOSE = "agent:read_session"
NOTHING_STATEMENT = ("no content was rebuilt from this session's packets; this is not a confirmed absence: the packets "
                     "may be missing from the capture, encrypted, or in a protocol the extraction does not rebuild")
STAGED_NOTE = ("already read in this hunt (by the packet stage or an earlier read): its stored events and findings "
               "are returned; the packets were not fetched again")
STAGED_DETAIL = ("the packet stage keeps only the events its rules retained, so the stored events are not everything "
                 "the session holds")
# what one read lists and keeps: its saved events (each citable), the findings it names, its previews
MAX_SAVED_EVENTS = 200
MAX_LISTED_CANDIDATES = 100
MAX_PREVIEW_RESPONSES = 10
MAX_PREVIEW_LINES = 24              # of one response body's excerpt
MAX_TURN_LINES = 12                 # of one conversation turn
MAX_CONTENT_BYTES = 48_000          # all previews of one read, as JSON text
MAX_LINE_CHARS = 200
MAX_TRANSCRIPT_TURNS = 60
MAX_TURN_BYTES = 4_096
MAX_REASONS = 20
MAX_LISTED_IDS = 20
ERROR_CHARS = 300
WITHHELD = "[withheld]"

# Credential forms masked in previews (the typed events and their raw copies never hold this text).
_SECRET_HEADERS = frozenset({"authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key",
                             "x-auth-token", "api-key", "apikey", "x-access-token", "x-csrf-token", "x-xsrf-token"})
_HEADER = re.compile(r"^(\s*)([A-Za-z0-9_-]{1,64})(\s*:\s*)(.*)$")
# a line protocol's credential command and its arguments: FTP and POP3 PASS, SMTP and POP3 AUTH, IMAP's tagged LOGIN
# and AUTHENTICATE (the arguments go; a prompt such as "Password:" or "Last login:" is no command)
_COMMAND = re.compile(r"(?i)^(\s*)(PASS|PASSWORD|AUTH)\s+(\S.*)$")
_TAGGED = re.compile(r"(?i)^(\s*\S{1,32}\s+)(LOGIN|AUTHENTICATE)\s+(\S.*)$")
_PAIR = re.compile(r"""(["']?)([A-Za-z0-9_.\-]{1,64})\1(\s*[=:]\s*)("[^"]*"?|'[^']*'?|[^\s&;,"']+)""")
# a prompt that asks for a secret (the next text the other side sends is withheld), and a server's request for the next
# part of an authentication exchange (SMTP 334, IMAP and POP "+" continuations)
_SECRET_PROMPT = re.compile(r"(?i)\b(?:pass(?:word|phrase|code)?|passcode|pin|secret|token|otp)\s*[:?]\s*$")
_CONTINUATION = re.compile(r"^(?:334|\+)(?:\s|$)")
_LINE_SPLIT = re.compile(rb"\r\n|\r\x00|\n|\r")


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _bounded(text, limit: int = ERROR_CHARS) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= limit else f"{text[:limit]}…[{len(text) - limit} chars omitted]"


def _epoch_ms(value) -> datetime | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        return datetime.fromtimestamp(value / 1000, UTC)
    except (OverflowError, OSError, ValueError):
        return None


def _iso(value) -> datetime | None:
    try:
        moment = datetime.fromisoformat(str(value))
    except ValueError:
        return None
    return _utc(moment) if moment.tzinfo is not None else None


class Masker:
    """Masks recognised credentials in preview text, line by line, with the state a conversation needs: the text one
    side sends after the other asked for a password (or the next part of an authentication exchange) is withheld until
    that side ends a line."""

    def __init__(self, settings: Settings | None):
        self.settings = settings
        self.secret_owed: str | None = None          # the side whose next text is a secret

    def line(self, text: str) -> str:
        header = _HEADER.match(text)
        if header and (header.group(2).casefold() in _SECRET_HEADERS or _credential_name(header.group(2))):
            text = f"{header.group(1)}{header.group(2)}{header.group(3)}{WITHHELD}"
        command = _COMMAND.match(text) or _TAGGED.match(text)
        if command:
            text = f"{command.group(1)}{command.group(2)} {WITHHELD}"
        text = _PAIR.sub(lambda m: (f"{m.group(1)}{m.group(2)}{m.group(1)}{m.group(3)}{WITHHELD}"
                                    if _credential_name(m.group(2)) else m.group(0)), text)
        if "://" in text:
            text = strip_uri_userinfo(text)[0]
        if self.settings is not None:
            text = redact_text(text, self.settings)
        return text

    def turn(self, side: str, raw: bytes) -> dict:
        """One side's bytes in a conversation turn, as preview lines (or a count of binary bytes)."""
        pieces = _LINE_SPLIT.split(raw)
        cleaned = [_clean(piece) for piece in pieces]
        if any(item is None for item in cleaned):
            return {"from": side, "binary_bytes": len(raw)}
        ended = len(pieces) > 1
        if self.secret_owed == side:
            if ended:
                self.secret_owed = None
            return {"from": side, "withheld": "text sent after a password prompt or an authentication challenge",
                    "bytes": len(raw)}
        lines = [item for item in cleaned if item]
        last = lines[-1] if lines else ""
        if lines and (PASSWORD_PROMPT.search(last) or _SECRET_PROMPT.search(last) or _CONTINUATION.match(last)):
            self.secret_owed = "client" if side == "server" else "server"
        shown = [show(self.line(item), MAX_LINE_CHARS) for item in lines[:MAX_TURN_LINES]]
        out = {"from": side, "lines": shown}
        if len(lines) > MAX_TURN_LINES:
            out["lines_not_shown"] = len(lines) - MAX_TURN_LINES
        return out


def body_excerpt(head: bytes, settings: Settings | None) -> dict:
    """A response body's first bytes as preview lines, or a note that they are binary."""
    if not head:
        return {"excerpt": [], "excerpt_note": "empty body"}
    text = _text(head)
    if text is None:
        return {"excerpt": None, "excerpt_note": "binary content (not shown)"}
    masker = Masker(settings)
    lines = text.splitlines()
    out = {"excerpt": [show(masker.line(line), MAX_LINE_CHARS) for line in lines[:MAX_PREVIEW_LINES]]}
    if len(lines) > MAX_PREVIEW_LINES:
        out["excerpt_lines_not_shown"] = len(lines) - MAX_PREVIEW_LINES
    return out


def transcript(data: dict[str, bytes], chunks, settings: Settings | None) -> tuple[list[dict], int]:
    """The conversation's first turns (consecutive bytes of one side are one turn), each bounded and masked; and how
    many turns were not shown."""
    turns: list[tuple[str, int, int]] = []
    for chunk in chunks:
        if turns and turns[-1][0] == chunk.direction and turns[-1][2] == chunk.offset:
            direction, start, _end = turns[-1]
            turns[-1] = (direction, start, chunk.offset + chunk.length)
        else:
            turns.append((chunk.direction, chunk.offset, chunk.offset + chunk.length))
    masker = Masker(settings)
    out = []
    for direction, start, end in turns[:MAX_TRANSCRIPT_TURNS]:
        side = "client" if direction == "c2s" else "server"
        raw = data[direction][start:min(end, start + MAX_TURN_BYTES)]
        item = masker.turn(side, raw)
        if end - start > MAX_TURN_BYTES:
            item["bytes_not_shown"] = end - start - MAX_TURN_BYTES
        out.append(item)
    return out, max(0, len(turns) - MAX_TRANSCRIPT_TURNS)


class _Ref:
    """The session a read names, resolved from a record the alias points at (never from model text)."""

    def __init__(self, *, index: str, session_id: str, targets: list[str], origin: str,
                 staged_ids: list[str] | None = None, span: tuple[datetime, datetime] | None = None):
        self.index, self.session_id, self.targets, self.origin = index, session_id, targets, origin
        self.staged_ids = staged_ids or []
        self.span = span


class SessionReader:
    """Run one session read through the pivot executor's client, budget and evidence store."""

    def __init__(self, pivot, settings: Settings | None, spend: Callable[[str], str | None], window: Window,
                 packets_factory: Callable[[], object] | None = None):
        self.pivot = pivot
        self.settings = settings or Settings()
        self.spend = spend
        self.window = window
        self.packets_factory = packets_factory

    # ---- what a read names -------------------------------------------------------------------------------------
    def arkime_targets(self) -> list[str]:
        return sorted(target for target, contract in self.pivot.contracts.items()
                      if contract is not None and getattr(contract, "time_field", "") == "firstPacket")

    def _targets_for(self, index: str) -> list[str]:
        """The hunt's Arkime session targets a record from `index` can belong to: those whose name or index patterns
        match it, else those named plainly (an index alias, which cannot be resolved here)."""
        arkime = self.arkime_targets()
        named = [target for target in arkime if _target_names(target, index)]
        return named or [target for target in arkime if not any(ch in target for ch in "*?[,")]

    @staticmethod
    def _refused(code: str, message: str, path: str = "session") -> dict:
        from romulus.agent.refusals import reason
        return {"code": code, "message": message, "reasons": [reason(path, code)]}

    def resolve(self, request) -> _Ref | dict:
        """The session the request's record names, or why it names none this hunt can read (a refusal)."""
        args = request.arguments
        repo, hunt_id = self.pivot.repo, self.pivot.hunt_id
        if not self.arkime_targets():
            return self._refused("no_arkime_source", "this hunt has no Arkime session source: there are no packets "
                                                     "to read")
        if args.raw_record_id is not None:
            rows = repo.agent_raw_records(hunt_id, [args.raw_record_id])
            if not rows:
                return self._refused("not_retained", "the aliased raw record is no longer retained by this hunt")
            row = rows[0]
            if row.get("source_kind") != "arkime_session":
                return self._refused("not_an_arkime_session", (
                    "this raw record is not an Arkime session record; read_session takes the evidence (E...) of an "
                    "Arkime session or packet event, or a raw record (Q...) an arkime: source query returned"))
            index, session_id = str(row["target"]), str(row["native_id"])
            span = None
        else:
            rows = repo.citation_events(hunt_id, [args.evidence_id])
            if not rows:
                return self._refused("not_retained", "the aliased evidence is no longer retained by this hunt")
            event = TypedEvent.model_validate(rows[0]["event"])
            if event.family in ("http_body", "tcp_stream"):
                return self._packet_event(event)
            if event.family != "net_session" or len(event.raw) != 1:
                return self._refused("not_an_arkime_session", (
                    f"this evidence is a {event.family} record, not an Arkime session; read_session takes the "
                    "evidence (E...) of an Arkime session (net_session) or packet event (http_body, tcp_stream), or "
                    "a raw record (Q...) an arkime: source query returned"))
            index, session_id = event.raw[0].target, event.raw[0].native_id
            first, last = _iso(event.get("flow.start")), _iso(event.get("flow.end"))
            span = (first, last) if first is not None and last is not None else None
        if not SESSION_ID.fullmatch(session_id):
            return self._refused("not_an_arkime_session", "the record carries no valid Arkime session id")
        if span is not None and (span[1] < self.window.start or span[0] >= self.window.end):
            return self._refused("outside_hunt_window", (
                f"this session ({span[0].isoformat()} to {span[1].isoformat()}) does not overlap the hunt window "
                f"{self.window.start.isoformat()} to {self.window.end.isoformat()}"))
        targets = self._targets_for(index)
        if not targets:
            return self._refused("not_hunt_arkime_source", (
                "this session's record is not from one of this hunt's Arkime session sources"))
        return _Ref(index=index, session_id=session_id, targets=targets, origin="record", span=span)

    def _packet_event(self, event: TypedEvent) -> _Ref | dict:
        target = event.raw[0].target.partition(":")[2] if event.raw else ""
        if not event.raw or not event.raw[0].target.startswith(f"{stage.PCAP_TARGET}:") \
                or target not in self.arkime_targets():
            return self._refused("not_hunt_arkime_source", (
                "this packet event is not from one of this hunt's Arkime session sources"))
        ids = event.get("arkime.session_ids") or [event.get("arkime.session_id")]
        ids = [item for item in ids if isinstance(item, str) and SESSION_ID.fullmatch(item)]
        if not ids:
            return self._refused("not_an_arkime_session", "this packet event names no valid Arkime session id")
        return _Ref(index=target, session_id=ids[0], targets=[target], origin="packet_event", staged_ids=ids)

    def refusal(self, request) -> dict | None:
        found = self.resolve(request)
        return found if isinstance(found, dict) else None

    # ---- the run -----------------------------------------------------------------------------------------------
    def run(self, case_id: str, request) -> PivotResult:
        started = perf_counter()
        ref = self.resolve(request)
        args = request.arguments
        if isinstance(ref, dict):
            return self._failed(None, [ref["message"]], started)
        pivot = self.pivot
        fingerprint = digest({"case_id": case_id, "tool": request.model_dump(mode="json")})
        task_id = "t-" + fingerprint[:20]
        pivot.repo.upsert_task(task_id, pivot.hunt_id, "pivot", case_id, {
            "purpose": READ_PURPOSE, "index": ref.index, "session_id": ref.session_id, "targets": ref.targets,
            "start": args.start.isoformat(), "end": args.end.isoformat(), "request_digest": fingerprint,
        }, fingerprint, owner_token=pivot.owner_token)
        pivot.repo.update_task(task_id, "leased", attempt=True, owner_token=pivot.owner_token)
        read = _Read(self, case_id, task_id, ref, started)
        try:
            return read.run()
        except Exception as exc:
            log.exception("session read %s failed", ref.session_id)
            return read.fail([f"the session read failed: {type(exc).__name__}: {_bounded(exc)}"])

    def _failed(self, target, reasons, started) -> PivotResult:
        return PivotResult(status="failed", reasons=sorted(set(reasons)),
                           coverage=[self._cell(target, "failed", reasons, 0)],
                           duration_ms=int((perf_counter() - started) * 1000),
                           query={"negative": "unresolved", "statement": NOTHING_STATEMENT})

    def _cell(self, target: str | None, status: str, reasons: list[str], returned: int,
              span: tuple[datetime, datetime] | None = None) -> PivotCoverage:
        start, end = span or (self.window.start, self.window.end)
        start, end = max(start, self.window.start), min(end, self.window.end)
        if start >= end:
            start, end = self.window.start, self.window.end
        unresolved = [] if status == "complete" else [
            _range(start, end, "; ".join(reasons[:3]) or "session read incomplete")]
        return PivotCoverage(target=f"{stage.PCAP_TARGET}:{target}" if target else stage.PCAP_TARGET, dataset=None,
                             start=start, end=end, status=status, reasons=sorted(set(reasons))[:MAX_REASONS],
                             returned=returned, total=None, unresolved_ranges=unresolved)


class _Read:
    """One read's state: what it found, kept, published and lost."""

    def __init__(self, reader: SessionReader, case_id: str, task_id: str, ref: _Ref, started: float):
        self.reader, self.case_id, self.task_id, self.ref, self.started = reader, case_id, task_id, ref, started
        self.pivot = reader.pivot
        self.settings = reader.settings
        self.target: str | None = ref.targets[0] if len(ref.targets) == 1 else None
        self.reasons: list[str] = []
        self.notes: list[str] = []
        self.events: dict[str, TypedEvent] = {}
        self.not_kept = 0
        self.candidates: list[str] = []
        self.responses: list[dict] = []
        self.responses_not_shown = 0
        self.stream: dict | None = None
        self.segments: list[dict] = []
        self.fetched = 0
        self.span: tuple[datetime, datetime] | None = ref.span
        self.direct: list | None = None
        self.held = False                    # answered from packet content the hunt already held

    # ---- outcome ------------------------------------------------------------------------------------------------
    def fail(self, reasons: list[str], *, query: dict | None = None) -> PivotResult:
        repo = self.pivot.repo
        repo.update_task(self.task_id, "failed", outcome={"completeness": "failed", "reasons": reasons[:MAX_REASONS]},
                         error=reasons[0], owner_token=self.pivot.owner_token)
        result = self.reader._failed(self.target, reasons, self.started)
        result.task_ids = [self.task_id]
        result.query = {**result.query, **self._session_view(), **(query or {})}
        return result

    def _session_view(self) -> dict:
        view: dict = {"session": {"origin": self.ref.origin, "arkime_session_ids": (
            [seg["_id"] for seg in self.segments][:MAX_LISTED_IDS] or [self.ref.session_id])}}
        if self.target:
            view["session"]["source"] = f"arkime:{self.target}"
        if self.segments:
            src = self.segments[0]["_source"]
            client, server = src.get("source") or {}, src.get("destination") or {}
            view["session"].update(
                client=f"{client.get('ip')}:{client.get('port')}", server=f"{server.get('ip')}:{server.get('port')}",
                protocols=sorted({str(p) for seg in self.segments for p in _list(seg["_source"].get("protocol"))}),
                segments=len(self.segments))
        if self.span is not None:
            view["session"].update(first_packet=self.span[0].isoformat(), last_packet=self.span[1].isoformat())
        return view

    def finish(self) -> PivotResult:
        pivot = self.pivot
        reasons = list(dict.fromkeys(self.reasons))
        status = "partial" if reasons else "complete"
        events = list(self.events.values())
        # content was found when a response was rebuilt, a stream carried bytes, or the hunt already held content
        stream_bytes = (self.stream or {}).get("client_bytes", 0) or (self.stream or {}).get("server_bytes", 0)
        found = (bool(self.responses) or bool(stream_bytes) or self.held
                 or any(event.family == "http_body" for event in events))
        entities = {(entity.kind, entity.value, entity.role): entity
                    for event in events for entity in _event_entities(event)}
        if len(entities) > MAX_SEARCH_ENTITIES:
            reasons.append(f"read_entities_listed:{MAX_SEARCH_ENTITIES}:of:{len(entities)}")
            entities = {key: entities[key] for key in sorted(entities)[:MAX_SEARCH_ENTITIES]}
        candidates = list(dict.fromkeys(self.candidates))
        if len(candidates) > MAX_LISTED_CANDIDATES:
            reasons.append(f"{len(candidates) - MAX_LISTED_CANDIDATES} more finding(s) this read published or "
                           "reached are not listed")
            candidates = candidates[:MAX_LISTED_CANDIDATES]
        pivot.repo.update_task(self.task_id, "executed", outcome={
            "completeness": status, "reasons": reasons[:MAX_REASONS], "returned": len(events),
            "fetched_bytes": self.fetched}, owner_token=pivot.owner_token)
        pivot.repo.update_task(self.task_id, "evaluated", owner_token=pivot.owner_token)
        sampled = _time_spread(events, MAX_EVENT_SUMMARIES, None)
        query = {**self._session_view(),
                 "negative": "content_found" if found else "unresolved",
                 "statement": None if found else NOTHING_STATEMENT,
                 "fetched_bytes": self.fetched, "notes": self.notes[:MAX_REASONS],
                 "content": bounded_content({"http_responses": self.responses,
                                             "http_responses_not_shown": self.responses_not_shown,
                                             "stream": self.stream})}
        return PivotResult(
            status=status, task_ids=[self.task_id], event_ids=[event.id for event in sampled],
            reach_event_ids=self._listed_order(), candidate_ids=candidates, entities=list(entities.values()),
            event_summaries=[_summary(event) for event in sampled], matched_event_count=len(events),
            coverage=[self.reader._cell(self.target, status, reasons, len(events), self.span)],
            reasons=sorted(set(reasons)), duration_ms=int((perf_counter() - self.started) * 1000), query=query)

    def _listed_order(self) -> list[str]:
        """The kept events in the order a result lists them: the ones the previews name first (so the first page
        issues their aliases), then the rest by id."""
        shown = [item.get("evidence") for item in [*(self.stream and [self.stream] or []), *self.responses]]
        first = [event_id for event_id in shown if isinstance(event_id, str) and event_id in self.events]
        return list(dict.fromkeys([*first, *sorted(self.events)]))

    # ---- the steps ----------------------------------------------------------------------------------------------
    def run(self) -> PivotResult:
        if self.ref.staged_ids:
            return self._staged(self.ref.staged_ids)
        held = self._held([self.ref.session_id])
        if held is not None:
            return held
        available = self.pivot.agent_available()
        if available is not None and available[0] == 0:
            cap = available[1]
            explained = _AGENT_CAP_EXPLAINED.get(cap.split(":", 1)[0], "the source-query budget is spent")
            return self.fail([cap, f"{explained}: nothing was read, and nothing was found or ruled out"])
        stop = self._lookup()
        if stop is not None:
            return stop
        held = self._held([seg["_id"] for seg in self.segments])
        if held is not None:
            return held
        return self._read_packets()

    def _held(self, ids: list[str]) -> PivotResult | None:
        """The packet content this hunt already holds for these session ids, as a result; None when it holds none."""
        window = self.reader.window
        found, candidates, complete = self.pivot.repo.packet_session_evidence(
            self.pivot.hunt_id, ids, window.start, window.end)
        if not found:
            if not complete:
                self.notes.append("this hunt holds too much packet content near this session to check all of it "
                                  "for an earlier read; the packets are read again")
            return None
        return self._staged(ids, (found, candidates, complete))

    def _staged(self, ids: list[str], held=None) -> PivotResult:
        window = self.reader.window
        found, candidates, complete = held or self.pivot.repo.packet_session_evidence(
            self.pivot.hunt_id, ids, window.start, window.end)
        if not found:
            return self.fail(["this packet event's session holds no stored packet content in this hunt any more"])
        self.held = True
        self.reasons.append(STAGED_NOTE)
        self.notes.append(STAGED_DETAIL)
        if not complete:
            self.reasons.append("this hunt holds more packet content near this session than one read lists; the "
                                "events listed are the first ones found")
        if len(found) > MAX_SAVED_EVENTS:
            self.reasons.append(f"{len(found) - MAX_SAVED_EVENTS} more stored packet event(s) of this session are "
                                "not listed")
            found = found[:MAX_SAVED_EVENTS]
        rows = self.pivot.repo.citation_events(self.pivot.hunt_id, found)
        for row in rows:
            event = TypedEvent.model_validate(row["event"])
            self.events[event.id] = event
        self.candidates.extend(candidates)
        raws = {}
        raw_ids = sorted({raw_id for row in rows if row["family"] == "http_body" for raw_id in row["raw_ids"] or []})
        for begin in range(0, len(raw_ids), 500):
            for item in self.pivot.repo.raw_records(raw_ids[begin:begin + 500]):
                raws[f"{item['target']}/{item['native_id']}"] = item["source"]
        for event in sorted(self.events.values(), key=lambda item: (item.ts, item.id)):
            if event.family == "http_body":
                self._preview_response(event, raws.get(event.raw[0].key) if event.raw else None)
            elif event.family == "tcp_stream" and self.stream is None:
                self.stream = {"evidence": event.id, "transcript": None,
                               "transcript_note": ("the stored stream event keeps sizes, offsets and indicators, "
                                                   "never payload; its fields are in the event summaries")}
        if self.target is None and self.ref.targets:
            self.target = self.ref.targets[0]
        return self.finish()

    def _spend(self) -> str | None:
        return self.reader.spend(self.task_id)

    def _lookup(self) -> PivotResult | None:
        """Re-read the session's record (and every saved document of a long session) from the hunt's Arkime index."""
        pivot, ref = self.pivot, self.ref
        body = {"query": {"ids": {"values": [ref.session_id]}}, "size": 2}
        doc = None
        errors = []
        for target in ref.targets:
            cap = self._spend()
            if cap is not None:
                return self.fail([cap, "the agent's source-query cap is reached: the session's record was not read"])
            try:
                response = pivot.client.search(target, body)
            except (SourceError, WriteAttemptBlocked) as exc:
                text = _bounded(redact_text(str(exc), self.settings))
                errors.append(f"{target}: the session's record could not be read: {text}")
                continue
            for hit in ((response or {}).get("hits") or {}).get("hits") or []:
                if (isinstance(hit, dict) and hit.get("_id") == ref.session_id and hit.get("_index") == ref.index
                        and isinstance(hit.get("_source"), dict)):
                    doc, self.target = hit, target
                    break
            if doc is not None:
                break
        if doc is None:
            return self.fail([*errors, ("the session's record was not found in this hunt's Arkime session sources "
                                       "(it may have aged out of the index): no packets were read")])
        src = doc["_source"]
        first, last = _epoch_ms(src.get("firstPacket")), _epoch_ms(src.get("lastPacket"))
        if first is None or last is None:
            return self.fail([("the session's record carries no typed first and last packet times: its packets were "
                              "not read")])
        self.span = (first, last)
        window = self.reader.window
        if last < window.start or first >= window.end:
            return self.fail([(f"outside_hunt_window: this session ({first.isoformat()} to {last.isoformat()}) does "
                              "not overlap the hunt window; its packets were not read")])
        segments = [doc]
        contract = pivot.contracts[self.target]
        if stage._can_complete(contract):
            cap = self._spend()
            if cap is not None:
                self.reasons.append(f"{cap}: the agent's source-query cap is reached: the session's other saved "
                                    "documents were not looked up; only the named document's packets are read")
            else:
                more, error = stage._connection_documents(pivot.client, self.target, contract, [doc])
                if error:
                    self.reasons.append(f"the session's other saved documents could not all be read: {_bounded(error)}")
                known = {doc["_id"]}
                segments += [item for item in more if isinstance(item, dict) and item.get("_id") not in known
                             and isinstance(item.get("_source"), dict) and stage._logical(item) == stage._logical(doc)]
        else:
            self.reasons.append("this source cannot be queried by endpoint: only the named document of the session is "
                                "read, so packets saved in its other documents (a long session) are not")
        self.segments = sorted({seg["_id"]: seg for seg in segments}.values(),
                               key=lambda seg: (stage._last_packet(seg), seg["_id"]))
        lasts = [stage._epoch(seg["_source"].get("lastPacket")) for seg in self.segments]
        if all(value is not None for value in lasts):
            self.span = (first, datetime.fromtimestamp(max(lasts), UTC))
        return None

    def _read_packets(self) -> PivotResult:
        settings, pivot = self.settings, self.pivot
        segs = self.segments
        src = segs[0]["_source"]
        protocols = {str(p) for seg in segs for p in _list(seg["_source"].get("protocol"))}
        is_http = "http" in protocols
        is_tcp = src.get("ipProtocol") == 6 or "tcp" in protocols
        if not is_tcp:
            return self.fail([(f"this session is not TCP (Arkime protocols: {', '.join(sorted(protocols)) or 'none'}): "
                              "the extraction rebuilds HTTP and TCP streams only, so its packets were not read")])
        client, server = src.get("source") or {}, src.get("destination") or {}
        try:
            key = stream_key(client.get("ip"), client.get("port"), server.get("ip"), server.get("port"))
        except PacketError:
            return self.fail(["the session's endpoints are not typed addresses and ports: its packets were not read"])
        cap = self._spend()
        if cap is not None:
            return self.fail([cap, "the agent's source-query cap is reached: the packets were not fetched"])
        _ordinal, left, refused = pivot.repo.reserve_agent_session_read(
            pivot.hunt_id, settings.agent_max_session_reads, settings.agent_max_session_read_bytes, self.task_id,
            owner_token=pivot.owner_token, session_id=getattr(pivot, "session_id", None))
        if refused is not None:
            what = ("sessions the agent may read" if refused.startswith("agent_session_reads:")
                    else "packet bytes the agent's reads may fetch")
            return self.fail([refused, (f"the hunt's cap on {what} is reached: the packets were not fetched, and "
                                       "nothing was found or ruled out")])
        packets = self.reader.packets_factory() if self.reader.packets_factory else ArkimePackets(settings)
        per_fetch = getattr(packets, "max_bytes", 32 * 1024 * 1024) if is_http else stage.STREAM_FETCH_BYTES
        budget = min(per_fetch, left)
        root = settings.stage_path
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        work = Path(tempfile.mkdtemp(prefix=PCAP_PREFIX, dir=root))
        try:
            try:
                path, capped, fetched, error = stage._fetch_segments(settings, packets, work, "read", segs, budget)
            except PacketError as exc:
                path, capped, fetched, error = None, False, 0, str(exc)
            self.fetched = fetched
            pivot.repo.record_agent_session_read_bytes(pivot.hunt_id, self.task_id, fetched,
                                                       owner_token=pivot.owner_token)
            if error or path is None:
                return self.fail([f"the packet download failed: {_bounded(error or 'no packets')}"])
            if capped:
                which = ("the hunt's remaining session-read byte budget" if budget < per_fetch
                         else f"the per-read byte cap ({per_fetch // (1024 * 1024)} MiB)")
                self.reasons.append(f"the packet download stopped at {which}: the content read is the session's "
                                    "first bytes only")
            if is_http:
                self._http(work, path, capped)
            else:
                self.notes.append("Arkime saw no HTTP in this session: only the cleartext stream analysis ran")
            self._stream(work, path, capped, key)
        finally:
            shutil.rmtree(work, ignore_errors=True)
            close = getattr(packets, "close", None)
            if callable(close):
                close()
        if self.not_kept:
            self.reasons.append(f"{self.not_kept} extracted event(s) beyond the per-read cap of {MAX_SAVED_EVENTS} "
                                "were judged by the rules but not kept as citable evidence")
        return self.finish()

    # ---- the stage's extraction ---------------------------------------------------------------------------------
    def _keep(self, events: list[TypedEvent], raws: dict[str, dict]) -> None:
        room = MAX_SAVED_EVENTS - len(self.events)
        kept = [event for event in events if event.id not in self.events][:max(0, room)]
        self.not_kept += sum(1 for event in events if event.id not in self.events) - len(kept)
        if kept:
            self.pivot._save_selected_events(kept, raws, {}, [self.task_id])
            for event in kept:
                self.events[event.id] = event

    def _publish(self, pb, matches, raw_sources) -> None:
        pivot = self.pivot
        for match in matches:
            row = publish_match(pivot.repo, pivot.hunt_id, pb, match, self.task_id, raw_sources,
                                source_case_id=self.case_id, owner_token=pivot.owner_token)
            self._published(pb, match, row)

    def _published(self, _pb, match, row: dict | None) -> None:
        """Name the finding a match published, or the one already published for it (the packet stage's own)."""
        identity = row["id"] if row is not None else decided_candidate_id(match, self.pivot.hunt_id)
        if row is not None or self.pivot.repo.candidate(identity) is not None:
            self.candidates.append(identity)

    def _direct(self, events: list[TypedEvent], raws: dict[str, dict]) -> None:
        """The direct rules over the extracted events, as over any record the agent's pivots return."""
        if self.direct is None:
            self.direct = bind_windows_site(fresh_direct_pack(), getattr(self.pivot, "site_facts", None))
        pivot = self.pivot
        for playbook in self.direct:
            for match in playbook.consume(events):
                row = publish_match(pivot.repo, pivot.hunt_id, playbook, match, self.task_id, raws,
                                    source_case_id=self.case_id, owner_token=pivot.owner_token)
                self._published(playbook, match, row)

    def _http(self, work: Path, path: Path, capped: bool) -> None:
        segs = self.segments
        run = stage._Target(self.settings, self.target, self.reader.window, work, None, self.pivot.heartbeat,
                            repo=self.pivot.repo, hunt_id=self.pivot.hunt_id, owner_token=self.pivot.owner_token)
        run.task_id, run.source_case_id = self.task_id, self.case_id

        def observe(events, raws):
            self._keep(events, raws)
            self._direct(events, raws)
            for event in events:
                self._preview_response(event, raws.get(event.raw[0].key))

        run.observe = observe
        run.on_published = self._published
        try:
            run.index(segs)
            what = f"one session's {len(segs)} segments" if len(segs) > 1 else "1 session document"
            run.read_capture(0, segs, what, path, capped)
            run.account()
            for pb in run.pack:
                matches = run.finalized(pb)
                self._publish(pb, matches, run.raw_sources)
                self.reasons.extend(pb.limit_reasons())
            self.reasons.extend(f"HTTP: {item}" for item in run.partial)
            self.notes.extend(f"HTTP: {item}" for item in run.notes)
            if run.c["outside_window"]:
                self.notes.append(f"HTTP: {run.c['outside_window']} response(s) outside the hunt window were not "
                                  "judged")
        finally:
            run.close()

    def _stream(self, work: Path, path: Path, capped: bool, key) -> None:
        run = stage._StreamTarget(self.settings, self.target, self.reader.window, work, None, self.pivot.heartbeat)

        def observe(event, raw, streams, analysis):
            if event is not None:
                self._keep([event], {event.raw[0].key: raw})
                self._direct([event], {event.raw[0].key: raw})
            turns, hidden = transcript(streams.data, streams.chunks, self.settings)
            self.stream = {
                "evidence": event.id if event is not None else None,
                "client": f"{key.client_ip}:{key.client_port}", "server": f"{key.server_ip}:{key.server_port}",
                "client_bytes": len(streams.data["c2s"]), "server_bytes": len(streams.data["s2c"]),
                "opened_by": streams.opened_by, "shell_side": analysis.side,
                "shell_indicators": analysis.kinds, "turns": analysis.turns,
                "limits": [*streams.limits(), *analysis.limits][:MAX_REASONS],
                "transcript": turns, "turns_not_shown": hidden}

        run.observe = observe
        run.judge_capture(self.segments, key, path, capped)
        for pb in run.pack:
            self._publish(pb, pb.finalize(), run.raw_sources)
        self.reasons.extend(f"stream: {item}" for item in run.loss_reasons())
        if run.c["outside_window"]:
            self.notes.append("stream: the shell indicators found all fall outside the hunt window: no stream event was "
                              "kept")
        if run.c["single_indicator"]:
            self.notes.append("stream: one shell indicator was found, below the rule's bar for a finding")

    def _preview_response(self, event: TypedEvent, raw: dict | None) -> None:
        if len(self.responses) >= MAX_PREVIEW_RESPONSES:
            self.responses_not_shown += 1
            return
        item = {"evidence": event.id, "time": event.ts.isoformat(),
                "uri": show(_redact_uri(event.get("url.original")), MAX_LINE_CHARS) if event.has("url.original")
                else None,
                "status": event.get("http.response.status_code"),
                "content_type": show(event.get("http.content_type"), 120) if event.has("http.content_type") else None,
                "body_bytes": event.get("file.size"), "body_sha256": event.get("file.sha256"),
                "body_kind": event.get("http.body.kind")}
        hexed = (raw or {}).get("body_excerpt_hex")
        if isinstance(hexed, str):
            try:
                item.update(body_excerpt(bytes.fromhex(hexed), self.settings))
            except ValueError:
                item.update(excerpt=None, excerpt_note="the stored excerpt could not be read")
        else:
            item.update(excerpt=None, excerpt_note="no excerpt is stored for this response")
        self.responses.append(item)


def bounded_content(content: dict) -> dict:
    """The previews cut to MAX_CONTENT_BYTES of JSON: the conversation's last turns go first, then the last
    responses, each counted as not shown."""
    def size() -> int:
        return len(json.dumps(content, ensure_ascii=False, sort_keys=True, default=str).encode("utf-8"))

    stream = content.get("stream") or {}
    while size() > MAX_CONTENT_BYTES:
        if stream.get("transcript"):
            stream["transcript"].pop()
            stream["turns_not_shown"] = int(stream.get("turns_not_shown") or 0) + 1
        elif content["http_responses"]:
            content["http_responses"].pop()
            content["http_responses_not_shown"] += 1
        else:
            break
    return content


def _list(value) -> list:
    return value if isinstance(value, list) else [value] if value is not None else []
