"""Packet stage: judge the content of selected HTTP sessions, after the sweep.

1. Select candidate session documents from each Arkime session index with typed predicates only: HTTP sessions
   overlapping the hunt window whose body Arkime classified as text or as an executable (scripts and droppers
   hide there). Selection is exhaustive up to a cap; anything beyond the cap, or any shortfall between what the
   index reported and what came back, is recorded. The selection actually used is stated in coverage.
2. Arkime saves a long session as several documents ("segments", one per 10,000 packets on the lab) that keep
   the session's original firstPacket. Segments of one session (same 4-tuple and firstPacket) form one logical
   session. Single-segment sessions are fetched in batches of 20 ids; a multi-segment session is fetched one
   segment at a time, in lastPacket order, and merged chronologically, so TShark sees one connection in packet
   order (a multi-id export is not in time order). Every fetch is byte-capped.
3. Let TShark rebuild the HTTP requests and responses with a fixed query.
4. Map each response to its logical session *within its batch* by server and client address and port, using
   the session's time span when two sessions share a 4-tuple. Turn each response body into a typed `http_body`
   event (what the bytes are, what the server said they were, size and hash of the whole body, a bounded
   excerpt as the retained raw copy) and run the packet rules over it batch by batch, keeping only the events
   the rules may cite.
5. Publish matches through the normal admission path, and write one coverage cell per target (non-Arkime
   targets get a not-applicable cell). Every way work can be lost makes the cell and the stage partial, from
   the same list of reasons: a partial, short or capped selection; a failed or truncated batch; a fetched
   session with no HTTP message TShark could rebuild; a response that maps to no session or to more than one;
   a frame holding several responses; a body that cannot be decoded; or a response missing a field the rule
   needs. A session where TShark saw only the request is "request only" (counted and noted, nothing to judge)
   only when Arkime agrees nobody answered: no HTTP status code and zero server bytes on every segment.
   Otherwise a response existed that TShark could not rebuild (a streaming reply that never ends, lost
   packets), and that is partial. Packet rules are positive-only, so even a complete stage is never a complete negative.

Any failure here is recorded and the hunt continues: packet evidence enriches the sweep; it is never required.
"""
from __future__ import annotations

import logging
import shutil
import tempfile
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

from romulus.config import Settings
from romulus.detect.packets import PACKET_PLAYBOOKS, analyze_body
from romulus.evidence.typed import RawRef, TypedEvent, event_id, fv
from romulus.hunt.publish import publish_match
from romulus.hunt.stage import PCAP_PREFIX
from romulus.sources.compile import CompileError
from romulus.sources.execute import execute
from romulus.sources.models import Completeness, Predicate, SearchIntent, Window
from romulus.sources.packets import (
    MAX_IDS_PER_REQUEST,
    ArkimePackets,
    PacketError,
    decode_hex_body,
    merge_captures,
    run_tshark,
)
from romulus.store.db import digest

log = logging.getLogger("romulus.packets")

TEXT_BODY_MAGICS = ["text/plain", "text/x-shellscript", "text/x-sh", "text/x-python", "text/x-script.python",
                    "text/x-perl", "text/x-php", "text/x-ruby", "application/x-sh", "application/x-shellscript",
                    "application/x-executable", "application/x-sharedlib", "application/x-pie-executable",
                    "application/x-dosexec", "application/x-mach-binary"]
OVERLAP_LOOKBACK = timedelta(days=7)
_SELECTED = ("Arkime session documents with protocol http and http.bodyMagic in a fixed list of text, script and "
             "executable types, ")
SELECTION_OVERLAP = (_SELECTED + f"overlapping the hunt window: lastPacket at or after its start, and firstPacket "
                     f"before its end and at most {OVERLAP_LOOKBACK.days} days before its start (Arkime keeps a "
                     "long session's original firstPacket on every saved segment)")
SELECTION_WINDOW = (_SELECTED + "with firstPacket inside the hunt window; lastPacket is not range-searchable on "
                    "this target, so sessions that began before the window are not selected")
MAX_SESSIONS = 2000                       # session documents (segments), not logical sessions
MAX_BODY_BYTES = 1024 * 1024
EXCERPT_BYTES = 4096
PCAP_TARGET = "arkime-pcap"
# The packet stage's normalizer (HTTP body -> http_body). Bump on any change to `_body_event`, `analyze_body` or
# `decode_hex_body`; tests/test_evidence_version.py pins them to this version.
PACKET_NORMALIZER = "tshark-http@3"
SPAN_SLACK_S = 1.0
MAX_LISTED_IDS = 50
COUNTERS = ("candidates", "logical_sessions", "multi_segment_sessions", "fetched_sessions", "sessions_with_responses",
            "sessions_request_only", "sessions_unrebuilt_response", "sessions_without_messages", "responses", "outside_window",
            "unmapped_responses", "ambiguous_responses", "unseparable_frames", "undecodable_bodies",
            "missing_required", "failed_batches", "truncated_batches", "matched")


def _first(value):
    return value[0] if isinstance(value, list) and value else value


def _last(values: list[str]) -> str | None:
    return values[-1] if values else None


def _epoch(ms) -> float | None:
    try:
        return float(ms) / 1000.0
    except (TypeError, ValueError):
        return None


def _candidates(client, target: str, contract, window: Window) -> tuple[list[dict], list[str], str]:
    """Returns (session documents, partial reasons, the selection actually used)."""
    filters = [Predicate(field="protocol", op="eq", value="http"),
               Predicate(field="http.bodyMagic", op="in", value=TEXT_BODY_MAGICS)]
    last = contract.spec("lastPacket")
    if last is not None and "gte" in last.ops:
        selection = SELECTION_OVERLAP
        intent = SearchIntent(kind="raw", target=target, max_records=MAX_SESSIONS + 1,
                              purpose="packet-stage candidates",
                              window=Window(start=window.start - OVERLAP_LOOKBACK, end=window.end),
                              filters=[*filters, Predicate(field="lastPacket", op="gte",
                                                           value=window.start.isoformat())])
    else:
        selection = SELECTION_WINDOW
        intent = SearchIntent(kind="raw", target=target, window=window, max_records=MAX_SESSIONS + 1,
                              purpose="packet-stage candidates", filters=filters)
    try:
        out = execute(client, intent, contract)
    except CompileError as exc:
        return [], [f"{target}: candidate selection failed: {exc}"], selection
    if out.completeness == Completeness.failed:
        return [], [f"{target}: candidate selection failed: {out.error}"], selection
    records = out.records
    if len(records) > MAX_SESSIONS:
        total = f" of {out.total}{'+' if out.total_relation != 'eq' else ''}" if out.total else ""
        partial = [f"{target}: candidate selection partial: {r}" for r in out.reasons if not r.startswith("cap:")]
        partial.append(f"{target}: candidate cap reached: first {MAX_SESSIONS}{total} session documents examined")
        records = records[:MAX_SESSIONS]
    else:
        # below our cap, any shortfall the executor reports (fewer records than the total) is lost work
        partial = [f"{target}: candidate selection partial: {r}" for r in out.reasons]
        if out.total is not None and out.total_relation == "eq" and len(records) < out.total and not partial:
            partial.append(f"{target}: candidate selection returned {len(records)} of {out.total} documents")
    return records, partial, selection


def _unclassified(client, target: str, contract, window: Window) -> int | None:
    """How many HTTP sessions in the window Arkime gave no body type (outside the selection by construction)."""
    try:
        seconds = max(1, int((window.end - window.start).total_seconds()))
        out = execute(client, SearchIntent(kind="histogram", target=target, window=window, interval_seconds=seconds,
                                           purpose="packet-stage selection scope",
                                           filters=[Predicate(field="protocol", op="eq", value="http"),
                                                    Predicate(field="http.bodyMagic", op="missing")]), contract)
    except CompileError:
        return None
    return out.total if out.completeness == Completeness.complete and out.total_relation == "eq" else None


def _addresses(row: dict[str, list[str]]) -> tuple:
    """Innermost IP layer (tunnels put the outer one first), and that packet's TCP ports."""
    protos = (_first(row.get("frame.protocols")) or "").split(":")
    upto = protos[: max((i for i, p in enumerate(protos) if p == "tcp"), default=len(protos))]
    inner = next((p for p in reversed(upto) if p in ("ip", "ipv6")), None)
    if inner is None:
        inner = "ip" if row.get("ip.src") else "ipv6"
    return (_last(row.get(f"{inner}.src", [])), _last(row.get("tcp.srcport", [])),
            _last(row.get(f"{inner}.dst", [])), _last(row.get("tcp.dstport", [])))


def _key(ip, port, cip, cport) -> tuple:
    return str(ip), str(port), str(cip), str(cport)


def _tuple(sess: dict) -> tuple:
    """(server ip, server port, client ip, client port) of a session document."""
    src = sess["_source"]
    client, server = src.get("source") or {}, src.get("destination") or {}
    return _key(server.get("ip"), server.get("port"), client.get("ip"), client.get("port"))


def _logical(sess: dict) -> tuple:
    """Segments of one Arkime session share the 4-tuple and the original firstPacket."""
    return _tuple(sess), sess["_source"].get("firstPacket")


def _last_packet(sess: dict) -> float:
    return _epoch(sess["_source"].get("lastPacket")) or 0.0


def _units(sessions: list[dict]) -> list[tuple[bool, list[dict]]]:
    """Units of work: (False, up to MAX_IDS_PER_REQUEST single-segment sessions fetched in one request) or
    (True, every segment of one multi-segment session in lastPacket order, fetched one by one and merged)."""
    groups: dict[tuple, list[dict]] = {}
    for sess in sessions:
        groups.setdefault(_logical(sess), []).append(sess)
    out: list[tuple[bool, list[dict]]] = []
    current: list[dict] = []
    for segs in groups.values():
        if len(segs) > 1:
            out.append((True, sorted(segs, key=_last_packet)))
            continue
        current += segs
        if len(current) == MAX_IDS_PER_REQUEST:
            out.append((False, current))
            current = []
    if current:
        out.append((False, current))
    return out


def _unanswered_per_arkime(segs: list[dict]) -> bool:
    """True only when Arkime's own record shows nobody answered: on every segment, no parsed HTTP status code and
    a server byte count that is present and zero. A missing field (another schema, older field names) is not
    evidence of silence."""
    if not segs:
        return False
    for seg in segs:
        src = seg["_source"]
        server_bytes = (src.get("server") or {}).get("bytes")
        if (src.get("http") or {}).get("statuscode") or not isinstance(server_bytes, int) or server_bytes != 0:
            return False
    return True


def _body_event(row: dict, addrs: tuple, ts: datetime, session: dict, index: str) -> tuple[TypedEvent, dict]:
    src_doc = session["_source"]
    sid = session["_id"]
    body = decode_hex_body(_first(row.get("http.file_data")), MAX_BODY_BYTES)
    info = analyze_body(body.head)
    epoch = _first(row.get("frame.time_epoch"))
    native = f"{sid}@{epoch}"                 # stable across re-runs; frame numbers depend on batch composition
    # Only facts of the session and the response: frame and stream numbers depend on which sessions shared
    # the batch capture, and would make the same response's raw copy differ between hunts.
    raw = {"arkime_session_id": sid, "node": src_doc.get("node"), "index": index, "frame_time_epoch": epoch,
           "body_bytes": body.size, "body_sha256": body.sha256, "body_analyzed_bytes": len(body.head),
           "body_excerpt_hex": body.head[:EXCERPT_BYTES].hex()}
    ref = RawRef(target=f"{PCAP_TARGET}:{index}", native_id=native, digest=digest(raw))
    o = f"{native}:tshark"
    server_ip, sport, client_ip, cport = addrs
    code = _first(row.get("http.response.code"))
    f = {
        "source.ip": fv(server_ip, f"{o}.ip.src"), "source.port": fv(int(sport), f"{o}.tcp.srcport"),
        "destination.ip": fv(client_ip, f"{o}.ip.dst"), "destination.port": fv(int(cport), f"{o}.tcp.dstport"),
        "url.original": fv(_first(row.get("http.response_for.uri")), f"{o}.http.response_for.uri"),
        "http.response.status_code": fv(int(code) if code else None, f"{o}.http.response.code"),
        "http.content_type": fv(_first(row.get("http.content_type")), f"{o}.http.content_type"),
        "http.content_encoding": fv(_first(row.get("http.content_encoding")), f"{o}.http.content_encoding"),
        "file.size": fv(body.size, f"{o}.http.file_data#bytes"),
        "file.sha256": fv(body.sha256, f"{o}.http.file_data#sha256"),
        "http.body.kind": fv(info.kind, f"{o}.http.file_data#analysis"),
        "http.body.basis": fv(info.basis, f"{o}.http.file_data#analysis"),
        "http.body.detail": fv(info.detail or None, f"{o}.http.file_data#analysis"),
        "http.body.interpreter": fv(info.interpreter, f"{o}.http.file_data#analysis"),
        "http.body.commands": fv(info.commands or None, f"{o}.http.file_data#analysis"),
        "http.body.piped_to": fv(info.piped_to or None, f"{o}.http.file_data#analysis"),
        "http.body.writes": fv(info.writes or None, f"{o}.http.file_data#analysis"),
        "http.body.analysis_limit": fv(len(body.head) if body.cut else None, f"{o}.http.file_data#analysis"),
        "arkime.session_id": fv(sid, f"{sid}:_id"),
        "network.community_id": fv(_first((src_doc.get("network") or {}).get("community_id")),
                                   f"{sid}:network.community_id"),
    }
    caveats = [f"content judged from the first {len(body.head)} bytes"] if body.cut else []
    event = TypedEvent(id=event_id("http_body", [ref], PACKET_NORMALIZER), family="http_body", ts=ts,
                       host=src_doc.get("node"),
                       fields={k: v for k, v in f.items() if v.value is not None}, raw=[ref],
                       normalizer=PACKET_NORMALIZER, caveats=caveats)
    return event, raw


def _ports(batch: list[dict]) -> list[int]:
    out = set()
    for sess in batch:
        port = ((sess["_source"].get("destination") or {}).get("port"))
        if isinstance(port, int) and not isinstance(port, bool) and 1 <= port <= 65535:
            out.add(port)
    return sorted(out)


class _Target:
    """One Arkime target's run: counters, partial reasons, and the packet rules over its responses."""

    def __init__(self, s: Settings, name: str, window: Window, work: Path, packets: ArkimePackets, heartbeat):
        self.s, self.name, self.window, self.work, self.packets, self.heartbeat = s, name, window, work, packets, \
            heartbeat
        self.c = dict.fromkeys(COUNTERS, 0)
        self.partial: list[str] = []
        self.notes: list[str] = []
        self.pack = [cls() for cls in PACKET_PLAYBOOKS]
        self.raw_sources: dict[str, dict] = {}
        self.spans: dict[tuple, tuple[float | None, float | None]] = {}
        self.fetched: set[tuple] = set()
        self.responded: set[tuple] = set()
        self.requested: set[tuple] = set()
        self.docs: dict[tuple, list[dict]] = {}
        self.unexamined: dict[str, list[str]] = {}

    def run(self, sessions: list[dict]) -> None:
        for sess in sessions:                           # a logical session spans all of its segments
            first = _epoch(sess["_source"].get("firstPacket"))
            last = _epoch(sess["_source"].get("lastPacket"))
            lo, hi = self.spans.get(_logical(sess), (first, None))
            ends = [x for x in (hi, last) if x is not None]
            self.spans[_logical(sess)] = (lo, max(ends) if ends else None)
            self.docs.setdefault(_logical(sess), []).append(sess)
        self.c["logical_sessions"] = len(self.spans)
        self.c["multi_segment_sessions"] = sum(1 for segs in self.docs.values() if len(segs) > 1)
        for n, (merged, docs) in enumerate(_units(sessions)):
            self.heartbeat()
            self._batch(n, docs, merged)
        silent = self.fetched - self.responded
        asked = silent & self.requested
        unanswered = {k for k in asked if _unanswered_per_arkime(self.docs.get(k, []))}
        self.c["fetched_sessions"] = len(self.fetched)
        self.c["sessions_with_responses"] = len(self.responded)
        self.c["sessions_request_only"] = len(unanswered)
        self.c["sessions_unrebuilt_response"] = len(asked - unanswered)
        self.c["sessions_without_messages"] = len(silent - self.requested)
        # name the sessions behind each count, so a reviewer can check what was not judged
        self.unexamined = {label: self._ids(keys) for label, keys in (
            ("request_only", unanswered), ("unrebuilt_response", asked - unanswered),
            ("without_messages", silent - self.requested)) if keys}
        missing = sum(pb.missing_required for pb in self.pack)
        self.c["missing_required"] = missing
        if self.c["sessions_request_only"]:
            self.notes.append(f"{self.name}: {self.c['sessions_request_only']} session(s) had an HTTP request and no "
                              "response; Arkime also recorded no status code and no server bytes (nothing served, "
                              "nothing to judge)")
        for label, n in (("fetched session(s) had no HTTP message TShark could rebuild",
                          self.c["sessions_without_messages"]),
                         (("session(s) had a response Arkime recorded that TShark could not rebuild (for example a "
                           "streaming reply that never ends, or lost packets)"), self.c["sessions_unrebuilt_response"]),
                         ("response(s) mapped to no selected session", self.c["unmapped_responses"]),
                         ("response(s) matched more than one session", self.c["ambiguous_responses"]),
                         ("frame(s) held several HTTP responses that cannot be separated", self.c["unseparable_frames"]),
                         ("response bod(ies) could not be decoded", self.c["undecodable_bodies"]),
                         ("response(s) lacked a field the rule needs (often no request was seen)", missing)):
            if n:
                self.partial.append(f"{self.name}: {n} {label}")

    def _fetch(self, n: int, batch: list[dict], merged: bool) -> tuple[Path | None, bool, str | None]:
        """(capture path, capped, error). A merged unit fetches each segment alone, in order, within one byte
        budget, then merges them chronologically."""
        pcap = self.work / f"batch-{n}.pcap"
        if not merged:
            fetched = self.packets.fetch([b["_id"] for b in batch], pcap)
            return fetched.path, fetched.capped, fetched.error or (None if fetched.path else "no packets")
        budget = getattr(self.packets, "max_bytes", 32 * 1024 * 1024)
        parts, total, capped = [], 0, False
        try:
            for i, seg in enumerate(batch):
                if total >= budget:                      # segments left unfetched: the session is cut short
                    capped = True
                    break
                fetched = self.packets.fetch([seg["_id"]], self.work / f"batch-{n}-seg{i}.pcap",
                                             max_bytes=budget - total)
                if fetched.error or fetched.path is None:
                    return None, False, fetched.error or "no packets"
                parts.append(fetched.path)
                total += fetched.bytes
                if fetched.capped:
                    capped = True
                    break
            error = merge_captures(self.s, parts, pcap, [self.work])
        finally:
            for part in parts:
                part.unlink(missing_ok=True)
        return (None, capped, error) if error else (pcap, capped, None)

    def _batch(self, n: int, batch: list[dict], merged: bool = False) -> None:
        what = f"one session's {len(batch)} segments" if merged else f"{len(batch)} session documents"
        try:
            path, capped, error = self._fetch(n, batch, merged)
        except PacketError as exc:
            path, capped, error = None, False, str(exc)
        if error:
            self.c["failed_batches"] += 1
            self.partial.append(f"{self.name}: batch {n} ({what}) not examined: {error}")
            return
        result = run_tshark(self.s, path, "http_messages", [self.work], http_ports=_ports(batch))
        path.unlink(missing_ok=True)
        if result.error:
            self.c["failed_batches"] += 1
            self.partial.append(f"{self.name}: batch {n} ({what}) not examined: {result.error}")
            return
        if capped or result.truncated:
            self.c["truncated_batches"] += 1
            self.partial.append(f"{self.name}: batch {n} ({what}) capture incomplete "
                                f"({'download byte cap' if capped else 'capture cut short'})")
        segments: dict[tuple, list[dict]] = {}
        by_tuple: dict[tuple, list[tuple]] = {}
        for sess in batch:
            lkey = _logical(sess)
            if lkey not in segments:
                by_tuple.setdefault(lkey[0], []).append(lkey)
            segments.setdefault(lkey, []).append(sess)
        self.fetched |= set(segments)
        events: list[TypedEvent] = []
        raws: dict[str, dict] = {}
        for row in result.rows:
            if row.get("http.request.method") and not row.get("http.response.code"):
                self._request(row, by_tuple)
                continue
            if max(len(row.get(f) or []) for f in ("http.response.code", "http.file_data",
                                                    "http.response_for.uri")) > 1:
                self.c["unseparable_frames"] += 1
                continue
            addrs = _addresses(row)
            epoch = _first(row.get("frame.time_epoch"))
            if not epoch or not all(addrs):
                self.c["unmapped_responses"] += 1
                continue
            ts = datetime.fromtimestamp(float(epoch), UTC)
            owners = self._owners(by_tuple.get(_key(*addrs), []), ts.timestamp())
            if not owners:
                self.c["unmapped_responses"] += 1
                continue
            if len(owners) > 1:
                self.c["ambiguous_responses"] += 1
                continue
            lkey = owners[0]
            self.responded.add(lkey)
            if not self.window.start <= ts < self.window.end:
                self.c["outside_window"] += 1
                continue
            sess = self._segment(segments[lkey], ts.timestamp())
            try:
                ev, raw = _body_event(row, addrs, ts, sess, self.name)
            except (PacketError, ValueError) as exc:
                self.c["undecodable_bodies"] += 1
                log.debug("undecodable body in %s: %s", sess["_id"], exc)
                continue
            events.append(ev)
            raws[ev.raw[0].key] = raw
        self.c["responses"] += len(events)
        for pb in self.pack:
            pb.consume(events)
        self.raw_sources.update(raws)
        keep = {e.raw[0].key for pb in self.pack for e in pb.retained_events()}
        self.raw_sources = {k: v for k, v in self.raw_sources.items() if k in keep}

    def _ids(self, keys: set[tuple]) -> list[str]:
        """Arkime session ids (every segment) of these logical sessions, sorted and capped."""
        return sorted(seg["_id"] for k in keys for seg in self.docs.get(k, []))[:MAX_LISTED_IDS]

    def _request(self, row: dict, by_tuple: dict) -> None:
        """A request travels client -> server, so its addresses are the response's, reversed."""
        cip, cport, sip, sport = _addresses(row)
        epoch = _first(row.get("frame.time_epoch"))
        if epoch and all((cip, cport, sip, sport)):
            owners = self._owners(by_tuple.get(_key(sip, sport, cip, cport), []), float(epoch))
            if len(owners) == 1:
                self.requested.add(owners[0])

    def _owners(self, lkeys: list[tuple], t: float) -> list[tuple]:
        if len(lkeys) <= 1:
            return lkeys
        return [k for k in lkeys if self._within(self.spans.get(k), t)]

    @staticmethod
    def _within(span, t: float) -> bool:
        first, last = span or (None, None)
        return first is not None and last is not None and first - SPAN_SLACK_S <= t <= last + SPAN_SLACK_S

    @staticmethod
    def _segment(segs: list[dict], t: float) -> dict:
        """The segment that holds time t: the earliest whose lastPacket is not before t."""
        ordered = sorted(segs, key=lambda x: _epoch(x["_source"].get("lastPacket")) or 0.0)
        return next((x for x in ordered if (_epoch(x["_source"].get("lastPacket")) or 0.0) + SPAN_SLACK_S >= t),
                    ordered[-1])


def _not_applicable(repo, hunt_id: str, window: Window, targets: list[str]) -> None:
    for target in targets:
        for cls in PACKET_PLAYBOOKS:
            repo.set_rule_cell(hunt_id, cls.id, cls.version, target, window.key(), "not_applicable_no_events", 0, 0,
                               {"reason": "not an Arkime session target: no packets to examine"})


def run_packet_stage(s: Settings, repo, client, hunt_id: str, window: Window, contracts: dict,
                     heartbeat: Callable[[], None] | None = None, packets: ArkimePackets | None = None,
                     owner_token: str | None = None) -> dict:
    heartbeat = heartbeat or (lambda: None)
    targets = [t for t, c in contracts.items() if c is not None and getattr(c, "time_field", "") == "firstPacket"]
    summary = {"status": "skipped", "finished": False, "targets": targets, "selection": {},
               **dict.fromkeys(COUNTERS, 0), "http_sessions_without_body_type": {}, "partial_reasons": [],
               "notes": [], "unexamined_sessions": {}}
    _not_applicable(repo, hunt_id, window, [t for t in contracts if t not in targets])
    if not targets:
        summary.update(finished=True, notes=["no Arkime session target in this hunt"])
        return summary
    own = packets is None
    packets = packets or ArkimePackets(s)
    work_root = s.home / "stage"
    work_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix=PCAP_PREFIX, dir=work_root))
    try:
        for target in targets:
            run = _Target(s, target, window, work, packets, heartbeat)
            sessions, partial, selection = _candidates(client, target, contracts[target], window)
            run.c["candidates"] = len(sessions)
            run.partial += partial
            summary["selection"][target] = selection
            unclassified = _unclassified(client, target, contracts[target], window)
            summary["http_sessions_without_body_type"][target] = unclassified
            run.run(sessions)
            heartbeat()
            for pb in run.pack:
                matches = pb.finalize()
                for m in matches:
                    publish_match(repo, hunt_id, pb, m, None, run.raw_sources, owner_token=owner_token)
                run.c["matched"] += len(matches)
                state = ("match_on_partial" if run.partial else "matched") if matches else \
                    ("positive_only_partial" if run.partial else "positive_only")
                repo.set_rule_cell(hunt_id, pb.id, pb.version, f"{PCAP_TARGET}:{target}", window.key(), state,
                                   len(matches), pb.evaluated,
                                   {**run.c, "selection": selection, "http_sessions_without_body_type": unclassified,
                                    "reasons": run.partial[:20], "notes": run.notes,
                                    "unexamined_sessions": run.unexamined})
            for k in COUNTERS:
                summary[k] += run.c[k]
            summary["partial_reasons"] += run.partial
            summary["notes"] += run.notes
            if run.unexamined:
                summary["unexamined_sessions"][target] = run.unexamined
        summary["status"] = "partial" if summary["partial_reasons"] else "complete"
        summary["finished"] = True
    finally:
        shutil.rmtree(work, ignore_errors=True)
        if own:
            packets.close()
    summary["partial_reasons"] = summary["partial_reasons"][:50]
    return summary
