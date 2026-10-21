"""Packet stage: judge the content of selected HTTP sessions and cleartext TCP connections, after the sweep.

HTTP sessions:

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

Cleartext streams, per Arkime target, after the HTTP pass:

1. Select session documents with typed predicates only: TCP connections Arkime gave no application protocol
   (protocol list exactly "tcp", through protocolCnt where the target maps it) or a cleartext remote-login
   protocol, with payload in either direction, overlapping the window. Group them into connections and keep
   those with an interactive shape across all their documents (payload both ways; packet, duration and
   mean-payload bounds). Protocols Arkime cannot parse (a message bus, say) are not excluded by port: the
   content rule simply does not match them.
2. Judge at most a fixed number of connections per target, external endpoints first, within a per-hunt packet
   byte budget. Each is fetched (segments merged as above, byte capped), read by TShark's fixed stream query
   with a filter built only from the connection's validated addresses and ports, rebuilt per direction up to a
   byte cap, and analysed for signs of an interactive shell.
3. Publish matches and write one coverage cell per target for the stream rule. Every connection not judged, or
   judged on incomplete content (a failed fetch or run, a download cap, a cut-short capture, a per-direction cap,
   holes or conflicting retransmissions, no payload rebuilt although Arkime counted some, a shape that cannot be
   computed for missing fields, or the per-target cap or byte budget) makes the cell partial and is listed by
   session id. A target whose mapping lacks the selection fields is not applicable, with the fields named.

Any failure here is recorded and the hunt continues: packet evidence enriches the sweep; it is never required.
"""
from __future__ import annotations

import hashlib
import ipaddress
import logging
import shutil
import tempfile
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

from romulus.config import Settings
from romulus.detect.correlation import external
from romulus.detect.packets import PACKET_PLAYBOOKS, ShellAnalysis, analyze_body, analyze_stream
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
    StreamKey,
    TcpStreams,
    addresses,
    decode_hex_body,
    merge_captures,
    reassemble_tcp,
    run_tshark,
    stream_key,
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
# The packet stage's normalizer (HTTP body -> http_body, TCP connection -> tcp_stream). Bump on any change to the
# functions tests/test_evidence_version.py pins to this version (`_body_event`, `_stream_event`, `analyze_body`,
# `analyze_stream`, `decode_hex_body`, `reassemble_tcp` and their helpers).
PACKET_NORMALIZER = "tshark-packets@5"
SPAN_SLACK_S = 1.0
MAX_LISTED_IDS = 50
COUNTERS = ("candidates", "logical_sessions", "multi_segment_sessions", "fetched_sessions", "sessions_with_responses",
            "sessions_request_only", "sessions_unrebuilt_response", "sessions_without_messages", "responses", "outside_window",
            "unmapped_responses", "ambiguous_responses", "unseparable_frames", "undecodable_bodies",
            "missing_required", "failed_batches", "truncated_batches", "matched")

# Cleartext streams.
STREAM_PURPOSE = "packet-stage stream candidates"
REMOTE_LOGIN_PROTOCOLS = ["telnet", "rlogin", "rsh", "rexec"]   # Arkime protocol names of cleartext logins
STREAM_MIN_PACKETS = 20              # each way, for a connection with no recognised protocol
LOGIN_MIN_PACKETS = 4                # each way, for a recognised remote-login protocol
STREAM_MIN_SECONDS = 30
STREAM_MAX_MEAN_PAYLOAD = 1024       # payload bytes per packet, each way (bulk transfer fills packets)
STREAM_MAX_DOCS = 2000               # session documents read per target
STREAM_MAX_CONNECTIONS = 200         # connections judged per target
STREAM_FETCH_BYTES = 4 * 1024 * 1024
STREAM_BUDGET_BYTES = 256 * 1024 * 1024      # packets fetched for streams per target
STREAM_DIRECTION_BYTES = 256 * 1024          # rebuilt payload analysed per direction
# Typed fields (and the operations on them) the selection needs from a target's mapping.
STREAM_FIELDS = {"protocol": ("eq", "in"), "client.bytes": ("gte",), "server.bytes": ("gte",),
                 "source.packets": ("gte",), "destination.packets": ("gte",)}
STREAM_COUNTERS = ("candidates", "connections", "shaped", "not_shaped", "shape_unknown", "judged",
                   "unjudged_over_cap", "failed", "capture_incomplete", "analysis_cut", "stream_incomplete",
                   "no_payload_rebuilt", "with_indicators", "outside_window", "missing_required", "fetched_bytes",
                   "matched")
# Why a connection was not judged, or was judged on incomplete content: counter -> what to say.
STREAM_LOSSES = {
    "shape_unknown": "connection(s) whose shape cannot be computed (a packet, byte or time field is missing)",
    "unjudged_over_cap": "connection(s) not judged: beyond the per-target connection cap or packet byte budget",
    "failed": "connection(s) not judged: invalid connection fields, or the fetch or TShark run failed",
    "capture_incomplete": "connection(s) judged on a capped download or a capture cut short",
    "analysis_cut": ("connection(s) judged on the first bytes of a direction only, or on the first command lines "
                     "only (analysis caps)"),
    "stream_incomplete": ("connection(s) with holes, retransmissions that disagree, or segments without their "
                          "payload"),
    "no_payload_rebuilt": "connection(s) where no payload was rebuilt although Arkime counted some",
}


def _first(value):
    return value[0] if isinstance(value, list) and value else value


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
    records, partial = _select(client, target, contract, intent, MAX_SESSIONS, f"{target}: ")
    return records, partial, selection


def _select(client, target: str, contract, intent: SearchIntent, cap: int, label: str) -> tuple[list[dict], list[str]]:
    """Run a selection capped at `cap` documents (the intent asks for one more, to see the cap). Returns the
    documents and why the selection is incomplete, if it is."""
    try:
        out = execute(client, intent, contract)
    except CompileError as exc:
        return [], [f"{label}candidate selection failed: {exc}"]
    if out.completeness == Completeness.failed:
        return [], [f"{label}candidate selection failed: {out.error}"]
    records = out.records
    if len(records) > cap:
        total = f" of {out.total}{'+' if out.total_relation != 'eq' else ''}" if out.total else ""
        partial = [f"{label}candidate selection partial: {r}" for r in out.reasons if not r.startswith("cap:")]
        partial.append(f"{label}candidate cap reached: first {cap}{total} session documents examined")
        records = records[:cap]
    else:
        # below our cap, any shortfall the executor reports (fewer records than the total) is lost work
        partial = [f"{label}candidate selection partial: {r}" for r in out.reasons]
        if out.total is not None and out.total_relation == "eq" and len(records) < out.total and not partial:
            partial.append(f"{label}candidate selection returned {len(records)} of {out.total} documents")
    return records, partial


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


_addresses = addresses


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
    # Stable across re-runs (frame numbers depend on batch composition). The packet normalizer is part of the
    # identity because this stage synthesizes the raw copy: a new format must never collide with a stored one.
    native = f"{sid}@{epoch}#{PACKET_NORMALIZER}"
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


def _fetch_segments(s: Settings, packets, work: Path, stem: str, segs: list[dict],
                    budget: int) -> tuple[Path | None, bool, int, str | None]:
    """(capture, capped, bytes fetched, error) for one logical session. A single document is one request; the
    segments of a long session are fetched one at a time in lastPacket order within one byte budget and merged
    chronologically (a multi-id export is not in time order)."""
    pcap = work / f"{stem}.pcap"
    if len(segs) == 1:
        fetched = packets.fetch([segs[0]["_id"]], pcap, max_bytes=budget)
        return fetched.path, fetched.capped, fetched.bytes, fetched.error or (None if fetched.path else "no packets")
    parts, total, capped = [], 0, False
    try:
        for i, seg in enumerate(segs):
            if total >= budget:                          # segments left unfetched: the session is cut short
                capped = True
                break
            fetched = packets.fetch([seg["_id"]], work / f"{stem}-seg{i}.pcap", max_bytes=budget - total)
            total += fetched.bytes
            if fetched.error or fetched.path is None:
                return None, False, total, fetched.error or "no packets"
            parts.append(fetched.path)
            if fetched.capped:
                capped = True
                break
        error = merge_captures(s, parts, pcap, [work])
    finally:
        for part in parts:
            part.unlink(missing_ok=True)
    return (None, capped, total, error) if error else (pcap, capped, total, None)


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
        self.pack = [cls() for cls in PACKET_PLAYBOOKS if "http_body" in cls.families]
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
        if not merged:
            fetched = self.packets.fetch([b["_id"] for b in batch], self.work / f"batch-{n}.pcap")
            return fetched.path, fetched.capped, fetched.error or (None if fetched.path else "no packets")
        budget = getattr(self.packets, "max_bytes", 32 * 1024 * 1024)
        path, capped, _fetched, error = _fetch_segments(self.s, self.packets, self.work, f"batch-{n}", batch, budget)
        return path, capped, error

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


# ---- cleartext streams ----------------------------------------------------------------------------------------

def stream_selection(overlap: bool, exact: bool) -> str:
    """What the stream selection examines, in words, for the mode actually used."""
    protocol = ("protocol list exactly 'tcp' (protocolCnt 1)" if exact else
                f"protocol 'tcp' and at least {STREAM_MIN_PACKETS} packets each way in that document (this "
                "target maps no protocolCnt, so documents with another protocol are read and set aside, and a "
                "quiet saved document of a long connection is not selected)")
    when = (f"overlapping the hunt window (lastPacket at or after its start, firstPacket before its end and at "
            f"most {OVERLAP_LOOKBACK.days} days before its start)" if overlap else
            "with firstPacket inside the hunt window (lastPacket is not range-searchable on this target, so "
            "connections that began before the window are not selected)")
    return (f"Arkime TCP session documents with payload in either direction and either a {protocol} or a "
            f"remote-login protocol ({', '.join(REMOTE_LOGIN_PROTOCOLS)}), {when}; grouped into connections and "
            f"kept when the connection, over all its documents, carries payload both ways with at least "
            f"{LOGIN_MIN_PACKETS} packets each way for a remote-login protocol, or for no recognised protocol at "
            f"least {STREAM_MIN_PACKETS} packets each way, at least {STREAM_MIN_SECONDS} s and at most "
            f"{STREAM_MAX_MEAN_PAYLOAD} payload bytes per packet each way. Up to {STREAM_MAX_CONNECTIONS} "
            f"connections are judged per target (external endpoints first) within "
            f"{STREAM_BUDGET_BYTES // (1024 * 1024)} MiB of packets, each from at most "
            f"{STREAM_FETCH_BYTES // (1024 * 1024)} MiB of packets and {STREAM_DIRECTION_BYTES // 1024} KiB of "
            f"rebuilt payload per direction")


def _stream_candidates(client, target: str, contract, window: Window) -> tuple[list[dict], list[str], str, list[str]]:
    """(session documents, partial reasons, selection used, contract fields missing). Missing fields mean the
    selection cannot be expressed on this target: nothing is queried."""
    missing = sorted(f for f, ops in STREAM_FIELDS.items() if not all(contract.supports(f, op) for op in ops))
    if missing:
        return [], [], "", missing
    overlap, exact = contract.supports("lastPacket", "gte"), contract.supports("protocolCnt", "eq")
    unrecognised = [Predicate(field="protocol", op="eq", value="tcp")]
    if exact:
        unrecognised.append(Predicate(field="protocolCnt", op="eq", value=1))
    else:
        unrecognised += [Predicate(field="source.packets", op="gte", value=STREAM_MIN_PACKETS),
                         Predicate(field="destination.packets", op="gte", value=STREAM_MIN_PACKETS)]
    login = [Predicate(field="protocol", op="in", value=REMOTE_LOGIN_PROTOCOLS)]
    groups = [[*base, Predicate(field=side, op="gte", value=1)] for base in (unrecognised, login)
              for side in ("client.bytes", "server.bytes")]
    if overlap:
        intent = SearchIntent(kind="raw", target=target, max_records=STREAM_MAX_DOCS + 1, purpose=STREAM_PURPOSE,
                              window=Window(start=window.start - OVERLAP_LOOKBACK, end=window.end), any_of=groups,
                              filters=[Predicate(field="lastPacket", op="gte", value=window.start.isoformat())])
    else:
        intent = SearchIntent(kind="raw", target=target, window=window, max_records=STREAM_MAX_DOCS + 1,
                              purpose=STREAM_PURPOSE, any_of=groups)
    records, partial = _select(client, target, contract, intent, STREAM_MAX_DOCS, f"{target}: streams: ")
    return records, partial, stream_selection(overlap, exact), []


def _count(value) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def _shape(segs: list[dict]) -> tuple[str, bool]:
    """('shaped' | 'not_shaped' | 'unknown', remote-login protocol) over all documents of one connection."""
    protocols: set[str] = set()
    totals = [0, 0, 0, 0]                    # client packets, server packets, client bytes, server bytes
    first, last = None, None
    for seg in segs:
        src = seg["_source"]
        proto = src.get("protocol")
        protocols |= set(proto if isinstance(proto, list) else [proto] if proto else [])
        values = [_count((src.get("source") or {}).get("packets")), _count((src.get("destination") or {}).get("packets")),
                  _count((src.get("client") or {}).get("bytes")), _count((src.get("server") or {}).get("bytes"))]
        lo, hi = _epoch(src.get("firstPacket")), _epoch(src.get("lastPacket"))
        if None in values or lo is None or hi is None:
            return "unknown", False
        totals = [a + b for a, b in zip(totals, values)]
        first, last = min(lo, first if first is not None else lo), max(hi, last if last is not None else hi)
    cpk, spk, cb, sb = totals
    if protocols & set(REMOTE_LOGIN_PROTOCOLS):
        ok = cpk >= LOGIN_MIN_PACKETS and spk >= LOGIN_MIN_PACKETS and cb > 0 and sb > 0
        return ("shaped" if ok else "not_shaped"), True
    if protocols != {"tcp"}:
        return "not_shaped", False
    ok = (cpk >= STREAM_MIN_PACKETS and spk >= STREAM_MIN_PACKETS and cb > 0 and sb > 0
          and last - first >= STREAM_MIN_SECONDS
          and cb / cpk <= STREAM_MAX_MEAN_PAYLOAD and sb / spk <= STREAM_MAX_MEAN_PAYLOAD)
    return ("shaped" if ok else "not_shaped"), False


def _external_endpoint(src: dict) -> bool:
    return any(external(_canon((src.get(side) or {}).get("ip"))) for side in ("source", "destination"))


def _canon(value) -> str | None:
    try:
        return str(ipaddress.ip_address(str(value)))
    except ValueError:
        return None


def _stream_event(key: StreamKey, streams: TcpStreams, analysis: ShellAnalysis, segs: list[dict], index: str,
                  ts: datetime, capture_cut: bool) -> tuple[TypedEvent, dict]:
    """One connection's rebuilt content as a typed `tcp_stream` event. The raw copy holds sizes, digests,
    offsets and the indicators, never payload bytes. The event has no host: the Arkime node observed the
    connection (kept as observer.name); it did not take part in it."""
    src_doc = segs[0]["_source"]
    sid, ids = segs[0]["_id"], [seg["_id"] for seg in segs]
    native = f"{sid}@stream#{PACKET_NORMALIZER}"
    limits = (streams.limits() + analysis.limits
              + (["the download was capped or the capture ends mid-packet"] if capture_cut else []))
    indicators = [i.as_dict() for i in analysis.indicators]
    directions = {d: {"bytes": len(streams.data[d]), "sha256": hashlib.sha256(streams.data[d]).hexdigest(),
                      "cut": streams.cut[d], "gaps": streams.gaps[d], "gap_bytes": streams.gap_bytes[d],
                      "conflicts": streams.conflicts[d]} for d in ("c2s", "s2c")}
    raw = {"arkime_session_ids": ids, "node": src_doc.get("node"), "index": index,
           "client": f"{key.client_ip}:{key.client_port}", "server": f"{key.server_ip}:{key.server_port}",
           "first_packet_ms": src_doc.get("firstPacket"),
           "last_packet_ms": max((seg["_source"].get("lastPacket") or 0) for seg in segs),
           **directions, "turns": analysis.turns, "unreadable_segments": streams.unreadable,
           "shell_side": analysis.side, "indicators": indicators, "limits": limits}
    ref = RawRef(target=f"{PCAP_TARGET}:{index}", native_id=native, digest=digest(raw))
    o = f"{native}:tshark.tcp.payload"
    protocols = src_doc.get("protocol")
    f = {
        "source.ip": fv(key.client_ip, f"{sid}:source.ip"), "source.port": fv(key.client_port, f"{sid}:source.port"),
        "destination.ip": fv(key.server_ip, f"{sid}:destination.ip"),
        "destination.port": fv(key.server_port, f"{sid}:destination.port"),
        "network.transport": fv("tcp", f"{sid}:protocol"),
        "network.protocols": fv(sorted(protocols) if isinstance(protocols, list) else protocols, f"{sid}:protocol"),
        "network.community_id": fv(_first((src_doc.get("network") or {}).get("community_id")),
                                   f"{sid}:network.community_id"),
        "arkime.session_id": fv(sid, f"{sid}:_id"),
        "arkime.session_ids": fv(ids if len(ids) > 1 else None, f"{sid}:_id#segments"),
        "observer.name": fv(src_doc.get("node"), f"{sid}:node"),
        "stream.c2s.bytes": fv(directions["c2s"]["bytes"], f"{o}#reassembled"),
        "stream.s2c.bytes": fv(directions["s2c"]["bytes"], f"{o}#reassembled"),
        "stream.c2s.sha256": fv(directions["c2s"]["sha256"], f"{o}#reassembled"),
        "stream.s2c.sha256": fv(directions["s2c"]["sha256"], f"{o}#reassembled"),
        "stream.turns": fv(analysis.turns, f"{o}#turns"),
        "stream.limits": fv(limits or None, f"{o}#reassembled"),
        "stream.shell.side": fv(analysis.side, f"{o}#shell-analysis"),
        "stream.shell.kinds": fv(analysis.kinds or None, f"{o}#shell-analysis"),
        "stream.shell.indicators": fv(indicators or None, f"{o}#shell-analysis"),
    }
    event = TypedEvent(id=event_id("tcp_stream", [ref], PACKET_NORMALIZER), family="tcp_stream", ts=ts, host=None,
                       fields={k: v for k, v in f.items() if v.value is not None}, raw=[ref],
                       normalizer=PACKET_NORMALIZER, caveats=limits)
    return event, raw


class _StreamTarget:
    """One Arkime target's cleartext-stream run: connections, their judgement, counters and losses."""

    def __init__(self, s: Settings, name: str, window: Window, work: Path, packets, heartbeat):
        self.s, self.name, self.window, self.work, self.packets, self.heartbeat = s, name, window, work, packets, \
            heartbeat
        self.c = dict.fromkeys(STREAM_COUNTERS, 0)
        self.partial: list[str] = []
        self.lost: dict[str, list[str]] = {}
        self.pack = [cls() for cls in PACKET_PLAYBOOKS if "tcp_stream" in cls.families]
        self.raw_sources: dict[str, dict] = {}
        self.budget = STREAM_BUDGET_BYTES

    def _lose(self, label: str, segs: list[dict]) -> None:
        self.c[label] += 1
        self.lost.setdefault(label, []).extend(seg["_id"] for seg in segs)

    def run(self, docs: list[dict]) -> None:
        conns: dict[tuple, list[dict]] = {}
        for doc in docs:
            conns.setdefault(_logical(doc), []).append(doc)
        self.c["connections"] = len(conns)
        shaped = []
        for segs in conns.values():
            verdict, login = _shape(segs)
            if verdict == "unknown":
                self._lose("shape_unknown", segs)
            elif verdict == "not_shaped":
                self.c["not_shaped"] += 1
            else:
                segs = sorted(segs, key=lambda x: (_last_packet(x), x["_id"]))
                src = segs[0]["_source"]
                shaped.append(((0 if _external_endpoint(src) else 1, 0 if login else 1,
                                _epoch(src.get("firstPacket")) or 0.0, segs[0]["_id"]), segs))
        shaped.sort(key=lambda x: x[0])
        self.c["shaped"] = len(shaped)
        for n, (_rank, segs) in enumerate(shaped):
            if n >= STREAM_MAX_CONNECTIONS or self.budget <= 0:
                self._lose("unjudged_over_cap", segs)
                continue
            self.heartbeat()
            self._judge(n, segs)
        self.c["missing_required"] = sum(pb.missing_required for pb in self.pack)
        for label, what in STREAM_LOSSES.items():
            if self.c[label]:
                self.partial.append(f"{self.name}: streams: {self.c[label]} {what}")
        if self.c["missing_required"]:
            self.partial.append(f"{self.name}: streams: {self.c['missing_required']} connection(s) lacked a field "
                                "the rule needs")

    def unexamined(self) -> dict[str, list[str]]:
        return {label: sorted(ids)[:MAX_LISTED_IDS] for label, ids in sorted(self.lost.items()) if ids}

    def _judge(self, n: int, segs: list[dict]) -> None:
        src = segs[0]["_source"]
        client, server = src.get("source") or {}, src.get("destination") or {}
        try:
            key = stream_key(client.get("ip"), client.get("port"), server.get("ip"), server.get("port"))
            path, capped, fetched, error = _fetch_segments(self.s, self.packets, self.work, f"stream-{n}", segs,
                                                           min(STREAM_FETCH_BYTES, self.budget))
        except PacketError as exc:
            log.debug("stream %s not judged: %s", segs[0]["_id"], exc)
            self._lose("failed", segs)
            return
        self.budget -= fetched
        self.c["fetched_bytes"] += fetched
        if error or path is None:
            log.debug("stream %s not fetched: %s", segs[0]["_id"], error)
            self._lose("failed", segs)
            return
        try:
            result = run_tshark(self.s, path, "tcp_payload", [self.work], stream=key)
        finally:
            path.unlink(missing_ok=True)
        if result.error:
            self._lose("failed", segs)
            return
        self.c["judged"] += 1
        streams = reassemble_tcp(result.rows, key, STREAM_DIRECTION_BYTES)
        if capped or result.truncated:
            self._lose("capture_incomplete", segs)
        if any(streams.gaps.values()) or any(streams.conflicts.values()) or streams.unreadable:
            self._lose("stream_incomplete", segs)
        if not streams.chunks:
            self._lose("no_payload_rebuilt", segs)       # the shape test required payload both ways
        analysis = analyze_stream(streams.data, streams.chunks)
        if any(streams.cut.values()) or analysis.limits:
            self._lose("analysis_cut", segs)
        if analysis.indicators:
            self.c["with_indicators"] += 1
            inside = sorted(i.time for i in analysis.indicators
                            if self.window.start.timestamp() <= i.time < self.window.end.timestamp())
            if not inside:
                self.c["outside_window"] += 1
                return
            ts = datetime.fromtimestamp(inside[0], UTC)
        else:
            first = streams.chunks[0].time if streams.chunks else _epoch(src.get("firstPacket")) or 0.0
            ts = datetime.fromtimestamp(first, UTC)
        event, raw = _stream_event(key, streams, analysis, segs, self.name, ts, capped or result.truncated)
        for pb in self.pack:
            pb.consume([event])
        keep = {e.raw[0].key for pb in self.pack for e in pb.retained_events()}
        if event.raw[0].key in keep:
            self.raw_sources[event.raw[0].key] = raw


def _not_applicable(repo, hunt_id: str, window: Window, targets: list[str]) -> None:
    for target in targets:
        for cls in PACKET_PLAYBOOKS:
            repo.set_rule_cell(hunt_id, cls.id, cls.version, target, window.key(), "not_applicable_no_events", 0, 0,
                               {"reason": "not an Arkime session target: no packets to examine"})


def _run_streams(s: Settings, repo, client, hunt_id: str, window: Window, target: str, contract, work: Path,
                 packets, heartbeat, owner_token: str | None) -> dict:
    """The cleartext-stream pass over one Arkime target: its summary, with the partial reasons to merge."""
    rules = [cls for cls in PACKET_PLAYBOOKS if "tcp_stream" in cls.families]
    cell_target = f"{PCAP_TARGET}:{target}"
    docs, partial, selection, missing = _stream_candidates(client, target, contract, window)
    if missing:
        reason = f"this target's mapping lacks the selection field(s) {missing}: connections cannot be selected"
        for cls in rules:
            repo.set_rule_cell(hunt_id, cls.id, cls.version, cell_target, window.key(), "not_applicable_no_events",
                               0, 0, {"reason": reason})
        return {"status": "not_applicable", "reason": reason, "partial_reasons": []}
    run = _StreamTarget(s, target, window, work, packets, heartbeat)
    run.c["candidates"] = len(docs)
    run.partial += partial
    run.run(docs)
    heartbeat()
    for pb in run.pack:
        matches = pb.finalize()
        for m in matches:
            publish_match(repo, hunt_id, pb, m, None, run.raw_sources, owner_token=owner_token)
        run.c["matched"] += len(matches)
        state = ("match_on_partial" if run.partial else "matched") if matches else \
            ("positive_only_partial" if run.partial else "positive_only")
        repo.set_rule_cell(hunt_id, pb.id, pb.version, cell_target, window.key(), state, len(matches), pb.evaluated,
                           {**run.c, "selection": selection, "reasons": run.partial[:20],
                            "unexamined_sessions": run.unexamined()})
    return {"status": "partial" if run.partial else "complete", **run.c, "selection": selection,
            "unexamined_sessions": run.unexamined(), "partial_reasons": run.partial}


def run_packet_stage(s: Settings, repo, client, hunt_id: str, window: Window, contracts: dict,
                     heartbeat: Callable[[], None] | None = None, packets: ArkimePackets | None = None,
                     owner_token: str | None = None) -> dict:
    heartbeat = heartbeat or (lambda: None)
    targets = [t for t, c in contracts.items() if c is not None and getattr(c, "time_field", "") == "firstPacket"]
    summary = {"status": "skipped", "finished": False, "targets": targets, "selection": {},
               **dict.fromkeys(COUNTERS, 0), "http_sessions_without_body_type": {}, "partial_reasons": [],
               "notes": [], "unexamined_sessions": {}, "streams": {}}
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
            summary["streams"][target] = _run_streams(s, repo, client, hunt_id, window, target, contracts[target],
                                                      work, packets, heartbeat, owner_token)
            summary["partial_reasons"] += summary["streams"][target].pop("partial_reasons")
        summary["status"] = "partial" if summary["partial_reasons"] else "complete"
        summary["finished"] = True
    finally:
        shutil.rmtree(work, ignore_errors=True)
        if own:
            packets.close()
    summary["partial_reasons"] = summary["partial_reasons"][:50]
    return summary
