"""Packet stage: judge the content of selected HTTP sessions, after the sweep.

1. Select candidate sessions from each Arkime session index with typed predicates only (SELECTION): HTTP
   sessions overlapping the hunt window whose body Arkime classified as text or as an executable (scripts and
   droppers hide there). Selection is exhaustive up to a cap; anything beyond the cap is recorded.
2. Fetch their packets from Arkime by explicit session id (batches of 20, byte-capped) and let TShark rebuild
   the HTTP responses with a fixed query.
3. Map each response to its session *within its batch* by server and client address and port, using the
   session's time span when two sessions share a 4-tuple. Turn each response body into a typed `http_body`
   event (what the bytes are, what the server said they were, size and hash of the whole body, a bounded
   excerpt as the retained raw copy) and run the packet rules over it batch by batch, keeping only the events
   the rules may cite.
4. Publish matches through the normal admission path, and write one coverage cell per target. Every way work
   can be lost makes the cell and the stage partial, from the same list of reasons: a partial or capped
   selection, a failed or truncated batch, a fetched session with no response TShark could rebuild, a
   response that maps to no session or to more than one, a frame holding several responses, a body that
   cannot be decoded, or a response missing a field the rule needs. Packet rules are positive-only, so even a
   complete stage is never a complete negative.

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
    run_tshark,
)
from romulus.store.db import digest

log = logging.getLogger("romulus.packets")

TEXT_BODY_MAGICS = ["text/plain", "text/x-shellscript", "text/x-sh", "text/x-python", "text/x-script.python",
                    "text/x-perl", "text/x-php", "text/x-ruby", "application/x-sh", "application/x-shellscript",
                    "application/x-executable", "application/x-sharedlib", "application/x-pie-executable",
                    "application/x-dosexec", "application/x-mach-binary"]
SELECTION = ("Arkime sessions with protocol http and http.bodyMagic in a fixed list of text, script and "
             "executable types, overlapping the hunt window (lastPacket at or after its start, firstPacket "
             "before its end and at most 1 h before its start)")
OVERLAP_LOOKBACK = timedelta(hours=1)
MAX_SESSIONS = 500
MAX_BODY_BYTES = 1024 * 1024
EXCERPT_BYTES = 4096
PCAP_TARGET = "arkime-pcap"
SPAN_SLACK_S = 1.0
COUNTERS = ("candidates", "fetched_sessions", "sessions_with_responses", "sessions_without_responses",
            "responses", "outside_window", "unmapped_responses", "ambiguous_responses", "unseparable_frames",
            "undecodable_bodies", "missing_required", "failed_batches", "truncated_batches", "matched")


def _first(value):
    return value[0] if isinstance(value, list) and value else value


def _last(values: list[str]) -> str | None:
    return values[-1] if values else None


def _epoch(ms) -> float | None:
    try:
        return float(ms) / 1000.0
    except (TypeError, ValueError):
        return None


def _candidates(client, target: str, contract, window: Window) -> tuple[list[dict], list[str], list[str]]:
    """Returns (sessions, partial reasons, notes)."""
    filters = [Predicate(field="protocol", op="eq", value="http"),
               Predicate(field="http.bodyMagic", op="in", value=TEXT_BODY_MAGICS)]
    notes = []
    last = contract.spec("lastPacket")
    if last is not None and "gte" in last.ops:
        intent = SearchIntent(kind="raw", target=target, max_records=MAX_SESSIONS + 1,
                              purpose="packet-stage candidates",
                              window=Window(start=window.start - OVERLAP_LOOKBACK, end=window.end),
                              filters=[*filters, Predicate(field="lastPacket", op="gte",
                                                           value=window.start.isoformat())])
    else:
        notes.append(f"{target}: lastPacket is not searchable, so sessions that began before the window are "
                     "not selected")
        intent = SearchIntent(kind="raw", target=target, window=window, max_records=MAX_SESSIONS + 1,
                              purpose="packet-stage candidates", filters=filters)
    try:
        out = execute(client, intent, contract)
    except CompileError as exc:
        return [], [f"{target}: candidate selection failed: {exc}"], notes
    if out.completeness == Completeness.failed:
        return [], [f"{target}: candidate selection failed: {out.error}"], notes
    records = out.records
    partial = [f"{target}: candidate selection partial: {r}" for r in out.reasons if not r.startswith("cap:")]
    if len(records) > MAX_SESSIONS:
        total = f" of {out.total}{'+' if out.total_relation != 'eq' else ''}" if out.total else ""
        partial.append(f"{target}: candidate cap reached: first {MAX_SESSIONS}{total} sessions examined")
        records = records[:MAX_SESSIONS]
    return records, partial, notes


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


def _body_event(row: dict, addrs: tuple, ts: datetime, session: dict, index: str) -> tuple[TypedEvent, dict]:
    src_doc = session["_source"]
    sid = session["_id"]
    body = decode_hex_body(_first(row.get("http.file_data")), MAX_BODY_BYTES)
    info = analyze_body(body.head)
    frame = _first(row.get("frame.number")) or "0"
    native = f"{sid}#frame{frame}"
    raw = {"arkime_session_id": sid, "node": src_doc.get("node"), "index": index, "frame": frame,
           "tcp_stream": _first(row.get("tcp.stream")), "body_bytes": body.size, "body_sha256": body.sha256,
           "body_analyzed_bytes": len(body.head), "body_excerpt_hex": body.head[:EXCERPT_BYTES].hex()}
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
    event = TypedEvent(id=event_id("http_body", [ref]), family="http_body", ts=ts, host=src_doc.get("node"),
                       fields={k: v for k, v in f.items() if v.value is not None}, raw=[ref],
                       normalizer="tshark-http@2", caveats=caveats)
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

    def run(self, sessions: list[dict]) -> None:
        for i in range(0, len(sessions), MAX_IDS_PER_REQUEST):
            self.heartbeat()
            self._batch(i // MAX_IDS_PER_REQUEST, sessions[i:i + MAX_IDS_PER_REQUEST])
        missing = sum(pb.missing_required for pb in self.pack)
        self.c["missing_required"] = missing
        for label, n in (("fetched session(s) had no HTTP response TShark could rebuild",
                          self.c["sessions_without_responses"]),
                         ("response(s) mapped to no selected session", self.c["unmapped_responses"]),
                         ("response(s) matched more than one session", self.c["ambiguous_responses"]),
                         ("frame(s) held several HTTP responses that cannot be separated", self.c["unseparable_frames"]),
                         ("response bod(ies) could not be decoded", self.c["undecodable_bodies"]),
                         ("response(s) lacked a field the rule needs (often no request was seen)", missing)):
            if n:
                self.partial.append(f"{self.name}: {n} {label}")

    def _batch(self, n: int, batch: list[dict]) -> None:
        pcap = self.work / f"batch-{n}.pcap"
        try:
            fetched = self.packets.fetch([b["_id"] for b in batch], pcap)
        except PacketError as exc:
            fetched = None
            error = str(exc)
        else:
            error = fetched.error or (None if fetched.path else "no packets")
        if error:
            self.c["failed_batches"] += 1
            self.partial.append(f"{self.name}: batch {n} ({len(batch)} sessions) not examined: {error}")
            return
        result = run_tshark(self.s, fetched.path, "http_responses", [self.work], http_ports=_ports(batch))
        pcap.unlink(missing_ok=True)
        if result.error:
            self.c["failed_batches"] += 1
            self.partial.append(f"{self.name}: batch {n} ({len(batch)} sessions) not examined: {result.error}")
            return
        self.c["fetched_sessions"] += len(batch)
        if fetched.capped or result.truncated:
            self.c["truncated_batches"] += 1
            self.partial.append(f"{self.name}: batch {n} capture incomplete "
                                f"({'download byte cap' if fetched.capped else 'capture cut short'})")
        by_tuple: dict[tuple, list[dict]] = {}
        for sess in batch:
            src = sess["_source"]
            client, server = src.get("source") or {}, src.get("destination") or {}
            by_tuple.setdefault(_key(server.get("ip"), server.get("port"), client.get("ip"), client.get("port")),
                                []).append(sess)
        seen: set[str] = set()
        events: list[TypedEvent] = []
        raws: dict[str, dict] = {}
        for row in result.rows:
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
            sessions = by_tuple.get(_key(*addrs), [])
            if len(sessions) > 1:
                sessions = [x for x in sessions if self._spans(x, ts.timestamp())]
            if not sessions:
                self.c["unmapped_responses"] += 1
                continue
            if len(sessions) > 1:
                self.c["ambiguous_responses"] += 1
                continue
            sess = sessions[0]
            seen.add(sess["_id"])
            if not self.window.start <= ts < self.window.end:
                self.c["outside_window"] += 1
                continue
            try:
                ev, raw = _body_event(row, addrs, ts, sess, self.name)
            except (PacketError, ValueError) as exc:
                self.c["undecodable_bodies"] += 1
                log.debug("undecodable body in %s: %s", sess["_id"], exc)
                continue
            events.append(ev)
            raws[ev.raw[0].key] = raw
        self.c["sessions_with_responses"] += len(seen)
        self.c["sessions_without_responses"] += len(batch) - len(seen)
        self.c["responses"] += len(events)
        for pb in self.pack:
            pb.consume(events)
        self.raw_sources.update(raws)
        keep = {e.raw[0].key for pb in self.pack for e in pb.retained_events()}
        self.raw_sources = {k: v for k, v in self.raw_sources.items() if k in keep}

    @staticmethod
    def _spans(sess: dict, t: float) -> bool:
        first, last = _epoch(sess["_source"].get("firstPacket")), _epoch(sess["_source"].get("lastPacket"))
        return first is not None and last is not None and first - SPAN_SLACK_S <= t <= last + SPAN_SLACK_S


def run_packet_stage(s: Settings, repo, client, hunt_id: str, window: Window, contracts: dict,
                     heartbeat: Callable[[], None] | None = None, packets: ArkimePackets | None = None,
                     owner_token: str | None = None) -> dict:
    heartbeat = heartbeat or (lambda: None)
    targets = [t for t, c in contracts.items() if c is not None and getattr(c, "time_field", "") == "firstPacket"]
    summary = {"status": "skipped", "finished": False, "targets": targets, "selection": SELECTION,
               **dict.fromkeys(COUNTERS, 0), "http_sessions_without_body_type": {}, "partial_reasons": [],
               "notes": []}
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
            sessions, partial, notes = _candidates(client, target, contracts[target], window)
            run.c["candidates"] = len(sessions)
            run.partial += partial
            run.notes += notes
            summary["http_sessions_without_body_type"][target] = _unclassified(client, target, contracts[target],
                                                                                window)
            run.run(sessions)
            heartbeat()
            cell_target = f"{PCAP_TARGET}:{target}"
            for pb in run.pack:
                matches = pb.finalize()
                for m in matches:
                    publish_match(repo, hunt_id, pb, m, None, run.raw_sources, owner_token=owner_token)
                run.c["matched"] += len(matches)
                state = ("match_on_partial" if run.partial else "matched") if matches else \
                    ("positive_only_partial" if run.partial else "positive_only")
                repo.set_rule_cell(hunt_id, pb.id, pb.version, cell_target, window.key(), state, len(matches),
                                   pb.evaluated, {**run.c, "selection": SELECTION,
                                                  "http_sessions_without_body_type":
                                                      summary["http_sessions_without_body_type"][target],
                                                  "reasons": run.partial[:20], "notes": run.notes})
            for k in COUNTERS:
                summary[k] += run.c[k]
            summary["partial_reasons"] += run.partial
            summary["notes"] += run.notes
        summary["status"] = "partial" if summary["partial_reasons"] else "complete"
        summary["finished"] = True
    finally:
        shutil.rmtree(work, ignore_errors=True)
        if own:
            packets.close()
    summary["partial_reasons"] = summary["partial_reasons"][:50]
    return summary
