"""Packet stage: judge the content of selected HTTP sessions, after the sweep.

1. Select candidate sessions from the Arkime session index with typed predicates only: HTTP sessions in the
   hunt window whose response body Arkime classified as text (scripts hide there). Selection is exhaustive up
   to a cap; anything beyond the cap is recorded, never silently dropped.
2. Fetch their packets from Arkime by explicit session id (batches of 20, byte-capped) and let TShark rebuild
   the HTTP responses with a fixed query.
3. Turn each response body into a typed `http_body` event (what the bytes are, what the server said they were,
   hashes, a bounded excerpt kept as the retained raw copy) and run the packet rules over them.
4. Publish matches through the normal admission path, and write a coverage cell that states exactly how many
   candidates were examined, failed, truncated or capped. Packet rules are positive-only, so a clean result is
   never a complete negative.

Any failure here is recorded and the hunt continues: packet evidence enriches the sweep; it is never required.
"""
from __future__ import annotations

import hashlib
import logging
import shutil
import tempfile
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from romulus.config import Settings
from romulus.detect.packets import PACKET_PLAYBOOKS, analyze_body
from romulus.evidence.typed import RawRef, TypedEvent, event_id, fv
from romulus.hunt.publish import publish_match
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
MAX_SESSIONS = 500
MAX_BODY_BYTES = 1024 * 1024
EXCERPT_BYTES = 4096
PCAP_TARGET = "arkime-pcap"


def _first(value):
    return value[0] if isinstance(value, list) and value else value


def _candidates(client, target: str, contract, window: Window) -> tuple[list[dict], list[str]]:
    intent = SearchIntent(kind="raw", target=target, window=window, max_records=MAX_SESSIONS + 1,
                          purpose="packet-stage candidates",
                          filters=[Predicate(field="protocol", op="eq", value="http"),
                                   Predicate(field="http.bodyMagic", op="in", value=TEXT_BODY_MAGICS)])
    out = execute(client, intent, contract)
    reasons = list(out.reasons)
    if out.completeness == Completeness.failed:
        return [], reasons + [f"candidate query failed: {out.error}"]
    records = out.records
    if len(records) > MAX_SESSIONS:
        reasons.append(f"candidate_cap:{MAX_SESSIONS}")
        records = records[:MAX_SESSIONS]
    return records, reasons


def _tuple_key(src, sport, dst, dport) -> tuple:
    return str(src), str(sport), str(dst), str(dport)


def _body_event(row: dict, session: dict, index: str) -> tuple[TypedEvent, dict, bool]:
    src_doc = session["_source"]
    sid = session["_id"]
    body, cut = decode_hex_body(row.get("http.file_data"), MAX_BODY_BYTES)
    info = analyze_body(body)
    sha = hashlib.sha256(body).hexdigest()
    frame = row.get("frame.number") or "0"
    native = f"{sid}#frame{frame}"
    raw = {"arkime_session_id": sid, "node": src_doc.get("node"), "index": index, "frame": frame,
           "tcp_stream": row.get("tcp.stream"), "body_bytes": len(body), "body_capped": cut, "body_sha256": sha,
           "body_excerpt_hex": body[:EXCERPT_BYTES].hex()}
    ref = RawRef(target=f"{PCAP_TARGET}:{index}", native_id=native, digest=digest(raw))
    o = f"{native}:tshark"
    server_ip = row.get("ip.src") or row.get("ipv6.src")
    client_ip = row.get("ip.dst") or row.get("ipv6.dst")
    f = {
        "source.ip": fv(server_ip, f"{o}.ip.src"), "source.port": fv(int(row["tcp.srcport"]), f"{o}.tcp.srcport"),
        "destination.ip": fv(client_ip, f"{o}.ip.dst"),
        "destination.port": fv(int(row["tcp.dstport"]), f"{o}.tcp.dstport"),
        "url.original": fv(row.get("http.response_for.uri"), f"{o}.http.response_for.uri"),
        "http.response.status_code": fv(int(row["http.response.code"]) if row.get("http.response.code") else None,
                                        f"{o}.http.response.code"),
        "http.content_type": fv(row.get("http.content_type"), f"{o}.http.content_type"),
        "file.size": fv(len(body), f"{o}.http.file_data#bytes"),
        "file.sha256": fv(sha, f"{o}.http.file_data#sha256"),
        "http.body.kind": fv(info.kind, f"{o}.http.file_data#analysis"),
        "http.body.detail": fv(info.detail or None, f"{o}.http.file_data#analysis"),
        "http.body.interpreter": fv(info.interpreter, f"{o}.http.file_data#analysis"),
        "http.body.commands": fv(info.commands or None, f"{o}.http.file_data#analysis"),
        "http.body.piped_to": fv(info.piped_to or None, f"{o}.http.file_data#analysis"),
        "arkime.session_id": fv(sid, f"{sid}:_id"),
        "network.community_id": fv(_first((src_doc.get("network") or {}).get("community_id")),
                                   f"{sid}:network.community_id"),
    }
    caveats = ["response body capped at 1 MiB for analysis"] if cut else []
    ts = datetime.fromtimestamp(float(row["frame.time_epoch"]), UTC)
    event = TypedEvent(id=event_id("http_body", [ref]), family="http_body", ts=ts, host=src_doc.get("node"),
                       fields={k: v for k, v in f.items() if v.value is not None}, raw=[ref],
                       normalizer="tshark-http@1", caveats=caveats)
    return event, raw, cut


def run_packet_stage(s: Settings, repo, client, hunt_id: str, window: Window, contracts: dict,
                     heartbeat: Callable[[], None] | None = None, packets: ArkimePackets | None = None,
                     owner_token: str | None = None) -> dict:
    heartbeat = heartbeat or (lambda: None)
    targets = [t for t, c in contracts.items() if c is not None and getattr(c, "time_field", "") == "firstPacket"]
    summary = {"status": "skipped", "targets": targets, "candidates": 0, "fetched": 0, "responses": 0,
               "matched": 0, "failed_batches": 0, "truncated_batches": 0, "reasons": []}
    if not targets:
        summary["reasons"].append("no Arkime session target in this hunt")
        return summary
    packets = packets or ArkimePackets(s)
    pack = [cls() for cls in PACKET_PLAYBOOKS]
    events: list[TypedEvent] = []
    raw_sources: dict[str, dict] = {}
    work_root = s.home / "stage"
    work_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="romulus-pcap-", dir=work_root))
    try:
        for target in targets:
            sessions, reasons = _candidates(client, target, contracts[target], window)
            summary["candidates"] += len(sessions)
            summary["reasons"] += reasons
            by_tuple = {}
            for sess in sessions:
                src = sess["_source"]
                client_side = (src.get("source") or {})
                server_side = (src.get("destination") or {})
                by_tuple[_tuple_key(server_side.get("ip"), server_side.get("port"),
                                    client_side.get("ip"), client_side.get("port"))] = sess
            for i in range(0, len(sessions), MAX_IDS_PER_REQUEST):
                heartbeat()
                batch = sessions[i:i + MAX_IDS_PER_REQUEST]
                pcap = work / f"batch-{i // MAX_IDS_PER_REQUEST}.pcap"
                try:
                    fetched = packets.fetch([b["_id"] for b in batch], pcap)
                except PacketError as exc:
                    summary["failed_batches"] += 1
                    summary["reasons"].append(str(exc))
                    continue
                if fetched.error or fetched.path is None:
                    summary["failed_batches"] += 1
                    summary["reasons"].append(fetched.error or "no packets")
                    continue
                if fetched.capped:
                    summary["truncated_batches"] += 1
                    summary["reasons"].append("packet download byte cap reached")
                summary["fetched"] += len(batch)
                result = run_tshark(s, fetched.path, "http_responses", [work])
                pcap.unlink(missing_ok=True)
                if result.error:
                    summary["failed_batches"] += 1
                    summary["reasons"].append(result.error)
                    continue
                if result.truncated:
                    summary["truncated_batches"] += 1
                    summary["reasons"].append("capture cut short")
                for row in result.rows:
                    sess = by_tuple.get(_tuple_key(row.get("ip.src") or row.get("ipv6.src"), row.get("tcp.srcport"),
                                                   row.get("ip.dst") or row.get("ipv6.dst"), row.get("tcp.dstport")))
                    if sess is None or not row.get("frame.time_epoch") or not row.get("tcp.srcport"):
                        continue
                    try:
                        ev, raw, _cut = _body_event(row, sess, target)
                    except (PacketError, ValueError) as exc:
                        summary["reasons"].append(f"response not decodable: {exc}")
                        continue
                    events.append(ev)
                    raw_sources[ev.raw[0].key] = raw
            summary["responses"] = len(events)
        heartbeat()
        for pb in pack:
            pb.consume(events)
            matches = pb.finalize()
            for m in matches:
                publish_match(repo, hunt_id, pb, m, None, raw_sources, owner_token=owner_token)
            summary["matched"] += len(matches)
            partial = bool(summary["failed_batches"] or summary["truncated_batches"]
                           or any(r.startswith(("candidate", "cap:", "total_relation")) for r in summary["reasons"]))
            state = ("match_on_partial" if partial else "matched") if matches else \
                ("positive_only_partial" if partial else "positive_only")
            repo.set_rule_cell(hunt_id, pb.id, pb.version, PCAP_TARGET, window.key(), state, len(matches),
                               pb.evaluated, {k: summary[k] for k in ("candidates", "fetched", "responses",
                                                                       "failed_batches", "truncated_batches")}
                               | {"reasons": sorted(set(summary["reasons"]))[:20]})
        summary["status"] = "partial" if (summary["failed_batches"] or summary["truncated_batches"]) else "complete"
    finally:
        shutil.rmtree(work, ignore_errors=True)
    summary["reasons"] = sorted(set(summary["reasons"]))[:50]
    return summary
