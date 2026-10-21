"""Packets for specific sessions: fetched from Arkime by explicit session id, read by a constrained TShark.

Read-only and bounded by construction:

- Arkime: only `GET /api/sessions/pcap?ids=...` for validated session ids, at most 20 per request, streamed to a
  private file with a byte cap. Never an expression export, never a free-text query.
- TShark: an argv list (no shell), a path that must resolve inside an allowed directory, a display filter and
  field list chosen from fixed tables in this module (never from telemetry, users or a model), reassembly
  preferences pinned per query so a site's TShark profile cannot change what is seen, a timeout that kills the
  process, memory and CPU limits (applied by `prlimit`, so nothing runs in the forked child before exec), and no
  `-c`: `-c` limits packets read *before* the display filter and would silently drop later matches. The only
  per-run inputs are typed and validated: a list of TCP ports to decode as HTTP (each an integer 1-65535;
  Arkime saw HTTP there, and TShark only dissects HTTP on its default ports otherwise), or, for the stream
  query, one connection's two addresses and ports, re-parsed as IP addresses and port integers and printed
  from the parsed values into a fixed filter template. A capture that ends mid-packet is reported as
  truncated, so its results are partial.
- Output is TShark JSON (`-T json -e ...`): every occurrence of every field, JSON-escaped, so field values can
  never break the row format and nothing is silently reduced to its first occurrence.
- The stream query returns each data segment's own payload; `reassemble_tcp` rebuilds each direction of the
  connection by relative sequence number (retransmissions dropped, conflicting overlaps, gaps and unreadable
  segments counted) up to a byte cap per direction, and keeps the order in which the two sides spoke.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from romulus.config import Settings

SESSION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9@:_-]{8,127}$")
PCAP_MAGICS = (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x0a\x0d\x0d\x0a")
MAX_IDS_PER_REQUEST = 20
MAX_DECODE_PORTS = 32
TRUNCATION_MARKERS = ("cut short in the middle of a packet", "appears to have been cut short", "truncated")
TSHARK_MEMORY_BYTES = 4 * 1024 ** 3

# Reassembly and decoding are pinned: a different default profile on a mission system must not change what
# the stage sees (an undesegmented body would look like no response at all).
PINNED_PREFS = ("tcp.desegment_tcp_streams:TRUE", "ip.defragment:TRUE", "ipv6.defragment:TRUE",
                "http.desegment_headers:TRUE", "http.desegment_body:TRUE", "http.dechunk_body:TRUE",
                "http.decompress_body:TRUE")

# The stream query turns desegmentation off: then every data segment carries its own bytes as tcp.payload,
# whatever dissector claims the port (a dissector that reassembles would move them into tcp.segment_data), and
# `reassemble_tcp` rebuilds each direction itself. Relative sequence numbers make the offsets cited in findings
# the ones an analyst sees in Wireshark.
STREAM_PREFS = ("tcp.desegment_tcp_streams:FALSE", "tcp.analyze_sequence_numbers:TRUE",
                "tcp.relative_sequence_numbers:TRUE", "tcp.check_checksum:FALSE", "ip.defragment:TRUE",
                "ipv6.defragment:TRUE")

# The only TShark queries this module runs: (display filter, fields). Adding one is a code change and a review.
# A filter of None is built per run by `stream_filter` from one validated connection, and from nothing else.
QUERIES = {
    "http_messages": (
        "http.request || http.response",
        ["frame.number", "frame.time_epoch", "frame.protocols", "tcp.stream", "ip.src", "ip.dst", "ipv6.src",
         "ipv6.dst", "tcp.srcport", "tcp.dstport", "http.request.method", "http.response.code",
         "http.content_type", "http.content_encoding", "http.content_length", "http.response_for.uri",
         "http.file_data"],
    ),
    "tcp_payload": (
        None,
        ["frame.number", "frame.time_epoch", "frame.protocols", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
         "tcp.srcport", "tcp.dstport", "tcp.seq", "tcp.len", "tcp.payload"],
    ),
}
QUERY_PREFS = {"http_messages": PINNED_PREFS, "tcp_payload": STREAM_PREFS}
MAX_ADDRESS_CHARS = 45


class PacketError(RuntimeError):
    pass


@dataclass
class PacketFetch:
    path: Path | None
    session_ids: list[str]
    bytes: int = 0
    capped: bool = False
    error: str | None = None


@dataclass
class TsharkResult:
    rows: list[dict[str, list[str]]] = field(default_factory=list)   # field -> every occurrence, in order
    truncated: bool = False
    error: str | None = None


@dataclass
class Body:
    head: bytes            # at most the analysis limit
    size: int              # full decoded length
    sha256: str            # over the full body
    cut: bool              # head is shorter than the body


@dataclass(frozen=True)
class StreamKey:
    """One TCP connection by its endpoints. Build it with `stream_key`, which validates every part."""
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int


@dataclass
class Chunk:
    """Bytes one side added to its rebuilt stream, in the order the two sides spoke."""
    direction: str         # "c2s" (client to server) or "s2c"
    offset: int            # offset of the first byte in that direction's rebuilt stream
    length: int
    seq: int               # relative TCP sequence number of the first byte
    time: float            # capture time of the segment that carried it
    frame: int
    after_gap: bool        # bytes are missing just before this chunk


@dataclass
class TcpStreams:
    """Both directions of one connection, rebuilt from per-segment payload."""
    data: dict[str, bytes]
    chunks: list[Chunk]                        # conversation order
    gaps: dict[str, int]                       # holes where segments were never captured
    gap_bytes: dict[str, int]
    cut: dict[str, bool]                       # the per-direction byte cap was reached
    conflicts: dict[str, int]                  # retransmissions whose bytes differ from the first copy
    unreadable: int = 0                        # data segments whose payload TShark did not print in full
    foreign: int = 0                           # rows of another connection (ignored)

    def limits(self) -> list[str]:
        """Why the rebuilt content is incomplete, if it is."""
        out = []
        for d in ("c2s", "s2c"):
            if self.cut[d]:
                out.append(f"{d}: cut at the per-direction byte cap ({len(self.data[d])} bytes kept)")
            if self.gaps[d]:
                out.append(f"{d}: {self.gaps[d]} gap(s), {self.gap_bytes[d]} byte(s) never captured")
            if self.conflicts[d]:
                out.append(f"{d}: {self.conflicts[d]} retransmission(s) with different bytes (first copy kept)")
        if self.unreadable:
            out.append(f"{self.unreadable} data segment(s) without their full payload")
        return out


class ArkimePackets:
    """Fetches packets for explicit Arkime session ids. Read-only: GET on one endpoint only."""

    def __init__(self, s: Settings, transport: httpx.BaseTransport | None = None, max_bytes: int = 32 * 1024 * 1024):
        self.max_bytes = max_bytes
        self.http = httpx.Client(base_url=s.arkime_url.rstrip("/"), timeout=120, transport=transport,
                                 verify=s.arkime_verify_tls,
                                 auth=httpx.DigestAuth(s.arkime_username, s.arkime_password.get_secret_value()))

    def close(self) -> None:
        self.http.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def fetch(self, session_ids: list[str], dest: Path, max_bytes: int | None = None) -> PacketFetch:
        """Stream the capture for these ids to `dest`, stopping at `max_bytes` (default: the fetcher's cap)."""
        limit = min(self.max_bytes, max_bytes) if max_bytes is not None else self.max_bytes
        ids = list(dict.fromkeys(session_ids))
        if not ids or len(ids) > MAX_IDS_PER_REQUEST:
            raise PacketError(f"fetch 1-{MAX_IDS_PER_REQUEST} sessions per request, got {len(ids)}")
        bad = [i for i in ids if not SESSION_ID.match(i)]
        if bad:
            raise PacketError(f"refusing invalid Arkime session id(s): {bad[:3]}")
        total, capped = 0, False
        try:
            with self.http.stream("GET", "/api/sessions/pcap", params={"ids": ",".join(ids)}) as r:
                if r.status_code == 403:
                    return PacketFetch(None, ids, error="Arkime refused packet download for this account (403)")
                if r.status_code != 200:
                    return PacketFetch(None, ids, error=f"Arkime packet download failed: HTTP {r.status_code}")
                with dest.open("wb") as out:
                    for chunk in r.iter_bytes(64 * 1024):
                        if total + len(chunk) > limit:
                            out.write(chunk[: limit - total])
                            total, capped = limit, True
                            break
                        out.write(chunk)
                        total += len(chunk)
        except httpx.HTTPError as exc:
            dest.unlink(missing_ok=True)
            return PacketFetch(None, ids, error=f"Arkime packet download failed: {type(exc).__name__}")
        with dest.open("rb") as f:
            magic = f.read(4)
        if magic not in PCAP_MAGICS:
            dest.unlink(missing_ok=True)
            return PacketFetch(None, ids, error="Arkime response is not a capture file")
        return PacketFetch(dest, ids, total, capped)


def _allowed(path: Path, allowed_dirs: list[Path]) -> Path:
    resolved = path.resolve(strict=True)
    if not resolved.is_file():
        raise PacketError("capture path is not a file")
    if not any(resolved.is_relative_to(d.resolve()) for d in allowed_dirs if d.exists()):
        raise PacketError("capture path is outside the allowed directories")
    return resolved


def _ports(ports) -> list[int]:
    out = set()
    for p in ports or ():
        if isinstance(p, bool) or not isinstance(p, int) or not 1 <= p <= 65535:
            raise PacketError(f"refusing decode-as port {p!r}: not an integer 1-65535")
        out.add(p)
    if len(out) > MAX_DECODE_PORTS:
        raise PacketError(f"refusing more than {MAX_DECODE_PORTS} decode-as ports")
    return sorted(out)


def _address(value) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """An IP address as typed data: a plain string, no IPv6 zone (`%...` is free text), IPv4-mapped unwrapped."""
    if not isinstance(value, str) or not value or len(value) > MAX_ADDRESS_CHARS or "%" in value:
        raise PacketError(f"refusing address {str(value)[:60]!r}: not a plain IP address")
    try:
        ip = ipaddress.ip_address(value)
    except ValueError as exc:
        raise PacketError(f"refusing address {value[:60]!r}: not an IP address") from exc
    if ip.version == 6 and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def _port(value) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
        raise PacketError(f"refusing port {str(value)[:20]!r}: not an integer 1-65535")
    return value


def stream_key(client_ip, client_port, server_ip, server_port) -> StreamKey:
    """Validate one connection's endpoints (typed session fields, never free text)."""
    client, server = _address(client_ip), _address(server_ip)
    if client.version != server.version:
        raise PacketError("refusing a connection whose endpoints are of different IP versions")
    return StreamKey(str(client), _port(client_port), str(server), _port(server_port))


def stream_filter(key: StreamKey) -> str:
    """The stream query's display filter: one connection's data segments. Every value is re-validated and
    printed from its parsed form, so nothing but an address or a port number can reach the filter."""
    if not isinstance(key, StreamKey):
        raise PacketError("the stream query needs a StreamKey")
    k = stream_key(key.client_ip, key.client_port, key.server_ip, key.server_port)
    layer = "ip" if ipaddress.ip_address(k.client_ip).version == 4 else "ipv6"
    return (f"tcp.len > 0 && {layer}.addr == {k.client_ip} && {layer}.addr == {k.server_ip} && "
            f"tcp.port == {k.client_port} && tcp.port == {k.server_port}")


def tshark_command(s: Settings, path: Path, query: str, http_ports=(), stream: StreamKey | None = None) -> list[str]:
    display_filter, fields = QUERIES[query]
    if display_filter is None:
        display_filter = stream_filter(stream)
    elif stream is not None:
        raise PacketError(f"query {query} takes no connection")
    if http_ports and query != "http_messages":
        raise PacketError(f"query {query} takes no decode-as ports")
    exe = shutil.which(s.tshark_bin) or s.tshark_bin
    cmd = [exe, "-n", "-r", str(path)]
    for pref in QUERY_PREFS[query]:
        cmd += ["-o", pref]
    for port in _ports(http_ports):
        cmd += ["-d", f"tcp.port=={port},http"]
    cmd += ["-Y", display_filter, "-T", "json"]
    for name in fields:
        cmd += ["-e", name]
    if os.name == "posix" and shutil.which("nice"):
        cmd = ["nice", "-n", "10", *cmd]
    return cmd


def limited(cmd: list[str], timeout: int) -> list[str]:
    """Memory and CPU limits through prlimit(1) where it exists (util-linux; every supported Linux)."""
    prlimit = shutil.which("prlimit") if os.name == "posix" else None
    if not prlimit:
        return cmd
    return [prlimit, f"--as={TSHARK_MEMORY_BYTES}", f"--cpu={timeout + 5}", "--", *cmd]


def merge_captures(s: Settings, parts: list[Path], dest: Path, allowed_dirs: list[Path], timeout: int = 120) -> str | None:
    """Merge captures chronologically into one file (mergecap's default): the segments of one long Arkime session,
    each fetched alone, become one capture in packet-time order so TShark can reassemble across them.
    Returns an error, or None."""
    paths = [_allowed(p, allowed_dirs) for p in parts]
    out_dir = dest.parent.resolve(strict=True)
    if not any(out_dir.is_relative_to(d.resolve()) for d in allowed_dirs if d.exists()):
        raise PacketError("merge output is outside the allowed directories")
    tshark = shutil.which(s.tshark_bin) or s.tshark_bin
    exe = shutil.which("mergecap") or str(Path(tshark).with_name("mergecap"))
    try:
        proc = subprocess.run(limited([exe, "-w", str(dest), *map(str, paths)], timeout), capture_output=True,
                              timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return f"mergecap exceeded {timeout} s"
    except OSError as exc:
        return f"mergecap could not start: {type(exc).__name__}"
    return None if proc.returncode == 0 else f"mergecap failed (exit {proc.returncode})"


def run_tshark(s: Settings, pcap: Path, query: str, allowed_dirs: list[Path], timeout: int = 180,
               http_ports=(), stream: StreamKey | None = None) -> TsharkResult:
    """Run one fixed query over a capture. Each row maps every query field to all its occurrences."""
    _, fields = QUERIES[query]
    path = _allowed(pcap, allowed_dirs)
    cmd = limited(tshark_command(s, path, query, http_ports, stream), timeout)
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return TsharkResult(error=f"TShark exceeded {timeout} s")
    except OSError as exc:
        return TsharkResult(error=f"TShark could not start: {type(exc).__name__}")
    stderr = proc.stderr[:2000].decode("utf-8", "replace").lower()
    truncated = any(marker in stderr for marker in TRUNCATION_MARKERS)
    if proc.returncode not in (0, 2) or (proc.returncode == 2 and not truncated):
        return TsharkResult(truncated=truncated, error=f"TShark failed (exit {proc.returncode})")
    try:
        packets = json.loads(proc.stdout.decode("utf-8", "replace") or "[]")
    except json.JSONDecodeError:
        return TsharkResult(truncated=truncated, error="TShark output is not valid JSON")
    rows = []
    for pkt in packets if isinstance(packets, list) else []:
        layers = ((pkt or {}).get("_source") or {}).get("layers") or {}
        rows.append({name: [str(v) for v in (layers.get(name) or [])] for name in fields})
    return TsharkResult(rows=rows, truncated=truncated)


def decode_hex_body(value: str | None, limit: int) -> Body:
    """TShark prints http.file_data as hex. Hash the whole body (incrementally, so a large body is never held
    twice) and keep at most `limit` bytes for analysis."""
    if not value:
        return Body(b"", 0, hashlib.sha256(b"").hexdigest(), False)
    clean = value.replace(":", "")
    if len(clean) % 2:
        raise PacketError("TShark body field is not hex")
    sha, head, size, step = hashlib.sha256(), bytearray(), 0, 2 * 1024 * 1024
    try:
        for i in range(0, len(clean), step):
            chunk = bytes.fromhex(clean[i:i + step])
            sha.update(chunk)
            size += len(chunk)
            if len(head) < limit:
                head += chunk[: limit - len(head)]
    except ValueError as exc:
        raise PacketError("TShark body field is not hex") from exc
    return Body(bytes(head), size, sha.hexdigest(), size > len(head))


def _first(values):
    return values[0] if isinstance(values, list) and values else None


def _last(values):
    return values[-1] if isinstance(values, list) and values else None


def addresses(row: dict[str, list[str]]) -> tuple:
    """(src ip, src port, dst ip, dst port) of a row: the innermost IP layer (tunnels put the outer one first)
    and that packet's TCP ports."""
    protos = (_first(row.get("frame.protocols")) or "").split(":")
    upto = protos[: max((i for i, p in enumerate(protos) if p == "tcp"), default=len(protos))]
    inner = next((p for p in reversed(upto) if p in ("ip", "ipv6")), None)
    if inner is None:
        inner = "ip" if row.get("ip.src") else "ipv6"
    return (_last(row.get(f"{inner}.src", [])), _last(row.get("tcp.srcport", [])),
            _last(row.get(f"{inner}.dst", [])), _last(row.get("tcp.dstport", [])))


def _endpoint(ip, port) -> tuple[str, int] | None:
    try:
        return str(_address(ip)), _port(int(port))
    except (PacketError, TypeError, ValueError):
        return None


def reassemble_tcp(rows: list[dict[str, list[str]]], key: StreamKey, cap: int) -> TcpStreams:
    """Rebuild both directions of one connection from the stream query's rows.

    Segments are placed by relative sequence number: a byte already placed is never replaced (the first copy in
    sequence order wins, and a retransmission that disagrees is counted), a hole where segments were never
    captured is counted and the next bytes follow it directly, and each direction stops at `cap` bytes.
    Chunks keep the capture time of their segment, never earlier than the previous chunk of the same direction,
    so the conversation order cannot reorder one side's bytes."""
    client, server = (key.client_ip, key.client_port), (key.server_ip, key.server_port)
    segments: dict[str, list[tuple[int, int, float, bytes]]] = {"c2s": [], "s2c": []}
    unreadable = foreign = 0
    for row in rows:
        src_ip, sport, dst_ip, dport = addresses(row)
        src, dst = _endpoint(src_ip, sport), _endpoint(dst_ip, dport)
        if (src, dst) == (client, server):
            direction = "c2s"
        elif (src, dst) == (server, client):
            direction = "s2c"
        else:
            foreign += 1
            continue
        try:
            seq, length = int(_last(row.get("tcp.seq"))), int(_last(row.get("tcp.len")))
            frame, when = int(_first(row.get("frame.number"))), float(_first(row.get("frame.time_epoch")))
            payload = bytes.fromhex((_last(row.get("tcp.payload")) or "").replace(":", ""))
        except (TypeError, ValueError):
            unreadable += 1
            continue
        if length <= 0:
            continue
        if len(payload) < length:                      # snap length or a dissector that printed less
            unreadable += 1
        payload = payload[:length]
        if payload:
            segments[direction].append((seq, frame, when, payload))
    data: dict[str, bytes] = {}
    gaps, gap_bytes, conflicts, cut = dict.fromkeys(segments, 0), dict.fromkeys(segments, 0), \
        dict.fromkeys(segments, 0), dict.fromkeys(segments, False)
    chunks: list[Chunk] = []
    for direction, items in segments.items():
        items.sort(key=lambda x: (x[0], x[1]))
        buf, expected, gap_at, last_time = bytearray(), None, 0, float("-inf")
        for seq, frame, when, payload in items:
            if expected is None:
                expected = seq
            after_gap = False
            if seq > expected:
                gaps[direction] += 1
                gap_bytes[direction] += seq - expected
                expected, after_gap, gap_at = seq, True, len(buf)
            start = expected - seq                       # bytes of this segment already placed
            if start > 0:
                overlap = min(start, len(payload))
                pos = len(buf) - start
                if pos >= gap_at and bytes(buf[pos:pos + overlap]) != payload[:overlap]:
                    conflicts[direction] += 1
            new = payload[start:] if start > 0 else payload
            if not new:
                continue
            room = cap - len(buf)
            if room <= 0:
                cut[direction] = True
                break
            if len(new) > room:
                new, cut[direction] = new[:room], True
            last_time = max(last_time, when)
            chunks.append(Chunk(direction, len(buf), len(new), expected, last_time, frame, after_gap))
            buf += new
            expected += len(new)
            if cut[direction]:
                break
        data[direction] = bytes(buf)
    chunks.sort(key=lambda c: (c.time, c.frame, c.direction, c.offset))
    return TcpStreams(data, chunks, gaps, gap_bytes, cut, conflicts, unreadable, foreign)
