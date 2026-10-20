"""Packets for specific sessions: fetched from Arkime by explicit session id, read by a constrained TShark.

Read-only and bounded by construction:

- Arkime: only `GET /api/sessions/pcap?ids=...` for validated session ids, at most 20 per request, streamed to a
  private file with a byte cap. Never an expression export, never a free-text query.
- TShark: an argv list (no shell), a path that must resolve inside an allowed directory, a display filter and
  field list chosen from fixed tables in this module (never from telemetry, users or a model), reassembly
  preferences pinned so a site's TShark profile cannot change what is seen, a timeout that kills the process,
  memory and CPU limits (applied by `prlimit`, so nothing runs in the forked child before exec), and no `-c`: `-c` limits packets read *before* the display filter and would silently
  drop later matches. The only per-run input is a list of TCP ports to decode as HTTP, and each must be an
  integer 1-65535 (Arkime saw HTTP there; TShark only dissects HTTP on its default ports otherwise).
  A capture that ends mid-packet is reported as truncated, so its results are partial.
- Output is TShark JSON (`-T json -e ...`): every occurrence of every field, JSON-escaped, so field values can
  never break the row format and nothing is silently reduced to its first occurrence.
"""
from __future__ import annotations

import hashlib
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

# The only TShark queries this module runs: (display filter, fields). Adding one is a code change and a review.
QUERIES = {
    "http_messages": (
        "http.request || http.response",
        ["frame.number", "frame.time_epoch", "frame.protocols", "tcp.stream", "ip.src", "ip.dst", "ipv6.src",
         "ipv6.dst", "tcp.srcport", "tcp.dstport", "http.request.method", "http.response.code",
         "http.content_type", "http.content_encoding", "http.content_length", "http.response_for.uri",
         "http.file_data"],
    ),
}


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

    def fetch(self, session_ids: list[str], dest: Path) -> PacketFetch:
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
                        if total + len(chunk) > self.max_bytes:
                            out.write(chunk[: self.max_bytes - total])
                            total, capped = self.max_bytes, True
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


def tshark_command(s: Settings, path: Path, query: str, http_ports=()) -> list[str]:
    display_filter, fields = QUERIES[query]
    exe = shutil.which(s.tshark_bin) or s.tshark_bin
    cmd = [exe, "-n", "-r", str(path)]
    for pref in PINNED_PREFS:
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
               http_ports=()) -> TsharkResult:
    """Run one fixed query over a capture. Each row maps every query field to all its occurrences."""
    _, fields = QUERIES[query]
    path = _allowed(pcap, allowed_dirs)
    cmd = limited(tshark_command(s, path, query, http_ports), timeout)
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
