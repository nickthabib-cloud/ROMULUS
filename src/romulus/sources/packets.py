"""Packets for specific sessions: fetched from Arkime by explicit session id, read by a constrained TShark.

Read-only and bounded by construction:

- Arkime: only `GET /api/sessions/pcap?ids=...` for validated session ids, at most 20 per request, streamed to a
  private file with a byte cap. Never an expression export, never a free-text query.
- TShark: an argv list (no shell), a path that must resolve inside an allowed directory, a display filter and
  field list chosen from fixed tables in this module (never from telemetry, users or a model), a timeout that
  kills the process, and no `-c`: `-c` limits packets read *before* the display filter and would silently drop
  later matches. A capture that ends mid-packet is reported as truncated, so its results are partial.
"""
from __future__ import annotations

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
TRUNCATION_MARKERS = ("cut short in the middle of a packet", "appears to have been cut short", "truncated")

# The only TShark queries this module runs: (display filter, fields). Adding one is a code change and a review.
QUERIES = {
    "http_responses": (
        "http.response",
        ["frame.number", "frame.time_epoch", "tcp.stream", "ip.src", "tcp.srcport", "ip.dst", "tcp.dstport",
         "ipv6.src", "ipv6.dst", "http.response.code", "http.content_type", "http.content_length",
         "http.response_for.uri", "http.file_data"],
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
    rows: list[dict] = field(default_factory=list)
    truncated: bool = False
    error: str | None = None


class ArkimePackets:
    """Fetches packets for explicit Arkime session ids. Read-only: GET on one endpoint only."""

    def __init__(self, s: Settings, transport: httpx.BaseTransport | None = None, max_bytes: int = 32 * 1024 * 1024):
        self.max_bytes = max_bytes
        self.http = httpx.Client(base_url=s.arkime_url.rstrip("/"), timeout=120, transport=transport,
                                 auth=httpx.DigestAuth(s.arkime_username, s.arkime_password.get_secret_value()))

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


def run_tshark(s: Settings, pcap: Path, query: str, allowed_dirs: list[Path], timeout: int = 180) -> TsharkResult:
    """Run one fixed query over a capture. Each output row is a dict of the query's fields."""
    display_filter, fields = QUERIES[query]
    path = _allowed(pcap, allowed_dirs)
    exe = shutil.which(s.tshark_bin) or s.tshark_bin
    cmd = [exe, "-n", "-r", str(path), "-Y", display_filter, "-T", "fields", "-E", "separator=\t",
           "-E", "occurrence=f"]
    for name in fields:
        cmd += ["-e", name]
    if os.name == "posix" and shutil.which("nice"):
        cmd = ["nice", "-n", "10", *cmd]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return TsharkResult(error=f"TShark exceeded {timeout} s")
    except OSError as exc:
        return TsharkResult(error=f"TShark could not start: {type(exc).__name__}")
    stderr = proc.stderr[:2000].lower()
    truncated = any(marker in stderr for marker in TRUNCATION_MARKERS)
    if proc.returncode not in (0, 2) or (proc.returncode == 2 and not truncated):
        return TsharkResult(truncated=truncated, error=f"TShark failed (exit {proc.returncode})")
    rows = []
    for line in proc.stdout.splitlines():
        values = line.split("\t")
        rows.append({name: (values[i] if i < len(values) and values[i] != "" else None)
                     for i, name in enumerate(fields)})
    return TsharkResult(rows=rows, truncated=truncated)


def decode_hex_body(value: str | None, limit: int) -> tuple[bytes, bool]:
    """TShark prints http.file_data as hex. Decode at most `limit` bytes; report whether it was cut."""
    if not value:
        return b"", False
    clean = value.replace(":", "")
    cut = len(clean) > limit * 2
    try:
        return bytes.fromhex(clean[: limit * 2]), cut
    except ValueError as exc:
        raise PacketError("TShark body field is not hex") from exc
