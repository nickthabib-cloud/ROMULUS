"""Packet-content rules over HTTP bodies reconstructed by TShark from specific Arkime sessions.

These rules judge what a response body *is*, using its bytes: an executable header, a script's shebang, or text
whose every command line starts with a known command. They compare that with what the server said the body was
(URL file extension and declared Content-Type). A script or executable served under a document's name or type is
a classic delivery disguise (ATT&CK T1036.008, T1105).

They are positive-only: content heuristics can show a disguised script, but a body that does not look like one
proves nothing, and the stage only examines the sessions it selected. Claims state that the body was observed in
the packets, not that any client executed it.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import ClassVar

from romulus.detect.base import Match, Playbook, basename, pf
from romulus.evidence.typed import TypedEvent

EXEC_MAGICS = ((b"\x7fELF", "ELF executable"), (b"MZ", "Windows PE executable"),
               (b"\xcf\xfa\xed\xfe", "Mach-O executable"), (b"\xfe\xed\xfa\xcf", "Mach-O executable"),
               (b"\xca\xfe\xba\xbe", "Mach-O universal binary"))
KNOWN_COMMANDS = {
    "curl", "wget", "echo", "printf", "chmod", "chown", "chattr", "mkdir", "cd", "cp", "mv", "rm", "cat", "tee",
    "touch", "ln", "python", "python2", "python3", "perl", "php", "ruby", "bash", "sh", "dash", "zsh", "nc", "ncat",
    "netcat", "socat", "base64", "openssl", "crontab", "systemctl", "service", "useradd", "usermod", "passwd",
    "ssh", "scp", "iptables", "nohup", "export", "sudo", "su", "kill", "pkill", "killall", "sed", "awk", "grep",
    "find", "tar", "unzip", "gzip", "gunzip", "xxd", "dd", "mkfifo", "exec", "eval", "source", "set", "unset",
    "history", "id", "whoami", "uname", "hostname", "ps", "env", "sleep", "while", "for", "if", "then", "fi", "do",
    "done", "nslookup", "dig", "ping", "apt", "apt-get", "yum", "dnf", "pip", "pip3", "git", "busybox", "setsid",
}
INTERPRETERS = {"sh", "bash", "dash", "zsh", "ksh", "python", "python2", "python3", "perl", "php", "ruby", "node",
                "lua", "pwsh", "powershell"}
DOCUMENT_EXTENSIONS = {"md", "markdown", "txt", "text", "log", "csv", "tsv", "json", "xml", "html", "htm", "css",
                       "jpg", "jpeg", "png", "gif", "bmp", "ico", "svg", "webp", "pdf", "doc", "docx", "xls", "xlsx",
                       "ppt", "pptx", "rtf", "odt", "zip", "gz", "tar", "mp3", "mp4", "avi", "wav"}
DOCUMENT_TYPE_PREFIXES = ("text/markdown", "text/plain", "text/html", "text/css", "text/csv", "text/xml",
                          "application/json", "application/xml", "application/pdf", "image/", "audio/", "video/")
_TOKEN = re.compile(r"[A-Za-z0-9_.+-]+")


@dataclass
class BodyInfo:
    kind: str                        # executable | script | text | binary | empty
    detail: str = ""
    interpreter: str | None = None
    commands: list[str] = field(default_factory=list)
    piped_to: list[str] = field(default_factory=list)


def analyze_body(body: bytes) -> BodyInfo:
    """What the bytes are, judged only from the bytes."""
    if not body:
        return BodyInfo("empty")
    for magic, label in EXEC_MAGICS:
        if body.startswith(magic):
            if magic == b"MZ" and b"PE\x00\x00" not in body[:4096]:
                continue
            return BodyInfo("executable", label)
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return BodyInfo("binary")
    if text.startswith("#!"):
        first = text.splitlines()[0][2:].strip().split()
        prog = basename(first[1] if first and basename(first[0]) == "env" and len(first) > 1 else
                        (first[0] if first else ""))
        return BodyInfo("script", f"shebang '{text.splitlines()[0][:80]}'", interpreter=prog)
    lines = [ln.strip() for ln in text.splitlines()]
    lines = [ln for ln in lines if ln and not ln.startswith("#")]
    if not lines or len(lines) > 400:
        return BodyInfo("text")
    commands, piped = [], []
    for ln in lines:
        m = _TOKEN.match(ln)
        if not m or basename(m.group(0)) not in KNOWN_COMMANDS:
            return BodyInfo("text")
        commands.append(basename(m.group(0)))
        for seg in ln.split("|")[1:]:
            t = _TOKEN.match(seg.strip())
            if t and basename(t.group(0)) in INTERPRETERS:
                piped.append(basename(t.group(0)))
    return BodyInfo("script", f"{len(lines)} line(s), each starting with a known command", commands=commands[:20],
                    piped_to=sorted(set(piped)))


def declared_document(path: str | None, content_type: str | None) -> list[str]:
    """Why the server presented this body as a document (extension and/or declared type); empty if it did not."""
    reasons = []
    name = basename((path or "").split("?", 1)[0]).lower()
    suffixes = [s for s in name.split(".")[1:] if s and not s.isdigit()]
    doc = [s for s in suffixes if s in DOCUMENT_EXTENSIONS]
    if doc:
        reasons.append(f"file name '{name}' (extension .{doc[-1]})")
    ctype = (content_type or "").split(";", 1)[0].strip().lower()
    if ctype.startswith(DOCUMENT_TYPE_PREFIXES):
        reasons.append(f"declared Content-Type {ctype}")
    return reasons


class DisguisedScriptOrExecutable(Playbook):
    """Positive-only content rule over packet-reconstructed HTTP bodies."""
    id = "pcap.disguised_script_or_executable"
    version = "1"
    title = "HTTP response body is a script or executable served as a document"
    kind: ClassVar[str] = "packet"            # runs only in the packet stage, never in the sweep
    families = ("http_body",)
    required_fields = ("http.body.kind", "url.original")
    claim_type = "network_observation"
    assures_negative = False
    severity, lane = "high", "lead"
    attack = ("T1036.008", "T1105", "T1059")
    benign = ("installers or setup scripts deliberately served as text", "documentation pages that only list commands")
    next_checks = ("the client host's processes at the same time (did a downloader pipe it into an interpreter?)",
                   "other responses from the same server", "the body's hash on other hosts")

    def __init__(self):
        super().__init__()
        self.groups: dict[tuple, list[TypedEvent]] = {}
        self.counts: dict[tuple, int] = {}
        self.clients: dict[tuple, set] = {}

    def consume(self, events):
        for e in self.applicable(events):
            if e.get("http.body.kind") not in ("script", "executable"):
                continue
            if not declared_document(e.get("url.original"), e.get("http.content_type")):
                continue
            key = (e.get("file.sha256"), e.get("source.ip"), e.get("url.original"))
            self.counts[key] = self.counts.get(key, 0) + 1
            self.clients.setdefault(key, set()).add(str(e.get("destination.ip")))
            group = self.groups.setdefault(key, [])
            if len(group) < 20:
                group.append(e)
        return []

    def finalize(self) -> list[Match]:
        out = []
        for key in sorted(self.groups, key=str):
            evs = sorted(self.groups[key], key=lambda x: (x.ts, x.id))
            e, n = evs[0], self.counts[key]
            kind = e.get("http.body.kind")
            reasons = declared_document(e.get("url.original"), e.get("http.content_type"))
            what = e.get("http.body.detail") or kind
            piped = e.get("http.body.piped_to") or []
            lane = "high" if kind == "executable" or piped else self.lane
            clients = sorted(self.clients[key])
            claim = (f"Packets of {n} Arkime session(s) show HTTP {e.get('http.response.status_code')} responses from "
                     f"{e.get('source.ip')} to {', '.join(clients[:5])}{' and more' if len(clients) > 5 else ''} for "
                     f"'{e.get('url.original')}' ({evs[0].ts.isoformat()} – {evs[-1].ts.isoformat()}), served as a "
                     f"document ({'; '.join(reasons)}), whose body is a {kind} ({what}"
                     + (f"; it pipes into {', '.join(piped)}" if piped else "")
                     + f"; {e.get('file.size')} bytes, SHA-256 {e.get('file.sha256')}). The body is observed in the "
                     f"packets; whether a client executed it is not established by these records.")
            preds = [pf(e, "http.body.kind"), pf(e, "url.original")]
            if e.has("http.content_type"):
                preds.append(pf(e, "http.content_type"))
            m = Match(self.id, claim, self.claim_type, evs, preds, e.ts, self.severity, lane, "high",
                      e.entities(), group_key="|".join(map(str, key)))
            if n > len(evs):
                m.notes.append(f"{n} matching responses; {len(evs)} are cited")
            out.append(m)
        return out

    def retained_events(self) -> list[TypedEvent]:
        return [e for evs in self.groups.values() for e in evs]


PACKET_PLAYBOOKS = [DisguisedScriptOrExecutable]
