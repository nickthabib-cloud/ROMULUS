"""Packet-content rules over HTTP bodies reconstructed by TShark from specific Arkime sessions.

These rules judge what a response body *is*, using its bytes, and compare that with what the server said it was
(the URL's file name and the declared Content-Type). A script or executable served under a document's name or
type is a classic delivery disguise (ATT&CK T1036.008, T1105).

What the bytes are, in decreasing strength:

- `magic`: an executable header (ELF, PE with its `PE\\0\\0` signature, Mach-O). Byte-level fact.
- `shebang`: an interpreter line (`#!` followed by an absolute path). Byte-level fact; noted when it sits
  after a byte-order mark or leading whitespace, where a kernel would not honour it but an interpreter would.
- `heuristic`: every non-comment line starts with a command name, and at least one of them fetches, runs,
  decodes or persists something. A content heuristic: it suggests a script; it never shows one, and a
  heuristic-only match is never above the lead lane.

The rules are positive-only: a body that does not look like a script proves nothing, and the stage examines
only the sessions it selected. Claims state that the body was observed in the packets, not that a client ran it.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime
from typing import ClassVar
from urllib.parse import unquote, urlsplit

from romulus.detect.base import Match, Playbook, basename, pf
from romulus.evidence.typed import TypedEvent

EXEC_MAGICS = ((b"\x7fELF", "ELF executable"), (b"MZ", "Windows PE executable"),
               (b"\xcf\xfa\xed\xfe", "Mach-O executable"), (b"\xfe\xed\xfa\xcf", "Mach-O executable"),
               (b"\xce\xfa\xed\xfe", "Mach-O executable"), (b"\xfe\xed\xfa\xce", "Mach-O executable"),
               (b"\xca\xfe\xba\xbe", "Mach-O universal binary or Java class file"))
UTF8_BOM = b"\xef\xbb\xbf"
UTF16_BOMS = (b"\xff\xfe", b"\xfe\xff")
SHEBANG = re.compile(rb"#![ \t]*(/[^\s]+)(?:[ \t]+([^\s]+))?")
KNOWN_COMMANDS = {
    "curl", "wget", "echo", "printf", "chmod", "chown", "chattr", "mkdir", "cd", "cp", "mv", "rm", "cat", "tee",
    "touch", "ln", "python", "python2", "python3", "perl", "php", "ruby", "bash", "sh", "dash", "zsh", "nc", "ncat",
    "netcat", "socat", "base64", "openssl", "crontab", "systemctl", "service", "useradd", "usermod", "passwd",
    "ssh", "scp", "iptables", "nohup", "export", "sudo", "su", "kill", "pkill", "killall", "sed", "awk", "grep",
    "find", "tar", "unzip", "gzip", "gunzip", "xxd", "dd", "mkfifo", "exec", "eval", "source", "set", "unset",
    "history", "id", "whoami", "uname", "hostname", "ps", "env", "sleep", "while", "for", "if", "then", "fi", "do",
    "done", "nslookup", "dig", "ping", "apt", "apt-get", "yum", "dnf", "pip", "pip3", "git", "busybox", "setsid",
    "powershell", "pwsh", "iex", "invoke-expression", "iwr", "invoke-webrequest", "certutil", "bitsadmin",
    "mshta", "rundll32", "regsvr32", "cmd", "start-process", "schtasks", "wmic", "reg",
    # shell keywords and builtins, so ordinary script structure does not turn a script into "text"
    "else", "elif", "esac", "case", "exit", "return", "local", "read", "test", "true", "false", "wait", "trap",
    "umask", "shift", "break", "continue", "function", "until", "select", "declare", "readonly", "alias",
}
# Commands that fetch, run, decode or persist something. A command list with none of these (a cheat sheet,
# a to-do list, build steps) is not called a script.
EXECUTION_COMMANDS = {
    "curl", "wget", "chmod", "python", "python2", "python3", "perl", "php", "ruby", "bash", "sh", "dash", "zsh",
    "nc", "ncat", "netcat", "socat", "base64", "xxd", "crontab", "useradd", "nohup", "setsid", "mkfifo", "exec",
    "eval", "source", "busybox", "powershell", "pwsh", "iex", "invoke-expression", "iwr", "invoke-webrequest",
    "certutil", "bitsadmin", "mshta", "rundll32", "regsvr32", "start-process", "schtasks",
}
INTERPRETERS = {"sh", "bash", "dash", "zsh", "ksh", "python", "python2", "python3", "perl", "php", "ruby", "node",
                "lua", "pwsh", "powershell", "iex", "invoke-expression"}
DOCUMENT_EXTENSIONS = {"md", "markdown", "txt", "text", "log", "csv", "tsv", "json", "xml", "html", "htm", "css",
                       "jpg", "jpeg", "png", "gif", "bmp", "ico", "svg", "webp", "pdf", "doc", "docx", "xls", "xlsx",
                       "ppt", "pptx", "rtf", "odt", "zip", "gz", "tar", "mp3", "mp4", "avi", "wav"}
MEDIA_EXTENSIONS = {"jpg", "jpeg", "png", "gif", "bmp", "ico", "webp", "pdf", "doc", "docx", "xls", "xlsx", "ppt",
                    "pptx", "rtf", "odt", "zip", "gz", "tar", "mp3", "mp4", "avi", "wav"}
# A body under one of these names is what it says it is: no disguise, whatever the Content-Type.
SCRIPT_OR_EXEC_EXTENSIONS = {"sh", "bash", "zsh", "ksh", "py", "pyw", "pl", "pm", "rb", "php", "ps1", "psm1", "bat",
                             "cmd", "vbs", "js", "lua", "exe", "dll", "elf", "bin", "so", "msi", "jar", "class",
                             "run", "out", "appimage"}
# text/plain is what servers send for any script, so it is never evidence of a disguise on its own.
DOCUMENT_TYPE_PREFIXES = ("text/markdown", "text/html", "text/css", "text/csv", "text/xml", "application/json",
                          "application/xml", "application/pdf", "image/", "audio/", "video/")
MEDIA_TYPE_PREFIXES = ("application/pdf", "image/", "audio/", "video/")
COMPRESSION_EXTENSIONS = {"gz", "tgz", "z", "zip", "bz2", "xz", "br", "zst"}
COMPRESSION_ENCODINGS = {"gzip", "x-gzip", "deflate", "br", "compress", "x-compress", "zstd"}
# What a pipe may hand text to and have it run.
PIPE_RUNNERS = INTERPRETERS | {"exec", "eval", "source", "busybox", "xargs"}
# Commands that put a file in place to run; a bare path invoked after one of these is a dropper's last step.
STAGING_COMMANDS = {"curl", "wget", "chmod", "certutil", "bitsadmin", "iwr", "invoke-webrequest", "base64", "xxd",
                    "cp", "mv", "tftp", "scp"}
# Redirect targets whose only reason to be written by a served script is persistence or configuration change.
PERSISTENCE_TARGET = re.compile(r"(^|/)\.ssh/|^/etc/|/cron|^/var/spool/|(^|/)\.(bash|zsh|ksh)rc$|"
                                r"(^|/)\.(bash_)?profile$|(^|/)\.config/autostart|/systemd/|"
                                r"rc\.local$|ld\.so\.preload$")
STAGING_DIRS = ("/tmp/", "/var/tmp/", "/dev/shm/")
_TOKEN = re.compile(r"[A-Za-z0-9_./+-]+")
_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_ESCAPED = re.compile(r"\\.")
_QUOTED = re.compile(r"'[^']*(?:'|$)|\"[^\"]*(?:\"|$)")       # an unclosed quote runs to the end of the line
_PIPE = re.compile(r"(?<!\|)\|(?!\|)")
_REDIRECT = re.compile(r"(?<![<>&])\d?>>?\s*([^\s;&|<>()]+)")


@dataclass
class BodyInfo:
    kind: str                        # executable | script | text | binary | empty
    basis: str | None = None         # magic | shebang | heuristic
    detail: str = ""
    interpreter: str | None = None
    commands: list[str] = field(default_factory=list)
    piped_to: list[str] = field(default_factory=list)
    writes: list[str] = field(default_factory=list)


def show(value, limit: int = 200) -> str:
    """Telemetry text safe to put in a claim: control, format (bidi) and other invisible characters become
    visible escapes, and long values are cut."""
    text = str(value)
    out = "".join(c if unicodedata.category(c)[0] != "C" else f"\\u{ord(c):04x}" for c in text)
    return out if len(out) <= limit else out[:limit] + "…"


def _text(body: bytes) -> str | None:
    """The body as text, or None when it is binary (NUL bytes or many control bytes)."""
    if body.startswith(UTF16_BOMS):
        return body.decode("utf-16", "replace").lstrip("\ufeff")
    body = body.removeprefix(UTF8_BOM)
    sample = body[:65536]
    if b"\x00" in sample or sum(b < 9 or 13 < b < 32 for b in sample) > len(sample) // 20:
        return None
    try:
        return body.decode("utf-8")
    except UnicodeDecodeError:
        return body.decode("latin-1")


def _shebang(body: bytes) -> BodyInfo | None:
    lead = UTF8_BOM if body.startswith(UTF8_BOM) else b""
    rest = body[len(lead):]
    stripped = rest.lstrip(b" \t\r\n")
    m = SHEBANG.match(stripped)
    if not m:
        return None
    path = m.group(1).decode("latin-1")
    arg = m.group(2).decode("latin-1") if m.group(2) else ""
    prog = basename(arg) if basename(path) == "env" and arg else basename(path)
    line = stripped.split(b"\n", 1)[0][:80].decode("latin-1").rstrip("\r")
    note = ""
    if lead or len(stripped) != len(rest):
        note = (" after a byte-order mark or leading whitespace, where a kernel would not honour it but an "
                "interpreter given the file would")
    return BodyInfo("script", "shebang", f"interpreter line '{line}'{note}", interpreter=prog or None)


def analyze_body(body: bytes) -> BodyInfo:
    """What the bytes are, judged only from the bytes."""
    if not body:
        return BodyInfo("empty")
    for magic, label in EXEC_MAGICS:
        if body.startswith(magic):
            if magic == b"MZ" and b"PE\x00\x00" not in body[:4096]:
                continue
            return BodyInfo("executable", "magic", f"{label} header")
    info = _shebang(body)
    if info:
        return info
    text = _text(body)
    if text is None:
        return BodyInfo("binary")
    lines = [ln.strip() for ln in text.splitlines()]
    lines = [ln for ln in lines if ln and not ln.startswith("#")]
    if not lines or len(lines) > 400:
        return BodyInfo("text")
    commands, piped, writes, executes, staged = [], [], [], False, False
    staged_writes, invoked = set(), set()
    for ln in lines:
        if _ASSIGNMENT.match(ln):
            continue
        m = _TOKEN.match(ln)
        token = "[" if ln.startswith("[") else (m.group(0) if m else "")
        name = basename(token).lower()
        if token == "[":                                        # test builtin: [ ... ] && ... / [[ ... ]] || ...
            commands.append("[")
        elif not token:
            return BodyInfo("text")
        elif token.startswith(("./", "/")) and len(token) > 2:
            # a bare path runs a program only in context: run from the working or a staging directory, with an
            # option or backgrounded, or after a fetch, chmod or copy (a list of paths, `find` output or a path
            # with a description is not a script)
            commands.append(f"path:{name}")
            invoked.add(name)
            args = ln.split()[1:]
            runs = (token.startswith("./") or token.startswith(STAGING_DIRS) or staged
                    or any(a.startswith("-") or a == "&" for a in args))
            if runs and _suffix(name) not in DOCUMENT_EXTENSIONS:
                executes = True
        elif name in KNOWN_COMMANDS:
            commands.append(name)
            executes = executes or name in EXECUTION_COMMANDS
            staged = staged or name in STAGING_COMMANDS
        else:
            return BodyInfo("text")
        bare = _QUOTED.sub("''", _ESCAPED.sub("_", ln))          # pipes and redirects outside quotes only
        for seg in _PIPE.split(bare)[1:]:
            t = _TOKEN.match(seg.strip())
            prog = basename(t.group(0)).lower() if t else ""
            if prog in PIPE_RUNNERS or prog in EXECUTION_COMMANDS:     # e.g. `| sh`, `| exec ...`, `| crontab -`
                piped.append(prog)
                executes = True
        for target in _REDIRECT.findall(bare):
            if target in ("/dev/null", "/dev/stdout", "/dev/stderr"):
                continue
            writes.append(target)
            if PERSISTENCE_TARGET.search(target.replace("~", "/root")):
                executes = True
            elif target.startswith(STAGING_DIRS):
                staged_writes.add(basename(target).lower())
                staged = True
    if staged_writes & invoked:                                 # written to a staging dir, then run
        executes = True
    if not commands or not executes:
        return BodyInfo("text")
    return BodyInfo("script", "heuristic",
                    f"every one of {len(lines)} non-comment line(s) starts with a command name, and at least one "
                    f"fetches, runs, decodes or writes something", commands=commands[:20],
                    piped_to=sorted(set(piped)), writes=list(dict.fromkeys(writes))[:10])


def _name(path: str | None, encoding: str | None = None) -> str:
    """The served file name. When the server set a compressing Content-Encoding, TShark has already undone it,
    so a compression suffix describes the transfer, not the body, and is dropped."""
    raw = path or ""
    parts = urlsplit(raw)
    if parts.scheme and parts.netloc:
        raw = parts.path
    raw = raw.split("?", 1)[0].split("#", 1)[0]
    name = basename(unquote(raw)).lower()
    if (encoding or "").strip().lower() in COMPRESSION_ENCODINGS and _suffix(name) in COMPRESSION_EXTENSIONS:
        name = name.rsplit(".", 1)[0]
    return name


def _suffix(name: str) -> str | None:
    suffixes = [s for s in name.split(".")[1:] if s and not s.isdigit()]
    return suffixes[-1] if suffixes else None


def declared_document(path: str | None, content_type: str | None, encoding: str | None = None) -> list[str]:
    """Why the server presented this body as a document (file name and/or declared type); empty if it did not,
    or if the name says it is a script or program (then it is not disguised)."""
    name = _name(path, encoding)
    suffix = _suffix(name)
    if suffix in SCRIPT_OR_EXEC_EXTENSIONS:
        return []
    reasons = []
    if suffix in DOCUMENT_EXTENSIONS:
        reasons.append(f"file name '{show(name, 120)}' (extension .{suffix})")
    ctype = (content_type or "").split(";", 1)[0].strip().lower()
    if ctype.startswith(DOCUMENT_TYPE_PREFIXES):
        reasons.append(f"declared Content-Type {show(ctype, 80)}")
    return reasons


def declared_media(path: str | None, content_type: str | None, encoding: str | None = None) -> bool:
    """Declared as an image, media, office or archive file: no reading of a script makes that name honest."""
    ctype = (content_type or "").split(";", 1)[0].strip().lower()
    return _suffix(_name(path, encoding)) in MEDIA_EXTENSIONS or ctype.startswith(MEDIA_TYPE_PREFIXES)


def _declared(e: TypedEvent) -> tuple[list[str], bool]:
    args = (e.get("url.original"), e.get("http.content_type"), e.get("http.content_encoding"))
    return declared_document(*args), declared_media(*args)


class DisguisedScriptOrExecutable(Playbook):
    """Positive-only content rule over packet-reconstructed HTTP bodies."""
    id = "pcap.disguised_script_or_executable"
    version = "3"
    title = "HTTP response body is a script or executable served as a document"
    kind: ClassVar[str] = "packet"            # runs only in the packet stage, never in the sweep
    families = ("http_body",)
    required_fields = ("http.body.kind", "url.original")
    claim_type = "network_observation"
    assures_negative = False
    severity, lane = "high", "lead"
    attack = ("T1036.008", "T1105", "T1059")
    benign = ("installers or setup scripts deliberately served as text or Markdown",
              ("documentation that consists only of commands (for example, setup steps that append to a shell "
               "profile)"),
              "a misconfigured server's file names or types")
    next_checks = ("the client host's processes at the same time (did a downloader pipe it into an interpreter?)",
                   "other responses from the same server", "the body's hash on other hosts")

    def __init__(self):
        super().__init__()
        self.groups: dict[tuple, list[TypedEvent]] = {}
        self.counts: dict[tuple, int] = {}
        self.clients: dict[tuple, set] = {}
        self.spans: dict[tuple, tuple[datetime, datetime]] = {}

    def consume(self, events):
        for e in self.applicable(events):
            if e.get("http.body.kind") not in ("script", "executable"):
                continue
            if not _declared(e)[0]:
                continue
            key = (e.get("file.sha256"), e.get("source.ip"), e.get("url.original"))
            self.counts[key] = self.counts.get(key, 0) + 1
            lo, hi = self.spans.get(key, (e.ts, e.ts))
            self.spans[key] = (min(lo, e.ts), max(hi, e.ts))
            self.clients.setdefault(key, set()).add(str(e.get("destination.ip")))
            group = self.groups.setdefault(key, [])
            if len(group) < 20:
                group.append(e)
        return []

    def _what(self, e: TypedEvent) -> str:
        basis, detail = e.get("http.body.basis"), show(e.get("http.body.detail") or "", 160)
        piped = e.get("http.body.piped_to") or []
        if basis == "magic":
            return f"whose body begins with an executable header ({detail})"
        if basis == "shebang":
            return f"whose body is a script by its {detail}"
        commands = ", ".join(dict.fromkeys(e.get("http.body.commands") or []))
        writes = ", ".join(e.get("http.body.writes") or [])
        return (f"whose body reads like a shell or command script: {detail} (commands: {show(commands, 120)}"
                + (f"; it pipes into {', '.join(piped)}" if piped else "")
                + (f"; it redirects output to {show(writes, 160)}" if writes else "")
                + "). This is a content heuristic; it suggests a script and does not show one")

    def finalize(self) -> list[Match]:
        out = []
        for key in sorted(self.groups, key=str):
            evs = sorted(self.groups[key], key=lambda x: (x.ts, x.id))
            e, n = evs[0], self.counts[key]
            basis = e.get("http.body.basis")
            reasons, media = _declared(e)
            lane = "high" if basis == "magic" or (basis == "shebang" and media) else self.lane
            confidence = "high" if basis in ("magic", "shebang") else "medium"
            first, last = self.spans[key]
            clients = sorted(self.clients[key])
            size = e.get("file.size")
            claim = (f"Packets show {n} HTTP {e.get('http.response.status_code')} response(s) from "
                     f"{e.get('source.ip')} to {', '.join(clients[:5])}{' and more' if len(clients) > 5 else ''} "
                     f"for '{show(e.get('url.original'))}' ({first.isoformat()} – {last.isoformat()}), "
                     f"served as a document ({'; '.join(reasons)}), {self._what(e)}. The body is {size} bytes, "
                     f"SHA-256 {e.get('file.sha256')}. It is observed in the packets; whether a client executed it "
                     f"is not established by these records.")
            preds = [pf(e, "http.body.kind"), pf(e, "url.original")]
            if e.has("http.body.basis"):
                preds.append(pf(e, "http.body.basis"))
            if e.has("http.content_type"):
                preds.append(pf(e, "http.content_type"))
            m = Match(self.id, claim, self.claim_type, evs, preds, e.ts, self.severity, lane, confidence,
                      e.entities(), group_key="|".join(map(str, key)))
            if n > len(evs):
                m.notes.append(f"{n} matching responses; {len(evs)} are cited")
            if e.has("http.body.analysis_limit"):
                m.notes.append(f"content judged from the first {e.get('http.body.analysis_limit')} bytes; "
                               "the size and SHA-256 cover the whole body")
            out.append(m)
        return out

    def retained_events(self) -> list[TypedEvent]:
        return [e for evs in self.groups.values() for e in evs]


PACKET_PLAYBOOKS = [DisguisedScriptOrExecutable]
