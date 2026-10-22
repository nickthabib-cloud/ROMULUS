"""Packet-content rules over content reconstructed by TShark from specific Arkime sessions.

HTTP bodies. These rules judge what a response body *is*, using its bytes, and compare that with what the server said it was
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

Cleartext streams. `analyze_stream` reads both rebuilt directions of one TCP connection and looks for
independent signs of an interactive command shell, each tied to the conversation's turn-taking (which side
spoke when), never to text anywhere in the bytes:

- `prompt` / `bare_prompt`: output bursts end in a full-form shell prompt (or a bare `$`, `#`, `%`), and the
  other side's next bytes are typed text;
- `banner`: a shell's start-up message in the shell side's opening text (every byte before it printable);
- `login_dialogue`: a login prompt and then a password prompt, each answered with text;
- `output:<command>`: a command line from one side, then that command's characteristic output from the other
  (`id` and `uid=...(...) gid=...(...)`, `uname` and an OS name line, `ls -l` and a long listing, and so on);
- `shell_error`: a command line, then the shell's "not found" message naming that same command.

A text line counts only when every character is printable once telnet negotiation, terminal escapes and line
editing are removed, so text embedded in a binary protocol's framing never counts. The rule needs two different
indicators. It is positive-only and cites offsets and digests, never the bytes.
"""
from __future__ import annotations

import bisect
import hashlib
import ipaddress
import itertools
import re
import shlex
import unicodedata
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import ClassVar, Protocol
from urllib.parse import unquote, urlsplit

from romulus.detect.base import Match, Playbook, basename, pf
from romulus.detect.correlation import external
from romulus.detect.host import is_internal
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
# What a pipe may hand text to and have it run (or installed, for crontab and at).
PIPE_RUNNERS = INTERPRETERS | {"exec", "eval", "source", "busybox", "xargs", "crontab", "at", "batch"}
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
            # a bare path runs a program only in context: with an option or backgrounded, or after a fetch,
            # chmod, copy or a write to a staging directory (a list of paths, `find` output, a list of temp files
            # or a path with a description is not a script)
            commands.append(f"path:{name}")
            invoked.add(name)
            args = ln.split()[1:]
            runs = staged or any(a.startswith("-") or a == "&" for a in args)
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
            if prog in PIPE_RUNNERS:                                 # e.g. `| sh`, `| exec ...`, `| crontab -`
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


# ---- cleartext interactive shells ---------------------------------------------------------------

DIRECTIONS = ("c2s", "s2c")
_LINE_END = re.compile(rb"\r\n|\r\x00|\n|\r")
# Telnet negotiation: subnegotiation, WILL/WONT/DO/DONT with their option byte, other commands; IAC IAC is a
# literal 0xff data byte.
_IAC = re.compile(rb"\xff\xfa.{0,256}?\xff\xf0|\xff[\xfb-\xfe].|\xff[\xf0-\xfa]|\xff\xff", re.DOTALL)
# Terminal escapes a PTY shell prints around a coloured prompt (CSI, OSC titles, charset and mode selects).
_ANSI = re.compile(rb"\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]{0,512}(?:\x07|\x1b\\)|\x1b[()][0-9A-Za-z]|"
                   rb"\x1b[=>78DEHMc]")
PROMPTS = tuple(re.compile(p) for p in (
    r"[A-Za-z0-9_.-]{1,32}@[A-Za-z0-9_.-]{1,64}:\S{0,240}[$#]",                # user@host:~/dir$
    r"\[[A-Za-z0-9_.-]{1,32}@[A-Za-z0-9_.-]{1,64}[ :][^\]]{0,240}\][$#]",      # [user@host dir]#
    r"(?:ba|da|z|k)?sh-\d+(?:\.\d+)*[$#]",                                     # bash-5.1$, sh-4.2#
    r"(?:PS )?[A-Za-z]:\\[^<>|\"]{0,240}>",                                    # C:\Users\bob>, PS C:\>
))
BARE_PROMPT = re.compile(r"[$#%]")                    # sh -i, dash, zsh: weak alone, so it needs more repeats
LOGIN_PROMPT = re.compile(r"(?:[A-Za-z0-9_.-]{1,64} )?[Ll]ogin: ?")
PASSWORD_PROMPT = re.compile(r"[Pp]assword: ?")
BANNERS = tuple(re.compile(p) for p in (
    r"(?:/[\w/]*/)?(?:ba|da|z|k)?sh: (?:\d+: )?can't access tty; job control turned off",
    r"(?:ba|da|z|k)?sh: no job control in this shell",
    r"(?:ba|z)?sh: cannot set terminal process group \(-?\d+\): Inappropriate ioctl for device",
    r"Microsoft Windows \[Version \d+(?:\.\d+)+\]",
    r"Windows PowerShell",
))
SHELL_ERRORS = tuple(re.compile(p) for p in (
    r"(?:/[\w/]*/)?(?:ba|da|z|k|mk)?sh: (?:line )?(?:\d+: )?(?P<cmd>[^\s:]{1,128}): (?:command )?not found",
    r"(?P<cmd>[^\s:]{1,128}): command not found",
    r"'(?P<cmd>[^']{1,128})' is not recognized as an internal or external command,",
    r"(?P<cmd>\S{1,128}) : The term '(?P=cmd)' is not recognized as .*",
))
_LISTING = (r"[-dlcbps][rwxsStT-]{9}[.+@]?\s+\d+\s+\S+\s+\S+\s+\d+(?:,\s*\d+)?\s+\S+\s+\d{1,2}\s+"
            r"(?:\d{1,2}:\d{2}|\d{4})\s+\S.*")
# DOMAIN\user only: a bare Unix account name is one lowercase word, which any line protocol can return.
_ACCOUNT = r"[A-Za-z0-9_.-]{1,64}\\[A-Za-z0-9_.$ -]{1,64}"
# command -> (output line pattern, matching lines needed, what that output is). Each pairing is one indicator.
OUTPUT_SIGNATURES = {
    "id": (r"uid=\d+\([^()\s]{1,64}\) gid=\d+\([^()\s]{1,64}\)(?: .*)?", 1, "uid=…(…) gid=…(…) identity line"),
    "uname": (r"(?:Linux|FreeBSD|OpenBSD|NetBSD|Darwin|SunOS|AIX)(?: \S.*)?", 1, "operating-system name line"),
    "ls": (_LISTING, 2, "long directory listing"),
    "cat": (r"root:[^:\s]*:0:0:.*", 1, "root account line of /etc/passwd"),
    "ps": (r"\s*(?:PID\s+TTY\s+(?:STAT\s+)?TIME\s+CMD|USER\s+PID\s+%CPU\s+%MEM\b.*|UID\s+PID\s+PPID\b.*)", 1,
           "process table header"),
    "ifconfig": (r"\s*inet (?:addr:)?\d{1,3}(?:\.\d{1,3}){3}\b.*", 1, "interface address line"),
    "ip": (r"\s*inet \d{1,3}(?:\.\d{1,3}){3}/\d{1,2}\b.*", 1, "interface address line"),
    "netstat": (r"\s*Proto\s+Recv-Q\s+Send-Q\b.*", 1, "socket table header"),
    "ss": (r"\s*(?:Netid\s+)?State\s+Recv-Q\s+Send-Q\b.*", 1, "socket table header"),
    "pwd": (r"/\S{0,255}", 1, "absolute directory path"),
    "whoami": (_ACCOUNT, 1, "domain-qualified account name"),
    "ipconfig": (r"\s*Windows IP Configuration\s*", 1, "Windows IP configuration header"),
    "dir": (r"\s*Directory of [A-Za-z]:\\.*", 1, "Windows directory listing header"),
    "systeminfo": (r"OS Name:\s+\S.*", 1, "Windows system information line"),
    "tasklist": (r"\s*Image Name\s+PID\s+Session Name\b.*", 1, "Windows process table header"),
}
_OUTPUT_RE = {cmd: re.compile(spec[0]) for cmd, spec in OUTPUT_SIGNATURES.items()}
WINDOWS_COMMANDS = {"whoami", "ipconfig", "dir", "systeminfo", "tasklist"}
OPENING_BYTES = 4096                 # a start-up banner sits in the shell side's opening text
OUTPUT_WINDOW_BYTES = 65536          # output examined after one command
MAX_COMMAND_CHARS = 512
MAX_COMMANDS = 2000                  # command lines paired with output per direction (more is a stated limit)
PROMPT_SCAN_BYTES = 512              # a prompt is the tail of the shell side's last line; longer lines are not prompts
MIN_INDICATORS = 2                   # independent kinds for the full claim and its lanes
# One of these alone still stands as a lead: each is the shell's own output in answer to the other side (a banner
# counts only when the other side then typed). A prompt or a login dialogue alone does not.
STRONG_KINDS = ("banner", "shell_error", "output:", "prompt")   # "prompt" is full-form only; not "bare_prompt"
SINGLE_MIN_TURNS = 4                 # a lone indicator needs a conversation, not one question and one answer
TYPED_TEXT_KINDS = {"shell_error"}   # matched bytes repeat what the operator typed: no digest is kept


class StreamChunk(Protocol):
    """Bytes one side added to its rebuilt stream (the packet source's chunk type, by shape)."""
    direction: str           # "c2s" | "s2c"
    offset: int              # in that direction's rebuilt stream
    length: int
    seq: int                 # relative TCP sequence number of the first byte
    time: float
    after_gap: bool          # bytes are missing just before it


@dataclass
class ShellIndicator:
    kind: str                        # prompt | banner | login_dialogue | shell_error | output:<command>
    direction: str                   # the direction whose bytes matched (the shell side's output)
    offset: int                      # offset in that direction's rebuilt stream
    seq: int | None                  # relative TCP sequence number of that byte
    length: int
    sha256: str | None               # of the matched bytes (None when they repeat typed text); bytes never kept
    time: float
    count: int = 1
    command_offset: int | None = None        # the command line, in the other direction
    command_seq: int | None = None
    command_length: int | None = None

    def as_dict(self) -> dict:
        out = {"kind": self.kind, "direction": self.direction, "offset": self.offset, "seq": self.seq,
               "length": self.length, "sha256": self.sha256, "count": self.count,
               "time": datetime.fromtimestamp(self.time, UTC).isoformat()}
        if self.command_offset is not None:
            out.update(command_offset=self.command_offset, command_seq=self.command_seq,
                       command_length=self.command_length)
        return out


@dataclass
class ShellAnalysis:
    side: str | None                 # "client" | "server": the endpoint whose bytes read as shell output
    indicators: list[ShellIndicator]
    turns: int                       # changes of speaker
    limits: list[str] = field(default_factory=list)      # analysis that stopped short

    @property
    def kinds(self) -> list[str]:
        return sorted({i.kind for i in self.indicators})


@dataclass
class _Burst:
    direction: str
    start: int
    end: int


@dataclass
class _Line:
    start: int
    end: int                         # exclusive, before the line terminator
    terminated: bool


def _clean(raw: bytes) -> str | None:
    """A line as printable text: telnet negotiation, terminal escapes, NUL and BEL removed, backspace and DEL
    applied as line editing. None when anything unprintable remains: binary data is never a text line."""
    b = _IAC.sub(lambda m: b"\xff" if m.group(0) == b"\xff\xff" else b"", raw)
    b = _ANSI.sub(b"", b).replace(b"\x00", b"").replace(b"\x07", b"")
    if b"\x08" in b or b"\x7f" in b:
        out = bytearray()
        for c in b:
            if c in (8, 127):
                if out:
                    out.pop()
            else:
                out.append(c)
        b = bytes(out)
    try:
        text = b.decode("utf-8")
    except UnicodeDecodeError:
        text = b.decode("latin-1")
    return text if text.replace("\t", " ").isprintable() else None


def _lines(data: bytes, start: int, end: int, breaks: list[int]) -> list[_Line]:
    """Lines of data[start:end]. A hole in the capture also ends a line, so bytes on both sides never join."""
    out = []
    bounds = [start, *[b for b in breaks if start < b < end], end]
    for lo, hi in itertools.pairwise(bounds):
        pos = lo
        for m in _LINE_END.finditer(data, lo, hi):
            out.append(_Line(pos, m.start(), True))
            pos = m.end()
        if pos < hi:
            out.append(_Line(pos, hi, False))
    return out


def _bursts(chunks: list[StreamChunk]) -> list[_Burst]:
    out: list[_Burst] = []
    for c in chunks:
        if out and out[-1].direction == c.direction and out[-1].end == c.offset:
            out[-1].end += c.length
        else:
            out.append(_Burst(c.direction, c.offset, c.offset + c.length))
    return out


def _texty(raw: bytes) -> bool:
    """Bytes a person types: printable text, Enter or line editing (telnet negotiation alone is not typing)."""
    pieces = _LINE_END.split(raw)
    cleaned = [_clean(p) for p in pieces]
    return all(c is not None for c in cleaned) and (any(cleaned) or len(pieces) > 1)


def _tokens(text: str) -> list[str]:
    """Shell words of a command line (quotes honoured), with a leading `sudo [-u user]` removed."""
    try:
        tokens = shlex.split(text, posix=True)
    except ValueError:
        tokens = text.split()
    while tokens and tokens[0] == "sudo":                # sudo [-u user] command ...
        tokens = tokens[1:]
        while tokens and tokens[0].startswith("-"):
            tokens = tokens[2:] if tokens[0] in ("-u", "-g") else tokens[1:]
    return tokens


def _args_fit(name: str, args: list[str]) -> bool:
    """Arguments an output pattern depends on: `ls` must ask for the long format (a short-option group holding
    `l`, as in -l, -la, -alh), `cat` must read /etc/passwd, `ip` must list addresses."""
    if name == "ls":
        return any(a.startswith("-") and not a.startswith("--") and "l" in a[1:] for a in args)
    if name == "cat":
        return "/etc/passwd" in args
    if name == "ip":
        return any(a in ("a", "addr", "address") for a in args)
    return True


def _echo(shown: str, command: str) -> bool:
    """The shell side repeating the command line (a terminal's echo, after a prompt or alone)."""
    return shown == command or shown.endswith((" " + command, ">" + command))


def _command_name(token: str) -> str | None:
    name = re.split(r"[\\/]", token)[-1].rstrip(";&|")
    if name.lower().endswith(".exe"):
        name = name[:-4]
    if name in OUTPUT_SIGNATURES:
        return name
    return name.lower() if name.lower() in WINDOWS_COMMANDS else None


class _Side:
    """One orientation: `out` is the direction read as shell output, `inp` the one read as commands."""

    def __init__(self, data: dict[str, bytes], chunks: list[StreamChunk], bursts: list[_Burst], out: str):
        self.data, self.bursts, self.out = data, bursts, out
        self.inp = "c2s" if out == "s2c" else "s2c"
        self.limits: list[str] = []
        self.breaks = {d: sorted(c.offset for c in chunks if c.direction == d and c.after_gap)
                       for d in DIRECTIONS}
        self.chunks = {d: [c for c in chunks if c.direction == d] for d in DIRECTIONS}
        self.starts = {d: [c.offset for c in self.chunks[d]] for d in DIRECTIONS}
        pos, self.after = dict.fromkeys(DIRECTIONS, 0), []
        for b in bursts:                              # bytes each side had sent once burst i ended
            pos[b.direction] = b.end
            self.after.append(dict(pos))

    def _chunk(self, d: str, offset: int) -> StreamChunk:
        i = max(0, bisect.bisect_right(self.starts[d], offset) - 1)
        return self.chunks[d][i]

    def _seq(self, d: str, offset: int) -> int:
        c = self._chunk(d, offset)
        return c.seq + (offset - c.offset)

    def indicator(self, kind: str, start: int, end: int, count: int = 1, command: _Line | None = None):
        """An indicator cited by position. The matched bytes get a digest only when they are the shell's own
        fixed-form output: a command line, or an error line that repeats what was typed, can hold a secret (a
        password typed at a prompt), and a digest of a short secret is a dictionary lookup away from it."""
        data = self.data[self.out][start:end]
        digest = hashlib.sha256(data).hexdigest() if kind not in TYPED_TEXT_KINDS else None
        ind = ShellIndicator(kind, self.out, start, self._seq(self.out, start), end - start, digest,
                             self._chunk(self.out, max(start, end - 1)).time, count)
        if command is not None:
            ind.command_offset, ind.command_seq = command.start, self._seq(self.inp, command.start)
            ind.command_length = command.end - command.start
        return ind

    def _pending(self, i: int) -> list[tuple[int, int, str]]:
        """The shell side's unfinished last line when burst i ended (what sat on screen when the other side
        spoke next), as (start, end, text): the whole unfinished line, and the part burst i added to it when the
        line began earlier (a shell without a terminal prints prompts back to back: `$ $ $ `)."""
        data, end = self.data[self.out], self.after[i][self.out]
        breaks = self.breaks[self.out]
        after_gap = bisect.bisect_right(breaks, end)            # a hole in the capture also ends a line
        floor = max(0, end - PROMPT_SCAN_BYTES, breaks[after_gap - 1] if after_gap else 0)
        start = max(floor, data.rfind(b"\n", floor, end) + 1, data.rfind(b"\r", floor, end) + 1)
        out = []
        for lo in dict.fromkeys((start, max(start, self.bursts[i].start))):
            text = _clean(data[lo:end])
            if text and text.strip():
                out.append((lo, end, text.rstrip(" \t")))
        return out

    def prompts(self) -> list[ShellIndicator]:
        strong, bare, logins, passwords = {}, {}, [], []
        for i in range(len(self.bursts) - 1):
            b, nxt = self.bursts[i], self.bursts[i + 1]      # consecutive bursts always change speaker
            if b.direction != self.out:
                continue
            if not _texty(self.data[self.inp][nxt.start:nxt.end]):
                continue
            for start, end, text in self._pending(i):
                if any(p.fullmatch(text) for p in PROMPTS):
                    strong.setdefault(start, end)
                elif BARE_PROMPT.fullmatch(text):
                    bare.setdefault(start, end)
                elif LOGIN_PROMPT.fullmatch(text):
                    logins.append((i, start, end))
                elif PASSWORD_PROMPT.fullmatch(text):
                    passwords.append((i, start, end))
                else:
                    continue
                break
        out = []
        if len(strong) >= 2 or len(strong) + len(bare) >= 3:
            # Full-form prompts (user@host:path$, C:\path>) are their own indicator; bare `$ `, `# ` and `% ` are
            # weaker and never stand alone.
            first = min({**bare, **strong})
            kind = "prompt" if len(strong) >= 2 else "bare_prompt"
            out.append(self.indicator(kind, first, {**bare, **strong}[first], len(strong) + len(bare)))
        for i, start, end in logins:
            if any(j > i for j, _s, _e in passwords):
                out.append(self.indicator("login_dialogue", start, end))
                break
        return out

    def banner(self) -> list[ShellIndicator]:
        data = self.data[self.out]
        for line in _lines(data, 0, min(len(data), OPENING_BYTES), self.breaks[self.out]):
            text = _clean(data[line.start:line.end])
            if text is None:
                return []                         # something unprintable came first: not a shell's opening
            if any(p.fullmatch(text.strip()) for p in BANNERS):
                answered = any(b.direction == self.inp and i > 0 and self.after[i - 1][self.out] >= line.end
                               and _texty(self.data[self.inp][b.start:b.end])
                               for i, b in enumerate(self.bursts))
                return [self.indicator("banner", line.start, line.end)] if answered else []
        return []

    def commands(self) -> list[tuple[int, _Line, str, list[str]]]:
        """(burst index holding the line's terminator, line, text, tokens) for the other side's text lines."""
        data = self.data[self.inp]
        ins = [(i, b) for i, b in enumerate(self.bursts) if b.direction == self.inp]
        ends = [b.end for _i, b in ins]
        out = []
        for line in _lines(data, 0, len(data), self.breaks[self.inp]):
            if not line.terminated or line.end == line.start or line.end - line.start > 4 * MAX_COMMAND_CHARS:
                continue
            text = _clean(data[line.start:line.end])
            if not text or not text.strip() or len(text) > MAX_COMMAND_CHARS:
                continue
            k = bisect.bisect_right(ends, line.end)
            if k >= len(ins):
                continue
            tokens = _tokens(text.strip())
            if tokens:
                out.append((ins[k][0], line, text.strip(), tokens))
        return out

    def _window(self, k: int, nxt: int) -> list[tuple[_Line, str]]:
        """The shell side's printable lines after burst k and before burst nxt (where the next command line
        ended), at most OUTPUT_WINDOW_BYTES of them."""
        data = self.data[self.out]
        lo = self.after[k][self.out]
        hi = min(self.after[nxt - 1][self.out], lo + OUTPUT_WINDOW_BYTES)
        out = []
        for line in _lines(data, lo, hi, self.breaks[self.out]) if hi > lo else []:
            shown = _clean(data[line.start:line.end])
            if shown and shown.strip():
                out.append((line, shown.rstrip()))
        return out

    def outputs(self) -> list[ShellIndicator]:
        found: dict[str, list] = {}
        cmds = self.commands()
        if len(cmds) > MAX_COMMANDS:
            self.limits.append(f"{self.inp}: {len(cmds)} text lines read as commands; the first {MAX_COMMANDS} "
                               "were paired with output")
        # Command lines that ended in one burst share their output window; each window's lines are matched once
        # per pattern, so the work grows with the bytes, not with commands times lines.
        windows: dict[int, tuple[list, dict, dict]] = {}
        for j, (k, line, text, tokens) in enumerate(cmds[:MAX_COMMANDS]):
            if k not in windows:
                lines = self._window(k, next((kk for kk, *_rest in cmds[j + 1:] if kk > k), len(self.bursts)))
                errors: dict[str, _Line] = {}
                for ln, shown in lines:
                    if "not found" in shown or "not recognized" in shown:
                        m = next((m for p in SHELL_ERRORS if (m := p.fullmatch(shown.strip()))), None)
                        if m:
                            errors.setdefault(m.group("cmd").lower(), ln)
                windows[k] = (lines, errors, {})
            lines, errors, matched = windows[k]
            name = _command_name(tokens[0])
            if name and _args_fit(name, tokens[1:]):
                if name not in matched:
                    matched[name] = [(ln, shown) for ln, shown in lines if _OUTPUT_RE[name].fullmatch(shown)]
                hits = [ln for ln, shown in matched[name] if not _echo(shown, text)]
                need = OUTPUT_SIGNATURES[name][1]
                if len(hits) >= need:
                    found.setdefault(f"output:{name}", []).append((hits[0].start, hits[need - 1].end, line))
            error = errors.get(tokens[0].lower())             # the shell's error names what was just sent
            if error is not None:
                found.setdefault("shell_error", []).append((error.start, error.end, line))
        return [self.indicator(kind, hits[0][0], hits[0][1], len(hits), hits[0][2])
                for kind, hits in sorted(found.items())]

    def all(self) -> list[ShellIndicator]:
        return self.prompts() + self.banner() + self.outputs()


def analyze_stream(data: dict[str, bytes], chunks: list[StreamChunk]) -> ShellAnalysis:
    """Signs of an interactive shell in one rebuilt connection (`data` per direction, `chunks` in the order the
    two sides spoke), for whichever side reads as the shell."""
    bursts = _bursts(chunks)
    turns = sum(1 for a, b in itertools.pairwise(bursts) if a.direction != b.direction)
    best, limits = None, []
    for out in ("s2c", "c2s"):                    # on a tie the server stays the shell side (the lower lane)
        side = _Side(data, chunks, bursts, out)
        found = side.all()
        limits += side.limits
        score = (len({i.kind for i in found}), sum(i.count for i in found))
        if found and (best is None or score > best[0]):
            best = (score, out, found)
    if best is None:
        return ShellAnalysis(None, [], turns, limits)
    return ShellAnalysis("server" if best[1] == "s2c" else "client",
                         sorted(best[2], key=lambda i: (i.offset, i.kind)), turns, limits)


def publishable(kinds, turns: int) -> str | None:
    """'multi' for two or more independent indicator kinds, 'single' for one strong kind in a real conversation,
    else None (a lone prompt or login dialogue, or one exchange)."""
    kinds = sorted(set(kinds))
    if len(kinds) >= MIN_INDICATORS:
        return "multi"
    if len(kinds) == 1 and kinds[0].startswith(STRONG_KINDS) and turns >= SINGLE_MIN_TURNS:
        return "single"
    return None


def _label(ind: dict) -> str:
    kind, count = ind.get("kind"), ind.get("count") or 1
    if kind == "prompt":
        what = f"a shell prompt ended {count} output burst(s), each answered with typed input"
    elif kind == "bare_prompt":
        what = f"a bare shell prompt ($, # or %) ended {count} output burst(s), each answered with typed input"
    elif kind == "banner":
        what = "a shell start-up message in the shell side's opening text"
    elif kind == "login_dialogue":
        what = "a login prompt and then a password prompt, each answered with text"
    elif kind == "shell_error":
        what = f"the shell's command-not-found message named the command just sent ({count} time(s))"
    elif isinstance(kind, str) and kind.startswith("output:") and kind[7:] in OUTPUT_SIGNATURES:
        what = (f"after a '{kind[7:]}' command, the other side returned a {OUTPUT_SIGNATURES[kind[7:]][2]}"
                + (f" ({count} time(s))" if count > 1 else ""))
    else:
        what = "an unrecognised indicator"
    sha = str(ind.get("sha256") or "")[:16]
    return (f"{what} [{ind.get('direction')} relative seq {ind.get('seq')}, {ind.get('length')} bytes"
            + (f", SHA-256 {sha}…]" if sha else "]"))


def _ip(value):
    try:
        return ipaddress.ip_address(str(value))
    except ValueError:
        return None


class CleartextInteractiveShell(Playbook):
    """Positive-only content rule over TCP connections rebuilt from packets by the packet stage."""
    id = "pcap.cleartext_interactive_shell"
    version = "1"
    title = "Packet content consistent with an interactive command shell over a cleartext channel"
    kind: ClassVar[str] = "packet"
    families = ("tcp_stream",)
    required_fields = ("source.ip", "source.port", "destination.ip", "destination.port", "arkime.session_id")
    claim_type = "network_observation"
    anchor_class = "network_observation"
    assures_negative = False
    positive_only_reason = (
        "content is judged only on the connections the packet stage selected and could rebuild, and a shell can "
        "run over an encrypted or recognised protocol, or show none of the prompts, banners and command outputs "
        "that are recognised, so absence proves nothing")
    severity, lane = "high", "lead"
    attack = ("T1059.004", "T1059.003", "T1095")
    benign = ("an administrator's telnet, rlogin or netcat session to a lab device, appliance or console server",
              "a training range, honeypot or CTF exercise",
              "a serial-over-IP or out-of-band management console")
    next_checks = ("the shell-side host's processes at the session's start (what owned the socket, what it spawned)",
                   "the full session in Arkime: the commands the operator sent and what came back",
                   "other connections between the two endpoints, and the operator side's other sessions")
    card: ClassVar[dict] = {
        "behavior": "the two directions of one TCP connection read as an interactive command shell: one side's "
                    "output shows prompts, a shell banner, a login dialogue or the characteristic output of "
                    "commands the other side sent",
        "telemetry": "Arkime SPI session documents (protocol, protocolCnt, source/destination ip, port and packets, "
                     "client.bytes, server.bytes, firstPacket, lastPacket) to select connections, and the session's "
                     "packets through Arkime's pcap API, read by TShark (tcp.seq, tcp.len, tcp.payload, and the opening SYN's tcp.flags). Present in "
                     "the lab profile (packets retrievable for every session); protocolCnt is to be confirmed live",
        "fidelity": "a content observation of what crossed the wire; it does not show which program produced it "
                    "or that commands succeeded on the host. Two different indicators are required, each tied to "
                    "turn-taking for the full claim; one banner, command output or shell error in a conversation "
                    "of at least four turns stands alone as a lead with low or medium confidence. Which side "
                    "opened the connection is stated only from a captured SYN",
        "benign_and_cost": "administrators on telnet or netcat consoles, training ranges, honeypots. One finding "
                           "per connection",
        "query_cost": "one SPI query per Arkime target; then per selected connection one pcap download (byte "
                      "capped) and one TShark run, within a per-hunt connection cap and packet byte budget",
        "next_pivot": "the shell-side host's process and socket records at the session start",
        "adds": "the only rule that reads raw-TCP payload: long raw-TCP connections are otherwise only duration "
                "or volume leads with no content proof, and Suricata payload logging is off",
        "research_basis": "ATT&CK Enterprise 20.0 T1059.004, T1059.003 and T1095 procedure examples (reverse and "
                          "bind shells over raw TCP); shell start-up and error messages of bash, dash and cmd.exe",
        "retrieval": "the SPI query selects every TCP document Arkime gave only the 'tcp' protocol (protocol and "
                     "protocolCnt) or a remote-login protocol, with payload in either direction: a superset of "
                     "the documents of every connection the local shape test accepts",
    }

    def __init__(self):
        super().__init__()
        self.groups: dict[str, list[TypedEvent]] = {}

    def consume(self, events):
        for e in self.applicable(events):
            if publishable(e.get("stream.shell.kinds") or [], e.get("stream.turns") or 0) is None:
                continue
            if e.get("stream.shell.side") not in ("client", "server") or not e.get("stream.shell.indicators"):
                self.missing_required += 1
                continue
            self.groups.setdefault(e.id, [e])
        return []

    def _lane(self, e: TypedEvent) -> tuple[str, str]:
        side = e.get("stream.shell.side")
        client, server = str(e.get("source.ip")), str(e.get("destination.ip"))
        shell, operator = (client, server) if side == "client" else (server, client)
        shell_ip = _ip(shell)
        shell_internal = shell_ip is not None and is_internal(shell_ip)
        operator_external = _ip(operator) is not None and external(str(_ip(operator)))
        if shell_internal and e.get("stream.opened_by") == side:
            return "high", "an internal host is the shell side and its SYN shows it opened the connection"
        if shell_internal and operator_external:
            return "high", "an internal host is the shell side and the operator side is external"
        return "lead", ("the shell side is not an internal host whose SYN shows it opened the connection, nor one "
                        "facing an external peer")

    def finalize(self) -> list[Match]:
        out = []
        for key in sorted(self.groups):
            e = self.groups[key][0]
            inds = e.get("stream.shell.indicators") or []
            kinds = sorted(set(e.get("stream.shell.kinds") or []))
            side = e.get("stream.shell.side")
            other = "server" if side == "client" else "client"
            client = f"{e.get('source.ip')}:{e.get('source.port')}"
            server = f"{e.get('destination.ip')}:{e.get('destination.port')}"
            shell_ep, op_ep = (client, server) if side == "client" else (server, client)
            times = sorted(str(i.get("time")) for i in inds if i.get("time"))
            lane, why = self._lane(e)
            opener = e.get("stream.opened_by")
            if opener == side:
                opened = "The shell side's SYN shows it opened the connection, as a reverse shell does."
            elif opener in ("client", "server"):
                opened = ("The operator side's SYN shows it opened the connection, as it does to a bind shell or a "
                          "remote-login service.")
            else:
                opened = ("The connection's opening SYN was not captured, so which side opened it is not "
                          "established.")
            single = publishable(kinds, e.get("stream.turns") or 0) == "single"
            if single:
                lane, why = "lead", "a single indicator: a lead whatever the endpoints"
            evidence = (f"a single indicator was seen: {_label(inds[0])}" if single else
                        f"{len(kinds)} independent indicator(s): " + "; ".join(_label(i) for i in inds[:8]))
            claim = (f"Packet content in Arkime session {show(e.get('arkime.session_id'), 80)} between "
                     f"{show(client, 60)} (client) and {show(server, 60)} (server), with indicators from "
                     f"{times[0] if times else '?'} to {times[-1] if times else '?'}, is "
                     + ("in one respect " if single else "")
                     + f"consistent with an interactive command shell over a cleartext channel: the {side} "
                     f"({show(shell_ep, 60)}) sent what reads as shell output and the {other} ({show(op_ep, 60)}) "
                     f"sent what reads as commands. " + evidence
                     + f". {opened} The bytes are cited by offset and digest; which program produced them, and "
                       "what the commands did on the host, is not established by these records.")
            preds = [pf(e, f) for f in ("stream.shell.kinds", "stream.shell.side", "stream.shell.indicators",
                                        "source.ip", "destination.ip") if e.has(f)]
            if single:
                confidence = "low" if kinds in (["banner"], ["prompt"]) else "medium"
            else:
                confidence = "high" if len(kinds) >= 3 else "medium"
            m = Match(self.id, claim, self.claim_type, [e], preds, e.ts, self.severity, lane, confidence,
                      e.entities(), group_key=key)
            m.notes.append(f"lane {lane}: {why}")
            for limit in e.get("stream.limits") or []:
                m.notes.append(f"content incomplete: {limit}")
            for note in e.get("stream.notes") or []:
                m.notes.append(note)
            out.append(m)
        return out

    def retained_events(self) -> list[TypedEvent]:
        return [e for evs in self.groups.values() for e in evs]


PACKET_PLAYBOOKS = [DisguisedScriptOrExecutable, CleartextInteractiveShell]
