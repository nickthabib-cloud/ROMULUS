"""A server-side script that first appears in an upload-style directory, read from web-server access logs alone.

With no process telemetry on a web host, its access log is the only record of a web shell: a request that uploads
something (a PUT or WebDAV MOVE/COPY, or a POST to an upload endpoint), then the first answered requests to a script
that had not been requested before, under a directory where uploads land, and requests to that script whose query
parameters hold commands. Access logs record the method, the request target, the status and the client: never the
request body, its content type or what the script did. So a POST that carries its commands in the body is invisible
here, multipart uploads are recognised only by their endpoint, and every statement is about requests and answers.
"""
from __future__ import annotations

import json
import posixpath
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import ClassVar
from urllib.parse import unquote, unquote_plus, urlsplit

from romulus.detect.base import Match, Playbook, pf
from romulus.detect.bounded import KeyedStore
from romulus.evidence.typed import TypedEvent
from romulus.hunt.citations import COMPACT_CITATION_NOTE, compact_event, expand_event

# Server-side script extensions a web server hands to an interpreter or application server (PHP, JSP, ASP and
# ASP.NET, ColdFusion, CGI and Perl/Python/Ruby handlers, server-side includes).
SCRIPT_EXTENSIONS = frozenset({
    "php", "php3", "php4", "php5", "php7", "php8", "phtml", "pht", "phar", "phps", "jsp", "jspx", "jspf", "jsw",
    "jsv", "asp", "aspx", "ashx", "asmx", "asa", "cer", "cshtml", "cfm", "cfml", "cfc", "pl", "cgi", "py", "rb",
    "sh", "shtml",
})
# Directory names where uploaded, generated or cached files land: no deployed code is expected there.
_WRITABLE_DIR = re.compile(
    r"(?:.*upload.*|upfiles?|user[_-]?files|files?|media|images?|imgs?|pics|pictures|photos|attach(?:ments?)?|"
    r"te?mp|cache|avatars?|backups?|storage|static|exports?|imports?|downloads?|var)")
# Endpoints that receive uploads (a multipart body is not logged, so the endpoint stands for it): generic upload
# handlers and the file managers web applications ship (elFinder, KCFinder, CKFinder/FCKeditor, Plupload,
# WordPress async-upload, Drupal file/ajax).
_UPLOAD_ENDPOINT = re.compile(
    r"(?:upload|uploader|fileupload|file[_-]upload|async-upload|filemanager|file[_-]manager|elfinder|kcfinder|"
    r"ckfinder|fckeditor|plupload|connector|attach(?:ment)?s?|import)", re.IGNORECASE)
WRITE_METHODS = frozenset({"PUT", "MOVE", "COPY", "MKCOL"})
# Commands an operator types into a web shell: the Linux and Windows living-off-the-land discovery and execution
# programs of the research register (lotl_linux, LOLBAS discovery and execution entries).
COMMANDS = frozenset({
    "cat", "tac", "head", "tail", "more", "less", "ls", "dir", "find", "grep", "id", "whoami", "uname", "hostname",
    "pwd", "ps", "env", "printenv", "ifconfig", "ip", "netstat", "ss", "route", "arp", "w", "who", "last", "df",
    "mount", "crontab", "sudo", "curl", "wget", "nc", "ncat", "netcat", "socat", "bash", "sh", "zsh", "dash", "ksh",
    "busybox", "python", "python2", "python3", "perl", "php", "ruby", "chmod", "chown", "rm", "mv", "cp", "mkdir",
    "touch", "echo", "base64", "tar", "zip", "unzip", "kill", "pkill", "nohup", "systemctl", "service", "useradd",
    "passwd", "ssh", "scp",
    "cmd", "powershell", "pwsh", "ipconfig", "systeminfo", "tasklist", "taskkill", "net", "net1", "nltest", "netsh",
    "reg", "sc", "schtasks", "wmic", "certutil", "bitsadmin", "mshta", "rundll32", "regsvr32", "type", "copy", "del",
    "query", "quser", "qwinsta", "dsquery", "nslookup", "ping", "tracert",
})
# Names that are commands whatever parameter carries them: none is an ordinary word, field name or value.
UNAMBIGUOUS = frozenset({"whoami", "uname", "ifconfig", "ipconfig", "systeminfo", "tasklist", "printenv", "netstat",
                         "nltest", "qwinsta", "quser"})
# Commands that do something with no operand: a command when a shell-style parameter carries them, or after a shell
# separator.
BARE = frozenset({"id", "ls", "dir", "pwd", "ps", "env", "w", "who", "hostname", "df", "mount", "last", "set"})
# Parameter names web shells use for their command.
SHELL_PARAMETERS = frozenset({"cmd", "command", "exec", "execute", "run", "shell", "sh", "c", "e", "x", "z", "q0",
                              "code", "system", "passthru", "act", "action_cmd"})
_SEPARATOR = re.compile(r"\s*(?:;|\|\|?|&&|\n|`|\$\()\s*")
_OPERAND = re.compile(r"""(?:-{1,2}[a-z0-9]|[/\\~$.'"*]|[a-z]:[/\\]|(?:https?|ftp|tftp)://|\d)""", re.IGNORECASE)


def request_path(target: str) -> str | None:
    """The decoded, normalised path of an origin-form request target ('/a/../b.php?x' -> '/b.php'); None for an
    absolute or authority-form target (a proxy's) or one that cannot be parsed."""
    if not isinstance(target, str) or not target.startswith("/"):
        return None
    try:
        path = urlsplit(target).path
    except ValueError:
        return None
    for _ in range(2):
        if "%" not in path:
            break
        path = unquote(path)
    path = path.replace("\\", "/")
    normal = posixpath.normpath("/" + path.lstrip("/"))
    return normal if normal.startswith("/") else "/" + normal


def script_kind(path: str) -> tuple[str, bool] | None:
    """(script extension, hidden) for a path whose last segment a server may run as a script: its extension, or one
    behind a ';' parameter ('shell.jsp;.png') or inside the name ('shell.php.jpg', run by handler-mapping servers);
    None otherwise."""
    leaf = posixpath.basename(path).lower()
    head = leaf.split(";", 1)[0]
    parts = head.split(".")
    if len(parts) < 2 or not parts[0] and len(parts) < 3:
        return None
    if parts[-1] in SCRIPT_EXTENSIONS:
        return parts[-1], head != leaf
    inner = [part for part in parts[1:-1] if part in SCRIPT_EXTENSIONS]
    return (inner[-1], True) if inner else None


def writable_directory(path: str) -> str | None:
    """The upload-style directory name a script path lies under, or None."""
    for segment in posixpath.dirname(path).lower().split("/"):
        if segment and _WRITABLE_DIR.fullmatch(segment):
            return segment
    return None


def upload_like(method: str, path: str) -> bool:
    """A request that may store a file: a write method, or a POST to an upload endpoint, named by the request's
    last segment ('/wp-admin/async-upload.php', '/api/files/upload'), or by its directory when that segment is an
    index ('/upload/index.php'). A POST to a script that merely lies under an uploads directory is no upload."""
    if method in WRITE_METHODS:
        return True
    if method != "POST":
        return False
    leaf = posixpath.basename(path)
    if posixpath.splitext(leaf)[0].lower() in ("", "index", "default"):
        leaf = posixpath.basename(posixpath.dirname(path))
    return bool(_UPLOAD_ENDPOINT.search(leaf))


def _decode(value: str) -> str:
    for _ in range(2):
        if "%" not in value and "+" not in value:
            break
        value = unquote_plus(value)
    return value


def parameters(target: str) -> list[tuple[str, str]]:
    """The query parameters of a request target, decoded (at most twice, as servers and shells decode)."""
    try:
        query = urlsplit(target).query
    except ValueError:
        return []
    out = []
    for item in query.split("&")[:64]:
        if not item:
            continue
        name, _, value = item.partition("=")
        out.append((_decode(name)[:64].lower(), _decode(value)[:2048]))
    return out


def command_in(name: str, value: str) -> str | None:
    """The command a parameter's value holds, or None. A command is a known program name with an operand, an
    unambiguous discovery name, or, under a shell-style parameter name or after a shell separator, a program that
    needs no operand. Words like `id`, `type` or `echo` alone under an ordinary parameter (`?sort=id`) are not."""
    shellish = name in SHELL_PARAMETERS
    segments = [segment for segment in _SEPARATOR.split(value.strip()) if segment]
    separated = len(segments) > 1
    for segment in segments:
        words = segment.split()
        if not words:
            continue
        program = posixpath.basename(words[0].replace("\\", "/")).lower().strip("'\"")
        program = program.removesuffix(".exe")
        if program not in COMMANDS:
            continue
        rest = words[1:]
        if program in ("cmd",) and any(word.lower() in ("/c", "/k", "/r") for word in rest):
            return segment
        if program in ("powershell", "pwsh") and rest:
            return segment
        if rest and _OPERAND.match(rest[0]):
            return segment
        if not rest and (program in UNAMBIGUOUS or (program in BARE and (shellish or separated))):
            return segment
        if rest and program in UNAMBIGUOUS:
            return segment
    return None


@dataclass
class _Script:
    """One script path on one host: its first answered request, the earliest exact-path writes, and the earliest
    answered requests with command parameters, each as (time, compact citation)."""
    extension: str
    hidden: bool
    directory: str
    served: int = 0
    first: tuple[float, bytes] | None = None
    write: tuple[float, bytes] | None = None
    commands: list[tuple[float, bytes, str, str]] = field(default_factory=list)
    command_count: int = 0


class AccessLogWebShell(Playbook):
    """Joins, per web host, a script's first answered request to the upload-style requests before it and to its
    requests carrying commands. Decided at finalize from disk-backed state, so the result does not depend on the
    order records are read."""
    id = "web.access_log_web_shell"
    version = "1"
    title = ("Script under an upload-style directory first requested after an upload, or requested with command "
             "parameters")
    families = ("http_access",)
    required_fields = ("url.original", "http.request.method", "http.response.status_code")
    kind = "aggregate"
    claim_type = "correlated_observation"
    anchor_class = "web_shell"
    severity, lane = "high", "lead"
    attack = ("T1505.003", "T1190")
    assures_negative = False
    positive_only_reason = ("Access logs do not record request bodies, content types or what a script ran: a web "
                            "shell driven by POST bodies, or uploaded through an endpoint not named as one, leaves "
                            "no trace this rule can read, so absence is never asserted.")
    benign = (("a deployment or plugin install that puts scripts into a cache, media or upload directory and requests "
              "them (an upload link without command parameters is a lead)"),
              ("an image resizer or download script that lives under an images or files directory and takes a path "
              "operand (it is not new when it was requested before the upload)"),
              "a site that answers every path with 200 (a catch-all page) probed by a scanner sending `?cmd=whoami`")
    next_checks = (("the host's process and file records for the script, if any exist; its content from a backup or "
                   "the live server (by the site owner)"),
                   "every request to the script and every other request from its clients",
                   "outbound connections from the web host after the first request")
    # An operator uploads a shell and opens it within minutes; an hour bounds what a busy site's other uploads can
    # coincide with while keeping a slow manual operator.
    UPLOAD_WINDOW = timedelta(hours=1)
    # A script not requested in the day of access log read before its first answered request is called new; with
    # less history read before it, newness is stated as unresolved.
    LOOKBACK = timedelta(hours=24)
    COMMANDS_KEPT = 3
    HOT: ClassVar[int] = 4096
    card: ClassVar[dict] = {
        "behavior": "on one web host, a server-side script (php, jsp, asp/aspx, cfm, pl, cgi, ...) under an "
                    "upload-style directory whose first answered request follows, within an hour, an upload-style "
                    "request (PUT/MOVE/COPY, or POST to an upload endpoint); or whose answered requests carry a "
                    "command in a query parameter",
        "telemetry": "http_access only (Apache/nginx/IIS access logs: url.original, http.request.method, "
                     "http.response.status_code, source.ip, host). Present in the lab profile. Request bodies, "
                     "content types and response sizes are not typed: multipart uploads are recognised by their "
                     "endpoint, and POST-body commands are not visible",
        "fidelity": "inferred link (correlated_observation): an upload request and a later first request to a new "
                    "script, joined by host and time; command parameters are typed request values. Neither shows "
                    "that the script ran a command",
        "benign_and_cost": "deployments into cache or media directories, resizers under image directories, "
                           "catch-all sites answering scanner probes; one finding per (host, script)",
        "query_cost": "none beyond the sweep",
        "next_pivot": "the script's every request and client, and the web host's process, file and network records",
        "adds": "web hosts with only an access log: host.web_shell_chain needs file-change records, "
                "network.web_attacks reads sensor HTTP, not access logs",
        "research_basis": "ATT&CK Enterprise 20.0 T1505.003 (Web Shell) and T1190 detection guidance (web server "
                          "logs: new files requested, uncommon parameters); NSA/ASD 'Detect and Prevent Web Shell "
                          "Malware' (U/OO/134094-20) access-log anomalies; CVE-2017-12615 (Tomcat PUT of a .jsp); "
                          "OWASP unrestricted file upload (handler-mapping double extensions, ';' path parameters)",
        "retrieval": "the sweep retrieves every record of the access-log datasets in each partition with no field "
                     "filter, a superset of what this evaluator reads",
        "state": "per (host, script path) under an upload-style directory: counts and compact citations of the "
                 "first answered request, the earliest exact-path write and the first command requests (keyed store, "
                 "hot set over the rule's disk spill); upload-style requests in a disk table; never released",
        "lanes": "high when an upload link and command parameters both hold, or a write request targeted the "
                 "script's own path before it was answered; lead for either alone. With less than 24 h of the "
                 "host's log read before the first answer, only the same client's upload links (another client's is "
                 "named on coverage as not linked). Severity high: a web shell is remote command execution on the "
                 "server",
    }

    def __init__(self):
        super().__init__()
        self.scripts = KeyedStore(self, "web_shell_scripts", self.HOT)
        self.hosts = KeyedStore(self, "web_shell_hosts", self.HOT)       # host -> earliest record time read
        self._uploads_ready = False
        self._outside = 0

    def release_state(self) -> None:
        self.scripts.clear()
        self.hosts.clear()

    def _uploads(self):
        spill = self.spill()
        if not self._uploads_ready:
            spill.table("uploads", "host TEXT, src TEXT, ts REAL, id TEXT, method TEXT, path TEXT, status INTEGER, "
                                   "blob BLOB")
            self._uploads_ready = True
        return spill

    def consume(self, events):
        for e in self.applicable(events):
            try:
                status = int(e.get("http.response.status_code"))
            except (TypeError, ValueError):
                self.evaluated -= 1
                self.missing_required += 1
                continue
            target = e.get("url.original")
            path = request_path(target) if isinstance(target, str) else None
            if path is None or not e.host:
                self._outside += 1
                self.note_coverage("outside", "Access-log records whose request target is not origin-form (a "
                                              "proxy's absolute or CONNECT target) or that name no host are outside "
                                              "this rule's scope.")
                continue
            ts = e.ts.timestamp()
            earliest = self.hosts.get(e.host)
            if (earliest is None or ts < earliest) and not self.hosts.put(e.host, ts):
                self.note_limit("hosts", "the hosts' store took no new key; a host's history read is unknown")
            method = str(e.get("http.request.method") or "").upper()
            answered = status < 400 or status >= 500
            if upload_like(method, path) and status < 400:
                self._uploads().add("uploads", (e.host, str(e.get("source.ip") or e.get("source.host") or ""), ts,
                                                e.id, method, path, status, compact_event(e)))
            kind = script_kind(path)
            directory = writable_directory(path) if kind else None
            if not kind or not directory:
                continue
            key = (e.host, path)
            state = self.scripts.get(key)
            if method in WRITE_METHODS:
                if status >= 400:
                    continue
                if state is None:
                    state = _Script(kind[0], kind[1], directory)
                    if not self.scripts.put(key, state):
                        self.refuse("scripts", "the scripts' store took no new key; a write to a new script path is "
                                               "not evaluated")
                        continue
                if state.write is None or ts < state.write[0]:
                    state.write = (ts, compact_event(e))
                self.scripts.put(key, state)
                continue
            if not answered:
                continue
            if state is None:
                state = _Script(kind[0], kind[1], directory)
                if not self.scripts.put(key, state):
                    self.refuse("scripts", "the scripts' store took no new key; a request to a new script path is "
                                           "not evaluated")
                    continue
            state.served += 1
            if state.first is None or ts < state.first[0]:
                state.first = (ts, compact_event(e))
            found = next(((name, command) for name, value in parameters(target)
                          if (command := command_in(name, value))), None)
            if found:
                state.command_count += 1
                held = state.commands
                if len(held) < self.COMMANDS_KEPT or ts < held[-1][0]:
                    held.append((ts, compact_event(e), found[0], found[1]))
                    held.sort(key=lambda item: item[0])
                    del held[self.COMMANDS_KEPT:]
            self.scripts.put(key, state)
        self.scripts.trim()
        self.hosts.trim()
        return []

    @staticmethod
    def _event(blob: bytes) -> TypedEvent:
        event = expand_event(blob)
        return event.model_copy(update={"caveats": [*event.caveats, COMPACT_CITATION_NOTE]})

    def _upload_before(self, host: str, path: str, client: str, first: float):
        """The upload-style request on `host`, to another path than the script's own (a write to the script itself is
        its own link), closest before `first` within the window, preferring the same client: (event, same client) or
        None."""
        if not self._uploads_ready:
            return None
        spill = self._uploads()
        row = spill.execute(
            "SELECT blob, src=? FROM uploads WHERE host=? AND path<>? AND ts>=? AND ts<=? "
            "ORDER BY src=? DESC, ts DESC, id LIMIT 1",
            (client, host, path, first - self.UPLOAD_WINDOW.total_seconds(), first, client)).fetchone()
        return (self._event(row[0]), bool(row[1])) if row else None

    def finalize(self):
        if self._uploads_ready:
            self._uploads().execute("CREATE INDEX IF NOT EXISTS uploads_host_ts ON uploads(host, ts)")
        out = []
        for key in sorted(self.scripts.keys(), key=lambda k: (str(k[0]), str(k[1]))):
            state = self.scripts.peek(key)
            if state is None or state.first is None:
                continue
            host, path = key
            first = self._event(state.first[1])
            client = str(first.get("source.ip") or first.get("source.host") or "")
            upload = self._upload_before(host, path, client, state.first[0])
            if upload is not None and not upload[1] and not self._history_read(host, first):
                # With less than a day of the host's log behind it, a script's first answer is often just the first
                # request the hunt read (a resizer at the window's start); another client's upload before it is then
                # no link. The same client's is kept.
                upload = None
                self.note_limit("short_history", "an upload-style request from another client preceded a script's "
                                                 "first answered request, but less than 24 h of the host's access "
                                                 "log was read before it, so the two were not linked", 1)
            write = (self._event(state.write[1]) if state.write is not None and state.write[0] <= state.first[0]
                     and state.first[0] - state.write[0] <= self.UPLOAD_WINDOW.total_seconds() else None)
            commands = [(self._event(blob), name, command) for _ts, blob, name, command in state.commands]
            if not (upload or write or commands):
                continue
            out.append(self._match(host, path, state, first, upload, write, commands))
        return out

    def _history_read(self, host: str, first: TypedEvent) -> bool:
        earliest = self.hosts.peek(host)
        return earliest is not None and first.ts - datetime.fromtimestamp(earliest, UTC) >= self.LOOKBACK

    def _newness(self, host: str, first: TypedEvent) -> str:
        """How much of the host's access log was read before the first answer: the history newness rests on (the
        records actually read, not the hunt window, which may start before the host logged anything)."""
        earliest = self.hosts.peek(host)
        start = datetime.fromtimestamp(earliest, UTC) if earliest is not None else first.ts
        read = max(first.ts - start, timedelta(0))
        hours = read.total_seconds() / 3600
        if read >= self.LOOKBACK:
            return (f" No earlier answered request to it was read in the {hours:.0f} h of this host's access log "
                    f"before it, so it is new in that history.")
        return (f" It is the first answered request to it read in this hunt, but only {hours:.1f} h of this host's "
                f"access log precede it here, so whether it was requested before is unresolved.")

    def _match(self, host, path, state, first, upload, write, commands) -> Match:
        status = first.get("http.response.status_code")
        where = f"under the '{state.directory}' directory"
        hidden = (f" Its name hides the .{state.extension} extension behind another ('{posixpath.basename(path)}'),"
                  " a form servers that map handlers by any extension, or stop at ';', still run as a script."
                  if state.hidden else "")
        claim = (f"On {host}, the script {path} {where} was first answered at {first.ts.isoformat()} (status "
                 f"{status}) to {first.get('source.ip') or first.get('source.host') or 'an unrecorded client'}."
                 + hidden + self._newness(host, first))
        cited = [first]
        context = set()
        exact_write = write is not None
        if write is not None:
            claim += (f" Before that, at {write.ts.isoformat()}, a {write.get('http.request.method')} request to the "
                      f"same path was answered with status {write.get('http.response.status_code')}: the write "
                      f"targeted the script itself.")
            cited.append(write)
        if upload is not None and (write is None or upload[0].id != write.id):
            event, same = upload
            gap = (first.ts - event.ts).total_seconds() / 60
            who = "the same client" if same else (f"another client ({event.get('source.ip') or 'unrecorded'})")
            claim += (f" {gap:.0f} minute(s) before the first answer, {who} sent an upload-style request, "
                      f"{event.get('http.request.method')} {request_path(event.get('url.original'))} (status "
                      f"{event.get('http.response.status_code')}).")
            cited.append(event)
        if commands:
            shown = commands[0]
            others = len(commands) - 1
            claim += (f" {state.command_count} answered request(s) to it carried a command in a query parameter; "
                      f"the earliest {len(commands)} are cited, the first at {shown[0].ts.isoformat()} with parameter "
                      f"`{shown[1]}` decoding to `{shown[2][:200]}`"
                      + (f", and {others} more cited" if others else "") + ".")
            cited += [event for event, _name, _command in commands]
        linked = exact_write or upload is not None
        high = (linked and bool(commands)) or exact_write
        claim += (" This is the request pattern of a web shell; the log records requests and status codes, not what "
                  "the script ran" + (" or what the upload held." if linked else "."))
        evs = sorted({event.id: event for event in cited}.values(), key=lambda event: (event.ts, event.id))
        predicate = [pf(first, "url.original"), pf(first, "http.response.status_code")]
        if first.has("source.ip"):
            predicate.append(pf(first, "source.ip"))
        for event in evs:
            if event.id != first.id:
                predicate += [pf(event, "url.original"), pf(event, "http.request.method")]
        attack = ("T1505.003", "T1190") + (("T1059",) if commands else ())
        match = Match(self.id, claim, self.claim_type, evs, predicate, first.ts, self.severity,
                      "high" if high else "lead", "medium", first.entities(),
                      group_key=json.dumps([host, path]), context_ids=context, attack=attack)
        if not linked:
            match.notes.append("no upload-style request was read within an hour before the first answer; the lead "
                               "rests on the command parameters")
        elif not commands:
            match.notes.append("no answered request with a command in its query was read; a web shell that takes "
                               "its commands in a POST body leaves none in an access log")
        return match


RULES = (AccessLogWebShell,)
