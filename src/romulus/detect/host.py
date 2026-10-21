"""Host playbooks over typed process_exec / auth events (Linux, lab telemetry)."""
from __future__ import annotations

import ast
import ipaddress
import itertools
import posixpath
import re
from collections import defaultdict

from romulus.detect.base import Match, Playbook, basename, outcome_phrase, pf
from romulus.evidence.shellparse import (
    SHELLS,
    UnknownShellScript,
    parse_script,
    shell_script_file_of,
    shell_script_of,
)
from romulus.evidence.typed import Outcome, TypedEvent, raw_identity

WEB_SERVICE_USERS = {"www-data", "apache", "nginx", "httpd", "_www", "wwwrun"}
INTERPRETERS = SHELLS | {"python", "python2", "python3", "perl", "ruby", "php", "lua", "nc", "ncat", "netcat",
                         "socat", "awk", "gawk", "busybox"}
SCRIPT_FILE_INTERPRETERS = {"python", "python2", "python3", "perl", "ruby", "php", "lua"}
AWK_INTERPRETERS = {"awk", "gawk"}
DOWNLOADERS = {"curl", "wget", "fetch", "tftp"}
TEMP_DIRS = ("/tmp/", "/var/tmp/", "/dev/shm/")
# System directories the package manager owns. A web-service account cannot write there without root, so a
# script operand there is usually a helper the application ships (cgi-bin is excluded: it is where web code lives).
PACKAGED_DIRS = ("/usr/bin/", "/usr/sbin/", "/usr/libexec/", "/usr/share/", "/bin/", "/sbin/", "/usr/lib/")
NOT_PACKAGED = ("/usr/lib/cgi-bin/",)
# Interpreter standard libraries and tool trees: their scripts run other code, consoles or servers (cProfile,
# pdb, timeit, code, http.server), so a run of one is never an application helper.
INTERPRETER_LIBRARIES = re.compile(
    r"^/usr/(?:local/)?lib(?:64)?/(?:python[\d.]*|pypy[\d.]*|ruby|php[\d.]*|lua)(?:/|$)"
    r"|^/usr/(?:local/)?share/(?:perl[\d.]*|perl5|ruby[\w.-]*|php[\w.-]*|lua)(?:/|$)"
    r"|^/usr/lib(?:64)?/(?:[\w.-]+/)?perl[\d.]*(?:/|$)")
# Packaged scripts that fetch, install, serve or open a console: dual-use from a web-service account.
DUAL_USE_SCRIPTS = {"ssh-import-id", "ssh-import-id-gh", "ssh-import-id-lp", "pip", "pip2", "pip3", "easy_install",
                    "lwp-download", "lwp-request", "lwp-mirror", "GET", "POST", "HEAD", "cpan", "gem", "npm",
                    "irb", "pry", "ri", "erb", "pydoc", "pydoc3", "pdb", "pdb3", "idle", "idle3", "ipython",
                    "ipython3", "jupyter", "perldoc", "perlbug", "php-cgi", "lua5.1", "lua5.3", "luarocks"}
# Packaged scripts that look up programs, users or the system: from a web-service account they are the
# reconnaissance an exploit runs before choosing its payload (which python3, which nc), so never context.
DISCOVERY_SCRIPTS = {"which", "whereis", "lsb_release", "hostnamectl", "lsof", "ldd", "getent", "groups", "id",
                     "whoami", "uname", "lscpu", "lsusb", "lspci", "lsblk", "dmidecode", "env", "printenv"}
# Flag-only options per interpreter (no argument, no inline code). Anything else ends the packaged check.
_FLAG_ONLY = {
    "python": {"-u", "-B", "-b", "-bb", "-d", "-E", "-I", "-O", "-OO", "-q", "-s", "-S", "-v"},
    "perl": {"-w", "-W", "-X", "-T", "-t", "-wT", "-Tw", "-tw", "-wt"},
    "ruby": {"-w", "-W", "-v", "-d"},
    "php": {"-q", "-n", "-H"},
    "lua": {"-W"},
}
_URLISH = re.compile(r"://|^[\w.-]+@[\w.-]+(?::|$)|^(?:gh|lp):", re.ASCII)


def _packaged_script(argv: list[str], cwd: str | None = None) -> str | None:
    """The system-directory script a web-service interpreter run executes, when the command line is exactly
    `<interpreter> [flag-only options] <absolute script> [args]`, nothing in it fetches or names a remote, and
    nothing points it at files the web account can write (its working directory, path operands); None
    otherwise (the run then stays a lead)."""
    from romulus.detect.indicators import script_operand
    name = interpreter_name(argv[0]) if argv else ""
    if name in SHELLS:
        script, rest = script_operand(argv), []
        if script and script in argv:
            rest = argv[argv.index(script) + 1:]
    else:
        flags = _FLAG_ONLY.get(name.rstrip("23"), set())
        i = 1
        while i < len(argv) and argv[i] in flags:
            i += 1
        if i >= len(argv) or argv[i].startswith(("-", "+")):
            return None
        script, rest = argv[i], argv[i + 1:]
    if not script or not script.startswith("/"):
        return None
    path = _normalize_posix_path(script)
    if not path.startswith(PACKAGED_DIRS) or path.startswith(NOT_PACKAGED) or INTERPRETER_LIBRARIES.match(path):
        return None
    if posixpath.basename(path) in DUAL_USE_SCRIPTS | DISCOVERY_SCRIPTS or any(_URLISH.search(a) for a in rest):
        return None
    # Build and task runners (rake, composer, pytest, flask) load code from the working directory.
    if cwd and _normalize_posix_path(cwd) != "/" and _outside_system(cwd, cwd):
        return None
    if any(_outside_system(a, cwd) for a in rest):     # the helper is pointed at a file the web account can write
        return None
    return path


_FILE_LIKE = re.compile(r"\.[A-Za-z0-9]{1,6}$")


def _outside_system(arg: str, cwd: str | None) -> bool:
    """A path operand (or an option's `=path` value) outside the system directories. A relative path is
    resolved against the working directory; without one it cannot be placed, so it counts as outside."""
    value = arg.split("=", 1)[1] if arg.startswith("-") and "=" in arg else arg
    if value.startswith("-") or not value:
        return False
    if not value.startswith("/"):
        if "/" not in value and not _FILE_LIKE.search(value):
            return False                                  # a word (startup, install), not a path
        value = _resolve_script_path(value, cwd or "")
        if not value:
            return True
    path = _normalize_posix_path(value)
    if path == "/dev/null" or path.startswith("/etc/"):     # root-owned configuration, the null device
        return False
    return not path.startswith(PACKAGED_DIRS) or path.startswith(NOT_PACKAGED)


CRED_FILES = {"/etc/shadow", "/etc/gshadow", "/etc/shadow-", "/etc/gshadow-"}
FILE_READERS = {"cat", "head", "tail", "less", "more", "cp", "base64", "xxd", "od", "strings", "tac", "nl",
                "dd", "tar", "vi", "vim", "nano", "view", "rsync", "scp"}
FW_TOOLS = {"iptables", "ip6tables", "iptables-legacy", "iptables-nft", "nft", "ufw", "firewall-cmd"}
FW_CHANGE_FLAGS = {"-A", "--append", "-I", "--insert", "-D", "--delete", "-R", "--replace", "-F", "--flush",
                   "-P", "--policy", "-X", "--delete-chain", "-N", "--new-chain", "-Z"}
NFT_CHANGE = {"add", "insert", "delete", "flush", "replace", "create", "destroy"}
# Explicit internal space (mission-configurable later). Not ipaddress.is_private, which also
# classifies documentation/benchmark ranges as private.
INTERNAL_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10",
    "::1/128", "fc00::/7", "fe80::/10")]


def _normalize_posix_path(path: str) -> str:
    normalized = posixpath.normpath(path)
    return "/" + normalized.lstrip("/") if normalized.startswith("//") else normalized


def _resolve_script_path(path: str, cwd: str) -> str:
    if path.startswith("/"):
        return _normalize_posix_path(path)
    if path and cwd.startswith("/"):
        return _normalize_posix_path(posixpath.join(_normalize_posix_path(cwd), path))
    return ""


def _awk_script_file_of(argv: list[str]) -> str:
    index = 1
    while index < len(argv):
        arg = argv[index]
        if arg == "--" or not arg.startswith("-"):
            return ""
        if arg in {"-v", "-F"}:
            if index + 1 >= len(argv):
                return ""
            index += 2
            continue
        if arg == "-f":
            return argv[index + 1] if index + 1 < len(argv) else ""
        return ""
    return ""


def interpreter_name(argv0: str) -> str:
    """Normalize an argv[0] for membership checks without expanding the allow-list."""
    name = basename(argv0).removeprefix("-")
    if name in INTERPRETERS:
        return name
    for base in sorted(INTERPRETERS, key=len, reverse=True):
        suffix = name[len(base):] if name.startswith(base) else ""
        if suffix and re.fullmatch(r"(?:\d+(?:\.\d+)*)|(?:\.\d+)+", suffix):
            return base
    return name


def is_internal(ip: ipaddress._BaseAddress) -> bool:
    return any(ip in n for n in INTERNAL_NETS if n.version == ip.version)


def _py_pty_spawn(code: str) -> bool:
    """True if the Python source actually calls pty.spawn(...) (parsed, not substring)."""
    try:
        tree = ast.parse(code)
    except (SyntaxError, ValueError):
        return False
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            fn = node.func
            if isinstance(fn, ast.Attribute) and fn.attr == "spawn" and isinstance(fn.value, ast.Name) \
                    and fn.value.id == "pty":
                return True
    return False


def _argv_summary(argv: list[str], limit: int = 160) -> str:
    s = " ".join(argv)
    return s if len(s) <= limit else s[: limit - 1] + "…"


def _exec_entities(e: TypedEvent) -> list[tuple[str, str, str]]:
    ents = e.entities()
    if e.get("process.user"):
        ents.append(("account", f"{e.host}\\{e.get('process.user')}", "actor"))
    return ents


def command_shape(argv: list[str]) -> str:
    """Stable shape for stack counting: first 4 args, digits normalized, truncated."""
    return " ".join(re.sub(r"\d+", "N", a)[:48] for a in argv[:4])


def _python_exec_of_decoded(code: str) -> bool:
    """exec()/eval() whose argument involves base64/zlib/codecs decoding (parsed AST)."""
    try:
        tree = ast.parse(code)
    except (SyntaxError, ValueError):
        return False
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in ("exec", "eval"):
            inner = ast.dump(node)
            if any(k in inner for k in ("b64decode", "decompress", "'base64'", "'zlib'", "'codecs'")):
                return True
    return False


def _interpreter_indicators(argv: list[str]) -> tuple[list[str], bool, bool]:
    """Return typed indicators, unevaluable state, and whether indicators used a clean prefix."""
    out = []
    unevaluable = False
    prefix_only = False
    name = interpreter_name(argv[0]) if argv else ""
    rest = argv[1:]
    if name in INTERPRETERS and (not rest or rest in (["-"], ["-i"], ["-p"])):
        out.append("interpreter reading commands from stdin (no script argument)")
    script = shell_script_of(argv)
    if isinstance(script, UnknownShellScript):
        unevaluable = True
    elif script:
        parsed = parse_script(script)
        if parsed.ok or parsed.partial:
            cmds = parsed.commands()
            if len(cmds) > 1 and cmds[0].argv and cmds[0].argv[0].startswith("/") and \
                    interpreter_name(cmds[0].argv[0]) not in INTERPRETERS:
                out.append(f"additional commands chained after application helper '{cmds[0].name}'")
            for c in cmds:
                if c.name.startswith("python"):
                    for i, a in enumerate(c.argv[1:-1], start=1):
                        if a == "-c" and _python_exec_of_decoded(c.argv[i + 1]):
                            out.append("python code executes decoded data")
                if c.name == "echo" and any("b64decode" in a or "decompress" in a for a in c.argv[1:]):
                    out.append("encoded payload text piped/echoed into another command")
        if not parsed.ok:
            unevaluable = True
            prefix_only = parsed.partial
    if name.startswith("python"):
        for i, a in enumerate(rest[:-1]):
            if a == "-c" and _python_exec_of_decoded(rest[i + 1]):
                out.append("python code executes decoded data")
    return sorted(set(out)), unevaluable, prefix_only


def interpreter_indicators(argv: list[str]) -> list[str]:
    """Typed-argv indicators that an interpreter run is attacker-shaped rather than routine."""
    return _interpreter_indicators(argv)[0]


class WebServiceSpawnsInterpreter(Playbook):
    """Stack-counted: routine shapes collapse into one context item; rare shapes become leads and
    are escalated only when typed argv indicators are present (rarity alone is not suspicion)."""
    id = "host.web_service_spawns_interpreter"
    anchor_class = "web_shell"
    # argv/text-identified programs and actions: findings only, never a complete negative
    assures_negative = False
    version = "11"
    title = "Web service account executed a shell or interpreter"
    kind = "aggregate"
    families = ("process_exec",)
    required_fields = ("process.argv", "process.user")
    severity, lane = "high", "high"
    attack = ("T1505.003", "T1059.004", "T1190")
    benign = ("CGI or application code that legitimately shells out (e.g. ZoneMinder helpers)",
              "service start-up at boot (rare shapes without indicators)")
    next_checks = ("process_tree for the parent PID", "http_requests to this host just before the event",
                   "host_network outbound connections from this host around the event")
    RARE_MAX = 5
    # A shape is routine only when it recurs like a schedule: in at least this many distinct clock hours, with no
    # hour holding more than half of its runs. A burst of the same command (an attacker looping a web shell), even
    # one that straddles hour boundaries, stays visible as a lead.
    ROUTINE_MIN_HOURS = 3

    def __init__(self):
        super().__init__()
        self.shapes: dict[tuple, list[TypedEvent]] = defaultdict(list)
        self.counts: dict[tuple, int] = defaultdict(int)
        self.hours: dict[tuple, dict] = defaultdict(lambda: defaultdict(int))

    def consume(self, events):
        matches = []
        for e in self.applicable(events):
            user, argv = e.get("process.user"), e.get("process.argv")
            if user not in WEB_SERVICE_USERS or not argv or interpreter_name(argv[0]) not in INTERPRETERS:
                continue
            indicators, unevaluable, prefix_only = _interpreter_indicators(argv)
            if unevaluable:
                self.missing_required += 1
            if indicators:
                matches.append(self._event_match(e, user, argv, indicators, prefix_only=prefix_only))
                continue
            key = (e.host, user, command_shape(argv), _packaged_script(argv, e.get("process.cwd")))
            self.counts[key] += 1
            self.hours[key][e.ts.replace(minute=0, second=0, microsecond=0)] += 1
            if len(self.shapes[key]) < 20:
                self.shapes[key].append(e)
        return matches

    @property
    def groups(self):
        return self.shapes

    def _event_match(self, e, user, argv, indicators, count=None, prefix_only=False):
        rce_shaped = any(("decoded data" in item) or ("stdin" in item) for item in indicators)
        lane, severity = (("urgent", "critical") if rce_shaped else
                          ("high", "high") if indicators else ("lead", "medium"))
        count_text = f" This command shape occurred {count} time(s) in the window." if count is not None else ""
        claim = (f"A process execution event on {e.host} records account '{user}' executing "
                 f"'{basename(argv[0])}' (argv: {_argv_summary(argv)}); {outcome_phrase(e)}.{count_text}")
        match = Match(
            self.id, claim, self.claim_type, [e], [pf(e, "process.user"), pf(e, "process.argv")],
            e.ts, severity, lane, "high" if e.outcome == Outcome.success else "medium", _exec_entities(e),
        )
        match.notes += [f"indicator: {item}" for item in indicators] or ["rare shape without typed indicators"]
        if prefix_only:
            match.notes.append("script indicator evaluated from clean prefix only; remainder was not modelled")
        return match

    def finalize(self):
        out = []
        for key, evs in self.shapes.items():
            host_, user, shape, packaged = key
            n = self.counts[key]
            if packaged and n <= self.RARE_MAX:
                # Rare, no typed indicator, and the script sits where a web-service account cannot write: most
                # likely the application's own helper (daemon start-up, maintenance), not code a request supplied.
                claim = (f"System-directory helper: account '{user}' on {host_} ran '{shape}' {n} time(s) in the "
                         f"window; the script operand '{packaged}' is under a system directory (package ownership "
                         f"not verified) and the command line carries no typed indicator (retained for context).")
                out.append(Match(self.id, claim, "aggregate_observation", evs[:5], [pf(evs[0], "process.argv")],
                                 evs[0].ts, "low", "context", "high", _exec_entities(evs[0]),
                                 group_key=f"packaged|{host_}|{user}|{shape}"))
                continue
            hours = self.hours[key]
            scheduled = len(hours) >= self.ROUTINE_MIN_HOURS and max(hours.values()) * 2 <= n
            if n > self.RARE_MAX and not scheduled:
                evs = sorted(evs, key=lambda e: (e.ts, e.id))
                claim = (f"Repeated shape: account '{user}' on {host_} executed '{shape}' {n} times; the runs are not "
                         f"spread across {self.ROUTINE_MIN_HOURS} or more hours like a schedule (most fall within one "
                         f"hour or few hours), and no typed indicator was found on the command line."
                         + (f" The earliest {len(evs)} runs are cited." if len(evs) < n else ""))
                out.append(Match(self.id, claim, "aggregate_observation", evs, [pf(e, "process.argv") for e in evs],
                                 evs[0].ts, "medium", "lead", "high", _exec_entities(evs[0]),
                                 group_key=f"burst|{host_}|{user}|{shape}" + (f"|{packaged}" if packaged else "")))
                continue
            if n > self.RARE_MAX:
                claim = (f"Routine pattern: account '{user}' on {host_} executed '{shape}' {n} times in the window, "
                         f"spread across {len(hours)} distinct hours like a schedule "
                         f"(stack-counted; retained for context).")
                out.append(Match(self.id, claim, "aggregate_observation", evs[:5], [pf(evs[0], "process.argv")],
                                 evs[0].ts, "low", "context", "high", _exec_entities(evs[0]),
                                 group_key=f"routine|{host_}|{user}|{shape}" + (f"|{packaged}" if packaged else "")))
                continue
            for e in evs:
                argv = e.get("process.argv")
                out.append(self._event_match(e, user, argv, [], count=n))
        return out


class DownloaderFeedsInterpreter(Playbook):
    """Sequence: a downloader exec and a stdin-reading interpreter exec with the same parent on the
    same host within MAX_GAP seconds (the shape of `curl URL | sh` typed into a shell or a script)."""
    id = "host.downloader_feeds_interpreter"
    # argv/text-identified programs and actions: findings only, never a complete negative
    assures_negative = False
    version = "2"
    title = "Downloader and stdin interpreter launched together by the same parent"
    kind = "aggregate"
    families = ("process_exec",)
    required_fields = ("process.argv", "process.ppid")
    severity, lane = "high", "urgent"
    attack = ("T1105", "T1059.004")
    benign = ("vendor install one-liners run by administrators",)
    next_checks = ("http_requests / ip_sessions to the download host", "process_tree of the parent",
                   "entity_timeline of the host after the event")
    MAX_GAP = 10.0

    def __init__(self):
        super().__init__()
        self.pending: dict[tuple, list[TypedEvent]] = defaultdict(list)
        self.found: list[Match] = []
        self.groups = {}

    def retained_events(self):
        # downloader events wait in `pending` across partitions until their interpreter arrives;
        # their raw copies must be kept now, or a pair split by a partition boundary loses evidence
        return super().retained_events() + [e for evs in self.pending.values() for e in evs]

    def consume(self, events):
        for e in sorted(self.applicable(events), key=lambda x: x.ts):
            argv = e.get("process.argv")
            name = interpreter_name(argv[0])
            key = (e.host, e.get("process.ppid"))
            if name in DOWNLOADERS and any("://" in a for a in argv[1:]):
                self.pending[key] = [p for p in self.pending[key] if (e.ts - p.ts).total_seconds() <= self.MAX_GAP]
                self.pending[key].append(e)
                continue
            if name in INTERPRETERS and (len(argv) == 1 or argv[1:] in (["-"], ["-s"])):
                for d in self.pending.get(key, []):
                    gap = abs((e.ts - d.ts).total_seconds())
                    if gap <= self.MAX_GAP:
                        url = next(a for a in d.get("process.argv")[1:] if "://" in a)
                        claim = (f"On {e.host}, '{basename(d.get('process.argv')[0])} {url}' and a stdin-reading "
                                 f"'{name}' were executed by the same parent process (ppid {key[1]}) {gap:.2f}s apart "
                                 f"— the process shape of downloaded content piped into a shell. The pipe itself and "
                                 f"the downloaded content are inferred, not directly recorded.")
                        m = Match(self.id, claim, self.claim_type, [d, e],
                                  [pf(d, "process.argv"), pf(d, "process.ppid"), pf(e, "process.argv"),
                                   pf(e, "process.ppid")], d.ts, self.severity, self.lane, "medium",
                                  _exec_entities(d), group_key=f"{raw_identity(d)}|{raw_identity(e)}")
                        m.notes.append(f"download URL: {url}")
                        self.found.append(m)
                        self.groups[m.group_key] = [d, e]
                        break
        return []

    def finalize(self):
        """Collapse repeats of the same (host, URL, interpreter) into one item; regular repetition is
        itself evidence of scheduled execution and is reported as such."""
        grouped: dict[tuple, list[Match]] = defaultdict(list)
        for m in self.found:
            d, e = m.events
            url = next(a for a in d.get("process.argv")[1:] if "://" in a)
            grouped[(d.host, url, basename(e.get("process.argv")[0]))].append(m)
        out = []
        for (host_, url, interp), ms in grouped.items():
            ms.sort(key=lambda x: x.ts)
            if len(ms) == 1:
                out.append(ms[0])
                continue
            gaps = [(b.ts - a.ts).total_seconds() for a, b in itertools.pairwise(ms)]
            gaps_sorted = sorted(gaps)
            median = gaps_sorted[len(gaps_sorted) // 2]
            regular = all(abs(g - median) <= max(5.0, 0.05 * median) for g in gaps)
            cadence = f"; repeats at a regular ~{median / 60:.1f}-minute interval" if regular else ""
            first = ms[0]
            claim = (f"On {host_}, the downloader→stdin-'{interp}' pattern for {url} occurred {len(ms)} times "
                     f"({ms[0].ts.isoformat()} – {ms[-1].ts.isoformat()}){cadence}. Each occurrence pairs a "
                     f"downloader exec and a stdin-reading interpreter exec under the same parent; the pipe and "
                     f"content are inferred.")
            evs = [ev for m in ms[:10] for ev in m.events]
            m = Match(self.id, claim, self.claim_type, evs, first.predicate, first.ts, self.severity, self.lane,
                      "high" if regular else "medium", first.entities, group_key=f"{host_}|{url}|{interp}")
            m.notes = [f"download URL: {url}", f"occurrences: {len(ms)}"] + \
                      (["regular cadence suggests scheduled execution (e.g. cron)"] if regular else [])
            out.append(m)
        return out


class DownloadPipedToShell(Playbook):
    """Script-text indicator: a shell was started with a script containing downloader | interpreter.
    Positive-only: whether the pipeline ran is shown by process-level evidence
    (host.downloader_feeds_interpreter), never inferred from text."""
    id = "host.download_piped_to_shell"
    version = "3"
    title = "Shell started with a script that pipes a download into an interpreter"
    claim_type = "script_content"
    assures_negative = False
    families = ("process_exec",)
    required_fields = ("process.argv",)
    severity, lane = "high", "urgent"
    attack = ("T1105", "T1059.004")
    benign = ("vendor install one-liners run by administrators",)
    next_checks = ("http_requests / ip_sessions to the download host", "process_tree of the shell",
                   "file_activity for files written by the child shell")

    def match(self, e):
        script = shell_script_of(e.get("process.argv"))
        if isinstance(script, UnknownShellScript):
            self.missing_required += 1
            return []
        if not script:
            return []
        parsed = parse_script(script)
        if not parsed.ok:
            self.missing_required += 1
            return []
        for p in parsed.pipelines:
            names = [c.name for c in p.commands]
            for i, c in enumerate(p.commands[:-1]):
                if c.name in DOWNLOADERS and interpreter_name(p.commands[i + 1].argv[0]) in INTERPRETERS:
                    urls = [a for a in c.argv[1:] if "://" in a or a.count(".") >= 1 and not a.startswith("-")]
                    claim = (f"A process execution event on {e.host} records a shell started with a script that "
                             f"contains the pipeline '{c.name} … | {names[i + 1]}' (script: {_argv_summary([script])}); "
                             f"{outcome_phrase(e)}. The script text shows intent; whether that pipeline ran, and "
                             f"whether the download succeeded, are not established by this event.")
                    m = Match(self.id, claim, self.claim_type, [e], [pf(e, "process.argv")], e.ts, self.severity,
                              self.lane, "high", _exec_entities(e))
                    m.notes.append(f"download target(s): {urls[:3]}")
                    return [m]
        return []


class PtyUpgrade(Playbook):
    id = "host.python_pty_spawn"
    # argv/text-identified programs and actions: findings only, never a complete negative
    assures_negative = False
    version = "2"
    title = "Python executed code that spawns a pseudo-terminal"
    families = ("process_exec",)
    required_fields = ("process.argv",)
    severity, lane = "high", "high"
    attack = ("T1059.006",)
    benign = ("rare in production; some admin tooling",)
    next_checks = ("process_tree for the parent (often a reverse shell)", "host_network around the event")

    def match(self, e):
        argv = e.get("process.argv")
        if not argv or not basename(argv[0]).startswith("python"):
            return []
        for i, a in enumerate(argv[1:-1], start=1):
            if a == "-c" and _py_pty_spawn(argv[i + 1]):
                claim = (f"A process execution event on {e.host} records '{basename(argv[0])} -c' executing code that "
                         f"calls pty.spawn ({_argv_summary(argv)}); {outcome_phrase(e)}.")
                return [Match(self.id, claim, self.claim_type, [e], [pf(e, "process.argv")], e.ts, self.severity,
                              self.lane, "high", _exec_entities(e))]
        return []


class ExecFromTempDir(Playbook):
    id = "host.exec_from_temp_dir"
    # argv/text-identified programs and actions: findings only, never a complete negative
    assures_negative = False
    version = "2"
    title = "Program executed from a world-writable temporary directory"
    families = ("process_exec",)
    required_fields = ("process.executable",)
    severity, lane = "medium", "lead"
    attack = ("T1059", "T1036.005")
    benign = ("installers and build tools unpacking into /tmp", "package manager hooks")
    next_checks = ("file_activity for how the file arrived", "process_tree", "http_requests that delivered it")

    def match(self, e):
        exe = e.get("process.executable") or ""
        if not exe:
            self.missing_required += 1
            return []
        path = _normalize_posix_path(exe) if exe.startswith("/") else exe
        if not path.startswith(TEMP_DIRS):
            return []
        claim = (f"A process execution event on {e.host} records process.executable '{path}' in a temporary "
                 f"directory; {outcome_phrase(e)}.")
        return [Match(self.id, claim, self.claim_type, [e], [pf(e, "process.executable")], e.ts, self.severity,
                      self.lane, "high", _exec_entities(e))]


# Debian/Ubuntu debconf runs each package's extracted config script as /tmp/<package>.config.XXXXXX with the
# maintainer-script action and the version: `sh /tmp/openssh-server.config.AbC123 configure 1:8.9p1`.
_DEBCONF_CONFIG = re.compile(r"^/tmp/[a-z0-9][a-z0-9+.-]*\.config\.[A-Za-z0-9]{6}$")
_DEBCONF_ACTIONS = {"configure", "reconfigure"}


class ScriptFromTempDir(Playbook):
    """Positive-only argv indicator: an interpreter was given a temp-directory script operand."""
    id = "host.script_from_temp_dir"
    version = "3"
    title = "Interpreter started with a script operand in a temporary directory"
    claim_type = "script_content"
    assures_negative = False
    families = ("process_exec",)
    required_fields = ("process.argv",)
    severity, lane = "medium", "lead"
    attack = ("T1059", "T1036.005")
    benign = ("installers and build tools unpacking into /tmp", "package manager hooks")
    next_checks = ("file_activity for how the script arrived", "process_tree", "http_requests that delivered it")

    def match(self, e):
        argv = e.get("process.argv")
        name = interpreter_name(argv[0])
        if name in SHELLS:
            script = shell_script_file_of(argv, shell_name=name)
            if isinstance(script, UnknownShellScript):
                self.missing_required += 1
                return []
        elif name in SCRIPT_FILE_INTERPRETERS:
            script = argv[1] if len(argv) > 1 and not argv[1].startswith(("-", "+")) else ""
        elif name in AWK_INTERPRETERS:
            script = _awk_script_file_of(argv)
        else:
            script = ""
        if not script:
            return []
        path = _resolve_script_path(script, e.get("process.cwd") or "")
        if not path:
            self.missing_required += 1
            return []
        if not path.startswith(TEMP_DIRS):
            return []
        fields = [pf(e, "process.argv")]
        if e.get("process.cwd"):
            fields.append(pf(e, "process.cwd"))
        rest = argv[argv.index(script) + 1:] if script in argv else []
        as_root = e.get("process.uid") == "0" if e.get("process.uid") is not None else e.get("process.user") == "root"
        if _DEBCONF_CONFIG.match(path) and rest and rest[0] in _DEBCONF_ACTIONS and as_root:
            claim = (f"A process execution event on {e.host} records '{name}' running '{path}' with "
                     f"'{rest[0]}' (argv: {_argv_summary(argv)}); {outcome_phrase(e)}. The name and arguments follow "
                     f"the Debian debconf convention for a package's configuration script, run as root, during installation "
                     f"(retained for context).")
            return [Match(self.id, claim, self.claim_type, [e], fields, e.ts, "low", "context", "medium",
                          _exec_entities(e))]
        claim = (f"A process execution event on {e.host} records that interpreter '{name}' was started with "
                 f"temp-directory script operand '{path}' (argv: {_argv_summary(argv)}); {outcome_phrase(e)}. "
                 f"The argv identifies a script operand; whether that script ran is not established by this event.")
        return [Match(self.id, claim, self.claim_type, [e], fields, e.ts, self.severity, self.lane, "medium",
                      _exec_entities(e))]


BUILTIN_CHAINS = {"INPUT", "OUTPUT", "FORWARD", "PREROUTING", "POSTROUTING"}
BLOCK_TARGETS = {"DROP", "REJECT"}


def _flag_value(args: list[str], *flags: str) -> str | None:
    for i, a in enumerate(args[:-1]):
        if a in flags:
            return args[i + 1]
    return None


class FirewallRuleChange(Playbook):
    """Direct findings for commands that block or unblock a specific address on a built-in chain, leads for
    commands that weaken the firewall (disable, flush, accept-by-default, open a port, remove a block); other
    rule-change commands are grouped per host as context."""
    id = "host.firewall_rule_change_command"
    # argv/text-identified programs and actions: findings only, never a complete negative
    assures_negative = False
    version = "4"
    title = "Firewall command blocking, unblocking or weakening"
    kind = "aggregate"
    families = ("process_exec",)
    required_fields = ("process.argv",)
    severity, lane = "high", "high"
    attack = ("T1562.004", "T1498", "T0815")
    benign = ("scheduled firewall management, VPN/IP-change scripts, configuration management",)
    next_checks = ("auth_activity for who was logged in", "entity_timeline of the host around the change",
                   "host_network for traffic to/from the affected address afterwards")

    def __init__(self):
        super().__init__()
        self.direct: list[Match] = []
        self.routine: dict[tuple, list[TypedEvent]] = defaultdict(list)
        self.routine_n: dict[tuple, int] = defaultdict(int)
        self.groups = self.routine

    def retained_events(self):
        # direct block/unblock matches are published at finalize too: their raw copies must be kept
        return super().retained_events() + [e for m in self.direct for e in m.events]

    def consume(self, events):
        for e in self.applicable(events):
            argv = e.get("process.argv")
            name, args = basename(argv[0]), argv[1:]
            if name not in FW_TOOLS:      # sudo wrappers are not counted; the child exec is the action
                continue
            changing = (name == "nft" and any(a in NFT_CHANGE for a in args)) or \
                       (name == "ufw" and any(a in {"allow", "deny", "reject", "delete", "insert", "disable"}
                                              for a in args)) or any(a in FW_CHANGE_FLAGS for a in args)
            if not changing:
                continue
            chain = _flag_value(args, "-A", "--append", "-I", "--insert", "-D", "--delete")
            target = _flag_value(args, "-j", "--jump")
            addr = _flag_value(args, "-s", "--source", "-d", "--destination")
            specific_block = chain in BUILTIN_CHAINS and target in BLOCK_TARGETS and addr
            weakening = None if specific_block else _firewall_weakening(name, args, chain, target)
            if weakening:
                # Disabling, flushing or opening the firewall is defense impairment (T1562.004), never routine.
                claim = (f"A process execution event on {e.host} records '{name}' run in a form that weakens the host "
                         f"firewall: {weakening} ({_argv_summary(argv)}); {outcome_phrase(e)}. Whether the change took "
                         f"effect is not established by this event.")
                self.direct.append(Match(self.id, claim, self.claim_type, [e], [pf(e, "process.argv")], e.ts,
                                         "medium", "lead", "high", _exec_entities(e)))
            elif specific_block:
                verb = "remove" if any(a in ("-D", "--delete") for a in args) else "add"
                claim = (f"A process execution event on {e.host} records '{name}' run to {verb} a {target} rule for "
                         f"{addr} on the {chain} chain ({_argv_summary(argv)}); {outcome_phrase(e)}. Whether the rule "
                         f"took effect is not established by this event.")
                m = Match(self.id, claim, self.claim_type, [e], [pf(e, "process.argv")], e.ts, self.severity,
                          self.lane, "high", _exec_entities(e))
                m.entities.append(("ip", addr.split("/")[0], "subject"))
                self.direct.append(m)
            else:
                key = (e.host, name)
                self.routine_n[key] += 1
                if len(self.routine[key]) < 10:
                    self.routine[key].append(e)
        return []

    def finalize(self):
        out = list(self.direct)
        for (host_, name), evs in self.routine.items():
            claim = (f"{self.routine_n[(host_, name)]} other '{name}' rule-change command(s) on {host_} that neither "
                     f"block a specific address on a built-in chain nor weaken the firewall (e.g. "
                     f"{_argv_summary(evs[0].get('process.argv'), 100)}); retained for context.")
            out.append(Match(self.id, claim, "aggregate_observation", evs[:5], [pf(evs[0], "process.argv")],
                             evs[0].ts, "low", "context", "high", _exec_entities(evs[0]),
                             group_key=f"routine|{host_}|{name}"))
        return out


_IPT_FLUSH = {"-F", "--flush", "-X", "--delete-chain"}
_OPEN_TARGETS = {"ACCEPT", "RETURN"}


def _firewall_weakening(name: str, args: list[str], chain: str | None, target: str | None) -> str | None:
    """Why a firewall command weakens protection, or None. Typed from argv tokens only."""
    if name == "ufw":
        if "disable" in args or "reset" in args:
            return "the firewall is disabled or reset"
        if "allow" in args:
            return "a rule allowing traffic is added"
        return None
    if name == "nft":
        if any(a in {"flush", "delete", "destroy"} for a in args):
            return "rules, chains or tables are flushed or deleted"
        if "accept" in args and any(a in {"add", "insert"} for a in args):
            return "an accept rule is added"
        return None
    if any(a in _IPT_FLUSH for a in args):
        return "rules or chains are flushed or deleted"
    policy = _flag_value(args, "-P", "--policy")
    if policy:
        position = args.index(policy) if policy in args else -1
        if 0 <= position < len(args) - 1 and args[position + 1] == "ACCEPT":
            return f"the default policy of {policy} is set to ACCEPT"
    if chain in BUILTIN_CHAINS and target in _OPEN_TARGETS and any(a in ("-A", "--append", "-I", "--insert")
                                                                   for a in args):
        return f"an {target} rule is added to the {chain} chain"
    if chain in BUILTIN_CHAINS and target in BLOCK_TARGETS and any(a in ("-D", "--delete") for a in args):
        return f"a {target} rule is removed from the {chain} chain"
    return None


class CredentialStoreRead(Playbook):
    id = "host.credential_store_read"
    anchor_class = "credential_access"
    # argv/text-identified programs and actions: findings only, never a complete negative
    assures_negative = False
    version = "2"
    title = "Local password hash file read by a file-reading tool"
    families = ("process_exec",)
    required_fields = ("process.argv",)
    severity, lane = "high", "high"
    attack = ("T1003.008",)
    benign = ("backup jobs, configuration management audits",)
    next_checks = ("auth_activity for the session that ran it", "process_tree", "host_network for exfiltration")

    def match(self, e):
        argv = e.get("process.argv")
        if not argv:
            return []
        name = basename(argv[0])
        args = argv[1:]
        if name not in FILE_READERS:      # sudo wrappers are not counted; the child exec is the action
            return []
        hits = [a for a in args if a in CRED_FILES]
        if not hits:
            return []
        claim = (f"A process execution event on {e.host} records '{name}' invoked with {hits[0]} as a file "
                 f"argument; {outcome_phrase(e)}.")
        return [Match(self.id, claim, self.claim_type, [e], [pf(e, "process.argv")], e.ts, self.severity, self.lane,
                      "high" if e.outcome == Outcome.success else "medium", _exec_entities(e))]


class AuthorizedKeysWrite(Playbook):
    """Indicator of an authorized_keys write: a tee/cp/mv/install exec naming the file (observed action),
    or a shell script containing a redirect into it (script content). Positive-only: shell-builtin
    redirects create no process, so absence can only be assured by file-access telemetry."""
    id = "host.ssh_authorized_keys_write"
    anchor_class = "persistence"
    version = "3"
    title = "Command or script writing to an SSH authorized_keys file"
    assures_negative = False
    families = ("process_exec",)
    required_fields = ("process.argv",)
    severity, lane = "high", "high"
    attack = ("T1098.004",)
    benign = ("provisioning / configuration management adding admin keys",)
    next_checks = ("auth_activity for later SSH logins with new keys", "process_tree of the writer")

    def match(self, e):
        argv = e.get("process.argv")
        targets = []
        from_script = False
        script = shell_script_of(argv)
        if isinstance(script, UnknownShellScript):
            self.missing_required += 1
        elif script:
            parsed = parse_script(script)
            if parsed.ok:
                for c in parsed.commands():
                    from_script = True
                    targets += [t for op, t in c.redirects if op in (">", ">>", ">|", "1>", "1>>")
                                and t.endswith("authorized_keys")]
                    if c.name in ("tee", "cp", "mv", "install") and c.argv and c.argv[-1].endswith("authorized_keys"):
                        targets.append(c.argv[-1])
            else:
                self.missing_required += 1
        elif argv and basename(argv[0]) in ("tee", "cp", "mv", "install") and argv[-1].endswith("authorized_keys"):
            targets.append(argv[-1])
        if not targets:
            return []
        if from_script:
            claim = (f"A process execution event on {e.host} records a shell started with a script that contains a "
                     f"write to {targets[0]}; {outcome_phrase(e)}. The script text shows intent; whether the write "
                     f"happened is not established by this event.")
            ctype = "script_content"
        else:
            claim = (f"A process execution event on {e.host} records a command that writes to {targets[0]}; "
                     f"{outcome_phrase(e)}. The file content written is not shown by this event.")
            ctype = "observed_action"
        return [Match(self.id, claim, ctype, [e], [pf(e, "process.argv")], e.ts, self.severity, self.lane,
                      "high", _exec_entities(e))]


class SshLoginFromExternal(Playbook):
    id = "host.ssh_login_external_source"
    anchor_class = "remote_login"
    # argv/text-identified programs and actions: findings only, never a complete negative
    assures_negative = False
    version = "3"
    title = "Successful SSH login from a non-private source address"
    kind = "aggregate"
    families = ("auth",)
    required_fields = ("auth.service", "source.ip", "user.name")
    claim_type = "aggregate_observation"
    severity, lane = "medium", "lead"
    attack = ("T1078", "T1021.004")
    benign = ("remote administration from approved external ranges",)
    next_checks = ("auth_activity for the account across hosts", "ip_sessions for the source address",
                   "entity_timeline for the host after login")

    def __init__(self):
        super().__init__()
        self.groups: dict[tuple, list[TypedEvent]] = defaultdict(list)

    def consume(self, events):
        for e in self.applicable(events):
            if e.get("auth.service") != "sshd" or e.outcome != Outcome.success:
                continue
            if e.get("auth.phase") == "session_open":      # a PAM session opening is not an authentication
                continue
            try:
                ip = ipaddress.ip_address(e.get("source.ip"))
            except ValueError:
                continue
            if is_internal(ip):
                continue
            self.groups[(e.host, e.get("user.name"), str(ip))].append(e)
        return []

    def finalize(self):
        out = []
        for (host, user, ip), evs in self.groups.items():
            evs.sort(key=lambda x: (x.ts, x.id))
            # Each login appears once per collected source (journal sshd "Accepted", audit USER_LOGIN), so the
            # login count is the larger per-source count, never their sum.
            journal = sum(1 for e in evs if e.get("auth.phase") != "login")
            audit = sum(1 for e in evs if e.get("auth.phase") == "login")
            logins = max(journal, audit)
            sources = "; ".join(part for part in (
                f"{journal} sshd 'Accepted' journal record(s)" if journal else "",
                f"{audit} audit USER_LOGIN record(s)" if audit else "") if part)
            claim = (f"At least {logins} successful SSH login(s) on {host} for account '{user}' from non-private address "
                     f"{ip} ({evs[0].ts.isoformat()} – {evs[-1].ts.isoformat()}; {sources}).")
            m = Match(self.id, claim, self.claim_type, evs[:20], [pf(evs[0], "source.ip"), pf(evs[0], "user.name")],
                      evs[0].ts, self.severity, self.lane, "high", evs[0].entities(), group_key=f"{host}|{user}|{ip}")
            if len(evs) > 20:
                m.notes.append(f"{len(evs)} matching records; the first 20 are cited and the time range covers "
                               "all of them")
            out.append(m)
        return out


HOST_PLAYBOOKS = [WebServiceSpawnsInterpreter, DownloadPipedToShell, DownloaderFeedsInterpreter, PtyUpgrade,
                  ExecFromTempDir, ScriptFromTempDir, FirewallRuleChange, CredentialStoreRead, AuthorizedKeysWrite,
                  SshLoginFromExternal]
