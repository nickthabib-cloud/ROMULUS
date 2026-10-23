"""Host playbooks over typed process_exec / auth events (Linux, lab telemetry)."""
from __future__ import annotations

import ast
import ipaddress
import itertools
import posixpath
import re
from bisect import bisect_right, insort
from collections import defaultdict
from datetime import UTC, datetime
from typing import ClassVar, NamedTuple

from romulus.detect.base import Match, Playbook, argv_incomplete, basename, outcome_phrase, pf
from romulus.detect.bounded import HOT_COUNT, HeldExamples, KeyedStore, RecentIds, SpillList, StateExhausted
from romulus.detect.linux_argv import canonical, program, read_operand_paths
from romulus.evidence.shellparse import (
    SHELLS,
    UnknownShellScript,
    classify_redirect,
    parse_script,
    shell_dialect,
    shell_script_file_of,
    shell_script_of,
)
from romulus.evidence.typed import Outcome, TypedEvent, raw_identity

# The disk budget of a finalize-time table built from records already held within their own budgets: never spent,
# so a finding is never lost while it is assembled.
UNBUDGETED = 2**62

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
FW_RESTORE_TOOLS = {"iptables-restore", "ip6tables-restore", "iptables-legacy-restore", "iptables-nft-restore"}
FW_SERVICES = {"ufw", "firewalld", "nftables", "iptables", "ip6tables", "netfilter-persistent"}
FW_SERVICE_VERBS = {"stop", "disable", "mask", "kill"}
FIREWALLD_CHANGE = ("--add-", "--remove-", "--panic-", "--set-default-zone", "--reload", "--change-")
NFT_BASE_CHAINS = {"input", "forward", "output", "prerouting", "postrouting"}
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


ALONE_NOTE = ("published from a record read after this rule's share of the hunt's state budget was spent: the group "
              "it belongs to could not be held, so later records of the same group are not counted or cited")


def alone(match: Match, rule: Playbook, record: TypedEvent) -> Match | None:
    """A strong match published from consume because the rule's state budget refused the state that would group it.
    It is identified per group (`<group key>|unheld`; a match without a group key is its own record's), so the first
    record of a group read after the budget was spent publishes it and later ones of the same group add nothing
    (None here while the rule still remembers the group; the candidate store drops a later repeat in any case).

    It cites every record it states. A record of the batch being read is cited from the partition's raw copies; an
    earlier record is cited from the event stage, where a staged rule put it when it held it (each strong rule stages
    every record it holds as it reads it). Only when the stage could not take this rule's citations (`stage` limit)
    is an earlier record dropped: its predicates go with it, and the claim says in its own text that it is not
    cited."""
    key = f"{match.group_key or f'record:{record.id}'}|unheld"
    seen = rule.__dict__.get("_unheld")
    if seen is None:
        seen = rule._unheld = RecentIds()
    if key in seen:
        return None
    seen.add(key)
    if not rule.staged or "stage" in rule.limits:
        batch = getattr(rule, "_batch", None) or [record]
        cache = getattr(rule, "_batch_ids", None)
        if cache is None or cache[0] is not batch:
            cache = rule._batch_ids = (batch, {e.id for e in batch})
        kept = [e for e in match.events if e.id in cache[1]] or [record]
        dropped = [e for e in match.events if e not in kept]
        if dropped:
            match.predicate = [p for p in match.predicate
                               if not any(_stated_by(p, e) for e in dropped) or any(_stated_by(p, e) for e in kept)]
            match.claim += (f" {len(dropped)} related record(s) named here were read in an earlier partition and "
                            f"are (not cited): the event stage could not hold their citation.")
            match.events = kept
    match.group_key = key
    match.notes.append(ALONE_NOTE)
    return match


def _stated_by(predicate, event: TypedEvent) -> bool:
    """Whether a predicate field is this record's own field value."""
    held = event.fields.get(predicate.field)
    return held is not None and held.origin == predicate.origin and held.value == predicate.value


def add_unheld(out: list, match: Match | None) -> None:
    """Add a match `alone` published (None: its group was already published)."""
    if match is not None:
        out.append(match)


def need(value, rule: Playbook, what: str):
    """A finalize table refused new state (the stage volume is at its reserve): finalize stops honestly, and the rule
    publishes what it can without disk (`finalize_fallback`)."""
    if value is None or value is False:
        budget = rule.budget
        reason = (budget.hard if budget is not None else "") or "a finalize table could not take new state"
        raise StateExhausted(f"{what}: {reason}")
    return value


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
    state_slice = "strong"           # a strong-indicator rule (see Playbook.state_slice)
    id = "host.web_service_spawns_interpreter"
    argv_prefix_safe = True
    anchor_class = "web_shell"
    # argv/text-identified programs and actions: findings only, never a complete negative
    assures_negative = False
    version = "12"
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
    # Shapes (host, account, command shape, packaged script) of web-service interpreter runs: their run count, their
    # exact runs per clock hour (so a run read late, from a target read after its hour, is counted in its own hour)
    # and their first 20 runs cited (staged, held as ids). Shapes live in a keyed store, HOT in memory and the rest
    # on the rule's disk spill; only its disk budget refuses a new shape, and coverage says so.
    staged = True
    HOT = HOT_COUNT  # a count cap only: the hunt's memory budget sizes it in bytes
    CITE = 20

    def __init__(self):
        super().__init__()
        self.shapes = KeyedStore(self, "web_shapes", self.HOT)    # key -> [runs, cited runs, {clock hour: runs}]
        # shapes in first-seen order: an index of shapes the store accepted, so the budget never refuses it
        self.order = SpillList(self, "web_shape_order", self.HOT, refusable=False)
        self._pending: list[TypedEvent] = []
        self._fresh: list[HeldExamples] = []
        self.load = lambda ids: []

    def drain_staged(self) -> list[TypedEvent]:
        out, self._pending = self._pending, []
        for store in self._fresh:
            store.staged()
        self._fresh = []
        self.shapes.trim()
        self.order.trim()
        return out

    def retained_events(self) -> list[TypedEvent]:
        return [item[1] for store in self._fresh for item in store.items if item[1] is not None]

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
            # a packaged-script run is judged on the whole command line; an incomplete one is never routine
            packaged = None if argv_incomplete(e) else _packaged_script(argv, e.get("process.cwd"))
            key = (e.host, user, command_shape(argv), packaged)
            state = self.shapes.get(key)
            if state is None:
                state = [0, HeldExamples(self.CITE), {}]
                if not self.shapes.put(key, state):
                    # its rarity cannot be judged without the shape's count: a lead per shape, published as read
                    self.note_limit("shapes_unheld", "the web-service interpreter shapes' disk budget is spent; a run "
                                                     "of a new shape is published as a lead without its count")
                    m = self._event_match(e, user, argv, [])
                    m.group_key = "|".join(map(str, key))
                    m.notes.append("the shape's run count is unknown, so its rarity was not judged")
                    add_unheld(matches, alone(m, self, e))
                    continue
                self.order.append(key)
            state[0] += 1
            hours = state[2]
            hour = e.ts.replace(minute=0, second=0, microsecond=0)
            hours[hour] = hours.get(hour, 0) + 1
            if state[1].offer(e):
                self._pending.append(e)
                self._fresh.append(state[1])
        return matches

    @staticmethod
    def _hour_stats(state: list) -> tuple[int, int]:
        """(distinct clock hours with a run, runs in the busiest hour)."""
        return len(state[2]), max(state[2].values())

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
        for key in self.order:
            state = self.shapes.peek(key)
            evs = state[1].events(self.load)
            host_, user, shape, packaged = key
            n = state[0]
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
            distinct_hours, busiest = self._hour_stats(state)
            scheduled = distinct_hours >= self.ROUTINE_MIN_HOURS and busiest * 2 <= n
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
                         f"spread across {distinct_hours} distinct hours like a schedule "
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
    state_slice = "strong"           # a strong-indicator rule (see Playbook.state_slice)
    id = "host.downloader_feeds_interpreter"
    # argv/text-identified programs and actions: findings only, never a complete negative
    assures_negative = False
    version = "3"
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

    # Downloaders wait MAX_GAP for their interpreter; a parent's waiting list is released once the newest exec read
    # is more than MAX_GAP past its latest downloader (an out-of-order batch within that gap still pairs). Every
    # downloader is staged when read (a pair split by a partition boundary keeps its evidence), and so is each
    # paired interpreter. Pairs are held on a list, HOT in memory and the rest on the rule's disk spill; only its
    # disk budget refuses, and coverage says so.
    staged = True
    HOT = HOT_COUNT  # a count cap only: the hunt's memory budget sizes it in bytes
    FINALIZE_TRIM = 10_000

    def __init__(self):
        super().__init__()
        self.pending: dict[tuple, list[TypedEvent]] = defaultdict(list)
        self.found = SpillList(self, "downloader_pairs", self.HOT)
        self._pending: list[TypedEvent] = []
        self.load = lambda ids: []

    def drain_staged(self) -> list[TypedEvent]:
        out, self._pending = self._pending, []
        self.found.trim()
        return out

    def retained_events(self) -> list[TypedEvent]:
        return list(self._pending)                      # the rest are staged on disk

    def consume(self, events):
        newest = None
        self._batch, out = events, []
        for e in sorted(self.applicable(events), key=lambda x: x.ts):
            newest = e.ts
            self._consume_one(e, out)
        if newest is not None:
            for key in [k for k, waiting in self.pending.items()
                        if not waiting or (newest - waiting[-1].ts).total_seconds() > self.MAX_GAP * 2]:
                del self.pending[key]
        self._batch = None
        return out

    def _consume_one(self, e, out: list) -> None:
        argv = e.get("process.argv")
        name = interpreter_name(argv[0])
        key = (e.host, e.get("process.ppid"))
        if name in DOWNLOADERS and any("://" in a for a in argv[1:]):
            self.pending[key] = [p for p in self.pending[key] if (e.ts - p.ts).total_seconds() <= self.MAX_GAP]
            self.pending[key].append(e)
            self._pending.append(e)
            return
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
                    if not self.found.append(m):
                        # the pair is a finding by itself: published now, ungrouped, instead of being refused
                        self.note_limit("pairs_alone", "the downloader-interpreter pairs' disk budget is spent; later "
                                                       "pairs are published one at a time, not grouped by URL")
                        add_unheld(out, alone(m, self, e))
                        break
                    self._pending.append(e)
                    break

    def finalize(self):
        """Collapse repeats of the same (host, URL, interpreter) into one item; regular repetition is
        itself evidence of scheduled execution and is reported as such."""
        grouped = KeyedStore(self, "downloader_grouped", self.HOT, disk_budget=UNBUDGETED)
        order = SpillList(self, "downloader_group_order", self.HOT, disk_budget=UNBUDGETED)
        for i, m in enumerate(self.found):
            d, e = m.events
            url = next(a for a in d.get("process.argv")[1:] if "://" in a)
            key = (d.host, url, basename(e.get("process.argv")[0]))
            ms = grouped.get(key)
            if ms is None:
                need(grouped.put(key, ms := []), self, "the downloader pairs' grouping")
                need(order.append(key), self, "the downloader pairs' grouping")
            ms.append(m)
            if i % self.FINALIZE_TRIM == self.FINALIZE_TRIM - 1:
                grouped.trim()
                order.trim()
        out = []
        for host_, url, interp in order:
            ms = grouped.peek((host_, url, interp))
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
        grouped.clear()
        order.clear()
        return out

    def finalize_fallback(self, reason: str) -> list[Match]:
        """Every pair held, each on its own (no grouping by URL needs disk)."""
        try:
            pairs = list(self.found)
        except StateExhausted:
            pairs = [m for _order, m in self.found.buffer]          # the list on disk cannot be read: memory only
        for m in pairs:
            m.notes.append(f"published on its own: grouping by URL needed disk ({reason})")
        return pairs


class DownloadPipedToShell(Playbook):
    """Script-text indicator: a shell was started with a script containing downloader | interpreter.
    Positive-only: whether the pipeline ran is shown by process-level evidence
    (host.downloader_feeds_interpreter), never inferred from text."""
    id = "host.download_piped_to_shell"
    argv_prefix_safe = True
    version = "4"
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
        parsed = parse_script(script, shell_dialect(e.get("process.executable"), e.get("process.argv")))
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
    argv_prefix_safe = True
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
    argv_prefix_safe = True
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
    argv_prefix_safe = True
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
    state_slice = "strong"           # a strong-indicator rule (see Playbook.state_slice)
    id = "host.firewall_rule_change_command"
    # argv/text-identified programs and actions: findings only, never a complete negative
    assures_negative = False
    version = "7"
    title = "Firewall command blocking, unblocking or weakening"
    kind = "aggregate"
    families = ("process_exec",)
    required_fields = ("process.argv",)
    severity, lane = "high", "high"
    attack = ("T1562.004", "T1498", "T0815")
    benign = ("scheduled firewall management, VPN/IP-change scripts, configuration management",)
    next_checks = ("auth_activity for who was logged in", "entity_timeline of the host around the change",
                   "host_network for traffic to/from the affected address afterwards")

    # Specific-address block/unblock commands are published at finalize: held on a list, HOT in memory and the rest
    # on the rule's disk spill (only its disk budget refuses, and coverage says so). Weakening and routine groups
    # hold at most 20 and 10 records per (host, tool, form). Every record a finding may cite is staged when kept.
    staged = True
    HOT = HOT_COUNT  # a count cap only: the hunt's memory budget sizes it in bytes

    def __init__(self):
        super().__init__()
        self.direct = SpillList(self, "firewall_direct", self.HOT)
        self.weak: dict[tuple, list[TypedEvent]] = defaultdict(list)
        self.weak_n: dict[tuple, int] = defaultdict(int)
        self.routine: dict[tuple, list[TypedEvent]] = defaultdict(list)
        self.routine_n: dict[tuple, int] = defaultdict(int)
        self.groups = self.routine
        self._pending: list[TypedEvent] = []
        self.load = lambda ids: []

    def drain_staged(self) -> list[TypedEvent]:
        out, self._pending = self._pending, []
        self.direct.trim()
        return out

    def retained_events(self) -> list[TypedEvent]:
        return list(self._pending)                      # the rest are staged on disk

    def consume(self, events):
        self._batch, out = events, []
        for e in self.applicable(events):
            argv = e.get("process.argv")
            name, args = basename(argv[0]), argv[1:]
            if name == "systemctl":
                if any(a in FW_SERVICE_VERBS for a in args) and any(a.removesuffix(".service") in FW_SERVICES
                                                                    for a in args):
                    self._weakening(e, name, ("the firewall service is stopped, disabled or masked", True))
                continue
            if name in FW_RESTORE_TOOLS or (name == "nft" and "-f" in args):
                replaced = "the rule set is replaced from a file or stdin, whose content is not visible in the command line"
                self._weakening(e, name, (replaced, False))
                continue
            if name not in FW_TOOLS:      # sudo wrappers are not counted; the child exec is the action
                continue
            changing = (name == "nft" and any(a in NFT_CHANGE for a in args)) or \
                       (name == "ufw" and any(a in {"allow", "deny", "reject", "delete", "insert", "disable", "reset"}
                                              for a in args)) or \
                       (name == "firewall-cmd" and any(a.startswith(FIREWALLD_CHANGE) for a in args)) or \
                       any(a in FW_CHANGE_FLAGS for a in args)
            if not changing:
                continue
            chain = _flag_value(args, "-A", "--append", "-I", "--insert", "-D", "--delete")
            target = _flag_value(args, "-j", "--jump")
            addr = _flag_value(args, "-s", "--source", "-d", "--destination")
            specific_block = chain in BUILTIN_CHAINS and target in BLOCK_TARGETS and addr
            weakening = None if specific_block else _firewall_weakening(name, args, chain, target)
            if weakening:
                self._weakening(e, name, weakening)
            elif specific_block:
                verb = "remove" if any(a in ("-D", "--delete") for a in args) else "add"
                claim = (f"A process execution event on {e.host} records '{name}' run to {verb} a {target} rule for "
                         f"{addr} on the {chain} chain ({_argv_summary(argv)}); {outcome_phrase(e)}. Whether the rule "
                         f"took effect is not established by this event.")
                m = Match(self.id, claim, self.claim_type, [e], [pf(e, "process.argv")], e.ts, self.severity,
                          self.lane, "high", _exec_entities(e))
                m.entities.append(("ip", addr.split("/")[0], "subject"))
                if not self.direct.append(m):
                    self.note_limit("direct_alone", "the specific-address firewall changes' disk budget is spent; "
                                                    "later ones are published as they are read")
                    add_unheld(out, alone(m, self, e))
                    continue
                self._pending.append(e)
            else:
                key = (e.host, name)
                self.routine_n[key] += 1
                if len(self.routine[key]) < 10:
                    self.routine[key].append(e)
                    self._pending.append(e)
        self._batch = None
        return out

    def _weakening(self, e: TypedEvent, name: str, weakening: tuple[str, bool]) -> None:
        # Disabling, flushing or opening the firewall is defense impairment (T1562.004): always a lead, grouped per
        # host, tool and form so a service restart that issues many such commands is one lead, not dozens.
        key = (e.host, name, weakening)
        self.weak_n[key] += 1
        if len(self.weak[key]) < 20:
            self.weak[key].append(e)
            self._pending.append(e)

    def finalize(self):
        out = list(self.direct)
        for key in sorted(self.weak, key=str):
            host_, name, (reason, weakens) = key
            evs = sorted(self.weak[key], key=lambda e: (e.ts, e.id))
            n = self.weak_n[key]
            what = "weakens the host firewall" if weakens else "changes firewall state"
            claim = (f"{n} '{name}' command(s) on {host_} in a form that {what}: {reason} (e.g. "
                     f"{_argv_summary(evs[0].get('process.argv'), 100)}); {_outcome_tally(evs)}."
                     + ("" if weakens else " Whether this weakens protection is not established by the command line.")
                     + (f" The earliest {len(evs)} are cited." if len(evs) < n else ""))
            out.append(Match(self.id, claim, self.claim_type, evs, [pf(x, "process.argv") for x in evs], evs[0].ts,
                             "medium", "lead", "high", _exec_entities(evs[0]),
                             group_key=f"weak|{host_}|{name}|{reason}"))
        for (host_, name), evs in self.routine.items():
            # Unclassified changes may open the firewall in a form not modelled here, so they are kept visible.
            evs = sorted(evs, key=lambda e: (e.ts, e.id))
            n = self.routine_n[(host_, name)]
            claim = (f"{n} other '{name}' rule-change command(s) on {host_} not recognised as a specific-address "
                     f"block or a known weakening form (e.g. {_argv_summary(evs[0].get('process.argv'), 100)}); "
                     f"whether they weaken protection is not established; {_outcome_tally(evs)}."
                     + (f" The earliest {len(evs)} are cited." if len(evs) < n else ""))
            out.append(Match(self.id, claim, "aggregate_observation", evs, [pf(x, "process.argv") for x in evs],
                             evs[0].ts, "low", "lead", "high", _exec_entities(evs[0]),
                             group_key=f"routine|{host_}|{name}"))
        return out


_IPT_FLUSH = {"-F", "--flush", "-X", "--delete-chain"}
_OPEN_TARGETS = {"ACCEPT", "RETURN"}


def _outcome_tally(events: list[TypedEvent]) -> str:
    counts = {outcome: sum(1 for e in events if e.outcome == outcome) for outcome in Outcome}
    return (f"recorded exec outcomes of the cited runs: {counts[Outcome.success]} succeeded, "
            f"{counts[Outcome.failure]} failed, {counts[Outcome.unknown]} unknown")


def _flushed_chain(args: list[str]) -> str | None:
    for i, a in enumerate(args):
        if a in _IPT_FLUSH:
            nxt = args[i + 1] if i + 1 < len(args) else ""
            return nxt if nxt and not nxt.startswith("-") else ""
    return None


def _firewall_weakening(name: str, args: list[str], chain: str | None, target: str | None) -> tuple[str, bool] | None:
    """(the form, True when it plainly weakens protection) for a firewall command that weakens it or changes it in a
    way that may; None otherwise. Typed from argv tokens only."""
    if name == "ufw":
        if "delete" in args:          # a removal: of a block it weakens; of an allow it tightens
            return ("a ufw blocking rule is removed", True) if any(a in ("deny", "reject") for a in args) else None
        if "disable" in args or "reset" in args:
            return ("the firewall is disabled or reset", True)
        if "allow" in args:
            return ("a ufw rule allowing traffic is added", True)
        return None
    if name == "firewall-cmd":
        opened = [a for a in args if a.startswith(("--add-port", "--add-service", "--add-rich-rule", "--add-source",
                                                   "--add-masquerade", "--add-forward-port"))]
        if opened:
            return (f"firewalld is opened ({opened[0].split('=')[0]})", True)
        if "--panic-off" in args or any(a.startswith("--set-default-zone=trusted") for a in args):
            return ("firewalld protection is relaxed (panic off or the trusted zone made default)", True)
        return None
    if name == "nft":
        if any(a in {"flush", "delete", "destroy"} for a in args):
            if "ruleset" in args or any(a in NFT_BASE_CHAINS for a in args):
                return ("the rule set or a base chain is flushed or deleted", True)
            return ("a table or chain is flushed or deleted", False)
        if "accept" in args and any(a in {"add", "insert"} for a in args):
            return ("an accept rule is added", True)
        return None
    flushed = _flushed_chain(args)
    if flushed is not None:
        if flushed in BUILTIN_CHAINS:
            return (f"built-in chain {flushed} is flushed", True)
        if flushed == "":
            if any(a in ("-F", "--flush") for a in args):
                return ("all rules of the table are flushed", True)
            return ("empty user-defined chains are deleted", False)
        return (f"user-defined chain {flushed} is flushed or deleted", False)
    policy = _flag_value(args, "-P", "--policy")
    if policy:
        position = args.index(policy) if policy in args else -1
        if 0 <= position < len(args) - 1 and args[position + 1] == "ACCEPT":
            return (f"the default policy of {policy} is set to ACCEPT", True)
    if chain in BUILTIN_CHAINS and target in _OPEN_TARGETS and any(a in ("-A", "--append", "-I", "--insert")
                                                                   for a in args):
        return (f"an {target} rule is added to the {chain} chain", True)
    if chain in BUILTIN_CHAINS and target in BLOCK_TARGETS and any(a in ("-D", "--delete") for a in args):
        return (f"a {target} rule is removed from the {chain} chain", True)
    return None


class CredentialStoreRead(Playbook):
    id = "host.credential_store_read"
    argv_prefix_safe = True
    anchor_class = "credential_access"
    # argv/text-identified programs and actions: findings only, never a complete negative
    assures_negative = False
    version = "3"
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
        paths, unplaced = read_operand_paths(name, args, e.get("process.cwd"))
        if unplaced:
            self.missing_required += 1      # a relative operand with no working directory: it may name the file
        hits = [a for a in args if a in CRED_FILES]
        # a file operand that names a hash file only once resolved (shadow from /etc, /etc/../etc/shadow)
        resolved = [p for p in paths if p in CRED_FILES and p not in hits]
        if not hits and not resolved:
            return []
        fields = [pf(e, "process.argv")]
        if hits:
            shown = hits[0]
        else:
            shown = f"a file operand that resolves to {resolved[0]}"
            if e.get("process.cwd"):
                fields.append(pf(e, "process.cwd"))
        claim = (f"A process execution event on {e.host} records '{name}' invoked with {shown} as a file "
                 f"argument; {outcome_phrase(e)}.")
        return [Match(self.id, claim, self.claim_type, [e], fields, e.ts, self.severity, self.lane,
                      "high" if e.outcome == Outcome.success else "medium", _exec_entities(e))]


class AuthorizedKeysWrite(Playbook):
    """Indicator of an authorized_keys write: a tee/cp/mv/install exec naming the file (observed action),
    or a shell script containing a redirect into it (script content). Positive-only: shell-builtin
    redirects create no process, so absence can only be assured by file-access telemetry."""
    id = "host.ssh_authorized_keys_write"
    argv_prefix_safe = True
    anchor_class = "persistence"
    version = "4"
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
            parsed = parse_script(script, shell_dialect(e.get("process.executable"), argv))
            if parsed.ok:
                for c in parsed.commands():
                    from_script = True
                    for op, t in c.redirects:
                        written = classify_redirect(op, t).writes_file
                        if written and written.endswith("authorized_keys"):
                            targets.append(written)
                    if c.name in ("tee", "cp", "mv", "install") and c.argv and c.argv[-1].endswith("authorized_keys"):
                        targets.append(c.argv[-1])
            else:
                self.missing_required += 1
        elif (argv and basename(argv[0]) in ("tee", "cp", "mv", "install") and argv[-1].endswith("authorized_keys")
              and not argv_incomplete(e)):       # the last operand is the destination only in a complete argv
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
    state_slice = "strong"           # a strong-indicator rule (see Playbook.state_slice)
    id = "host.ssh_login_external_source"
    anchor_class = "remote_login"
    # argv/text-identified programs and actions: findings only, never a complete negative
    assures_negative = False
    version = "4"
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

    # Per (host, account, source): the earliest 20 records cited (staged, held as ids) and the counts, so a group
    # costs references, not every login. Groups live in a keyed store, HOT in memory and the rest on the rule's
    # disk spill; only its disk budget refuses a new group, and coverage says so.
    staged = True
    HOT = HOT_COUNT  # a count cap only: the hunt's memory budget sizes it in bytes

    def __init__(self):
        super().__init__()
        # (host, account, source) -> [journal records, audit records, latest time, cited records]
        self.groups = KeyedStore(self, "ssh_external_groups", self.HOT)
        # groups in first-seen order: an index of groups the store accepted, so the budget never refuses it
        self.order = SpillList(self, "ssh_external_order", self.HOT, refusable=False)
        self._pending: list[TypedEvent] = []
        self._fresh: list[HeldExamples] = []
        self.load = lambda ids: []

    def drain_staged(self) -> list[TypedEvent]:
        out, self._pending = self._pending, []
        for store in self._fresh:
            store.staged()
        self._fresh = []
        self.groups.trim()
        self.order.trim()
        return out

    def retained_events(self) -> list[TypedEvent]:
        return [item[1] for store in self._fresh for item in store.items if item[1] is not None]

    def consume(self, events):
        self._batch, out = events, []
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
            key = (e.host, e.get("user.name"), str(ip))
            tally = self.groups.get(key)
            if tally is None:
                tally = [0, 0, e.ts, HeldExamples(20, earliest=True)]
                if not self.groups.put(key, tally):
                    # a login from outside is a finding by itself: published now, ungrouped, instead of refused
                    self.note_limit("groups_alone", "the (host, account, source) groups' disk budget is spent; "
                                                    "logins of a new group are published one at a time")
                    login = e.get("auth.phase") == "login"
                    add_unheld(out, alone(self._login_match(key, int(not login), int(login), e.ts, [e]), self, e))
                    continue
                self.order.append(key)
            tally[1 if e.get("auth.phase") == "login" else 0] += 1
            tally[2] = max(tally[2], e.ts)
            store = tally[3]
            if store.offer(e):
                self._pending.append(e)
                self._fresh.append(store)
        self._batch = None
        return out

    def finalize(self):
        out = []
        for host, user, ip in self.order:
            journal, audit, last, store = self.groups.peek((host, user, ip))
            out.append(self._login_match((host, user, ip), journal, audit, last, store.events(self.load)))
        return out

    def _login_match(self, key: tuple, journal: int, audit: int, last, evs: list[TypedEvent]) -> Match:
        host, user, ip = key
        # Each login appears once per collected source (journal sshd "Accepted", audit USER_LOGIN), so the
        # login count is the larger per-source count, never their sum.
        logins = max(journal, audit)
        sources = "; ".join(part for part in (
            f"{journal} sshd 'Accepted' journal record(s)" if journal else "",
            f"{audit} audit USER_LOGIN record(s)" if audit else "") if part)
        claim = (f"At least {logins} successful SSH login(s) on {host} for account '{user}' from non-private address "
                 f"{ip} ({evs[0].ts.isoformat()} – {last.isoformat()}; {sources}).")
        m = Match(self.id, claim, self.claim_type, evs, [pf(evs[0], "source.ip"), pf(evs[0], "user.name")],
                  evs[0].ts, self.severity, self.lane, "high", evs[0].entities(), group_key=f"{host}|{user}|{ip}")
        if journal + audit > 20:
            m.notes.append(f"{journal + audit} matching records; the first 20 are cited and the time range covers "
                           "all of them")
        return m


_DELETED_SUFFIX = " (deleted)"
_UNBACKED_CITE = 10


def unbacked_executable(exe: str) -> tuple[str, str] | None:
    """(class, meaning) when a kernel-recorded executable path shows an image with no ordinary file behind it."""
    if exe.startswith("/memfd:"):
        return ("memfd", ("the program image is an anonymous memory-backed file (memfd) with no path on any "
                         "filesystem. In-memory loaders and fileless implants run this way; so does runc, which "
                         "re-executes a copy of itself from a memfd when it starts a container"))
    if exe.endswith(_DELETED_SUFFIX):
        path = exe[:-len(_DELETED_SUFFIX)]
        packaged = ". The path is in a package-managed directory" if path.startswith(PACKAGED_DIRS) else ""
        return ("deleted", "the file at that path was deleted or replaced after the process started, so the "
                           "running image no longer matches any file there. A package upgrade that replaces a "
                           "long-running daemon's binary leaves this record; so does a program that deletes itself "
                           "after starting" + packaged)
    path = _normalize_posix_path(exe) if exe.startswith("/") else exe
    if path.startswith("/dev/shm/"):
        return ("shm", ("the executable is in /dev/shm, a shared-memory filesystem every account can write and "
                       "that does not survive a reboot"))
    if path.startswith("/run/user/"):
        return ("run_user", ("the executable is in /run/user, an account's in-memory runtime directory that does "
                            "not survive logout or a reboot"))
    return None


class UnbackedExecutable(Playbook):
    """A process whose kernel-recorded executable is memory-backed, deleted or in an in-memory runtime directory,
    seen on any audit record that carries the executable (exec, socket or file-change calls)."""
    state_slice = "strong"           # a strong-indicator rule (see Playbook.state_slice)
    id = "host.unbacked_or_deleted_executable"
    version = "2"
    title = "Process running from a memory-backed, deleted or in-memory-directory executable"
    anchor_class = "execution"
    kind = "aggregate"
    claim_type = "aggregate_observation"
    families = ("process_exec", "net_socket", "file_change")
    required_fields = ("process.executable",)
    assures_negative = False
    positive_only_reason = ("the audit rules record only some processes' calls (which accounts, calls and paths "
                            "is not visible in telemetry), so a process absent from the records proves nothing")
    severity, lane = "high", "lead"
    attack = ("T1027.011", "T1620", "T1070.004", "T1036.005")
    benign = ("daemons still running after a package upgrade replaced their binary (the path ends in ' (deleted)')",
              "runc and other container runtimes re-executing themselves from a memfd",
              "per-user tooling unpacked into /run/user (desktop sessions)")
    next_checks = ("the process's parent and how it started; whether the path is package-owned and was upgraded",
                   "the process's sockets and children while it ran",
                   "for a memfd or self-deleted image: the creating process and its download or write")
    card: ClassVar[dict] = {
        "behavior": "the kernel-recorded executable of a process (SYSCALL exe) is a memfd, a deleted file, or a "
                    "file in /dev/shm or /run/user",
        "telemetry": "Linux auditd SYSCALL exe on process_exec, net_socket and file_change events "
                     "(process.executable); present on every SYSCALL record in the lab profile, where the "
                     "' (deleted)' records seen are package-upgraded daemons",
        "fidelity": "direct kernel record of the running image's path at the call; it does not show who deleted "
                    "the file or what the image contains",
        "benign_and_cost": "post-upgrade daemons and container runtimes; grouped per (host, executable), so one "
                           "lead per upgraded daemon",
        "query_cost": "none beyond the sweep: it reads the host partitions every host rule reads",
        "next_pivot": "the process lineage and its network activity; package upgrade history for deleted paths",
        "adds": "the temp-directory exec rule sees only exec records under temporary directories; this sees "
                "fileless and self-deleted images on any recorded call, including sockets",
        "research_basis": "ATT&CK Enterprise 20.0 T1027.011 (Fileless Storage), T1620 (Reflective Code Loading), "
                          "T1070.004 (File Deletion); /proc/<pid>/exe ' (deleted)' and memfd naming in the Linux "
                          "kernel d_path conventions",
        "retrieval": "the sweep retrieves every record of the host datasets in each partition (dataset filter "
                     "only), a superset of what this evaluator reads",
    }

    # Per (host, executable): the first records cited (staged, held as ids), counts per family, span and uids. Groups
    # live in a keyed store, HOT in memory and the rest on the rule's disk spill; only its disk budget refuses a new
    # group, and coverage says so.
    staged = True
    HOT = HOT_COUNT  # a count cap only: the hunt's memory budget sizes it in bytes

    def __init__(self):
        super().__init__()
        self._seen = RecentIds()        # bounded re-read guard
        # (host, executable) -> [{family: records}, [first, last], {uid}, cited records]
        self.groups = KeyedStore(self, "unbacked_groups", self.HOT)
        self._pending: list[TypedEvent] = []
        self._fresh: list[HeldExamples] = []
        self.load = lambda ids: []

    def consume(self, events):
        self._batch, out = events, []
        for e in sorted((e for e in events if e.family in self.families and e.id not in self._seen),
                        key=lambda e: (e.ts, e.id)):
            self._seen.add(e.id)
            exe = e.get("process.executable")
            if not exe:
                self.missing_required += 1
                continue
            self.evaluated += 1
            if unbacked_executable(str(exe)) is None:
                continue
            key = (e.host or "", str(exe))
            ts = e.ts.timestamp()
            group = self.groups.setdefault(key, lambda ts=ts: [{}, [ts, ts], set(), HeldExamples(_UNBACKED_CITE)])
            if group is None:
                # the record is a finding by itself: published now, ungrouped, instead of being refused
                self.note_limit("groups_alone", "the (host, executable) groups' disk budget is spent; records of a "
                                                "new group are published one at a time")
                uid = e.get("process.uid")
                add_unheld(out, alone(self._group_match(key, {e.family: 1}, ts, ts,
                                                   {str(uid)} if uid is not None else set(), [e]), self, e))
                continue
            counts, span, uids, store = group
            counts[e.family] = counts.get(e.family, 0) + 1
            span[0], span[1] = min(span[0], ts), max(span[1], ts)
            if e.get("process.uid") is not None:
                uids.add(str(e.get("process.uid")))
            if store.offer(e):
                self._pending.append(e)
                self._fresh.append(store)
        self._batch = None
        return out

    def drain_staged(self) -> list[TypedEvent]:
        out, self._pending = self._pending, []
        for store in self._fresh:
            store.staged()
        self._fresh = []
        self.groups.trim()
        return out

    def retained_events(self) -> list[TypedEvent]:
        return [item[1] for store in self._fresh for item in store.items if item[1] is not None]

    def finalize(self):
        out = []
        for key in sorted(self.groups.keys()):
            counts, (first, last), uids, store = self.groups.peek(key)
            out.append(self._group_match(key, counts, first, last, uids, store.events(self.load)))
        return out

    def _group_match(self, key: tuple, counts: dict, first: float, last: float, uids: set,
                     evs: list[TypedEvent]) -> Match:
        names = {"process_exec": "exec", "net_socket": "socket call", "file_change": "file-change call"}
        host, exe = key
        cls, meaning = unbacked_executable(exe)
        evs = sorted(evs, key=lambda x: (x.ts, x.id))
        total = sum(counts.values())
        when = (f"at {evs[0].ts.isoformat()}" if first == last else
                f"from {datetime.fromtimestamp(first, UTC).isoformat()} to "
                f"{datetime.fromtimestamp(last, UTC).isoformat()}")
        kinds = ", ".join(f"{counts[f]} {names[f]} record(s)" for f in self.families if counts.get(f))
        uids = sorted(uids)
        claim = (f"On {host}, {total} audit record(s) {when} carry the kernel-recorded executable '{exe}' "
                 f"({kinds}; process uid(s) {', '.join(uids) or 'not recorded'}): {meaning}.")
        if total > len(evs):
            claim += f" {len(evs)} of these records are cited."
        m = Match(self.id, claim, self.claim_type, evs, [pf(e, "process.executable") for e in evs], evs[0].ts,
                  self.severity, self.lane, "high", _exec_entities(evs[0]), group_key=f"{host}|{exe}")
        m.notes = [f"executable class: {cls}"]
        return m


# ------------------------------------------------------------------------------------------------
# Process ancestry from exec records (shared by rules that weigh who started a command).
# ------------------------------------------------------------------------------------------------

PACKAGE_TOOLS = {"dpkg", "apt", "apt-get", "aptitude", "unattended-upgrade", "unattended-upgrades", "rpm", "yum",
                 "dnf", "microdnf", "zypper", "apk", "pacman", "packagekitd", "snapd"}
CLOUD_INIT_TOOLS = {"cloud-init"}
LOG_ROTATORS = {"logrotate"}
SYSTEM_BIN_DIRS = ("/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/usr/lib/", "/usr/libexec/")
# Package maintainer scripts: Debian's /var/lib/dpkg/info/<package>.<phase> and the scriptlets rpm writes to
# /var/tmp/rpm-tmp.XXXXXX.
_MAINTAINER_SCRIPT = re.compile(r"^/var/lib/dpkg/info/[^/]+\.(?:preinst|postinst|prerm|postrm|config)$"
                                r"|^/var/tmp/rpm-tmp\.\w+$")


def boot_of(e: TypedEvent) -> str | None:
    """The boot id a record carries (`host.boot.id`), or None when the source did not record it."""
    value = e.get("host.boot.id")
    return None if value in (None, "") else str(value)


def boots_conflict(a: str | None, b: str | None) -> bool:
    """Whether two records are known to come from different boots of a host. Process ids and audit session ids
    restart at every boot, so a pid or session join across a boot boundary is false. Only two recorded boot ids that
    differ prove a boundary: an unrecorded boot id (None) is compatible with any boot, so such a record keeps the
    boot-blind join it had before boot identity was recorded (and a pid or session id reused after a reboot can
    still join it)."""
    return a is not None and b is not None and a != b


class Ancestor(NamedTuple):
    ts: float
    ppid: int | None
    name: str              # program name; for an interpreter, the script it was given
    user: str | None
    marker: str            # "package" | "cloud-init" | "logrotate" | ""
    event_id: str
    boot: str | None = None
    serial: int | None = None   # the exec's audit serial (orders execs of one instant)


class Lineage(NamedTuple):
    kind: str              # "web" | "package" | "cloud-init" | "logrotate" | ""
    ancestor: Ancestor | None
    depth: int             # 0: the record itself; 1: its parent; ...


class ExecRecord(NamedTuple):
    """One process_exec record as every lineage view needs it, held once per exec. `name` and `marker` are what
    `ProcessLineage.entry` derives; `flags` carries the derived facts a view filters on (DAEMON)."""
    ts: float
    event_id: str
    ppid: int | None
    exe: str                # the kernel-recorded executable ("" when not recorded)
    name: str
    user: str | None
    marker: str
    raw_id: str             # the first raw record's native id
    boot: str | None
    flags: int
    serial: int | None = None   # the audit serial: orders execs of one pid at one instant (a #! chain)


# A real-uid-0 exec outside any login session (no audit login uid), with its executable and argv recorded and a
# program identity: the records the root-job rule's service-lineage walk may step through.
DAEMON = 1


def _record_order(record: ExecRecord) -> tuple:
    return record.ts, record.serial is None, record.serial or 0, record.event_id


def _latest_image(tied: list[ExecRecord]) -> ExecRecord | None:
    """One instant's execs of one pid: the latest by audit serial, or None when they cannot be ordered (a serial
    missing or repeated) and their executables differ, as the baseline carry decides it (`place_child`)."""
    serials = [record.serial for record in tied]
    if None not in serials and len(set(serials)) == len(serials):
        return max(tied, key=lambda record: record.serial)
    return tied[-1] if len({record.exe for record in tied}) == 1 else None


def _audit_serial(event: TypedEvent) -> int | None:
    serial = event.get("audit.serial")
    return serial if isinstance(serial, int) and not isinstance(serial, bool) else None


def _record_ts(record: ExecRecord) -> float:
    return record.ts


def _daemon(event: TypedEvent) -> bool:
    argv = event.get("process.argv")
    if not event.get("process.executable") or not isinstance(argv, list) or not argv:
        return False
    uid = event.get("process.uid")
    if uid is not None:
        root = str(uid) == "0"
    else:
        user = event.get("process.user")
        root = bool(user) and user == "root"
    return root and event.get("process.auid") is None and program(event) is not None


class ExecLineage:
    """Every process_exec record with a pid, held once for every rule that needs process ancestry, per (host, pid)
    in time order (pids are reused; a pid's history is unbounded and waits on disk when cold, so a lookup is exact
    however old the process). The key keeps the host as recorded, and each record keeps its boot id instead of
    the boot being part of the key: a record without a recorded boot id stays joinable from either side
    (`boots_conflict`), which a (host, boot, pid) key could not express.

    In a sweep one ExecLineage is shared by every rule that needs ancestry (`share_lineage`): its rows live on the
    first such rule's spill, each record is observed once (the first rule to read a batch observes it, the others
    find it observed), and a disk refusal is noted on every rule that shares it. A rule constructed alone (tests,
    expansion and baseline callers of PidTable) keeps its own. Each rule reads its own view of the records."""

    def __init__(self, owner=None, capacity: int = HOT_COUNT, members: list | None = None):
        self.store = KeyedStore(owner, "exec_lineage", capacity)
        self.members = members if members is not None else [owner] if owner is not None else []
        # The one store every ancestry rule reads, and most of a host hunt's state (one record per exec): it holds a
        # floor of the hunt's disk budget for each rule it serves, as their own stores would have had.
        self.store.weight = max(1, len(self.members))
        self._observed = RecentIds()            # exec records already observed (by any rule sharing this store)
        # processes whose exec record the state budget refused to hold (recent ones): a rule may still judge a join
        # whose other side it holds, saying the lineage was not recorded
        self.refused = RecentIds()
        self.incomplete = False                 # any process refused so far in the hunt: lineage may have gaps

    @property
    def records(self) -> KeyedStore:
        return self.store

    def __len__(self) -> int:
        return len(self.store)

    @property
    def evicted(self) -> int:
        """Processes whose records are on disk now (read back when needed; never forgotten)."""
        return self.store.on_disk

    def trim(self) -> None:
        self.store.trim()

    def clear(self) -> None:
        self.store.clear()

    @staticmethod
    def record(event: TypedEvent) -> ExecRecord:
        ancestor = ProcessLineage.entry(event)
        exe = event.get("process.executable")
        return ExecRecord(ancestor.ts, event.id, ancestor.ppid, str(exe) if exe else "", ancestor.name,
                          ancestor.user, ancestor.marker, event.raw[0].native_id if event.raw else "",
                          ancestor.boot, DAEMON if _daemon(event) else 0, ancestor.serial)

    def observe(self, event: TypedEvent) -> None:
        """Hold an exec record (once, however many rules hand it over)."""
        pid = event.get("process.pid")
        seen = (event.id, event.ts)             # a record handed over again (by another rule or a re-read batch)
        if not isinstance(pid, int) or seen in self._observed:
            return
        self._observed.add(seen)
        key = (event.host, pid)
        entries = self.store.get(key)
        if entries is None:
            if not self.store.put(key, [self.record(event)]):
                self.refused.add(key)
                self.incomplete = True
                for member in self.members:
                    member.note_limit("lineage", "the exec store took no new process (its share of the state budget "
                                                 "is spent); a later process's lineage is not recorded")
            return
        insort(entries, self.record(event), key=_record_order)       # in place: the store holds this list

    def entries(self, host: str | None, pid: int) -> list[ExecRecord]:
        """The process's records in time order; read in place when the store does not bring a process back to
        memory (below the stage volume's reserve)."""
        found = self.store.get((host, pid))
        return found if found is not None else self.store.peek((host, pid), None) or []

    def latest(self, host: str | None, pid: int, ts: float, *, strict: bool = False, where=None,
               serial: int | None = None, exclude: str | None = None) -> ExecRecord | None:
        """The record of `pid` that was its image when something happened at (`ts`, audit `serial`): its latest exec
        before that, among the records `where` accepts, or None when there is none or it is ambiguous.

        Execs are ordered by (time, audit serial), as the baseline carry orders them (`place_child`). An exec at the
        same instant precedes only when both serials are known and its serial is lower; without them its order is
        unknown, so the answer is None when execs of that instant name different executables (a `#!/usr/bin/env`
        chain execs twice in one pid at one instant: without serials the image at that instant is unknown, never an
        arbitrary pick). When they all name one executable the answer is that instant's latest record, as it is for
        a process asked about at its own exec instant; the carry instead also waits on a lone exec at the child's
        instant, since it can take a later answer and a lineage step has none. `exclude` is the asking record's own event id; `strict` (the image
        a pid held before its own record) needs it, or it ignores every exec at that instant."""
        if not isinstance(serial, int) or isinstance(serial, bool):
            serial = None                       # only a recorded integer serial orders execs
        entries = self.entries(host, pid)
        index = bisect_right(entries, ts, key=_record_ts)
        at_instant, unsure, before, before_ts = [], [], [], None
        for position in range(index - 1, -1, -1):
            record = entries[position]
            if where is not None and not where(record):
                continue
            if record.ts == ts:
                if record.event_id == exclude or (strict and exclude is None):
                    continue
                if serial is not None and record.serial is not None:
                    if record.serial < serial:
                        at_instant.append(record)       # precedes the asking record at this instant
                else:
                    unsure.append(record)               # one serial missing: its order is unknown
                continue
            if before_ts is None:
                before_ts = record.ts
            elif record.ts != before_ts:
                break
            before.append(record)
        group = at_instant or before
        answer = _latest_image(sorted(group, key=_record_order)) if group else None
        if group and answer is None:
            return None
        if unsure:
            if len({record.exe for record in unsure} | ({answer.exe} if at_instant else set())) > 1:
                return None                     # differing images at one instant without serials: ambiguous
            if not at_instant:                  # one image at that instant: its latest record
                answer = max(unsure, key=_record_order)
        return answer


class ProcessLineage:
    """Exec-record ancestry on each host: a record's parent is the latest exec of its parent pid that began no
    later than it did. The records are an ExecLineage (every exec held once, its history unbounded per pid, cold
    processes on disk and read back when a walk reaches them, so nothing is forgotten). The walk is only as
    complete as the retrieved exec records: a parent that did not exec inside the window (a daemon started
    earlier) ends the chain. Lineage can therefore raise or explain a lane, but its absence proves nothing.

    In a sweep one ProcessLineage is shared by every rule that keeps one, over the hunt's one ExecLineage
    (`share_lineage`)."""
    DEPTH = 16
    CAPACITY = HOT_COUNT  # a count cap only: the hunt's memory budget sizes it in bytes

    def __init__(self, owner=None, members: list | None = None):
        self.execs = ExecLineage(owner, self.CAPACITY)
        self.members = members if members is not None else [owner] if owner is not None else []

    @property
    def records(self) -> KeyedStore:
        return self.execs.store

    def trim(self) -> None:
        """Move the least recently used processes to disk (when a batch ends)."""
        self.execs.trim()

    @staticmethod
    def entry(event: TypedEvent) -> Ancestor:
        argv = event.get("process.argv") or []
        executable = event.get("process.executable")
        name = canonical(basename(str(executable))) if executable else canonical(basename(str(argv[0]))) if argv else ""
        # Only a program installed where the package manager puts it can mark a lineage: a copy named dpkg in
        # /tmp is not package management. Without a recorded executable no marker is given.
        located = str(executable or "")
        script = next((str(a) for a in argv[1:] if not str(a).startswith("-")), "")
        if name in SHELLS | SCRIPT_FILE_INTERPRETERS and script:
            name, located = basename(script) or name, script
        system = located.startswith(SYSTEM_BIN_DIRS)
        marker = ("package" if (system and name in PACKAGE_TOOLS)
                  or any(_MAINTAINER_SCRIPT.match(str(a)) for a in argv[1:3])
                  else "cloud-init" if system and name in CLOUD_INIT_TOOLS
                  else "logrotate" if system and name in LOG_ROTATORS else "")
        ppid = event.get("process.ppid")
        return Ancestor(event.ts.timestamp(), ppid if isinstance(ppid, int) else None, name,
                        event.get("process.user"), marker, event.id, boot_of(event), _audit_serial(event))

    def observe(self, event: TypedEvent) -> None:
        if event.family == "process_exec":
            self.execs.observe(event)

    def parent(self, host: str | None, ppid: int | None, ts: float, boot: str | None = None,
               serial: int | None = None) -> Ancestor | None:
        """The exec of `ppid` that was its image at (`ts`, audit `serial`) (`ExecLineage.latest`: None when that is
        ambiguous), unless it was recorded in a boot other than `boot`: the pid restarted at the reboot, and every
        earlier exec of it is in that boot or an earlier one."""
        if ppid is None or ppid <= 1:
            return None
        found = self.execs.latest(host, ppid, ts, serial=serial)
        if found is None or boots_conflict(boot, found.boot):
            return None
        return Ancestor(found.ts, found.ppid, found.name, found.user, found.marker, found.event_id, found.boot,
                        found.serial)

    def classify(self, event: TypedEvent) -> Lineage:
        """The record's own account or nearest exec ancestor that is a web-service account (which wins at any
        depth), else the nearest package-manager, cloud-init or log-rotation ancestor."""
        return self._walk(event.host, self.entry(event))

    def classify_pid(self, host: str | None, pid: int | None, ts: float, boot: str | None = None,
                     serial: int | None = None) -> Lineage:
        """Lineage of the process with this pid at this time in `boot` (its exec record that was its image then),
        for records that name a process but are not exec records themselves."""
        start = self.parent(host, pid, ts, boot, serial) if isinstance(pid, int) else None
        return self._walk(host, start, boot) if start is not None else Lineage("", None, 0)

    def _walk(self, host: str | None, current: Ancestor, boot: str | None = None) -> Lineage:
        nearest: Lineage | None = None
        for depth in range(self.DEPTH + 1):
            if current.user in WEB_SERVICE_USERS:
                return Lineage("web", current, depth)
            if current.marker and nearest is None:
                nearest = Lineage(current.marker, current, depth)
            boot = boot if boot is not None else current.boot      # a parent is in its child's boot
            found = self.parent(host, current.ppid, current.ts, boot, current.serial)
            if found is None or found.event_id == current.event_id:
                break
            current = found
        return nearest or Lineage("", None, 0)


def share_lineage(pack: list) -> None:
    """Give every rule of a pack that reads process ancestry the hunt's one ExecLineage, so each exec record is
    observed and held once (its rows on the first such rule's spill; a disk refusal noted on every rule that
    shares it), and every rule that keeps a ProcessLineage the same one over it. A rule's ExecLineage is any
    attribute of the rule, or of its `lineage` or `pids` view, holding one."""
    holders = [pb for pb in pack if isinstance(getattr(pb, "lineage", None), ProcessLineage)]
    if len(holders) >= 2:
        shared_view = ProcessLineage(holders[0], holders)
        for pb in holders:
            pb.lineage = shared_view
    sites, members = [], []
    for pb in pack:
        for holder in (pb, getattr(pb, "lineage", None), getattr(pb, "pids", None)):
            for name, value in list(getattr(holder, "__dict__", {}).items()):
                if isinstance(value, ExecLineage):
                    sites.append((holder, name))
                    if pb not in members:
                        members.append(pb)
    if len(members) < 2:
        return
    shared = ExecLineage(members[0], HOT_COUNT, members)
    for holder, name in sites:
        setattr(holder, name, shared)


def lineage_phrase(lineage: Lineage) -> str:
    """Plain wording for a lineage, naming the record it rests on."""
    if not lineage.kind or lineage.ancestor is None:
        return ""
    who = "it" if lineage.depth == 0 else f"its exec ancestor {lineage.depth} level(s) up"
    if lineage.kind == "web":
        return f"{who} ran as web-service account '{lineage.ancestor.user}' ('{lineage.ancestor.name}')"
    what = {"package": "package management", "cloud-init": "cloud-init", "logrotate": "log rotation"}[lineage.kind]
    return f"{who} is '{lineage.ancestor.name}' ({what})"


HOST_PLAYBOOKS = [WebServiceSpawnsInterpreter, DownloadPipedToShell, DownloaderFeedsInterpreter, PtyUpgrade,
                  ExecFromTempDir, ScriptFromTempDir, FirewallRuleChange, CredentialStoreRead, AuthorizedKeysWrite,
                  SshLoginFromExternal, UnbackedExecutable]
