"""Host playbooks over typed process_exec / auth events (Linux, lab telemetry)."""
from __future__ import annotations

import ast
import ipaddress
import re
from collections import defaultdict

from romulus.detect.base import Match, Playbook, basename, outcome_phrase, pf
from romulus.evidence.shellparse import SHELLS, UnknownShellScript, parse_script, shell_script_of
from romulus.evidence.typed import Outcome, TypedEvent

WEB_SERVICE_USERS = {"www-data", "apache", "nginx", "httpd", "_www", "wwwrun"}
INTERPRETERS = SHELLS | {"python", "python2", "python3", "perl", "ruby", "php", "lua", "nc", "ncat", "netcat",
                         "socat", "awk", "gawk", "busybox"}
DOWNLOADERS = {"curl", "wget", "fetch", "tftp"}
TEMP_DIRS = ("/tmp/", "/var/tmp/", "/dev/shm/")
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


def _interpreter_indicators(argv: list[str]) -> tuple[list[str], bool]:
    """Return typed indicators and whether shell-script inspection was unevaluable."""
    out = []
    unevaluable = False
    name = basename(argv[0]) if argv else ""
    rest = argv[1:]
    if name in INTERPRETERS and (not rest or rest in (["-"], ["-i"], ["-p"])):
        out.append("interpreter reading commands from stdin (no script argument)")
    script = shell_script_of(argv)
    if isinstance(script, UnknownShellScript):
        unevaluable = True
    elif script:
        parsed = parse_script(script)
        if parsed.ok:
            cmds = parsed.commands()
            if len(cmds) > 1 and cmds[0].argv and cmds[0].argv[0].startswith("/") and \
                    cmds[0].name not in INTERPRETERS:
                out.append(f"additional commands chained after application helper '{cmds[0].name}'")
            for c in cmds:
                if c.name.startswith("python"):
                    for i, a in enumerate(c.argv[1:-1], start=1):
                        if a == "-c" and _python_exec_of_decoded(c.argv[i + 1]):
                            out.append("python code executes decoded data")
                if c.name == "echo" and any("b64decode" in a or "decompress" in a for a in c.argv[1:]):
                    out.append("encoded payload text piped/echoed into another command")
        else:
            unevaluable = True
    if name.startswith("python"):
        for i, a in enumerate(rest[:-1]):
            if a == "-c" and _python_exec_of_decoded(rest[i + 1]):
                out.append("python code executes decoded data")
    return sorted(set(out)), unevaluable


def interpreter_indicators(argv: list[str]) -> list[str]:
    """Typed-argv indicators that an interpreter run is attacker-shaped rather than routine."""
    return _interpreter_indicators(argv)[0]


class WebServiceSpawnsInterpreter(Playbook):
    """Stack-counted: routine shapes collapse into one context item; rare shapes become leads and
    are escalated only when typed argv indicators are present (rarity alone is not suspicion)."""
    id = "host.web_service_spawns_interpreter"
    version = "3"
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

    def __init__(self):
        super().__init__()
        self.shapes: dict[tuple, list[TypedEvent]] = defaultdict(list)
        self.counts: dict[tuple, int] = defaultdict(int)

    def consume(self, events):
        matches = []
        for e in self.applicable(events):
            user, argv = e.get("process.user"), e.get("process.argv")
            if user not in WEB_SERVICE_USERS or not argv or basename(argv[0]) not in INTERPRETERS:
                continue
            indicators, unevaluable = _interpreter_indicators(argv)
            if unevaluable:
                self.missing_required += 1
            if indicators:
                matches.append(self._event_match(e, user, argv, indicators))
                continue
            key = (e.host, user, command_shape(argv))
            self.counts[key] += 1
            if len(self.shapes[key]) < 20:
                self.shapes[key].append(e)
        return matches

    @property
    def groups(self):
        return self.shapes

    def _event_match(self, e, user, argv, indicators, count=None):
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
        return match

    def finalize(self):
        out = []
        for key, evs in self.shapes.items():
            host_, user, shape = key
            n = self.counts[key]
            if n > self.RARE_MAX:
                claim = (f"Routine pattern: account '{user}' on {host_} executed '{shape}' {n} times in the window "
                         f"(stack-counted; retained for context).")
                out.append(Match(self.id, claim, "aggregate_observation", evs[:5], [pf(evs[0], "process.argv")],
                                 evs[0].ts, "low", "context", "high", _exec_entities(evs[0]),
                                 group_key=f"routine|{host_}|{user}|{shape}"))
                continue
            for e in evs:
                argv = e.get("process.argv")
                out.append(self._event_match(e, user, argv, [], count=n))
        return out


class DownloaderFeedsInterpreter(Playbook):
    """Sequence: a downloader exec and a stdin-reading interpreter exec with the same parent on the
    same host within MAX_GAP seconds (the shape of `curl URL | sh` typed into a shell or a script)."""
    id = "host.downloader_feeds_interpreter"
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
            name = basename(argv[0])
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
                                  _exec_entities(d), group_key=f"{d.id}|{e.id}")
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
            gaps = [(b.ts - a.ts).total_seconds() for a, b in zip(ms, ms[1:])]
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
                if c.name in DOWNLOADERS and names[i + 1] in INTERPRETERS:
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
    title = "Program executed from a world-writable temporary directory"
    families = ("process_exec",)
    required_fields = ("process.argv",)
    severity, lane = "medium", "lead"
    attack = ("T1059", "T1036.005")
    benign = ("installers and build tools unpacking into /tmp", "package manager hooks")
    next_checks = ("file_activity for how the file arrived", "process_tree", "http_requests that delivered it")

    def match(self, e):
        argv = e.get("process.argv")
        exe = e.get("process.executable") or ""
        a0 = argv[0] if argv else ""
        cwd = e.get("process.cwd") or ""
        def resolve(p: str) -> str:
            if p.startswith("/"):
                return p
            if p.startswith("./") and cwd.startswith("/"):
                return cwd.rstrip("/") + "/" + p[2:]
            return ""

        path = exe if exe.startswith("/") else ""
        if not path.startswith(TEMP_DIRS):
            path = resolve(a0)
        via = ""
        if not path.startswith(TEMP_DIRS) and basename(a0) in INTERPRETERS and len(argv) > 1:
            # interpreter running a script file: first non-option argument is the program
            script = next((a for a in argv[1:] if not a.startswith("-")), "")
            layout = shell_script_of(argv)
            if isinstance(layout, UnknownShellScript):
                self.missing_required += 1      # cannot tell a script-file run from -c: unevaluable, not absent
                return []
            if script and layout is None:
                path, via = resolve(script), basename(a0)
        if not path.startswith(TEMP_DIRS):
            return []
        fields = [pf(e, "process.argv")] + ([pf(e, "process.executable")] if exe else []) + \
                 ([pf(e, "process.cwd")] if cwd else [])
        how = f" via interpreter '{via}'" if via else ""
        claim = (f"A process execution event on {e.host} records execution of '{path}'{how} from a temporary "
                 f"directory (argv: {_argv_summary(argv)}); {outcome_phrase(e)}.")
        return [Match(self.id, claim, self.claim_type, [e], fields, e.ts, self.severity, self.lane,
                      "high" if exe else "medium", _exec_entities(e))]


BUILTIN_CHAINS = {"INPUT", "OUTPUT", "FORWARD", "PREROUTING", "POSTROUTING"}
BLOCK_TARGETS = {"DROP", "REJECT"}


def _flag_value(args: list[str], *flags: str) -> str | None:
    for i, a in enumerate(args[:-1]):
        if a in flags:
            return args[i + 1]
    return None


class FirewallRuleChange(Playbook):
    """Direct finding for commands that block/unblock a specific address on a built-in chain;
    other rule-change commands are grouped per host as routine context."""
    id = "host.firewall_rule_change_command"
    version = "2"
    title = "Firewall command blocking or unblocking a specific address"
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
            if chain in BUILTIN_CHAINS and target in BLOCK_TARGETS and addr:
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
            claim = (f"Routine pattern: {self.routine_n[(host_, name)]} '{name}' rule-change command(s) on {host_} "
                     f"without a specific-address block on a built-in chain (e.g. {_argv_summary(evs[0].get('process.argv'), 100)}).")
            out.append(Match(self.id, claim, "aggregate_observation", evs[:5], [pf(evs[0], "process.argv")],
                             evs[0].ts, "low", "context", "high", _exec_entities(evs[0]),
                             group_key=f"routine|{host_}|{name}"))
        return out


class CredentialStoreRead(Playbook):
    id = "host.credential_store_read"
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
            evs.sort(key=lambda x: x.ts)
            claim = (f"{len(evs)} successful SSH authentication record(s) on {host} for account '{user}' from "
                     f"non-private address {ip} ({evs[0].ts.isoformat()} – {evs[-1].ts.isoformat()}).")
            m = Match(self.id, claim, self.claim_type, evs[:20], [pf(evs[0], "source.ip"), pf(evs[0], "user.name")],
                      evs[0].ts, self.severity, self.lane, "high", evs[0].entities(), group_key=f"{host}|{user}|{ip}")
            if len(evs) > 20:
                m.notes.append(f"{len(evs) - 20} further matching records retained by reference only")
            out.append(m)
        return out


HOST_PLAYBOOKS = [WebServiceSpawnsInterpreter, DownloadPipedToShell, DownloaderFeedsInterpreter, PtyUpgrade,
                  ExecFromTempDir, FirewallRuleChange, CredentialStoreRead, AuthorizedKeysWrite, SshLoginFromExternal]
