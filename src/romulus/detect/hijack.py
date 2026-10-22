"""A non-root account runs a write-capable command on a file that a root process executes.

The privilege-escalation shape this catches: a root scheduled job (cron, anacron, at, a systemd unit or timer) or
another root process runs a script or program that a lower-privileged account (most dangerously a web-service
account) can change. The attacker edits the file, appends to it or replaces it, and waits for root to run it.

What the evidence shows, and what it does not:
- The write side is an exec record of a write-capable program (an editor, `sed -i`, `tee`, `cp`/`mv`/`install`/
  `ln` onto the file, `chmod`/`chown`, `truncate`, `dd of=`, `perl -pi`, `curl -o`, `wget -O`, `scp`/`rsync` to a
  local destination) or a shell started with command text that redirects into the file. That proves the command
  was started on the file, not that the file changed. A kernel file-change record (family `file_change`, contract
  below) is what proves the change; when one is present for the same account and file, the claim says so.
- The execute side is a root (real uid 0) exec record whose kernel-recorded executable is the file, whose
  interpreter was given the file as its script operand, or whose shell command text runs it. The executor is
  classified from typed fields only: a session opened by a scheduler (audit USER_START from cron/anacron/atd,
  joined by audit session id or parent pid), a process started by the service manager (pid 1) outside any login
  session, a root process outside any login session whose launcher is not in the records, or a root process in
  another account's login session. A root process in the writer's own login session (the writer elevating their
  own file) is set apart: when it is the only root run, the finding is a lead that says so, because a sudo rule
  running a file its user can edit is the same shape.
- A non-root write-capable command on a root scheduling configuration path (system crontabs, cron directories,
  root's spool crontab, system unit directories) matches on its own: those files are what root's scheduler runs.

Findings are grouped per (host, writer account, file). The rule reads argv and command text, so it is
positive-only: it never claims a complete negative.

Kernel file-change contract (family `file_change`, from Linux audit SYSCALL+PATH records). On sources that lack it
the "changed" upgrade is not applicable and claims say the change is not established.
- `file.path`: absolute path of the changed file as the kernel recorded it (resolved against the record's CWD).
- `file.change`: what changed: `content` (opened for writing or truncated), `create`, `rename_target`
  (another file was renamed onto this path), `link` (a link was created at this path), `attributes` (mode, owner,
  extended attributes or times), `delete` or `rename_source` (the file left this path; not a write of it).
- `process.uid`, `process.user`, `process.auid`, `process.pid`, `process.executable`: the actor, as for exec.
- outcome: success when the system call succeeded.
A non-root account's kernel-recorded change of a file a root process runs is a write in its own right: it is
reported with the root runs even when no write-capable command was recorded (an interactive shell's redirect
starts no process).
"""
from __future__ import annotations

import bisect
import posixpath
from collections import OrderedDict, defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import ClassVar

from romulus.detect.base import Match, Playbook, argv_incomplete, pf
from romulus.detect.correlation import StageMissing
from romulus.detect.host import _FLAG_ONLY, SCRIPT_FILE_INTERPRETERS, WEB_SERVICE_USERS
from romulus.detect.linux_argv import canonical, is_under, normalize_path, program, write_targets
from romulus.evidence.shellparse import (
    SHELLS,
    UnknownShellScript,
    classify_redirect,
    parse_script,
    shell_dialect,
    shell_script_file_of,
    shell_script_of,
)
from romulus.evidence.typed import Outcome, TypedEvent

# PAM services (the audit record's exe name) that open a session for a scheduled job, and their technique.
SCHEDULER_SERVICES = {"cron": "T1053.003", "crond": "T1053.003", "anacron": "T1053.003", "fcron": "T1053.003",
                      "atd": "T1053.002"}
# Root scheduling configuration: what root's cron, anacron, at and systemd read and run.
ROOT_SCHEDULE_FILES = {
    "/etc/crontab": ("the system crontab", "T1053.003"),
    "/etc/anacrontab": ("the anacron table", "T1053.003"),
    "/var/spool/cron/crontabs/root": ("root's crontab", "T1053.003"),
    "/var/spool/cron/root": ("root's crontab", "T1053.003"),
    "/var/spool/cron/tabs/root": ("root's crontab", "T1053.003"),
}
ROOT_SCHEDULE_DIRS = (
    ("/etc/cron.d", "a system cron table directory", "T1053.003"),
    ("/etc/cron.hourly", "a root cron job directory", "T1053.003"),
    ("/etc/cron.daily", "a root cron job directory", "T1053.003"),
    ("/etc/cron.weekly", "a root cron job directory", "T1053.003"),
    ("/etc/cron.monthly", "a root cron job directory", "T1053.003"),
    ("/var/spool/cron/atjobs", "the at job spool", "T1053.002"),
    ("/etc/systemd/system", "a system unit directory (services and timers)", "T1053.006"),
    ("/run/systemd/system", "a system unit directory (services and timers)", "T1053.006"),
    ("/usr/local/lib/systemd/system", "a system unit directory (services and timers)", "T1053.006"),
    ("/usr/lib/systemd/system", "a system unit directory (services and timers)", "T1053.006"),
)
# Directories whose every entry is root scheduling configuration (or, for the spool, a per-account crontab named
# after the account). A file copied, linked or downloaded into one is a write to it, whatever the operand looked like.
SCHEDULE_DIRECTORIES = frozenset({prefix for prefix, _d, _t in ROOT_SCHEDULE_DIRS}
                                 | {"/var/spool/cron", "/var/spool/cron/crontabs", "/var/spool/cron/tabs"})
# Elevation helpers inside command text: what they run does not run as the shell's account.
_ELEVATION = {"sudo", "su", "doas", "pkexec", "run0"}
# Merged-/usr aliases, folded for joining only (claims show the recorded paths).
_USR_ALIASES = (("/bin/", "/usr/bin/"), ("/sbin/", "/usr/sbin/"), ("/lib/", "/usr/lib/"),
                ("/lib64/", "/usr/lib64/"), ("/lib32/", "/usr/lib32/"))
_PSEUDO_FS = ("/dev", "/proc", "/sys")
_FAMILY_ORDER = {"auth": 0, "file_change": 1, "process_exec": 2}
# What a kernel file-change record shows was done to the file, in claim wording.
CHANGE_WORDS = {"content": "opened it for writing", "create": "created it", "rename_target": "renamed a file onto it",
                "link": "created a link at its path", "attributes": "changed its mode, owner or attributes"}
WRITE_CITE = 10                 # writer records cited per (host, account, file); the claim gives exact totals
EXEC_FIRST = 2                  # earliest root runs cited per (host, file, executor)
AUTH_MEMORY = 1024              # scheduler session records kept per host for citation
LINEAGE_DEPTH = 16
_EXECUTOR_TECHNIQUE = {"service": "T1053.006", "daemon": "T1053", "login": "T1574"}


def path_key(path: str) -> str:
    """Join key for a normalized path: merged-/usr aliases folded together."""
    for alias, real in _USR_ALIASES:
        if path.startswith(alias):
            return real + path[len(alias):]
    return path


def schedule_config(path: str) -> tuple[str, str] | None:
    """(description, technique) when the path is root scheduling configuration."""
    if path in ROOT_SCHEDULE_FILES:
        return ROOT_SCHEDULE_FILES[path]
    for prefix, description, technique in ROOT_SCHEDULE_DIRS:
        if path != prefix and is_under(path, (prefix,)):
            return (f"a file in {description} ({prefix})", technique)
    return None


def _uid(event: TypedEvent) -> str | None:
    uid = event.get("process.uid")
    return None if uid is None else str(uid)


def _auid(event: TypedEvent) -> str | None:
    auid = event.get("process.auid")
    return None if auid is None else str(auid)


def _is_root(event: TypedEvent) -> bool | None:
    """Real uid 0; None when neither the uid nor the account name is recorded."""
    uid = _uid(event)
    if uid is not None:
        return uid == "0"
    user = event.get("process.user")
    return None if not user else user == "root"


def _account(event: TypedEvent) -> str:
    return str(event.get("process.user") or f"uid {_uid(event)}")


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, UTC).isoformat()


def _interpreter_script(name: str, args: list[str]) -> str | None:
    """The script operand of a script-file interpreter: `<interp> [flag-only options] <script>`."""
    flags = _FLAG_ONLY.get(name.rstrip("23"), set())
    index = 0
    while index < len(args) and args[index] in flags:
        index += 1
    if index >= len(args) or args[index].startswith(("-", "+")):
        return None
    return args[index]


def _text_commands(script: str, cwd: str | None, dialect: str = "bash"):
    """(command, working directory) for each parsed command of shell text, following `cd DIR`; and whether the
    text was only partly modelled. A `cd` the parser cannot place (`cd`, `cd -`, `cd ~`) leaves the directory
    unknown, so later relative operands are unresolved, never guessed."""
    parsed = parse_script(script, dialect)
    if not parsed.ok and not parsed.partial:
        return [], True
    out = []
    current = cwd
    for command in parsed.commands():
        out.append((command, current))
        if command.argv and command.argv[0] == "cd":
            target = command.argv[1] if len(command.argv) == 2 else ""
            current = (normalize_path(target, current) or None) if target and target[0] not in "-~" else None
    return out, not parsed.ok


@dataclass
class _Write:
    ts: float
    event_id: str
    path: str
    form: str
    account: str
    uid: str | None
    session: tuple | None   # (boot id, audit session id) of the writing process, when recorded
    web: bool
    assumed: bool           # the path was derived by reading a destination operand as a directory
    kernel: bool = False    # a kernel file-change record, not a write-capable command


@dataclass
class _Run:
    ts: float
    event_id: str
    path: str
    form: str
    auth_id: str | None


@dataclass
class _Series:
    """Root runs of one file by one executor class."""
    detail: str
    ok_ts: list[float] = field(default_factory=list)      # sorted; runs whose exec did not fail
    failed: int = 0
    first: list[_Run] = field(default_factory=list)
    after: dict[str, _Run] = field(default_factory=dict)  # writer record id -> first non-failed run after it


class NonRootWriteRootExecutedFile(Playbook):
    id = "host.nonroot_write_root_executed_file"
    version = "4"
    title = "Non-root write-capable command on a file a root process runs, or on root's schedule"
    anchor_class = "persistence"
    kind = "aggregate"
    staged = True
    claim_type = "correlated_observation"
    families = ("process_exec", "auth", "file_change")
    required_fields = ("process.executable", "process.argv", "process.uid")
    assures_negative = False
    positive_only_reason = (
        "the writing command, its target file and the root run are identified from argv and shell command text; "
        "a file can be changed or run in ways exec records do not show (shell built-in redirects in an "
        "interactive shell, interpreters writing files from their own code), so absence proves nothing")
    severity, lane = "high", "high"
    attack = ("T1053", "T1053.002", "T1053.003", "T1053.006", "T1543.002", "T1574")
    benign = (("a deployment or service account that owns a script a root job runs (still a privilege "
               "boundary weakness worth review)"),
              "an administrator editing a job script as one account and running it as root from another login",
              "a non-root user opening root's schedule in an editor without saving")
    next_checks = ("the file's current content, owner and mode, and its package ownership",
                   "every root run of the file after the write, and what those runs started or connected to",
                   "how the writing account got a shell (web requests or a login just before the write)")
    card: ClassVar[dict] = {
        "behavior": "a non-root account starts a write-capable command on a file that a root process (scheduled "
                    "job, systemd unit, daemon or another account's login) executes, or on root's scheduling "
                    "configuration",
        "telemetry": "Linux auditd EXECVE+SYSCALL+CWD as process_exec (process.executable, process.argv, "
                     "process.uid, process.euid, process.auid, process.session_id, process.pid, process.ppid, "
                     "process.cwd, process.user) and audit USER_START as auth (auth.service, auth.phase, "
                     "process.session_id, process.pid): present in the lab profile. file_change (audit SYSCALL+PATH "
                     "records: file.path, file.change, process.uid) proves a change where the audit rules watch the "
                     "file; the lab watches only some directories, so the 'changed' upgrade applies there only",
        "fidelity": "direct action for 'a write-capable command was started on the file' and 'root ran the file'; "
                    "the file's change is established only by a file_change record; exec outcomes are stated",
        "benign_and_cost": "deployment accounts owning root-run scripts; admins opening root's crontab without "
                           "sudo. One grouped finding per (host, account, file)",
        "query_cost": "none beyond the sweep: it reads the host partitions every host rule reads",
        "next_pivot": "the file's content now, and the first root run after the write (its children and sockets)",
        "adds": "no other rule joins a lower-privileged write with a root execution of the same file",
        "research_basis": "ATT&CK Enterprise 20.0 T1053.003 and T1053.006 (modifying scripts that privileged "
                          "scheduled jobs run); GTFOBins file-write entries for the write-capable program list",
        "retrieval": "the sweep retrieves every record of the host datasets in each partition (dataset filter "
                     "only), a superset of what this evaluator reads",
    }

    def __init__(self):
        super().__init__()
        self._seen: set[str] = set()
        self._staged: set[str] = set()
        self._pending: list[TypedEvent] = []
        self.load = lambda ids: []
        self.writes: dict[tuple[str, str], list[_Write]] = defaultdict(list)
        self.write_counts: dict[tuple[str, str, str], int] = defaultdict(int)
        self.write_ok: dict[tuple[str, str, str], int] = defaultdict(int)     # writer execs that did not fail
        self.runs: dict[tuple[str, str], dict[tuple, _Series]] = defaultdict(dict)
        self.sessions: dict[tuple, list[tuple[float, str, str]]] = defaultdict(list)
        self.session_pids: dict[tuple, list[tuple[float, str, str]]] = defaultdict(list)
        self.recent_auth: dict[str, OrderedDict[str, TypedEvent]] = defaultdict(OrderedDict)
        self.daemons: dict[tuple, list[tuple[float, int | None]]] = defaultdict(list)
        self.changes: dict[tuple[str, str], list[tuple[float, str, str, str]]] = defaultdict(list)
        self.kernel_writes: dict[tuple[str, str], list[_Write]] = defaultdict(list)
        self.file_change_records = 0

    # ---------------------------------------------------------------- staging
    def drain_staged(self) -> list[TypedEvent]:
        out, self._pending = self._pending, []
        return out

    def retained_events(self) -> list[TypedEvent]:
        return []                                   # staged on disk instead

    def _stage(self, event: TypedEvent) -> None:
        if event.id not in self._staged:
            self._staged.add(event.id)
            self._pending.append(event)

    # ---------------------------------------------------------------- consume
    def consume(self, events):
        fresh = [e for e in events if e.family in _FAMILY_ORDER and e.id not in self._seen]
        for event in sorted(fresh, key=lambda e: (e.ts, _FAMILY_ORDER[e.family], e.id)):
            self._seen.add(event.id)            # re-reading a partition must not count a record twice
            if event.family == "auth":
                self._auth(event)
            elif event.family == "file_change":
                self._file_change(event)
            else:
                self._exec(event)
        return []

    def _auth(self, event: TypedEvent) -> None:
        service = event.get("auth.service")
        if not service:
            self.missing_required += 1
            return
        self.evaluated += 1
        if service not in SCHEDULER_SERVICES or event.get("auth.phase") not in ("session_open", "login"):
            return
        if event.outcome == Outcome.failure:
            return
        entry = (event.ts.timestamp(), str(service), event.id)
        session, pid = event.get("process.session_id"), event.get("process.pid")
        if session is not None:
            self.sessions[(event.host, event.get("host.boot.id"), session)].append(entry)
        if isinstance(pid, int):
            self.session_pids[(event.host, pid)].append(entry)
        recent = self.recent_auth[event.host or ""]
        recent[event.id] = event
        while len(recent) > AUTH_MEMORY:
            recent.popitem(last=False)

    def _file_change(self, event: TypedEvent) -> None:
        path = event.get("file.path")
        root = _is_root(event)
        change = event.get("file.change")
        if change in ("delete", "rename_source"):
            self.evaluated += 1                 # the file left this path: not a write of it, whatever the path
            self.file_change_records += 1
            return
        if not path or not str(path).startswith("/") or root is None or not change:
            self.missing_required += 1
            return
        self.evaluated += 1
        self.file_change_records += 1
        # root, a setuid-root writer (it writes as root) and a failed call change nothing a non-root account
        # controls
        if root or event.outcome == Outcome.failure or str(event.get("process.euid", "")) == "0":
            return
        key = (event.host or "", path_key(normalize_path(str(path))))
        account = _account(event)
        entries = self.changes[key]
        if sum(1 for item in entries if item[2] == account) >= WRITE_CITE:
            return
        self._stage(event)
        entries.append((event.ts.timestamp(), event.id, account, str(change)))
        session = event.get("process.session_id")
        self.kernel_writes[key].append(_Write(
            event.ts.timestamp(), event.id, normalize_path(str(path)), f"a kernel file-change record ({change})",
            account, _uid(event), (event.get("host.boot.id"), session) if session is not None else None,
            event.get("process.user") in WEB_SERVICE_USERS, False, kernel=True))

    def _exec(self, event: TypedEvent) -> None:
        argv = event.get("process.argv")
        if not event.get("process.executable") or not isinstance(argv, list) or not argv:
            self.missing_required += 1
            return
        root = _is_root(event)
        prog = program(event)
        if root is None or prog is None:
            self.missing_required += 1          # neither a writer nor a root executor can be decided
            return
        self.evaluated += 1
        incomplete = argv_incomplete(event)
        if incomplete:
            self.missing_required += 1          # some arguments were lost: never a clean evaluation
        if root:
            if _auid(event) is None and isinstance(event.get("process.pid"), int):
                self.daemons[(event.host, event.get("process.pid"))].append(
                    (event.ts.timestamp(), event.get("process.ppid")))
            self._root_run(event, prog)
        elif str(event.get("process.euid", "")) != "0" and not incomplete:
            # a setuid-root program writes as root; a write target is often the last operand, which an incomplete
            # argv cannot show
            self._writer(event, prog, argv)

    # ---------------------------------------------------------------- writer side
    def _writer(self, event: TypedEvent, prog, argv: list[str]) -> None:
        cwd = event.get("process.cwd")
        targets, incomplete = write_targets(prog.name, prog.args, cwd, argv0=str(argv[0]))
        found = [(target.path, target.form, target.assumed) for target in targets]
        if prog.name in SHELLS:
            script = shell_script_of([prog.name, *prog.args])
            if isinstance(script, UnknownShellScript):
                incomplete = True
            elif script:
                text_found, text_incomplete = self._text_writes(
                    script, cwd, shell_dialect(event.get("process.executable"), argv))
                found += text_found
                incomplete = incomplete or text_incomplete
        if incomplete:
            self.missing_required += 1          # a write target could not be placed: never a clean no-match
        by_key: dict[str, list[tuple[str, str, bool]]] = {}
        for path, form, assumed in found:
            by_key.setdefault(path_key(path), []).append((path, form, assumed))
        account = _account(event)
        session = event.get("process.session_id")
        own_session = (event.get("host.boot.id"), session) if session is not None else None
        for pkey, items in by_key.items():
            key = (event.host or "", pkey)
            count_key = (key[0], pkey, account)
            self.write_counts[count_key] += 1
            if event.outcome != Outcome.failure:
                self.write_ok[count_key] += 1
            if self.write_counts[count_key] > WRITE_CITE:
                continue
            self._stage(event)
            forms = list(dict.fromkeys(form for _path, form, _assumed in items))
            # A leaf derived inside a known schedule directory is certain: the command writes into that directory.
            assumed = all(flag and posixpath.dirname(path) not in SCHEDULE_DIRECTORIES for path, _f, flag in items)
            self.writes[key].append(_Write(event.ts.timestamp(), event.id, items[0][0], " and ".join(forms),
                                           account, _uid(event), own_session,
                                           event.get("process.user") in WEB_SERVICE_USERS, assumed))

    @staticmethod
    def _text_writes(script: str, cwd: str | None,
                     dialect: str = "bash") -> tuple[list[tuple[str, str, bool]], bool]:
        commands, incomplete = _text_commands(script, cwd, dialect)
        found: list[tuple[str, str, bool]] = []
        for command, current in commands:
            for op, target in command.redirects:
                written = classify_redirect(op, target).writes_file
                if written is None:                 # a read, duplication or close writes no file
                    continue
                path = normalize_path(written, current)
                if not path:
                    incomplete = True
                elif not is_under(path, _PSEUDO_FS):
                    found.append((path, f"shell command text redirects output into it ('{op}')", False))
            if not command.argv or command.name in _ELEVATION:
                continue
            targets, unresolved = write_targets(canonical(command.name), command.argv[1:], current,
                                                argv0=command.argv[0])
            incomplete = incomplete or unresolved
            found += [(target.path, f"shell command text in which {target.form}", target.assumed)
                      for target in targets]
        return found, incomplete

    # ---------------------------------------------------------------- root side
    def _root_run(self, event: TypedEvent, prog) -> None:
        cwd = event.get("process.cwd")
        runs: list[tuple[str, str]] = [(normalize_path(str(event.get("process.executable"))),
                                        "as the kernel-recorded executable")]
        incomplete = False
        name = prog.name
        if name in SHELLS:
            script_file = shell_script_file_of([name, *prog.args], shell_name=name)
            if isinstance(script_file, UnknownShellScript):
                incomplete = True
            elif script_file:
                path = normalize_path(script_file, cwd)
                if path:
                    runs.append((path, f"as the script operand of '{name}'"))
                else:
                    incomplete = True
            script = shell_script_of([name, *prog.args])
            if isinstance(script, UnknownShellScript):
                incomplete = True
            elif script:
                text_runs, text_incomplete = self._text_runs(
                    script, cwd, shell_dialect(event.get("process.executable")))
                runs += text_runs
                incomplete = incomplete or text_incomplete
        elif name in SCRIPT_FILE_INTERPRETERS:
            script_file = _interpreter_script(name, prog.args)
            if script_file:
                path = normalize_path(script_file, cwd)
                if path:
                    runs.append((path, f"as the script operand of '{name}'"))
                else:
                    incomplete = True
        if incomplete:
            self.missing_required += 1
        executor, detail, auth = self._executor(event)
        by_key: dict[str, list[tuple[str, str]]] = {}
        for path, form in runs:
            if path:
                by_key.setdefault(path_key(path), []).append((path, form))
        for pkey, items in by_key.items():
            key = (event.host or "", pkey)
            series = self.runs[key].setdefault(executor, _Series(detail=detail))
            forms = list(dict.fromkeys(form for _path, form in items))
            run = _Run(event.ts.timestamp(), event.id, items[0][0], " and ".join(forms), auth.id if auth else None)
            cite = False
            if event.outcome == Outcome.failure:
                series.failed += 1
            else:
                bisect.insort(series.ok_ts, run.ts)
                for write in (*self.writes.get(key, ()), *self.kernel_writes.get(key, ())):
                    if write.ts < run.ts and write.event_id not in series.after:
                        series.after[write.event_id] = run
                        cite = True
            if len(series.first) < EXEC_FIRST:
                series.first.append(run)
                cite = True
            if cite:
                self._stage(event)
                if auth is not None:
                    self._stage(auth)

    @staticmethod
    def _text_runs(script: str, cwd: str | None, dialect: str = "bash") -> tuple[list[tuple[str, str]], bool]:
        commands, incomplete = _text_commands(script, cwd, dialect)
        runs: list[tuple[str, str]] = []
        for command, current in commands:
            if not command.argv or command.name in _ELEVATION:
                continue
            first = command.argv[0]
            name = canonical(command.name)
            operand, form = None, ""
            if "/" in first:
                operand, form = first, "named as a command in a root shell's command text"
            elif name in {".", "source"} and len(command.argv) > 1:
                operand, form = command.argv[1], "sourced in a root shell's command text"
            elif name in SHELLS:
                found = shell_script_file_of(command.argv, shell_name=name)
                if isinstance(found, UnknownShellScript):
                    incomplete = True
                elif found:
                    operand, form = found, f"as the script operand of '{name}' in a root shell's command text"
            elif name in SCRIPT_FILE_INTERPRETERS:
                found = _interpreter_script(name, command.argv[1:])
                if found:
                    operand, form = found, f"as the script operand of '{name}' in a root shell's command text"
            if operand is None:
                continue
            path = normalize_path(operand, current)
            if path:
                runs.append((path, form))
            else:
                incomplete = True
        return runs, incomplete

    def _executor(self, event: TypedEvent) -> tuple[tuple, str, TypedEvent | None]:
        """(executor key, description, scheduler session record) for a root exec record."""
        ts = event.ts.timestamp()
        auid = _auid(event)
        session = event.get("process.session_id")
        found = None
        if session is not None:
            found = self._latest(self.sessions.get((event.host, event.get("host.boot.id"), session), ()), ts)
        if found is None and isinstance(event.get("process.ppid"), int):
            found = self._latest(self.session_pids.get((event.host, event.get("process.ppid")), ()), ts)
        if found is not None:
            _when, service, auth_id = found
            return (("scheduler", service, auid),
                    f"in sessions the scheduler '{service}' opened, joined by audit session id or parent pid",
                    self.recent_auth[event.host or ""].get(auth_id))
        if auid is None:
            if self._service_lineage(event):
                return (("service", None, None),
                        ("started by the service manager (pid 1) outside any login session, as a systemd unit's "
                         "process is; a timer-triggered unit cannot be told apart from other units in exec records"),
                        None)
            return (("daemon", None, None),
                    ("outside any login session (no audit login uid), launched by a process whose exec is not in "
                     "the retrieved records, such as a scheduler or daemon"), None)
        tag = (event.get("host.boot.id"), session) if session is not None else None
        where = f" (audit session {session})" if session is not None else ""
        return (("login", tag, auid), f"in a login session{where} of audit login uid {auid}", None)

    @staticmethod
    def _latest(entries, ts: float):
        best = None
        for entry in entries:
            if entry[0] <= ts and (best is None or entry[0] >= best[0]):
                best = entry
        return best

    def _service_lineage(self, event: TypedEvent) -> bool:
        """True when the ppid chain, through root exec records outside any login session, reaches pid 1."""
        ppid, ts = event.get("process.ppid"), event.ts.timestamp()
        for _ in range(LINEAGE_DEPTH):
            if ppid == 1:
                return True
            if not isinstance(ppid, int) or ppid <= 1:
                return False
            parent = self._latest(self.daemons.get((event.host, ppid), ()), ts)
            if parent is None:
                return False
            ts, ppid = parent
        return False

    # ---------------------------------------------------------------- finalize
    def _events(self, ids: list[str]) -> dict[str, TypedEvent]:
        unique = sorted(set(ids))
        loaded = self.load(unique)
        if len(loaded) != len(unique):
            raise StageMissing(f"{self.id}: {len(unique) - len(loaded)} cited event(s) absent from the stage")
        return {event.id: event for event in loaded}

    def finalize(self):
        out = []
        for key in sorted(set(self.writes) | set(self.kernel_writes)):
            by_account: dict[str, list[_Write]] = defaultdict(list)
            for write in (*self.writes.get(key, ()), *self.kernel_writes.get(key, ())):
                by_account[write.account].append(write)
            for account in sorted(by_account):
                actors = sorted(by_account[account], key=lambda w: (w.ts, w.event_id))
                match = self._finding(key[0], key[1], account, [w for w in actors if not w.kernel],
                                      [w for w in actors if w.kernel])
                if match is not None:
                    out.append(match)
        return out

    def _finding(self, host: str, pkey: str, account: str, writes: list[_Write],
                 kernel: list[_Write] = ()) -> Match | None:
        """`writes` are write-capable commands; `kernel` are kernel file-change records by the same account. With
        no command, the kernel records are the writes, and a finding needs a root run of the file."""
        every = sorted(self.runs.get((host, pkey), {}).items(), key=lambda item: str(item[0]))
        series = [(executor, s) for executor, s in every if not _own_elevation(executor, [*writes, *kernel])]
        # A path derived by assuming a destination is a directory can join a root run, but on its own it is not
        # evidence of a write to root's schedule.
        config = schedule_config(pkey) if any(not w.assumed for w in writes) else None
        own_only = False
        if not series and config is None:
            # Only the writer's own elevation ran the file. That is never dropped: a sudo rule that runs a file its
            # user can edit is the same shape (T1548.003). It is reported as a lead.
            series = [(executor, s) for executor, s in every if _own_elevation(executor, [*writes, *kernel])]
            if not series:
                return None
            own_only = True
        actors = writes or list(kernel)
        first, web = actors[0], any(w.web for w in (*writes, *kernel))
        since = "the first write-capable command" if writes else "the first kernel file-change record"
        changes = sorted(c for c in self.changes.get((host, pkey), ()) if c[2] == account)
        content_changes = [c for c in changes if c[3] != "attributes"]
        total_writes = self.write_counts[(host, pkey, account)]

        cited_ids = [w.event_id for w in writes] + [c[1] for c in changes]
        techniques: set[str] = {config[1]} if config else set()
        runs_after, run_after_change = 0, False
        exec_lines = []
        for (kind, service, _auid_value), s in series:
            techniques.add(SCHEDULER_SERVICES.get(service or "", "T1053") if kind == "scheduler"
                           else _EXECUTOR_TECHNIQUE[kind])
            if kind == "service":
                techniques.add("T1543.002")
            n_after = len(s.ok_ts) - bisect.bisect_right(s.ok_ts, first.ts)
            runs_after += n_after
            if content_changes and s.ok_ts and s.ok_ts[-1] > content_changes[0][0]:
                run_after_change = True
            after = s.after.get(first.event_id)
            cited_runs = list(s.first) + ([after] if after is not None else [])
            for run in cited_runs:
                cited_ids.append(run.event_id)
                if run.auth_id:
                    cited_ids.append(run.auth_id)
            forms = sorted({run.form for run in cited_runs})
            line = (f"{len(s.ok_ts) + s.failed} root exec record(s) in the window execute {s.first[0].path} or name "
                    f"it as a command in a root shell's command text ({s.detail}; cited forms: {'; '.join(forms)})")
            if n_after:
                line += (f"; {n_after} of them began after {since}, the first at "
                         f"{_iso(after.ts)}" if after is not None else
                         f"; {n_after} of them began after {since} (the record of the "
                         f"first of them is not among the citations)")
            else:
                line += (f"; none whose exec did not fail began after {since} (they are "
                         "earlier, or at the same recorded time)")
            if s.failed:
                line += f"; {s.failed} of them recorded a failed exec"
            exec_lines.append(line)

        events = self._events(cited_ids)
        cited = sorted(events.values(), key=lambda e: (e.ts, e.id))
        writer_events = [events[w.event_id] for w in actors]
        uids = sorted({w.uid for w in actors if w.uid})
        who = f"account '{account}'" + (f" (uid {', '.join(uids)})" if uids and not account.startswith("uid ")
                                         else "")
        if web:
            who += ", a web-service account,"
        count = "a write-capable command" if total_writes == 1 else f"{total_writes} write-capable commands"
        when = (f"at {_iso(first.ts)}" if actors[-1].ts == first.ts
                else f"from {_iso(first.ts)} to {_iso(actors[-1].ts)}")
        if writes:
            claim = (f"On {host}, {who} ran {count} on {first.path} {when}: "
                     f"{_listed(sorted({w.form for w in writes}))}; {_tally(writer_events)}.")
        else:
            claim = (f"On {host}, kernel file-change records show {who} acting on {first.path} {when}: "
                     f"{_listed(sorted({CHANGE_WORDS.get(c[3], c[3]) for c in changes}))}; no write-capable command "
                     f"on the file was recorded (an interactive shell's redirect or a program's own file writes start "
                     f"no process).")
        if writes and total_writes > len(writes):
            claim += f" The earliest {len(writes)} of these records are cited."
        claim += "".join(f" {line[0].upper()}{line[1:]}." for line in exec_lines)
        if config is not None:
            claim += f" {first.path} is {config[0]}, which root's scheduler or service manager reads."
        if own_only:
            claim += (" Every root run is the writer's own elevation (in the writer's own audit session or under its "
                      "own login uid): the writer ran its own writable file as root. An administrator running their "
                      "own script through sudo looks like this; so does a sudo or su rule that runs a file its user "
                      "can edit, which gives that account root whenever it edits the file.")
        if changes:
            claim += (f" A kernel file-change record shows this account {CHANGE_WORDS.get(changes[0][3], changes[0][3])}"
                      f" at {_iso(changes[0][0])}.")
        elif self.file_change_records:
            claim += (" No kernel file-change record for this file and account was retrieved, so whether the "
                      "file's content changed is not established.")
        else:
            claim += (" The exec records show the command was started on the file; whether the file's content "
                      "changed is not established (the retrieved telemetry carries no kernel file-change records).")

        # Lanes. A web-service account has no business writing what root runs: high on the command alone, urgent
        # once a kernel file-change record of a content kind (opened for writing, created, renamed onto, linked; an
        # open for writing shows write intent, not the bytes written) is followed by a non-failed root run. Another
        # non-root account is a lead (deployment accounts own such files) until that same record raises it to high.
        # A writer that only elevated its own file is a lead.
        if web:
            lane = "urgent" if run_after_change else "high"
        else:
            lane = "high" if run_after_change else "lead"
        notes = []
        if own_only:
            lane = "lead"
            techniques.add("T1548.003")
            notes.append("own elevation is matched by audit session id and boot id, or by login uid; where the boot "
                         "id is not recorded, a session id reused after a reboot can match a different login")
        if not changes and lane in ("urgent", "high") and not self.write_ok[(host, pkey, account)]:
            lane = "lead"
            notes.append("lane lowered: every recorded exec of the write-capable command failed")
        if series and not runs_after:
            notes.append("no root run of the file began after the write in this window; the next run is the risk")
        confidence = "high" if (changes or runs_after) else "medium"
        match = Match(self.id, claim, self.claim_type, cited, _predicate(cited), writer_events[0].ts,
                      self.severity, lane, confidence, writer_events[0].entities(),
                      group_key=f"{host}|{account}|{pkey}")
        match.notes = notes + sorted(techniques)
        return match


def _own_elevation(executor: tuple, writes: list[_Write]) -> bool:
    """True when a root run is the writer elevating their own file, which is not this behaviour: the run is in the
    writer's own audit session, or its login uid is the writer's own uid (a sudo from another of the writer's
    logins, or a job in the writer's own crontab). The writer's login uid is never used: a daemon inherits that of
    whoever started it. A web-service writer is never excluded: it has no business elevating at all."""
    if any(w.web for w in writes):
        return False
    kind, tag, auid = executor
    own_uids = {w.uid for w in writes if w.uid}
    if kind == "scheduler":
        return auid is not None and auid in own_uids
    if kind == "login":
        own_sessions = {w.session for w in writes if w.session is not None}
        return (tag is not None and tag in own_sessions) or auid in own_uids
    return False


def _listed(items: list[str], limit: int = 6) -> str:
    text = "; ".join(items[:limit])
    return text + (f"; and {len(items) - limit} more form(s)" if len(items) > limit else "")


def _tally(events: list[TypedEvent]) -> str:
    counts = {outcome: sum(1 for e in events if e.outcome == outcome) for outcome in Outcome}
    return (f"recorded exec outcomes of the cited writer records: {counts[Outcome.success]} succeeded, "
            f"{counts[Outcome.failure]} failed, {counts[Outcome.unknown]} unknown")


_PREDICATE_FIELDS = {
    "process_exec": ("process.uid", "process.auid", "process.session_id", "process.ppid", "process.executable",
                     "process.argv", "process.cwd"),
    "auth": ("auth.service", "auth.phase", "process.session_id", "process.pid"),
    "file_change": ("file.path", "file.change", "process.uid"),
}


def _predicate(events: list[TypedEvent]):
    return [pf(event, name) for event in events for name in _PREDICATE_FIELDS.get(event.family, ())
            if event.has(name)]


HIJACK_PLAYBOOKS = [NonRootWriteRootExecutedFile]
