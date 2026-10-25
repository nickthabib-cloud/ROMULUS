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
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import ClassVar

from romulus.detect.base import Match, Playbook, argv_incomplete, pf
from romulus.detect.bounded import HOT_COUNT, KeyedStore, RecentIds
from romulus.detect.correlation import StageMissing, boot_of, boots_conflict
from romulus.detect.host import (
    _FLAG_ONLY,
    DAEMON,
    SCRIPT_FILE_INTERPRETERS,
    WEB_SERVICE_USERS,
    ExecLineage,
    ExecRecord,
    add_unheld,
    alone,
)
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


def _daemon(record: ExecRecord) -> bool:
    return bool(record.flags & DAEMON)


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


class _OkTimes:
    """Start times of the runs whose exec did not fail: an exact count, the latest, and the latest KEPT times. How
    many began after a time t is exact when t is at or after the earliest kept time (every later run is kept), and a
    lower bound otherwise."""

    KEPT = 64
    __slots__ = ("count", "kept")

    def __init__(self):
        self.count = 0
        self.kept: list[float] = []

    def __len__(self) -> int:
        return self.count

    def add(self, ts: float) -> None:
        self.count += 1
        bisect.insort(self.kept, ts)
        if len(self.kept) > self.KEPT:
            del self.kept[0]

    def last(self) -> float | None:
        return self.kept[-1] if self.kept else None

    def after(self, ts: float) -> tuple[int, bool]:
        """(runs that began after `ts`, whether that number is exact)."""
        n = len(self.kept) - bisect.bisect_right(self.kept, ts)
        exact = self.count == len(self.kept) or (bool(self.kept) and ts >= self.kept[0])
        return n, exact


@dataclass
class _Series:
    """Root runs of one file by one executor class."""
    detail: str
    ok_ts: _OkTimes = field(default_factory=_OkTimes)      # runs whose exec did not fail
    failed: int = 0
    first: list[_Run] = field(default_factory=list)
    after: dict[str, _Run] = field(default_factory=dict)  # writer record id -> first non-failed run after it
    # writer record id -> [non-failed runs that began after it, whether that count is exact], kept as runs arrive
    after_n: dict[str, list] = field(default_factory=dict)

    def count_after(self, write: _Write) -> list:
        counted = self.after_n.get(write.event_id)
        if counted is None:
            # the runs already held: exact unless some of them were released from the kept times
            counted = self.after_n[write.event_id] = list(self.ok_ts.after(write.ts))
        return counted


class _File:
    """Everything the rule holds for one (host, file): the non-root writes (commands and kernel records, at most
    WRITE_CITE per account), the kernel change records, the root runs per executor, and per account the
    write-capable command count and how many did not fail."""

    __slots__ = ("changes", "counts", "kernel_writes", "runs", "writes")

    def __init__(self):
        self.writes: list[_Write] = []
        self.kernel_writes: list[_Write] = []
        self.changes: list[tuple[float, str, str, str]] = []
        self.runs: dict[tuple, _Series] = {}
        self.counts: dict[str, list[int]] = {}      # account -> [write-capable commands, of them not failed]


def _written(state: _File) -> bool:
    return bool(state.writes or state.kernel_writes)


def _first_record(m: Match) -> TypedEvent:
    """A per-file finding's own time-stamping record: the cited record its time is taken from (its first write)."""
    ordered = sorted(m.events, key=lambda e: (e.ts, e.id))
    return next((e for e in ordered if e.ts == m.ts), ordered[0])


def _span_records(matches: list[Match]) -> list[TypedEvent]:
    """The records that bound a group's stated span (from the earliest finding's time to the latest's): the
    earliest finding's first record and the latest finding's first record."""
    earliest = min(matches, key=lambda m: (m.ts, _first_record(m).id))
    latest = max(matches, key=lambda m: (m.ts, _first_record(m).id))
    return list({e.id: e for e in (_first_record(earliest), _first_record(latest))}.values())


class NonRootWriteRootExecutedFile(Playbook):
    os_families = ("linux",)
    state_slice = "strong"           # a strong-indicator rule (see Playbook.state_slice)
    id = "host.nonroot_write_root_executed_file"
    version = "9"
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
                           "sudo. One grouped finding per (host, account, file); files the writer only ran through "
                           "its own elevation are one lead per (host, account), and one lead across hosts when the "
                           "same account name does so on several hosts under the same parent directories of the "
                           "per-run directories (configuration management run against many hosts)",
        "query_cost": "none beyond the sweep: it reads the host partitions every host rule reads",
        "next_pivot": "the file's content now, and the first root run after the write (its children and sockets)",
        "adds": "no other rule joins a lower-privileged write with a root execution of the same file",
        "research_basis": "ATT&CK Enterprise 20.0 T1053.003 and T1053.006 (modifying scripts that privileged "
                          "scheduled jobs run); GTFOBins file-write entries for the write-capable program list",
        "retrieval": "the sweep retrieves every record of the host datasets in each partition (dataset filter "
                     "only), a superset of what this evaluator reads",
    }

    # Per-file state, scheduler sessions (by audit session id and by pid) and root execs outside any login are keyed
    # stores: the HOT most recently used keys in memory, the rest on the rule's disk spill, read back when the key
    # returns, never forgotten. A scheduler session is held for the whole hunt, so a job that runs for days is still
    # attributed to the scheduler that opened it; joining a run reads the session back and makes it recent. Only a
    # store's disk byte budget refuses a record, and coverage says so. A scheduler session's own record is staged when
    # read, so a run joined to it can cite it however much later the run comes.
    HOT = HOT_COUNT  # a count cap only: the hunt's memory budget sizes it in bytes
    DAEMON_CAPACITY = HOT_COUNT  # a count cap only: the hunt's memory budget sizes it in bytes

    def __init__(self):
        super().__init__()
        self._seen = RecentIds()        # bounded re-read guard
        self._staged = RecentIds()      # bounded re-stage guard
        self._pending: list[TypedEvent] = []
        self._alone: list[Match] = []   # schedule writes published as they were read (no room to hold their file)
        self.load = lambda ids: []
        # (host, file) -> _File; only files with a non-root write can be reported
        self.files = KeyedStore(self, "hijack_files", self.HOT, candidate=_written)
        # (host, audit session id) and (host, pid) -> entries whose last element is the record's boot id
        self.sessions = KeyedStore(self, "hijack_sessions", self.HOT)
        self.session_pids = KeyedStore(self, "hijack_session_pids", self.HOT)
        # exec records per (host, pid), read for root execs outside any login (`DAEMON`): the hunt's one exec store
        # in a sweep (`share_lineage`), the most recent in memory, the rest on disk
        self.daemons = ExecLineage(self, self.DAEMON_CAPACITY)
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
        for store in (self.files, self.sessions, self.session_pids):
            store.trim()
        self.daemons.trim()
        out, self._alone = self._alone, []
        return out

    def _file(self, key: tuple, alone: bool = False) -> _File | None:
        """The file's state, created when new; None when the disk budget is spent: the record is refused, unless it
        is judged `alone` (the caller publishes it on its own)."""
        state = self.files.setdefault(key, _File)
        if state is None and not alone:
            self.refuse("disk", "the per-file state's disk budget is spent; a record of a new file is not evaluated")
        return state

    @staticmethod
    def _schedule_write(pkey: str, items: list[tuple[str, str, bool]]) -> bool:
        """A write to root's schedule or service configuration, by a path that is not assumed: a finding by itself."""
        return schedule_config(pkey) is not None and any(not assumed for _path, _form, assumed in items)

    def _write_alone(self, event: TypedEvent, pkey: str, items, account: str, own_session) -> None:
        """A write to root's schedule whose file has no room in the per-file store: judged now, as a write of one
        record (no run is needed to report it), and published on its own once per file."""
        self.note_limit("writes_alone", "the per-file state took no new file; a later write to root's schedule is "
                                        "published as it is read, not grouped with the file's other writes and runs")
        forms = list(dict.fromkeys(form for _path, form, _assumed in items))
        write = _Write(event.ts.timestamp(), event.id, items[0][0], " and ".join(forms), account, _uid(event),
                       own_session, event.get("process.user") in WEB_SERVICE_USERS, False)
        state = _File()
        state.counts[account] = [1, int(event.outcome != Outcome.failure)]
        load, self.load = self.load, lambda ids: [event] if event.id in ids else []
        try:
            m = self._finding(event.host or "", pkey, account, [write], state=state)
        finally:
            self.load = load
        if m is not None:
            add_unheld(self._alone, alone(m, self, event))

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
        entry = (event.ts.timestamp(), str(service), event.id, boot_of(event))
        session, pid = event.get("process.session_id"), event.get("process.pid")
        held = False
        for store, key in ((self.sessions, (event.host, session) if session is not None else None),
                           (self.session_pids, (event.host, pid) if isinstance(pid, int) else None)):
            if key is None:
                continue
            entries = store.setdefault(key, list)
            if entries is None:
                self.refuse("disk", "the scheduler sessions' disk budget is spent; a later session is not held")
                continue
            entries.append(entry)
            held = True
        if held:
            self._stage(event)          # a run joined to this session cites it, however much later it comes

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
        state = self._file(key)
        if state is None:
            self.evaluated -= 1
            return
        if sum(1 for item in state.changes if item[2] == account) >= WRITE_CITE:
            return
        self._stage(event)
        state.changes.append((event.ts.timestamp(), event.id, account, str(change)))
        session = event.get("process.session_id")
        state.kernel_writes.append(_Write(
            event.ts.timestamp(), event.id, normalize_path(str(path)), f"a kernel file-change record ({change})",
            account, _uid(event), (boot_of(event), session) if session is not None else None,
            event.get("process.user") in WEB_SERVICE_USERS, False, kernel=True))
        for series in state.runs.values():
            series.count_after(state.kernel_writes[-1])

    def _exec(self, event: TypedEvent) -> None:
        self.daemons.observe(event)             # held once, for every rule reading process ancestry
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
        own_session = (boot_of(event), session) if session is not None else None
        refused = False
        for pkey, items in by_key.items():
            key = (event.host or "", pkey)
            state = self._file(key, alone=self._schedule_write(pkey, items))
            if state is None:
                if self._schedule_write(pkey, items):
                    self._write_alone(event, pkey, items, account, own_session)
                else:
                    refused = True
                continue
            counts = state.counts.setdefault(account, [0, 0])
            counts[0] += 1
            if event.outcome != Outcome.failure:
                counts[1] += 1
            if counts[0] > WRITE_CITE:
                continue
            self._stage(event)
            forms = list(dict.fromkeys(form for _path, form, _assumed in items))
            # A leaf derived inside a known schedule directory is certain: the command writes into that directory.
            assumed = all(flag and posixpath.dirname(path) not in SCHEDULE_DIRECTORIES for path, _f, flag in items)
            state.writes.append(_Write(event.ts.timestamp(), event.id, items[0][0], " and ".join(forms),
                                       account, _uid(event), own_session,
                                       event.get("process.user") in WEB_SERVICE_USERS, assumed))
            for series in state.runs.values():
                series.count_after(state.writes[-1])
        if refused:
            self.evaluated -= 1

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
        executor, detail, auth_id = self._executor(event)
        by_key: dict[str, list[tuple[str, str]]] = {}
        for path, form in runs:
            if path:
                by_key.setdefault(path_key(path), []).append((path, form))
        refused = False
        for pkey, items in by_key.items():
            key = (event.host or "", pkey)
            state = self._file(key)
            if state is None:
                refused = True
                continue
            series = state.runs.setdefault(executor, _Series(detail=detail))
            forms = list(dict.fromkeys(form for _path, form in items))
            run = _Run(event.ts.timestamp(), event.id, items[0][0], " and ".join(forms), auth_id)
            cite = False
            if event.outcome == Outcome.failure:
                series.failed += 1
            else:
                for write in (*state.writes, *state.kernel_writes):
                    counted = series.count_after(write)
                    if write.ts < run.ts:
                        counted[0] += 1
                        if write.event_id not in series.after:
                            series.after[write.event_id] = run
                            cite = True
                series.ok_ts.add(run.ts)
            if len(series.first) < EXEC_FIRST:
                series.first.append(run)
                cite = True
            if cite:
                self._stage(event)
        if refused:
            self.evaluated -= 1

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

    def _executor(self, event: TypedEvent) -> tuple[tuple, str, str | None]:
        """(executor key, description, scheduler session record id) for a root exec record."""
        ts = event.ts.timestamp()
        auid = _auid(event)
        session, boot = event.get("process.session_id"), boot_of(event)
        found = None
        if session is not None:
            found = self._latest(self.sessions.get((event.host, session), ()), ts, boot)
        if found is None and isinstance(event.get("process.ppid"), int):
            found = self._latest(self.session_pids.get((event.host, event.get("process.ppid")), ()), ts, boot)
        if found is not None:
            _when, service, auth_id, _boot = found
            return (("scheduler", service, auid),
                    f"in sessions the scheduler '{service}' opened, joined by audit session id or parent pid",
                    auth_id)
        if auid is None:
            if self._service_lineage(event):
                return (("service", None, None),
                        ("started by the service manager (pid 1) outside any login session, as a systemd unit's "
                         "process is; a timer-triggered unit cannot be told apart from other units in exec records"),
                        None)
            return (("daemon", None, None),
                    ("outside any login session (no audit login uid), launched by a process whose exec is not in "
                     "the retrieved records, such as a scheduler or daemon"), None)
        tag = (boot, session) if session is not None else None
        where = f" (audit session {session})" if session is not None else ""
        return (("login", tag, auid), f"in a login session{where} of audit login uid {auid}", None)

    @staticmethod
    def _latest(entries, ts: float, boot: str | None = None):
        """The latest entry at or before `ts`, unless it is in a boot other than `boot` (its last element): pids
        and audit session ids restart at a reboot, so an earlier entry is in that other boot or an earlier one."""
        best = None
        for entry in entries:
            if entry[0] <= ts and (best is None or entry[0] >= best[0]):
                best = entry
        return None if best is not None and boots_conflict(boot, best[-1]) else best

    def _service_lineage(self, event: TypedEvent) -> bool:
        """True when the ppid chain, through root exec records outside any login session, reaches pid 1."""
        ppid, ts, boot = event.get("process.ppid"), event.ts.timestamp(), boot_of(event)
        serial = event.get("audit.serial")
        for _ in range(LINEAGE_DEPTH):
            if ppid == 1:
                return True
            if not isinstance(ppid, int) or ppid <= 1:
                return False
            parent = self.daemons.latest(event.host, ppid, ts, where=_daemon,
                                         serial=serial if isinstance(serial, int) else None)
            if parent is None or boots_conflict(boot, parent.boot):
                return False
            ts, ppid, serial = parent.ts, parent.ppid, parent.serial
            boot = boot if boot is not None else parent.boot
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
        own: dict[tuple[str, str], list[tuple[str, Match]]] = defaultdict(list)
        for key in sorted(self.files.keys(candidates=True)):
            state = self.files.peek(key)
            by_account: dict[str, list[_Write]] = defaultdict(list)
            for write in (*state.writes, *state.kernel_writes):
                by_account[write.account].append(write)
            for account in sorted(by_account):
                actors = sorted(by_account[account], key=lambda w: (w.ts, w.event_id))
                match = self._finding(key[0], key[1], account, [w for w in actors if not w.kernel],
                                      [w for w in actors if w.kernel], state)
                if match is None:
                    continue
                if getattr(match, "own_path", None):
                    own[(key[0], account)].append((match.own_path, match))
                else:
                    out.append(match)
        # The same account name elevating its own files under the same layout on several hosts (configuration
        # management run against each of them) is one lead; a host whose layout differs keeps its own.
        layouts: dict[tuple[str, frozenset[str]], list[str]] = defaultdict(list)
        for host, account in sorted(own):
            layouts[(account, _layout(own[(host, account)]))].append(host)
        for (account, layout), hosts in sorted(layouts.items(), key=lambda kv: (kv[0][0], sorted(kv[0][1]))):
            if len(hosts) == 1:
                out.append(self._own_group(hosts[0], account, own[(hosts[0], account)]))
            else:
                out.append(self._own_across(account, layout, {host: own[(host, account)] for host in hosts}))
        return out

    def _own_across(self, account: str, layout: frozenset[str],
                    by_host: dict[str, list[tuple[str, Match]]]) -> Match:
        """Own-elevation-only leads of one account name on several hosts with the same layout, as one lead. Every
        per-file finding is kept: its host and path in the notes, its count in the claim; the first record of
        each host's earliest file is cited before any host's second."""
        hosts = sorted(by_host)
        items = {host: sorted(by_host[host], key=lambda item: (item[1].ts, item[0])) for host in hosts}
        total = sum(len(v) for v in items.values())
        firsts = {host: [_first_record(m) for _p, m in items[host]] for host in hosts}
        # the records that bound the stated span, and every host's earliest file, are cited whatever the cap; later
        # files fill up to the cap
        every = [m for v in items.values() for _p, m in v]
        cited: dict[str, TypedEvent] = {e.id: e for e in _span_records(every)}
        cited.update({firsts[host][0].id: firsts[host][0] for host in hosts})
        for rank in range(1, max(len(v) for v in firsts.values())):
            for host in hosts:
                if rank < len(firsts[host]) and len(cited) < WRITE_CITE:
                    cited.setdefault(firsts[host][rank].id, firsts[host][rank])
        events = sorted(cited.values(), key=lambda e: (e.ts, e.id))
        start = min(m.ts for m in every)
        end = max(m.ts for m in every)
        shown = [f"{host}:{path}" for host in hosts for path, _m in items[host]]
        claim = (f"Across {len(hosts)} hosts, account '{account}' (an account of that name on each host) ran "
                 f"write-capable commands on, or changed (per kernel records), {total} files "
                 f"({', '.join(f'{host}: {len(items[host])}' for host in hosts)}), all in per-run directories under "
                 f"{', '.join(sorted(layout))}, from {start.isoformat()} to {end.isoformat()}; each file was then "
                 f"run as root on its own host only by the account's own elevation (its own audit session or login "
                 f"uid): {'; '.join(shown[:WRITE_CITE])}"
                 + (f"; and {len(shown) - WRITE_CITE} more (every host and path is in the notes)"
                    if len(shown) > WRITE_CITE else "")
                 + ". Configuration management that writes a module on every host it manages and runs it with "
                 "privilege escalation looks like this; so does a sudo or su rule that runs files the account can "
                 f"edit, which gives that account root on that host. The first record of {len(events)} of the "
                 f"{total} files is cited: the earliest and the latest file, then the earliest file of each host.")
        all_matches = [m for v in items.values() for _p, m in v]
        notes = sorted({n for m in all_matches for n in m.notes if n.startswith("T")})
        notes += [n for n in all_matches[0].notes if n.startswith("own elevation")]
        notes += [f"file: {path}" for path in shown]
        entities = list(dict.fromkeys([*(("host", host, "host") for host in hosts),
                                       *(entity for e in events for entity in e.entities())]))
        match = Match(self.id, claim, self.claim_type, events, _predicate(events), events[0].ts, self.severity,
                      "lead", "high", entities, group_key=f"{'+'.join(hosts)}|{account}|own-elevation")
        match.notes = notes
        return match

    def _own_group(self, host: str, account: str, items: list[tuple[str, Match]]) -> Match:
        """Own-elevation-only leads of one writer on one host, as one lead (configuration management writes and
        then runs many one-off files this way). Every per-file finding is kept: its path in the claim or notes,
        its first record cited up to the cap, its total in the counts."""
        items = sorted(items, key=lambda item: (item[1].ts, item[0]))
        if len(items) == 1:
            return items[0][1]
        paths = [path for path, _m in items]
        directories = sorted({posixpath.dirname(path) for path in paths})
        # the records that bound the stated span are cited whatever the cap; the files fill up to it in order
        cited: dict[str, TypedEvent] = {e.id: e for e in _span_records([m for _p, m in items])}
        for _path, m in items:
            first = _first_record(m)
            if len(cited) < WRITE_CITE:
                cited.setdefault(first.id, first)
        events = sorted(cited.values(), key=lambda e: (e.ts, e.id))
        start, end = items[0][1].ts, max(m.ts for _p, m in items)
        shown = paths[:WRITE_CITE]
        claim = (f"On {host}, account '{account}' ran write-capable commands on, or changed (per kernel records), "
                 f"{len(paths)} files in {len(directories)} director(ies) "
                 f"from {start.isoformat()} to {end.isoformat()}, and each was then run as root only by the "
                 f"account's own elevation (its own audit session or login uid): {'; '.join(shown)}"
                 + (f"; and {len(paths) - len(shown)} more (every path is in the notes)" if len(paths) > len(shown)
                    else "") + ". Configuration management that writes a module and runs it with privilege "
                 "escalation looks like this; so does a sudo or su rule that runs files the account can edit, which "
                 f"gives that account root. The first record of {len(events)} of the {len(paths)} files is cited, "
                 f"the earliest and the latest file among them.")
        notes = sorted({n for _p, m in items for n in m.notes if n.startswith("T")})
        notes += [n for n in items[0][1].notes if n.startswith("own elevation")]
        notes += [f"file: {path}" for path in paths]
        match = Match(self.id, claim, self.claim_type, events, _predicate(events), events[0].ts, self.severity,
                      "lead", "high", events[0].entities(), group_key=f"{host}|{account}|own-elevation")
        match.notes = notes
        return match

    def _finding(self, host: str, pkey: str, account: str, writes: list[_Write],
                 kernel: list[_Write] = (), state: _File | None = None) -> Match | None:
        """`writes` are write-capable commands; `kernel` are kernel file-change records by the same account. With
        no command, the kernel records are the writes, and a finding needs a root run of the file."""
        state = state if state is not None else self.files.peek((host, pkey), _File())
        every = sorted(state.runs.items(), key=lambda item: str(item[0]))
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
        changes = sorted(c for c in state.changes if c[2] == account)
        content_changes = [c for c in changes if c[3] != "attributes"]
        total_writes, ok_writes = state.counts.get(account, (0, 0))

        cited_ids = [w.event_id for w in writes] + [c[1] for c in changes]
        techniques: set[str] = {config[1]} if config else set()
        runs_after, run_after_change = 0, False
        exec_lines = []
        for (kind, service, _auid_value), s in series:
            techniques.add(SCHEDULER_SERVICES.get(service or "", "T1053") if kind == "scheduler"
                           else _EXECUTOR_TECHNIQUE[kind])
            if kind == "service":
                techniques.add("T1543.002")
            n_after, exact = s.after_n.get(first.event_id) or s.ok_ts.after(first.ts)
            runs_after += n_after
            if content_changes and s.ok_ts and s.ok_ts.last() > content_changes[0][0]:
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
                n_after = n_after if exact else f"at least {n_after}"
                line += (f"; {n_after} of them began after {since}, the first at "
                         f"{_iso(after.ts)}" if after is not None else
                         f"; {n_after} of them began after {since} (the record of the "
                         f"first of them is not among the citations)")
            else:
                line += (f"; none whose exec did not fail began after {since} (they are "
                         "earlier, or at the same recorded time)")
            if s.failed:
                line += f"; {s.failed} of them recorded a failed exec"
            total_runs = len(s.ok_ts) + s.failed
            if total_runs > len({run.event_id for run in cited_runs}):
                line += f"; {len({run.event_id for run in cited_runs})} of these {total_runs} records are cited"
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
        if not changes and lane in ("urgent", "high") and not ok_writes:
            lane = "lead"
            notes.append("lane lowered: every recorded exec of the write-capable command failed")
        if series and not runs_after:
            notes.append("no root run of the file began after the write in this window; the next run is the risk")
        confidence = "high" if (changes or runs_after) else "medium"
        match = Match(self.id, claim, self.claim_type, cited, _predicate(cited), writer_events[0].ts,
                      self.severity, lane, confidence, writer_events[0].entities(),
                      group_key=f"{host}|{account}|{pkey}")
        match.notes = notes + sorted(techniques)
        if own_only:
            match.own_path = first.path
        return match


def _layout(items: list[tuple[str, Match]]) -> frozenset[str]:
    """Where a writer's own-elevation files sit: the parents of their directories (per-run directories such as a
    configuration-management temporary directory differ each run; the directory holding them does not)."""
    return frozenset(posixpath.dirname(posixpath.dirname(path)) for path, _m in items)


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
        return any(_same_session(tag, w.session) for w in writes) or auid in own_uids
    return False


def _same_session(a: tuple | None, b: tuple | None) -> bool:
    """Two (boot id, audit session id) tags name one login session: the same session id, and boots that are not
    known to differ (a session id restarts at a reboot; see `boots_conflict`)."""
    return a is not None and b is not None and a[1] == b[1] and not boots_conflict(a[0], b[0])


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
