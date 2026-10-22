"""Rules over kernel file records: exec-file ownership and file-change (PATH) records from Linux audit.

Both rules read what the kernel recorded at the system call: the owner, group and mode of the file an exec named,
and the path, change kind and actor of a file change. Neither knows which files and calls the host's audit rules
cover (that inventory is not in the telemetry), so both are positive-only: absence proves nothing.
"""
from __future__ import annotations

import posixpath
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import ClassVar

from romulus.detect.base import Match, Playbook, pf
from romulus.detect.bounded import (
    HOT_COUNT,
    ExecHistory,
    HeldExamples,
    KeyedStore,
    RecentIds,
    SpillList,
    StateExhausted,
)
from romulus.detect.correlation import StageMissing, boot_of, boots_conflict, merge_unknown_boot
from romulus.detect.hijack import CHANGE_WORDS, _own_elevation, _Write, path_key
from romulus.detect.host import WEB_SERVICE_USERS, add_unheld, alone, need
from romulus.evidence.typed import Outcome, TypedEvent

CITE = 10                       # records cited per finding; claims give exact totals
# Records of one (pid, executable) further apart than this are not read as one process run: process ids are reused.
PROCESS_GAP_SECONDS = 300
LINEAGE_DEPTH = 16


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, UTC).isoformat()


def _str(value) -> str | None:
    return None if value is None else str(value)


def _mode(value) -> int | None:
    try:
        return int(str(value), 8)
    except (TypeError, ValueError):
        return None


def _tally(events: list[TypedEvent], noun: str) -> str:
    counts = {outcome: sum(1 for e in events if e.outcome == outcome) for outcome in Outcome}
    return (f"recorded outcomes of the cited {noun}: {counts[Outcome.success]} succeeded, "
            f"{counts[Outcome.failure]} failed, {counts[Outcome.unknown]} unknown")


def _span(first: float, last: float) -> str:
    return f"at {_iso(first)}" if first == last else f"from {_iso(first)} to {_iso(last)}"


# =============================================================================================================
# Root executes a file that a non-root account owns or can write
# =============================================================================================================

_EXEC_FILES = (("process.exec_file", None), ("process.interpreter_file", "as the interpreter of the #! script"))


@dataclass
class _Runs:
    """Root runs of one file in one audit session (or outside any session)."""
    count: int = 0
    failed: int = 0
    first: float = 0.0
    last: float = 0.0
    auid: str | None = None                                 # the login uid the latest run recorded
    cited: HeldExamples = field(default_factory=lambda: HeldExamples(CITE))     # the first runs to arrive
    prefixes: dict[str, set[str]] = field(default_factory=dict)                 # cited event -> field prefix


@dataclass
class _ModifiableFile:
    """One file (by host, path and owner) that root ran, with what the kernel recorded about it on any run."""
    paths: set[str]
    roles: set[str]
    owner: str
    owner_name: str | None
    groups: set[str]
    modes: set[str]
    reasons: set[str]
    web: bool
    world: bool
    others_can_write: bool
    prefix: str

    def merge(self, other: _ModifiableFile) -> None:
        self.paths |= other.paths
        self.roles |= other.roles
        self.groups |= other.groups
        self.modes |= other.modes
        self.reasons |= other.reasons
        self.owner_name = self.owner_name or other.owner_name
        self.web = self.web or other.web
        self.world = self.world or other.world
        self.others_can_write = self.others_can_write or other.others_can_write


class _RunTally:
    """Root runs summed one session at a time: totals, span, login uids, and the CITE earliest cited runs by
    (time, id) with the field prefixes each matched on."""

    def __init__(self):
        self.count = self.failed = 0
        self.first = self.last = None
        self.auids: set[str] = set()
        self.cited: dict[str, list] = {}                    # event id -> [(time, id), event or None]
        self.prefixes: dict[str, set[str]] = defaultdict(set)

    def __bool__(self) -> bool:
        return self.count > 0

    def add(self, runs: _Runs | _RunTally) -> None:
        self.count += runs.count
        self.failed += runs.failed
        self.first = runs.first if self.first is None else min(self.first, runs.first)
        self.last = runs.last if self.last is None else max(self.last, runs.last)
        if isinstance(runs, _Runs):
            self.auids.add(runs.auid or "none")
            items = runs.cited.items
        else:
            self.auids |= runs.auids
            items = list(runs.cited.values())
        for ref, event in items:
            held = self.cited.setdefault(ref[1], [ref, event])
            if held[1] is None:
                held[1] = event
            self.prefixes[ref[1]] |= runs.prefixes.get(ref[1], set())
        if len(self.cited) > CITE:
            for _ref, _event in sorted(self.cited.values(), key=lambda item: item[0])[CITE:]:
                del self.cited[_ref[1]]
                self.prefixes.pop(_ref[1], None)

    def events(self, load) -> list[TypedEvent]:
        items = sorted(self.cited.values(), key=lambda item: item[0])
        wanted = [ref[1] for ref, event in items if event is None]
        found = {event.id: event for event in load(wanted)} if wanted else {}
        missing = [event_id for event_id in wanted if event_id not in found]
        if missing:
            raise LookupError(f"{len(missing)} cited event(s) absent from the stage, e.g. {missing[0]}")
        return [event if event is not None else found[ref[1]] for ref, event in items]


class RootExecNonRootModifiableFile(Playbook):
    state_slice = "strong"           # a protected slice of the hunt's disk budget
    id = "host.root_exec_nonroot_modifiable_file"
    version = "2"
    title = "Root executed a file that a non-root account owns or can write"
    anchor_class = "execution"
    kind = "aggregate"
    claim_type = "aggregate_observation"
    families = ("process_exec",)
    required_fields = ("process.uid",)
    assures_negative = False
    positive_only_reason = (
        "the audit rule set's exec coverage (which accounts' and paths' execs it records) is not visible in "
        "telemetry, so a missing root exec of such a file proves nothing")
    severity, lane = "high", "high"
    attack = ("T1574", "T1053", "T1543.002")
    benign = ("vendor software installed under a service account's ownership that a root unit or job runs",
              "a deployment account that owns scripts root's scheduler runs (still a privilege boundary weakness)",
              ("an administrator running their own file through sudo (runs in the owner's own audit session or "
              "under the owner's login uid are one separate lead per host and owner)"))
    next_checks = ("the file's current owner, mode and content, and its package ownership",
                   "the file's change history: kernel file-change records, package and deploy logs",
                   "what the root runs started or connected to, and who can log in as the owning account")
    card: ClassVar[dict] = {
        "behavior": "a process with real or effective uid 0 executed a file (or a #! script's interpreter) that "
                    "the kernel recorded at exec time as owned by a non-root uid, world-writable, or writable by "
                    "a non-root group",
        "telemetry": "Linux auditd EXECVE+SYSCALL+PATH+CWD as process_exec: process.uid, process.euid, "
                     "process.auid, process.session_id, process.exec_file.{path,owner.id,owner.name,group.id,mode,"
                     "inode,role}, process.interpreter_file.* (PATH item 0 and the #! interpreter item). Present "
                     "in the lab profile on nearly every exec event",
        "fidelity": "direct kernel record of the exec and of the file's ownership and mode at that moment; it "
                    "does not show that the file was changed, nor writable parent directories or ACLs",
        "benign_and_cost": "vendor or deployment accounts owning root-run files. One grouped finding per (host, "
                           "file, owner); such files are rare",
        "query_cost": "none beyond the sweep: it reads the host partitions every host rule reads",
        "next_pivot": "the file's change history and the owning account's activity before the root runs",
        "adds": "the argv-identified hijack rule needs a recorded write; this one needs only the ownership the "
                "kernel recorded at exec, so it finds the weakness before or without a recorded write",
        "research_basis": "ATT&CK Enterprise 20.0 T1574 (Hijack Execution Flow), T1053 and T1543.002 (privileged "
                          "jobs and units running modifiable files); GTFOBins/linpeas checks for writable "
                          "root-run files; Linux audit PATH record fields (ouid, ogid, mode)",
        "retrieval": "the sweep retrieves every record of the host datasets in each partition (dataset filter "
                     "only), a superset of what this evaluator reads",
    }

    # Root runs are kept per (file, audit session): a job run by a scheduler opens a new session each run. The files,
    # the session runs (with their cited ids) and the owners' own sessions are keyed stores: the HOT most recently
    # used in memory, the rest on the rule's disk spill, read back when the key returns, never forgotten. Finalize
    # reads one file's session runs at a time. Citations are staged; only a store's disk byte budget refuses a run,
    # and coverage says so.
    staged = True
    HOT = HOT_COUNT  # a count cap only: the hunt's memory budget sizes it in bytes

    def __init__(self):
        super().__init__()
        self._seen = RecentIds()        # bounded re-read guard
        self.files = KeyedStore(self, "rx_files", self.HOT)                       # (host, file, owner) -> file
        # (host, file, owner, session tag) -> _Runs, grouped by file
        self.runs = KeyedStore(self, "rx_runs", self.HOT, group=lambda key: "\x00".join(key[:3]))
        # (host, uid, audit session id) -> boot ids of that account's own sessions with that id
        self.owner_sessions = KeyedStore(self, "rx_owner_sessions", self.HOT)
        self._pending: list[TypedEvent] = []
        self._fresh: list[HeldExamples] = []
        self.load = lambda ids: []

    def drain_staged(self) -> list[TypedEvent]:
        out, self._pending = self._pending, []
        for store in self._fresh:
            store.staged()
        self._fresh = []
        for store in (self.files, self.runs, self.owner_sessions):
            store.trim()
        return out

    def retained_events(self) -> list[TypedEvent]:
        # the sweep stages these instead; before staging they are the cited runs still held as events
        return list(self._pending)

    def consume(self, events):
        for event in sorted((e for e in events if e.family == "process_exec" and e.id not in self._seen),
                            key=lambda e: (e.ts, e.id)):
            self._seen.add(event.id)
            self._exec(event)
        return []

    def _exec(self, event: TypedEvent) -> None:
        uid, euid = _str(event.get("process.uid")), _str(event.get("process.euid"))
        if uid is None and euid is None:
            self.missing_required += 1
            return
        session = event.get("process.session_id")
        tag = (boot_of(event), session) if session is not None else None
        if "0" not in (uid, euid):
            self.evaluated += 1
            if tag is not None and uid is not None:
                boots = self.owner_sessions.setdefault((event.host or "", uid, session), set)
                if boots is None:
                    self.note_limit("disk", "the own audit sessions' disk budget is spent; a later root run in such a "
                                            "session is reported as another account's, never as own")
                else:
                    boots.add(tag[0])
            return
        found = [f for f in (self._modifiable(event, prefix, role) for prefix, role in _EXEC_FILES) if f]
        if not found and not event.has("process.exec_file.owner.id") and not event.has("process.exec_file.mode"):
            self.missing_required += 1        # ownership of the executed file is not recorded: undecidable
            return
        self.evaluated += 1
        for candidate in found:
            key = (event.host or "", path_key(next(iter(candidate.paths))), candidate.owner)
            entry = self.files.get(key)
            if entry is None:
                entry = candidate if self.files.put(key, candidate) else None
            else:
                entry.merge(candidate)
            runs = None if entry is None else self.runs.setdefault((*key, tag),
                                                                   lambda: _Runs(first=event.ts.timestamp()))
            if runs is None:
                self.evaluated -= 1
                self.refuse("disk", "the root runs' disk budget is spent; a run of a new file or session is not "
                                    "evaluated")
                return
            runs.auid = _str(event.get("process.auid"))
            runs.count += 1
            runs.failed += event.outcome == Outcome.failure
            runs.last = max(runs.last, event.ts.timestamp())
            runs.first = min(runs.first, event.ts.timestamp())
            if runs.cited.offer(event):
                self._pending.append(event)
                self._fresh.append(runs.cited)
            if event.id in runs.cited.ids():               # only a cited record's predicate is ever stated
                runs.prefixes.setdefault(event.id, set()).add(candidate.prefix)

    def _modifiable(self, event: TypedEvent, prefix: str, role: str | None) -> _ModifiableFile | None:
        owner = _str(event.get(f"{prefix}.owner.id"))
        mode_text = event.get(f"{prefix}.mode")
        mode = _mode(mode_text)
        group = _str(event.get(f"{prefix}.group.id"))
        if owner is None and mode is None:
            return None
        reasons = []
        if owner is not None and owner != "0":
            reasons.append("it is owned by a non-root account")
        world = mode is not None and bool(mode & 0o002)
        if world:
            reasons.append("it is writable by every account (world-writable mode)")
        group_writable = mode is not None and bool(mode & 0o020) and group not in (None, "0")
        if group_writable:
            reasons.append(f"it is writable by group id {group}")
        if not reasons:
            return None
        recorded = event.get(f"{prefix}.path")
        if recorded:
            path = str(recorded)
        else:
            inode, device = event.get(f"{prefix}.inode"), event.get(f"{prefix}.device")
            path = f"(unplaced name; inode {inode} on device {device})"
        if role is None:
            role = ("as the #! script" if event.get("process.exec_file.role") == "script"
                    else "as the executed program")
        owner_name = event.get(f"{prefix}.owner.name")
        return _ModifiableFile(paths={path}, roles={role}, owner=owner or "0", owner_name=_str(owner_name),
                               groups={group} if group is not None else set(),
                               modes={str(mode_text)} if mode_text is not None else set(), reasons=set(reasons),
                               web=owner_name in WEB_SERVICE_USERS, world=world,
                               others_can_write=world or group_writable, prefix=prefix)

    def finalize(self):
        out = []
        own = KeyedStore(self, "rx_own", self.HOT)      # (host, owner) -> [(file, tally of own runs)]
        current = f = others = mine = None
        for key, runs in self.runs.grouped():           # one file's session runs at a time, files in key order
            if key[:3] != current:
                self._file_done(current, f, others, mine, out, own)
                current, others, mine = key[:3], _RunTally(), _RunTally()
                f = self.files.peek(current)
            (mine if self._own(current[0], f, key[3], runs.auid) else others).add(runs)
        self._file_done(current, f, others, mine, out, own)
        out += [self._own_finding(host, owner, own.peek((host, owner))) for host, owner in sorted(own.keys())]
        own.clear()
        return out

    def _file_done(self, key, f, others: _RunTally, mine: _RunTally, out: list, own: KeyedStore) -> None:
        if key is None:
            return
        if others:
            out.append(self._finding(key, f, others))
        if mine:
            held = own.setdefault((key[0], f.owner), list)
            if held is None:
                self.refuse("disk", "the own-run leads' disk budget is spent; a file's own runs are not evaluated",
                            records=mine.count)
            else:
                held.append((f, mine))
                own.trim()

    def _predicate(self, cited: list[TypedEvent], prefixes: dict[str, set[str]]) -> list:
        """Predicate fields of each cited event, from the field prefix (program or interpreter) it matched on."""
        out = []
        for event in cited:
            names = ["process.uid", "process.euid"] + [f"{p}.{n}" for p in sorted(prefixes.get(event.id, set()))
                                                       for n in ("owner.id", "mode", "path")]
            out += [pf(event, name) for name in names if event.has(name)]
        return out

    def _own(self, host: str, f: _ModifiableFile, tag: tuple | None, auid: str | None) -> bool:
        """The owner running their own file as root, by the write/run rule's own-elevation test. Such runs are
        reported as their own lead, never dropped. The test applies only when non-root ownership is the whole
        reason; a file other accounts can write is never the owner's own matter."""
        if auid is None or f.owner == "0" or f.others_can_write:
            return False                         # outside any login session: a daemon, unit or scheduler run
        boots = self.owner_sessions.peek((host, f.owner, tag[1]), ()) if tag is not None else ()
        sessions = sorted({(boot, tag[1]) for boot in boots}, key=str) or [None]
        owners = [_Write(0.0, "", min(f.paths), "", f.owner_name or f.owner, f.owner, session, f.web, False)
                  for session in sessions]
        return _own_elevation(("login", tag, auid), owners)

    def _finding(self, key: tuple[str, str, str], f: _ModifiableFile, kept: _RunTally) -> Match:
        host = key[0]
        total, failed, first, last = kept.count, kept.failed, kept.first, kept.last
        cited = kept.events(self.load)
        auids = sorted(kept.auids)
        who = f"uid {f.owner}" + (f" ('{f.owner_name}')" if f.owner_name else "")
        if f.web:
            who += ", a web-service account"
        attributes = [f"owner {who}"]
        if f.groups:
            attributes.append(f"group id {', '.join(sorted(f.groups))}")
        if f.modes:
            attributes.append(f"mode {', '.join(sorted(f.modes))}")
        runs_text = "once" if total == 1 else f"{total} times"
        sessions = ("outside any login session (no audit login uid)" if auids == ["none"]
                    else f"under audit login uid(s) {', '.join(auids)}")
        claim = (f"On {host}, a root process (real or effective uid 0) executed {' or '.join(sorted(f.paths))} "
                 f"{' and '.join(sorted(f.roles))} {runs_text} {_span(first, last)}, {sessions}. At exec time the "
                 f"kernel recorded the file with {', '.join(attributes)}: {'; '.join(sorted(f.reasons))}. Root "
                 f"running a file that a non-root account can "
                 f"change lets that account run code as root. These records show the ownership and mode at exec; "
                 f"they do not show whether the file was changed.")
        if total > len(cited):
            claim += f" {len(cited)} of these runs are cited."
        claim += f" The {_tally(cited, 'exec calls')}."
        lane = "high" if (f.web or f.world) else "lead"
        notes = []
        if failed == total:
            lane = "lead"
            notes.append("lane lowered: every recorded exec of the file failed")
        match = Match(self.id, claim, self.claim_type, cited, self._predicate(cited, kept.prefixes), cited[0].ts,
                      self.severity, lane, "high", cited[0].entities(), group_key=f"{host}|{f.owner}|{key[1]}")
        match.notes = notes + ["T1574"]
        return match

    def _own_finding(self, host: str, owner: str, files: list[tuple[_ModifiableFile, _RunTally]]) -> Match:
        """One lead per (host, owner) for root runs of the owner's files in the owner's own session or login."""
        runs = _RunTally()
        for _f, tally in files:
            runs.add(tally)
        total, first, last = runs.count, runs.first, runs.last
        cited = runs.events(self.load)
        name = next((f.owner_name for f, _rs in files if f.owner_name), None)
        who = f"uid {owner}" + (f" ('{name}')" if name else "")
        listed = "; ".join(f"{' or '.join(sorted(f.paths))} ({tally.count} run(s), mode "
                           f"{', '.join(sorted(f.modes)) or 'not recorded'})" for f, tally in files)
        claim = (f"On {host}, root ran file(s) owned by {who} {total} time(s) {_span(first, last)} in the owner's own "
                 f"audit session or under the owner's own login uid: {listed}. The owner ran their own writable file "
                 f"as root. An administrator running their own script through sudo looks like this; so does a sudo "
                 f"or su rule that runs a file its owner can edit, which gives that account root whenever it edits "
                 f"the file.")
        if total > len(cited):
            claim += f" {len(cited)} of these runs are cited."
        claim += f" The {_tally(cited, 'exec calls')}."
        match = Match(self.id, claim, self.claim_type, cited, self._predicate(cited, runs.prefixes),
                      cited[0].ts, self.severity, "lead", "high", cited[0].entities(), group_key=f"{host}|own:{owner}")
        match.notes = ["T1548.003", "T1574",
                       ("own sessions are matched by audit session id and boot id; where the boot id is not recorded, "
                       "a session id reused after a reboot can match a different login")]
        return match


# =============================================================================================================
# Persistence-location changes from kernel file-change records
# =============================================================================================================

# Locations whose files a scheduler, the service manager, init, the login path or the loader reads and acts on.
# (prefix, description, technique). A path matches the first entry it equals or lies beneath.
_DIRS = (
    ("/var/spool/cron/atjobs", "the at job spool", "T1053.002"),
    ("/var/spool/at", "the at job spool", "T1053.002"),
    ("/var/spool/cron", "the per-account crontab spool", "T1053.003"),
    ("/etc/cron.d", "a system cron table directory", "T1053.003"),
    ("/etc/cron.hourly", "a root cron job directory", "T1053.003"),
    ("/etc/cron.daily", "a root cron job directory", "T1053.003"),
    ("/etc/cron.weekly", "a root cron job directory", "T1053.003"),
    ("/etc/cron.monthly", "a root cron job directory", "T1053.003"),
    ("/etc/init.d", "the init script directory", "T1037.004"),
    ("/etc/rc.d", "the rc script directory", "T1037.004"),
    ("/etc/systemd/system-generators", "a systemd generator directory", "T1543.002"),
    ("/usr/lib/systemd/system-generators", "a systemd generator directory", "T1543.002"),
    ("/lib/systemd/system-generators", "a systemd generator directory", "T1543.002"),
    ("/etc/systemd/system", "a system unit directory", "T1543.002"),
    ("/run/systemd/system", "a system unit directory", "T1543.002"),
    ("/usr/local/lib/systemd/system", "a system unit directory", "T1543.002"),
    ("/usr/lib/systemd/system", "a system unit directory", "T1543.002"),
    ("/lib/systemd/system", "a system unit directory", "T1543.002"),
    ("/etc/systemd/user", "a user unit directory", "T1543.002"),
    ("/run/systemd/user", "a user unit directory", "T1543.002"),
    ("/usr/lib/systemd/user", "a user unit directory", "T1543.002"),
    ("/lib/systemd/user", "a user unit directory", "T1543.002"),
    ("/etc/profile.d", "the login shell profile directory", "T1546.004"),
    ("/etc/pam.d", "the PAM configuration directory", "T1556.003"),
    ("/etc/ld.so.conf.d", "the dynamic linker search-path directory", "T1574.006"),
    ("/etc/sudoers.d", "the sudo policy directory", "T1548.003"),
    ("/etc/update-motd.d", "the login message script directory (run as root at login)", "T1037"),
    ("/etc/udev/rules.d", "a udev rules directory", "T1546.017"),
    ("/usr/lib/udev/rules.d", "a udev rules directory", "T1546.017"),
    ("/lib/udev/rules.d", "a udev rules directory", "T1546.017"),
    ("/etc/modules-load.d", "a kernel module load list directory", "T1547.006"),
    ("/usr/lib/modules-load.d", "a kernel module load list directory", "T1547.006"),
    ("/etc/xdg/autostart", "the desktop autostart directory", "T1547.013"),
    ("/etc/ssh/sshd_config.d", "the SSH server configuration directory", "T1098.004"),
)
_FILES = {
    "/etc/crontab": ("the system crontab", "T1053.003"),
    "/etc/anacrontab": ("the anacron table", "T1053.003"),
    "/etc/rc.local": ("the rc.local boot script", "T1037.004"),
    "/etc/profile": ("the system login shell profile", "T1546.004"),
    "/etc/bash.bashrc": ("the system bash startup file", "T1546.004"),
    "/etc/bashrc": ("the system bash startup file", "T1546.004"),
    "/etc/zshrc": ("a system zsh startup file", "T1546.004"),
    "/etc/zprofile": ("a system zsh startup file", "T1546.004"),
    "/etc/zshenv": ("a system zsh startup file", "T1546.004"),
    "/etc/zlogin": ("a system zsh startup file", "T1546.004"),
    "/etc/zsh/zshrc": ("a system zsh startup file", "T1546.004"),
    "/etc/zsh/zprofile": ("a system zsh startup file", "T1546.004"),
    "/etc/zsh/zshenv": ("a system zsh startup file", "T1546.004"),
    "/etc/zsh/zlogin": ("a system zsh startup file", "T1546.004"),
    "/etc/environment": ("the login environment file", "T1546.004"),
    "/etc/ld.so.preload": ("the dynamic linker preload list", "T1574.006"),
    "/etc/ld.so.conf": ("the dynamic linker search-path configuration", "T1574.006"),
    "/etc/sudoers": ("the sudo policy", "T1548.003"),
    "/etc/ssh/sshd_config": ("the SSH server configuration", "T1098.004"),
    "/etc/modules": ("the kernel module load list", "T1547.006"),
}
# Per-account startup files, by name, wherever the account's home is.
_SHELL_RC = {".bashrc", ".bash_profile", ".bash_login", ".bash_logout", ".profile", ".zshrc", ".zprofile",
             ".zshenv", ".zlogin", ".zlogout"}
_AUTHORIZED_KEYS = {"authorized_keys", "authorized_keys2"}
_PAM_MODULE = re.compile(r"^/(?:usr/)?lib(?:32|64)?/(?:[^/]+/)?security/[^/]+\.so$")
_RC_LEVEL_DIR = re.compile(r"^/etc/rc[0-6S]\.d$")
# Spools whose entries belong to the account that submitted them (its crontab, its at jobs).
_PER_ACCOUNT_SPOOLS = {"/var/spool/cron", "/var/spool/cron/atjobs", "/var/spool/at"}

# Changes that can install or alter what is run or read; removing a file does not establish anything.
_INSTALLING = {"content", "create", "rename_target", "link", "attributes"}
# Package managers by kernel-recorded executable name; the executable must be in a system directory.
PACKAGE_MANAGERS = {"dpkg", "apt", "apt-get", "aptitude", "rpm", "rpmdb", "dnf", "dnf-3", "yum", "microdnf",
                    "zypper", "snap", "snapd", "flatpak", "pacman", "apk", "packagekitd"}
_SYSTEM_EXE_DIRS = ("/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/usr/lib/", "/usr/libexec/", "/lib/")


def persistence_location(path: str) -> tuple[str, str, str, bool] | None:
    """(grouping location, description, technique, per-account) when a changed file is one the system acts on.
    A per-account location belongs to one account's own setup (its crontab, shell startup files, keys, units)."""
    if path in _FILES:
        description, technique = _FILES[path]
        return path, description, technique, False
    for prefix, description, technique in _DIRS:
        if path.startswith(prefix + "/"):
            return prefix, f"a file in {description} ({prefix})", technique, prefix in _PER_ACCOUNT_SPOOLS
    directory, name = posixpath.split(path)
    if _RC_LEVEL_DIR.match(directory):
        return directory, f"a file in a runlevel script directory ({directory})", "T1037.004", False
    if name in _AUTHORIZED_KEYS:
        return path, "an SSH authorized keys file", "T1098.004", True
    if "/.ssh/" in path and name == "rc":
        return path, "a per-account SSH login script", "T1098.004", True
    if name in _SHELL_RC:
        return path, "a shell startup file", "T1546.004", True
    if "/.config/systemd/user/" in path:
        base = path[:path.index("/.config/systemd/user/")] + "/.config/systemd/user"
        return base, f"a file in a per-account systemd unit directory ({base})", "T1543.002", True
    if "/.config/autostart/" in path:
        base = path[:path.index("/.config/autostart/")] + "/.config/autostart"
        return base, f"a file in a per-account desktop autostart directory ({base})", "T1547.013", True
    if _PAM_MODULE.match(path):
        return directory, f"a PAM module in {directory}", "T1556.003", False
    return None


@dataclass
class _Change:
    ts: float
    event_id: str
    host: str
    path: str
    change: str
    location: str
    description: str
    technique: str
    uid: str
    account: str
    web: bool
    per_account: bool       # a per-account location (an account's own crontab, at jobs, keys, startup files)
    own: bool               # a per-account location, in a file the actor's own uid owns
    setuid: bool            # a non-root account through a setuid-root program (effective uid 0)
    exe: str
    boot: str | None
    pid: int | None
    ppid: int | None
    auid: str | None
    tty: str | None
    outcome: Outcome


class PersistencePathChange(Playbook):
    state_slice = "strong"           # a protected slice of the hunt's disk budget
    id = "host.persistence_path_change"
    version = "4"
    title = "Kernel-recorded change to a file that a scheduler, init, the login path or the loader acts on"
    anchor_class = "persistence"
    kind = "aggregate"
    staged = True
    claim_type = "aggregate_observation"
    families = ("file_change", "process_exec")
    required_fields = ("file.path", "process.uid")
    assures_negative = False
    positive_only_reason = (
        "which files and directories the audit rules watch is not visible in telemetry, so a missing change record "
        "for a location proves nothing")
    severity, lane = "high", "high"
    attack = ("T1053.002", "T1053.003", "T1037", "T1037.004", "T1543.002", "T1546.004", "T1546.017", "T1556.003",
              "T1574.006", "T1548.003", "T1098.004", "T1547.006", "T1547.013")
    benign = ("package installs and upgrades (grouped and worded as package activity)",
              ("administrators editing configuration as root (an editor also writes swap and backup files beside "
              "the file)"),
              "configuration management agents and log or account maintenance jobs running as root",
              "an account managing its own crontab or shell startup files")
    next_checks = ("the file's content now and its package ownership (package verification)",
                   "what runs or reads the file next (a cron or unit run, a login) and what that started",
                   "the writing process's lineage and login session")
    card: ClassVar[dict] = {
        "behavior": "a kernel file-change record (write-intent open, create, rename onto, link, or mode/owner "
                    "change) on a file in a persistence location: cron and at spools and tables, init and rc "
                    "scripts, system and user systemd units and generators, shell startup files, PAM "
                    "configuration and modules, the dynamic linker preload and search path, authorized_keys, "
                    "sudoers, login message scripts, udev rules, module load lists, autostart entries, sshd "
                    "configuration",
        "telemetry": "Linux auditd SYSCALL+PATH(+CWD) of file-changing calls as file_change: file.path, "
                     "file.change, file.nametype, process.uid, process.user, process.auid, process.tty, "
                     "process.pid, process.ppid, process.executable; process_exec for the package-manager "
                     "lineage. Coverage is watch-scoped: only locations the host's audit rules watch produce "
                     "records, and the lab profile watches some of these locations, not all",
        "fidelity": "direct kernel record of the call on the file and its outcome; a write-intent open shows the "
                    "file was opened for writing, not what was written",
        "benign_and_cost": "package activity (one grouped lead per host, manager and location), root editors and "
                           "agents (lead per host, location and account), an account's own crontab, at jobs, keys "
                           "or startup files and setuid-root helpers acting for an account (lead). Other non-root "
                           "changes, and every web-service account change, are rare and high",
        "query_cost": "none beyond the sweep: it reads the host partitions every host rule reads",
        "next_pivot": "the file's content and the next run or read of it; the writer's session and lineage",
        "adds": "the argv rules see only commands that name the file; this sees the kernel's record of the change "
                "whatever made it (shell redirects, interpreters, editors' renames)",
        "research_basis": "ATT&CK Enterprise 20.0 persistence techniques listed in `attack`; SigmaHQ "
                          "rules/linux/auditd file-event rules (cron, systemd, ld.so.preload, sudoers, "
                          "authorized_keys, pam) as the location corpus, reimplemented; the Linux audit PATH "
                          "nametype semantics",
        "retrieval": "the sweep retrieves every record of the host datasets in each partition (dataset filter "
                     "only), a superset of what this evaluator reads",
    }

    # The exec history holds EXEC_CAPACITY processes in memory (about 200 bytes each, so 60 MB), the rest on the
    # rule's disk spill. Changes in persistence locations (rare except package upgrades, about 600 bytes each) and
    # finalize's groups of them hold HOT in memory and the rest on disk. Only a disk byte budget refuses a change, and
    # coverage says so.
    EXEC_CAPACITY = HOT_COUNT  # a count cap only: the hunt's memory budget sizes it in bytes
    HOT = HOT_COUNT  # a count cap only: the hunt's memory budget sizes it in bytes
    TRIM_EVERY = 10_000

    def __init__(self):
        super().__init__()
        self._seen = RecentIds()        # bounded re-read guard
        self._staged = RecentIds()      # bounded re-stage guard
        self._pending: list[TypedEvent] = []
        self.load = lambda ids: []
        self.changes = SpillList(self, "persistence_changes", self.HOT)
        # (time, parent pid, executable, boot) per (host, pid): the most recent in memory, the rest on disk
        self.execs = ExecHistory(self.EXEC_CAPACITY, 2**62, self, "persistence_execs")
        self._alone: list[Match] = []   # changes published on their own (the budget refused holding them)

    def drain_staged(self) -> list[TypedEvent]:
        out, self._pending = self._pending, []
        return out

    def retained_events(self) -> list[TypedEvent]:
        return []

    def consume(self, events):
        fresh = [e for e in events if e.family in self.families and e.id not in self._seen]
        self._batch = events
        for event in sorted(fresh, key=lambda e: (e.ts, e.id)):
            self._seen.add(event.id)
            if event.family == "process_exec":
                self._exec(event)
            else:
                self._change(event)
        self.changes.trim()
        self.execs.trim()
        self._batch = None
        out, self._alone = self._alone, []
        return out

    def _exec(self, event: TypedEvent) -> None:
        """Process lineage only: (time, parent pid, kernel-recorded executable, boot id) per process id."""
        pid, exe = event.get("process.pid"), event.get("process.executable")
        if isinstance(pid, int) and exe:
            self.execs.add((event.host or "", pid), (event.ts.timestamp(), event.get("process.ppid"), str(exe),
                                                     boot_of(event)))

    def _change(self, event: TypedEvent) -> None:
        path, uid = event.get("file.path"), _str(event.get("process.uid"))
        if event.get("file.change") in ("delete", "rename_source"):
            self.evaluated += 1                 # removing or moving a file away installs nothing, whatever the path
            return
        if not path or uid is None:
            self.missing_required += 1
            return
        location = persistence_location(str(path))
        if location is None:
            self.evaluated += 1
            return
        change = event.get("file.change")
        if change is None:
            self.missing_required += 1        # in a persistence location, but whether it was a write is unknown
            return
        self.evaluated += 1
        if change not in _INSTALLING:
            return
        user = event.get("process.user")
        change = _Change(
            ts=event.ts.timestamp(), event_id=event.id, host=event.host or "", path=str(path), change=str(change),
            location=location[0], description=location[1], technique=location[2], uid=uid,
            account=str(user or f"uid {uid}"), web=user in WEB_SERVICE_USERS,
            per_account=location[3], own=location[3] and _str(event.get("file.owner.id")) == uid,
            setuid=uid != "0" and _str(event.get("process.euid")) == "0",
            exe=str(event.get("process.executable") or ""), pid=event.get("process.pid"),
            ppid=event.get("process.ppid"), auid=_str(event.get("process.auid")), tty=_str(event.get("process.tty")),
            boot=boot_of(event),
            outcome=event.outcome)
        if not self.changes.append(change):
            # a write to a persistence location is a finding by itself: published now, on its own
            self.note_limit("changes_alone", "the persistence-location changes' disk budget is spent; later changes "
                                             "are published as they are read, not grouped per process")
            load, self.load = self.load, lambda ids: [event]
            try:
                add_unheld(self._alone, alone(self._single(change), self, event))
            finally:
                self.load = load
            return
        if event.id not in self._staged:
            self._staged.add(event.id)
            self._pending.append(event)

    # ---------------------------------------------------------------- finalize
    def _manager(self, change: _Change) -> str | None:
        """The package manager in the writer's kernel-recorded lineage (its own executable, then parents)."""
        exe, ppid, ts, boot = change.exe, change.ppid, change.ts, change.boot
        for _ in range(LINEAGE_DEPTH):
            name = posixpath.basename(exe)
            if name in PACKAGE_MANAGERS and exe.startswith(_SYSTEM_EXE_DIRS):
                return name
            if not isinstance(ppid, int) or ppid <= 1:
                return None
            parent = _latest(self.execs.get((change.host, ppid), touch=True)
                             or self.execs.store.peek((change.host, ppid), []), ts, boot)
            if parent is None:
                return None
            ts, ppid, exe, parent_boot = parent
            boot = boot if boot is not None else parent_boot
        return None

    def _events(self, ids: list[str]) -> dict[str, TypedEvent]:
        unique = sorted(set(ids))
        loaded = self.load(unique)
        if len(loaded) != len(unique):
            raise StageMissing(f"{self.id}: {len(unique) - len(loaded)} cited event(s) absent from the stage")
        return {event.id: event for event in loaded}

    def finalize(self):
        groups = KeyedStore(self, "persistence_groups", self.HOT)          # group key -> [_Change]
        for i, change in enumerate(self.changes):
            # Package activity is batched per (host, manager). Anything else is one finding per writing process
            # (host, uid, pid) and directory, so one editor run (file, swap and backup files) is one finding; without
            # a pid it is one finding per file. Every file is named and its first record cited.
            key = self._key(change)
            need(groups.setdefault(key, list), self, "the persistence change grouping").append(change)
            if i % self.TRIM_EVERY == self.TRIM_EVERY - 1:
                groups.trim()
                self.execs.trim()
        # one process's records whose boot is not recorded stay with it unless the records show a second boot
        keys = groups.keys()
        merged = {**{k: [k] for k in keys if k[0] != "account"},
                  **merge_unknown_boot({k: [k] for k in keys if k[0] == "account"}, 6)}
        out = []
        for key, parts in merged.items():               # one merged group read at a time
            items = [change for part in parts for change in groups.peek(part)]
            for final, run in self._split_runs({key: items}).items():
                run = sorted(run, key=lambda c: (c.ts, c.event_id))
                out.append((tuple(str(part) for part in final),
                            self._package_finding(final, run) if final[0] == "package" else self._finding(final, run)))
        groups.clear()
        return [match for _key, match in sorted(out, key=lambda item: item[0])]

    def _key(self, change: _Change) -> tuple:
        """The finding a change belongs to: package activity per (host, manager); anything else per writing
        process and directory (per file without a pid)."""
        manager = self._manager(change) if change.uid == "0" else None
        if manager:
            return ("package", change.host, manager)
        if isinstance(change.pid, int):
            return ("account", change.host, posixpath.dirname(change.path), change.uid, change.pid, change.exe,
                    change.boot)
        return ("account", change.host, change.path, change.uid, None, change.exe, change.boot)

    def _single(self, change: _Change) -> Match:
        """The finding of one change on its own."""
        ((final, run),) = self._split_runs({self._key(change): [change]}).items()
        return self._package_finding(final, run) if final[0] == "package" else self._finding(final, run)

    def finalize_fallback(self, reason: str) -> list[Match]:
        """Every held change on its own (grouping needed disk)."""
        out = []
        try:
            for change in self.changes:
                m = self._single(change)
                m.group_key += f"|alone:{change.event_id}"
                m.notes.append(f"published on its own: grouping per process needed disk ({reason})")
                out.append(m)
        except StateExhausted:
            pass                                    # the list on disk cannot be read: what was read stands
        return out

    @staticmethod
    def _split_runs(groups: dict[tuple, list[_Change]]) -> dict[tuple, list[_Change]]:
        """Split a per-process group where its records are more than PROCESS_GAP_SECONDS apart: a process id
        reused later (by another program run, possibly hours later) must not join an earlier run."""
        out: dict[tuple, list[_Change]] = {}
        for key, items in groups.items():
            if key[0] != "account" or key[4] is None:
                out[key] = items
                continue
            items = sorted(items, key=lambda c: (c.ts, c.event_id))
            run = [items[0]]
            for change in items[1:]:
                if change.ts - run[-1].ts > PROCESS_GAP_SECONDS:
                    out[(*key, run[0].ts)] = run
                    run = []
                run.append(change)
            out[(*key, run[0].ts)] = run
        return out

    def _cite(self, items: list[_Change]) -> tuple[list[TypedEvent], list]:
        """The first record of each distinct file, then the earliest others, up to the cap."""
        firsts = list({c.path: c.event_id for c in reversed(items)}.values())
        ordered = sorted(firsts, key=lambda i: next(n for n, c in enumerate(items) if c.event_id == i))
        ids = ordered[:CITE]
        ids += [c.event_id for c in items if c.event_id not in ids][:max(0, CITE - len(ids))]
        events = self._events(ids)
        cited = sorted(events.values(), key=lambda e: (e.ts, e.id))
        predicate = [pf(e, name) for e in cited for name in ("file.path", "file.change", "process.uid",
                                                             "process.executable") if e.has(name)]
        return cited, predicate

    @staticmethod
    def _changes_text(items: list[_Change]) -> str:
        counts: dict[tuple[str, str], int] = defaultdict(int)
        for c in items:
            counts[(c.change, c.path)] += 1
        parts = [f"{path}: {CHANGE_WORDS.get(change, change)}" + (f" ({n} records)" if n > 1 else "")
                 for (change, path), n in sorted(counts.items(), key=lambda kv: (kv[0][1], kv[0][0]))]
        text = "; ".join(parts[:CITE])
        return text + (f"; and {len(parts) - CITE} more" if len(parts) > CITE else "")

    def _finding(self, key: tuple, items: list[_Change]) -> Match:
        _kind, host, place, uid, pid = key[:5]
        first = items[0]
        files = sorted({c.path for c in items})
        cited, predicate = self._cite(items)
        root = uid == "0"
        executables = sorted({c.exe for c in items if c.exe})
        ok = [c for c in items if c.outcome != Outcome.failure]
        if root:
            who = "root (uid 0)"
        else:
            who = f"account '{first.account}'" + (f" (uid {uid})" if not first.account.startswith("uid ") else "")
            if any(c.web for c in items):
                who += ", a web-service account,"
        claim = (f"On {host}, {len(items)} kernel file-change record(s) {_span(items[0].ts, items[-1].ts)} show "
                 f"{who} acting on {first.description} ({self._changes_text(items)}), by "
                 f"{', '.join(executables) or 'an unrecorded executable'}")
        if root:
            claim += f" {_root_session(items)}"
        claim += f". The {_tally(cited, 'calls')}."
        if not ok:
            claim += " Every recorded call failed: these are attempts; no change was made by them."
        own_only = not root and all(c.own and not c.web for c in items)
        # only an account's own spool or startup entry can be read as a helper acting for the account
        setuid_only = not root and all(c.setuid and c.per_account and not c.web for c in items)
        setuid = sum(1 for c in items if c.setuid)
        if own_only:
            claim += (" The file is the account's own (a per-account location, owned by the account's uid), as "
                      "when an account manages its own crontab, keys or shell startup files.")
        elif setuid_only:
            claim += (" Every call ran with effective uid 0 through a setuid-root program on the account's own "
                      "per-account entry: crontab, at and chsh do this for an account, and an exploited setuid "
                      "program does too.")
        elif setuid:
            claim += f" {setuid} of the calls ran with effective uid 0 (a setuid-root program)."
        claim += (" The records show the system call on the file, not the content written; the files here are "
                  "read or run by the system (scheduler, init, the login path or the loader).")
        if len(files) > 1:
            claim += (f" The {len(files)} files were changed by process id {pid} running {first.exe} (records no more "
                      f"than {PROCESS_GAP_SECONDS} seconds apart).")
        if len(items) > len(cited):
            claim += f" {len(cited)} records are cited (the first of each file first)."
        # A non-root account changing what the system or another account acts on is high; a web-service account
        # always is. An account changing its own per-account files, or a setuid-root helper writing the account's
        # own spool entry, is a lead: that is also routine use.
        lane = "high" if (not root and ok and not own_only and not setuid_only) else "lead"
        notes = sorted({c.technique for c in items})
        if not root and not ok:
            notes.insert(0, "lane lowered: every recorded call failed (attempts)")
        elif own_only:
            notes.insert(0, "lead: the account acted only on its own per-account files")
        elif setuid_only:
            notes.insert(0, "lead: every call was a setuid-root program on the account's own per-account entry")
        confidence = "high" if ok and all(c.outcome == Outcome.success for c in ok) else "medium"
        match = Match(self.id, claim, self.claim_type, cited, predicate, cited[0].ts, self.severity, lane,
                      confidence, cited[0].entities(),
                      group_key=f"{host}|{uid}|{place}" + (f"|pid {pid}" if pid is not None else "")
                      + (f"|{first.exe}|{_iso(first.ts)}" if pid is not None else ""))
        match.notes = notes + [f"file: {path}" for path in files]
        return match

    def _package_finding(self, key: tuple, items: list[_Change]) -> Match:
        _kind, host, manager = key
        cited, predicate = self._cite(items)
        files = sorted({c.path for c in items})
        places = sorted({c.location for c in items})
        claim = (f"On {host}, {len(items)} kernel file-change record(s) on {len(files)} file(s) in "
                 f"{len(places)} location(s) ({', '.join(places)}) {_span(items[0].ts, items[-1].ts)} show package "
                 f"activity acting on files the system runs or reads "
                 f"({self._changes_text(items)}). Each writing process is '{manager}' or a descendant of it in the "
                 f"kernel-recorded process lineage (executables {', '.join(sorted({c.exe for c in items}))}). "
                 f"This is how package installs and upgrades change these files; a malicious or tampered package "
                 f"would change them the same way. The {_tally(cited, 'calls')}.")
        if len(items) > len(cited):
            claim += f" {len(cited)} records are cited (the first of each file first)."
        match = Match(self.id, claim, self.claim_type, cited, predicate, cited[0].ts, self.severity, "lead",
                      "high", cited[0].entities(), group_key=f"{host}|package:{manager}")
        match.notes = sorted({c.technique for c in items}) + [f"file: {path}" for path in files]
        return match


def _latest(entries, ts: float, boot: str | None = None):
    """The latest entry at or before `ts`, unless it is in a boot other than `boot` (its last element): a pid
    restarts at a reboot, so an earlier entry is in that other boot or an earlier one."""
    best = None
    for entry in entries:
        if entry[0] <= ts and (best is None or entry[0] >= best[0]):
            best = entry
    return None if best is not None and boots_conflict(boot, best[-1]) else best


def _root_session(items: list[_Change]) -> str:
    interactive = sorted({(c.auid, c.tty) for c in items if c.auid is not None and c.tty not in (None, "(none)")})
    login = sorted({c.auid for c in items if c.auid is not None and c.tty in (None, "(none)")})
    daemon = sum(1 for c in items if c.auid is None)
    parts = []
    if interactive:
        parts.append("in an interactive login session (" + ", ".join(
            f"audit login uid {auid} on terminal {tty}" for auid, tty in interactive) + ")")
    if login:
        parts.append(f"in a login session without a terminal (audit login uid {', '.join(login)})")
    if daemon:
        parts.append(f"outside any login session ({daemon} record(s); no audit login uid)")
    return "; ".join(parts)


KERNEL_FILE_PLAYBOOKS = [RootExecNonRootModifiableFile, PersistencePathChange]
