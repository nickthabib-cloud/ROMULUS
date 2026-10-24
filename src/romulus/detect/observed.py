"""Process states seen in a process's own audit SYSCALL records, for lineage.

An exec record says what a pid ran from that exec on. A process that forked and never exec'd (a daemon's worker, a
web server's child, a shell's subshell) has no exec record, but every system call the audit rules record for it
names its executable, its parent and its audit session at that instant. Those records teach the lineage what the
process ran and who its parent was, whether or not they become typed events of another family.

What an observation proves, and what it does not:
- It proves the pid's image and parent at that instant only. Between two records of a pid with no exec recorded
  between them the image is the same, unless the two records disagree: then an exec went unrecorded (the audit rule
  set has gaps) or the pid was reused, and the image there is ambiguous.
- The parent that counts is the parent at fork: the earliest parent recorded for the process. A process whose parent
  exits is reparented to pid 1 (or to its nearest ancestor subreaper), so a later parent of 1 shows a reparent, not
  who started it. A change of parent to 1 is joined to the earlier parent only when the same image is seen on both
  sides and the earlier state was seen within REPARENT_GAP seconds; anything else starts another process.
- A service start is proved only by the process's earliest record showing it running the service manager's own
  executable (a child the service manager forked, recorded before its exec; systemd's spawn child connects to
  journald for its output, which a connect() rule records), or by an exec of systemd's spawn helper. A parent of
  pid 1 alone never proves it.

Storage is one entry per change of (boot, image, parent, session) of a pid, never one per record; an entry keeps the
first record of its state (cited when a lineage names it) and the time of the latest.
"""
from __future__ import annotations

import json
import zlib
from typing import NamedTuple

from romulus.detect.base import basename
from romulus.evidence.typed import TypedEvent

# A parent change to pid 1 is a reparent of the same process only when the earlier parent was seen this recently.
# A daemonizing double fork reparents its child when the intermediate exits, milliseconds to seconds after the fork.
# A pid is reused only after the kernel's allocator wraps around the pid space: within this gap even the smallest
# default space (32768) needs thousands of forks per second, and the reused pid must also show the same executable.
# A longer gap starts another process, so its parent is the recorded one (pid 1, which proves nothing).
REPARENT_GAP = 10.0

# Executables of a service manager: their forked children run this image until they exec the service. systemd 255
# and later exec its spawn helper first, which only the service manager can run (it reads the job from a descriptor
# the manager passes).
SERVICE_MANAGER_IMAGES = frozenset({"systemd", "init"})
SPAWN_HELPERS = frozenset({"systemd-executor"})
# Programs that commonly adopt orphaned descendants (subreapers, and the init of a container): a process recorded
# under one of them may have been reparented there, so it is taken as its child only when its own earliest record
# shows it running that parent's image (it was forked, not adopted). Any program can make itself a subreaper; one
# with another name, above a web server, is the residual case this list does not cover.
REAPER_IMAGES = SERVICE_MANAGER_IMAGES | {"tini", "docker-init", "dumb-init", "catatonit", "conmon", "s6-svscan",
                                          "runsvdir", "upstart"}
REAPER_PREFIXES = ("containerd-shim",)


def is_reaper(exe: str) -> bool:
    name = basename(exe)
    return name in REAPER_IMAGES or name.startswith(REAPER_PREFIXES)


def is_service_manager(exe: str) -> bool:
    return basename(exe) in SERVICE_MANAGER_IMAGES


class Observed(NamedTuple):
    """One state of a process seen in its own audit SYSCALL records (not an exec)."""
    ts: float
    serial: int | None
    exe: str
    ppid: int | None
    session: int | None     # the audit session id; None when unset
    boot: str | None
    event_id: str           # the first record of this state, as a typed event
    raw_id: str             # its raw record's native id
    last: float             # the latest record of this state so far
    cited: bool = True      # its record is held for citation (False when the citation store refused it)


def observation(event: TypedEvent) -> tuple[int, Observed] | None:
    """(pid, state) from a typed event whose process fields come from an audit SYSCALL record, other than an exec
    (an exec record is the exec lineage's own). None when the record does not name the pid, parent and executable."""
    if event.family == "process_exec":
        return None
    field = event.fields.get("process.pid")
    if field is None or not field.origin.endswith("#auditd:SYSCALL.pid"):
        return None
    pid, ppid, exe = field.value, event.get("process.ppid"), event.get("process.executable")
    if not isinstance(pid, int) or isinstance(pid, bool) or not isinstance(ppid, int) or not exe:
        return None
    serial = event.get("audit.serial")
    serial = serial if isinstance(serial, int) and not isinstance(serial, bool) else None
    session = event.get("process.session_id")
    boot = event.get("host.boot.id")
    ts = event.ts.timestamp()
    return pid, Observed(ts, serial, str(exe), ppid, session if isinstance(session, int) else None,
                         None if boot in (None, "") else str(boot), event.id,
                         event.raw[0].native_id if event.raw else "", ts)


def same_state(a, b) -> bool:
    """Whether two lineage entries (an exec record or an observation) show one state of a pid."""
    return (a.exe == b.exe and a.ppid == b.ppid and _session(a) == _session(b) and a.boot == b.boot)


def _session(entry) -> int | None:
    return getattr(entry, "session", None)


def citation(event: TypedEvent, raw: dict[str, dict]) -> bytes:
    """An observation's record as its lineage keeps it for citation: the typed event and its raw copies."""
    return zlib.compress(json.dumps([event.model_dump_json(), raw], sort_keys=True).encode(), 6)


def uncite(blob: bytes) -> tuple[TypedEvent, dict[str, dict]]:
    body, raw = json.loads(zlib.decompress(blob))
    return TypedEvent.model_validate_json(body), raw


# ---- one pid's process at an instant ----------------------------------------------------------------------------
EXEC, OBSERVED = "exec", "observed"


class Step(NamedTuple):
    """One lineage entry of a pid, exec record or observation, in a form both share."""
    order: tuple
    kind: str
    exe: str
    ppid: int | None
    session: int | None
    boot: str | None
    ts: float
    serial: int | None
    domain: object
    last: float
    entry: object           # the ExecRecord or Observed


def _exec_step(record) -> Step:
    order = (record.ts, repr(record.order_domain), record.serial is None, record.serial or 0, record.event_id)
    return Step(order, EXEC, record.exe, record.ppid, getattr(record, "session", None), record.boot, record.ts,
                record.serial, record.order_domain, record.ts, record)


def _observed_step(entry: Observed) -> Step:
    domain = "audit" if entry.serial is not None else None
    order = (entry.ts, repr(domain), entry.serial is None, entry.serial or 0, entry.event_id)
    return Step(order, OBSERVED, entry.exe, entry.ppid, entry.session, entry.boot, entry.ts, entry.serial, domain,
                entry.last, entry)


class ProcessView(NamedTuple):
    """A pid's process at an instant: its image there, the entries of the same process up to then (earliest first),
    and the observations the answer rests on. `why` says why it is unknown (`image` None); both None when nothing
    of the pid is recorded."""
    image: Step | None
    span: list[Step]
    used: list[Observed]
    why: str | None = None

    @property
    def first(self) -> Step:
        return self.span[0]


def _side(step: Step, ts: float, serial: int | None, domain, inclusive: bool) -> int:
    """-1 when the entry precedes the asked instant, 1 when it follows, 0 when their order is unknown (one instant,
    no comparable audit serials)."""
    if step.ts != ts:
        return -1 if step.ts < ts else 1
    if serial is not None and step.serial is not None and step.domain == domain:
        return -1 if step.serial < serial or (inclusive and step.serial == serial) else 1
    return 0


def _joins(prev: Step, cur: Step) -> bool:
    """Whether an earlier entry of a pid is the same process as the next one (the same-process guard).

    An audit session, once set, never changes. An exec keeps the process's parent; an observation also keeps its
    image. Where the parent is pid 1 (shared by every service and every orphan), and from an image seen before an
    exec to that exec (a fork execs within moments), sharing a parent is evidence of one process only within
    REPARENT_GAP seconds. A recorded parent of pid 1 after another parent is a reparent within REPARENT_GAP seconds
    only: of a running image (the same image on both sides), or of a forked process recorded under its parent that
    then execs under pid 1 (a daemonizing double fork). An exec's state is timed by the exec itself: observations
    repeating it are not stored, so a reparent long after an exec starts another process (its parent then proves
    nothing)."""
    if prev.session is not None and cur.session != prev.session:
        return False
    continuous = cur.ts - prev.last <= REPARENT_GAP
    if prev.ppid == cur.ppid:
        if cur.kind == OBSERVED and prev.exe != cur.exe:
            return False
        if cur.ppid in (0, 1) or (prev.kind == OBSERVED and cur.kind == EXEC):
            return continuous
        return True
    if cur.ppid in (0, 1) and prev.ppid not in (0, 1) and continuous:
        return (cur.kind == OBSERVED and prev.exe == cur.exe) or (cur.kind == EXEC and prev.kind == OBSERVED)
    return False


def process_view(execs: list, observed: list[Observed], ts: float, serial: int | None, boot: str | None, *,
                 inclusive: bool, pid: int, host: str | None) -> ProcessView:
    """The process holding `pid` at (`ts`, audit `serial`): from its execs and observations, never across a recorded
    boot other than `boot`. `inclusive` counts an entry at the asked serial (the asking record's own process);
    otherwise only entries strictly before count (a parent when its child was recorded).

    The image is the latest exec at or before the instant, else an observation with no exec recorded between it and
    the instant (on either side). The nearest observations around the instant and that exec must agree, or the image
    is ambiguous (an unrecorded exec or a reused pid)."""
    domain = "audit" if serial is not None else None
    steps =sorted([_exec_step(r) for r in execs] + [_observed_step(o) for o in observed], key=lambda s: s.order)
    before, unsure, after = [], [], []
    for step in steps:
        side = _side(step, ts, serial, domain, inclusive)
        (before if side < 0 else after if side > 0 else unsure).append(step)
    if boot is not None:
        # entries of another recorded boot are another process: everything before the latest such entry is in an
        # earlier boot, everything after the first such entry in a later one
        cut = next((i for i in range(len(before) - 1, -1, -1) if before[i].boot not in (None, boot)), None)
        if cut is not None:
            before = before[cut + 1:]
        end = next((i for i, step in enumerate(after) if step.boot not in (None, boot)), None)
        if end is not None:
            after = after[:end]
        unsure = [step for step in unsure if step.boot in (None, boot)]
    where = f"pid {pid} on {host}"
    prev_exec = next((s for s in reversed(before) if s.kind == EXEC), None)
    next_exec = next((s for s in after if s.kind == EXEC), None)
    before_obs = next((s for s in reversed(before) if s.kind == OBSERVED
                       and (prev_exec is None or s.order > prev_exec.order)), None)
    after_obs = next((s for s in after if s.kind == OBSERVED and (next_exec is None or s.order < next_exec.order)),
                     None)
    if prev_exec is not None and not prev_exec.exe:
        return ProcessView(None, [], [], f"the latest exec of {where} before that time names no executable")
    images = {s.exe for s in (prev_exec, before_obs, after_obs) if s is not None}
    if len(images) > 1:
        return ProcessView(None, [], [], f"lineage ambiguous for {where}: its records show different executables "
                                         f"({', '.join(sorted(images))}) with no exec recorded between them")
    image = before[-1] if before else after_obs
    if unsure:
        # entries at the asked instant whose order is unknown: harmless only when they show the same state
        reference = image or unsure[0]
        if any(s.exe != reference.exe or s.ppid != reference.ppid for s in unsure):
            return ProcessView(None, [], [], f"lineage ambiguous for {where}: records at one instant without audit "
                                             f"serials to order them show different states")
        if image is None:
            image = unsure[-1]
    if image is None:
        return ProcessView(None, [], [], None)
    span = [image]
    if image is not after_obs:
        position = len(before) - 1 if before and before[-1] is image else None
        for i in range(position - 1, -1, -1) if position is not None else ():
            if not _joins(before[i], span[0]):
                break
            span.insert(0, before[i])
    used = [s.entry for s in span if s.kind == OBSERVED]
    if after_obs is not None and after_obs.entry not in used:
        used.append(after_obs.entry)
    return ProcessView(image, span, used)
