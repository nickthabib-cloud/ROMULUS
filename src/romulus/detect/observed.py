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
- A recorded parent is the parent at fork only with proof of the fork (`PidTable.ancestry_of`): the process's earliest
  record shows it running its parent's image, or is its exec under a parent recorded before it that is not a known
  subreaper. Otherwise it may have been adopted, and the lineage is unknown.
- A service start is proved only by the process's earliest record showing it, as a child of pid 1, running the service
  manager's own executable at its real system path (a child the service manager forked, recorded before its exec;
  systemd's spawn child connects to journald for its output, which a connect() rule records), or the manager's spawn
  helper. A parent of pid 1 alone never proves it, and a program merely named like the manager never does.
- A service the manager starts on request (a transient unit, `systemd-run`) has the same spawn record: who asked for
  it is not in these records.

Storage is one entry per change of (boot, image, parent, session) of a pid, never one per record; an entry keeps the
time of the latest record of its state. Only an entry that can begin a process (it does not continue the entry before
it) keeps its record for citation: a verdict cites only the earliest record of each process it names.
"""
from __future__ import annotations

import hashlib
import json
import zlib
from datetime import UTC, datetime
from typing import NamedTuple

from romulus.evidence.typed import RawRef, TypedEvent, event_id

# A parent change to pid 1 is a reparent of the same process only when the earlier parent was seen this recently.
# A daemonizing double fork reparents its child when the intermediate exits, milliseconds to seconds after the fork.
# A pid is reused only after the kernel's allocator wraps around the pid space: within this gap even the smallest
# default space (32768) needs thousands of forks per second, and the reused pid must also show the same executable.
# A longer gap starts another process, so its parent is the recorded one (pid 1, which proves nothing).
REPARENT_GAP = 10.0

# The service manager's executables at their real system paths (the kernel records the resolved path, so a copy or a
# link elsewhere never matches, and replacing these files needs root): its forked children run this image until they
# exec the service. systemd 255 and later exec its spawn helper first, which only the service manager can run (it
# reads the job from a descriptor the manager passes).
SERVICE_MANAGER_PATHS = frozenset({"/usr/lib/systemd/systemd", "/lib/systemd/systemd", "/sbin/init", "/usr/sbin/init"})
SPAWN_HELPER_PATHS = frozenset({"/usr/lib/systemd/systemd-executor", "/lib/systemd/systemd-executor"})
# Programs that commonly adopt orphaned descendants (subreapers, and the init of a container), at their installed
# paths: a process recorded under one of them is taken as its child only when its own earliest record shows it
# running that parent's image (forked, not adopted). Any other parent also needs proof of the fork (see the module
# notes), so this list only makes the rule stricter for these.
REAPER_PATHS = SERVICE_MANAGER_PATHS | frozenset({
    "/usr/bin/tini", "/usr/local/bin/tini", "/sbin/tini", "/tini", "/usr/bin/tini-static",
    "/usr/bin/docker-init", "/usr/local/bin/docker-init", "/sbin/docker-init", "/usr/libexec/docker/docker-init",
    "/usr/bin/dumb-init", "/usr/local/bin/dumb-init", "/usr/bin/catatonit", "/usr/libexec/catatonit/catatonit",
    "/usr/libexec/podman/catatonit", "/usr/bin/conmon", "/usr/libexec/podman/conmon", "/usr/bin/s6-svscan",
    "/command/s6-svscan", "/package/admin/s6/command/s6-svscan", "/usr/bin/runsvdir", "/sbin/runsvdir",
    "/sbin/upstart"})
REAPER_PREFIXES = ("/usr/bin/containerd-shim", "/usr/local/bin/containerd-shim")


def is_reaper(exe: str) -> bool:
    return exe in REAPER_PATHS or exe.startswith(REAPER_PREFIXES)


class Observed(NamedTuple):
    """One state of a process seen in its own audit SYSCALL records (not an exec)."""
    ts: float
    serial: int | None
    exe: str
    ppid: int | None
    session: int | None     # the audit session id; None when unset
    boot: str | None
    event_id: str           # the first record of this state, as the typed event a citation gives
    raw_id: str             # its SYSCALL record's native id
    last: float             # the latest record of this state so far
    cited: bool = True      # its record is held for citation
    user: str | None = None # account named by the observation, when the audit record carries one


def observation(event: TypedEvent) -> tuple[int, Observed, RawRef | None] | None:
    """(pid, state, its SYSCALL record's reference) from a typed event whose process fields come from an audit SYSCALL
    record, other than an exec (an exec record is the exec lineage's own). None when the record does not name the
    pid, parent and executable."""
    if event.family == "process_exec":
        return None
    field = event.fields.get("process.pid")
    suffix = ":event.original#auditd:SYSCALL.pid"
    if field is None or not field.origin.endswith(suffix):
        return None
    pid, ppid, exe = field.value, event.get("process.ppid"), event.get("process.executable")
    if not isinstance(pid, int) or isinstance(pid, bool) or not isinstance(ppid, int) or not exe:
        return None
    native = field.origin[:-len(suffix)]
    ref = next((r for r in event.raw if r.native_id == native), None)
    serial = event.get("audit.serial")
    serial = serial if isinstance(serial, int) and not isinstance(serial, bool) else None
    session = event.get("process.session_id")
    boot = event.get("host.boot.id")
    ts = event.ts.timestamp()
    user = event.get("process.user") or event.get("process.effective_user")
    return pid, Observed(ts, serial, str(exe), ppid, session if isinstance(session, int) else None,
                         None if boot in (None, "") else str(boot), event.id, native, ts,
                         user=str(user) if user not in (None, "") else None), ref


def observed_view_id(ref: RawRef) -> str:
    """The id of the process_observed view of a SYSCALL record (what a citation of its process gives)."""
    return event_id("process_observed", [ref])


def same_state(a, b) -> bool:
    """Whether two lineage entries (an exec record or an observation) show one state of a pid."""
    return (a.exe == b.exe and a.ppid == b.ppid and getattr(a, "session", None) == getattr(b, "session", None)
            and a.boot == b.boot)


def citation_pointer(
    event: TypedEvent,
    refs: list[RawRef],
    sources: dict[str, dict],
    kind: str,
    source_target: str | None = None,
) -> bytes | None:
    """A compact pointer to raw records that can rebuild one cited lineage view."""
    if not refs or any(ref.key not in sources for ref in refs):
        return None
    raw = [sources[ref.key] for ref in refs]
    encoded = json.dumps(raw, sort_keys=True, separators=(",", ":"), default=str).encode()
    boot = event.fields.get("host.boot.id")
    body = {
        "v": 1,
        "kind": kind,
        "target": source_target or refs[0].target,
        "records": [[ref.target, ref.native_id] for ref in refs],
        "raw_digest": hashlib.sha256(encoded).hexdigest(),
        "boot": [boot.value, boot.origin] if boot is not None else None,
    }
    return zlib.compress(json.dumps(body, sort_keys=True, separators=(",", ":")).encode(), 6)


def citation(
    event: TypedEvent,
    ref: RawRef | None,
    source: dict | None,
    source_target: str | None = None,
) -> bytes | None:
    """A compact source pointer for an observation, or None when its source record is unavailable."""
    if ref is not None and source is not None:
        return citation_pointer(event, [ref], {ref.key: source}, "observed", source_target)
    return None


def pointer_body(blob: bytes) -> dict | None:
    """Decode a lineage citation pointer; legacy inline citation blobs are not pointers."""
    body = json.loads(zlib.decompress(blob))
    return body if body.get("v") == 1 and body.get("kind") in {"observed", "exec"} else None


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


def step(entry) -> Step:
    return _observed_step(entry) if isinstance(entry, Observed) else _exec_step(entry)


def spawned(first: Step) -> bool:
    """Whether a process's earliest record proves that the service manager (pid 1) started it: the process, as a child
    of pid 1, running the manager's own executable at its system path (a child it forked, recorded before its exec),
    or the manager's spawn helper, which only the manager runs."""
    if first.ppid != 1:
        return False
    return first.exe in SPAWN_HELPER_PATHS or (first.kind == OBSERVED and first.exe in SERVICE_MANAGER_PATHS)


class ProcessView(NamedTuple):
    """A pid's process at an instant: its image there, the entries of the same process up to then (earliest first),
    and the observations the answer rests on (the process's earliest record, when it is one). `prior`: the image comes
    from a record at or before the instant (not only from a later one). `why` says why it is unknown (`image` None);
    both None when nothing of the pid is recorded."""
    image: Step | None
    span: list[Step]
    used: list[Observed]
    why: str | None = None
    prior: bool = True

    @property
    def first(self) -> Step:
        return self.span[0]

    @property
    def named(self) -> Step:
        """The record a claim names the process by: its latest exec up to the instant, else its earliest record."""
        return next((s for s in reversed(self.span) if s.kind == EXEC), self.span[0])


def _side(step: Step, ts: float, serial: int | None, domain, inclusive: bool) -> int:
    """-1 when the entry precedes the asked instant, 1 when it follows, 0 when their order is unknown (one instant,
    no comparable audit serials)."""
    if step.ts != ts:
        return -1 if step.ts < ts else 1
    if serial is not None and step.serial is not None and step.domain == domain:
        return -1 if step.serial < serial or (inclusive and step.serial == serial) else 1
    return 0


def _by_serial(step: Step, serial: int, inclusive: bool) -> int:
    return -1 if step.serial < serial or (inclusive and step.serial == serial) else 1


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
    continuous = abs(cur.ts - prev.last) <= REPARENT_GAP
    if prev.ppid == cur.ppid:
        if cur.kind == OBSERVED and prev.exe != cur.exe:
            return False
        if cur.ppid in (0, 1) or (prev.kind == OBSERVED and cur.kind == EXEC):
            return continuous
        return True
    if cur.ppid in (0, 1) and prev.ppid not in (0, 1) and continuous:
        return (cur.kind == OBSERVED and prev.exe == cur.exe) or (cur.kind == EXEC and prev.kind == OBSERVED)
    return False


def continues(prev, entry: Observed) -> bool:
    """Whether an observation continues the process of the lineage entry before it (so it cannot begin a process)."""
    return prev is not None and _joins(step(prev), _observed_step(entry))


def process_view(execs: list, observed: list[Observed], ts: float, serial: int | None, boot: str | None, *,
                 inclusive: bool, pid: int, host: str | None, order_domain=None) -> ProcessView:
    """The process holding `pid` at (`ts`, audit `serial`): from its execs and observations, never across a recorded
    boot other than `boot`. `inclusive` counts an entry at the asked serial (the asking record's own process);
    otherwise only entries strictly before count (a parent when its child was recorded).

    Records of one recorded boot that all carry audit serials are ordered by serial, which the kernel assigns in
    order, rather than by time (an exec's time is the shipper's and may lag its audit header). Otherwise they are
    ordered by time, then serial.

    The image is the latest exec at or before the instant, else an observation with no exec recorded between it and
    the instant (on either side). The nearest observations around the instant and that exec must agree, or the image
    is ambiguous (an unrecorded exec or a reused pid)."""
    if serial is None:
        domain = None
    else:
        domain = "audit" if order_domain is None else order_domain
    steps = [_exec_step(r) for r in execs] + [_observed_step(o) for o in observed]
    before, unsure, after = [], [], []
    in_boot = [s for s in steps if s.boot == boot] if boot is not None and serial is not None else []
    if in_boot and all(s.boot is not None for s in steps) and all(s.serial is not None and s.domain == "audit"
                                                                  for s in in_boot):
        # one boot, every record serially ordered: records of other boots are other processes
        for s in sorted(in_boot, key=lambda s: s.serial):
            (before if _by_serial(s, serial, inclusive) < 0 else after).append(s)
    else:
        for s in sorted(steps, key=lambda s: s.order):
            side = _side(s, ts, serial, domain, inclusive)
            (before if side < 0 else after if side > 0 else unsure).append(s)
        if boot is not None:
            # entries of another recorded boot are another process: everything before the latest such entry is in an
            # earlier boot, everything after the first such entry in a later one
            cut = next((i for i in range(len(before) - 1, -1, -1) if before[i].boot not in (None, boot)), None)
            if cut is not None:
                before = before[cut + 1:]
            end = next((i for i, s in enumerate(after) if s.boot not in (None, boot)), None)
            if end is not None:
                after = after[:end]
            unsure = [s for s in unsure if s.boot in (None, boot)]
    where = f"pid {pid} on {host}"
    if before:
        latest_ts = before[-1].ts
        tied = [entry for entry in before if entry.ts == latest_ts]
        serials = [entry.serial for entry in tied]
        domains = {entry.domain for entry in tied}
        if (None not in serials and None not in domains and len(domains) == 1
                and len(set(serials)) == len(serials)):
            latest = max(tied, key=lambda entry: entry.serial)
        elif len({(entry.exe, entry.ppid, entry.session, entry.boot) for entry in tied}) == 1:
            latest = max(tied, key=lambda entry: entry.order)
        else:
            when = datetime.fromtimestamp(latest_ts, UTC).isoformat()
            return ProcessView(None, [], [], f"lineage ambiguous at {when} for {where}: records at one instant "
                                             f"without comparable ordering show different states")
        # Keep the proven latest state last for the span walk below; the other entries share its instant.
        before = [entry for entry in before if entry is not latest] + [latest]
    prev_exec = next((s for s in reversed(before) if s.kind == EXEC), None)
    # the nearest observations on either side with no exec between them and the instant
    before_obs = before[-1] if before and before[-1].kind == OBSERVED else None
    after_obs = after[0] if after and after[0].kind == OBSERVED else None
    if prev_exec is not None and not prev_exec.exe:
        return ProcessView(None, [], [], f"the latest exec of {where} before that time names no executable")
    images = {s.exe for s in (prev_exec, before_obs, after_obs) if s is not None}
    if len(images) > 1:
        return ProcessView(None, [], [], f"lineage ambiguous for {where}: its records show different executables "
                                         f"({', '.join(sorted(images))}) with no exec recorded between them")
    image = before[-1] if before else after_obs
    prior = bool(before)
    if unsure:
        # entries at the asked instant whose order is unknown: harmless only when they show the same state
        reference = image or unsure[0]
        if any((s.exe, s.ppid, s.session, s.boot)
               != (reference.exe, reference.ppid, reference.session, reference.boot) for s in unsure):
            return ProcessView(None, [], [], f"lineage ambiguous for {where}: records at one instant without audit "
                                             f"serials to order them show different states")
        if image is None:
            image, prior = unsure[-1], True
    if image is None:
        return ProcessView(None, [], [], None)
    span = [image]
    if before and before[-1] is image:
        for i in range(len(before) - 2, -1, -1):
            if not _joins(before[i], span[0]):
                break
            span.insert(0, before[i])
    used = [span[0].entry] if span[0].kind == OBSERVED else []
    return ProcessView(image, span, used, None, prior)
