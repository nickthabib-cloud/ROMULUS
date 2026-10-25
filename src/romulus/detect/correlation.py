"""Host↔network playbooks: process sockets from auditd, and their joins to network-sensor records.

A join is a correlation, never an observation (spec section 1). Each side is an observed fact cited to
its own record; the link between them is inferred from typed address, port and time (and, on the network
side, from the sensor's own flow identity bounded by the flow's lifetime) and is worded as inferred.
A correlated item's lane never exceeds its strongest observed component, and drops to lead whenever the
same network records also match another host's or process's connect() call.
"""
from __future__ import annotations

import bisect
import heapq
import ipaddress
import json
import sqlite3
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import lru_cache
from typing import ClassVar, NamedTuple

from romulus.detect import netdef
from romulus.detect.base import Match, Playbook, basename, pf
from romulus.detect.bounded import (
    HOT_COUNT,
    HeldExamples,
    KeyedStore,
    RecentIds,
    Spill,
    StateExhausted,
    register_store,
    scalar,
    store_refuses,
)
from romulus.detect.citing import (
    BoundStage,
    Ends,
    Holds,
    Named,
    bound_note,
    cited_phrase,
    drained_holds,
    more,
)
from romulus.detect.host import (  # boot_of and boots_conflict are defined in host.py (no import cycle)
    INTERPRETERS,
    WEB_SERVICE_USERS,
    ExecLineage,
    ExecRecord,
    _audit_serial,
    add_unheld,
    alone,
    boot_of,
    boots_conflict,
    interpreter_name,
    is_internal,
)
from romulus.detect.observed import EXEC, OBSERVED, ProcessView, Step, is_reaper, spawned
from romulus.evidence.shellparse import SHELLS
from romulus.evidence.typed import Outcome, TypedEvent

RELAYS = {"nc", "ncat", "netcat", "socat"}
JOIN_BEFORE = 3.0        # seconds a sensor's flow start may precede the audit record
JOIN_AFTER = 5.0
FLOW_SLACK = 1.0         # seconds around a flow's lifetime within which same-flow records are pulled in
NETWORK_JOIN_FAMILIES = ("net_flow", "net_session", "net_alert", "http_tx", "tls_session", "ssh_session",
                         "file_transfer")
EXAMPLE_LIMIT = 20
ADDRESS_MIN_JOINS, ADDRESS_MIN_SHARE = 2, 0.8
LANE_RANK = {"high": 0, "lead": 1, "context": 2}
LANE_SEVERITY = {"high": "high", "lead": "medium", "context": "low"}
SOCKET_TYPE_CAVEAT = "auditd does not record the socket type; a connect() on a UDP socket sends no packets"


# Distinct addresses whose canonical form and scope are kept (least recently used dropped first): the detectors ask
# about the same addresses millions of times, and a cache miss only costs the parse again.
ADDRESS_CACHE = 65_536


def _canon_ip_uncached(text: str) -> str | None:
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


_canon_text = lru_cache(maxsize=ADDRESS_CACHE)(_canon_ip_uncached)


def canon_ip(value) -> str | None:
    return _canon_text(value if type(value) is str else str(value))


def routable_remote(ip: str | None) -> bool:
    if ip is None:
        return False
    a = ipaddress.ip_address(ip)
    return not (a.is_loopback or a.is_unspecified or a.is_multicast or a.is_link_local or a.is_reserved
                or (a.version == 4 and a == ipaddress.IPv4Address("255.255.255.255")))


def _external_uncached(ip: str | None) -> bool:
    return routable_remote(ip) and not is_internal(ipaddress.ip_address(ip))


# The answer depends on the installed internal-network definition: installing one clears this cache.
_external_text = lru_cache(maxsize=ADDRESS_CACHE)(_external_uncached)
netdef.on_install(_external_text.cache_clear)


def external(ip: str | None) -> bool:
    return _external_text(ip) if type(ip) is str else _external_uncached(ip)


def connect_phrase(e: TypedEvent) -> str:
    if e.outcome == Outcome.success:
        return "the call succeeded"
    if e.outcome == Outcome.failure:
        return "the call failed"
    if e.get("socket.exit") == "-115":
        return "the call started a non-blocking connection whose completion is not recorded"
    return "the call's outcome is unknown"


def process_interest(e: TypedEvent) -> tuple[str | None, str]:
    """Why a connecting process is notable (a noun phrase with its article), and the lane that reason
    supports. Identity comes from kernel-recorded SYSCALL fields only (exe, uid), never argv text."""
    exe = e.get("process.executable") or ""
    name = interpreter_name(basename(exe))
    user = e.get("process.user") or ""
    euser = e.get("process.effective_user") or ""
    account = user if user in WEB_SERVICE_USERS else euser
    if account in WEB_SERVICE_USERS and name in INTERPRETERS:
        return f"an interpreter '{name}' running as web-service account '{account}'", "high"
    if account in WEB_SERVICE_USERS:
        return f"a process running as web-service account '{account}'", "high"
    if name in SHELLS:
        return f"a shell '{name}'", "high"
    if name in RELAYS:
        return f"a network relay tool '{name}'", "high"
    if name in INTERPRETERS:
        return f"an interpreter '{name}'", "lead"
    return None, "lead"


def _process_words(e: TypedEvent, pids: list[int] | None = None, more: bool = False,
                   listed: int | None = None) -> str:
    """The program, the pid(s) of its group (the record's own when `pids` is None; the first `listed`, PIDS_LISTED by
    default, then a count; `more`: records came from further processes not counted) and the account."""
    listed = PIDS_LISTED if listed is None else listed
    if pids is None:
        pid = e.get("process.pid")
        pids = [pid] if pid is not None else []
    user = e.get("process.user") or e.get("process.uid")
    if not pids:
        who = "pid unknown"
    elif not listed:
        who = f"{len(pids)} pid(s) not listed" + (", and further processes not counted" if more else "")
    elif len(pids) == 1 and not more:
        who = f"pid {pids[0]}"
    else:
        who = (f"pids {', '.join(str(p) for p in pids[:listed])}"
               + (f" and {len(pids) - listed} more" if len(pids) > listed else "")
               + (", and further processes not counted" if more else ""))
    return f"'{e.get('process.executable')}' ({who}" + (f", user '{user}')" if user is not None else ")")


# A group's processes: the pids a claim lists (the rest are counted), the distinct processes it keeps with their
# earliest record (so the count is exact up to there), and the processes whose lineage its lane judgement walks.
PIDS_LISTED = 8
PROCESSES_HELD = 256
PROCESSES_JUDGED = 16


def process_key(e: TypedEvent) -> tuple | None:
    """A connecting process as a group tells processes apart: pid, parent, boot and audit session (a reused pid
    usually differs in one of them). None without a pid."""
    pid = e.get("process.pid")
    if not isinstance(pid, int) or isinstance(pid, bool):
        return None
    return pid, e.get("process.ppid"), boot_of(e), e.get("process.session_id")


def _order(ts: float, serial: int | None) -> tuple:
    return ts, serial is None, serial or 0


def note_process(procs: dict, key: tuple | None, ts: float, serial: int | None, event_id: str = "") -> bool:
    """Keep a process's earliest record (time, audit serial, event id) in a group's `procs`; False when the group
    already holds PROCESSES_HELD other processes (the record's process is then counted as not held)."""
    if key is None:
        return True
    held = procs.get(key)
    if held is None:
        if len(procs) >= PROCESSES_HELD:
            return False
        procs[key] = (ts, serial, event_id)
    elif _order(ts, serial) < _order(held[0], held[1]):
        procs[key] = (ts, serial, event_id)
    return True


def _process_order(key: tuple, ts: float, serial: int | None) -> tuple:
    """A process's place among a group's processes: its earliest record, then its key (as `judge_processes` orders)."""
    return _order(ts, serial), repr(key)


def hold_earliest(earliest: list, key: tuple, ts: float, serial: int | None, event: TypedEvent,
                  holds: Holds) -> None:
    """Hold for citation the earliest record of each of a group's PROCESSES_JUDGED earliest processes: the processes a
    claim lists by pid and whose lineage it judges. `earliest` is the group's sorted [(order, key, event id)]; a record
    that stops being one of them is released, so a group holds at most PROCESSES_JUDGED. Call it only for a record
    whose process `note_process` holds."""
    order = _process_order(key, ts, serial)
    for i, (held, held_key, held_id) in enumerate(earliest):
        if held_key == key:
            if order >= held:
                return
            holds.release(held_id)
            del earliest[i]
            break
    if len(earliest) >= PROCESSES_JUDGED and order >= earliest[-1][0]:
        return
    bisect.insort(earliest, (order, key, event.id), key=lambda item: item[0])
    holds.hold(event)
    if len(earliest) > PROCESSES_JUDGED:
        holds.release(earliest.pop()[2])


def listed_pids(procs: dict) -> list[int]:
    """A group's distinct pids, earliest process first (the first ones are those whose records are cited)."""
    ordered = sorted(procs.items(), key=lambda item: _process_order(item[0], item[1][0], item[1][1]))
    return list(dict.fromkeys(key[0] for key, _value in ordered))


class Judged(NamedTuple):
    pid: int
    ancestry: Ancestry


def judge_processes(pids: PidTable, host: str | None, procs: dict, unheld: int
                    ) -> tuple[list[Judged], int, list[TypedEvent], dict[str, dict]]:
    """The lineage of a group's processes, each walked from its earliest record: the first PROCESSES_JUDGED by
    time. Returns (judged, processes not judged, the observed records the named lineages rest on, their raw copies).
    A lineage whose records cannot be read back for citation is unknown. The caller cites each judged process's
    earliest record (`judged_records`)."""
    ordered = sorted(procs.items(), key=lambda item: _process_order(item[0], item[1][0], item[1][1]))
    judged = [Judged(key[0], pids.ancestry_of(host, key[0], ts, key[2], serial))
              for key, (ts, serial, _event_id) in ordered[:PROCESSES_JUDGED]]
    unjudged = len(ordered) - len(judged) + (1 if unheld else 0)
    wanted = list(dict.fromkeys(i for j in judged for i in (*j.ancestry.cites, *j.ancestry.execs)))
    found, raw = pids.execs.cited(wanted)
    out, cited = [], {}
    for item in judged:
        ancestry = item.ancestry
        if ancestry.verdict != "unknown" and any(i not in found for i in ancestry.cites):
            ancestry = ancestry._replace(verdict="unknown", why="a record this lineage rests on could not be read "
                                                                "back for citation")
        # every record the walk named is cited, for an unknown lineage too (its reason names what it read); an exec
        # record the store did not keep is named by its native id only (lineage_notes says so)
        cited.update((i, found[i]) for i in (*ancestry.cites, *ancestry.execs) if i in found)
        out.append(Judged(item.pid, ancestry._replace(execs=tuple(i for i in ancestry.execs if i not in found))))
    raws = {r.key: raw[r.key] for event in cited.values() for r in event.raw if r.key in raw}
    return out, unjudged, list(cited.values()), raws


def judged_records(procs: dict) -> list[str]:
    """The event ids of the earliest records of the processes `judge_processes` judges (in its order)."""
    ordered = sorted(procs.items(), key=lambda item: _process_order(item[0], item[1][0], item[1][1]))
    return [value[2] for _key, value in ordered[:PROCESSES_JUDGED] if value[2]]


def _verdict_words(item: Judged, alone: bool) -> str:
    ancestry = item.ancestry
    subject, owner = ("It", "Its") if alone else (f"pid {item.pid}", f"pid {item.pid}'s")
    if ancestry.verdict == "web_server":
        web = ancestry.chain[-1]
        if web.level == 0:
            return f"{subject} is, or was forked from, the web server '{web.exe}'"
        return f"{owner} ancestry includes the web server '{web.exe}'"
    if ancestry.verdict == "service_manager":
        return f"{owner} ancestry reaches the service manager with no web server"
    return f"{owner} ancestry is not fully recorded in the window"


def lineage_sentence(judged: list[Judged], unjudged: int) -> str:
    """The claim's sentence on the group's lineage, per process when there are several."""
    if not judged:
        return (" The connecting process's pid is not recorded, so its ancestry is unknown." if not unjudged else
                f" The ancestry of its {unjudged} process(es) was not judged.")
    if len(judged) == 1 and not unjudged:
        return f" {_verdict_words(judged[0], True)}."
    text = " Ancestry, per process: " + "; ".join(_verdict_words(item, False) for item in judged) + "."
    if unjudged:
        text += (f" {unjudged} further process(es) were not judged (the lineage of the first {len(judged)} by time "
                 f"was).")
    return text


def lineage_notes(judged: list[Judged]) -> list[str]:
    """Why each process's lineage is unknown, the chain each named lineage rests on, and the exec records it names that
    were not kept for citation (`judge_processes` leaves only those in `execs`)."""
    notes = []
    for item in judged:
        ancestry = item.ancestry
        if ancestry.execs:
            notes.append(f"lineage of pid {item.pid}: {len(ancestry.execs)} exec record(s) it reads were not kept for "
                         f"citation; the chain names them by native id")
        if ancestry.verdict == "unknown":
            notes.append(f"lineage of pid {item.pid} not established: {ancestry.why}")
        elif ancestry.verdict == "web_server":
            notes.append(f"lineage of pid {item.pid}: " + " <- ".join(link.words() for link in ancestry.chain))
    return notes


WEB_SERVER_PREFIXES = ("apache2", "httpd", "nginx", "lighttpd", "php-fpm", "php-cgi", "uwsgi", "gunicorn", "caddy")
LINEAGE_DEPTH = 6
# The families whose records teach a rule's process lineage: exec records, and the process state any other audit
# SYSCALL record shows (`romulus.detect.observed`).
LINEAGE_FAMILIES = ("process_exec", "process_observed", "net_socket", "file_change")
# What the selection cards of the rules that judge lineage say about it.
LINEAGE_LANES = (
    f"lineage only lowers: a web-service group goes to lead when every one of its processes (at most "
    f"{PROCESSES_JUDGED}, each walked from its earliest call through the parent each process had when it was "
    "forked) is proved to descend from a start by the service manager with no web server in between; a parent of "
    "pid 1, a subreaper, or a program merely named like the service manager never proves that, and any unknown, "
    "unjudged or uncitable lineage keeps the lane. Residual: a unit started on request (systemd-run, a transient "
    "unit) by an account allowed to start one has the same spawn record as a configured service, and is lowered "
    "like one; who asked for it is in the journal, not in these records. Residual: a process that made itself a "
    "subreaper above a web server, under a proven service start, adopts an orphan that then execs, and the web "
    "server between them is not seen")
LINEAGE_TELEMETRY = (
    "lineage from process_exec and from the process state every other audit SYSCALL record shows (process_observed, "
    "net_socket, file_change: process.pid, process.ppid, process.executable, process.session_id, audit.serial, "
    "host.boot.id); present in the lab profile, where connect() is audited for every process (so systemd's spawn "
    "child, connecting to journald before its exec as a child of pid 1 running /usr/lib/systemd/systemd, proves a "
    "service start) and exec auditing covers euid 0 or uid<1000 only; the lab's audit records carry no unit name")
_UNBOUNDED = 2**62


def merge_unknown_boot(groups: dict[tuple, list], index: int) -> dict[tuple, list]:
    """Groups whose keys carry a boot id at `key[index]`. A group with an unrecorded boot (None) joins the group that
    differs from it only by a recorded boot when there is exactly one such group: nothing shows a second boot, so
    the records stay together as they did without boot identity. With two or more recorded boots it stays apart:
    it cannot be placed in either boot, so it is never merged."""
    known: dict[tuple, list[tuple]] = defaultdict(list)
    for key in groups:
        if key[index] is not None:
            known[key[:index] + key[index + 1:]].append(key)
    out: dict[tuple, list] = {}
    for key in sorted(groups, key=lambda k: tuple("" if part is None else str(part) for part in k)):
        if key[index] is None:
            others = known.get(key[:index] + key[index + 1:], [])
            if len(others) == 1:
                out.setdefault(others[0], []).extend(groups[key])
                continue
        out.setdefault(key, []).extend(groups[key])
    return out


class ChainLink(NamedTuple):
    """One process of an ancestry walk, as the claim and notes name it, with the record that shows it."""
    pid: int
    exe: str
    raw_id: str
    observed: bool          # an observed record (the process's own non-exec record, cited), not an exec record
    level: int              # 0: the asking process; 1: its parent at fork; ...
    start: bool = False     # the record proving the service manager started it
    ppid: int | None = None             # the parent the record shows

    def words(self) -> str:
        record = f"{'observed' if self.observed else 'exec'} record {self.raw_id}"
        if self.start:
            what = ("running the service manager's own executable as a child of pid 1, before its exec"
                    if self.observed else "exec of the service manager's spawn helper as a child of pid 1")
            return f"{self.exe} (pid {self.pid}, {what}, {record})"
        parent = f", parent pid {self.ppid}" if self.ppid is not None else ""
        return f"{self.exe} (pid {self.pid}{parent}, {record})"


class Ancestry(NamedTuple):
    """An ancestry walk (`PidTable.ancestry_of`): the verdict, the processes it named, the event ids of the observed
    records it rests on (cited with any claim that names them; the verdict needs them), why it is unknown, and the
    event ids of the exec records it named (cited when they were kept for citation; the verdict does not need the
    copy, as it reads the exec store itself)."""
    verdict: str            # "web_server" | "service_manager" | "unknown"
    chain: list[ChainLink]
    cites: list[str]
    why: str = ""
    execs: tuple = ()


def _link(pid: int, step: Step, level: int, *, start: bool = False) -> ChainLink:
    return ChainLink(pid, step.exe, step.entry.raw_id, step.kind == OBSERVED, level, start, step.ppid)


def _not_forked(child: Step | None, child_pid: int | None, pid: int, view: ProcessView) -> str | None:
    """Why pid `pid` (its process `view` when its child was first recorded) is not shown to be the parent at fork of
    the process below, whose earliest record is `child` (None: the walk began at this parent). A process whose parent
    exits is adopted by pid 1 or by its nearest subreaper, so a recorded parent proves the fork only when the child's
    earliest record shows it still running its parent's image (forked, not yet exec'd), or is its exec under a parent
    recorded before it that is not a known subreaper."""
    image = view.image.exe
    if child is None:
        return (f"pid {pid} ('{image}') adopts orphaned processes, and no record of its child shows it was forked "
                f"there" if is_reaper(image) else None)
    if child.kind == OBSERVED:
        if child.exe != image:
            return (f"the earliest record of pid {child_pid} shows it running '{child.exe}', not the image of its "
                    f"recorded parent pid {pid} ('{image}'): it may have been adopted by pid {pid} after its parent "
                    f"exited, so pid {pid} is not shown to be its parent at fork")
        return None
    if is_reaper(image):
        return (f"pid {pid} ('{image}') adopts orphaned processes, and the earliest record of pid {child_pid} is its "
                f"exec, so it may have been reparented to pid {pid}")
    if not view.prior:
        return (f"pid {pid} is recorded only after the earliest record of pid {child_pid}, so it is not shown to have "
                f"been its parent then")
    return None


class ExecImage(NamedTuple):
    """A pid's image at a moment (`PidTable.image`): the exec record, or why it is unknown."""
    record: ExecRecord | None
    why: str | None             # set only when execs exist but which one was the image cannot be decided
    at: float | None            # the instant of the execs that cannot be ordered


class PidTable:
    """Kernel-recorded exec history per (host, pid), for lineage questions about a socket's process: a view of an
    ExecLineage (the hunt's one exec store in a sweep, see `share_lineage`) over the exec records that name their
    executable, each read as `(exec_ts, exe, parent_pid, raw_id, boot)`; a pid's meaning at time t is its latest
    exec at or before t (pids are reused). A lookup in a recorded boot never returns an exec recorded in a
    different boot: the pid restarted at the reboot, and its exec in the new boot is not in the window. An exec or
    a lookup without a recorded boot is boot-blind (see `boots_conflict`)."""

    # A detector rule (`owner`) holds its most recently used processes in memory and the rest in its on-disk
    # spill, read back when a walk reaches them: every lookup is exact. Callers without an owner (an expansion
    # fetch, a baseline period) hold everything they were given in memory.
    CAPACITY = HOT_COUNT  # a count cap only: the hunt's memory budget sizes it in bytes

    def __init__(self, capacity: int | None = None, owner=None, observing: bool = False):
        # an observing table also keeps its exec records for citation: the lineages it judges name them
        self.execs = ExecLineage(owner, capacity if capacity is not None else _UNBOUNDED, observing=observing,
                                 citing=observing)
        self.observing = observing

    def add(
        self,
        e: TypedEvent,
        raw: dict[str, dict] | None = None,
        source_target: str | None = None,
    ) -> None:
        """Hold an exec record; with `observing`, also the process state any other audit SYSCALL record shows (its
        raw copies `raw` are kept for citation)."""
        if e.family == "process_exec":
            self.execs.observe(e, raw, source_target)
        elif self.observing:
            self.execs.observe_process(e, raw, source_target)

    def trim(self) -> None:
        """Move the least recently used processes beyond the capacity to disk (when a batch ends)."""
        self.execs.trim()

    def image(self, host: str, pid: int, ts: float, boot: str | None = None, *, strict: bool = False,
              serial: int | None = None, exclude: str | None = None, inclusive: bool = False) -> ExecImage:
        """The pid's image at (`ts`, audit `serial`) in `boot` (`ExecLineage.resolve`; `inclusive` for the process
        that made the asking record itself, strict-before by default for a parent at its child's exec). `why` is
        None when the record was found or no exec of the pid is recorded; when execs exist but which one was the
        image cannot be decided, it names the ambiguity and `at` is the instant of the unordered execs."""
        if host is None:
            return ExecImage(None, None, None)  # a record without a host is never joined
        latest, ambiguous_at = self.execs.resolve(host, pid, ts, strict=strict, where=_named, serial=serial,
                                                  exclude=exclude, inclusive=inclusive)
        if ambiguous_at is not None:
            when = datetime.fromtimestamp(ambiguous_at, UTC).isoformat()
            return ExecImage(None, f"lineage ambiguous at {when} for pid {pid} on {host}: execs of different "
                                   f"programs at one instant without audit serials to order them", ambiguous_at)
        # The latest exec of this pid before `ts` is in another boot: every earlier one is too (boots follow each
        # other in time), so this pid has no recorded exec in `boot` before `ts`.
        if latest is None or boots_conflict(boot, latest.boot):
            return ExecImage(None, None, None)
        return ExecImage(latest, None, None)

    def _record(self, host: str, pid: int, ts: float, boot: str | None = None, *, strict: bool = False,
                serial: int | None = None, exclude: str | None = None, inclusive: bool = False):
        """The pid's image at (`ts`, audit `serial`) as an ExecRecord, or None when unknown or ambiguous."""
        return self.image(host, pid, ts, boot, strict=strict, serial=serial, exclude=exclude,
                          inclusive=inclusive)[0]

    def _lookup(self, host: str, pid: int, ts: float, boot: str | None = None, *, strict: bool = False,
                serial: int | None = None, exclude: str | None = None, inclusive: bool = False):
        latest = self._record(host, pid, ts, boot, strict=strict, serial=serial, exclude=exclude,
                              inclusive=inclusive)
        return None if latest is None else (latest.ts, latest.exe, latest.ppid, latest.raw_id, latest.boot)

    def lookup(self, host: str, pid: int, ts: float, boot: str | None = None, serial: int | None = None,
               *, inclusive: bool = False):
        """The exec identity a PID had at (`ts`, audit `serial`) in `boot` (None when unknown or ambiguous):
        strictly before that serial (a parent at its child's exec), or with `inclusive` at or equal to it (the
        process of the asking record itself)."""
        return self._lookup(host, pid, ts, boot, serial=serial, inclusive=inclusive)

    def lookup_ordered(self, host: str, pid: int, ts: float, boot: str | None, serial: int | None):
        """The baseline extractors' parent lookup (`parent_at`): the parent's image at its child's (ts, serial)."""
        return self._lookup(host, pid, ts, boot, serial=serial)

    def exec_before(self, host: str, pid: int, ts: float, boot: str | None = None, serial: int | None = None,
                    exclude: str | None = None):
        """The exec identity a PID held before its own exec record `exclude` at (`ts`, `serial`) in `boot` — the
        program it ran before that exec replaced it (None when unknown or ambiguous: a #! chain without serials).
        Returns `(exec_ts, exe, parent_pid, raw_id, boot)` or None."""
        return self._lookup(host, pid, ts, boot, strict=True, serial=serial, exclude=exclude)

    def lineage_entries(self, host: str, ppid, ts: float, depth: int = LINEAGE_DEPTH, boot: str | None = None,
                        serial: int | None = None):
        """Walk up the recorded parent chain from `ppid` as of `ts` in `boot`. Returns a list of
        `(pid, exec_ts, exe, raw_id)`, nearest ancestor first, stopping at an ancestor whose exec is
        not in the window (so the chain never invents a link). A parent is in its child's boot, so an
        ancestor's recorded boot carries up the chain when the start had none."""
        entries = []
        pid = ppid
        for _ in range(depth):
            if not isinstance(pid, int) or pid in (0, 1):
                break
            record = self._record(host, pid, ts, boot, serial=serial)
            if record is None:
                break
            entries.append((pid, record.ts, record.exe, record.raw_id))
            pid, ts, serial = record.ppid, record.ts, record.serial
            boot = boot if boot is not None else record.boot
        return entries

    def ancestry(self, host: str, ppid, ts: float, boot: str | None = None,
                 serial: int | None = None) -> tuple[str, list[tuple[str, str]]]:
        """Walk up from a parent pid in `boot` (`ancestry_of` without the child's own records). Returns (verdict,
        [(exe, raw id)]). Without the child's records nothing shows that it was forked rather than adopted, so a
        service manager or subreaper parent, like a parent of pid 1, gives 'unknown'."""
        if not isinstance(ppid, int) or ppid in (0, 1):
            return "unknown", []
        found = self._walk(host, ppid, ts, boot, serial, inclusive=False, depth=1)
        return found.verdict, [(link.exe, link.raw_id) for link in found.chain]

    def ancestry_of(self, host: str | None, pid, ts: float, boot: str | None = None,
                    serial: int | None = None) -> Ancestry:
        """Walk up from the process that made a record at (`ts`, audit `serial`) in `boot`, through the parent each
        process had when it was forked (`romulus.detect.observed`). The verdict is 'web_server' when a web server's
        image is in the chain (the process itself before its exec counts), 'service_manager' when a process of the
        chain is proved to have been started by the service manager with no web server below it, and 'unknown'
        otherwise: a record not in the window, an ambiguous image, a parent of pid 1 or a subreaper that nothing
        shows was the parent at fork, a record not kept for citation, or a lineage store that refused records."""
        if host is None or not isinstance(pid, int) or isinstance(pid, bool):
            return Ancestry("unknown", [], [], "the record names no host and process id")
        return self._walk(host, pid, ts, boot, serial, inclusive=True, depth=0)

    def _walk(self, host: str, pid: int, ts: float, boot: str | None, serial: int | None, *, inclusive: bool,
              depth: int) -> Ancestry:
        execs: list[str] = []
        found = self._walk_steps(host, pid, ts, boot, serial, inclusive=inclusive, depth=depth, execs=execs)
        return found._replace(execs=tuple(execs))

    def _walk_steps(self, host: str, pid: int, ts: float, boot: str | None, serial: int | None, *, inclusive: bool,
                    depth: int, execs: list[str]) -> Ancestry:
        chain: list[ChainLink] = []
        cites: list[str] = []
        child: Step | None = None               # the earliest record of the process below (how it was started)
        child_pid = None
        # A step whose fork is not proved: the recorded parent is still an ancestor (orphans are adopted only by an
        # ancestor or pid 1), so a web server above it is in the ancestry, but processes between may be missing, so
        # no start by the service manager is proved through it.
        gap: str | None = None
        for level in range(depth, LINEAGE_DEPTH + 1):
            view = self.execs.view(host, pid, ts, serial, boot, inclusive=inclusive)
            if view.image is None:
                when = datetime.fromtimestamp(ts, UTC).isoformat()
                return Ancestry("unknown", chain, cites, view.why or (
                    f"no exec or other audit record of pid {pid} on {host} at or before {when} is in the window"))
            if any(not entry.cited for entry in view.used):
                return Ancestry("unknown", chain, cites, (
                    f"the earliest record of pid {pid} on {host}, which this lineage rests on, is not held for "
                    f"citation (the store of observed records had no room, or it arrived after a later record of the "
                    f"same process)"))
            if level and gap is None:
                gap = _not_forked(child, child_pid, pid, view)
            cites += [entry.event_id for entry in view.used if entry.event_id not in cites]
            named = view.named
            # the exec records the claim names the process by and reads its parent from
            for step in (named, view.first):
                if step.kind == EXEC and step.entry.event_id not in execs:
                    execs.append(step.entry.event_id)
            if level:
                chain.append(_link(pid, named, level))
            # a web server's image in the process's own records (an exec, or its cited earliest record: an image
            # seen in any other observation of the span is also one of these)
            web = next((s for s in reversed(view.span) if basename(s.exe).startswith(WEB_SERVER_PREFIXES)
                        and (s.kind == EXEC or s.entry.cited)), None)
            if web is not None:
                if web is not named or not level:
                    chain.append(_link(pid, web, level))
                if web.kind == EXEC and web.entry.event_id not in execs:
                    execs.append(web.entry.event_id)
                return Ancestry("web_server", chain, cites)
            first = view.first
            if spawned(first):
                if gap is not None:
                    return Ancestry("unknown", chain, cites, gap)
                if first is not named or not level:
                    chain.append(_link(pid, first, level, start=True))
                else:
                    chain[-1] = chain[-1]._replace(start=True)
                return self._started(chain, cites)
            parent = first.ppid
            if not isinstance(parent, int):
                return Ancestry("unknown", chain, cites, f"the earliest record of pid {pid} on {host} names no parent")
            if parent in (0, 1):
                when = datetime.fromtimestamp(first.ts, UTC).isoformat()
                return Ancestry("unknown", chain, cites, gap or (
                    f"the earliest record of pid {pid} on {host} ({when}) shows parent pid {parent}: it was started by "
                    f"the service manager or reparented to it after its parent exited, and no record shows which"))
            child, child_pid = first, pid
            pid, ts, serial, inclusive = parent, first.ts, first.serial, False
            boot = boot if boot is not None else first.boot
        return Ancestry("unknown", chain, cites, gap or f"the lineage is deeper than the {LINEAGE_DEPTH} levels walked")

    def _started(self, chain: list[ChainLink], cites: list[str]) -> Ancestry:
        """A service-manager verdict, unless a lineage store refused records in this hunt: then a record that would
        change it may be missing."""
        if self.execs.incomplete or self.execs.observed_incomplete:
            return Ancestry("unknown", chain, cites, "the lineage stores refused records in this hunt (their share of "
                                                     "the state budget was spent), so a missing record that would "
                                                     "change this lineage cannot be excluded")
        return Ancestry("service_manager", chain, cites)


def _named(record: ExecRecord) -> bool:
    return bool(record.exe)


def lineage_lane(reason: str | None, lane: str, judged: list[Judged], unjudged: int) -> tuple[str, list[str]]:
    """Lineage can only lower a lane. A group of web-service processes each of which provably descends from a
    service-manager start with no web server in between is a daemon of that account, not a request-driven child:
    lead. A process whose lineage is unknown, or that was not judged, keeps the lane, so missing records can never
    hide a web shell."""
    if (reason is None or "web-service account" not in reason or lane != "high" or not judged or unjudged
            or any(item.ancestry.verdict != "service_manager" for item in judged)):
        return lane, []
    return "lead", [(f"lane lowered to lead: audit records trace pid {item.pid} to a start by the service manager "
                     f"with no web server in between ("
                     + " <- ".join(link.words() for link in item.ancestry.chain)
                     + "); the start is proved by the service manager's spawn record, and a unit started on request "
                       "(for example with systemd-run by an account allowed to) has the same record")
                    for item in judged]


class InterpreterExternalConnection(Playbook):
    """Positive-only: the audit rule set's scope (syscalls, families, ports) is not visible in telemetry,
    so a missing connect record never proves a connection did not happen. One item per (host, program,
    account, port), listing every destination, so routine update traffic is one lead, not one per address."""
    state_slice = "strong"           # a strong-indicator rule (see Playbook.state_slice)
    id = "host.interpreter_external_connection"
    version = "7"
    title = ("Shell, interpreter, relay tool or web-service process made connect() calls to addresses outside the "
             "site's internal networks")
    kind = "aggregate"
    families = LINEAGE_FAMILIES
    context_families = ("process_observed", "file_change")     # its lineage only (exec records it always read)
    os_families = ("linux",)
    required_fields = ()
    assures_negative = False
    severity, lane = "high", "lead"
    attack = ("T1059", "T1071", "T1095")
    benign = ("package managers and update checks run from scripts", "monitoring or backup scripts calling out",
              "web applications and their daemons making approved outbound API calls",
              "name resolution: resolvers and address sorting call connect() on UDP sockets")
    next_checks = ("process_tree for the connecting process", "network records for the same destination and time",
                   "entity_timeline of the host around the connection",
                   ("whether this process or a child then executed a shell "
                    "(host.shell_spawned_by_connected_process), which would make this a reverse shell"))
    card: ClassVar[dict] = {
        "behavior": "a shell, interpreter or relay tool (kernel exe), or a process running as a web-service account "
                    "(uid or euid), made connect() calls to addresses outside the site's internal networks (port not 0)",
        "telemetry": "Linux auditd net_socket (socket.syscall connect, destination.ip/port from SOCKADDR, "
                     "process.executable, process.user/effective_user, process.pid, outcome); " + LINEAGE_TELEMETRY,
        "fidelity": "direct observation of each call and its outcome; the socket type is not recorded (a UDP connect "
                    "sends nothing); the lineage claim names the records it rests on, exec and observed ones cited; "
                    "the claim cites the calls bounding its span, the earliest call of each pid it lists and the first "
                    "call to each destination it names, and says how many calls are cited",
        "benign_and_cost": "package managers and update checks, monitoring and backup scripts, web applications' "
                           "approved API calls and daemons of the web account, resolvers' UDP connects; one item per "
                           "(host, program, account, port) listing every destination and pid",
        "query_cost": "none beyond the sweep: it reads the host partitions every host rule reads",
        "next_pivot": "the connecting process's tree and the network records for the same destination and time",
        "adds": "the outbound connection itself; host.shell_spawned_by_connected_process reports a shell under it, "
                "corr.process_network_link joins it to sensor records",
        "research_basis": "ATT&CK Enterprise 20.0 T1059, T1071, T1095; Linux reparenting of orphans to pid 1 or the "
                          "nearest subreaper (prctl(2) PR_SET_CHILD_SUBREAPER); systemd's spawn child running the "
                          "manager's image until it execs the service (systemd.exec(5))",
        "retrieval": "the sweep retrieves every record of the host datasets in each partition (dataset filter only), a "
                     "superset of the records this evaluator reads",
        "lanes": "high for a web-service account, a shell or a relay tool; lead for another interpreter; lead when "
                 "every call failed; " + LINEAGE_LANES,
    }

    # Per (host, program, account, port) of notable processes: counts, destinations and the first cited calls (as ids
    # once staged), in a keyed store: the HOT most recent groups in memory, the rest on disk, never forgotten. Besides
    # the first calls a group cites the calls that bound its span (held while they bound it), the earliest call of
    # each process it lists by pid (held while it is among the earliest PROCESSES_JUDGED) and the first call to each
    # destination it names: at most 2 + PROCESSES_JUDGED + DESTINATIONS_NAMED records beyond the first ones.
    staged = True
    HOT = HOT_COUNT  # a count cap only: the hunt's memory budget sizes it in bytes
    DESTINATIONS_NAMED = 8

    def __init__(self):
        super().__init__()
        self.pids = PidTable(PidTable.CAPACITY, owner=self, observing=True)
        self.groups = KeyedStore(self, "iec_groups", self.HOT)        # key -> [info, HeldExamples]
        self._pending: list[TypedEvent] = []
        self._fresh: list[HeldExamples] = []
        self.bounds = BoundStage()
        self.holds = Holds()
        self.load = lambda ids: []

    def drain_staged(self) -> list[TypedEvent]:
        out, self._pending = self._pending + self.bounds.drain() + self.holds.drain(), []
        for store in self._fresh:
            store.staged()
        self._fresh = []
        self.groups.trim()
        self.pids.trim()
        return out

    def drain_bounds(self) -> tuple[list[str], list[str]]:
        return drained_holds(self.bounds, self.holds)

    def _info(self, e: TypedEvent, reason: str, lane: str) -> dict:
        return {"count": 0, "dests": Counter(), "outcomes": Counter(), "first": e.ts, "last": e.ts,
                "reason": reason, "lane": lane, "procs": {}, "unheld": 0, "ends": Ends(), "earliest": [],
                "named": Named(self.DESTINATIONS_NAMED)}

    def consume(self, events):
        self._batch, out = events, []
        for e in events:
            if e.family in LINEAGE_FAMILIES:
                self.pids.add(e, self.raw_of(e), self.raw_target())
            if e.family != "net_socket" or e.get("socket.syscall") != "connect":
                continue
            if not e.has("process.executable") or not e.has("destination.ip"):
                self.missing_required += 1
                continue
            self.evaluated += 1
            ip, port = canon_ip(e.get("destination.ip")), e.get("destination.port")
            if not external(ip) or not port:          # port 0: a route probe, never a connection
                continue
            reason, lane = process_interest(e)
            if reason is None:
                continue
            key = f"{e.host}|{e.get('process.executable')}|{e.get('process.user')}|{port}"
            state = self.groups.setdefault(key, lambda e=e, reason=reason, lane=lane: [
                self._info(e, reason, lane), HeldExamples(EXAMPLE_LIMIT)])
            if state is None:
                # the call is a finding by itself: published now, on its own, instead of being refused
                self.note_limit("groups_alone", "the groups' disk budget is spent; calls of a new group are published "
                                                "one at a time")
                # judged when read, before the rest of the hunt's records: its lineage is not judged (never lowered)
                info = {**self._info(e, reason, lane), "count": 1, "dests": Counter({ip: 1}),
                        "outcomes": Counter({str(e.outcome): 1}), "unheld": 1}
                info["named"].offer(ip, e)
                add_unheld(out, alone(self._group_match(key, info, [e]), self, e))
                continue
            info, group = state
            info["count"] += 1
            info["dests"][ip] += 1
            info["outcomes"][str(e.outcome)] += 1
            info["first"], info["last"] = min(info["first"], e.ts), max(info["last"], e.ts)
            self.bounds.offer_at(key, info["ends"], e)
            process, ts, serial = process_key(e), e.ts.timestamp(), _audit_serial(e)
            if not note_process(info["procs"], process, ts, serial, e.id):
                info["unheld"] += 1
            elif process is not None:
                hold_earliest(info["earliest"], process, ts, serial, e, self.holds)
            kept = group.offer(e)
            if info["named"].offer(ip, e) or kept:
                self._pending.append(e)
            if kept:
                self._fresh.append(group)
        self._batch = None
        return out

    def finalize(self):
        out = []
        for key in sorted(self.groups.keys()):
            info, group = self.groups.peek(key)
            out.append(self._group_match(key, info, group.events(self.load)))
        return out

    def _group_match(self, key: str, info: dict, evs: list[TypedEvent]) -> Match:
        # the first calls, the calls bounding the span, the earliest call of each judged process, and the first call
        # to each named destination
        named = info["named"]
        have = {e.id for e in evs}
        extra = [i for i in dict.fromkeys([*info["ends"].ids(), *judged_records(info["procs"]), *named.ids.values()])
                 if i not in have]
        own = {e.id for e in evs}                      # the group's first calls: what the finding is about
        evs = sorted([*evs, *self._load(extra)], key=lambda x: (x.ts, x.id))
        e0 = evs[0]
        procs = info["procs"]
        judged, unjudged, lineage_events, raw = judge_processes(self.pids, e0.host, procs, info["unheld"])
        lane, notes = lineage_lane(info["reason"], info["lane"], judged, unjudged)
        notes += lineage_notes(judged)
        if lane == "high" and all(o == Outcome.failure for o in info["outcomes"]):
            lane = "lead"
            notes.append("lane lowered to lead: every connect() call failed")
        shown = sorted((ip for ip in info["dests"] if ip in named), key=lambda ip: (-info["dests"][ip], ip))
        dests = ", ".join(f"{ip} ({info['dests'][ip]})" for ip in shown) + more(len(shown), len(info["dests"]))
        outcomes = ", ".join(f"{n} {w}" for w, n in (
            ("succeeded", info["outcomes"].get(Outcome.success, 0)),
            ("failed", info["outcomes"].get(Outcome.failure, 0)),
            ("with unknown or in-progress outcome", info["outcomes"].get(Outcome.unknown, 0))) if n)
        port = e0.get("destination.port")
        pids = listed_pids(procs)
        who = _process_words(e0, pids, bool(info["unheld"])) if pids else _process_words(e0)
        bounded = set(info["ends"].ids()) <= {e.id for e in evs}
        claim = (f"auditd connect() records on {e0.host} show {who}, "
                 f"{info['reason']}, making {info['count']} connect() call(s) to {len(info['dests'])} address(es) "
                 f"outside the site's internal networks on port {port} ({info['first'].isoformat()} – "
                 f"{info['last'].isoformat()}): {dests}; {outcomes}."
                 + cited_phrase(len(evs), info["count"], bounded, "connect() records", "connect() record")
                 + f"{lineage_sentence(judged, unjudged)} {SOCKET_TYPE_CAVEAT[0].upper()}{SOCKET_TYPE_CAVEAT[1:]}.")
        preds = [pf(e0, "socket.syscall"), pf(e0, "process.executable"), pf(e0, "destination.port")]
        if e0.has("process.user"):
            preds.append(pf(e0, "process.user"))
        known = {e.id for e in evs}
        cited = evs + [e for e in lineage_events if e.id not in known]    # the observed records the lineage names
        m = Match(self.id, claim, self.claim_type, cited, preds, e0.ts, self.severity, lane, "high",
                  e0.entities(), group_key=key, context_ids={e.id for e in cited} - own)
        m.raw_copies.update(raw)
        m.notes.extend(notes)
        if lineage_events:
            m.notes.append(f"{len(lineage_events)} process record(s) (exec and observed) the named lineage rests on "
                           f"are cited")
        return m

    def _load(self, ids: list[str]) -> list[TypedEvent]:
        found = self.load(ids) if ids else []
        if len(found) != len(ids):
            raise StageMissing(f"{self.id}: {len(ids) - len(found)} cited event(s) absent from the stage")
        return found

    def release_state(self) -> None:
        self.bounds.clear()
        self.holds.clear()

    def retained_events(self) -> list[TypedEvent]:
        return []                               # staged on disk instead


# ---------------------------------------------------------------------------------------------
# correlation
# ---------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class Sock:
    id: str
    host: str
    ts: float
    ip: str
    port: int
    exe: str
    user: str
    pid: int | None
    outcome: str
    reason: str | None
    process_lane: str
    ppid: int | None = None
    boot: str | None = None
    serial: int | None = None
    session: int | None = None
    staged: int = 0             # kept on the stage for citation to the end (the group's first calls)

    @property
    def group(self) -> str:
        return f"{self.host}|{self.exe}|{self.user}|{self.ip}|{self.port}"

    @property
    def claimant(self) -> tuple[str, str, int | None]:
        return self.host, self.exe, self.pid


@dataclass(frozen=True)
class Net:
    id: str
    family: str
    observer: str
    start: float
    end: float | None
    src: str
    sport: int
    dst: str
    dport: int
    cid: str | None
    alert_sev: int | None
    alert_cat: str | None
    alert_sig: str | None
    conn: str = ""              # the connection's identity: transport and both endpoints, in either direction
    staged: int = 0             # kept on the stage for citation

    def local_side(self, ip: str, port: int) -> str | None:
        """The non-remote endpoint, if this record is one direction of a connection to ip:port."""
        if (self.dst, self.dport) == (ip, port):
            return self.src
        if (self.src, self.sport) == (ip, port):
            return self.dst
        return None


def connection_identity(transport, src: str, sport: int, dst: str, dport: int) -> str:
    """One connection's identity whichever sensor recorded it and whichever side it recorded first: the transport and
    the two endpoints in a fixed order (what a community id hashes). A sensor that wrote no community id, or a record
    type that carries none, still joins the same connection."""
    a, b = sorted([(src, sport), (dst, dport)], key=lambda end: (ip_sort(end[0]), end[1]))
    return f"{str(transport or '').lower()}|{a[0]}:{a[1]}|{b[0]}:{b[1]}"


def ip_sort(ip: str):
    try:
        address = ipaddress.ip_address(ip)
        return address.version, int(address)
    except ValueError:
        return 9, ip


def count_connections(rows) -> int:
    """Distinct connections among (identity, start, end) rows sorted by identity and start. Records of one identity
    are one connection while each starts within CONNECTION_GAP seconds of the latest end (or start) before it: a
    client cannot open the same 5-tuple again until the previous connection has left TIME_WAIT (60 s on Linux, twice
    the maximum segment lifetime elsewhere), while the records two sensors write of one connection differ by clock
    offsets and log-time starts of seconds."""
    count, current, reach = 0, None, 0.0
    for identity, start, end in rows:
        if identity != current or start > reach + CONNECTION_GAP:
            count += 1
            current, reach = identity, start
        reach = max(reach, end if end is not None else start, start)
    return count


class _SockGroup:
    """A (host, program, account, endpoint) group's calls as the sweep reads them: how many of its first calls are
    kept on the stage, the calls bounding its span (held while they bound it) and the earliest call of each of its
    PROCESSES_JUDGED earliest notable processes (held while they are)."""
    __slots__ = ("earliest", "ends", "kept")

    def __init__(self):
        self.kept = 0
        self.ends = Ends()
        self.earliest: list = []


def _claimant_key(claimant: tuple) -> str:
    return json.dumps(claimant, default=str)


def _epoch(value) -> float | None:
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError:
            return None
        return (parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)).timestamp()
    return None


def alert_lane(n: Net) -> str | None:
    """Exactly the lane SuricataAlertStack gives the same alert on its own; None when the alert lacks the
    severity that stack requires (it would not publish it either)."""
    if n.alert_cat == "Not Suspicious Traffic" or n.alert_sev == 3:
        return "context"
    if n.alert_sev is None:
        return None
    return "high" if n.alert_sev == 1 else "lead"


def _version(ip: str) -> int:
    return ipaddress.ip_address(ip).version


# Connection records two sensors (or one sensor's record types) wrote of one connection start within this many seconds
# of its latest record (see count_connections).
CONNECTION_GAP = 30.0
# Records of a connection to one service endpoint from one address kept on the stage for citation (and as many
# alerts), per sensor, once a connect() call to that endpoint has been read: a group cites at most EXAMPLE_LIMIT records
# (plus one more for each further sensor), all to its endpoint, from its host's address.
PARTNERS_PER_PAIR = EXAMPLE_LIMIT
# Before any connect() call to the endpoint has been read (a network target read before the host target, or traffic no
# call reaches), a pair's first record from each sensor is kept: a call read later can still join it. That is one
# record per pair and sensor, not one per connection; the stage's disk budget is what bounds it (the sweep stops
# staging citations when it is spent, and the rule then says its findings are not computed from them).
PARTNERS_UNMATCHED = 1
EPHEMERAL_FLOOR = 32768         # client ports start here on modern stacks (Linux 32768-60999, Windows 49152-65535)


class StageMissing(RuntimeError):
    """A cited event is absent from the stage: a defect, never a reason to drop a finding quietly."""


class ProcessNetworkLink(Playbook):
    """Join each IP connect() to network-sensor records of the same connection: records for the same
    remote endpoint (either direction) that start within the join window, plus records sharing their
    community ID inside the flow's own lifetime. Publishes when the joined records carry an IDS alert
    (the alert gets a process) or when the process meets the external-connection criteria (the process
    gets its network evidence).

    State: socket calls and network records are compact rows in the rule's private on-disk spill (one target is
    read whole before the next, so the two sides cannot be streamed against each other); the full events are
    staged. Finalize links them with SQL and builds each (host, program, account, endpoint) group by streaming its
    rows: memory holds a bounded sample of the group (its first cited calls and records, counts), and the group's
    distinct records sit in spill tables emptied when it is done. Only disk refuses a record: the rule's own byte
    budget for its rows, and the hunt's state budget (the sweep refuses later records once it is spent). Every write,
    finalize's join tables included, is charged to the hunt's budget; a finalize that would need disk below the
    stage volume's free-space reserve stops with StateExhausted, and its window cell says so.

    Attribution: a host's local address on a sensor (per IP version) is inferred from its unique joins.
    A record whose local address is established for another host is never linked. A record whose local
    address is not established for this host is linked but stated, and caps the lane at lead, as do
    multiple local addresses and records shared with another process."""
    id = "corr.process_network_link"
    version = "8"
    title = "Host process connect() calls linked to network-sensor records for the same connection (inferred)"
    kind = "aggregate"
    staged = True
    claim_type = "correlated_observation"
    families = LINEAGE_FAMILIES + NETWORK_JOIN_FAMILIES
    context_families = ("process_exec", "process_observed", "file_change")     # its lineage only
    os_families = ("linux",)
    required_fields = ()
    # a join that finds nothing proves nothing: sensors and audit rules each see only part of the traffic
    assures_negative = False
    severity, lane = "high", "lead"
    attack = ("T1071", "T1095", "T1571")
    benign = ("another host or process reaching the same endpoint at the same second (stated when seen)",
              "benign IDS signatures on routine traffic")
    next_checks = ("flow detail for the linked community IDs", "process_tree for the connecting process",
                   "peer activity for the remote address across hosts and sessions")
    card: ClassVar[dict] = {
        "behavior": "an IP connect() recorded by auditd and network-sensor records of the same connection (same remote "
                    "endpoint within seconds, or the same community ID inside the flow's lifetime), published when "
                    "the joined records carry an IDS alert or the process meets the external-connection criteria",
        "telemetry": "Linux auditd net_socket (destination.ip/port, process.executable, process.user, process.pid) "
                     "and sensor flow, session, alert, HTTP, TLS, SSH and file-transfer records (source/destination "
                     "ip and port, flow start/end, community_id, alert severity/category/signature); "
                     + LINEAGE_TELEMETRY,
        "fidelity": "each side directly observed; the link is inferred from address, port and time and worded as "
                    "inferred; the host's own address on a sensor is inferred from its unique joins. Connections are "
                    "counted by transport and both endpoints in either direction, records of one identity within "
                    f"{CONNECTION_GAP:.0f} s of each other being one connection, so a connection two sensors recorded "
                    "(with or without a community id) counts once. The claim cites the group's first calls, the "
                    "calls bounding its span, its judged processes' earliest calls and the records their lineage "
                    "names, and the first network records of the endpoint pair, and says how many of each are cited",
        "benign_and_cost": "another host or process reaching the same endpoint at the same second (stated, capped at "
                           "lead), benign IDS signatures on routine traffic; one item per (host, program, account, "
                           "endpoint)",
        "query_cost": "none beyond the sweep; the join runs on the rule's disk spill at finalize",
        "next_pivot": "flow detail for the linked community IDs and the connecting process's tree",
        "adds": "gives an IDS alert its process and a notable process its network evidence",
        "research_basis": "ATT&CK Enterprise 20.0 T1071, T1095, T1571; Community ID flow hashing; the lineage basis "
                          "of host.interpreter_external_connection",
        "retrieval": "the sweep retrieves every record of the host and network datasets in each partition, a superset "
                     "of the records this evaluator reads",
        "lanes": "never above its strongest observed component: the IDS alert's own lane, or the notable process's "
                 "(lead when every notable call failed); lead when the attribution is shared, ambiguous or not "
                 "established; " + LINEAGE_LANES,
    }
    HEARTBEAT_EVERY = 1000
    # Bytes of spilled rows (socket calls, network records and their endpoint index) after which a further record is
    # refused through the coverage ledger, counted at ROW_BYTES per row (about what a row takes on disk), so this is
    # about 100 million records; the join's own tables at finalize take a similar amount again. The spill file's real
    # growth is charged to the hunt's state budget.
    DISK_BUDGET = 16 * 2**30
    ROW_BYTES = 160
    JOIN_CHUNK = 50_000             # socket calls joined per statement at finalize
    holds_state = True

    def __init__(self):
        super().__init__()
        self._spill: Spill | None = None
        self._net_seq = 0
        self.spilled_bytes = 0
        self._seen = RecentIds()        # bounded re-read guard
        self._pending: list[TypedEvent] = []
        self.load = lambda ids: []
        self.heartbeat = lambda: None
        self._rows_account = None
        self._tables = False
        register_store(self, self)      # its rows are one store of the hunt's state budget
        # the lineage of the connecting processes, which can lower a web-service process's lane (never raise it)
        self.pids = PidTable(PidTable.CAPACITY, owner=self, observing=True)
        # What the stage keeps for citation, bounded by groups rather than records: each (host, program, account,
        # endpoint) group's first calls, the calls bounding its span and its earliest processes' first calls; and the
        # first records (and alerts) of each (service endpoint, client address) pair.
        self.sock_groups = KeyedStore(self, "pnl_sock_groups", HOT_COUNT)
        self.pairs = KeyedStore(self, "pnl_pairs", HOT_COUNT)
        self.endpoints = KeyedStore(self, "pnl_endpoints", HOT_COUNT)     # remote endpoints of the calls read
        self.bounds = BoundStage()
        self.holds = Holds()

    def account(self):
        """The join rows' Account in the hunt's state budget."""
        if self._rows_account is None:
            self._rows_account = self.state_budget().account(f"{self.id}:rows")
        return self._rows_account

    def drain_staged(self) -> list[TypedEvent]:
        out, self._pending = self._pending + self.bounds.drain() + self.holds.drain(), []
        self.pids.trim()
        self.sock_groups.trim()
        self.pairs.trim()
        self.endpoints.trim()
        return out

    def drain_bounds(self) -> tuple[list[str], list[str]]:
        return drained_holds(self.bounds, self.holds)

    def _store(self) -> Spill:
        """The join's tables, on the rule's spill (which the lineage's stores may share)."""
        spill = self.spill()
        if not self._tables:
            spill.table("sock", "id, host, ts, ip, port, exe, user, pid, outcome, reason, lane, grp, claimant, "
                                "ppid, boot, serial, session, staged")
            spill.table("net", 'id, family, observer, start, "end", src, sport, dst, dport, cid, sev, cat, sig, '
                               "seq INTEGER PRIMARY KEY, conn, staged")
            spill.table("ep", "ip, port, start, net")
            self._tables = True
        return spill

    def close_spill(self) -> None:
        if self._spill is not None:
            self._spill.close()
            self._spill = None
        self._tables = False

    def release_state(self) -> None:
        self.bounds.clear()
        self.holds.clear()
        self.sock_groups.clear()
        self.pairs.clear()
        self.endpoints.clear()
        self.close_spill()

    def _room(self, rows: int) -> bool:
        """Count the rows against the disk budget. Once it, or this store's share of the hunt's state budget (its
        floor, once the shared headroom is spent), is spent the record is refused (not evaluated) instead: every
        record here needs new rows."""
        if store_refuses(self, self.account):
            self.evaluated -= 1
            self.refuse("state_disk", "the join's rows took their share of the hunt's state budget; later socket calls "
                                      "and network records are not evaluated")
            return False
        if self.spilled_bytes >= self.DISK_BUDGET:
            self.evaluated -= 1
            self.refuse("disk", f"the join's spilled rows reached their disk budget of {self.DISK_BUDGET:,} bytes; "
                                f"later socket calls and network records are not evaluated")
            return False
        self.spilled_bytes += rows * self.ROW_BYTES
        if self.budget is not None:
            self.budget.charge(self.account(), rows * self.ROW_BYTES)
        return True

    def _sock(self, e: TypedEvent) -> None:
        if e.get("socket.syscall") != "connect":
            return
        ip, port = canon_ip(e.get("destination.ip")), e.get("destination.port")
        if ip is None or port is None:
            self.missing_required += 1
            return
        if not routable_remote(ip) or not port:
            return
        reason, lane = process_interest(e) if external(ip) else (None, "lead")
        self.evaluated += 1
        key = process_key(e)
        s = Sock(e.id, e.host or "", e.ts.timestamp(), ip, int(port), str(e.get("process.executable")),
                 str(e.get("process.user")), scalar(e.get("process.pid")), str(e.outcome), reason, lane,
                 *((scalar(key[1]), key[2], _audit_serial(e), scalar(key[3])) if key else (None, None, None, None)))
        if not self._room(1):
            return
        staged = self._cite_sock(s, e, key)
        if self.endpoints.get((s.ip, s.port)) is None and not self.endpoints.put((s.ip, s.port), 1):
            self.note_limit("endpoints", "the called endpoints' disk budget is spent; network records to a new endpoint "
                                         "are only held for citation (a bounded number), and findings say how many "
                                         "are cited")
        row = (s.id, s.host, s.ts, s.ip, s.port, s.exe, s.user, s.pid, s.outcome, s.reason, s.process_lane, s.group,
               _claimant_key(s.claimant), s.ppid, s.boot, s.serial, s.session, staged)
        try:
            self._store().add("sock", row)
        except StateExhausted as exc:
            self._lost(exc)
            return

    def _cite_sock(self, s: Sock, e: TypedEvent, key: tuple | None) -> int:
        """Stage what the call's group may cite: its first EXAMPLE_LIMIT calls (kept; 1 is returned), the calls
        bounding its span and the earliest call of each of its earliest notable processes (held while they are)."""
        state = self.sock_groups.setdefault(s.group, _SockGroup)
        if state is None:
            # every call of a group the store cannot track is kept on the stage instead (its disk budget bounds them),
            # so the group's finding is still published with its calls cited
            self.note_limit("sock_groups", "the connecting groups' store took no new group; the calls of a later group "
                                           "are each kept for citation instead of its first ones, and its span is "
                                           "cited only through them")
            self._pending.append(e)
            return 1
        self.bounds.offer_at(s.group, state.ends, e)
        if s.reason is not None and key is not None:
            hold_earliest(state.earliest, key, s.ts, s.serial, e, self.holds)
        if state.kept >= EXAMPLE_LIMIT:
            return 0
        state.kept += 1
        self._pending.append(e)
        return 1

    def _net(self, e: TypedEvent) -> None:
        src, dst = canon_ip(e.get("source.ip")), canon_ip(e.get("destination.ip"))
        try:
            sport, dport = int(e.get("source.port")), int(e.get("destination.port"))
        except (TypeError, ValueError):
            self.missing_required += 1
            return
        if src is None or dst is None:
            self.missing_required += 1
            return
        self.evaluated += 1
        start = _epoch(e.get("flow.start")) or e.ts.timestamp()
        end = _epoch(e.get("flow.end"))
        sev = e.get("alert.severity")
        seq = self._net_seq + 1
        endpoints = [(dst, dport, start, seq)] + ([(src, sport, start, seq)] if (src, sport) != (dst, dport) else [])
        if not self._room(1 + len(endpoints)):
            return
        staged = self._cite_net(e, src, sport, dst, dport)
        row = (e.id, e.family, e.host or "", start, end, src, sport, dst, dport,
               scalar(e.get("network.community_id")) or None, sev if isinstance(sev, int) else None,
               scalar(e.get("alert.category")), scalar(e.get("alert.signature")), seq,
               connection_identity(e.get("network.transport"), src, sport, dst, dport), staged)
        self._net_seq = seq
        store = self._store()
        try:
            store.add("net", row)
            for endpoint in endpoints:
                store.add("ep", endpoint)
        except StateExhausted as exc:
            self._lost(exc)
            return

    def _cite_net(self, e: TypedEvent, src: str, sport: int, dst: str, dport: int) -> int:
        """Stage the record when it may be cited (1, else 0): when it is among its sensor's first PARTNERS_PER_PAIR
        records (or alerts) of its (service endpoint, client address) pair once a call to that endpoint has been read,
        or among the sensor's first PARTNERS_UNMATCHED of the pair before any call reached the endpoint. The service
        side is the destination, as a sensor records a connection it saw open; a record whose source port is the lower
        one, below the client range, is also offered as recorded from the server's side (a connection picked up
        mid-stream)."""
        alert = e.family == "net_alert"
        pairs = [(dst, dport, src)]
        if sport < dport and sport < EPHEMERAL_FLOOR:
            pairs.append((src, sport, dst))
        staged = 0
        for pair in pairs:
            count = self.pairs.setdefault((*pair, alert, e.host or ""), lambda: [0])
            if count is None:
                self.note_limit("pairs", "the endpoint pairs' disk budget is spent; a new pair's records are not kept "
                                         "for citation, and findings say how many are cited")
                continue
            matched = self.endpoints.get(pair[:2]) is not None
            if count[0] < (PARTNERS_PER_PAIR if matched else PARTNERS_UNMATCHED):
                count[0] += 1
                staged = 1
        if staged:
            self._pending.append(e)
        return staged

    def _lost(self, exc: StateExhausted) -> None:
        """A batch of rows could not be written (the stage volume is at its reserve): this record is refused, and
        finalize, which needs every row, says so."""
        self.evaluated -= 1
        self.refuse("state_disk", f"a write to the stage volume failed ({exc}); later socket calls and network "
                                  f"records are not evaluated")

    def consume(self, events):
        for e in events:
            if e.family in LINEAGE_FAMILIES:
                self.pids.add(e, self.raw_of(e), self.raw_target())
            if e.id in self._seen:
                continue                      # re-reading a partition must not count a record twice
            if e.family == "net_socket":
                self._seen.add(e.id)
                self._sock(e)
            elif e.family in NETWORK_JOIN_FAMILIES:
                self._seen.add(e.id)
                self._net(e)
        return []

    def retained_events(self) -> list[TypedEvent]:
        return []           # staged on disk instead

    # ---- join ------------------------------------------------------------------------------
    def _link(self, spill: Spill) -> None:
        """Every (socket call, network record) pair the join links: records for the call's remote endpoint (either
        direction) starting within the join window, then records sharing a directly linked record's community ID
        and endpoint pair inside its flow's lifetime (plus slack)."""
        db = spill.db
        spill.cap()                     # every statement below stops itself at the volume's headroom
        db.execute("CREATE INDEX ep_key ON ep (ip, port, start)")
        db.execute("CREATE INDEX net_conn ON net (conn)")
        spill.check()
        db.execute("CREATE TABLE link (sock INTEGER, net INTEGER, direct INTEGER, PRIMARY KEY (sock, net)) "
                   "WITHOUT ROWID")
        last = db.execute("SELECT COALESCE(MAX(rowid), 0) FROM sock").fetchone()[0]
        # in socket-call chunks, with the budget checked between them: one statement never runs the volume past
        # its reserve (the page cap stops it first) and a stop loses at most one chunk's work
        for low in range(0, last + 1, self.JOIN_CHUNK):
            db.execute("INSERT OR IGNORE INTO link SELECT s.rowid, ep.net, 1 FROM sock s JOIN ep ON ep.ip = s.ip "
                       "AND ep.port = s.port AND ep.start >= s.ts - ? AND ep.start <= s.ts + ? "
                       "WHERE s.rowid > ? AND s.rowid <= ?", (JOIN_BEFORE, JOIN_AFTER, low, low + self.JOIN_CHUNK))
            spill.check()
            self.heartbeat()
        for low in range(0, last + 1, self.JOIN_CHUNK):
            db.execute('INSERT OR IGNORE INTO link SELECT l.sock, m.seq, 0 FROM link l JOIN net d ON d.seq = l.net '
                       'JOIN net m ON m.conn = d.conn WHERE l.direct = 1 '
                       'AND l.sock > ? AND l.sock <= ? '
                       'AND m.start >= d.start - ? AND m.start <= COALESCE(d."end", d.start + ?) + ?',
                       (low, low + self.JOIN_CHUNK, FLOW_SLACK, JOIN_AFTER, FLOW_SLACK))
            spill.check()
            self.heartbeat()
        db.execute("CREATE INDEX link_net ON link (net)")
        spill.check()
        # how many distinct processes claim each linked record
        db.execute("CREATE TABLE nc (net INTEGER PRIMARY KEY, n INTEGER)")
        db.execute("INSERT INTO nc SELECT l.net, COUNT(DISTINCT s.claimant) FROM link l JOIN sock s "
                   "ON s.rowid = l.sock GROUP BY l.net")
        # the group being built: its distinct linked records (with the latest call's attribution status), the calls
        # that kept a link, and the records more than one process claims
        db.execute('CREATE TABLE gp (nid PRIMARY KEY, family, observer, local, conn, sig, status, start, "end")')
        db.execute("CREATE TABLE gs (sock INTEGER PRIMARY KEY)")
        db.execute("CREATE TABLE gsh (nid, seq INTEGER, PRIMARY KEY (nid, seq)) WITHOUT ROWID")
        db.commit()

    _ROWS = ('SELECT s.rowid, s.id, s.host, s.ts, s.ip, s.port, s.exe, s.user, s.pid, s.outcome, s.reason, s.lane, '
             's.grp, n.id, n.family, n.observer, n.start, n."end", n.src, n.sport, n.dst, n.dport, n.cid, n.sev, '
             'n.cat, n.sig, nc.n, n.seq, s.ppid, s.boot, s.serial, s.session, n.conn, n.staged, s.staged '
             'FROM link l JOIN sock s '
             'ON s.rowid = l.sock JOIN net n ON n.seq = l.net JOIN nc ON nc.net = l.net ')

    @staticmethod
    def _row(row) -> tuple[int, Sock, Net, int, int]:
        sock = Sock(row[1], row[2], row[3], row[4], row[5], row[6], row[7], row[8], row[9], row[10], row[11],
                    row[28], row[29], row[30], row[31], row[34])
        net = Net(row[13], row[14], row[15], row[16], row[17], row[18], row[19], row[20], row[21], row[22],
                  row[23], row[24], row[25], row[32], row[33])
        return row[0], sock, net, row[26], row[27]

    def _socket_rows(self, order: str):
        """The linked rows, one socket call at a time, in `order`: (call rowid, call, record, claimants, record seq)."""
        current, rows = None, []
        for i, row in enumerate(self._spill.execute(self._ROWS + order)):
            if i % (self.HEARTBEAT_EVERY * 10) == 0:
                self.heartbeat()
            sock_rowid, sock, net, claimed, seq = self._row(row)
            if sock_rowid != current and rows:
                yield rows
                rows = []
            current = sock_rowid
            rows.append((sock_rowid, sock, net, claimed, seq))
        if rows:
            yield rows

    def finalize(self):
        if self._spill is None or not self._tables:
            return []
        try:
            return self._finalize()
        except sqlite3.OperationalError as exc:
            raise self._spill.failed(exc) from exc

    def _finalize(self):
        self._spill.flush()
        self._link(self._spill)
        self._spill.check()
        # pass 1: each host's local address per (sensor, IP version), from calls whose records nobody else claims
        seen: dict[tuple[str, str, int], Counter] = defaultdict(Counter)
        for rows in self._socket_rows("ORDER BY l.sock, n.start, n.id"):
            s = rows[0][1]
            if any(claimed > 1 for _r, _s, _n, claimed, _q in rows):
                continue
            by_observer: dict[str, set] = defaultdict(set)
            for _r, _s, n, _c, _q in rows:
                by_observer[n.observer].add(n.local_side(s.ip, s.port))
            for observer, locals_ in by_observer.items():
                if len(locals_) == 1:
                    local = locals_.pop()
                    seen[(s.host, observer, _version(local))][local] += 1
        address: dict[tuple[str, str, int], tuple[str, int, int]] = {}
        for key, counts in seen.items():
            best, n = max(counts.items(), key=lambda kv: (kv[1], kv[0]))
            total = sum(counts.values())
            if n >= ADDRESS_MIN_JOINS and n / total >= ADDRESS_MIN_SHARE:
                address[key] = (best, n, total)
        owner: dict[tuple[str, str], set[str]] = defaultdict(set)      # (sensor, address) -> hosts
        for (host, observer, _v), (best, _n, _t) in address.items():
            owner[(observer, best)].add(host)
        # pass 2, one group at a time, streamed: never link a record whose local address another host owns; mark
        # unestablished ones
        out = []
        group: _Group | None = None
        for rows in self._socket_rows("ORDER BY s.grp, s.ts, s.id, l.sock, n.start, n.id"):
            sock_rowid, s = rows[0][0], rows[0][1]
            if group is None or s.group != group.key:
                if group is not None:
                    out += self._finish(group, address)
                    self._spill.check()
                state = self.sock_groups.peek(s.group, None)
                group = _Group(s.group, self._spill.db, state if state is not None else _SockGroup())
            kept = []
            for _r, _s, n, claimed, seq in rows:
                if claimed > 1:
                    group.shared(n.id, seq)
                local = n.local_side(s.ip, s.port)
                known = address.get((s.host, n.observer, _version(local)))
                if known and local == known[0]:
                    kept.append((n, local, "established"))
                elif owner.get((n.observer, local), set()) - {s.host}:
                    continue                              # positively another host's address on this sensor
                else:
                    kept.append((n, local, "differs" if known else "unestablished"))
            if kept:
                group.add(sock_rowid, s, kept)
        if group is not None:
            out += self._finish(group, address)
        return out

    def _finish(self, group: _Group, address) -> list[Match]:
        try:
            m = self._group_match(group, address) if group.socks else None
        finally:
            group.clear()
        return [m] if m is not None else []

    def _group_match(self, g: _Group, address) -> Match | None:
        db = self._spill.db
        components = []
        judged, unjudged, lineage_events, lineage_raw, lineage_lines = [], 0, [], {}, []
        # the processes whose lineage is judged: the group's notable processes with a linked call, walked from their
        # earliest linked call, each cited by a linked call of its own; a linked process with no call kept for
        # citation is left unjudged (that only keeps the lane)
        procs = {key: (ts, serial, g.proc_cites[key]) for key, (ts, serial, _event_id) in g.procs.items()
                 if key in g.proc_cites}
        if g.notable is not None:
            unheld = len(set(g.procs) - set(procs)) + g.unheld
            judged, unjudged, lineage_events, lineage_raw = judge_processes(self.pids, g.notable.host, procs, unheld)
            lane, lineage_lines = lineage_lane(g.notable.reason, g.notable.process_lane, judged, unjudged)
            lineage_lines += lineage_notes(judged)
            if g.notable_all_failed:
                lane = "lead"                       # every notable call failed: an attempt, not a connection
            components.append(lane)
        if g.alert_lane is not None:
            components.append(g.alert_lane)
        if not components:
            return None
        lane = min(components, key=LANE_RANK.__getitem__)
        s0 = g.first
        # other processes claiming the group's shared records: counted, and the first five with a call kept for
        # citation named (with that call cited)
        n_others, others = 0, []
        for host, exe, pid, cited_id in db.execute(
                "SELECT s.host, s.exe, s.pid, MIN(CASE WHEN s.staged = 1 THEN s.id END) FROM gsh JOIN gp "
                "ON gp.nid = gsh.nid JOIN link l ON l.net = gsh.seq JOIN sock s ON s.rowid = l.sock "
                "WHERE NOT EXISTS (SELECT 1 FROM gs JOIN sock t ON t.rowid = gs.sock WHERE t.host = s.host "
                "AND t.exe = s.exe AND t.pid IS s.pid) GROUP BY s.host, s.exe, s.pid"):
            n_others += 1
            if cited_id is not None:
                others = heapq.nsmallest(5, [*others, (host, exe, pid, cited_id)], key=str)
        locals_ = [local for (local,) in db.execute(
            "SELECT DISTINCT local FROM gp WHERE local IS NOT NULL ORDER BY local")]
        unestablished = [observer for (observer,) in db.execute(
            "SELECT DISTINCT observer FROM gp WHERE status = 'unestablished' ORDER BY observer")]
        differs = [local for (local,) in db.execute(
            "SELECT DISTINCT local FROM gp WHERE status = 'differs' AND local IS NOT NULL ORDER BY local")]
        caps = []
        if n_others:
            caps.append("shared")
        if len(locals_) > 1:
            caps.append("ambiguous")
        if unestablished or differs:
            caps.append("unestablished")
        if caps and lane == "high":
            lane = "lead"
        n_partners, n_flows, n_alerts = db.execute(
            "SELECT COUNT(*), TOTAL(family IN ('net_flow', 'net_session')), TOTAL(family = 'net_alert') "
            "FROM gp").fetchone()
        n_flows, n_alerts = int(n_flows), int(n_alerts)
        n_connections = count_connections(db.execute('SELECT conn, start, "end" FROM gp ORDER BY conn, start, nid'))
        observers = [observer for (observer,) in db.execute("SELECT DISTINCT observer FROM gp ORDER BY observer")]
        (n_sigs,) = db.execute("SELECT COUNT(DISTINCT sig) FROM gp WHERE family = 'net_alert'").fetchone()
        outcomes = g.outcomes

        # cited: the group's first kept calls, the calls bounding its span (when held), each judged process's
        # earliest call, the first records in citation order that are kept, and a call of each named other process
        bounds = g.ends.ids()
        held_bounds = [i for i in bounds if i in g.citable]
        sock_ids = list(dict.fromkeys([*held_bounds, *(s.id for s in g.socks), *judged_records(procs)]))
        partners = g.partners()
        partner_ids = [n.id for _k, n, _o in partners]
        ids = list(dict.fromkeys([*sock_ids, *partner_ids, *(o[3] for o in others)]))
        loaded = {e.id: e for e in self.load(ids)}
        missing = [i for i in ids if i not in loaded]
        if missing:
            raise StageMissing(f"{self.id}: {len(missing)} cited event(s) absent from the stage, e.g. {missing[0]}")
        cited = [loaded[i] for i in ids]
        first = loaded[g.socks[0].id] if g.socks else loaded[sock_ids[0]] if sock_ids else None
        if first is None:
            return None                             # nothing of the group could be cited (stated on coverage)
        sigs = sorted({str(n.alert_sig) for _k, n, _o in partners if n.family == "net_alert"})[:3]
        # the sensors named are those with a cited record; the others are counted
        cited_observers = sorted({n.observer for _k, n, _o in partners})
        per_observer = dict(db.execute("SELECT observer, COUNT(*) FROM gp GROUP BY observer").fetchall())
        uncited_observers = [o for o in observers if o not in cited_observers]
        sensors = ", ".join(cited_observers) + (
            f" (and {sum(per_observer.get(o, 0) for o in uncited_observers)} record(s) from "
            f"{len(uncited_observers)} other sensor(s), not cited)" if uncited_observers else "")
        unestablished_cited = [o for o in unestablished if o in cited_observers]
        outcome_words = ", ".join(f"{n} {w}" for w, n in (
            ("succeeded", outcomes.get(Outcome.success, 0)), ("failed", outcomes.get(Outcome.failure, 0)),
            ("with unknown or in-progress outcome", outcomes.get(Outcome.unknown, 0))) if n)
        # the group's own linked calls (another process's call cited for the shared records is not one of them)
        own_calls = [loaded[i] for i in sock_ids]
        cited_pids = list(dict.fromkeys(e.get("process.pid") for e in own_calls
                                        if isinstance(e.get("process.pid"), int)))
        pids = cited_pids + sorted(p for p in g.pids if p not in cited_pids)
        n_cited_socks = len(own_calls)
        n_cited_partners = len(partner_ids)
        span_note = bound_note(set(bounds) - set(held_bounds), g.ends, "these calls' interval")
        parts = [
            (f"Observed on {s0.host} (auditd): "
             f"{_process_words(first, pids, g.pids_more, listed=min(PIDS_LISTED, len(cited_pids)))} made "
             f"{g.n_socks} connect() call(s) to "
             f"{s0.ip} port {s0.port} that join network records "
             f"({datetime.fromtimestamp(s0.ts, UTC).isoformat()} – "
             f"{datetime.fromtimestamp(g.last_ts, UTC).isoformat()}); {outcome_words}. {SOCKET_TYPE_CAVEAT}."
             + span_note),
            f"Observed by network sensor(s) {sensors}: {n_flows} flow or session record(s) across "
            f"{n_connections} connection(s) to {s0.ip} port {s0.port} starting within seconds of those calls"
            + (f", with local address(es) {', '.join(locals_)}" if locals_ else "")
            + (f", and {n_alerts} IDS alert(s) on those connections"
               + (f", among them {'; '.join(f"'{sig}'" for sig in sigs)}" + more(len(sigs), n_sigs) if sigs else "")
               if n_alerts else "") + ".",
            "Of these, " + " and ".join(
                (f"all {total} {noun}" if total > 1 else f"the one {noun[:-1]}") if cited_n >= total
                else f"{cited_n} of the {total} {noun}"
                for cited_n, total, noun in ((n_cited_socks, g.n_socks, "connect() records"),
                                             (n_cited_partners, n_partners, "network records")))
            + (" is cited." if g.n_socks == 1 and n_partners == 1 else " are cited."),
            "The link between the host process and these network records is inferred from address, port and "
            "time; it is not itself observed"
            + (". It is ambiguous: more than one local address matched" if len(locals_) > 1 else "") + ".",
        ]
        if unestablished:
            where = (f"on sensor(s) {', '.join(unestablished_cited)}" if unestablished_cited else "")
            others_n = len(unestablished) - len(unestablished_cited)
            where += ((" and " if where else "on ") + f"{others_n} sensor(s) with no cited record" if others_n else "")
            parts.append(f"{s0.host}'s own address {where} is not established from other joins, so these records "
                         f"could belong to another machine reaching the same endpoint.")
        if differs:
            parts.append(f"Local address(es) {', '.join(differs)} differ from the address usually seen for "
                         f"{s0.host} on the same sensor.")
        if n_others:
            names = "; ".join(f"{h} '{exe}' (pid {pid})" for h, exe, pid, _i in others)
            parts.append(f"The same network records also join connect() calls by {n_others} other "
                         f"process(es)" + (f": {names}" + more(len(others), n_others) if others else "") + ".")
        if caps:
            parts.append("Because the attribution is " + " and ".join(
                {"shared": "shared", "ambiguous": "ambiguous", "unestablished": "not established"}[c] for c in caps)
                + ", the lane is capped at lead.")
        if g.notable is not None:
            parts.append(f"The process is notable as {g.notable.reason} calling connect() to an address "
                         f"outside the site's internal networks." + lineage_sentence(judged, unjudged))
        known = set(ids)
        cited += [e for e in lineage_events if e.id not in known]         # the observed records the lineage names
        # the first-seen alert (and flow) among the cited records
        by_order = sorted(partners, key=lambda item: item[2])
        alert_event = next((loaded[n.id] for _k, n, _o in by_order if n.family == "net_alert"), None)
        flow_event = next((loaded[n.id] for _k, n, _o in by_order if n.family in ("net_flow", "net_session")), None)
        preds = [pf(first, "process.executable"), pf(first, "destination.ip"), pf(first, "destination.port")]
        if alert_event is not None and alert_event.has("alert.signature"):
            preds.append(pf(alert_event, "alert.signature"))
        elif flow_event is not None and flow_event.has("network.community_id"):
            preds.append(pf(flow_event, "network.community_id"))
        m = Match(self.id, " ".join(parts), self.claim_type, cited, preds, first.ts, LANE_SEVERITY[lane], lane,
                  "medium", first.entities(), group_key=g.key,
                  context_ids={e.id for e in cited} - {s.id for s in g.socks} - set(partner_ids))
        m.raw_copies.update(lineage_raw)
        m.notes.extend(lineage_lines)
        if lineage_events:
            m.notes.append(f"{len(lineage_events)} process record(s) (exec and observed) the named lineage rests on "
                           f"are cited")
        for observer in cited_observers:
            for version in (4, 6):
                known = address.get((s0.host, observer, version))
                if known:
                    best, n, total = known
                    m.notes.append(f"inferred, not an asset record: sensor {observer} saw {s0.host}'s uniquely "
                                   f"joined IPv{version} connections from {best} in {n} of {total} joins")
        return m


class _Group:
    """One (host, program, account, endpoint) group while its linked rows stream by. Memory holds its first
    EXAMPLE_LIMIT calls kept for citation, the calls bounding its span, counts, the first notable call, the strongest
    alert lane, and the EXAMPLE_LIMIT kept partner records first in citation order (alerts, then by start and id). Its
    distinct partners, the calls that kept a link and its shared records are rows of the spill's gp, gs and gsh tables,
    emptied by `clear`. `state` is what the sweep staged for the group (`_SockGroup`)."""

    def __init__(self, key: str, db, state: _SockGroup):
        self.key = key
        self.db = db
        self.state = state
        # calls on the stage: the group's first kept calls (row flag), the held bounds and earliest-process calls
        self.citable = set(state.ends.ids()) | {event_id for _o, _k, event_id in state.earliest}
        self.socks: list[Sock] = []
        self.first: Sock | None = None
        self.ends = Ends()                        # the linked calls bounding the stated span
        self.n_socks = 0
        self.last_ts = 0.0
        self.outcomes: Counter = Counter()
        self.notable: Sock | None = None
        self.notable_all_failed = True
        self.alert_lane: str | None = None
        self.first_partners: list[tuple] = []     # (citation key, record, first-seen order), sorted by key
        self.observer_first: dict = {}            # sensor -> its first kept record in citation order
        self.conn_first: dict = {}                # connection -> its first kept record, for the EXAMPLE_LIMIT
                                                  # connections whose first record comes first in citation order
        self.order = 0
        self.procs: dict = {}                     # notable processes and their earliest calls (`note_process`)
        self.unheld = 0                           # notable calls of processes past PROCESSES_HELD
        self.pids: set = set()                    # the group's pids (PROCESSES_HELD at most)
        self.pids_more = False
        self.proc_cites: dict = {}                # notable process -> its earliest linked call kept for citation

    def shared(self, net_id: str, seq: int) -> None:
        self.db.execute("INSERT OR IGNORE INTO gsh VALUES (?, ?)", (net_id, seq))

    def add(self, sock_rowid: int, s: Sock, kept: list[tuple]) -> None:
        self.n_socks += 1
        if self.first is None:
            self.first = s
        if s.staged:
            self.citable.add(s.id)
        if s.id in self.citable and len(self.socks) < EXAMPLE_LIMIT:
            self.socks.append(s)
        self.ends.offer(s.ts, s.ts, s.id)
        self.last_ts = s.ts
        self.outcomes[s.outcome] += 1
        if s.pid is not None and s.pid not in self.pids:
            if len(self.pids) < PROCESSES_HELD:
                self.pids.add(s.pid)
            else:
                self.pids_more = True
        if s.reason is not None:
            if self.notable is None:
                self.notable = s
            self.notable_all_failed = self.notable_all_failed and s.outcome == Outcome.failure
            key = (s.pid, s.ppid, s.boot, s.session) if isinstance(s.pid, int) else None
            if not note_process(self.procs, key, s.ts, s.serial, s.id):
                self.unheld += 1
            elif s.id in self.citable and key is not None and key not in self.proc_cites:
                self.proc_cites[key] = s.id     # rows stream in time order: the process's earliest citable call
        self.db.execute("INSERT OR IGNORE INTO gs VALUES (?)", (sock_rowid,))
        for n, local, status in kept:
            if not self.db.execute(
                    'INSERT OR IGNORE INTO gp VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
                    (n.id, n.family, n.observer, local, n.conn, str(n.alert_sig), status, n.start, n.end)).rowcount:
                self.db.execute("UPDATE gp SET status = ? WHERE nid = ?", (status, n.id))   # the latest call's
                continue
            if n.family == "net_alert":
                lane = alert_lane(n)
                if lane is not None and (self.alert_lane is None or LANE_RANK[lane] < LANE_RANK[self.alert_lane]):
                    self.alert_lane = lane
            key = (n.family != "net_alert", n.start, n.id)
            if n.staged:
                item = (key, n, self.order)
                if len(self.first_partners) < EXAMPLE_LIMIT or key < self.first_partners[-1][0]:
                    bisect.insort(self.first_partners, item, key=lambda each: each[0])
                    del self.first_partners[EXAMPLE_LIMIT:]
                held = self.observer_first.get(n.observer)
                if held is None or key < held[0]:
                    self.observer_first[n.observer] = item
                held = self.conn_first.get(n.conn)
                if held is not None:
                    if key < held[0]:
                        self.conn_first[n.conn] = item
                elif len(self.conn_first) < EXAMPLE_LIMIT:
                    self.conn_first[n.conn] = item
                else:
                    last = max(self.conn_first, key=lambda conn: self.conn_first[conn][0])
                    if key < self.conn_first[last][0]:
                        del self.conn_first[last]
                        self.conn_first[n.conn] = item
            self.order += 1

    def partners(self) -> list[tuple]:
        """The network records the group cites: the first of each sensor (always, so every sensor named has a cited
        record), then the first of each connection, then the first in citation order, up to EXAMPLE_LIMIT."""
        chosen: dict = {}
        for item in sorted(self.observer_first.values(), key=lambda each: each[0]):
            chosen[item[1].id] = item
        for pool in (sorted(self.conn_first.values(), key=lambda each: each[0]), self.first_partners):
            for item in pool:
                if len(chosen) >= EXAMPLE_LIMIT:
                    break
                chosen.setdefault(item[1].id, item)
        return sorted(chosen.values(), key=lambda each: each[0])

    def clear(self) -> None:
        for table in ("gp", "gs", "gsh"):
            self.db.execute(f"DELETE FROM {table}")


CORRELATION_PLAYBOOKS = [InterpreterExternalConnection, ProcessNetworkLink]
