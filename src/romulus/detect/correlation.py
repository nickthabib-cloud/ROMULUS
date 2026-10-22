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

from romulus.detect.base import Match, Playbook, basename, pf
from romulus.detect.bounded import (
    HOT_COUNT,
    ExecHistory,
    HeldExamples,
    KeyedStore,
    RecentIds,
    Spill,
    StateExhausted,
    _budget_refuses,
    scalar,
)
from romulus.detect.host import (  # boot_of and boots_conflict are defined in host.py (no import cycle)
    INTERPRETERS,
    WEB_SERVICE_USERS,
    add_unheld,
    alone,
    boot_of,
    boots_conflict,
    interpreter_name,
    is_internal,
)
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


# INTERNAL_NETS is a constant table, so an address's answer never changes during a run.
_external_text = lru_cache(maxsize=ADDRESS_CACHE)(_external_uncached)


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


def _process_words(e: TypedEvent) -> str:
    pid = e.get("process.pid")
    user = e.get("process.user") or e.get("process.uid")
    return (f"'{e.get('process.executable')}'" + (f" (pid {pid}" if pid is not None else " (pid unknown")
            + (f", user '{user}')" if user is not None else ")"))


WEB_SERVER_PREFIXES = ("apache2", "httpd", "nginx", "lighttpd", "php-fpm", "php-cgi", "uwsgi", "gunicorn", "caddy")
SERVICE_MANAGERS = {"systemd", "init"}
LINEAGE_DEPTH = 6
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


class PidTable:
    """Kernel-recorded exec history per (host, pid), for lineage questions about a socket's process. Holds
    compact tuples `(exec_ts, exe, parent_pid, raw_id, boot)`; a pid's meaning at time t is its latest exec at or
    before t (pids are reused). A lookup in a recorded boot never returns an exec recorded in a different boot: the
    pid restarted at the reboot, and its exec in the new boot is not in the window. An exec or a lookup without a
    recorded boot is boot-blind (see `boots_conflict`)."""

    # A detector rule (`owner`) holds the CAPACITY most recently used processes in memory (about 250 bytes each, so
    # 75 MB) and the rest in its on-disk spill, read back when a walk reaches them: every lookup is exact. Callers
    # without an owner (an expansion fetch, a baseline period) hold everything they were given in memory.
    CAPACITY = HOT_COUNT  # a count cap only: the hunt's memory budget sizes it in bytes

    def __init__(self, capacity: int | None = None, owner=None):
        self.execs = ExecHistory(capacity if capacity is not None else _UNBOUNDED, _UNBOUNDED, owner, "pid_table")

    def add(self, e: TypedEvent) -> None:
        pid, exe = e.get("process.pid"), e.get("process.executable")
        if not isinstance(pid, int) or not exe or e.host is None:
            return
        ppid = e.get("process.ppid")
        self.execs.add((e.host, pid), (e.ts.timestamp(), str(exe), ppid if isinstance(ppid, int) else None,
                                       e.raw[0].native_id if e.raw else "", boot_of(e)))

    def trim(self) -> None:
        """Move the least recently used processes beyond the capacity to disk (when a batch ends)."""
        self.execs.trim()

    def _entries(self, host: str, pid: int):
        # read in place when the store does not bring a process back to memory (below the volume's reserve)
        return self.execs.get((host, pid)) or self.execs.store.peek((host, pid), [])

    def _lookup(self, host: str, pid: int, ts: float, boot: str | None = None, *, strict: bool = False):
        latest = None
        for entry in self._entries(host, pid):     # one pid rarely has more than a few execs in a window
            if entry[0] < ts or (entry[0] == ts and not strict):
                latest = entry
            else:
                break
        # The latest exec of this pid before `ts` is in another boot: every earlier one is too (boots follow each
        # other in time), so this pid has no recorded exec in `boot` before `ts`.
        if latest is not None and boots_conflict(boot, latest[4]):
            return None
        return latest

    def lookup(self, host: str, pid: int, ts: float, boot: str | None = None):
        """Latest exec identity for a PID at or before `ts` in `boot`; public for expansion lineage links."""
        return self._lookup(host, pid, ts, boot)

    def exec_before(self, host: str, pid: int, ts: float, boot: str | None = None):
        """The exec identity a PID held strictly before `ts` in `boot` — the program it ran before a later exec
        on the same PID replaced it. Returns `(exec_ts, exe, parent_pid, raw_id, boot)` or None."""
        return self._lookup(host, pid, ts, boot, strict=True)

    def lineage_entries(self, host: str, ppid, ts: float, depth: int = LINEAGE_DEPTH, boot: str | None = None):
        """Walk up the recorded parent chain from `ppid` as of `ts` in `boot`. Returns a list of
        `(pid, exec_ts, exe, raw_id)`, nearest ancestor first, stopping at an ancestor whose exec is
        not in the window (so the chain never invents a link). A parent is in its child's boot, so an
        ancestor's recorded boot carries up the chain when the start had none."""
        entries = []
        pid = ppid
        for _ in range(depth):
            if not isinstance(pid, int) or pid in (0, 1):
                break
            entry = self._lookup(host, pid, ts, boot)
            if entry is None:
                break
            exec_ts, exe, parent, raw_id, entry_boot = entry
            entries.append((pid, exec_ts, exe, raw_id))
            pid, ts, boot = parent, exec_ts, boot if boot is not None else entry_boot
        return entries

    def ancestry(self, host: str, ppid, ts: float, boot: str | None = None) -> tuple[str, list[tuple[str, str]]]:
        """Walk up from a parent pid in `boot`. Returns (verdict, [(exe, raw id)]) with verdict 'web_server' when a
        web server is an ancestor, 'service_manager' when the chain provably reaches pid 1 or systemd/init without
        one, and 'unknown' when an ancestor's exec is not in the window."""
        chain: list[tuple[str, str]] = []
        pid = ppid
        for _ in range(LINEAGE_DEPTH):
            if pid in (0, 1):
                return "service_manager", chain
            if not isinstance(pid, int):
                return "unknown", chain
            entry = self._lookup(host, pid, ts, boot)
            if entry is None:
                return "unknown", chain
            t, exe, parent, raw_id, entry_boot = entry
            name = basename(exe)
            chain.append((exe, raw_id))
            if name.startswith(WEB_SERVER_PREFIXES):
                return "web_server", chain
            if name in SERVICE_MANAGERS:
                return "service_manager", chain
            pid, ts, boot = parent, t, boot if boot is not None else entry_boot
        return "unknown", chain


def lineage_lane(reason: str | None, lane: str, verdict: str, chain) -> tuple[str, list[str]]:
    """Lineage can only lower a lane. A web-service process whose ancestry provably reaches the service
    manager without a web server is a daemon of that account, not a request-driven child: lead. Unknown
    lineage keeps the lane, so missing records can never hide a web shell."""
    if reason is None or "web-service account" not in reason or verdict != "service_manager" or lane != "high":
        return lane, []
    names = " <- ".join(f"{exe} ({rid})" for exe, rid in chain) or "pid 1"
    return "lead", [(f"lane lowered to lead: auditd exec records trace the process to the service manager with no "
                    f"web server in between ({names})")]


class InterpreterExternalConnection(Playbook):
    """Positive-only: the audit rule set's scope (syscalls, families, ports) is not visible in telemetry,
    so a missing connect record never proves a connection did not happen. One item per (host, program,
    account, port), listing every destination, so routine update traffic is one lead, not one per address."""
    state_slice = "strong"           # a protected slice of the hunt's disk budget
    id = "host.interpreter_external_connection"
    version = "4"
    title = "Shell, interpreter, relay tool or web-service process made connect() calls to non-private addresses"
    kind = "aggregate"
    families = ("net_socket", "process_exec")
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

    # Per (host, program, account, port) of notable processes: counts, destinations and the first cited calls (as ids
    # once staged), in a keyed store: the HOT most recent groups in memory, the rest on disk, never forgotten.
    staged = True
    HOT = HOT_COUNT  # a count cap only: the hunt's memory budget sizes it in bytes

    def __init__(self):
        super().__init__()
        self.pids = PidTable(PidTable.CAPACITY, owner=self)
        self.groups = KeyedStore(self, "iec_groups", self.HOT)        # key -> [info, HeldExamples]
        self._pending: list[TypedEvent] = []
        self._fresh: list[HeldExamples] = []
        self.load = lambda ids: []

    def drain_staged(self) -> list[TypedEvent]:
        out, self._pending = self._pending, []
        for store in self._fresh:
            store.staged()
        self._fresh = []
        self.groups.trim()
        self.pids.trim()
        return out

    def consume(self, events):
        self._batch, out = events, []
        for e in events:
            if e.family == "process_exec":
                self.pids.add(e)
                continue
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
                {"count": 0, "dests": Counter(), "outcomes": Counter(), "first": e.ts, "last": e.ts,
                 "reason": reason, "lane": lane}, HeldExamples(EXAMPLE_LIMIT)])
            if state is None:
                # the call is a finding by itself: published now, on its own, instead of being refused
                self.note_limit("groups_alone", "the groups' disk budget is spent; calls of a new group are published "
                                                "one at a time")
                info = {"count": 1, "dests": Counter({ip: 1}), "outcomes": Counter({str(e.outcome): 1}),
                        "first": e.ts, "last": e.ts, "reason": reason, "lane": lane}
                add_unheld(out, alone(self._group_match(key, info, [e]), self, e))
                continue
            info, group = state
            info["count"] += 1
            info["dests"][ip] += 1
            info["outcomes"][str(e.outcome)] += 1
            info["first"], info["last"] = min(info["first"], e.ts), max(info["last"], e.ts)
            if group.offer(e):
                self._pending.append(e)
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
        evs = sorted(evs, key=lambda x: (x.ts, x.id))
        e0 = evs[0]
        verdict, chain = self.pids.ancestry(e0.host, e0.get("process.ppid"), e0.ts.timestamp(), boot_of(e0))
        lane, notes = lineage_lane(info["reason"], info["lane"], verdict, chain)
        if lane == "high" and all(o == Outcome.failure for o in info["outcomes"]):
            lane = "lead"
            notes.append("lane lowered to lead: every connect() call failed")
        dests = ", ".join(f"{ip} ({n})" for ip, n in info["dests"].most_common(8))
        more = f" and {len(info['dests']) - 8} more" if len(info["dests"]) > 8 else ""
        outcomes = ", ".join(f"{n} {w}" for w, n in (
            ("succeeded", info["outcomes"].get(Outcome.success, 0)),
            ("failed", info["outcomes"].get(Outcome.failure, 0)),
            ("with unknown or in-progress outcome", info["outcomes"].get(Outcome.unknown, 0))) if n)
        port = e0.get("destination.port")
        if verdict == "web_server":
            lineage = f" Its ancestry includes the web server '{chain[-1][0]}'."
        elif verdict == "service_manager":
            lineage = " Its ancestry reaches the service manager with no web server."
        else:
            lineage = " Its ancestry is not fully recorded in the window."
        claim = (f"auditd connect() records on {e0.host} show {_process_words(e0)}, {info['reason']}, making "
                 f"{info['count']} connect() call(s) to {len(info['dests'])} non-private address(es) on port "
                 f"{port} ({info['first'].isoformat()} – {info['last'].isoformat()}): {dests}{more}; "
                 f"{outcomes}.{lineage} {SOCKET_TYPE_CAVEAT[0].upper()}{SOCKET_TYPE_CAVEAT[1:]}.")
        preds = [pf(e0, "socket.syscall"), pf(e0, "process.executable"), pf(e0, "destination.port")]
        if e0.has("process.user"):
            preds.append(pf(e0, "process.user"))
        m = Match(self.id, claim, self.claim_type, evs, preds, e0.ts, self.severity, lane, "high",
                  e0.entities(), group_key=key)
        m.notes.extend(notes)
        if info["count"] > len(evs):
            m.notes.append(f"{info['count']} matching connect() records; {len(evs)} are cited")
        return m

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

    def local_side(self, ip: str, port: int) -> str | None:
        """The non-remote endpoint, if this record is one direction of a connection to ip:port."""
        if (self.dst, self.dport) == (ip, port):
            return self.src
        if (self.src, self.sport) == (ip, port):
            return self.dst
        return None


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
    version = "3"
    title = "Host process connect() calls linked to network-sensor records for the same connection (inferred)"
    kind = "aggregate"
    staged = True
    claim_type = "correlated_observation"
    families = ("net_socket",) + NETWORK_JOIN_FAMILIES
    required_fields = ()
    # a join that finds nothing proves nothing: sensors and audit rules each see only part of the traffic
    assures_negative = False
    severity, lane = "high", "lead"
    attack = ("T1071", "T1095", "T1571")
    benign = ("another host or process reaching the same endpoint at the same second (stated when seen)",
              "benign IDS signatures on routine traffic")
    next_checks = ("flow detail for the linked community IDs", "process_tree for the connecting process",
                   "peer activity for the remote address across hosts and sessions")
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

    def drain_staged(self) -> list[TypedEvent]:
        out, self._pending = self._pending, []
        return out

    def _store(self) -> Spill:
        if self._spill is None:
            spill = self._spill = Spill(self.spill_dir, self.state_budget(), self.state_slice)
            spill.table("sock", "id, host, ts, ip, port, exe, user, pid, outcome, reason, lane, grp, claimant")
            spill.table("net", 'id, family, observer, start, "end", src, sport, dst, dport, cid, sev, cat, sig, '
                               "seq INTEGER PRIMARY KEY")
            spill.table("ep", "ip, port, start, net")
        return self._spill

    def close_spill(self) -> None:
        if self._spill is not None:
            self._spill.close()
            self._spill = None

    def release_state(self) -> None:
        self.close_spill()

    def _room(self, rows: int) -> bool:
        """Count the rows against the disk budget. Once it, or the rule's slice of the hunt's state budget, is spent
        the record is refused (not evaluated) instead: every record here needs new rows."""
        if _budget_refuses(self):
            self.evaluated -= 1
            self.refuse("state_disk", "the hunt's state budget for this join is spent; later socket calls and network "
                                      "records are not evaluated")
            return False
        if self.spilled_bytes >= self.DISK_BUDGET:
            self.evaluated -= 1
            self.refuse("disk", f"the join's spilled rows reached their disk budget of {self.DISK_BUDGET:,} bytes; "
                                f"later socket calls and network records are not evaluated")
            return False
        self.spilled_bytes += rows * self.ROW_BYTES
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
        s = Sock(e.id, e.host or "", e.ts.timestamp(), ip, int(port), str(e.get("process.executable")),
                 str(e.get("process.user")), scalar(e.get("process.pid")), str(e.outcome), reason, lane)
        row = (s.id, s.host, s.ts, s.ip, s.port, s.exe, s.user, s.pid, s.outcome, s.reason, s.process_lane, s.group,
               _claimant_key(s.claimant))
        if not self._room(1):
            return
        try:
            self._store().add("sock", row)
        except StateExhausted as exc:
            self._lost(exc)
            return
        self._pending.append(e)

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
        row = (e.id, e.family, e.host or "", start, end, src, sport, dst, dport,
               scalar(e.get("network.community_id")) or None, sev if isinstance(sev, int) else None,
               scalar(e.get("alert.category")), scalar(e.get("alert.signature")), seq)
        endpoints = [(dst, dport, start, seq)] + ([(src, sport, start, seq)] if (src, sport) != (dst, dport) else [])
        if not self._room(1 + len(endpoints)):
            return
        self._net_seq = seq
        store = self._store()
        try:
            store.add("net", row)
            for endpoint in endpoints:
                store.add("ep", endpoint)
        except StateExhausted as exc:
            self._lost(exc)
            return
        self._pending.append(e)

    def _lost(self, exc: StateExhausted) -> None:
        """A batch of rows could not be written (the stage volume is at its reserve): this record is refused, and
        finalize, which needs every row, says so."""
        self.evaluated -= 1
        self.refuse("state_disk", f"a write to the stage volume failed ({exc}); later socket calls and network "
                                  f"records are not evaluated")

    def consume(self, events):
        for e in events:
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
        db.execute("CREATE INDEX net_cid ON net (cid)")
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
                       'JOIN net m ON m.cid = d.cid WHERE l.direct = 1 AND d.cid IS NOT NULL '
                       'AND l.sock > ? AND l.sock <= ? '
                       'AND m.start >= d.start - ? AND m.start <= COALESCE(d."end", d.start + ?) + ? '
                       'AND ((m.src = d.src AND m.sport = d.sport AND m.dst = d.dst AND m.dport = d.dport) '
                       'OR (m.src = d.dst AND m.sport = d.dport AND m.dst = d.src AND m.dport = d.sport))',
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
        db.execute("CREATE TABLE gp (nid PRIMARY KEY, family, observer, local, conn, sig, status)")
        db.execute("CREATE TABLE gs (sock INTEGER PRIMARY KEY)")
        db.execute("CREATE TABLE gsh (nid, seq INTEGER, PRIMARY KEY (nid, seq)) WITHOUT ROWID")
        db.commit()

    _ROWS = ('SELECT s.rowid, s.id, s.host, s.ts, s.ip, s.port, s.exe, s.user, s.pid, s.outcome, s.reason, s.lane, '
             's.grp, n.id, n.family, n.observer, n.start, n."end", n.src, n.sport, n.dst, n.dport, n.cid, n.sev, '
             'n.cat, n.sig, nc.n, n.seq FROM link l JOIN sock s ON s.rowid = l.sock JOIN net n ON n.seq = l.net '
             'JOIN nc ON nc.net = l.net ')

    @staticmethod
    def _row(row) -> tuple[int, Sock, Net, int, int]:
        sock = Sock(row[1], row[2], row[3], row[4], row[5], row[6], row[7], row[8], row[9], row[10], row[11])
        net = Net(row[13], row[14], row[15], row[16], row[17], row[18], row[19], row[20], row[21], row[22],
                  row[23], row[24], row[25])
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
        if self._spill is None:
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
                group = _Group(s.group, self._spill.db)
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
        if g.notable is not None:
            lane = g.notable.process_lane
            if g.notable_all_failed:
                lane = "lead"                       # every notable call failed: an attempt, not a connection
            components.append(lane)
        if g.alert_lane is not None:
            components.append(g.alert_lane)
        if not components:
            return None
        lane = min(components, key=LANE_RANK.__getitem__)
        s0 = g.socks[0]
        # other processes claiming the group's shared records: counted, and the first five named, as they stream
        n_others, others = 0, []
        for claimant in db.execute(
                "SELECT DISTINCT s.host, s.exe, s.pid FROM gsh JOIN gp ON gp.nid = gsh.nid JOIN link l "
                "ON l.net = gsh.seq JOIN sock s ON s.rowid = l.sock EXCEPT SELECT s.host, s.exe, s.pid FROM gs "
                "JOIN sock s ON s.rowid = gs.sock"):
            n_others += 1
            others = heapq.nsmallest(5, [*others, tuple(claimant)], key=str)
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
        n_partners, n_flows, n_alerts, n_connections = db.execute(
            "SELECT COUNT(*), TOTAL(family IN ('net_flow', 'net_session')), TOTAL(family = 'net_alert'), "
            "COUNT(DISTINCT conn) FROM gp").fetchone()
        n_flows, n_alerts = int(n_flows), int(n_alerts)
        observers = [observer for (observer,) in db.execute("SELECT DISTINCT observer FROM gp ORDER BY observer")]
        (n_sigs,) = db.execute("SELECT COUNT(DISTINCT sig) FROM gp WHERE family = 'net_alert'").fetchone()
        sigs = [sig for (sig,) in db.execute(
            "SELECT DISTINCT sig FROM gp WHERE family = 'net_alert' ORDER BY sig LIMIT 3")]
        outcomes = g.outcomes

        ids = [s.id for s in g.socks] + [n.id for _k, n, _o in g.first_partners]
        loaded = {e.id: e for e in self.load(ids)}
        missing = [i for i in ids if i not in loaded]
        if missing:
            raise StageMissing(f"{self.id}: {len(missing)} cited event(s) absent from the stage, e.g. {missing[0]}")
        cited = [loaded[i] for i in ids]
        first = loaded[s0.id]
        outcome_words = ", ".join(f"{n} {w}" for w, n in (
            ("succeeded", outcomes.get(Outcome.success, 0)), ("failed", outcomes.get(Outcome.failure, 0)),
            ("with unknown or in-progress outcome", outcomes.get(Outcome.unknown, 0))) if n)
        parts = [
            (f"Observed on {s0.host} (auditd): {_process_words(first)} made {g.n_socks} connect() call(s) to "
             f"{s0.ip} port {s0.port} that join network records "
             f"({datetime.fromtimestamp(s0.ts, UTC).isoformat()} – "
             f"{datetime.fromtimestamp(g.last_ts, UTC).isoformat()}); {outcome_words}. {SOCKET_TYPE_CAVEAT}."),
            f"Observed by network sensor(s) {', '.join(observers)}: {n_flows} flow or session record(s) across "
            f"{n_connections} connection(s) to {s0.ip} port {s0.port} starting within seconds of those calls"
            + (f", with local address(es) {', '.join(locals_)}" if locals_ else "")
            + (f", and {n_alerts} IDS alert(s) on those connections: {'; '.join(sigs)}"
               + (f" and {n_sigs - 3} more" if n_sigs > 3 else "") if n_alerts else "") + ".",
            "The link between the host process and these network records is inferred from address, port and "
            "time; it is not itself observed"
            + (". It is ambiguous: more than one local address matched" if len(locals_) > 1 else "") + ".",
        ]
        if unestablished:
            parts.append(f"{s0.host}'s own address on sensor(s) {', '.join(unestablished)} is not established from "
                         f"other joins, so these records could belong to another machine reaching the same "
                         f"endpoint.")
        if differs:
            parts.append(f"Local address(es) {', '.join(differs)} differ from the address usually seen for "
                         f"{s0.host} on the same sensor.")
        if n_others:
            names = "; ".join(f"{h} '{exe}' (pid {pid})" for h, exe, pid in others)
            parts.append(f"The same network records also join connect() calls by {n_others} other "
                         f"process(es): {names}" + (" and more" if n_others > 5 else "") + ".")
        if caps:
            parts.append("Because the attribution is " + " and ".join(
                {"shared": "shared", "ambiguous": "ambiguous", "unestablished": "not established"}[c] for c in caps)
                + ", the lane is capped at lead.")
        if g.notable is not None:
            parts.append(f"The process is notable as {g.notable.reason} calling connect() to a non-private "
                         f"address.")
        # the first-seen alert (and flow) among the cited records
        by_order = sorted(g.first_partners, key=lambda item: item[2])
        alert_event = next((loaded[n.id] for _k, n, _o in by_order if n.family == "net_alert"), None)
        flow_event = next((loaded[n.id] for _k, n, _o in by_order if n.family in ("net_flow", "net_session")), None)
        preds = [pf(first, "process.executable"), pf(first, "destination.ip"), pf(first, "destination.port")]
        if alert_event is not None and alert_event.has("alert.signature"):
            preds.append(pf(alert_event, "alert.signature"))
        elif flow_event is not None and flow_event.has("network.community_id"):
            preds.append(pf(flow_event, "network.community_id"))
        m = Match(self.id, " ".join(parts), self.claim_type, cited, preds, first.ts, LANE_SEVERITY[lane], lane,
                  "medium", first.entities(), group_key=g.key)
        for observer in observers:
            for version in (4, 6):
                known = address.get((s0.host, observer, version))
                if known:
                    best, n, total = known
                    m.notes.append(f"inferred, not an asset record: sensor {observer} saw {s0.host}'s uniquely "
                                   f"joined IPv{version} connections from {best} in {n} of {total} joins")
        if g.n_socks > EXAMPLE_LIMIT or n_partners > EXAMPLE_LIMIT:
            m.notes.append(f"{g.n_socks} connect() record(s) and {n_partners} network record(s) joined; up to "
                           f"{EXAMPLE_LIMIT} of each are cited")
        return m


class _Group:
    """One (host, program, account, endpoint) group while its linked rows stream by. Memory holds its first
    EXAMPLE_LIMIT calls, counts, the first notable call, the strongest alert lane, and the EXAMPLE_LIMIT partner records
    first in citation order (alerts, then by start and id). Its distinct partners, the calls that kept a link and its
    shared records are rows of the spill's gp, gs and gsh tables, emptied by `clear`."""

    def __init__(self, key: str, db):
        self.key = key
        self.db = db
        self.socks: list[Sock] = []
        self.n_socks = 0
        self.last_ts = 0.0
        self.outcomes: Counter = Counter()
        self.notable: Sock | None = None
        self.notable_all_failed = True
        self.alert_lane: str | None = None
        self.first_partners: list[tuple] = []     # (citation key, record, first-seen order), sorted by key
        self.order = 0

    def shared(self, net_id: str, seq: int) -> None:
        self.db.execute("INSERT OR IGNORE INTO gsh VALUES (?, ?)", (net_id, seq))

    def add(self, sock_rowid: int, s: Sock, kept: list[tuple]) -> None:
        self.n_socks += 1
        if len(self.socks) < EXAMPLE_LIMIT:
            self.socks.append(s)
        self.last_ts = s.ts
        self.outcomes[s.outcome] += 1
        if s.reason is not None:
            if self.notable is None:
                self.notable = s
            self.notable_all_failed = self.notable_all_failed and s.outcome == Outcome.failure
        self.db.execute("INSERT OR IGNORE INTO gs VALUES (?)", (sock_rowid,))
        for n, local, status in kept:
            if not self.db.execute(
                    "INSERT OR IGNORE INTO gp VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (n.id, n.family, n.observer, local, n.cid or f"{n.src}:{n.sport}-{n.dst}:{n.dport}",
                     str(n.alert_sig), status)).rowcount:
                self.db.execute("UPDATE gp SET status = ? WHERE nid = ?", (status, n.id))   # the latest call's
                continue
            if n.family == "net_alert":
                lane = alert_lane(n)
                if lane is not None and (self.alert_lane is None or LANE_RANK[lane] < LANE_RANK[self.alert_lane]):
                    self.alert_lane = lane
            key = (n.family != "net_alert", n.start, n.id)
            if len(self.first_partners) < EXAMPLE_LIMIT or key < self.first_partners[-1][0]:
                bisect.insort(self.first_partners, (key, n, self.order), key=lambda item: item[0])
                del self.first_partners[EXAMPLE_LIMIT:]
            self.order += 1

    def clear(self) -> None:
        for table in ("gp", "gs", "gsh"):
            self.db.execute(f"DELETE FROM {table}")


CORRELATION_PLAYBOOKS = [InterpreterExternalConnection, ProcessNetworkLink]
