"""Host↔network playbooks: process sockets from auditd, and their joins to network-sensor records.

A join is a correlation, never an observation (spec section 1). Each side is an observed fact cited to
its own record; the link between them is inferred from typed address, port and time (and, on the network
side, from the sensor's own flow identity bounded by the flow's lifetime) and is worded as inferred.
A correlated item's lane never exceeds its strongest observed component, and drops to lead whenever the
same network records also match another host's or process's connect() call.
"""
from __future__ import annotations

import ipaddress
from bisect import bisect_left, bisect_right
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime

from romulus.detect.base import Match, Playbook, basename, pf
from romulus.detect.bounded import ExecHistory, HeldExamples, RecentIds
from romulus.detect.host import (  # boot_of and boots_conflict are defined in host.py (no import cycle)
    INTERPRETERS,
    WEB_SERVICE_USERS,
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


def canon_ip(value) -> str | None:
    try:
        return str(ipaddress.ip_address(str(value)))
    except ValueError:
        return None


def routable_remote(ip: str | None) -> bool:
    if ip is None:
        return False
    a = ipaddress.ip_address(ip)
    return not (a.is_loopback or a.is_unspecified or a.is_multicast or a.is_link_local or a.is_reserved
                or (a.version == 4 and a == ipaddress.IPv4Address("255.255.255.255")))


def external(ip: str | None) -> bool:
    return routable_remote(ip) and not is_internal(ipaddress.ip_address(ip))


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

    # Detector rules hold at most CAPACITY processes (about 250 bytes each, so 75 MB), PER_PID execs each; other
    # callers (an expansion fetch, a baseline period) pass no capacity and hold everything they were given.
    CAPACITY = 300_000
    PER_PID = 16

    def __init__(self, capacity: int | None = None):
        bounded = capacity is not None
        self.execs = ExecHistory(capacity if bounded else _UNBOUNDED, self.PER_PID if bounded else _UNBOUNDED)

    @property
    def evicted(self) -> int:
        """Processes whose exec records were released to stay within the capacity."""
        return self.execs.evicted

    def add(self, e: TypedEvent) -> None:
        pid, exe = e.get("process.pid"), e.get("process.executable")
        if not isinstance(pid, int) or not exe or e.host is None:
            return
        ppid = e.get("process.ppid")
        self.execs.add((e.host, pid), (e.ts.timestamp(), str(exe), ppid if isinstance(ppid, int) else None,
                                       e.raw[0].native_id if e.raw else "", boot_of(e)))

    def _entries(self, host: str, pid: int):
        return self.execs.get((host, pid), touch=True)

    def pin_chain(self, host: str, ppid, ts: float, boot: str | None = None, *, own_pid=None) -> None:
        """Pin the exec entries a lineage walk from `ppid` as of `ts` rests on now (and, with `own_pid`, that pid's
        exec strictly before `ts`), so a walk made later still finds them after their processes were released."""
        if isinstance(own_pid, int):
            prior = self._lookup(host, own_pid, ts, boot, strict=True)
            if prior is not None:
                self.execs.pin((host, own_pid), [prior])
        pid = ppid
        for _ in range(LINEAGE_DEPTH):
            if not isinstance(pid, int) or pid in (0, 1):
                return
            entry = self._lookup(host, pid, ts, boot)
            if entry is None:
                return
            self.execs.pin((host, pid), [entry])
            pid, ts, boot = entry[2], entry[0], boot if boot is not None else entry[4]

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
    id = "host.interpreter_external_connection"
    version = "3"
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

    # Groups are (host, program, account, port) of notable processes: about 3 KB each with their cited ids, so 150 MB
    # at the budget. Destinations are counted per group up to DESTS_PER_GROUP; above it the claim says "at least".
    staged = True
    MAX_KEYS = 50_000
    DESTS_PER_GROUP = 10_000

    def __init__(self):
        super().__init__()
        self.pids = PidTable(PidTable.CAPACITY)
        self.groups: dict[str, HeldExamples] = {}
        self.info: dict[str, dict] = {}
        self._pending: list[TypedEvent] = []
        self._fresh: list[HeldExamples] = []
        self.load = lambda ids: []

    def drain_staged(self) -> list[TypedEvent]:
        out, self._pending = self._pending, []
        for store in self._fresh:
            store.staged()
        self._fresh = []
        return out

    def consume(self, events):
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
            if key not in self.info and len(self.info) >= self.MAX_KEYS:
                self.evaluated -= 1
                self.refuse("groups", f"(host, program, account, port) groups reached {self.MAX_KEYS:,}; a call of a "
                                      f"new group is not evaluated")
                continue
            info = self.info.setdefault(key, {"count": 0, "dests": Counter(), "outcomes": Counter(),
                                              "first": e.ts, "last": e.ts, "reason": reason, "lane": lane,
                                              "capped": False})
            info["count"] += 1
            if ip in info["dests"] or len(info["dests"]) < self.DESTS_PER_GROUP:
                info["dests"][ip] += 1
            else:
                info["capped"] = True
            info["outcomes"][str(e.outcome)] += 1
            info["first"], info["last"] = min(info["first"], e.ts), max(info["last"], e.ts)
            group = self.groups.get(key)
            if group is None:
                group = self.groups[key] = HeldExamples(EXAMPLE_LIMIT)
            if group.offer(e):
                self._pending.append(e)
                self._fresh.append(group)
                # the lineage the finding may rest on, held beyond the release of its processes
                self.pids.pin_chain(e.host, e.get("process.ppid"), e.ts.timestamp(), boot_of(e))
        return []

    def finalize(self):
        if self.pids.evicted:
            self.note_limit("lineage", f"exec records of {self.pids.evicted} process(es) were released to hold at "
                                       f"most {PidTable.CAPACITY:,}; an ancestry walk may stop early and is then "
                                       f"stated as not fully recorded (lineage can only lower a lane)")
        out = []
        for key in sorted(self.groups):
            evs = sorted(self.groups[key].events(self.load), key=lambda x: (x.ts, x.id))
            info, e0 = self.info[key], evs[0]
            verdict, chain = self.pids.ancestry(e0.host, e0.get("process.ppid"), e0.ts.timestamp(), boot_of(e0))
            lane, notes = lineage_lane(info["reason"], info["lane"], verdict, chain)
            if lane == "high" and all(o == Outcome.failure for o in info["outcomes"]):
                lane = "lead"
                notes.append("lane lowered to lead: every connect() call failed")
            dests = ", ".join(f"{ip} ({n})" for ip, n in info["dests"].most_common(8))
            more = f" and {len(info['dests']) - 8} more" if len(info["dests"]) > 8 else ""
            if info["capped"]:
                more += " (destination count capped: a lower bound)"
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
            out.append(m)
        return out

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
    gets its network evidence). Memory holds compact keys only; full events are staged on disk.

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

    def __init__(self):
        super().__init__()
        self.sockets: list[Sock] = []
        self.by_endpoint: dict[tuple[str, int], list[Net]] = defaultdict(list)
        self.by_community: dict[str, list[Net]] = defaultdict(list)
        self._seen = RecentIds()        # bounded re-read guard
        self._pending: list[TypedEvent] = []
        self.load = lambda ids: []
        self.heartbeat = lambda: None

    def drain_staged(self) -> list[TypedEvent]:
        out, self._pending = self._pending, []
        return out

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
        self.sockets.append(Sock(e.id, e.host or "", e.ts.timestamp(), ip, int(port),
                                 str(e.get("process.executable")), str(e.get("process.user")),
                                 e.get("process.pid"), str(e.outcome), reason, lane))
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
        n = Net(e.id, e.family, e.host or "", start, end, src, sport, dst, dport, e.get("network.community_id"),
                sev if isinstance(sev, int) else None, e.get("alert.category"), e.get("alert.signature"))
        self.by_endpoint[(dst, dport)].append(n)
        self.by_endpoint[(src, sport)].append(n)
        if n.cid:
            self.by_community[n.cid].append(n)
        self._pending.append(e)

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
    def _index(self) -> None:
        self._starts = {}
        for key, nets in self.by_endpoint.items():
            nets.sort(key=lambda n: (n.start, n.id))
            self._starts[key] = [n.start for n in nets]

    def _join(self, s: Sock) -> list[Net]:
        key = (s.ip, s.port)
        nets, starts = self.by_endpoint.get(key, []), self._starts.get(key, [])
        lo, hi = bisect_left(starts, s.ts - JOIN_BEFORE), bisect_right(starts, s.ts + JOIN_AFTER)
        direct = [n for n in nets[lo:hi] if n.local_side(s.ip, s.port)]
        linked = {n.id: n for n in direct}
        for d in direct:
            if not d.cid:
                continue
            first = d.start - FLOW_SLACK
            last = (d.end if d.end is not None else d.start + JOIN_AFTER) + FLOW_SLACK
            pair = {(d.src, d.sport), (d.dst, d.dport)}
            for m in self.by_community[d.cid]:
                if first <= m.start <= last and {(m.src, m.sport), (m.dst, m.dport)} == pair:
                    linked.setdefault(m.id, m)
        return sorted(linked.values(), key=lambda n: (n.start, n.id))

    def finalize(self):
        self._index()
        raw: dict[str, list[Net]] = {}
        for i, s in enumerate(self.sockets):
            if i % self.HEARTBEAT_EVERY == 0:
                self.heartbeat()
            raw[s.id] = self._join(s)
        # pass 1: who else claims each record, and each host's local address per (sensor, IP version)
        claimants: dict[str, set] = defaultdict(set)
        for s in self.sockets:
            for n in raw[s.id]:
                claimants[n.id].add(s.claimant)
        seen: dict[tuple[str, str, int], Counter] = defaultdict(Counter)
        for s in self.sockets:
            partners = raw[s.id]
            if not partners or any(len(claimants[n.id]) > 1 for n in partners):
                continue
            by_observer: dict[str, set] = defaultdict(set)
            for n in partners:
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
        # pass 2: never link a record whose local address another host owns; mark unestablished ones
        joins: dict[str, list[tuple[Net, str]]] = {}
        for s in self.sockets:
            kept = []
            for n in raw[s.id]:
                local = n.local_side(s.ip, s.port)
                known = address.get((s.host, n.observer, _version(local)))
                if known and local == known[0]:
                    kept.append((n, "established"))
                elif owner.get((n.observer, local), set()) - {s.host}:
                    continue                              # positively another host's address on this sensor
                else:
                    kept.append((n, "differs" if known else "unestablished"))
            if kept:
                joins[s.id] = kept
        groups: dict[str, list[Sock]] = defaultdict(list)
        for s in self.sockets:
            if s.id in joins:
                groups[s.group].append(s)
        out = []
        for key in sorted(groups):
            m = self._group_match(key, sorted(groups[key], key=lambda x: (x.ts, x.id)), joins, claimants, address)
            if m is not None:
                out.append(m)
        return out

    def _group_match(self, key, socks, joins, claimants, address) -> Match | None:
        partners: dict[str, Net] = {}
        attribution: dict[str, str] = {}
        for s in socks:
            for n, status in joins[s.id]:
                partners.setdefault(n.id, n)
                attribution[n.id] = status
        alerts = [n for n in partners.values() if n.family == "net_alert"]
        notable = [s for s in socks if s.reason is not None]
        components = []
        if notable:
            lane = notable[0].process_lane
            if all(s.outcome == Outcome.failure for s in notable):
                lane = "lead"                       # every notable call failed: an attempt, not a connection
            components.append(lane)
        alert_lanes = [lane for lane in (alert_lane(a) for a in alerts) if lane is not None]
        if alert_lanes:
            components.append(min(alert_lanes, key=LANE_RANK.__getitem__))
        if not components:
            return None
        lane = min(components, key=LANE_RANK.__getitem__)
        s0 = socks[0]
        others = sorted({c for n in partners.values() for c in claimants[n.id]} - {s.claimant for s in socks},
                        key=str)
        locals_ = sorted({n.local_side(s0.ip, s0.port) for n in partners.values()} - {None})
        unestablished = sorted({n.observer for n in partners.values() if attribution[n.id] == "unestablished"})
        differs = sorted({n.local_side(s0.ip, s0.port) for n in partners.values()
                          if attribution[n.id] == "differs"} - {None})
        caps = []
        if others:
            caps.append("shared")
        if len(locals_) > 1:
            caps.append("ambiguous")
        if unestablished or differs:
            caps.append("unestablished")
        if caps and lane == "high":
            lane = "lead"
        flows = [n for n in partners.values() if n.family in ("net_flow", "net_session")]
        connections = {n.cid or f"{n.src}:{n.sport}-{n.dst}:{n.dport}" for n in partners.values()}
        observers = sorted({n.observer for n in partners.values()})
        sigs = sorted({str(a.alert_sig) for a in alerts})
        outcomes = Counter(s.outcome for s in socks)

        ids = [s.id for s in socks[:EXAMPLE_LIMIT]] + [
            n.id for n in sorted(partners.values(), key=lambda n: (n.family != "net_alert", n.start, n.id))
        ][:EXAMPLE_LIMIT]
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
            (f"Observed on {s0.host} (auditd): {_process_words(first)} made {len(socks)} connect() call(s) to "
            f"{s0.ip} port {s0.port} that join network records "
            f"({datetime.fromtimestamp(socks[0].ts, UTC).isoformat()} – "
            f"{datetime.fromtimestamp(socks[-1].ts, UTC).isoformat()}); {outcome_words}. {SOCKET_TYPE_CAVEAT}."),
            f"Observed by network sensor(s) {', '.join(observers)}: {len(flows)} flow or session record(s) across "
            f"{len(connections)} connection(s) to {s0.ip} port {s0.port} starting within seconds of those calls"
            + (f", with local address(es) {', '.join(locals_)}" if locals_ else "")
            + (f", and {len(alerts)} IDS alert(s) on those connections: {'; '.join(sigs[:3])}"
               + (f" and {len(sigs) - 3} more" if len(sigs) > 3 else "") if alerts else "") + ".",
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
        if others:
            names = "; ".join(f"{h} '{exe}' (pid {pid})" for h, exe, pid in others[:5])
            parts.append(f"The same network records also join connect() calls by {len(others)} other "
                         f"process(es): {names}" + (" and more" if len(others) > 5 else "") + ".")
        if caps:
            parts.append("Because the attribution is " + " and ".join(
                {"shared": "shared", "ambiguous": "ambiguous", "unestablished": "not established"}[c] for c in caps)
                + ", the lane is capped at lead.")
        if notable:
            parts.append(f"The process is notable as {notable[0].reason} calling connect() to a non-private "
                         f"address.")
        alert_event = next((loaded[n.id] for n in alerts if n.id in loaded), None)
        flow_event = next((loaded[n.id] for n in flows if n.id in loaded), None)
        preds = [pf(first, "process.executable"), pf(first, "destination.ip"), pf(first, "destination.port")]
        if alert_event is not None and alert_event.has("alert.signature"):
            preds.append(pf(alert_event, "alert.signature"))
        elif flow_event is not None and flow_event.has("network.community_id"):
            preds.append(pf(flow_event, "network.community_id"))
        m = Match(self.id, " ".join(parts), self.claim_type, cited, preds, first.ts, LANE_SEVERITY[lane], lane,
                  "medium", first.entities(), group_key=key)
        for observer in observers:
            for version in (4, 6):
                known = address.get((s0.host, observer, version))
                if known:
                    best, n, total = known
                    m.notes.append(f"inferred, not an asset record: sensor {observer} saw {s0.host}'s uniquely "
                                   f"joined IPv{version} connections from {best} in {n} of {total} joins")
        if len(socks) > EXAMPLE_LIMIT or len(partners) > EXAMPLE_LIMIT:
            m.notes.append(f"{len(socks)} connect() record(s) and {len(partners)} network record(s) joined; up to "
                           f"{EXAMPLE_LIMIT} of each are cited")
        return m


CORRELATION_PLAYBOOKS = [InterpreterExternalConnection, ProcessNetworkLink]
