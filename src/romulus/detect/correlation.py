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
from romulus.detect.host import INTERPRETERS, WEB_SERVICE_USERS, interpreter_name, is_internal
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


class InterpreterExternalConnection(Playbook):
    """Positive-only: the audit rule set's scope (syscalls, families, ports) is not visible in telemetry,
    so a missing connect record never proves a connection did not happen."""
    id = "host.interpreter_external_connection"
    version = "2"
    title = "Shell, interpreter, relay tool or web-service process made a connect() call to a non-private address"
    families = ("net_socket",)
    required_fields = ("socket.syscall", "process.executable", "destination.ip")
    assures_negative = False
    severity, lane = "high", "lead"
    attack = ("T1059", "T1071", "T1095")
    benign = ("package managers and update checks run from scripts", "monitoring or backup scripts calling out",
              "web applications making approved outbound API calls",
              "name resolution: resolvers and address sorting call connect() on UDP sockets")
    next_checks = ("process_tree for the connecting process", "network records for the same destination and time",
                   "entity_timeline of the host around the connection")

    def match(self, e: TypedEvent) -> list[Match]:
        if e.get("socket.syscall") != "connect":
            return []
        ip, port = canon_ip(e.get("destination.ip")), e.get("destination.port")
        if not external(ip) or not port:          # port 0: a route probe, never a connection
            return []
        reason, lane = process_interest(e)
        if reason is None:
            return []
        claim = (f"An auditd connect() record on {e.host} shows {_process_words(e)}, {reason}, calling connect() "
                 f"to non-private address {ip} port {port} at {e.ts.isoformat()}; {connect_phrase(e)}. "
                 f"{SOCKET_TYPE_CAVEAT[0].upper()}{SOCKET_TYPE_CAVEAT[1:]}.")
        preds = [pf(e, "socket.syscall"), pf(e, "process.executable"), pf(e, "destination.ip")]
        if e.has("process.user"):
            preds.append(pf(e, "process.user"))
        # the outcome is part of the identity: a refused call must never hide a later successful one
        key = f"{e.host}|{e.get('process.executable')}|{e.get('process.user')}|{ip}|{port}|{e.outcome}"
        return [Match(self.id, claim, self.claim_type, [e], preds, e.ts, self.severity, lane, "high",
                      e.entities(), group_key=key)]


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
        self._seen: set[str] = set()
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
            f"Observed on {s0.host} (auditd): {_process_words(first)} made {len(socks)} connect() call(s) to "
            f"{s0.ip} port {s0.port} that join network records "
            f"({datetime.fromtimestamp(socks[0].ts, UTC).isoformat()} – "
            f"{datetime.fromtimestamp(socks[-1].ts, UTC).isoformat()}); {outcome_words}. {SOCKET_TYPE_CAVEAT}.",
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
