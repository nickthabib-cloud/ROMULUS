"""Host↔network playbooks: process sockets from auditd, and their joins to network-sensor records.

A join is a correlation, never an observation (spec section 1). Each side is an observed fact cited to
its own record; the link between them is inferred from typed address, port and time (and, inside the
network side, from the sensor's own flow identity) and is worded as inferred. A correlated item's lane
is never higher than its strongest observed component.
"""
from __future__ import annotations

import ipaddress
from collections import defaultdict
from datetime import UTC, datetime, timedelta

from romulus.detect.base import Match, Playbook, basename, pf
from romulus.detect.host import INTERPRETERS, WEB_SERVICE_USERS, interpreter_name, is_internal
from romulus.evidence.shellparse import SHELLS
from romulus.evidence.typed import Outcome, TypedEvent

RELAYS = {"nc", "ncat", "netcat", "socat"}
JOIN_BEFORE = timedelta(seconds=3)      # sensor flow start may precede the audit record slightly
JOIN_AFTER = timedelta(seconds=5)
NETWORK_JOIN_FAMILIES = ("net_flow", "net_alert", "http_tx", "tls_session", "ssh_session", "file_transfer")
EXAMPLE_LIMIT = 20


def _ip(value) -> ipaddress._BaseAddress | None:
    try:
        return ipaddress.ip_address(str(value))
    except ValueError:
        return None


def _routable_remote(ip: ipaddress._BaseAddress | None) -> bool:
    return ip is not None and not (ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_link_local)


def connect_phrase(e: TypedEvent) -> str:
    if e.outcome == Outcome.success:
        return "the call succeeded"
    if e.outcome == Outcome.failure:
        return "the call failed"
    if e.get("socket.exit") == "-115":
        return "the connection was started (non-blocking; completion is not recorded)"
    return "the call's outcome is unknown"


def process_interest(e: TypedEvent) -> tuple[str | None, str]:
    """Why a connecting process is notable, and the lane that reason supports (None: not notable).
    Identity comes from kernel-recorded fields only (SYSCALL exe and uid), never from argv text."""
    exe = e.get("process.executable") or ""
    name = interpreter_name(basename(exe))
    user = e.get("process.user") or ""
    euser = e.get("process.effective_user") or ""
    web = user in WEB_SERVICE_USERS or euser in WEB_SERVICE_USERS
    if web and name in INTERPRETERS:
        return f"interpreter '{name}' running as web-service account '{user or euser}'", "high"
    if web:
        return f"process running as web-service account '{user or euser}'", "high"
    if name in SHELLS or name in RELAYS:
        return f"{'shell' if name in SHELLS else 'network relay tool'} '{name}'", "high"
    if name in INTERPRETERS:
        return f"interpreter '{name}'", "lead"
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
    title = "Shell, interpreter, relay tool or web-service process connected to a non-private address"
    families = ("net_socket",)
    required_fields = ("socket.syscall", "process.executable", "destination.ip")
    assures_negative = False
    severity, lane = "high", "lead"
    attack = ("T1059", "T1071", "T1095")
    benign = ("package managers and update checks run from scripts", "monitoring or backup scripts calling out",
              "web applications making approved outbound API calls")
    next_checks = ("process_tree for the connecting process", "network records for the same destination and time",
                   "entity_timeline of the host around the connection")

    def match(self, e: TypedEvent) -> list[Match]:
        if e.get("socket.syscall") != "connect":
            return []
        ip = _ip(e.get("destination.ip"))
        if not _routable_remote(ip) or is_internal(ip):
            return []
        reason, lane = process_interest(e)
        if reason is None:
            return []
        port = e.get("destination.port")
        claim = (f"An auditd connect() record on {e.host} shows {_process_words(e)}, a {reason}, connecting to "
                 f"non-private address {ip} port {port} at {e.ts.isoformat()}; {connect_phrase(e)}.")
        preds = [pf(e, "socket.syscall"), pf(e, "process.executable"), pf(e, "destination.ip")]
        if e.has("process.user"):
            preds.append(pf(e, "process.user"))
        key = f"{e.host}|{e.get('process.executable')}|{e.get('process.user')}|{ip}|{port}"
        return [Match(self.id, claim, self.claim_type, [e], preds, e.ts, self.severity, lane, "high",
                      e.entities(), group_key=key)]


class ProcessNetworkLink(Playbook):
    """Join each IP connect() to network-sensor records for the same remote address and port that start
    within the join window, then pull in every sensor record sharing those flows' community IDs. Publishes
    when the network side carries an IDS alert (the alert gets a process) or the process is notable (the
    process gets its network evidence)."""
    id = "corr.process_network_link"
    title = "Host process connection linked to network-sensor records for the same flow (inferred link)"
    kind = "aggregate"
    claim_type = "correlated_observation"
    families = ("net_socket",) + NETWORK_JOIN_FAMILIES
    required_fields = ()
    # a join that finds nothing proves nothing: sensors and audit rules each see only part of the traffic
    assures_negative = False
    severity, lane = "high", "lead"
    attack = ("T1071", "T1095", "T1571")
    benign = ("the same destination contacted by another host at the same second (shared NAT, proxies)",
              "benign IDS signatures on routine traffic")
    next_checks = ("flow detail for the linked community IDs", "process_tree for the connecting process",
                   "peer activity for the remote address across hosts and sessions")

    def __init__(self):
        super().__init__()
        self.sockets: list[TypedEvent] = []
        self.by_endpoint: dict[tuple[str, int], list[TypedEvent]] = defaultdict(list)
        self.by_community: dict[str, list[TypedEvent]] = defaultdict(list)

    def consume(self, events):
        for e in events:
            if e.family not in self.families:
                continue
            if e.family == "net_socket":
                if e.get("socket.syscall") != "connect":
                    continue
                if not e.has("destination.ip") or e.get("destination.port") is None:
                    self.missing_required += 1
                    continue
                if not _routable_remote(_ip(e.get("destination.ip"))):
                    continue
                self.evaluated += 1
                self.sockets.append(e)
                continue
            dst, port = e.get("destination.ip"), e.get("destination.port")
            if dst is None or port is None:
                continue
            self.evaluated += 1
            try:
                self.by_endpoint[(str(dst), int(port))].append(e)
            except (TypeError, ValueError):
                self.missing_required += 1
                continue
            cid = e.get("network.community_id")
            if cid:
                self.by_community[cid].append(e)
        return []

    def retained_events(self) -> list[TypedEvent]:
        # Any of these may be cited at finalize, whatever order the targets are swept in.
        return self.sockets + [e for evs in self.by_endpoint.values() for e in evs]

    @staticmethod
    def _start(e: TypedEvent) -> datetime:
        start = e.get("flow.start")
        if isinstance(start, str):
            try:
                parsed = datetime.fromisoformat(start)
            except ValueError:
                return e.ts
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
        return e.ts

    def _join(self, s: TypedEvent) -> list[TypedEvent]:
        key = (str(s.get("destination.ip")), int(s.get("destination.port")))
        lo, hi = s.ts - JOIN_BEFORE, s.ts + JOIN_AFTER
        direct = [n for n in self.by_endpoint.get(key, []) if lo <= self._start(n) <= hi]
        linked: dict[str, TypedEvent] = {n.id: n for n in direct}
        for n in direct:
            cid = n.get("network.community_id")
            for m in self.by_community.get(cid, []) if cid else []:
                linked.setdefault(m.id, m)
        return sorted(linked.values(), key=lambda n: (n.ts, n.id))

    def finalize(self):
        joins: dict[str, list[TypedEvent]] = {}
        addresses: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        for s in self.sockets:
            partners = self._join(s)
            if not partners:
                continue
            joins[s.id] = partners
            sources = {str(n.get("source.ip")) for n in partners if n.family == "net_flow" and n.get("source.ip")}
            if len(sources) == 1:
                addresses[s.host or ""][sources.pop()] += 1
        groups: dict[str, list[TypedEvent]] = defaultdict(list)
        for s in self.sockets:
            if s.id in joins:
                key = f"{s.host}|{s.get('process.executable')}|{s.get('process.user')}|" \
                      f"{s.get('destination.ip')}|{s.get('destination.port')}"
                groups[key].append(s)
        out = []
        for key, socks in groups.items():
            socks.sort(key=lambda x: (x.ts, x.id))
            partners: dict[str, TypedEvent] = {}
            for s in socks:
                for n in joins[s.id]:
                    partners.setdefault(n.id, n)
            alerts = [n for n in partners.values() if n.family == "net_alert"]
            reason, process_lane = process_interest(socks[0])
            if not alerts and reason is None:
                continue
            out.append(self._match(key, socks, list(partners.values()), alerts, reason, process_lane, addresses))
        return out

    def _match(self, key, socks, partners, alerts, reason, process_lane, addresses) -> Match:
        s0 = socks[0]
        dst, port = s0.get("destination.ip"), s0.get("destination.port")
        lanes = []
        if alerts:
            lanes.append("high" if any(a.get("alert.severity") == 1 for a in alerts) else "lead")
        if reason is not None:
            lanes.append(process_lane)
        lane = "high" if "high" in lanes else "lead"
        flows = [n for n in partners if n.family == "net_flow"]
        sources = sorted({str(n.get("source.ip")) for n in flows if n.get("source.ip")})
        sigs = sorted({str(a.get("alert.signature")) for a in alerts})
        parts = [(f"Observed on {s0.host} (auditd): {_process_words(s0)} called connect() to {dst} port {port} "
                 f"{len(socks)} time(s) ({socks[0].ts.isoformat()} – {socks[-1].ts.isoformat()}); first call: "
                 f"{connect_phrase(s0)}.")]
        parts.append(f"Observed by network sensors: {len(flows)} flow record(s) to {dst} port {port} starting within "
                     f"seconds of those calls" + (f", from source address(es) {', '.join(sources)}" if sources else "")
                     + (f", and {len(alerts)} IDS alert(s) on the same flows: {'; '.join(sigs[:3])}"
                        + (f" and {len(sigs) - 3} more" if len(sigs) > 3 else "") if alerts else "") + ".")
        parts.append("The link between the host process and these network records is inferred from destination "
                     "address, port and time" + (" and is ambiguous: more than one source address matched"
                                                  if len(sources) > 1 else "") + "; it is not itself observed.")
        if reason is not None:
            parts.append(f"The process is notable as a {reason}.")
        cited = socks[:EXAMPLE_LIMIT] + sorted(partners, key=lambda n: (n.family != "net_alert", n.ts))[:EXAMPLE_LIMIT]
        preds = [pf(s0, "process.executable"), pf(s0, "destination.ip"), pf(s0, "destination.port")]
        if alerts:
            preds.append(pf(alerts[0], "alert.signature"))
        elif flows and flows[0].has("network.community_id"):
            preds.append(pf(flows[0], "network.community_id"))
        m = Match(self.id, " ".join(parts), self.claim_type, cited, preds, s0.ts, self.severity, lane, "medium",
                  s0.entities(), group_key=key)
        seen = addresses.get(s0.host or "", {})
        if seen:
            total = sum(seen.values())
            best, n = max(seen.items(), key=lambda kv: (kv[1], kv[0]))
            m.notes.append(f"inferred, not an asset record: network sensors saw {s0.host}'s joined connections from "
                           f"{best} in {n} of {total} uniquely joined connect() calls")
        if len(socks) > EXAMPLE_LIMIT or len(partners) > EXAMPLE_LIMIT:
            m.notes.append(f"{len(socks)} connect record(s) and {len(partners)} network record(s) joined; "
                           f"up to {EXAMPLE_LIMIT} of each are cited")
        return m


CORRELATION_PLAYBOOKS = [InterpreterExternalConnection, ProcessNetworkLink]
