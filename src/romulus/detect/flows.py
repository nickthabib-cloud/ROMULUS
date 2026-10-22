"""Flow-shape playbooks over bidirectional connection records (Suricata flow records, Arkime sessions).

The families are net_flow (Suricata EVE) and net_session (Arkime SPI).

Record kinds. Suricata writes two record types into net_flow:
- `flow` records are bidirectional: the initiator is the source, and they carry per-direction counters
  (`flow.bytes_toserver`, `flow.bytes_toclient`, `flow.pkts_toserver`, `flow.pkts_toclient`) and `flow.state`.
- `netflow` records are unidirectional: each direction is its own record, so a service's answer appears as a record
  from the server to the client's ephemeral port. They carry only `flow.bytes` and `flow.pkts`.
These rules read `flow` records and Arkime sessions only. A netflow record describes traffic that the same sensor's
flow record also describes, so it is skipped without counting against coverage while that sensor also wrote flow
records in the same batch; a sensor that wrote only netflow records in a batch leaves its traffic unevaluated, and
those records are counted as missing (the coverage cell is partial, never a clean negative).

Connection identity. One connection is named by its transport and its two endpoints in a direction-independent
order (the same identity a community ID hashes), so the same connection seen by Suricata and by Arkime, or by Arkime
in several save-interval records, is counted once. A 5-tuple reused later is the same identity; rules that measure
duration split it again where records are more than STITCH_GAP seconds apart.

Internal and external are the built-in private-address boundary shared with the other network rules.
"""
from __future__ import annotations

import bisect
import ipaddress
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import ClassVar

from romulus.detect.base import Match, Playbook, pf
from romulus.detect.correlation import StageMissing, canon_ip, external, routable_remote
from romulus.detect.netdef import assume_direction
from romulus.evidence.typed import TypedEvent

EXAMPLE_LIMIT = 20
SURICATA, ARKIME = "suricata", "arkime"
SENSOR_NAMES = {SURICATA: "Suricata", ARKIME: "Arkime"}
PORTED = ("tcp", "udp", "sctp")
_DIRECTIONAL = ("flow.state", "flow.bytes_toserver", "flow.bytes_toclient", "flow.pkts_toserver",
                "flow.pkts_toclient")
_UNIDIRECTIONAL = ("flow.bytes", "flow.pkts")
# Connections whose records lie further apart than this are separate connections that reused a 5-tuple. Arkime
# closes an idle TCP session after a few minutes and starts a new record if traffic resumes; 15 minutes keeps an
# idle-but-open connection together while separating a port reused much later.
STITCH_GAP = 900.0
# Suricata counts whole frames. Application bytes in one direction are estimated as the byte count minus a header
# size per packet: for TCP, Ethernet 14 + IPv4 20 + TCP 20 with 12 bytes of timestamp options; for UDP, Ethernet 14 +
# IPv4 20 + UDP 8. These are upper bounds for common IPv4 headers, so the estimate errs low. A direction carried
# application data when the estimate reaches MIN_PAYLOAD_BYTES: handshakes, acknowledgements and keepalives alone
# stay at or below zero.
HEADER_BYTES = {"tcp": 66, "udp": 42}
DEFAULT_HEADER_BYTES = 66
MIN_PAYLOAD_BYTES = 64
# Modern stacks pick client ports from 32768 upwards (Linux 32768-60999, Windows 49152-65535).
EPHEMERAL_FLOOR = 32768


# ---------------------------------------------------------------------------------------------
# protocol and port tables
# ---------------------------------------------------------------------------------------------

def _ports(*items) -> frozenset[int]:
    out: set[int] = set()
    for item in items:
        if isinstance(item, tuple):
            out.update(range(item[0], item[1] + 1))
        else:
            out.add(item)
    return frozenset(out)


_TCP, _UDP, _BOTH = ("tcp",), ("udp",), ("tcp", "udp")
# Registered or conventional server ports per application protocol and transport (IANA assignments plus the
# alternates that are routine for the protocol, such as 8080 for HTTP and the implicit-TLS ports for TLS). A
# protocol on a port outside its own set is a deviation worth a look; the table never decides that it is malicious.
_PROTOCOL_TABLE: tuple[tuple[str, tuple[str, ...], frozenset[int]], ...] = (
    ("http", _TCP, _ports(80, 591, 3128, 5985, 8000, 8008, 8080, 8081, 8088, 8888)),
    ("tls", _TCP, _ports(443, 465, 563, 636, 853, 989, 990, 992, 993, 994, 995, 3269, 3389, 4443, 5061, 5671, 5986,
                         6443, 6514, 6697, 8443, 8883, 9443)),
    ("quic", _UDP, _ports(443)),
    ("dtls", _UDP, _ports(443, 853, 3391, 4433, 5684)),
    ("ssh", _TCP, _ports(22)),
    ("telnet", _TCP, _ports(23)),
    ("ftp", _TCP, _ports(21)),
    ("smtp", _TCP, _ports(25, 587, 2525)),
    ("pop3", _TCP, _ports(110)),
    ("imap", _TCP, _ports(143)),
    ("dns", _BOTH, _ports(53, 5353, 5355)),
    ("mdns", _UDP, _ports(5353)),             # multicast DNS (RFC 6762), as Arkime names it
    ("llmnr", _BOTH, _ports(5355)),           # link-local multicast name resolution (RFC 4795)
    ("krb5", _BOTH, _ports(88, 464)),
    ("ldap", _BOTH, _ports(389, 3268)),
    ("smb", _TCP, _ports(139, 445)),
    ("netbios", _UDP, _ports(137, 138)),
    ("rdp", _BOTH, _ports(3389)),
    ("rfb", _TCP, _ports((5900, 5909))),
    ("x11", _TCP, _ports((6000, 6063))),
    ("sip", _BOTH, _ports(5060, 5061)),
    ("mqtt", _TCP, _ports(1883)),
    ("ntp", _UDP, _ports(123)),
    ("snmp", _UDP, _ports(161, 162)),
    ("dhcp", _UDP, _ports(67, 68, 546, 547)),
    ("tftp", _UDP, _ports(69)),
    ("ike", _UDP, _ports(500, 4500)),
    ("nfs", _BOTH, _ports(2049)),
    ("syslog", _BOTH, _ports(514, 6514)),
    ("radius", _UDP, _ports(1645, 1646, 1812, 1813)),
    ("tacacs", _TCP, _ports(49)),
    ("bgp", _TCP, _ports(179)),
    ("stun", _BOTH, _ports(3478)),
    ("ssdp", _UDP, _ports(1900)),
    ("rtsp", _TCP, _ports(554, 8554)),
    ("mysql", _TCP, _ports(3306)),
    ("postgresql", _TCP, _ports(5432)),
    ("redis", _TCP, _ports(6379)),
    ("mongo", _TCP, _ports(27017)),
    ("kafka", _TCP, _ports(9092)),
    ("irc", _TCP, _ports((6660, 6669), 6697)),
    ("socks", _TCP, _ports(1080)),
    ("modbus", _TCP, _ports(502)),
    ("dnp3", _BOTH, _ports(20000)),
    ("enip", _TCP, _ports(44818)),
    ("enip", _UDP, _ports(44818, 2222)),
    ("s7comm", _TCP, _ports(102)),
    ("iec104", _TCP, _ports(2404)),
    ("opcua", _TCP, _ports(4840)),
    ("bacnet", _UDP, _ports(47808)),
)
PROTOCOL_PORTS: dict[str, dict[str, frozenset[int]]] = {}
for _name, _transports, _set in _PROTOCOL_TABLE:
    for _transport in _transports:
        PROTOCOL_PORTS.setdefault(_name, {})[_transport] = _set
PORT_PROTOCOLS: dict[tuple[str, int], frozenset[str]] = {}
for _name, _by_transport in PROTOCOL_PORTS.items():
    for _transport, _set in _by_transport.items():
        for _port in _set:
            PORT_PROTOCOLS[(_transport, _port)] = PORT_PROTOCOLS.get((_transport, _port), frozenset()) | {_name}

# Protocols that negotiate their ports at run time: on an unregistered port they are not a deviation.
DYNAMIC_PROTOCOLS = frozenset({"dcerpc", "ftp-data", "rtp", "rtcp", "sunrpc", "bittorrent", "bittorrent-dht"})
# Sensor protocol names folded to one name per protocol.
ALIASES = {"https": "tls", "ssl": "tls", "http2": "http", "websocket": "http", "doh2": "http", "gquic": "quic",
           "ikev2": "ike", "smb2": "smb", "krb": "krb5", "kerberos": "krb5", "pgsql": "postgresql",
           "postgres": "postgresql", "mongodb": "mongo", "vnc": "rfb", "nbns": "netbios", "netbios-ns": "netbios"}
# Arkime lists the transport in its protocol field; these are not application protocols.
NON_APPLICATION = frozenset({"tcp", "udp", "icmp", "sctp", "ipv6-icmp", "icmpv6", "esp", "ah", "gre"})
UNIDENTIFIED_NAMES = frozenset({"failed", "unknown", ""})
# Application parsers each sensor runs by default, conservatively: only those present and enabled by default
# across current releases. An unidentified session is judged only against protocols its sensor can parse
# (Suricata has no Kafka parser, so a Suricata flow on 9092 with no protocol says nothing).
PARSERS = {
    SURICATA: frozenset({"http", "tls", "ssh", "dns", "smtp", "ftp", "smb", "nfs", "tftp", "ike", "krb5", "dhcp",
                         "snmp", "sip", "rfb", "mqtt", "rdp", "ntp"}),
    ARKIME: frozenset({"http", "tls", "ssh", "dns", "smtp", "smb", "krb5", "ldap", "dhcp", "ntp", "snmp", "rdp",
                       "mysql", "postgresql", "redis", "mongo", "kafka", "rtsp", "socks", "irc", "quic", "radius",
                       "tacacs", "bgp", "imap", "pop3", "rfb", "sip", "x11", "syslog"}),
}


def canonical_protocol(name: str) -> str:
    name = name.strip().lower()
    return ALIASES.get(name, name)


# Protocols built on another protocol's message syntax, so that protocol's parser labels them with its own name. RTSP
# (RFC 2326, RFC 7826) uses HTTP/1.1 request and response syntax and defines tunnelling through HTTP: a sensor without
# an RTSP parser labels RTSP on its port as HTTP. Keyed by the registered protocol.
SYNTAX_SIBLINGS: dict[str, frozenset[str]] = {"rtsp": frozenset({"http"})}


def standard_on(protocol: str, transport: str, port: int | None) -> bool:
    return port is not None and port in PROTOCOL_PORTS.get(protocol, {}).get(transport, frozenset())


def sibling_label(protocol: str, transport: str, dport: int | None, sensor: str) -> bool:
    """The label is the syntax sibling of a protocol registered on the destination port that this sensor cannot
    parse, so its parser names it by the sibling. A sensor that parses the registered protocol would have named it;
    the source port is never used."""
    return any(protocol in SYNTAX_SIBLINGS.get(registered, ()) and registered not in PARSERS[sensor]
               for registered in expected_protocols(transport, dport))


def expected_protocols(transport: str, port: int | None) -> frozenset[str]:
    return PORT_PROTOCOLS.get((transport, port), frozenset()) if port is not None else frozenset()


def port_ranges(ports) -> str:
    """'22' or '5900-5909, 6000' for a set of ports."""
    values = sorted(ports)
    runs: list[list[int]] = []
    for port in values:
        if runs and port == runs[-1][1] + 1:
            runs[-1][1] = port
        else:
            runs.append([port, port])
    return ", ".join(str(a) if a == b else f"{a}-{b}" for a, b in runs)


# ---------------------------------------------------------------------------------------------
# typed record view
# ---------------------------------------------------------------------------------------------

def _int(value) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None


def _port(value) -> int | None:
    port = _int(value)
    return port if port is not None and 0 <= port <= 65535 else None


def _epoch(value) -> float | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return (parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)).timestamp()


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, UTC).isoformat()


def record_kind(event: TypedEvent) -> str | None:
    """'flow' (bidirectional Suricata flow), 'netflow' (unidirectional Suricata netflow), 'session' (Arkime), or
    None when a net_flow record carries no counters to tell which it is."""
    if event.family == "net_session":
        return "session"
    if event.family != "net_flow":
        return None
    if any(event.has(name) for name in _DIRECTIONAL):
        return "flow"
    if any(event.has(name) for name in _UNIDIRECTIONAL):
        return "netflow"
    return None


@dataclass(frozen=True, slots=True)
class FlowView:
    """One connection record in sensor-neutral typed terms. The source is the initiator as the sensor saw it."""
    sensor: str
    src: str
    sport: int | None
    dst: str
    dport: int | None
    transport: str
    start: float
    end: float
    timed: bool                         # start and end both come from typed fields
    c2s_bytes: int | None               # headers included, initiator to responder
    s2c_bytes: int | None
    s2c_packets: int | None             # packets the responder sent
    payload: bool | None                # application data both ways; None when the counters are absent
    protocols: frozenset[str] | None    # identified application protocols; None when the sensor recorded no field
    failed: bool                        # Suricata reported that protocol detection failed

    @property
    def key(self) -> tuple:
        """Direction-independent connection identity."""
        a = (self.src, -1 if self.sport is None else self.sport)
        b = (self.dst, -1 if self.dport is None else self.dport)
        return (self.transport,) + (a + b if a <= b else b + a)

    @property
    def service(self) -> str:
        return f"{self.transport}/{self.dport}" if self.dport is not None else self.transport


def _framed_payload(transport, c2s_bytes, c2s_packets, s2c_bytes, s2c_packets) -> bool | None:
    """Whether both directions carried application data, estimated from whole-frame bytes and packet counts;
    None when a counter is absent."""
    if None in (c2s_bytes, c2s_packets, s2c_bytes, s2c_packets):
        return None
    header = HEADER_BYTES.get(transport, DEFAULT_HEADER_BYTES)
    return (c2s_bytes - header * c2s_packets >= MIN_PAYLOAD_BYTES
            and s2c_bytes - header * s2c_packets >= MIN_PAYLOAD_BYTES)


def flow_view(event: TypedEvent, kind: str) -> FlowView | None:
    """The typed view of a flow or session record, or None when an identity field is missing or malformed."""
    src, dst = canon_ip(event.get("source.ip")), canon_ip(event.get("destination.ip"))
    transport = event.get("network.transport")
    if src is None or dst is None or not isinstance(transport, str) or not transport:
        return None
    transport = transport.lower()
    sport, dport = _port(event.get("source.port")), _port(event.get("destination.port"))
    if transport in PORTED and dport is None:
        return None
    if transport not in PORTED:
        sport = dport = None
    start, end = _epoch(event.get("flow.start")), _epoch(event.get("flow.end"))
    timed = start is not None and end is not None
    start = start if start is not None else event.ts.timestamp()
    end = max(end if end is not None else start, start)
    if kind == "session":
        sensor = ARKIME
        c2s, s2c = _int(event.get("source.bytes")), _int(event.get("destination.bytes"))
        s2c_packets = _int(event.get("destination.packets"))
        data_c, data_s = _int(event.get("client.bytes")), _int(event.get("server.bytes"))
        if data_c is not None and data_s is not None:
            payload = data_c > 0 and data_s > 0
        else:
            payload = _framed_payload(transport, c2s, _int(event.get("source.packets")), s2c, s2c_packets)
        listed = event.get("network.protocols")
        if listed is None:
            protocols, failed = None, False
        else:
            names = {canonical_protocol(str(p)) for p in (listed if isinstance(listed, list) else [listed])}
            protocols, failed = frozenset(names - NON_APPLICATION - UNIDENTIFIED_NAMES), False
    else:
        sensor = SURICATA
        c2s, s2c = _int(event.get("flow.bytes_toserver")), _int(event.get("flow.bytes_toclient"))
        s2c_packets = _int(event.get("flow.pkts_toclient"))
        payload = _framed_payload(transport, c2s, _int(event.get("flow.pkts_toserver")), s2c, s2c_packets)
        # Suricata writes app_proto only once detection concluded; its absence is the record's own statement that
        # no protocol was identified, and 'failed' says detection gave up.
        app = event.get("network.app_proto")
        name = canonical_protocol(app) if isinstance(app, str) else ""
        failed = name == "failed"
        protocols = frozenset() if name in UNIDENTIFIED_NAMES else frozenset({name})
    return FlowView(sensor, src, sport, dst, dport, transport, start, end, timed, c2s, s2c, s2c_packets, payload,
                    protocols, failed)


def ip_sort_key(ip: str):
    address = ipaddress.ip_address(ip)
    return (address.version, int(address))


def internal_address(ip: str) -> bool:
    """Routable and inside the configured internal space."""
    return routable_remote(ip) and not external(ip)


def _plural(n: int, word: str, plural: str | None = None) -> str:
    return f"{n} {word if n == 1 else (plural or word + 's')}"


def _sensor_counts(counts: Counter) -> str:
    parts = []
    if counts.get(SURICATA):
        parts.append(_plural(counts[SURICATA], "Suricata flow record"))
    if counts.get(ARKIME):
        parts.append(_plural(counts[ARKIME], "Arkime session record"))
    return " and ".join(parts) or "no records"


class _FlowRule(Playbook):
    """Shared plumbing: record-kind selection, netflow accounting, re-read protection and the disk stage."""
    kind = "aggregate"
    anchor_class = "network_observation"
    claim_type = "aggregate_observation"
    staged = True
    families = ("net_flow", "net_session")
    required_fields = ("source.ip", "destination.ip", "network.transport")
    card: ClassVar[dict] = {}

    def __init__(self):
        super().__init__()
        self._seen: set[str] = set()
        self._staged: set[str] = set()
        self._pending: list[TypedEvent] = []
        self.load = lambda ids: []

    def drain_staged(self) -> list[TypedEvent]:
        out, self._pending = self._pending, []
        return out

    def retained_events(self) -> list[TypedEvent]:
        return []                                   # staged on disk instead

    def release_state(self) -> None:
        self.load = lambda ids: []
        for value in vars(self).values():
            if isinstance(value, (dict, list, set)):
                value.clear()

    def _stage(self, event: TypedEvent) -> None:
        if event.id not in self._staged:
            self._staged.add(event.id)
            self._pending.append(event)

    def _events(self, ids) -> list[TypedEvent]:
        wanted = list(dict.fromkeys(ids))
        loaded = self.load(wanted)
        if len(loaded) != len(wanted):
            raise StageMissing(f"{self.id}: {len(wanted) - len(loaded)} cited event(s) absent from the stage")
        return sorted(loaded, key=lambda e: (e.ts, e.id))

    def consume(self, events):
        fresh = [e for e in events if e.family in self.families and e.id not in self._seen]
        flow_observers: set[str | None] = set()
        netflow: Counter = Counter()
        for event in sorted(fresh, key=lambda e: (e.ts, e.id)):
            self._seen.add(event.id)            # re-reading a partition must not count a record twice
            kind = record_kind(event)
            if kind == "netflow":
                netflow[event.host] += 1
                continue
            if kind is None:
                self.missing_required += 1
                continue
            if kind == "flow":
                flow_observers.add(event.host)
            view = flow_view(event, kind)
            if view is None:
                self.missing_required += 1
                continue
            if self.take(view, event):
                self.evaluated += 1
            else:
                self.missing_required += 1
        for observer, count in netflow.items():
            if observer not in flow_observers:
                self.missing_required += count
        return []

    def take(self, view: FlowView, event: TypedEvent) -> bool:
        """Record one typed view. False when a field this rule needs is absent (counted as missing)."""
        raise NotImplementedError


def _entities(events: list[TypedEvent]) -> list[tuple[str, str, str]]:
    seen: dict[tuple[str, str, str], None] = {}
    for event in events:
        for entity in event.entities():
            seen.setdefault(entity, None)
    return list(seen)


def _predicates(event: TypedEvent, names: tuple[str, ...]):
    return [pf(event, name) for name in names if event.has(name)]


# ---------------------------------------------------------------------------------------------
# horizontal sweep
# ---------------------------------------------------------------------------------------------

class _Clusters:
    """Times one source reached one destination, kept as runs whose consecutive gaps are at most the window width.
    Within a run every half-open window that holds one of its times is covered, so the distinct-destination count
    of any window is exact without keeping every time."""
    __slots__ = ("his", "los")

    def __init__(self):
        self.los: list[float] = []
        self.his: list[float] = []

    def add(self, ts: float, gap: float) -> bool:
        """Insert a time; True when it starts a new run."""
        i = bisect.bisect_right(self.los, ts)
        left = i - 1 if i > 0 and ts - self.his[i - 1] <= gap else None
        right = i if i < len(self.los) and self.los[i] - ts <= gap else None
        if left is not None and right is not None:
            self.his[left] = max(self.his[left], self.his[right])
            del self.los[right], self.his[right]
        elif left is not None:
            self.his[left] = max(self.his[left], ts)
        elif right is not None:
            self.los[right] = ts
        else:
            self.los.insert(i, ts)
            self.his.insert(i, ts)
            return True
        return False


@dataclass
class _Destination:
    runs: dict[int, _Clusters]
    answered: bool = False          # some record shows the destination sent a packet back
    silent: bool = False            # some record shows no packet back
    connections: set = field(default_factory=set)
    records: int = 0

    @property
    def state(self) -> str:
        if self.answered:
            return "answered"
        return "no reply" if self.silent else "reply unknown"


@dataclass
class _SweepGroup:
    destinations: dict[str, _Destination] = field(default_factory=dict)
    records: Counter = field(default_factory=Counter)
    first: float = float("inf")
    last: float = float("-inf")
    staged: list[tuple[float, str, str]] = field(default_factory=list)   # (start, event id, destination)
    hour_budget: Counter = field(default_factory=Counter)                # staged re-contact records per hour


@dataclass(frozen=True)
class _Window:
    """One half-open window [start, start + width) and the destinations reached inside it."""
    width: int
    start: float
    members: tuple[str, ...]
    silent: int                     # members that never sent a packet back on any recorded connection

    @property
    def size(self) -> int:
        return len(self.members)


def _window_counts(destinations: dict[str, _Destination], width: int):
    """(window start, destinations inside, silent destinations inside) at every point where the counts can change.
    A destination reached at time s is inside [t, t + width) exactly when s - width < t <= s, so each run [lo, hi]
    covers the window starts (lo - width, hi]; counts are constant between consecutive run edges."""
    opens, closes, silent_opens, silent_closes = [], [], [], []
    for destination in destinations.values():
        runs = destination.runs[width]
        silent = destination.state == "no reply"
        for lo, hi in zip(runs.los, runs.his, strict=True):
            opens.append(lo - width)
            closes.append(hi)
            if silent:
                silent_opens.append(lo - width)
                silent_closes.append(hi)
    for values in (opens, closes, silent_opens, silent_closes):
        values.sort()
    for t in sorted(set(opens) | set(closes)):
        total = bisect.bisect_left(opens, t) - bisect.bisect_left(closes, t)
        silent = bisect.bisect_left(silent_opens, t) - bisect.bisect_left(silent_closes, t)
        yield t, total, silent


def _window_at(destinations: dict[str, _Destination], width: int, t: float) -> _Window:
    members = sorted((ip for ip, destination in destinations.items()
                      if any(lo - width < t <= hi for lo, hi in zip(destination.runs[width].los,
                                                                     destination.runs[width].his, strict=True))),
                     key=ip_sort_key)
    return _Window(width, t, tuple(members), sum(1 for ip in members if destinations[ip].state == "no reply"))


def busiest_window(destinations: dict[str, _Destination], width: int, *, min_size: int = 1,
                   min_silent_share: float = 0.0) -> _Window | None:
    """The window of this width holding the most distinct destinations (the earliest such), among windows with at
    least min_size destinations of which at least min_silent_share never answered; None when no window qualifies."""
    best = None
    for t, total, silent in _window_counts(destinations, width):
        if total >= min_size and silent >= min_silent_share * total and (best is None or total > best[1]):
            best = (t, total)
    return None if best is None else _window_at(destinations, width, best[0])


class HorizontalSweep(_FlowRule):
    """One source reaching many distinct addresses on the same transport and port (or by ICMP) within a short
    window: the shape of host discovery and service sweeps, and of worm-style propagation."""
    id = "net.horizontal_sweep"
    version = "2"
    direction_dependent = True
    title = "One source contacted many distinct addresses on the same port within minutes"
    severity, lane = "medium", "lead"
    attack = ("T1046", "T1018", "T1595.001")
    benign = ("authorized vulnerability scanners and asset-discovery tools",
              "monitoring, backup and management servers polling many hosts",
              "DNS resolvers, mail relays and proxies that reach many external servers on one port")
    next_checks = ("which destinations answered and what the source did with them next (sessions on other ports)",
                   "whether the source is an authorized scanner or management host",
                   "the process on the source host that opened the connections")
    WINDOWS = (300, 3600)
    # Distinct destinations per (source, transport, port) needed in each window. A client normally reaches a
    # handful of internal servers on one port (domain controllers, file and print servers); 20 inside five minutes
    # is well above that and well below even a /27 sweep, and 40 in an hour catches a sweep paced to stay under the
    # short window. External fan-out on one port is routine for resolvers, relays and proxies, so it needs more, and
    # at least half of the destinations in the window must never have answered: browsing reaches many web servers
    # and they all answer.
    THRESHOLDS: ClassVar[dict[str, dict[int, int]]] = {"internal": {300: 20, 3600: 40},
                                                        "external": {300: 50, 3600: 100}}
    EXTERNAL_MIN_SILENT_SHARE = 0.5
    # High: an internal source reaching this many internal addresses over TCP within one hour, at least half of which
    # never sent a packet back on any recorded connection. That is the shape of address-space discovery, not of a
    # service polling the hosts it manages (those answer). TCP only: a TCP connection attempt to a live host draws a
    # SYN-ACK or a reset, so silence means no host or a dropping filter, while UDP and ICMP silence is normal
    # (services that do not answer, one-way announcements, ICMP that is not an echo request).
    HIGH_MIN_DESTINATIONS = 64
    HIGH_MIN_SILENT_SHARE = 0.5
    CONNECTIONS_PER_DESTINATION = 64      # distinct connections counted per destination; beyond it, "at least"
    # The first record of every destination is always staged. A destination reached again after a quiet spell is
    # staged within a per-hour budget, so long-running polling cannot use up the citations a later sweep needs.
    RECONTACT_STAGE_PER_HOUR = 16
    LIST_LIMIT = 30
    card: ClassVar[dict] = {
        "behavior": "one source address reached N distinct destination addresses on the same transport and "
                    "destination port (or by ICMP) within a 5-minute or 60-minute window",
        "telemetry": "Suricata EVE flow records as net_flow (source.ip, destination.ip, destination.port, "
                     "network.transport, flow.start, flow.pkts_toclient) and Arkime sessions as net_session "
                     "(the same address fields, flow.start, destination.packets): present in the lab profile. "
                     "Suricata netflow records are not read (unidirectional; answers carry the client's ephemeral "
                     "port as the destination port)",
        "fidelity": "aggregate observation over typed connection records; 'answered' means the responder sent at "
                    "least one packet on a recorded connection (a TCP reset counts as an answer), 'no reply' means "
                    "every recorded connection shows zero packets from it. Internal or external destinations are "
                    "decided by the site's internal-network definition; under the default (not configured for the "
                    "site) a partition holding an external-scope record, judged by the stricter external standard, "
                    "is partial with the reason 'direction assumed', never a complete negative",
        "benign_and_cost": "authorized scanners, monitoring and management servers polling internal hosts; external "
                           "fan-out from resolvers or relays only when most destinations stay silent. One grouped "
                           "item per (source, transport, port, internal or external destinations)",
        "query_cost": "none beyond the sweep: it reads the flow and session partitions every network rule reads",
        "next_pivot": "the answering destinations and the source's later sessions to them; the source host's "
                      "process for the connections",
        "adds": "net.port_scan counts ports per (source, destination) (vertical); nothing else counts distinct "
                "destinations per (source, port)",
        "research_basis": "ATT&CK Enterprise 20.0 T1046, T1018 and T1595.001 (network traffic flow detection); "
                          "Elastic detection-rules rules/network/discovery_potential_network_sweep_detected.toml at "
                          "commit 0475804db02a36aa0cc9331765424469bac35655 (Elastic License v2: research reference "
                          "only, reimplemented; it counts 100 destinations per source in 9 minutes on nine admin "
                          "ports, this rule counts per port on every port)",
        "retrieval": "the sweep retrieves every record of the network flow datasets and the Arkime session index in "
                     "each partition (dataset filter only), a superset of what this evaluator reads",
        "lanes": "lead by default; high only over TCP for an internal source with some one-hour window holding at "
                 "least 64 internal addresses of which at least half never answered. External destinations need "
                 "at least half silent to be reported at all. Severity medium: discovery precedes, but is not, "
                 "impact",
    }

    def __init__(self):
        super().__init__()
        self.sweeps: dict[tuple, _SweepGroup] = {}

    def take(self, view: FlowView, event: TypedEvent) -> bool:
        if not routable_remote(view.dst):
            return True                 # multicast, broadcast, loopback or link-local: not a host being reached
        scope = "external" if external(view.dst) else "internal"
        if scope == "external":
            # judged by the stricter external fan-out standard; on a site in public space it may be internal
            assume_direction(self)
        key = (view.src, view.transport, view.dport, scope)
        group = self.sweeps.get(key)
        if group is None:
            group = self.sweeps[key] = _SweepGroup()
        destination = group.destinations.get(view.dst)
        new = destination is None
        if new:
            destination = group.destinations[view.dst] = _Destination(runs={w: _Clusters() for w in self.WINDOWS})
        started = {width: destination.runs[width].add(view.start, width) for width in self.WINDOWS}
        if view.s2c_packets is not None:
            if view.s2c_packets > 0:
                destination.answered = True
            else:
                destination.silent = True
        if len(destination.connections) < self.CONNECTIONS_PER_DESTINATION:
            destination.connections.add(view.key)
        destination.records += 1
        group.records[view.sensor] += 1
        group.first, group.last = min(group.first, view.start), max(group.last, view.start)
        hour = int(view.start // 3600)
        if new or (started[self.WINDOWS[0]] and group.hour_budget[hour] < self.RECONTACT_STAGE_PER_HOUR):
            if not new:
                group.hour_budget[hour] += 1
            group.staged.append((view.start, event.id, view.dst))
            self._stage(event)
        return True

    def finalize(self):
        out = []
        for key in sorted(self.sweeps, key=lambda k: (k[0], k[1], -1 if k[2] is None else k[2], k[3])):
            src, transport, _port, scope = key
            group = self.sweeps[key]
            limits = self.THRESHOLDS[scope]
            if len(group.destinations) < min(limits.values()):
                continue
            share = self.EXTERNAL_MIN_SILENT_SHARE if scope == "external" else 0.0
            qualifying = [busiest_window(group.destinations, width, min_size=limits[width], min_silent_share=share)
                          for width in self.WINDOWS]
            qualifying = [window for window in qualifying if window is not None]
            if not qualifying:
                continue
            high = None
            if scope == "internal" and transport == "tcp" and internal_address(src):
                high = busiest_window(group.destinations, 3600, min_size=self.HIGH_MIN_DESTINATIONS,
                                      min_silent_share=self.HIGH_MIN_SILENT_SHARE)
            # the window that decided the lane: the high window, else the widest qualifying window
            deciding = high or max(qualifying, key=lambda window: (window.width, window.size))
            out.append(self._match(key, group, deciding, high is not None))
        return out

    def _match(self, key, group: _SweepGroup, deciding: _Window, high: bool) -> Match:
        src, transport, port, scope = key
        service = f"{transport}/{port}" if port is not None else transport
        short = busiest_window(group.destinations, 300)
        long = busiest_window(group.destinations, 3600)
        dests = group.destinations
        states = Counter(d.state for d in dests.values())
        connections = sum(len(d.connections) for d in dests.values())
        capped = any(len(d.connections) >= self.CONNECTIONS_PER_DESTINATION for d in dests.values())
        src_scope = "internal" if internal_address(src) else "external" if external(src) else "non-routable"
        label = {True: "lane window", False: "deciding window"}[high]
        span = "5 minutes" if deciding.width == 300 else "hour"
        listed = ", ".join(f"{ip} ({_plural(len(dests[ip].connections), 'connection')}, {dests[ip].state})"
                           for ip in deciding.members[:self.LIST_LIMIT])
        more = (f" and {deciding.size - self.LIST_LIMIT} more" if deciding.size > self.LIST_LIMIT else "")
        claim = (f"{src} ({src_scope} address) contacted {len(dests)} distinct {scope} addresses on {service} in the "
                 f"hunt window ({_iso(group.first)} – {_iso(group.last)}): up to {short.size} within 5 minutes (from "
                 f"{_iso(short.start)}) and up to {long.size} within 60 minutes (from {_iso(long.start)}). "
                 f"{'At least ' if capped else ''}{connections} distinct connection(s), each counted once across "
                 f"sensors ({_sensor_counts(group.records)}). Of the {len(dests)} addresses, "
                 f"{states['no reply']} never sent a packet back on any recorded connection, {states['answered']} "
                 f"answered and {states['reply unknown']} have no typed packet count; in the busiest hour "
                 f"{long.silent} of {long.size} never answered. The {label} is the {span} from "
                 f"{_iso(deciding.start)}: {deciding.size} addresses, {deciding.silent} of {deciding.size} never "
                 f"answered. Addresses in the {label}: {listed}{more}.")
        members = set(deciding.members)
        end = deciding.start + deciding.width
        inside = [(dests[ip].state != "no reply", ts, eid) for ts, eid, ip in group.staged
                  if ip in members and deciding.start <= ts < end]
        rest = [(ts, eid) for ts, eid, ip in group.staged if not (ip in members and deciding.start <= ts < end)]
        ids = [eid for _answered, _ts, eid in sorted(inside)] + [eid for _ts, eid in sorted(rest)]
        evs = self._events(ids[:EXAMPLE_LIMIT])
        cited = next((e for e in evs if e.has("destination.port")), evs[0])
        match = Match(self.id, claim, self.claim_type, evs,
                      _predicates(cited, ("source.ip", "destination.ip", "destination.port", "network.transport")),
                      evs[0].ts, self.severity, "high" if high else self.lane, "high", _entities(evs),
                      group_key=f"{src}|{transport}|{port}|{scope}")
        if scope == "internal" and src_scope == "internal":
            match.notes.append("ATT&CK context: T1046 Network Service Discovery / T1018 Remote System Discovery")
        elif scope == "internal":
            match.notes.append("ATT&CK context: T1595.001 Scanning IP Blocks (an outside source sweeping internal "
                               "addresses)")
        else:
            match.notes.append("ATT&CK context: T1046 Network Service Discovery (fan-out to external addresses)")
        if high:
            match.notes.append(f"lane high: {deciding.size} internal addresses over TCP within one hour from an "
                               f"internal source, {deciding.silent} of them never answered")
        return match


# ---------------------------------------------------------------------------------------------
# protocol and port disagreement
# ---------------------------------------------------------------------------------------------

@dataclass
class _Unidentified:
    """One connection's data-carrying records with no identified protocol, on a port registered for a protocol
    the recording sensor can parse."""
    src: str
    sport: int | None
    dst: str
    dport: int
    transport: str
    first: float
    last: float
    event_id: str                   # the connection's first candidate record, kept on the stage for citation
    on_source: bool = False         # the registered port is the initiator's source port
    records: Counter = field(default_factory=Counter)
    failed: int = 0


@dataclass
class _Mismatch:
    connections: set = field(default_factory=set)
    sources: dict[str, set] = field(default_factory=dict)     # source address -> its connections
    records: Counter = field(default_factory=Counter)
    first: float = float("inf")
    last: float = float("-inf")
    cited: list[str] = field(default_factory=list)


SOURCE_LIST_LIMIT = 30


def _address_list(counts: dict[str, int], noun: str) -> str:
    """'2 sources (10.0.0.5: 3, 10.0.0.6: 2)' with every address up to the list limit."""
    ordered = sorted(counts, key=ip_sort_key)
    listed = ", ".join(f"{ip}: {counts[ip]}" for ip in ordered[:SOURCE_LIST_LIMIT])
    more = f" and {len(ordered) - SOURCE_LIST_LIMIT} more" if len(ordered) > SOURCE_LIST_LIMIT else ""
    return f"{_plural(len(ordered), noun)} ({listed}{more})"


def _sources_phrase(counts: dict[str, int]) -> str:
    return "from " + _address_list(counts, "source")


class ProtocolPortMismatch(_FlowRule):
    """A sensor identified an application protocol that is not registered on either port of the connection, or a
    data-carrying connection to a registered port had no protocol identified although the sensor can parse the
    protocol registered there."""
    id = "net.protocol_port_mismatch"
    version = "4"
    title = "Application protocol and port disagree on a connection"
    severity, lane = "medium", "lead"
    attack = ("T1571", "T1572", "T1095")
    assures_negative = False
    positive_only_reason = (
        "protocol identity comes from the sensors' application parsers; a parser that does not recognise traffic, "
        "or recognises it wrongly, shows nothing about what was really sent, so the absence of a disagreement "
        "proves nothing")
    benign = ("internal services deliberately run on custom ports", "proxies and gateways on alternate ports",
              ("sessions the sensor picked up mid-stream or saw in one direction only, which its parser cannot "
               "recognise"))
    next_checks = ("the process on each host that owns the connection",
                   "the first packets of a cited connection (does the payload match the registered protocol?)",
                   "other connections between the same pair and their protocols")
    STAGE_PER_GROUP = EXAMPLE_LIMIT
    card: ClassVar[dict] = {
        "behavior": "(a) an identified application protocol on a connection where neither port is registered for "
                    "it, including a registered port carrying a different identified protocol (ssh on tcp/443); "
                    "(b) a connection to a registered port that carried data both ways with no protocol identified "
                    "by a sensor that parses the protocol registered there; a record whose initiator is on a "
                    "registered port and whose other end is a client port (a reversed or mid-stream view, or a "
                    "program bound to the service port) is judged against its source port, and cleared when a "
                    "forward record of the same connection had its protocol identified. Multicast name "
                    "resolution under its own name (Arkime's mdns on udp/5353, llmnr on 5355) is registered on its "
                    "port, and an HTTP label on a destination port registered for RTSP, from a sensor with no RTSP "
                    "parser (Suricata), is RTSP's own HTTP-based syntax, not a different protocol; Arkime parses "
                    "RTSP, so its HTTP-only label there is still reported",
        "telemetry": "Suricata EVE flow records (network.app_proto, ports, transport, flow.bytes_* and flow.pkts_* "
                     "per direction) and Arkime sessions (network.protocols, ports, transport, client.bytes/"
                     "server.bytes, or source/destination bytes and packets): present in the lab profile, app_proto "
                     "on about 92% of flow records. 'Data both ways' for Suricata is whole-frame bytes minus 66 "
                     "header bytes per packet of at least 64 in each direction",
        "fidelity": "the sensors' protocol identification is typed but is a parser's judgement, not proof; a port "
                    "is checked in both directions, so answers from a registered port (NTP replies to ephemeral "
                    "ports) are consistent. Positive-only",
        "benign_and_cost": "custom service ports, proxies, mid-stream pickups and sensor parser gaps (Kafka without "
                           "a Suricata parser is excluded by the parser table; partial Arkime Kafka recognition "
                           "stays visible as a grouped lead with the destination's identified share). Plain HTTP "
                           "on an RTSP port seen only by Suricata is not told apart from RTSP and is not reported by "
                           "this rule (the HTTP and beaconing rules still read it). One item "
                           "per (destination, port, protocol), or per (destination, port) for unidentified traffic, "
                           "listing every source with its connection count",
        "query_cost": "none beyond the sweep",
        "next_pivot": "the owning processes, and the first packets of a cited connection",
        "adds": "net.long_external_connection and net.beaconing judge timing only; nothing else compares protocol "
                "identity with the port",
        "research_basis": "ATT&CK Enterprise 20.0 T1571 (detection: traffic patterns on ports not associated with "
                          "the protocol), T1572 and T1095; IANA service name and port registry for the port table; "
                          "Suricata and Arkime documentation for the default parser sets; RFC 6762 (mDNS), RFC 4795 "
                          "(LLMNR), RFC 2326 and RFC 7826 (RTSP's HTTP-based syntax and HTTP tunnelling)",
        "retrieval": "the sweep retrieves every record of the network flow datasets and the Arkime session index in "
                     "each partition (dataset filter only), a superset of what this evaluator reads",
        "lanes": "lead: a parser's judgement against a port convention is ambiguous by nature. Severity medium",
    }

    def __init__(self):
        super().__init__()
        self.identified: dict[tuple, dict[str, set[str]]] = {}
        self.unidentified: dict[tuple, _Unidentified] = {}
        self.mismatches: dict[tuple, _Mismatch] = {}
        self.pairs: dict[tuple, dict[str, Counter]] = {}

    def take(self, view: FlowView, event: TypedEvent) -> bool:
        if view.protocols is None:
            return False
        if view.transport not in ("tcp", "udp"):
            return True
        expected = expected_protocols(view.transport, view.dport)
        registered = bool(expected) or bool(expected_protocols(view.transport, view.sport))
        if expected:
            counts = self.pairs.setdefault((view.dst, view.dport, view.transport), {})
            tally = counts.setdefault(view.sensor, Counter())
            tally["records"] += 1
            for protocol in view.protocols:
                tally[protocol] += 1
        if view.protocols:
            # a protocol that negotiates its ports at run time is consistent with any port
            consistent = any(p in DYNAMIC_PROTOCOLS or standard_on(p, view.transport, port)
                             or sibling_label(p, view.transport, view.dport, view.sensor)
                             for p in view.protocols for port in (view.sport, view.dport))
            judged = expected or any(p in PROTOCOL_PORTS for p in view.protocols)
            if registered or (not consistent and judged):
                self.identified.setdefault(view.key, {}).setdefault(view.sensor, set()).update(view.protocols)
            if not consistent and judged:
                group_key = (view.dst, view.dport, view.transport, tuple(sorted(view.protocols)))
                group = self.mismatches.setdefault(group_key, _Mismatch())
                group.connections.add(view.key)
                group.sources.setdefault(view.src, set()).add(view.key)
                group.records[view.sensor] += 1
                group.first, group.last = min(group.first, view.start), max(group.last, view.end)
                if len(group.cited) < self.STAGE_PER_GROUP:
                    group.cited.append(event.id)
                    self._stage(event)
            return True
        capable = expected & PARSERS[view.sensor]
        on_source = False
        if not capable:
            # A record whose initiator sits on a registered port and whose other end is a client port is either a
            # reversed or mid-stream view of a connection to that service, or a client bound to the service port.
            # It is judged against the source port when the sensor can parse that port's protocol; a forward record
            # of the same connection with an identified protocol clears it.
            source_capable = expected_protocols(view.transport, view.sport) & PARSERS[view.sensor]
            if expected or not source_capable or view.dport < EPHEMERAL_FLOOR:
                return True
            on_source = True
        if view.payload is None:
            return False
        if not view.payload:
            return True
        entry = self.unidentified.get(view.key)
        if entry is None:
            # every candidate connection keeps its first record on the stage, so whichever connections stay
            # unidentified after the other sensor's records are in can be cited
            entry = self.unidentified[view.key] = _Unidentified(view.src, view.sport, view.dst, view.dport,
                                                                 view.transport, view.start, view.end, event.id,
                                                                 on_source)
            self._stage(event)
        entry.first, entry.last = min(entry.first, view.start), max(entry.last, view.end)
        entry.records[view.sensor] += 1
        entry.failed += view.failed
        return True

    def finalize(self):
        out = [self._mismatch(key, group) for key, group in sorted(
            self.mismatches.items(), key=lambda item: (ip_sort_key(item[0][0]),) + item[0][1:])]
        groups: dict[tuple, list[_Unidentified]] = defaultdict(list)
        for key, entry in self.unidentified.items():
            if key in self.identified:
                continue                # another record of the same connection had its protocol identified
            if entry.on_source:
                groups[(entry.src, entry.sport, entry.transport, "source")].append(entry)
            else:
                groups[(entry.dst, entry.dport, entry.transport, "destination")].append(entry)
        for key in sorted(groups, key=lambda k: (ip_sort_key(k[0]),) + k[1:]):
            out.append(self._unidentified(key, groups[key]))
        return out

    def _mismatch(self, key, group: _Mismatch) -> Match:
        dst, port, transport, protocols = key
        expected = expected_protocols(transport, port)
        sensors = " and ".join(SENSOR_NAMES[s] for s in sorted(group.records))
        names = ", ".join(protocols)
        port_phrase = (f"{transport}/{port} is registered here for {', '.join(sorted(expected))}" if expected else
                       f"{transport}/{port} is not registered here for any protocol")
        protocol_phrases = []
        for protocol in protocols:
            ports = PROTOCOL_PORTS.get(protocol, {}).get(transport)
            protocol_phrases.append(f"{protocol} is registered on {transport} {port_ranges(ports)}" if ports else
                                    f"{protocol} has no registered {transport} port in the table")
        others: dict[str, set[str]] = defaultdict(set)
        for connection in group.connections:
            for sensor, seen in self.identified.get(connection, {}).items():
                extra = seen - set(protocols)
                if extra:
                    others[sensor].update(extra)
        sources = _sources_phrase({src: len(keys) for src, keys in group.sources.items()})
        claim = (f"{sensors} identified {names} on {_plural(len(group.connections), 'connection')} to {dst} on "
                 f"{transport}/{port} {sources} ({_iso(group.first)} – {_iso(group.last)}; "
                 f"{_sensor_counts(group.records)}). {port_phrase}; {'; '.join(protocol_phrases)}.")
        if others:
            claim += " On the same connection(s) " + "; ".join(
                f"{SENSOR_NAMES[s]} also identified {', '.join(sorted(v))}" for s, v in sorted(others.items())) + "."
        claim += " Protocol identity is the sensor parser's judgement."
        evs = self._events(group.cited)
        match = Match(self.id, claim, "network_observation", evs,
                      _predicates(evs[0], ("source.ip", "destination.ip", "destination.port", "network.app_proto",
                                           "network.protocols")),
                      evs[0].ts, self.severity, self.lane, "medium", _entities(evs),
                      group_key=f"{dst}|{transport}/{port}|{names}")
        match.notes.append("ATT&CK context: T1571 Non-Standard Port; T1572 Protocol Tunneling when a registered port "
                           "carries a different protocol")
        return match

    def _unidentified(self, key, entries: list[_Unidentified]) -> Match:
        server, port, transport, side = key
        expected = expected_protocols(transport, port)
        records: Counter = Counter()
        failed = 0
        for entry in entries:
            records.update(entry.records)
            failed += entry.failed
        first, last = min(e.first for e in entries), max(e.last for e in entries)
        how = []
        if records[SURICATA]:
            missing = records[SURICATA] - failed
            parts = []
            if missing:
                parts.append(f"recorded no app_proto on {_plural(missing, 'flow record')}")
            if failed:
                parts.append(f"reported protocol detection 'failed' on {_plural(failed, 'flow record')}")
            how.append("Suricata " + " and ".join(parts))
        if records[ARKIME]:
            how.append(f"Arkime listed only the transport on {_plural(records[ARKIME], 'session record')}")
        capable = sorted({SENSOR_NAMES[s] for s in records if expected & PARSERS[s]})
        parsable = sorted(expected & set().union(*(PARSERS[s] for s in records)))
        denominators = []
        tallies = self.pairs.get((server, port, transport), {}) if side == "destination" else {}
        for sensor, tally in sorted(tallies.items()):
            identified = ", ".join(f"{p} {n}" for p, n in sorted(tally.items()) if p != "records")
            kind = "flow record" if sensor == SURICATA else "session record"
            denominators.append(f"{SENSOR_NAMES[sensor]} wrote {_plural(tally['records'], kind)} to {server} on "
                                f"this port" + (f", identified as {identified}" if identified else
                                                ", none with an identified protocol"))
        if side == "source":
            peers = _address_list(Counter(entry.dst for entry in entries), "peer")
            subject = (f"{_plural(len(entries), 'connection')} from {server} port {transport}/{port} to {peers}; "
                       f"the registered port is the initiator's source port (a reversed or mid-stream view of a "
                       f"connection to that service, or a program bound to the service port to make outgoing "
                       f"connections)")
        else:
            sources = _sources_phrase(Counter(entry.src for entry in entries))
            subject = f"{_plural(len(entries), 'connection')} to {server} on {transport}/{port} {sources}"
        registered = f"{transport}/{port} is registered here for {', '.join(sorted(expected))}"
        claim = (f"{subject} ({_iso(first)} – {_iso(last)}) carried data in both directions with no application "
                 f"protocol identified: {'; '.join(how)}. {registered}, which {' and '.join(capable)} can parse "
                 f"({', '.join(parsable)}). " + (f"{'; '.join(denominators)}. " if denominators else "")
                 + "A parser that does not recognise traffic is not proof that a different protocol was used.")
        evs = self._events([e.event_id for e in sorted(entries, key=lambda e: (e.first, e.event_id))][:EXAMPLE_LIMIT])
        match = Match(self.id, claim, "network_observation", evs,
                      _predicates(evs[0], ("source.ip", "source.port", "destination.ip", "destination.port",
                                           "network.app_proto", "network.protocols")),
                      evs[0].ts, self.severity, self.lane, "medium", _entities(evs),
                      group_key=f"{server}|{transport}/{port}|unidentified|{side}")
        match.notes.append("ATT&CK context: T1571 Non-Standard Port / T1095 Non-Application Layer Protocol")
        return match


# ---------------------------------------------------------------------------------------------
# long sessions with no identified protocol
# ---------------------------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class _Piece:
    start: float
    end: float
    sensor: str
    identified: bool
    payload: bool
    failed: bool
    capable: bool                   # the sensor parses a protocol registered on the destination port
    event_id: str
    src: str
    dst: str
    dport: int
    transport: str


class LongUnidentifiedSession(_FlowRule):
    """A long connection that carried data both ways while no sensor identified its application protocol, on a
    port that is unregistered or registered only for protocols the recording sensor cannot parse."""
    id = "net.long_unidentified_session"
    version = "3"
    title = "Long data-carrying connection with no identified protocol on a port its sensor cannot judge"
    severity, lane = "medium", "lead"
    attack = ("T1095", "T1571", "T1573")
    assures_negative = False
    positive_only_reason = (
        "'no identified protocol' is a statement about the sensors' parsers, not about the traffic; a custom or "
        "encrypted channel that a parser happens to label is not seen, so the absence of a match proves nothing")
    benign = ("custom or proprietary application protocols on their own ports",
              "message brokers, database replication and streaming clients that hold connections open",
              "VPN and tunnel software on non-default ports")
    next_checks = ("the process on each host that owns the connection",
                   "the first packets of the connection (handshake shape, cleartext, entropy)",
                   "whether the destination port is a documented service at the site")
    MIN_SECONDS = 1800
    STAGE_PER_CONNECTION = 6
    card: ClassVar[dict] = {
        "behavior": "a connection lasted at least 30 minutes (records stitched across sensors and Arkime save "
                    "intervals) and carried data both ways, no sensor identified an application protocol on any of "
                    "its records, and its destination port is registered for no protocol in the table or only for "
                    "protocols no sensor that recorded it can parse (a sensor that can parse the registered protocol "
                    "hands the connection to the protocol/port rule)",
        "telemetry": "Suricata EVE flow records (network.app_proto, flow.start, flow.end, flow.bytes_toserver/"
                     "toclient) and Arkime sessions (network.protocols, flow.start, flow.end, client.bytes/"
                     "server.bytes): present in the lab profile",
        "fidelity": "duration and data volume are typed counters; 'data both ways' is Arkime application payload "
                    "bytes, or for Suricata whole-frame bytes minus 66 header bytes per packet of at least 64 in "
                    "each direction; 'no protocol identified' is the parsers' judgement. Positive-only",
        "benign_and_cost": "custom application protocols, brokers, database pools and replication, VPNs. One item "
                           "per (destination, port, transport), listing every source with its long-connection count",

        "query_cost": "none beyond the sweep",
        "next_pivot": "the owning processes, and the first packets of a cited connection",
        "adds": "net.long_external_connection reports each long Arkime TCP connection across the internal/external "
                "boundary on duration alone; this rule adds protocol identity from both sensors, covers internal "
                "pairs and UDP, and groups a pair's connections. Where both apply the item says so in its notes "
                "rather than suppressing either",
        "research_basis": "ATT&CK Enterprise 20.0 T1095 (detection: traffic that does not follow the expected "
                          "protocol standards and flows), T1571 and T1573",
        "retrieval": "the sweep retrieves every record of the network flow datasets and the Arkime session index in "
                     "each partition (dataset filter only), a superset of what this evaluator reads",
        "lanes": "lead: long unidentified traffic is ambiguous without the owning process. Severity medium",
    }

    def __init__(self):
        super().__init__()
        self.pieces: dict[tuple, list[_Piece]] = defaultdict(list)
        self.staged_per_key: Counter = Counter()
        self.last_staged: dict[tuple, float] = {}

    def take(self, view: FlowView, event: TypedEvent) -> bool:
        if view.transport not in ("tcp", "udp"):
            return True
        expected = expected_protocols(view.transport, view.dport)
        if expected and all(expected & parsers for parsers in PARSERS.values()):
            return True                 # every sensor can parse the registered protocol: the mismatch rule judges it
        if expected_protocols(view.transport, view.sport) and view.dport >= EPHEMERAL_FLOOR:
            # A registered service's side seen as the initiator. When the sensor can parse the service, the
            # protocol/port rule judges the record against the source port (and clears it when a forward record of
            # the same connection was identified); when it cannot, its silence says nothing.
            return True
        if view.protocols is None or not view.timed:
            return False
        if view.payload is None:
            return False
        capable = bool(expected & PARSERS[view.sensor])
        piece = _Piece(view.start, view.end, view.sensor, bool(view.protocols), view.payload, view.failed, capable,
                       event.id, view.src, view.dst, view.dport, view.transport)
        self.pieces[view.key].append(piece)
        if not piece.identified and piece.payload and not capable:
            # the first few candidate records of an identity, and the first of any later connection that reuses it
            last = self.last_staged.get(view.key)
            if self.staged_per_key[view.key] < self.STAGE_PER_CONNECTION or abs(view.start - last) > STITCH_GAP:
                self.staged_per_key[view.key] += 1
                self.last_staged[view.key] = view.start
                self._stage(event)
        return True

    def _connections(self):
        """Stitched connections: records of one identity whose spans lie within STITCH_GAP of each other."""
        for key in sorted(self.pieces):
            pieces = sorted(self.pieces[key], key=lambda p: (p.start, p.end, p.event_id))
            current: list[_Piece] = []
            end = None
            for piece in pieces:
                if current and piece.start > end + STITCH_GAP:
                    yield current
                    current = []
                current.append(piece)
                end = piece.end if len(current) == 1 else max(end, piece.end)
            if current:
                yield current

    def finalize(self):
        groups: dict[tuple, list[list[_Piece]]] = defaultdict(list)
        for pieces in self._connections():
            if any(p.identified or p.capable for p in pieces) or not any(p.payload for p in pieces):
                continue                # identified, owned by the protocol/port rule, or never carried data
            first = pieces[0]
            groups[(first.dst, first.dport, first.transport)].append(pieces)
        out = []
        for key in sorted(groups, key=lambda k: (ip_sort_key(k[0]),) + k[1:]):
            connections = groups[key]
            spans = [(max(p.end for p in c) - c[0].start, c) for c in connections]
            long = [(span, c) for span, c in spans if span >= self.MIN_SECONDS]
            if long:
                out.append(self._match(key, connections, long))
        return out

    def _match(self, key, connections, long) -> Match:
        dst, port, transport = key
        longest, longest_conn = max(long, key=lambda item: (item[0], -item[1][0].start))
        records: Counter = Counter(p.sensor for c in connections for p in c)
        failed = sum(p.failed for c in connections for p in c)
        sensors = " or ".join(SENSOR_NAMES[s] for s in sorted(records))
        expected = expected_protocols(transport, port)
        registration = (f"{transport}/{port} is registered here for {', '.join(sorted(expected))}, which {sensors} "
                        f"cannot parse" if expected else f"{transport}/{port} is registered here for no protocol")
        sources = _sources_phrase(Counter(c[0].src for _span, c in long))
        claim = (f"{_plural(len(long), 'connection')} to {dst} on {transport}/{port} {sources} lasted at least "
                 f"{self.MIN_SECONDS // 60} minutes with data in both directions and no application protocol "
                 f"identified by {sensors}; the longest ran {longest / 60:.0f} minutes ({_iso(longest_conn[0].start)} "
                 f"– {_iso(max(p.end for p in longest_conn))}, from {longest_conn[0].src}). "
                 f"{_plural(len(connections), 'unidentified data-carrying connection')} to it on this port "
                 f"in total ({_sensor_counts(records)}"
                 + (f"; Suricata reported protocol detection 'failed' on {failed}" if failed else "") + "). "
                 f"{registration}. Times are as the sensors recorded them.")
        ids = [p.event_id for _span, c in sorted(long, key=lambda item: (-item[0], item[1][0].start))
               for p in c if not p.identified and p.payload and p.event_id in self._staged]
        ids += [p.event_id for c in connections for p in c if p.event_id in self._staged]
        evs = self._events(list(dict.fromkeys(ids))[:EXAMPLE_LIMIT])
        match = Match(self.id, claim, "network_observation", evs,
                      _predicates(evs[0], ("source.ip", "destination.ip", "destination.port", "flow.start",
                                           "flow.end")),
                      evs[0].ts, self.severity, self.lane, "medium", _entities(evs),
                      group_key=f"{dst}|{transport}/{port}")
        if transport == "tcp" and any(external(c[0].src) != external(dst) for _span, c in long):
            match.notes.append("net.long_external_connection reports each long TCP connection across the "
                               "internal/external boundary on its own (duration); this item adds that no sensor "
                               "identified an application protocol, groups every client of the port, and counts "
                               "the shorter connections")
        match.notes.append("ATT&CK context: T1095 Non-Application Layer Protocol / T1571 Non-Standard Port")
        return match


# ---------------------------------------------------------------------------------------------
# outbound volume asymmetry
# ---------------------------------------------------------------------------------------------

@dataclass
class _Pair:
    connections: dict[tuple, dict[str, list[int]]] = field(default_factory=dict)   # key -> sensor -> [out, in, n]
    ports: Counter = field(default_factory=Counter)
    first: float = float("inf")
    last: float = float("-inf")
    cited: list[tuple[int, str]] = field(default_factory=list)                   # (outbound bytes, event id)


class OutboundVolumeAsymmetry(_FlowRule):
    """An internal address sent far more to one external address than it received back, in absolute and relative
    terms, with the source's own outbound total as the denominator."""
    id = "net.outbound_volume_asymmetry"
    version = "1"
    title = "Internal address sent much more data to one external address than it received"
    severity, lane = "high", "lead"
    attack = ("T1041", "T1048", "T1567")
    assures_negative = False
    positive_only_reason = (
        "internal and external are judged from the built-in private-address list, not the site's own address plan, "
        "and only connections that internal addresses initiated are read; transfers outside that view are not "
        "evaluated, so the absence of a match proves nothing")
    benign = ("backups and cloud file synchronisation", "log and telemetry shipping", "video and media uploads",
              "software publishing to external repositories")
    next_checks = ("the process on the internal host that owns the connections",
                   "files archived, compressed or staged on the internal host shortly before",
                   "what the destination is (ownership, other internal clients, reputation)")
    MIN_OUTBOUND_BYTES = 50 * 2**20
    MIN_RATIO = 10.0
    CITE_BYTES = 2**20
    FIRST_CITES = 3
    card: ClassVar[dict] = {
        "behavior": "an internal address sent at least 50 MiB to one external address over connections it "
                    "initiated in the hunt window, at least ten times what it received back from it",
        "telemetry": "Suricata EVE flow records (flow.bytes_toserver, flow.bytes_toclient) and Arkime sessions "
                     "(source.bytes, destination.bytes): present in the lab profile on every record. Suricata "
                     "netflow records are not read",
        "fidelity": "typed byte counters (headers included); each connection is counted once, from the sensor "
                    "that recorded the most bytes for it. Volume and ratio are a deviation, not proof of theft",
        "benign_and_cost": "backups, cloud sync, log shipping, media uploads (the lab carries CCTV traffic). One "
                           "item per (internal source, external destination); the claim gives the destination's "
                           "other internal senders for prevalence",
        "query_cost": "none beyond the sweep",
        "next_pivot": "the uploading process and staging (archives, encoders) on the source host",
        "adds": "no other rule measures byte asymmetry",
        "research_basis": "ATT&CK Enterprise 20.0 T1041, T1048 and T1567 (detection: network traffic flow, "
                          "uncommon data flows and outbound volume relative to inbound)",
        "retrieval": "the sweep retrieves every record of the network flow datasets and the Arkime session index in "
                     "each partition (dataset filter only), a superset of what this evaluator reads",
        "lanes": "lead: large uploads are common and legitimate; severity high because exfiltration, if that is what "
                 "it is, is high impact. 50 MiB in one hunt window is above routine client chatter and well below "
                 "bulk backup volumes; a 10:1 ratio excludes interactive and download-heavy traffic",
    }

    def __init__(self):
        super().__init__()
        self.pairs: dict[tuple[str, str], _Pair] = {}

    def take(self, view: FlowView, event: TypedEvent) -> bool:
        if view.c2s_bytes is None or view.s2c_bytes is None:
            return False
        if not (internal_address(view.src) and external(view.dst)):
            return True
        pair = self.pairs.get((view.src, view.dst))
        if pair is None:
            pair = self.pairs[(view.src, view.dst)] = _Pair()
        per_sensor = pair.connections.setdefault(view.key, {})
        tally = per_sensor.setdefault(view.sensor, [0, 0, 0])
        tally[0] += view.c2s_bytes
        tally[1] += view.s2c_bytes
        tally[2] += 1
        if view.dport is not None:
            pair.ports[f"{view.transport}/{view.dport}"] += 1
        pair.first, pair.last = min(pair.first, view.start), max(pair.last, view.end)
        if len(pair.cited) < self.FIRST_CITES or (view.c2s_bytes >= self.CITE_BYTES
                                                   and len(pair.cited) < EXAMPLE_LIMIT):
            pair.cited.append((view.c2s_bytes, event.id))
            self._stage(event)
        return True

    @staticmethod
    def _resolve(pair: _Pair) -> tuple[int, int, Counter]:
        """Outbound and inbound bytes with each connection counted once, from its best-recorded sensor."""
        out = inn = 0
        records: Counter = Counter()
        for per_sensor in pair.connections.values():
            sensor = max(sorted(per_sensor), key=lambda s: per_sensor[s][0] + per_sensor[s][1])
            out += per_sensor[sensor][0]
            inn += per_sensor[sensor][1]
            for name, tally in per_sensor.items():
                records[name] += tally[2]
        return out, inn, records

    def finalize(self):
        resolved = {key: self._resolve(pair) for key, pair in self.pairs.items()}
        totals: Counter = Counter()
        senders: dict[str, set[str]] = defaultdict(set)
        for (src, dst), (out, _inn, _records) in resolved.items():
            totals[src] += out
            if out > 0:
                senders[dst].add(src)
        matches = []
        for (src, dst) in sorted(resolved):
            out, inn, records = resolved[(src, dst)]
            if out < self.MIN_OUTBOUND_BYTES or out < self.MIN_RATIO * inn:
                continue
            matches.append(self._match(src, dst, out, inn, records, totals[src], len(senders[dst] - {src})))
        return matches

    def _match(self, src, dst, out, inn, records, total, others) -> Match:
        pair = self.pairs[(src, dst)]
        ratio = f"{out / inn:.1f}:1 outbound to inbound" if inn else "nothing came back"
        ports = ", ".join(f"{p} ({n})" for p, n in sorted(pair.ports.items(), key=lambda i: (-i[1], i[0]))[:5])
        claim = (f"{src} sent {out:,} bytes ({out / 2**20:.1f} MiB) to {dst} and received {inn:,} bytes back over "
                 f"{_plural(len(pair.connections), 'connection')} it initiated ({_iso(pair.first)} – "
                 f"{_iso(pair.last)}; {ratio}; ports {ports}). That is {out / total:.0%} of the {total:,} bytes "
                 f"{src} sent to external addresses in the hunt window. Byte counts include packet headers and each "
                 f"connection is counted once, from the sensor that recorded the most bytes for it "
                 f"({_sensor_counts(records)}). {_plural(others, 'other internal address', 'other internal addresses')}"
                 f" also sent data to {dst} in the window. Volume is a deviation, not proof that data was stolen.")
        ids = [eid for _bytes, eid in sorted(pair.cited, key=lambda item: (-item[0], item[1]))][:EXAMPLE_LIMIT]
        evs = self._events(ids)
        cited = next((e for e in evs if e.has("flow.bytes_toserver") or e.has("source.bytes")), evs[0])
        match = Match(self.id, claim, "aggregate_observation", evs,
                      _predicates(cited, ("source.ip", "destination.ip", "flow.bytes_toserver", "flow.bytes_toclient",
                                          "source.bytes", "destination.bytes")),
                      evs[0].ts, self.severity, self.lane, "medium", _entities(evs), group_key=f"{src}|{dst}")
        match.notes.append("ATT&CK context: T1041 / T1048 / T1567 (exfiltration), if the transfer is unauthorized")
        return match


FLOW_PLAYBOOKS = [HorizontalSweep, ProtocolPortMismatch, LongUnidentifiedSession, OutboundVolumeAsymmetry]
