"""Flow-shape playbooks over bidirectional connection records (Suricata flow records, Arkime sessions).

The families are net_flow (Suricata EVE) and net_session (Arkime SPI).

Record kinds. Suricata writes two record types into net_flow:
- `flow` records are bidirectional: the source is the side that sent the first packet Suricata saw, and they carry
  per-direction counters (`flow.bytes_toserver`, `flow.bytes_toclient`, `flow.pkts_toserver`, `flow.pkts_toclient`)
  and `flow.state`.
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

Which side opened a connection. Both sensors orient a record by the first packet they saw, so a connection picked
up mid-stream (the capture started late, the sensor dropped packets, or Arkime closed a session and opened a new one
on the same traffic) is recorded with whichever side spoke first as its source. A record states the opener only when
it shows the opening (FlowView.opened); otherwise its source is just the side the sensor recorded first, and claims
say so instead of naming an initiator.

Internal and external come from the site's internal-network definition (romulus.detect.netdef), shared with the
other network rules.
"""
from __future__ import annotations

import bisect
import heapq
import ipaddress
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import ClassVar

from romulus.detect.base import Match, Playbook, pf
from romulus.detect.bounded import HOT_COUNT, KeyedStore, Limit, RecentIds
from romulus.detect.citing import BoundStage, Ends, bound_note, cite_with_bounds, cited_phrase
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
# A record shows which side opened a TCP connection only when its sensor saw the opening.
# - Arkime makes the sender of a session's first packet its source, swapping the two sides only when that packet is a
#   SYN-ACK, and counts pure SYNs in tcpflags.syn (capture/parsers/tcp.c, tcp_pre_process and tcp_packet_process). A
#   session that counted a SYN normally began with it, so its source sent it. The exception is a reused 5-tuple whose
#   new SYN lands on an older session Arkime picked up mid-stream and never saw close; the rule that reads this treats
#   records of one connection that disagree about the opener as unknown. A SYN-ACK alone is not taken: it can land on
#   such a session the same way.
# - Suricata tracks a TCP session only from its opening SYN while stream.midstream is off (its default), marks the
#   flow established or closed only for a session it tracked, and records the flow from the side that sent the first
#   packet. A flow it picked up mid-stream stays 'new'. A sensor run with midstream pickup enabled marks picked-up
#   sessions established too, and this reading does not hold there.
# Anything else (a session picked up mid-stream, UDP and other connectionless traffic, a record without the fields)
# leaves the opener unknown.
OPENED_STATES = frozenset({"established", "closed"})
# States folded at finalize are written out to disk every this many reads.
FINALIZE_TRIM = 10_000


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
    """One connection record in sensor-neutral typed terms. The source is the side the sensor recorded first; it is
    the side that opened the connection only when `opened` is True."""
    sensor: str
    src: str
    sport: int | None
    dst: str
    dport: int | None
    transport: str
    start: float
    end: float
    timed: bool                         # start and end both come from typed fields
    c2s_bytes: int | None               # headers included, sent by the source side
    s2c_bytes: int | None               # sent by the destination side
    s2c_packets: int | None             # packets the destination side sent
    payload: bool | None                # application data both ways; None when the counters are absent
    protocols: frozenset[str] | None    # identified application protocols; None when the sensor recorded no field
    failed: bool                        # Suricata reported that protocol detection failed
    opened: bool = False                # a typed field shows the source opened the TCP connection (OPENED_STATES)
    c2s_data: int | None = None         # application bytes the source side sent (Arkime's own count, else estimated)
    s2c_data: int | None = None         # ... and the destination side; None when the counters are absent

    @property
    def key(self) -> tuple:
        """Direction-independent connection identity."""
        a = (self.src, -1 if self.sport is None else self.sport)
        b = (self.dst, -1 if self.dport is None else self.dport)
        return (self.transport,) + (a + b if a <= b else b + a)

    @property
    def service(self) -> str:
        return f"{self.transport}/{self.dport}" if self.dport is not None else self.transport


def _framed_data(transport, frame_bytes, packets) -> int | None:
    """Application bytes one side sent, estimated from whole-frame bytes and packets (0 for headers alone); None when
    a counter is absent."""
    if frame_bytes is None or packets is None:
        return None
    return max(frame_bytes - HEADER_BYTES.get(transport, DEFAULT_HEADER_BYTES) * packets, 0)


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
        c2s_packets = _int(event.get("source.packets"))
        if data_c is not None and data_s is not None:
            payload = data_c > 0 and data_s > 0
        else:
            payload = _framed_payload(transport, c2s, c2s_packets, s2c, s2c_packets)
            data_c, data_s = _framed_data(transport, c2s, c2s_packets), _framed_data(transport, s2c, s2c_packets)
        listed = event.get("network.protocols")
        if listed is None:
            protocols, failed = None, False
        else:
            names = {canonical_protocol(str(p)) for p in (listed if isinstance(listed, list) else [listed])}
            protocols, failed = frozenset(names - NON_APPLICATION - UNIDENTIFIED_NAMES), False
        syn = _int(event.get("tcp.flags.syn"))
        opened = transport == "tcp" and syn is not None and syn > 0
    else:
        sensor = SURICATA
        c2s, s2c = _int(event.get("flow.bytes_toserver")), _int(event.get("flow.bytes_toclient"))
        s2c_packets = _int(event.get("flow.pkts_toclient"))
        c2s_packets = _int(event.get("flow.pkts_toserver"))
        payload = _framed_payload(transport, c2s, c2s_packets, s2c, s2c_packets)
        data_c, data_s = _framed_data(transport, c2s, c2s_packets), _framed_data(transport, s2c, s2c_packets)
        # Suricata writes app_proto only once detection concluded; its absence is the record's own statement that
        # no protocol was identified, and 'failed' says detection gave up.
        app = event.get("network.app_proto")
        name = canonical_protocol(app) if isinstance(app, str) else ""
        failed = name == "failed"
        protocols = frozenset() if name in UNIDENTIFIED_NAMES else frozenset({name})
        state = event.get("flow.state")
        opened = transport == "tcp" and isinstance(state, str) and state in OPENED_STATES
    return FlowView(sensor, src, sport, dst, dport, transport, start, end, timed, c2s, s2c, s2c_packets, payload,
                    protocols, failed, opened, data_c, data_s)


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
        self._seen = RecentIds()        # bounded re-read guard
        self._staged = RecentIds()      # bounded re-stage guard
        self._pending: list[TypedEvent] = []
        self.bounds = BoundStage()      # records bounding the intervals claims state, staged when a batch ends
        self.load = lambda ids: []

    def drain_staged(self) -> list[TypedEvent]:
        out, self._pending = self._pending + self.bounds.drain(), []
        for value in list(vars(self).values()):
            if isinstance(value, KeyedStore):
                value.trim()                        # a batch has ended: states beyond the hot sets go to disk
        return out

    def drain_bounds(self) -> tuple[list[str], list[str]]:
        return self.bounds.last

    def retained_events(self) -> list[TypedEvent]:
        return []                                   # staged on disk instead

    def release_state(self) -> None:
        self.load = lambda ids: []
        for value in list(vars(self).values()):
            if isinstance(value, (dict, list, set, RecentIds, KeyedStore, BoundStage)):
                value.clear()
        self.close_spill()

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

    def _cite(self, ends: Ends, ids, limit: int = EXAMPLE_LIMIT) -> tuple[list[TypedEvent], set[str]]:
        """The cited records: the records bounding the claim's interval first, when the stage holds them, then `ids`
        (each of them staged) up to `limit`. Returns the events and the bounding ids the stage does not hold."""
        return cite_with_bounds(self.load, self._events, ends, ids, limit)

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
            taken = self.take(view, event)
            if taken:
                self.evaluated += 1
            elif taken is not None:             # None: a disk budget refused the record (counted as capped)
                self.missing_required += 1
        for observer, count in netflow.items():
            if observer not in flow_observers:
                self.missing_required += count
        return []

    def take(self, view: FlowView, event: TypedEvent) -> bool | None:
        """Record one typed view. False when a field this rule needs is absent (counted as missing); None when a
        disk budget refused it (counted as capped)."""
        raise NotImplementedError

    def _refused(self, what: str) -> None:
        """A store's disk budget is spent: the record is refused and coverage says so."""
        self.refuse("disk", f"the {what} disk budget is spent; a record needing a new one is not evaluated")


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
    staged: list[tuple[float, str]] = field(default_factory=list)       # (start, event id) on the stage

    @property
    def state(self) -> str:
        if self.answered:
            return "answered"
        return "no reply" if self.silent else "reply unknown"


@dataclass
class _SweepGroup:
    reached: int = 0                                                     # distinct destinations
    records: Counter = field(default_factory=Counter)
    first: float = float("inf")
    last: float = float("-inf")
    hour_budget: Counter = field(default_factory=Counter)                # staged re-contact records per hour
    ends: Ends = field(default_factory=Ends)                             # the records with the first and last start


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
    version = "5"
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

    # Whole-window distinct destinations need every (group, destination) for the window; the sensors' records of one
    # connection arrive in different targets, so they cannot be released early. Group summaries and destinations
    # (about 600 bytes each with runs and up to 64 connection hashes) are held in keyed stores: HOT in memory, the
    # rest on disk; only their disk budget refuses a record needing a new one. Finalize reads one group's
    # destinations at a time, and only for groups with enough destinations to qualify.
    HOT_GROUPS = HOT_COUNT  # a count cap only: the hunt's memory budget sizes it in bytes
    HOT_DESTINATIONS = HOT_COUNT  # a count cap only: the hunt's memory budget sizes it in bytes

    def __init__(self):
        super().__init__()
        self.sweeps = KeyedStore(self, "sweep_groups", self.HOT_GROUPS)
        self.destinations = KeyedStore(self, "sweep_destinations", self.HOT_DESTINATIONS,
                                       group=lambda key: repr(key[0]))      # (group key, destination address)

    def take(self, view: FlowView, event: TypedEvent) -> bool | None:
        if not routable_remote(view.dst):
            return True                 # multicast, broadcast, loopback or link-local: not a host being reached
        scope = "external" if external(view.dst) else "internal"
        key = (view.src, view.transport, view.dport, scope)
        group = self.sweeps.get(key)
        if group is None:
            group = _SweepGroup()
            if not self.sweeps.put(key, group):
                return self._refused("sweep groups'")
        destination = self.destinations.get((key, view.dst))
        new = destination is None
        if new:
            destination = _Destination(runs={w: _Clusters() for w in self.WINDOWS})
            if not self.destinations.put((key, view.dst), destination):
                return self._refused("destinations'")
            group.reached += 1
        if scope == "external":
            # judged (not refused) by the stricter external fan-out standard; on a site in public space it may be
            # internal, so the direction is an assumption
            assume_direction(self)
        started = {width: destination.runs[width].add(view.start, width) for width in self.WINDOWS}
        if view.s2c_packets is not None:
            if view.s2c_packets > 0:
                destination.answered = True
            else:
                destination.silent = True
        if len(destination.connections) < self.CONNECTIONS_PER_DESTINATION:
            destination.connections.add(hash(view.key))      # a connection identity, counted (8 bytes, not a tuple)
        destination.records += 1
        group.records[view.sensor] += 1
        group.first, group.last = min(group.first, view.start), max(group.last, view.start)
        # the group's bounds are staged once it has enough destinations to qualify; before that they are tracked
        # (its first record is a destination's first record, staged above)
        self.bounds.offer(key, group.ends, view.start, view.start, event,
                          stage=group.reached >= min(self.THRESHOLDS[scope].values()))
        hour = int(view.start // 3600)
        if new or (started[self.WINDOWS[0]] and group.hour_budget[hour] < self.RECONTACT_STAGE_PER_HOUR):
            if not new:
                group.hour_budget[hour] += 1
            destination.staged.append((view.start, event.id))
            self._stage(event)
        return True

    def _groups(self):
        """(group key, summary, destinations) for every group with enough destinations to qualify, one group's
        destinations in memory at a time."""
        key = summary = None
        dests: dict[str, _Destination] = {}
        for (group_key, ip), destination in self.destinations.grouped():
            if group_key != key:
                if dests:
                    yield key, summary, dests
                key, dests = group_key, {}
                summary = self.sweeps.peek(key)
                if summary is not None and summary.reached < min(self.THRESHOLDS[key[3]].values()):
                    summary = None
            if summary is not None:
                dests[ip] = destination
        if dests:
            yield key, summary, dests

    def finalize(self):
        out = []
        for key, group, dests in self._groups():
            src, transport, _port, scope = key
            limits = self.THRESHOLDS[scope]
            share = self.EXTERNAL_MIN_SILENT_SHARE if scope == "external" else 0.0
            qualifying = [busiest_window(dests, width, min_size=limits[width], min_silent_share=share)
                          for width in self.WINDOWS]
            qualifying = [window for window in qualifying if window is not None]
            if not qualifying:
                continue
            high = None
            if scope == "internal" and transport == "tcp" and internal_address(src):
                high = busiest_window(dests, 3600, min_size=self.HIGH_MIN_DESTINATIONS,
                                      min_silent_share=self.HIGH_MIN_SILENT_SHARE)
            # the window that decided the lane: the high window, else the widest qualifying window
            deciding = high or max(qualifying, key=lambda window: (window.width, window.size))
            out.append(((key[0], key[1], -1 if key[2] is None else key[2], key[3]),
                        self._match(key, group, dests, deciding, high is not None)))
        return [match for _order, match in sorted(out, key=lambda item: item[0])]

    def _match(self, key, group: _SweepGroup, dests: dict[str, _Destination], deciding: _Window,
               high: bool) -> Match:
        src, transport, port, scope = key
        service = f"{transport}/{port}" if port is not None else transport
        short = busiest_window(dests, 300)
        long = busiest_window(dests, 3600)
        states = Counter(d.state for d in dests.values())
        connections = sum(len(d.connections) for d in dests.values())
        capped = any(len(d.connections) >= self.CONNECTIONS_PER_DESTINATION for d in dests.values())
        if capped:
            self.note_limit("connections", f"a destination passed {self.CONNECTIONS_PER_DESTINATION:,} distinct "
                                           f"connections held; its connection count is a lower bound")
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
        staged = [(ts, eid, ip) for ip, destination in dests.items() for ts, eid in destination.staged]
        inside = [(dests[ip].state != "no reply", ts, eid) for ts, eid, ip in staged
                  if ip in members and deciding.start <= ts < end]
        rest = [(ts, eid) for ts, eid, ip in staged if not (ip in members and deciding.start <= ts < end)]
        # the hunt-window span's first and last records, then the deciding window's first and last cited records,
        # then the window's records (silent destinations first) and the rest
        timed = sorted((ts, eid) for _answered, ts, eid in inside)
        window = [timed[0][1], timed[-1][1]] if timed else []
        ids = window + [eid for _answered, _ts, eid in sorted(inside)] + [eid for _ts, eid in sorted(rest)]
        evs, missing = self._cite(group.ends, ids)
        claim += bound_note(missing, group.ends, "the hunt-window span")
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
    on_source: bool = False         # the registered port is the recorded source side's port
    records: Counter = field(default_factory=Counter)
    failed: int = 0
    ends: Ends = field(default_factory=Ends)


@dataclass
class _Mismatch:
    connections: set = field(default_factory=set)
    capped: bool = False                                      # connections beyond the per-group cap were not held
    sources: dict[str, set] = field(default_factory=dict)     # source address -> its connections
    records: Counter = field(default_factory=Counter)
    first: float = float("inf")
    last: float = float("-inf")
    cited: list[str] = field(default_factory=list)
    ends: Ends = field(default_factory=Ends)


@dataclass
class _UnidentifiedGroup:
    """The candidate connections of one (server, port, transport, side), folded as they are read at finalize."""
    connections: int = 0
    records: Counter = field(default_factory=Counter)
    failed: int = 0
    first: float = float("inf")
    last: float = float("-inf")
    addresses: Counter = field(default_factory=Counter)      # the other end -> its connections
    cites: list[tuple[float, str]] = field(default_factory=list)    # (first, event id) of the earliest connections
    ends: Ends = field(default_factory=Ends)

    def add(self, entry: _Unidentified, side: str) -> None:
        self.connections += 1
        self.records.update(entry.records)
        self.failed += entry.failed
        self.first, self.last = min(self.first, entry.first), max(self.last, entry.last)
        self.ends.fold(entry.ends)
        self.addresses[entry.dst if side == "source" else entry.src] += 1
        ref = (entry.first, entry.event_id)
        if len(self.cites) < EXAMPLE_LIMIT or ref < self.cites[-1]:
            bisect.insort(self.cites, ref)
            del self.cites[EXAMPLE_LIMIT:]


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
    version = "6"
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
                    "by a sensor that parses the protocol registered there; a record whose recorded source is on a "
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

    # Every connection a sensor identified on a registered port is held, so the other sensor's unidentified record of
    # the same connection (read from another target) is always cleared. Identified connections, candidate
    # connections, mismatch groups (connections per group capped, worded "at least") and per-server tallies are held
    # in keyed stores: HOT in memory, the rest on disk; only their disk budget refuses a record needing a new entry.
    CONNECTIONS_PER_MISMATCH = 100_000
    HOT = HOT_COUNT  # a count cap only: the hunt's memory budget sizes it in bytes
    HOT_GROUPS = HOT_COUNT  # a count cap only: the hunt's memory budget sizes it in bytes

    def __init__(self):
        super().__init__()
        self.identified = KeyedStore(self, "ppm_identified", self.HOT)        # connection -> sensor -> protocols
        self.unidentified = KeyedStore(self, "ppm_unidentified", self.HOT)    # connection -> _Unidentified
        self.mismatches = KeyedStore(self, "ppm_mismatches", self.HOT_GROUPS)
        self.pairs = KeyedStore(self, "ppm_pairs", self.HOT)                  # (server, port, transport) tallies

    def take(self, view: FlowView, event: TypedEvent) -> bool | None:
        if view.protocols is None:
            return False
        if view.transport not in ("tcp", "udp"):
            return True
        expected = expected_protocols(view.transport, view.dport)
        registered = bool(expected) or bool(expected_protocols(view.transport, view.sport))
        if expected:
            counts = self.pairs.setdefault((view.dst, view.dport, view.transport), dict)
            if counts is None:
                return self._refused("server tallies'")
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
                seen = self.identified.setdefault(view.key, dict)
                if seen is None:
                    return self._refused("identified connections'")
                seen.setdefault(view.sensor, set()).update(view.protocols)
            if not consistent and judged:
                group_key = (view.dst, view.dport, view.transport, tuple(sorted(view.protocols)))
                group = self.mismatches.setdefault(group_key, _Mismatch)
                if group is None:
                    return self._refused("mismatch groups'")
                if view.key in group.connections or len(group.connections) < self.CONNECTIONS_PER_MISMATCH:
                    group.connections.add(view.key)
                    group.sources.setdefault(view.src, set()).add(view.key)
                else:
                    group.capped = True
                    self.note_limit("connections", f"a mismatch group passed {self.CONNECTIONS_PER_MISMATCH:,} "
                                                   f"distinct connections held; its connection count is a lower bound")
                group.records[view.sensor] += 1
                group.first, group.last = min(group.first, view.start), max(group.last, view.end)
                self.bounds.offer(("mismatch",) + group_key, group.ends, view.start, view.end, event)
                if len(group.cited) < self.STAGE_PER_GROUP:
                    group.cited.append(event.id)
                    self._stage(event)
            return True
        capable = expected & PARSERS[view.sensor]
        on_source = False
        if not capable:
            # A record whose recorded source sits on a registered port and whose other end is a client port is either a
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
            entry = _Unidentified(view.src, view.sport, view.dst, view.dport, view.transport, view.start, view.end,
                                  event.id, on_source)
            if not self.unidentified.put(view.key, entry):
                return self._refused("candidate connections'")
            self._stage(event)
        entry.first, entry.last = min(entry.first, view.start), max(entry.last, view.end)
        entry.records[view.sensor] += 1
        entry.failed += view.failed
        # A connection's first record is kept above, and it bounds a connection of one record on both sides: bounds
        # are held only once the connection has more records than that.
        self.bounds.offer(("connection", view.key), entry.ends, view.start, view.end, event,
                          stage=sum(entry.records.values()) > 1)
        return True

    def finalize(self):
        out = [self._mismatch(key, self.mismatches.peek(key))
               for key in sorted(self.mismatches.keys(), key=lambda k: (ip_sort_key(k[0]),) + k[1:])]
        groups = KeyedStore(self, "ppm_unidentified_groups", self.HOT_GROUPS)
        for i, (key, entry) in enumerate(self.unidentified.items()):
            if key in self.identified:
                continue                # another record of the same connection had its protocol identified
            side = "source" if entry.on_source else "destination"
            group = groups.setdefault((entry.src, entry.sport, entry.transport, side) if entry.on_source else
                                      (entry.dst, entry.dport, entry.transport, side), _UnidentifiedGroup)
            if group is None:
                self.refuse("disk", "the unidentified groups' disk budget is spent; a candidate connection is not "
                                    "evaluated")
                continue
            group.add(entry, side)
            if i % FINALIZE_TRIM == FINALIZE_TRIM - 1:
                groups.trim()
        for key in sorted(groups.keys(), key=lambda k: (ip_sort_key(k[0]),) + k[1:]):
            out.append(self._unidentified(key, groups.peek(key)))
        groups.clear()
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
            for sensor, seen in self.identified.peek(connection, {}).items():
                extra = seen - set(protocols)
                if extra:
                    others[sensor].update(extra)
        sources = _sources_phrase({src: len(keys) for src, keys in group.sources.items()})
        claim = (f"{sensors} identified {names} on {'at least ' if group.capped else ''}"
                 f"{_plural(len(group.connections), 'connection')} to {dst} on "
                 f"{transport}/{port} {sources} ({_iso(group.first)} – {_iso(group.last)}; "
                 f"{_sensor_counts(group.records)}). {port_phrase}; {'; '.join(protocol_phrases)}.")
        if others:
            claim += " On the same connection(s) " + "; ".join(
                f"{SENSOR_NAMES[s]} also identified {', '.join(sorted(v))}" for s, v in sorted(others.items())) + "."
        claim += " Protocol identity is the sensor parser's judgement."
        evs, missing = self._cite(group.ends, group.cited)
        claim += bound_note(missing, group.ends)
        match = Match(self.id, claim, "network_observation", evs,
                      _predicates(evs[0], ("source.ip", "destination.ip", "destination.port", "network.app_proto",
                                           "network.protocols")),
                      evs[0].ts, self.severity, self.lane, "medium", _entities(evs),
                      group_key=f"{dst}|{transport}/{port}|{names}")
        match.notes.append("ATT&CK context: T1571 Non-Standard Port; T1572 Protocol Tunneling when a registered port "
                           "carries a different protocol")
        return match

    def _unidentified(self, key, group: _UnidentifiedGroup) -> Match:
        server, port, transport, side = key
        expected = expected_protocols(transport, port)
        records, failed, first, last = group.records, group.failed, group.first, group.last
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
        tallies = self.pairs.peek((server, port, transport), {}) if side == "destination" else {}
        for sensor, tally in sorted(tallies.items()):
            identified = ", ".join(f"{p} {n}" for p, n in sorted(tally.items()) if p != "records")
            kind = "flow record" if sensor == SURICATA else "session record"
            denominators.append(f"{SENSOR_NAMES[sensor]} wrote {_plural(tally['records'], kind)} to {server} on "
                                f"this port" + (f", identified as {identified}" if identified else
                                                ", none with an identified protocol"))
        if side == "source":
            peers = _address_list(group.addresses, "peer")
            subject = (f"{_plural(group.connections, 'connection')} recorded from {server} port {transport}/{port} to "
                       f"{peers}; the registered port is on the side the sensor recorded as the source (a reversed or "
                       f"mid-stream view of a connection to that service, or a program bound to the service port to "
                       f"make outgoing connections)")
        else:
            sources = _sources_phrase(group.addresses)
            subject = f"{_plural(group.connections, 'connection')} to {server} on {transport}/{port} {sources}"
        registered = f"{transport}/{port} is registered here for {', '.join(sorted(expected))}"
        claim = (f"{subject} ({_iso(first)} – {_iso(last)}) carried data in both directions with no application "
                 f"protocol identified: {'; '.join(how)}. {registered}, which {' and '.join(capable)} can parse "
                 f"({', '.join(parsable)}). " + (f"{'; '.join(denominators)}. " if denominators else "")
                 + "A parser that does not recognise traffic is not proof that a different protocol was used.")
        evs, missing = self._cite(group.ends, [event_id for _first, event_id in group.cites])
        claim += bound_note(missing, group.ends)
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
    staged: bool = False            # the record is on the stage, so it can be cited


@dataclass
class _Identity:
    """Every record of one connection identity that can be stitched, and how many of them were staged."""
    pieces: list[_Piece] = field(default_factory=list)
    staged: int = 0
    last_staged: float | None = None
    reportable: bool = False        # some record carried data with no protocol identified, on a port it cannot judge
    ends: Ends = field(default_factory=Ends)


@dataclass
class _LongGroup:
    """The unidentified data-carrying connections to one (server, port, transport), folded at finalize."""
    connections: int = 0
    records: Counter = field(default_factory=Counter)
    failed: int = 0
    long: int = 0
    sources: Counter = field(default_factory=Counter)        # long connections per source
    longest: tuple | None = None        # (span, start, end, source, first id, last id), the earliest on a tie
    crossing: bool = False                                   # a long connection across the internal/external boundary
    ranked: list[tuple] = field(default_factory=list)        # (-span, start, order, cited ids): the first-ranked long
    rest: list[str] = field(default_factory=list)            # staged ids of every connection, in reading order

    def add(self, pieces: list[_Piece], min_seconds: int) -> None:
        self.connections += 1
        self.records.update(p.sensor for p in pieces)
        self.failed += sum(p.failed for p in pieces)
        first, end = pieces[0], max(p.end for p in pieces)
        span = end - first.start
        if span >= min_seconds:
            self.long += 1
            self.sources[first.src] += 1
            self.crossing = self.crossing or external(first.src) != external(first.dst)
            if self.longest is None or (span, -first.start) > (self.longest[0], -self.longest[1]):
                # the records that bound the span, chosen as Ends chooses them (ties to the lower event id)
                opening = min(pieces, key=lambda p: (p.start, p.event_id))
                closing = min(pieces, key=lambda p: (-p.end, p.event_id))
                self.longest = (span, first.start, end, first.src, opening.event_id, closing.event_id)
            ids = [p.event_id for p in pieces if not p.identified and p.payload and p.staged]
            if ids:                                          # a connection with nothing to cite adds nothing
                bisect.insort(self.ranked, (-span, first.start, self.long, ids))
            while (len(self.ranked) > 1
                   and len({i for *_rank, held in self.ranked[:-1] for i in held}) >= EXAMPLE_LIMIT):
                self.ranked.pop()
        if len(self.rest) < EXAMPLE_LIMIT:
            self.rest.extend(p.event_id for p in pieces if p.staged)
            del self.rest[EXAMPLE_LIMIT:]


class LongUnidentifiedSession(_FlowRule):
    """A long connection that carried data both ways while no sensor identified its application protocol, on a
    port that is unregistered or registered only for protocols the recording sensor cannot parse."""
    id = "net.long_unidentified_session"
    version = "5"
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

    # Every record of a candidate connection is a piece (stitching needs them, from both sensors' targets): about
    # 150 bytes each, held per connection identity in a keyed store (HOT identities in memory, the rest on disk);
    # only its disk budget refuses. Finalize reads only identities with a record that can be reported, one at a time,
    # and folds their connections into per-(server, port) groups held in a second store.
    HOT = HOT_COUNT  # a count cap only: the hunt's memory budget sizes it in bytes

    def __init__(self):
        super().__init__()
        self.pieces = KeyedStore(self, "lus_pieces", self.HOT, candidate=lambda state: state.reportable)

    def take(self, view: FlowView, event: TypedEvent) -> bool:
        if view.transport not in ("tcp", "udp"):
            return True
        expected = expected_protocols(view.transport, view.dport)
        if expected and all(expected & parsers for parsers in PARSERS.values()):
            return True                 # every sensor can parse the registered protocol: the mismatch rule judges it
        if expected_protocols(view.transport, view.sport) and view.dport >= EPHEMERAL_FLOOR:
            # A registered service's port on the side the sensor recorded first. When the sensor can parse it, the
            # protocol/port rule judges the record against the source port (and clears it when a forward record of
            # the same connection was identified); when it cannot, its silence says nothing.
            return True
        if view.protocols is None or not view.timed:
            return False
        if view.payload is None:
            return False
        capable = bool(expected & PARSERS[view.sensor])
        state = self.pieces.get(view.key)
        if state is None:
            state = _Identity()
            if not self.pieces.put(view.key, state):
                return self._refused("connection records'")
        candidate = not view.protocols and view.payload and not capable
        state.reportable = state.reportable or candidate
        # Bounds are staged only for an identity that can be reported, and never for a record with an identified
        # protocol (a connection holding one is never reported); before that they are only tracked.
        stage = state.reportable and not view.protocols
        staged = False
        if state.ends.last is not None and view.start > state.ends.last[0] + STITCH_GAP:
            # an earlier connection on this identity has ended: the record that ends it stays citable, and this one
            # opens the next connection
            self.bounds.settle(("identity", view.key), state.ends)
            if stage:
                self._stage(event)
                staged = True
        self.bounds.offer(("identity", view.key), state.ends, view.start, view.end, event, stage=stage)
        # the first few candidate records of an identity, and the first of any later connection that reuses it
        if candidate and (state.staged < self.STAGE_PER_CONNECTION
                          or abs(view.start - state.last_staged) > STITCH_GAP):
            state.staged += 1
            state.last_staged = view.start
            self._stage(event)
            staged = True
        state.pieces.append(_Piece(view.start, view.end, view.sensor, bool(view.protocols), view.payload,
                                            view.failed, capable, event.id, view.src, view.dst, view.dport,
                                            view.transport, staged))
        return True

    def _connections(self):
        """Stitched connections: records of one identity whose spans lie within STITCH_GAP of each other."""
        for key in sorted(self.pieces.keys(candidates=True)):
            pieces = sorted(self.pieces.peek(key).pieces, key=lambda p: (p.start, p.end, p.event_id))
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
        groups = KeyedStore(self, "lus_groups", self.HOT, candidate=lambda group: group.long > 0)
        for i, pieces in enumerate(self._connections()):
            if any(p.identified or p.capable for p in pieces) or not any(p.payload for p in pieces):
                continue                # identified, owned by the protocol/port rule, or never carried data
            first = pieces[0]
            group = groups.setdefault((first.dst, first.dport, first.transport), _LongGroup)
            if group is None:
                self.refuse("disk", "the connection groups' disk budget is spent; a connection is not evaluated")
                continue
            group.add(pieces, self.MIN_SECONDS)
            if i % FINALIZE_TRIM == FINALIZE_TRIM - 1:
                groups.trim()
        out = [self._match(key, groups.peek(key))
               for key in sorted(groups.keys(candidates=True), key=lambda k: (ip_sort_key(k[0]),) + k[1:])]
        groups.clear()
        return out

    def _match(self, key, group: _LongGroup) -> Match:
        dst, port, transport = key
        longest, start, end, longest_src, opening, closing = group.longest
        records, failed = group.records, group.failed
        sensors = " or ".join(SENSOR_NAMES[s] for s in sorted(records))
        expected = expected_protocols(transport, port)
        registration = (f"{transport}/{port} is registered here for {', '.join(sorted(expected))}, which {sensors} "
                        f"cannot parse" if expected else f"{transport}/{port} is registered here for no protocol")
        sources = _sources_phrase(group.sources)
        claim = (f"{_plural(group.long, 'connection')} to {dst} on {transport}/{port} {sources} lasted at least "
                 f"{self.MIN_SECONDS // 60} minutes with data in both directions and no application protocol "
                 f"identified by {sensors}; the longest ran {longest / 60:.0f} minutes ({_iso(start)} "
                 f"– {_iso(end)}, from {longest_src}). "
                 f"{_plural(group.connections, 'unidentified data-carrying connection')} to it on this port "
                 f"in total ({_sensor_counts(records)}"
                 + (f"; Suricata reported protocol detection 'failed' on {failed}" if failed else "") + "). "
                 f"{registration}. Times are as the sensors recorded them.")
        ids = [event_id for *_rank, held in group.ranked for event_id in held] + group.rest
        bounds = Ends((start, opening), (end, closing))
        evs, missing = self._cite(bounds, ids)
        claim += bound_note(missing, bounds, "the longest connection")
        match = Match(self.id, claim, "network_observation", evs,
                      _predicates(evs[0], ("source.ip", "destination.ip", "destination.port", "flow.start",
                                           "flow.end")),
                      evs[0].ts, self.severity, self.lane, "medium", _entities(evs),
                      group_key=f"{dst}|{transport}/{port}")
        if transport == "tcp" and group.crossing:
            match.notes.append("net.long_external_connection reports each long TCP connection across the "
                               "internal/external boundary on its own (duration); this item adds that no sensor "
                               "identified an application protocol, groups every client of the port, and counts "
                               "the shorter connections")
        match.notes.append("ATT&CK context: T1095 Non-Application Layer Protocol / T1571 Non-Standard Port")
        return match


# ---------------------------------------------------------------------------------------------
# outbound volume asymmetry
# ---------------------------------------------------------------------------------------------

# How a connection between an internal and an external address is read, from what its records show.
OPENED_INSIDE = "opened inside"     # a record shows the internal address opened it: what it sent is an upload
SERVED = "served"                   # a record shows the external address opened it: the internal address answered
CLIENT_SHAPED = "client-shaped"     # opener not recorded (or records disagree); internal port ephemeral, external not
SERVER_SHAPED = "server-shaped"     # opener not recorded; external port ephemeral, internal not: a server's answers
UNSHAPED = "unshaped"               # opener not recorded; both ports ephemeral or both below that range
PORTLESS = "portless"               # opener not recorded, on a transport without ports
COUNTED = frozenset({OPENED_INSIDE, CLIENT_SHAPED, UNSHAPED, PORTLESS})
# Connections not read as uploads, as the window cell names them: served and shown by an Arkime SYN (informational),
# served and shown only by a Suricata flow state, and server-shaped (both partial: each can be wrong).
SERVED_ARKIME, SERVED_SURICATA = "served (Arkime)", "served (Suricata only)"
NOT_READ_LISTED = 10                # qualifying server-shaped pairs listed by name on the window cell
# The typed fact that showed an opener (bit flags on _Connection.opened_inside / opened_outside).
ARKIME_SYN, SURICATA_STATE = 1, 2
SURICATA_STATE_NOTE = ("a Suricata flow in state established or closed, which shows a tracked handshake on a sensor "
                       "that does not pick up mid-stream")
UNKNOWN_REASONS = {"tcp": "TCP with no record of the opening (picked up mid-stream, or opened before the hunt window)",
                   "udp": "UDP, which has no opening to record", "sctp": "SCTP, whose opening no typed field shows",
                   "disagree": "TCP whose records disagree about which side opened it"}


@dataclass
class _Connection:
    """One connection between an internal and an external address, from every record of it."""
    tallies: dict = field(default_factory=dict)     # sensor -> [bytes the internal address sent, received, records]
    opened_inside: int = 0                          # the facts (ARKIME_SYN, SURICATA_STATE) showing the internal
    opened_outside: int = 0                         # ... or the external address opened it
    first: float = float("inf")
    last: float = float("-inf")

    def best(self) -> list[int]:
        """The tally of the sensor that recorded the most bytes for the connection."""
        return self.tallies[max(sorted(self.tallies), key=lambda s: self.tallies[s][0] + self.tallies[s][1])]

    def sent(self) -> int:
        """Bytes the internal address sent, from the best-recorded sensor."""
        return self.best()[0]


def _sides(key: tuple, inside: str) -> tuple[str, int | None, int | None]:
    """(transport, internal port, external port) from a direction-independent connection identity."""
    transport, ip_a, port_a, _ip_b, port_b = key
    inside_port, outside_port = (port_a, port_b) if ip_a == inside else (port_b, port_a)
    return transport, None if inside_port < 0 else inside_port, None if outside_port < 0 else outside_port


def connection_reading(conn: _Connection, transport: str, inside_port: int | None, outside_port: int | None) -> str:
    """How the bytes the internal address sent on this connection are read (OPENED_INSIDE ... PORTLESS). Without a
    recorded opener the ports decide only the two clear shapes: an internal ephemeral port facing a service port is a
    client, the reverse is a server answering; anything else is counted with its direction stated as unknown."""
    if bool(conn.opened_inside) != bool(conn.opened_outside):
        return OPENED_INSIDE if conn.opened_inside else SERVED
    if transport not in PORTED or inside_port is None or outside_port is None:
        return PORTLESS
    if inside_port >= EPHEMERAL_FLOOR > outside_port:
        return CLIENT_SHAPED
    if outside_port >= EPHEMERAL_FLOOR > inside_port:
        return SERVER_SHAPED
    return UNSHAPED


@dataclass
class _Pair:
    """One (internal, external) pair's citation candidates, among the records of connections that may be counted.
    Its totals are read from its connections at finalize."""
    cited: list[tuple[int, str, tuple]] = field(default_factory=list)  # (bytes sent inside out, event id, connection)
    ends: Ends = field(default_factory=Ends)
    bound_connections: dict = field(default_factory=dict)              # bounding event id -> its connection
    sent: int = 0                   # bytes the internal address sent on connections that may count, as read so far


@dataclass
class _PairTotals:
    """A pair's connections, each from the sensor that recorded the most bytes for it: the counted ones by how they
    were read, and the bytes of those not read as uploads."""
    out: int = 0
    inn: int = 0
    records: Counter = field(default_factory=Counter)
    readings: Counter = field(default_factory=Counter)      # counted connections per reading
    suricata_only: int = 0                                  # opened inside, shown only by a Suricata flow state
    unknown: dict = field(default_factory=dict)             # reading -> Counter of why the opener is unknown
    inside_ports: dict = field(default_factory=dict)        # reading -> Counter of the internal address's ports
    outside_ports: dict = field(default_factory=dict)       # reading -> Counter of the external address's ports
    first: float = float("inf")
    last: float = float("-inf")
    counted: set = field(default_factory=set)               # the pair's cited connections that are counted
    not_read: Counter = field(default_factory=Counter)      # (kind, 'connections' | 'bytes' | 'received')

    @property
    def connections(self) -> int:
        return sum(self.readings.values())

    def add(self, conn: _Connection, reading: str, transport: str, inside_port, outside_port) -> None:
        best = conn.best()
        if reading not in COUNTED:
            # Named only when the internal address sent application data: a SYN-ACK, acknowledgements or a reset
            # carry none (their estimated data stays at zero), and MIN_PAYLOAD_BYTES is the same floor the other
            # flow rules use for "carried data". Probes a site's servers merely answered are not named.
            if best[3] >= MIN_PAYLOAD_BYTES:
                kind = reading if reading != SERVED else (SERVED_ARKIME if conn.opened_outside & ARKIME_SYN
                                                          else SERVED_SURICATA)
                self.not_read[kind, "connections"] += 1
                self.not_read[kind, "bytes"] += best[0]
                self.not_read[kind, "received"] += best[1]
                if inside_port is not None:
                    self.inside_ports.setdefault(kind, Counter())[f"{transport}/{inside_port}"] += 1
            return
        self.out += best[0]
        self.inn += best[1]
        for name, tally in conn.tallies.items():
            self.records[name] += tally[2]
        self.readings[reading] += 1
        if reading == OPENED_INSIDE:
            self.suricata_only += conn.opened_inside == SURICATA_STATE
        else:
            why = "disagree" if conn.opened_inside else transport
            self.unknown.setdefault(reading, Counter())[why] += 1
        if inside_port is not None:
            self.inside_ports.setdefault(reading, Counter())[f"{transport}/{inside_port}"] += 1
            self.outside_ports.setdefault(reading, Counter())[f"{transport}/{outside_port}"] += 1
        self.first, self.last = min(self.first, conn.first), max(self.last, conn.last)


class _NotRead(Limit):
    """Connections whose bytes this rule did not read as uploads because of what their records show (not a state
    budget): named on the window cell with the count and the bytes, and the cell is partial."""

    def reason(self) -> str:
        return f"not read as uploads: {self.text} ({self.records} connection(s))"


class _Uncited(Limit):
    """Pairs that met the thresholds but could not be cited: named on the window cell, which is partial."""

    def reason(self) -> str:
        return f"not reported: {self.text} ({self.records} pair(s))"


def _port_list(ports: Counter) -> str:
    """'tcp/443 (3 connections), udp/443 (1 connection)', the five most used, then how many more."""
    listed = sorted(ports.items(), key=lambda i: (-i[1], i[0]))
    return ", ".join(f"{p} ({_plural(n, 'connection')})" for p, n in listed[:5]) + (
        f" and {len(listed) - 5} more" if len(listed) > 5 else "")


class OutboundVolumeAsymmetry(_FlowRule):
    """An internal address sent far more to one external address than it received back, in absolute and relative
    terms, with the source's own outbound total as the denominator."""
    id = "net.outbound_volume_asymmetry"
    version = "4"
    title = "Internal address sent much more data to one external address than it received"
    severity, lane = "high", "lead"
    attack = ("T1041", "T1048", "T1567")
    assures_negative = False
    positive_only_reason = (
        "internal and external are judged from the site's internal-network definition (the RFC 1918 and reserved "
        "ranges when it is not configured). Connections a recorded opening shows an outside address opened (an "
        "internal server answering), and connections whose opener is not recorded but whose ports have an internal "
        "server's shape, are not read as uploads; those carrying data from the internal address are named on the "
        "window cell with their bytes, and server-shaped pairs that met the upload thresholds are listed. A Suricata "
        "flow state counts as a recorded opening only on a sensor that does not pick up mid-stream (stream.midstream "
        "off, its default); on one that does, such a connection may have been opened from inside. Transfers outside "
        "that view are not seen, so the absence of a match proves nothing")
    benign = ("backups and cloud file synchronisation", "log and telemetry shipping", "video and media uploads",
              "software publishing to external repositories",
              ("internal servers and VPN gateways answering outside clients where no record shows the opening and the "
              "ports do not mark a client (the claim says so)"))
    next_checks = ("the process on the internal host that owns the connections",
                   "files archived, compressed or staged on the internal host shortly before",
                   "what the destination is (ownership, other internal clients, reputation)")
    MIN_OUTBOUND_BYTES = 50 * 2**20
    MIN_RATIO = 10.0
    CITE_BYTES = 2**20
    FIRST_CITES = 3
    card: ClassVar[dict] = {
        "behavior": "an internal address sent at least 50 MiB to one external address in the hunt window, at least "
                    "ten times what it received back from it, over connections other than those an outside address "
                    "is shown to have opened or whose ports have an internal server's shape. The claim says, per "
                    "connection, whether a recorded TCP opening shows the internal address opened it, or that the "
                    "opener is not recorded and what the ports show (a client's shape, or no shape, in which case "
                    "the bytes may be a server's answers)",
        "telemetry": "Suricata EVE flow records (flow.bytes_toserver, flow.bytes_toclient, flow.state) and Arkime "
                     "sessions (source.bytes, destination.bytes, tcp.flags.syn): present in the lab profile on every "
                     "record (Arkime counts SYNs on every TCP session; lab Suricata flows it picked up mid-stream "
                     "carry state 'new'). Suricata netflow records are not read",
        "fidelity": "typed per-side byte counters (headers included), read for each address whichever side the "
                    "sensor recorded first; each connection is counted once, from the sensor that recorded the most "
                    "bytes for it. The opener is stated only from a recorded TCP opening: an Arkime session that "
                    "counted a SYN (Arkime orients such a session by it), or a Suricata flow its TCP engine tracked "
                    "from the handshake (state established or closed; valid while the sensor's stream.midstream is "
                    "off, its default, and the claim says so where it is the only fact). Without one the claim says "
                    "the opener is unknown and why. Volume and ratio are a deviation, not proof of theft",
        "benign_and_cost": "backups, cloud sync, log shipping, media uploads (the lab carries CCTV traffic). A "
                           "connection an outside address is shown to have opened to an internal server is not read "
                           "as an upload (the server's answers are the outside client's download), nor is one whose "
                           "opener is not recorded and whose external port is ephemeral while the internal port is "
                           "not (an internal server answering). Those on which the internal address sent application "
                           "data (at least 64 bytes beyond packet headers, so a SYN-ACK or reset to a scanner is not "
                           "one) are named on the window cell with their count, the bytes and the largest pair: as an "
                           "informational line when an Arkime SYN shows the outside opener, and as a partial cell when "
                           "only a Suricata flow state shows it or only the port shape does; server-shaped pairs that "
                           "met the upload thresholds are listed by name (ten, then how many more). Connections with no "
                           "recorded opener and no clear port shape (both ports ephemeral or both below that range, "
                           "or no ports at all) are counted and worded as possibly a server's answers. One item per "
                           "(internal source, external destination); the claim gives the destination's other internal "
                           "senders for prevalence",
        "query_cost": "none beyond the sweep",
        "next_pivot": "the uploading process and staging (archives, encoders) on the source host",
        "adds": "no other rule measures byte asymmetry",
        "research_basis": "ATT&CK Enterprise 20.0 T1041, T1048 and T1567 (detection: network traffic flow, "
                          "uncommon data flows and outbound volume relative to inbound); Arkime capture/parsers/tcp.c "
                          "(session orientation and SYN counts) and Suricata's stream engine documentation "
                          "(stream.midstream) for the opener",
        "retrieval": "the sweep retrieves every record of the network flow datasets and the Arkime session index in "
                     "each partition (dataset filter only), a superset of what this evaluator reads",
        "lanes": "lead: large uploads are common and legitimate; severity high because exfiltration, if that is what "
                 "it is, is high impact. 50 MiB in one hunt window is above routine client chatter and well below "
                 "bulk backup volumes; a 10:1 ratio excludes interactive and download-heavy traffic",
    }

    # Every connection between an internal and an external address keeps its per-sensor tallies and what its records
    # show about its opener (about 250 bytes) to the end, beside the pairs' citation candidates (about 1 KB each), in
    # keyed stores: HOT in memory, the rest on disk; only their disk budget refuses. Which connections count is known
    # only at finalize, when every record of each is in.
    HOT_PAIRS = HOT_COUNT  # a count cap only: the hunt's memory budget sizes it in bytes
    HOT_CONNECTIONS = HOT_COUNT  # a count cap only: the hunt's memory budget sizes it in bytes

    def __init__(self):
        super().__init__()
        self.pairs = KeyedStore(self, "ova_pairs", self.HOT_PAIRS)
        self._notes: list[str] = []     # the window cell's informational lines, set at finalize
        # (internal, external, connection) -> _Connection, read back one pair at a time
        self.connections = KeyedStore(self, "ova_connections", self.HOT_CONNECTIONS,
                                      group=lambda key: f"{key[0]}|{key[1]}")

    def take(self, view: FlowView, event: TypedEvent) -> bool:
        if view.c2s_bytes is None or view.s2c_bytes is None:
            return False
        # Each address's bytes are its own side's counter, whichever side the sensor recorded first.
        if internal_address(view.src) and external(view.dst):
            inside, outside, sent, received, inside_first = view.src, view.dst, view.c2s_bytes, view.s2c_bytes, True
        elif external(view.src) and internal_address(view.dst):
            inside, outside, sent, received, inside_first = view.dst, view.src, view.s2c_bytes, view.c2s_bytes, False
        else:
            return True
        pair = self.pairs.get((inside, outside))
        if pair is None:
            pair = _Pair()
            if not self.pairs.put((inside, outside), pair):
                return self._refused("(internal, external) pairs'")
        conn = self.connections.get((inside, outside, view.key))
        if conn is None:
            conn = _Connection()
            if not self.connections.put((inside, outside, view.key), conn):
                return self._refused("connections'")
        # [bytes the internal address sent, received, records, application bytes it sent (all its bytes when the
        # counters cannot tell)]
        tally = conn.tallies.setdefault(view.sensor, [0, 0, 0, 0])
        data = view.c2s_data if inside_first else view.s2c_data
        tally[0] += sent
        tally[1] += received
        tally[2] += 1
        tally[3] += sent if data is None else data
        if view.opened:
            fact = ARKIME_SYN if view.sensor == ARKIME else SURICATA_STATE
            if inside_first:
                conn.opened_inside |= fact
            else:
                conn.opened_outside |= fact
        conn.first, conn.last = min(conn.first, view.start), max(conn.last, view.end)
        if connection_reading(conn, *_sides(view.key, inside)) not in COUNTED:
            return True                 # as read so far, not an upload: nothing to cite
        pair.sent += sent
        if len(pair.cited) < self.FIRST_CITES or (sent >= self.CITE_BYTES and len(pair.cited) < EXAMPLE_LIMIT):
            pair.cited.append((sent, event.id, view.key))
            self._stage(event)
        # the pair's bounds are staged once it has sent enough to qualify; its first records are staged above
        if self.bounds.offer(("pair", inside, outside), pair.ends, view.start, view.end, event,
                             stage=pair.sent >= self.MIN_OUTBOUND_BYTES):
            pair.bound_connections[event.id] = view.key
            held = set(pair.ends.ids())
            for event_id in [i for i in pair.bound_connections if i not in held]:
                del pair.bound_connections[event_id]
        return True

    def _resolved(self):
        """((internal, external), totals) per pair; one pair's connections are read at a time."""
        pair_key, totals, cited = None, _PairTotals(), set()
        for (inside, outside, key), conn in self.connections.grouped():
            if (inside, outside) != pair_key:
                if pair_key is not None:
                    yield pair_key, totals
                pair_key, totals = (inside, outside), _PairTotals()
                held = self.pairs.peek(pair_key)
                cited = ({c for *_ref, c in held.cited} | set(held.bound_connections.values())) if held else set()
            transport, inside_port, outside_port = _sides(key, inside)
            reading = connection_reading(conn, transport, inside_port, outside_port)
            totals.add(conn, reading, transport, inside_port, outside_port)
            if reading in COUNTED and key in cited:
                totals.counted.add(key)
        if pair_key is not None:
            yield pair_key, totals

    def finalize(self):
        totals_by_source = KeyedStore(self, "ova_totals", self.HOT_PAIRS)     # internal source -> [bytes sent out]
        senders = KeyedStore(self, "ova_senders", self.HOT_PAIRS)             # external destination -> [senders]
        not_read: Counter = Counter()
        largest: dict[str, tuple[int, str, str]] = {}                        # kind -> (bytes, internal, external)
        shaped: list[tuple] = []        # the qualifying server-shaped pairs with the most bytes (a bounded heap)
        hits = []
        self._notes = []
        for i, ((src, dst), totals) in enumerate(self._resolved()):
            not_read.update(totals.not_read)
            for kind in (SERVED_ARKIME, SERVED_SURICATA, SERVER_SHAPED):
                sent_here = totals.not_read[kind, "bytes"]
                if sent_here and sent_here > largest.get(kind, (0,))[0]:
                    largest[kind] = (sent_here, src, dst)
            out, back = totals.not_read[SERVER_SHAPED, "bytes"], totals.not_read[SERVER_SHAPED, "received"]
            if out >= self.MIN_OUTBOUND_BYTES and out >= self.MIN_RATIO * back:
                # met the upload thresholds on connections not read as uploads only because of their port shape
                not_read[SERVER_SHAPED, "qualifying"] += 1
                ports = totals.inside_ports.get(SERVER_SHAPED, Counter())
                entry = (out, src, dst, back, ", ".join(p for p, _n in ports.most_common(3)))
                if len(shaped) < NOT_READ_LISTED:
                    heapq.heappush(shaped, entry)
                elif entry > shaped[0]:
                    heapq.heapreplace(shaped, entry)
            if not totals.connections:
                continue
            total = totals_by_source.setdefault(src, lambda: [0])
            sent = senders.setdefault(dst, lambda: [0]) if totals.out > 0 else [0]
            if total is None or sent is None:
                self.refuse("disk", "the per-address totals' disk budget is spent; a pair is not evaluated")
                continue
            total[0] += totals.out
            sent[0] += totals.out > 0
            if totals.out >= self.MIN_OUTBOUND_BYTES and totals.out >= self.MIN_RATIO * totals.inn:
                hits.append((src, dst, totals))
            if i % FINALIZE_TRIM == FINALIZE_TRIM - 1:
                totals_by_source.trim()
                senders.trim()
        self._note_not_read(not_read, largest, sorted(shaped, reverse=True))
        # a reported source sent data to the destination, so it is one of the destination's senders
        matches = [self._match(src, dst, totals, totals_by_source.peek(src)[0], senders.peek(dst)[0] - 1)
                   for src, dst, totals in sorted(hits, key=lambda hit: hit[:2])]
        uncited = sum(match is None for match in matches)
        if uncited:
            self.limits["uncited"] = _Uncited(
                "a pair met the volume and ratio thresholds, but no record of its counted connections was kept for "
                "citation (every record kept came from connections that turned out not to count)", records=uncited,
                hits=1)
        totals_by_source.clear()
        senders.clear()
        return [match for match in matches if match is not None]

    def _note_not_read(self, not_read: Counter, largest: dict, shaped: list[tuple]) -> None:
        """Name, on the window cell, the connections whose internal-address data was not read as uploads: how many,
        the bytes, and the pair with the most. Served connections an Arkime SYN shows are an informational note; those
        shown only by a Suricata flow state, and server-shaped ones, make the cell partial (each reading can be wrong),
        and server-shaped pairs that met the upload thresholds are listed by name."""
        texts = {
            SERVED_ARKIME: "connections an Arkime session shows an external address opened (it counted the SYN), so "
                           "the internal address answered as a server",
            SERVED_SURICATA: f"connections whose only record of the opening, by an external address, is "
                             f"{SURICATA_STATE_NOTE}, so the internal address answered as a server",
            SERVER_SHAPED: f"connections whose opener is not recorded, with the internal address on a port below "
                           f"{EPHEMERAL_FLOOR} and the external address on one at or above it (the port shape of an "
                           f"internal server answering an outside client)",
        }
        for kind, text in texts.items():
            count = not_read[kind, "connections"]
            if not count:
                continue
            most, src, dst = largest[kind]
            text += (f": the internal addresses sent {not_read[kind, 'bytes']:,} bytes on them, the most from one pair "
                     f"{most:,} bytes from {src} to {dst}")
            qualifying = not_read[kind, "qualifying"]
            if qualifying:
                listed = "; ".join(f"{a} to {b}, {out:,} bytes sent and {back:,} back, from {ports}"
                                   for out, a, b, back, ports in shaped)
                more = f"; and {qualifying - len(shaped)} more" if qualifying > len(shaped) else ""
                text += (f". {_plural(qualifying, 'pair')} met the upload thresholds (at least "
                         f"{self.MIN_OUTBOUND_BYTES // 2**20} MiB sent and at least {self.MIN_RATIO:.0f} times what "
                         f"came back) on these connections and {'was' if qualifying == 1 else 'were'} not read as "
                         f"uploads only because of the port shape: {listed}{more}")
            if kind == SERVED_ARKIME:
                self._notes.append(f"not read as uploads (informational): {text} ({count} connection(s))")
            else:
                self.limits[f"not_read_{kind}"] = _NotRead(text, records=count, hits=1)

    def coverage_notes(self) -> list[str]:
        return list(getattr(self, "_notes", []))

    @staticmethod
    def _openings(src: str, dst: str, totals: _PairTotals) -> str:
        """What the records show about who opened the counted connections, one sentence per reading."""
        n = totals.connections

        def which(k: int) -> str:
            return "the connection" if n == 1 else f"all {n} connections" if k == n else _plural(k, "connection")

        def reasons(reading: str) -> str:
            counts = totals.unknown[reading]
            if n == 1:
                return f"it is {UNKNOWN_REASONS[next(iter(counts))]}"
            return "; ".join(f"{count} {'is' if count == 1 else 'are'} {UNKNOWN_REASONS[why]}"
                             for why, count in sorted(counts.items()))

        parts = []
        k = totals.readings[OPENED_INSIDE]
        if k:
            arkime = k - totals.suricata_only
            facts = ([f"Arkime counted the SYN{'' if n == 1 else f' for {arkime}'}"] if arkime else []) + (
                [(f"{'the only' if n == 1 else f'for {totals.suricata_only} the only'} record of the opening is "
                 f"{SURICATA_STATE_NOTE}")] if totals.suricata_only else [])
            parts.append(f"A recorded TCP opening shows {src} opened {which(k)}, to server port "
                         f"{_port_list(totals.outside_ports[OPENED_INSIDE])} on {dst} ({'; '.join(facts)}).")
        k = totals.readings[CLIENT_SHAPED]
        if k:
            parts.append(f"Which side opened {which(k)} is not recorded: {reasons(CLIENT_SHAPED)}. On "
                         f"{'it' if k == 1 else 'them'} {src} used a port of {EPHEMERAL_FLOOR} or above and {dst} used "
                         f"{_port_list(totals.outside_ports[CLIENT_SHAPED])}, the port shape of {src} as the client.")
        k = totals.readings[UNSHAPED]
        if k:
            parts.append(f"Which side opened {which(k)} is not recorded: {reasons(UNSHAPED)}. The ports do not "
                         f"mark a client either: {src} used {_port_list(totals.inside_ports[UNSHAPED])} and {dst} "
                         f"used {_port_list(totals.outside_ports[UNSHAPED])}, so what {src} sent on "
                         f"{'it' if k == 1 else 'them'} may be a server's answers.")
        k = totals.readings[PORTLESS]
        if k:
            kinds = ", ".join(f"{count} {name.upper()}" if n > 1 else name.upper()
                              for name, count in sorted(totals.unknown[PORTLESS].items()))
            parts.append(f"{which(k)[0].upper()}{which(k)[1:]} {'is' if k == 1 else 'are'} {kinds}, with no ports "
                         f"and no opening the sensors record, so nothing marks a client: what {src} sent on "
                         f"{'it' if k == 1 else 'them'} may be a server's answers.")
        return " ".join(parts)

    def _match(self, src, dst, totals: _PairTotals, total, others) -> Match | None:
        pair = self.pairs.peek((src, dst))
        out, inn = totals.out, totals.inn
        ratio = f"{out / inn:.1f}:1 outbound to inbound" if inn else "nothing came back"
        claim = (f"{src} sent {out:,} bytes ({out / 2**20:.1f} MiB) to {dst} and received {inn:,} bytes back over "
                 f"{_plural(totals.connections, 'connection')} ({_iso(totals.first)} – {_iso(totals.last)}; "
                 f"{ratio}). {self._openings(src, dst, totals)} That is {out / total:.0%} of the {total:,} bytes "
                 f"{src} sent to external addresses in the hunt window over connections read the same way. Byte "
                 f"counts are each side's own and include packet headers; each connection is counted once, from the "
                 f"sensor that recorded the most bytes for it ({_sensor_counts(totals.records)}). "
                 f"{_plural(others, 'other internal address', 'other internal addresses')} also sent data to {dst} "
                 f"in the window. Volume is a deviation, not proof that data was stolen.")
        # The records bounding the stated interval are cited when they are the counted connections' first and last;
        # a bound whose connection did not count (or that is not the true bound) is named as not kept.
        bound = {event_id: key for event_id, key in pair.bound_connections.items() if key in totals.counted}
        first = pair.ends.first[1] if (pair.ends.first and pair.ends.first[0] == totals.first
                                       and pair.ends.first[1] in bound) else "-"
        last = pair.ends.last[1] if (pair.ends.last and pair.ends.last[0] == totals.last
                                     and pair.ends.last[1] in bound) else "-"
        ends = Ends((totals.first, first), (totals.last, last))
        ids = [eid for _bytes, eid, key in sorted(pair.cited, key=lambda item: (-item[0], item[1]))
               if key in totals.counted]
        evs, missing = self._cite(ends, ids)
        if not evs:
            return None
        claim += cited_phrase(len(evs), sum(totals.records.values()), not missing) + bound_note(missing, ends)
        cited = next((e for e in evs if e.has("flow.bytes_toserver") or e.has("source.bytes")), evs[0])
        match = Match(self.id, claim, "aggregate_observation", evs,
                      _predicates(cited, ("source.ip", "destination.ip", "flow.bytes_toserver", "flow.bytes_toclient",
                                          "source.bytes", "destination.bytes", "flow.state", "tcp.flags.syn")),
                      evs[0].ts, self.severity, self.lane, "medium", _entities(evs), group_key=f"{src}|{dst}")
        match.notes.append("ATT&CK context: T1041 / T1048 / T1567 (exfiltration), if the transfer is unauthorized")
        return match


FLOW_PLAYBOOKS = [HorizontalSweep, ProtocolPortMismatch, LongUnidentifiedSession, OutboundVolumeAsymmetry]
