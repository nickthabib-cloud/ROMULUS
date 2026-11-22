"""Administration sessions a network finding cites, joined to the destination host's own logon and what ran in it.

A network sensor records a client opening an administration session (SMB, RPC, WinRM, RDP, SSH, Telnet, the r-services,
VNC, X11) to a server address. The server host's own telemetry may record the logon that session carried. Host
records often carry no address of the host itself, so the join assumes no address-to-host map: it is keyed on the
*client* endpoint, which the destination host writes into its own logon record, in tiers (strongest first):

- ``endpoint``: the host's logon or share record names the session's client address and client port.
- ``host_connection``: the host recorded the connection itself (Sysmon 3 or an audit socket record with the session's
  exact endpoints) and a logon from the client address, without a port, of a type the protocol produces.
- ``address``: one host only logged a logon from the client address, without a port, of a type the protocol produces
  within the window, and the client held no other session of that logon class to another address in it.

Anything else is unresolved with a named reason, never a negative. The join is an inference: every item says so, shows
its key and the clock offset, and is a lead. Its lane rises to high only when a typed host finding the hunt already
published at high or urgent cites a record in the joined logon session; the join alone never raises a lane, and it
never lowers the network finding, which stands on its own.

Cross-target joins cannot stream (the sweep reads one target to its end before the next), so both sides are kept as
compact rows on the rule's disk spill and joined at finalize. The network findings to join are read from the hunt's
store after every other rule has published (``after_findings``); a hunt that publishes them later (expansion, the
agent) is not joined here.
"""
from __future__ import annotations

import ipaddress
import json
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import ClassVar

from romulus.detect import netdef
from romulus.detect.base import Match, Playbook, PredicateField, pf
from romulus.detect.bounded import KeyedStore, RecentIds, StateExhausted, register_store, store_refuses
from romulus.detect.correlation import EPHEMERAL_FLOOR, canon_ip, external
from romulus.evidence.typed import Outcome, TypedEvent, event_os_family
from romulus.hunt.citations import COMPACT_CITATION_NOTE, compact_event, expand_event

# ---- what an administration session is ---------------------------------------------------------------------------
# Server-side TCP ports of remote-administration services (IANA assignments; RPC's endpoint mapper is the entry to
# DCOM, WMI, remote service control and remote task scheduling, whose later calls use dynamic ports and are known
# only by a sensor's protocol parser).
PORT_SERVICE: dict[int, str] = {
    22: "ssh", 23: "telnet", 512: "rexec", 513: "rlogin", 514: "rsh", 135: "rpc", 139: "smb", 445: "smb",
    3389: "rdp", 5985: "winrm", 5986: "winrm",
    **{port: "vnc" for port in range(5900, 5910)},
    **{port: "x11" for port in range(6000, 6064)},
}
# Protocol names sensors write (Zeek conn `service`, Suricata `app_proto`, Arkime `protocol`).
PROTOCOL_SERVICE: dict[str, str] = {
    "ssh": "ssh", "telnet": "telnet", "smb": "smb", "smb2": "smb", "netbios-ssn": "smb", "dce_rpc": "rpc",
    "dcerpc": "rpc", "rdp": "rdp", "rfb": "vnc", "vnc": "vnc", "x11": "x11", "winrm": "winrm",
}
# Record families that are themselves one protocol's transactions.
FAMILY_SERVICE = {"ssh_session": "ssh", "smb_tx": "smb", "rpc_tx": "rpc"}
SERVICE_NAMES = {"ssh": "SSH", "telnet": "Telnet", "rexec": "rexec", "rlogin": "rlogin", "rsh": "rsh",
                 "rpc": "RPC (DCOM, WMI, service control, task scheduling)", "smb": "SMB", "rdp": "RDP",
                 "winrm": "WinRM", "vnc": "VNC", "x11": "X11"}
SERVICE_ATTACK = {"ssh": "T1021.004", "rdp": "T1021.001", "smb": "T1021.002", "rpc": "T1021.003",
                  "winrm": "T1021.006", "vnc": "T1021.005"}
# Services whose sessions leave no logon record any supported host family types (VNC and X11 authenticate inside
# their own protocol).
NO_HOST_LOGON = frozenset({"vnc", "x11"})

# ---- what a host's logon evidence is ---------------------------------------------------------------------------------
# Windows logon types each protocol produces on the server (Microsoft "Audit logon events" / 4624 logon types):
# network (3) for SMB, RPC/DCOM/WMI, WinRM and service control; RemoteInteractive (10), with Network (3) first under
# Network Level Authentication, Unlock (7) on reconnect and CachedRemoteInteractive (12) for RDP; Network (3) or
# NetworkCleartext (8) for the Win32-OpenSSH server.
WINDOWS_LOGON_TYPES = {"smb": frozenset({3}), "rpc": frozenset({3}), "winrm": frozenset({3}),
                       "rdp": frozenset({3, 7, 10, 12}), "ssh": frozenset({3, 8})}
WINDOWS_LOGON_CODES = frozenset({4624, 4625})
WINDOWS_RDP_CODES = frozenset({4778})
# Linux services that log a remote client's address, by the PAM service or daemon name they log under.
LINUX_SERVICE = {"sshd": "ssh", "login": "telnet", "in.telnetd": "telnet", "telnetd": "telnet",
                 "rlogind": "rlogin", "in.rlogind": "rlogin", "rshd": "rsh", "in.rshd": "rsh",
                 "rexecd": "rexec", "in.rexecd": "rexec", "remote": "telnet"}
# Logon classes: services whose sessions produce the same logon evidence, so a client's sessions of one class to two
# addresses cannot be told apart by an address-only logon.
LOGON_CLASS = {"smb": "win_network", "rpc": "win_network", "winrm": "win_network", "rdp": "rdp",
               "ssh": "ssh", "telnet": "telnet", "rlogin": "rlogin", "rsh": "rsh", "rexec": "rexec"}

NETWORK_FAMILIES = ("net_flow", "net_session", "net_alert", "ssh_session", "smb_tx", "rpc_tx", "remote_session",
                    "ntlm_tx", "kerberos_tx", "http_tx", "tls_session")
HOST_FAMILIES = ("auth", "remote_access", "share_access", "process_exec", "net_socket")
_UNSET_SESSIONS = {"0", "4294967295", "-1"}

TIER_WORDS = {
    "endpoint": "the host's own record names the session's client address and client port",
    "host_connection": ("the host recorded this connection itself (same endpoints), and a logon from the client "
                        "address without a port"),
    "address": ("only this host logged a logon from the client address (no port) of a type the protocol produces in "
                "the window, and the client held no other session of that kind to another address in it"),
}
TIER_CONFIDENCE = {"endpoint": "medium", "host_connection": "medium", "address": "low"}
UNRESOLVED_WORDS = {
    "no_logon": "no host logged a logon from the client address within the window",
    "type_inconsistent": "logons from the client address in the window are of types the protocol does not produce",
    "other_connections": "the host's logons from the client address name other client ports (other connections)",
    "ambiguous_endpoint": "several hosts logged a logon naming the same client endpoint in the window",
    "ambiguous_connection": "several hosts recorded the same connection endpoints in the window",
    "ambiguous_address": "several hosts logged a portless logon from the client address in the window",
    "ambiguous_pairing": ("the client held sessions of the same logon class to other addresses in the window, so a "
                          "portless logon cannot be paired with this one"),
    "pairing_unknown": "the client's other sessions could not all be kept (state budget), so a portless pairing is "
                       "not decided",
    "no_host_logon": "the protocol authenticates inside itself and leaves no host logon record a supported family "
                     "types (VNC, X11)",
    "logon_scan_capped": "the client address logged more logons in the window than one lookup reads",
    "connection_host_no_logon": ("the host that recorded the connection logged no portless logon of a fitting type "
                                 "from the client in the window"),
    "external_server": ("the server address is outside the site's internal networks, and no port or host connection "
                        "record ties a host's portless logon to it"),
}


def _num(value) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    try:
        return int(str(value).strip())
    except ValueError:
        return None


def _epoch(value) -> float | None:
    if isinstance(value, datetime):
        return (value if value.tzinfo else value.replace(tzinfo=UTC)).timestamp()
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        return (parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)).timestamp()
    return None


def canon_session(value) -> str | None:
    """A logon session id in one spelling: Windows logon ids arrive as hexadecimal (`0x3e7`) or decimal text, audit
    session ids as integers. Unset ids (0, the audit 'unset' value) are none."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        number = value
    else:
        text = str(value).strip().lower()
        try:
            number = int(text, 16) if text.startswith("0x") else int(text)
        except ValueError:
            return None
    text = str(number)
    return None if number < 0 or text in _UNSET_SESSIONS else text


def _usable_client(ip: str | None) -> bool:
    if ip is None:
        return False
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (address.is_loopback or address.is_unspecified or address.is_multicast or address.is_link_local)


def _names(event: TypedEvent) -> set[str]:
    listed = event.get("network.protocols")
    names = {str(p).lower() for p in (listed if isinstance(listed, list) else [listed]) if p}
    app = event.get("network.app_proto")
    if isinstance(app, str) and app:
        names.add(app.lower())
    return names


@dataclass(frozen=True)
class AdminSession:
    """One network record of an administration session, oriented client to server."""
    eid: str
    client: str
    cport: int
    server: str
    sport: int
    service: str
    start: float
    end: float | None


def admin_session(event: TypedEvent) -> AdminSession | str | None:
    """The administration session a network record shows, oriented client to server; a reason (str) when it is one
    but cannot be read; None when it is no administration session."""
    transport = str(event.get("network.transport") or "").lower()
    if transport and transport not in ("tcp", "6"):
        return None                                     # RDP's UDP channel and the like carry no logon of their own
    names = _names(event)
    named = {PROTOCOL_SERVICE[name] for name in names if name in PROTOCOL_SERVICE}
    family_service = FAMILY_SERVICE.get(event.family)
    src, dst = canon_ip(event.get("source.ip")), canon_ip(event.get("destination.ip"))
    sport, dport = _num(event.get("source.port")), _num(event.get("destination.port"))
    by_port = PORT_SERVICE.get(dport) if dport is not None else None
    reversed_port = (PORT_SERVICE.get(sport) if sport is not None and dport is not None and dport >= 1024
                     and dport not in PORT_SERVICE else None)
    if event.family == "remote_session" and not named:
        named = {"vnc"} if (by_port or reversed_port) == "vnc" else {"rdp"}
    candidates = named | ({family_service} if family_service else set())
    service = None
    if len(candidates) == 1:
        service = next(iter(candidates))
    elif len(candidates) > 1:
        service = by_port if by_port in candidates else (reversed_port if reversed_port in candidates else None)
        if service is None:
            return "the record names several administration protocols"
    elif by_port or reversed_port:
        service = by_port or reversed_port
    if service is None:
        return None
    if src is None or dst is None or sport is None or dport is None:
        return "the record lacks a client or server address or port"
    # The server is the side on the service's port: a record written from the server's side is turned around.
    swap = (by_port != service and reversed_port == service) or (
        by_port is None and reversed_port is None and sport < dport and sport < EPHEMERAL_FLOOR <= dport)
    if swap:
        src, sport, dst, dport = dst, dport, src, sport
    if src == dst:
        return None
    start = _epoch(event.get("flow.start")) or event.ts.timestamp()
    end = _epoch(event.get("flow.end"))
    return AdminSession(event.id, src, sport, dst, dport, service, start, end if end is not None and end >= start
                        else None)


@dataclass(frozen=True)
class LogonRow:
    rid: int
    host: str
    boot: str
    ts: float
    src: str
    sport: int | None
    kind: str
    code: int | None
    ltype: int | None
    svc: str
    outcome: str
    session: str | None
    account: str


def logon_kind(event: TypedEvent) -> str | None:
    """What kind of host logon evidence a record is (None: none the join reads). Records written on the client side
    (4648) or by a domain controller about another host's logon (4768, 4769, 4776) are never read: they would tie
    the client to the wrong host."""
    os_family = event_os_family(event)
    code = _num(event.get("event.code"))
    if event.family == "auth" and os_family == "windows":
        if code in WINDOWS_LOGON_CODES:
            return "win_logon"
        if code in WINDOWS_RDP_CODES:
            return "win_rdp"
        return None
    if event.family == "remote_access" and os_family == "windows":
        return "win_rdp"
    if event.family == "share_access" and os_family == "windows":
        return "win_share"
    if event.family == "auth" and os_family == "linux" and str(event.get("auth.service") or "") in LINUX_SERVICE:
        return "linux"
    return None


def consistent(service: str, server_port: int, row: LogonRow) -> bool:
    """Whether a host logon record is of a kind the session's protocol produces on its server."""
    if row.kind == "win_logon":
        return row.ltype is not None and row.ltype in WINDOWS_LOGON_TYPES.get(service, frozenset())
    if row.kind == "win_rdp":
        return service == "rdp"
    if row.kind == "win_share":
        return service == "smb" or (service == "rpc" and server_port in (139, 445))
    if row.kind == "linux":
        return LINUX_SERVICE.get(row.svc) == service
    return False


def _session_of(event: TypedEvent) -> str | None:
    for name in ("auth.session_id", "share.session_id", "process.session_id"):
        session = canon_session(event.get(name))
        if session is not None:
            return session
    return None


def _process_sessions(event: TypedEvent) -> list[str]:
    out = []
    for name in ("process.session_id", "process.subject_session_id", "share.session_id"):
        session = canon_session(event.get(name))
        if session is not None and session not in out:
            out.append(session)
    return out


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, UTC).isoformat().replace("+00:00", "Z")


def _offset(seconds: float) -> str:
    return f"{seconds:+.1f} s"


class NetworkAdminLogonJoin(Playbook):
    """Join each administration session a published network finding cites to the destination host's logon record,
    then to what ran in that logon session (see the module docstring for the keys)."""
    id = "corr.network_admin_logon"
    version = "1"
    title = ("An administration session a network finding cites, joined (inferred) to the logon the destination host "
             "recorded from that client, and what ran in that logon session")
    families = NETWORK_FAMILIES + HOST_FAMILIES
    context_families = ("process_exec", "net_socket", "share_access")
    os_families = ("linux", "windows")
    claim_type = "correlated_observation"
    kind = "aggregate"
    anchor_class = "lateral_movement"
    severity, lane = "high", "lead"
    # each item carries the sub-technique of its own protocol (VNC sessions are never joined, see NO_HOST_LOGON)
    attack = ("T1021", "T1021.001", "T1021.002", "T1021.003", "T1021.004", "T1021.006", "T1078")
    assures_negative = False
    positive_only_reason = (
        "a join is an inference from the client endpoint, address and time; a session that does not join is "
        "unresolved (the destination may keep no host telemetry, a NAT may sit between sensor and host, or clocks may "
        "differ beyond the allowance), never evidence that no logon happened")
    benign = ("authorized administration over the named protocol (help desk, patching, configuration management, "
              "backup and inventory agents)",
              "domain members fetching group policy over SMB from a domain controller")
    next_checks = ("what the account did on the destination host in the joined logon session beyond the cited records",
                   "whether the account and the client are expected to administer that host",
                   "the client host's own activity just before the session (how it got the credentials)")
    after_findings: ClassVar[bool] = True
    holds_state = True
    # The clock allowance between a network sensor and a host. A Windows domain member whose clock is more than five
    # minutes from its domain controller's fails Kerberos authentication (Microsoft's default "Maximum tolerance for
    # computer clock synchronization"), so the logons this join reads come from hosts within it; NTP-synchronized
    # hosts are far closer. It also bounds how long after the session's recorded end, or after an open-ended record's
    # time, a logon is read as the session's own (a person typing a password into an RDP prompt). A host whose clock is
    # further off leaves its sessions unresolved, never unmatched.
    SKEW_SECONDS = 300.0
    # sshd's own "Accepted" line carries the client port but no audit session; the audit login record (USER_LOGIN,
    # USER_START) carries the session but no port. The audit record follows within seconds of the authentication; two
    # minutes also covers a PAM account or session module that waits on a directory service.
    COMPANION_BEFORE, COMPANION_AFTER = 5.0, 120.0
    ACTIVITY_KEPT = 8              # process and share records cited per joined logon session (earliest first)
    LOGONS_CITED = 4               # host logon records cited per item
    SESSIONS_CITED = 4             # network records cited per item
    LOGON_SCAN = 4096              # logon rows one session's lookup reads (more is a named partial)
    FINDING_PAGE = 500
    EVENT_BATCH = 400
    # Hot-set ceilings (the hunt's memory budget trims them further): session keys are small; an activity state holds
    # up to ACTIVITY_KEPT compact records (a few KiB), so fewer of them stay in memory.
    HOT = 200_000
    ACTIVITY_HOT = 20_000
    ROW_BYTES = 200
    card: ClassVar[dict] = {
        "behavior": "an administration session (SMB, RPC/DCOM/WMI/service control, WinRM, RDP, SSH, Telnet, rlogin, "
                    "rsh, rexec; VNC and X11 are named unresolved) that a published network finding cites, joined to "
                    "the logon record the destination host wrote from that client, and to the process creation and "
                    "share access records in that logon session",
        "telemetry": "network: net_flow, net_session, net_alert, ssh_session, smb_tx, rpc_tx, remote_session, ntlm_tx, "
                     "kerberos_tx, http_tx, tls_session with source/destination ip and port, flow.start/flow.end, "
                     "network.protocols / network.app_proto. Host: Windows 4624/4625 (source.ip, source.port, "
                     "auth.logon_type, auth.session_id), 4778, RDP RemoteConnectionManager 1149 and LocalSessionManager "
                     "records (remote_access), 5140/5145 (share_access with source.ip, source.port, share.session_id), "
                     "4688 and Sysmon 1 (process.session_id, process.subject_session_id), Sysmon 3 and audit socket "
                     "records (net_socket); Linux sshd authentication lines (source.ip, source.port) and audit "
                     "USER_LOGIN/USER_START (source.ip, process.session_id), audit EXECVE (process.session_id). The lab "
                     "source profiles have the Linux side (sshd lines with port, audit login and exec records with "
                     "session ids) and Suricata/Arkime sessions; no host record carries host.ip there, which this "
                     "join does not need",
        "fidelity": "inferred: each side is an observed record cited to its source; the link between them is a "
                    "hypothesis keyed on the client endpoint (address and port), the host's own record of the "
                    "connection, or the client address alone, within a stated clock allowance. Process records are "
                    "joined by the logon session id the host wrote; they show what started in the session, not that "
                    "the session's client caused it",
        "benign_and_cost": "routine administration and group-policy SMB from members to domain controllers; one item "
                           "per (destination host, client address, protocol) across every network finding that cites "
                           "such sessions, so routine traffic merges. Only sessions a network finding already cites "
                           "are joined, so the join adds items in proportion to network findings, not to traffic",
        "query_cost": "none beyond the sweep: compact rows on the rule's disk spill, joined at finalize; cited host "
                      "records are kept compact and their bodies fetched by native id when an item is published",
        "next_pivot": "the joined logon session's full activity on the destination host",
        "adds": "turns a network-only administration lead into 'network session -> logon -> what ran' without any "
                "address-to-host map; expansion reaches host records only for network findings it anchors and only "
                "through a host.ip resolution",
        "research_basis": "ATT&CK Enterprise 20.0 T1021 (.001 RDP, .002 SMB/Windows Admin Shares, .003 DCOM, .004 "
                          "SSH, .005 VNC, .006 WinRM) and T1078 (data components: logon session creation, network "
                          "connection creation); Microsoft 4624 logon-type and IpPort documentation; Microsoft Kerberos "
                          "policy 'Maximum tolerance for computer clock synchronization' (5 minutes); OpenSSH sshd "
                          "'Accepted ... from <addr> port <port>' and Linux audit USER_LOGIN addr/ses fields",
        "retrieval": "the sweep retrieves every record of the host and network datasets in each partition, a superset "
                     "of the records this evaluator reads; the network findings and the host findings that flag a "
                     "session are read from the hunt's store after every other sweep rule has published",
        "window": "logon time within the session's recorded lifetime widened by 300 s on each side (an open-ended "
                  "record: its own time +-300 s); the offset of each joined logon from the session's start is stated",
        "lanes": "lead. High only when a typed host finding this hunt published at high or urgent cites a process or "
                 "share record in the joined logon session (the item cites it and names it); never above its "
                 "strongest observed component, never urgent; the network finding keeps its own lane",
        "state": "every administration session record, every remote-capable host logon record (compact), host "
                 "connection records on administration ports and, per remote logon session, a count and the earliest "
                 "8 process and share records, on the rule's disk spill and keyed stores; a record refused by the "
                 "hunt's state budget makes the result partial and is named",
    }

    def __init__(self):
        super().__init__()
        self._spill = None
        self._tables = False
        self._seen = RecentIds()
        self._rows_account = None
        self._published = None
        self._load_events = None
        self._net_refused = 0
        self._target_seq: dict[str | None, int] = {}
        self._rid = 0
        register_store(self, self)
        # (host, session, boot) of remote logons read so far -> the logon time first registered
        self.remote = KeyedStore(self, "join_remote_sessions", self.HOT)
        # (host, session, boot) -> [count, first ts, last ts, [(ts, id, compact record), ...] earliest kept]
        self.activity = KeyedStore(self, "join_session_activity", self.ACTIVITY_HOT)
        # host -> earliest target order that delivered a session-bearing process or share record not yet joinable
        self.unjoined_activity = KeyedStore(self, "join_unjoined_activity", self.HOT)
        self.unresolved: Counter = Counter()
        self.tiers: Counter = Counter()

    # ------------------------------------------------------------------------------------------------ binding
    def bind_published(self, pages, load_events) -> None:
        """`pages(lane, offset, limit)`: the hunt's stored findings in one lane, a stable page at a time;
        `load_events(ids)`: their cited records as typed events."""
        self._published = pages
        self._load_events = load_events

    def account(self):
        if self._rows_account is None:
            self._rows_account = self.state_budget().account(f"{self.id}:rows")
        return self._rows_account

    def _store(self):
        spill = self.spill()
        if not self._tables:
            spill.table("net", "eid, client, cport, server, sport, service, start, \"end\"")
            spill.table("logon", "rid, host, boot, ts, src, sport, kind, code, ltype, svc, outcome, session, "
                                 "account, tseq, blob")
            spill.table("hostconn", "host, ts, ckey, eid, blob")
            self._tables = True
        return spill

    def close_spill(self) -> None:
        if self._spill is not None:
            self._spill.close()
            self._spill = None
        self._tables = False

    def release_state(self) -> None:
        for store in (self.remote, self.activity, self.unjoined_activity):
            store.clear()
        self.close_spill()

    def _room(self, rows: int) -> bool:
        if store_refuses(self, self.account):
            self.refuse("state_disk", "the join's rows took their share of the hunt's state budget; later "
                                      "administration sessions and logon records are not joined")
            return False
        if self.budget is not None:
            self.budget.charge(self.account(), rows * self.ROW_BYTES)
        return True

    def _add(self, table: str, row: tuple) -> bool:
        try:
            self._store().add(table, row)
            return True
        except StateExhausted as exc:
            self.refuse("state_disk", f"a write to the stage volume failed ({exc}); later administration sessions "
                                      "and logon records are not joined")
            return False

    # ------------------------------------------------------------------------------------------------ consume
    @staticmethod
    def _order(event: TypedEvent):
        # a logon before the process records of the same instant
        return event.ts, 0 if event.family in ("auth", "remote_access", "share_access") else 1, event.id

    def consume(self, events):
        target = self.raw_target()
        seq = self._target_seq.setdefault(target, len(self._target_seq))
        for event in sorted(self.applicable(events), key=self._order):
            if event.id in self._seen:
                continue
            self._seen.add(event.id)
            if event.family in NETWORK_FAMILIES:
                self._network(event)
                continue
            kind = logon_kind(event)
            if kind is not None:
                self._logon(event, kind, seq)
            if event.family == "net_socket":
                self._host_connection(event)
            if event.family in ("process_exec", "share_access") and event.host:
                self._activity(event, seq)
        for store in (self.remote, self.activity, self.unjoined_activity):
            store.trim()
        return []

    def _network(self, event: TypedEvent) -> None:
        session = admin_session(event)
        if session is None:
            return
        if isinstance(session, str):
            self.missing_required += 1
            return
        if not self._room(1):
            self._net_refused += 1
            return
        if not self._add("net", (session.eid, session.client, session.cport, session.server, session.sport,
                                 session.service, session.start, session.end)):
            self._net_refused += 1

    def _logon(self, event: TypedEvent, kind: str, seq: int) -> None:
        src = canon_ip(event.get("source.ip"))
        if not _usable_client(src) or not event.host:
            return
        if not self._room(1):
            return
        session = _session_of(event)
        boot = str(event.get("host.boot.id") or "")
        self._rid += 1
        account = logon_account(event) or ""
        row = (self._rid, event.host, boot, event.ts.timestamp(), src, _num(event.get("source.port")), kind,
               _num(event.get("event.code")), _num(event.get("auth.logon_type")), str(event.get("auth.service") or ""),
               event.outcome.value if isinstance(event.outcome, Outcome) else str(event.outcome), session,
               str(account), seq, compact_event(event))
        if not self._add("logon", row):
            return
        if session is not None and event.outcome == Outcome.success:
            key = (event.host, session, boot)
            if self.remote.get(key) is None and not self.remote.put(key, event.ts.timestamp()):
                self.note_limit("remote_sessions", "the remote logon sessions' store took no new session; later "
                                                   "process records of a new session are not joined to it")

    def _host_connection(self, event: TypedEvent) -> None:
        a, b = canon_ip(event.get("source.ip")), canon_ip(event.get("destination.ip"))
        ap, bp = _num(event.get("source.port")), _num(event.get("destination.port"))
        if None in (a, b, ap, bp) or not event.host:
            return
        if PORT_SERVICE.get(ap) is None and PORT_SERVICE.get(bp) is None:
            return
        if not self._room(1):
            return
        self._add("hostconn", (event.host, event.ts.timestamp(), _ckey(a, ap, b, bp), event.id,
                               compact_event(event)))

    def _activity(self, event: TypedEvent, seq: int) -> None:
        boot = str(event.get("host.boot.id") or "")
        for session in _process_sessions(event):
            key = (event.host, session, boot)
            if self.remote.get(key) is None:
                continue
            state = self.activity.setdefault(key, lambda: [0, None, None, []])
            if state is None:
                self.note_limit("session_activity", "the joined sessions' activity store took no new session; "
                                                    "later process records of a new session are not joined")
                return
            when = event.ts.timestamp()
            state[0] += 1
            state[1] = when if state[1] is None else min(state[1], when)
            state[2] = when if state[2] is None else max(state[2], when)
            kept = state[3]
            if len(kept) < self.ACTIVITY_KEPT or (when, event.id) < (kept[-1][0], kept[-1][1]):
                kept.append((when, event.id, compact_event(event)))
                kept.sort(key=lambda item: (item[0], item[1]))
                del kept[self.ACTIVITY_KEPT:]
            return
        # No remote logon of this session has been read yet: the logon may be in a target read later (it then
        # cannot cite these records), or the session is local. Remember the earliest target that delivered one.
        if _process_sessions(event):
            held = self.unjoined_activity.get(event.host)
            if held is None or seq < held:
                self.unjoined_activity.put(event.host, seq)

    # ------------------------------------------------------------------------------------------------ finalize
    def finalize(self):
        if self._published is None:
            self.note_coverage("no_findings", "the hunt's published network findings were not available to this "
                                              "rule, so no session was joined")
            return []
        return self._finalize()

    def _finalize(self):
        spill = self._store()
        spill.flush()
        db = spill.db
        for sql in ("CREATE INDEX IF NOT EXISTS net_eid ON net(eid)",
                    "CREATE INDEX IF NOT EXISTS net_client ON net(client, start)",
                    "CREATE INDEX IF NOT EXISTS logon_src ON logon(src, sport, ts)",
                    "CREATE INDEX IF NOT EXISTS logon_host ON logon(host, src, ts)",
                    "CREATE INDEX IF NOT EXISTS hostconn_key ON hostconn(ckey, ts)"):
            spill.write(sql, [()])
        spill.table("lead", "eid, cid, rule, lane")
        spill.table("flag", "host, session, boot, cid, rule, lane, eid")
        spill.table("res", "gkey, host, client, service, eid, tier, rids, offset, keys, conn")
        self._collect_findings(spill)
        spill.flush()
        spill.write("CREATE INDEX IF NOT EXISTS lead_eid ON lead(eid)", [()])
        spill.write("CREATE INDEX IF NOT EXISTS flag_key ON flag(host, session, boot)", [()])
        self._resolve_leads(spill)
        spill.flush()
        spill.write("CREATE INDEX IF NOT EXISTS res_key ON res(gkey)", [()])
        self._summarize()
        yield from self._matches(spill)

    def _collect_findings(self, spill) -> None:
        """The leads (records cited by the hunt's urgent, high and lead findings) and the session records host
        findings flag at urgent or high. Read in full before anything is published, so paging is stable."""
        for lane in ("urgent", "high", "lead"):
            offset = 0
            while True:
                page = self._published(lane, offset, self.FINDING_PAGE)
                if not page:
                    break
                offset += len(page)
                flagged_ids: dict[str, tuple] = {}
                for row in page:
                    if row.get("rule_id") == self.id or row.get("provenance", "deterministic") != "deterministic":
                        continue
                    for eid in row.get("event_ids") or []:
                        spill.add("lead", (str(eid), row["id"], row["rule_id"], lane))
                        if lane in ("urgent", "high"):
                            flagged_ids.setdefault(str(eid), (row["id"], row["rule_id"], lane))
                ids = sorted(flagged_ids)
                for start in range(0, len(ids), self.EVENT_BATCH):
                    for event in self._load_events(ids[start:start + self.EVENT_BATCH]):
                        if event.family not in ("process_exec", "share_access") or not event.host:
                            continue
                        cid, rule, flag_lane = flagged_ids[event.id]
                        boot = str(event.get("host.boot.id") or "")
                        for session in _process_sessions(event):
                            spill.add("flag", (event.host, session, boot, cid, rule, flag_lane, event.id))
                if hasattr(self, "heartbeat"):
                    self.heartbeat()

    def _logon_rows(self, db, sql: str, params: tuple) -> list[LogonRow]:
        return [LogonRow(*row) for row in db.execute(sql, params)]

    def _lead_sessions(self, spill):
        """The administration session records the findings cite, in connection order, a page at a time (result rows
        are written between pages, so no read stays open across a write)."""
        spill.write("CREATE TABLE leadnet AS SELECT DISTINCT net.eid AS eid, client, cport, server, sport, service, "
                    "start, \"end\" FROM net JOIN lead ON lead.eid = net.eid "
                    "ORDER BY client, cport, server, sport, start, net.eid", [()])
        after = 0
        while True:
            page = spill.db.execute("SELECT rowid, eid, client, cport, server, sport, service, start, \"end\" "
                                    "FROM leadnet WHERE rowid > ? ORDER BY rowid LIMIT 2000", (after,)).fetchall()
            if not page:
                return
            after = page[-1][0]
            for row in page:
                yield row[1:]

    def _resolve_leads(self, spill) -> None:
        db = spill.db
        last_identity = None
        for eid, client, cport, server, sport, service, start, end in self._lead_sessions(spill):
            session = AdminSession(eid, client, cport, server, sport, service, start, end)
            identity = (client, cport, server, sport)
            outcome = self._resolve(db, session)
            if isinstance(outcome, str):
                if identity != last_identity:
                    self.unresolved[outcome] += 1
                last_identity = identity
                continue
            host, tier, rows, keys = outcome
            if identity != last_identity:
                self.tiers[tier] += 1
            last_identity = identity
            first = min(rows, key=lambda row: abs(row.ts - start))
            spill.add("res", (f"{host}|{client}|{service}", host, client, service, eid, tier,
                              json.dumps([row.rid for row in rows]), first.ts - start, json.dumps(keys),
                              f"{cport}|{server}|{sport}"))
            if hasattr(self, "heartbeat"):
                self.heartbeat()

    def _resolve(self, db, session: AdminSession):
        """(host, tier, logon rows, activity keys) for a session, or an unresolved reason."""
        if session.service in NO_HOST_LOGON:
            return "no_host_logon"
        low = session.start - self.SKEW_SECONDS
        high = (session.end if session.end is not None else session.start) + self.SKEW_SECONDS
        columns = "rid, host, boot, ts, src, sport, kind, code, ltype, svc, outcome, session, account"
        # The client endpoint first: a busy client (a jump host, a NAT) logs many logons, but few name this port.
        endpoint = [row for row in self._logon_rows(
            db, f"SELECT {columns} FROM logon WHERE src = ? AND sport = ? AND ts BETWEEN ? AND ? ORDER BY ts, rid "
                "LIMIT ?", (session.client, session.cport, low, high, self.LOGON_SCAN + 1))
            if consistent(session.service, session.sport, row)]
        if len(endpoint) > self.LOGON_SCAN:
            return "logon_scan_capped"
        if endpoint:
            if len({row.host for row in endpoint}) > 1:
                return "ambiguous_endpoint"
            return self._joined(db, session, endpoint, "endpoint")
        rows = self._logon_rows(db, f"SELECT {columns} FROM logon WHERE src = ? AND sport IS NULL "
                                    "AND ts BETWEEN ? AND ? ORDER BY ts, rid LIMIT ?",
                                (session.client, low, high, self.LOGON_SCAN + 1))
        if len(rows) > self.LOGON_SCAN:
            return "logon_scan_capped"
        portless = [row for row in rows if consistent(session.service, session.sport, row)]
        if not portless:
            ported = self._logon_rows(db, f"SELECT {columns} FROM logon WHERE src = ? AND sport IS NOT NULL "
                                          "AND ts BETWEEN ? AND ? ORDER BY ts, rid LIMIT ?",
                                      (session.client, low, high, self.LOGON_SCAN))
            if any(consistent(session.service, session.sport, row) for row in ported):
                return "other_connections"
            return "type_inconsistent" if rows or ported else "no_logon"
        seen = {row[0] for row in db.execute(
            "SELECT DISTINCT host FROM hostconn WHERE ckey = ? AND ts BETWEEN ? AND ? LIMIT 3",
            (_ckey(session.client, session.cport, session.server, session.sport), low, high))}
        if len(seen) > 1:
            return "ambiguous_connection"
        if seen:
            on_host = [row for row in portless if row.host in seen]
            if on_host:
                return self._joined(db, session, on_host, "host_connection")
            return "connection_host_no_logon"
        hosts = {row.host for row in portless}
        if len(hosts) > 1:
            return "ambiguous_address"
        if external(session.server):
            # the hosts whose telemetry the hunt reads are the site's; an outside server is not one of them unless
            # a port or the host's own connection record says so
            if not netdef.current().configured:
                self.note_coverage("direction", f"{netdef.DIRECTION_ASSUMED_REASON} (address-only joins to servers "
                                                "read as outside the site were refused)")
            return "external_server"
        if self._net_refused:
            return "pairing_unknown"
        services = [name for name, cls in LOGON_CLASS.items() if cls == LOGON_CLASS.get(session.service)]
        others = db.execute(
            f"SELECT 1 FROM net WHERE client = ? AND server != ? AND service IN ({','.join('?' * len(services))}) "
            "AND start <= ? AND coalesce(\"end\", start) >= ? LIMIT 1",
            (session.client, session.server, *services, high, low)).fetchone()
        if others is not None:
            return "ambiguous_pairing"
        return self._joined(db, session, portless, "address")

    def _joined(self, db, session: AdminSession, rows: list[LogonRow], tier: str):
        """The joined logon rows (successes first, nearest first, a bounded number) and the logon sessions whose
        activity to read, with the audit login record that carries a session an sshd line lacks."""
        rows = sorted(rows, key=lambda row: (row.outcome != "success", abs(row.ts - session.start), row.rid))
        host = rows[0].host
        chosen = rows[:self.LOGONS_CITED]
        keys = []
        for row in chosen:
            if row.outcome != "success":
                continue
            if row.session is not None:
                key = [row.host, row.session, row.boot]
                if key not in keys:
                    keys.append(key)
                continue
            if row.kind != "linux":
                continue
            companions = self._logon_rows(
                db, "SELECT rid, host, boot, ts, src, sport, kind, code, ltype, svc, outcome, session, account "
                    "FROM logon WHERE host = ? AND src = ? AND ts BETWEEN ? AND ? AND session IS NOT NULL "
                    "AND svc = ? AND outcome = 'success' ORDER BY ts, rid LIMIT 8",
                (row.host, row.src, row.ts - self.COMPANION_BEFORE, row.ts + self.COMPANION_AFTER, row.svc))
            if len({(item.session, item.boot) for item in companions}) == 1:
                companion = companions[0]
                if all(item.rid != companion.rid for item in chosen):
                    chosen.append(companion)
                key = [companion.host, companion.session, companion.boot]
                if key not in keys:
                    keys.append(key)
            elif companions:
                self.note_coverage("companion_ambiguous", "an sshd authentication line had several audit login "
                                                          "sessions from its client within two minutes; its logon "
                                                          "session's activity was not joined")
        return host, tier, chosen, keys

    def _summarize(self) -> None:
        self.note_coverage("scope", "joins the administration sessions cited by findings the sweep published; findings "
                                    "the packet and baseline stages, expansion and the AI agent publish later are not "
                                    "joined")
        if self.tiers:
            self.note_coverage("joined", "administration sessions joined to a host logon: " + ", ".join(
                f"{count} by {tier}" for tier, count in sorted(self.tiers.items())))
        if self.unresolved:
            self.note_coverage("unresolved", "administration sessions cited by network findings left unresolved "
                               "(never a negative): " + "; ".join(
                                   f"{count}: {UNRESOLVED_WORDS[reason]}"
                                   for reason, count in sorted(self.unresolved.items())))
        if self.unresolved.get("logon_scan_capped"):
            self.note_limit("logon_scan", f"a client logged more than {self.LOGON_SCAN} portless logons within one "
                                          "session's window; those sessions were not joined", records=0)
        if self._net_refused:
            self.note_limit("net_rows", "administration session records the state budget refused are not joined and "
                                        "make portless pairings undecidable", records=0)

    # ------------------------------------------------------------------------------------------------ publishing
    def _matches(self, spill):
        """One item per (destination host, client address, service); group keys are read a page at a time."""
        db = spill.db
        after = ""
        while True:
            keys = [row[0] for row in db.execute("SELECT DISTINCT gkey FROM res WHERE gkey > ? ORDER BY gkey "
                                                 "LIMIT 500", (after,)).fetchall()]
            if not keys:
                return
            after = keys[-1]
            for gkey in keys:
                rows = db.execute("SELECT gkey, host, client, service, eid, tier, rids, offset, keys, conn FROM res "
                                  "WHERE gkey = ? ORDER BY eid", (gkey,)).fetchall()
                yield self._match(db, rows)

    def _logon_events(self, db, rids: list[int]) -> dict[int, TypedEvent]:
        out = {}
        for start in range(0, len(rids), 500):
            batch = rids[start:start + 500]
            for rid, blob in db.execute(f"SELECT rid, blob FROM logon WHERE rid IN ({','.join('?' * len(batch))})",
                                        tuple(batch)):
                out[rid] = _compact(blob)
        return out

    def _match(self, db, rows) -> Match:
        _gkey, host, client, service = rows[0][:4]
        tiers = Counter(row[5] for row in rows)
        tier = min(tiers, key=lambda name: list(TIER_WORDS).index(name))
        session_ids = list(dict.fromkeys(row[4] for row in rows))
        connections = len({row[9] for row in rows})
        rids = list(dict.fromkeys(rid for row in rows for rid in json.loads(row[6])))
        keys = list(dict.fromkeys(tuple(key) for row in rows for key in json.loads(row[8])))
        offsets = [row[7] for row in rows]
        logons = self._logon_events(db, rids)
        logon_events = [logons[rid] for rid in rids[: self.LOGONS_CITED * 2] if rid in logons]
        network_events = self._load_events(session_ids[: self.SESSIONS_CITED]) if self._load_events else []
        network_events = sorted(network_events, key=lambda event: (event.ts, event.id))
        named = session_ids[:900]
        findings = db.execute(
            f"SELECT DISTINCT rule, lane, cid FROM lead WHERE eid IN ({','.join('?' * len(named))}) "
            "ORDER BY rule, cid", tuple(named)).fetchall()
        activity_events, counts, flags = [], [], []
        for key in keys:
            state = self.activity.peek(tuple(key))
            if state is not None:
                counts.append((key, state[0]))
                activity_events += [_compact(blob) for _ts, _id, blob in state[3]]
            for flag in db.execute("SELECT DISTINCT cid, rule, lane, eid FROM flag WHERE host = ? AND session = ? "
                                   "AND boot = ? ORDER BY lane DESC, rule, cid", tuple(key)).fetchall():
                flags.append(flag)
        flag_ids = {flag[3] for flag in flags}
        flagged_events = [event for event in (self._load_events(sorted(flag_ids)[:self.ACTIVITY_KEPT])
                                              if flag_ids and self._load_events else [])
                          if event.id not in {item.id for item in activity_events}]
        lane = "high" if flags else "lead"
        successes = [event for event in logon_events if event.outcome == Outcome.success]
        severity = "high" if successes else "medium"
        claim = self._claim(host, client, service, tier, connections, len(session_ids), findings, logon_events,
                            offsets, counts, activity_events, flags, network_events)
        events = list({event.id: event for event in
                       [*network_events, *logon_events, *activity_events, *flagged_events]}.values())
        predicate = self._predicate(network_events, logon_events, tier)
        notes = [f"Join key: {TIER_WORDS[tier]}; clock allowance +-{self.SKEW_SECONDS:.0f} s around the session's "
                 "recorded lifetime.",
                 "The link between the network session and the host's logon is inferred, not observed: NAT, a shared "
                 "client address or a host clock beyond the allowance can make it wrong."]
        if tier == "address":
            notes.append("Address-only join: no port ties the logon to this connection, so it rests on this host "
                         "being the only one with a fitting logon from the client in the window.")
        order_note = self._order_note(host, logon_events)
        if order_note:
            notes.append(order_note)
        attack = tuple(sorted({"T1021", *(SERVICE_ATTACK.get(service, "T1021"),),
                               *(("T1078",) if successes else ())}))
        entities = list(dict.fromkeys(entity for event in [*logon_events, *network_events[:1]]
                                      for entity in event.entities()))
        return Match(self.id, claim, self.claim_type, events, predicate,
                     min((event.ts for event in logon_events), default=None), severity, lane,
                     TIER_CONFIDENCE[tier], entities, notes, group_key=f"{self.id}|{host}|{client}|{service}",
                     context_ids={event.id for event in network_events}, attack=attack)

    def _order_note(self, host: str, logon_events: list[TypedEvent]) -> str:
        """Process records of this host read from a target before its logons were: those in a joined session were
        not joined (they arrived before the logon that names their session)."""
        earliest = self.unjoined_activity.peek(host)
        if earliest is None:
            return ""
        return ("Some process or share records of this host were read before a remote logon naming their session "
                "had been read (a source target read earlier than the logon's); any that belong to the joined "
                "session are not counted here.")

    def _predicate(self, network_events, logon_events, tier) -> list[PredicateField]:
        out = []
        for event in network_events[:1]:
            for name in ("source.ip", "source.port", "destination.ip", "destination.port"):
                if event.has(name):
                    out.append(pf(event, name))
        for event in logon_events[:1]:
            for name in ("source.ip", *(("source.port",) if tier == "endpoint" else ()), "auth.logon_type",
                         "auth.session_id", "auth.service"):
                if event.has(name):
                    out.append(pf(event, name))
        return out

    def _claim(self, host, client, service, tier, connections, records, findings, logons, offsets, counts,
               activity, flags, network_events) -> str:
        cited_by = ", ".join(f"{rule} ({lane})" for rule, lane, _cid in findings[:6])
        if len(findings) > 6:
            cited_by += f" and {len(findings) - 6} more"
        server = next((event.get("destination.ip") for event in network_events if event.has("destination.ip")), None)
        parts = [f"Inferred join (a hypothesis, not an observed link): {connections} {SERVICE_NAMES[service]} "
                 f"connection(s) ({records} network record(s)) from {client}"
                 + (f" (to {server})" if server else "")
                 + f", cited by {cited_by}, match logon records host {host} wrote from that client. "
                 f"Key: {TIER_WORDS[tier]}. Logon time minus session start: "
                 + ", ".join(_offset(offset) for offset in sorted(offsets, key=abs)[:4])
                 + f" (allowance +-{self.SKEW_SECONDS:.0f} s)."]
        for event in logons[: self.LOGONS_CITED]:
            parts.append(" " + _logon_words(event))
        if counts:
            total = sum(count for _key, count in counts)
            names = list(dict.fromkeys(_activity_name(event) for event in activity))
            windows = any(event_os_family(event) == "windows" for event in logons)
            parts.append(f" {total} process or share record(s) in the joined logon session(s) "
                         f"({', '.join(f'session {_shown(key[1], windows)}' for key, _count in counts[:4])}); the "
                         f"earliest "
                         f"{len(activity)} cited: {', '.join(names[:8])}.")
        elif any(event.outcome == Outcome.success for event in logons):
            parts.append(" No process or share record of the joined logon session was read (this states nothing "
                         "about what ran: the host may not record it).")
        if flags:
            named = list(dict.fromkeys(f"{rule} ({lane})" for _cid, rule, lane, _eid in flags))
            parts.append(f" A typed host finding cites a record in that session: {', '.join(named[:4])}.")
        return "".join(parts)


def _ckey(a: str, ap: int, b: str, bp: int) -> str:
    ends = sorted([(a, ap), (b, bp)])
    return f"{ends[0][0]}:{ends[0][1]}|{ends[1][0]}:{ends[1][1]}"


def _compact(blob: bytes) -> TypedEvent:
    event = expand_event(blob)
    return event.model_copy(update={"caveats": list(dict.fromkeys([*event.caveats, COMPACT_CITATION_NOTE]))})


def logon_account(event: TypedEvent) -> str | None:
    """The account a host logon record names as logged on: Windows' target account (the subject is the service
    that wrote it), the RDP session manager's user, else the Linux login's account."""
    for name, domain in (("account.name", "account.domain"), ("remote.user", "remote.domain"),
                         ("user.name", "user.domain")):
        value = event.get(name)
        if value not in (None, "", "-"):
            qualifier = event.get(domain) if event_os_family(event) == "windows" else None
            return f"{qualifier}\\{value}" if qualifier not in (None, "", "-") else str(value)
    return None


def _logon_words(event: TypedEvent) -> str:
    who = logon_account(event) or "an unrecorded account"
    result = {"success": "succeeded", "failure": "failed"}.get(
        event.outcome.value if isinstance(event.outcome, Outcome) else str(event.outcome), "outcome unknown")
    code = event.get("event.code")
    what = (f"Windows event {code}" + (f" logon type {event.get('auth.logon_type')}"
                                       if event.has("auth.logon_type") else "")
            if code is not None else f"{event.get('auth.service') or 'login'} {event.get('auth.phase') or 'record'}")
    session = _session_of(event)
    endpoint = event.get("source.ip")
    if event.has("source.port"):
        endpoint = f"{endpoint}:{event.get('source.port')}"
    return (f"{what} for {who} from {endpoint} at {_iso(event.ts.timestamp())} ({result}"
            + (f", logon session {_shown(session, event_os_family(event) == 'windows')}" if session else "") + ").")


def _shown(session: str, windows: bool) -> str:
    """A canonical session id as its operating system writes it (Windows logon ids in hexadecimal)."""
    return hex(int(session)) if windows else session


def _activity_name(event: TypedEvent) -> str:
    if event.family == "share_access":
        return f"share {event.get('share.name') or '?'}"
    executable = str(event.get("process.executable") or "?")
    return executable.replace("\\", "/").rsplit("/", 1)[-1]


RULES = (NetworkAdminLogonJoin,)

__all__ = ["RULES", "NetworkAdminLogonJoin", "admin_session", "canon_session", "consistent", "logon_account",
           "logon_kind"]
