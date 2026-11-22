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
published at high or urgent cites a record in a logon session the join reached by the client endpoint or the host's
own connection record (an address-only join never raises it); the join alone never raises a lane, and it never lowers
the network finding, which stands on its own.

Cross-target joins cannot stream (the sweep reads one target to its end before the next), so both sides are kept as
compact rows on the rule's disk spill and joined at finalize. The network findings to join are read from the hunt's
store after every other rule has published (``after_findings``); a hunt that publishes them later (expansion, the
agent) is not joined here.
"""
from __future__ import annotations

import contextlib
import hashlib
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
# Services that authenticate once, when the connection opens: their logon is read around the opening only.
CONNECT_AUTH = frozenset({"ssh", "telnet", "rlogin", "rsh", "rexec"})

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

# The join's tables: the sweep's rows (kept after the sweep for the pass after the packet and baseline stages) and
# what each pass adds. A session record is judged once (res or unres, by its record id); a lead is a (record, finding)
# pair; pub holds each item's last published content digest, so a pass republishes only what changed.
JOIN_SCHEMA = {
    "net": 'eid, client, cport, server, sport, service, start, "end", origin',
    "logon": "rid, host, boot, ts, src, sport, kind, code, ltype, svc, outcome, session, account, tseq, blob",
    "hostconn": "host, ts, ckey, eid, blob",
    "remote_rows": "host, session, entry, min_ts, boot, PRIMARY KEY (host, session, entry)",
    "act": "host, session, entry, count, PRIMARY KEY (host, session, entry)",
    "act_ex": "host, session, entry, ts, eid, blob, PRIMARY KEY (host, session, entry, eid)",
    "unjoined": "host PRIMARY KEY, seq",
    "meta": "k PRIMARY KEY, v",
    "lead": "eid, cid, rule, lane, PRIMARY KEY (eid, cid)",
    "flag": "host, session, boot, cid, rule, lane, eid, ts",
    "res": "eid PRIMARY KEY, gkey, host, client, service, tier, rids, offset, keys, identity",
    "unres": "eid PRIMARY KEY, reason, identity",
    "pub": "gkey PRIMARY KEY, digest",
}
KEPT_TABLES = tuple(JOIN_SCHEMA)
JOIN_INDEXES = (
    "CREATE INDEX IF NOT EXISTS net_eid ON net(eid)",
    "CREATE INDEX IF NOT EXISTS net_client ON net(client, start)",
    "CREATE INDEX IF NOT EXISTS logon_src ON logon(src, sport, ts)",
    "CREATE INDEX IF NOT EXISTS logon_host ON logon(host, src, ts)",
    "CREATE INDEX IF NOT EXISTS logon_rid ON logon(rid)",
    "CREATE INDEX IF NOT EXISTS hostconn_key ON hostconn(ckey, ts)",
    "CREATE INDEX IF NOT EXISTS flag_key ON flag(host, session)",
    "CREATE INDEX IF NOT EXISTS res_key ON res(gkey)",
)
NOTE_PREFIX = "network-host join: "
LIMIT_PREFIX = NOTE_PREFIX + "state limit: "

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
    "logon_type_missing": ("a Windows logon from the client in the window does not record its logon type, so whether "
                           "the protocol produced it is not decided"),
    "logons_refused": ("the state budget refused some host logon or connection records, so this host being the only one "
                       "with a fitting portless logon is not known"),
    "port_reused": ("the client used the same port toward another server in the window, so the host's logon naming "
                    "that endpoint may be the other connection's"),
    "pairing_unread": ("the session was read by a later stage, not the sweep, so the client's other sessions in its "
                       "source were not all read and a portless logon cannot be paired with it"),
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
            parsed = datetime.fromisoformat(value)
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
    origin: str = "sweep"      # "cited": typed from a later stage's cited record, not read by the sweep


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


def _untyped(service: str, row: LogonRow) -> bool:
    """A Windows logon record without its logon type, for a protocol whose fitting logon is told by its type."""
    return row.kind == "win_logon" and row.ltype is None and service in WINDOWS_LOGON_TYPES


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
    benign = (("authorized administration over the named protocol (help desk, patching, configuration management, "
               "backup and inventory agents)"),
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
    ENTRIES_KEPT = 8               # logons per (host, session id) told apart by boot: reboots within one hunt
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
                     "session are read from the hunt's store after every other sweep rule has published, and again "
                     "after the packet and baseline stages (their findings, the first-seen administration pair among "
                     "them, joined against the rows the sweep kept)",
        "window": "logon time within the session's recorded lifetime widened by 300 s on each side (an open-ended "
                  "record: its own time +-300 s); the offset of each joined logon from the session's start is stated",
        "lanes": "lead. High only when a typed host finding this hunt published at high or urgent cites a process or "
                 "share record in a logon session the join reached by the client endpoint or the host's own "
                 "connection record (the item cites it and names it); an address-only join never raises the lane; "
                 "never above its strongest observed component, never urgent; the network finding keeps its own lane",
        "state": "every administration session record, every remote-capable host logon record (compact), host "
                 "connection records on administration ports and, per remote logon session, a count and the earliest "
                 "8 process and share records, on the rule's disk spill and keyed stores; a record refused by the "
                 "hunt's state budget makes the result partial and is named. The rows are kept in the hunt's stage "
                 "directory for the pass after the packet and baseline stages and removed when it finishes, when the "
                 "hunt is deleted, or at the next hunt's start once its pass finished",
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
        self._host_refused = 0          # host logon and connection records the state budget refused
        self._target_seq: dict[str | None, int] = {}
        self._rid = 0
        register_store(self, self)
        # (host, session) of remote logons read so far -> [[logon id, earliest logon time, boot], ...]: one entry per
        # logon, a new one only when a boot both records name differs (the id was reused after a reboot)
        self.remote = KeyedStore(self, "join_remote_sessions", self.HOT)
        # (host, session, logon id) -> [count, first ts, last ts, [(ts, id, compact record), ...] earliest kept]
        self.activity = KeyedStore(self, "join_session_activity", self.ACTIVITY_HOT)
        # host -> earliest target order that delivered a session-bearing process or share record not yet joinable
        self.unjoined_activity = KeyedStore(self, "join_unjoined_activity", self.HOT)

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

    TABLES = (("net", JOIN_SCHEMA["net"]),
              ("logon", "rid, host, boot, ts, src, sport, kind, code, ltype, svc, outcome, session, account, tseq, blob"),
              ("hostconn", "host, ts, ckey, eid, blob"))

    def _store(self):
        """The rule's spill with its tables; a table the volume refused is created again on the next write, and one
        already made is never made twice."""
        spill = self.spill()
        if not self._tables:
            made = self.__dict__.setdefault("_made", set())
            for name, columns in self.TABLES:
                if name not in made:
                    spill.table(name, columns)
                    made.add(name)
            self._tables = True
        return spill

    def close_spill(self) -> None:
        if self._spill is not None:
            self._spill.close()
            self._spill = None
        self._tables = False
        self.__dict__.pop("_made", None)

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
                                 session.service, session.start, session.end, "sweep")):
            self._net_refused += 1

    def _logon(self, event: TypedEvent, kind: str, seq: int) -> None:
        src = canon_ip(event.get("source.ip"))
        if not _usable_client(src) or not event.host:
            return
        if not self._room(1):
            self._host_refused += 1
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
            self._host_refused += 1
            return
        if session is not None and event.outcome == Outcome.success:
            self._register(event.host, session, boot, event.ts.timestamp())

    def _register(self, host: str, session: str, boot: str, when: float) -> None:
        """Record a remote logon session. Records of one logon (sshd's line and the audit login, 4624 and 5140)
        share one entry, the earliest time kept; a reboot (both records naming different boots) starts another."""
        entries = self.remote.get((host, session)) or []
        for entry in entries:
            if not _boots_conflict(entry[2], boot):
                entry[1] = min(entry[1], when)
                entry[2] = entry[2] or boot
                return
        entries = [*entries, [f"{when:.6f}", when, boot]][-self.ENTRIES_KEPT:]
        if not self.remote.put((host, session), entries):
            self.note_limit("remote_sessions", "the remote logon sessions' store took no new session; later "
                                               "process records of a new session are not joined to it")

    def _entry(self, host: str, session: str, boot: str, when: float | None):
        """The remote logon entry a record of this session belongs to: boots agree (or one is unknown) and, for a
        record with a time, the logon came first (one second of slack for clock rounding). The latest such."""
        entries = self.remote.peek((host, session)) if when is None else self.remote.get((host, session))
        fitting = [entry for entry in entries or [] if not _boots_conflict(entry[2], boot)
                   and (when is None or entry[1] <= when + 1.0)]
        return max(fitting, key=lambda entry: entry[1]) if fitting else None

    def _host_connection(self, event: TypedEvent) -> None:
        a, b = canon_ip(event.get("source.ip")), canon_ip(event.get("destination.ip"))
        ap, bp = _num(event.get("source.port")), _num(event.get("destination.port"))
        if None in (a, b, ap, bp) or not event.host:
            return
        if PORT_SERVICE.get(ap) is None and PORT_SERVICE.get(bp) is None:
            return
        # Only the server's record of the connection places it: a host that initiated it (Sysmon's Initiated, an audit
        # connect() call) is the client, and a record that does not say which side the host was places nothing.
        accepted = (event.get("network.direction") == "ingress"
                    or str(event.get("socket.syscall") or "").startswith("accept"))
        if not accepted:
            return
        if not self._room(1) or not self._add("hostconn", (event.host, event.ts.timestamp(), _ckey(a, ap, b, bp),
                                                             event.id, compact_event(event))):
            self._host_refused += 1

    def _activity(self, event: TypedEvent, seq: int) -> None:
        boot = str(event.get("host.boot.id") or "")
        when = event.ts.timestamp()
        for session in _process_sessions(event):
            entry = self._entry(event.host, session, boot, when)
            if entry is None:
                continue
            key = (event.host, session, entry[0])
            state = self.activity.setdefault(key, lambda: [0, None, None, []])
            if state is None:
                self.note_limit("session_activity", "the joined sessions' activity store took no new session; "
                                                    "later process records of a new session are not joined")
                return
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
    # Where the sweep keeps the join's rows for the pass after the packet and baseline stages (set by the sweep; None
    # keeps nothing).
    persist_path = None
    # Rules of the stages after the sweep (packet, baseline): their findings may cite records the sweep never read.
    later_rules: frozenset = frozenset()
    LATER_REVISION = ("findings published after the sweep (packet and baseline stages) cite sessions of this item, or "
                      "a host finding flags a record in its logon session")

    def finalize(self):
        if self._published is None:
            self.note_coverage("no_findings", "the hunt's published network findings were not available to this "
                                              "rule, so no session was joined")
            return []
        return self._finalize()

    def _finalize(self):
        spill = self._store()
        spill.flush()
        self._materialize(spill)
        yield from self.join_pass(spill, later=False)
        self._persist(spill)

    def _materialize(self, spill) -> None:
        """The keyed stores as plain tables, so both passes (and the pass after the later stages, from the kept rows)
        read the same thing."""
        for name in ("remote_rows", "act", "act_ex", "unjoined", "meta"):
            spill.write(f"CREATE TABLE IF NOT EXISTS {name} ({JOIN_SCHEMA[name]})", [()])
        rows: dict[str, list] = {"remote_rows": [], "act": [], "act_ex": [], "unjoined": []}

        def flush(force=False):
            for name, batch in rows.items():
                if batch and (force or len(batch) >= 5000):
                    spill.write(f"INSERT OR IGNORE INTO {name} VALUES ({','.join('?' * len(batch[0]))})", batch)
                    batch.clear()
        for (host, session), entries in self.remote.items():
            for entry_id, min_ts, boot in entries:
                rows["remote_rows"].append((host, session, entry_id, min_ts, boot))
            flush()
        for (host, session, entry_id), state in self.activity.items():
            rows["act"].append((host, session, entry_id, state[0]))
            rows["act_ex"].extend((host, session, entry_id, when, eid, blob) for when, eid, blob in state[3])
            flush()
        for host, seq in self.unjoined_activity.items():
            rows["unjoined"].append((host, seq))
        flush(force=True)
        spill.write("INSERT OR REPLACE INTO meta VALUES (?, ?)",
                    [("net_refused", str(self._net_refused)), ("host_refused", str(self._host_refused)),
                     ("limits", json.dumps(sorted(self.limit_reasons())))])

    def _persist(self, spill) -> None:
        """Keep the join's rows for the pass after the packet and baseline stages: written whole to a temporary file
        beside the kept file and moved into place, so a half-written copy is never read. Kept only while the stage
        volume has room for it above its reserve; otherwise the later pass finds none and says so."""
        import os
        from pathlib import Path
        path = self.persist_path
        if path is None:
            self.note_coverage("not_kept", "the join's rows were not kept for findings published after the sweep (no "
                                           "stage directory)")
            return
        path = Path(path)
        size = spill.path.stat().st_size if spill.path.exists() else 0
        headroom = self.state_budget().headroom()
        if headroom is not None and size > headroom:
            self.note_limit("kept_rows", "the stage volume had no room to keep the join's rows for findings published "
                                         "after the sweep; those findings' sessions are left unresolved", records=0)
            return
        import sqlite3
        partial = path.with_name(path.name + ".part")
        db = spill.db
        attached = False
        try:
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            partial.unlink(missing_ok=True)
            db.commit()
            db.execute("ATTACH DATABASE ? AS kept", (str(partial),))
            attached = True
            for name in KEPT_TABLES:
                db.execute(f"CREATE TABLE kept.{name} ({JOIN_SCHEMA[name]})")
                if db.execute("SELECT 1 FROM main.sqlite_master WHERE type = 'table' AND name = ?",
                              (name,)).fetchone():
                    db.execute(f"INSERT OR IGNORE INTO kept.{name} SELECT * FROM main.{name}")
            for index in JOIN_INDEXES:
                db.execute(index.replace("CREATE INDEX IF NOT EXISTS ", "CREATE INDEX IF NOT EXISTS kept."))
            db.commit()
            db.execute("DETACH DATABASE kept")
            attached = False
            os.replace(partial, path)
        except (sqlite3.Error, OSError) as exc:
            # the volume filled (or the folder could not be written) between the room check and the copy: the sweep's
            # own results stand; the later pass finds no rows and leaves its findings' sessions unresolved, named
            with contextlib.suppress(sqlite3.Error):
                db.rollback()
                if attached:
                    db.execute("DETACH DATABASE kept")
            with contextlib.suppress(OSError):
                partial.unlink(missing_ok=True)
            self.note_limit("kept_rows", f"the join's rows could not be kept for findings published after the sweep "
                                         f"({exc.__class__.__name__}: {str(exc)[:120]}); those findings' sessions are "
                                         "left unresolved", records=0)

    # ---- the join itself, over the sweep's spill or over the kept rows ------------------------------------------------
    def join_pass(self, rows, *, later: bool):
        """Join the sessions the hunt's findings cite that no earlier pass judged, and yield the item of every
        (destination host, client address, service) whose content changed. `rows` holds the join's tables (`.db`
        to read, `.write(sql, rows)` to write)."""
        for name in ("lead", "flag", "res", "unres", "pub", "meta"):
            rows.write(f"CREATE TABLE IF NOT EXISTS {name} ({JOIN_SCHEMA[name]})", [()])
        for index in JOIN_INDEXES:
            rows.write(index, [()])
        meta = dict(rows.db.execute("SELECT k, v FROM meta").fetchall())
        self._net_refused = int(meta.get("net_refused") or self._net_refused or 0)
        self._host_refused = int(meta.get("host_refused") or self._host_refused or 0)
        rows.write("DELETE FROM flag", [()])
        self._collect_findings(rows)
        self._resolve_leads(rows)
        for number, line in enumerate(self.summary_notes(rows)):
            if line.startswith(LIMIT_PREFIX):
                self.note_limit(f"join{number}", line[len(LIMIT_PREFIX):], records=0)
            else:
                self.note_coverage(f"join{number}", line)
        yield from self._matches(rows, later)

    def _insert(self, rows, table: str, batch: list[tuple]) -> None:
        if batch:
            rows.write(f"INSERT OR IGNORE INTO {table} VALUES ({','.join('?' * len(batch[0]))})", batch)
            batch.clear()

    def _collect_findings(self, rows) -> None:
        """The leads (records cited by the hunt's urgent, high and lead findings) and the session records host
        findings flag at urgent or high. Read in full before anything is published, so paging is stable. Findings an
        expansion reach or the AI agent produced are not leads: expansion follows typed links itself, and agent output
        is not typed evidence."""
        leads, flags, later_cited = [], [], set()
        for lane in ("urgent", "high", "lead"):
            offset = 0
            while True:
                page = self._published(lane, offset, self.FINDING_PAGE)
                if not page:
                    break
                offset += len(page)
                flagged_ids: dict[str, tuple] = {}
                for row in page:
                    if (row.get("rule_id") == self.id or row.get("provenance", "deterministic") != "deterministic"
                            or row.get("source_anchor_id") or row.get("source_case_id")):
                        continue
                    # a record cited only in support of a statement (a lineage ancestor, a span bound) is not
                    # what a host finding flags
                    supporting = set(row.get("context_event_ids") or ())
                    later = row["rule_id"] in self.later_rules
                    for eid in row.get("event_ids") or []:
                        leads.append((str(eid), row["id"], row["rule_id"], lane))
                        if later:
                            later_cited.add(str(eid))
                        if lane in ("urgent", "high") and eid not in supporting:
                            flagged_ids.setdefault(str(eid), (row["id"], row["rule_id"], lane))
                    if len(leads) >= 5000:
                        self._insert(rows, "lead", leads)
                ids = sorted(flagged_ids)
                for start in range(0, len(ids), self.EVENT_BATCH):
                    for event in self._load_events(ids[start:start + self.EVENT_BATCH]):
                        if event.family not in ("process_exec", "share_access") or not event.host:
                            continue
                        cid, rule, flag_lane = flagged_ids[event.id]
                        boot = str(event.get("host.boot.id") or "")
                        for session in _process_sessions(event):
                            flags.append((event.host, session, boot, cid, rule, flag_lane, event.id,
                                          event.ts.timestamp()))
                    self._insert(rows, "flag", flags)
                if hasattr(self, "heartbeat"):
                    self.heartbeat()
        self._insert(rows, "lead", leads)
        self._insert(rows, "flag", flags)
        self._add_cited_sessions(rows, later_cited)

    def _add_cited_sessions(self, rows, cited: set[str]) -> None:
        """Session records a later stage's finding cites that the sweep never read (the packet stage's own Arkime
        records, say): typed from the cited record itself, like any the sweep read."""
        ids = sorted(cited)
        for start in range(0, len(ids), self.EVENT_BATCH):
            batch = ids[start:start + self.EVENT_BATCH]
            known = {row[0] for row in rows.db.execute(
                f"SELECT eid FROM net WHERE eid IN ({','.join('?' * len(batch))})", tuple(batch))}
            wanted = [eid for eid in batch if eid not in known]
            added = []
            for event in (self._load_events(wanted) if wanted else []):
                session = admin_session(event) if event.family in NETWORK_FAMILIES else None
                if isinstance(session, AdminSession):
                    added.append((session.eid, session.client, session.cport, session.server, session.sport,
                                  session.service, session.start, session.end, "cited"))
            if added:
                rows.write(f"INSERT INTO net VALUES ({','.join('?' * 9)})", added)

    def _logon_rows(self, db, sql: str, params: tuple) -> list[LogonRow]:
        return [LogonRow(*row) for row in db.execute(sql, params)]

    def _lead_sessions(self, rows):
        """The administration session records the findings cite that no pass has judged, in connection order, a page
        at a time (result rows are written between pages, so no read stays open across a write)."""
        rows.write("DROP TABLE IF EXISTS leadnet", [()])
        rows.write("CREATE TABLE leadnet AS SELECT DISTINCT net.eid AS eid, client, cport, server, sport, service, "
                   "start, \"end\", origin FROM net JOIN lead ON lead.eid = net.eid "
                   "WHERE net.eid NOT IN (SELECT eid FROM res) AND net.eid NOT IN (SELECT eid FROM unres) "
                   "ORDER BY client, cport, server, sport, start, net.eid", [()])
        after = 0
        while True:
            page = rows.db.execute("SELECT rowid, eid, client, cport, server, sport, service, start, \"end\", "
                                   "origin "
                                   "FROM leadnet WHERE rowid > ? ORDER BY rowid LIMIT 2000", (after,)).fetchall()
            if not page:
                return
            after = page[-1][0]
            yield from (row[1:] for row in page)

    def _resolve_leads(self, rows) -> None:
        db = rows.db
        results, unresolved = [], []
        for eid, client, cport, server, sport, service, start, end, origin in self._lead_sessions(rows):
            session = AdminSession(eid, client, cport, server, sport, service, start, end, origin)
            identity = f"{client}|{cport}|{server}|{sport}"
            outcome = self._resolve(rows, session)
            if isinstance(outcome, str):
                unresolved.append((eid, outcome, identity))
            else:
                host, tier, chosen, keys = outcome
                first = min(chosen, key=lambda row: abs(row.ts - start))
                results.append((eid, f"{host}|{client}|{service}", host, client, service, tier,
                                json.dumps([row.rid for row in chosen]), first.ts - start, json.dumps(keys), identity))
            if len(results) + len(unresolved) >= 2000:
                # written between pages of the lead read, which is fully fetched page by page
                self._insert(rows, "res", results)
                self._insert(rows, "unres", unresolved)
            if hasattr(self, "heartbeat"):
                self.heartbeat()
        self._insert(rows, "res", results)
        self._insert(rows, "unres", unresolved)
        del db

    def _resolve(self, rows, session: AdminSession):
        """(host, tier, logon rows, activity keys) for a session, or an unresolved reason."""
        db = rows.db
        if session.service in NO_HOST_LOGON:
            return "no_host_logon"
        low = session.start - self.SKEW_SECONDS
        high = (session.end if session.end is not None else session.start) + self.SKEW_SECONDS
        columns = "rid, host, boot, ts, src, sport, kind, code, ltype, svc, outcome, session, account"
        # The client endpoint first: a busy client (a jump host, a NAT) logs many logons, but few name this port. A
        # protocol that authenticates when its connection opens (SSH, Telnet, the r-services) logs its logon then, so
        # its endpoint is read only around the opening: a long session's client port can be used again later for
        # another connection (Linux shares an ephemeral port across destinations), whose logon is not this one's.
        end_low = low
        end_high = session.start + self.SKEW_SECONDS if session.service in CONNECT_AUTH else high
        named = self._logon_rows(
            db, f"SELECT {columns} FROM logon WHERE src = ? AND sport = ? AND ts BETWEEN ? AND ? ORDER BY ts, rid "
                "LIMIT ?", (session.client, session.cport, end_low, end_high, self.LOGON_SCAN + 1))
        if len(named) > self.LOGON_SCAN:
            return "logon_scan_capped"
        endpoint = [row for row in named if consistent(session.service, session.sport, row)]
        if not endpoint and any(_untyped(session.service, row) for row in named):
            return "logon_type_missing"
        if endpoint:
            if len({row.host for row in endpoint}) > 1:
                return "ambiguous_endpoint"
            # the same client endpoint toward another server in the window: the logon may be that connection's
            reused = db.execute(
                "SELECT 1 FROM net WHERE client = ? AND cport = ? AND server != ? AND start <= ? "
                "AND coalesce(\"end\", start) >= ? LIMIT 1",
                (session.client, session.cport, session.server, end_high, end_low)).fetchone()
            if reused is not None:
                return "port_reused"
            return self._joined(rows, session, endpoint, "endpoint")
        candidates = self._logon_rows(db, f"SELECT {columns} FROM logon WHERE src = ? AND sport IS NULL "
                                          "AND ts BETWEEN ? AND ? ORDER BY ts, rid LIMIT ?",
                                      (session.client, low, high, self.LOGON_SCAN + 1))
        if len(candidates) > self.LOGON_SCAN:
            return "logon_scan_capped"
        portless = [row for row in candidates if consistent(session.service, session.sport, row)]
        if not portless:
            ported = self._logon_rows(db, f"SELECT {columns} FROM logon WHERE src = ? AND sport IS NOT NULL "
                                          "AND ts BETWEEN ? AND ? ORDER BY ts, rid LIMIT ?",
                                      (session.client, low, high, self.LOGON_SCAN))
            if any(consistent(session.service, session.sport, row) for row in ported):
                return "other_connections"
            if any(_untyped(session.service, row) for row in candidates):
                return "logon_type_missing"
            return "type_inconsistent" if candidates or ported else "no_logon"
        seen = {row[0] for row in db.execute(
            "SELECT DISTINCT host FROM hostconn WHERE ckey = ? AND ts BETWEEN ? AND ? LIMIT 3",
            (_ckey(session.client, session.cport, session.server, session.sport), low, high))}
        if len(seen) > 1:
            return "ambiguous_connection"
        if seen:
            on_host = [row for row in portless if row.host in seen]
            if on_host:
                return self._joined(rows, session, on_host, "host_connection")
            return "connection_host_no_logon"
        if len({row.host for row in portless}) > 1:
            return "ambiguous_address"
        if external(session.server):
            # the hosts whose telemetry the hunt reads are the site's; an outside server is not one of them unless
            # a port or the host's own connection record says so
            return "external_server"
        if self._net_refused:
            return "pairing_unknown"
        if self._host_refused:
            # a refused logon record may be another host's portless logon from this client: "only this host" is not
            # known
            return "logons_refused"
        if session.origin != "sweep":
            # a session a later stage's finding cites that the sweep never read: the client's other sessions in that
            # source were not all read, so a portless pairing cannot be checked
            return "pairing_unread"
        services = [name for name, cls in LOGON_CLASS.items() if cls == LOGON_CLASS.get(session.service)]
        others = db.execute(
            f"SELECT 1 FROM net WHERE client = ? AND server != ? AND service IN ({','.join('?' * len(services))}) "
            "AND start <= ? AND coalesce(\"end\", start) >= ? LIMIT 1",
            (session.client, session.server, *services, high, low)).fetchone()
        if others is not None:
            return "ambiguous_pairing"
        return self._joined(rows, session, portless, "address")

    def _joined(self, rows, session: AdminSession, candidates: list[LogonRow], tier: str):
        """The joined logon rows (successes first, nearest first, a bounded number) and the logon sessions whose
        activity to read, with the audit login record that carries a session an sshd line lacks."""
        candidates = sorted(candidates, key=lambda row: (row.outcome != "success", abs(row.ts - session.start),
                                                         row.rid))
        host = candidates[0].host
        chosen = candidates[:self.LOGONS_CITED]
        keys = []
        for row in list(chosen):
            if row.outcome != "success":
                continue
            if row.session is not None:
                key = [row.host, row.session, row.boot, row.ts]
                if key not in keys:
                    keys.append(key)
                continue
            if row.kind != "linux":
                continue
            companions = self._logon_rows(
                rows.db, "SELECT rid, host, boot, ts, src, sport, kind, code, ltype, svc, outcome, session, account "
                         "FROM logon WHERE host = ? AND src = ? AND ts BETWEEN ? AND ? AND session IS NOT NULL "
                         "AND svc = ? AND outcome = 'success' ORDER BY ts, rid LIMIT 8",
                (row.host, row.src, row.ts - self.COMPANION_BEFORE, row.ts + self.COMPANION_AFTER, row.svc))
            if len({(item.session, item.boot) for item in companions}) == 1:
                companion = companions[0]
                if all(item.rid != companion.rid for item in chosen):
                    chosen.append(companion)
                key = [companion.host, companion.session, companion.boot, companion.ts]
                if key not in keys:
                    keys.append(key)
            elif companions:
                rows.write("INSERT OR REPLACE INTO meta VALUES (?, ?)", [("companion_ambiguous", "1")])
        return host, tier, chosen, keys

    def summary_notes(self, rows) -> list[str]:
        """What the rule's window cell says about the join, from its tables (so every pass states the whole)."""
        db = rows.db
        meta = dict(db.execute("SELECT k, v FROM meta").fetchall())
        notes = [NOTE_PREFIX + "joins the administration sessions cited by the findings of the sweep, the packet stage "
                               "and the baseline stage; findings of expansion reaches and of the AI agent are not "
                               "joined"]
        tiers = db.execute("SELECT tier, count(DISTINCT identity) FROM res GROUP BY tier "
                           "ORDER BY tier").fetchall()
        if tiers:
            notes.append(NOTE_PREFIX + "administration sessions joined to a host logon: "
                         + ", ".join(f"{count} by {tier}" for tier, count in tiers))
        unresolved = db.execute("SELECT reason, count(DISTINCT identity) FROM unres GROUP BY reason "
                                "ORDER BY reason").fetchall()
        if unresolved:
            notes.append(NOTE_PREFIX + "administration sessions cited by findings left unresolved (never a negative): "
                         + "; ".join(f"{count}: {UNRESOLVED_WORDS[reason]}" for reason, count in unresolved))
        reasons = {reason for reason, _count in unresolved}
        if "external_server" in reasons and not netdef.current().configured:
            notes.append(NOTE_PREFIX + f"{netdef.DIRECTION_ASSUMED_REASON} (address-only joins to servers read as "
                                       "outside the site were refused)")
        if meta.get("companion_ambiguous"):
            notes.append(NOTE_PREFIX + "an sshd authentication line had several audit login sessions from its client "
                                       "within two minutes; its logon session's activity was not joined")
        if "logon_scan_capped" in reasons:
            notes.append(NOTE_PREFIX + f"state limit: a client logged more than {self.LOGON_SCAN} logons within one "
                                       "session's window; those sessions were not joined")
        if int(meta.get("net_refused") or 0):
            notes.append(NOTE_PREFIX + "state limit: administration session records the state budget refused are not "
                                       "joined and make portless pairings undecidable")
        if int(meta.get("host_refused") or 0):
            notes.append(NOTE_PREFIX + f"state limit: {meta['host_refused']} host logon or connection record(s) the "
                                       "state budget refused were not kept: no address-only join was made, and a "
                                       "joined host's uniqueness is stated as unchecked")
        return notes

    def partial_notes(self, notes: list[str]) -> bool:
        """Whether the notes name a cap or refusal (the window cell is then partial)."""
        return any("state limit:" in note for note in notes)

    # ------------------------------------------------------------------------------------------------ publishing
    def _matches(self, rows, later: bool):
        """One item per (destination host, client address, service), yielded when its content changed since it was
        last published; group keys are read a page at a time."""
        db = rows.db
        after = ""
        while True:
            gkeys = [row[0] for row in db.execute("SELECT DISTINCT gkey FROM res WHERE gkey > ? ORDER BY gkey "
                                                  "LIMIT 500", (after,)).fetchall()]
            if not gkeys:
                return
            after = gkeys[-1]
            for gkey in gkeys:
                group = db.execute("SELECT gkey, host, client, service, eid, tier, rids, offset, keys, identity FROM "
                                   "res WHERE gkey = ? ORDER BY eid", (gkey,)).fetchall()
                match = self._match(db, group)
                digest = hashlib.sha256(json.dumps([match.claim, match.proposed_lane, match.severity,
                                                    sorted(event.id for event in match.events)]).encode()).hexdigest()
                known = db.execute("SELECT digest FROM pub WHERE gkey = ?", (gkey,)).fetchone()
                if known is not None and known[0] == digest:
                    continue
                if later or known is not None:
                    match.revision_reason = self.LATER_REVISION
                yield match
                rows.write("INSERT OR REPLACE INTO pub VALUES (?, ?)", [(gkey, digest)])

    def _logon_events(self, db, rids: list[int]) -> dict[int, TypedEvent]:
        out = {}
        for start in range(0, len(rids), 500):
            batch = rids[start:start + 500]
            for rid, blob in db.execute(f"SELECT rid, blob FROM logon WHERE rid IN ({','.join('?' * len(batch))})",
                                        tuple(batch)):
                out[rid] = _compact(blob)
        return out

    def _match(self, db, group) -> Match:
        _gkey, host, client, service = group[0][:4]
        tiers = Counter(row[5] for row in group)
        tier = min(tiers, key=lambda name: list(TIER_WORDS).index(name))
        session_ids = list(dict.fromkeys(row[4] for row in group))
        connections = len({row[9] for row in group})
        rids = list(dict.fromkeys(rid for row in group for rid in json.loads(row[6])))
        # each logon session with whether a port or the host's own connection record tied it to a session (an
        # address-only join never raises the lane)
        keys: dict[tuple, bool] = {}
        for row in group:
            for key in json.loads(row[8]):
                keys[tuple(key)] = keys.get(tuple(key), False) or row[5] != "address"
        offsets = [row[7] for row in group]
        logons = self._logon_events(db, rids)
        logon_events = [logons[rid] for rid in rids[: self.LOGONS_CITED * 2] if rid in logons]
        network_events = self._load_events(session_ids[: self.SESSIONS_CITED]) if self._load_events else []
        network_events = sorted(network_events, key=lambda event: (event.ts, event.id))
        named = session_ids[:900]
        findings = db.execute(
            f"SELECT DISTINCT rule, lane, cid FROM lead WHERE eid IN ({','.join('?' * len(named))}) "
            "ORDER BY rule, cid", tuple(named)).fetchall()
        activity_events, counts, flags, seen, raising = [], [], [], set(), False
        for (key_host, session, boot, when), tied in keys.items():
            entry = self._entry_at(db, key_host, session, boot, when)
            if entry is None or (key_host, session, entry[0]) in seen:
                continue
            seen.add((key_host, session, entry[0]))
            count = db.execute("SELECT count FROM act WHERE host = ? AND session = ? AND entry = ?",
                               (key_host, session, entry[0])).fetchone()
            if count is not None:
                counts.append(((key_host, session), count[0]))
                activity_events += [_compact(blob) for (blob,) in db.execute(
                    "SELECT blob FROM act_ex WHERE host = ? AND session = ? AND entry = ? ORDER BY ts, eid",
                    (key_host, session, entry[0]))]
            for cid, rule, flag_lane, eid, flag_boot, flag_ts in db.execute(
                    "SELECT DISTINCT cid, rule, lane, eid, boot, ts FROM flag WHERE host = ? AND session = ? "
                    "ORDER BY lane DESC, rule, cid, eid", (key_host, session)).fetchall():
                if not _boots_conflict(entry[2], flag_boot) and flag_ts >= entry[1] - 1.0:
                    flags.append((cid, rule, flag_lane, eid))
                    raising = raising or tied
        flag_ids = {flag[3] for flag in flags}
        flagged_events = [event for event in (self._load_events(sorted(flag_ids)[:self.ACTIVITY_KEPT])
                                              if flag_ids and self._load_events else [])
                          if event.id not in {item.id for item in activity_events}]
        lane = "high" if raising else "lead"
        successes = [event for event in logon_events if event.outcome == Outcome.success]
        severity = "high" if successes else "medium"
        claim = self._claim(host, client, service, tier, connections, len(session_ids), findings, logon_events,
                            offsets, counts, activity_events, flags, network_events, raising)
        if self._host_refused:
            claim += (" Some host logon or connection records were refused by the state budget, so this host being "
                      "the only one naming the client endpoint or connection is unchecked.")
        events = list({event.id: event for event in
                       [*network_events, *logon_events, *activity_events, *flagged_events]}.values())
        predicate = self._predicate(network_events, logon_events, tier)
        notes = [(f"Join key: {TIER_WORDS[tier]}; clock allowance +-{self.SKEW_SECONDS:.0f} s around the session's "
                  "recorded lifetime."),
                 ("The link between the network session and the host's logon is inferred, not observed: NAT, a "
                  "shared client address or a host clock beyond the allowance can make it wrong.")]
        if self._host_refused:
            notes.append("The state budget refused some host logon or connection records: another host's record "
                         "naming the same client endpoint or connection may be among them, so this host being the only "
                         "one is unchecked.")
        if tier == "address":
            notes.append("Address-only join: no port ties the logon to this connection, so it rests on this host "
                         "being the only one with a fitting logon from the client in the window.")
        if self._read_before(db, host, rids):
            notes.append("Some process or share records of this host were read from a source target read before the "
                         "joined logon's, while no remote logon naming their session had been read; any that belong "
                         "to the joined session are not counted here.")
        attack = tuple(sorted({"T1021", *(SERVICE_ATTACK.get(service, "T1021"),),
                               *(("T1078",) if successes else ())}))
        entities = list(dict.fromkeys(entity for event in [*logon_events, *network_events[:1]]
                                      for entity in event.entities()))
        return Match(self.id, claim, self.claim_type, events, predicate,
                     min((event.ts for event in logon_events), default=None), severity, lane,
                     TIER_CONFIDENCE[tier], entities, notes, group_key=f"{self.id}|{host}|{client}|{service}",
                     context_ids={event.id for event in network_events}, attack=attack)

    def _read_before(self, db, host: str, rids: list[int]) -> bool:
        """Whether session-bearing process records of this host that joined no remote logon came from a source target
        read before a joined logon's target: those of the joined session arrived before the logon naming it. Records
        of the logon's own target (read in time order) or a later one were judged with the logon known."""
        earliest = db.execute("SELECT seq FROM unjoined WHERE host = ?", (host,)).fetchone()
        if earliest is None or not rids:
            return False
        batch = rids[:900]
        latest = db.execute(f"SELECT max(tseq) FROM logon WHERE rid IN ({','.join('?' * len(batch))})",
                            tuple(batch)).fetchone()[0]
        return latest is not None and earliest[0] < latest

    def _entry_at(self, db, host: str, session: str, boot: str, when: float):
        """The remote logon entry a joined logon record of this session belongs to."""
        fitting = [entry for entry in db.execute("SELECT entry, min_ts, boot FROM remote_rows WHERE host = ? AND "
                                                 "session = ?", (host, session)).fetchall()
                   if not _boots_conflict(entry[2], boot) and entry[1] <= when + 1.0]
        return max(fitting, key=lambda entry: entry[1]) if fitting else None

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
               activity, flags, network_events, raising=True) -> str:
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
            parts.append(f" A typed host finding cites a record in that session: {', '.join(named[:4])}"
                         + ("." if raising else "; the item stays a lead, since only an address-only join reaches "
                                              "that session and an address-only join never raises the lane."))
        return "".join(parts)


def _boots_conflict(left: str, right: str) -> bool:
    """Two records' boots differ only when both name one (an unknown boot conflicts with none)."""
    return bool(left) and bool(right) and left != right


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
