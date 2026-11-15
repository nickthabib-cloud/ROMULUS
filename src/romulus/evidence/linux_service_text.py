"""Bounded, per-line parsers for documented Linux service log statements.

These parsers never join records or treat embedded message text as another event.
The caller supplies record timestamps, host identity and field provenance.
"""
from __future__ import annotations

import ipaddress
import re
import shlex

from romulus.evidence.linux_auth_text import _exim_tokens, parse_auth
from romulus.evidence.linux_text_types import ParsedLine
from romulus.evidence.typed import Outcome

MAX_LINE = 65536
LIST_LIMIT = 32
SCHEDULER_CAVEAT = "Scheduler log observation; not a kernel audit exec record"
VPN_IDENTITY_CAVEAT = "OpenVPN identity is the logged common name; it need not be an authenticated username"
_EXIM_ID = r"[A-Za-z0-9]{6,}-[A-Za-z0-9]{6,}-[A-Za-z0-9]{2,}"
_EXIM_TIME = re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?(?: [+-]\d{4})? (?:\[\d+\] )?(.*)$")
_SQUID = re.compile(
    r"^(\d{9,19}(?:\.\d{1,9})?)\s+(\d{1,19})\s+(\S+)\s+([A-Z_]+)/([0-9]{3})\s+(\d{1,19})\s+"
    r"([A-Z]+)\s+(\S+)\s+(\S+)\s+([A-Z_]+)/([^\s]+)\s+(\S+)$"
)


def _ip(value: str) -> str | None:
    try:
        return str(ipaddress.ip_address(value.strip("[]")))
    except ValueError:
        return None


def _port(value: str) -> int | None:
    return int(value) if value.isascii() and value.isdigit() and len(value) <= 5 and int(value) <= 65535 else None


def _endpoint(value: str) -> tuple[str, int | None] | None:
    value = re.sub(r"^\[AF_INET6?\]", "", value)
    host, sep, port = value.rpartition(":")
    address = _ip(host) if sep else None
    number = _port(port)
    if address and number is not None:
        return address, number
    address = _ip(value)
    return (address, None) if address else None


def _peer(fields: dict, host: str, address: str | None, port: str | None, side: str) -> None:
    if host and host not in ("unknown", "none", "-"):
        fields[f"{side}.host"] = host
    if address and (parsed := _ip(address)):
        fields[f"{side}.ip"] = parsed
    if port and (number := _port(port)) is not None:
        fields[f"{side}.port"] = number


def _recipients(fields: dict, values) -> tuple[str, ...]:
    count = 0
    kept = []
    for value in values:
        if not value:
            continue
        count += 1
        if len(kept) < LIST_LIMIT:
            kept.append(value.strip("<>"))
    fields["mail.to"] = kept
    fields["mail.to_count"] = count
    return (f"Mail recipients limited to {LIST_LIMIT} of {count} logged recipients",) if count > LIST_LIMIT else ()


def _exim(message: str) -> ParsedLine | None:
    # Exim specification, Log files: reception, delivery, rejection and log selectors.
    if timestamp := _EXIM_TIME.fullmatch(message):
        message = timestamp[1]
    marker = re.match(rf"^({_EXIM_ID}) (<=|=>|->|\*\*|==) (\S+)(?: (.*))?$", message)
    if not marker:
        return _exim_reject(message)
    queue, direction, address, rest = marker.groups()
    # These are Exim discard deliveries, not recipient addresses or actual deliveries.
    if address in ("discarded", ":blackhole:"):
        return None
    fields: dict[str, object] = {
        "mail.service": "exim", "mail.message_id": queue,
        "mail.direction": {"<=": "received", "=>": "delivered", "->": "delivered",
                           "**": "bounced", "==": "deferred"}[direction],
    }
    caveats: tuple[str, ...] = ()
    if direction == "<=":
        fields["mail.from"] = address.strip("<>")
    else:
        caveats = _recipients(fields, (address,))
    tokens = _exim_tokens(rest or "")
    if tokens is None:
        return None
    token_iter = iter(tokens)
    authentication = parse_auth("exim", message) if direction == "<=" else None
    if authentication and authentication.outcome == Outcome.success and authentication.fields.get("user.name"):
        fields["mail.authenticated_user"] = authentication.fields["user.name"]
    peer_host = ""
    peer_address = peer_port = None
    peer_logged = False
    try:
        for token in token_iter:
            if token == "for" and direction == "<=":
                caveats = _recipients(fields, token_iter)
                break
            key, equals, value = token.partition("=")
            if equals and key == "H":
                peer_logged = True
                peer_host = value if not value.startswith(("(", "[")) else ""
                if value.startswith("["):
                    match = re.fullmatch(r"\[([^\]]+)\](?::(\d+))?", value)
                    if match:
                        peer_address, peer_port = match.groups()
            elif not equals and peer_logged and token.startswith("["):
                match = re.fullmatch(r"\[([^\]]+)\](?::(\d+))?", token)
                if match:
                    peer_address, peer_port = match.groups()
            elif equals and key == "S" and value.isascii() and value.isdigit() and len(value) < 20:
                fields["mail.size"] = int(value)
            elif equals and key == "X" and value:
                fields["mail.tls"] = True
            elif equals and key == "T" and direction == "<=":
                fields["mail.subject"] = shlex.split(value)[0] if value else ""
    except ValueError:
        return None
    _peer(fields, peer_host, peer_address, peer_port, "source" if direction == "<=" else "destination")
    return ParsedLine("mail_message", fields,
                      Outcome.failure if direction in ("**", "==") else Outcome.success, caveats)


def _exim_reject(message: str) -> ParsedLine | None:
    # A reject can precede queue-id assignment; retain that absence.
    match = re.fullmatch(
        rf"(?:(?P<queue>{_EXIM_ID}) )?H=(?P<host>\S+)(?: \([^)]*\))? "
        r"\[(?P<ip>[^\]]+)\](?::(?P<port>\d+))?(?: [A-Z]=\S+)* "
        r"F=<(?P<sender>[^>]*)>(?: [A-Z]=\S+)* rejected (?:RCPT <(?P<to>[^>]+)>|MAIL|DATA)(?::.*)?",
        message,
    )
    if match:
        fields: dict[str, object] = {"mail.service": "exim", "mail.direction": "rejected", "mail.from": match["sender"]}
        if match["queue"]:
            fields["mail.message_id"] = match["queue"]
        if match["to"]:
            _recipients(fields, (match["to"],))
        _peer(fields, match["host"], match["ip"], match["port"], "source")
        return ParsedLine("mail_message", fields, Outcome.failure)
    match = re.match(rf"^({_EXIM_ID}) rejected from \[([^\]]+)\](?: .*)?$", message)
    if match and _ip(match[2]):
        return ParsedLine("mail_message", {"mail.service": "exim", "mail.message_id": match[1],
                                           "mail.direction": "rejected", "source.ip": _ip(match[2])}, Outcome.failure)
    return None


def _postfix(program: str, message: str) -> ParsedLine | None:
    match = re.match(r"^([A-Za-z0-9]+): (.*)$", message)
    if not match:
        return None
    queue, body = match.groups()
    fields: dict[str, object] = {"mail.service": "postfix"}
    if queue != "NOQUEUE":
        fields["mail.message_id"] = queue
    else:
        return None
    component = program.rsplit("/", 1)[-1]
    if component == "qmgr":
        part = re.fullmatch(r"from=<([^>]*)>, size=(\d{1,19}), nrcpt=(\d{1,19}) \(queue active\)", body)
        if not part:
            return None
        fields.update({"mail.direction": "received", "mail.from": part[1],
                       "mail.size": int(part[2]), "mail.to_count": int(part[3])})
    elif component in ("smtp", "lmtp", "local", "virtual"):
        # Postfix's status follows its DSN; the final reason is untrusted reply text.
        # Split once so a fake DSN/status inside that reason cannot replace either field.
        delivery, _, response = body.partition(", status=")
        part = re.fullmatch(r"to=<([^>]*)>, (.*), dsn=\S+", delivery)
        status = re.fullmatch(r"(sent|deferred|bounced)(?: \(.*\))?", response)
        if not part or not status:
            return None
        _recipients(fields, (part[1],))
        fields["mail.direction"] = {"sent": "delivered", "deferred": "deferred", "bounced": "bounced"}[status[1]]
        relay = re.search(r"(?:^|, )relay=([^,\s]+)", part[2])
        if relay:
            peer = re.fullmatch(r"([^\[]+)\[([^\]]+)\](?::(\d+))?", relay[1])
            if peer:
                _peer(fields, *peer.groups(), "destination")
            elif relay[1] != "none":
                fields["destination.host"] = relay[1]
    elif component == "smtpd":
        part = re.fullmatch(r"client=([^\[]+)\[([^\]]+)\](?:, sasl_method=([^,\s]+), sasl_username=(\S+))?", body)
        if not part:
            return None
        _peer(fields, part[1], part[2], None, "source")
        if part[4]:
            fields["mail.authenticated_user"] = part[4].strip("<>")
    elif component == "cleanup":
        part = re.fullmatch(r"message-id=<([^>]*)>", body)
        if not part:
            return None
        fields["mail.header_message_id"] = part[1]
    else:
        return None
    outcome = (Outcome.failure if fields.get("mail.direction") in ("bounced", "deferred")
               else Outcome.success if "mail.direction" in fields else Outcome.unknown)
    return ParsedLine("mail_message", fields, outcome)


# dnsmasq's query log (src/cache.c, log_query): "<source> <name> <verb> <dest>" with the verbs "from" (a client's
# query[TYPE], or auth[TYPE] for a question to its authoritative server), "to" (forwarded upstream, "#port" when the
# port is not 53) and "is" (a reply, a cache, config, DHCP, auth or hosts-file answer). An answer to a reverse lookup
# (F_REVERSE) swaps the roles: the looked-up address stands where the name does and the host name where the address
# does. A reply code without a mnemonic is written as its number. --log-queries=extra prefixes every line with a serial
# that ties the lines of one query together and the requestor's "address/port"; =proto adds "TCP " or "UDP " before
# the serial. Lines are typed one at a time: the serial is recorded, never joined.
_DNSMASQ_EXTRA = re.compile(r"^(?:(TCP|UDP) )?(\d{1,10}) (?:([^\s/]+)/(\d{1,5}) )?(.*)$")
_DNSMASQ_SUFFIX = r"(?: \((?:EDE: [^()\r\n]*|DNSSEC signed)\))?"
_DNSMASQ_RCODES = {"NXDOMAIN": "NXDOMAIN", "NODATA": "NOERROR", "NODATA-IPv4": "NOERROR", "NODATA-IPv6": "NOERROR",
                   "SERVFAIL": "SERVFAIL", "REFUSED": "REFUSED", "FORMERR": "FORMERR", "not implemented": "NOTIMP"}
_RCODE_NUMBERS = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED", 6: "YXDOMAIN",
                  7: "YXRRSET", 8: "NXRRSET", 9: "NOTAUTH", 10: "NOTZONE"}
_HOSTNAME = re.compile(r"(?=.{1,253}$)[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,62})(?:\.[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,62}))*\.?")
DNSMASQ_ANSWER_CAVEAT = "DNS answer line omits the question type and is not joined to its query line"
DNSMASQ_FORWARD_CAVEAT = ("DNS forwarding line: dnsmasq's own upstream query, without the question type; its client is "
                          "the dnsmasq host, whose address the line does not name, and the requesting client is the "
                          "query line's")
DNSMASQ_REVERSE_CAVEAT = ("Reverse-lookup answer line: dnsmasq writes the looked-up address in place of the name, so "
                          "the question name is read as that address's reverse-lookup name (a forward question for an "
                          "address literal would be written the same way)")
# A question a DNS server logged itself: the server that received it is the host that wrote the log, which names no
# address of its own. Rules that need the server read the record's host then.
SERVER_LOGGED = "dns.server_logged"


def _dnsmasq_type(value: str) -> str:
    """dnsmasq writes types it has no name for as "type=N"; the DNS rules read those as "TYPEN"."""
    return f"TYPE{value[5:]}" if value.startswith("type=") else value


def _dnsmasq(message: str) -> ParsedLine | None:
    extra = _DNSMASQ_EXTRA.fullmatch(message)
    requester: tuple[str, int] | None = None
    context: dict[str, object] = {}
    if extra:
        message = extra[5]
        context["dnsmasq.serial"] = int(extra[2])
        if extra[1]:
            context["network.transport"] = extra[1].lower()
        if extra[3] is not None:
            address, port = _ip(extra[3]), _port(extra[4])
            if address is None or port is None:
                return None
            requester = (address, port)
    question = re.fullmatch(r"(query|auth)\[([A-Za-z0-9_-]+|type=\d{1,5})\] (\S+) from (\S+)", message)
    if question:
        if not (address := _ip(question[4])):
            return None
        fields: dict[str, object] = {**context, "dns.type": "query", "dns.question.name": question[3],
                                    "dns.question.type": _dnsmasq_type(question[2]), "source.ip": address,
                                    SERVER_LOGGED: True}
        if question[1] == "auth":
            fields["dnsmasq.authoritative"] = True
        if requester and requester[0] == address:
            fields["source.port"] = requester[1]
        return ParsedLine("dns_query", fields)
    forward = re.fullmatch(r"forwarded (\S+) to ([^\s#]+)(?:#(\d{1,5}))?" + _DNSMASQ_SUFFIX, message)
    if forward and (address := _ip(forward[2])):
        fields = {**context, "dns.type": "query", "dns.question.name": forward[1], "destination.ip": address}
        if forward[3] is not None and (port := _port(forward[3])) is not None:
            fields["destination.port"] = port
        if requester:
            # the requester asked dnsmasq, not the upstream server: it is not this question's client
            fields.update({"dnsmasq.requester.ip": requester[0], "dnsmasq.requester.port": requester[1]})
        return ParsedLine("dns_query", fields, caveats=(DNSMASQ_FORWARD_CAVEAT,))
    answer = re.fullmatch(r"(reply|cached(?:-stale)?|config|auth|DHCP|/\S+) (\S+) is "
                          r"(not implemented|\S+)" + _DNSMASQ_SUFFIX, message)
    if not answer:
        return None
    name, dest = answer[2], answer[3]
    caveats = [DNSMASQ_ANSWER_CAVEAT]
    looked_up = _ip(name)
    if looked_up is not None:
        # F_REVERSE: the name position holds the looked-up address
        name = ipaddress.ip_address(looked_up).reverse_pointer
        caveats.append(DNSMASQ_REVERSE_CAVEAT)
    fields = {**context, "dns.type": "answer", "dns.question.name": name}
    if requester:
        # the answer was sent to the requester: the client of this reply
        fields.update({"client.ip": requester[0], "client.port": requester[1]})
    address = _ip(dest)
    if address and looked_up is None:
        kind = "AAAA" if ":" in address else "A"
        fields["dns.answers"] = [{"name": name, "type": kind, "ttl": None, "data": address}]
    elif dest in _DNSMASQ_RCODES:
        fields["dns.response_code"] = _DNSMASQ_RCODES[dest]
    elif dest.isascii() and dest.isdigit() and len(dest) <= 5:
        fields["dns.response_code"] = _RCODE_NUMBERS.get(int(dest), f"RCODE{int(dest)}")
    elif looked_up is not None and address is None and _HOSTNAME.fullmatch(dest):
        fields["dns.answers"] = [{"name": name, "type": "PTR", "ttl": None, "data": dest.rstrip(".")}]
    elif not re.fullmatch(r"<(?:[A-Za-z0-9-]+|type=\d{1,5})>", dest):
        return None
    return ParsedLine("dns_query", fields, caveats=tuple(caveats))


# dnsmasq's DHCP log (src/rfc2131.c, log_packet; written by the "dnsmasq-dhcp" tag in src/log.c):
# "<TYPE>(<interface>) [<address> ]<mac or client id>[ <host name>]", with log-dhcp prefixing the transaction id.
_DHCP = re.compile(r"(?:(\d{1,10}) )?(DHCP[A-Z]+|BOOTP|PXE|NOANSWER)\(([^()\s]{1,64})\)(?: (.*))?")
_MAC = re.compile(r"[0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5}")
DHCP_ACK_CAVEAT = ("dnsmasq DHCPACK line: the server acknowledged this address for the client hardware address; an "
                   "acknowledgement of a DHCPINFORM names the client's own address, and lines are not joined to tell "
                   "the two apart")


def _dnsmasq_dhcp(message: str) -> ParsedLine | None:
    match = _DHCP.fullmatch(message)
    if not match or match[2] != "DHCPACK" or not match[4]:
        return None
    parts = match[4].split(" ")
    if len(parts) < 2 or not (address := _ip(parts[0])) or ":" in address or not _MAC.fullmatch(parts[1]):
        return None
    fields: dict[str, object] = {"dhcp.message_type": "DHCPACK", "dhcp.interface": match[3],
                                 "dhcp.client_address": address, "dhcp.client_mac": parts[1].lower().replace("-", ":")}
    if match[1] is not None:
        fields["dhcp.transaction_id"] = int(match[1])
    if len(parts) == 3 and _HOSTNAME.fullmatch(parts[2]):
        fields["dhcp.hostname"] = parts[2].rstrip(".")
    elif len(parts) > 2:
        return None
    return ParsedLine("address_assignment", fields, Outcome.success, (DHCP_ACK_CAVEAT,))


# dnsmasq lines that are not query, reply or lease events. They are counted as skips with these reasons.
_DNSMASQ_OTHER = (
    (re.compile(r"(?:started, version|compile time options:|using nameserver|using local addresses only|"
                r"using only locally-known addresses|reading |read |cleared cache|exiting on receipt|"
                r"failed to |no servers found|setting upstream servers|DNS service limited|"
                r"ignoring nameserver|warning: |LOUD WARNING|directory |inotify|cannot |"
                r"DHCP, |DHCPv6, |router advertisement|IPv6 router|TFTP root|"
                r"chown of PID file|dnsmasq (?:started|exiting)|"
                r"default DNSSEC|DNSSEC (?:validation|signature)|"
                r"(?:\d{1,10} )?(?:available DHCP|vendor class|user class|client provides|requested options|"
                r"tags:|next server|sent size|broadcast response|bootfile name|server name|"
                r"DHCP packet received|no address range|DHCP range|static leases|abandoning lease|"
                r"not giving name|disabling DHCP|Ignoring domain))"),
     "dnsmasq lifecycle, configuration or DHCP option detail line"),
    (re.compile(r"(?:time \d|cache size \d|queries forwarded \d|queries for authoritative|server [^\s]+: queries|"
                r"pool memory|failed to allocate|Maximum number of concurrent DNS queries|DNSSEC memory|"
                r"(?:\d{1,10} )?cache entries)"),
     "dnsmasq statistics or resource line"),
    (re.compile(r"(?:(?:TCP |UDP )?\d{1,10} (?:[^\s/]+/\d{1,5} )?)?(?:validation |dnssec-query\[|"
                r"(?:reply|cached|cached-stale) \S+ is (?:DS|DNSKEY) |ipset add |nftset add |non-query opcode)"),
     "dnsmasq DNSSEC, ipset or opcode line"),
    (re.compile(r"(?:possible DNS-rebind attack detected|nameserver \S+ refused to do a recursive query)"),
     "dnsmasq resolver notice (no client address is logged)"),
    (re.compile(r"(?:\d{1,10} )?(?:DHCP[A-Z]+|BOOTP|PXE|NOANSWER|RTR-[A-Z]+|SLAAC)[-(]"),
     "dnsmasq DHCP packet line other than an IPv4 DHCPACK with a hardware address"),
)


def service_skip_reason(program: str, message: str) -> str | None:
    """A precise reason for a recognized line of a supported program that is not a typed event, or None."""
    if not isinstance(message, str) or not isinstance(program, str):
        return None
    program = program.lower()
    if program in ("dnsmasq", "dnsmasq-dhcp"):
        for pattern, reason in _DNSMASQ_OTHER:
            if pattern.match(message):
                return reason
        return None
    if program == "openvpn" or program.startswith("openvpn-"):
        return openvpn_skip_reason(message)
    return None


# Suricata's fast.log (src/alert-fastlog.c, AlertFastLogger), one alert per line:
# "<time>  [Drop] [**] [gid:sid:rev] <msg> [**] [Classification: <class>] [Priority: <n>] {<proto>} <src>:<sp> -> <dst>:<dp>"
# The time is CreateTimeString's "MM/DD/YYYY-HH:MM:SS.uuuuuu" (sensor local time, no zone). "[Drop] " marks a packet
# dropped in IPS mode, "[wDrop] " one a drop rule matched outside IPS mode. A protocol without a name prints as
# "PROTO:nnn". ICMP and ICMPv6 alerts print the ICMP type and code in the port slots. IPv6 addresses print without
# brackets, so the port is after the last colon. The message is printed raw, so the last "[**] [Classification:" is
# the trailer. A decoder-event alert (no IP header) prints raw packet bytes instead of addresses and is not typed.
_FAST = re.compile(
    r"(?P<time>\d{2}/\d{2}/\d{4}-\d{2}:\d{2}:\d{2}\.\d{1,9})  (?:\[(?P<action>Drop|wDrop)\] )?"
    r"\[\*\*\] \[(?P<gid>\d{1,10}):(?P<sid>\d{1,10}):(?P<rev>\d{1,10})\] (?P<msg>.*) \[\*\*\] "
    r"\[Classification: (?P<cls>[^\]\r\n]*)\] \[Priority: (?P<prio>\d{1,10})\] "
    r"\{(?P<proto>[A-Za-z0-9-]{1,32}|PROTO:\d{3})\} (?P<src>[0-9A-Fa-f.:]+):(?P<sp>\d{1,5}) -> "
    r"(?P<dst>[0-9A-Fa-f.:]+):(?P<dp>\d{1,5})")
FAST_TIME = re.compile(r"\d{2}/\d{2}/\d{4}-\d{2}:\d{2}:\d{2}\.\d{1,9}")
FASTLOG_CAVEAT = ("Suricata fast.log alert line: no flow id, application protocol or signature metadata (ATT&CK ids, "
                  "signature severity) is logged; the sensor's local time is diagnostic only")


def _fastlog(line: str) -> ParsedLine | None:
    match = _FAST.fullmatch(line)
    if not match or not match["msg"]:
        return None
    source, destination = _ip(match["src"]), _ip(match["dst"])
    sport, dport = _port(match["sp"]), _port(match["dp"])
    if source is None or destination is None or sport is None or dport is None:
        return None
    fields: dict[str, object] = {
        "alert.signature": match["msg"], "alert.signature_id": int(match["sid"]), "alert.gid": int(match["gid"]),
        "alert.rev": int(match["rev"]), "alert.severity": int(match["prio"]),
        # a fast.log line without "[Drop]" was not dropped by the engine
        "alert.action": "blocked" if match["action"] == "Drop" else "allowed",
        "source.ip": source, "destination.ip": destination,
    }
    if match["cls"] not in ("", "(null)"):
        fields["alert.category"] = match["cls"]
    proto = match["proto"]
    if proto.startswith("PROTO:"):
        fields["network.iana_number"] = str(int(proto[6:]))
    else:
        fields["network.transport"] = proto.lower()
    if proto.upper() in ("ICMP", "IPV6-ICMP", "ICMPV6"):
        fields["icmp.type"], fields["icmp.code"] = sport, dport
    else:
        fields["source.port"], fields["destination.port"] = sport, dport
    return ParsedLine("net_alert", fields, Outcome.unknown, (FASTLOG_CAVEAT,))


def _bind(message: str) -> ParsedLine | None:
    match = re.fullmatch(
        r"client (?:@0x[0-9a-fA-F]+ )?([^\s#]+)#(\d+) \(([^)]+)\): "
        r"query: (\S+) (IN|CH|HS) ([A-Z0-9]+) ([+\-][A-Za-z0-9()+\-]*) \(([^)]+)\)(?: \[.*\])?", message)
    if not match or not (address := _ip(match[1])) or _port(match[2]) is None:
        return None
    fields: dict[str, object] = {"dns.type": "query", "source.ip": address, "source.port": int(match[2]),
                                "dns.question.name": match[4], "dns.question.type": match[6], SERVER_LOGGED: True}
    if _ip(match[8]):
        fields["destination.ip"] = _ip(match[8])
    return ParsedLine("dns_query", fields)


def _unbound(message: str) -> ParsedLine | None:
    match = re.fullmatch(r"(?:\[\d+:\d+\] )?info: (?:query )?(\S+) (\S+) ([A-Z0-9]+) (IN|CH|HS)", message)
    if not match or not (address := _ip(match[1])):
        return None
    return ParsedLine("dns_query", {"dns.type": "query", "source.ip": address, SERVER_LOGGED: True,
                                    "dns.question.name": match[2], "dns.question.type": match[3]})


def _openvpn(message: str) -> ParsedLine | None:
    fields: dict[str, object] = {"vpn.service": "openvpn"}
    # multi.c's client context prefixes every lifecycle message, including socket.c's connect line.
    prefix = re.fullmatch(r"(?:([^\s/]+)/)?(\S+) ((?:\[[^\]]+\] )?Peer Connection Initiated with \S+|"
                          r"MULTI_sva:.*|MULTI: Learn:.*|SIG(?:TERM|USR1|INT)\[.*|TLS: Initial packet from .*|"
                          r"(?:\[[^\]]+\] )?Inactivity timeout .*)", message)
    if prefix and (endpoint := _endpoint(prefix[2])):
        if prefix[1]:
            fields["user.name"] = prefix[1]
        fields["source.ip"] = endpoint[0]
        if endpoint[1] is not None:
            fields["source.port"] = endpoint[1]
        message = prefix[3]
    assignment = re.fullmatch(r"MULTI_sva: pool returned IPv4=([^,]+), IPv6=(.+)", message)
    learn = re.fullmatch(r"MULTI: Learn: (\S+) -> ([^\s/]+)/(\S+)", message)
    # sig.c print_signal: a server closes the client instance on SIGTERM ("exiting") and on a soft SIGUSR1 restart
    # ("restarting", after a ping timeout or connection reset); the bracket holds the signal's source and reason
    closed = re.fullmatch(r"SIG(?:TERM|USR1|INT)\[([^\]]+)\] received, client-instance (?:exiting|restarting)",
                          message)
    initial = re.fullmatch(r"TLS: Initial packet from (\S+?), sid=\S+(?: \S+)?", message)
    timeout = re.fullmatch(r"(?:\[[^\]]+\] )?Inactivity timeout \((--[a-z-]+)\), (?:restarting|exiting)", message)
    if assignment:
        fields["vpn.action"] = "assign"
        for value, key in ((assignment[1], "vpn.assigned_ip"), (assignment[2], "vpn.assigned_ipv6")):
            if address := _ip(value):
                fields[key] = address
    elif learn and (address := _ip(learn[1])) and (endpoint := _endpoint(learn[3])):
        fields.update({"vpn.action": "assign", "vpn.assigned_ip": address,
                       "user.name": learn[2], "source.ip": endpoint[0]})
        if endpoint[1] is not None:
            fields["source.port"] = endpoint[1]
    elif closed:
        fields["vpn.action"] = "disconnect"
        fields["vpn.reason"] = closed[1]
    elif initial and (endpoint := _endpoint(initial[1])):
        # the first packet of a TLS handshake from a peer: an attempt, before any certificate or password check
        fields.update({"vpn.action": "attempt", "source.ip": endpoint[0]})
        fields.pop("source.port", None)
        if endpoint[1] is not None:
            fields["source.port"] = endpoint[1]
    elif timeout:
        # the signal line that follows closes the instance; this line only gives the reason, so it is not a boundary
        fields.update({"vpn.action": "timeout", "vpn.reason": timeout[1]})
    else:
        connection = re.fullmatch(r"(?:\[([^\]]+)\] )?Peer Connection Initiated with (\S+)", message)
        if not connection or not (endpoint := _endpoint(connection[2])):
            return None
        fields["vpn.action"] = "connect"
        fields["source.ip"] = endpoint[0]
        fields.pop("source.port", None)  # the explicit peer must not inherit a context endpoint's port
        if endpoint[1] is not None:
            fields["source.port"] = endpoint[1]
        if connection[1]:
            fields["user.name"] = connection[1]
    outcome = Outcome.unknown if fields["vpn.action"] in ("attempt", "timeout") else Outcome.success
    return ParsedLine("vpn_session", fields, outcome, (VPN_IDENTITY_CAVEAT,) if "user.name" in fields else ())


# OpenVPN's own log file (error.c x_msg_va): "<time> <prefix> <message>", the time from otime.c time_string as
# "%Y-%m-%d %H:%M:%S" (2.5 and later; " us=<n>" follows at high verbosity) or ctime's "Www Mmm dd hh:mm:ss yyyy"
# (2.4 and earlier), and the prefix a server's client context ("common-name/address:port", or "address:port" before
# the certificate is read). Lines without either time (--suppress-timestamps, --machine-readable-output) are not
# identified.
_OPENVPN_TIME = re.compile(r"(?:\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?: us=\d{1,6})?|"
                           r"(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) (?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)"
                           r" +\d{1,2} \d{2}:\d{2}:\d{2} \d{4}) (.*)")
_OPENVPN_PEER = re.compile(r"(?:[^\s/]+/)?(?:\[AF_INET6?\])?(?:\[[0-9A-Fa-f:.]+\]|[0-9A-Fa-f:.]+):\d{1,5} ")
# OpenVPN messages that are not authentication decisions or session boundaries, by their fixed opening words.
_OPENVPN_OTHER = (
    (re.compile(r"SENT CONTROL \[[^\]]*\]: 'AUTH_FAILED"),
     "OpenVPN AUTH_FAILED notice sent to the client (the decision is its TLS Auth Error line)"),
    # openers no other program writes
    (re.compile(r"(?:\[[^\]]+\] )?(?:OpenVPN \d|library versions:|Initialization Sequence Completed|Diffie-Hellman|"
                r"TUN/TAP device|net_(?:route|addr|iface|link)_|UDPv[46] link|TCPv[46]_SERVER link|MULTI: |"
                r"MULTI_sva:|IFCONFIG POOL|Control Channel:|Data Channel:|Outgoing Data Channel:|"
                r"Incoming Data Channel:|Outgoing Static Key|Incoming Static Key|VERIFY (?:KU|EKU|SCRIPT|X509NAME) OK|"
                r"VERIFY OK: depth=[1-9]|PUSH: |SENT CONTROL \[|peer info:|TLS: (?:soft reset|tls_|move_session|"
                r"new session|Username/Password authentication)|Re-using SSL/TLS context|PLUGIN_|AUTH-PAM:|"
                r"Authenticate/Decrypt packet error|Data Channel MTU|Outgoing Control Channel|"
                r"Incoming Control Channel|MANAGEMENT:|Fatal TLS error)"),
     "OpenVPN status, channel or configuration line (not an authentication decision or session boundary)"),
)
# Generic openers that identify OpenVPN only behind a server's client-context prefix.
_OPENVPN_PEER_ONLY = re.compile(r"(?:\[[^\]]+\] )?(?:NOTE: |Note: |WARNING: |Connection reset|LZO compression|"
                                r"OPTIONS IMPORT|Expected Remote Options|Local Options|Validating certificate|"
                                r"Restart pause|SIG(?:TERM|USR1|USR2|HUP|INT)\[|Timers:|Preserving recently used|"
                                r"GDG6?:|ROUTE6?:|client-instance|TCP connection established|Socket Buffers:)")


def openvpn_skip_reason(message: str) -> str | None:
    """The reason an identified OpenVPN message is not typed, or None for a message OpenVPN is not known to write."""
    peer = _OPENVPN_PEER.match(message)
    body = message[peer.end():] if peer else message
    for pattern, reason in _OPENVPN_OTHER:
        if pattern.match(body):
            return reason
    if peer and _OPENVPN_PEER_ONLY.match(body):
        return _OPENVPN_OTHER[1][1]
    return None


def _identify_openvpn(line: str) -> tuple[str, str] | None:
    stamped = _OPENVPN_TIME.fullmatch(line)
    if not stamped:
        return None
    body = stamped[1]
    if _openvpn(body) or parse_auth("openvpn", body) or openvpn_skip_reason(body):
        return "openvpn", body
    return None


def _strongswan(message: str) -> ParsedLine | None:
    message = re.sub(r"^\d+\[[A-Z]+\] ", "", message)
    match = re.fullmatch(r"(closing )?CHILD_SA ([^\s{}]+)\{(\d+)\} (established with|with) SPIs (.+)", message)
    if not match or bool(match[1]) == (match[4] == "established with"):
        return None
    fields: dict[str, object] = {"vpn.service": "strongswan", "vpn.action": "disconnect" if match[1] else "connect",
                                "vpn.session_id": match[3], "vpn.connection_name": match[2]}
    counts = re.match(r"[0-9a-fA-F]+_i \((\d{1,19}) bytes\) [0-9a-fA-F]+_o \((\d{1,19}) bytes\)(?: |$)", match[5])
    if counts:
        fields["vpn.bytes_received"] = int(counts[1])
        fields["vpn.bytes_sent"] = int(counts[2])
    return ParsedLine("vpn_session", fields, Outcome.success,
                      ("CHILD_SA name is a connection configuration name; user and peer address are not logged",))


def _squid(message: str) -> ParsedLine | None:
    match = _SQUID.fullmatch(message)
    if not match or not (address := _ip(match[3])):
        return None
    status = int(match[5])
    fields: dict[str, object] = {"source.ip": address, "http.request.method": match[7], "url.original": match[8],
                                "http.response.status_code": status, "http.response.bytes": int(match[6]),
                                "proxy.result": match[4]}
    if match[9] != "-":
        fields["user.name"] = match[9]
    _peer(fields, "" if _ip(match[11]) else match[11], match[11], None, "destination")
    outcome = Outcome.unknown if status == 0 else Outcome.success if status < 400 else Outcome.failure
    return ParsedLine("http_access", fields, outcome)


def _firewall(message: str) -> ParsedLine | None:
    message = re.sub(r"^\[\s*\d+(?:\.\d+)?\] ", "", message)
    match = re.fullmatch(r"(.*?)\bIN=(\S*) OUT=(\S*) (.*)", message)
    if not match:
        return None
    tokens = {}
    for token in match[4].split():
        key, equal, value = token.partition("=")
        if equal and key in {"SRC", "DST", "PROTO", "SPT", "DPT", "LEN"}:
            if key in tokens:
                return None
            tokens[key] = value
    if not (source := _ip(tokens.get("SRC", ""))) or not (destination := _ip(tokens.get("DST", ""))):
        return None
    protocol = tokens.get("PROTO", "")
    if not protocol:
        return None
    action = re.fullmatch(r"\[UFW (BLOCK|ALLOW|AUDIT)\] ?", match[1])
    fields: dict[str, object] = {"source.ip": source, "destination.ip": destination,
                                "firewall.action": action[1].lower() if action else "logged"}
    if protocol in ("TCP", "UDP", "ICMP", "ICMPv6", "SCTP"):
        fields["network.transport"] = protocol.lower()
    elif protocol.isascii() and protocol.isdigit() and len(protocol) < 4 and int(protocol) <= 255:
        fields["network.iana_number"] = protocol
    else:
        return None
    for key, name in (("SPT", "source.port"), ("DPT", "destination.port")):
        if key in tokens and (port := _port(tokens[key])) is not None:
            fields[name] = port
    return ParsedLine("net_flow", fields,
                      caveats=("Firewall packet log; no bidirectional flow counters, duration or connection success is implied",))


def _cron(program: str, message: str) -> ParsedLine | None:
    if program in ("cron", "crond"):
        match = re.fullmatch(r"\(([^()\s]+)\) CMD \((.*)\)", message)
        if match:
            return ParsedLine("process_observed", {"process.user": match[1], "process.command_line": match[2],
                                                   "scheduler.service": "cron"}, caveats=(SCHEDULER_CAVEAT,))
    elif program == "crontab":
        match = re.fullmatch(r"\(([^()\s]+)\) (REPLACE|BEGIN EDIT) \(([^()\s]+)\)", message)
        if match:
            return ParsedLine("service_change", {"service.name": "cron", "service.action": match[2].lower().replace(" ", "_"),
                                                  "user.name": match[1], "account.name": match[3]},
                              caveats=("Crontab manager log; numeric user ID and spool path are not recorded",))
    return None


def _account(program: str, message: str) -> ParsedLine | None:
    fields: dict[str, object] = {}
    if program == "usermod":
        match = re.fullmatch(r"(lock|unlock) user '([^']+)' password", message)
        if match:
            fields = {"account.action": match[1] + "_user", "account.name": match[2]}
        match = re.fullmatch(r"(add|delete) '([^']+)' (?:to|from) (shadow )?group '([^']+)'", message)
        if match:
            fields = {"account.action": "add_user_to_group" if match[1] == "add" else "remove_user_from_group",
                      "account.name": match[2], "group.name": match[4]}
        match = re.fullmatch(r"change user '([^']+)' (UID|GID|shell|home|inactive|expiration) from '([^']*)' to '([^']*)'", message)
        if match:
            key = {"UID": "account.id", "GID": "group.id", "shell": "account.shell", "home": "account.home",
                   "inactive": "account.inactive_days", "expiration": "account.expiration"}[match[2]]
            fields = {"account.action": "modify_user", "account.name": match[1], key: match[4],
                      "account.changed_attribute": match[2].lower(), "account.previous_value": match[3]}
        match = re.fullmatch(r"change user name '([^']+)' to '([^']+)'", message)
        if match:
            fields = {"account.action": "rename_user", "account.name": match[2], "account.previous_name": match[1]}
    elif program == "userdel":
        match = re.fullmatch(r"delete user '([^']+)'", message)
        if match:
            fields = {"account.action": "delete_user", "account.name": match[1]}
    elif program in ("passwd", "chpasswd"):
        match = re.fullmatch(r"password for '([^']+)' changed by '([^']+)'", message)
        if match:
            fields = {"account.action": "change_password", "account.name": match[1], "user.name": match[2]}
        match = re.fullmatch(r"pam_unix\((?:passwd|chpasswd):chauthtok\): password changed for ([^\s]+)", message)
        if match:
            fields = {"account.action": "change_password", "account.name": match[1]}
    return ParsedLine("account_change", fields, Outcome.success) if fields else None


def parse_service(program: str, message: str) -> ParsedLine | None:
    """Return only documented action records for an identified daemon, or None."""
    if (not isinstance(message, str) or len(message) > MAX_LINE
            or len(message.encode("utf-8", errors="replace")) > MAX_LINE
            or any(char in message for char in "\r\n\x00")):
        return None
    program = program.lower()
    if program in ("exim", "exim4"):
        return _exim(message)
    if program.startswith("postfix/"):
        return _postfix(program, message)
    if program == "dnsmasq":
        return _dnsmasq(message)
    if program == "dnsmasq-dhcp":
        return _dnsmasq_dhcp(message)
    if program == "suricata-fastlog":
        return _fastlog(message)
    if program in ("named", "bind9"):
        return _bind(message)
    if program == "unbound":
        return _unbound(message)
    if program == "openvpn" or program.startswith("openvpn-"):
        return _openvpn(message)
    if program in ("charon", "charon-systemd", "strongswan"):
        return _strongswan(message)
    if program in ("squid", "squid3"):
        return _squid(message)
    if program in ("kernel", "iptables", "ip6tables", "ufw"):
        return _firewall(message)
    if program in ("cron", "crond", "crontab"):
        return _cron(program, message)
    if program in ("usermod", "userdel", "passwd", "chpasswd"):
        return _account(program, message)
    return None


def identify_service(line: str) -> tuple[str, str] | None:
    """Identify fixed application envelopes; no host or record timestamp is invented."""
    if (not isinstance(line, str) or len(line) > MAX_LINE
            or len(line.encode("utf-8", errors="replace")) > MAX_LINE
            or any(char in line for char in "\r\n\x00")):
        return None
    exim = _EXIM_TIME.fullmatch(line)
    if exim and (re.match(rf"{_EXIM_ID} ", exim[1]) or exim[1].startswith(("H=", "SMTP connection"))
                 or re.match(r"\S+ authenticator failed for ", exim[1])):
        return "exim", exim[1]
    if _SQUID.fullmatch(line):
        return "squid", line
    if _FAST.fullmatch(line):
        return "suricata-fastlog", line
    # src/log.c my_syslog: a log file line is ctime's "Mmm dd hh:mm:ss", then "dnsmasq" with the facility tag of DHCP,
    # TFTP and script messages ("-dhcp", "-tftp", "-script") and the pid
    dns = re.fullmatch(r"[A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}:\d{2} (dnsmasq(?:-dhcp|-tftp|-script)?)\[\d+\]: (.*)", line)
    if dns:
        return dns[1], dns[2]
    openvpn = _identify_openvpn(line)
    if openvpn:
        return openvpn
    vpn = re.fullmatch(r"[A-Z][a-z]{2} [A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}:\d{2} \d{4} (.*)", line)
    if vpn:
        transfer = re.fullmatch(r"\d+ (\S+) \d+ \S+ [ab] [_CTU]+ [iod] [agr] \S+ ftp [01] \S+ [ci]", vpn[1])
        if transfer and _ip(transfer[1]):
            return "ftp-xferlog", line
        native = re.fullmatch(r'\[pid \d+\] (?:\[[^\]]+\] )?(?:OK|FAIL) (?:UPLOAD|DOWNLOAD|MKDIR|RMDIR|DELETE|RENAME|CHMOD): Client "[^"]+"(?:, .*)?', vpn[1])
        if native:
            return "vsftpd", line
    if re.fullmatch(r"\[\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?, +\d+(?:, [^\]]+)?\] [^\s]+:\d+\([^()]*\)", line):
        return "smbd", line
    if re.fullmatch(r"--[0-9a-fA-F]{1,64}-[ABF]--", line):
        return "modsecurity-audit", line
    return None
