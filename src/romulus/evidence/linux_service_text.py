"""Bounded, per-line parsers for documented Linux service log statements.

These parsers never join records or treat embedded message text as another event.
The caller supplies record timestamps, host identity and field provenance.
"""
from __future__ import annotations

import ipaddress
import re
import shlex

from romulus.evidence.linux_auth_text import _exim_tokens, openvpn_identifier, parse_auth
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
    if openvpn_identifier(program):
        return openvpn_skip_reason(message)
    if program in ("named", "bind9"):
        client = _BIND_CLIENT.fullmatch(message)
        if client and _BIND_ENDED.fullmatch(client[3]):
            return "BIND transfer completion line (the same transfer's started line is typed)"
        return None
    return account_skip_reason(program, message) or privilege_skip_reason(program, message)


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


# BIND 9 lib/ns: a client-context prefix ("client @0x<ptr> <addr>#<port> (<name>): ", the pointer and name absent in
# older releases), then xfrout.c's outgoing transfer statements (default xfer-out category) or the security
# category's ACL decision from client.c, built by ns_client_aclmsg as "zone transfer '<zone>/<type>/<class>'".
_BIND_CLIENT = re.compile(r"client (?:@0x\S+ )?([^\s#]+)#(\d+)(?:/key \S+)?(?: \([^)]*\))?(?:: view [^:\s]+)?: (.*)")
# ns_client_aclmsg gives "zone transfer '<zone>/<type>/<class>'"; the DLZ path logs "zone transfer '<zone>/<class>'",
# which does not say whether the request was AXFR or IXFR
_BIND_DENIED = re.compile(r"zone transfer '([^'/\s]+)(?:/(AXFR|IXFR))?/(IN|CH|HS)' denied")
_BIND_STARTED = re.compile(r"transfer of '([^'/\s]+)/(IN|CH|HS)': (AXFR|IXFR|AXFR-style IXFR) started"
                           r"(?:: TSIG \S+)?(?: \(serial \d+(?: -> \d+)?\))?")
_BIND_ENDED = re.compile(r"transfer of '[^'/\s]+/(?:IN|CH|HS)': (?:AXFR|IXFR|AXFR-style IXFR) ended: .*")
BIND_TRANSFER_CAVEAT = ("BIND transfer log line: a request the server denied, or a transfer it started; the zone's "
                        "content and the records sent are not shown")


def _bind_transfer(message: str) -> ParsedLine | None:
    client = _BIND_CLIENT.fullmatch(message)
    if not client or not (address := _ip(client[1])) or _port(client[2]) is None:
        return None
    if denied := _BIND_DENIED.fullmatch(client[3]):
        zone, qtype, result, outcome = denied[1], denied[2], "denied", Outcome.failure
    elif started := _BIND_STARTED.fullmatch(client[3]):
        zone, qtype, result, outcome = started[1], started[3].rsplit(" ", 1)[-1], "started", Outcome.success
    else:
        return None
    fields: dict[str, object] = {"dns.type": "query", "source.ip": address, "source.port": int(client[2]),
                                 "dns.question.name": zone.rstrip(".") or ".", "dns.transfer.result": result,
                                 SERVER_LOGGED: True}
    if qtype:
        fields["dns.question.type"] = qtype
    return ParsedLine("dns_query", fields, outcome, (BIND_TRANSFER_CAVEAT,))


def _bind(message: str) -> ParsedLine | None:
    if message.startswith("client ") and (transfer := _bind_transfer(message)) is not None:
        return transfer
    match = re.fullmatch(
        r"client (?:@0x[0-9a-fA-F]+ )?([^\s#]+)#(\d+)(?:/key \S+)? \(([^)]+)\):(?: view [^:\s]+:)? "
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


def _identify_openvpn(line: str, openvpn_file: bool) -> tuple[str, str] | None:
    """An OpenVPN log-file line. Other programs write the same ISO time and the same words ("AUTH_FAILED",
    "WARNING:"), so an ISO-stamped line, and any line known only by an untyped OpenVPN phrase, is OpenVPN's only when the
    record's typed fields say it was read from an OpenVPN log (`openvpn_file`). A ctime-stamped line whose message is
    an OpenVPN session or authentication statement is identified by the line alone."""
    stamped = _OPENVPN_TIME.fullmatch(line)
    if not stamped:
        return None
    body = stamped[1]
    typed = _openvpn(body) is not None or parse_auth("openvpn", body) is not None
    if openvpn_file and (typed or openvpn_skip_reason(body)):
        return "openvpn", body
    if typed and not line[:1].isdigit():
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


# shadow-utils account tools (src/useradd.c, usermod.c, userdel.c, groupadd.c, groupdel.c, groupmod.c, gpasswd.c,
# chage.c, passwd.c), typed with the actions and operations the tools' own audit records carry (ADD_USER create_user,
# USER_MGMT modify_user with op add-user-to-group, ...), so a syslog line and an audit record of one change read alike.
# A tool logs one membership or deletion once per database it writes ("... group 'g'" for /etc/group, then "... shadow
# group 'g'" or "... in /etc/gshadow" for /etc/gshadow, and groupadd's "group added to <db>" before its "new group"
# line): only the /etc/group statement, or the final one, is typed, and the others are counted as recognized skips.
ACCOUNT_TOOLS = ("useradd", "usermod", "userdel", "groupadd", "groupdel", "groupmod", "gpasswd", "chage", "passwd",
                 "chpasswd")
_NAME = r"[^'\s]+"
_ACCOUNT_DUPLICATES = re.compile(
    rf"(?:add '{_NAME}' to shadow group '{_NAME}'|delete '{_NAME}' from shadow group '{_NAME}'|"
    rf"removed shadow group '{_NAME}'(?: owned by '{_NAME}')?|group added to \S+: name=\S+(?:, GID=\d+)?|"
    rf"group '{_NAME}' removed from \S+|change (?:admin )?'{_NAME}' to '{_NAME}' in shadow group '{_NAME}'|"
    r"\S+ failed to (?:add user \S+ to|remove user \S+ from) group \S+ in \S+|"
    r"(?:user \S+ (?:added by \S+ to|removed by \S+ from) group \S+|members of group \S+ set by \S+ to .*|"
    r"administrators of group \S+ set by \S+ to .*|password of group \S+ (?:changed|removed) by \S+|"
    r"access to group \S+ restricted by \S+) in \S+)")
_GROUPMOD = re.compile(r"group changed in (\S+) \((?:changing \S+; )?group ([^/\s,]+)(?:/\d+)?"
                       r"(?:, new name: ([^\s,]+))?(, new password)?(?:, new gid: (\d+))?\)")


def account_skip_reason(program: str, message: str) -> str | None:
    if program in ACCOUNT_TOOLS and (_ACCOUNT_DUPLICATES.fullmatch(message) or (
            (groupmod := _GROUPMOD.fullmatch(message)) and groupmod[1].rsplit("/", 1)[-1] != "group")):
        return "account tool line for its shadow database (the same change's /etc/group line is typed)"
    return None


def _account(program: str, message: str) -> ParsedLine | None:
    fields: dict[str, object] = {}
    outcome = Outcome.success
    if program in ("useradd", "usermod", "userdel", "gpasswd"):
        # useradd and usermod: "add 'u' to group 'g'"; usermod and userdel: "delete 'u' from group 'g'"
        match = re.fullmatch(rf"(add|delete) '({_NAME})' (?:to|from) group '({_NAME})'", message)
        if match and program in (("useradd", "usermod") if match[1] == "add" else ("usermod", "userdel")):
            fields = {"account.action": "modify_user", "account.name": match[2], "account.group": match[3],
                      "account.op": "add-user-to-group" if match[1] == "add" else "delete-user-from-group"}
        # gpasswd -a / -d: "user u added by actor to group g", "user u removed by actor from group g"
        match = re.fullmatch(r"user (\S+) (added|removed) by (\S+) (?:to|from) group (\S+)", message)
        if match and program == "gpasswd":
            fields = {"account.action": "modify_user", "account.name": match[1], "account.group": match[4],
                      "user.name": match[3],
                      "account.op": "add-user-to-group" if match[2] == "added" else "delete-user-from-group"}
        # gpasswd log_gpasswd_failure: "<caller> failed to add user <u> to group <g>" (or ": Permission denied")
        match = re.fullmatch(r"(\S+) failed to (add user (\S+) to|remove user (\S+) from) group (\S+?)"
                             r"(?:: Permission denied)?", message)
        if match and program == "gpasswd" and not _ACCOUNT_DUPLICATES.fullmatch(message):
            fields = {"account.action": "modify_user", "account.name": match[3] or match[4], "account.group": match[5],
                      "user.name": match[1],
                      "account.op": "add-user-to-group" if match[3] else "delete-user-from-group"}
            outcome = Outcome.failure
        # usermod -l: "change '<old>' to '<new>' in group '<g>'" (the member renamed with the account)
        match = re.fullmatch(rf"change '({_NAME})' to '({_NAME})' in group '({_NAME})'", message)
        if match and program == "usermod":
            fields = {"account.action": "modify_user", "account.name": match[2], "account.previous_name": match[1],
                      "account.group": match[3], "account.op": "rename-group-member"}
    if program == "useradd":
        match = re.fullmatch(r"new user: name=([^,\s]+), UID=(\d+), GID=(\d+)(?:, .*)?", message)
        if match:
            fields = {"account.action": "create_user", "account.name": match[1], "account.id": match[2],
                      "account.group_id": match[3]}
        match = re.fullmatch(r"new group: name=([^,\s]+), GID=(\d+)", message)
        if match:
            fields = {"account.action": "create_group", "account.name": match[1], "account.id": match[2]}
        match = re.fullmatch(rf"failed adding user '({_NAME})', (?:exit code: \d+|data deleted)", message)
        if match:
            fields, outcome = {"account.action": "create_user", "account.name": match[1]}, Outcome.failure
    elif program == "usermod":
        match = re.fullmatch(rf"(lock|unlock) user '({_NAME})' password", message)
        if match:
            fields = {"account.action": match[1], "account.name": match[2], "account.op": f"{match[1]}-password"}
        match = re.fullmatch(rf"change user '({_NAME})' password", message)
        if match:
            fields = {"account.action": "password_change", "account.name": match[1]}
        match = re.fullmatch(rf"change user '({_NAME})' (UID|GID|shell|home|inactive|expiration) "
                             r"from '([^']*)' to '([^']*)'", message)
        if match:
            # account.new_id, not account.id: an audit record's id names the account changed, not a value assigned
            key = {"UID": "account.new_id", "GID": "account.group_id", "shell": "account.shell",
                   "home": "account.home", "inactive": "account.inactive_days",
                   "expiration": "account.expiration"}[match[2]]
            fields = {"account.action": "modify_user", "account.name": match[1], key: match[4],
                      "account.changed_attribute": match[2].lower(), "account.previous_value": match[3],
                      "account.op": f"change-{match[2].lower()}"}
        match = re.fullmatch(rf"change user name '({_NAME})' to '({_NAME})'", message)
        if match:
            fields = {"account.action": "modify_user", "account.name": match[2], "account.previous_name": match[1],
                      "account.op": "change-name"}
    elif program == "userdel":
        match = re.fullmatch(rf"delete user '({_NAME})'", message)
        if match:
            fields = {"account.action": "delete_user", "account.name": match[1]}
        match = re.fullmatch(rf"removed group '({_NAME})'(?: owned by '({_NAME})')?", message)
        if match:
            fields = {"account.action": "delete_group", "account.name": match[1]}
    elif program == "groupadd":
        match = re.fullmatch(r"new group: name=([^,\s]+), GID=(\d+)", message)
        if match:
            fields = {"account.action": "create_group", "account.name": match[1], "account.id": match[2]}
    elif program == "groupdel":
        match = re.fullmatch(rf"group '({_NAME})' removed", message)
        if match:
            fields = {"account.action": "delete_group", "account.name": match[1]}
    elif program == "groupmod":
        match = _GROUPMOD.fullmatch(message)
        if match and match[1].rsplit("/", 1)[-1] == "group":
            fields = {"account.action": "modify_group", "account.name": match[3] or match[2], "account.op": "modify-group"}
            if match[3]:
                fields["account.previous_name"] = match[2]
            if match[5]:
                fields["account.new_id"] = match[5]
    elif program == "gpasswd":
        match = re.fullmatch(r"password of group (\S+) (changed|removed) by (\S+)", message)
        if match:
            fields = {"account.action": "group_password_change", "account.name": match[1], "user.name": match[3],
                      "account.op": "change-group-password" if match[2] == "changed" else "remove-group-password"}
        match = re.fullmatch(r"(members|administrators) of group (\S+) set by (\S+) to (.*)", message)
        if match and not _ACCOUNT_DUPLICATES.fullmatch(message):
            # the group is the one whose list was set: a privileged group's members or administrators set is a grant
            fields = {"account.action": "modify_group", "account.name": match[2], "account.group": match[2],
                      "user.name": match[3], "account.op": f"set-group-{match[1]}",
                      "account.members": [name for name in match[4].split(",") if name][:LIST_LIMIT]}
        match = re.fullmatch(r"access to group (\S+) restricted by (\S+)", message)
        if match:
            fields = {"account.action": "modify_group", "account.name": match[1], "user.name": match[2],
                      "account.op": "restrict-group"}
    elif program == "chage":
        match = re.fullmatch(r"changed password expiry for (\S+)", message)
        if match:
            fields = {"account.action": "modify_user", "account.name": match[1], "account.op": "change-password-expiry"}
    elif program in ("passwd", "chpasswd"):
        match = re.fullmatch(r"password for '([^']+)' changed by '([^']+)'", message)
        if match:
            fields = {"account.action": "password_change", "account.name": match[1], "user.name": match[2]}
        match = re.fullmatch(r"pam_unix\((?:passwd|chpasswd):chauthtok\): password changed for ([^\s]+)", message)
        if match:
            fields = {"account.action": "password_change", "account.name": match[1]}
    return ParsedLine("account_change", fields, outcome) if fields else None


# Privilege brokers. util-linux login-utils/su-common.c log_syslog: "%s(to %s) %s on %s", the prefix "" on success,
# "FAILED SU " or "FAILED RUNUSER " on failure, then the target, the caller ("" when unknown) and the terminal
# ("none"). shadow-utils lib/sulog.c: "Successful su for <target> by <caller>" and "FAILED su for <target> by <caller>";
# its su.c also logs "+ <tty> <caller>:<target>" / "- ..." for the same attempt, counted as a recognized skip.
# polkit src/programs/pkexec.c log_message: "<caller>: <message> [USER=<target>] [TTY=<tty>] [CWD=<cwd>] [COMMAND=<cmd>]".
_SU_UTIL = re.compile(r"(FAILED (SU|RUNUSER) )?\(to ([^()\s]+)\) (\S*) on (\S+)")
_SU_SHADOW = re.compile(r"(Successful|FAILED) su for (\S+) by (\S+)")
_SU_SESSION = re.compile(r"[+-] \S+ \S*:\S*")
# pkexec's refusals. The SHELL and environment messages are the checks CVE-2021-4034 exploitation trips; polkit 0.105
# to 0.120 word them "was not found the /etc/shells file" and "contains suscipious content", later releases "was not
# found in the /etc/shells file" and "contains suspicious content".
_PKEXEC_SHELL = re.compile(r"The value for the SHELL variable was not found (?:in )?the /etc/shells file")
_PKEXEC_ENV = re.compile(r"The value for environment variable ([A-Za-z_][A-Za-z0-9_]{0,63}) contains "
                         r"(?:suspicious|suscipious) content")
_PKEXEC = re.compile(r"([^\s:]+): (Executing command|Error executing command as another user: (?:Not authorized|"
                     r"Request dismissed)|The value for the SHELL variable was not found (?:in )?the /etc/shells file|"
                     r"The value for environment variable [A-Za-z_][A-Za-z0-9_]{0,63} contains "
                     r"(?:suspicious|suscipious) content) \[USER=([^\]\s]+)\] \[TTY=([^\]]*)\] "
                     r"\[CWD=([\s\S]*)\] \[COMMAND=([\s\S]*)\]")
PRIVILEGE_TEXT_CAVEAT = "Privilege broker log line; the command and working directory are the invoking user's text"
PKEXEC_REJECTION_CAVEAT = ("pkexec logs a rejected SHELL or environment value before it reports it and exits; whether "
                           "it then refused, or code ran while it reported (CVE-2021-4034), is not shown")
PKEXEC_AMBIGUOUS_CAVEAT = ("The pkexec record repeats its field framing inside the working directory or command text; "
                           "neither is typed")


def _privilege(program: str, message: str) -> ParsedLine | None:
    if program in ("su", "runuser"):
        match = _SU_UTIL.fullmatch(message)
        if match and (match[2] is None or match[2].lower() == program):
            fields: dict[str, object] = {"auth.service": program, "auth.target_user": match[3]}
            if match[4]:
                fields["user.name"] = match[4]
            if match[5] != "none":
                fields["process.tty"] = match[5]
            if match[1]:
                fields["privilege.denial_reason"] = match[1].strip()
            return ParsedLine("privilege_use", fields, Outcome.failure if match[1] else Outcome.success)
        match = _SU_SHADOW.fullmatch(message)
        if match and program == "su":
            fields = {"auth.service": "su", "auth.target_user": match[2], "user.name": match[3]}
            if match[1] == "FAILED":
                fields["privilege.denial_reason"] = "FAILED su"
            return ParsedLine("privilege_use", fields, Outcome.failure if match[1] == "FAILED" else Outcome.success)
        return None
    if program == "pkexec":
        match = _PKEXEC.fullmatch(message)
        if not match:
            return None
        decision = match[2]
        fields = {"auth.service": "pkexec", "user.name": match[1], "auth.target_user": match[3]}
        if match[4] and match[4] != "unknown":
            fields["process.tty"] = match[4]
        caveats = [PRIVILEGE_TEXT_CAVEAT]
        if (len(re.findall(r"\]\s*\[COMMAND=", message)) == 1 and not re.search(r"\]\s*\[CWD=", match[5])
                and not re.search(r"\]\s*\[CWD=", match[6])):
            fields["process.cwd"], fields["privilege.command"] = match[5], match[6]
        else:
            caveats.append(PKEXEC_AMBIGUOUS_CAVEAT)
        if decision != "Executing command":
            fields["privilege.denial_reason"] = decision
            if _PKEXEC_SHELL.fullmatch(decision):
                fields["privilege.rejected_variable"] = "SHELL"
            elif env := _PKEXEC_ENV.fullmatch(decision):
                fields["privilege.rejected_variable"] = env[1]
        outcome = Outcome.success if decision == "Executing command" else Outcome.failure
        if "privilege.rejected_variable" in fields:
            # pkexec writes this line before it prints the same message and exits; that printing is where
            # CVE-2021-4034 exploitation runs its code, so the line does not show that pkexec went on to refuse.
            outcome = Outcome.unknown
            caveats.append(PKEXEC_REJECTION_CAVEAT)
        return ParsedLine("privilege_use", fields, outcome, tuple(caveats))
    return None


# Linux kernel/module/main.c module_augment_kernel_taints and module_sig_check: the notes the kernel prints while it
# loads a module that taints it. Each is printed only while that taint is not yet set (pr_notice_once for the
# signature note), so a boot shows at most one of each kind: the first module of that kind, never the later ones.
_KERNEL_TAINTS = (
    ("loading out-of-tree module taints kernel.", "out_of_tree"),
    ("module verification failed: signature and/or required key missing - tainting kernel", "unsigned"),
    ("loading test module taints kernel.", "test"),
    ("module license taints kernel.", "license"),
    ("module is from the staging directory, the quality is unknown, you have been warned.", "staging"),
    ("tainting kernel with TAINT_LIVEPATCH", "livepatch"),
)
KERNEL_MODULE_NAME_CAVEAT = "The module name holds characters kernel module names do not normally carry"
_KERNEL_LICENSE = re.compile(r"module license '([^'\r\n]{0,128})' taints kernel\.")
KERNEL_TAINT_CAVEAT = ("Kernel taint notice: the kernel prints it for the first module of its kind after boot only, "
                       "names no loading process or file, and does not show that the module's initialization "
                       "succeeded")


def _kernel(message: str) -> ParsedLine | None:
    message = re.sub(r"^\[\s*\d+(?:\.\d+)?\] ", "", message)
    name, sep, note = message.partition(": ")
    if not sep or not re.fullmatch(r"\S{1,256}", name):
        return None
    taint = next((kind for text, kind in _KERNEL_TAINTS if note == text), None)
    fields: dict[str, object] = {"module.name": name, "module.op": "load"}
    if taint is None and (license_note := _KERNEL_LICENSE.fullmatch(note)):
        taint = "proprietary_license"
        fields["module.license"] = license_note[1]
    if taint is None:
        return None
    fields["module.taint"] = taint
    caveats = (KERNEL_TAINT_CAVEAT,) if re.fullmatch(r"[A-Za-z0-9_-]{1,64}", name) else (
        KERNEL_TAINT_CAVEAT, KERNEL_MODULE_NAME_CAVEAT)
    return ParsedLine("kernel_module", fields, Outcome.unknown, caveats)


def privilege_skip_reason(program: str, message: str) -> str | None:
    if program == "su" and _SU_SESSION.fullmatch(message):
        return "su attempt line repeating its Successful/FAILED su record"
    return None


def parse_service(program: str, message: str) -> ParsedLine | None:
    """Return only documented action records for an identified daemon, or None."""
    if (not isinstance(message, str) or len(message) > MAX_LINE
            or len(message.encode("utf-8", errors="replace")) > MAX_LINE
            or "\x00" in message):
        return None
    program = program.lower()
    if program == "pkexec":
        # pkexec logs the caller's working directory and command verbatim, newlines included; its decision text
        # comes before both
        return _privilege(program, message)
    # a statement written with its own trailing newline (shadow-utils userdel and groupdel) keeps it in the message
    message = message.removesuffix("\n")
    if "\r" in message or "\n" in message:
        return None
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
    if openvpn_identifier(program):
        return _openvpn(message)
    if program in ("charon", "charon-systemd", "strongswan"):
        return _strongswan(message)
    if program in ("squid", "squid3"):
        return _squid(message)
    if program in ("kernel", "iptables", "ip6tables", "ufw"):
        return _firewall(message) or (_kernel(message) if program == "kernel" else None)
    if program in ("cron", "crond", "crontab"):
        return _cron(program, message)
    if program in ACCOUNT_TOOLS:
        return _account(program, message)
    if program in ("su", "runuser", "pkexec"):
        return _privilege(program, message)
    return None


def identify_service(line: str, *, openvpn_file: bool = False) -> tuple[str, str] | None:
    """Identify fixed application envelopes; no host or record timestamp is invented. `openvpn_file` is the record's
    typed evidence that it was read from an OpenVPN log (see `_identify_openvpn`)."""
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
    openvpn = _identify_openvpn(line, openvpn_file)
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
