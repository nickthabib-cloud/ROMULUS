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
        part = re.fullmatch(r"to=<([^>]*)>, (.*), status=(sent|deferred|bounced)(?: \(.*\))?", body)
        if not part:
            return None
        _recipients(fields, (part[1],))
        fields["mail.direction"] = {"sent": "delivered", "deferred": "deferred", "bounced": "bounced"}[part[3]]
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


def _dnsmasq(message: str) -> ParsedLine | None:
    extra = re.match(r"^(\d+) ([^\s/]+)/(\d+) (.*)$", message)
    if extra:
        message = extra[4]
    question = re.fullmatch(r"query\[([A-Za-z0-9_-]+)\] (\S+) from (\S+)", message)
    if question:
        if not (address := _ip(question[3])):
            return None
        fields: dict[str, object] = {"dns.type": "query", "dns.question.name": question[2],
                                    "dns.question.type": question[1], "source.ip": address}
        if extra and _ip(extra[2]) == address and (port := _port(extra[3])) is not None:
            fields["source.port"] = port
        return ParsedLine("dns_query", fields)
    forward = re.fullmatch(r"forwarded (\S+) to (\S+)", message)
    if forward and (address := _ip(forward[2])):
        return ParsedLine("dns_query", {"dns.type": "query", "dns.question.name": forward[1],
                                        "destination.ip": address}, caveats=("DNS forwarding line omits the requesting client and question type",))
    answer = re.fullmatch(r"(reply|cached(?:-stale)?|config|/etc/hosts) (\S+) is (\S+)", message)
    if not answer:
        return None
    fields = {"dns.type": "answer", "dns.question.name": answer[2]}
    address = _ip(answer[3])
    if address:
        kind = "AAAA" if ":" in address else "A"
        fields["dns.answers"] = [{"name": answer[2], "type": kind, "ttl": None, "data": address}]
    elif answer[3] in ("NXDOMAIN", "NODATA", "SERVFAIL", "REFUSED"):
        fields["dns.response_code"] = "NOERROR" if answer[3] == "NODATA" else answer[3]
    elif answer[3] != "<CNAME>":
        return None
    return ParsedLine("dns_query", fields,
                      caveats=("DNS answer line omits client address and query linkage; no per-line join is inferred",))


def _bind(message: str) -> ParsedLine | None:
    match = re.fullmatch(
        r"client (?:@0x[0-9a-fA-F]+ )?([^\s#]+)#(\d+) \(([^)]+)\): "
        r"query: (\S+) (IN|CH|HS) ([A-Z0-9]+) ([+\-][A-Za-z0-9()+\-]*) \(([^)]+)\)(?: \[.*\])?", message)
    if not match or not (address := _ip(match[1])) or _port(match[2]) is None:
        return None
    fields: dict[str, object] = {"dns.type": "query", "source.ip": address, "source.port": int(match[2]),
                                "dns.question.name": match[4], "dns.question.type": match[6]}
    if _ip(match[8]):
        fields["destination.ip"] = _ip(match[8])
    return ParsedLine("dns_query", fields)


def _unbound(message: str) -> ParsedLine | None:
    match = re.fullmatch(r"(?:\[\d+:\d+\] )?info: (?:query )?(\S+) (\S+) ([A-Z0-9]+) (IN|CH|HS)", message)
    if not match or not (address := _ip(match[1])):
        return None
    return ParsedLine("dns_query", {"dns.type": "query", "source.ip": address,
                                    "dns.question.name": match[2], "dns.question.type": match[3]})


def _openvpn(message: str) -> ParsedLine | None:
    fields: dict[str, object] = {"vpn.service": "openvpn"}
    # multi.c's client context prefixes every lifecycle message, including socket.c's connect line.
    prefix = re.fullmatch(r"(?:([^\s/]+)/)?(\S+) ((?:\[[^\]]+\] )?Peer Connection Initiated with \S+|"
                          r"MULTI_sva:.*|MULTI: Learn:.*|SIG(?:TERM|USR1|INT)\[.*)", message)
    if prefix and (endpoint := _endpoint(prefix[2])):
        if prefix[1]:
            fields["user.name"] = prefix[1]
        fields["source.ip"] = endpoint[0]
        if endpoint[1] is not None:
            fields["source.port"] = endpoint[1]
        message = prefix[3]
    assignment = re.fullmatch(r"MULTI_sva: pool returned IPv4=([^,]+), IPv6=(.+)", message)
    learn = re.fullmatch(r"MULTI: Learn: (\S+) -> ([^\s/]+)/(\S+)", message)
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
    elif re.fullmatch(r"SIG(?:TERM|USR1|INT)\[[^\]]+\] received, client-instance exiting", message):
        fields["vpn.action"] = "disconnect"
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
    return ParsedLine("vpn_session", fields, Outcome.success,
                      (VPN_IDENTITY_CAVEAT,) if "user.name" in fields else ())


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
    dns = re.fullmatch(r"[A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}:\d{2} dnsmasq\[\d+\]: (.*)", line)
    if dns:
        return "dnsmasq", dns[1]
    vpn = re.fullmatch(r"[A-Z][a-z]{2} [A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}:\d{2} \d{4} (.*)", line)
    if vpn and _openvpn(vpn[1]):
        return "openvpn", vpn[1]
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
