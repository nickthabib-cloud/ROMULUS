"""Pure, bounded parsing of vendor authentication messages.

Decision words are read only from anchored grammar positions. Unknown fields
remain absent; a malformed identity never supplies a guessed source or user.
The normalizer owns field provenance and retains the original record.
"""
from __future__ import annotations

import ipaddress
import re

from romulus.evidence.linux_text_types import ParsedLine
from romulus.evidence.typed import Outcome

_PARTIAL = "Authentication identity fields are ambiguous in the application log."
_PAM = re.compile(r"pam_unix\((?P<service>[^():\s]+):(?P<phase>auth|session)\): (?P<body>.*)")
# These services also log their own authentication decisions (parsed below), so
# one attempt can appear twice: once from the daemon, once from its PAM backend.
# Their PAM failures stay typed, on a separate "pam" channel that the rules never
# add to the daemon's own count: a site that ships only the PAM lines (the daemon
# may log natively to a file nobody collects) still sees a guessing burst. Exact
# service names, including documented PAM aliases; SSH stays with its own path.
PAM_CHANNEL = "pam"
# Each PAM service name (with its documented aliases) and the service its daemon's own log names.
PAM_NATIVE_SERVICE = {
    **dict.fromkeys(("dovecot", "imap", "pop3"), "dovecot"),
    **dict.fromkeys(("postfix", "postfix/smtpd", "smtpd", "smtp"), "postfix"),
    **dict.fromkeys(("exim", "exim4"), "exim"),
    **dict.fromkeys(("cyrus", "cyrus/imap", "cyrus/pop3", "imapd", "pop3d"), "cyrus"),
    "saslauthd": "saslauthd", "openvpn": "openvpn",
    **dict.fromkeys(("charon", "charon-systemd", "strongswan"), "charon"),
    **dict.fromkeys(("pppd", "xl2tpd"), "pppd"),
    "vsftpd": "vsftpd",
    **dict.fromkeys(("proftpd", "ftp"), "proftpd"),
    **dict.fromkeys(("smbd", "samba"), "samba"),
    **dict.fromkeys(("mysql", "mysqld", "mariadbd"), "mysql"),
    **dict.fromkeys(("postgres", "postgresql"), "postgresql"),
    **dict.fromkeys(("roundcube", "roundcubemail"), "roundcube"),
    "horde": "horde",
}
_NATIVE_AUTH_PAM_SERVICES = frozenset(PAM_NATIVE_SERVICE)
_DOVECOT = re.compile(r"(?:imap|pop3|submission|managesieve)-login: (?:Info: )?(?P<body>.*)")
_CTIME = re.compile(
    r"(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) (?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)"
    r" +\d{1,2} \d{2}:\d{2}:\d{2} \d{4} (?P<body>.*)"
)
_DATE = re.compile(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)? (?P<body>.*)")


def _bounded(text: str) -> bool:
    return len(text) <= 65536 and len(text.encode("utf-8", errors="surrogatepass")) <= 65536 and not any(
        c in text for c in ("\n", "\r", "\x00")
    )


def _ip(value: str | None) -> str | None:
    if not value or len(value) > 45:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def _event(service: str, outcome: Outcome, *, method: str | None = None,
           user: str | None = None, ip: str | None = None, port: str | None = None,
           phase: str = "authentication", fields: dict[str, object] | None = None,
           caveats: tuple[str, ...] = ()) -> ParsedLine:
    values: dict[str, object] = {"auth.service": service, "auth.phase": phase}
    if method:
        values["auth.method"] = method
    if user and user not in ("(unavailable)", "(null)"):
        values["user.name"] = user
        if outcome == Outcome.success and phase == "authentication":
            values["auth.user_valid"] = True
    if address := _ip(ip):
        values["source.ip"] = address
        if port and port.isascii() and port.isdigit() and len(port) <= 5 and int(port) <= 65535:
            values["source.port"] = int(port)
    values.update(fields or {})
    return ParsedLine("auth", values, outcome, caveats)


def _pam(program: str, message: str) -> ParsedLine | None:
    match = _PAM.fullmatch(message)
    if not match:
        return None
    service, phase, body = match.group("service", "phase", "body")
    if service == "sshd":
        if program not in {"sshd", "sshd-session", "sshd-auth"}:
            return None
        if program == "sshd" and phase == "auth":
            # Native SSH decisions already own these attempts. A PAM failure
            # has no connection port and would be counted as another attempt.
            return None
        # Split SSH helpers feed only the generic authentication rules. The
        # caller uses journald's captured comm when it is available.
        service = program
    if phase == "auth":
        if not body.startswith("authentication failure;"):
            return None
        # The user is last in PAM's statement; a user containing rhost= cannot
        # replace the earlier peer field. Do not search other free-text fields.
        data = re.fullmatch(
            r"authentication failure; logname=\S* uid=\d+ euid=\d+ tty=\S* "
            r"ruser=\S* rhost=(\S*)(?: +user=(.*))?", body
        )
        channel = {"auth.channel": PAM_CHANNEL} if service in _NATIVE_AUTH_PAM_SERVICES else None
        return _event(service, Outcome.failure, method="pam_unix",
                      ip=data[1] if data else None, user=data[2] if data else None,
                      fields=channel, caveats=() if data else (_PARTIAL,))
    if body.startswith("session opened for user "):
        user, sep, opener = body[len("session opened for user "):].rpartition(" by ")
        if sep and re.fullmatch(r"[^()]*\(uid=\d+\)", opener):
            user = re.sub(r"\(uid=\d+\)$", "", user)
            return _event(service, Outcome.success, method="pam_unix", user=user, phase="session_open")
    if body.startswith("session closed for user "):
        return _event(service, Outcome.success, method="pam_unix",
                      user=body[len("session closed for user "):], phase="session_close")
    return None


def _logind(message: str) -> ParsedLine | None:
    data = re.fullmatch(r"New session [^'\s]+ of user (.+)\.", message)
    if data:
        return _event("systemd-logind", Outcome.success, user=data[1], phase="session_open")
    data = re.fullmatch(r"New session '[^']+' of user '([^']+)' with class '[^']+' and type '[^']+'\.",
                        message)
    if data:
        return _event("systemd-logind", Outcome.success, user=data[1], phase="session_open")
    if re.fullmatch(r"Removed session \S+\.", message):
        return _event("systemd-logind", Outcome.success, phase="session_close")
    return None


def _dovecot(message: str) -> ParsedLine | None:
    match = _DOVECOT.fullmatch(message)
    if not match:
        return None
    body = match["body"]
    header, sep, attributes = body.partition(": user=")
    if not sep:
        return None
    if header == "Login":
        outcome = Outcome.success
    elif re.fullmatch(
        r"(?:Aborted login|Disconnected|Disconnected: Connection closed|Login aborted: Connection closed) "
        r"\(auth failed, \d+ attempts?(?: in \d+ secs)?\)(?: \(auth_failed\))?", header
    ):
        outcome = Outcome.failure
    else:
        return None
    # Dovecot's default log format encloses the user in <>. Reject extra
    # delimiters instead of turning attacker-controlled text into typed fields.
    user_part, _, rest = attributes.partition(", ")
    if not re.fullmatch(r"<[^<>]*>", user_part):
        return _event("dovecot", outcome, caveats=(_PARTIAL,))
    attributes_map: dict[str, str] = {}
    ambiguous = False
    for token in rest.split(", "):
        key, equals, value = token.partition("=")
        if equals and key in {"method", "rip", "lip", "rport", "lport"}:
            if key in attributes_map:
                ambiguous = True
            attributes_map[key] = value
    if ambiguous:
        return _event("dovecot", outcome, caveats=(_PARTIAL,))
    fields: dict[str, object] = {}
    if local := _ip(attributes_map.get("lip")):
        fields["destination.ip"] = local
    return _event("dovecot", outcome, user=user_part[1:-1], method=attributes_map.get("method"),
                  ip=attributes_map.get("rip"), port=attributes_map.get("rport"), fields=fields)


def _postfix(message: str) -> ParsedLine | None:
    match = re.fullmatch(
        r"warning: [^\[\]\s]+\[(?P<ip>[^\]]+)\](?::(?P<port>\d+))?: "
        r"SASL (?P<method>[^\s]+) authentication failed(?:: (?P<detail>.*))?", message
    )
    if not match:
        return None
    detail = match["detail"] or ""
    _, separator, user = detail.partition(", sasl_username=")
    return _event("postfix", Outcome.failure, method=match["method"], ip=match["ip"],
                  port=match["port"], user=user if separator else None)


def _exim(message: str) -> ParsedLine | None:
    match = re.fullmatch(r"(?P<method>\S+) authenticator failed for (?P<detail>.*)", message)
    if match:
        # host_and_ident puts the peer after the optional hostname/HELO and
        # before interface/ident metadata. Neither HELO nor the error is a peer.
        peer_tail = (r"\[[^\[\]\r\n]+\](?::\d+)?(?: I=\[[^\[\]]+\](?::\d+)?)?"
                     r"(?: U=\S+)?(?: Ci=\S+)?: [45]\d{2} ")
        boundaries = re.finditer(peer_tail, match["detail"])
        if next(boundaries, None) is None or next(boundaries, None) is not None:
            # Permissive HELO and account text can contain complete fake framing.
            # No first/last delimiter choice can authenticate an ambiguous peer.
            return _event("exim", Outcome.failure, method=match["method"], caveats=(_PARTIAL,))
        address = re.fullmatch(
            r"(?:H=)?(?:[^\s()[\]]+ )?(?:\([^()\r\n]*\) )?"
            r"\[(?P<ip>[^\[\]]+)\](?::(?P<port>\d+))?"
            r"(?: I=\[[^\[\]]+\](?::\d+)?)?(?: U=\S+)?(?: Ci=\S+)?"
            r": (?P<error>[45]\d{2} .*)", match["detail"])
        if address is None:
            # The failure decision is explicit, but an unsupported peer envelope
            # cannot establish an address or account for a guessing claim.
            return _event("exim", Outcome.failure, method=match["method"])
        error = address["error"]
        _, user_sep, user = error.partition(" (set_id=")
        return _event("exim", Outcome.failure, method=match["method"],
                      ip=address["ip"], port=address["port"],
                      user=user[:-1] if user_sep and user.endswith(")") else None)
    # Only message arrival metadata can assert an authenticated sender. A
    # subject or another free-text field containing A= is never inspected.
    match = re.fullmatch(r"[A-Za-z0-9]+-[A-Za-z0-9]+-[A-Za-z0-9]+ <= \S+ (?P<meta>.*)", message)
    if not match:
        return None
    tokens = _exim_tokens(match["meta"])
    if tokens is None:
        return None
    attributes: dict[str, str] = {}
    for token in tokens:
        key, sep, value = token.partition("=")
        if key == "S":
            break
        if sep and key in {"A", "P"}:
            if key in attributes:
                return None
            attributes[key] = value
    # P is server-generated. Requiring the authenticated protocol also avoids
    # treating an isolated A= mention as a successful SMTP authentication.
    if attributes.get("P") not in {"esmtpa", "esmtpsa", "smtpa", "smtpsa"}:
        return None
    auth = re.fullmatch(r"([A-Za-z0-9_-]+):([^\s]+)", attributes.get("A", ""))
    if not auth:
        return None
    peer = None
    for index, token in enumerate(tokens):
        if token.startswith("P=") and index:
            peer = re.fullmatch(r"\[([^\]]+)\](?::(\d+))?", tokens[index - 1])
            break
    return _event("exim", Outcome.success, method=auth[1], user=auth[2],
                  ip=peer[1] if peer else None, port=peer[2] if peer else None)


def _exim_tokens(text: str) -> list[str] | None:
    """Split top-level metadata once, keeping HELO parentheses and quoted text opaque."""
    tokens: list[str] = []
    start, depth, quoted, escaped = 0, 0, False, False
    for index, char in enumerate(text):
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == '"':
            quoted = not quoted
        elif not quoted and char == "(":
            depth += 1
        elif not quoted and char == ")":
            depth -= 1
            if depth < 0:
                return None
        elif char == " " and not quoted and depth == 0:
            if index > start:
                tokens.append(text[start:index])
            start = index + 1
    if quoted or depth or escaped:
        return None
    if start < len(text):
        tokens.append(text[start:])
    return tokens


def _cyrus(message: str) -> ParsedLine | None:
    match = re.fullmatch(r"badlogin: [^\[\]]*\[([^\]]+)\] (\S+) (.*?) SASL\(-?\d+\): .*", message)
    if match:
        return _event("cyrus", Outcome.failure, ip=match[1], method=match[2], user=match[3])
    return None


def _saslauthd(message: str) -> ParsedLine | None:
    match = re.fullmatch(
        r"do_auth +: auth (success(?: \(cached\))?|failure): \[user=([^\[\]]*)\] "
        r"\[service=[^\[\]]*\] \[realm=[^\[\]]*\](?: \[remote=([^\[\]]*)\])?"
        r"(?: \[mech=([^\[\]]*)\])?(?: \[reason=[^\[\]]*\])?", message
    )
    if match:
        return _event("saslauthd", Outcome.failure if match[1] == "failure" else Outcome.success,
                      user=match[2], ip=match[3], method=match[4])
    return None


def _openvpn(message: str) -> ParsedLine | None:
    # OpenVPN's logging prefix may carry common-name/real-address. The common
    # name is not a password-authenticated user, so only the peer is retained.
    peer = re.match(r"(?:[^/\s]+/)?(?:\[AF_INET6?\])?(?:\[([^\]]+)\]|([0-9A-Fa-f:.]+)):(\d+) ", message)
    address, port = None, None
    if peer:
        address, port = peer[1] or peer[2], peer[3]
        message = message[peer.end():]
    data = re.fullmatch(
        r"TLS: Username/Password authentication (succeeded|deferred) for username '([^']*)' ?(?:\[CN SET\])?",
        message
    )
    if data:
        return _event("openvpn", Outcome.success if data[1] == "succeeded" else Outcome.unknown,
                      method="password", user=data[2], ip=address, port=port)
    if message.startswith("TLS Auth Error: "):
        return _event("openvpn", Outcome.failure, method="tls", ip=address, port=port)
    if re.fullmatch(r"(?:AUTH: Received control message: )?AUTH_FAILED(?:,.*)?", message):
        return _event("openvpn", Outcome.failure, ip=address, port=port)
    if re.fullmatch(
        r"PLUGIN_CALL: plugin function (?:PLUGIN_|OPENVPN_PLUGIN_)?AUTH_USER_PASS_VERIFY "
        r"failed with status \d+: .+", message
    ):
        return _event("openvpn", Outcome.failure, method="plugin", ip=address, port=port)
    if re.fullmatch(
        r"WARNING: Failed running command \(--auth-user-pass-verify\): "
        r"external program exited with error status: [1-9]\d*", message
    ):
        return _event("openvpn", Outcome.failure, method="script", ip=address, port=port)
    return None


def _charon(message: str) -> ParsedLine | None:
    message = re.sub(r"^\d+\[IKE\] (?:<[^>]*> )?", "", message, count=1)
    match = re.fullmatch(r"authentication of '([^']+)' with ([A-Za-z0-9_ -]+) successful", message)
    if match:
        return _event("charon", Outcome.success, method=match[2], user=match[1])
    if message == "received EAP_FAILURE, EAP authentication failed":
        return _event("charon", Outcome.failure, method="EAP")
    match = re.fullmatch(r"tried \d+ shared keys? for '[^']*' - '([^']*)', but MAC mismatched", message)
    if match:
        return _event("charon", Outcome.failure, method="pre-shared key", user=match[1])
    return None


def _ppp(message: str) -> ParsedLine | None:
    match = re.fullmatch(r"(PAP|CHAP) peer authentication (succeeded|failed) for (.+)", message)
    if match:
        return _event("pppd", Outcome.success if match[2] == "succeeded" else Outcome.failure,
                      method=match[1], user=match[3])
    match = re.fullmatch(r"(PAP|CHAP) authentication (succeeded|failed)(?: due to protocol-reject)?", message)
    if match:
        return _event("pppd", Outcome.success if match[2] == "succeeded" else Outcome.failure,
                      method=match[1])
    match = re.fullmatch(r"Peer (.+) failed CHAP authentication", message)
    if match:
        return _event("pppd", Outcome.failure, method="CHAP", user=match[1])
    return None


def _ftp(program: str, message: str) -> ParsedLine | None:
    if program == "vsftpd":
        data = re.fullmatch(r'(?:\[pid \d+\] )?(?:\[([^\[\]]*)\] )?(OK|FAIL) LOGIN: Client "([^"\r\n]+)"',
                            message)
        if data:
            return _event("vsftpd", Outcome.success if data[2] == "OK" else Outcome.failure,
                          user=data[1], ip=data[3])
        return None
    prefix = re.match(r"(?:[^\s()]+ )?\([^()\[\]]*\[([^\]]+)\]\): ", message)
    peer = None
    if prefix:
        peer = prefix[1]
        message = message[prefix.end():]
    data = re.fullmatch(r"USER (.+): Login successful\.", message)
    if data:
        return _event("proftpd", Outcome.success, user=data[1], ip=peer)
    user, sep, details = message.rpartition(": no such user found from ")
    data = re.fullmatch(r"[^\[\]]+ \[([^\]]+)\] to \S+:\d+", details) if sep else None
    if data and user.startswith("USER "):
        return _event("proftpd", Outcome.failure, user=user[5:], ip=data[1],
                      fields={"auth.user_valid": False})
    data = re.fullmatch(r"USER (.+) \(Login failed\): (No such user found|Incorrect password|Account disabled)",
                        message)
    if data:
        return _event("proftpd", Outcome.failure, user=data[1], ip=peer,
                      fields={"auth.user_valid": False} if data[2] == "No such user found" else None)
    return None


def _samba(message: str) -> ParsedLine | None:
    data = re.fullmatch(
        r"check_ntlm_password: +[Aa]uthentication for user \[([^\[\]]*)\] -> \[[^\[\]]*\] "
        r"FAILED with error (NT_STATUS_[A-Z_]+)(?:, authoritative=\d+)?", message
    )
    if data:
        return _event("samba", Outcome.failure, method="NTLM", user=data[1],
                      fields={"auth.user_valid": False} if data[2] == "NT_STATUS_NO_SUCH_USER" else None)
    data = re.fullmatch(
        r"check_ntlm_password: +authentication for user \[([^\[\]]*)\] -> \[[^\[\]]*\] -> "
        r"\[[^\[\]]*\] succeeded", message
    )
    if data:
        return _event("samba", Outcome.success, method="NTLM", user=data[1])
    return None


def _database(program: str, message: str) -> ParsedLine | None:
    if program in {"postgres", "postgresql"}:
        data = re.fullmatch(r'(?:FATAL: +)?password authentication failed for user "([^"\r\n]*)"', message)
        if data:
            return _event("postgresql", Outcome.failure, method="password", user=data[1])
        return None
    data = re.fullmatch(r"(?:\[Warning\] )?Access denied for user '(.*)'@'([^']*)' \(using password: (YES|NO)\)",
                        message)
    if data:
        return _event("mysql", Outcome.failure, method="password" if data[3] == "YES" else None,
                      user=data[1], ip=data[2])
    return None


def _webmail(program: str, message: str) -> ParsedLine | None:
    if program in {"roundcube", "roundcubemail"}:
        message = message.removeprefix("userlogins: ")
        message = re.sub(r"^<[A-Za-z0-9,-]+> ", "", message, count=1)
        if message.startswith("Failed login for "):
            outcome, text = Outcome.failure, message[len("Failed login for "):]
        elif message.startswith("Successful login for "):
            outcome, text = Outcome.success, message[len("Successful login for "):]
        else:
            return None
        identity, sep, session = text.rpartition(" in session ")
        expected = r"\S+ \(error: -?\d+\)" if outcome == Outcome.failure else r"\S+"
        if not sep or not re.fullmatch(expected, session):
            return None
        user, sep, address = identity.rpartition(" from ")
        if not sep or not _ip(address):
            return None
        if outcome == Outcome.success:
            user, sep, user_id = user.rpartition(" (ID: ")
            if not sep or not re.fullmatch(r"\d+\)", user_id):
                return None
        return _event("roundcube", outcome, user=user, ip=address)
    message = message.removeprefix("[horde] ")
    message = re.sub(r' \[pid \d+(?: on line \d+ of "[^"\r\n]*")?\]$', "", message, count=1)
    if message.startswith("FAILED LOGIN for "):
        outcome, text = Outcome.failure, message[len("FAILED LOGIN for "):]
    elif message.startswith("Login success for "):
        outcome, text = Outcome.success, message[len("Login success for "):]
    else:
        return None
    identity, sep, address = text.rpartition(" (")
    if not sep or not address.endswith(")") or not _ip(address[:-1]):
        return None
    user, sep, app = identity.rpartition(" to ")
    if not sep or not re.fullmatch(r"[\w-]+", app):
        return None
    return _event("horde", outcome, user=user, ip=address[:-1])


def parse_auth(program: str, message: str) -> ParsedLine | None:
    """Parse a program's authentication record without changing legacy SSH."""
    if not _bounded(message) or len(program) > 256:
        return None
    program = re.sub(r"\[\d+\]$", "", program)
    if message.startswith("pam_unix("):
        return _pam(program, message)
    program = program.lower()
    if program == "sshd":
        return None
    if program == "systemd-logind":
        return _logind(message)
    if program == "dovecot":
        return _dovecot(message)
    if program == "smtpd" or program.startswith("postfix/") and program.endswith("/smtpd"):
        return _postfix(message)
    if program in {"exim", "exim4"}:
        return _exim(message)
    if program in {"cyrus/imap", "cyrus/pop3", "imapd", "pop3d", "cyrus"}:
        return _cyrus(message)
    if program == "saslauthd":
        return _saslauthd(message)
    if program == "openvpn":
        return _openvpn(message)
    if program in {"charon", "charon-systemd", "strongswan"}:
        return _charon(message)
    if program in {"pppd", "xl2tpd"}:
        return _ppp(message)
    if program in {"vsftpd", "proftpd"}:
        return _ftp(program, message)
    if program in {"smbd", "samba"}:
        return _samba(message)
    if program in {"mysql", "mysqld", "mariadbd", "postgres", "postgresql"}:
        return _database(program, message)
    if program in {"roundcube", "roundcubemail", "horde"}:
        return _webmail(program, message)
    return None


def identify_auth(line: str) -> tuple[str, str] | None:
    """Recognize fixed native-file envelopes; syslog envelopes belong upstream."""
    if not _bounded(line):
        return None
    ctime = _CTIME.fullmatch(line)
    date = ctime or _DATE.fullmatch(line)
    if date:
        body = date["body"]
        if body.startswith("[pid ") and parse_auth("vsftpd", body):
            return "vsftpd", body
        if ctime and parse_auth("openvpn", body):
            return "openvpn", body
    dovecot = re.fullmatch(r"[A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}:\d{2} (?P<body>.*)", line)
    if dovecot and parse_auth("dovecot", dovecot["body"]):
        return "dovecot", dovecot["body"]
    proftpd = re.fullmatch(
        r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3} \S+ proftpd\[\d+\] (?P<body>.*)", line
    )
    if proftpd and parse_auth("proftpd", proftpd["body"]):
        return "proftpd", proftpd["body"]
    roundcube = re.fullmatch(
        r"\[\d{2}-[A-Z][a-z]{2}-\d{4} \d{2}:\d{2}:\d{2} [+-]\d{4}\]: (?P<body>.*)", line
    )
    if roundcube and parse_auth("roundcube", roundcube["body"]):
        return "roundcube", roundcube["body"]
    return None
