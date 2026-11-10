"""Bounded content identification for independently shipped Linux text records.

Headers follow RFC 3164 section 4.1 and RFC 5424 section 6. Web formats follow
httpd.apache.org/docs/2.4/logs.html and nginx.org/en/docs/http/ngx_http_log_module.html.
Only a complete documented envelope identifies a format; arbitrary message phrases do not.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime

from romulus.evidence.linux_auth_text import identify_auth
from romulus.evidence.linux_service_text import identify_service

MAX_LINE_BYTES = 65_536
_BSD = re.compile(r"^(?:<\d{1,3}>)?(?P<time>[A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}:\d{2}|"
                  r"\d{4}-\d{2}-\d{2}T\S+) (?P<host>\S+) (?P<program>[^\s:\[]+)"
                  r"(?:\[(?P<pid>\d+)\])?: ?(?P<body>[^\r\n]*)$")
_RFC = re.compile(r"^<\d{1,3}>[1-9]\d{0,2} (?P<time>\S+) (?P<host>\S+) (?P<program>\S+) "
                  r"(?P<pid>\S+) (?P<msgid>\S+) (?P<rest>[^\r\n]*)$")
_QUOTED = r'(?:[^"\\\r\n]|\\[^\r\n])*'
_ACCESS = re.compile(r'^(?:(?P<vhost>\S+) )?(?P<client>\S+) \S+ \S+ '
                     r'\[(?P<time>[^\]\r\n]{1,64})\] "(?P<request>' + _QUOTED + r')" '
                     r'(?P<status>\d{3}) (?:\d+|-)(?: "' + _QUOTED + r'" "(?P<agent>' + _QUOTED + r')")?$')
_APACHE_ERROR = re.compile(r"^\[(?P<time>[A-Z][a-z]{2} [A-Z][a-z]{2} +\d{1,2} "
                           r"\d{2}:\d{2}:\d{2}(?:\.\d+)? \d{4})\] \[[^\]\r\n]+\] (?P<body>[^\r\n]*)$")
_NGINX_ERROR = re.compile(r"^(?P<time>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) "
                          r"\[(?:emerg|alert|crit|error|warn|notice|info|debug)\] \d+#\d+: (?P<body>[^\r\n]*)$")


def _structured_body(rest: str) -> str | None:
    if rest == "-":
        return ""
    if rest.startswith("- "):
        return rest[2:].removeprefix("\ufeff")
    pos = 0
    while pos < len(rest) and rest[pos] == "[":
        pos += 1
        quoted = escaped = False
        while pos < len(rest):
            char = rest[pos]
            pos += 1
            if escaped:
                escaped = False
            elif char == "\\" and quoted:
                escaped = True
            elif char == '"':
                quoted = not quoted
            elif char == "]" and not quoted:
                break
        else:
            return None
    if pos == 0 or quoted:
        return None
    if pos == len(rest):
        return ""
    return rest[pos + 1:].removeprefix("\ufeff") if rest[pos] == " " else None


@dataclass(frozen=True)
class TextLine:
    format: str
    program: str = ""
    message: str = ""
    hostname: str | None = None
    timestamp: str | None = None
    fields: dict[str, object] = field(default_factory=dict)


def classify(line: str) -> TextLine:
    if not isinstance(line, str):
        return TextLine("unknown")
    if len(line) > MAX_LINE_BYTES or len(line.encode("utf-8", errors="replace")) > MAX_LINE_BYTES:
        return TextLine("too_long")
    # Fixed native envelopes precede BSD headers: Dovecot's native file has a
    # timestamp followed directly by imap-login, without a syslog hostname.
    native = identify_auth(line) or identify_service(line)
    if native is not None:
        stamp = re.match(r"^(?:\[)?(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?(?: [+-]\d{4})?|"
                         r"[A-Z][a-z]{2} [A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}:\d{2} \d{4}|"
                         r"[A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}:\d{2}|\d{9,19}(?:\.\d{1,9})?)(?: |\])", line)
        return TextLine("application", native[0], native[1], timestamp=stamp[1] if stamp else None)
    if match := _RFC.fullmatch(line):
        body = _structured_body(match["rest"])
        if body is not None:
            return TextLine("syslog", match["program"], body, match["host"], match["time"])
        return TextLine("unknown")
    if match := _BSD.fullmatch(line):
        return TextLine("syslog", match["program"], match["body"], match["host"], match["time"])
    if match := _ACCESS.fullmatch(line):
        fields = {"http.response.status_code": int(match["status"])}
        request = match["request"].split(" ")
        if len(request) == 3 and request[0].isalpha() and request[2].startswith("HTTP/"):
            fields.update({"http.request.method": request[0], "url.original": request[1]})
        elif match["request"] != "-":
            return TextLine("unknown")
        try:
            fields["source.ip"] = str(ipaddress.ip_address(match["client"]))
        except ValueError:
            fields["source.host"] = match["client"]
        if match["agent"] is not None:
            fields["user_agent.original"] = match["agent"]
        return TextLine("http_access", "apache", line, timestamp=match["time"], fields=fields)
    for pattern, program in ((_APACHE_ERROR, "apache"), (_NGINX_ERROR, "nginx")):
        if match := pattern.fullmatch(line):
            return TextLine("web_error", program, match["body"], timestamp=match["time"],
                            fields={"web.error_message": match["body"]})
    return TextLine("unknown")


def inline_time(value: str | None, pipeline: datetime) -> datetime | None:
    """Parse diagnostic inline time only. A missing year/zone uses the pipeline's year/zone."""
    if not value or value == "-":
        return None
    if re.fullmatch(r"\d{9,19}(?:\.\d{1,9})?", value):
        try:
            return datetime.fromtimestamp(float(value), UTC)
        except (OverflowError, OSError, ValueError):
            return None
    try:
        result = datetime.fromisoformat(value)
    except ValueError:
        result = None
        for pattern in ("%d/%b/%Y:%H:%M:%S %z", "%a %b %d %H:%M:%S.%f %Y", "%a %b %d %H:%M:%S %Y",
                        "%Y/%m/%d %H:%M:%S", "%b %d %H:%M:%S"):
            try:
                result = datetime.strptime(value, pattern)
                if pattern == "%b %d %H:%M:%S":
                    result = result.replace(year=pipeline.year)
                break
            except ValueError:
                pass
    return result.replace(tzinfo=pipeline.tzinfo) if result and result.tzinfo is None else result
