"""Zeek records, in each shipper shape the catalog describes, into typed events.

Shape recognition reads only fields the shipper writes (`event.provider`, `event.dataset`, `event.module`, and for
plain Zeek JSON the site's declaration with Zeek's own `_path`); never content, `message` or index names. Every
typed field names, in its origin, the path it was read from; fields read from the Zeek line kept in `event.original`
are labelled `#original`. Values of the wrong type are dropped and listed in `parse.malformed`; a record without a
readable first-packet time or log name is an error; a log outside the catalog is a counted skip.

Byte counts. Zeek's `orig_bytes`/`resp_bytes` are payload bytes (from TCP sequence numbers) and are typed as
`flow.bytes_toserver`/`flow.bytes_toclient` with `flow.bytes_are_payload`; `orig_ip_bytes`/`resp_ip_bytes` are
IP-level bytes and are typed as `source.bytes`/`destination.bytes`. The two are never substituted for each other.

ICMP. Zeek keys an ICMP connection by the message type (`id.orig_p`) and, for request/reply types, the counterpart
type (`id.resp_p`: 0 for an echo request's reply, 129 for an ICMPv6 echo request's), else the code. So the type is
typed from `id.orig_p`, and the code only from a field that holds nothing else; `id.resp_p` stays the destination
port. Zeek writes "icmp" as the transport of ICMPv6 too, so the address family decides "ipv6-icmp".

Analyzer logs. Each is typed through its catalog table into the family whose contract the existing rules read (dns
rows as whole-transaction `dns_query` records, http as `http_tx`, ssl as `tls_session` with the shared certificate
contract, files and pe as `file_transfer`, ssh as `ssh_session`, notice/weird/signatures/intel as `net_alert` with
`alert.provider` "zeek"), x509 rows as `x509_certificate` records keyed by fingerprint (they name no connection), and
logs no family carries as `app_tx` (command, argument, reply).

Secrets. Credential values (Malcolm's `related.password`, `url.password`, `url.full` and `post_password_*`, Zeek's
own `password` columns, the argument of a credential command (FTP PASS/ACCT/ADAT, IRC PASS/OPER/AUTHENTICATE and JOIN
keys, Redis AUTH), an SNMPv1/v2c community) are never kept in a typed value, an origin, a caveat or an error. Inside
free text (a URI's userinfo, a SIP URI's password, a SQL statement's password literals, a Redis reply's passwords) only
the credential is replaced by "<redacted>" and the rest kept (see zeek_credentials). Only
`auth.cleartext_credentials_present` (or, where text that can carry one was withheld because it could not be read,
`auth.cleartext_credentials_unknown`) is typed, its origin naming where.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from functools import lru_cache

from romulus.evidence.certificates import certificate_fields, dn_parts, name_key
from romulus.evidence.community import community_id
from romulus.evidence.typed import FieldValue, RawRef, TypedEvent, event_id, fv
from romulus.evidence.zeek_catalog import (
    CONN,
    ELASTIC,
    MALCOLM,
    PLAIN,
    SECURITY_ONION,
    SHAPE_NAMES,
    ZEEK_LOGS,
    ZeekField,
    ZeekLog,
    lookup_log,
)
from romulus.evidence.zeek_credentials import (
    REDACTED,
    SIP_UNREAD,
    Scrubbed,
    scrub_redis_reply,
    scrub_sql,
    strip_sip_password,
    strip_uri_userinfo,
)

ZEEK_NORMALIZER = "zeek-ecs@1"
ZEEK_DUPLICATE = "duplicate Zeek record copy (sensor/log/uid)"
ZEEK_INTERIM_SUPERSEDED = "Zeek interim conn record superseded by a later record of the same connection"
MISSED_BYTES_CAVEAT = ("Zeek missed {n} bytes of this connection in content gaps (missed_bytes): its payload byte "
                       "counts and what Zeek's analyzers logged for it may be incomplete")
CONTENT_GAP_CAVEAT = ("Zeek's history for this connection records a content gap (g): its payload byte counts and what "
                      "Zeek's analyzers logged for it may be incomplete")
PARTIAL_CAVEAT = ("Zeek's history for this connection records partial analysis (x, for example a limit exceeded): "
                  "what Zeek's analyzers logged for it may be incomplete")
INTERIM_CAVEAT = ("an interim record of a connection still open when it was written: its counters and duration run "
                  "only to that moment, and a later record of the same connection supersedes it")
MALCOLM_MISSING_TS_CAVEAT = "Malcolm found no Zeek ts on this record and gave it the time Malcolm ingested it"

ICMP_TRANSPORTS = frozenset({"icmp", "ipv6-icmp", "icmpv6"})
IP_PROTOCOLS = {1: "icmp", 6: "tcp", 17: "udp", 58: "ipv6-icmp", 132: "sctp"}
# Zeek's text logs write "-" for an unset field and "(empty)" for an empty set; JSON omits both.
PLACEHOLDERS = frozenset({"", "-", "(empty)"})
_DIGITS = re.compile(r"^[0-9]+$")
_DECIMAL = re.compile(r"^[0-9]+(?:\.[0-9]+)?$")
_MAC = re.compile(r"^[0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5}$")
# Zeek names some analyzers per transport (krb_tcp) and Spicy-based ones with a prefix (spicy_ldap); the transport
# is typed on its own, so the service names are the protocol's (Malcolm's conn pipeline does the same).
_SERVICE_SUFFIXES = ("_tcp", "_udp")
_SERVICE_PREFIX = "spicy_"
# Fields excluded from a record's content signature: they describe how the copy was read, not the record.
_UNSIGNED = frozenset({"parse.malformed"})


class ZeekNotNormalized(Exception):
    """A Zeek record of a log outside the catalog: counted as not normalized, never an error."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


_MISSING = object()
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


@lru_cache(maxsize=4096)
def _parts(path: str) -> tuple[str, ...]:
    return tuple(path.split("."))


_CONFLICT = object()


def _routes(cur, parts: tuple[str, ...], i: int):
    """Every value at parts[i:] below `cur`, one per way the rest of the path splits into nested and literal dotted
    keys (`a.b.c` may be written as a/b/c, a.b/c, a/b.c or a.b.c)."""
    if i == len(parts):
        yield cur
        return
    if not isinstance(cur, dict):
        return
    for j in range(i + 1, len(parts) + 1):
        key = parts[i] if j == i + 1 else ".".join(parts[i:j])
        if key in cur:
            yield from _routes(cur[key], parts, j)


def _resolve(src, parts: tuple[str, ...]):
    """The value at a path written with any mix of nested and literal dotted keys; _CONFLICT when the record writes
    the path more than once with different values (never silently resolved), _MISSING when absent."""
    values: list = []
    for value in _routes(src, parts, 0):
        if not any(value == seen for seen in values):
            values.append(value)
    if not values:
        return _MISSING
    return values[0] if len(values) == 1 else _CONFLICT


def _nested(src, parts: tuple[str, ...]):
    cur = src
    for part in parts:
        if not isinstance(cur, dict) or part not in cur:
            return _MISSING
        cur = cur[part]
    return cur


def _has_dotted_keys(value) -> bool:
    """Whether any object in a record holds a literal dotted key (an explicit stack: no depth limit to hit)."""
    stack = [value]
    while stack:
        level = stack.pop()
        if isinstance(level, dict):
            for key, item in level.items():
                if isinstance(key, str) and "." in key:
                    return True
                if isinstance(item, dict):
                    stack.append(item)
    return False


def dotted(src, path: str):
    """The value at a dotted path, whether the shipper nested the keys or kept them literal ("id.orig_h"), or any
    mix. _MISSING when absent, and when the record writes the path twice with different values."""
    parts = _parts(path)
    if not _has_dotted_keys(src):
        return _nested(src, parts)
    value = _resolve(src, parts)
    return _MISSING if value is _CONFLICT else value


def _present(value) -> bool:
    return value is not _MISSING and value is not None and not (isinstance(value, str) and value in PLACEHOLDERS) \
        and value != [] and value != {}


@dataclass(frozen=True)
class ZeekRecord:
    """A recognized Zeek record: its shipper shape, the log names it carries, where they were read, and the catalog
    entry they denote (None when no log of the catalog)."""
    shape: str
    names: tuple[str, ...]
    origin: str                     # where the log names were read
    log: ZeekLog | None
    recognized_by: str              # the shipper-written field (or the site declaration) that says it is Zeek
    # The skip reason while the record's log is not normalized: the one every record of a dataset no normalizer
    # reads gets, which the sweep counts as records no rule evaluated (so no rule's search over them is complete).
    unsupported: str

    @property
    def token(self) -> str:
        return self.log.token if self.log is not None else "zeek"


def _names(value) -> tuple[str, ...] | None:
    """The log names a dataset field carries, lowercased; None when absent or not text."""
    items = value if isinstance(value, list) else [value]
    if not items or not all(isinstance(item, str) and item.strip() for item in items):
        return None
    return tuple(dict.fromkeys(item.strip().lower() for item in items))


def _unsupported(dataset) -> str:
    return f"dataset:{dataset if dataset is not _MISSING and dataset else ''} is not normalized"


def _record(src: dict, shape: str, names: tuple[str, ...] | None, origin: str, recognized_by: str,
            unsupported: str) -> ZeekRecord:
    if names is None:
        return ZeekRecord(shape, (), origin, None, recognized_by, unsupported)
    logs = list(dict.fromkeys(log for name in names if (log := lookup_log(shape, name)) is not None))
    if len(names) > 1:
        # a row naming several logs (Malcolm's SMB rows) is a log only when it carries that log's object
        logs = [log for log in logs
                if log.log_objects.get(shape) and _present(_nested(src, _parts(log.log_objects[shape])))]
    return ZeekRecord(shape, names, origin, logs[0] if len(logs) == 1 else None, recognized_by, unsupported)


_PROVIDER, _DATASET, _STREAM, _MODULE, _FILESET = (_parts(path) for path in (
    "event.provider", "event.dataset", "data_stream.dataset", "event.module", "fileset.name"))
# What a record whose shipper cannot be told is: never read, counted like any dataset no normalizer reads (so no
# rule's search over it is complete), its reason naming the ambiguity.
AMBIGUOUS = "ambiguous"
AMBIGUOUS_SHAPE = ("dataset:{dataset} is not normalized: the record carries neither Security Onion's markers "
                   "(event.module and data_stream.dataset \"zeek\") nor Elastic's (data_stream.dataset {dataset}, or "
                   "Filebeat's event.module \"zeek\" with fileset.name), and the dataset alone does not tell their "
                   "layouts apart, so its sensor, uid and time units are not known")
# zeek.<name> datasets no catalogued log of Security Onion is named: only Elastic writes them
_ELASTIC_ONLY = frozenset(name for log in ZEEK_LOGS for name in log.names.get(ELASTIC, ())) - frozenset(
    name for log in ZEEK_LOGS for name in log.names.get(SECURITY_ONION, ()))


def zeek_record(src: dict) -> ZeekRecord | None:
    """The Zeek shape of an indexed record, from shipper-written fields only, or None for a record that is not Zeek.

    - Security Onion 2.4: `event.module` "zeek" with `data_stream.dataset` exactly "zeek" (its agent policy's one
      stream for every Zeek log) and `event.dataset` `zeek.<log>` (its common pipeline prefixes the module), or a
      bare log name (a record that did not pass that pipeline);
    - Security Onion 2.3: `event.module` "zeek" with a bare log name as `event.dataset` and no data stream (its
      Filebeat inputs' module and dataset fields, which its common pipeline renames and does not prefix);
    - Elastic Agent: `data_stream.dataset` `zeek.<stream>`, the same as `event.dataset` when that is written;
    - Filebeat's zeek module: `event.module` "zeek", `event.dataset` `zeek.<fileset>` and `fileset.name` the fileset
      (Filebeat always writes a module's dataset as `<module>.<fileset>`, so a bare name is never its own);
    - Malcolm: `event.provider` "zeek" with a bare log name (or a list of them) as `event.dataset`; Malcolm writes the
      provider on every Zeek row, and `event.module` "zeek" on notice and signatures rows too, so the provider is
      read first.
    Security Onion and Elastic both name most logs `zeek.<log>` (dns, http, ssl, ...), and read with the other's
    layout a record loses its sensor and uid and changes units. So a `zeek.<log>` record with neither shipper's
    markers is never read: it is a skip whose reason says why (`AMBIGUOUS_SHAPE`), counted like a dataset no
    normalizer reads. Only a name Security Onion never uses (`zeek.connection`, `zeek.files`, `zeek.signature`) is
    Elastic's without its markers. A provider of "suricata" or "arkime" (Malcolm's other rows) decides that the record
    is not Zeek; a dotted dataset that is not `zeek.*` is not a Zeek log name, and the record keeps the path it took
    before Zeek was read. These shippers write the fields as objects, which is how every other normalizer reads
    `event.dataset` too. Plain Zeek JSON carries no such field: a site declares it, and `plain_record` reads it."""
    provider = _nested(src, _PROVIDER)
    if provider in ("suricata", "arkime"):
        return None
    dataset = _nested(src, _DATASET)
    stream = _MISSING if _present(dataset) else _nested(src, _STREAM)
    module, data_stream = _nested(src, _MODULE), _nested(src, _STREAM)
    for path, value in (("event.dataset", dataset), ("data_stream.dataset", stream)):
        if isinstance(value, str) and value.startswith("zeek."):
            names = _names(value[len("zeek."):])
            if names is None:
                return None
            if path == "data_stream.dataset":           # only the Elastic Agent writes a zeek.<stream> data stream
                return _record(src, ELASTIC, names, path, path, _unsupported(dataset))
            if module == "zeek" and data_stream == "zeek":
                return _record(src, SECURITY_ONION, names, path, "event.module", _unsupported(dataset))
            if data_stream == value:
                return _record(src, ELASTIC, names, path, path, _unsupported(dataset))
            fileset = _nested(src, _FILESET)
            if module == "zeek" and isinstance(fileset, str) and _names(fileset) == names:
                return _record(src, ELASTIC, names, path, "fileset.name", _unsupported(dataset))
            if set(names) <= _ELASTIC_ONLY:
                return _record(src, ELASTIC, names, path, path, _unsupported(dataset))
            return ZeekRecord(AMBIGUOUS, names, path, None, path, AMBIGUOUS_SHAPE.format(dataset=value))
    names = _names(dataset)
    if names is None or any("." in name for name in names):
        # no readable log name: the record keeps the path it took before Zeek was read (a Malcolm row without its
        # dataset is read for the Arkime session fields Malcolm adds, as it always was)
        return None
    if provider == "zeek":
        return _record(src, MALCOLM, names, "event.dataset", "event.provider", _unsupported(dataset))
    if module == "zeek":
        return _record(src, SECURITY_ONION, names, "event.dataset", "event.module", _unsupported(dataset))
    return None


def plain_record(src: dict, declared_log: str | None = None) -> ZeekRecord:
    """A record of a target the site declares as plain Zeek JSON: the log is Zeek's own `_path` when present, else
    the declared log. A `_path` that contradicts the declaration is an error, never a guess."""
    path = dotted(src, "_path")
    if _present(path):
        names = _names(path)
        if names is not None and declared_log and names != (declared_log.strip().lower(),):
            raise ValueError("plain Zeek record's _path names a different log than the target declares")
        return _record(src, PLAIN, names, "_path", "#declared", _unsupported("/".join(names or ())))
    names = _names(declared_log) if declared_log else None
    return _record(src, PLAIN, names, "#declared", "#declared", _unsupported("/".join(names or ())))


# ---- value readers -------------------------------------------------------------------------------------------------

_BAD = object()


def _number_text(value, shape: str, pattern: re.Pattern):
    """Zeek's text form of a number, which Malcolm keeps for logs it reads as text; other shapes write JSON
    numbers, so text there is malformed."""
    return shape == MALCOLM and isinstance(value, str) and bool(pattern.match(value))


@lru_cache(maxsize=65536)
def _address(text: str) -> str | None:
    """The address as written when it parses as one (a bounded cache: sensors see the same hosts again and again)."""
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return None
    return text


def _read_ip(value, shape):
    if not isinstance(value, str) or len(value) > 64:
        return _BAD
    address = _address(value.strip())
    return _BAD if address is None else address


# Zeek's count type is an unsigned 64-bit integer: a larger value is not one Zeek wrote.
COUNT_MAX = 2**64 - 1


def _read_count(value, shape, limit=COUNT_MAX):
    if _number_text(value, shape, _DIGITS) and len(value) <= 20:
        value = int(value)
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= limit:
        return _BAD
    return value


def _read_seconds(value, shape):
    """Zeek's interval: a finite, non-negative number of seconds (or a unit the catalog names)."""
    if _number_text(value, shape, _DECIMAL):
        value = float(value)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return _BAD
    try:
        seconds = float(value)
    except OverflowError:                               # an integer beyond any float
        return _BAD
    return seconds if 0 <= seconds < float("inf") else _BAD


def _read_text(value, shape):
    return value if isinstance(value, str) else _BAD


def _read_flag(value, shape):
    if isinstance(value, bool):
        return value
    if shape == MALCOLM and isinstance(value, str) and value in ("T", "F", "true", "false"):
        return value in ("T", "true")
    return _BAD


def _read_list(value, shape, *, comma: bool):
    """A Zeek set or vector of strings as a list. Zeek's JSON writes an array; its text form (and the service
    field everywhere) is comma-separated."""
    if isinstance(value, str) and comma:
        value = value.split(",")
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        return _BAD
    items = [item.strip() for item in value if item.strip() and item.strip() not in PLACEHOLDERS]
    return items or None


def _read_services(value, shape):
    items = _read_list(value, shape, comma=True)
    if items is _BAD or items is None:
        return items
    return list(dict.fromkeys(item.lower() for item in items))


def _read_names(value, shape):
    items = _read_list(value, shape, comma=shape == MALCOLM)
    if items is _BAD or items is None:
        return items
    return sorted(set(items))


def _read_mac(value, shape):
    if not isinstance(value, str) or not _MAC.match(value.strip()):
        return _BAD
    return value.strip().lower().replace("-", ":")


def _read_vector(value, shape):
    """A Zeek vector of strings in Zeek's order. A shipper may store a one-element vector as its string, and Malcolm
    a text log's vector as one comma-separated string."""
    if isinstance(value, str):
        value = value.split(",") if shape == MALCOLM else [value]
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        return _BAD
    items = [item.strip() for item in value if item.strip() and item.strip() not in PLACEHOLDERS]
    return items or None


def _read_text1(value, shape):
    """One string, which a shipper that splits a text log's columns may have written as a one-element list."""
    if isinstance(value, list) and len(value) == 1:
        value = value[0]
    if not isinstance(value, str):
        return _BAD
    return None if value.strip() in PLACEHOLDERS else value


def _read_count_text(value, shape):
    """A count a shipper converted to text (Elastic writes the DNS transaction id as a string)."""
    if isinstance(value, str) and _DIGITS.match(value) and len(value) <= 20:
        value = int(value)
    return _read_count(value, shape)


_HEX = re.compile(r"^[0-9a-fA-F:]+$")


def _read_hex(value, shape):
    if not isinstance(value, str) or not _HEX.match(value.strip()):
        return _BAD
    return value.strip().lower()


def _read_hexes(value, shape):
    """Hex digests (JA3, HASSH) as a sorted distinct lowercase list: a record may carry one or several."""
    items = _read_vector(value, shape)
    if items is _BAD or items is None:
        return items
    if not all(_HEX.match(item) for item in items):
        return _BAD
    return sorted({item.lower() for item in items})


def _read_addresses(value, shape):
    items = _read_vector(value, shape)
    if items is _BAD or items is None:
        return items
    addresses = [_address(item) if len(item) <= 64 else None for item in items]
    return _BAD if any(address is None for address in addresses) else addresses


def _read_seconds_list(value, shape):
    items = value if isinstance(value, list) else (value.split(",") if shape == MALCOLM and isinstance(value, str)
                                                    else [value])
    out = []
    for item in items:
        if isinstance(item, str) and item.strip() in PLACEHOLDERS:
            continue
        seconds = _read_seconds(item.strip() if isinstance(item, str) else item, shape)
        if seconds is _BAD:
            return _BAD
        out.append(seconds)
    return out or None


def _read_time(value, shape):
    """An absolute time as ISO-8601 UTC: Zeek's epoch seconds (as text in Malcolm's text logs), or the ISO time a
    shipper converted it to. A time no datetime can hold is malformed."""
    if isinstance(value, str) and _DECIMAL.match(value.strip()):
        value = float(value)
    try:
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            if not 0 <= value < float("inf"):
                return _BAD
            return (_EPOCH + timedelta(seconds=value)).isoformat()
        if isinstance(value, str):
            text = value.strip()
            when = datetime.fromisoformat(text.replace("Z", "+00:00") if text.endswith("Z") else text)
            return (when if when.tzinfo else when.replace(tzinfo=UTC)).astimezone(UTC).isoformat()
    except (ValueError, OverflowError, OSError):
        pass
    return _BAD


READERS = {"ip": _read_ip, "port": lambda v, s: _read_count(v, s, 65535), "count": _read_count,
           "seconds": _read_seconds, "text": _read_text, "flag": _read_flag, "services": _read_services,
           "names": _read_names, "mac": _read_mac, "list": _read_vector, "text1": _read_text1,
           "count_text": _read_count_text, "time": _read_time, "hex": _read_hex, "hexes": _read_hexes,
           "addresses": _read_addresses, "seconds_list": _read_seconds_list}
# divisors to seconds (a division of two exact integers is correctly rounded; a product with 1e-9 is not)
_UNITS = {"ns": 1e9, "ms": 1e3}


@dataclass(frozen=True, slots=True)
class _Path:
    """One compiled catalog path: where to look, in the record or in the Zeek line kept in event.original."""
    key: str
    original: bool
    divisor: float | None
    origin: str                     # the origin after "<id>:"; also the name a malformed value is listed under


@lru_cache(maxsize=4096)            # every (field, shape) pair of the catalog fits (about 1,600)
def _compiled(spec: ZeekField, shape: str) -> tuple[tuple[_Path, ...], object]:
    paths = []
    for path in spec.paths.get(shape, ()):
        divisor = None
        if path.endswith((":ns", ":ms")):
            path, divisor = path[:-3], _UNITS[path[-2:]]
        if path.startswith("original:"):
            key = path[len("original:"):]
            paths.append(_Path(key, True, divisor, f"event.original#original.{key}"))
        else:
            paths.append(_Path(path, False, divisor, path))
    return tuple(paths), READERS[spec.kind]


class _Reader:
    """Reads one record's catalogued fields, in one shape, collecting the malformed ones."""

    def __init__(self, hit: dict, shape: str):
        self.src, self.nid, self.shape = hit["_source"], hit["_id"], shape
        self.bad: list[str] = []
        self._original = _MISSING
        self._literal: bool | None = None       # whether the record holds a literal dotted key anywhere

    def get(self, path: str):
        """The value at a path, or _MISSING. A value standing where the path needs an object (a string where
        `zeek` or `source` should be) and a path the record writes twice with different values (nested and
        literal) are listed as malformed, never read past or silently resolved."""
        parts = _parts(path)
        if self._literal is None:
            self._literal = _has_dotted_keys(self.src)
        if self._literal:
            value = _resolve(self.src, parts)
            if value is _CONFLICT:
                self.bad.append(path)
                return _MISSING
            if value is not _MISSING:
                return value
        cur = self.src
        for depth, part in enumerate(parts):
            if cur is None:
                return _MISSING
            if not isinstance(cur, dict):
                self.bad.append(".".join(parts[:depth]))
                return _MISSING
            if part not in cur:
                return _MISSING
            cur = cur[part]
        return cur

    def original(self):
        """The Zeek line Elastic keeps in event.original, parsed once; None when absent or not a JSON object."""
        if self._original is _MISSING:
            self._original = None
            text = self.get("event.original")
            if _present(text):
                try:
                    parsed = json.loads(text) if isinstance(text, str) else None
                except json.JSONDecodeError:
                    parsed = None
                if isinstance(parsed, dict):
                    self._original = parsed
                else:
                    self.bad.append("event.original")
        return self._original

    def field(self, spec: ZeekField) -> FieldValue | None:
        paths, read = _compiled(spec, self.shape)
        for path in paths:
            if path.original:
                parsed = self.original()
                value = _MISSING if parsed is None else dotted(parsed, path.key)
            else:
                value = self.get(path.key)
            if not _present(value):
                continue
            typed = read(value, self.shape)
            if typed is _BAD:
                self.bad.append(path.origin)
                return None
            if typed is None:
                return None
            if path.divisor is not None:
                typed = typed / path.divisor
            return fv(typed, f"{self.nid}:{path.origin}")
        return None


def _time(reader: _Reader, log: ZeekLog) -> tuple[datetime, str]:
    """The record's first-packet time (Zeek's ts) and its origin. An error when no candidate is readable."""
    for path in log.time_paths.get(reader.shape, ()):
        unit = None
        if path.endswith(":ms"):
            path, unit = path[:-3], "ms"
        value = reader.get(path)
        if not _present(value):
            continue
        try:
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                # epoch arithmetic, not fromtimestamp: the platform's C library limits that one (to year 3000)
                when = _EPOCH + timedelta(seconds=value / 1000 if unit == "ms" else value)
            elif isinstance(value, str):
                when = datetime.fromisoformat(value.replace("Z", "+00:00") if value.endswith("Z") else value)
                when = (when if when.tzinfo else when.replace(tzinfo=UTC)).astimezone(UTC)
            else:
                raise TypeError
        except (TypeError, ValueError, OverflowError, OSError):
            raise ValueError(f"zeek {log.name} record's first-packet time at {path} is not a time") from None
        return when, f"{reader.nid}:{path}"
    raise ValueError(f"zeek {log.name} record has no first-packet time")


def _sensor(reader: _Reader, log: ZeekLog) -> FieldValue | None:
    """The sensor at the first of the shape's paths the record writes; a value that is not one name is malformed."""
    for path in log.sensor_paths.get(reader.shape, ()):
        value = reader.get(path)
        if not _present(value):
            continue
        if isinstance(value, str) and value.strip():
            return fv(value.strip(), f"{reader.nid}:{path}")
        reader.bad.append(path)
        return None
    return None


def _credentials_present(reader: _Reader, log: ZeekLog) -> str | None:
    """The path of a password value the record carries, never the value itself."""
    paths = ["related.password", "url.password"] if reader.shape == MALCOLM else []
    log_object = log.log_objects.get(reader.shape)
    if log_object is not None:
        paths.append(f"{log_object}.password" if log_object else "password")
    for path in paths:
        if _present(reader.get(path)):
            return path
    return None


def _services(value: list[str]) -> tuple[list[str], list[str]]:
    """(confirmed services, services Zeek removed after a protocol violation, written with a leading "-")."""
    confirmed, removed = [], []
    for item in value:
        target = removed if item.startswith("-") else confirmed
        name = item.lstrip("-").removeprefix(_SERVICE_PREFIX)
        for suffix in _SERVICE_SUFFIXES:
            name = name.removesuffix(suffix)
        if name and name not in target:
            target.append(name)
    return confirmed, removed


def _raw_ref(hit: dict) -> RawRef:
    encoded = json.dumps(hit["_source"], sort_keys=True, separators=(",", ":")).encode()
    return RawRef(target=hit["_index"], native_id=hit["_id"], digest=hashlib.sha256(encoded).hexdigest())


def _canonical(value):
    """A typed value in a form whose repr is canonical: str, int, float, bool and lists of them as they are; objects
    (certificates, DNS answers) as sorted-key JSON."""
    if isinstance(value, dict) or (isinstance(value, list) and any(isinstance(item, dict) for item in value)):
        return json.dumps(value, sort_keys=True)
    return value


def _signature(fields: dict[str, FieldValue]) -> str:
    """A digest of the record's typed values (never origins): two copies of one Zeek row agree, two different rows
    sharing a uid (interim and final conn rows) do not."""
    items = sorted((name, _canonical(value.value)) for name, value in fields.items() if name not in _UNSIGNED)
    return hashlib.sha256(repr(items).encode()).hexdigest()[:20]


# ---- normalization ---------------------------------------------------------------------------------------------

def normalize_zeek(hit: dict, record: ZeekRecord, *, sensor: str | None = None) -> TypedEvent:
    """One recognized Zeek record as a typed event. `sensor` is the site-declared sensor of plain Zeek JSON."""
    if record.log is None:
        if not record.names:
            raise ValueError(f"{SHAPE_NAMES[record.shape]} Zeek record names no log at {record.origin}")
        raise ZeekNotNormalized(record.unsupported)
    if record.log is CONN:
        return _conn(hit, record, sensor)
    return _analyzer(hit, record, sensor)


def normalize_plain_zeek(hit: dict, log: str | None = None, sensor: str | None = None) -> TypedEvent:
    """A record of a target the site declares as plain Zeek JSON (`log`: the declared log, used when the record
    has no `_path`; `sensor`: the declared sensor name)."""
    return normalize_zeek(hit, plain_record(hit["_source"], log), sensor=sensor)


def _conn(hit: dict, record: ZeekRecord, declared_sensor: str | None) -> TypedEvent:
    shape, log = record.shape, record.log
    reader = _Reader(hit, shape)
    nid = reader.nid
    when, time_origin = _time(reader, log)
    f: dict[str, FieldValue] = {}
    for spec in log.fields:
        value = reader.field(spec)
        if value is not None:
            f[spec.typed] = value
    caveats: list[str] = []
    f["observer.product"] = fv("zeek", f"{nid}:{record.recognized_by}#producer")
    f["zeek.log"] = fv(log.name, f"{nid}:{record.origin}")
    if len(record.names) > 1:
        f["zeek.datasets"] = fv(list(record.names), f"{nid}:{record.origin}")
    sensor = _sensor(reader, log) if shape != PLAIN else (
        fv(declared_sensor, f"{nid}:#declared:sensor") if declared_sensor else None)
    if sensor is not None:
        f["observer.name"] = sensor
    _transport(f)
    _icmp(f, reader)
    services = f.pop("network.protocols", None)
    if services is not None:
        confirmed, removed = _services(services.value)
        if confirmed:
            f["network.protocols"] = fv(confirmed, services.origin)
            if len(confirmed) == 1:
                f["network.app_proto"] = fv(confirmed[0], f"{services.origin}#derived:sole-service")
        if removed:
            f["network.protocols_removed"] = fv(removed, f"{services.origin}#derived:removed-services")
    f["flow.start"] = fv(when.isoformat(), time_origin)
    _end(f, reader, when, time_origin)
    payload_paths = [log.spec(name).paths[shape][0] for name in ("flow.bytes_toserver", "flow.bytes_toclient")]
    f["flow.bytes_are_payload"] = fv(True, f"{nid}:{'+'.join(payload_paths)}#semantics")
    history = f.get("conn.history")
    transport = f.get("network.transport")
    if history is not None and transport is not None and transport.value == "tcp" \
            and history.value.startswith("S") and "^" not in history.value:
        # the first packet Zeek saw was the originator's SYN, and Zeek did not flip the direction
        f["tcp.opened_by_orig"] = fv(True, f"{history.origin}#derived:opened-by-orig")
    if "network.community_id" not in f:
        computed = community_id(*(f[name].value if name in f else None for name in
                                  ("source.ip", "source.port", "destination.ip", "destination.port",
                                   "network.transport")))
        if computed is not None:
            f["network.community_id"] = fv(computed, f"{nid}:id.orig_h+id.orig_p+id.resp_h+id.resp_p+proto"
                                                     f"#computed:community_id_v1")
    if record.names == ("conn_long",) and "conn.interim" not in f:
        f["conn.interim"] = fv(True, f"{nid}:{record.origin}")
    if f.get("conn.interim") is not None and f["conn.interim"].value is not True:
        del f["conn.interim"]
    missed = f.get("conn.missed_bytes")
    if missed is not None and missed.value > 0:
        caveats.append(MISSED_BYTES_CAVEAT.format(n=missed.value))
    if history is not None and "g" in history.value.lower():
        caveats.append(CONTENT_GAP_CAVEAT)
    if history is not None and "x" in history.value.lower():
        caveats.append(PARTIAL_CAVEAT)
    if "conn.interim" in f:
        caveats.append(INTERIM_CAVEAT)
    tags = reader.get("tags")
    if shape == MALCOLM and "_missing_timestamp" in (tags if isinstance(tags, list) else [tags]):
        caveats.append(MALCOLM_MISSING_TS_CAVEAT)
    password = _credentials_present(reader, log)
    if password is not None:
        f["auth.cleartext_credentials_present"] = fv(True, f"{nid}:{password}#present")
    if reader.bad:
        f["parse.malformed"] = fv(sorted(set(reader.bad)), f"{nid}:#malformed")
    ref = _raw_ref(hit)
    uid = f.get("zeek.uid")
    host = sensor.value if sensor is not None else None
    # a record a password was withheld from is its own document (see the analyzer logs' identity below)
    identity = [ref] if uid is None or password is not None else [
        RawRef(target=f"zeek:{host or ''}:{log.name}", native_id=f"{uid.value}|{_signature(f)}")]
    return TypedEvent(id=event_id(log.family, identity, ZEEK_NORMALIZER), family=log.family, ts=when, host=host,
                      fields=f, raw=[ref], normalizer=ZEEK_NORMALIZER, caveats=caveats)


def _end(f: dict[str, FieldValue], reader: _Reader, when: datetime, time_origin: str) -> None:
    """flow.end from the first-packet time and the duration. A duration no time span can hold is malformed (and
    dropped); when the end lies beyond any representable time, flow.end is left out and the pair listed, never
    guessed."""
    duration = f.get("session.duration_s")
    if duration is None:
        return
    duration_path = duration.origin.split(":", 1)[1]
    try:
        span = timedelta(seconds=duration.value)
    except OverflowError:
        reader.bad.append(duration_path)
        del f["session.duration_s"]
        return
    try:
        end = when + span
    except OverflowError:
        reader.bad.append(f"{time_origin.split(':', 1)[1]}+{duration_path}")
        return
    f["flow.end"] = fv(end.isoformat(), f"{time_origin}+{duration_path}")


def _transport(f: dict[str, FieldValue]) -> None:
    """Zeek's proto, lowercased; ICMP named by the address family (Zeek writes "icmp" for ICMPv6 too), and an
    unknown transport by the IP protocol number when Zeek wrote it."""
    value = f.get("network.transport")
    if value is None:
        return
    transport = value.value.lower()
    if transport in ICMP_TRANSPORTS:
        addresses = [f[name].value for name in ("source.ip", "destination.ip") if name in f]
        if len(addresses) == 2:         # without both, the family is not known and Zeek's word stands
            v6 = any(ipaddress.ip_address(address).version == 6 for address in addresses)
            transport = "ipv6-icmp" if v6 else "icmp"
    elif transport == "unknown_transport" and "network.iana_number" in f:
        number = f["network.iana_number"]
        f["network.transport"] = fv(IP_PROTOCOLS.get(number.value, str(number.value)), number.origin)
        return
    f["network.transport"] = fv(transport, value.origin)


def _icmp(f: dict[str, FieldValue], reader: _Reader) -> None:
    """ICMP type from Zeek's originator port; the code only from a field that holds nothing else."""
    transport = f.get("network.transport")
    if transport is None or transport.value not in ICMP_TRANSPORTS:
        return
    explicit = {}
    if reader.shape == ELASTIC:
        # Zeek's names under the log object, as some Elastic-shaped pipelines keep them
        for typed, path in (("icmp.type", "zeek.connection.icmp_type"), ("icmp.code", "zeek.connection.icmp_code")):
            value = reader.get(path)
            if value is not _MISSING:
                explicit[typed] = (value, f"{reader.nid}:{path}")
    if "icmp.type" not in explicit and "source.port" in f:
        explicit["icmp.type"] = (f["source.port"].value, f"{f['source.port'].origin}#zeek-icmp-type")
    for typed, (value, origin) in explicit.items():
        if value is None:
            continue
        number = _read_count(value, ELASTIC, 255)      # strict: a JSON integer, never text
        if number is _BAD:
            reader.bad.append(typed)
        else:
            f[typed] = fv(number, origin)


def superseded_interim(events: list[TypedEvent]) -> list[TypedEvent]:
    """The Zeek interim conn events a later record of the same connection (sensor and uid) supersedes: every interim
    event of a connection whose final conn record is present, else all but the latest interim one. Interim counters
    are totals to the moment of writing, so keeping them beside a later record would count the connection twice."""
    groups: dict[tuple, list[TypedEvent]] = defaultdict(list)
    for event in events:
        if event.normalizer == ZEEK_NORMALIZER and event.get("zeek.log") == "conn" and event.has("zeek.uid"):
            groups[(event.host, event.get("zeek.uid"))].append(event)
    out = []
    for members in groups.values():
        interim = [e for e in members if e.get("conn.interim") is True]
        if not interim:
            continue
        if len(interim) < len(members):
            out.extend(interim)
            continue
        latest = max(interim, key=lambda e: (e.get("session.duration_s") or 0.0, e.get("flow.bytes_toserver") or 0,
                                             e.get("flow.bytes_toclient") or 0, e.id))
        out.extend(e for e in interim if e is not latest)
    return out


# ---- the analyzer logs ---------------------------------------------------------------------------------------------
#
# Each analyzer log's record is typed through its catalog table, then by the log's own step below. Shared by all:
# - `zeek.ts` (the record's time, as its origin names it), `observer.product`, `observer.name` and `zeek.log`;
# - `network.transport` from Zeek's proto when the record has one, else the analyzer's only transport (origin
#   `#derived:analyzer-transport`); the Community ID as the shipper wrote it, else computed from the 5-tuple;
# - `auth.cleartext_credentials_present: True` when the record carries a credential sent in cleartext (a password
#   column, a Basic-auth username, a credential command's argument, an SNMPv1/v2c community, a SOCKS5 user, a URI's
#   userinfo, a password literal in SQL, a password in a Redis reply), and `auth.cleartext_credentials_unknown: True`
#   when text that can carry one was withheld because it could not be read (an argument of an unreadable command, an
#   ambiguous reply): the origin names where, the value itself is never kept;
# - identity: (sensor, log, the record's key, its time, its sequence, its typed values), so copies of one row merge;
#   a record a value was withheld from is identified by its own document (index and id) instead.

ZEEK_TRUNCATED_FILE = ("Zeek did not see {n} bytes of this file (missing_bytes): its hashes, type and content "
                       "checks describe only the bytes it saw")
ZEEK_OVERFLOW_FILE = ("{n} bytes of this file arrived beyond Zeek's reassembly buffer (overflow_bytes) and were not "
                      "analyzed: its hashes and content checks describe only the bytes Zeek analyzed")
ZEEK_TIMEDOUT_FILE = ("Zeek stopped analyzing this file when it went idle (timedout): its hashes, size and content "
                      "checks describe only the bytes seen before then")
ZEEK_FIRST_HOST_ONLY = ("the shipper keeps only the first of Zeek's sending and receiving hosts of this file "
                        "(tx_hosts, rx_hosts): other hosts that carried it are not typed")
ZEEK_ARGUMENT_WITHHELD = ("an argument of this record was not typed: its command is missing or could not be read, or "
                          "is one whose argument can be a credential (a password, a key) that cannot be told from any "
                          "other")
ZEEK_IRC_STALE = ("Zeek logs one IRC record per connection again for each command, so on this row {fields} still held "
                  "an earlier command's values: they were not typed")
ZEEK_X509_NAME_PARTS = ("Elastic keeps this certificate's subject and issuer only split into attributes (the whole "
                        "names are in its Zeek line, kept only with its preserve_original_event tag): they are typed "
                        "from their CN and O, and compared by them")
_ZEEK_VERSION = re.compile(r"^(D?TLS)v(\d)(\d)$")
_MNEMONIC = re.compile(r"^[A-Za-z][A-Za-z0-9-]*$")
# the names Zeek gives a query type or reply code it has no mnemonic for (base/protocols/dns/consts.zeek)
_DEFAULT_NAME = re.compile(r"^(?:query|rcode)-(\d+)$")
_DNS_FLAGS = ("AA", "TC", "RD", "RA")


def _analyzer(hit: dict, record: ZeekRecord, declared_sensor: str | None) -> TypedEvent:
    shape, log = record.shape, record.log
    reader = _Reader(hit, shape)
    nid = reader.nid
    when, time_origin = _time(reader, log)
    f: dict[str, FieldValue] = {}
    for spec in log.fields:
        value = reader.field(spec)
        if value is not None:
            f[spec.typed] = value
    caveats: list[str] = []
    f["observer.product"] = fv("zeek", f"{nid}:{record.recognized_by}#producer")
    f["zeek.log"] = fv(log.name, f"{nid}:{record.origin}")
    if len(record.names) > 1:
        f["zeek.datasets"] = fv(list(record.names), f"{nid}:{record.origin}")
    sensor = _sensor(reader, log) if shape != PLAIN else (
        fv(declared_sensor, f"{nid}:#declared:sensor") if declared_sensor else None)
    if sensor is not None:
        f["observer.name"] = sensor
    f["zeek.ts"] = fv(when.isoformat(), time_origin)
    guard = _Guard()
    for path in _secret_paths(log, shape):
        if _present(reader.get(path)):          # a password column: never read, its presence typed
            guard.present.append(path)
            guard.withheld = True
    step = _STEPS.get(log.name)
    if step is not None:
        step(f, reader, log, caveats, guard)
    _withhold_arguments(f, reader, log, caveats, guard)
    _strip_userinfo(f, log, caveats, guard)
    if log.family == "app_tx":
        f["app.protocol"] = fv(log.name, f"{nid}:{record.origin}")
    if log.family == "net_alert":
        f["alert.provider"] = fv("zeek", f"{nid}:{record.recognized_by}#producer")
        f["alert.kind"] = fv(_ALERT_KINDS[log.name], f"{nid}:{record.origin}")
    if "network.transport" in f:
        _transport(f)
    elif log.transport is not None:
        f["network.transport"] = fv(log.transport, f"{nid}:{record.origin}#derived:analyzer-transport")
    if "network.community_id" not in f:
        computed = community_id(*(f[name].value if name in f else None for name in
                                  ("source.ip", "source.port", "destination.ip", "destination.port",
                                   "network.transport")))
        if computed is not None:
            f["network.community_id"] = fv(computed, f"{nid}:id.orig_h+id.orig_p+id.resp_h+id.resp_p+proto"
                                                     f"#computed:community_id_v1")
    if guard.present:
        f["auth.cleartext_credentials_present"] = fv(True, f"{nid}:{'+'.join(dict.fromkeys(guard.present))}#present")
    elif guard.unknown:
        f["auth.cleartext_credentials_unknown"] = fv(True, f"{nid}:{'+'.join(dict.fromkeys(guard.unknown))}#unknown")
    tags = reader.get("tags")
    if shape == MALCOLM and "_missing_timestamp" in (tags if isinstance(tags, list) else [tags]):
        caveats.append(MALCOLM_MISSING_TS_CAVEAT)
    if reader.bad:
        f["parse.malformed"] = fv(sorted(set(reader.bad)), f"{nid}:#malformed")
    ref = _raw_ref(hit)
    host = sensor.value if sensor is not None else None
    key = next((f[name].value for name in log.key if name in f), None)
    if key is None or guard.withheld:
        # A record a value was withheld from is its own document: rows that differ only in what was withheld (five
        # AUTH attempts in one connection and one millisecond) stay apart, and the same document read twice merges.
        identity = [ref]
    else:
        sequence = "|".join(str(f[name].value) if name in f else "" for name in log.sequence)
        identity = [RawRef(target=f"zeek:{host or ''}:{log.name}",
                           native_id=f"{key}|{when.isoformat()}|{sequence}|{_signature(f)}")]
    return TypedEvent(id=event_id(log.family, identity, ZEEK_NORMALIZER), family=log.family, ts=when, host=host,
                      fields=f, raw=[ref], normalizer=ZEEK_NORMALIZER, caveats=caveats)


_ALERT_KINDS = {"notice": "notice", "weird": "weird", "signatures": "signature", "intel": "intel"}
# where Malcolm puts any log's password column (it lifts every `password` to related.password and builds http's
# url.password from it)
_MALCOLM_PASSWORDS = ("related.password", "url.password")


def _secret_paths(log: ZeekLog, shape: str) -> list[str]:
    """Where a record of this log and shape may carry a credential: the catalog's paths, and any log's own
    `password` column where the shape keeps unrenamed columns."""
    paths = list(log.secrets.get(shape, ()))
    defaults = list(_MALCOLM_PASSWORDS) if shape == MALCOLM else []
    log_object = log.log_objects.get(shape)
    if log_object is not None:
        defaults.append(f"{log_object}.password" if log_object else "password")
    return paths + [path for path in defaults if path not in paths]


@dataclass
class _Guard:
    """What a record's credentials did to its typed event: where one certainly travels, where one may, and whether a
    value was withheld (left untyped) for it. Lists of paths (path#what), never values."""
    present: list[str] = field(default_factory=list)
    unknown: list[str] = field(default_factory=list)
    withheld: bool = False


@dataclass(frozen=True)
class _CommandArguments:
    """A log whose command's argument can be a credential: the typed command, the typed fields its arguments are
    written to, and per command (as sent, compared stripped and uppercased) which of those fields are a credential
    (`present`) or may hold one (`unknown`). `sql`: the argument is SQL text, whose password literals are redacted,
    and `echoes` the fields where the server may quote it back (an error naming the text near a syntax error). A
    record whose command is missing or unreadable keeps none of its arguments."""
    command: str
    arguments: tuple[str, ...]
    present: dict[str, tuple[str, ...]]
    unknown: dict[str, tuple[str, ...]]
    sql: bool = False
    echoes: tuple[str, ...] = ()


_IRC_ARGUMENTS = ("app.arg", "irc.addl")
_COMMAND_ARGUMENTS = {
    # RFC 959 PASS <password> and ACCT <account-information>, RFC 2228 ADAT <base64 security data>
    "ftp": _CommandArguments("app.command", ("app.arg",),
                             {name: ("app.arg",) for name in ("PASS", "ACCT", "ADAT")}, {}),
    # RFC 2812 PASS <password> and OPER <name> <password>, JOIN's channel keys (Zeek writes them to addl), IRCv3
    # SASL AUTHENTICATE <base64 credentials>, and services commands sent as commands (NICKSERV/NS IDENTIFY <password>)
    "irc": _CommandArguments("app.command", _IRC_ARGUMENTS,
                             {**{name: _IRC_ARGUMENTS for name in ("PASS", "OPER", "AUTHENTICATE", "NICKSERV", "NS",
                                                                     "IDENTIFY")}, "JOIN": ("irc.addl",)}, {}),
    # AUTH [username] password; HELLO <protover> AUTH <username> <password>; MIGRATE ... AUTH <password> / AUTH2
    # <username> <password>; CONFIG SET requirepass/masterauth/masteruser; ACL SETUSER <user> ><password>. Zeek types
    # only the command's name and key: AUTH's key is a credential, the others may carry one beyond it.
    "redis": _CommandArguments("app.command", ("app.arg",), {"AUTH": ("app.arg",)},
                               {name: ("app.arg",) for name in ("HELLO", "MIGRATE", "CONFIG", "ACL")}),
    # COM_CHANGE_USER's argument is the new user's authentication data until Zeek's parser reduces it to the user
    # name; a query's text can set or compare a password (IDENTIFIED BY, SET PASSWORD, MASTER_PASSWORD=), and an
    # error response quotes the text near a syntax error
    "mysql": _CommandArguments("app.command", ("app.arg",), {}, {"CHANGE_USER": ("app.arg",)}, sql=True,
                               echoes=("app.reply",)),
    # a simple query's text can set or compare a password (CREATE ROLE ... PASSWORD '...'); an error's fields can
    # quote it
    "postgresql": _CommandArguments("app.command", ("app.arg",), {}, {}, sql=True,
                                    echoes=("postgresql.backend_arg",)),
}
# IRC services that take a password in a message (NickServ IDENTIFY, AuthServ AUTH, QuakeNet's Q, Undernet's X), and the
# services commands that carry one as their first words
_IRC_SERVICES = frozenset({"nickserv", "ns", "chanserv", "cs", "authserv", "q", "x", "operserv", "os", "hostserv"})
_IRC_SERVICE_COMMANDS = frozenset({"IDENTIFY", "AUTH", "LOGIN", "REGISTER", "GHOST", "RECOVER", "RELEASE", "REGAIN",
                                   "SETPASS", "PASSWORD", "OPER"})
_IRC_MESSAGES = frozenset({"PRIVMSG", "NOTICE", "SQUERY"})
# Zeek's IRC script keeps one record per connection and logs it again for each command, setting only that command's
# columns (base/protocols/irc/main.zeek, dcc-send.zeek): NICK sets the value, USER the value and addl, JOIN the value
# and addl (the channel key), and a DCC row is the record as the last command left it, with the dcc_* columns set. So
# these columns of a row hold an earlier command's values (a JOIN's key among them): they are not typed.
_IRC_STALE = {"DCC": ("app.arg", "irc.addl")}
_IRC_FRESH = frozenset({"USER", "JOIN"})
# how Zeek writes a JOIN's channel key into addl
_IRC_CHANNEL_KEY = "with channel key:"
# the most redacted values whose echo is removed from a reply; with more, the reply is withheld
_ECHO_LIMIT = 32
# the typed values of each log that hold a URI, a SIP URI, or a host name
_URI_FIELDS = {"http": ("url.original", "http.request.referrer", "http.request.origin"), "ftp": ("app.arg",),
               "intel": ("intel.indicator",), "mysql": ("app.arg",), "postgresql": ("app.arg",)}
_SIP_FIELDS = {"sip": ("app.arg", "sip.request_from", "sip.request_to")}
_HOST_FIELDS = {"http": ("http.hostname",)}


def _raw_path(reader: _Reader, log: ZeekLog, typed: str) -> str | None:
    """The path of the record's value for a typed field, whether or not that value could be typed."""
    paths, _read = _compiled(log.spec(typed), reader.shape)
    for path in paths:
        if path.original:
            parsed = reader.original()
            value = _MISSING if parsed is None else dotted(parsed, path.key)
        else:
            value = reader.get(path.key)
        if _present(value):
            return path.origin
    return None


def _withhold_arguments(f: dict[str, FieldValue], reader: _Reader, log: ZeekLog, caveats: list[str],
                        guard: _Guard) -> None:
    """Drop the arguments of a credential command (and of a command that cannot be read) before they are kept, drop
    the IRC columns a row holds from an earlier command, and redact the password literals of SQL text."""
    rule = _COMMAND_ARGUMENTS.get(log.name)
    if rule is None:
        return
    written = {typed: path for typed in rule.arguments if (path := _raw_path(reader, log, typed)) is not None}
    command = f.get(rule.command)
    name = command.value.strip().upper() if command is not None and isinstance(command.value, str) else ""

    def withhold(fields: tuple[str, ...], into: list[str], what: str) -> None:
        for typed in fields:
            if typed in written:
                f.pop(typed, None)
                into.append(f"{written[typed]}#{what}")
                guard.withheld = True
                if into is guard.unknown and ZEEK_ARGUMENT_WITHHELD not in caveats:
                    caveats.append(ZEEK_ARGUMENT_WITHHELD)

    if not name:                                    # missing, empty or unreadable: fail closed
        withhold(rule.arguments, guard.unknown, "unread-command")
        return
    if name in rule.present:
        if not any(typed in written for typed in rule.present[name]) and set(rule.present[name]) == set(
                rule.arguments):
            # the command itself sends a credential (PASS, AUTH, ...), whether or not its argument was logged: the
            # row is its own document, like one whose argument was withheld
            guard.present.append(f"{_path(command)}#{name.lower()}-command")
            guard.withheld = True
        withhold(rule.present[name], guard.present, f"{name.lower()}-argument")
    if name in rule.unknown:
        withhold(rule.unknown[name], guard.unknown, f"{name.lower()}-argument")
    if log.name == "irc" and name not in rule.present and name not in _IRC_FRESH:
        _irc_stale(f, name, caveats, guard)
    if rule.sql:
        _redact_sql(f, rule, caveats, guard)


def _irc_stale(f: dict[str, FieldValue], name: str, caveats: list[str], guard: _Guard) -> None:
    """Drop what a row holds from an earlier command: a DCC row's value and addl, any other row's addl (only USER and
    JOIN write their own). A dropped JOIN key is a credential the row carried; a message to a services nick may be
    one."""
    dropped = []
    for typed in _IRC_STALE.get(name, ("irc.addl",)):
        value = f.pop(typed, None)
        if value is None:
            continue
        dropped.append(_native(value))
        if typed != "irc.addl" or not isinstance(value.value, str):
            continue
        if value.value.strip().startswith(_IRC_CHANNEL_KEY):
            guard.present.append(f"{_native(value)}#earlier-channel-key")
            guard.withheld = True
        elif name in _IRC_MESSAGES:
            target = f.get("app.arg")
            nick = target.value.strip().split("@", 1)[0].lower() if target is not None else ""
            first = value.value.strip().split(" ", 1)[0].lstrip(":").upper()
            if nick in _IRC_SERVICES or first in _IRC_SERVICE_COMMANDS:
                guard.unknown.append(f"{_native(value)}#services-message")
                guard.withheld = True
    if dropped:
        caveats.append(ZEEK_IRC_STALE.format(fields=" and ".join(dropped)))


def _redact_sql(f: dict[str, FieldValue], rule: _CommandArguments, caveats: list[str], guard: _Guard) -> None:
    """Redact the password literals of a statement, and their echo in the server's reply on the same row (withheld
    when the statement could not be read, or held more credentials than are looked for)."""
    value = f.get("app.arg")
    if value is None or not isinstance(value.value, str):
        return
    result = scrub_sql(value.value)
    _scrubbed(f, "app.arg", value, result, caveats, guard, "sql")
    if not (result.redacted or result.unread):
        return
    secrets = sorted({secret for secret in result.secrets if len(secret) >= 2}, key=len, reverse=True)
    for typed in rule.echoes:
        echo = f.get(typed)
        if echo is None or not isinstance(echo.value, str):
            continue
        if result.unread or len(secrets) > _ECHO_LIMIT:
            del f[typed]
            guard.unknown.append(f"{_native(echo)}#statement-echo")
            guard.withheld = True
            continue
        text = echo.value
        for secret in secrets:
            text = text.replace(secret, REDACTED)
        if text != echo.value:
            f[typed] = fv(text, f"{echo.origin}#derived:credentials-redacted")
            guard.present.append(f"{_native(echo)}#statement-echo")
            guard.withheld = True


def _scrubbed(f: dict[str, FieldValue], typed: str, value: FieldValue, result: Scrubbed, caveats: list[str],
              guard: _Guard, what: str) -> None:
    """Keep a value with its credentials redacted (or withhold it whole), and say what was found."""
    if result.text is None:
        del f[typed]
        guard.withheld = True
    elif result.text != value.value:
        f[typed] = fv(result.text, f"{value.origin}#derived:credentials-redacted")
        guard.withheld = True
    if result.redacted:
        guard.present.append(f"{_native(value)}#{what}-credential")
    if result.unread or result.text is None:
        guard.unknown.append(f"{_native(value)}#unread-{what}")
    caveats.extend(caveat for caveat in result.caveats if caveat not in caveats)


def _strip_userinfo(f: dict[str, FieldValue], log: ZeekLog, caveats: list[str], guard: _Guard) -> None:
    """Remove the userinfo of every URI a typed value holds (a password, or a token sent as the user), the password of
    a SIP URI's userinfo, and a user part written before a host name."""
    for typed in _URI_FIELDS.get(log.name, ()):
        value = f.get(typed)
        if value is None or not isinstance(value.value, str):
            continue
        text, removed, password = strip_uri_userinfo(value.value)
        if removed:
            f[typed] = fv(text, _derived(value, "userinfo-removed"))
            (guard.present if password else guard.unknown).append(f"{_native(value)}#uri-userinfo")
            guard.withheld = True
    for typed in _SIP_FIELDS.get(log.name, ()):
        value = f.get(typed)
        if value is None or not isinstance(value.value, str):
            continue
        text, removed = strip_sip_password(value.value)
        if text is None:                    # more SIP URIs than are read: withheld whole
            del f[typed]
            guard.unknown.append(f"{_native(value)}#unread-sip-uris")
            guard.withheld = True
            if SIP_UNREAD not in caveats:
                caveats.append(SIP_UNREAD)
        elif removed:
            f[typed] = fv(text, _derived(value, "password-removed"))
            guard.present.append(f"{_native(value)}#sip-userinfo")
            guard.withheld = True
    for typed in _HOST_FIELDS.get(log.name, ()):
        value = f.get(typed)
        if value is not None and isinstance(value.value, str) and "@" in value.value:
            userinfo, _at, host = value.value.rpartition("@")
            f[typed] = fv(host, _derived(value, "userinfo-removed"))
            (guard.present if ":" in userinfo else guard.unknown).append(f"{_native(value)}#host-userinfo")
            guard.withheld = True


def _derived(value: FieldValue, how: str) -> str:
    """A changed value's origin: its own, marked derived once."""
    return value.origin if "#derived:" in value.origin else f"{value.origin}#derived:{how}"


def _path(value: FieldValue) -> str:
    """The native path a typed value was read from (its origin without the record id)."""
    return value.origin.split(":", 1)[1]


def _native(value: FieldValue) -> str:
    """The native path alone (without what was derived from it)."""
    return _path(value).split("#", 1)[0]


def _derive(f: dict[str, FieldValue], typed: str, value, source: FieldValue, how: str) -> None:
    f[typed] = fv(value, source.origin if value == source.value else f"{source.origin}#derived:{how}")


def _dns(f: dict[str, FieldValue], reader: _Reader, log: ZeekLog, caveats: list[str], guard: _Guard) -> None:
    """One dns.log row is a whole transaction (question and reply): it is typed with no `dns.type`, which is how the
    shared contract names a transaction record. Names, types and reply codes are typed as one-element lists and
    scalars; answers as the shared answer objects (Zeek writes no answer's owner name or type), with their TTLs when
    Zeek wrote one for each answer."""
    number = {"dns.question.type": f.pop("zeek.dns.qtype", None), "dns.response_code": f.pop("zeek.dns.rcode", None)}
    for typed, generic in (("dns.question.type", "TYPE"), ("dns.response_code", "RCODE")):
        name, code = f.get(typed), number[typed]
        if name is not None and _MNEMONIC.match(name.value) and not _DEFAULT_NAME.match(name.value):
            continue
        if code is not None:                # Zeek's name for a code it has no mnemonic for: the generic form
            f[typed] = fv(f"{generic}{code.value}", f"{code.origin}#derived:generic-mnemonic")
        elif name is not None and (match := _DEFAULT_NAME.match(name.value)):
            f[typed] = fv(f"{generic}{match.group(1)}", f"{name.origin}#derived:generic-mnemonic")
    for single, plural in (("dns.question.name", "dns.question.names"), ("dns.question.type", "dns.question.types"),
                           ("dns.response_code", "dns.response_codes")):
        if single in f:
            f[plural] = fv([f[single].value], f[single].origin)
    qclass = f.get("dns.question.class")
    if qclass is not None:                  # Zeek's class names carry a "C_" prefix that Malcolm removes
        _derive(f, "dns.question.class", qclass.value.removeprefix("C_"), qclass, "class-name")
    answers, ttls = f.pop("zeek.dns.answers", None), f.get("dns.ttls")
    if ttls is not None:
        f["dns.ttls"] = fv([_whole(t) for t in ttls.value], ttls.origin)
    if answers is not None:
        paired = ttls is not None and len(ttls.value) == len(answers.value)
        f["dns.answers"] = fv([{"name": None, "type": None, "ttl": _whole(ttls.value[i]) if paired else None,
                                "data": data} for i, data in enumerate(answers.value)],
                              answers.origin + (f"+{_path(ttls)}" if paired else ""))
    flags = [f.pop(f"zeek.dns.{flag}", None) for flag in _DNS_FLAGS]
    if all(flag is not None for flag in flags):
        f["dns.header_flags"] = fv([name for name, flag in zip(_DNS_FLAGS, flags) if flag.value],
                                   "+".join([flags[0].origin, *(_path(flag) for flag in flags[1:])]))


def _whole(seconds: float):
    """A DNS TTL as Zeek writes it (an interval): the integer it is."""
    return int(seconds) if float(seconds).is_integer() else seconds


def _http(f, reader, log, caveats, guard):
    user = f.get("user.name")
    if user is not None:
        # Zeek sets the username only from a Basic Authorization header, whose credentials travel in cleartext
        guard.present.append(f"{_path(user)}#basic-auth")


def _ssl(f, reader, log, caveats, guard):
    version = f.pop("zeek.ssl.version", None)
    if version is not None:
        match = _ZEEK_VERSION.match(version.value)
        text = f"{match.group(1)}v{match.group(2)}.{match.group(3)}" if match else version.value
        f["tls.version"] = fv([text], version.origin if text == version.value
                              else f"{version.origin}#derived:version-name")
        if version.value.startswith("DTLS"):
            # DTLS runs over UDP; a TLS version alone does not say TCP (Zeek logs QUIC's handshakes here too)
            f["network.transport"] = fv("udp", f"{version.origin}#derived:dtls")
    subject, issuer = f.pop("zeek.ssl.subject", None), f.pop("zeek.ssl.issuer", None)
    if subject is not None:
        f["tls.server.subject"] = subject
    if issuer is not None:
        f["tls.server.issuer"] = issuer
    if subject is not None or issuer is not None:
        # ssl.log names the server's own (first) certificate only; its validity and fingerprint are on the x509 row
        cert = _certificate(subject.value if subject else None, issuer.value if issuer else None)
        parts = [value for value in (subject, issuer) if value is not None]
        origin = "+".join([parts[0].origin, *(_path(value) for value in parts[1:])])
        f.update(certificate_fields([cert], origin, caveats))


def _certificate(subject: str | None, issuer: str | None, **values) -> dict:
    """A certificate in the shared contract from Zeek's one-line names (RFC 2253 order, "CN=host,O=Org,C=US")."""
    sparts, iparts = dn_parts(subject or ""), dn_parts(issuer or "")
    return {"subject_cn": [v for k, v in sparts if k == "CN"], "subject_on": [v for k, v in sparts if k == "O"],
            "issuer_cn": [v for k, v in iparts if k == "CN"], "issuer_on": [v for k, v in iparts if k == "O"],
            "subject_dn": subject, "issuer_dn": issuer, "not_before": values.get("not_before"),
            "not_after": values.get("not_after"), "valid_days": None, "alt_names": values.get("alt_names") or [],
            "sha1": None, "serial": values.get("serial")}


def _x509(f, reader, log, caveats, guard):
    fingerprint = f.get("x509.fingerprint")
    if fingerprint is not None:
        _derive(f, "x509.fingerprint", fingerprint.value.lower(), fingerprint, "lowercase")
    subject, issuer = f.get("x509.subject"), f.get("x509.issuer")
    # Elastic's attribute split of the names: used for a name whose whole text its document does not keep
    split = {name: f.pop(f"zeek.x509.{name}", None) for name in ("subject_cn", "subject_on", "issuer_cn",
                                                                 "issuer_on")}
    from_parts = {side: whole is None and (split[f"{side}_cn"] is not None or split[f"{side}_on"] is not None)
                  for side, whole in (("subject", subject), ("issuer", issuer))}
    if subject is None and issuer is None and not any(from_parts.values()):
        return
    serial = f.get("x509.serial")
    cert = _certificate(subject.value if subject else None, issuer.value if issuer else None,
                        not_before=f["x509.not_before"].value if "x509.not_before" in f else None,
                        not_after=f["x509.not_after"].value if "x509.not_after" in f else None,
                        alt_names=f["x509.san_dns"].value if "x509.san_dns" in f else None,
                        serial=serial.value.replace(":", "") if serial else None)
    for side, parts_only in from_parts.items():
        if parts_only:
            for part in ("cn", "on"):
                value = split[f"{side}_{part}"]
                cert[f"{side}_{part}"] = list(value.value) if value is not None else []
    if any(from_parts.values()):
        caveats.append(ZEEK_X509_NAME_PARTS)
    subject_key, issuer_key = name_key(cert, "subject"), name_key(cert, "issuer")
    cert["names_compared"] = "distinguished name" if cert["subject_dn"] and cert["issuer_dn"] else "CN and O"
    cert["self_issued"] = None if subject_key is None or issuer_key is None else subject_key == issuer_key
    cert["issues_other"] = False            # one certificate per row: what else it issued is not on the row
    used = [split[f"{side}_{part}"] for side, parts_only in from_parts.items() if parts_only for part in ("cn", "on")]
    parts = [value for value in (subject, issuer, *used, f.get("x509.not_before"), f.get("x509.not_after"),
                                 f.get("x509.san_dns"), serial) if value is not None]
    origin = "+".join([parts[0].origin, *(_path(value) for value in parts[1:])])
    f["x509.certificate"] = fv(cert, origin)
    if cert["self_issued"] is not None:
        f["x509.self_issued"] = fv(cert["self_issued"], f"{origin}#derived:names-compared")


_FILE_SOURCES = {"SSL": "TLS"}


def _files(f, reader, log, caveats, guard):
    """Zeek 5.1 and later write the row's connection (uid, id.*); Zeek 5.0 the sets conn_uids, tx_hosts, rx_hosts.
    Security Onion writes both layouts' identifiers to log.id.uid (a string, or 5.0's list) and 5.0's first sending
    and receiving hosts to source.ip and destination.ip, so the layout decides what those are."""
    if reader.shape == SECURITY_ONION:
        uid = reader.get("log.id.uid")
        if isinstance(uid, str) and _present(uid):
            f["zeek.uid"] = fv(uid, f"{reader.nid}:log.id.uid")
        elif isinstance(uid, list) and uid:
            uids = _read_names(uid, reader.shape)
            if uids is _BAD:
                reader.bad.append("log.id.uid")
            elif uids:
                f["file.conn_uids"] = fv(uids, f"{reader.nid}:log.id.uid")
            for side, hosts in (("source", "file.tx_hosts"), ("destination", "file.rx_hosts")):
                address = f.pop(f"{side}.ip", None)
                f.pop(f"{side}.port", None)
                if address is not None:
                    f[hosts] = fv([address.value], address.origin)
            f.pop("network.community_id", None)
        elif _present(uid):
            reader.bad.append("log.id.uid")
    if reader.shape in (ELASTIC, SECURITY_ONION) and ("file.tx_hosts" in f or "file.rx_hosts" in f):
        caveats.append(ZEEK_FIRST_HOST_ONLY)
    source = f.get("file.source")
    if source is not None:
        name = source.value.upper().removeprefix("SPICY_")
        for suffix in ("_TCP", "_UDP", "_DATA"):
            name = name.removesuffix(suffix)
        _derive(f, "file.source", _FILE_SOURCES.get(name, name), source, "analyzer-protocol")
    for typed, caveat in (("file.missing_bytes", ZEEK_TRUNCATED_FILE), ("file.overflow_bytes", ZEEK_OVERFLOW_FILE)):
        value = f.get(typed)
        if value is not None and value.value > 0:
            caveats.append(caveat.format(n=value.value))
    timedout = f.get("file.timedout")
    if timedout is not None and timedout.value:
        caveats.append(ZEEK_TIMEDOUT_FILE)


def _banner(f: dict[str, FieldValue], side: str) -> None:
    """An SSH identification string ("SSH-2.0-OpenSSH_9.6 Ubuntu-3"): its protocol version, and its software version
    up to the first space (the comments after it are not part of it), as Suricata's parser reads it."""
    banner = f.get(f"ssh.{side}.banner")
    if banner is None or not banner.value.startswith("SSH-"):
        return
    proto, sep, rest = banner.value[4:].partition("-")
    software = rest.split(" ", 1)[0].rstrip("\r\n")
    if sep and proto:
        f[f"ssh.{side}.proto_version"] = fv(proto, f"{banner.origin}#derived:banner")
    if sep and software:
        f[f"ssh.{side}.software"] = fv(software, f"{banner.origin}#derived:banner")


def _ssh(f, reader, log, caveats, guard):
    _banner(f, "client")
    _banner(f, "server")


def _ftp(f, reader, log, caveats, guard):
    user = f.get("user.name")
    if user is not None and user.value == "<unknown>":     # Zeek's value until a USER command is seen
        del f["user.name"]


def _socks(f, reader, log, caveats, guard):
    user, version = f.get("user.name"), f.get("socks.version")
    if user is not None and version is not None and version.value == 5:
        # a SOCKS5 user name is sent only by the username/password method, whose password travels in cleartext
        guard.present.append(f"{_path(user)}#socks5-userpass")


def _tunnel(f, reader, log, caveats, guard):
    for typed in ("tunnel.type", "app.command"):
        value = f.get(typed)
        if value is not None:
            _derive(f, typed, value.value.removeprefix("Tunnel::"), value, "name")


def _radius(f, reader, log, caveats, guard):
    result = f.get("app.result")
    if result is not None and result.value in ("success", "failed"):
        f["app.success"] = fv(result.value == "success", f"{result.origin}#derived:result")


def _redis(f, reader, log, caveats, guard):
    """A reply keeps everything but the credentials it carries (zeek_credentials.scrub_redis_reply)."""
    reply, command = f.get("app.reply"), f.get("app.command")
    if reply is None or not isinstance(reply.value, str):
        return
    name = command.value.strip().upper() if command is not None and isinstance(command.value, str) else ""
    _scrubbed(f, "app.reply", reply, scrub_redis_reply(reply.value, name), caveats, guard, "reply")


# SNMP's community needs no step: Zeek writes it only from an SNMPv1 or v2c message's header (an SNMPv3 header has
# none), whatever the session's version column says (that is its first message's), so it is always a cleartext
# community and only its presence is typed (the catalog's secret paths).
_STEPS = {"dns": _dns, "http": _http, "ssl": _ssl, "x509": _x509, "files": _files, "ssh": _ssh, "ftp": _ftp,
          "socks": _socks, "tunnel": _tunnel, "radius": _radius, "redis": _redis}
