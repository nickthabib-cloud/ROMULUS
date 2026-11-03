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

Secrets. Password values (Malcolm's `related.password` and `url.password`, Zeek's own `password` fields) are never
read into a typed value, an origin, a caveat or an error; only `auth.cleartext_credentials_present` is typed.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from functools import lru_cache

from romulus.evidence.community import community_id
from romulus.evidence.typed import FieldValue, RawRef, TypedEvent, event_id, fv
from romulus.evidence.zeek_catalog import (
    CONN,
    ELASTIC,
    MALCOLM,
    PLAIN,
    SECURITY_ONION,
    SHAPE_NAMES,
    ZeekField,
    ZeekLog,
    lookup_log,
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
_LOG_NAME = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")
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


@lru_cache(maxsize=4096)
def _parts(path: str) -> tuple[str, ...]:
    return tuple(path.split("."))


def _walk(cur, parts: tuple[str, ...], i: int) -> object:
    """The value at parts[i:] below `cur`, where any level may hold literal dotted keys: each way the rest of the
    path can start at a level is tried, the longest literal key first."""
    n = len(parts)
    if i == n:
        return cur
    if not isinstance(cur, dict):
        return _MISSING
    for j in range(n, i, -1):
        key = parts[i] if j == i + 1 else ".".join(parts[i:j])
        if key in cur:
            found = _walk(cur[key], parts, j)
            if found is not _MISSING:
                return found
    return _MISSING


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
    mix. The nested value is found first; literal dotted keys are searched only when there is none. _MISSING when
    absent."""
    parts = _parts(path)
    found = _nested(src, parts)
    if found is not _MISSING or len(parts) == 1:
        return found
    return _walk(src, parts, 0) if _has_dotted_keys(src) else _MISSING


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

    @property
    def token(self) -> str:
        return self.log.token if self.log is not None else "zeek"

    def skip_reason(self) -> str:
        safe = [name for name in self.names if _LOG_NAME.match(name)]
        if not safe or len(safe) != len(self.names):
            return f"Zeek log with an unrecognised name is not normalized ({SHAPE_NAMES[self.shape]})"
        return f"Zeek {'/'.join(safe)} log is not normalized ({SHAPE_NAMES[self.shape]})"


def _names(value) -> tuple[str, ...] | None:
    """The log names a dataset field carries, lowercased; None when absent or not text."""
    items = value if isinstance(value, list) else [value]
    if not items or not all(isinstance(item, str) and item.strip() for item in items):
        return None
    return tuple(dict.fromkeys(item.strip().lower() for item in items))


def _record(src: dict, shape: str, names: tuple[str, ...] | None, origin: str, recognized_by: str) -> ZeekRecord:
    if names is None:
        return ZeekRecord(shape, (), origin, None, recognized_by)
    logs = list(dict.fromkeys(log for name in names if (log := lookup_log(shape, name)) is not None))
    if len(logs) > 1:
        # a row naming several logs (Malcolm's SMB rows) is the log whose object it carries
        logs = [log for log in logs
                if log.log_objects.get(shape) and _present(_nested(src, _parts(log.log_objects[shape])))]
    return ZeekRecord(shape, names, origin, logs[0] if len(logs) == 1 else None, recognized_by)


_PROVIDER, _DATASET, _STREAM, _MODULE = (_parts(path) for path in (
    "event.provider", "event.dataset", "data_stream.dataset", "event.module"))


def zeek_record(src: dict) -> ZeekRecord | None:
    """The Zeek shape of an indexed record, from shipper-written fields only, or None for a record that is not Zeek.

    - Malcolm: `event.provider` "zeek" (its Suricata and Arkime rows name their own provider, which decides);
    - Elastic Agent and Filebeat: `event.dataset` (else `data_stream.dataset`) `zeek.<stream>`;
    - Security Onion: `event.module` "zeek" with its bare `event.dataset`.
    These shippers write the fields as objects, which is how every other normalizer reads `event.dataset` too.
    Plain Zeek JSON carries no such field: a site declares it, and `plain_record` reads it."""
    provider = _nested(src, _PROVIDER)
    if provider == "zeek":
        return _record(src, MALCOLM, _names(_nested(src, _DATASET)), "event.dataset", "event.provider")
    if provider in ("suricata", "arkime"):
        return None
    for path, parts in (("event.dataset", _DATASET), ("data_stream.dataset", _STREAM)):
        dataset = _nested(src, parts)
        if isinstance(dataset, str) and dataset.startswith("zeek."):
            return _record(src, ELASTIC, _names(dataset[len("zeek."):]), path, path)
        if _present(dataset):
            break
    if _nested(src, _MODULE) == "zeek":
        return _record(src, SECURITY_ONION, _names(_nested(src, _DATASET)), "event.dataset", "event.module")
    return None


def plain_record(src: dict, declared_log: str | None = None) -> ZeekRecord:
    """A record of a target the site declares as plain Zeek JSON: the log is Zeek's own `_path` when present, else
    the declared log. A `_path` that contradicts the declaration is an error, never a guess."""
    path = dotted(src, "_path")
    if _present(path):
        names = _names(path)
        if names is not None and declared_log and names != (declared_log.strip().lower(),):
            raise ValueError("plain Zeek record's _path names a different log than the target declares")
        return _record(src, PLAIN, names, "_path", "#declared")
    names = _names(declared_log) if declared_log else None
    return _record(src, PLAIN, names, "#declared", "#declared")


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


def _read_count(value, shape, limit=None):
    if _number_text(value, shape, _DIGITS):
        value = int(value)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0 or (limit is not None and value > limit):
        return _BAD
    return value


def _read_seconds(value, shape):
    if _number_text(value, shape, _DECIMAL):
        value = float(value)
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 <= value < float("inf"):
        return _BAD
    return float(value)


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


READERS = {"ip": _read_ip, "port": lambda v, s: _read_count(v, s, 65535), "count": _read_count,
           "seconds": _read_seconds, "text": _read_text, "flag": _read_flag, "services": _read_services,
           "names": _read_names, "mac": _read_mac}
# divisors to seconds (a division of two exact integers is correctly rounded; a product with 1e-9 is not)
_UNITS = {"ns": 1e9, "ms": 1e3}


@dataclass(frozen=True, slots=True)
class _Path:
    """One compiled catalog path: where to look, in the record or in the Zeek line kept in event.original."""
    key: str
    original: bool
    divisor: float | None
    origin: str                     # the origin after "<id>:"; also the name a malformed value is listed under


@lru_cache(maxsize=1024)
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
        self._literal: dict[int, bool] = {}     # per object of the record: whether it holds a literal dotted key

    def _holds_literal(self, level: dict) -> bool:
        found = self._literal.get(id(level))
        if found is None:
            found = self._literal[id(level)] = any(isinstance(key, str) and "." in key for key in level)
        return found

    def get(self, path: str):
        parts = _parts(path)
        found = _nested(self.src, parts)
        if found is not _MISSING or len(parts) == 1:
            return found
        # a literal dotted key that could complete the path sits on a level the nested walk reached
        cur = self.src
        for part in parts:
            if not isinstance(cur, dict):
                break
            if self._holds_literal(cur):
                return _walk(self.src, parts, 0)
            if part not in cur:
                break
            cur = cur[part]
        return _MISSING

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
                when = datetime.fromtimestamp(value / 1000 if unit == "ms" else value, UTC)
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
    for path in log.sensor_paths.get(reader.shape, ()):
        value = reader.get(path)
        if isinstance(value, str) and value.strip():
            return fv(value.strip(), f"{reader.nid}:{path}")
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


def _signature(fields: dict[str, FieldValue]) -> str:
    """A digest of the record's typed values (never origins): two copies of one Zeek row agree, two different rows
    sharing a uid (interim and final conn rows) do not."""
    # typed values are str, int, float, bool or lists of str, whose repr is canonical
    items = sorted((name, value.value) for name, value in fields.items() if name not in _UNSIGNED)
    return hashlib.sha256(repr(items).encode()).hexdigest()[:20]


# ---- normalization ---------------------------------------------------------------------------------------------

def normalize_zeek(hit: dict, record: ZeekRecord, *, sensor: str | None = None) -> TypedEvent:
    """One recognized Zeek record as a typed event. `sensor` is the site-declared sensor of plain Zeek JSON."""
    if record.log is None:
        if not record.names:
            raise ValueError(f"{SHAPE_NAMES[record.shape]} Zeek record names no log at {record.origin}")
        raise ZeekNotNormalized(record.skip_reason())
    if record.log is CONN:
        return _conn(hit, record, sensor)
    raise ZeekNotNormalized(record.skip_reason())       # catalogued, with no normalizer yet


def normalize_plain_zeek(hit: dict, log: str | None = None, sensor: str | None = None) -> TypedEvent:
    """A record of a target the site declares as plain Zeek JSON (`log`: the declared log, used when the record
    has no `_path`; `sensor`: the declared sensor name)."""
    return normalize_zeek(hit, plain_record(hit["_source"], log), sensor=sensor)


def _conn(hit: dict, record: ZeekRecord, declared_sensor: str | None) -> TypedEvent:
    shape, log = record.shape, record.log
    reader = _Reader(hit, shape)
    nid = reader.nid
    log_object = log.log_objects.get(shape)
    if log_object and reader.get(log_object) is not _MISSING \
            and not isinstance(reader.get(log_object), dict):
        raise TypeError(f"{SHAPE_NAMES[shape]} Zeek conn record's {log_object} is not an object")
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
    duration = f.get("session.duration_s")
    if duration is not None:
        f["flow.end"] = fv((when + timedelta(seconds=duration.value)).isoformat(),
                           f"{time_origin}+{duration.origin.split(':', 1)[1]}")
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
    identity = [ref] if uid is None else [RawRef(target=f"zeek:{host or ''}:{log.name}",
                                                 native_id=f"{uid.value}|{_signature(f)}")]
    return TypedEvent(id=event_id(log.family, identity, ZEEK_NORMALIZER), family=log.family, ts=when, host=host,
                      fields=f, raw=[ref], normalizer=ZEEK_NORMALIZER, caveats=caveats)


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
