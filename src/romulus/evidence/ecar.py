"""Strict, stateless eCAR endpoint records with native field origins.

Sources: https://github.com/FiveDirections/OpTC-data/blob/master/ecar.md,
https://github.com/FiveDirections/OpTC-data/blob/master/errata.md and
https://car.mitre.org/data_model/. No Windows event-log identity is synthesized.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from datetime import UTC, datetime
from uuid import UUID

from romulus.evidence.community import community_id
from romulus.evidence.ecar_catalog import lookup_ecar
from romulus.evidence.raw_scrub import clean_source
from romulus.evidence.typed import Outcome, RawRef, TypedEvent, event_id, fv
from romulus.evidence.windows import _path_metadata, registry_path_key, windows_path_key

ECAR_NORMALIZER = "ecar@1"
ECAR_DUPLICATE = "duplicate eCAR record UUID"
_MARKERS = frozenset({"object", "action", "objectID", "actorID", "hostname", "properties"})
_ZERO = "00000000-0000-0000-0000-000000000000"
_INTEGER_FIELDS = frozenset({"source.port", "destination.port", "source.pid", "target.pid", "source.thread.id",
                             "thread.id", "process.access.mask", "auth.logon_type", "ecar.acuity_level"})
_MAX_NOTICE = 256


class EcarInputError(ValueError):
    """A recognized eCAR record lacks a valid identity or event time."""


class EcarSkip(Exception):
    """A counted unsupported object/action, scoped only to its catalogued families."""

    def __init__(self, reason: str, families: tuple[str, ...] = ()):
        super().__init__(reason[:_MAX_NOTICE])
        self.families = families


def is_ecar_source(source: object) -> bool:
    return isinstance(source, dict) and _MARKERS <= source.keys()


def _uuid(value, *, required=False):
    try:
        result = str(UUID(value)) if isinstance(value, str) else ""
    except (ValueError, AttributeError):
        result = ""
    if not result or result == _ZERO:
        if required:
            raise EcarInputError("eCAR record id is not a nonzero UUID")
        return None
    return result


def record_identity(source: dict) -> str:
    """An event UUID, independent of the object UUID and its indexed copies."""
    return _uuid(source.get("id"), required=True)


def _integer(value):
    if isinstance(value, bool):
        raise TypeError("boolean is not an integer")
    if isinstance(value, int):
        return value
    if isinstance(value, str) and re.fullmatch(r"-?\d+", value, re.ASCII):
        return int(value)
    raise ValueError("not decimal integer text")


def _pid(value):
    try:
        number = _integer(value)
        return number if 0 < number <= 0xffffffff else None
    except (ValueError, TypeError):
        return None


def _time(source):
    name = "timestamp_ms" if "timestamp_ms" in source else "timestamp"
    try:
        native = _integer(source.get(name))
        native_time = datetime.fromtimestamp(native / 1000, UTC)
    except (ValueError, TypeError, OverflowError, OSError) as exc:
        raise EcarInputError("eCAR timestamp is not epoch milliseconds") from exc
    if "@timestamp" not in source:
        return native_time, native, name
    value = source["@timestamp"]
    try:
        if not isinstance(value, str):
            raise TypeError("pipeline time is not text")
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            raise ValueError("pipeline time lacks timezone")
    except (ValueError, TypeError) as exc:
        raise EcarInputError("eCAR pipeline @timestamp is malformed") from exc
    return parsed.astimezone(UTC), native, name


def _pair(source):
    return "/".join(str(source.get(name, "<missing>"))[:64] for name in ("object", "action"))


def _property(typed, value):
    if typed in {"source.ip", "destination.ip"}:
        if not isinstance(value, str):
            raise ValueError("address is not text")
        return str(ipaddress.ip_address(value))
    if typed in _INTEGER_FIELDS:
        number = _integer(value)
        maximum = 65535 if typed.endswith(".port") else 0xffffffff
        if number < 0 or number > maximum:
            raise ValueError("outside typed integer range")
        if typed.endswith(".pid") and number == 0:
            raise ValueError("unknown pid")
        return number
    if typed == "auth.login_successful":
        if isinstance(value, bool):
            return value
        if isinstance(value, str) and value.casefold() in {"true", "false"}:
            return value.casefold() == "true"
        raise ValueError("authentication outcome is not boolean")
    if not isinstance(value, str):
        raise TypeError("property is not text")
    if typed == "network.direction":
        direction = {"inbound": "ingress", "outbound": "egress", "ingress": "ingress", "egress": "egress"}
        if value.casefold() not in direction:
            raise ValueError("unknown direction")
        return direction[value.casefold()]
    if typed == "network.transport":
        protocol = {"tcp": "tcp", "udp": "udp", "icmp": "icmp", "icmpv6": "ipv6-icmp",
                    "6": "tcp", "17": "udp", "1": "icmp", "58": "ipv6-icmp"}
        if value.casefold() not in protocol:
            raise ValueError("unknown transport")
        return protocol[value.casefold()]
    return value


def normalization_notices(source: dict) -> list[tuple[str, tuple[str, ...]]]:
    """At most two fixed-reason notices per record; no property values enter labels."""
    row = lookup_ecar(source)
    properties = source.get("properties")
    if row is None or row.family is None or not isinstance(properties, dict):
        return []
    unknown = malformed = False
    for key, value in properties.items():
        typed = row.properties.get(key)
        if typed is None:
            unknown = True
        else:
            try:
                _property(typed, value)
            except (ValueError, TypeError):
                malformed = True
    result = []
    for exists, reason in ((unknown, "unsupported properties"), (malformed, "malformed properties")):
        if exists:
            result.append((f"eCAR {_pair(source)}: {reason}; those fields were not typed"[:_MAX_NOTICE], (row.family,)))
    return result


def _account(fields, value, origin, *, target=False):
    if not isinstance(value, str) or not value.strip():
        return
    domain, separator, name = value.strip().rpartition("\\")
    name = name.casefold()
    if target:
        fields["auth.target_user"] = fv(name, origin + "#parsed:account-name")
        if separator:
            fields["auth.target_domain"] = fv(domain.casefold(), origin + "#parsed:account-domain")
        fields["auth.target_account"] = fv((domain.casefold() + "\\" if separator else "") + name, origin)
    else:
        fields["user.name"] = fv(name, origin + "#parsed:account-name")
        if separator:
            fields["user.domain"] = fv(domain.casefold(), origin + "#parsed:account-domain")
        fields["user.entity_id"] = fv("name:" + (domain.casefold() + "\\" if separator else "") + name, origin)


def normalize_ecar(hit: dict) -> TypedEvent:
    source = hit.get("_source")
    if not isinstance(source, dict):
        raise EcarInputError("eCAR source is not an object")
    record_id = record_identity(source)
    hostname = source.get("hostname")
    if not isinstance(hostname, str) or not hostname.strip() or hostname.strip() == "-":
        raise EcarInputError("eCAR hostname is missing")
    full_host = hostname.strip().casefold().rstrip(".")
    host = full_host.split(".", 1)[0]
    ts, native_time, time_name = _time(source)
    properties = source.get("properties")
    if not isinstance(properties, dict):
        raise EcarInputError("eCAR properties is not an object")
    row = lookup_ecar(source)
    if row is None:
        raise EcarSkip("eCAR unsupported object/action: not typed")
    if row.family is None:
        raise EcarSkip(f"eCAR {_pair(source)}: not typed; {row.reason}")
    native_id = str(hit["_id"])
    def origin(name):
        return f"{native_id}:{name}"
    fields = {
        "host.name": fv(host, origin("hostname") + "#short-name"),
        "host.full_name": fv(full_host, origin("hostname")),
        "host.os.family": fv("windows", origin("object") + "#catalog:ecar-endpoint"),
        "ecar.object": fv(source["object"], origin("object")),
        "ecar.action": fv(source["action"], origin("action")),
        "ecar.record_id": fv(record_id, origin("id")),
        "ecar.timestamp_ms": fv(native_time, origin(time_name)),
    }
    caveats = []
    if row.support == "expected":
        caveats.append("eCAR object/action uses expected CAR export vocabulary; sensor-specific semantics are unverified")
    for key, value in properties.items():
        typed = row.properties.get(key)
        if typed is None:
            continue
        try:
            converted = _property(typed, value)
        except (ValueError, TypeError):
            continue
        if typed not in fields:
            fields[typed] = fv(converted, origin("properties." + key))
    caveats.extend(reason for reason, _ in normalization_notices(source))
    _account(fields, source.get("principal"), origin("principal"))
    if row.family == "auth" and "user" in properties:
        _account(fields, properties["user"], origin("properties.user"), target=True)
    elif "user" in properties:
        _account(fields, properties["user"], origin("properties.user"))
    process_object = source["object"] == "PROCESS" and source["action"] in {"CREATE", "TERMINATE"}
    process_key = "objectID" if process_object else "actorID"
    process_id = _uuid(source.get(process_key))
    if process_id and source["object"] != "HOST":
        fields["process.entity_id"] = fv("ecar:" + process_id, origin(process_key))
        fields["process.id_kind"] = fv("ecar", origin(process_key))
    for native, typed in (("pid", "process.pid"), ("ppid", "process.ppid"), ("tid", "process.thread.id")):
        pid = _pid(source.get(native))
        if pid is not None:
            fields[typed] = fv(pid, origin(native))
    ppid = fields.get("process.ppid")
    if ppid:
        fields["process.parent.entity_id"] = fv(f"pid:{host}:{ppid.value}", ppid.origin)
        fields["process.parent.id_kind"] = fv("fenced_pid", ppid.origin)
    for name in ("process.executable", "process.parent.executable"):
        _path_metadata(fields, name, name + "_key", preserve_recorded_prefix=True)
    action_origin = origin("action")
    family = row.family
    outcome = Outcome.success
    if family == "process_termination":
        fields["process.fence"] = fv("termination", action_origin)
    elif family == "file_change":
        fields["file.action"] = fv({"CREATE": "created", "DELETE": "deleted", "RENAME": "renamed"}[source["action"]], action_origin)
        for name in ("file.path", "file.new_path"):
            if name in fields:
                fields[name + "_key"] = fv(windows_path_key(fields[name].value), fields[name].origin + "#canonical:windows-path")
    elif family == "registry_change":
        has_value = "registry.value_name" in fields
        value_kind_known = "value" not in properties or has_value
        action = source["action"]
        semantics = {"ADD": "value_set" if has_value else "object_created",
                     "EDIT": "value_modified" if has_value else "object_modified", "REMOVE": "object_deleted"}
        if value_kind_known:
            fields["registry.action"] = fv(semantics[action], action_origin)
        if action == "ADD" and not has_value and value_kind_known:
            fields["registry.event_type"] = fv("CreateKey", action_origin)
        if action == "REMOVE" and value_kind_known:
            fields["registry.event_type"] = fv("DeleteValue" if has_value else "DeleteKey", action_origin)
        if "registry.path" in fields:
            item = fields["registry.path"]
            fields["registry.path_key"] = fv(registry_path_key(item.value), item.origin + "#canonical:registry-path")
    elif family == "image_load":
        fields["image.kind"] = fv("image", origin("object") + "#catalog")
        if "image.path" in fields:
            item = fields["image.path"]
            fields["image.path_key"] = fv(windows_path_key(item.value), item.origin + "#canonical:windows-path")
    elif family == "net_socket":
        names = ("source.ip", "source.port", "destination.ip", "destination.port", "network.transport")
        if all(name in fields for name in names):
            connection = community_id(*(fields[name].value for name in names))
            if connection:
                fields["network.community_id"] = fv(connection, "+".join(fields[name].origin for name in names) + "#computed:community_id_v1")
    elif family in {"process_access", "remote_thread"}:
        for source_name, target_name in (("process.executable", "source.executable"), ("process.pid", "source.pid"),
                                         ("process.entity_id", "source.entity_id")):
            if source_name in fields and target_name not in fields:
                fields[target_name] = fields[source_name]
        if family == "process_access":
            fields["process.access.action"] = fv("opened", action_origin)
            target_id = _uuid(source.get("objectID"))
            if target_id:
                fields["target.entity_id"] = fv("ecar:" + target_id, origin("objectID"))
        for role in ("source", "target"):
            _path_metadata(fields, role + ".executable", role + ".executable_key")
            for suffix in ("pid", "executable", "executable_key", "entity_id"):
                if role + "." + suffix in fields:
                    fields["process." + role + "." + suffix] = fields[role + "." + suffix]
    elif family == "auth":
        fields["auth.action"] = fv({"LOGIN": "logon", "LOGOUT": "logoff", "UNLOCK": "unlock",
                                    "GRANT": "grant"}.get(source["action"], "logon"), action_origin)
        successful = fields.get("auth.login_successful")
        outcome = (Outcome.success if successful.value else Outcome.failure) if successful else Outcome.unknown
    elif family == "service_change":
        fields["service.action"] = fv("installed", action_origin)
    elif family == "scheduled_task":
        fields["task.action"] = fv({"CREATE": "created", "MODIFY": "updated", "DELETE": "deleted", "START": "started"}[source["action"]], action_origin)
    elif family == "script_block":
        fields["script.action"] = fv("execution", action_origin)
    elif family == "system_state":
        fields["system.event"] = fv("boot_start", action_origin)
        fields["process.fence"] = fv("boot", action_origin)
    encoded = json.dumps(clean_source(source), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    raw = RawRef(target=str(hit["_index"]), native_id=native_id, digest=hashlib.sha256(encoded).hexdigest())
    identity = RawRef(target="ecar", native_id=record_id)
    # The record UUID, rather than mutable payload classification, owns identity.
    return TypedEvent(id=event_id("ecar_record", [identity], ECAR_NORMALIZER), family=family, ts=ts, host=host,
                      outcome=outcome, fields=fields, raw=[raw], normalizer=ECAR_NORMALIZER, caveats=caveats)
