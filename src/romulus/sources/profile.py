"""Build SourceProfiles and FieldContracts from the live mapping of a concrete target."""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel

from romulus.store.db import digest

# Which predicate ops each native mapping type supports *with a retrieval-superset guarantee*.
# `text` fields are analyzed: phrase matching can miss qualifying records (tokenization), so no
# op is a superset there. Rules needing text content must retrieve by type and evaluate locally.
OPS_BY_TYPE: dict[str, set[str]] = {
    "keyword": {"eq", "in", "prefix", "exists", "missing", "contains"},
    "constant_keyword": {"eq", "in", "exists", "missing"},
    "wildcard": {"eq", "in", "prefix", "contains", "exists", "missing"},
    "ip": {"eq", "in", "cidr", "exists", "missing"},
    "long": {"eq", "in", "gte", "lt", "exists", "missing"},
    "integer": {"eq", "in", "gte", "lt", "exists", "missing"},
    "short": {"eq", "in", "gte", "lt", "exists", "missing"},
    "double": {"gte", "lt", "exists", "missing"},
    "float": {"gte", "lt", "exists", "missing"},
    "date": {"gte", "lt", "exists", "missing"},
    "boolean": {"eq", "exists", "missing"},
    "text": {"exists", "missing"},
    # A flattened leaf is indexed like a keyword. Aliases below name the leaf explicitly; the object root itself
    # is never used for a value predicate.
    "flattened": {"eq", "in", "prefix", "contains", "exists", "missing"},
}
AGGREGATABLE = {
    "keyword", "constant_keyword", "ip", "long", "integer", "short", "boolean", "date", "wildcard",
}


class FieldSpec(BaseModel):
    native: str
    natives: tuple[str, ...] = ()
    type: str
    ops: list[str]
    aggregatable: bool


class FieldContract(BaseModel):
    """Single mapping from ROMULUS typed fields to native fields for one target."""
    target: str
    fields: dict[str, FieldSpec]
    time_field: str = "@timestamp"
    role: Literal["host", "network"] = "host"
    os_family: Literal["linux", "windows", "unknown"] = "linux"
    hosts: tuple[str, ...] = ()
    host_inventory_complete: bool = True

    def spec(self, typed: str) -> FieldSpec | None:
        return self.fields.get(typed)

    def supports(self, typed: str, op: str) -> bool:
        s = self.fields.get(typed)
        return bool(s and op in s.ops)


class SourceProfile(BaseModel):
    id: str
    target: str
    kind: str
    role: Literal["host", "network"]
    backend: str
    backend_version: str
    captured_at: datetime
    field_types: dict[str, str]
    datasets: dict[str, int] = {}
    hosts: dict[str, int] = {}
    time_min: str | None = None
    time_max: str | None = None
    doc_count: int | None = None
    notes: list[str] = []


def flatten_mapping(mapping: dict) -> dict[str, str]:
    out: dict[str, str] = {}

    def walk(prefix: str, props: dict[str, Any]):
        for name, spec in props.items():
            full = f"{prefix}{name}"
            if "properties" in spec:
                walk(full + ".", spec["properties"])
            else:
                out[full] = spec.get("type", "object")
            for sub, sspec in spec.get("fields", {}).items():
                out[f"{full}.{sub}"] = sspec.get("type", "object")

    for body in mapping.values():
        walk("", body.get("mappings", {}).get("properties", {}))
    return out


ARKIME_SESSION_MARKERS = ("firstPacket", "lastPacket", "network.community_id")

# A flattened Winlogbeat/Elastic Agent object does not expose child mappings, so aliases name the native leaf.
# Forwarded events deliberately map host identity to the computer that wrote the event, not the collector.
WINDOWS_FIELD_MAPPINGS: dict[str, tuple[str, ...]] = {
    "event.channel": ("winlog.channel",),
    "event.provider": ("winlog.provider_name",),
    "event.code": ("winlog.event_id",),
    "host.name": ("winlog.computer_name",),
    "process.command_line": ("winlog.event_data.CommandLine",),
    "process.executable": (
        "winlog.event_data.Image", "winlog.event_data.NewProcessName", "winlog.event_data.ProcessName",
    ),
    "process.pid": ("winlog.event_data.ProcessId", "winlog.event_data.NewProcessId"),
    "process.ppid": ("winlog.event_data.ParentProcessId", "winlog.event_data.CreatorProcessId"),
    "process.guid": ("winlog.event_data.ProcessGuid",),
    "process.parent.guid": ("winlog.event_data.ParentProcessGuid",),
    "auth.session_id": ("winlog.event_data.TargetLogonId", "winlog.event_data.SubjectLogonId"),
    "user.name": ("winlog.event_data.SubjectUserName",),
    "user.entity_id": (
        "winlog.event_data.SubjectUserSid", "winlog.event_data.SubjectUserName", "winlog.event_data.User",
    ),
    "auth.target_account": ("winlog.event_data.TargetUserSid", "winlog.event_data.TargetUserName"),
    "source.ip": ("winlog.event_data.SourceIp", "winlog.event_data.IpAddress"),
    "source.port": ("winlog.event_data.SourcePort", "winlog.event_data.IpPort"),
    "destination.ip": ("winlog.event_data.DestinationIp",),
    "destination.port": ("winlog.event_data.DestinationPort",),
}


def schema_of(field_types: dict[str, str]) -> str:
    """Which normalizer family a target's mapping belongs to, from its fields (never its name)."""
    if all(f in field_types for f in ARKIME_SESSION_MARKERS):
        return "arkime_sessions"
    return "lab_ecs"


def source_role(field_types: dict[str, str], datasets: set[str] | None = None) -> Literal["host", "network"]:
    """Classify a mapping/inventory by telemetry semantics, never by its target name."""
    if schema_of(field_types) == "arkime_sessions":
        return "network"
    datasets = datasets or set()
    if any(dataset.startswith("suricata.eve") for dataset in datasets):
        return "network"
    network_shape = all(field in field_types for field in ("source.ip", "destination.ip"))
    host_shape = any(
        field == "host.ip" or field.startswith(("process.", "user.", "winlog."))
        for field in field_types
    )
    return "network" if network_shape and not host_shape else "host"


def source_os_family(field_types: dict[str, str], role: str) -> Literal["linux", "windows", "unknown"]:
    if any(field == "winlog" or field.startswith("winlog.") for field in field_types):
        return "windows"
    return "linux" if role == "host" else "unknown"


def _native_type(field_types: dict[str, str], native: str) -> str | None:
    direct = field_types.get(native)
    if direct is not None:
        return direct
    parts = native.split(".")
    for end in range(len(parts) - 1, 0, -1):
        parent = ".".join(parts[:end])
        if field_types.get(parent) == "flattened":
            return "flattened"
    return None


def contract_from_types(
    target: str,
    field_types: dict[str, str],
    *,
    role: Literal["host", "network"] | None = None,
    os_family: Literal["linux", "windows", "unknown"] | None = None,
    field_mappings: dict[str, tuple[str, ...] | str] | None = None,
    hosts: tuple[str, ...] = (),
    host_inventory_complete: bool = True,
) -> FieldContract:
    """Build a typed contract, adding explicit aliases for native schemas such as Windows event data."""
    fields = {
        name: FieldSpec(
            native=name,
            natives=(name,),
            type=t,
            ops=sorted(OPS_BY_TYPE.get(t, set())),
            aggregatable=t in AGGREGATABLE,
        )
        for name, t in field_types.items()
    }
    mappings = dict(field_mappings or {})
    if any(field == "winlog" or field.startswith("winlog.") for field in field_types):
        mappings = {**WINDOWS_FIELD_MAPPINGS, **mappings}
    for typed, candidates in mappings.items():
        native_candidates = (candidates,) if isinstance(candidates, str) else candidates
        available = [
            (native, native_type)
            for native in native_candidates
            if (native_type := _native_type(field_types, native)) is not None
        ]
        if not available:
            continue
        common_ops = set.intersection(*(OPS_BY_TYPE.get(native_type, set()) for _, native_type in available))
        native, native_type = available[0]
        fields[typed] = FieldSpec(
            native=native,
            natives=tuple(item[0] for item in available),
            type=native_type,
            ops=sorted(common_ops),
            aggregatable=len(available) == 1 and native_type in AGGREGATABLE,
        )
    time_field = "firstPacket" if schema_of(field_types) == "arkime_sessions" else "@timestamp"
    resolved_role = role or source_role(field_types)
    resolved_os = os_family or source_os_family(field_types, resolved_role)
    return FieldContract(
        target=target, fields=fields, time_field=time_field, role=resolved_role, os_family=resolved_os,
        hosts=hosts, host_inventory_complete=host_inventory_complete,
    )


def build_profile(client, target: str) -> tuple[SourceProfile, FieldContract]:
    """Read-only preflight of one concrete index."""
    field_types = flatten_mapping(client.mapping(target))
    schema = schema_of(field_types)
    # Arkime sessions: time is the first packet; the "dataset" is the session protocol and the
    # reporting host is the capture node
    windows = "winlog.computer_name" in field_types
    tf, ds_field, host_field = (("firstPacket", "protocol", "node") if schema == "arkime_sessions"
                                else ("@timestamp", "event.dataset",
                                      "winlog.computer_name" if windows else "host.name"))
    body = {
        "size": 0, "track_total_hits": True,
        "aggs": {
            "tmin": {"min": {"field": tf}}, "tmax": {"max": {"field": tf}},
            "ds": {"terms": {"field": ds_field, "size": 200}},
            "hosts": {"terms": {"field": host_field, "size": 500}},
        },
    }
    d = client.search(target, body)
    aggs = d.get("aggregations", {})
    notes = []
    for k in ("ds", "hosts"):
        if aggs.get(k, {}).get("sum_other_doc_count"):
            notes.append(f"{k} inventory truncated (sum_other_doc_count>0)")
    datasets = {b["key"]: b["doc_count"] for b in aggs.get("ds", {}).get("buckets", [])}
    role = source_role(field_types, set(datasets))
    prof = {
        "target": target, "kind": "es_index" if schema == "lab_ecs" else schema,
        "role": role,
        "backend": client.settings.es_flavor, "backend_version": client.version,
        "captured_at": datetime.now(UTC), "field_types": field_types,
        "datasets": datasets,
        "hosts": {b["key"]: b["doc_count"] for b in aggs.get("hosts", {}).get("buckets", [])},
        "time_min": aggs.get("tmin", {}).get("value_as_string"),
        "time_max": aggs.get("tmax", {}).get("value_as_string"),
        "doc_count": d.get("hits", {}).get("total", {}).get("value"), "notes": notes,
    }
    pid = digest({k: v for k, v in prof.items() if k != "captured_at"})[:16]
    profile = SourceProfile(id=pid, **prof)
    return profile, contract_from_types(
        target,
        field_types,
        role=role,
        hosts=tuple(sorted(profile.hosts)),
        host_inventory_complete=not any(note.startswith("hosts inventory truncated") for note in notes),
    )
