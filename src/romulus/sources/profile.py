"""Build SourceProfiles and FieldContracts from the live mapping of a concrete target."""
from __future__ import annotations

import json
from collections import Counter
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, model_serializer, model_validator

from romulus.errors import SourceError
from romulus.evidence.ecar_catalog import ECAR_ROWS
from romulus.evidence.linux_catalog import (
    LINUX_LOGICAL_DATASETS,
    TEXT_INPUT_TYPES,
    logical_of,
    text_dataset_inventory,
    text_payload,
)
from romulus.evidence.windows_catalog import WINDOWS_DATASETS
from romulus.evidence.zeek_catalog import MALCOLM, lookup_log
from romulus.sources.models import typed_field_name
from romulus.store.db import digest

HOST_INVENTORY_PAGE_SIZE = 500
HOST_INVENTORY_PAGE_LIMIT = 100
HOST_INVENTORY_BYTE_BUDGET = 8 * 1024 * 1024
TEXT_SAMPLE_LIMIT = 1000

# Which predicate ops each native mapping type supports *with a retrieval-superset guarantee*.
# `text` fields are analyzed: phrase matching can miss qualifying records (tokenization), so no
# op is a superset there. Rules needing text content must retrieve by type and evaluate locally.
OPS_BY_TYPE: dict[str, set[str]] = {
    "keyword": {"eq", "in", "not_in", "prefix", "exists", "missing", "contains"},
    "constant_keyword": {"eq", "in", "not_in", "exists", "missing"},
    "wildcard": {"eq", "in", "not_in", "prefix", "contains", "exists", "missing"},
    "ip": {"eq", "in", "cidr", "exists", "missing"},
    "long": {"eq", "in", "not_in", "gte", "lt", "exists", "missing"},
    "integer": {"eq", "in", "not_in", "gte", "lt", "exists", "missing"},
    "short": {"eq", "in", "not_in", "gte", "lt", "exists", "missing"},
    "double": {"gte", "lt", "exists", "missing"},
    "float": {"gte", "lt", "exists", "missing"},
    "date": {"gte", "lt", "exists", "missing"},
    "boolean": {"eq", "exists", "missing"},
    "text": {"exists", "missing"},
    # A flattened leaf is indexed like a keyword. Aliases below name the leaf explicitly; the object root itself
    # is never used for a value predicate.
    "flattened": {"eq", "in", "not_in", "prefix", "contains", "exists", "missing"},
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
    # For an alias whose natives are all analyzed text: each native's keyword subfield, in the same order. Equality
    # ('eq', 'in') is compiled against these (sources.compile); every other op still reads the text natives.
    exact: tuple[str, ...] = ()
    # The smallest ignore_above among those subfields, in UTF-16 code units: a longer value is in none of them.
    # None when every subfield keeps values of any length.
    exact_limit: int | None = None
    # A text native can be searched without dropping long values while its keyword child supplies inventory keys.
    aggregation_native: str | None = None
    # Search each source layout through its own exact-field rules; aggregation keeps the primary layout.
    alternatives: tuple[FieldSpec, ...] = ()

    @model_serializer(mode="wrap")
    def _serialize(self, handler):
        data = handler(self)
        if not self.exact:
            data.pop("exact", None)
        if self.exact_limit is None:
            data.pop("exact_limit", None)
        if self.aggregation_native is None:
            data.pop("aggregation_native", None)
        if not self.alternatives:
            data.pop("alternatives", None)
        return data


class FieldContract(BaseModel):
    """Single mapping from ROMULUS typed fields to native fields for one target."""
    target: str
    fields: dict[str, FieldSpec]
    linux_fields: dict[str, FieldSpec] = {}
    time_field: str = "@timestamp"
    role: Literal["host", "network"] = "host"
    os_family: Literal["linux", "windows", "unknown"] = "linux"
    hosts: tuple[str, ...] = ()
    host_inventory_complete: bool = True

    zeek_sensor: str | None = None
    zeek_log: str | None = None
    # A Linux target whose mapping also holds NXLog's flat Windows records: both shapes are selected, each as it
    # would be alone (sources.profile.nxlog_mixed).
    nxlog_mixed: bool = False
    windows_shapes: tuple[str, ...] = ()
    # None means the bounded text-source count was unavailable, never a complete negative.
    linux_text_mixed: bool | None = False
    ecar: bool = False
    temporal_gaps: tuple[str, ...] = ()

    @model_validator(mode="after")
    def _untyped_names(self):
        """A source field whose name no predicate can carry (`typed_field_name`: `zeek.dns.@proc`, `a-b`, `a b`)
        stays in the contract, so consumers still see that the source has it, but it supports no predicate op:
        `supports` and `native_field` refuse it, so no predicate is ever built on it. Normalization still reads its
        values from the records. Aggregation is unchanged: aggregated fields are named by code (`@timestamp` among
        them) and compiled to the native name, which the backend takes as written. One pass over the names, each
        checked once."""
        for table in (self.fields, self.linux_fields):
            for name, spec in table.items():
                if spec.ops and not typed_field_name(name):
                    table[name] = spec.model_copy(update={"ops": []})
        return self

    @model_serializer(mode="wrap")
    def _serialize(self, handler):
        data = handler(self)
        if self.zeek_sensor is None:
            data.pop("zeek_sensor", None)
        if self.zeek_log is None:
            data.pop("zeek_log", None)
        if not self.nxlog_mixed:
            data.pop("nxlog_mixed", None)
        if not self.windows_shapes:
            data.pop("windows_shapes", None)
        if self.linux_text_mixed is False:
            data.pop("linux_text_mixed", None)
        if not self.ecar:
            data.pop("ecar", None)
        if not self.temporal_gaps:
            data.pop("temporal_gaps", None)
        return data

    def spec(self, typed: str, *, os_family: str | None = None) -> FieldSpec | None:
        if os_family == "linux" and self.linux_fields:
            return self.linux_fields.get(typed)
        return self.fields.get(typed)

    def supports(self, typed: str, op: str) -> bool:
        s = self.fields.get(typed)
        return bool(s and op in s.ops)



def native_field(contract, path, op='eq'):
    """Resolve an exact-capable native field or a reported text multifield without guessing a suffix."""
    if contract.supports(path, op):
        return path
    direct = next((name for name, spec in contract.fields.items()
                   if spec.native == path and op in spec.ops), None)
    if direct or not any(spec.native == path and spec.type == 'text' for spec in contract.fields.values()):
        return direct
    return next((name for name, spec in contract.fields.items()
                 if spec.native.startswith(path + '.') and op in spec.ops), None)


def _aggregation_field(field_types, path):
    """The native field an inventory aggregation reads for `path`: itself when aggregatable, else a reported exact
    multifield (a text field's keyword subfield), else None. Resolved on the index's own mapping, never through the
    typed alias layer, which joins event.dataset and data_stream.dataset into one field that cannot be aggregated.
    An unmapped field aggregates validly and empty, so it is returned as it is."""
    kind = field_types.get(path)
    if kind is None or kind in AGGREGATABLE:
        return path
    return next((name for name, sub in sorted(field_types.items())
                 if name.startswith(path + ".") and sub in AGGREGATABLE), None)


def apply_zeek_declaration(contract, site_facts):
    """Bind an explicit site's plain JSON declaration without changing undeclared contracts."""
    declaration = site_facts.zeek.plain_sources.get(contract.target)
    if declaration is None:
        return contract
    stamp = contract.fields.get("ts")
    if stamp is None or stamp.type not in {"double", "float", "long", "integer"}:
        raise ValueError("declared plain Zeek source requires numeric epoch-second ts")
    return contract.model_copy(update={"zeek_sensor": declaration.sensor, "zeek_log": declaration.log,
                                       "time_field": "ts", "role": "network", "os_family": "unknown"})


class SourceProfile(BaseModel):
    id: str
    target: str
    kind: str
    role: Literal["host", "network"]
    os_family: Literal["linux", "windows", "unknown"]
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
    # A mixed network index's profile also carries `inventory`: its (provider, dataset) buckets as the source counted
    # them. Other profiles have no such key (an extra field, so their stored form is what it always was).
    model_config = ConfigDict(extra="allow")


def flatten_mapping(mapping: dict) -> dict[str, str]:
    out: dict[str, str] = {}
    objects: set[str] = set()

    def record(name, kind):
        previous = out.get(name)
        out[name] = "mixed" if name in objects or previous is not None and previous != kind else kind

    def walk(prefix: str, props: dict[str, Any]):
        for name, spec in props.items():
            full = f"{prefix}{name}"
            if "properties" in spec:
                objects.add(full)
                if full in out:
                    out[full] = "mixed"
                walk(full + ".", spec["properties"])
            else:
                record(full, spec.get("type", "object"))
            for sub, sspec in spec.get("fields", {}).items():
                record(f"{full}.{sub}", sspec.get("type", "object"))

    for body in mapping.values():
        walk("", body.get("mappings", {}).get("properties", {}))
    return out


def keyword_subfield_limits(mapping: dict) -> dict[str, int | None]:
    """Each keyword subfield of a text field (`Hostname.keyword`) with its ignore_above: the longest value it indexes,
    or None when it indexes values of any length. Across the indices of a pattern target, the smallest limit any of
    them sets. Kept apart from the field types, which identify the profile."""
    limits: dict[str, list[int | None]] = {}

    def walk(prefix: str, props: dict[str, Any]):
        for name, spec in props.items():
            full = f"{prefix}{name}"
            if "properties" in spec:
                walk(full + ".", spec["properties"])
            if spec.get("type") != "text":
                continue
            for sub, sspec in spec.get("fields", {}).items():
                if sspec.get("type") == "keyword":
                    limit = sspec.get("ignore_above")
                    limits.setdefault(f"{full}.{sub}", []).append(int(limit) if limit is not None else None)

    for body in mapping.values():
        walk("", body.get("mappings", {}).get("properties", {}))
    return {path: min((value for value in values if value is not None), default=None)
            for path, values in limits.items()}


ARKIME_SESSION_MARKERS = ("firstPacket", "lastPacket", "network.community_id")

# A flattened Winlogbeat/Elastic Agent object does not expose child mappings, so aliases name the native leaf.
# Forwarded events deliberately map host identity to the computer that wrote the event, not the collector.
WINDOWS_FIELD_MAPPINGS: dict[str, tuple[str, ...]] = {
    "rpc.interface_uuid": ("winlog.event_data.InterfaceUuid",),
    "rpc.protocol": ("winlog.event_data.Protocol",),
    "remote.channel_name": ("winlog.event_data.ChannelName",),
    "wfp.source_address": ("winlog.event_data.SourceAddress",),
    "wfp.source_port": ("winlog.event_data.SourcePort",),
    "wfp.destination_address": ("winlog.event_data.DestAddress",),
    "wfp.destination_port": ("winlog.event_data.DestPort",),
    "event.dataset": ("event.dataset", "data_stream.dataset"),
    "event.channel": ("winlog.channel",),
    "event.provider": ("winlog.provider_name",),
    "event.code": ("winlog.event_id",),
    "object.type": ("winlog.event_data.ObjectType",),
    "host.name": ("winlog.computer_name",),
    "process.command_line": ("winlog.event_data.CommandLine",),
    "process.executable": (
        "winlog.event_data.Image", "winlog.event_data.NewProcessName", "winlog.event_data.ProcessName",
    ),
    "process.parent.executable": ("winlog.event_data.ParentImage", "winlog.event_data.ParentProcessName"),
    "process.pid": ("winlog.event_data.ProcessId", "winlog.event_data.NewProcessId"),
    "process.ppid": (
        "winlog.event_data.ParentProcessId", "winlog.event_data.CreatorProcessId",
        "winlog.event_data.ProcessId",
    ),
    "process.guid": ("winlog.event_data.ProcessGuid",),
    "process.parent.guid": ("winlog.event_data.ParentProcessGuid",),
    "source.guid": ("winlog.event_data.SourceProcessGuid", "winlog.event_data.SourceProcessGUID"),
    "target.guid": ("winlog.event_data.TargetProcessGuid", "winlog.event_data.TargetProcessGUID"),
    "process.session_id": (
        "winlog.event_data.LogonId", "winlog.event_data.SubjectLogonId", "winlog.event_data.TargetLogonId",
    ),
    "auth.session_id": ("winlog.event_data.TargetLogonId", "winlog.event_data.SubjectLogonId"),
    "auth.logon_guid": ("winlog.event_data.LogonGuid",),
    "auth.logon_type": ("winlog.event_data.LogonType",),
    "user.name": ("winlog.event_data.SubjectUserName",),
    "user.entity_id": (
        "winlog.event_data.SubjectUserSid", "winlog.event_data.SubjectUserName", "winlog.event_data.User",
    ),
    "auth.target_account": ("winlog.event_data.TargetUserSid", "winlog.event_data.TargetUserName"),
    "source.ip": ("winlog.event_data.SourceIp", "winlog.event_data.IpAddress"),
    "source.hostname": (
        "winlog.event_data.SourceHostname", "winlog.event_data.WorkstationName",
        "winlog.event_data.Workstation", "winlog.event_data.ClientName",
    ),
    "source.port": ("winlog.event_data.SourcePort", "winlog.event_data.IpPort"),
    "destination.ip": ("winlog.event_data.DestinationIp",),
    "destination.port": ("winlog.event_data.DestinationPort",),
    "service.image_path": ("winlog.event_data.ImagePath", "winlog.event_data.ServiceFileName"),
}


# NXLog's flat Windows records (evidence.windows.nxlog_to_winlog) hold the same values at the top level, under
# NXLog's System names and the providers' own event-data names: on a target that maps them, every Windows alias
# also reads the flat name.
NXLOG_MARKERS = ("Channel", "EventID")
_NXLOG_SYSTEM_NAMES = {"winlog.channel": "Channel", "winlog.provider_name": "SourceName", "winlog.event_id": "EventID",
                       "winlog.computer_name": "Hostname", "winlog.record_id": "RecordNumber"}


def _nxlog_name(native: str) -> str | None:
    if native.startswith("winlog.event_data."):
        return native.removeprefix("winlog.event_data.")
    return _NXLOG_SYSTEM_NAMES.get(native)


# Each Windows alias's flat names (beside its Winlogbeat names in WINDOWS_FIELD_MAPPINGS).
NXLOG_FLAT_NAMES: dict[str, tuple[str, ...]] = {
    **{typed: names for typed, natives in WINDOWS_FIELD_MAPPINGS.items()
       if (names := tuple(dict.fromkeys(flat for native in natives if (flat := _nxlog_name(native)))))},
    "winlog.record_id": ("RecordNumber",),
}

_EVTX_SYSTEM_NAMES = {
    "winlog.channel": "Event.System.Channel", "winlog.provider_name": "Event.System.Provider.#attributes.Name",
    "winlog.event_id": "Event.System.EventID", "winlog.computer_name": "Event.System.Computer",
    "winlog.record_id": "Event.System.EventRecordID", "winlog.time_created": "Event.System.TimeCreated.#attributes.SystemTime",
}


def _evtx_name(native: str) -> str | None:
    if native.startswith("winlog.event_data."):
        return "Event.EventData." + native.removeprefix("winlog.event_data.")
    return _EVTX_SYSTEM_NAMES.get(native)


EVTX_JSON_FIELD_MAPPINGS: dict[str, tuple[str, ...]] = {
    **{typed: names for typed, natives in WINDOWS_FIELD_MAPPINGS.items()
       if (names := tuple(dict.fromkeys(path for native in natives if (path := _evtx_name(native)))))},
    "winlog.record_id": ("Event.System.EventRecordID",),
    "winlog.time_created": ("Event.System.TimeCreated.#attributes.SystemTime",),
    "evtx.provider": ("Event.System.Provider.#attributes.Name",),
}
EVTX_JSON_FLAT_FIELD_MAPPINGS = {
    typed: tuple(native.replace(".#attributes.", "_attributes.") for native in natives)
    for typed, natives in EVTX_JSON_FIELD_MAPPINGS.items()
}
# Aliases the sweep aggregates on (continuity metadata, the event-class inventory): a second native would make them
# unaggregatable, so on a target that also maps Winlogbeat's names they keep those alone.
_GROUPED_ALIASES = frozenset({"host.name", "event.channel", "event.provider", "event.code", "winlog.record_id"})
# Field prefixes only Linux host shippers write (audit, journald, system auth): a mapping with NXLog's flat fields and
# any of these is a Linux target that also holds NXLog records, not a Windows target. ECS process.*/user.* and
# apache.* are not Linux-only (Logstash's ECS template maps process.* and user.* on every index), and neither is ECS
# log.syslog.*: any syslog transport writes it, Windows events forwarded over syslog included. Syslog-carried Linux
# data still counts through its Linux dataset in the inventory.
LINUX_FIELD_PREFIXES = ("auditd.", "auditbeat.", "journald.", "systemd.", "system.auth.")


def nxlog_flat(field_types) -> bool:
    """Whether a mapping holds NXLog's flat Windows record fields."""
    return all(field in field_types for field in NXLOG_MARKERS)


def _winlog_mapping(field_types) -> bool:
    return any(field == "winlog" or field.startswith("winlog.") for field in field_types)


def _evtx_json_mapping(field_types) -> bool:
    # Provider-only event classes can have a native null Channel, which a dynamic mapping never indexes.
    return ("Event.System.Computer" in field_types
            and any(name == "Event.System.EventID" or name.startswith("Event.System.EventID.") for name in field_types)
            and any(name in field_types for name in ("Event.System.Channel", "Event.System.Provider.#attributes.Name",
                                                      "Event.System.Provider_attributes.Name")))


def evtx_json_shapes(field_types) -> tuple[str, ...]:
    if not _evtx_json_mapping(field_types):
        return ()
    shapes = []
    if "Event.System.Provider.#attributes.Name" in field_types:
        shapes.append("evtx_json")
    if "Event.System.Provider_attributes.Name" in field_types:
        shapes.append("evtx_json_flat")
    return tuple(shapes or ["evtx_json"])


def _evtx_time_field(field_types) -> str:
    if "@timestamp" in field_types:
        return "@timestamp"
    return next((name for name in ("Event.System.TimeCreated.#attributes.SystemTime",
                                   "Event.System.TimeCreated_attributes.SystemTime") if name in field_types), "@timestamp")


def ecar_mapping(field_types) -> bool:
    return all(name in field_types for name in ("object", "action", "objectID", "actorID", "hostname")) and any(
        name == "properties" or name.startswith("properties.") for name in field_types)


ECAR_FIELD_MAPPINGS = {"host.name": ("hostname",), "host.full_name": ("hostname",), "process.pid": ("pid",),
    "process.ppid": ("ppid",), "ecar.object": ("object",), "ecar.action": ("action",), "ecar.record_id": ("id",),
    "process.entity_id": ("objectID", "actorID")}
for _row in ECAR_ROWS.values():
    for _native, _typed in _row.properties.items():
        ECAR_FIELD_MAPPINGS[_typed] = tuple(dict.fromkeys((*ECAR_FIELD_MAPPINGS.get(_typed, ()), "properties."+_native)))


def _ecar_time_field(field_types):
    return next((name for name in ("@timestamp", "timestamp_ms", "timestamp") if name in field_types), "timestamp_ms")


def linux_markers(field_types, datasets=None) -> bool:
    """Whether a target holds Linux host telemetry: a Linux shipper dataset in its inventory (a logical Linux dataset
    or a shipper's name for one), or a field only Linux host shippers write. Dataset-less Linux shapes (journald,
    Auditbeat without a dataset) are not in the inventory, so the fields still count."""
    if any(str(name) in LINUX_LOGICAL_DATASETS or logical_of(str(name)) is not None for name in datasets or ()):
        return True
    return any(field.startswith(LINUX_FIELD_PREFIXES) for field in field_types)


def _windows_mapping(field_types, datasets=None) -> bool:
    return (_winlog_mapping(field_types) or _evtx_json_mapping(field_types)
            or (nxlog_flat(field_types) and not linux_markers(field_types, datasets)))


def schema_of(field_types: dict[str, str]) -> str:
    """Which normalizer family a target's mapping belongs to, from its fields (never its name)."""
    if all(f in field_types for f in ARKIME_SESSION_MARKERS):
        return "arkime_sessions"
    return "lab_ecs"


def source_role(field_types: dict[str, str], datasets: set[str] | None = None) -> Literal["host", "network"]:
    """Classify a mapping/inventory by telemetry semantics, never by its target name. The datasets a shipper wrote
    decide first: a Zeek index whose kerberos or ntlm rows carry `user.*` fields is still a network sensor's."""
    if schema_of(field_types) == "arkime_sessions":
        return "network"
    datasets = datasets or set()
    if any(dataset.startswith(("suricata.eve", "zeek.", "zeek:")) for dataset in datasets):
        return "network"
    network_shape = all(field in field_types for field in ("source.ip", "destination.ip"))
    host_shape = any(
        field == "host.ip" or field.startswith(("process.", "user.", "winlog."))
        for field in field_types
    ) or nxlog_flat(field_types) or _evtx_json_mapping(field_types) or ecar_mapping(field_types)
    return "network" if network_shape and not host_shape else "host"


def source_os_family(field_types: dict[str, str], role: str, datasets=None) -> Literal["linux", "windows", "unknown"]:
    if role == "host" and ecar_mapping(field_types):
        return "windows"
    if _windows_mapping(field_types, datasets):
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


# The ops a text alias gains through its natives' keyword subfields. A keyword subfield holds each value whole, so
# equality on it is exact; it leaves out values longer than its ignore_above (FieldSpec.exact_limit), which the
# compiler covers by also matching such a value as a phrase on the text field (sources.compile). Prefix and substring matching on it would
# silently miss those long values (command lines, script text), so they stay unavailable.
SUBFIELD_EQUALITY_OPS = frozenset({"eq", "in"})
# Aliases that select event classes rather than name an entity. On a text-mapped target they stay without equality:
# a provider's own Channel data can overwrite NXLog's Channel, so its flat records are selected by their shape there
# (hunt.windows_filters.nxlog_windows_group) and never by a class predicate that would miss such a record.
_CLASS_SELECTORS = frozenset({"event.dataset", "event.channel", "event.provider", "object.type", "remote.channel_name",
                              "rpc.interface_uuid", "rpc.protocol"})


def _keyword_subfields(available: list[tuple[str, str]],
                       limits: dict[str, int | None]) -> tuple[tuple[str, ...], int | None]:
    """(each text native's keyword subfield, the smallest ignore_above among them) for an alias whose natives are all
    text with a keyword subfield whose limit the mapping reported (`limits`, from keyword_subfield_limits): a
    dynamically mapped string's `<name>.keyword`, else any keyword subfield. Empty otherwise. Equality on a Windows
    alias then reads the exact value, as it does on a Winlogbeat keyword or flattened field, instead of being
    unavailable."""
    if not available or any(kind != "text" for _native, kind in available):
        return (), None
    subfields = []
    for native, _kind in available:
        preferred = f"{native}.keyword"
        if preferred in limits:
            subfields.append(preferred)
            continue
        found = next((name for name in sorted(limits)
                      if name.startswith(native + ".") and "." not in name[len(native) + 1:]), None)
        if found is None:
            return (), None
        subfields.append(found)
    return tuple(subfields), min((limit for name in subfields if (limit := limits[name]) is not None), default=None)


def contract_from_types(
    target: str,
    field_types: dict[str, str],
    *,
    role: Literal["host", "network"] | None = None,
    os_family: Literal["linux", "windows", "unknown"] | None = None,
    field_mappings: dict[str, tuple[str, ...] | str] | None = None,
    hosts: tuple[str, ...] = (),
    host_inventory_complete: bool = True,
    datasets=None,
    keyword_limits: dict[str, int | None] | None = None,
    linux_text_mixed: bool | None | Literal["mapping"] = "mapping",
    temporal_gaps: tuple[str, ...] = (),
) -> FieldContract:
    """Build a typed contract, adding explicit aliases for native schemas such as Windows event data. `datasets` is
    the target's dataset inventory, when known: a Linux dataset in it makes a mapping that also holds NXLog's flat
    fields a Linux target that holds NXLog records too (`nxlog_mixed`). `keyword_limits` are the mapping's keyword
    subfields of text fields with their ignore_above (keyword_subfield_limits); without them no text alias gains
    equality, since what its subfields keep is unknown."""
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
    direct_fields = dict(fields)
    mappings = dict(field_mappings or {})
    resolved_role = role or source_role(field_types, set(datasets or ()))
    ecar = resolved_role == "host" and ecar_mapping(field_types)
    windows = not ecar and resolved_role == "host" and os_family not in {"linux", "unknown"} and (
        _windows_mapping(field_types, datasets) or (os_family == "windows" and nxlog_flat(field_types)))
    flat = windows and nxlog_flat(field_types)
    evtx = windows and _evtx_json_mapping(field_types)
    grouped_evtx = []
    if windows:
        mappings = {**WINDOWS_FIELD_MAPPINGS, **({"winlog.record_id": ("winlog.record_id",)} if flat or evtx else {}),
                    **mappings}
    if ecar:
        mappings = {**ECAR_FIELD_MAPPINGS, **mappings}
    if evtx:
        for typed, natives in EVTX_JSON_FIELD_MAPPINGS.items():
            existing = mappings.get(typed, ())
            existing = (existing,) if isinstance(existing, str) else existing
            additions = tuple(dict.fromkeys((*natives, *EVTX_JSON_FLAT_FIELD_MAPPINGS[typed])))
            # Existing grouped aliases remain one native; each extra layout is inventoried by its own shape.
            if typed in _GROUPED_ALIASES and any(_native_type(field_types, native) is not None for native in existing):
                grouped_evtx.append(typed)
                continue
            mappings[typed] = (*existing, *additions)
        for native in field_types:
            if native.startswith("Event.EventData.") and not native.endswith(".keyword"):
                mappings.setdefault("winlog.event_data." + native.removeprefix("Event.EventData."), (native,))
    for typed, candidates in mappings.items():
        native_candidates = (candidates,) if isinstance(candidates, str) else candidates
        available = [
            (native, native_type)
            for native in native_candidates
            if (native_type := _native_type(field_types, native)) is not None
        ]
        flat_available = [(native, native_type) for native in (NXLOG_FLAT_NAMES.get(typed, ()) if flat else ())
                          if (native_type := _native_type(field_types, native)) is not None]
        if not available:
            available = flat_available            # NXLog's flat records alone name this value
        elif flat_available:
            # An NXLog name joins a Winlogbeat alias only when it never narrows it: its ops cover the alias's,
            # and an alias the sweep aggregates keeps one native. Otherwise the flat records stay selected by
            # their shape, and value queries on them are listed as unresolved (hunt.sweep._nxlog_selector).
            base_ops = set.intersection(*(OPS_BY_TYPE.get(kind, set()) for _, kind in available))
            grouped = typed in _GROUPED_ALIASES and len(available) == 1 and available[0][1] in AGGREGATABLE
            if not grouped:
                available += [(native, kind) for native, kind in flat_available
                              if OPS_BY_TYPE.get(kind, set()) >= base_ops]
        if not available:
            continue
        common_ops = set.intersection(*(OPS_BY_TYPE.get(native_type, set()) for _, native_type in available))
        # Object-type equality is case-insensitive locally. The compiler's wildcard
        # form is not supported by flattened fields on Elasticsearch 8.19; a plain
        # term would silently miss differently cased values. Keep retrieval broad
        # until the contract carries a backend capability for that operation.
        # https://www.elastic.co/guide/en/elasticsearch/reference/8.19/flattened.html#supported-operations
        if typed == "object.type" and any(kind == "flattened" for _, kind in available):
            common_ops.discard("eq")
        evtx_alias = any(native.startswith("Event.") for native, _kind in available)
        exact, exact_limit = (_keyword_subfields(available, keyword_limits or {})
                              if (windows or ecar) and (typed not in _CLASS_SELECTORS or evtx_alias) else ((), None))
        if exact:
            common_ops |= SUBFIELD_EQUALITY_OPS
        native, native_type = available[0]
        aggregation_native = exact[0] if (evtx_alias or ecar) and len(available) == 1 and exact else None
        if ecar and typed in {"network.direction", "network.transport", "auth.target_user", "user.name", "user.domain"}:
            common_ops &= {"exists", "missing"}  # normalized enum/account values are not raw native equalities
        if ecar and typed in {"process.entity_id", "ecar.record_id"}:
            common_ops &= {"exists", "missing"}  # UUID accepts more source spellings than a canonical value can select
        if ecar and typed in {"source.ip", "destination.ip"} and any(kind != "ip" for _native, kind in available):
            common_ops &= {"exists", "missing"}  # normalized IPv6 spelling need not equal a keyword's source spelling
        if ecar and typed in {"source.port", "destination.port", "source.pid", "target.pid", "source.thread.id",
                              "thread.id", "process.access.mask", "auth.logon_type"} and any(
            kind not in {"long", "integer", "short"} for _native, kind in available
        ):
            common_ops &= {"exists", "missing"}  # decimal strings may carry noncanonical leading zeroes
        fields[typed] = FieldSpec(
            native=native,
            natives=tuple(item[0] for item in available),
            type=native_type,
            ops=sorted(common_ops),
            aggregatable=(len(available) == 1 and (native_type in AGGREGATABLE or aggregation_native is not None)
                          and not (ecar and typed in {"process.entity_id", "ecar.record_id"})),
            exact=exact,
            exact_limit=exact_limit,
            aggregation_native=aggregation_native,
        )
    if grouped_evtx:
        raw = contract_from_types(target, {name: kind for name, kind in field_types.items()
                                          if name.startswith("Event.") or name == "@timestamp"},
                                  role="host", os_family="windows", keyword_limits=keyword_limits,
                                  linux_text_mixed=False)
        for typed in grouped_evtx:
            alternative = raw.fields.get(typed)
            if alternative is None and typed == "event.code":
                alternative = FieldSpec(native="Event.System.EventID", type="object", ops=["exists", "missing"],
                                        aggregatable=False)
            if alternative is not None:
                base = fields[typed]
                fields[typed] = base.model_copy(update={"alternatives": (alternative,),
                    "ops": sorted(set(base.ops) & set(alternative.ops))})
    time_field = "firstPacket" if schema_of(field_types) == "arkime_sessions" else "@timestamp"
    if evtx:
        time_field = _evtx_time_field(field_types)
    if ecar:
        time_field = _ecar_time_field(field_types)
    resolved_os = os_family or source_os_family(field_types, resolved_role, datasets)
    return FieldContract(
        target=target, fields=fields, time_field=time_field, role=resolved_role, os_family=resolved_os,
        linux_fields=direct_fields if windows else {},
        hosts=hosts, host_inventory_complete=host_inventory_complete,
        nxlog_mixed=nxlog_mixed(field_types, resolved_role, resolved_os),
        windows_shapes=evtx_json_shapes(field_types) if evtx else (),
        ecar=ecar, temporal_gaps=temporal_gaps,
        linux_text_mixed=(not ecar and resolved_role == "host" and resolved_os == "windows"
                          and any(name in field_types for name in ("message", "event.original"))
                          and any(name in field_types for name in ("event.dataset", "data_stream.dataset",
                                                                  "input.type", "log.file.path")))
                         if linux_text_mixed == "mapping" else (False if ecar else linux_text_mixed),
    )


def nxlog_mixed(field_types, role: str, os_family: str) -> bool:
    """A Linux host target whose mapping also holds NXLog's flat Windows records: the sweep selects its Linux
    datasets and the flat Windows shape together, each exactly as it would alone. Its contract keeps the Linux names
    (no Windows alias is added), so value queries on the flat records are listed as unresolved."""
    return (role == "host" and os_family != "windows" and nxlog_flat(field_types)
            and not _winlog_mapping(field_types))


MIXED_NETWORK_KIND = "mixed_network"
PROVIDER_INVENTORY_PAGE_SIZE = 500
PROVIDER_INVENTORY_PAGE_LIMIT = 20
# Providers whose rows another normalizer reads in a mixed index (Malcolm writes event.provider on each row).
MIXED_PROVIDERS = frozenset({"zeek", "suricata"})


def inventory_key(provider, dataset) -> str:
    """The dataset key one (provider, dataset) bucket of a mixed index is listed under, in the sweep's names: a Zeek
    row by its log's dispatch token (`zeek:conn`; a log outside the catalog as `zeek:<name>`), a Suricata row by its
    EVE event type (`suricata.eve.alert`), an Arkime session (Arkime's provider, or no provider and no dataset) as
    `arkime.session`, and anything else by its dataset as written."""
    name = dataset.strip().lower() if isinstance(dataset, str) and dataset.strip() else None
    if provider == "zeek" and name is not None:
        log = lookup_log(MALCOLM, name)
        return log.token if log is not None else f"zeek:{name}"
    if provider == "suricata" and name is not None:
        return f"suricata.eve.{name}"
    if provider == "arkime" or (provider in (None, "") and name is None):
        return "arkime.session"
    return name if name is not None else f"{provider}:"


def provider_inventory(client, target: str, *, provider_field='event.provider', dataset_field='event.dataset'
                       ) -> tuple[list[dict], dict[str, int], list[str]] | None:
    """A mixed index's inventory by (event.provider, event.dataset), paged to exhaustion within a page budget, or None
    when the index holds no Zeek or Suricata rows (it stays an Arkime session index). Returns the buckets, the counts
    by `inventory_key`, and notes (a page budget reached is named as a truncated inventory)."""
    if provider_field is None or dataset_field is None:
        return [], {}, ['ds inventory truncated (provider/dataset fields have no exact-searchable aggregation field)']
    after = None
    buckets: list[dict] = []
    notes: list[str] = []
    for _page in range(PROVIDER_INVENTORY_PAGE_LIMIT):
        composite = {"size": PROVIDER_INVENTORY_PAGE_SIZE, "sources": [
            {"provider": {"terms": {"field": provider_field, "missing_bucket": True}}},
            {"dataset": {"terms": {"field": dataset_field, "missing_bucket": True}}},
        ]}
        if after is not None:
            composite["after"] = after
        response = client.search(target, {"size": 0, "track_total_hits": False,
                                          "aggs": {"inventory": {"composite": composite}}})
        agg = (response.get("aggregations") or {}).get("inventory") or {}
        page = agg.get("buckets") or []
        for bucket in page:
            key = bucket.get("key") if isinstance(bucket.get("key"), dict) else {}
            buckets.append({"provider": key.get("provider"), "dataset": key.get("dataset"),
                            "records": int(bucket.get("doc_count") or 0)})
        after = agg.get("after_key")
        if not after or not page:
            break
    else:
        notes.append(f"ds inventory truncated (provider/dataset composite page budget {PROVIDER_INVENTORY_PAGE_LIMIT} "
                     f"exceeded)")
    if not any(bucket["provider"] in MIXED_PROVIDERS for bucket in buckets):
        return None
    datasets: dict[str, int] = {}
    for bucket in buckets:
        key = inventory_key(bucket["provider"], bucket["dataset"])
        datasets[key] = datasets.get(key, 0) + bucket["records"]
    return buckets, dict(sorted(datasets.items())), notes


def _text_sample(client, target: str, query: dict, records: int | None, *, count=False) -> dict:
    """One bounded source sample; format counts describe this sample, never the whole index."""
    from romulus.evidence.linux_text import classify

    result = {"sampled": 0, "formats": {}, "programs": {}, "complete": False,
              "sample_complete": False, "notes": []}
    if count:
        result["records"] = None
    try:
        response = client.search(target, {
            "size": TEXT_SAMPLE_LIMIT, "track_total_hits": count, "query": query,
            "_source": ["message", "event.original", "event.dataset", "data_stream.dataset"],
        })
    except SourceError as error:
        result["notes"].append(f"text sample unavailable: {error}")
        return result
    partial = bool(response.get("timed_out") or response.get("terminated_early")
                   or (response.get("_shards") or {}).get("failed"))
    result["sample_complete"] = not partial
    if partial:
        result["notes"].append("text sample incomplete: source timeout, early termination, or failed shards")
    if count:
        total = (response.get("hits") or {}).get("total")
        if isinstance(total, dict) and total.get("relation") == "eq" and not partial:
            records = int(total["value"])
            result["records"] = records
        else:
            result["notes"].append("potential source record count unknown: no complete exact source total")
    hits = (response.get("hits") or {}).get("hits") or []
    formats: Counter = Counter()
    programs: Counter = Counter()
    for hit in hits[:TEXT_SAMPLE_LIMIT]:
        payload = text_payload(hit.get("_source") or {})
        if payload is None:
            formats["no_text_payload"] += 1
            continue
        parsed = classify(payload[1])
        formats[parsed.format] += 1
        if parsed.program:
            # The sample has at most 1000 keys; bound each untrusted log identifier too.
            program = parsed.program if len(parsed.program) <= 256 else parsed.program[:256] + "..."
            programs[program] += 1
            if len(parsed.program) > 256 and "program names shortened to 256 characters" not in result["notes"]:
                result["notes"].append("program names shortened to 256 characters")
    result.update(sampled=min(len(hits), TEXT_SAMPLE_LIMIT), formats=dict(sorted(formats.items())),
                  programs=dict(sorted(programs.items())))
    result["complete"] = not partial and records is not None and result["sampled"] == records
    if records is not None and records > TEXT_SAMPLE_LIMIT:
        result["notes"].append(f"format sample capped at {TEXT_SAMPLE_LIMIT} of {records} potential source records")
    elif not result["complete"] and not result["notes"]:
        result["notes"].append("format sample does not cover every potential source record")
    return result


def _missing_dataset(field_types: dict, name: str) -> dict:
    """Match an absent/null or empty dataset, as document_dataset falls through to the next native field."""
    absent = {"bool": {"must_not": [{"exists": {"field": name}}]}}
    exact = _aggregation_field(field_types, name) if name in field_types else None
    if exact is None:
        return absent
    return {"bool": {"should": [absent, {"term": {exact: ""}}], "minimum_should_match": 1}}


def _fallback_text_inventory(client, target: str, field_types: dict, notes: list[str]) -> tuple[dict, str | None]:
    """Bound the second native dataset inventory to records where event.dataset does not name a dataset."""
    if not all(name in field_types for name in ("event.dataset", "data_stream.dataset")):
        return {}, None
    field = _aggregation_field(field_types, "data_stream.dataset")
    if field is None:
        notes.append("ds inventory truncated (data_stream.dataset has no exact-searchable aggregation field)")
        return {}, None
    query = {"bool": {"filter": [_missing_dataset(field_types, "event.dataset"),
                                  {"exists": {"field": "data_stream.dataset"}}],
                       "must_not": [{"term": {field: ""}}]}}
    try:
        response = client.search(target, {"size": 0, "track_total_hits": True, "query": query,
                                          "aggs": {"ds": {"terms": {"field": field, "size": 200}}}})
    except SourceError as error:
        notes.append(f"ds inventory truncated (data_stream.dataset fallback unavailable: {error})")
        return {}, field
    agg = (response.get("aggregations") or {}).get("ds") or {}
    buckets = agg.get("buckets") or []
    inventory = {bucket["key"]: int(bucket["doc_count"]) for bucket in buckets if bucket["key"]}
    total = (response.get("hits") or {}).get("total") or {}
    if (response.get("timed_out") or response.get("terminated_early")
            or (response.get("_shards") or {}).get("failed") or "buckets" not in agg
            or agg.get("sum_other_doc_count") or agg.get("doc_count_error_upper_bound")
            or not isinstance(total, dict) or total.get("relation") != "eq"
            or total.get("value") != sum(inventory.values())):
        notes.append("ds inventory truncated (data_stream.dataset fallback did not return a complete exact inventory)")
    return inventory, field


def _text_profile(client, target: str, field_types: dict, datasets: dict, dataset_field: str | None,
                  role: str, os_family: str, notes: list[str]) -> dict | None:
    """Preserve raw inventory and add an explicitly non-additive logical capability roll-up."""
    if role != "host" or os_family != "linux" or not any(
        name in field_types for name in ("message", "event.original")
    ):
        return None
    secondary, secondary_field = _fallback_text_inventory(client, target, field_types, notes)
    # Empty native values are not dataset names; the record is selected through the next native field or as
    # datasetless. Keeping the empty bucket here would count those same records twice in the logical roll-up.
    datasets.pop("", None)
    for name, records in secondary.items():
        datasets[name] = datasets.get(name, 0) + records
    inventory = text_dataset_inventory(datasets)
    if "linux.text" in datasets:
        inventory["linux.text"] = datasets["linux.text"]
    datasetless = any(name in field_types for name in ("input.type", "log.file.path"))
    if not inventory and not datasetless:
        return None
    detail = {
        "logical_dataset": "linux.text", "inventory": dict(sorted(inventory.items())),
        "count_scope": "whole index at source preflight; potential source records, not typed events; "
                       "the logical roll-up is non-additive",
        "samples": {},
    }
    for name, records in sorted(inventory.items()):
        if dataset_field is None:
            detail["samples"][name] = {"sampled": 0, "formats": {}, "programs": {}, "complete": False,
                                       "notes": ["dataset has no exact-searchable field for sampling"]}
        else:
            query = {"term": {dataset_field: name}}
            if name in secondary:
                query = {"bool": {"should": [query, {"bool": {"filter": [
                    _missing_dataset(field_types, "event.dataset"), {"term": {secondary_field: name}},
                ]}}], "minimum_should_match": 1}}
            detail["samples"][name] = _text_sample(client, target, query, records)
    rollup_count = sum(inventory.values())
    if datasetless:
        sources = []
        input_field = _aggregation_field(field_types, "input.type") if "input.type" in field_types else None
        if input_field:
            sources.append({"terms": {input_field: list(TEXT_INPUT_TYPES)}})
        if "log.file.path" in field_types:
            sources.append({"exists": {"field": "log.file.path"}})
        if sources:
            query = {"bool": {"filter": [
                *[_missing_dataset(field_types, name) for name in ("event.dataset", "data_stream.dataset")],
                {"bool": {"should": [{"exists": {"field": name}} for name in ("message", "event.original")
                                       if name in field_types], "minimum_should_match": 1}},
                {"bool": {"should": sources, "minimum_should_match": 1}},
            ]}}
            module = _aggregation_field(field_types, "event.module") if "event.module" in field_types else None
            if module:
                query["bool"]["must_not"] = [{"terms": {module: ["auditd", "system", "apache"]}}]
            sample = _text_sample(client, target, query, None, count=True)
        else:
            sample = {"records": None, "sampled": 0, "formats": {}, "programs": {}, "complete": False,
                      "notes": ["datasetless input has no exact-searchable source selector"]}
        if sample["records"] == 0:
            datasetless = False
        else:
            detail["datasetless"] = sample
        if sample["records"] is None:
            rollup_count = None
            notes.append("ds inventory truncated (linux.text potential source count is unknown)")
        else:
            rollup_count += sample["records"]
        if rollup_count == 0:
            return None
    detail["rollup"] = {"records": rollup_count, "non_additive": True,
                        "members": sorted(inventory), "includes_datasetless": bool(datasetless)}
    if rollup_count is not None:
        datasets["linux.text"] = rollup_count
    notes.append("linux.text is a non-additive roll-up of potential source records; format counts are a bounded sample")
    return detail


def mixed_text_query(fields) -> dict:
    """Bounded native shape selector shared by preflight and retrieval.

    Object exists queries inspect their indexed children. Empty/unindexed Windows objects may pass this source
    superset; record-level dispatch still rejects them as text rather than guessing their source.
    """
    return {"bool": {"filter": [{"bool": {"should": [
        {"exists": {"field": name}} for name in ("message", "event.original") if name in fields
    ], "minimum_should_match": 1}}], "must_not": [
        {"exists": {"field": name}} for name in ("winlog", "Event.System", "Channel", "EventID", "SourceName")
    ]}}


def _mixed_text_profile(client, target, field_types, datasets, notes):
    """One bounded sample and exact source total; failures remain unknown and zero changes no inventory."""
    sample = _text_sample(client, target, mixed_text_query(field_types), None, count=True)
    count = sample.get("records")
    if count == 0:
        return False, None
    if count is None:
        notes.append("mixed Linux text count unavailable; text families unresolved")
    else:
        datasets["linux.text"] = count
    return (None if count is None else True), {
        "logical_dataset": "linux.text", "inventory": {}, "samples": {}, "datasetless": sample,
        "count_scope": "whole index at source preflight; text payload without indexed Windows markers",
        "rollup": {"records": count, "non_additive": True, "members": [], "includes_datasetless": True},
    }


def _windows_record_count(client, target, field_types, datasets, role, notes):
    """Records, not shared mappings, decide live Windows classification. None preserves the unverified fallback."""
    known = {name: count for name, count in datasets.items() if str(name).casefold() in WINDOWS_DATASETS}
    if known and role == "host":
        return sum(known.values())
    if not (_winlog_mapping(field_types) or _evtx_json_mapping(field_types) or nxlog_flat(field_types) or known):
        return 0
    markers = [{"exists": {"field": name}} for name in (
        "winlog.channel", "winlog.provider_name", "Event.System.Channel") if name in field_types]
    for provider in ("Event.System.Provider.#attributes.Name", "Event.System.Provider_attributes.Name"):
        if provider in field_types and "Event.System.Computer" in field_types:
            # A native null Channel is legitimate for the existing RPC catalog exception.
            markers.append({"bool": {"filter": [{"exists": {"field": provider}},
                                                {"exists": {"field": "Event.System.Computer"}}]}})
    if nxlog_flat(field_types):
        markers.append({"bool": {"filter": [{"exists": {"field": name}} for name in NXLOG_MARKERS]}})
    for name in ("event.dataset", "data_stream.dataset"):
        if name in field_types and (native := _aggregation_field(field_types, name)):
            markers.append({"terms": {native: sorted(WINDOWS_DATASETS)}})
    if not markers:
        return 0
    try:
        result = client.search(target, {"size": 0, "track_total_hits": True,
            "query": {"bool": {"should": markers, "minimum_should_match": 1}}})
    except SourceError as error:
        reason = str(error)
    else:
        total = (result.get("hits") or {}).get("total")
        partial = result.get("timed_out") or result.get("terminated_early") or (result.get("_shards") or {}).get("failed")
        if isinstance(total, dict) and total.get("relation") == "eq" and not partial:
            return int(total["value"])
        reason = "no complete exact source total"
    notes.append(f"Windows classification unverified: marker count unavailable ({reason})")
    return None


def _extra_host_inventory(client, target, field, notes, *, query=None, paged=True):
    """A bounded native host pass, used for additional layouts or replacing template-only Windows host fields."""
    if field is None:
        notes.append("hosts inventory truncated (additional layout has no aggregatable host field)")
        return {}
    agg = ({"composite": {"size": HOST_INVENTORY_PAGE_SIZE, "sources": [{"host": {"terms": {"field": field}}}]}}
           if paged else {"terms": {"field": field, "size": 500}})
    body = {"size": 0, "aggs": {"hosts": agg}, **({"query": query} if query else {})}
    counts, used = {}, 0
    for _ in range(HOST_INVENTORY_PAGE_LIMIT):
        try:
            result = client.search(target, body)
        except SourceError as error:
            notes.append(f"hosts inventory truncated ({field}: {error})")
            break
        hosts = (result.get("aggregations") or {}).get("hosts") or {}
        used += len(json.dumps(hosts, separators=(",", ":"), default=str).encode())
        if used > HOST_INVENTORY_BYTE_BUDGET:
            notes.append(f"hosts inventory truncated ({field}: byte budget exceeded)")
            break
        if (result.get("timed_out") or result.get("terminated_early") or (result.get("_shards") or {}).get("failed")
                or hosts.get("sum_other_doc_count") or "buckets" not in hosts):
            notes.append(f"hosts inventory truncated ({field}: source inventory incomplete)")
        for bucket in hosts.get("buckets", []):
            key = bucket.get("key")
            host = key.get("host") if isinstance(key, dict) else key
            if host not in (None, ""):
                counts[str(host)] = counts.get(str(host), 0) + int(bucket.get("doc_count") or 0)
        if not paged or not hosts.get("after_key") or not hosts.get("buckets"):
            break
        agg["composite"]["after"] = hosts["after_key"]
    else:
        notes.append(f"hosts inventory truncated ({field}: page budget exceeded)")
    return counts


def build_profile(client, target: str, *, site_facts=None) -> tuple[SourceProfile, FieldContract]:
    """Read-only preflight of one concrete index."""
    mapping = client.mapping(target)
    field_types = flatten_mapping(mapping)
    schema = schema_of(field_types)
    declaration = site_facts.zeek.plain_sources.get(target) if site_facts is not None else None
    # Arkime sessions: time is the first packet; the "dataset" is the session protocol and the
    # reporting host is the capture node
    evtx_shapes = evtx_json_shapes(field_types)
    ecar = ecar_mapping(field_types)
    windows = ecar or bool(evtx_shapes) or "winlog.computer_name" in field_types or (
        _windows_mapping(field_types) and nxlog_flat(field_types) and "Hostname" in field_types)
    dataset_field = "event.dataset" if "event.dataset" in field_types else "data_stream.dataset"
    tf, ds_field, host_field = (("firstPacket", "protocol", "node") if schema == "arkime_sessions"
                                else ("@timestamp", dataset_field,
                                      ("winlog.computer_name" if "winlog.computer_name" in field_types
                                       else "Event.System.Computer" if evtx_shapes else "Hostname") if windows else "host.name"))
    if evtx_shapes:
        tf = _evtx_time_field(field_types)
    if ecar:
        tf, host_field = _ecar_time_field(field_types), "hostname"
    if declaration is not None:
        tf, ds_field, host_field = "ts", "_path", "_romulus_no_observer_field"
    notes = []
    declared_dataset = ds_field
    ds_field = _aggregation_field(field_types, ds_field)
    if ds_field is None:
        notes.append(f'ds inventory truncated ({declared_dataset} has no exact-searchable aggregation field)')
    declared_host = host_field
    host_field = _aggregation_field(field_types, host_field)
    if host_field is None:
        notes.append(f'hosts inventory truncated ({declared_host} has no exact-searchable aggregation field)')
    host_aggregation = ({"composite": {
        "size": HOST_INVENTORY_PAGE_SIZE,
        "sources": [{"host": {"terms": {"field": host_field}}}],
    }} if windows else {"terms": {"field": host_field, "size": 500}})
    body = {
        "size": 0, "track_total_hits": True,
        "aggs": {
            "tmin": {"min": {"field": tf}}, "tmax": {"max": {"field": tf}},
            "ds": {"terms": {"field": ds_field, "size": 200}},
            "hosts": host_aggregation,
        },
    }
    if ds_field is None:
        body['aggs'].pop('ds')
    if host_field is None:
        body['aggs'].pop('hosts')
    host_counts: dict[str, int] = {}
    if not windows:
        d = client.search(target, body)
        host_agg = d.get("aggregations", {}).get("hosts", {})
        host_counts = {str(b["key"]): int(b["doc_count"]) for b in host_agg.get("buckets", [])}
        if host_agg.get("sum_other_doc_count"):
            notes.append("hosts inventory truncated (sum_other_doc_count>0)")
    else:
        first = None
        host_bytes = 0
        for _page in range(HOST_INVENTORY_PAGE_LIMIT):
            d = client.search(target, body)
            first = first or d
            host_agg = d.get("aggregations", {}).get("hosts", {})
            host_bytes += len(json.dumps(host_agg, separators=(",", ":"), default=str).encode())
            if host_bytes > HOST_INVENTORY_BYTE_BUDGET:
                notes.append(
                    f"hosts inventory truncated (composite byte budget {HOST_INVENTORY_BYTE_BUDGET} exceeded)"
                )
                break
            for bucket in host_agg.get("buckets", []):
                key = bucket.get("key") or {}
                host = key.get("host") if isinstance(key, dict) else key
                if host not in (None, ""):
                    host_counts[str(host)] = host_counts.get(str(host), 0) + int(bucket.get("doc_count") or 0)
            after = host_agg.get("after_key")
            if not after or not host_agg.get("buckets"):
                break
            body = {
                **body,
                "aggs": {
                    **body["aggs"],
                    "hosts": {"composite": {**body["aggs"]["hosts"]["composite"], "after": after}},
                },
            }
        else:
            notes.append(f"hosts inventory truncated (composite page budget {HOST_INVENTORY_PAGE_LIMIT} exceeded)")
        d = first or {}
    aggs = d.get("aggregations", {})
    if aggs.get("ds", {}).get("sum_other_doc_count"):
        notes.append("ds inventory truncated (sum_other_doc_count>0)")
    datasets = {b["key"]: b["doc_count"] for b in aggs.get("ds", {}).get("buckets", [])}
    kind = "es_index" if schema == "lab_ecs" else schema
    inventory = None
    if schema == "arkime_sessions" and "event.provider" in field_types and "event.dataset" in field_types:
        # Malcolm indexes Zeek and Suricata rows beside Arkime's sessions in one index: each row is read by its own
        # normalizer, so the inventory is by (provider, dataset), not by Arkime protocol.
        mixed = provider_inventory(client, target,
            provider_field=_aggregation_field(field_types, 'event.provider'),
            dataset_field=_aggregation_field(field_types, 'event.dataset'))
        if mixed is not None:
            inventory, datasets, mixed_notes = mixed
            notes = [note for note in notes if not note.startswith("ds inventory truncated")] + mixed_notes
            kind = MIXED_NETWORK_KIND
    role = source_role(field_types, set(datasets))
    os_family = source_os_family(field_types, role, datasets)
    windows_records = _windows_record_count(client, target, field_types, datasets, role, notes)
    if windows_records is not None:
        os_family = "windows" if role == "host" and (ecar or windows_records > 0) else ("linux" if role == "host" else "unknown")
    if windows and (os_family != "windows" or role == "network"):
        notes[:] = [note for note in notes if not note.startswith("hosts inventory truncated")]
        host_counts = _extra_host_inventory(client, target, _aggregation_field(field_types, "host.name"), notes, paged=False)
    if role == "host" and os_family == "windows" and evtx_shapes and "winlog.computer_name" in field_types:
        additional = _extra_host_inventory(client, target, _aggregation_field(field_types, "Event.System.Computer"), notes,
            query={"bool": {"filter": [{"exists": {"field": "Event.System.Computer"}},
                {"bool": {"must_not": [{"exists": {"field": "winlog.computer_name"}}]}}]}})
        for host, count in additional.items():
            host_counts[host] = host_counts.get(host, 0) + count
    if host_field == "Hostname" and os_family != "windows":
        # counted by NXLog's computer name before the inventory showed Linux datasets: their hosts are not counted
        notes.append("hosts inventory truncated (counted by NXLog's Hostname; the Linux records' hosts are not)")
    prof = {
        "target": target, "kind": kind,
        "role": role, "os_family": os_family,
        "backend": client.settings.es_flavor, "backend_version": client.version,
        "captured_at": datetime.now(UTC), "field_types": field_types,
        "datasets": datasets,
        "hosts": host_counts,
        "time_min": aggs.get("tmin", {}).get("value_as_string"),
        "time_max": aggs.get("tmax", {}).get("value_as_string"),
        "doc_count": d.get("hits", {}).get("total", {}).get("value"), "notes": notes,
    }
    if declaration is not None:
        role, os_family = "network", "unknown"
        datasets = {"zeek:"+name: count for name, count in datasets.items()}
        if declaration.log is not None:
            datasets = {"zeek:"+declaration.log: prof["doc_count"] or 0}
        prof.update(kind="plain_zeek", role=role, os_family=os_family, datasets=datasets,
                    hosts={declaration.sensor: prof["doc_count"] or 0}, zeek_sensor=declaration.sensor,
                    zeek_log=declaration.log,
                    time_min=datetime.fromtimestamp(aggs["tmin"]["value"], UTC).isoformat()
                        if aggs.get("tmin", {}).get("value") is not None else None,
                    time_max=datetime.fromtimestamp(aggs["tmax"]["value"], UTC).isoformat()
                        if aggs.get("tmax", {}).get("value") is not None else None)
    if inventory is not None:
        prof["inventory"] = inventory
    if ecar and role == "host":
        count, reason = _source_count(client, target, {"bool": {"filter": [
            {"exists": {"field": name}} for name in ("object", "action", "objectID", "actorID", "hostname")]}})
        prof.update(ecar=True, windows_shapes={"ecar": {"records": count, "complete": count is not None,
                                                        **({"reason": reason} if reason else {})}})
        if tf != "@timestamp":
            for label in ("tmin", "tmax"):
                value = aggs.get(label, {}).get("value")
                prof["time_min" if label == "tmin" else "time_max"] = (
                    datetime.fromtimestamp(value/1000, UTC).isoformat() if value is not None else None)
    if role == "network" and windows_records:
        reason = f"Windows event records on a network target: {windows_records}, not evaluated"
        notes.append(reason)
        prof["windows_not_assessed"] = {"records": windows_records, "reason": reason,
                                         "count_scope": "whole index at source preflight"}
    if evtx_shapes and role == "host" and os_family == "windows":
        prof["windows_shapes"] = _evtx_shape_inventory(client, target, evtx_shapes)
    mixed_text = False
    temporal = _temporal_inventory(client, target, field_types, tf, ecar=ecar) if role == "host" and os_family == "windows" else []
    if temporal:
        prof["temporal_gaps"] = temporal
        notes.extend(item["reason"] for item in temporal)
    if declaration is None and not ecar and role == "host" and os_family == "windows" and any(
        name in field_types for name in ("message", "event.original")
    ):
        mixed_text, text_detail = _mixed_text_profile(client, target, field_types, datasets, notes)
        if mixed_text is not False:
            prof.update(linux_text_mixed=mixed_text, linux_text=text_detail)
    elif declaration is None:
        text_detail = _text_profile(client, target, field_types, datasets, ds_field, role, os_family, notes)
        if text_detail is not None:
            prof["linux_text"] = text_detail
    # Role and OS are source semantics, so they intentionally participate in the profile id. Adding them changes
    # ids made by older builds; the manifest also records both values explicitly for resume validation.
    pid = digest({k: v for k, v in prof.items() if k != "captured_at"})[:16]
    profile = SourceProfile(id=pid, **prof)
    contract = contract_from_types(
        target,
        field_types,
        role=role, os_family=os_family,
        hosts=tuple(sorted(profile.hosts)),
        host_inventory_complete=not any(note.startswith("hosts inventory truncated") for note in notes),
        datasets=datasets,
        keyword_limits=keyword_subfield_limits(mapping),
        linux_text_mixed=mixed_text,
        temporal_gaps=tuple(item["reason"] for item in temporal),
    )

    return profile, apply_zeek_declaration(contract, site_facts) if declaration is not None else contract


def _evtx_shape_inventory(client, target, shapes) -> dict:
    """One exact count per mapped EVTX layout; failed counts stay unknown rather than becoming zero."""
    inventory = {}
    for shape in shapes:
        provider = ("Event.System.Provider_attributes.Name" if shape == "evtx_json_flat"
                    else "Event.System.Provider.#attributes.Name")
        entry = {"records": None, "complete": False}
        try:
            result = client.search(target, {"size": 0, "track_total_hits": True, "query": {"bool": {"filter": [
                {"exists": {"field": "Event.System.Computer"}}, {"exists": {"field": provider}},
            ]}}})
        except SourceError as error:
            entry["reason"] = f"Windows source shape count unavailable: {error}"
        else:
            total = (result.get("hits") or {}).get("total")
            partial = result.get("timed_out") or result.get("terminated_early") or (result.get("_shards") or {}).get("failed")
            if isinstance(total, dict) and total.get("relation") == "eq" and not partial:
                entry.update(records=int(total["value"]), complete=True)
            else:
                entry["reason"] = "Windows source shape count unavailable: no complete exact source total"
        inventory[shape] = entry
    return inventory


def _source_count(client, target, query):
    try:
        result = client.search(target, {"size": 0, "track_total_hits": True, "query": query})
    except SourceError as error:
        return None, str(error)
    total = (result.get("hits") or {}).get("total")
    partial = result.get("timed_out") or result.get("terminated_early") or (result.get("_shards") or {}).get("failed")
    if isinstance(total, dict) and total.get("relation") == "eq" and not partial:
        return int(total["value"]), None
    return None, "no complete exact source total"


def _temporal_inventory(client, target, field_types, primary, *, ecar=False):
    """Count source rows the single native time range cannot reach, preserving per-record fallback precedence.

    This is whole-index preflight, not a hunt-window negative: any nonzero or unknown count leaves temporal
    coverage unresolved. Coalesced multi-field sort/histogram retrieval is deliberately not claimed.
    """
    alternatives = (["timestamp_ms", "timestamp"] if ecar else [
        "Event.System.TimeCreated.#attributes.SystemTime", "Event.System.TimeCreated_attributes.SystemTime"])
    markers = ["object", "action", "objectID", "actorID", "hostname"] if ecar else ["Event.System.Computer"]
    gaps, prior = [], [primary]
    for alternate in alternatives:
        if alternate == primary or alternate not in field_types:
            continue
        query = {"bool": {"filter": [{"exists": {"field": name}} for name in (*markers, alternate)],
                          "must_not": [{"exists": {"field": name}} for name in prior]}}
        count, error = _source_count(client, target, query)
        prior.append(alternate)
        if count == 0:
            continue
        scope = "whole index at source preflight; hunt-window membership unverified"
        reason = (f"temporal coverage unresolved: {count if count is not None else 'unknown'} source records omitted "
                  f"when {primary} is absent and {alternate} supplies time ({scope})"
                  + (f"; count unavailable: {error}" if error else ""))
        gaps.append({"records": count, "primary": primary, "alternate": alternate, "count_scope": scope, "reason": reason})
    return gaps
