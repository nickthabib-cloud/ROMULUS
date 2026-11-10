"""Build SourceProfiles and FieldContracts from the live mapping of a concrete target."""
from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, model_serializer, model_validator

from romulus.evidence.linux_catalog import LINUX_LOGICAL_DATASETS, logical_of
from romulus.evidence.zeek_catalog import MALCOLM, lookup_log
from romulus.sources.models import typed_field_name
from romulus.store.db import digest

HOST_INVENTORY_PAGE_SIZE = 500
HOST_INVENTORY_PAGE_LIMIT = 100
HOST_INVENTORY_BYTE_BUDGET = 8 * 1024 * 1024

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


def linux_markers(field_types, datasets=None) -> bool:
    """Whether a target holds Linux host telemetry: a Linux shipper dataset in its inventory (a logical Linux dataset
    or a shipper's name for one), or a field only Linux host shippers write. Dataset-less Linux shapes (journald,
    Auditbeat without a dataset) are not in the inventory, so the fields still count."""
    if any(str(name) in LINUX_LOGICAL_DATASETS or logical_of(str(name)) is not None for name in datasets or ()):
        return True
    return any(field.startswith(LINUX_FIELD_PREFIXES) for field in field_types)


def _windows_mapping(field_types, datasets=None) -> bool:
    return _winlog_mapping(field_types) or (nxlog_flat(field_types) and not linux_markers(field_types, datasets))


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
    ) or nxlog_flat(field_types)
    return "network" if network_shape and not host_shape else "host"


def source_os_family(field_types: dict[str, str], role: str, datasets=None) -> Literal["linux", "windows", "unknown"]:
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
) -> FieldContract:
    """Build a typed contract, adding explicit aliases for native schemas such as Windows event data. `datasets` is
    the target's dataset inventory, when known: a Linux dataset in it makes a mapping that also holds NXLog's flat
    fields a Linux target that holds NXLog records too (`nxlog_mixed`)."""
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
    windows = _windows_mapping(field_types, datasets) or (os_family == "windows" and nxlog_flat(field_types))
    flat = windows and nxlog_flat(field_types)
    if windows:
        mappings = {**WINDOWS_FIELD_MAPPINGS, **({"winlog.record_id": ("winlog.record_id",)} if flat else {}),
                    **mappings}
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
    resolved_os = os_family or source_os_family(field_types, resolved_role, datasets)
    return FieldContract(
        target=target, fields=fields, time_field=time_field, role=resolved_role, os_family=resolved_os,
        linux_fields=direct_fields if windows else {},
        hosts=hosts, host_inventory_complete=host_inventory_complete,
        nxlog_mixed=nxlog_mixed(field_types, resolved_role, resolved_os),
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


def build_profile(client, target: str, *, site_facts=None) -> tuple[SourceProfile, FieldContract]:
    """Read-only preflight of one concrete index."""
    field_types = flatten_mapping(client.mapping(target))
    schema = schema_of(field_types)
    declaration = site_facts.zeek.plain_sources.get(target) if site_facts is not None else None
    # Arkime sessions: time is the first packet; the "dataset" is the session protocol and the
    # reporting host is the capture node
    windows = "winlog.computer_name" in field_types or (
        _windows_mapping(field_types) and nxlog_flat(field_types) and "Hostname" in field_types)
    dataset_field = "event.dataset" if "event.dataset" in field_types else "data_stream.dataset"
    tf, ds_field, host_field = (("firstPacket", "protocol", "node") if schema == "arkime_sessions"
                                else ("@timestamp", dataset_field,
                                      ("winlog.computer_name" if "winlog.computer_name" in field_types
                                       else "Hostname") if windows else "host.name"))
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
    )

    return profile, apply_zeek_declaration(contract, site_facts) if declaration is not None else contract
