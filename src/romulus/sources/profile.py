"""Build SourceProfiles and FieldContracts from the live mapping of a concrete target."""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

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
}
AGGREGATABLE = {"keyword", "constant_keyword", "ip", "long", "integer", "short", "boolean", "date", "wildcard"}


class FieldSpec(BaseModel):
    native: str
    type: str
    ops: list[str]
    aggregatable: bool


class FieldContract(BaseModel):
    """Single mapping from ROMULUS typed fields to native fields for one target."""
    target: str
    fields: dict[str, FieldSpec]
    time_field: str = "@timestamp"

    def spec(self, typed: str) -> FieldSpec | None:
        return self.fields.get(typed)

    def supports(self, typed: str, op: str) -> bool:
        s = self.fields.get(typed)
        return bool(s and op in s.ops)


class SourceProfile(BaseModel):
    id: str
    target: str
    kind: str
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

    for _index, body in mapping.items():
        walk("", body.get("mappings", {}).get("properties", {}))
    return out


def contract_from_types(target: str, field_types: dict[str, str]) -> FieldContract:
    """Lab indices already use ECS-like names, so typed name == native name. Non-ECS schemas
    get an explicit alias table here when they are added (Zeek, Malcolm, Winlogbeat)."""
    fields = {
        name: FieldSpec(native=name, type=t, ops=sorted(OPS_BY_TYPE.get(t, set())), aggregatable=t in AGGREGATABLE)
        for name, t in field_types.items()
    }
    return FieldContract(target=target, fields=fields)


def build_profile(client, target: str) -> tuple[SourceProfile, FieldContract]:
    """Read-only preflight of one concrete index."""
    field_types = flatten_mapping(client.mapping(target))
    body = {
        "size": 0, "track_total_hits": True,
        "aggs": {
            "tmin": {"min": {"field": "@timestamp"}}, "tmax": {"max": {"field": "@timestamp"}},
            "ds": {"terms": {"field": "event.dataset", "size": 200}},
            "hosts": {"terms": {"field": "host.name", "size": 500}},
        },
    }
    d = client.request("POST", f"/{target}/_search", body)
    aggs = d.get("aggregations", {})
    notes = []
    for k in ("ds", "hosts"):
        if aggs.get(k, {}).get("sum_other_doc_count"):
            notes.append(f"{k} inventory truncated (sum_other_doc_count>0)")
    prof = dict(
        target=target, kind="es_index", backend=client.settings.es_flavor, backend_version=client.version,
        captured_at=datetime.now(UTC), field_types=field_types,
        datasets={b["key"]: b["doc_count"] for b in aggs.get("ds", {}).get("buckets", [])},
        hosts={b["key"]: b["doc_count"] for b in aggs.get("hosts", {}).get("buckets", [])},
        time_min=aggs.get("tmin", {}).get("value_as_string"), time_max=aggs.get("tmax", {}).get("value_as_string"),
        doc_count=d.get("hits", {}).get("total", {}).get("value"), notes=notes,
    )
    pid = digest({k: v for k, v in prof.items() if k != "captured_at"})[:16]
    profile = SourceProfile(id=pid, **prof)
    return profile, contract_from_types(target, field_types)
