"""Compile typed SearchIntents into validated backend queries through the FieldContract."""
from __future__ import annotations

import ipaddress
import re

from romulus.evidence.linux_catalog import (
    LINUX_LOGICAL_DATASETS,
    LINUX_SHIPPER_DATASETS,
    dataset_selection,
    shipper_names,
)
from romulus.evidence.normalize import ELASTIC_DATASET, ELASTIC_EVENT_TYPES
from romulus.sources.models import CompiledQuery, Predicate, SearchIntent
from romulus.sources.profile import FieldContract
from romulus.store.db import digest


class CompileError(ValueError):
    """The intent cannot be compiled exactly; never silently loosened."""


_WILDCARD_META = re.compile(r"([*?\\])")


def _escape_wildcard(s: str) -> str:
    return _WILDCARD_META.sub(r"\\\1", s)


def _pred_native(p: Predicate, native: str) -> dict:
    f = native
    v = p.value
    if p.op == "eq":
        return {"term": {f: v}}
    if p.op in {"in", "not_in"}:
        if not isinstance(v, list) or not v or len(v) > 1000:
            raise CompileError("'in' needs a non-empty list of at most 1000 values")
        terms = {"terms": {f: v}}
        return {"bool": {"must_not": [terms]}} if p.op == "not_in" else terms
    if p.op == "exists":
        return {"exists": {"field": f}}
    if p.op == "missing":
        return {"bool": {"must_not": [{"exists": {"field": f}}]}}
    if p.op == "prefix":
        return {"prefix": {f: {"value": str(v)}}}
    if p.op == "contains":
        # A list is any of its strings: one clause group, so alternatives never multiply across a group's predicates.
        values = v if isinstance(v, list) else [v]
        if not values or len(values) > 256 or not all(isinstance(item, str) and item for item in values):
            raise CompileError("'contains' needs a non-empty string, or a list of at most 256 of them")
        # case_insensitive keeps retrieval a superset of case-insensitive local evaluators
        clauses = [{"wildcard": {f: {"value": f"*{_escape_wildcard(item)}*", "case_insensitive": True}}}
                   for item in values]
        return clauses[0] if len(clauses) == 1 else {"bool": {"should": clauses, "minimum_should_match": 1}}
    if p.op == "gte":
        return {"range": {f: {"gte": v}}}
    if p.op == "lt":
        return {"range": {f: {"lt": v}}}
    if p.op == "cidr":
        ipaddress.ip_network(str(v), strict=False)  # validates
        return {"term": {f: str(v)}}
    raise CompileError(f"unknown op {p.op}")


_LINUX_HOST_DATASETS = frozenset({*LINUX_LOGICAL_DATASETS, *shipper_names()})
# Windows names matched without case (channel, provider, object type), in Winlogbeat's layout and NXLog's flat one
# (whose channel names keep the source's spelling, "security" for "Security").
_CASELESS_WINDOWS_NATIVES = frozenset({"winlog.channel", "winlog.provider_name", "winlog.event_data.ObjectType",
                                       "Channel", "SourceName", "ObjectType"})
_WINDOWS_COMPUTER_NATIVES = frozenset({"winlog.computer_name", "Hostname"})


def _linux_datasets(p: Predicate, contract: FieldContract, natives: tuple[str, ...]) -> dict | None:
    """A dataset predicate naming logical Linux datasets: any shipper shape of each, on every dataset field the
    target maps (event.dataset and data_stream.dataset). Auditbeat's bare `auditd` also needs its event.module, and
    a document that names no dataset is selected by its input.type (journald) or event.module (Auditbeat); a shape
    whose field the target cannot
    search is left out (the sweep lists it as not assessed). None when the predicate names no logical dataset."""
    if p.field != "event.dataset" or p.op not in {"eq", "in"}:
        return None
    values = [str(value) for value in (p.value if isinstance(p.value, list) else [p.value])]
    if not any(value in LINUX_SHIPPER_DATASETS for value in values):
        return None
    direct = contract.fields.get("data_stream.dataset")
    fields = [*natives, *(["data_stream.dataset"] if direct is not None and "in" in direct.ops
                          and "data_stream.dataset" not in natives else [])]
    plain, with_module, undated, _unsearchable = dataset_selection(
        values, module_searchable=contract.supports("event.module", "eq"),
        input_type_searchable=contract.supports("input.type", "eq"))
    if len(plain) > 1000:
        raise CompileError("'in' needs a non-empty list of at most 1000 values")
    clauses = [{"terms": {field: plain}} for field in fields] if plain else []
    module = contract.spec("event.module")
    for dataset, name in with_module:
        clauses.append({"bool": {"filter": [
            {"bool": {"should": [{"term": {field: dataset}} for field in fields], "minimum_should_match": 1}},
            {"term": {module.native if module is not None else "event.module": name}}]}})
    for name, value in undated:
        spec = contract.spec(name)
        clauses.append({"bool": {"filter": [{"term": {spec.native if spec is not None else name: value}}],
                                 "must_not": [{"exists": {"field": field}} for field in fields]}})
    return clauses[0] if len(clauses) == 1 else {"bool": {"should": clauses, "minimum_should_match": 1}}


def _suricata_datasets(p: Predicate, contract: FieldContract, natives: tuple[str, ...]) -> dict | None:
    """A dataset predicate naming Suricata's per-type datasets (`suricata.eve.alert`, ...) also selects the documents
    of those types that Filebeat's suricata module and the Agent's Suricata integration index under the one dataset
    `suricata.eve` (on either dataset field), by their parsed suricata.eve.event_type. Only on a target that maps that
    field (the shippers' templates do); None otherwise, and for a predicate naming no such dataset."""
    if p.field != "event.dataset" or p.op not in {"eq", "in"}:
        return None
    values = [str(value) for value in (p.value if isinstance(p.value, list) else [p.value])]
    types = sorted({value.removeprefix(f"{ELASTIC_DATASET}.") for value in values
                    if value.removeprefix(f"{ELASTIC_DATASET}.") in ELASTIC_EVENT_TYPES
                    and value.startswith(f"{ELASTIC_DATASET}.")})
    event_type = contract.fields.get("suricata.eve.event_type")
    if not types or event_type is None or "in" not in event_type.ops:
        return None
    direct = contract.fields.get("data_stream.dataset")
    fields = [*natives, *(["data_stream.dataset"] if direct is not None and "eq" in direct.ops
                          and "data_stream.dataset" not in natives else [])]
    named = [_pred_native(p, native) for native in natives]
    elastic = {"bool": {"filter": [
        {"bool": {"should": [{"term": {field: ELASTIC_DATASET}} for field in fields], "minimum_should_match": 1}},
        {"terms": {event_type.native: types}}]}}
    return {"bool": {"should": [*named, elastic], "minimum_should_match": 1}}


def _intent_os_family(intent: SearchIntent) -> str | None:
    values: set[str] = set()
    for predicate in [*intent.filters, *(item for group in intent.any_of for item in group)]:
        if predicate.field != "event.dataset" or predicate.op not in {"eq", "in"}:
            continue
        candidates = predicate.value if isinstance(predicate.value, list) else [predicate.value]
        values.update(str(value) for value in candidates)
    return "linux" if values and values <= _LINUX_HOST_DATASETS else None


def _pred(p: Predicate, contract: FieldContract, *, os_family: str | None = None) -> dict:
    spec = contract.spec(p.field, os_family=os_family)
    if spec is None:
        raise CompileError(f"field {p.field!r} not in field contract for {contract.target}")
    if p.op not in spec.ops:
        raise CompileError(f"op {p.op!r} not supported on {p.field} ({spec.type}) with superset guarantee")
    natives = spec.natives or (spec.native,)
    linux = _linux_datasets(p, contract, natives)
    if linux is not None:
        return linux
    suricata = _suricata_datasets(p, contract, natives)
    if suricata is not None:
        return suricata
    if (
        p.op == "eq"
        and p.field in {"event.channel", "event.provider", "object.type"}
        and any(native in _CASELESS_WINDOWS_NATIVES for native in natives)
    ):
        clauses = [
            {"wildcard": {native: {
                "value": _escape_wildcard(str(p.value)), "case_insensitive": True,
            }}}
            for native in natives
        ]
        return clauses[0] if len(clauses) == 1 else {
            "bool": {"should": clauses, "minimum_should_match": 1}
        }
    if p.op == "eq" and p.field in {"user.entity_id", "auth.target_account"}:
        value = str(p.value)
        if value.startswith("sid:"):
            raw_value = value.removeprefix("sid:")
            selected = [(native, raw_value) for native in natives if native.casefold().endswith("sid")]
        elif value.startswith("name:"):
            full_name = value.removeprefix("name:")
            short_name = full_name.rsplit("\\", 1)[-1]
            selected = [
                (native, full_name if native.casefold().endswith(".user") or native.casefold() == "user"
                 else short_name)
                for native in natives if not native.casefold().endswith("sid")
            ]
        else:
            selected = []
        if not selected:
            raise CompileError(f"canonical account value {value!r} has no compatible native mapping")
        clauses = [
            {"wildcard": {native: {"value": _escape_wildcard(raw), "case_insensitive": True}}}
            for native, raw in selected
        ]
        return clauses[0] if len(clauses) == 1 else {
            "bool": {"should": clauses, "minimum_should_match": 1}
        }
    if p.field == "host.name" and p.op == "eq" and any(native in _WINDOWS_COMPUTER_NATIVES for native in natives):
        # Normalized Windows hosts use their first DNS label. Query both the native
        # short form and any FQDN regardless of which form the caller supplied.
        value = _escape_wildcard(str(p.value).strip().rstrip(".").split(".", 1)[0])
        clauses = [
            {"wildcard": {native: {"value": pattern, "case_insensitive": True}}}
            for native in natives for pattern in (value, f"{value}.*")
        ]
        return {"bool": {"should": clauses, "minimum_should_match": 1}}
    clauses = [_pred_native(p, native) for native in natives]
    if len(clauses) == 1:
        return clauses[0]
    if p.op in {"missing", "not_in"}:
        return {"bool": {"filter": clauses}}
    return {"bool": {"should": clauses, "minimum_should_match": 1}}


def build_query(intent: SearchIntent, contract: FieldContract) -> dict:
    tf = contract.time_field
    os_family = _intent_os_family(intent)
    must = [{"range": {tf: {"gte": intent.window.start.isoformat(), "lt": intent.window.end.isoformat(),
                            "format": "strict_date_optional_time"}}}]
    if contract.zeek_sensor:
        must = [{"range": {tf: {"gte": intent.window.start.timestamp(), "lt": intent.window.end.timestamp()}}}]
    must += [_pred(p, contract, os_family=os_family) for p in intent.filters]
    query: dict = {"bool": {"filter": must}}
    if intent.any_of:
        groups = [{"bool": {"filter": [
            _pred(p, contract, os_family=os_family) for p in g
        ]}} for g in intent.any_of]
        query["bool"]["should"] = groups
        query["bool"]["minimum_should_match"] = 1
    return query


def compile_es(intent: SearchIntent, contract: FieldContract, flavor: str = "elasticsearch") -> CompiledQuery:
    if intent.target != contract.target:
        raise CompileError("intent target does not match contract target")
    query = build_query(intent, contract)
    if intent.kind == "raw":
        time_sort = {"order": intent.order}
        if flavor != "opensearch" and not contract.zeek_sensor:
            # OpenSearch's field sort refuses `format`; its date sort values are the field's own epoch numbers
            time_sort["format"] = "strict_date_optional_time_nanos"
        body = {
            "query": query,
            "sort": [
                {contract.time_field: time_sort},
                {"_shard_doc": intent.order},
            ],
        }
    elif intent.kind == "aggregate":
        if not intent.group_by:
            raise CompileError("aggregate intent needs group_by")
        sources = []
        for g in intent.group_by:
            spec = contract.spec(g, os_family=_intent_os_family(intent))
            if spec is None or not spec.aggregatable:
                raise CompileError(f"field {g!r} is not aggregatable on {contract.target}")
            sources.append({g: {"terms": {"field": spec.native, "missing_bucket": True}}})
        body = {"size": 0, "query": query, "track_total_hits": True,
                "aggs": {"g": {"composite": {"size": min(1000, intent.max_records), "sources": sources},
                               "aggs": {"first": {"min": {"field": contract.time_field}},
                                        "last": {"max": {"field": contract.time_field}}}}}}
    elif intent.kind == "histogram":
        sec = intent.interval_seconds or 3600
        body = {"size": 0, "query": query, "track_total_hits": True,
                "aggs": {"h": {"date_histogram": {"field": contract.time_field, "fixed_interval": f"{sec}s",
                                                  "min_doc_count": 0,
                                                  "extended_bounds": {"min": intent.window.start.isoformat(),
                                                                      "max": intent.window.end.isoformat()}}}}}
        if contract.zeek_sensor:
            body["aggs"]["h"] = {"histogram": {"field": contract.time_field, "interval": sec,
                "min_doc_count": 0, "extended_bounds": {"min": intent.window.start.timestamp(),
                                                         "max": intent.window.end.timestamp()}}}
    else:
        raise CompileError(f"unknown intent kind {intent.kind}")
    fp = digest({"target": intent.target, "kind": intent.kind, "body": body})
    return CompiledQuery(backend=flavor, target=intent.target, body=body, fingerprint=fp,
                         time_unit=time_unit(contract))


def time_unit(contract: FieldContract) -> str:
    """The resolution of the time field's epoch sort values: nanoseconds for `date_nanos`, else milliseconds."""
    if contract.zeek_sensor:
        return "s"
    time_spec = contract.fields.get(contract.time_field)
    return "ns" if time_spec is not None and time_spec.type == "date_nanos" else "ms"
