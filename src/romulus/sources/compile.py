"""Compile typed SearchIntents into validated backend queries through the FieldContract."""
from __future__ import annotations

import ipaddress
import re

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
    if p.op == "in":
        if not isinstance(v, list) or not v or len(v) > 1000:
            raise CompileError("'in' needs a non-empty list of at most 1000 values")
        return {"terms": {f: v}}
    if p.op == "exists":
        return {"exists": {"field": f}}
    if p.op == "missing":
        return {"bool": {"must_not": [{"exists": {"field": f}}]}}
    if p.op == "prefix":
        return {"prefix": {f: {"value": str(v)}}}
    if p.op == "contains":
        if not isinstance(v, str) or not v:
            raise CompileError("'contains' needs a non-empty string")
        # case_insensitive keeps retrieval a superset of case-insensitive local evaluators
        return {"wildcard": {f: {"value": f"*{_escape_wildcard(v)}*", "case_insensitive": True}}}
    if p.op == "gte":
        return {"range": {f: {"gte": v}}}
    if p.op == "lt":
        return {"range": {f: {"lt": v}}}
    if p.op == "cidr":
        ipaddress.ip_network(str(v), strict=False)  # validates
        return {"term": {f: str(v)}}
    raise CompileError(f"unknown op {p.op}")


def _pred(p: Predicate, contract: FieldContract) -> dict:
    spec = contract.spec(p.field)
    if spec is None:
        raise CompileError(f"field {p.field!r} not in field contract for {contract.target}")
    if p.op not in spec.ops:
        raise CompileError(f"op {p.op!r} not supported on {p.field} ({spec.type}) with superset guarantee")
    natives = spec.natives or (spec.native,)
    if p.op == "eq" and p.field in {"user.entity_id", "auth.target_account"}:
        value = str(p.value)
        if value.startswith("sid:"):
            raw_value = value.removeprefix("sid:")
            selected = [(native, raw_value) for native in natives if native.casefold().endswith("sid")]
        elif value.startswith("name:"):
            full_name = value.removeprefix("name:")
            short_name = full_name.rsplit("\\", 1)[-1]
            selected = [
                (native, full_name if native.casefold().endswith(".user") else short_name)
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
    if p.field == "host.name" and p.op == "eq" and spec.native == "winlog.computer_name":
        # Normalized Windows hosts use their first DNS label. Query both the native
        # short form and any FQDN regardless of which form the caller supplied.
        value = _escape_wildcard(str(p.value).strip().rstrip(".").split(".", 1)[0])
        clauses = [
            {"wildcard": {spec.native: {"value": pattern, "case_insensitive": True}}}
            for pattern in (value, f"{value}.*")
        ]
        return {"bool": {"should": clauses, "minimum_should_match": 1}}
    clauses = [_pred_native(p, native) for native in natives]
    if len(clauses) == 1:
        return clauses[0]
    if p.op == "missing":
        return {"bool": {"filter": clauses}}
    return {"bool": {"should": clauses, "minimum_should_match": 1}}


def build_query(intent: SearchIntent, contract: FieldContract) -> dict:
    tf = contract.time_field
    must = [{"range": {tf: {"gte": intent.window.start.isoformat(), "lt": intent.window.end.isoformat(),
                            "format": "strict_date_optional_time"}}}]
    must += [_pred(p, contract) for p in intent.filters]
    query: dict = {"bool": {"filter": must}}
    if intent.any_of:
        groups = [{"bool": {"filter": [_pred(p, contract) for p in g]}} for g in intent.any_of]
        query["bool"]["should"] = groups
        query["bool"]["minimum_should_match"] = 1
    return query


def compile_es(intent: SearchIntent, contract: FieldContract, flavor: str = "elasticsearch") -> CompiledQuery:
    if intent.target != contract.target:
        raise CompileError("intent target does not match contract target")
    query = build_query(intent, contract)
    if intent.kind == "raw":
        body = {
            "query": query,
            "sort": [
                {contract.time_field: {
                    "order": intent.order, "format": "strict_date_optional_time_nanos",
                }},
                {"_shard_doc": intent.order},
            ],
        }
    elif intent.kind == "aggregate":
        if not intent.group_by:
            raise CompileError("aggregate intent needs group_by")
        sources = []
        for g in intent.group_by:
            spec = contract.spec(g)
            if spec is None or not spec.aggregatable:
                raise CompileError(f"field {g!r} is not aggregatable on {contract.target}")
            sources.append({g: {"terms": {"field": spec.native, "missing_bucket": True}}})
        body = {"size": 0, "query": query, "track_total_hits": True,
                "aggs": {"g": {"composite": {"size": 1000, "sources": sources},
                               "aggs": {"first": {"min": {"field": contract.time_field}},
                                        "last": {"max": {"field": contract.time_field}}}}}}
    elif intent.kind == "histogram":
        sec = intent.interval_seconds or 3600
        body = {"size": 0, "query": query, "track_total_hits": True,
                "aggs": {"h": {"date_histogram": {"field": contract.time_field, "fixed_interval": f"{sec}s",
                                                  "min_doc_count": 0,
                                                  "extended_bounds": {"min": intent.window.start.isoformat(),
                                                                      "max": intent.window.end.isoformat()}}}}}
    else:
        raise CompileError(f"unknown intent kind {intent.kind}")
    fp = digest({"target": intent.target, "kind": intent.kind, "body": body})
    return CompiledQuery(backend=flavor, target=intent.target, body=body, fingerprint=fp)
