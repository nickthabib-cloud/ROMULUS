"""Compile source-anchored Elasticsearch behavior signatures from a small catalog."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..tools.elasticsearch_client import validate_query
from .behavior_catalog import event_matches_match, resolve_semantic_fields
from .rule_model import SOURCE_QUERY_LANGUAGES, SourceStage
from .source_compilers import compile_source_stage


SEARCH_MATRIX_PATH = Path(__file__).with_name("search_matrix_catalog.json")
MAX_SIGNATURES_PER_QUERY = 4


def load_search_matrix(path: Path = SEARCH_MATRIX_PATH) -> dict[str, Any]:
    """Load and minimally validate the checked-in, read-only query recipe catalog."""
    with Path(path).open("r", encoding="utf-8") as handle:
        catalog = json.load(handle)
    if not isinstance(catalog, dict) or not isinstance(catalog.get("families"), list):
        raise ValueError("Search matrix must contain a families array")
    sets = catalog.get("signature_sets")
    if not isinstance(sets, dict):
        raise ValueError("Search matrix must contain signature_sets")
    identifiers = set()
    for family in catalog["families"]:
        if not isinstance(family, dict) or not isinstance(family.get("id"), str):
            raise ValueError("Search matrix family is malformed")
        if family["id"] in identifiers:
            raise ValueError("Search matrix family IDs must be unique")
        identifiers.add(family["id"])
        if family.get("signature_set") not in sets or not isinstance(family.get("selectors"), list):
            raise ValueError(f"Search matrix family {family['id']} has invalid selectors or signature set")
        source=family.get("source")
        if source not in SOURCE_QUERY_LANGUAGES or family.get("query_language") != SOURCE_QUERY_LANGUAGES[source]:
            raise ValueError(f"Search matrix family {family['id']} has mismatched source language")
    return catalog


def compile_search_matrix(
    catalog: dict[str, Any],
    index_field_metadata: dict[str, dict[str, dict[str, Any]]],
    timestamp_field: str | None,
    time_range: dict[str, str] | None,
    *,
    limit: int = 32,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Compile bounded same-document source+behavior queries for each mapped index.

    Identical queries are combined across indices. Mapping gaps are reported
    instead of generating unbounded or invalid searches.
    """
    by_query: dict[str, dict[str, Any]] = {}
    unsupported: list[dict[str, Any]] = []
    for index_name, metadata in sorted(index_field_metadata.items()):
        if not isinstance(metadata, dict) or not metadata:
            continue
        fields = sorted(metadata)
        bindings = resolve_semantic_fields(fields)
        for family in catalog.get("families", []):
            if family.get("source") != "elasticsearch":
                unsupported.append({"id":family.get("id"),"index":index_name,
                    "reason":"family belongs to a different source compiler","missing_roles":[]})
                continue
            signature_rows = catalog.get("signature_sets", {}).get(family.get("signature_set"), [])
            compiled_signatures = []
            missing_selectors = [selector.get("role") for selector in family.get("selectors", [])
                if not bindings.get(selector.get("role"))]
            if missing_selectors:
                unsupported.append({"id": family.get("id"), "index": index_name,
                    "reason": "missing source selector fields", "missing_roles": sorted(set(missing_selectors))})
                continue
            timestamp_meta=metadata.get(timestamp_field,{}) if timestamp_field else {}
            if time_range and (not timestamp_field or timestamp_field not in fields
                    or not isinstance(timestamp_meta,dict) or timestamp_meta.get("searchable") is not True):
                unsupported.append({"id": family.get("id"), "index": index_name,
                    "reason": "no mapped timestamp for the required hunt window", "missing_roles": ["event.time"]})
                continue
            for signature in signature_rows:
                predicates = signature.get("predicates", [])
                mode = signature.get("match_mode", "any")
                match = {"all": list(family["selectors"])}
                if mode == "all":
                    match["all"].extend(predicates)
                elif mode == "any":
                    match["any"] = predicates
                else:
                    unsupported.append({"id": f"{family.get('id')}:{signature.get('id')}",
                        "index": index_name, "reason": "unsupported match mode", "missing_roles": []})
                    continue
                stage=SourceStage.from_mapping({"stage_id":f"{family.get('id')}:{signature.get('id')}",
                    "source":family.get("source"),"query_language":family.get("query_language"),"match":match})
                query = compile_source_stage(stage,bindings=bindings,timestamp_field=timestamp_field or "@timestamp",
                    time_range=None,field_metadata=metadata)
                if query is None:
                    roles = [predicate.get("role") for predicate in [*family["selectors"], *predicates]
                        if not bindings.get(predicate.get("role"))]
                    roles.extend(predicate.get("role") for predicate in [*family["selectors"], *predicates]
                        if not any(isinstance(metadata.get(field),dict) and metadata[field].get("searchable") is True
                            for field in bindings.get(predicate.get("role"),[])))
                    unsupported.append({"id": f"{family.get('id')}:{signature.get('id')}",
                        "index": index_name, "reason": "behavior predicates could not be compiled",
                        "missing_roles": sorted(set(roles))})
                    continue
                compiled_signatures.append({
                    "id": signature.get("id"), "title": signature.get("title", signature.get("id", "")),
                    "priority_tier": signature.get("priority_tier", family.get("priority_tier", "medium")),
                    "base_priority": int(signature.get("base_priority", 50)), "query": query,
                })
            compiled_signatures.sort(key=lambda item: (-item["base_priority"], str(item["id"])))
            for batch_number, offset in enumerate(range(0, len(compiled_signatures), MAX_SIGNATURES_PER_QUERY), start=1):
                rows = compiled_signatures[offset:offset + MAX_SIGNATURES_PER_QUERY]
                clauses = [row["query"] for row in rows]
                query: dict[str, Any] = clauses[0] if len(clauses) == 1 else {
                    "bool": {"should": clauses, "minimum_should_match": 1}
                }
                if time_range:
                    query = {"bool": {"must": [query], "filter": [{"range": {timestamp_field: time_range}}]}}
                try:
                    validate_query(query)
                except (TypeError, ValueError) as exc:
                    unsupported.append({"id": f"{family.get('id')}:batch-{batch_number}",
                        "index": index_name, "reason": f"compiled DSL rejected: {type(exc).__name__}",
                        "missing_roles": []})
                    continue
                serialized = json.dumps(query, sort_keys=True, separators=(",", ":"))
                signature_ids = [item["id"] for item in rows]
                key = f"{family.get('id')}|{batch_number}|{','.join(signature_ids)}|{serialized}"
                row = by_query.setdefault(key, {
                    "analytic_id": f"matrix-{family.get('id')}-{batch_number:02d}",
                    "title": f"{family.get('title')} — {len(rows)} behavior signatures",
                    "family_id": family.get("id"), "signature_ids": signature_ids,
                    "base_priority": max(item["base_priority"] for item in rows),
                    "priority_tier": _highest_priority(item["priority_tier"] for item in rows),
                    "query": query, "source_targets": [],
                })
                row["source_targets"].append(index_name)

    compiled = sorted(by_query.values(), key=lambda item: (-int(item["base_priority"]), item["analytic_id"]))
    selected = compiled[:max(0, int(limit))]
    if len(compiled) > len(selected):
        unsupported.append({"id": "search-matrix-limit", "reason": f"query budget retained {len(selected)} of {len(compiled)} compiled batches",
            "omitted_batches": len(compiled) - len(selected), "missing_roles": []})
    for row in selected:
        row["source_targets"] = sorted(set(row["source_targets"]))
    return selected, sorted(unsupported, key=lambda item: (str(item.get("id", "")), str(item.get("index", ""))))


def _highest_priority(values) -> str:
    ranks = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}
    return max((str(value) for value in values), key=lambda value: ranks.get(value, 0), default="medium")


def attribute_signature_hits(
    evidence: list[dict[str, Any]],
    catalog: dict[str, Any],
    signature_ids: list[str],
) -> dict[str, list[str]]:
    """Re-evaluate batched results so coverage identifies the exact matching signatures."""
    requested=set(str(value) for value in signature_ids)
    definitions=[]
    for family in catalog.get("families",[]):
        selectors=list(family.get("selectors",[]))
        for signature in catalog.get("signature_sets",{}).get(family.get("signature_set"),[]):
            identifier=str(signature.get("id") or "")
            if identifier not in requested:
                continue
            predicates=list(signature.get("predicates",[]))
            match={"all":selectors+predicates if signature.get("match_mode","any")=="all" else selectors,
                "any":[] if signature.get("match_mode","any")=="all" else predicates,"none":[]}
            definitions.append((identifier,match))
    matches={}
    for identifier,match in sorted(definitions):
        ids=[str(event.get("evidence_id")) for event in evidence
            if event.get("evidence_id") and event_matches_match(match,event)]
        if ids:
            matches[identifier]=ids[:100]
    return matches
