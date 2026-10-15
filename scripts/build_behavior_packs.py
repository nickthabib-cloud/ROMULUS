#!/usr/bin/env python3
"""Compile the reviewed indicator corpus into deterministic ROMULUS packs."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
CORPUS_PATH = ROOT / "docs" / "research" / "common-indicator-corpus.json"
TRANSLATIONS_PATH = ROOT / "scripts" / "behavior_pack_translations.json"
ATTACK_PATH = ROOT / "romulus" / "intelligence" / "attack_catalog.json"
OUTPUT_DIR = ROOT / "romulus" / "intelligence" / "behavior_packs"
COMPILER_VERSION = "5.0.0"
EXPECTED = {
    "entries": 3863,
    "curated_behavioral_indicator": 902,
    "direct": 549,
    "sequence": 89,
    "aggregate": 206,
    "baseline_deviation": 58,
    "source_capability_reference": 1216,
    "detection_analytic_reference": 1745,
}


class PackError(ValueError):
    """Raised when the source corpus cannot be safely translated."""


def _read(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PackError(f"{path}: {exc}") from exc


def _hash_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _hash_file(path: Path) -> str:
    return _hash_bytes(path.read_bytes())


def _stable_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _validate_sources(corpus: dict[str, Any], entries: list[dict[str, Any]]) -> None:
    source_ids = set(corpus.get("source_registry", {}))
    seen: set[str] = set()
    for index, row in enumerate(entries):
        identifier = row.get("id")
        if not isinstance(identifier, str) or not identifier:
            raise PackError(f"entries[{index}].id: expected non-empty string")
        if identifier in seen:
            raise PackError(f"entries[{index}].id: duplicate {identifier}")
        seen.add(identifier)
        for source_id in row.get("source_refs", []):
            if source_id not in source_ids:
                raise PackError(f"{identifier}.source_refs: unknown source {source_id}")


def _validate_attack_ids(entries: list[dict[str, Any]]) -> None:
    attack = _read(ATTACK_PATH)
    known = {
        str(row.get("technique_id"))
        for row in attack.get("techniques", [])
        if isinstance(row, dict) and row.get("technique_id")
    }
    if not known:
        raise PackError(f"{ATTACK_PATH}: no pinned ATT&CK technique IDs found")
    for row in entries:
        for technique_id in row.get("attack_techniques", []):
            if technique_id not in known:
                raise PackError(f"{row.get('id')}.attack_techniques: unknown ATT&CK ID {technique_id}")


def _rule(row: dict[str, Any], registry: dict[str, Any], source_registry: dict[str, Any]) -> dict[str, Any]:
    identifier = str(row["id"])
    predicates = []
    for number, observable in enumerate(row.get("observables", [])):
        role = observable.get("role")
        operator = observable.get("operator")
        if role not in registry["direct_roles"]:
            raise PackError(f"{identifier}.observables[{number}].role: untranslated role {role}")
        if operator not in registry["operators"]:
            raise PackError(f"{identifier}.observables[{number}].operator: untranslated operator {operator}")
        values = observable.get("values")
        if not isinstance(values, list) or not values or not all(isinstance(x, str) and x for x in values):
            raise PackError(f"{identifier}.observables[{number}].values: expected non-empty strings")
        predicates.append({
            "role": registry["direct_roles"][role],
            "operator": registry["operators"][operator],
            "values": values,
        })
    if not predicates:
        raise PackError(f"{identifier}: direct behavior has no executable predicates")
    provenance = []
    for source_id in row.get("source_refs", []):
        source = source_registry.get(source_id, {})
        provenance.append({"name": source.get("name", source_id), "url": source.get("url", "")})
    if not provenance or any(not item["url"] for item in provenance):
        raise PackError(f"{identifier}.source_refs: no resolvable provenance URL")

    policy = registry["activation_policy"]
    active = row.get("priority") in policy["active_priorities"] and row.get("expected_noise") in policy["active_noise"]
    return {
        "id": identifier,
        "research_id": identifier,
        "signal_name": identifier,
        "title": row["title"],
        "description": row["description"],
        "review_date": "2026-10-15",
        "version": 1,
        "enabled": True,
        "activation_mode": "active" if active else "observe",
        "supported": True,
        "source": "elasticsearch",
        "source_language": "elasticsearch_dsl",
        "stage_id": f"{identifier}:elasticsearch",
        "platforms": row.get("platforms", []),
        "categories": row.get("tactics", []),
        "required_roles": sorted({item["role"] for item in predicates}),
        "optional_roles": [],
        "attack_techniques": row.get("attack_techniques", []),
        "benign_explanations": row.get("benign_explanations", []),
        "required_corroboration": [],
        "follow_up": row.get("follow_up", []),
        "priority_tier": row.get("priority"),
        "base_priority": row.get("base_score"),
        "specificity": row.get("specificity"),
        "expected_noise": row.get("expected_noise"),
        "provenance": provenance,
        "match": {"all": predicates, "any": [], "none": []},
        "domain": row.get("domain"),
        "signal_type": row.get("signal_type"),
        "telemetry_requirements": row.get("telemetry_requirements", []),
        "escalation_conditions": row.get("escalation_conditions", []),
        "source_refs": row.get("source_refs", []),
    }


def _sequence_rule(row: dict[str, Any], registry: dict[str, Any]) -> dict[str, Any]:
    relationship=(row.get("relationship_logic") or [{}])[0]
    pattern=relationship.get("pattern")
    translations=registry.get("sequence_translations",{})
    translation=translations.get(row.get("id")) or translations.get(pattern)
    if not isinstance(translation,dict):
        missing=str(pattern or row.get("id"))
        return {**row,"activation_mode":"reference","supported":False,
            "support_reason":"No reviewed canonical stage translation is available.",
            "execution":{"status":"reference_only","execution_kind":"sequence",
                "reason_code":"missing_canonical_signal_translation","missing_semantics":[missing]}}
    stage_names=translation.get("stages",[])
    sources=translation.get("source_families") or [["host"] for _ in stage_names]
    if not stage_names or len(sources)!=len(stage_names):
        raise PackError(f"{row.get('id')}: invalid sequence translation stages/source_families")
    stages=[]
    for number,(signal,families) in enumerate(zip(stage_names,sources),start=1):
        if not isinstance(signal,str) or not signal or not isinstance(families,list) or not families:
            raise PackError(f"{row.get('id')}: invalid sequence stage {number}")
        if any(value not in {"host","network"} for value in families):
            raise PackError(f"{row.get('id')}: invalid source family in sequence stage {number}")
        stages.append({"stage_id":f"{row['id']}:{number:02d}","signal":signal,
            "source_families":families})
    window=int(translation.get("window_minutes") or relationship.get("within_minutes")
        or relationship.get("default_window_minutes") or 30)
    return {**row,"activation_mode":"active","supported":True,"support_reason":"",
        "execution":{"status":"executable","execution_kind":"sequence",
            "order":translation.get("order","ordered"),"threshold":int(translation.get("threshold") or len(stages)),
            "window_minutes":window,"joins":list(translation.get("joins") or []),
            "join_mode":translation.get("join_mode","all"),"stages":stages}}


def _aggregate_rule(row: dict[str, Any], registry: dict[str, Any]) -> dict[str, Any]:
    values = [value for observable in row.get("observables", [])
              if observable.get("role") == "aggregate.signal"
              for value in observable.get("values", [])]
    marker = values[0] if len(values) == 1 else None
    translation = registry.get("aggregate_translations", {}).get(str(marker))
    if not isinstance(translation, dict):
        missing = str(marker or row.get("id"))
        return {**row, "activation_mode": "reference", "supported": False,
            "support_reason": "No reviewed aggregate parameters are available.",
            "execution": {"status": "reference_only", "execution_kind": "aggregate",
                "reason_code": "missing_explicit_aggregate_semantics", "missing_semantics": [missing]}}

    primitive = translation.get("primitive")
    allowed = {"count", "distinct_count", "fanout", "rate", "transition",
               "volume", "ratio", "duration", "periodicity"}
    if primitive not in allowed:
        raise PackError(f"{row.get('id')}: unsupported aggregate primitive {primitive}")
    threshold = translation.get("threshold")
    if (not isinstance(threshold, dict) or threshold.get("operator") not in {"gte", "gt", "lte", "lt", "eq"}
            or not isinstance(threshold.get("value"), (int, float))):
        raise PackError(f"{row.get('id')}: aggregate threshold is incomplete")
    families = translation.get("source_families")
    if not isinstance(families, list) or not families or any(value not in {"host", "network"} for value in families):
        raise PackError(f"{row.get('id')}: aggregate source_families are invalid")
    required = {
        "distinct_count": ("distinct_field",), "fanout": ("distinct_field",),
        "volume": ("measure_field",), "transition": ("from_filter", "to_filter"),
    }.get(str(primitive), ())
    if primitive == "ratio" and not ({"numerator_field", "denominator_field"} <= set(translation)
                                     or {"numerator_filter", "denominator_filter"} <= set(translation)):
        raise PackError(f"{row.get('id')}: aggregate ratio fields or filters are incomplete")
    if any(not translation.get(field) for field in required):
        raise PackError(f"{row.get('id')}: aggregate {primitive} parameters are incomplete")
    execution = {
        "status": "executable", "execution_kind": "aggregate", "primitive": primitive,
        "evaluation_location": "normalized_evidence", "source_families": families,
        "source_stages": ([{"source": "elasticsearch", "source_language": "elasticsearch_dsl"}]
                          if families == ["host"] else [
                              {"source": "elasticsearch", "source_language": "elasticsearch_dsl"},
                              {"source": "arkime", "source_language": "arkime_expression"},
                              {"source": "tshark", "source_language": "wireshark_display_filter"},
                          ]),
        "window_minutes": int(translation.get("window_minutes") or 60),
        "group_by": list(translation.get("group_by") or []),
        "sample_min": int(translation.get("sample_min") or 1),
        "threshold": threshold,
    }
    for name in ("filter", "distinct_field", "measure_field", "numerator_field", "denominator_field",
                 "numerator_filter", "denominator_filter", "from_filter", "to_filter", "from_count"):
        if name in translation:
            execution[name] = translation[name]
    return {**row, "activation_mode": "active", "supported": True, "support_reason": "",
            "execution": execution}


def _baseline_rule(row: dict[str, Any], registry: dict[str, Any]) -> dict[str, Any]:
    values = [value for observable in row.get("observables", [])
              if observable.get("role") == "aggregate.signal"
              for value in observable.get("values", [])]
    marker = values[0] if len(values) == 1 else None
    translation = registry.get("baseline_translations", {}).get(str(marker))
    if not isinstance(translation, dict):
        missing = str(marker or row.get("id"))
        return {**row, "activation_mode": "reference", "supported": False,
            "support_reason": "No reviewed historical baseline parameters are available.",
            "execution": {"status": "reference_only", "execution_kind": "baseline",
                "reason_code": "missing_explicit_baseline_semantics", "missing_semantics": [missing]}}
    primitive = translation.get("primitive")
    if primitive not in {"first_seen", "prevalence", "deviation"}:
        raise PackError(f"{row.get('id')}: unsupported baseline primitive {primitive}")
    families = translation.get("source_families")
    scopes = translation.get("scope_fields")
    if not isinstance(families, list) or not families or any(value not in {"host", "network"} for value in families):
        raise PackError(f"{row.get('id')}: baseline source_families are invalid")
    if not isinstance(scopes, list) or not scopes or not all(isinstance(value, str) and value for value in scopes):
        raise PackError(f"{row.get('id')}: baseline scope_fields are invalid")
    if not isinstance(translation.get("warmup_min"), int) or translation["warmup_min"] < 1:
        raise PackError(f"{row.get('id')}: baseline warmup_min is invalid")
    if primitive in {"first_seen", "prevalence"}:
        fields = translation.get("value_fields")
        if not isinstance(fields, list) or not fields or not all(isinstance(value, str) and value for value in fields):
            raise PackError(f"{row.get('id')}: baseline value_fields are invalid")
    if primitive == "prevalence" and (not isinstance(translation.get("peer_min_scopes"), int)
            or not isinstance(translation.get("max_prevalence"), (int, float))):
        raise PackError(f"{row.get('id')}: baseline prevalence parameters are incomplete")
    if primitive == "deviation":
        aggregation = translation.get("aggregation")
        if aggregation not in {"count", "sum", "distinct_count", "ratio"}:
            raise PackError(f"{row.get('id')}: baseline aggregation is invalid")
        if aggregation == "sum" and not translation.get("measure_field"):
            raise PackError(f"{row.get('id')}: baseline measure_field is missing")
        if aggregation == "distinct_count" and not translation.get("distinct_field"):
            raise PackError(f"{row.get('id')}: baseline distinct_field is missing")
        if aggregation == "ratio" and not (translation.get("numerator_filter") and translation.get("denominator_filter")):
            raise PackError(f"{row.get('id')}: baseline ratio filters are missing")
        for name in ("multiplier", "zscore", "minimum"):
            if not isinstance(translation.get(name), (int, float)):
                raise PackError(f"{row.get('id')}: baseline {name} is missing")
    execution = {"status": "executable", "execution_kind": "baseline", "primitive": primitive,
        "evaluation_location": "completed_hunt_history", "source_families": families,
        "scope_fields": scopes, "warmup_min": translation["warmup_min"],
        "source_stages": ([{"source": "elasticsearch", "source_language": "elasticsearch_dsl"}]
                          if families == ["host"] else [
                              {"source": "elasticsearch", "source_language": "elasticsearch_dsl"},
                              {"source": "arkime", "source_language": "arkime_expression"},
                              {"source": "tshark", "source_language": "wireshark_display_filter"},
                          ])}
    for name in ("filter", "value_fields", "value_transform", "peer_min_scopes", "max_prevalence",
                 "aggregation", "measure_field", "distinct_field", "numerator_filter", "denominator_filter",
                 "multiplier", "zscore", "minimum"):
        if name in translation:
            execution[name] = translation[name]
    return {**row, "activation_mode": "active", "supported": True, "support_reason": "", "execution": execution}


def compile_packs(corpus: dict[str, Any], registry: dict[str, Any]) -> dict[str, Any]:
    entries = corpus.get("entries")
    if not isinstance(entries, list):
        raise PackError("corpus.entries: expected array")
    _validate_sources(corpus, entries)
    _validate_attack_ids(entries)

    by_type: dict[str, list[dict[str, Any]]] = {}
    for row in entries:
        by_type.setdefault(str(row.get("record_type")), []).append(row)
    curated = by_type.get("curated_behavioral_indicator", [])
    direct_rows = [row for row in curated if row.get("romulus_compatibility") == "catalog_now"]
    sequence_rows = [row for row in curated if row.get("signal_type") in {"sequence", "cross_source"}]
    aggregate_rows = [row for row in curated if row.get("signal_type") == "aggregate"]
    baseline_rows = [row for row in curated if row.get("signal_type") == "baseline_deviation"]
    capabilities = by_type.get("source_capability_reference", [])
    analytic_refs = by_type.get("detection_analytic_reference", [])
    actual = {
        "entries": len(entries),
        "curated_behavioral_indicator": len(curated),
        "direct": len(direct_rows),
        "sequence": len(sequence_rows),
        "aggregate": len(aggregate_rows),
        "baseline_deviation": len(baseline_rows),
        "source_capability_reference": len(capabilities),
        "detection_analytic_reference": len(analytic_refs),
    }
    if actual != EXPECTED:
        raise PackError(f"source corpus count mismatch: expected {EXPECTED}, found {actual}")
    ids = [row["id"] for row in curated]
    if len(set(ids)) != len(ids):
        raise PackError("curated behavior IDs are not unique")

    source_registry = corpus.get("source_registry", {})
    direct = [_rule(row, registry, source_registry) for row in sorted(direct_rows, key=lambda row: row["id"])]
    active_direct = sum(row["activation_mode"] == "active" for row in direct)
    if active_direct != int(registry["activation_policy"]["direct_active_limit"]):
        raise PackError(f"activation policy expected {registry['activation_policy']['direct_active_limit']} active direct rules, found {active_direct}")

    sequences = [_sequence_rule(row,registry) for row in sorted(sequence_rows,key=lambda row:row["id"])]
    aggregates = [_aggregate_rule(row, registry) for row in sorted(aggregate_rows, key=lambda row: row["id"])]
    baselines = [_baseline_rule(row, registry) for row in sorted(baseline_rows, key=lambda row: row["id"])]
    capabilities_pack = {
        "schema_version": "2.0.0",
        "record_type": "source_capability_reference",
        "records": sorted(capabilities, key=lambda row: row["id"]),
    }
    return {
        "direct": {"schema_version": "1.0.0", "records": direct},
        "sequences": {"schema_version": "2.0.0", "records": sequences},
        "aggregates": {"schema_version": "2.0.0", "records": aggregates},
        "baselines": {"schema_version": "2.0.0", "records": baselines},
        "capabilities": capabilities_pack,
    }


def write_packs(packs: dict[str, Any], output_dir: Path, corpus: dict[str, Any]) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    hashes: dict[str, str] = {}
    counts: dict[str, int] = {}
    for name, pack in sorted(packs.items()):
        data = _stable_json(pack)
        path = output_dir / f"{name}.json"
        path.write_bytes(data)
        hashes[path.name] = _hash_bytes(data)
        counts[name] = len(pack.get("records", [])) if isinstance(pack, dict) else 0
    active_direct = sum(row["activation_mode"] == "active" for row in packs["direct"]["records"])
    active_sequences = sum(row.get("activation_mode") == "active" for row in packs["sequences"]["records"])
    active_aggregates = sum(row.get("activation_mode") == "active" for row in packs["aggregates"]["records"])
    active_baselines = sum(row.get("activation_mode") == "active" for row in packs["baselines"]["records"])
    active = active_direct + active_sequences + active_aggregates + active_baselines
    observe_direct = len(packs["direct"]["records"]) - active_direct
    reference_only_curated = sum(row.get("supported") is not True for name in ("sequences","aggregates","baselines")
        for row in packs[name]["records"])
    executable = sum(row.get("supported") is True for name in ("direct","sequences","aggregates","baselines")
        for row in packs[name]["records"])
    manifest = {
        "manifest_version": "1.0.0",
        "compiler_version": COMPILER_VERSION,
        "corpus_version": corpus.get("corpus_version"),
        "source_status": corpus.get("status"),
        "source_counts": EXPECTED,
        "pack_counts": counts,
        "curated_activation": {"active": active, "observe": observe_direct,
            "reference_only": reference_only_curated},
        "direct_activation": {"active": active_direct, "observe": len(packs["direct"]["records"])-active_direct},
        "sequence_activation": {"active": active_sequences,
            "reference_only": len(packs["sequences"]["records"])-active_sequences},
        "aggregate_activation": {"active": active_aggregates,
            "reference_only": len(packs["aggregates"]["records"])-active_aggregates},
        "baseline_activation": {"active": active_baselines,
            "reference_only": len(packs["baselines"]["records"])-active_baselines},
        "execution_states": {
            "curated_executable": executable,
            "curated_reference_only": reference_only_curated,
            "capability_references": len(packs["capabilities"]["records"]),
        },
        "observe_score_ceiling": 39,
        "source_hashes": {
            "corpus_sha256": _hash_file(CORPUS_PATH),
            "translations_sha256": _hash_file(TRANSLATIONS_PATH),
            "attack_catalog_sha256": _hash_file(ATTACK_PATH),
        },
        "pack_sha256": hashes,
    }
    manifest_path = output_dir / "manifest.json"
    manifest_path.write_bytes(_stable_json(manifest))
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true", help="write generated packs")
    mode.add_argument("--check", action="store_true", help="compare generated packs with disk")
    args = parser.parse_args()
    try:
        corpus = _read(CORPUS_PATH)
        registry = _read(TRANSLATIONS_PATH)
        packs = compile_packs(corpus, registry)
        if args.write:
            manifest = write_packs(packs, OUTPUT_DIR, corpus)
            print(json.dumps({"status": "written", "directory": str(OUTPUT_DIR), "counts": manifest["pack_counts"],
                              "activation": manifest["curated_activation"]}, indent=2))
            return 0
        expected_dir = Path.cwd() / "romulus" / "intelligence" / "behavior_packs"
        for name, pack in packs.items():
            target = expected_dir / f"{name}.json"
            if not target.is_file() or target.read_bytes() != _stable_json(pack):
                raise PackError(f"{target}: generated contents differ; run with --write")
        manifest_path = expected_dir / "manifest.json"
        if not manifest_path.is_file():
            raise PackError(f"{manifest_path}: manifest missing")
        print(json.dumps({"status": "matches", "directory": str(expected_dir),
                          "counts": {name: len(pack["records"]) for name, pack in packs.items()}}, indent=2))
        return 0
    except PackError as exc:
        parser.error(str(exc))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
