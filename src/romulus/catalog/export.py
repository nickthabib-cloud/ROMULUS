"""Stable JSON-ready export of the public detection catalog."""

from __future__ import annotations

from typing import Any

from .build import build_catalog
from .models import Catalog, CoverageStrength, RuleMetadata


def _rule_strength(rule: RuleMetadata) -> str:
    if rule.kind == "context":
        return CoverageStrength.CONTEXT_ONLY.value
    if rule.kind == "baseline":
        return CoverageStrength.LEAD_CAPPED.value
    if rule.assures_negative:
        return CoverageStrength.NEGATIVE_CAPABLE.value
    return CoverageStrength.POSITIVE_ONLY.value


def _rules(catalog: Catalog) -> list[dict[str, Any]]:
    return [
        {
            "id": rule.id,
            "version": rule.version,
            "title": rule.title,
            "kind": rule.kind,
            "lane": rule.lane,
            "severity": rule.severity,
            "status": rule.status,
            "coverage_strength": _rule_strength(rule),
            "assures_negative": rule.assures_negative,
            "positive_only_reason": rule.positive_only_reason,
            "attack_exempt": rule.attack_exempt,
            "attack_ids": list(rule.attack_ids),
            "families": list(rule.families),
            "datasets": list(rule.datasets),
            "required_fields": list(rule.required_fields),
            "behavior": rule.behavior,
            "fidelity": rule.fidelity,
        }
        for rule in catalog.rules
    ]


def _techniques(catalog: Catalog) -> list[dict[str, Any]]:
    return [
        {
            "id": item.technique.id,
            "name": item.technique.name,
            "is_subtechnique": item.technique.is_subtechnique,
            "parent_id": item.technique.parent_id,
            "tactics": list(item.technique.tactics),
            "platforms": list(item.technique.platforms),
            "data_sources": list(item.technique.data_sources),
            "data_components": list(item.technique.data_components),
            "strength": item.strength.value,
            "rule_ids": list(item.rule_ids),
            "telemetry_families": list(item.telemetry_families),
            "status": "not covered" if item.strength is CoverageStrength.NONE else "covered",
        }
        for item in catalog.coverage_by_technique
    ]


def _tactics(catalog: Catalog) -> list[dict[str, Any]]:
    return [
        {
            "id": item.tactic.id,
            "name": item.tactic.name,
            "shortname": item.tactic.shortname,
            "total": item.total,
            "strengths": {strength.value: item.strength_counts[strength] for strength in CoverageStrength},
        }
        for item in catalog.tactic_rollups
    ]


def _telemetry(catalog: Catalog) -> list[dict[str, Any]]:
    families = sorted({family for rule in catalog.rules for family in rule.families})
    return [
        {
            "family": family,
            "rule_ids": [rule.id for rule in catalog.rules if family in rule.families],
            "required_fields": sorted(
                {field for rule in catalog.rules if family in rule.families for field in rule.required_fields}
            ),
        }
        for family in families
    ]


def export(catalog: Catalog | None = None) -> dict[str, Any]:
    """Return the reusable public matrix as JSON-serializable built-in values."""
    catalog = catalog or build_catalog()
    techniques = _techniques(catalog)
    gaps = [
        {
            "id": item["id"],
            "name": item["name"],
            "parent_id": item["parent_id"],
            "tactics": item["tactics"],
            "status": "not covered",
            "telemetry": {
                "families": item["telemetry_families"],
                "attack_data_sources": item["data_sources"],
                "attack_data_components": item["data_components"],
            },
        }
        for item in techniques
        if item["status"] == "not covered"
    ]
    return {
        "schema_version": 1,
        "attack_version": catalog.attack_version,
        "pack_version": catalog.pack_version,
        "rules": _rules(catalog),
        "techniques": techniques,
        "tactics": _tactics(catalog),
        "telemetry": _telemetry(catalog),
        "gaps": gaps,
        "metadata_issues": {
            "missing_attack_ids": list(catalog.missing_attack_ids),
            "invalid_attack_ids": [
                {
                    "rule_id": issue.rule_id,
                    "attack_id": issue.attack_id,
                    "reason": issue.reason,
                }
                for issue in catalog.invalid_attack_ids
            ],
        },
    }
