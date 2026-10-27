"""Build public detection coverage from typed playbook metadata."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from collections import Counter
from collections.abc import Iterable
from functools import lru_cache
from pathlib import Path
from types import MappingProxyType
from typing import Any

from .attack import load_attack_bundle
from .models import (
    AttackKnowledge,
    Catalog,
    CoverageStrength,
    RuleAttackIssue,
    RuleMetadata,
    TacticRollup,
    TechniqueCoverage,
)

_STRENGTH_RANK = {
    CoverageStrength.NONE: 0,
    CoverageStrength.CONTEXT_ONLY: 1,
    CoverageStrength.POSITIVE_ONLY: 2,
    CoverageStrength.FULL_SEARCH: 3,
}

_ROOT = Path(__file__).resolve().parents[3]
_SRC_ROOT = _ROOT / "src"
_PUBLIC_INDICATOR_DIR = _ROOT / "content" / "indicators"
_NON_ENTERPRISE_ID_REASONS = {
    "T0815": "ATT&CK for ICS id (not in the Enterprise bundle)",
}


def _public_version(playbook: type) -> str:
    version = str(getattr(playbook, "version", "1"))
    if str(getattr(playbook, "id", "")) != "ioc.indicator_match":
        return version
    from romulus.detect.indicators import load_indicators

    base = version.split("+", maxsplit=1)[0]
    return f"{base}+{load_indicators(_PUBLIC_INDICATOR_DIR).digest}"


def strength_for_rule(playbook: type) -> CoverageStrength:
    """Classify coverage only from the rule's declared execution and assurance properties."""
    kind = str(getattr(playbook, "kind", "direct"))
    lane = str(getattr(playbook, "lane", "lead"))
    if kind == "context" or lane == "context":
        return CoverageStrength.CONTEXT_ONLY
    if bool(getattr(playbook, "assures_negative", True)):
        return CoverageStrength.FULL_SEARCH
    return CoverageStrength.POSITIVE_ONLY


def _rule_metadata(playbook: type) -> RuleMetadata:
    card = getattr(playbook, "card", {}) or {}
    if not isinstance(card, dict):
        card = {}
    required_by_family = getattr(playbook, "required_by_family", {}) or {}
    stable_requirements = MappingProxyType(
        {
            str(family): tuple(sorted(map(str, fields)))
            for family, fields in sorted(required_by_family.items())
        }
    )
    return RuleMetadata(
        id=str(playbook.id),
        version=_public_version(playbook),
        title=str(getattr(playbook, "title", playbook.id)),
        kind=str(getattr(playbook, "kind", "direct")),
        lane=str(getattr(playbook, "lane", "lead")),
        severity=str(getattr(playbook, "severity", "medium")),
        assures_negative=bool(getattr(playbook, "assures_negative", True)),
        positive_only_reason=str(getattr(playbook, "positive_only_reason", "")),
        families=tuple(sorted(map(str, getattr(playbook, "families", ())))),
        datasets=tuple(sorted(map(str, getattr(playbook, "datasets", ())))),
        required_fields=tuple(sorted(map(str, getattr(playbook, "required_fields", ())))),
        required_by_family=stable_requirements,
        telemetry=str(card.get("telemetry", "")),
        attack_ids=tuple(sorted(map(str, getattr(playbook, "attack", ())))),
        status=str(getattr(playbook, "status", "active")),
        attack_exempt=str(getattr(playbook, "attack_exempt", "")),
        behavior=str(card.get("behavior", "")),
        fidelity=str(card.get("fidelity", "")),
    )


def _rule_document(rule: RuleMetadata) -> dict[str, Any]:
    return {
        "id": rule.id,
        "version": rule.version,
        "title": rule.title,
        "kind": rule.kind,
        "lane": rule.lane,
        "severity": rule.severity,
        "assures_negative": rule.assures_negative,
        "positive_only_reason": rule.positive_only_reason,
        "families": list(rule.families),
        "datasets": list(rule.datasets),
        "required_fields": list(rule.required_fields),
        "required_by_family": {
            family: list(fields) for family, fields in rule.required_by_family.items()
        },
        "telemetry": rule.telemetry,
        "attack_ids": list(rule.attack_ids),
        "status": rule.status,
        "attack_exempt": rule.attack_exempt,
        "behavior": rule.behavior,
        "fidelity": rule.fidelity,
    }


def _pack_probe_document() -> dict[str, Any]:
    """Run inside a sanitized child process when runtime detection modules are not loaded."""
    from romulus.detect.registry import ALL_PLAYBOOKS, PACK_VERSION

    rules = tuple(sorted((_rule_metadata(playbook) for playbook in ALL_PLAYBOOKS), key=lambda item: item.id))
    return {"pack_version": PACK_VERSION, "rules": [_rule_document(rule) for rule in rules]}


def _rule_from_document(item: dict[str, Any]) -> RuleMetadata:
    return RuleMetadata(
        id=str(item["id"]),
        version=str(item["version"]),
        title=str(item["title"]),
        kind=str(item["kind"]),
        lane=str(item["lane"]),
        severity=str(item["severity"]),
        assures_negative=bool(item["assures_negative"]),
        positive_only_reason=str(item["positive_only_reason"]),
        families=tuple(map(str, item["families"])),
        datasets=tuple(map(str, item["datasets"])),
        required_fields=tuple(map(str, item["required_fields"])),
        required_by_family=MappingProxyType(
            {
                str(family): tuple(map(str, fields))
                for family, fields in dict(item["required_by_family"]).items()
            }
        ),
        telemetry=str(item["telemetry"]),
        attack_ids=tuple(map(str, item["attack_ids"])),
        status=str(item["status"]),
        attack_exempt=str(item["attack_exempt"]),
        behavior=str(item["behavior"]),
        fidelity=str(item["fidelity"]),
    )


@lru_cache(maxsize=1)
def _public_pack() -> tuple[tuple[RuleMetadata, ...], str]:
    """Read public pack metadata without changing the caller's runtime indicator environment."""
    if "romulus.detect.registry" in sys.modules:
        rules = tuple(
            sorted(
                (
                    _rule_metadata(playbook)
                    for playbook in sys.modules["romulus.detect.registry"].ALL_PLAYBOOKS
                ),
                key=lambda item: item.id,
            )
        )
        return (
            rules,
            str(sys.modules["romulus.detect.registry"].PACK_VERSION),
        )
    env = os.environ.copy()
    env.pop("ROMULUS_INDICATOR_DIR", None)
    existing_path = env.get("PYTHONPATH")
    env["PYTHONPATH"] = str(_SRC_ROOT) + (os.pathsep + existing_path if existing_path else "")
    code = (
        "import json; "
        "from romulus.catalog.build import _pack_probe_document; "
        "print(json.dumps(_pack_probe_document(), sort_keys=True, separators=(',', ':')))"
    )
    completed = subprocess.run(
        [sys.executable, "-B", "-c", code],
        cwd=_ROOT,
        env=env,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"public pack metadata probe failed: {completed.stderr.strip()}")
    try:
        document = json.loads(completed.stdout)
        rules = tuple(_rule_from_document(item) for item in document["rules"])
        pack_version = str(document["pack_version"])
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise RuntimeError("public pack metadata probe returned invalid JSON") from exc
    return rules, pack_version


def _rule_issues(rules: tuple[RuleMetadata, ...], attack: AttackKnowledge) -> tuple[RuleAttackIssue, ...]:
    ids = {item.id: item for item in attack.techniques}
    seen: set[str] = set()
    issues: list[RuleAttackIssue] = []
    for rule in rules:
        if rule.id in seen:
            raise ValueError(f"duplicate playbook id: {rule.id}")
        seen.add(rule.id)
        for attack_id in rule.attack_ids:
            technique = ids.get(attack_id)
            if technique is None:
                reason = _NON_ENTERPRISE_ID_REASONS.get(attack_id, "unknown")
                issues.append(RuleAttackIssue(rule.id, attack_id, reason))
            elif technique.revoked or technique.deprecated:
                reason = "revoked" if technique.revoked else "deprecated"
                issues.append(
                    RuleAttackIssue(rule.id, attack_id, reason, attack.replacement(attack_id))
                )
    return tuple(sorted(issues, key=lambda item: (item.rule_id, item.attack_id)))


def build_catalog(
    *,
    attack: AttackKnowledge | None = None,
    playbooks: Iterable[type] | None = None,
    strict: bool = False,
) -> Catalog:
    """Return a sorted catalog; strict mode makes invalid ATT&CK mappings fail."""
    public_rules, pack_version = _public_pack()
    attack = attack or load_attack_bundle()
    rules = (
        tuple(sorted((_rule_metadata(playbook) for playbook in playbooks), key=lambda item: item.id))
        if playbooks is not None
        else public_rules
    )
    invalid = _rule_issues(rules, attack)
    if strict and invalid:
        issue = invalid[0]
        raise ValueError(f"playbook {issue.rule_id} maps {issue.reason} ATT&CK id {issue.attack_id}")
    rules_by_id = {rule.id: rule for rule in rules}
    active_rules = tuple(rule for rule in rules if rule.status == "active")
    missing = tuple(rule.id for rule in active_rules if not rule.attack_ids and not rule.attack_exempt)

    rule_ids_by_technique: dict[str, list[str]] = {}
    for rule in active_rules:
        invalid_ids = {issue.attack_id for issue in invalid if issue.rule_id == rule.id}
        for attack_id in rule.attack_ids:
            if attack_id in invalid_ids:
                continue
            rule_ids_by_technique.setdefault(attack_id, []).append(rule.id)

    coverage: list[TechniqueCoverage] = []
    for technique in attack.techniques:
        if technique.revoked or technique.deprecated:
            continue
        rule_ids = tuple(sorted(rule_ids_by_technique.get(technique.id, ())))
        strengths = [strength_for_rule(rules_by_id[rule_id]) for rule_id in rule_ids]
        strength = max(strengths, key=_STRENGTH_RANK.__getitem__) if strengths else CoverageStrength.NONE
        families = tuple(sorted({family for rule_id in rule_ids for family in rules_by_id[rule_id].families}))
        coverage.append(
            TechniqueCoverage(
                technique=technique,
                rule_ids=rule_ids,
                strength=strength,
                telemetry_families=families,
            )
        )
    coverage_tuple = tuple(sorted(coverage, key=lambda item: item.technique.id))

    rollups: list[TacticRollup] = []
    for tactic in attack.tactics:
        if tactic.revoked or tactic.deprecated:
            continue
        rows = [item for item in coverage_tuple if tactic.shortname in item.technique.tactics]
        counts = Counter(item.strength for item in rows)
        stable_counts = MappingProxyType({strength: counts[strength] for strength in CoverageStrength})
        rollups.append(TacticRollup(tactic=tactic, total=len(rows), strength_counts=stable_counts))
    return Catalog(
        attack_version=attack.version,
        pack_version=pack_version,
        tactics=tuple(
            sorted(
                (item for item in attack.tactics if not item.revoked and not item.deprecated),
                key=lambda item: item.id,
            )
        ),
        rules=rules,
        coverage_by_technique=coverage_tuple,
        tactic_rollups=tuple(sorted(rollups, key=lambda item: item.tactic.id)),
        missing_attack_ids=missing,
        invalid_attack_ids=invalid,
    )
