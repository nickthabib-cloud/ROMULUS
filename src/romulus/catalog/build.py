"""Build public detection coverage from typed playbook metadata."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from types import MappingProxyType

from romulus.detect.registry import ALL_PLAYBOOKS, PACK_VERSION

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
    CoverageStrength.LEAD_CAPPED: 1,
    CoverageStrength.CONTEXT_ONLY: 2,
    CoverageStrength.POSITIVE_ONLY: 3,
    CoverageStrength.NEGATIVE_CAPABLE: 4,
}


def strength_for_rule(playbook: type) -> CoverageStrength:
    """Classify coverage only from the rule's declared execution and assurance properties."""
    kind = str(getattr(playbook, "kind", "direct"))
    if kind == "context":
        return CoverageStrength.CONTEXT_ONLY
    if kind == "baseline":
        return CoverageStrength.LEAD_CAPPED
    if bool(getattr(playbook, "assures_negative", True)):
        return CoverageStrength.NEGATIVE_CAPABLE
    return CoverageStrength.POSITIVE_ONLY


def _rule_metadata(playbook: type) -> RuleMetadata:
    card = getattr(playbook, "card", {}) or {}
    if not isinstance(card, dict):
        card = {}
    return RuleMetadata(
        id=str(playbook.id),
        version=str(getattr(playbook, "version", "1")),
        title=str(getattr(playbook, "title", playbook.id)),
        kind=str(getattr(playbook, "kind", "direct")),
        lane=str(getattr(playbook, "lane", "lead")),
        severity=str(getattr(playbook, "severity", "medium")),
        assures_negative=bool(getattr(playbook, "assures_negative", True)),
        positive_only_reason=str(getattr(playbook, "positive_only_reason", "")),
        families=tuple(sorted(map(str, getattr(playbook, "families", ())))),
        datasets=tuple(sorted(map(str, getattr(playbook, "datasets", ())))),
        required_fields=tuple(sorted(map(str, getattr(playbook, "required_fields", ())))),
        telemetry=str(card.get("telemetry", "")),
        attack_ids=tuple(sorted(map(str, getattr(playbook, "attack", ())))),
        status=str(getattr(playbook, "status", "active")),
        attack_exempt=str(getattr(playbook, "attack_exempt", "")),
        behavior=str(card.get("behavior", "")),
        fidelity=str(card.get("fidelity", "")),
    )


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
                issues.append(RuleAttackIssue(rule.id, attack_id, "unknown"))
            elif technique.revoked or technique.deprecated:
                reason = "revoked" if technique.revoked else "deprecated"
                issues.append(RuleAttackIssue(rule.id, attack_id, reason))
    return tuple(sorted(issues, key=lambda item: (item.rule_id, item.attack_id)))


def build_catalog(
    *,
    attack: AttackKnowledge | None = None,
    playbooks: Iterable[type] = ALL_PLAYBOOKS,
    strict: bool = False,
) -> Catalog:
    """Return a sorted catalog; strict mode makes invalid ATT&CK mappings fail."""
    attack = attack or load_attack_bundle()
    classes = tuple(playbooks)
    rules = tuple(sorted((_rule_metadata(playbook) for playbook in classes), key=lambda item: item.id))
    invalid = _rule_issues(rules, attack)
    if strict and invalid:
        issue = invalid[0]
        raise ValueError(f"playbook {issue.rule_id} maps {issue.reason} ATT&CK id {issue.attack_id}")
    classes_by_id = {str(playbook.id): playbook for playbook in classes}
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
        strengths = [strength_for_rule(classes_by_id[rule_id]) for rule_id in rule_ids]
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
        pack_version=PACK_VERSION,
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
