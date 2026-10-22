"""Typed, deterministic public catalog records."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum


class CoverageStrength(str, Enum):
    """What a rule mapping can establish when its required telemetry is complete."""

    NEGATIVE_CAPABLE = "negative-capable"
    POSITIVE_ONLY = "positive-only"
    CONTEXT_ONLY = "context-only"
    NONE = "none"


TECHNIQUE_STRENGTH_POLICY = (
    "A technique's strength is the strongest strength among its active covering rules."
)

COVERAGE_STRENGTH_LEGEND: tuple[tuple[CoverageStrength, str], ...] = (
    (
        CoverageStrength.NEGATIVE_CAPABLE,
        (
            "A covering rule can report a complete negative for its own predicate when runtime "
            "coverage is complete; this never means the ATT&CK technique is absent."
        ),
    ),
    (
        CoverageStrength.POSITIVE_ONLY,
        (
            "A covering rule can report matching evidence, but a non-match cannot support a "
            "complete negative."
        ),
    ),
    (
        CoverageStrength.CONTEXT_ONLY,
        (
            "A covering rule is judged only on evidence reached through an explicit investigation "
            "context and cannot support a technique-wide negative."
        ),
    ),
    (
        CoverageStrength.NONE,
        "No active rule explicitly maps to the technique.",
    ),
)


@dataclass(frozen=True)
class AttackTactic:
    id: str
    stix_id: str
    name: str
    shortname: str
    revoked: bool
    deprecated: bool


@dataclass(frozen=True)
class AttackDataSource:
    id: str
    stix_id: str
    name: str
    platforms: tuple[str, ...]
    revoked: bool
    deprecated: bool


@dataclass(frozen=True)
class AttackDataComponent:
    id: str
    stix_id: str
    name: str
    log_sources: tuple[str, ...]
    revoked: bool
    deprecated: bool


@dataclass(frozen=True)
class AttackTechnique:
    id: str
    stix_id: str
    name: str
    is_subtechnique: bool
    parent_id: str | None
    tactics: tuple[str, ...]
    platforms: tuple[str, ...]
    data_sources: tuple[str, ...]
    data_components: tuple[str, ...]
    revoked: bool
    deprecated: bool


@dataclass(frozen=True)
class AttackKnowledge:
    version: str
    tactics: tuple[AttackTactic, ...]
    techniques: tuple[AttackTechnique, ...]
    data_sources: tuple[AttackDataSource, ...]
    data_components: tuple[AttackDataComponent, ...]
    replacements: Mapping[str, str]

    def technique(self, attack_id: str) -> AttackTechnique:
        try:
            return next(item for item in self.techniques if item.id == attack_id)
        except StopIteration as exc:
            raise KeyError(attack_id) from exc

    def replacement(self, attack_id: str) -> str | None:
        return self.replacements.get(attack_id)


@dataclass(frozen=True)
class RuleMetadata:
    id: str
    version: str
    title: str
    kind: str
    lane: str
    severity: str
    assures_negative: bool
    positive_only_reason: str
    families: tuple[str, ...]
    datasets: tuple[str, ...]
    required_fields: tuple[str, ...]
    required_by_family: Mapping[str, tuple[str, ...]]
    telemetry: str
    attack_ids: tuple[str, ...]
    status: str
    attack_exempt: str
    behavior: str
    fidelity: str


@dataclass(frozen=True)
class TechniqueCoverage:
    technique: AttackTechnique
    rule_ids: tuple[str, ...]
    strength: CoverageStrength
    telemetry_families: tuple[str, ...]


@dataclass(frozen=True)
class RuleAttackIssue:
    rule_id: str
    attack_id: str
    reason: str
    replacement_id: str | None = None


@dataclass(frozen=True)
class TacticRollup:
    tactic: AttackTactic
    total: int
    strength_counts: Mapping[CoverageStrength, int]


@dataclass(frozen=True)
class Catalog:
    attack_version: str
    pack_version: str
    tactics: tuple[AttackTactic, ...]
    rules: tuple[RuleMetadata, ...]
    coverage_by_technique: tuple[TechniqueCoverage, ...]
    tactic_rollups: tuple[TacticRollup, ...]
    missing_attack_ids: tuple[str, ...]
    invalid_attack_ids: tuple[RuleAttackIssue, ...]

    def rule(self, rule_id: str) -> RuleMetadata:
        try:
            return next(item for item in self.rules if item.id == rule_id)
        except StopIteration as exc:
            raise KeyError(rule_id) from exc

    def coverage(self, attack_id: str) -> TechniqueCoverage:
        try:
            return next(item for item in self.coverage_by_technique if item.technique.id == attack_id)
        except StopIteration as exc:
            raise KeyError(attack_id) from exc

    def tactic(self, shortname: str) -> TacticRollup:
        try:
            return next(item for item in self.tactic_rollups if item.tactic.shortname == shortname)
        except StopIteration as exc:
            raise KeyError(shortname) from exc
