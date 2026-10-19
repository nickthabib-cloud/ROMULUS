"""Resolve one constrained menu selection to an existing typed decision."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from romulus.agent.brief import BuiltBrief
from romulus.agent.constraints import eligible_evidence_aliases
from romulus.agent.models import AgentDecision
from romulus.agent.validate import ValidationResult, validate_decision


class _Selection(BaseModel):
    model_config = ConfigDict(extra="forbid")

    option: str = Field(min_length=1)
    evidence: list[str] = Field(min_length=1, max_length=4)
    rationale: str
    benign_alternative: str | None = None


@dataclass(frozen=True)
class Resolution:
    decision: AgentDecision | None = None
    validation: ValidationResult | None = None
    errors: list[str] = field(default_factory=list)
    truncated_fields: list[str] = field(default_factory=list)
    constraint_defect: bool = False

    @property
    def ok(self) -> bool:
        return self.decision is not None and not self.errors and bool(self.validation and self.validation.ok)


def resolve_output(
    value: Any,
    brief: BuiltBrief,
    hunt_window: Any,
    duplicate_check: Callable[[Any], dict | None] | None = None,
) -> Resolution:
    """Map aliases exactly, truncate text, then re-run semantic and duplicate admission."""
    try:
        selection = _Selection.model_validate(value)
    except ValidationError as exc:
        return Resolution(errors=[f"invalid constrained output: {exc}"], constraint_defect=True)

    option = next((item for item in brief.menu.options if item.id == selection.option), None)
    if option is None:
        return Resolution(errors=[f"unknown option: {selection.option}"], constraint_defect=True)
    if len(set(selection.evidence)) != len(selection.evidence):
        return Resolution(errors=["evidence aliases must be unique"], constraint_defect=True)

    known_aliases = brief.aliases.get("evidence") or {}
    allowed = set(eligible_evidence_aliases(
        option, brief.aliases, brief.known_candidates, brief.injection_evidence_ids,
    ))
    errors = []
    for alias in selection.evidence:
        if alias not in known_aliases:
            errors.append(f"unknown evidence alias: {alias}")
        elif alias not in allowed:
            errors.append(f"evidence alias {alias} is not allowed for option {option.id}")
    if errors:
        return Resolution(errors=errors, constraint_defect=True)

    rationale = selection.rationale[:300]
    benign = None if selection.benign_alternative is None else selection.benign_alternative[:200]
    truncated = []
    if rationale != selection.rationale:
        truncated.append("rationale")
    if benign != selection.benign_alternative:
        truncated.append("benign_alternative")
    updates: dict[str, Any] = {
        "evidence_ids": [known_aliases[alias] for alias in selection.evidence],
        "reasoning": rationale,
    }
    if benign is not None:
        updates["benign_alternatives"] = [benign]
    decision = option.decision.model_copy(update=updates)
    validation = validate_decision(decision, brief, hunt_window)
    errors = list(validation.errors)
    if validation.ok and decision.action == "pivot" and duplicate_check is not None:
        duplicate = duplicate_check(validation.request)
        if duplicate is not None:
            step = duplicate["n"]
            errors = [
                (f"duplicate pivot: normalized request already executed at step {step}; "
                 f"reuse prior_steps step {step} result_digest")
            ]
            validation = ValidationResult(ok=False, errors=errors, request=validation.request)
    return Resolution(
        decision=decision,
        validation=validation,
        errors=errors,
        truncated_fields=truncated,
        constraint_defect=bool(errors),
    )
