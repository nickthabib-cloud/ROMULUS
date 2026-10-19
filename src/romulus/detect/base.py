"""Playbook contract: required typed fields, claim wording, evaluation, coverage semantics."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import ClassVar

from romulus.evidence.typed import Outcome, TypedEvent

SEVERITIES = ("critical", "high", "medium", "low", "info")
LANES = ("urgent", "high", "lead", "context")
CLAIM_TYPES = ("observed_action", "script_content", "network_observation", "aggregate_observation", "anomaly",
               "correlated_observation", "mention")


@dataclass
class PredicateField:
    field: str
    value: object
    origin: str


@dataclass
class Match:
    playbook_id: str
    claim: str                       # exact, restrained wording supported by the cited fields
    claim_type: str
    events: list[TypedEvent]
    predicate: list[PredicateField]
    ts: datetime
    severity: str
    proposed_lane: str
    confidence: str                  # high | medium | low
    entities: list[tuple[str, str, str]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    group_key: str = ""              # stable dedupe identity for aggregates


def pf(ev: TypedEvent, name: str) -> PredicateField:
    f = ev.fields[name]
    return PredicateField(field=name, value=f.value, origin=f.origin)


class Playbook:
    id: ClassVar[str]
    version: ClassVar[str] = "1"
    title: ClassVar[str]
    families: ClassVar[tuple[str, ...]]
    required_fields: ClassVar[tuple[str, ...]] = ()
    claim_type: ClassVar[str] = "observed_action"
    severity: ClassVar[str] = "medium"
    lane: ClassVar[str] = "lead"
    attack: ClassVar[tuple[str, ...]] = ()
    benign: ClassVar[tuple[str, ...]] = ()
    next_checks: ClassVar[tuple[str, ...]] = ()
    kind: ClassVar[str] = "direct"            # direct | aggregate
    # False for rules that read script *text*: text can show intent but can never prove that something
    # did not run, so such rules publish positives only and never write a complete negative.
    assures_negative: ClassVar[bool] = True

    def __init__(self) -> None:
        self.evaluated = 0
        self.missing_required = 0

    def applicable(self, events: list[TypedEvent]) -> list[TypedEvent]:
        """Events of the right family. Events missing required fields are counted (they make a
        no-match unresolvable for those records) and excluded from evaluation."""
        out = []
        for e in events:
            if e.family not in self.families:
                continue
            if any(e.get(f) in (None, "", [], {}) for f in self.required_fields):
                self.missing_required += 1
                continue
            out.append(e)
        self.evaluated += len(out)
        return out

    def consume(self, events: list[TypedEvent]) -> list[Match]:
        """Direct playbooks return matches immediately (publishable before the hunt ends)."""
        return [m for e in self.applicable(events) for m in self.match(e)]

    def match(self, e: TypedEvent) -> list[Match]:
        return []

    def finalize(self) -> list[Match]:
        return []

    def retained_events(self) -> list[TypedEvent]:
        """Every event an aggregate playbook may still cite at finalize. The sweep keeps raw copies of
        exactly these, so no published citation can point at a raw record that was never retained."""
        groups = getattr(self, "groups", {}) or {}
        return [e for evs in groups.values() for e in evs]


def outcome_phrase(e: TypedEvent) -> str:
    if e.outcome == Outcome.success:
        return "the exec call succeeded"
    if e.outcome == Outcome.failure:
        return "the exec call failed"
    return "the exec outcome is unknown"


def basename(path: str) -> str:
    return path.rsplit("/", 1)[-1] if path else ""
