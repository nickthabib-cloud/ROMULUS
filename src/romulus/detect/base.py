"""Playbook contract: required typed fields, claim wording, evaluation, coverage semantics."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, ClassVar, Literal

from romulus.detect.bounded import Limit
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

    def __post_init__(self) -> None:
        # A positive stays valid on a command line some of whose arguments were lost; the claim says so.
        if any(argv_incomplete(event) for event in self.events) and INCOMPLETE_ARGV_NOTE not in self.claim:
            self.claim = f"{self.claim} {INCOMPLETE_ARGV_NOTE}"


INCOMPLETE_ARGV_NOTE = ("The recorded command line is incomplete (an audit record of it was lost); arguments after "
                        "the gap are unknown.")


def argv_incomplete(event: TypedEvent) -> bool:
    """True when some of the exec's arguments did not arrive (`process.argv` holds only those before the gap)."""
    return event.get("process.argv_complete") is False


@dataclass
class ContextAnchor:
    id: str
    anchor_class: str
    lane: str
    claim: str
    events: list[TypedEvent]
    rule_id: str = ""
    ts: datetime | None = None

    @property
    def identity(self) -> str:
        """A content identity, stable across hunts: the anchor's rule and its records (the id is hunt-scoped)."""
        records = ",".join(sorted(event.id for event in self.events))
        return hashlib.sha256(f"{self.rule_id}|{records}".encode()).hexdigest()[:16]


@dataclass
class ContextLink:
    id: str
    link_type: str
    strength: Literal["observed", "inferred"]
    key: dict[str, Any]
    evidence_events: list[TypedEvent]
    status: str
    reasons: list[str] = field(default_factory=list)
    window_start: datetime | None = None
    window_end: datetime | None = None


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
    kind: ClassVar[str] = "direct"            # direct | aggregate | context
    anchor_class: ClassVar[str] = "execution"
    # False for rules that read script *text*: text can show intent but can never prove that something
    # did not run, so such rules publish positives only and never write a complete negative.
    assures_negative: ClassVar[bool] = True
    # A positive-only rule carries its own explicit, non-rule-naming reason for assuring no negative (spec
    # §7 catalog detail, §9). The report may also hold a copy; this is the rule's own source of truth.
    positive_only_reason: ClassVar[str] = ""
    # True when the rule's positive predicate only tests for argv tokens being present, so the arguments that
    # arrived before a gap still support it. Otherwise an exec with an incomplete argv is counted as missing a
    # required field and not evaluated: a test for an absent token, or for a last operand, cannot be decided.
    argv_prefix_safe: ClassVar[bool] = False

    def __init__(self) -> None:
        self.evaluated = 0
        self.missing_required = 0
        # Records a full state budget kept from evaluation (see romulus.detect.bounded): the sweep makes the
        # partition's coverage partial with the limit named, exactly as for a record missing a required field.
        self.capped = 0
        self.limits: dict[str, Limit] = {}

    def refuse(self, name: str, text: str, records: int = 1) -> None:
        """A state budget is full: `records` record(s) were not evaluated. Coverage becomes partial and says why."""
        self.capped += records
        self.note_limit(name, text, records)

    def note_limit(self, name: str, text: str, records: int = 0) -> None:
        """A state budget was reached. With `records` 0 nothing went unevaluated, but what the rule can state became
        less exact (a count became a lower bound, an older record was released); the window cell is partial."""
        limit = self.limits.get(name)
        if limit is None:
            limit = self.limits[name] = Limit(text)
        limit.records += records
        limit.hits += 1

    def limit_reasons(self) -> list[str]:
        """Every state budget this playbook reached, worded for the coverage ledger."""
        return [self.limits[name].reason() for name in sorted(self.limits)]

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
            if argv_incomplete(e):
                self.missing_required += 1          # never a clean evaluation, even when the prefix is used
                if not self.argv_prefix_safe:
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

    # Joining aggregates keep compact keys in memory and hand full events to the sweep's disk stage
    # (romulus.hunt.stage); at finalize they load back only what they cite.
    staged: ClassVar[bool] = False

    def drain_staged(self) -> list[TypedEvent]:
        """Events consumed since the last call that this playbook may cite later (staged playbooks)."""
        return []

    def bind_loader(self, load) -> None:
        """Give a staged playbook the function that loads staged events back by id."""
        self.load = load

    def retained_events(self) -> list[TypedEvent]:
        """Every event an aggregate playbook may still cite at finalize. The sweep keeps raw copies of
        exactly these, so no published citation can point at a raw record that was never retained."""
        groups = getattr(self, "groups", {}) or {}
        return [e for evs in groups.values() for e in evs]

    # Where a playbook that spills rows to disk (romulus.detect.bounded.Spill) puts its private directory: the sweep's
    # stage directory; None (tests, ad hoc runs) uses the system temporary directory.
    spill_dir = None
    _spill = None

    def spill(self):
        """This playbook's private on-disk tables (created on first use)."""
        if self._spill is None:
            from romulus.detect.bounded import Spill
            self._spill = Spill(self.spill_dir)
        return self._spill

    def close_spill(self) -> None:
        """Remove any on-disk spill. The sweep calls it on every exit path it controls."""
        if self._spill is not None:
            self._spill.close()
            self._spill = None

    def release_state(self) -> None:
        """Release aggregate working state after its findings and coverage are persisted."""


class ContextPlaybook(Playbook):
    """A rule that may evaluate only evidence reached through an explicit anchor link."""

    kind: ClassVar[str] = "context"
    anchor_classes: ClassVar[tuple[str, ...]] = ("*",)
    link_types: ClassVar[tuple[str, ...]] = ()
    # Typed fields a record of each family must carry to be evaluated (missing ones are counted, never a clean
    # no-match). The finalize pass reads it to pick the records a rule would see for a link.
    required_by_family: ClassVar[dict[str, tuple[str, ...]]] = {}

    def consume(self, events: list[TypedEvent]) -> list[Match]:
        return []

    def accepts(self, anchor: ContextAnchor | None, link: ContextLink) -> bool:
        """Whether this rule may read records that arrived through this anchor class and link type. A rule only
        ever sees records from a link type it lists, so out-of-scope links never reach it."""
        return (anchor is not None
                and ("*" in self.anchor_classes or anchor.anchor_class in self.anchor_classes)
                and link.link_type in self.link_types)

    def consume_linked(
        self, anchor: ContextAnchor | None, link: ContextLink,
        events: list[TypedEvent],
    ) -> list[Match]:
        if not self.accepts(anchor, link):
            return []
        matches = self.match_linked(anchor, link, events)
        for match in matches:
            if link.strength == "inferred" and match.proposed_lane in ("urgent", "high"):
                match.proposed_lane = "lead"
                match.notes.append("lane capped at lead: the context link is inferred")
            elif link.strength == "observed" and match.proposed_lane == "urgent":
                match.proposed_lane = "high"
                match.notes.append("lane capped at high: a context finding never reaches the urgent lane")
            cited = {event.id: event for event in match.events + anchor.events + link.evidence_events}
            match.events = sorted(cited.values(), key=lambda event: (event.ts, event.id))
        return matches

    def match_linked(
        self, anchor: ContextAnchor, link: ContextLink, events: list[TypedEvent],
    ) -> list[Match]:
        return []

    def eligible_records(self, events: list[TypedEvent]) -> list[TypedEvent]:
        """Eligible records using this rule's declared `required_by_family` (counts evaluated/missing)."""
        return self.eligible(events, self.required_by_family)

    def eligible(
        self, events: list[TypedEvent], required_by_family: dict[str, tuple[str, ...]],
    ) -> list[TypedEvent]:
        """Events of a wanted family that carry that family's required typed fields. A wanted event missing a
        required field is counted (missing_required), so the coverage cell is partial, never a clean no-match;
        an event of an unwanted family is ignored (it is not evidence for or against this rule)."""
        out = []
        for event in events:
            required = required_by_family.get(event.family)
            if required is None:
                continue
            if any(event.get(name) in (None, "", [], {}) for name in required):
                self.missing_required += 1
                continue
            if argv_incomplete(event):
                self.missing_required += 1          # never a clean evaluation, even when the prefix is used
                if not self.argv_prefix_safe:
                    continue
            self.evaluated += 1
            out.append(event)
        return out


def outcome_phrase(e: TypedEvent) -> str:
    if e.outcome == Outcome.success:
        return "the exec call succeeded"
    if e.outcome == Outcome.failure:
        return "the exec call failed"
    return "the exec outcome is unknown"


def basename(path: str) -> str:
    return path.rsplit("/", 1)[-1] if path else ""
