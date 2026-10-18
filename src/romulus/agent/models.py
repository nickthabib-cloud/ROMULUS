"""Source-independent types exchanged by the investigator controller."""
from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter

EntityKind = Literal["host", "account", "ip", "domain"]
ToolName = Literal["entity_timeline", "auth_activity", "process_tree", "ids_alerts"]
DecisionAction = Literal["pivot", "escalate", "park_as_lead", "close", "spawn"]


class EntityRef(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: EntityKind
    value: str = Field(min_length=1)
    role: str = ""


class SeedCluster(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    primary_entity: EntityRef | None
    seed_candidate_ids: list[str]
    entities: list[EntityRef]
    lane: str
    priority: float
    first_ts: datetime
    last_ts: datetime


class AgentDecision(BaseModel):
    """One untrusted model proposal. Conditional semantics are validated separately."""

    model_config = ConfigDict(extra="forbid")

    action: DecisionAction
    tool: ToolName | None = None
    arguments: dict[str, Any] = Field(default_factory=dict)
    hypothesis: str = ""
    expected_true: str = ""
    expected_false: str = ""
    candidate_id: str | None = None
    claim: str = ""
    proposed_lane: Literal["urgent", "high", "lead", "context"] | None = None
    evidence_ids: list[str] = Field(default_factory=list)
    reasoning: str = ""
    benign_alternatives: list[str] = Field(default_factory=list)
    resolution_needed: str = ""
    entity: EntityRef | None = None


class _DecisionOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")


class PivotDecisionOutput(_DecisionOutput):
    action: Literal["pivot"]
    tool: ToolName
    arguments: dict[str, Any]
    hypothesis: str = Field(min_length=1)
    expected_true: str = Field(min_length=1)
    expected_false: str = Field(min_length=1)
    evidence_ids: list[str] = Field(min_length=1)


class EscalateDecisionOutput(_DecisionOutput):
    action: Literal["escalate"]
    candidate_id: str = Field(min_length=1)
    claim: str = Field(min_length=1)
    proposed_lane: Literal["urgent", "high", "lead", "context"]
    evidence_ids: list[str] = Field(min_length=1)
    reasoning: str = Field(min_length=1)
    benign_alternatives: list[str] = Field(default_factory=list)


class ParkDecisionOutput(_DecisionOutput):
    action: Literal["park_as_lead"]
    evidence_ids: list[str] = Field(min_length=1)
    reasoning: str = Field(min_length=1)
    resolution_needed: str = Field(min_length=1)


class CloseDecisionOutput(_DecisionOutput):
    action: Literal["close"]
    evidence_ids: list[str] = Field(min_length=1)
    reasoning: str = Field(min_length=1)


class SpawnDecisionOutput(_DecisionOutput):
    action: Literal["spawn"]
    entity: EntityRef
    evidence_ids: list[str] = Field(min_length=1)
    reasoning: str = Field(min_length=1)


DecisionOutput = Annotated[
    PivotDecisionOutput | EscalateDecisionOutput | ParkDecisionOutput | CloseDecisionOutput | SpawnDecisionOutput,
    Field(discriminator="action"),
]
_DECISION_OUTPUT = TypeAdapter(DecisionOutput)


def parse_decision_output(value: Any) -> AgentDecision:
    """Enforce per-action required fields before semantic admission."""
    parsed = _DECISION_OUTPUT.validate_python(value)
    return AgentDecision.model_validate(parsed.model_dump())


def decision_schema() -> dict:
    """Conditional JSON schema used by Ollama structured output."""
    return _DECISION_OUTPUT.json_schema()


class PivotTimeRange(BaseModel):
    """Truth-preserving time bounds within an attempted pivot partition."""

    model_config = ConfigDict(extra="forbid")

    start: str = Field(min_length=1)
    end: str = Field(min_length=1)
    start_inclusive: bool = True
    end_inclusive: bool = False
    reason: str = ""


class PivotCoverage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target: str
    start: datetime
    end: datetime
    status: Literal["complete", "partial", "failed"]
    reasons: list[str] = Field(default_factory=list)
    returned: int = 0
    total: int | None = None
    covered_ranges: list[PivotTimeRange] = Field(default_factory=list)
    unresolved_ranges: list[PivotTimeRange] = Field(default_factory=list)


class PivotResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["complete", "partial", "failed", "unsupported"]
    task_ids: list[str] = Field(default_factory=list)
    event_ids: list[str] = Field(default_factory=list)
    candidate_ids: list[str] = Field(default_factory=list)
    entities: list[EntityRef] = Field(default_factory=list)
    event_summaries: list[dict[str, Any]] = Field(default_factory=list)
    anchor_event_ids: list[str] = Field(default_factory=list)
    matched_event_count: int = 0
    coverage: list[PivotCoverage] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
    duration_ms: int = 0

