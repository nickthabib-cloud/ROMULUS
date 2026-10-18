"""Source-independent types exchanged by the investigator controller."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

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


class PivotResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["complete", "partial", "failed", "unsupported"]
    task_ids: list[str] = Field(default_factory=list)
    event_ids: list[str] = Field(default_factory=list)
    candidate_ids: list[str] = Field(default_factory=list)
    entities: list[EntityRef] = Field(default_factory=list)
    event_summaries: list[dict[str, Any]] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
    duration_ms: int = 0

