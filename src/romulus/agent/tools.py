"""Strict source-neutral argument schemas for the M1 investigator tools."""
from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, field_validator, model_validator

from romulus.agent.models import AgentDecision, EntityRef


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class _WindowArgs(_Strict):
    start: datetime
    end: datetime

    @model_validator(mode="after")
    def _valid_window(self):
        if self.start.tzinfo is None or self.end.tzinfo is None:
            raise ValueError("window bounds must be timezone-aware")
        if self.start >= self.end:
            raise ValueError("start must be before end")
        return self


class EntityTimelineArgs(_WindowArgs):
    entity: EntityRef


class AuthActivityArgs(_WindowArgs):
    entity: EntityRef

    @field_validator("entity")
    @classmethod
    def _auth_entity(cls, value: EntityRef) -> EntityRef:
        if value.kind not in ("host", "account"):
            raise ValueError("entity must be a host or account")
        return value


class ProcessTreeArgs(_WindowArgs):
    host: str = Field(min_length=1)
    process_id: int = Field(ge=1)


class IdsAlertsArgs(_WindowArgs):
    entity: EntityRef

    @field_validator("entity")
    @classmethod
    def _ids_entity(cls, value: EntityRef) -> EntityRef:
        if value.kind not in ("host", "ip"):
            raise ValueError("entity must be a host or IP")
        return value


class EntityTimelineRequest(_Strict):
    tool: Literal["entity_timeline"]
    arguments: EntityTimelineArgs


class AuthActivityRequest(_Strict):
    tool: Literal["auth_activity"]
    arguments: AuthActivityArgs


class ProcessTreeRequest(_Strict):
    tool: Literal["process_tree"]
    arguments: ProcessTreeArgs


class IdsAlertsRequest(_Strict):
    tool: Literal["ids_alerts"]
    arguments: IdsAlertsArgs


ToolRequest = Annotated[
    EntityTimelineRequest | AuthActivityRequest | ProcessTreeRequest | IdsAlertsRequest,
    Field(discriminator="tool"),
]
_REQUEST = TypeAdapter(ToolRequest)


def parse_tool_request(decision: AgentDecision):
    if decision.action != "pivot" or decision.tool is None:
        raise ValueError("decision is not a pivot with a named tool")
    return _REQUEST.validate_python({"tool": decision.tool, "arguments": decision.arguments})


def tool_schema() -> dict:
    """JSON schema supplied to the model for pivot argument validation."""
    return _REQUEST.json_schema()


def tool_catalog() -> dict:
    """Compact model-facing catalog; strict validation still uses ``tool_schema``."""
    return {
        "entity_timeline": {
            "arguments": "entity {kind: host|ip, value, role}, start, end",
            "purpose": "retrieve a cited host or IP timeline within the hunt window",
        },
        "auth_activity": {
            "arguments": "entity {kind: host|account, value, role}, start, end",
            "purpose": "retrieve authentication and privilege activity",
        },
        "process_tree": {
            "arguments": "host, process_id, start, end",
            "purpose": "retrieve process events for a process ID already present in case evidence",
        },
        "ids_alerts": {
            "arguments": "entity {kind: host|ip, value, role}, start, end",
            "purpose": "retrieve IDS alerts for a known host or IP",
        },
    }

