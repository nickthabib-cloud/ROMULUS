"""Strict source-neutral argument schemas for the investigator tools."""
from __future__ import annotations

import ipaddress
from datetime import datetime
from typing import Annotated, Any, Literal

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
        if value.kind != "ip":
            raise ValueError("entity must be an IP")
        return value


SearchScope = Literal["host", "network", "all"]
# The operations an agent search may use. `contains` is only a retrieval aid (a mention is not an action), and
# `not_in`, `missing` and a bare `exists` select almost everything: none of them is offered.
SearchOp = Literal["eq", "in", "prefix", "cidr", "gte", "lt"]
SEARCH_OPS: tuple[str, ...] = ("eq", "in", "prefix", "cidr", "gte", "lt")
# A search must hold at least one of these: each names the values it selects.
SELECTIVE_OPS = frozenset({"eq", "in", "prefix", "cidr"})
MAX_SEARCH_CONDITIONS = 4
MAX_SEARCH_VALUES = 20
MAX_SEARCH_VALUE_CHARS = 256
# The typed field names a search condition can carry: dot-separated ASCII letters, digits and underscores.
MAX_SEARCH_FIELD_CHARS = 128
SEARCH_FIELD_PATTERN = r"^[A-Za-z0-9_]+(\.[A-Za-z0-9_]+)*$"
# A prefix shorter than this selects too much to be a lead (a drive letter, a single path separator)
MIN_PREFIX_CHARS = 3
# A network broader than these is most of an address space, not a lead
MIN_CIDR_PREFIX = {4: 8, 6: 16}


class SearchCondition(_Strict):
    """One typed condition of an agent search: a typed field of the target's field contract, an operation and its
    values. Values stay exactly as written (no case folding, no Unicode normalization); the hunt layer parses each
    one by the field's native type and sends it to the source only as a literal query value."""
    field: str = Field(min_length=1, max_length=MAX_SEARCH_FIELD_CHARS, pattern=SEARCH_FIELD_PATTERN, description=(
        "A typed field name: dot-separated letters, digits and underscores, such as destination.port."))
    op: SearchOp = Field(description=(
        "eq, prefix, cidr, gte and lt take one value; in takes up to 20. A prefix is at least 3 characters; a cidr "
        "network is /8 (IPv4) or /16 (IPv6) or narrower."))
    values: list[Annotated[str, Field(min_length=1, max_length=MAX_SEARCH_VALUE_CHARS)]] = Field(
        min_length=1, max_length=MAX_SEARCH_VALUES, description=(
            "The values as strings, numbers and times included (\"443\", \"2024-11-18T10:00:00Z\")."))

    @field_validator("field")
    @classmethod
    def _typed(cls, value: str) -> str:
        # the rule of sources.models.typed_field_name (the agent package imports nothing from sources); the hunt
        # layer's Predicate checks it again
        if not all(part.replace("_", "").isalnum() and part.isascii() for part in value.split(".")):
            raise ValueError("field must be a typed field name: dot-separated letters, digits and underscores")
        return value

    @model_validator(mode="after")
    def _shape(self):
        if self.op != "in" and len(self.values) != 1:
            raise ValueError(f"{self.op} takes exactly one value; use in for several")
        if self.op == "prefix" and len(self.values[0]) < MIN_PREFIX_CHARS:
            raise ValueError(f"a prefix must be at least {MIN_PREFIX_CHARS} characters")
        if self.op == "cidr":
            try:
                network = ipaddress.ip_network(self.values[0], strict=False)
            except ValueError:
                raise ValueError("cidr takes one IP network, such as 192.0.2.0/24") from None
            if network.prefixlen < MIN_CIDR_PREFIX[network.version]:
                raise ValueError(f"a cidr network must be /{MIN_CIDR_PREFIX[network.version]} or narrower")
        return self

    def canonical(self) -> SearchCondition:
        """The same condition with an `in` list deduplicated and sorted, so a repeated search has one identity."""
        values = sorted(set(self.values)) if self.op == "in" else list(self.values)
        return self.model_copy(update={"values": values})


def check_search_conditions(conditions: list[SearchCondition]) -> list[SearchCondition]:
    """Deduplicate and order conditions, and require at least one that names the values it selects."""
    canonical = sorted({(item.field, item.op, tuple(item.canonical().values)): item.canonical()
                        for item in conditions}.values(), key=lambda item: (item.field, item.op, item.values))
    if not any(item.op in SELECTIVE_OPS for item in canonical):
        raise ValueError("a search needs at least one eq, in, prefix or cidr condition; gte and lt alone select "
                         "too much")
    return canonical


class SearchEventsArgs(_WindowArgs):
    scope: SearchScope
    conditions: list[SearchCondition] = Field(min_length=1, max_length=MAX_SEARCH_CONDITIONS)

    @field_validator("conditions")
    @classmethod
    def _selective(cls, value: list[SearchCondition]) -> list[SearchCondition]:
        return check_search_conditions(value)


MAX_QUERY_SIZE = 100
QUERY_SOURCE_NAME = r"^[A-Za-z0-9_.+:@\-]+$"


class QuerySourceArgs(_WindowArgs):
    """An agent-written query of one hunt source, as the toolbox accepted it (window inside the hunt's). Its shape is
    checked here; what it may contain is decided in the hunt layer, which refuses anything outside its allowlists
    before any source query (sources.agent_query)."""
    source: str = Field(min_length=1, max_length=300, pattern=QUERY_SOURCE_NAME)
    query: dict[str, Any] | None = None
    expression: str | None = Field(default=None, min_length=1, max_length=2_000)
    aggs: dict[str, Any] | None = None
    sort: list[Any] | None = Field(default=None, min_length=1, max_length=3)
    size: int = Field(default=20, ge=0, le=MAX_QUERY_SIZE)
    source_fields: list[str] | None = Field(default=None, min_length=1, max_length=50)
    # whether the toolbox narrowed the requested window to the hunt's
    window_clamped: bool = False

    @model_validator(mode="after")
    def _one_language(self):
        if self.expression is not None and any(
                value is not None for value in (self.query, self.aggs, self.sort, self.source_fields)):
            raise ValueError("an Arkime expression takes no query, aggs, sort or source_fields")
        return self


class QuerySourceRequest(_Strict):
    tool: Literal["query_source"]
    arguments: QuerySourceArgs


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


class SearchEventsRequest(_Strict):
    tool: Literal["search_events"]
    arguments: SearchEventsArgs


ToolRequest = Annotated[
    EntityTimelineRequest | AuthActivityRequest | ProcessTreeRequest | IdsAlertsRequest | SearchEventsRequest,
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
            "arguments": "entity {kind: ip, value, role}, start, end",
            "purpose": "retrieve IDS alerts for a known IP",
        },
        "search_events": {
            "arguments": ("scope: host|network|all, conditions [{field, op: eq|in|prefix|cidr|gte|lt, values}] "
                          "(1-4, at least one eq, in, prefix or cidr), start, end"),
            "purpose": "find the records in the hunt window whose typed fields hold given values",
        },
    }

