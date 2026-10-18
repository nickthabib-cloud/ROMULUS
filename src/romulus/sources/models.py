"""Typed search intents, compiled queries and search outcomes shared by all adapters."""
from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator


class Window(BaseModel):
    """UTC half-open interval [start, end)."""
    start: datetime
    end: datetime

    @model_validator(mode="after")
    def _check(self):
        if self.start.tzinfo is None or self.end.tzinfo is None:
            raise ValueError("window bounds must be timezone-aware")
        if not self.start < self.end:
            raise ValueError("window start must be before end")
        return self

    def key(self) -> str:
        return f"{self.start.isoformat()}/{self.end.isoformat()}"


PredicateOp = Literal["eq", "in", "exists", "missing", "prefix", "contains", "gte", "lt", "cidr"]


class Predicate(BaseModel):
    """One typed condition. `contains` is only legal on fields whose contract allows it, and
    it is a retrieval aid: evaluators must still apply exact typed logic locally."""
    field: str
    op: PredicateOp
    value: Any = None

    @field_validator("field")
    @classmethod
    def _field(cls, v: str) -> str:
        if not v or not all(part.replace("_", "").isalnum() for part in v.split(".")):
            raise ValueError(f"invalid field name: {v!r}")
        return v


class SearchIntent(BaseModel):
    """Source-neutral description of a search. Never contains backend syntax."""
    kind: Literal["raw", "aggregate", "histogram"]
    target: str
    window: Window
    filters: list[Predicate] = []
    any_of: list[list[Predicate]] = []           # OR of AND-groups, ANDed with filters
    group_by: list[str] = []                     # aggregate
    interval_seconds: int | None = None          # histogram
    max_records: int = Field(default=10_000, ge=1, le=2_000_000)
    order: Literal["asc", "desc"] = "asc"       # raw retrieval order; never model supplied
    purpose: str = ""

    @model_validator(mode="after")
    def _raw_order_only(self):
        if self.kind != "raw" and self.order != "asc":
            raise ValueError("descending order is only valid for raw retrieval")
        return self


class CompiledQuery(BaseModel):
    backend: Literal["elasticsearch", "opensearch", "arkime", "tshark"]
    target: str
    body: dict[str, Any]
    fingerprint: str


class Completeness(StrEnum):
    complete = "complete"
    partial = "partial"          # cap, timeout, shard failure, other-bucket, etc.
    failed = "failed"


class SearchOutcome(BaseModel):
    target: str
    fingerprint: str
    started_at: datetime
    ended_at: datetime
    backend_version: str = ""
    completeness: Completeness
    reasons: list[str] = []                      # why not complete
    total: int | None = None
    total_relation: Literal["eq", "gte", "unknown"] = "unknown"
    returned: int = 0
    records: list[dict[str, Any]] = []           # {"_id", "_index", "_source"} for raw
    buckets: list[dict[str, Any]] = []           # {"key": {...}, "count": n} for aggregate/histogram
    error: str | None = None
