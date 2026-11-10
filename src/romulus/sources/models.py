"""Typed search intents, compiled queries and search outcomes shared by all adapters."""
from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field, PrivateAttr, field_validator, model_validator


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


PredicateOp = Literal["eq", "in", "not_in", "exists", "missing", "prefix", "contains", "gte", "lt", "cidr"]


def typed_field_name(name) -> bool:
    """Whether `name` can be a predicate's field: dot-separated parts, each of letters, digits and underscores.
    Source mappings can hold other names (`zeek.dns.@proc`, `a-b`, `a b`); a field contract keeps those as
    record fields that no predicate searches (sources.profile.FieldContract)."""
    return isinstance(name, str) and bool(name) and all(part.replace("_", "").isalnum() for part in name.split("."))


class Predicate(BaseModel):
    """One typed condition. `contains` is only legal on fields whose contract allows it, and
    it is a retrieval aid: evaluators must still apply exact typed logic locally. Its value is
    a string, or a list of strings meaning any of them."""
    field: str
    op: PredicateOp
    value: Any = None

    @field_validator("field")
    @classmethod
    def _field(cls, v: str) -> str:
        if not typed_field_name(v):
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
    max_records: int = Field(default=10_000, ge=1, le=2_000_000)  # raw hits or aggregate buckets
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
    # the time field's resolution, which an OpenSearch date sort value is written in (`date` ms, `date_nanos` ns)
    time_unit: Literal["ms", "ns", "s"] = "ms"


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
    # Every response of a raw outcome was surrogate free (sources.es.surrogate_free): its records hold no lone UTF-16
    # surrogate, so normalization may skip looking for one. Never serialized; False unless established.
    _surrogate_free: bool = PrivateAttr(default=False)

    @property
    def surrogate_free(self) -> bool:
        return self._surrogate_free

    def model_copy(self, *, update=None, deep: bool = False):
        copy = super().model_copy(update=update, deep=deep)
        if update and "records" in update:
            # records put together from elsewhere (merged samples) carry no proof: whoever has one sets it again
            copy._surrogate_free = False
        return copy
