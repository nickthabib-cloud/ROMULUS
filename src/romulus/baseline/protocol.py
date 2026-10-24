"""Source-neutral contracts for exact baseline history retrieval."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Literal, Protocol, runtime_checkable

from romulus.evidence.typed import TypedEvent

# omitted_budget: the hunt's lookback budget (queries, records, wall clock, partition cap) ended the read; history is
# then short, which is not a source failure
type FetchState = Literal["complete", "partial", "failed", "omitted_budget"]


@dataclass(frozen=True)
class HistoryPartition:
    """One exact-count source partition within an hour-sized history request."""

    target: str
    start: datetime
    end: datetime
    expected_records: int
    identity: str


@dataclass(frozen=True)
class HistoryFetch:
    """Normalized records plus the source's explicit completeness verdict."""

    events: tuple[TypedEvent, ...]
    completeness: FetchState
    reasons: tuple[str, ...]
    record_count: int
    query_count: int = 1


@dataclass(frozen=True)
class HistoryPlan:
    """Exact partitions plus the physical planning spend and its completeness."""

    partitions: tuple[HistoryPartition, ...]
    query_count: int
    completeness: FetchState
    reasons: tuple[str, ...]


@runtime_checkable
class HistorySource(Protocol):
    """Executor boundary; pure baseline code cannot reach adapters or source syntax."""

    def plan(self, target: str, start: datetime, end: datetime, *, query_budget: int) -> HistoryPlan: ...

    def fetch(self, partition: HistoryPartition, *, record_budget: int | None = None,
              query_budget: int | None = None, deadline: float | None = None) -> HistoryFetch: ...
