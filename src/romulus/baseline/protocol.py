"""Source-neutral contracts for exact baseline history retrieval."""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from typing import Literal, Protocol, runtime_checkable

from romulus.evidence.typed import TypedEvent

type FetchState = Literal["complete", "partial", "failed"]


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


@runtime_checkable
class HistorySource(Protocol):
    """Executor boundary; pure baseline code cannot reach adapters or source syntax."""

    def plan(self, target: str, start: datetime, end: datetime) -> Iterable[HistoryPartition]: ...

    def fetch(self, partition: HistoryPartition) -> HistoryFetch: ...
