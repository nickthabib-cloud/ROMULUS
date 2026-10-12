"""Deterministic bounded sampling plans shared by telemetry adapters."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


SAMPLING_POLICY_VERSION = 1
SAMPLING_STRATEGY = "time_or_rank_stratified"


def time_strata(start: datetime, end: datetime, count: int) -> list[dict[str, Any]]:
    """Split one aware interval into stable, adjacent UTC strata."""

    if not isinstance(start, datetime) or not isinstance(end, datetime):
        raise ValueError("Sampling bounds must be datetimes")
    if start.tzinfo is None or end.tzinfo is None:
        raise ValueError("Sampling bounds must be timezone-aware")
    start_utc = start.astimezone(timezone.utc)
    end_utc = end.astimezone(timezone.utc)
    if start_utc >= end_utc:
        raise ValueError("Sampling bounds must define a positive interval")
    pieces = max(1, int(count))
    span = end_utc - start_utc
    boundaries = [start_utc + (span * index / pieces) for index in range(pieces)] + [end_utc]
    return [
        {
            "index": index,
            "start": boundaries[index],
            "end": boundaries[index + 1],
            "include_end": index == pieces - 1,
        }
        for index in range(pieces)
    ]


def allocate_cap(cap: int, count: int) -> list[int]:
    """Allocate exactly cap slots while avoiding zero-length strata."""

    cap_value = int(cap)
    count_value = int(count)
    if cap_value < 1 or count_value < 1:
        raise ValueError("Sampling cap and stratum count must be positive")
    pieces = min(cap_value, count_value)
    base, remainder = divmod(cap_value, pieces)
    return [base + (1 if index < remainder else 0) for index in range(pieces)]


def rank_windows(total: int, cap: int, count: int) -> list[dict[str, int]]:
    """Return bounded windows spread deterministically across an ordered result set."""

    total_value = int(total)
    cap_value = int(cap)
    if total_value < 0 or cap_value < 1 or int(count) < 1:
        raise ValueError("Rank sampling inputs are invalid")
    if total_value == 0:
        return []
    if total_value <= cap_value:
        return [{"index": 0, "offset": 0, "length": total_value}]
    allocations = allocate_cap(cap_value, int(count))
    last = len(allocations) - 1
    windows = []
    for index, length in enumerate(allocations):
        offset = 0 if last == 0 else round(index * (total_value - length) / last)
        windows.append({"index": index, "offset": offset, "length": length})
    return windows


def sampling_policy(settings: Any) -> dict[str, Any]:
    """Return the model-inaccessible sampling policy persisted with a task."""

    return {
        "version": SAMPLING_POLICY_VERSION,
        "strategy": SAMPLING_STRATEGY,
        "strata": max(2, min(int(settings.time_sampling_strata), 24)),
    }
