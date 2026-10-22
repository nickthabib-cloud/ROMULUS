"""Bounded detector state.

A hunt can read hundreds of millions of records over weeks from thousands of hosts, so no playbook may keep state
that grows with the number of records it reads. Each structure is bounded in one of four ways:

- a time horizon the rule's own semantics define (a join window, a protocol timeout, a burst interval);
- a cap sized by an explicit memory budget; reaching it makes the rule's coverage partial and names what was not
  evaluated (`Playbook.refuse` and `Playbook.note_limit`), and it never lowers the lane of what was evaluated;
- the sweep's on-disk event stage (full events on disk, compact keys in memory);
- streaming.

This module holds the shared pieces: the re-delivery guard and the limit record the sweep turns into coverage.
"""
from __future__ import annotations

from dataclasses import dataclass

# Ids remembered by the re-delivery guard per generation (two generations are kept). The sweep reads each raw record
# once: partitions are disjoint half-open windows of one time field per target, and a capped fetch is discarded
# before any playbook sees it. The guard therefore protects only against a batch handed over again, which it
# catches whenever fewer than this many other ids arrived in between. Budget: about 100 bytes per id, so at most
# about 13 MB per playbook.
RECENT_IDS = 65_536


class RecentIds:
    """A duplicate check over recently seen ids, in two generations of at most `limit` ids each: an id is
    recognised again while fewer than `limit` other ids arrived after it. Memory is at most 2 x `limit` ids."""

    __slots__ = ("_current", "_previous", "limit")

    def __init__(self, limit: int | None = None):
        self.limit = RECENT_IDS if limit is None else limit
        self._current: set[str] = set()
        self._previous: set[str] = set()

    def __contains__(self, key: object) -> bool:
        return key in self._current or key in self._previous

    def add(self, key: str) -> None:
        if key in self._current:
            return
        self._current.add(key)
        if len(self._current) >= self.limit:
            self._previous, self._current = self._current, set()

    def __len__(self) -> int:
        return len(self._current) + len(self._previous)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, RecentIds):
            return self._current | self._previous == other._current | other._previous
        if isinstance(other, (set, frozenset)):
            return self._current | self._previous == other
        return NotImplemented

    __hash__ = None                 # mutable, like a set

    def clear(self) -> None:
        self._current.clear()
        self._previous.clear()


@dataclass
class Limit:
    """One budget a playbook reached: what it bounds, and how many records it left unevaluated (0 when the cap
    only reduced what the claims can say, such as an exact count becoming a lower bound)."""
    text: str
    records: int = 0
    hits: int = 0

    def reason(self) -> str:
        if self.records:
            return f"state limit: {self.text} ({self.records} record(s) not evaluated)"
        return f"state limit: {self.text}"
