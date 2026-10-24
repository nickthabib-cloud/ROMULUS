"""What an aggregate claim cites, and how it says so.

An aggregate claim usually rests on more records than it can cite. It may still state a total, a time span or an
example value only when the citations carry what it states:
- a span ('A – B') starts at the time of a cited record and ends at the time of a cited record. The records that bound
  it are tracked per group (`Ends`) and staged as holds the stage releases when a later record takes the bound
  (`BoundStage`), so a group costs at most two held records however many it has;
- a total over more records than are cited says how many are cited ('20 of the 479 records are cited, including the
  first and the last': `cited_phrase`);
- every example value the claim names (a signature, a user agent, a port, a process) is taken from a cited record,
  and a list cut short says how many more there are (`more`). `Named` keeps one record for each of the first few
  distinct values of a group for this.

When the stage could not hold a bounding record (its volume reached the reserve), the claim says the interval is
computed from every record and that record was not kept (`bound_note`); nothing is dropped from what is stated.
"""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from romulus.evidence.typed import TypedEvent


@dataclass
class Ends:
    """The records that bound an interval a claim states: the one with the earliest start and the one with the
    latest end, each held as (time, event id). Ties go to the lower event id, so the choice does not depend on the
    order records are read."""
    first: tuple[float, str] | None = None
    last: tuple[float, str] | None = None
    held: list = field(default_factory=lambda: [None, None])   # the id the stage holds for each bound (BoundStage)

    def offer(self, start: float, end: float, event_id: str) -> tuple[bool, bool]:
        """Take one record's span: (it became the earliest, it became the latest)."""
        first = self.first is None or (start, event_id) < self.first
        last = self.last is None or end > self.last[0] or (end == self.last[0] and event_id < self.last[1])
        if first:
            self.first = (start, event_id)
        if last:
            self.last = (end, event_id)
        return first, last

    def fold(self, other: Ends) -> None:
        """Take another group's bounds (folding groups at finalize)."""
        if other.first is not None and (self.first is None or other.first < self.first):
            self.first = other.first
        if other.last is not None and (self.last is None or other.last[0] > self.last[0]
                                       or (other.last[0] == self.last[0] and other.last[1] < self.last[1])):
            self.last = other.last

    def ids(self) -> list[str]:
        return list(dict.fromkeys(ref[1] for ref in (self.first, self.last) if ref is not None))


class BoundStage:
    """Stages the records that bound each group's interval, as holds the stage releases when a later record takes
    the bound, so the stage holds at most two records per group however many records the group has. A bound moves
    only outwards, so a record that stops being one never becomes one again. The latest changes with nearly every
    record of a long-lived group, so a new bound waits until the batch ends: only the record still holding it then is
    held, and the record it replaces is released. A rule offers bounds only for groups that can still be reported
    (`stage=False` tracks the bound without staging it), so a group that never qualifies stages nothing for them.

    The sweep reads `drain` (the events to stage, with the playbook's other citations) and then `last` (which of
    them are holds, and which earlier holds to release)."""

    def __init__(self):
        self.pending: dict[tuple, tuple[TypedEvent, Ends]] = {}
        self.kept: list[TypedEvent] = []        # bounds of intervals that have closed: kept to the end
        self.releasing: list[str] = []
        self.last: tuple[list[str], list[str]] = ([], [])

    def offer(self, key, ends: Ends, start: float, end: float, event: TypedEvent, stage: bool = True) -> bool:
        """Offer a record to the group's bounds; True when it became one of them. A bound taken by a record that is
        not staged releases the hold it replaces (that record is no longer the bound)."""
        moved = ends.offer(start, end, event.id)
        for side in (0, 1):
            if not moved[side]:
                continue
            if stage:
                self.pending[(key, side)] = (event, ends)
                continue
            self.pending.pop((key, side), None)
            if ends.held[side] is not None:
                self.releasing.append(ends.held[side])
                ends.held[side] = None
        return moved[0] or moved[1]

    def offer_at(self, key, ends: Ends, event: TypedEvent, stage: bool = True) -> bool:
        """Offer a record whose span is its own time (a log line, an alert, a question)."""
        t = event.ts.timestamp()
        return self.offer(key, ends, t, t, event, stage)

    def settle(self, key, ends: Ends) -> None:
        """The group's latest record bounds an interval that has closed (a later record starts a new one): it is kept
        to the end however the group grows from here."""
        entry = self.pending.pop((key, 1), None)
        if entry is not None:
            self.kept.append(entry[0])
            if ends.held[1] is not None and ends.held[1] != entry[0].id:
                self.releasing.append(ends.held[1])       # an earlier latest of the same interval
        ends.held[1] = None                                # a hold from an earlier batch stays: it is that bound

    def drain(self) -> list[TypedEvent]:
        out, held, released = list(self.kept), [], self.releasing
        for (_key, side), (event, ends) in self.pending.items():
            old = ends.held[side]
            if old == event.id:
                continue
            if old is not None:
                released.append(old)
            ends.held[side] = event.id
            out.append(event)
            held.append(event.id)
        self.last = (held, released)
        self.pending, self.kept, self.releasing = {}, [], []
        return out

    def clear(self) -> None:
        self.pending.clear()
        self.kept.clear()
        self.releasing.clear()
        self.last = ([], [])


class Holds:
    """Records a rule holds on the stage only while it may cite them (a group's earliest few processes, say), each
    released when it can no longer be cited, so the stage holds a bounded number per group however the group grows.
    One hold per call: a record held twice (by two groups) is released twice. Drained with the rule's other staged
    records; `last` then says which of them are holds and which earlier holds to release (`Playbook.drain_bounds`)."""

    def __init__(self):
        self.pending: dict[str, list] = {}      # event id -> [event, holds taken this batch]
        self.releasing: list[str] = []
        self.last: tuple[list[str], list[str]] = ([], [])

    def hold(self, event: TypedEvent) -> None:
        entry = self.pending.setdefault(event.id, [event, 0])
        entry[1] += 1

    def release(self, event_id: str) -> None:
        """Let go of one hold of the record: one not yet handed to the stage is simply not staged."""
        entry = self.pending.get(event_id)
        if entry is None:
            self.releasing.append(event_id)
            return
        entry[1] -= 1
        if entry[1] <= 0:
            del self.pending[event_id]

    def drain(self) -> list[TypedEvent]:
        out = [event for event, n in self.pending.values() for _ in range(n)]
        self.last = ([event.id for event in out], self.releasing)
        self.pending, self.releasing = {}, []
        return out

    def clear(self) -> None:
        self.pending, self.releasing = {}, []
        self.last = ([], [])


class Named:
    """One cited record for each of the first `limit` distinct values a group shows (signatures, user agents, ports),
    so every value a claim names comes from a cited record. Held as {value: event id}; the record is staged once,
    kept to the end, when its value enters."""

    __slots__ = ("ids", "limit")

    def __init__(self, limit: int):
        self.limit = limit
        self.ids: dict = {}

    def offer(self, value, event: TypedEvent) -> bool:
        """True when `value` entered (its record must reach the stage)."""
        if value in self.ids or len(self.ids) >= self.limit:
            return False
        self.ids[value] = event.id
        return True

    def values(self) -> list:
        return list(self.ids)

    def __contains__(self, value) -> bool:
        return value in self.ids


def cite_with_bounds(load, events, ends: Ends | Iterable[Ends], ids, limit: int, named=()
                     ) -> tuple[list[TypedEvent], set[str]]:
    """Cited records: the records bounding the claim's intervals that the stage holds (`load`), then `named` (records
    a stated value comes from, always cited), then `ids`, up to `limit` in all (or more, when the bounds and the named
    records alone pass it). Every id of `named` and `ids` must be staged (`events` raises otherwise). Returns the
    events in time order and the bounding ids the stage does not hold."""
    every = [ends] if isinstance(ends, Ends) else list(ends)
    bounds = list(dict.fromkeys(i for each in every for i in each.ids()))
    held = {event.id: event for event in load(bounds)} if bounds else {}
    required = list(dict.fromkeys([*(i for i in bounds if i in held), *named]))
    wanted = list(dict.fromkeys([*required, *ids]))[:max(limit, len(required))]
    rest = [i for i in wanted if i not in held]
    found = [held[i] for i in wanted if i in held] + (events(rest) if rest else [])
    return sorted(found, key=lambda e: (e.ts, e.id)), set(bounds) - set(held)


def cite_group(load, examples: list[TypedEvent], bounds: BoundStage, ends: Ends | Iterable[Ends],
               limit: int = 20, named=()) -> tuple[list[TypedEvent], set[str]]:
    """`cite_with_bounds` for a group whose first records are already loaded (`examples`): bounding and named records
    come from the stage (`load`), or from `bounds` while not yet handed to it (a rule driven without a sweep)."""
    known = {e.id: e for e in examples}
    known.update((event.id, event) for event, _ends in bounds.pending.values())

    def get(ids):
        found = {e.id: e for e in load([i for i in ids if i not in known])} if any(i not in known for i in ids) else {}
        return [known.get(i) or found[i] for i in ids if i in known or i in found]

    def strict(ids):
        found = get(ids)
        if len(found) != len(set(ids)):
            raise LookupError(f"{len(set(ids)) - len(found)} cited event(s) absent from the stage")
        return found

    return cite_with_bounds(get, strict, ends, [e.id for e in examples], limit, named)


def cited_phrase(cited: int, records: int, bounded: bool, noun: str = "records", one: str = "record") -> str:
    """How many of the records a claim rests on are cited: '20 of the 47 records are cited, including the first and
    the last.'"""
    if records == 1:
        return f" Its one {one} is cited."
    if cited >= records:
        return f" All {records} {noun} are cited."
    return f" {cited} of the {records} {noun} are cited" + (", including the first and the last." if bounded else ".")


def bound_note(missing: set[str], ends: Ends, what: str = "this interval") -> str:
    """The claim's sentence when a record bounding its interval was not held for citation ('' when both are)."""
    sides = [name for name, ref in (("starts", ends.first), ("ends", ends.last)) if ref and ref[1] in missing]
    if not sides:
        return ""
    return (f" The record that {' and the record that '.join(sides)} {what} was not kept for citation; the "
            f"interval is computed from every record.")


def more(shown: int, total: int) -> str:
    """' and 3 more' when a list names `shown` of `total` values ('' when it names them all)."""
    return f" and {total - shown} more" if total > shown else ""
