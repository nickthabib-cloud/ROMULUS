"""Bounded coverage reasons: classes with exact counts and a few example record ids, never one entry per record."""
from __future__ import annotations

from collections.abc import Iterable

# Example record ids kept per reason class, and reason classes kept per list.
EXAMPLES = 5
CLASSES = 20


def _split(reason: str) -> tuple[str | None, str]:
    """("<record id>", "<text>") for a per-record reason "<id>: <text>", else (None, reason)."""
    head, separator, tail = reason.partition(": ")
    if separator and head and " " not in head and tail:
        return head, tail
    return None, reason


class ReasonTally:
    """Per-record reasons folded into classes as they arrive: memory is bounded by the classes, not the records.

    A per-record reason "<id>: <text>" counts toward its text's class and keeps its id among the first `EXAMPLES`;
    any other reason is a class of its own. `summary()` states every class with its exact count, up to `CLASSES`
    classes and a stated remainder.
    """

    def __init__(self) -> None:
        self._classes: dict[str, list] = {}   # text -> [count, example ids]

    def add(self, reason: str) -> None:
        record, text = _split(reason)
        entry = self._classes.setdefault(text, [0, []])
        entry[0] += 1
        if record is not None and len(entry[1]) < EXAMPLES and record not in entry[1]:
            entry[1].append(record)

    def __bool__(self) -> bool:
        return bool(self._classes)

    def summary(self) -> tuple[str, ...]:
        out = []
        for text in sorted(self._classes):
            count, examples = self._classes[text]
            if not examples:
                out.append(text if count == 1 else f"{text} ({count} times)")
                continue
            listed = ", ".join(sorted(examples))
            more = f" and {count - len(examples)} more" if count > len(examples) else ""
            out.append(f"{text} ({count} record(s): {listed}{more})")
        if len(out) > CLASSES:
            out = [*out[:CLASSES], f"and {len(out) - CLASSES} more reason class(es)"]
        return tuple(out)


def summarize(reasons: Iterable[str]) -> list[str]:
    """A bounded summary of any reason list (see `ReasonTally`)."""
    tally = ReasonTally()
    for reason in reasons:
        tally.add(reason)
    return list(tally.summary())
