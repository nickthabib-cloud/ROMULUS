"""How a claim names the writer of a Linux log line it rests on.

A syslog identifier is chosen by whatever process wrote the line (`logger -t pkexec ...` writes a "pkexec" line).
journald records the writing process itself (_COMM, _EXE), and the normalizer compares the two: a line whose
identifier journald confirms carries no writer caveat; one journald contradicts carries WRITER_MISMATCH_CAVEAT and
names the process in `log.writer`; one with no journald identity (plain syslog, or a journal shape without the
process fields) carries an unverifiable-writer caveat. A claim built on such a line says so, without changing its lane:
the finding stays visible, its subject is what the record proves.
"""
from __future__ import annotations

from romulus.evidence.linux_text_types import NEW_WRITER_CAVEAT, SYSLOG_WRITER_CAVEAT, WRITER_MISMATCH_CAVEAT
from romulus.evidence.typed import TypedEvent


def writer_state(event: TypedEvent) -> str:
    """'verified', 'mismatch' or 'unverified' for a line-derived event; 'verified' when no writer caveat applies."""
    if WRITER_MISMATCH_CAVEAT in event.caveats:
        return "mismatch"
    if NEW_WRITER_CAVEAT in event.caveats or SYSLOG_WRITER_CAVEAT in event.caveats:
        return "unverified"
    return "verified"


def line_subject(event: TypedEvent, identifier: str) -> str:
    """The subject a claim uses for the line: "" when journald confirms its writer (the claim keeps its own wording),
    else "a line logged under the identifier X (...)" saying what is known about the writer."""
    state = writer_state(event)
    if state == "mismatch":
        other = event.get("log.writer")
        shown = f", {str(other)!r}," if other else ""
        return f"a line logged under the identifier {identifier!r} (journald shows another program{shown} wrote it)"
    if state == "unverified":
        # a raw text line (log.format typed from its own envelope) or a syslog line the shipper flagged
        source = ("plain syslog" if SYSLOG_WRITER_CAVEAT in event.caveats or event.has("log.format")
                  else "this record, which carries no journald process identity")
        return f"a line logged under the identifier {identifier!r} (writer not verifiable from {source})"
    return ""


def writer_sentence(events: list[TypedEvent], identifier_of) -> str:
    """One sentence naming the writer state of the line records a claim cites, or "" when journald confirms all."""
    notes = []
    for event in events:
        subject = line_subject(event, identifier_of(event))
        if subject and subject not in notes:
            notes.append(subject)
    if not notes:
        return ""
    shown = "; ".join(notes[:3]) + (f"; and {len(notes) - 3} more" if len(notes) > 3 else "")
    return f" The record(s) are {shown}."
