"""Source-neutral parser results; normalization adds record identity and field provenance."""
from __future__ import annotations

from dataclasses import dataclass, field

from romulus.evidence.typed import Outcome

# The caveat on an event whose logging process (journald's comm or executable) is not the program it names.
WRITER_MISMATCH_CAVEAT = "Writer identity disagrees with the logging process"
# The caveat on an event whose identifier no journald process identity could confirm (none was recorded).
NEW_WRITER_CAVEAT = "Writer identity not verifiable"
# The caveat on a sudo record that repeats a field separator inside the caller's text.
SUDO_AMBIGUOUS_CAVEAT = ("The sudo record repeats a field separator inside its working directory or command text; the "
                         "run-as account and the command are read at the first separator and may be misattributed")
# The caveat on a syslog line whose program comes only from its own header.
SYSLOG_WRITER_CAVEAT = "Writer identity from the syslog header only."


@dataclass(frozen=True)
class ParsedLine:
    family: str
    fields: dict[str, object] = field(default_factory=dict)
    outcome: Outcome = Outcome.unknown
    caveats: tuple[str, ...] = ()
