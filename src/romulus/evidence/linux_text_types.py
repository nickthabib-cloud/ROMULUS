"""Source-neutral parser results; normalization adds record identity and field provenance."""
from __future__ import annotations

from dataclasses import dataclass, field

from romulus.evidence.typed import Outcome

# The caveat on an event whose logging process (journald's comm or executable) is not the program it names.
WRITER_MISMATCH_CAVEAT = "Writer identity disagrees with the logging process"


@dataclass(frozen=True)
class ParsedLine:
    family: str
    fields: dict[str, object] = field(default_factory=dict)
    outcome: Outcome = Outcome.unknown
    caveats: tuple[str, ...] = ()
