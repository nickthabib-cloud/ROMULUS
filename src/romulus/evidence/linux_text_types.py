"""Source-neutral parser results; normalization adds record identity and field provenance."""
from __future__ import annotations

from dataclasses import dataclass, field

from romulus.evidence.typed import Outcome


@dataclass(frozen=True)
class ParsedLine:
    family: str
    fields: dict[str, object] = field(default_factory=dict)
    outcome: Outcome = Outcome.unknown
    caveats: tuple[str, ...] = ()
