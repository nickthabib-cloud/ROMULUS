"""What every stored telemetry body and typed event passes through before it is written.

The evidence package registers its cleaners when it is imported (credentials of a recognized record masked, lone
UTF-16 surrogates replaced): the store applies them without importing evidence. A typed event exists only once the
evidence package is imported, so a store that is handed events always has them; a write with none registered is
refused rather than stored uncleaned.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

_source_cleaner: Callable[[Any], Any] | None = None
_event_cleaner: Callable[[Any], Any] | None = None


def register(source: Callable[[Any], Any], event: Callable[[Any], Any]) -> None:
    global _source_cleaner, _event_cleaner
    _source_cleaner, _event_cleaner = source, event


def clean_source(source):
    if _source_cleaner is None:
        raise RuntimeError("no raw-source cleaner is registered: import romulus.evidence before storing telemetry")
    return _source_cleaner(source)


def clean_event(event):
    if _event_cleaner is None:
        raise RuntimeError("no event cleaner is registered: import romulus.evidence before storing events")
    return _event_cleaner(event)
