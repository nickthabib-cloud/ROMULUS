"""A raw record as ROMULUS keeps it: every lone UTF-16 surrogate replaced (evidence.surrogates) and every credential
of a Zeek record masked (evidence.zeek.scrub_zeek_source). Every path that stores a record's `_source` (the hunt store,
the event stage) stores this form, and a record's digest is computed over it, so a copy fetched again from the source
verifies against the stored one. Any other record is returned as it is (the same object)."""
from __future__ import annotations

from romulus.evidence import surrogates
from romulus.evidence.typed import TypedEvent
from romulus.evidence.zeek import scrub_zeek_source
from romulus.store import cleaning as store_cleaning


def might_be_zeek(source: dict) -> bool:
    """Whether a record carries any field by which evidence.zeek recognizes a Zeek record (a superset of what
    `zeek_record` accepts, and of plain Zeek JSON's keys); every other record is stored as it is."""
    event = source.get("event")
    if type(event) is dict:
        if event.get("provider") == "zeek" or event.get("module") == "zeek":
            return True
        dataset = event.get("dataset")
        if isinstance(dataset, str) and dataset.startswith("zeek."):
            return True
    stream = source.get("data_stream")
    if type(stream) is dict:
        dataset = stream.get("dataset")
        if isinstance(dataset, str) and dataset.startswith("zeek."):
            return True
    return "_path" in source or "id.orig_h" in source


def clean_source(source):
    """The `_source` as it may be stored (the same object when nothing changes)."""
    if not isinstance(source, dict):
        return source
    sanitized, _paths = surrogates.sanitize(source)
    return scrub_zeek_source(sanitized) if might_be_zeek(sanitized) else sanitized


def clean_sources(raw_sources: dict[str, dict]) -> dict[str, dict]:
    """A key -> `_source` map with each source as it may be stored (the same map when nothing changes)."""
    out = None
    for key, source in raw_sources.items():
        cleaned = clean_source(source)
        if cleaned is not source:
            if out is None:
                out = dict(raw_sources)
            out[key] = cleaned
    return raw_sources if out is None else out


def clean_event(event: TypedEvent) -> TypedEvent:
    """The event with every lone surrogate in its text replaced and a caveat naming where (the same object when it
    holds none). normalize_hits already cleans what it makes; this is for an event built elsewhere."""
    found = surrogates.event_paths(event)
    if not found and not any(surrogates.has_surrogate(ref.native_id) or surrogates.has_surrogate(ref.target)
                             for ref in event.raw):
        return event
    return surrogates.clean_event(event, found or ["raw"])


# The store applies these to everything it writes, without importing this package.
store_cleaning.register(clean_source, clean_event)
