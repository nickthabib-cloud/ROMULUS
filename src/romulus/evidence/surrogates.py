"""Text that is not valid Unicode: a lone UTF-16 surrogate (a JSON "\\ud800" escape with no partner) in telemetry.

Python keeps such a code point in a str, but it cannot be encoded as UTF-8, so serializing or storing the text fails.
Telemetry is attacker-influenced (user agents, URIs, names), so each lone surrogate is replaced with U+FFFD (the
replacement character) at the normalization boundary, and the record's events say which fields held one.
"""
from __future__ import annotations

import re

REPLACEMENT = "�"
_SURROGATE = re.compile("[\ud800-\udfff]")
# the fields a caveat names, at most
NAMED_FIELDS = 5
MALFORMED_TEXT_CAVEAT = ("text in {fields} of this record was not valid Unicode (a lone UTF-16 surrogate); each such "
                         "character was replaced with U+FFFD")


def has_surrogate(text: str) -> bool:
    return not text.isascii() and _SURROGATE.search(text) is not None


def _clean(text: str) -> str:
    return _SURROGATE.sub(REPLACEMENT, text)


def dirty(value) -> bool:
    """Whether any key or text in a JSON value holds a lone surrogate (ASCII text is passed over without a search)."""
    if type(value) is str:
        return not value.isascii() and _SURROGATE.search(value) is not None
    if type(value) is dict:
        for key, item in value.items():
            if (type(key) is str and not key.isascii() and _SURROGATE.search(key)) or (
                    type(item) in _CONTAINERS and dirty(item)):
                return True
        return False
    if type(value) is list:
        for item in value:
            if type(item) in _CONTAINERS and dirty(item):
                return True
        return False
    if isinstance(value, (str, dict, list)):         # a subclass: the general walk
        return bool(sanitize(value, "", [])[1])
    return False


_CONTAINERS = frozenset({str, dict, list})


def sanitize(value, path: str = "", found: list[str] | None = None):
    """(value, paths): the value with every lone surrogate in its keys and text replaced (a copy where anything changed,
    else the same object) and the dotted paths that held one. A clean value is passed over by `dirty` first."""
    if found is None:
        found = []
        if not dirty(value):
            return value, found
    if isinstance(value, str):
        if has_surrogate(value):
            found.append(path or "<value>")
            return _clean(value), found
        return value, found
    if isinstance(value, dict):
        out = None
        for key, item in value.items():
            name = _clean(key) if isinstance(key, str) and has_surrogate(key) else key
            child = f"{path}.{name}" if path else str(name)
            if name is not key:
                found.append(child)
            new, _found = sanitize(item, child, found)
            if out is None and (new is not item or name is not key):
                out = {}
                for done_key, done_item in value.items():
                    if done_key is key:
                        break
                    out[done_key] = done_item
            if out is not None:
                out[name] = new
        return (value if out is None else out), found
    if isinstance(value, list):
        out = None
        for index, item in enumerate(value):
            new, _found = sanitize(item, path, found)
            if new is not item and out is None:
                out = list(value[:index])
            if out is not None:
                out.append(new)
        return (value if out is None else out), found
    return value, found


def event_paths(event) -> list[str]:
    """The typed fields (and `host`, `caveats`) of a typed event whose text holds a lone surrogate (a value parsed out
    of text the record carried, such as a Suricata EVE line, can hold one its record's own text did not show)."""
    found: list[str] = []
    if isinstance(event.host, str) and has_surrogate(event.host):
        found.append("host")
    for name, value in event.fields.items():
        typed = value.value
        kind = type(typed)
        if kind is str:
            if not typed.isascii() and _SURROGATE.search(typed):
                found.append(name)
        elif kind in _CONTAINERS and dirty(typed):
            sanitize(typed, name, found)
        origin = value.origin
        if type(origin) is str and not origin.isascii() and _SURROGATE.search(origin):
            found.append(f"{name} (origin)")
    for text in event.caveats:
        if has_surrogate(text):
            found.append("caveats")
            break
    return found


def clean_event(event, paths: list[str]):
    """A copy of the event with every lone surrogate replaced, and a caveat naming `paths`."""
    from romulus.evidence.typed import TypedEvent

    body, _found = sanitize(event.model_dump())
    cleaned = TypedEvent.model_validate(body)
    note = caveat(paths)
    if note not in cleaned.caveats:
        cleaned.caveats.append(note)
    return cleaned


def caveat(paths: list[str]) -> str:
    """The caveat naming the fields that held a lone surrogate."""
    names = list(dict.fromkeys(paths))
    shown = ", ".join(names[:NAMED_FIELDS]) + (f" and {len(names) - NAMED_FIELDS} more" if len(names) > NAMED_FIELDS
                                               else "")
    return MALFORMED_TEXT_CAVEAT.format(fields=shown)
