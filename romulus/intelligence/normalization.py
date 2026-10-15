"""Deterministic source-record normalization used before evidence persistence."""

from __future__ import annotations

import copy
import re
from pathlib import PurePath
from typing import Any


_AUDIT_ARGUMENT = re.compile(
    r"\ba(?P<index>\d+)=(?:\"(?P<double>[^\"]*)\"|'(?P<single>[^']*)'|(?P<bare>\S+))"
)


def normalize_elasticsearch_event(hit: dict[str, Any]) -> dict[str, Any]:
    """Return a copy with safe derived fields for known source encodings."""

    normalized = copy.deepcopy(hit)
    message = _text_value(normalized, "message") or _text_value(normalized, "event.original")
    record_type = (_text_value(normalized, "audit.record_type") or "").lower()
    if not message or ("TYPE=EXECVE" not in message.upper() and record_type != "execve"):
        return normalized

    arguments: list[tuple[int, str]] = []
    for match in _AUDIT_ARGUMENT.finditer(message):
        raw = next(
            (value for value in (match.group("double"), match.group("single"), match.group("bare"))
             if value is not None),
            "",
        )
        value = _decode_audit_argument(raw) if match.group("bare") is not None else raw
        arguments.append((int(match.group("index")), value))
    if not arguments:
        return normalized

    args = [value for _, value in sorted(arguments) if value]
    if not args:
        return normalized
    executable = args[0]
    normalized.setdefault("process.args", args)
    normalized.setdefault("process.command_line", " ".join(args))
    normalized.setdefault("process.executable", executable)
    normalized.setdefault("process.name", PurePath(executable.replace("\\", "/")).name)
    return normalized


def _decode_audit_argument(value: str) -> str:
    if len(value) < 2 or len(value) % 2 or re.fullmatch(r"[0-9A-Fa-f]+", value) is None:
        return value
    try:
        decoded = bytes.fromhex(value).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return value
    if not decoded or any(not character.isprintable() and character not in "\t\r\n" for character in decoded):
        return value
    return decoded


def _text_value(value: dict[str, Any], path: str) -> str:
    if path in value and isinstance(value[path], str):
        return value[path]
    current: Any = value
    for part in path.split("."):
        if not isinstance(current, dict):
            return ""
        current = current.get(part)
    return current if isinstance(current, str) else ""
