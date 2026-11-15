"""Why a model's tool call or answer was refused: field paths and error types, never the values.

A reason reads `<path>: <type>`, for example `summary: string_too_short` or `cites[]: alias_not_issued`. The path
names only fields the schema declares: a list position is `[]`, a key the model invented is `*`, any other segment
is `?`, and the whole input is `$`. The type is a fixed lower-case word. Input values can hold telemetry or model
text, so a reason never carries one, and every reason is checked against that shape before it is stored or shown.
"""
from __future__ import annotations

import re
from collections.abc import Iterable

MAX_REASONS = 20
_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}")
_KIND = re.compile(r"[a-z][a-z0-9_]{0,63}")
_PATH = re.compile(r"(\$|(\*|\?|[A-Za-z_][A-Za-z0-9_]{0,63})(\[\])*(\.(\*|\?|[A-Za-z_][A-Za-z0-9_]{0,63})(\[\])*)*)")
EXTRA = "*"        # marks a key the model supplied that the schema does not declare
MORE = "$: more_reasons_omitted"


def field_path(loc: Iterable) -> str:
    """A validation location as a path of declared field names (`a.b[]`); `$` for the whole input."""
    out = ""
    for part in loc:
        if isinstance(part, int) and not isinstance(part, bool):
            out = (out or "?") + "[]"
            continue
        name = part if isinstance(part, str) and (part == EXTRA or _NAME.fullmatch(part)) else "?"
        out = f"{out}.{name}" if out else name
    return out or "$"


def reason(path: str, kind: str) -> str:
    """One reason; a path or type outside the allowed shapes is replaced, so no value can pass through."""
    return f"{path if _PATH.fullmatch(path) else '?'}: {kind if _KIND.fullmatch(kind) else 'invalid'}"


def is_reason(text: object) -> bool:
    if not isinstance(text, str) or ": " not in text:
        return False
    path, _, kind = text.partition(": ")
    return bool(_PATH.fullmatch(path) and _KIND.fullmatch(kind))


def bounded(reasons: Iterable[str]) -> list[str]:
    """Distinct, well-formed reasons in order, at most MAX_REASONS (the last says that more were omitted)."""
    unique = list(dict.fromkeys(item if is_reason(item) else "?: invalid" for item in reasons))
    if len(unique) > MAX_REASONS:
        unique = [*unique[:MAX_REASONS - 1], MORE]
    return unique


def validation_reasons(errors: Iterable[dict]) -> list[str]:
    """Reasons from pydantic's `ValidationError.errors()`: each error's location and type, never its input, message or
    context. An undeclared key the model supplied is shown as `*`."""
    out = []
    for error in errors:
        loc = tuple(error.get("loc") or ())
        kind = str(error.get("type") or "invalid")
        if kind == "extra_forbidden" and loc:
            loc = (*loc[:-1], EXTRA)
        out.append(reason(field_path(loc), kind))
    return bounded(out)


def tool_result_reasons(result: dict) -> list[str] | None:
    """Why a tool call was refused, from its result: the reasons the refusing code gave, else its error code. None
    for a call that was not refused."""
    if not isinstance(result, dict) or result.get("status") not in ("refused", "unsupported"):
        return None
    data = result.get("data")
    error = data.get("error") if isinstance(data, dict) else None
    if isinstance(error, dict):
        given = error.get("reasons")
        if isinstance(given, list) and given:
            return bounded(given)
        code = error.get("code")
        if isinstance(code, str):
            return [reason("$", code)]
    return [reason("$", "refused")]
