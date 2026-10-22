"""Flag instruction-shaped untrusted data without interpreting or executing it."""
from __future__ import annotations

import re
from typing import Any

_PATTERNS = {
    "instruction_override": re.compile(r"\bignore\b.{0,60}\binstructions?\b", re.IGNORECASE | re.DOTALL),
    "agent_action": re.compile(r"\badd_note\b.{0,80}\bbenign\b", re.IGNORECASE | re.DOTALL),
    "pivot_directive": re.compile(
        r"\bpivot\b.{0,40}\b(?:\d{1,3}\.){3}\d{1,3}\b", re.IGNORECASE | re.DOTALL,
    ),
    "fake_tool_call": re.compile(r"\btool_calls?\b", re.IGNORECASE),
    "html_control": re.compile(r"</?(?:script|html|system|assistant|tool|data)\b", re.IGNORECASE),
    "markdown_control": re.compile(r"(?m)^\s{0,3}(?:#{1,6}\s|[-*]\s|\[[^\]]+\]\()"),
}


def injection_flags(value: Any, path: str = "$") -> list[dict[str, Any]]:
    """Return A7 metadata only; never copy the suspicious text into control fields."""
    flags: list[dict[str, Any]] = []

    def walk(item: Any, location: str) -> None:
        if isinstance(item, str):
            matched = sorted(name for name, pattern in _PATTERNS.items() if pattern.search(item))
            if matched:
                flags.append({
                    "code": "A7", "path": location, "detections": matched,
                    "reason": "untrusted data contains instruction-shaped content",
                })
            return
        if isinstance(item, dict):
            for key in sorted(item, key=str):
                walk(item[key], f"{location}.{key}")
            return
        if isinstance(item, (list, tuple)):
            for index, child in enumerate(item):
                walk(child, f"{location}[{index}]")

    walk(value, path)
    return flags
