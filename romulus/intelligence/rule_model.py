"""Closed source-aware rule types shared by search and correlation engines."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


SOURCE_QUERY_LANGUAGES = {
    "elasticsearch": "elasticsearch_dsl",
    "arkime": "arkime",
    "tshark": "tshark",
}
PREDICATE_OPERATORS = {
    "contains_any", "equals_any", "ends_with_any", "path_prefix_any", "exists",
}


class RuleModelError(ValueError):
    """Raised when a source stage cannot be represented safely."""


@dataclass(frozen=True)
class Predicate:
    role: str
    operator: str
    values: tuple[str, ...] = ()

    @classmethod
    def from_mapping(cls, value: dict[str, Any], path: str) -> "Predicate":
        if not isinstance(value, dict):
            raise RuleModelError(f"{path}: expected predicate object")
        role = value.get("role")
        operator = value.get("operator")
        values = value.get("values", [])
        if not isinstance(role, str) or not role.strip():
            raise RuleModelError(f"{path}.role: expected non-empty string")
        if operator not in PREDICATE_OPERATORS:
            raise RuleModelError(f"{path}.operator: unsupported operator {operator}")
        if operator == "exists":
            if values not in ([], None):
                raise RuleModelError(f"{path}.values: exists accepts no values")
            normalized: tuple[str, ...] = ()
        else:
            if not isinstance(values, list) or not values or not all(isinstance(item, str) and item for item in values):
                raise RuleModelError(f"{path}.values: expected non-empty string array")
            normalized = tuple(values)
        return cls(role=role, operator=str(operator), values=normalized)

    def as_mapping(self) -> dict[str, Any]:
        return {"role": self.role, "operator": self.operator, "values": list(self.values)}


@dataclass(frozen=True)
class SourceStage:
    stage_id: str
    source: str
    query_language: str
    all: tuple[Predicate, ...] = ()
    any: tuple[Predicate, ...] = ()
    none: tuple[Predicate, ...] = ()

    @classmethod
    def from_mapping(cls, value: dict[str, Any]) -> "SourceStage":
        if not isinstance(value, dict):
            raise RuleModelError("source stage must be an object")
        stage_id = value.get("stage_id")
        source = value.get("source")
        language = value.get("query_language") or value.get("source_language")
        if not isinstance(stage_id, str) or not stage_id.strip():
            raise RuleModelError("stage_id: expected non-empty string")
        if source not in SOURCE_QUERY_LANGUAGES:
            raise RuleModelError(f"source: unsupported source {source}")
        if language != SOURCE_QUERY_LANGUAGES[source]:
            raise RuleModelError(f"query language {language!r} is invalid for source {source}")
        match = value.get("match")
        if not isinstance(match, dict):
            raise RuleModelError("match: expected object")
        groups = {}
        for group in ("all", "any", "none"):
            rows = match.get(group, [])
            if not isinstance(rows, list):
                raise RuleModelError(f"match.{group}: expected array")
            groups[group] = tuple(Predicate.from_mapping(row, f"match.{group}[{index}]")
                                  for index, row in enumerate(rows))
        if not groups["all"] and not groups["any"]:
            raise RuleModelError("match: at least one positive predicate is required")
        return cls(stage_id=stage_id, source=source, query_language=language, **groups)

    def match_mapping(self) -> dict[str, list[dict[str, Any]]]:
        return {
            "all": [item.as_mapping() for item in self.all],
            "any": [item.as_mapping() for item in self.any],
            "none": [item.as_mapping() for item in self.none],
        }
