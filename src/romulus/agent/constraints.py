"""Per-call JSON schemas for investigator menu selections."""
from __future__ import annotations

from romulus.agent.options import Menu, MenuOption

SCHEMA_FORM = "flat"


def eligible_evidence_aliases(
    option: MenuOption,
    aliases: dict[str, dict],
    candidates: dict[str, dict],
    injection_evidence_ids: set[str],
) -> list[str]:
    evidence = aliases.get("evidence") or {}
    if option.decision.action == "escalate":
        candidate = candidates.get(option.decision.candidate_id or "") or {}
        allowed_ids = {str(event_id) for event_id in candidate.get("event_ids") or []}
        return [alias for alias, event_id in evidence.items() if event_id in allowed_ids]
    if option.decision.action in {"close", "park_as_lead"}:
        return [alias for alias, event_id in evidence.items() if event_id not in injection_evidence_ids]
    return list(evidence)


def build_output_schema(
    menu: Menu,
    aliases: dict[str, dict],
    candidates: dict[str, dict],
    injection_evidence_ids: set[str],
) -> dict:
    """Build Ollama's flat constrained schema; the resolver enforces option-specific subsets."""
    del candidates, injection_evidence_ids
    return {
        "type": "object",
        "properties": {
            "option": {"type": "string", "enum": [option.id for option in menu.options]},
            "evidence": {
                "type": "array",
                "items": {"type": "string", "enum": list((aliases.get("evidence") or {}).keys())},
                "minItems": 1,
                "maxItems": 4,
                "uniqueItems": True,
            },
            "rationale": {"type": "string", "maxLength": 300},
            "benign_alternative": {"type": "string", "maxLength": 200},
        },
        "required": ["option", "evidence", "rationale"],
        "additionalProperties": False,
    }
