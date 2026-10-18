"""Semantic validation for one untrusted investigator proposal."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol

from pydantic import ValidationError

from romulus.agent.brief import BuiltBrief
from romulus.agent.models import AgentDecision, EntityRef
from romulus.agent.tools import ProcessTreeRequest, parse_tool_request


class HuntWindow(Protocol):
    start: datetime
    end: datetime


@dataclass
class ValidationResult:
    ok: bool
    errors: list[str]
    request: Any | None = None


def _known_entity(entity: EntityRef, brief: BuiltBrief) -> bool:
    return any(known.kind == entity.kind and known.value == entity.value for known in brief.known_entities)


def _observer_only_host(value: str, brief: BuiltBrief) -> bool:
    matching = [entity for entity in brief.known_entities if entity.kind == "host" and entity.value == value]
    return bool(matching) and all(entity.role == "observer" for entity in matching)


def validate_decision(decision: AgentDecision, brief_context: BuiltBrief,
                      hunt_window: HuntWindow) -> ValidationResult:
    errors: list[str] = []
    request = None

    if not decision.evidence_ids:
        errors.append("decision must cite at least one evidence ID")
    unknown_evidence = sorted(set(decision.evidence_ids) - brief_context.known_evidence_ids)
    if unknown_evidence:
        errors.append(f"unknown evidence IDs: {unknown_evidence}")

    if decision.action == "pivot":
        try:
            request = parse_tool_request(decision)
        except (ValidationError, ValueError) as exc:
            errors.append(f"invalid tool arguments: {exc}")
        if not decision.hypothesis or not decision.expected_true or not decision.expected_false:
            errors.append("pivot requires hypothesis plus expected true and false outcomes")
        if request is not None:
            args = request.arguments
            if args.start < hunt_window.start or args.end > hunt_window.end:
                errors.append("pivot window must remain within the hunt window")
            entity = getattr(args, "entity", None)
            host = getattr(args, "host", None)
            if entity is not None:
                if not _known_entity(entity, brief_context):
                    errors.append(f"unknown entity: {entity.kind}:{entity.value}")
                if entity.kind == "host" and _observer_only_host(entity.value, brief_context):
                    errors.append(f"observer host {entity.value!r} cannot be used as an investigated host")
            if host is not None:
                if not any(item.kind == "host" and item.value == host for item in brief_context.known_entities):
                    errors.append(f"unknown entity: host:{host}")
                elif _observer_only_host(host, brief_context):
                    errors.append(f"observer host {host!r} cannot be used as an investigated host")
            if (isinstance(request, ProcessTreeRequest)
                    and (request.arguments.host, request.arguments.process_id) not in brief_context.known_process_ids):
                errors.append(
                    f"unknown process ID {request.arguments.process_id} on host {request.arguments.host!r}"
                )

    elif decision.action == "escalate":
        candidate = brief_context.known_candidates.get(decision.candidate_id or "")
        if candidate is None:
            errors.append("escalation must reference a known deterministic candidate")
        else:
            if decision.claim != candidate["claim"]:
                errors.append("model cannot change the deterministic candidate claim")
            if decision.proposed_lane != candidate["lane"]:
                errors.append("model cannot change the deterministic candidate lane")
            if not set(decision.evidence_ids).intersection(candidate.get("event_ids") or []):
                errors.append("escalation must cite evidence supporting the deterministic candidate")

    elif decision.action in {"close", "park_as_lead"}:
        hostile_citations = set(decision.evidence_ids).intersection(brief_context.injection_evidence_ids)
        if hostile_citations:
            errors.append("untrusted instruction-like telemetry cannot authorize close or park")
        if decision.action == "park_as_lead" and not decision.resolution_needed:
            errors.append("park_as_lead requires resolution_needed")
        if not decision.reasoning:
            errors.append(f"{decision.action} requires cited reasoning")

    elif decision.action == "spawn":
        if decision.entity is None or not _known_entity(decision.entity, brief_context):
            errors.append("spawn requires a known discovered entity")
        elif decision.entity.kind == "host" and _observer_only_host(decision.entity.value, brief_context):
            errors.append("observer hosts cannot seed an investigation case")

    return ValidationResult(ok=not errors, errors=errors, request=request)
