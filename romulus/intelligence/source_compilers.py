"""Compile typed rule stages only into the language of their declared source."""
from __future__ import annotations

from typing import Any

from .rule_model import Predicate, SourceStage
from ..investigation.search_planner import validate_native_arkime, validate_native_tshark


class SourceCompileError(ValueError):
    """Raised when mapped source fields cannot express a typed stage."""


ARKIME_ROLE_FIELDS = {
    "source.ip": ("ip.src",),
    "destination.ip": ("ip.dst",),
    "destination.port": ("port.dst",),
    "dns.question": ("dns.host",),
    "url.full": ("http.uri",),
    "tls.server_name": ("tls.host",),
    "network.protocol": ("protocol",),
    "network.bytes": ("bytes",),
}
TSHARK_ROLE_FIELDS = {
    "source.ip": ("ip.src", "ipv6.src"),
    "destination.ip": ("ip.dst", "ipv6.dst"),
    "destination.port": ("tcp.dstport", "udp.dstport"),
    "dns.question": ("dns.qry.name",),
    "url.full": ("http.request.uri",),
    "tls.server_name": ("tls.handshake.extensions_server_name",),
    "network.bytes": ("frame.len",),
}


def compile_source_stage(stage: SourceStage, **context: Any) -> Any:
    if stage.source == "elasticsearch":
        from .behavior_catalog import compile_elasticsearch_seed
        return compile_elasticsearch_seed(
            {"match": stage.match_mapping()},
            context.get("bindings") or {},
            context.get("timestamp_field") or "@timestamp",
            context.get("time_range"),
            context.get("field_metadata"),
        )
    available = list(context.get("available_fields") or [])
    if stage.source == "arkime":
        expression = _compile_text_stage(stage, available, ARKIME_ROLE_FIELDS, "arkime")
        return validate_native_arkime(expression, available)
    if stage.source == "tshark":
        expression = _compile_text_stage(stage, available, TSHARK_ROLE_FIELDS, "tshark")
        return validate_native_tshark(expression, available)
    raise SourceCompileError(f"unsupported source {stage.source}")


def _compile_text_stage(
    stage: SourceStage,
    available_fields: list[str],
    role_fields: dict[str, tuple[str, ...]],
    language: str,
) -> str:
    available = set(available_fields)

    def compile_predicate(predicate: Predicate) -> str:
        fields = [field for field in role_fields.get(predicate.role, ()) if field in available]
        if not fields:
            raise SourceCompileError(f"{stage.stage_id}: no available field for role {predicate.role}")
        clauses = [_field_predicate(field, predicate, language) for field in fields]
        return clauses[0] if len(clauses) == 1 else "(" + " || ".join(clauses) + ")"

    all_parts = [compile_predicate(item) for item in stage.all]
    if stage.any:
        all_parts.append("(" + " || ".join(compile_predicate(item) for item in stage.any) + ")")
    all_parts.extend("!(" + compile_predicate(item) + ")" for item in stage.none)
    return all_parts[0] if len(all_parts) == 1 else " && ".join(f"({part})" for part in all_parts)


def _field_predicate(field: str, predicate: Predicate, language: str) -> str:
    if predicate.operator == "exists":
        return f"{field} != null" if language == "arkime" else field
    clauses = []
    for value in predicate.values[:12]:
        literal = _quote(value)
        if language == "arkime":
            if predicate.operator == "equals_any":
                clauses.append(f"{field} == {literal}")
            elif predicate.operator == "contains_any":
                clauses.append(f"{field} == {_quote('*' + value + '*')}")
            elif predicate.operator == "ends_with_any":
                clauses.append(f"{field} == {_quote('*' + value)}")
            elif predicate.operator == "path_prefix_any":
                clauses.append(f"{field} == {_quote(value + '*')}")
            else:
                raise SourceCompileError(f"unsupported Arkime operator {predicate.operator}")
        else:
            if predicate.operator == "equals_any":
                clauses.append(f"{field} == {literal}")
            elif predicate.operator in {"contains_any", "ends_with_any", "path_prefix_any"}:
                clauses.append(f"{field} contains {literal}")
            else:
                raise SourceCompileError(f"unsupported TShark operator {predicate.operator}")
    return clauses[0] if len(clauses) == 1 else "(" + " || ".join(clauses) + ")"


def _quote(value: Any) -> str:
    escaped = str(value).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'
