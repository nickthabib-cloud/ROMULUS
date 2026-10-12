"""Offline behavioral analytic and trusted-indicator catalogs.

The catalog is intentionally data driven. Entries refer to semantic roles so
the same analytic can bind to ECS, Sysmon, auditd, Zeek, and unfamiliar data
sets when their fields can be resolved safely.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any


BEHAVIOR_CATALOG_PATH = Path(__file__).with_name("behavior_catalog.json")
LOCAL_INDICATORS_PATH = Path(__file__).with_name("local_indicators.json")

ALLOWED_OPERATORS = {
    "contains_any", "equals_any", "ends_with_any", "path_prefix_any",
    "regex", "exists", "lookalike_process",
}
ALLOWED_SOURCES = {"elasticsearch", "aggregate"}
PRIORITIES = {"informational", "low", "medium", "high", "critical"}
NOISE_LEVELS = {"low", "medium", "high"}

SEMANTIC_ROLE_ALIASES: dict[str, tuple[str, ...]] = {
    "event.time": ("@timestamp", "timestamp", "event.created", "event.start", "winlog.time_created"),
    "event.action": ("event.action", "event.type", "event.code", "event.id", "winlog.event_id", "action"),
    "host.name": ("host.name", "host.hostname", "hostname", "computer_name", "agent.hostname"),
    "user.name": ("user.name", "account.name", "winlog.event_data.SubjectUserName", "user", "username"),
    "process.name": ("process.name", "process.executable", "winlog.event_data.Image", "exe", "comm"),
    "process.executable": ("process.executable", "winlog.event_data.Image", "process.path", "exe", "image"),
    "process.command_line": (
        "process.command_line", "process.args", "winlog.event_data.CommandLine",
        "audit.command", "cmdline", "command_line", "message", "event.original",
    ),
    "process.parent.name": (
        "process.parent.name", "process.parent.executable",
        "winlog.event_data.ParentImage", "parent_process_name", "ppid_name",
    ),
    "file.path": ("file.path", "file.name", "target.file.path", "winlog.event_data.TargetFilename", "path"),
    "registry.path": ("registry.path", "registry.key", "winlog.event_data.TargetObject"),
    "service.name": ("service.name", "winlog.event_data.ServiceName", "systemd.unit"),
    "source.ip": ("source.ip", "src_ip", "srcIp", "ip.src", "client.ip"),
    "destination.ip": ("destination.ip", "dst_ip", "dstIp", "ip.dst", "server.ip"),
    "destination.port": ("destination.port", "dst_port", "dstPort", "tcp.dstport", "udp.dstport", "port"),
    "network.protocol": ("network.protocol", "network.transport", "network.application", "protocol", "protocols"),
    "network.bytes": ("network.bytes", "source.bytes", "destination.bytes", "bytes", "totBytes"),
    "dns.question": ("dns.question.name", "dns.qry.name", "dns.host", "query", "domain"),
    "dns.rcode": ("dns.response_code", "dns.header.response_code", "dns.flags.rcode", "rcode"),
    "url.full": ("url.full", "url.original", "http.request.uri", "http.uri", "uri"),
    "tls.server_name": ("tls.server.name", "tls.handshake.extensions_server_name", "server_name", "sni"),
    "aggregate.signal": ("aggregate.signal",),
}


class CatalogValidationError(ValueError):
    """Catalog content is unsafe or structurally invalid."""


def load_behavior_catalog(path: Path = BEHAVIOR_CATALOG_PATH) -> dict[str, Any]:
    value = _read_json(Path(path), "behavior catalog")
    if not isinstance(value, dict):
        raise CatalogValidationError("$: behavior catalog must be an object")
    if not _nonempty_string(value.get("catalog_version")):
        raise CatalogValidationError("catalog_version: expected non-empty string")
    analytics = value.get("analytics")
    if not isinstance(analytics, list):
        raise CatalogValidationError("analytics: expected array")
    seen: set[str] = set()
    for index, analytic in enumerate(analytics):
        _validate_analytic(analytic, index, seen)
    return value


def load_local_indicators(path: Path = LOCAL_INDICATORS_PATH) -> dict[str, Any]:
    value = _read_json(Path(path), "local indicator catalog")
    if not isinstance(value, dict):
        raise CatalogValidationError("$: local indicator catalog must be an object")
    if not _nonempty_string(value.get("catalog_version")):
        raise CatalogValidationError("catalog_version: expected non-empty string")
    indicators = value.get("indicators")
    if not isinstance(indicators, list):
        raise CatalogValidationError("indicators: expected array")
    seen: set[str] = set()
    allowed_types = {"sha256", "sha1", "md5", "domain", "ip", "path", "process", "certificate"}
    for index, item in enumerate(indicators):
        prefix = f"indicators[{index}]"
        if not isinstance(item, dict):
            raise CatalogValidationError(f"{prefix}: expected object")
        identifier = item.get("id")
        if not _nonempty_string(identifier):
            raise CatalogValidationError(f"{prefix}.id: expected non-empty string")
        if identifier in seen:
            raise CatalogValidationError(f"{prefix}.id: duplicate id {identifier}")
        seen.add(identifier)
        if item.get("type") not in allowed_types:
            raise CatalogValidationError(f"{prefix}.type: unsupported indicator type")
        for field in ("value", "source", "created_at"):
            if not _nonempty_string(item.get(field)):
                raise CatalogValidationError(f"{prefix}.{field}: expected non-empty string")
        confidence = item.get("confidence")
        if not isinstance(confidence, int) or isinstance(confidence, bool) or not 0 <= confidence <= 100:
            raise CatalogValidationError(f"{prefix}.confidence: expected integer 0 through 100")
        for field in ("created_at", "expires_at"):
            if item.get(field):
                _parse_time(item[field], f"{prefix}.{field}")
    return value


def resolve_semantic_fields(fields: list[str] | set[str] | tuple[str, ...]) -> dict[str, list[str]]:
    available = {str(field) for field in fields}
    lower = {field.lower(): field for field in available}
    bindings: dict[str, list[str]] = {}
    for role, aliases in SEMANTIC_ROLE_ALIASES.items():
        matches = []
        for alias in aliases:
            if alias in available:
                matches.append(alias)
            elif alias.lower() in lower:
                matches.append(lower[alias.lower()])
        if matches:
            bindings[role] = list(dict.fromkeys(matches))
    return bindings


def applicable_analytics(
    catalog: dict[str, Any], bindings: dict[str, list[str]], source: str
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    applicable: list[dict[str, Any]] = []
    unsupported: list[dict[str, Any]] = []
    for analytic in catalog.get("analytics", []):
        if not analytic.get("enabled", True) or analytic.get("source") != source:
            continue
        missing = [role for role in analytic.get("required_roles", []) if not bindings.get(role)]
        if missing:
            unsupported.append({"id": analytic["id"], "missing_roles": missing})
        else:
            applicable.append(analytic)
    return applicable, unsupported


def _read_json(path: Path, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise CatalogValidationError(f"{path}: {label} file not found") from exc
    except json.JSONDecodeError as exc:
        raise CatalogValidationError(f"{path}:{exc.lineno}:{exc.colno}: invalid JSON") from exc
    except OSError as exc:
        raise CatalogValidationError(f"{path}: unable to read {label}") from exc


def _validate_analytic(item: Any, index: int, seen: set[str]) -> None:
    prefix = f"analytics[{index}]"
    if not isinstance(item, dict):
        raise CatalogValidationError(f"{prefix}: expected object")
    identifier = item.get("id")
    if not _nonempty_string(identifier):
        raise CatalogValidationError(f"{prefix}.id: expected non-empty string")
    if identifier in seen:
        raise CatalogValidationError(f"{prefix}.id: duplicate id {identifier}")
    seen.add(identifier)
    for field in ("title", "description", "review_date"):
        if not _nonempty_string(item.get(field)):
            raise CatalogValidationError(f"{prefix}.{field}: expected non-empty string")
    if not isinstance(item.get("version"), int) or item["version"] < 1:
        raise CatalogValidationError(f"{prefix}.version: expected positive integer")
    if not isinstance(item.get("enabled"), bool):
        raise CatalogValidationError(f"{prefix}.enabled: expected boolean")
    if item.get("source") not in ALLOWED_SOURCES:
        raise CatalogValidationError(f"{prefix}.source: unsupported source")
    for field in (
        "platforms", "categories", "required_roles", "optional_roles",
        "attack_techniques", "benign_explanations", "required_corroboration", "follow_up",
    ):
        values = item.get(field)
        if not isinstance(values, list) or (field not in {"optional_roles", "required_corroboration"} and not values):
            raise CatalogValidationError(f"{prefix}.{field}: expected non-empty array")
        if not all(_nonempty_string(value) for value in values):
            raise CatalogValidationError(f"{prefix}.{field}: expected strings")
    known_roles = set(SEMANTIC_ROLE_ALIASES)
    for field in ("required_roles", "optional_roles"):
        for role in item[field]:
            if role not in known_roles:
                raise CatalogValidationError(f"{prefix}.{field}: unsupported semantic role {role}")
    if item.get("priority_tier", "low") not in PRIORITIES:
        raise CatalogValidationError(f"{prefix}.priority_tier: unsupported priority")
    for field in ("base_priority", "specificity"):
        value = item.get(field)
        if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 100:
            raise CatalogValidationError(f"{prefix}.{field}: expected integer 0 through 100")
    if item.get("expected_noise") not in NOISE_LEVELS:
        raise CatalogValidationError(f"{prefix}.expected_noise: unsupported noise level")
    provenance = item.get("provenance")
    if not isinstance(provenance, list) or not provenance:
        raise CatalogValidationError(f"{prefix}.provenance: expected non-empty array")
    for number, source in enumerate(provenance):
        if not isinstance(source, dict) or not _nonempty_string(source.get("name")) or not _nonempty_string(source.get("url")):
            raise CatalogValidationError(f"{prefix}.provenance[{number}]: expected name and url")
    match = item.get("match")
    if not isinstance(match, dict):
        raise CatalogValidationError(f"{prefix}.match: expected object")
    if not any(match.get(group) for group in ("all", "any")):
        raise CatalogValidationError(f"{prefix}.match: at least one all or any predicate is required")
    for group in ("all", "any", "none"):
        predicates = match.get(group, [])
        if not isinstance(predicates, list):
            raise CatalogValidationError(f"{prefix}.match.{group}: expected array")
        for number, predicate in enumerate(predicates):
            _validate_predicate(predicate, f"{prefix}.match.{group}[{number}]")


def _validate_predicate(predicate: Any, path: str) -> None:
    if not isinstance(predicate, dict):
        raise CatalogValidationError(f"{path}: expected object")
    role = predicate.get("role")
    if role not in SEMANTIC_ROLE_ALIASES:
        raise CatalogValidationError(f"{path}.role: unsupported semantic role")
    operator = predicate.get("operator")
    if operator not in ALLOWED_OPERATORS:
        raise CatalogValidationError(f"{path}.operator: unsupported operator {operator}")
    values = predicate.get("values", [])
    if operator == "exists":
        if values not in ([], None):
            raise CatalogValidationError(f"{path}.values: exists does not accept values")
    elif not isinstance(values, list) or not values or not all(_nonempty_string(value) for value in values):
        raise CatalogValidationError(f"{path}.values: expected non-empty string array")


def _parse_time(value: str, path: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)
    except (TypeError, ValueError) as exc:
        raise CatalogValidationError(f"{path}: expected ISO-8601 timestamp") from exc


def _nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())
