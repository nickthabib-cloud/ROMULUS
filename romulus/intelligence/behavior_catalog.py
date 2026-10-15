"""Offline behavioral analytic and trusted-indicator catalogs.

The catalog is intentionally data driven. Entries refer to semantic roles so
the same analytic can bind to ECS, Sysmon, auditd, Zeek, and unfamiliar data
sets when their fields can be resolved safely.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import re
from pathlib import Path
from typing import Any

from .attack_catalog import load_attack_catalog
from .behavior_packs import BEHAVIOR_PACK_DIR, load_behavior_packs


BEHAVIOR_CATALOG_PATH = Path(__file__).with_name("behavior_catalog.json")
WINDOWS_EVENT_CATALOG_PATH = Path(__file__).with_name("windows_event_catalog.json")
LOCAL_INDICATORS_PATH = Path(__file__).with_name("local_indicators.json")

ALLOWED_OPERATORS = {
    "contains_any", "equals_any", "ends_with_any", "path_prefix_any",
    "regex", "exists", "lookalike_process",
}
ALLOWED_SOURCES = {"elasticsearch", "aggregate"}
PRIORITIES = {"informational", "low", "medium", "high", "critical"}
NOISE_LEVELS = {"low", "medium", "high"}
MAX_CANDIDATE_EVIDENCE_IDS = 40
OBSERVE_SCORE_CEILING = 39
CORROBORATION_WINDOW_MINUTES = 30
_ATTACK_TECHNIQUE_IDS: set[str] | None = None

SEMANTIC_ROLE_ALIASES: dict[str, tuple[str, ...]] = {
    "event.time": ("@timestamp", "timestamp", "event.created", "event.start", "winlog.time_created"),
    "event.action": ("event.action", "event.type", "event.code", "event.id", "winlog.event_id", "event_id", "EventID", "action"),
    "event.code.exact": ("event.code", "winlog.event_id", "event_id", "EventID"),
    "event.provider": ("event.provider", "winlog.provider_name", "winlog.provider", "provider", "ProviderName"),
    "event.channel": ("event.channel", "winlog.channel", "channel", "Channel"),
    # Dataset names differ from module/provider names across integrations;
    # do not bind them interchangeably or exact event-source selectors can miss.
    "event.dataset": ("event.dataset",),
    "event.message": (
        "message", "winlog.event_data.Message", "winlog.message", "system.auth.message",
        "auditd.log.message", "auditd_manager.auditd.message", "event.original",
    ),
    "powershell.script_block": (
        "winlog.event_data.ScriptBlockText", "powershell.file.script_block_text",
        "ScriptBlockText", "scriptblock_text",
    ),
    "auditd.syscall": ("auditd.data.syscall", "auditd.log.syscall", "auditd.syscall", "syscall"),
    "host.name": ("host.name", "host.hostname", "hostname", "computer_name", "agent.hostname"),
    "host.os.platform": ("host.os.platform", "host.os.type", "host.platform", "os.type", "agent.os.name", "platform"),
    "user.name": (
        "user.name", "account.name", "winlog.event_data.SubjectUserName",
        "winlog.event_data.TargetUserName", "winlog.event_data.AccountName",
        "winlog.event_data.UserName", "eventdata.SubjectUserName", "eventdata.TargetUserName",
        "EventData.SubjectUserName", "EventData.TargetUserName", "user", "username",
    ),
    "user.target.name": (
        "user.target.name", "winlog.event_data.TargetUserName",
        "winlog.event_data.AccountName", "TargetUserName",
    ),
    "user.id": ("user.id", "winlog.event_data.SubjectUserSid", "winlog.event_data.TargetUserSid", "user.sid"),
    "session.id": (
        "session.id", "winlog.event_data.TargetLogonId", "winlog.event_data.SubjectLogonId",
        "winlog.event_data.LogonId", "winlog.event_data.LogonGuid", "logon.id",
    ),
    "logon.type": ("winlog.event_data.LogonType", "logon.type", "LogonType"),
    "process.name": (
        "process.name", "process.executable", "winlog.event_data.Image",
        "winlog.event_data.NewProcessName", "winlog.event_data.ProcessName", "exe", "comm",
        "winlog.event_data.SourceImage", "winlog.event_data.TargetImage",
    ),
    "process.executable": (
        "process.executable", "winlog.event_data.Image", "winlog.event_data.NewProcessName",
        "winlog.event_data.ProcessName", "process.path", "exe", "image",
        "winlog.event_data.SourceImage", "winlog.event_data.TargetImage",
    ),
    "process.pid": (
        "process.pid", "winlog.event_data.NewProcessId", "winlog.event_data.ProcessId",
        "winlog.event_data.CallerProcessId", "winlog.event_data.SourceProcessId",
        "winlog.event_data.TargetProcessId", "process.entity_id", "process.entityid",
    ),
    "process.entity_id": ("process.entity_id", "process.entityid", "winlog.event_data.ProcessGuid"),
    "process.parent.pid": (
        "process.parent.pid", "winlog.event_data.ProcessId", "winlog.event_data.ParentProcessId",
        "process.parent.entity_id",
    ),
    "process.command_line": (
        "process.command_line", "process.args", "winlog.event_data.CommandLine",
        "winlog.event_data.ScriptBlockText", "ScriptBlockText", "scriptblock_text",
        "eventdata.CommandLine", "EventData.CommandLine", "eventdata.ScriptBlockText",
        "EventData.ScriptBlockText",
        "audit.command", "cmdline", "command_line", "message", "event.original",
    ),
    "process.title": ("process.title", "auditd.log.proctitle", "auditd.proctitle", "process.command_line"),
    "process.parent.name": (
        "process.parent.name", "process.parent.executable",
        "winlog.event_data.ParentImage", "winlog.event_data.ParentProcessName",
        "parent_process_name", "ppid_name",
    ),
    "file.path": (
        "file.path", "file.name", "target.file.path", "winlog.event_data.TargetFilename",
        "winlog.event_data.ObjectName", "path",
    ),
    "registry.path": ("registry.path", "registry.key", "winlog.event_data.TargetObject"),
    "service.name": ("service.name", "winlog.event_data.ServiceName", "systemd.unit"),
    "service.image": (
        "service.executable", "winlog.event_data.ServiceFileName", "winlog.event_data.ImagePath",
        "ServiceFileName", "ImagePath", "service.path",
    ),
    "task.name": ("task.name", "winlog.event_data.TaskName", "TaskName"),
    "task.content": (
        "winlog.event_data.TaskContent", "winlog.event_data.Task", "TaskContent",
        "task.action", "task.command",
    ),
    "system.auth.ssh.event": ("system.auth.ssh.event",),
    "system.auth.sudo.command": ("system.auth.sudo.command",),
    "event.status": ("event.outcome", "winlog.event_data.Status", "winlog.event_data.SubStatus", "status"),
    "event.target.name": (
        "event.target.name", "winlog.event_data.TargetObject", "winlog.event_data.ObjectName",
        "winlog.event_data.ShareName", "winlog.event_data.RelativeTargetName",
    ),
    "source.ip": (
        "source.ip", "src_ip", "srcIp", "ip.src", "client.ip",
        "winlog.event_data.SourceAddress", "winlog.event_data.IpAddress",
    ),
    "destination.ip": (
        "destination.ip", "dst_ip", "dstIp", "ip.dst", "server.ip",
        "winlog.event_data.DestAddress", "winlog.event_data.DestinationAddress",
    ),
    "destination.port": (
        "destination.port", "dst_port", "dstPort", "tcp.dstport", "udp.dstport", "port",
        "winlog.event_data.DestPort", "winlog.event_data.DestinationPort",
    ),
    "network.protocol": ("network.protocol", "network.transport", "network.application", "protocol", "protocols"),
    "network.bytes": ("network.bytes", "source.bytes", "destination.bytes", "bytes", "totBytes"),
    "dns.question": ("dns.question.name", "dns.qry.name", "dns.host", "query", "domain"),
    "dns.rcode": ("dns.response_code", "dns.header.response_code", "dns.flags.rcode", "rcode"),
    "url.full": ("url.full", "url.original", "http.request.uri", "http.uri", "uri"),
    "tls.server_name": ("tls.server.name", "tls.handshake.extensions_server_name", "server_name", "sni"),
    "file.hash.sha256": ("file.hash.sha256", "hash.sha256", "sha256"),
    "file.hash.sha1": ("file.hash.sha1", "hash.sha1", "sha1"),
    "file.hash.md5": ("file.hash.md5", "hash.md5", "md5"),
    "tls.certificate.fingerprint": ("tls.server.hash.sha256", "tls.certificate.fingerprint", "certificate.fingerprint"),
    "aggregate.signal": ("aggregate.signal",),
}


class CatalogValidationError(ValueError):
    """Catalog content is unsafe or structurally invalid."""


def load_behavior_catalog(
    path: Path = BEHAVIOR_CATALOG_PATH,
    pack_dir: Path = BEHAVIOR_PACK_DIR,
) -> dict[str, Any]:
    value = _read_json(Path(path), "behavior catalog")
    if not isinstance(value, dict):
        raise CatalogValidationError("$: behavior catalog must be an object")
    if not _nonempty_string(value.get("catalog_version")):
        raise CatalogValidationError("catalog_version: expected non-empty string")
    analytics = value.get("analytics")
    if not isinstance(analytics, list):
        raise CatalogValidationError("analytics: expected array")
    base_analytics = list(analytics)
    seen: set[str] = set()
    for index, analytic in enumerate(base_analytics):
        _validate_analytic(analytic, index, seen)
    packs = load_behavior_packs(Path(pack_dir))
    direct = packs["direct"]["records"]
    windows_catalog = _read_json(WINDOWS_EVENT_CATALOG_PATH, "Windows event catalog")
    if not isinstance(windows_catalog, dict) or not isinstance(windows_catalog.get("analytics"), list):
        raise CatalogValidationError("windows_event_catalog.json: expected analytics array")
    windows_events = windows_catalog["analytics"]
    for index, analytic in enumerate(direct + windows_events):
        _validate_analytic(analytic, len(base_analytics) + index, seen)
    value["analytics"] = base_analytics + direct + windows_events
    value["pack_status"] = {
        "manifest_version": packs["manifest"].get("manifest_version"),
        "corpus_version": packs["manifest"].get("corpus_version"),
        "curated_total": packs["manifest"].get("source_counts", {}).get("curated_behavioral_indicator"),
        "active_direct": packs["manifest"].get("direct_activation", {}).get("active"),
        "active_sequences": packs["manifest"].get("sequence_activation", {}).get("active"),
        "observe_or_unsupported": packs["manifest"].get("curated_activation", {}).get("observe_or_unsupported"),
        "direct_loaded": len(direct),
        "windows_event_rules": len(windows_events),
        "sequence_loaded": len(packs["sequences"].get("records", [])),
        "aggregate_loaded": len(packs["aggregates"].get("records", [])),
        "baseline_loaded": len(packs["baselines"].get("records", [])),
        "capability_references": len(packs["capabilities"].get("records", [])),
        "executable_rules": packs["manifest"].get("execution_states", {}).get("executable", len(direct)),
        "reference_only": packs["manifest"].get("execution_states", {}).get("reference_only", 0),
        "unsupported_sequences": sum(row.get("supported") is not True for row in packs["sequences"].get("records", [])),
        "unsupported_aggregates": sum(row.get("supported") is not True for row in packs["aggregates"].get("records", [])),
        "unsupported_baselines": sum(row.get("supported") is not True for row in packs["baselines"].get("records", [])),
    }
    value["behavior_packs"] = packs
    value["windows_event_catalog_version"] = windows_catalog.get("catalog_version")
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
        if (not analytic.get("enabled", True) or analytic.get("source") != source
                or analytic.get("activation_mode", "active") != "active"):
            continue
        missing = [role for role in analytic.get("required_roles", []) if not bindings.get(role)]
        if missing:
            unsupported.append({"id": analytic["id"], "missing_roles": missing})
        else:
            applicable.append(analytic)
    return applicable, unsupported


def _valid_attack_technique_ids() -> set[str]:
    global _ATTACK_TECHNIQUE_IDS
    if _ATTACK_TECHNIQUE_IDS is None:
        _ATTACK_TECHNIQUE_IDS = {
            str(item.get("technique_id"))
            for item in load_attack_catalog().get("techniques", [])
            if isinstance(item, dict) and item.get("technique_id")
        }
        if not _ATTACK_TECHNIQUE_IDS:
            raise CatalogValidationError("attack_catalog.json: pinned ATT&CK catalog is unavailable or invalid")
    return _ATTACK_TECHNIQUE_IDS


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
    activation_mode = item.get("activation_mode", "active")
    if activation_mode not in {"active", "observe", "reference"}:
        raise CatalogValidationError(f"{prefix}.activation_mode: unsupported activation mode")
    if "supported" in item and not isinstance(item["supported"], bool):
        raise CatalogValidationError(f"{prefix}.supported: expected boolean")
    if activation_mode == "active" and item.get("supported", True) is not True:
        raise CatalogValidationError(f"{prefix}.supported: active rule must be supported")
    for field in ("title", "description", "review_date"):
        if not _nonempty_string(item.get(field)):
            raise CatalogValidationError(f"{prefix}.{field}: expected non-empty string")
    if not isinstance(item.get("version"), int) or item["version"] < 1:
        raise CatalogValidationError(f"{prefix}.version: expected positive integer")
    if not isinstance(item.get("enabled"), bool):
        raise CatalogValidationError(f"{prefix}.enabled: expected boolean")
    if item.get("source") not in ALLOWED_SOURCES:
        raise CatalogValidationError(f"{prefix}.source: unsupported source")
    if item.get("source") == "elasticsearch":
        if item.get("source_language") != "elasticsearch_dsl":
            raise CatalogValidationError(f"{prefix}.source_language: expected elasticsearch_dsl")
        if not _nonempty_string(item.get("stage_id")):
            raise CatalogValidationError(f"{prefix}.stage_id: expected non-empty string")
    for field in (
        "platforms", "categories", "required_roles", "optional_roles",
        "attack_techniques", "benign_explanations", "required_corroboration", "follow_up",
    ):
        values = item.get(field)
        if not isinstance(values, list) or (field not in {"optional_roles", "required_corroboration"} and not values):
            raise CatalogValidationError(f"{prefix}.{field}: expected non-empty array")
        if not all(_nonempty_string(value) for value in values):
            raise CatalogValidationError(f"{prefix}.{field}: expected strings")
    valid_attack_ids = _valid_attack_technique_ids()
    for technique_id in item["attack_techniques"]:
        if technique_id not in valid_attack_ids:
            raise CatalogValidationError(f"{prefix}.attack_techniques: unknown pinned ATT&CK technique {technique_id}")
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


def compile_elasticsearch_seed(
    analytic: dict[str, Any],
    bindings: dict[str, list[str]],
    timestamp_field: str,
    time_range: dict[str, str] | None,
    field_metadata: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any] | None:
    """Compile a catalog entry into a bounded, validator-compatible ES query."""
    match = analytic.get("match", {})
    must = []
    should = []
    must_not = []
    for predicate in match.get("all", []):
        clause = _predicate_query(predicate, bindings, field_metadata)
        if clause is None:
            return None
        must.append(clause)
    for predicate in match.get("any", []):
        clause = _predicate_query(predicate, bindings, field_metadata)
        if clause is not None:
            should.append(clause)
    for predicate in match.get("none", []):
        clause = _predicate_query(predicate, bindings, field_metadata)
        if clause is None:
            return None
        must_not.append(clause)
    if not must and not should:
        return None
    body: dict[str, Any] = {}
    if must:
        body["must"] = must
    if should:
        body["should"] = should
        body["minimum_should_match"] = 1
    if must_not:
        body["must_not"] = must_not
    if time_range:
        body["filter"] = [{"range": {timestamp_field: dict(time_range)}}]
    return {"bool": body}


def build_candidate_queue(
    evidence: list[dict[str, Any]],
    catalog: dict[str, Any],
    indicators: dict[str, Any],
    analytic_summary: dict[str, Any] | None = None,
    now: str | datetime | None = None,
) -> list[dict[str, Any]]:
    """Match evidence and return a stable, explainable candidate queue."""
    events = list(evidence) + _aggregate_events(analytic_summary or {})
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
    analytics = [item for item in catalog.get("analytics", []) if item.get("enabled", True)]
    analytics_by_id = {str(item["id"]): item for item in analytics}
    matched_pairs: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for analytic in analytics:
        if analytic.get("supported", True) is not True or analytic.get("activation_mode", "active") == "reference":
            continue
        for event in events:
            if analytic.get("source") == "aggregate" and event.get("source") != "aggregate":
                continue
            if analytic.get("source") == "elasticsearch" and event.get("source") == "aggregate":
                continue
            if _analytic_matches(analytic, event):
                asset = str(event.get("asset") or "unknown")
                grouped.setdefault((analytic["id"], asset), []).append(event)
                matched_pairs.append((analytic, event))

    candidates: list[dict[str, Any]] = []
    for (analytic_id, asset), rows in grouped.items():
        analytic = analytics_by_id[str(analytic_id)]
        related_groups: set[str] = set()
        if analytic.get("activation_mode", "active") == "active":
            own_group = str(analytic.get("corroboration_group") or analytic["id"])
            for other, other_event in matched_pairs:
                if other["id"] == analytic["id"] or other.get("activation_mode", "active") != "active":
                    continue
                other_group = str(other.get("corroboration_group") or other["id"])
                if other_group == own_group:
                    continue
                if any(_has_correlated_support(row, other_event) for row in rows):
                    related_groups.add(other_group)
        independent = len(related_groups)
        score = int(analytic["base_priority"]) + min(10, int(analytic["specificity"]) // 10)
        reasons = [
            f"base analytic priority {analytic['base_priority']}",
            f"specificity contribution {min(10, int(analytic['specificity']) // 10)}",
        ]
        noise_penalty={"low":0,"medium":6,"high":12}[str(analytic.get("expected_noise") or "high")]
        if noise_penalty:
            score-=noise_penalty
            reasons.append(f"expected noise penalty {noise_penalty}")
        if len(rows) > 1:
            repeat_bonus = min(9, (len(rows) - 1) * 3)
            score += repeat_bonus
            reasons.append(f"repeat observation contribution {repeat_bonus}")
        if independent:
            corroboration_bonus = min(30, independent * 15)
            score += corroboration_bonus
            reasons.append(
                f"related independent behavior corroboration contribution {corroboration_bonus} "
                f"from {independent} distinct behavior group(s)"
            )
        if analytic.get("activation_mode", "active") == "observe":
            score = min(OBSERVE_SCORE_CEILING, score)
            reasons.append(f"observe-only score ceiling {OBSERVE_SCORE_CEILING}")
        score = max(0,min(100, score))
        disposition = "corroborated" if analytic.get("activation_mode", "active") == "active" and score >= 70 and independent else "observed"
        candidates.append(_behavior_candidate(analytic, asset, rows, score, disposition, reasons))

    reference_time = _coerce_time(now) if now is not None else datetime.now(timezone.utc)
    for indicator in indicators.get("indicators", []):
        expires = indicator.get("expires_at")
        if expires and _parse_time(expires, f"indicator {indicator.get('id')}.expires_at") <= reference_time:
            continue
        matched = [event for event in evidence if _indicator_matches(indicator, event)]
        if not matched:
            continue
        by_asset: dict[str, list[dict[str, Any]]] = {}
        for event in matched:
            by_asset.setdefault(str(event.get("asset") or "unknown"), []).append(event)
        for asset, rows in by_asset.items():
            score = max(90, min(100, int(indicator.get("confidence", 0))))
            identifier = str(indicator["id"])
            candidate_id = _candidate_id("indicator", identifier, asset)
            follow_up = ["Validate the indicator source and investigate the cited event and adjacent activity."]
            candidates.append({
                "candidate_id": candidate_id,
                "kind": "trusted_indicator", "indicator_id": identifier,
                "analytic_id": None, "title": f"Trusted indicator observed: {identifier}",
                "description": f"An exact {indicator.get('type')} indicator supplied by {indicator.get('source')} was observed.",
                "priority_score": score, "priority_tier": "critical",
                "disposition": "observed", "customer_visible": True,
                "evidence_ids": _evidence_ids(rows), "evidence_match_count": len(rows), "assets": [asset],
                "first_observed": _observed_bounds(rows)[0], "last_observed": _observed_bounds(rows)[1],
                "score_reasons": [
                    f"trusted exact indicator confidence {indicator.get('confidence')}",
                    "exact value match with current provenance",
                ],
                "attack_techniques": [], "benign_explanations": [],
                "follow_up": follow_up, "follow_ups": _follow_up_records(candidate_id, follow_up),
                "finding_ids": [],
                "indicator_source": indicator.get("source"), "indicator_confidence": indicator.get("confidence"),
                "indicator_type": indicator.get("type"), "indicator_value": indicator.get("value"),
                "indicator_expires_at": indicator.get("expires_at"),
            })
    return sorted(
        candidates,
        key=lambda item: (
            -int(item.get("priority_score", 0)),
            0 if item.get("kind") == "trusted_indicator" else 1,
            str(item.get("candidate_id")),
        ),
    )


def customer_visible_candidates(candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [item for item in candidates if item.get("customer_visible")]


def merge_candidate_queue(previous: list[dict[str, Any]], current: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Merge fresh detections without erasing investigation decisions or follow-up history."""
    prior_by_id = {str(item.get("candidate_id")): item for item in previous if item.get("candidate_id")}
    merged = []
    refreshed_ids = set()
    disposition_rank = {"observed": 0, "investigating": 1, "corroborated": 2}
    terminal = {"benign_likely", "dismissed", "unresolved"}
    for fresh in current:
        item = dict(fresh)
        prior = prior_by_id.get(str(item.get("candidate_id")))
        refreshed_ids.add(str(item.get("candidate_id")))
        if prior:
            prior_disposition = str(prior.get("disposition") or "observed")
            fresh_disposition = str(item.get("disposition") or "observed")
            if prior_disposition in terminal or disposition_rank.get(prior_disposition, 0) > disposition_rank.get(fresh_disposition, 0):
                item["disposition"] = prior_disposition
            item["evidence_ids"] = list(dict.fromkeys(
                item.get("evidence_ids", []) + prior.get("evidence_ids", [])))[:MAX_CANDIDATE_EVIDENCE_IDS]
            item["evidence_match_count"] = max(int(item.get("evidence_match_count",0) or 0),
                int(prior.get("evidence_match_count",0) or 0))
            observed = [value for value in (prior.get("first_observed"), item.get("first_observed")) if value]
            item["first_observed"] = min(observed) if observed else None
            observed = [value for value in (prior.get("last_observed"), item.get("last_observed")) if value]
            item["last_observed"] = max(observed) if observed else None
            item["finding_ids"] = list(dict.fromkeys(prior.get("finding_ids", []) + item.get("finding_ids", [])))
            old_follow_ups = {entry.get("follow_up_id"): entry for entry in prior.get("follow_ups", [])}
            preserved = []
            for follow_up in item.get("follow_ups", []):
                old = old_follow_ups.get(follow_up.get("follow_up_id"))
                preserved.append(dict(follow_up, status=old.get("status", follow_up.get("status")),
                    history=list(old.get("history", []))) if old else follow_up)
            refreshed_follow_up_ids = {entry.get("follow_up_id") for entry in preserved}
            preserved.extend(dict(entry, history=list(entry.get("history", [])))
                for entry in prior.get("follow_ups", []) if entry.get("follow_up_id") not in refreshed_follow_up_ids)
            item["follow_ups"] = preserved
            for field in ("disposition_history", "telemetry_gaps"):
                if prior.get(field): item[field] = list(prior[field])
        merged.append(item)
    # A bounded re-analysis may not reproduce a previously observed candidate
    # (for example after context retention or source availability changes).
    # Preserve it until an explicit analyst disposition closes it.
    for prior_item in previous:
        if str(prior_item.get("candidate_id")) in refreshed_ids: continue
        preserved=dict(prior_item,follow_ups=[dict(entry,history=list(entry.get("history",[])))
            for entry in prior_item.get("follow_ups",[])])
        preserved["evidence_ids"]=list(dict.fromkeys(preserved.get("evidence_ids",[])))[:MAX_CANDIDATE_EVIDENCE_IDS]
        merged.append(preserved)
    return sorted(merged, key=lambda item: (-int(item.get("priority_score", 0)),
        0 if item.get("kind") == "trusted_indicator" else 1, str(item.get("candidate_id"))))


def _predicate_query(
    predicate: dict[str, Any],
    bindings: dict[str, list[str]],
    field_metadata: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any] | None:
    fields = bindings.get(predicate.get("role"), [])
    if not fields:
        return None
    operator = predicate.get("operator")
    values = predicate.get("values", [])
    clauses = []
    for field in fields[:4]:
        metadata = field_metadata.get(field) if field_metadata is not None else None
        if field_metadata is not None and (not isinstance(metadata, dict) or metadata.get("searchable") is not True):
            continue
        raw_types = metadata.get("types", metadata.get("type", [])) if isinstance(metadata, dict) else []
        field_types = ({str(raw_types)} if isinstance(raw_types, str) else
            {str(value) for value in raw_types} if isinstance(raw_types, (list, tuple, set)) else set())
        text_types = field_types.intersection({"text", "match_only_text"})
        keyword_types = field_types.intersection({"keyword", "constant_keyword", "wildcard"})
        if operator == "exists":
            clauses.append({"exists": {"field": field}})
        elif operator == "equals_any":
            # Exact event identifiers may be mapped as keyword or numeric
            # fields depending on the integration. Only text-only fields need
            # analyzed phrase queries.
            if field_metadata is None or keyword_types or not text_types:
                clauses.append({"terms": {field: values[:20]}})
            if text_types:
                clauses.extend({"match_phrase": {field: value}} for value in values[:12])
        elif operator == "path_prefix_any":
            if field_metadata is None or keyword_types or not field_types:
                clauses.extend({"prefix": {field: value}} for value in values[:12])
        elif operator == "contains_any":
            if text_types:
                clauses.extend({"match_phrase": {field: value}} for value in values[:12])
            if keyword_types:
                for value in values[:12]:
                    literal = _escape_wildcard_literal(value)
                    if len(literal) >= 3:
                        clauses.append({"wildcard": {field: {"value": f"*{literal}*", "case_insensitive": True}}})
            if field_metadata is None:
                clauses.extend({"match_phrase": {field: value}} for value in values[:12])
            if field in {"message", "event.original", "audit.command", "auditd.log.message",
                         "auditd_manager.auditd.message"}:
                for value in values[:12]:
                    token = re.match(r"[A-Za-z0-9][A-Za-z0-9_.-]{2,}", str(value).strip())
                    if token:
                        encoded = token.group(0).encode("utf-8").hex()
                        if text_types or field_metadata is None:
                            clauses.append({"match_phrase": {field: encoded}})
                        if keyword_types:
                            clauses.append({"wildcard": {field: {
                                "value": f"*{encoded}*", "case_insensitive": True,
                            }}})
        elif operator == "ends_with_any":
            if keyword_types or field_metadata is None or not field_types:
                for value in values[:12]:
                    literal = _escape_wildcard_literal(value)
                    if len(literal) >= 3:
                        clauses.append({"wildcard": {field: {"value": f"*{literal}", "case_insensitive": True}}})
        else:
            continue
    if not clauses:
        return None
    return clauses[0] if len(clauses) == 1 else {"bool": {"should": clauses, "minimum_should_match": 1}}


def _escape_wildcard_literal(value: Any) -> str:
    """Escape a literal before embedding it in one bounded wildcard pattern."""
    return str(value).replace("\\", "\\\\").replace("*", "\\*").replace("?", "\\?")


def _analytic_matches(analytic: dict[str, Any], event: dict[str, Any]) -> bool:
    if not _platform_compatible(analytic, event):
        return False
    match = analytic.get("match", {})
    all_results = [_predicate_matches(item, event) for item in match.get("all", [])]
    any_results = [_predicate_matches(item, event) for item in match.get("any", [])]
    none_results = [_predicate_matches(item, event) for item in match.get("none", [])]
    return all(all_results) and (any(any_results) if any_results else True) and not any(none_results)


def event_matches_match(match: dict[str, Any], event: dict[str, Any]) -> bool:
    """Evaluate one normalized event against a closed Boolean predicate mapping."""
    return _analytic_matches({"platforms": [], "match": match}, event)


def _platform_compatible(analytic: dict[str, Any], event: dict[str, Any]) -> bool:
    expected = {str(value).strip().lower() for value in analytic.get("platforms", [])}
    endpoint_platforms = {"windows", "linux", "macos", "darwin"}
    expected_endpoint = expected.intersection(endpoint_platforms)
    if not expected_endpoint:
        return True
    observed = {value.strip().lower() for value in _role_values(event, "host.os.platform") if value.strip()}
    providers = [value.lower() for value in _role_values(event, "event.provider")]
    channels = [value.lower() for value in _role_values(event, "event.channel")]
    if any("microsoft-windows" in value for value in providers) or any(value == "security" or "windows defender" in value for value in channels):
        observed.add("windows")
    if any("linux" in value for value in observed):
        observed.add("linux")
    if any("darwin" in value or "macos" in value or "mac os" in value for value in observed):
        observed.update(("macos", "darwin"))
    if any("windows" in value or value.startswith("win") for value in observed):
        observed.add("windows")
    if not observed:
        return True
    if "macos" in expected_endpoint or "darwin" in expected_endpoint:
        expected_endpoint.update(("macos", "darwin"))
    return bool(expected_endpoint.intersection(observed))


def _predicate_matches(predicate: dict[str, Any], event: dict[str, Any]) -> bool:
    role = str(predicate.get("role"))
    operator = predicate.get("operator")
    values = [str(value).lower() for value in predicate.get("values", [])]
    observed = [value.lower() for value in _role_values(event, role)]
    if operator == "exists":
        return bool(observed)
    if operator == "contains_any":
        return any(needle in value for value in observed for needle in values)
    if operator == "equals_any":
        return any(value == needle for value in observed for needle in values)
    if operator == "ends_with_any":
        return any(value.endswith(needle) for value in observed for needle in values)
    if operator == "path_prefix_any":
        normalized_values = [_normalize_path(value) for value in values]
        return any(_normalize_path(value).startswith(prefix) for value in observed for prefix in normalized_values)
    if operator == "regex":
        for pattern in predicate.get("values", []):
            try:
                if any(re.search(str(pattern), value, flags=re.IGNORECASE) for value in observed):
                    return True
            except re.error:
                return False
        return False
    if operator == "lookalike_process":
        paths = _role_values(event, "process.executable")
        if not paths:
            return False
        for value in observed:
            basename = _basename(value)
            for expected in values:
                if basename != expected and _edit_distance_at_most_one(basename, expected):
                    return any(_basename(path).lower() == basename for path in paths)
        return False
    return False


def _role_values(event: dict[str, Any], role: str) -> list[str]:
    out: list[str] = []
    for field in SEMANTIC_ROLE_ALIASES.get(role, ()):
        value = _nested_value(event.get("raw", {}), field)
        if value is None:
            value = event.get("raw", {}).get(field) if isinstance(event.get("raw"), dict) else None
        if value is None:
            value = _nested_value(event, field)
        for item in value if isinstance(value, list) else [value]:
            if item is not None and str(item).strip() and str(item) not in out:
                out.append(str(item))
    if role == "host.name" and event.get("asset") and str(event["asset"]) not in out:
        out.append(str(event["asset"]))
    return out


def _has_correlated_support(left: dict[str, Any], right: dict[str, Any]) -> bool:
    """Require separate evidence, same host, bounded time, and a real join key."""
    left_ids = set(_evidence_ids([left]))
    right_ids = set(_evidence_ids([right]))
    if left_ids and right_ids and left_ids == right_ids:
        return False

    left_hosts = {value.strip().lower() for value in _role_values(left, "host.name") if value.strip()}
    right_hosts = {value.strip().lower() for value in _role_values(right, "host.name") if value.strip()}
    left_asset = str(left.get("asset") or "").strip().lower()
    right_asset = str(right.get("asset") or "").strip().lower()
    if left_asset not in {"", "unknown", "none"}:
        left_hosts.add(left_asset)
    if right_asset not in {"", "unknown", "none"}:
        right_hosts.add(right_asset)
    if not left_hosts.intersection(right_hosts):
        return False

    left_time = _event_time(left)
    right_time = _event_time(right)
    if left_time is None or right_time is None:
        return False
    if abs((left_time - right_time).total_seconds()) > CORROBORATION_WINDOW_MINUTES * 60:
        return False

    for role in ("session.id", "user.name", "process.entity_id"):
        if _join_values(left, role).intersection(_join_values(right, role)):
            return True
    left_pids = _join_values(left, "process.pid")
    left_parents = _join_values(left, "process.parent.pid")
    right_pids = _join_values(right, "process.pid")
    right_parents = _join_values(right, "process.parent.pid")
    if left_pids.intersection(right_parents) or right_pids.intersection(left_parents):
        return True
    for role in ("file.path", "registry.path", "destination.ip"):
        if _join_values(left, role).intersection(_join_values(right, role)):
            return True
    return False


def _join_values(event: dict[str, Any], role: str) -> set[str]:
    values = set()
    placeholders = {"", "-", "unknown", "none", "null", "n/a", "system", "nt authority\\system"}
    for value in _role_values(event, role):
        normalized = str(value).strip().lower()
        if normalized in placeholders:
            continue
        if role in {"process.pid", "process.parent.pid", "session.id"}:
            token = normalized
            try:
                if re.fullmatch(r"0x[0-9a-f]+", token):
                    normalized = str(int(token, 16))
                elif re.fullmatch(r"\d+", token):
                    normalized = str(int(token, 10))
            except ValueError:
                pass
        elif role in {"file.path", "registry.path"}:
            normalized = _normalize_path(normalized)
        if normalized not in placeholders:
            values.add(normalized)
    return values


def _event_time(event: dict[str, Any]) -> datetime | None:
    value = event.get("observed_at")
    if not value:
        values = _role_values(event, "event.time")
        value = values[0] if values else None
    if not value:
        return None
    try:
        return _coerce_time(str(value))
    except (CatalogValidationError, TypeError, ValueError):
        return None


def _indicator_matches(indicator: dict[str, Any], event: dict[str, Any]) -> bool:
    expected = _normalize_indicator(str(indicator.get("type")), str(indicator.get("value")))
    if not expected:
        return False
    kind = str(indicator.get("type"))
    values = _flatten_strings({
        "observation": event.get("observation"),
        "asset": event.get("asset"),
        "raw": event.get("raw", {}),
    })
    observed: set[str] = set()
    for value in values:
        observed.update(_extract_indicator_values(kind, value))
    return expected in observed


def _normalize_indicator(kind: str, value: str) -> str:
    value = value.strip().lower()
    if kind == "path":
        return _normalize_path(value)
    if kind == "process":
        return _basename(value)
    if kind == "domain":
        return value.rstrip(".")
    return value


def _extract_indicator_values(kind: str, value: str) -> set[str]:
    text = str(value).strip().lower()
    if not text:
        return set()
    if kind in {"sha256", "sha1", "md5"}:
        lengths = {"sha256": 64, "sha1": 40, "md5": 32}
        return set(re.findall(rf"(?<![0-9a-f])[0-9a-f]{{{lengths[kind]}}}(?![0-9a-f])", text))
    if kind == "ip":
        values = set()
        for token in re.findall(r"(?<![0-9a-f:.])(?:[0-9a-f]*:[0-9a-f:.]+|(?:\d{1,3}\.){3}\d{1,3})(?![0-9a-f:.])", text):
            try:
                values.add(str(ipaddress.ip_address(token)))
            except ValueError:
                pass
        return values
    if kind == "domain":
        return {value.rstrip(".") for value in re.findall(r"(?<![a-z0-9-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?![a-z0-9-])", text)}
    if kind == "path":
        return {_normalize_path(text)}
    if kind == "process":
        return {_basename(text)}
    return {text}


def _behavior_candidate(
    analytic: dict[str, Any],
    asset: str,
    rows: list[dict[str, Any]],
    score: int,
    disposition: str,
    reasons: list[str],
) -> dict[str, Any]:
    tier = "critical" if score >= 90 else ("high" if score >= 70 else ("medium" if score >= 40 else "low"))
    candidate_id = _candidate_id("behavior", analytic["id"], asset)
    follow_up = analytic.get("follow_up", [])
    return {
        "candidate_id": candidate_id,
        "kind": "behavior", "analytic_id": analytic["id"], "indicator_id": None,
        "research_id": analytic.get("research_id"),
        "activation_mode": analytic.get("activation_mode", "active"),
        "supported": analytic.get("supported", True),
        "title": analytic["title"], "description": analytic["description"],
        "priority_score": score, "priority_tier": tier, "disposition": disposition,
        "customer_visible": bool(score >= 70 and disposition == "corroborated"),
        "evidence_ids": _evidence_ids(rows), "evidence_match_count": len(rows), "assets": [asset],
        "first_observed": _observed_bounds(rows)[0], "last_observed": _observed_bounds(rows)[1],
        "score_reasons": reasons, "attack_techniques": analytic.get("attack_techniques", []),
        "benign_explanations": analytic.get("benign_explanations", []),
        "follow_up": follow_up, "follow_ups": _follow_up_records(candidate_id, follow_up),
        "finding_ids": [],
    }


def _aggregate_events(summary: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    aggregate_signals = summary.get("aggregate_signals")
    if isinstance(aggregate_signals, dict):
        for signal, rows in aggregate_signals.items():
            for row in rows or []:
                refs = list(row.get("sample_evidence_ids") or [])
                if row.get("sample_evidence_id"):
                    refs.append(row["sample_evidence_id"])
                asset = (row.get("asset") or row.get("source") or row.get("destination")
                    or row.get("user") or "unknown")
                out.append(_aggregate_event(str(signal), asset, *refs))
        return out
    host_profile = summary.get("host_profile", {})
    for row in host_profile.get("authentication_sequences", []) or []:
        out.append(_aggregate_event("auth_failures_then_success", row.get("source") or row.get("user"), row.get("sample_evidence_id")))
    network = summary.get("network_profile", {})
    for row in network.get("high_fanout", []) or []:
        out.append(_aggregate_event("high_fanout", row.get("source"), *(row.get("sample_evidence_ids") or [])))
    for row in network.get("periodic_edge_candidates", []) or []:
        out.append(_aggregate_event("periodic_edge", row.get("source"), *(row.get("sample_evidence_ids") or [])))
    for row in network.get("low_frequency_external_destinations", []) or []:
        out.append(_aggregate_event("rare_external_destination", row.get("destination"), *(row.get("sample_evidence_ids") or [])))
    return out


def _aggregate_event(signal: str, asset: Any, *evidence_ids: Any) -> dict[str, Any]:
    supporting = list(dict.fromkeys(str(value) for value in evidence_ids if value))
    return {
        "evidence_id": supporting[0] if supporting else f"AGG-{signal}",
        "source": "aggregate", "observed_at": "", "asset": str(asset or "unknown"),
        "observation": signal, "supporting_evidence_ids": supporting,
        "raw": {"aggregate": {"signal": signal, "supporting_evidence_ids": supporting}},
    }


def _candidate_id(kind: str, identifier: str, asset: str) -> str:
    digest = hashlib.sha1(f"{kind}|{identifier}|{asset}".encode("utf-8", errors="replace")).hexdigest()[:12].upper()
    return f"CL-{digest}"


def _follow_up_records(candidate_id: str, intents: list[str]) -> list[dict[str, Any]]:
    out = []
    for intent in intents:
        digest = hashlib.sha1(f"{candidate_id}|{intent}".encode("utf-8", errors="replace")).hexdigest()[:10].upper()
        out.append({"follow_up_id": f"FU-{digest}", "intent": str(intent), "status": "pending", "history": []})
    return out


def _evidence_ids(rows: list[dict[str, Any]]) -> list[str]:
    values = set()
    for row in rows:
        if row.get("evidence_id"):
            values.add(str(row["evidence_id"]))
        values.update(str(value) for value in row.get("supporting_evidence_ids", []) if value)
    return sorted(values)[:MAX_CANDIDATE_EVIDENCE_IDS]


def _observed_bounds(rows: list[dict[str, Any]]) -> tuple[str | None, str | None]:
    values = sorted(str(row.get("observed_at")) for row in rows if row.get("observed_at"))
    return (values[0], values[-1]) if values else (None, None)


def _nested_value(value: Any, path: str) -> Any:
    for part in path.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def _flatten_strings(value: Any, depth: int = 0) -> list[str]:
    if depth > 6:
        return []
    if isinstance(value, dict):
        return [item for child in value.values() for item in _flatten_strings(child, depth + 1)]
    if isinstance(value, list):
        return [item for child in value[:100] for item in _flatten_strings(child, depth + 1)]
    return [str(value)] if value is not None else []


def _normalize_path(value: str) -> str:
    return str(value).strip().lower().replace("\\", "/")


def _basename(value: str) -> str:
    return _normalize_path(value).rsplit("/", 1)[-1]


def _edit_distance_at_most_one(left: str, right: str) -> bool:
    if abs(len(left) - len(right)) > 1:
        return False
    if left == right:
        return True
    if len(left) == len(right):
        return sum(a != b for a, b in zip(left, right)) <= 1
    short, long = (left, right) if len(left) < len(right) else (right, left)
    index = 0
    for position, char in enumerate(long):
        if index < len(short) and short[index] == char:
            index += 1
        elif position - index >= 1:
            return False
    return True


def _coerce_time(value: str | datetime) -> datetime:
    if isinstance(value, datetime):
        return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
    return _parse_time(value, "now")



def compile_elasticsearch_indicator_seed(
    indicator: dict[str, Any],
    bindings: dict[str, list[str]],
    timestamp_field: str,
    time_range: dict[str, str] | None,
) -> dict[str, Any] | None:
    """Compile a trusted exact indicator into a strict field-bound query."""
    roles_by_type = {
        "domain": ("dns.question", "url.full", "tls.server_name"),
        "ip": ("source.ip", "destination.ip"),
        "path": ("file.path", "process.executable"),
        "process": ("process.name", "process.executable"),
        "sha256": ("file.hash.sha256",),
        "sha1": ("file.hash.sha1",),
        "md5": ("file.hash.md5",),
        "certificate": ("tls.certificate.fingerprint",),
    }
    fields = [
        field
        for role in roles_by_type.get(str(indicator.get("type")), ())
        for field in bindings.get(role, [])
    ]
    if not fields:
        return None
    value = str(indicator.get("value") or "").strip()
    if not value:
        return None
    should = [{"term": {field: value}} for field in list(dict.fromkeys(fields))[:8]]
    body: dict[str, Any] = {"should": should, "minimum_should_match": 1}
    if time_range:
        body["filter"] = [{"range": {timestamp_field: dict(time_range)}}]
    return {"bool": body}
