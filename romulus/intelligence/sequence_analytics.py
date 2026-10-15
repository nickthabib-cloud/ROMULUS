"""Deterministic, bounded correlation for translated sequence intelligence."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import re
from typing import Any

from .analytics import evidence_source_family


MAX_SEQUENCE_EVENTS = 10_000
MAX_STAGE_MATCHES = 500


def evaluate_sequences(
    evidence: list[dict[str, Any]],
    definitions: list[dict[str, Any]],
    source_outcomes: list[dict[str, Any]] | None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Evaluate translated sequences over complete eligible evidence."""
    envelopes = sorted(
        (_envelope(row) for row in evidence[:MAX_SEQUENCE_EVENTS]),
        key=lambda row: (row["time"], row["evidence_id"]),
    )
    matches: list[dict[str, Any]] = []
    by_rule: dict[str, dict[str, Any]] = {}
    for definition in definitions:
        identifier = str(definition.get("id") or "")
        execution = definition.get("execution") if isinstance(definition.get("execution"), dict) else {}
        if execution.get("status") != "executable":
            by_rule[identifier] = {
                "state": "reference_only",
                "reason_code": execution.get("reason_code", "missing_executable_translation"),
            }
            continue
        required_sources = sorted({family for stage in execution.get("stages", [])
                                   for family in stage.get("source_families", [])})
        incomplete = _incomplete_sources(required_sources, source_outcomes)
        selected = _match_definition(envelopes, execution)
        if selected:
            candidate = _candidate(definition, selected, bool(incomplete))
            matches.append(candidate)
            by_rule[identifier] = {
                "state": "matched_partial" if incomplete else "matched",
                "incomplete_sources": incomplete,
                "evidence_ids": candidate["evidence_ids"],
            }
        elif incomplete:
            by_rule[identifier] = {"state": "partial", "incomplete_sources": incomplete}
        else:
            by_rule[identifier] = {"state": "no_match", "incomplete_sources": []}
    coverage = {
        "total": len(definitions),
        "executable": sum(row.get("execution", {}).get("status") == "executable" for row in definitions),
        "reference_only": sum(row.get("execution", {}).get("status") != "executable" for row in definitions),
        "matched": len(matches),
        "evaluated_events": len(envelopes),
        "event_limit_reached": len(evidence) > MAX_SEQUENCE_EVENTS,
        "by_rule": by_rule,
    }
    return sorted(matches, key=lambda row: (-int(row["priority_score"]), row["candidate_id"])), coverage


def _match_definition(events: list[dict[str, Any]], execution: dict[str, Any]) -> list[dict[str, Any]]:
    stages = list(execution.get("stages") or [])
    if not stages:
        return []
    candidates = []
    for stage in stages:
        allowed = set(stage.get("source_families") or [])
        rows = [event for event in events
                if str(stage.get("signal")) in event["signals"]
                and (not allowed or event["source_family"] in allowed)]
        candidates.append(rows[:MAX_STAGE_MATCHES])
    threshold = int(execution.get("threshold") or len(stages))
    if sum(bool(rows) for rows in candidates) < threshold:
        return []
    order = execution.get("order", "ordered")
    window_seconds = max(1, int(execution.get("window_minutes") or 30)) * 60
    joins = list(execution.get("joins") or [])
    join_mode = execution.get("join_mode", "all")
    if order == "ordered":
        return _ordered(candidates, window_seconds, joins, join_mode)
    return _unordered(candidates, threshold, window_seconds, joins, join_mode)


def _ordered(
    candidates: list[list[dict[str, Any]]], window_seconds: int, joins: list[str], join_mode: str
) -> list[dict[str, Any]]:
    def walk(index: int, chosen: list[dict[str, Any]]) -> list[dict[str, Any]]:
        if index == len(candidates):
            return chosen
        for event in candidates[index]:
            if _already_chosen(event, chosen):
                continue
            if chosen and event["time"] < chosen[-1]["time"]:
                continue
            trial = chosen + [event]
            if (trial[-1]["time"] - trial[0]["time"]).total_seconds() > window_seconds:
                continue
            if _joins_hold(trial, joins, join_mode):
                found = walk(index + 1, trial)
                if found:
                    return found
        return []
    return walk(0, [])


def _unordered(
    candidates: list[list[dict[str, Any]]], threshold: int, window_seconds: int,
    joins: list[str], join_mode: str,
) -> list[dict[str, Any]]:
    populated = [(index, rows) for index, rows in enumerate(candidates) if rows]

    def walk(offset: int, chosen: list[dict[str, Any]]) -> list[dict[str, Any]]:
        if len(chosen) >= threshold:
            return sorted(chosen, key=lambda row: (row["time"], row["evidence_id"]))
        for position in range(offset, len(populated)):
            _, rows = populated[position]
            for event in rows:
                if _already_chosen(event, chosen):
                    continue
                trial = chosen + [event]
                times = [row["time"] for row in trial]
                if (max(times) - min(times)).total_seconds() > window_seconds:
                    continue
                if _joins_hold(trial, joins, join_mode):
                    found = walk(position + 1, trial)
                    if found:
                        return found
        return []
    return walk(0, [])


def _already_chosen(event: dict[str, Any], chosen: list[dict[str, Any]]) -> bool:
    identifier = str(event.get("evidence_id") or "")
    return any(
        (identifier and identifier == str(row.get("evidence_id") or "")) or event is row
        for row in chosen
    )


def _joins_hold(events: list[dict[str, Any]], joins: list[str], join_mode: str) -> bool:
    if len(events) < 2 or not joins:
        return True
    results = []
    for join in joins:
        sets = [set(event.get(join, set())) for event in events]
        results.append(bool(sets) and all(sets) and bool(set.intersection(*sets)))
    return any(results) if join_mode == "any" else all(results)


def _incomplete_sources(required: list[str], outcomes: list[dict[str, Any]] | None) -> list[str]:
    if outcomes is None:
        return []
    incomplete = []
    for family in required:
        rows = [row for row in outcomes if row.get("source_family") == family]
        healthy = any(row.get("status") == "completed" and not row.get("capped")
                      and not row.get("incomplete") and not row.get("timed_out")
                      and not row.get("shard_failures") for row in rows)
        if not healthy:
            incomplete.append(family)
    return incomplete


def _candidate(definition: dict[str, Any], events: list[dict[str, Any]], partial: bool) -> dict[str, Any]:
    evidence_ids = [row["evidence_id"] for row in events]
    assets = sorted({value for row in events for value in row["asset"]}) or ["unknown"]
    identifier = str(definition["id"])
    digest = hashlib.sha256((identifier + "|" + "|".join(evidence_ids)).encode("utf-8")).hexdigest()[:16].upper()
    score = min(100, int(definition.get("base_score", 50)) + min(10, int(definition.get("specificity", 0)) // 10))
    complete = not partial
    disposition = "corroborated" if complete and score >= 70 else "observed"
    stage_ids = []
    for event in events:
        for stage in definition.get("execution", {}).get("stages", []):
            if stage.get("signal") in event["signals"] and stage.get("stage_id") not in stage_ids:
                stage_ids.append(stage.get("stage_id"))
                break
    return {
        "candidate_id": f"SEQ-{digest}",
        "kind": "sequence",
        "analytic_id": identifier,
        "indicator_id": None,
        "title": definition.get("title", identifier),
        "description": definition.get("description", "Correlated behavior sequence."),
        "priority_score": score,
        "priority_tier": "critical" if score >= 90 else "high" if score >= 70 else "medium" if score >= 40 else "low",
        "disposition": disposition,
        "customer_visible": bool(disposition == "corroborated"),
        "evidence_ids": evidence_ids[:40],
        "evidence_match_count": len(evidence_ids),
        "assets": assets,
        "first_observed": events[0]["time"].isoformat().replace("+00:00", "Z"),
        "last_observed": events[-1]["time"].isoformat().replace("+00:00", "Z"),
        "matched_stage_ids": stage_ids,
        "source_families": sorted({row["source_family"] for row in events}),
        "completeness": "partial" if partial else "complete",
        "score_reasons": ["translated multi-event sequence completed", f"base analytic priority {definition.get('base_score', 50)}"],
        "attack_techniques": list(definition.get("attack_techniques") or []),
        "benign_explanations": list(definition.get("benign_explanations") or []),
        "follow_up": list(definition.get("follow_up") or []),
        "follow_ups": [],
        "finding_ids": [],
    }


def _envelope(event: dict[str, Any]) -> dict[str, Any]:
    raw = event.get("raw") if isinstance(event.get("raw"), dict) else {}
    text = " ".join(_strings(raw) + [str(event.get("observation") or "")]).lower()
    signals = {str(value) for value in event.get("signals", []) if value}
    signals.update(_derived_signals(text, raw))
    return {
        "evidence_id": str(event.get("evidence_id") or ""),
        "time": _time(event.get("observed_at")),
        "source_family": _source_family(event, raw),
        "asset": _values(event, raw, ("host.name", "host.hostname"), fallback=event.get("asset")),
        "actor": _values(event, raw, ("user.name", "account.name", "session.id")),
        "path": _values(event, raw, ("file.path", "process.executable", "target.file.path")),
        "signals": signals,
    }


def _derived_signals(text: str, raw: dict[str, Any]) -> set[str]:
    signals: set[str] = set()
    patterns = {
        "download": ("curl http", "wget http", "downloadstring", "invoke-webrequest", "bitsadmin"),
        "execute": ("process.command_line", " /bin/sh", "cmd.exe", "powershell", "bash ", "python"),
        "chmod": ("chmod +x", "chmod 7", "chmod u+x"),
        "archive": ("tar ", "zip ", "7z ", "compress-archive", ".zip", ".tar"),
        "upload": (" upload", "curl -t", "curl --upload", "http.request.method post", "scp "),
        "sensitive_read": ("/etc/shadow", "ntds.dit", "sam save", "security save", "credential"),
        "credential_access": ("mimikatz", "sekurlsa", "lsass", "/etc/shadow", "credential dump"),
        "logging_impairment": ("wevtutil cl", "clear-eventlog", "systemctl stop auditd", "auditpol /clear", "log deletion"),
        "persistence": ("schtasks /create", "new-service", "systemctl enable", "crontab", "currentversion\\run", "launchctl"),
        "remote_login": ("sshd", "rdp", "logon type 10", "remote authentication", "winrm"),
        "discovery": ("whoami", "uname -a", "get-aduser", "net user", "ipconfig", "ifconfig", "sudo -l"),
        "remote_service": ("smb", "rdp", "winrm", "wmi", "ssh", "psexec", "remote service"),
        "temp_execution": ("/tmp/", "/dev/shm/", "\\temp\\"),
        "security_change": ("disable", "exclusion", "firewall", "audit policy", "tamper"),
        "privilege_change": ("sudo ", "setuid", "admin group", "role assignment", "special privileges"),
        "new_user": ("useradd", "net user /add", "account created"),
        "admin_group": ("administrators", "sudoers", "domain admins", "admin group"),
        "service_creation": ("new-service", "sc.exe create", "service installed"),
        "network_connection": ("destination.ip", "ip.dst", "outbound connection"),
        "pty_upgrade": ("pty.spawn(", "script /dev/null", "socat exec:"),
        "event_log_clear": ("wevtutil cl", "clear-eventlog", "event log clear"),
        "audit_stop": ("systemctl stop auditd", "service auditd stop", "audit stop"),
        "firewall_drop": ("iptables", " -j drop", "ufw deny", "firewall drop"),
        "c2": ("beacon", "command-and-control", "reverse shell", "/dev/tcp/"),
        "scan": ("nmap", "masscan", "port scan"),
        "exploit_response": ("exploit", "ids alert", "http 500", "segmentation fault"),
        "ids_alert": ("suricata", "snort", "ids alert"),
        "host_behavior": ("process.command_line", "process.executable", "endpoint execution"),
        "failed_attempts": ("failed login", "authentication failure", "event.code 4625"),
        "alternate_method_success": ("successful login", "authentication success", "event.code 4624"),
        "shell": ("/bin/sh", "/bin/bash", "cmd.exe", "powershell"),
    }
    for signal, needles in patterns.items():
        if any(needle in text for needle in needles):
            signals.add(signal)
    if _nested(raw, "process.command_line") is not None or _nested(raw, "process.executable") is not None:
        signals.update(("execute", "host_behavior"))
    if any(_nested(raw, field) is not None for field in ("source.ip", "destination.ip", "ip.src", "ip.dst")):
        signals.add("network_connection")
    event_code = str(_nested(raw, "event.code") or _nested(raw, "winlog.event_id") or "")
    event_outcome = str(_nested(raw, "event.outcome") or "").lower()
    if event_code == "4625" or event_outcome in {"failure", "failed"}:
        signals.add("failed_attempts")
    if event_code == "4624" or event_outcome in {"success", "succeeded"}:
        signals.add("alternate_method_success")
    command = text.strip()
    exact_commands = {
        "id": r"(?:^|\s)id(?:\s|$)", "whoami": r"\bwhoami\b", "groups": r"\bgroups\b",
        "sudo": r"\bsudo\s+-l\b", "uname": r"\buname\s+-a\b", "os_release": r"/etc/os-release",
        "find_suid": r"find.+-perm.+(?:4000|/u=s)", "getcap": r"\bgetcap\s+-r\b",
        "list_cron": r"\b(?:crontab\s+-l|ls\s+/etc/cron)", "list_services": r"\b(?:systemctl\s+list|service\s+--status)"
    }
    for signal, pattern in exact_commands.items():
        if re.search(pattern, command):
            signals.add(signal)
    if _nested(raw, "file.path"):
        signals.add("write_local")
    return signals


def _source_family(event: dict[str, Any], raw: dict[str, Any]) -> str:
    return evidence_source_family(event, raw)


def _values(event: dict[str, Any], raw: dict[str, Any], fields: tuple[str, ...], fallback: Any = None) -> set[str]:
    out: set[str] = set()
    for field in fields:
        value = _nested(raw, field)
        if value is None:
            value = _nested(event, field)
        for item in value if isinstance(value, list) else [value]:
            if item is not None and str(item).strip():
                out.add(str(item).strip().lower().replace("\\", "/"))
    if fallback is not None and str(fallback).strip():
        out.add(str(fallback).strip().lower())
    return out


def _nested(value: dict[str, Any], path: str) -> Any:
    if isinstance(value, dict) and path in value:
        return value[path]
    current: Any = value
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _strings(value: Any) -> list[str]:
    if isinstance(value, dict):
        return [item for nested in value.values() for item in _strings(nested)]
    if isinstance(value, list):
        return [item for nested in value for item in _strings(nested)]
    return [str(value)] if value is not None else []


def _time(value: Any) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)
    except (TypeError, ValueError):
        return datetime.min.replace(tzinfo=timezone.utc)
