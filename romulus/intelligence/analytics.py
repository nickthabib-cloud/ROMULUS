"""Deterministic behavioral summaries for analyst reasoning.

The model should reason over compact distributions and cited observations, not
an arbitrary handful of raw rows. These routines make no malicious/benign
decision; they describe rarity, fan-out, cadence, sequences, and data quality.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
import ipaddress
import math
import re
from typing import Any, Iterable


def summarize_evidence(host_events: list[dict], network_events: list[dict], limit: int = 12) -> dict[str, Any]:
    all_events = list(host_events) + list(network_events)
    source_counts = Counter(str(e.get("source") or "unknown") for e in all_events)
    times = [(stamp, e) for e in all_events if (stamp := _time(e.get("observed_at"))) is not None]
    host_assets = Counter(_values(e, ("host.name", "host.hostname", "host.ip"), include_asset=True)[0]
                          for e in host_events if _values(e, ("host.name", "host.hostname", "host.ip"), include_asset=True))
    processes = Counter(x.lower() for e in host_events for x in _values(e, ("process.name", "process.executable", "process.parent.name")))
    users = Counter(x.lower() for e in host_events for x in _values(e, ("user.name", "winlog.event_data.SubjectUserName", "account.name")))
    event_codes = Counter(x for e in host_events for x in _values(e, ("event.code", "event.id", "winlog.event_id", "event_id")))

    src_counts: Counter[str] = Counter()
    dst_counts: Counter[str] = Counter()
    port_counts: Counter[str] = Counter()
    protocol_counts: Counter[str] = Counter()
    domain_counts: Counter[str] = Counter()
    edge_counts: Counter[tuple[str, str, str]] = Counter()
    fanout: dict[str, set[str]] = defaultdict(set)
    fanout_ports: dict[str, set[str]] = defaultdict(set)
    edge_events: dict[tuple[str, str, str], list[dict]] = defaultdict(list)
    byte_rows: list[tuple[int, dict]] = []
    for event in network_events:
        srcs = _values(event, ("source.ip", "srcIp", "src_ip", "ip.src", "ipSource"))
        dsts = _values(event, ("destination.ip", "dstIp", "dst_ip", "ip.dst", "ipDestination"))
        ports = _values(event, ("destination.port", "dstPort", "dst_port", "tcp.dstport", "udp.dstport", "port"))
        protocols = _values(event, ("network.protocol", "network.transport", "network.application", "protocol", "protocols", "ipProtocol"))
        domains = _values(event, ("dns.question.name", "dns.qry.name", "dns.host", "http.host", "host.http", "tls.handshake.extensions_server_name"))
        src_counts.update(srcs); dst_counts.update(dsts); port_counts.update(ports)
        protocol_counts.update(x.lower() for x in protocols); domain_counts.update(x.lower() for x in domains)
        src = srcs[0] if srcs else "?"; dst = dsts[0] if dsts else "?"; port = ports[0] if ports else "?"
        if src != "?" and dst != "?":
            edge = (src, dst, port); edge_counts[edge] += 1; edge_events[edge].append(event)
            fanout[src].add(dst)
            if port != "?": fanout_ports[src].add(port)
        byte_value = _first_number(event, ("network.bytes", "totBytes", "bytes", "source.bytes", "destination.bytes"))
        if byte_value is not None: byte_rows.append((byte_value, event))

    authentication = _authentication_sequences(host_events, limit)
    periodic = _periodic_edges(edge_events, limit)
    high_fanout = []
    for src in sorted(fanout, key=lambda x: (len(fanout[x]), len(fanout_ports[x])), reverse=True)[:limit]:
        refs = [e.get("evidence_id") for edge, rows in edge_events.items() if edge[0] == src for e in rows[:1] if e.get("evidence_id")]
        high_fanout.append({"source": src, "unique_destinations": len(fanout[src]),
                            "unique_destination_ports": len(fanout_ports[src]), "sample_evidence_ids": refs[:4]})
    rare_external = []
    for destination, count in sorted(dst_counts.items(), key=lambda item: (item[1], item[0])):
        if count > 2 or not _external_ip(destination): continue
        refs = [e.get("evidence_id") for e in network_events if destination in _values(e, ("destination.ip", "dstIp", "dst_ip", "ip.dst")) and e.get("evidence_id")]
        rare_external.append({"destination": destination, "observations": count, "sample_evidence_ids": refs[:3]})
        if len(rare_external) >= limit: break

    signals = _behavior_signals(all_events, limit)
    quality = {
        "events_total": len(all_events),
        "timestamp_coverage_pct": _percent(len(times), len(all_events)),
        "host_entity_coverage_pct": _percent(sum(bool(_values(e, ("host.name", "host.hostname", "host.ip"), True)) for e in host_events), len(host_events)),
        "network_endpoint_coverage_pct": _percent(sum(bool(_values(e, ("source.ip", "srcIp", "ip.src"))) and bool(_values(e, ("destination.ip", "dstIp", "ip.dst"))) for e in network_events), len(network_events)),
    }
    return {
        "scope": {"host_events": len(host_events), "network_events": len(network_events),
                  "sources": dict(source_counts),
                  "first_observed": min((x[0] for x in times), default=None).isoformat() if times else None,
                  "last_observed": max((x[0] for x in times), default=None).isoformat() if times else None},
        "telemetry_quality": quality,
        "host_profile": {"top_assets": _top(host_assets, limit), "top_processes": _top(processes, limit),
                         "top_users": _top(users, limit), "top_event_codes": _top(event_codes, limit),
                         "authentication_sequences": authentication},
        "network_profile": {"top_sources": _top(src_counts, limit), "top_destinations": _top(dst_counts, limit),
                            "top_destination_ports": _top(port_counts, limit), "top_protocols": _top(protocol_counts, limit),
                            "top_domains": _top(domain_counts, limit), "high_fanout": high_fanout,
                            "low_frequency_external_destinations": rare_external, "periodic_edge_candidates": periodic,
                            "largest_byte_records": [{"bytes": value, "evidence_id": event.get("evidence_id")} for value, event in sorted(byte_rows, reverse=True, key=lambda x: x[0])[:limit]]},
        "behavioral_observations": signals,
    }


def build_coverage_ledger(hypotheses: list[dict], lead_catalog: list[dict], completed_leads: Iterable[str],
                          search_results: list[dict], host_available: bool, network_available: bool) -> dict[str, Any]:
    """Summarize closure status without letting queue exhaustion imply completion."""
    completed = set(completed_leads)
    results_by_id = {str(x.get("search_id") or x.get("lead_id")): x for x in search_results}
    rows = []
    for hypothesis in hypotheses:
        hid = hypothesis.get("hypothesis_id")
        planned = [x for x in lead_catalog if x.get("hypothesis_id") == hid]
        executed = [x for x in planned if x.get("id") in completed]
        sources = sorted({str(x.get("source")) for x in executed})
        result_rows = [results_by_id[x.get("id")] for x in executed if x.get("id") in results_by_id]
        returned = sum(int(x.get("returned", 0) or 0) for x in result_rows)
        assessment = hypothesis.get("model_assessment") if isinstance(hypothesis.get("model_assessment"), dict) else {}
        gaps = []
        needs_host = bool(hypothesis.get("expected_host")); needs_network = bool(hypothesis.get("expected_network"))
        if needs_host and not host_available: gaps.append("host telemetry unavailable")
        if needs_network and not network_available: gaps.append("network telemetry unavailable")
        searched = bool(executed)
        status = assessment.get("status") or ("searched_unassessed" if searched else "untested")
        closed = status in {"supported", "contradicted", "inconclusive"} or (searched and bool(gaps))
        rows.append({"hypothesis_id": hid, "technique_id": hypothesis.get("technique_id"),
                     "priority": hypothesis.get("priority", 3), "tactics": hypothesis.get("tactics", []),
                     "planned_analytics": len(planned), "executed_analytics": len(executed), "sources": sources,
                     "returned": returned, "assessment": status, "telemetry_gaps": gaps, "closed": closed})
    high = [x for x in rows if int(x.get("priority") or 3) >= 4]
    return {"rows": rows, "high_priority_total": len(high),
            "high_priority_tested": sum(x["executed_analytics"] > 0 or bool(x["telemetry_gaps"]) for x in high),
            "high_priority_closed": sum(bool(x["closed"]) for x in high),
            "untested_hypotheses": [x["hypothesis_id"] for x in rows if not x["executed_analytics"] and not x["telemetry_gaps"]],
            "closure_ready": bool(rows) and all(x["executed_analytics"] > 0 or bool(x["telemetry_gaps"]) for x in high)}


def _authentication_sequences(events: list[dict], limit: int) -> list[dict]:
    grouped: dict[tuple[str, str], list[tuple[datetime, str, str]]] = defaultdict(list)
    for event in events:
        code = next(iter(_values(event, ("event.code", "event.id", "winlog.event_id", "event_id"))), "")
        text = _event_text(event)
        outcome = "failure" if code == "4625" or any(x in text for x in ("failed logon", "authentication failure", "invalid password")) else (
            "success" if code == "4624" or any(x in text for x in ("successful logon", "accepted password", "accepted publickey")) else "")
        stamp = _time(event.get("observed_at"))
        if not outcome or stamp is None: continue
        user = next(iter(_values(event, ("user.name", "winlog.event_data.SubjectUserName"))), "unknown")
        source = next(iter(_values(event, ("source.ip", "winlog.event_data.IpAddress", "ip.src"))), "unknown")
        grouped[(user, source)].append((stamp, outcome, str(event.get("evidence_id") or "")))
    out = []
    for (user, source), rows in grouped.items():
        rows.sort(); failures = 0
        for stamp, outcome, ref in rows:
            if outcome == "failure": failures += 1; continue
            if failures:
                out.append({"user": user, "source": source, "failures_before_success": failures,
                            "success_at": stamp.isoformat(), "sample_evidence_id": ref})
            failures = 0
    return sorted(out, key=lambda x: x["failures_before_success"], reverse=True)[:limit]


def _periodic_edges(edge_events: dict[tuple[str, str, str], list[dict]], limit: int) -> list[dict]:
    out = []
    for edge, events in edge_events.items():
        rows = sorted(
            ((stamp, event) for event in events if (stamp := _time(event.get("observed_at"))) is not None),
            key=lambda row: (row[0], str(row[1].get("evidence_id") or "")),
        )
        if len(rows) < 4: continue
        intervals = [(rows[i][0] - rows[i - 1][0]).total_seconds() for i in range(1, len(rows))]
        mean = sum(intervals) / len(intervals)
        if mean <= 0: continue
        variance = sum((x - mean) ** 2 for x in intervals) / len(intervals)
        cv = math.sqrt(variance) / mean
        if cv <= 0.25:
            out.append({"source": edge[0], "destination": edge[1], "port": edge[2], "observations": len(rows),
                        "mean_interval_seconds": round(mean, 1), "interval_cv": round(cv, 3),
                        "sample_evidence_ids": [e.get("evidence_id") for _, e in rows[:3] if e.get("evidence_id")]})
    return sorted(out, key=lambda x: (x["interval_cv"], -x["observations"]))[:limit]


def _behavior_signals(events: list[dict], limit: int) -> list[dict]:
    families = {
        "transfer_or_download": ("wget", "curl", "certutil", "bitsadmin", "scp ", "download"),
        "discovery_or_scanning": ("linpeas", "systeminfo", "whoami", "net user", "nmap", "masscan", "arp -a"),
        "remote_execution_or_service": ("psexec", "wmic", "wsmprovhost", "schtasks", "service install", "sc.exe"),
        "credential_access": ("mimikatz", "secretsdump", "lsass", "/etc/shadow", "sam save"),
        "defense_impairment": ("disable defender", "wevtutil cl", "auditd stop", "clear-eventlog"),
        "tunneling_or_remote_access": ("chisel", "ngrok", "socat", "anydesk", "teamviewer", "screenconnect"),
        "staging_or_impact": ("7z ", "rar ", "tar ", "vssadmin delete", "wbadmin delete", "ransom"),
    }
    contextualized = [(event, _behavior_context(event)) for event in events]
    out = []
    for name, needles in families.items():
        matched = [event for event, text in contextualized if text and any(_word(text, needle) for needle in needles)]
        if matched:
            out.append({"analytic": name, "observations": len(matched),
                        "sample_evidence_ids": [e.get("evidence_id") for e in matched[:5] if e.get("evidence_id")],
                        "note": "Command or artifact-context seed match; validate execution, intent, and causal effects."})
    return sorted(out, key=lambda x: x["observations"], reverse=True)[:limit]


def _behavior_context(event: dict) -> str:
    """Return bounded command/artifact context without flattening unrelated text.

    Broad telemetry messages often contain software feature lists, signatures,
    documentation, or search expressions. Treating every mention as execution
    creates high-volume false signals. Prefer structured command fields and
    parse only bounded execution-oriented message fragments.
    """
    raw = event.get("raw") if isinstance(event.get("raw"), dict) else {}
    parts = _values(event, (
        "process.name", "process.executable", "process.command_line", "process.args",
        "winlog.event_data.Image", "winlog.event_data.CommandLine",
        "winlog.event_data.ParentCommandLine", "audit.command", "audit.exe",
    ))
    message = str(_nested(raw, "message") or raw.get("message") or "")
    dataset = " ".join(_values(event, ("event.dataset", "event.module"))).lower()
    record_type = " ".join(_values(event, ("audit.record_type",))).lower()
    event_codes = set(_values(event, ("event.code", "event.id", "winlog.event_id", "event_id")))

    if record_type in {"execve", "user_cmd", "proctitle"} or "audit" in dataset:
        arguments = []
        for match in re.finditer(r"\ba\d+=(?:\"([^\"]*)\"|'([^']*)'|(\S+))", message):
            value = next((group for group in match.groups() if group is not None), "")
            if value: arguments.append(value)
        if arguments:
            # Keep the executable and ordinary bounded arguments. This drops a
            # giant sed/grep pattern that merely enumerates tool names while
            # retaining direct execution and shell command strings.
            parts.extend(arg for index, arg in enumerate(arguments[:10]) if index == 0 or len(arg) <= 240)
        elif len(message) <= 800:
            parts.append(message)

    if event_codes & {"1", "4688"} and len(message) <= 2000:
        parts.append(message)

    command_match = re.search(r"(?:\bCOMMAND=|\bCommandLine\s*[:=])(.{1,600})", message, flags=re.IGNORECASE)
    if command_match:
        parts.append(command_match.group(1))

    parts.extend(_values(event, (
        "file.path", "file.name", "url.path", "http.request.uri", "http.uri",
        "smb2.filename", "dns.question.name", "dns.qry.name",
    )))
    return " ".join(str(value) for value in parts if str(value).strip())[:4000].lower()


def _values(event: dict, fields: tuple[str, ...], include_asset: bool = False) -> list[str]:
    raw = event.get("raw") if isinstance(event.get("raw"), dict) else {}
    out = []
    for field in fields:
        value = _nested(raw, field)
        if value is None: value = raw.get(field)
        if value is None: value = _nested(event, field)
        for item in value if isinstance(value, list) else [value]:
            if item is not None and str(item).strip() and str(item) not in out: out.append(str(item))
    if include_asset and event.get("asset") and str(event["asset"]) not in out: out.append(str(event["asset"]))
    return out


def _nested(value: Any, path: str) -> Any:
    for part in path.split("."):
        if not isinstance(value, dict): return None
        value = value.get(part)
    return value


def _event_text(event: dict) -> str:
    raw = event.get("raw") if isinstance(event.get("raw"), dict) else {}
    return (str(event.get("observation") or "") + " " + " ".join(str(x) for x in _flatten(raw))).lower()


def _flatten(value: Any, depth: int = 0):
    if depth > 4: return []
    if isinstance(value, dict):
        return [item for child in value.values() for item in _flatten(child, depth + 1)]
    if isinstance(value, list):
        return [item for child in value[:30] for item in _flatten(child, depth + 1)]
    return [value]


def _first_number(event: dict, fields: tuple[str, ...]) -> int | None:
    for value in _values(event, fields):
        try: return int(float(value))
        except (TypeError, ValueError): pass
    return None


def _time(value: Any) -> datetime | None:
    if not value: return None
    try:
        number = float(value)
        if number > 10_000_000_000: number /= 1000
        return datetime.fromtimestamp(number, tz=timezone.utc)
    except (TypeError, ValueError, OSError, OverflowError): pass
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)
    except (TypeError, ValueError): return None


def _external_ip(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
        return not (address.is_private or address.is_loopback or address.is_multicast or address.is_unspecified or address.is_link_local)
    except ValueError: return False


def _top(counter: Counter, limit: int) -> list[dict]:
    return [{"value": str(value), "count": count} for value, count in counter.most_common(limit) if str(value)]


def _percent(numerator: int, denominator: int) -> float | None:
    return round(100 * numerator / denominator, 1) if denominator else None


def _word(text: str, needle: str) -> bool:
    if any(x in needle for x in (" ", "/", ".")): return needle in text
    return bool(re.search(r"(?<![a-z0-9_])" + re.escape(needle) + r"(?![a-z0-9_])", text))
