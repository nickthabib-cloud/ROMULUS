"""Conservative cross-domain correlation over normalized entity roles."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def correlate(host_events: list[dict[str, Any]], network_events: list[dict[str, Any]], window_seconds: int = 300) -> list[dict[str, Any]]:
    """Correlate on typed entities, close time, and compatible behavior.

    IP/time proximity alone remains a lead. Multiple reasons are retained so the
    report can distinguish a strong entity/session link from a weak overlap.
    """
    out = []
    seen = set()
    for host in host_events:
        ht = _time(host.get("observed_at") or _pick(host, "@timestamp", "timestamp", "event.created"))
        if ht is None: continue
        h = _entities(host)
        for network in network_events:
            nt = _time(network.get("observed_at") or _pick(network, "firstPacket", "frame.time_epoch", "@timestamp"))
            if nt is None: continue
            delta = abs(int((nt - ht).total_seconds()))
            if delta > window_seconds: continue
            n = _entities(network)
            reasons = []
            shared_ips = sorted((h["host_ips"] | h["source_ips"] | h["destination_ips"]) &
                                (n["source_ips"] | n["destination_ips"] | n["host_ips"]))
            shared_names = sorted((h["hostnames"] | h["domains"]) & (n["hostnames"] | n["domains"]))
            shared_users = sorted(h["users"] & n["users"])
            if shared_ips: reasons.append("shared typed IP: " + ", ".join(shared_ips[:3]))
            if shared_names: reasons.append("shared hostname/domain: " + ", ".join(shared_names[:2]))
            if shared_users: reasons.append("shared user: " + ", ".join(shared_users[:2]))
            if not reasons or not _behavior_match(host, network): continue
            score = min(1.0, 0.35 + 0.15 * len(reasons) + 0.25 * max(0, 1 - delta / max(1, window_seconds)))
            key = (host.get("evidence_id"), network.get("evidence_id"))
            if key in seen: continue
            seen.add(key)
            out.append({"host_ref": key[0], "network_ref": key[1], "ip": shared_ips[0] if shared_ips else "",
                        "delta_seconds": delta, "score": round(score, 2), "reasons": reasons,
                        "direction": _direction(h, n),
                        "caveat": "Validate identity, clock alignment, NAT, DHCP, and process/session attribution before treating this as one actor or action."})
    return sorted(out, key=lambda x: (-x["score"], x["delta_seconds"]))[:500]


def _entities(event: dict) -> dict[str, set[str]]:
    return {
        "host_ips": set(_values(event, "host.ip", "related.ip")),
        "source_ips": set(_values(event, "source.ip", "srcIp", "src_ip", "ip.src", "ipSource")),
        "destination_ips": set(_values(event, "destination.ip", "dstIp", "dst_ip", "ip.dst", "ipDestination")),
        "hostnames": {x.lower() for x in _values(event, "host.name", "host.hostname", "computer_name", "hostname")},
        "domains": {x.lower() for x in _values(event, "dns.question.name", "dns.qry.name", "dns.host", "http.host", "host.http", "tls.handshake.extensions_server_name")},
        "users": {x.lower() for x in _values(event, "user.name", "winlog.event_data.SubjectUserName", "account.name")},
    }


def _values(event: dict, *fields: str) -> list[str]:
    raw = event.get("raw") if isinstance(event.get("raw"), dict) else {}
    values = []
    for field in fields:
        value = _nested(raw, field)
        if value is None: value = raw.get(field)
        if value is None: value = _nested(event, field)
        for item in value if isinstance(value, list) else [value]:
            if item is not None and str(item).strip() and str(item) not in values: values.append(str(item))
    asset = event.get("asset")
    if asset and any(x.startswith("host.") for x in fields) and str(asset) not in values: values.append(str(asset))
    return values


def _pick(event: dict, *fields: str):
    values = _values(event, *fields)
    return values[0] if values else None


def _nested(value: Any, path: str):
    for part in path.split("."):
        if not isinstance(value, dict): return None
        value = value.get(part)
    return value


def _time(value: Any):
    if not value: return None
    try:
        numeric = float(value)
        if numeric > 10_000_000_000: numeric /= 1000
        return datetime.fromtimestamp(numeric, tz=timezone.utc)
    except (ValueError, TypeError, OSError, OverflowError): pass
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)
    except (ValueError, TypeError): return None


def _behavior_match(host: dict[str, Any], network: dict[str, Any]) -> bool:
    host_text = (str(host.get("observation", "")) + " " + str(host.get("raw", {}))).lower()
    net_text = (str(network.get("observation", "")) + " " + str(network.get("raw", {}))).lower()
    host_families = {
        "auth": ("4624", "4625", "logon", "authentication", "accepted password"),
        "remote": ("7045", "service", "powershell", "wmi", "ssh", "scheduled task"),
        "web": ("wget", "curl", "download", "http", "dns", "tls"),
        "discovery": ("nmap", "masscan", "ping", "net view", "arp -a"),
    }
    net_families = {
        "auth": ("3389", "22", "445", "5985", "5986", "rdp", "ssh", "smb", "winrm"),
        "remote": ("445", "135", "5985", "5986", "smb", "dcom", "winrm"),
        "web": ("dns", "http", "tls", "80", "443"),
        "discovery": ("icmp", "syn", "network connection"),
    }
    return any(any(term in host_text for term in host_families[name]) and any(term in net_text for term in net_families[name])
               for name in host_families)


def _direction(host: dict[str, set[str]], network: dict[str, set[str]]) -> str:
    if host["host_ips"] & network["source_ips"]: return "host_as_network_source"
    if host["host_ips"] & network["destination_ips"]: return "host_as_network_destination"
    return "role_unresolved"
