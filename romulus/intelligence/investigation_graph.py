"""Deterministic evidence, entity, and activity graph construction.

The graph is deliberately model-independent.  A record may establish facts
inside that record; relationships between records are labeled as inferences
and retain the evidence and caveats that produced them.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
import hashlib
import ipaddress
from typing import Any


INFERENCE_CAVEAT = "Temporal or entity association is an investigative lead, not causation."


def build_investigation_graph(
    evidence: list[dict[str, Any]],
    correlations: list[dict[str, Any]] | None = None,
    temporal_window_seconds: int = 1800,
) -> dict[str, Any]:
    """Build a stable compact graph from normalized evidence and correlations."""
    nodes: dict[str, dict[str, Any]] = {}
    edges: dict[tuple[str, str, str], dict[str, Any]] = {}
    activity_by_evidence: dict[str, str] = {}
    activity_times: dict[str, datetime | None] = {}
    entity_activities: dict[str, list[str]] = defaultdict(list)

    events = sorted(
        (event for event in evidence if isinstance(event, dict) and event.get("evidence_id")),
        key=lambda event: str(event.get("evidence_id")),
    )
    for event in events:
        evidence_id = str(event["evidence_id"])
        evidence_node_id = f"evidence:{evidence_id}"
        activity_node_id = f"activity:{evidence_id}"
        observed_at = str(event.get("observed_at") or "")
        nodes[evidence_node_id] = {
            "node_id": evidence_node_id,
            "node_type": "evidence",
            "evidence_id": evidence_id,
            "source": str(event.get("source") or "unknown"),
            "observed_at": observed_at,
            "observation": str(event.get("observation") or "")[:500],
        }
        nodes[activity_node_id] = {
            "node_id": activity_node_id,
            "node_type": "activity",
            "activity_type": _activity_type(event),
            "label": str(event.get("observation") or "Observed activity")[:240],
            "observed_at": observed_at,
            "evidence_ids": [evidence_id],
        }
        activity_by_evidence[evidence_id] = activity_node_id
        activity_times[activity_node_id] = _time(observed_at)
        _add_edge(
            edges, evidence_node_id, activity_node_id, "supports", "observed",
            [evidence_id], "high", ["The activity is normalized from this source record."], [], 0,
        )

        for entity_type, normalized_value, relationship in _entities(event):
            entity_node_id = _entity_id(entity_type, normalized_value)
            nodes.setdefault(entity_node_id, {
                "node_id": entity_node_id,
                "node_type": "entity",
                "entity_type": entity_type,
                "normalized_value": normalized_value,
                "label": normalized_value,
            })
            _add_edge(
                edges, activity_node_id, entity_node_id, relationship, "observed",
                [evidence_id], "high", [f"The source record contains this {entity_type}."], [], None,
            )
            if activity_node_id not in entity_activities[entity_node_id]:
                entity_activities[entity_node_id].append(activity_node_id)

    for entity_node_id, activity_ids in sorted(entity_activities.items()):
        ordered = sorted(
            (activity_id for activity_id in activity_ids if activity_times.get(activity_id) is not None),
            key=lambda activity_id: (activity_times[activity_id], activity_id),
        )
        for left, right in zip(ordered, ordered[1:]):
            delta = int((activity_times[right] - activity_times[left]).total_seconds())
            if delta < 0 or delta > temporal_window_seconds:
                continue
            entity = nodes[entity_node_id]
            left_ref = left.removeprefix("activity:")
            right_ref = right.removeprefix("activity:")
            _add_edge(
                edges, left, right, "precedes_with_shared_entity", "inferred",
                [left_ref, right_ref], "low",
                [f"Both records contain {entity['entity_type']} {entity['normalized_value']} within {delta} seconds."],
                [INFERENCE_CAVEAT], delta,
            )

    for correlation in sorted(correlations or [], key=_correlation_key):
        host_ref = str(correlation.get("host_ref") or "")
        network_ref = str(correlation.get("network_ref") or "")
        if host_ref not in activity_by_evidence or network_ref not in activity_by_evidence:
            continue
        host_activity = activity_by_evidence[host_ref]
        network_activity = activity_by_evidence[network_ref]
        source, target = _ordered_activities(host_activity, network_activity, activity_times)
        score = float(correlation.get("score") or 0)
        caveats = [INFERENCE_CAVEAT]
        if correlation.get("caveat"):
            caveats.append(str(correlation["caveat"]))
        _add_edge(
            edges, source, target, "possibly_related", "inferred",
            [host_ref, network_ref], "moderate" if score >= 0.65 else "low",
            [str(reason) for reason in correlation.get("reasons", []) if str(reason).strip()],
            caveats, _integer_or_none(correlation.get("delta_seconds")),
        )

    ordered_nodes = sorted(nodes.values(), key=lambda node: node["node_id"])
    ordered_edges = sorted(edges.values(), key=lambda edge: edge["edge_id"])
    return {
        "version": 1,
        "nodes": ordered_nodes,
        "edges": ordered_edges,
        "paths": [],
        "summary": {
            "evidence_nodes": sum(node["node_type"] == "evidence" for node in ordered_nodes),
            "activity_nodes": sum(node["node_type"] == "activity" for node in ordered_nodes),
            "entity_nodes": sum(node["node_type"] == "entity" for node in ordered_nodes),
            "observed_edges": sum(edge["basis"] == "observed" for edge in ordered_edges),
            "inferred_edges": sum(edge["basis"] == "inferred" for edge in ordered_edges),
        },
    }


def derive_finding_paths(
    graph: dict[str, Any], findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Derive ordered, possibly disconnected path segments from cited evidence only."""
    nodes = {node.get("node_id"): node for node in graph.get("nodes", []) if node.get("node_id")}
    cross_edges = [
        edge for edge in graph.get("edges", [])
        if edge.get("basis") == "inferred"
        and str(edge.get("source", "")).startswith("activity:")
        and str(edge.get("target", "")).startswith("activity:")
    ]
    entity_edges = [
        edge for edge in graph.get("edges", [])
        if edge.get("basis") == "observed"
        and str(edge.get("source", "")).startswith("activity:")
        and str(edge.get("target", "")).startswith("entity:")
    ]
    paths: list[dict[str, Any]] = []
    for finding in sorted(findings or [], key=lambda item: str(item.get("finding_id") or "")):
        finding_id = str(finding.get("finding_id") or "")
        cited = sorted({str(value) for value in finding.get("evidence_ids", []) if str(value).strip()})
        selected = {
            f"activity:{evidence_id}" for evidence_id in cited
            if f"activity:{evidence_id}" in nodes
        }
        if not finding_id or not selected:
            continue
        adjacency: dict[str, set[str]] = {activity_id: set() for activity_id in selected}
        for edge in cross_edges:
            source, target = edge.get("source"), edge.get("target")
            if source in selected and target in selected:
                adjacency[source].add(target)
                adjacency[target].add(source)
        components: list[list[str]] = []
        remaining = set(selected)
        while remaining:
            start = min(remaining)
            stack = [start]
            component: set[str] = set()
            while stack:
                current = stack.pop()
                if current in component:
                    continue
                component.add(current)
                stack.extend(sorted(adjacency[current] - component, reverse=True))
            remaining -= component
            components.append(sorted(component, key=lambda node_id: _activity_sort_key(nodes[node_id])))
        components.sort(key=lambda component: _activity_sort_key(nodes[component[0]]))
        gap = (
            f"Cited evidence forms {len(components)} disconnected segments; no supported relationship joins them."
            if len(components) > 1 else ""
        )
        for index, component in enumerate(components, 1):
            component_set = set(component)
            relationships = sorted(
                (
                    _path_relationship(edge)
                    for edge in cross_edges
                    if edge.get("source") in component_set and edge.get("target") in component_set
                ),
                key=lambda edge: (
                    0 if edge["relationship"] == "possibly_related" else 1,
                    edge["source_sequence"], edge["target_sequence"], edge["edge_id"],
                ),
            )
            sequence_by_activity = {activity_id: sequence for sequence, activity_id in enumerate(component, 1)}
            for relationship in relationships:
                relationship["source_sequence"] = sequence_by_activity[relationship.pop("source")]
                relationship["target_sequence"] = sequence_by_activity[relationship.pop("target")]
            relationships.sort(key=lambda edge: (
                edge["source_sequence"], edge["target_sequence"],
                0 if edge["relationship"] == "possibly_related" else 1, edge["edge_id"],
            ))
            steps = [
                _path_step(activity_id, sequence, nodes, entity_edges)
                for sequence, activity_id in enumerate(component, 1)
            ]
            evidence_ids = sorted({value for step in steps for value in step["evidence_ids"]})
            digest = hashlib.sha1(
                f"{finding_id}|{'|'.join(evidence_ids)}".encode("utf-8")
            ).hexdigest()[:12].upper()
            caveats = sorted({
                caveat for relationship in relationships for caveat in relationship.get("caveats", [])
            })
            if len(steps) == 1:
                caveats.append("A single observed step does not establish a complete intrusion chain.")
            confidence = _path_confidence(relationships)
            paths.append({
                "path_id": f"PATH-{digest}",
                "finding_id": finding_id,
                "title": str(finding.get("title") or "Evidence-supported activity"),
                "segment_index": index,
                "segment_count": len(components),
                "confidence": confidence,
                "steps": steps,
                "relationships": relationships,
                "caveats": sorted(set(caveats)),
                "gaps": [gap] if gap else [],
            })
    return sorted(paths, key=lambda path: (path["finding_id"], path["segment_index"], path["path_id"]))


def _path_step(
    activity_id: str, sequence: int, nodes: dict[str, dict[str, Any]],
    entity_edges: list[dict[str, Any]],
) -> dict[str, Any]:
    activity = nodes[activity_id]
    entities = []
    for edge in entity_edges:
        if edge.get("source") != activity_id:
            continue
        entity = nodes.get(edge.get("target"), {})
        if entity.get("node_type") != "entity":
            continue
        entities.append({
            "entity_type": entity.get("entity_type"),
            "value": entity.get("normalized_value"),
            "relationship": edge.get("relationship"),
        })
    entities.sort(key=lambda value: (str(value.get("entity_type")), str(value.get("value")), str(value.get("relationship"))))
    return {
        "sequence": sequence,
        "activity_node_id": activity_id,
        "activity_type": activity.get("activity_type"),
        "label": activity.get("label"),
        "observed_at": activity.get("observed_at"),
        "evidence_ids": sorted(activity.get("evidence_ids", [])),
        "entities": entities,
    }


def _path_relationship(edge: dict[str, Any]) -> dict[str, Any]:
    return {
        "edge_id": edge.get("edge_id"),
        "source": edge.get("source"),
        "target": edge.get("target"),
        "source_sequence": 0,
        "target_sequence": 0,
        "relationship": edge.get("relationship"),
        "basis": edge.get("basis"),
        "confidence": edge.get("confidence"),
        "time_delta_seconds": edge.get("time_delta_seconds"),
        "reasons": list(edge.get("reasons", [])),
        "caveats": list(edge.get("caveats", [])),
        "evidence_ids": list(edge.get("evidence_ids", [])),
    }


def _path_confidence(relationships: list[dict[str, Any]]) -> str:
    if not relationships:
        return "observed step only"
    ranks = {"low": 0, "moderate": 1, "high": 2}
    return min((str(edge.get("confidence") or "low") for edge in relationships), key=lambda value: ranks.get(value, 0))


def _activity_sort_key(activity: dict[str, Any]) -> tuple[datetime, str]:
    return _time(activity.get("observed_at")) or datetime.max.replace(tzinfo=timezone.utc), str(activity.get("node_id") or "")


def _entities(event: dict[str, Any]) -> list[tuple[str, str, str]]:
    raw = event.get("raw") if isinstance(event.get("raw"), dict) else {}
    definitions = (
        ("host", "occurred_on", ("host.name", "host.hostname", "computer_name", "hostname", "host")),
        ("ip", "initiated_from", ("source.ip", "src_ip", "srcIp", "ip.src", "ipSource")),
        ("ip", "targeted", ("destination.ip", "dst_ip", "dstIp", "ip.dst", "ipDestination")),
        ("ip", "associated_address", ("host.ip", "related.ip", "ip")),
        ("user", "used_account", ("user.name", "account.name", "winlog.event_data.SubjectUserName", "account", "username", "user")),
        ("process", "executed_process", ("process.name", "process.executable", "winlog.event_data.Image", "exe", "image")),
        ("process", "spawned_by", ("process.parent.name", "process.parent.executable", "winlog.event_data.ParentImage", "parent_process_name")),
        ("file", "affected_file", ("file.path", "file.name", "target.file.path", "winlog.event_data.TargetFilename", "path")),
        ("domain", "contacted_domain", ("dns.question.name", "dns.qry.name", "dns.host", "http.host", "host.http", "tls.handshake.extensions_server_name")),
        ("session", "part_of_session", ("session.id", "session_id", "id")),
        ("service", "changed_service", ("service.name", "winlog.event_data.ServiceName", "service")),
        ("task", "changed_task", ("task.name", "winlog.event_data.TaskName", "task")),
    )
    found: set[tuple[str, str, str]] = set()
    for entity_type, relationship, fields in definitions:
        for field in fields:
            value = _get(raw, field)
            if value is None:
                value = _get(event, field)
            for item in value if isinstance(value, list) else [value]:
                normalized = _normalize(entity_type, item)
                if normalized:
                    found.add((entity_type, normalized, relationship))
    asset = _normalize("ip" if _is_ip(event.get("asset")) else "host", event.get("asset"))
    if asset:
        entity_type = "ip" if _is_ip(asset) else "host"
        found.add((entity_type, asset, "involved_asset" if entity_type == "ip" else "occurred_on"))
    return sorted(found)


def _activity_type(event: dict[str, Any]) -> str:
    raw = event.get("raw") if isinstance(event.get("raw"), dict) else {}
    code = str(_first(raw, "event.code", "event.id", "winlog.event_id", "event_id") or "").lower()
    text = (str(event.get("observation") or "") + " " + str(raw)).lower()
    if code in {"4624", "4625", "4648", "4768", "4769", "4771", "4776"} or any(term in text for term in ("logon", "login", "authentication")):
        return "authentication"
    if code in {"4697", "7045"} or "service install" in text or "service creation" in text:
        return "service_change"
    if code in {"1", "4688"} or _first(raw, "process.name", "process.executable", "winlog.event_data.Image", "exe"):
        return "process_execution"
    if _first(raw, "dns.question.name", "dns.qry.name", "dns.host"):
        return "dns_resolution"
    if _first(raw, "source.ip", "src_ip", "srcIp", "ip.src") or _first(raw, "destination.ip", "dst_ip", "dstIp", "ip.dst"):
        return "network_connection"
    if _first(raw, "file.path", "file.name", "target.file.path", "winlog.event_data.TargetFilename"):
        return "file_change"
    return "observation"


def _add_edge(
    edges: dict[tuple[str, str, str], dict[str, Any]], source: str, target: str,
    relationship: str, basis: str, evidence_ids: list[str], confidence: str,
    reasons: list[str], caveats: list[str], delta_seconds: int | None,
) -> None:
    key = (source, target, relationship)
    if key in edges:
        edge = edges[key]
        edge["evidence_ids"] = sorted(set(edge["evidence_ids"]) | set(evidence_ids))
        edge["reasons"] = sorted(set(edge["reasons"]) | set(reasons))
        edge["caveats"] = sorted(set(edge["caveats"]) | set(caveats))
        return
    digest = hashlib.sha1("|".join(key).encode("utf-8")).hexdigest()[:12].upper()
    edges[key] = {
        "edge_id": f"EDGE-{digest}",
        "source": source,
        "target": target,
        "relationship": relationship,
        "basis": basis,
        "evidence_ids": sorted(set(evidence_ids)),
        "confidence": confidence,
        "reasons": sorted(set(reasons)),
        "caveats": sorted(set(caveats)),
        "time_delta_seconds": delta_seconds,
    }


def _entity_id(entity_type: str, normalized_value: str) -> str:
    digest = hashlib.sha1(f"{entity_type}|{normalized_value}".encode("utf-8")).hexdigest()[:12].upper()
    return f"entity:{entity_type}:{digest}"


def _normalize(entity_type: str, value: Any) -> str:
    if value is None or not str(value).strip():
        return ""
    text = str(value).strip()
    if entity_type == "ip":
        try:
            return str(ipaddress.ip_address(text))
        except ValueError:
            return ""
    if entity_type in {"host", "domain", "user", "process", "service", "task"}:
        return text.lower()
    return text


def _get(value: Any, path: str) -> Any:
    if not isinstance(value, dict):
        return None
    if path in value:
        return value[path]
    current = value
    for part in path.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


def _first(value: dict[str, Any], *paths: str) -> Any:
    for path in paths:
        item = _get(value, path)
        if item is not None:
            return item[0] if isinstance(item, list) and item else item
    return None


def _is_ip(value: Any) -> bool:
    try:
        ipaddress.ip_address(str(value))
        return True
    except ValueError:
        return False


def _time(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)
    except (TypeError, ValueError):
        return None


def _ordered_activities(left: str, right: str, times: dict[str, datetime | None]) -> tuple[str, str]:
    left_time = times.get(left)
    right_time = times.get(right)
    if left_time is not None and right_time is not None and right_time < left_time:
        return right, left
    return left, right


def _integer_or_none(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _correlation_key(value: dict[str, Any]) -> tuple[str, str]:
    return str(value.get("host_ref") or ""), str(value.get("network_ref") or "")
