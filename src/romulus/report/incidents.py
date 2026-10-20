"""Deterministic incident graph projection from persisted findings and expansion links."""
from __future__ import annotations

from collections import defaultdict

from romulus.detect.registry import ALL_PLAYBOOKS
from romulus.store.db import digest
from romulus.store.repo import Repo

_PLAYBOOKS = {playbook.id: playbook for playbook in ALL_PLAYBOOKS}
_TACTICS = {
    "T1190": ("initial-access",),
    "T1078": ("initial-access", "persistence", "privilege-escalation", "defense-evasion"),
    "T1059": ("execution",), "T1059.004": ("execution",), "T1059.006": ("execution",),
    "T1505.003": ("persistence",), "T1098.004": ("persistence",),
    "T1003.008": ("credential-access",), "T1021.004": ("lateral-movement",),
    "T1033": ("discovery",), "T1082": ("discovery",), "T1016": ("discovery",),
    "T1087": ("discovery",), "T1069": ("discovery",), "T1046": ("discovery",),
    "T1036.005": ("defense-evasion",), "T1562.004": ("defense-evasion",),
    "T1105": ("command-and-control",), "T1071": ("command-and-control",),
    "T1071.001": ("command-and-control",), "T1095": ("command-and-control",),
    "T1571": ("command-and-control",), "T1029": ("command-and-control",),
    "T1573": ("command-and-control",), "T1498": ("impact",),
    "T1590.002": ("reconnaissance",), "T1595.001": ("reconnaissance",),
    "T1595.002": ("reconnaissance",), "T1595.003": ("reconnaissance",),
}


def _entity_id(kind: str, value: str) -> str:
    return "E-" + digest({"kind": kind, "value": value})[:16]


def build_incident_graph(repo: Repo, hunt_id: str, findings: list[dict]) -> dict:
    """Observed expansion edges form components; inferred edges remain visible suggestions."""
    finding_by_id = {finding["id"]: finding for finding in findings}
    nodes = [{
        "id": finding["id"], "kind": "finding", "lane": finding["lane"],
        "observed_at": finding["observed_at"], "rule_id": finding["rule_id"],
    } for finding in findings]
    entity_nodes = {}
    finding_entities: dict[str, list[str]] = defaultdict(list)
    for finding in findings:
        for kind, value, _role in finding.get("entities") or []:
            node_id = _entity_id(str(kind), str(value))
            entity_nodes[node_id] = {"id": node_id, "kind": "entity", "entity_kind": kind, "value": value}
            finding_entities[finding["id"]].append(node_id)
    nodes.extend(entity_nodes[key] for key in sorted(entity_nodes))

    children: dict[str, list[str]] = defaultdict(list)
    for finding in findings:
        if finding.get("source_link_id"):
            children[finding["source_link_id"]].append(finding["id"])
    links = []
    edges = []
    for row in sorted(repo.expansion_links(hunt_id), key=lambda item: (
            item["anchor_id"], item["link_type"], item["window_start"], item["id"])):
        targets = sorted(children.get(row["id"], []))
        links.append({
            "id": row["id"], "anchor_finding_id": row["anchor_id"],
            "target_finding_ids": targets, "link_type": row["link_type"],
            "style": row["strength"], "key": row["key"], "status": row["status"],
            "window": {"label": row["window_label"], "start": str(row["window_start"]),
                       "end": str(row["window_end"])},
            "evidence_ids": row["evidence_ids"], "coverage": row["coverage"], "reasons": row["reasons"],
        })
        edges.extend({
            "id": f"{row['id']}:{target}", "from": row["anchor_id"], "to": target,
            "link_id": row["id"], "link_type": row["link_type"], "style": row["strength"],
        } for target in targets if row["anchor_id"] in finding_by_id and target in finding_by_id)

    parent = {finding_id: finding_id for finding_id in finding_by_id}

    def find(item):
        while parent[item] != item:
            parent[item] = parent[parent[item]]
            item = parent[item]
        return item

    def union(left, right):
        left_root, right_root = find(left), find(right)
        if left_root != right_root:
            parent[max(left_root, right_root)] = min(left_root, right_root)

    for edge in edges:
        if edge["style"] == "observed":
            union(edge["from"], edge["to"])
    components: dict[str, list[str]] = defaultdict(list)
    for finding_id in sorted(finding_by_id):
        components[find(finding_id)].append(finding_id)

    anchor_by_id = {row["id"]: row for row in repo.expansion_anchors(hunt_id)}
    incidents = []
    for finding_ids in components.values():
        finding_ids.sort(key=lambda item: (finding_by_id[item]["observed_at"], item))
        member_set = set(finding_ids)
        incoming = {edge["to"] for edge in edges if edge["style"] == "observed"
                    and edge["from"] in member_set and edge["to"] in member_set}
        entry_candidates = [item for item in finding_ids if item not in incoming]
        entry_point = entry_candidates[0] if entry_candidates else finding_ids[0]
        techniques = sorted({technique for item in finding_ids
                             for technique in getattr(_PLAYBOOKS.get(finding_by_id[item]["rule_id"]), "attack", ())})
        tactics = sorted({tactic for technique in techniques for tactic in _TACTICS.get(technique, ())})
        entity_ids = sorted({entity for item in finding_ids for entity in finding_entities[item]})
        hosts = sorted({str(entity_nodes[item]["value"]) for item in entity_ids
                        if entity_nodes[item]["entity_kind"] == "host"})
        accounts = sorted({str(entity_nodes[item]["value"]) for item in entity_ids
                           if entity_nodes[item]["entity_kind"] == "account"})
        incident_links = [link for link in links if link["anchor_finding_id"] in member_set]
        unexpanded = [{"anchor_id": item, "reasons": anchor_by_id[item]["reasons"]}
                      for item in finding_ids if item in anchor_by_id
                      and anchor_by_id[item]["status"] == "unexpanded"]
        unresolved = [{"link_id": link["id"], "status": link["status"], "reasons": link["reasons"]}
                      for link in incident_links if link["status"] != "complete"]
        incidents.append({
            "id": "I-" + digest(finding_ids)[:12], "finding_ids": finding_ids,
            "entity_node_ids": entity_ids, "timeline": finding_ids, "entry_point": entry_point,
            "attack_techniques": techniques, "attack_tactics": tactics,
            "hosts": hosts, "accounts": accounts,
            "link_ids": [link["id"] for link in incident_links],
            "observed_edges": sum(edge["style"] == "observed" and edge["from"] in member_set
                                  for edge in edges),
            "inferred_edges": sum(edge["style"] == "inferred" and edge["from"] in member_set
                                  for edge in edges),
            "open_ends": {"unexpanded_anchors": unexpanded, "unresolved_links": unresolved},
        })
    incidents.sort(key=lambda incident: (finding_by_id[incident["finding_ids"][0]]["observed_at"], incident["id"]))
    return {"nodes": nodes, "edges": edges, "links": links, "incidents": incidents}
