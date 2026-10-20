"""Deterministic incident graph projection from persisted findings and expansion links."""
from __future__ import annotations

from collections import defaultdict

from romulus.detect.registry import ALL_PLAYBOOKS
from romulus.store.db import digest
from romulus.store.repo import Repo

_PLAYBOOKS = {playbook.id: playbook for playbook in ALL_PLAYBOOKS}
# Rules whose one finding groups events of different processes, flows or sessions by a rule key. Two anchors
# that each reach a different member of the group are not thereby related, so such a finding is a leaf: it
# joins an incident only when everything it is observed-linked to is already one incident.
GROUPING_KINDS = frozenset({"aggregate", "packet"})


def _groups(rule_id: str) -> bool:
    return getattr(_PLAYBOOKS.get(rule_id), "kind", "direct") in GROUPING_KINDS
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


def _title(rule_id: str) -> str:
    return getattr(_PLAYBOOKS.get(rule_id), "title", None) or rule_id


def incident_narrative(incident: dict, finding_by_id: dict[str, dict], edges: list[dict]) -> list[dict]:
    """A deterministic account of one incident, built from typed fields only (ADR-006 template narrative).
    Each sentence carries its citations and a kind: `observed` (what the cited findings record), `mapping`
    (rule metadata such as ATT&CK tactics), `hypothesis` (inferred links) or `gap` (what is not known)."""
    members = incident["timeline"]
    first, last = finding_by_id[members[0]], finding_by_id[members[-1]]
    where = ", ".join(incident["hosts"]) or "no recorded host"
    who = f" involving account(s) {', '.join(incident['accounts'])}" if incident["accounts"] else ""
    sentences = [{
        "text": (f"{len(members)} finding(s) on {where}{who}, from {first['observed_at']} to "
                 f"{last['observed_at']}."),
        "cites": list(members), "kind": "observed",
    }]
    entry = finding_by_id[incident["entry_point"]]
    sentences.append({
        "text": f"It begins with {_title(entry['rule_id'])} ({entry['lane']}) at {entry['observed_at']}.",
        "cites": [entry["id"]], "kind": "observed",
    })
    member_set = set(members)
    observed_into: dict[str, dict] = {}
    for edge in sorted(edges, key=lambda e: (e["from"], e["to"], e["link_id"])):
        if edge["style"] == "observed" and edge["from"] in member_set and edge["to"] in member_set:
            observed_into.setdefault(edge["to"], edge)
    for item in members:
        if item == entry["id"]:
            continue
        finding = finding_by_id[item]
        edge = observed_into.get(item)
        how = (f", reached from {edge['from']} by an observed {edge['link_type'].replace('_', ' ')} link"
               if edge else "")
        sentences.append({
            "text": f"Then {_title(finding['rule_id'])} ({finding['lane']}) at {finding['observed_at']}{how}.",
            "cites": [item] + ([edge["from"]] if edge else []), "kind": "observed",
        })
    if incident["attack_tactics"]:
        sentences.append({
            "text": f"Rule mappings place these steps in ATT&CK tactic(s): {', '.join(incident['attack_tactics'])}.",
            "cites": list(members), "kind": "mapping",
        })
    inferred = sorted({(e["from"], e["to"], e["link_type"]) for e in edges
                       if e["style"] == "inferred" and e["from"] in member_set})
    if inferred:
        listed = "; ".join(f"{a} to {b} ({t.replace('_', ' ')})" for a, b, t in inferred[:8])
        more = f" and {len(inferred) - 8} more" if len(inferred) > 8 else ""
        sentences.append({
            "text": (f"{len(inferred)} inferred link(s) from this incident remain hypotheses, not shown to be the "
                     f"same actor: {listed}{more}."),
            "cites": sorted({x for a, b, _t in inferred for x in (a, b)}), "kind": "hypothesis",
        })
    ends = incident["open_ends"]
    gaps = (len(ends["unexpanded_anchors"]) + len(ends["pending_anchors"]), len(ends["unresolved_links"]))
    if any(gaps):
        sentences.append({
            "text": (f"This account may be incomplete: {gaps[0]} anchor(s) were not expanded and {gaps[1]} link(s) "
                     f"were not fully resolved."),
            "cites": [], "kind": "gap",
        })
    return sentences


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
    findings_by_event: dict[str, set[str]] = defaultdict(set)
    for finding in findings:
        if finding.get("source_link_id"):
            children[finding["source_link_id"]].append(finding["id"])
        cited = set(finding.get("event_ids") or [])
        cited.update(citation["event_id"] for citation in finding.get("citations") or [])
        for event_id in cited:
            findings_by_event[event_id].add(finding["id"])
    links = []
    edges = []
    for row in sorted(repo.expansion_links(hunt_id), key=lambda item: (
            item["anchor_id"], item["link_type"], item["window_start"], item["id"])):
        targets = set(children.get(row["id"], []))
        for event_id in row["event_ids"]:
            targets.update(findings_by_event.get(event_id, ()))
        targets.discard(row["anchor_id"])
        targets = sorted(targets)
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

    observed = [edge for edge in edges if edge["style"] == "observed"]
    grouping = {item for item, finding in finding_by_id.items() if _groups(finding["rule_id"])}
    for edge in observed:
        if edge["from"] not in grouping and edge["to"] not in grouping:
            union(edge["from"], edge["to"])
    for item in sorted(grouping):
        neighbours = {find(edge["to"] if edge["from"] == item else edge["from"]) for edge in observed
                      if item in (edge["from"], edge["to"])
                      and (edge["to"] if edge["from"] == item else edge["from"]) not in grouping}
        if len(neighbours) == 1:
            union(item, next(iter(neighbours)))
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
        pending = [{"anchor_id": item, "reasons": anchor_by_id[item]["reasons"]}
                   for item in finding_ids if item in anchor_by_id
                   and anchor_by_id[item]["status"] == "pending"]
        unresolved = [{"link_id": link["id"], "status": link["status"], "reasons": link["reasons"]}
                      for link in incident_links if link["status"] != "complete"]
        incident = {
            "id": "I-" + digest(finding_ids)[:12], "finding_ids": finding_ids,
            "entity_node_ids": entity_ids, "timeline": finding_ids, "entry_point": entry_point,
            "attack_techniques": techniques, "attack_tactics": tactics,
            "hosts": hosts, "accounts": accounts,
            "link_ids": [link["id"] for link in incident_links],
            "observed_edges": sum(edge["style"] == "observed" and edge["from"] in member_set
                                  for edge in edges),
            "inferred_edges": sum(edge["style"] == "inferred" and edge["from"] in member_set
                                  for edge in edges),
            "open_ends": {"unexpanded_anchors": unexpanded, "pending_anchors": pending,
                          "unresolved_links": unresolved},
        }
        incident["narrative"] = incident_narrative(incident, finding_by_id, edges)
        incidents.append(incident)
    incidents.sort(key=lambda incident: (finding_by_id[incident["finding_ids"][0]]["observed_at"], incident["id"]))
    return {"nodes": nodes, "edges": edges, "links": links, "incidents": incidents}
