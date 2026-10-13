"""Bounded, evidence-constrained possible-activity narrative admission."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import hashlib
import ipaddress
import json
import re
from typing import Any


_TOP_LEVEL_KEYS = {
    "no_coherent_narrative", "clusters", "unconnected_item_ids", "limitations",
}
_CLUSTER_KEYS = {
    "item_ids", "relationship_ids", "evidence_ids", "possible_sequence",
    "narrative", "confidence", "alternate_explanations", "missing_evidence",
}
_ISO_TIME = re.compile(
    r"\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2}(?:\.\d{1,9})?)?(?:Z|[+-]\d{2}:\d{2})\b"
)
_DOMAIN = re.compile(
    r"(?<![A-Za-z0-9_-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}(?![A-Za-z0-9_-])"
)
_CAUSAL_ASSERTION = re.compile(
    r"\b(?:caused?|therefore caused|resulted in|proves?|confirmed that|establishes that)\b",
    re.IGNORECASE,
)


def build_narrative_case(
    state: Mapping[str, Any], items: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Project at most 12 accepted report items and 48 of their owned facts."""
    source = state if isinstance(state, Mapping) else {}
    selected = sorted(
        (
            dict(item) for item in items
            if isinstance(item, Mapping)
            and item.get("item_id")
            and item.get("classification") in {"suspicious", "malicious"}
            and item.get("investigation_status") != "dismissed"
        ),
        key=lambda item: str(item.get("item_id")),
    )[:12]
    evidence_index = {
        str(row.get("evidence_id")): row
        for key in ("host", "network")
        for row in _mapping_rows(source.get(key))
        if row.get("evidence_id")
    }
    visible_evidence_ids: list[str] = []
    for item in selected:
        for evidence_id in _unique_strings(item.get("evidence_ids")):
            if evidence_id in evidence_index and evidence_id not in visible_evidence_ids:
                visible_evidence_ids.append(evidence_id)
                if len(visible_evidence_ids) >= 48:
                    break
        if len(visible_evidence_ids) >= 48:
            break
    visible_set = set(visible_evidence_ids)

    case_items = []
    for item in selected:
        case_items.append({
            "item_id": str(item["item_id"])[:120],
            "title": _bounded(item.get("title"), 240),
            "observation": _bounded(item.get("observation"), 600),
            "why_it_matters": _bounded(item.get("why_it_matters"), 500),
            "evidence_ids": [
                value for value in _unique_strings(item.get("evidence_ids")) if value in visible_set
            ],
            "assets": _bounded_strings(item.get("assets"), 8, 160),
            "first_observed": _bounded(item.get("first_observed"), 80) or None,
            "last_observed": _bounded(item.get("last_observed"), 80) or None,
            "benign_alternatives": _bounded_strings(item.get("benign_alternatives"), 4, 240),
            "coverage_gaps": _bounded_strings(item.get("coverage_gaps"), 4, 240),
        })

    case_evidence = [_evidence_fact(evidence_index[evidence_id]) for evidence_id in visible_evidence_ids]
    relationships = _case_relationships(source, selected, visible_set)
    gaps = []
    for item in case_items:
        gaps.extend(item.get("coverage_gaps", []))
    coverage = source.get("coverage") if isinstance(source.get("coverage"), Mapping) else {}
    for gap in _mapping_rows(coverage.get("scheduler_gaps")):
        gaps.append(_bounded(gap.get("reason") or gap.get("event"), 240))
    for error in _mapping_rows(source.get("source_errors")):
        gaps.append(_bounded(error.get("reason") or error.get("error"), 240))
    return {
        "version": 1,
        "hunt_id": _bounded(source.get("hunt_id"), 120),
        "items": case_items,
        "evidence": case_evidence,
        "relationships": relationships[:48],
        "coverage_gaps": _unique_strings(gaps)[:12],
    }


def admit_activity_narrative(
    case: Mapping[str, Any], proposal: Mapping[str, Any],
) -> dict[str, Any]:
    """Admit only structurally valid, visible, connected possible interpretations."""
    case_items = _mapping_rows(case.get("items") if isinstance(case, Mapping) else None)
    item_order = [str(row.get("item_id")) for row in case_items if row.get("item_id")]
    try:
        if not isinstance(proposal, Mapping):
            raise ValueError("Narrative output is not an object")
        if set(proposal) != _TOP_LEVEL_KEYS:
            raise ValueError("Narrative output contains missing or unauthorized fields")
        if not isinstance(proposal.get("no_coherent_narrative"), bool):
            raise ValueError("Narrative coherence flag is invalid")
        clusters = proposal.get("clusters")
        limitations = proposal.get("limitations")
        unconnected = proposal.get("unconnected_item_ids")
        if not isinstance(clusters, list) or len(clusters) > 6:
            raise ValueError("Narrative cluster set is invalid")
        if not isinstance(unconnected, list) or not isinstance(limitations, list):
            raise ValueError("Narrative unconnected items or limitations are invalid")
        if proposal["no_coherent_narrative"] and clusters:
            raise ValueError("A no-coherent-narrative result cannot contain clusters")
        if not proposal["no_coherent_narrative"] and not clusters:
            raise ValueError("A coherent narrative result requires at least one cluster")

        item_ids = set(item_order)
        evidence_by_item = {
            str(row.get("item_id")): set(_unique_strings(row.get("evidence_ids")))
            for row in case_items
        }
        relationships = {
            str(row.get("relationship_id")): row
            for row in _mapping_rows(case.get("relationships")) if row.get("relationship_id")
        }
        known_evidence = {
            str(row.get("evidence_id")) for row in _mapping_rows(case.get("evidence"))
            if row.get("evidence_id")
        }
        visible_tokens = _fact_tokens(case)
        normalized_limitations = _text_list(limitations, 6, 300, "limitations")
        _validate_visible_tokens(normalized_limitations, visible_tokens)
        normalized_unconnected = _id_list(unconnected, item_ids, "unconnected item")
        placed = set(normalized_unconnected)
        normalized_clusters = []
        for index, cluster in enumerate(clusters):
            if not isinstance(cluster, Mapping) or set(cluster) != _CLUSTER_KEYS:
                raise ValueError("Narrative cluster contains missing or unauthorized fields")
            members = _id_list(cluster.get("item_ids"), item_ids, "cluster item", minimum=1)
            if placed.intersection(members):
                raise ValueError("A report item was placed more than once")
            placed.update(members)
            sequence = _id_list(cluster.get("possible_sequence"), set(members), "sequence item", minimum=1)
            if set(sequence) != set(members):
                raise ValueError("Possible sequence must place every cluster item once")
            evidence_ids = _id_list(
                cluster.get("evidence_ids"), known_evidence, "cluster evidence", minimum=1,
            )
            owned = set().union(*(evidence_by_item.get(item_id, set()) for item_id in members))
            if not set(evidence_ids).issubset(owned):
                raise ValueError("Narrative cites evidence invisible to its cluster items")
            if any(not (evidence_by_item.get(item_id, set()) & set(evidence_ids)) for item_id in members):
                raise ValueError("Narrative omits owned evidence for a clustered item")
            relationship_ids = _id_list(
                cluster.get("relationship_ids"), set(relationships), "relationship",
            )
            if len(members) == 1 and relationship_ids:
                raise ValueError("A single-item cluster cannot cite a relationship")
            if len(members) > 1:
                _require_connected(members, relationship_ids, relationships)
            confidence = cluster.get("confidence")
            if confidence not in {"low", "moderate", "high"}:
                raise ValueError("Narrative confidence is invalid")
            narrative = _required_text(cluster.get("narrative"), 800, "narrative")
            alternatives = _text_list(
                cluster.get("alternate_explanations"), 4, 300, "alternate explanations",
            )
            missing = _text_list(cluster.get("missing_evidence"), 4, 300, "missing evidence")
            _validate_visible_tokens([narrative, *alternatives, *missing], visible_tokens)
            if _CAUSAL_ASSERTION.search(narrative):
                raise ValueError("Narrative makes an unsupported causal assertion")
            normalized_clusters.append({
                "cluster_id": f"NC-{index + 1:02d}",
                "item_ids": members,
                "relationship_ids": relationship_ids,
                "evidence_ids": evidence_ids,
                "possible_sequence": sequence,
                "narrative": narrative,
                "confidence": confidence,
                "alternate_explanations": alternatives,
                "missing_evidence": missing,
            })
        omitted = [item_id for item_id in item_order if item_id not in placed]
        normalized_unconnected.extend(omitted)
        normalized_unconnected = [
            item_id for item_id in item_order if item_id in set(normalized_unconnected)
        ]
        if proposal["no_coherent_narrative"]:
            normalized_unconnected = item_order
        return {
            "version": 1,
            "status": "admitted",
            "no_coherent_narrative": bool(proposal["no_coherent_narrative"]),
            "clusters": normalized_clusters,
            "unconnected_item_ids": normalized_unconnected,
            "limitations": normalized_limitations,
        }
    except (TypeError, ValueError) as exc:
        rejected = unavailable_activity_narrative(case_items, str(exc))
        rejected["status"] = "rejected"
        return rejected


def unavailable_activity_narrative(
    items: Sequence[Mapping[str, Any]], reason: str,
) -> dict[str, Any]:
    """Return a compact safe fallback without hiding any visible report item."""
    item_ids = []
    for item in items if isinstance(items, Sequence) else ():
        if not isinstance(item, Mapping) or not item.get("item_id"):
            continue
        classification = item.get("classification")
        if classification is not None and classification not in {"suspicious", "malicious"}:
            continue
        item_id = str(item["item_id"])[:120]
        if item_id not in item_ids:
            item_ids.append(item_id)
    return {
        "version": 1,
        "status": "unavailable",
        "no_coherent_narrative": True,
        "clusters": [],
        "unconnected_item_ids": item_ids,
        "limitations": [],
        "reason": _bounded(reason, 240) or "Narrative synthesis was unavailable.",
    }


def _case_relationships(
    state: Mapping[str, Any], items: Sequence[Mapping[str, Any]], visible_evidence: set[str],
) -> list[dict[str, Any]]:
    item_ids = {str(item.get("item_id")) for item in items if item.get("item_id")}
    item_by_candidate = {
        str(candidate_id): str(item.get("item_id"))
        for item in items
        for candidate_id in _unique_strings(item.get("candidate_ids"))
        if item.get("item_id")
    }
    records = []
    for candidate in _mapping_rows(state.get("candidate_leads")):
        left_candidate = str(candidate.get("candidate_id") or "")
        left_item = item_by_candidate.get(left_candidate)
        if not left_item:
            continue
        for relation in _mapping_rows(candidate.get("related_candidates")):
            right_candidate = str(relation.get("candidate_id") or "")
            right_item = item_by_candidate.get(right_candidate)
            if not right_item or right_item == left_item:
                continue
            evidence_ids = sorted(
                value for value in set(_unique_strings(relation.get("evidence_ids")))
                if value in visible_evidence
            )
            if not evidence_ids:
                continue
            records.append(_relationship({
                "item_ids": sorted([left_item, right_item]),
                "evidence_ids": evidence_ids,
                "basis": "shared_typed_entity_within_time_window",
                "shared_entity_type": _bounded(relation.get("shared_entity_type"), 80),
                "shared_entity": _bounded(relation.get("shared_entity"), 200),
                "time_delta_seconds": _nonnegative_int(relation.get("time_delta_seconds")),
                "confidence": _bounded(relation.get("confidence"), 40) or "not assessed",
                "caveat": _bounded(relation.get("caveat"), 300)
                    or "An admitted relationship does not by itself prove causality.",
            }))

    # Supported graph-path relationships are already deterministically admitted.
    for path in _mapping_rows((state.get("investigation_graph") or {}).get("paths")
            if isinstance(state.get("investigation_graph"), Mapping) else None):
        steps = {str(step.get("sequence")): step for step in _mapping_rows(path.get("steps"))}
        for relation in _mapping_rows(path.get("relationships")):
            left_step = steps.get(str(relation.get("source_sequence")))
            right_step = steps.get(str(relation.get("target_sequence")))
            if not left_step or not right_step:
                continue
            left_items = _items_owning_evidence(items, left_step.get("evidence_ids"))
            right_items = _items_owning_evidence(items, right_step.get("evidence_ids"))
            evidence_ids = sorted(
                value for value in set(
                    _unique_strings(left_step.get("evidence_ids"))
                    + _unique_strings(right_step.get("evidence_ids"))
                    + _unique_strings(relation.get("evidence_ids"))
                ) if value in visible_evidence
            )
            for left_item in left_items:
                for right_item in right_items:
                    if left_item == right_item or {left_item, right_item} - item_ids or not evidence_ids:
                        continue
                    records.append(_relationship({
                        "item_ids": sorted([left_item, right_item]),
                        "evidence_ids": evidence_ids,
                        "basis": _bounded(relation.get("relationship") or relation.get("basis"), 160)
                            or "admitted_graph_relationship",
                        "shared_entity_type": "",
                        "shared_entity": "",
                        "time_delta_seconds": _nonnegative_int(relation.get("time_delta_seconds")),
                        "confidence": _bounded(relation.get("confidence"), 40) or "not assessed",
                        "caveat": _bounded(
                            " ".join(_bounded_strings(relation.get("caveats"), 3, 200)), 300,
                        ) or "An admitted graph relationship does not by itself prove causality.",
                    }))
    unique = {row["relationship_id"]: row for row in records}
    return [unique[key] for key in sorted(unique)]


def _relationship(payload: dict[str, Any]) -> dict[str, Any]:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    relationship_id = "REL-" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16].upper()
    return {"relationship_id": relationship_id, **payload}


def _items_owning_evidence(
    items: Sequence[Mapping[str, Any]], evidence_ids: Any,
) -> list[str]:
    target = set(_unique_strings(evidence_ids))
    return [
        str(item.get("item_id")) for item in items
        if item.get("item_id") and target.intersection(_unique_strings(item.get("evidence_ids")))
    ]


def _evidence_fact(event: Mapping[str, Any]) -> dict[str, Any]:
    provenance = event.get("provenance") if isinstance(event.get("provenance"), Mapping) else {}
    safe_provenance = {
        key: _bounded(provenance.get(key), 160)
        for key in ("search_id", "lead_id", "index", "document_id", "session_id", "pcap")
        if provenance.get(key) is not None
    }
    return {
        "evidence_id": str(event.get("evidence_id"))[:120],
        "source": _bounded(event.get("source"), 80),
        "observed_at": _bounded(event.get("observed_at"), 80) or None,
        "asset": _bounded(event.get("asset"), 160) or None,
        "observation": _bounded(event.get("observation"), 600),
        "provenance": safe_provenance,
    }


def _require_connected(
    members: list[str], relationship_ids: list[str],
    relationships: Mapping[str, Mapping[str, Any]],
) -> None:
    member_set = set(members)
    adjacency = {item_id: set() for item_id in members}
    for relationship_id in relationship_ids:
        endpoints = set(_unique_strings(relationships[relationship_id].get("item_ids")))
        if len(endpoints) != 2 or not endpoints.issubset(member_set):
            raise ValueError("A cited relationship falls outside its narrative cluster")
        left, right = sorted(endpoints)
        adjacency[left].add(right)
        adjacency[right].add(left)
    visited = set()
    pending = [members[0]]
    while pending:
        current = pending.pop()
        if current in visited:
            continue
        visited.add(current)
        pending.extend(adjacency[current] - visited)
    if visited != member_set:
        raise ValueError("Narrative cluster is not connected by admitted relationships")


def _validate_visible_tokens(texts: Sequence[str], allowed: Mapping[str, set[str]]) -> None:
    observed = _tokens(" ".join(texts))
    for token_type in ("ip", "domain", "time"):
        invented = observed[token_type] - allowed[token_type]
        if invented:
            raise ValueError(f"Narrative invents an unobserved {token_type} fact")


def _fact_tokens(value: Any) -> dict[str, set[str]]:
    strings = []
    pending = [value]
    while pending:
        current = pending.pop()
        if isinstance(current, Mapping):
            pending.extend(current.values())
        elif isinstance(current, (list, tuple, set)):
            pending.extend(current)
        elif current is not None:
            strings.append(str(current))
    return _tokens(" ".join(strings))


def _tokens(text: str) -> dict[str, set[str]]:
    ips = set()
    for raw in re.findall(r"[0-9A-Fa-f:.]+", text):
        candidate = raw.strip(".,;:()[]{}<>'\"")
        if not candidate or not ("." in candidate or ":" in candidate):
            continue
        try:
            ips.add(str(ipaddress.ip_address(candidate)))
        except ValueError:
            pass
    domains = {match.group(0).lower().rstrip(".") for match in _DOMAIN.finditer(text)}
    times = {match.group(0) for match in _ISO_TIME.finditer(text)}
    return {"ip": ips, "domain": domains, "time": times}


def _id_list(
    value: Any, allowed: set[str], label: str, minimum: int = 0,
) -> list[str]:
    if not isinstance(value, list) or len(value) < minimum:
        raise ValueError(f"Narrative {label} list is invalid")
    values = [str(item) for item in value]
    if len(values) != len(set(values)):
        raise ValueError(f"Narrative {label} list contains duplicates")
    if not set(values).issubset(allowed):
        raise ValueError(f"Narrative cites an unknown {label}")
    return values


def _text_list(value: Any, maximum: int, limit: int, label: str) -> list[str]:
    if not isinstance(value, list) or len(value) > maximum:
        raise ValueError(f"Narrative {label} list is invalid")
    return [_required_text(item, limit, label) for item in value]


def _required_text(value: Any, limit: int, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise ValueError(f"Narrative {label} text is invalid")
    return " ".join(value.split())


def _mapping_rows(value: Any) -> list[Mapping[str, Any]]:
    return [row for row in value if isinstance(row, Mapping)] if isinstance(value, list) else []


def _unique_strings(value: Any) -> list[str]:
    values = value if isinstance(value, (list, tuple, set)) else ([value] if value is not None else [])
    return list(dict.fromkeys(str(item).strip() for item in values if str(item).strip()))


def _bounded_strings(value: Any, maximum: int, limit: int) -> list[str]:
    return [_bounded(item, limit) for item in _unique_strings(value)[:maximum] if _bounded(item, limit)]


def _bounded(value: Any, limit: int) -> str:
    return " ".join(str(value).split())[:limit] if value is not None else ""


def _nonnegative_int(value: Any) -> int | None:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return None
