"""Deterministic, evidence-scoped candidate triage.

Relationships produced here are investigative associations only.  They do not
publish findings or assert that one observed behavior caused another.
"""
from __future__ import annotations

import copy
from datetime import datetime, timezone
import ipaddress
from typing import Any, Collection, Mapping, Sequence

from .classification import apply_classification, migrate_candidate


RELATIONSHIP_CAVEAT = "Temporal or entity association is an investigative lead, not causation."

_ENTITY_PATHS: dict[str, tuple[str, ...]] = {
    "ip": (
        "host.ip", "source.ip", "destination.ip", "client.ip", "server.ip",
        "src_ip", "srcIp", "dst_ip", "dstIp", "ip.src", "ip.dst",
    ),
    "host": (
        "host.name", "host.hostname", "hostname", "computer_name", "agent.hostname",
    ),
    "user": (
        "user.name", "account.name", "username", "winlog.event_data.SubjectUserName",
        "winlog.event_data.TargetUserName",
    ),
    "domain": (
        "dns.question.name", "dns.qry.name", "dns.host", "url.domain", "http.host",
        "tls.server.name", "tls.handshake.extensions_server_name", "server_name", "sni",
    ),
    "process": (
        "process.name", "process.executable", "process.parent.name", "process.parent.executable",
        "winlog.event_data.Image", "winlog.event_data.ParentImage", "exe", "comm",
    ),
    "session": (
        "session.id", "network.community_id", "process.entity_id", "user.id",
        "winlog.event_data.LogonId", "winlog.event_data.TargetLogonId",
    ),
}


def relate_candidates(
    candidates: Sequence[Mapping[str, Any]],
    evidence: Sequence[Mapping[str, Any]],
    window_seconds: int = 1800,
) -> list[dict[str, Any]]:
    """Return stable candidate copies with cited, time-bounded relationships.

    A pair must use distinct evidence records, distinct analytic groups, one
    shared normalized entity, and parseable timestamps inside ``window_seconds``.
    Candidate asset labels and prose are deliberately excluded.
    """
    if window_seconds < 0:
        raise ValueError("window_seconds must be non-negative")

    evidence_by_id: dict[str, Mapping[str, Any]] = {}
    for event in sorted(evidence, key=_evidence_sort_key):
        identifier = str(event.get("evidence_id") or "").strip()
        if identifier:
            evidence_by_id.setdefault(identifier, event)

    items = [migrate_candidate(copy.deepcopy(dict(candidate))) for candidate in candidates]
    items.sort(key=_candidate_sort_key)
    relationships: dict[str, list[dict[str, Any]]] = {
        str(item.get("candidate_id") or ""): [] for item in items
    }
    related_groups: dict[str, set[str]] = {
        str(item.get("candidate_id") or ""): set() for item in items
    }

    for left_index, left in enumerate(items):
        left_id = str(left.get("candidate_id") or "")
        left_group = _candidate_group(left)
        if not left_id or not left_group:
            continue
        for right in items[left_index + 1:]:
            right_id = str(right.get("candidate_id") or "")
            right_group = _candidate_group(right)
            if not right_id or not right_group or left_group == right_group:
                continue
            match = _best_relationship(left, right, evidence_by_id, window_seconds)
            if match is None:
                continue
            entity_type, entity, left_evidence_id, right_evidence_id, delta = match
            relationships[left_id].append(_relationship_record(
                right_id, entity_type, entity, left_evidence_id, right_evidence_id, delta,
            ))
            relationships[right_id].append(_relationship_record(
                left_id, entity_type, entity, right_evidence_id, left_evidence_id, delta,
            ))
            related_groups[left_id].add(right_group)
            related_groups[right_id].add(left_group)

    for item in items:
        candidate_id = str(item.get("candidate_id") or "")
        records = sorted(
            relationships.get(candidate_id, []),
            key=lambda row: (
                int(row["time_delta_seconds"]), str(row["shared_entity_type"]),
                str(row["shared_entity"]), str(row["candidate_id"]), tuple(row["evidence_ids"]),
            ),
        )
        item["related_candidates"] = records
        groups = sorted(related_groups.get(candidate_id, set()))
        old_bonus = _bounded_int(item.get("corroboration_bonus"), 0, 20)
        inferred_base = max(0, _bounded_int(item.get("priority_score"), 0, 100) - old_bonus)
        base_score = (
            _bounded_int(item.get("base_priority_score"), 0, 100)
            if item.get("base_priority_score") is not None else inferred_base
        )
        bonus = min(20, len(groups) * 10)
        score = min(100, base_score + bonus)
        item["base_priority_score"] = base_score
        item["corroboration_bonus"] = bonus
        item["priority_score"] = score
        item["priority_tier"] = _priority_tier(score)
        old_reasons = [
            str(reason) for reason in item.get("score_reasons", [])
            if not str(reason).startswith("evidence-backed corroboration contribution ")
        ]
        if bonus:
            old_reasons.append(f"evidence-backed corroboration contribution {bonus}")
        item["score_reasons"] = old_reasons
        item["corroboration_reasons"] = [
            f"Related to {row['candidate_id']} ({_group_for_id(items, row['candidate_id'])}) via "
            f"shared {row['shared_entity_type']} {row['shared_entity']} within "
            f"{row['time_delta_seconds']} seconds; {RELATIONSHIP_CAVEAT}"
            for row in records
        ]

        disposition = str(item.get("disposition") or "observed")
        terminal = disposition in {"benign_likely", "dismissed", "unresolved"}
        investigating = disposition == "investigating"
        finding_backed = bool(item.get("finding_ids"))
        if not terminal and not investigating:
            item["disposition"] = (
                "corroborated" if finding_backed or (bonus and score >= 70) else "observed"
            )
        if item.get("classification") in {"anomalous", "suspicious", "malicious"}:
            item["customer_visible"] = bool(
                item.get("classification") in {"suspicious", "malicious"}
                and disposition not in {"benign_likely", "dismissed"}
            )
        elif item.get("kind") == "trusted_indicator":
            item["customer_visible"] = True
        elif terminal:
            item["customer_visible"] = bool(item.get("customer_visible"))
        elif finding_backed:
            item["customer_visible"] = True
        else:
            item["customer_visible"] = bool(bonus and score >= 70 and not investigating)
        classified = apply_classification(item, relationship_count=len(records))
        item.clear()
        item.update(classified)

    return sorted(items, key=_candidate_sort_key)


def select_candidate_frontier(
    candidates: Sequence[Mapping[str, Any]],
    limit: int = 8,
    exploration_slots: int = 2,
    max_per_group: int = 2,
    preferred_ids: Collection[str] | None = None,
    minimum_score: int = 40,
) -> list[dict[str, Any]]:
    """Select a stable, evidence-backed, behavior-diverse candidate frontier.

    Critical and trusted candidates lead the primary pool, then preferred
    candidates, then ordinary candidates.  Up to ``exploration_slots`` are
    reserved for the strongest cited candidates below ``minimum_score``.
    Excluded candidates are not mutated or closed and remain eligible later.
    """
    limit = max(0, int(limit))
    exploration_slots = max(0, min(max(0, limit - 1), int(exploration_slots)))
    max_per_group = max(1, int(max_per_group))
    minimum_score = max(0, min(100, int(minimum_score)))
    if not limit:
        return []

    preferred = {str(value) for value in preferred_ids or () if value}
    unique: dict[str, dict[str, Any]] = {}
    for candidate in candidates:
        candidate_id = str(candidate.get("candidate_id") or "").strip()
        evidence_ids = [value for value in candidate.get("evidence_ids", []) if value]
        if not candidate_id or not evidence_ids or candidate_id in unique:
            continue
        unique[candidate_id] = copy.deepcopy(dict(candidate))

    ordered = sorted(unique.values(), key=lambda item: _frontier_sort_key(item, preferred))
    primary = [
        item for item in ordered
        if _bounded_int(item.get("priority_score"), 0, 100) >= minimum_score
        or item.get("kind") == "trusted_indicator"
        or str(item.get("priority_tier") or "").lower() == "critical"
    ]
    protected = [item for item in primary if _is_protected(item)]
    preferred_candidates = [
        item for item in ordered
        if str(item.get("candidate_id") or "") in preferred and not _is_protected(item)
    ]
    ordinary_primary = [
        item for item in primary
        if not _is_protected(item) and str(item.get("candidate_id") or "") not in preferred
    ]
    exploratory = [
        item for item in ordered
        if item not in primary and str(item.get("candidate_id") or "") not in preferred
    ]
    selected: list[dict[str, Any]] = []
    selected_ids: set[str] = set()
    group_counts: dict[str, int] = {}

    def take(pool: Sequence[dict[str, Any]], capacity: int) -> None:
        for item in pool:
            if capacity <= 0 or len(selected) >= limit:
                break
            candidate_id = str(item.get("candidate_id") or "")
            group = _frontier_group(item)
            if candidate_id in selected_ids or group_counts.get(group, 0) >= max_per_group:
                continue
            selected.append(item)
            selected_ids.add(candidate_id)
            group_counts[group] = group_counts.get(group, 0) + 1
            capacity -= 1

    take(protected, limit)
    take(preferred_candidates, limit - len(selected))
    reserved = min(exploration_slots, max(0, limit - len(selected)))
    take(ordinary_primary, max(0, limit - len(selected) - reserved))
    take(exploratory, reserved)
    take(ordinary_primary, limit - len(selected))
    return selected


def _best_relationship(
    left: Mapping[str, Any],
    right: Mapping[str, Any],
    evidence_by_id: Mapping[str, Mapping[str, Any]],
    window_seconds: int,
) -> tuple[str, str, str, str, int] | None:
    possible: list[tuple[int, str, str, str, str]] = []
    left_ids = sorted({str(value) for value in left.get("evidence_ids", []) if value})
    right_ids = sorted({str(value) for value in right.get("evidence_ids", []) if value})
    for left_id in left_ids:
        left_event = evidence_by_id.get(left_id)
        left_time = _event_time(left_event)
        if left_event is None or left_time is None:
            continue
        left_entities = _typed_entities(left_event)
        for right_id in right_ids:
            if right_id == left_id:
                continue
            right_event = evidence_by_id.get(right_id)
            right_time = _event_time(right_event)
            if right_event is None or right_time is None:
                continue
            delta_seconds = abs((left_time - right_time).total_seconds())
            if delta_seconds > window_seconds:
                continue
            delta = int(delta_seconds)
            right_entities = _typed_entities(right_event)
            for entity_type in sorted(set(left_entities) & set(right_entities)):
                for entity in sorted(left_entities[entity_type] & right_entities[entity_type]):
                    possible.append((delta, entity_type, entity, left_id, right_id))
    if not possible:
        return None
    delta, entity_type, entity, left_id, right_id = min(possible)
    return entity_type, entity, left_id, right_id, delta


def _relationship_record(
    related_id: str,
    entity_type: str,
    entity: str,
    own_evidence_id: str,
    related_evidence_id: str,
    delta: int,
) -> dict[str, Any]:
    return {
        "candidate_id": related_id,
        "shared_entity_type": entity_type,
        "shared_entity": entity,
        "evidence_ids": [own_evidence_id, related_evidence_id],
        "time_delta_seconds": delta,
        "confidence": "moderate",
        "caveat": RELATIONSHIP_CAVEAT,
    }


def _typed_entities(event: Mapping[str, Any]) -> dict[str, set[str]]:
    entities: dict[str, set[str]] = {}
    raw = event.get("raw") if isinstance(event.get("raw"), Mapping) else {}
    for entity_type, paths in _ENTITY_PATHS.items():
        values: set[str] = set()
        for path in paths:
            for root in (raw, event):
                value = _nested_value(root, path)
                if value is None and isinstance(root, Mapping):
                    value = root.get(path)
                for observed in value if isinstance(value, list) else [value]:
                    normalized = _normalize_entity(entity_type, observed)
                    if normalized:
                        values.add(normalized)
        if values:
            entities[entity_type] = values
    return entities


def _normalize_entity(entity_type: str, value: Any) -> str | None:
    text = str(value or "").strip()
    if not text:
        return None
    if entity_type == "ip":
        try:
            return str(ipaddress.ip_address(text))
        except ValueError:
            return None
    if entity_type in {"host", "domain"}:
        return text.lower().rstrip(".")
    if entity_type == "process":
        return text.lower().replace("\\", "/").rsplit("/", 1)[-1]
    return text.lower()


def _event_time(event: Mapping[str, Any] | None) -> datetime | None:
    if event is None or not event.get("observed_at"):
        return None
    try:
        value = datetime.fromisoformat(str(event["observed_at"]).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def _nested_value(value: Any, path: str) -> Any:
    for part in path.split("."):
        if not isinstance(value, Mapping):
            return None
        value = value.get(part)
    return value


def _candidate_group(candidate: Mapping[str, Any]) -> str:
    return str(candidate.get("corroboration_group") or candidate.get("analytic_id") or "").strip()


def _frontier_group(candidate: Mapping[str, Any]) -> str:
    return str(
        candidate.get("corroboration_group")
        or candidate.get("analytic_id")
        or candidate.get("indicator_id")
        or candidate.get("candidate_id")
        or "unknown"
    ).strip()


def _group_for_id(candidates: Sequence[Mapping[str, Any]], candidate_id: str) -> str:
    for candidate in candidates:
        if str(candidate.get("candidate_id") or "") == candidate_id:
            return _candidate_group(candidate)
    return "unknown"


def _priority_tier(score: int) -> str:
    return "critical" if score >= 90 else ("high" if score >= 70 else ("medium" if score >= 40 else "low"))


def _bounded_int(value: Any, lower: int, upper: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        number = lower
    return max(lower, min(upper, number))


def _candidate_sort_key(candidate: Mapping[str, Any]) -> tuple[int, int, str]:
    return (
        -_bounded_int(candidate.get("priority_score"), 0, 100),
        0 if candidate.get("kind") == "trusted_indicator" else 1,
        str(candidate.get("candidate_id") or ""),
    )


def _frontier_sort_key(
    candidate: Mapping[str, Any], preferred_ids: set[str],
) -> tuple[int, int, int, int, int, str]:
    protected = _is_protected(candidate)
    candidate_id = str(candidate.get("candidate_id") or "")
    return (
        0 if protected else 1,
        0 if candidate_id in preferred_ids else 1,
        -_bounded_int(candidate.get("priority_score"), 0, 100),
        {"malicious": 0, "suspicious": 1, "anomalous": 2}.get(
            str(candidate.get("classification") or ""), 3,
        ),
        0 if candidate.get("kind") == "trusted_indicator" else 1,
        candidate_id,
    )


def _is_protected(candidate: Mapping[str, Any]) -> bool:
    return bool(
        candidate.get("kind") == "trusted_indicator"
        or str(candidate.get("priority_tier") or "").lower() == "critical"
        or _bounded_int(candidate.get("priority_score"), 0, 100) >= 90
    )


def _evidence_sort_key(event: Mapping[str, Any]) -> tuple[str, str, str]:
    return (
        str(event.get("evidence_id") or ""),
        str(event.get("observed_at") or ""),
        str(event.get("source") or ""),
    )
