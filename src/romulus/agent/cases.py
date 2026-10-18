"""Deterministic seed clustering for bounded, breadth-first investigations."""
from __future__ import annotations

import hashlib
from collections import defaultdict
from datetime import datetime, timedelta

from romulus.agent.models import EntityRef, SeedCluster

_LANE_ORDER = {"urgent": 0, "high": 1, "lead": 2, "context": 3}


def _ts(value) -> datetime:
    return value if isinstance(value, datetime) else datetime.fromisoformat(str(value))


def _entities(candidate: dict) -> list[EntityRef]:
    out = []
    for raw in candidate.get("entities") or []:
        if len(raw) >= 3:
            out.append(EntityRef(kind=raw[0], value=str(raw[1]), role=str(raw[2])))
    return out


def primary_seed_entity(candidate: dict) -> EntityRef | None:
    entities = [e for e in _entities(candidate) if e.role != "observer"]

    def rank(entity: EntityRef) -> tuple[int, str]:
        if entity.kind == "host" and entity.role == "host":
            return 0, entity.value
        if entity.kind == "account":
            return 1, entity.value
        if entity.kind == "ip" and entity.role == "dst":
            return 2, entity.value
        if entity.kind == "ip":
            return 3, entity.value
        if entity.kind == "domain":
            return 4, entity.value
        return 9, entity.value

    return min(entities, key=rank) if entities else None


def _make_cluster(seeds: list[dict], primary: EntityRef | None) -> SeedCluster:
    ordered = sorted(seeds, key=lambda c: (_ts(c["ts"]), c["id"]))
    ids = [c["id"] for c in ordered]
    identity = f"{primary.kind}:{primary.value}" if primary else ids[0]
    cid = "case-" + hashlib.sha256((identity + "|" + "|".join(ids)).encode()).hexdigest()[:16]
    unique: dict[tuple[str, str, str], EntityRef] = {}
    for candidate in ordered:
        for entity in _entities(candidate):
            if entity.role != "observer":
                unique[(entity.kind, entity.value, entity.role)] = entity
    lane = min((str(c.get("lane", "context")) for c in ordered), key=lambda x: _LANE_ORDER.get(x, 9))
    return SeedCluster(
        id=cid, primary_entity=primary, seed_candidate_ids=ids, entities=list(unique.values()), lane=lane,
        priority=max(float(c.get("priority", 0)) for c in ordered), first_ts=_ts(ordered[0]["ts"]),
        last_ts=_ts(ordered[-1]["ts"]),
    )


def cluster_seed_candidates(candidates: list[dict], gap: timedelta = timedelta(minutes=15)) -> list[SeedCluster]:
    grouped: dict[tuple[str, str] | tuple[str, str, str], list[dict]] = defaultdict(list)
    primary_by_key: dict[tuple, EntityRef | None] = {}
    for candidate in candidates:
        primary = primary_seed_entity(candidate)
        key = (primary.kind, primary.value) if primary else ("candidate", candidate["id"], candidate["id"])
        grouped[key].append(candidate)
        primary_by_key[key] = primary

    clusters: list[SeedCluster] = []
    for key, seeds in grouped.items():
        current: list[dict] = []
        latest: datetime | None = None
        for seed in sorted(seeds, key=lambda c: (_ts(c["ts"]), c["id"])):
            when = _ts(seed["ts"])
            if current and latest is not None and when - latest > gap:
                clusters.append(_make_cluster(current, primary_by_key[key]))
                current = []
            current.append(seed)
            latest = when
        if current:
            clusters.append(_make_cluster(current, primary_by_key[key]))
    return sorted(clusters, key=lambda c: (_LANE_ORDER.get(c.lane, 9), -c.priority, c.first_ts, c.id))

