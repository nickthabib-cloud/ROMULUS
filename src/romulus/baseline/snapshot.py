"""Deterministic planning of a hunt's immutable baseline history cut."""
from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from typing import Any

from romulus.baseline.spec import BaselineSpec
from romulus.store.repo import Repo

_HOUR = timedelta(hours=1)


def _utc_hour(value: datetime, name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must carry a timezone")
    value = value.astimezone(UTC)
    if (value.minute, value.second, value.microsecond) != (0, 0, 0):
        raise ValueError(f"{name} must be hour-aligned")
    return value


def _iso(value: datetime) -> str:
    return value.isoformat()


def _digest(value: Any) -> str:
    material = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(material.encode()).hexdigest()


def _hours(start: datetime, end: datetime) -> list[datetime]:
    return [start + index * _HOUR for index in range(int((end - start) / _HOUR))]


def _gaps(covered: set[datetime], earliest: datetime | None, end: datetime) -> list[dict]:
    """Coalesce holes after the first available record; leading absence is reported separately."""
    if earliest is None:
        return []
    missing = [hour for hour in _hours(earliest, end) if hour not in covered]
    out: list[dict] = []
    for hour in missing:
        if out and out[-1]["end"] == _iso(hour):
            out[-1]["end"] = _iso(hour + _HOUR)
        else:
            out.append({
                "start": _iso(hour), "end": _iso(hour + _HOUR), "reason": "no complete segment",
            })
    return out


class SnapshotPlanner:
    """Freeze a deterministic, membership-backed cover once per hunt."""

    def __init__(self, repo: Repo):
        self.repo = repo

    def freeze(self, *, hunt_id: str, window_start: datetime, lookback: timedelta,
               min_live_hours: int, site: str, targets: list[str],
               specs: list[BaselineSpec]) -> dict:
        existing = self.repo.baseline_snapshot(hunt_id)
        if existing is not None:
            return existing
        window_start = _utc_hour(window_start, "window_start")
        if lookback <= timedelta(0) or lookback % _HOUR:
            raise ValueError("lookback must be a positive whole number of hours")
        if min_live_hours < 1:
            raise ValueError("min_live_hours must be positive")
        history_start = window_start - lookback
        plan = {
            "window_start": _iso(window_start), "history_start": _iso(history_start),
            "lookback_hours": int(lookback / _HOUR), "min_live_hours": min_live_hours,
            "site": site, "targets": sorted(set(targets)),
            "specs": [{"id": spec.id, "version": spec.version, "key_version": spec.key_version}
                      for spec in sorted(specs, key=lambda item: item.id)],
        }
        selected_ids: set[str] = set()
        coverage: dict[str, dict] = {}
        cut_material: list[dict] = []
        statuses: list[str] = []
        for target in plan["targets"]:
            for spec in sorted(specs, key=lambda item: item.id):
                eligible = self.repo.baseline_segments_for_cover(
                    site=site, target=target, spec_id=spec.id, spec_version=spec.version,
                    key_version=spec.key_version, start=history_start, end=window_start,
                )
                cut_material.extend({
                    "id": row["id"], "status": row["status"], "target": target, "spec_id": spec.id,
                } for row in eligible)
                ranked = sorted(eligible, key=lambda row: (
                    0 if row["origin"] == "hunt" else 1, -row["created_at"].timestamp(), row["id"],
                ))
                claimed: set[datetime] = set()
                chosen: list[dict] = []
                for row in ranked:
                    span = set(_hours(row["start"], row["end"]))
                    if span and not (span & claimed):
                        chosen.append(row)
                        claimed.update(span)
                        selected_ids.add(row["id"])
                earliest = min((row["start"] for row in eligible), default=None)
                cursor = window_start
                while cursor - _HOUR in claimed:
                    cursor -= _HOUR
                effective_hours = int((window_start - cursor) / _HOUR)
                if effective_hours < min_live_hours:
                    status = "unresolved"
                elif effective_hours == int(lookback / _HOUR):
                    status = "resolved"
                else:
                    status = "shortened"
                statuses.append(status)
                coverage[f"{target}|{spec.id}"] = {
                    "effective_start": _iso(cursor), "effective_hours": effective_hours,
                    "gaps": _gaps(claimed, earliest, window_start),
                    "absent_before": _iso(earliest) if earliest is not None and earliest > history_start else None,
                    "status": status, "segment_ids": sorted(row["id"] for row in chosen),
                }
        status = ("unresolved" if "unresolved" in statuses else
                  "shortened" if "shortened" in statuses else "resolved")
        segment_ids = sorted(selected_ids)
        store_cut = {
            "eligible_digest": _digest(sorted(cut_material, key=lambda row: (
                row["target"], row["spec_id"], row["id"],
            ))),
            "eligible_segments": len(cut_material),
        }
        material = {
            "plan": plan, "store_cut": store_cut, "segment_ids": segment_ids,
            "coverage": coverage, "status": status,
        }
        row = {"hunt_id": hunt_id, **material, "digest": _digest(material)}
        if self.repo.save_baseline_snapshot(row):
            return row
        # Another runner won the write-once race. Its frozen cut is authoritative.
        return self.repo.baseline_snapshot(hunt_id)  # type: ignore[return-value]
