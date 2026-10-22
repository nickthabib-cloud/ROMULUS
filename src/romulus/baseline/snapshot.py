"""Deterministic planning of a hunt's immutable baseline history cut."""
from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from typing import Any

from romulus.baseline.lookback import HistoryGap
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


# When several history gaps name one hour, the state that says most about why it is missing wins.
_GAP_STATE_ORDER = {"failed": 0, "partial": 1, "omitted_budget": 2}
_NO_SEGMENT = ("missing", "no complete segment")


def _gap_causes(history_gaps: Iterable[HistoryGap], target: str, spec_id: str,
                start: datetime, end: datetime) -> dict[datetime, tuple[str, str]]:
    """The recorded (state, reason) of each history hour of one target and spec, inside [start, end)."""
    found: dict[datetime, set[tuple[str, str]]] = {}
    for gap in history_gaps:
        if gap.target != target or spec_id not in gap.spec_ids:
            continue
        for hour in _hours(max(gap.start, start), min(gap.end, end)):
            found.setdefault(hour, set()).add((gap.state, gap.reason))
    causes: dict[datetime, tuple[str, str]] = {}
    for hour, items in found.items():
        state = min((state for state, _ in items), key=lambda value: (_GAP_STATE_ORDER.get(value, 9), value))
        causes[hour] = (state, "; ".join(sorted({reason for _, reason in items})))
    return causes


def _gaps(covered: set[datetime], start: datetime, end: datetime,
          causes: dict[datetime, tuple[str, str]]) -> list[dict]:
    """Every uncovered history hour is a gap with its recorded cause; adjacent hours with one cause coalesce.

    A missing segment is never evidence that the source was empty: only a complete zero-record segment is.
    """
    out: list[dict] = []
    for hour in _hours(start, end):
        if hour in covered:
            continue
        state, reason = causes.get(hour, _NO_SEGMENT)
        if out and out[-1]["end"] == _iso(hour) and (out[-1]["state"], out[-1]["reason"]) == (state, reason):
            out[-1]["end"] = _iso(hour + _HOUR)
        else:
            out.append({"start": _iso(hour), "end": _iso(hour + _HOUR), "state": state, "reason": reason})
    return out


class SnapshotPlanner:
    """Freeze a deterministic, membership-backed cover once per hunt."""

    def __init__(self, repo: Repo):
        self.repo = repo

    def freeze(self, *, hunt_id: str, window_start: datetime, lookback: timedelta,
               min_live_hours: int, site: str, targets: list[str],
               specs: list[BaselineSpec], history_gaps: Iterable[HistoryGap] = ()) -> dict:
        """Freeze the cover once per hunt.

        `history_gaps` are the lookback's coverage facts; they give uncovered hours their real reason.
        Coverage per (target, spec):
        - the effective span is the contiguous covered run ending at the window start, beginning at its first
          segment holding records; complete zero-record segments before that are evidence of absence
          (`absent_before`), and a run with no records at all is `absent`, never resolved;
        - a span shorter than the lookback is `gap_shortened` when the run stopped at an uncovered hour, and
          `shortened` only when it reaches history_start and is short by evidenced absence alone;
        - every uncovered hour of [history_start, window_start) is a gap, never absence.
        """
        history_gaps = tuple(history_gaps)
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
                claimed: dict[datetime, dict] = {}
                chosen: list[dict] = []
                for row in ranked:
                    span = _hours(row["start"], row["end"])
                    if span and not any(hour in claimed for hour in span):
                        chosen.append(row)
                        claimed.update(dict.fromkeys(span, row))
                        selected_ids.add(row["id"])
                cursor = window_start
                while cursor - _HOUR in claimed:
                    cursor -= _HOUR
                # The first record within the run: the oldest covering segment that holds any. Earlier hours of
                # the run are complete and empty, which is the only evidence of absence.
                first_record = next((hour for hour in _hours(cursor, window_start)
                                     if claimed[hour]["events_total"] > 0), None)
                if first_record is None:
                    effective_start = window_start
                    absent_before = _iso(window_start) if cursor < window_start else None
                else:
                    effective_start = claimed[first_record]["start"]
                    absent_before = _iso(effective_start) if effective_start > cursor else None
                effective_hours = int((window_start - effective_start) / _HOUR)
                if first_record is None and cursor < window_start:
                    status = "absent"
                elif effective_hours < min_live_hours:
                    status = "unresolved"
                elif effective_hours == int(lookback / _HOUR):
                    status = "resolved"
                elif cursor > history_start:
                    # The run stopped at an uncovered hour: shortened by a gap, which is a failure to S5.
                    status = "gap_shortened"
                else:
                    # The run reaches history_start and is short only by evidenced absence.
                    status = "shortened"
                statuses.append(status)
                causes = _gap_causes(history_gaps, target, spec.id, history_start, window_start)
                coverage[f"{target}|{spec.id}"] = {
                    "effective_start": _iso(effective_start), "effective_hours": effective_hours,
                    "gaps": _gaps(set(claimed), history_start, window_start, causes),
                    "absent_before": absent_before,
                    "status": status, "segment_ids": sorted(row["id"] for row in chosen),
                }
        # Absent history resolves nothing, so it is unresolved at the snapshot level. A gap outranks absence.
        status = ("unresolved" if {"unresolved", "absent"} & set(statuses) else
                  "gap_shortened" if "gap_shortened" in statuses else
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
