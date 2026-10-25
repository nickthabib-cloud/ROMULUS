"""Publish complete hunt-window counts as immutable baseline segments."""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from romulus.baseline.carry import CarryInStore, PendingResolver
from romulus.baseline.lookback import exclusion_digest, segment_content_id
from romulus.baseline.spec import SPEC_BY_ID, KeyContext, Pending
from romulus.detect import netdef
from romulus.evidence.typed import TypedEvent
from romulus.store.db import utcnow
from romulus.store.repo import Repo

_COMPLETE_CELL_STATES = {"evaluated_complete", "not_applicable_no_events"}
_HOUR = timedelta(hours=1)


def _canonical(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _window(manifest: dict) -> tuple[datetime, datetime]:
    row = manifest["window"]
    return datetime.fromisoformat(row["start"]).astimezone(UTC), datetime.fromisoformat(row["end"]).astimezone(UTC)


def _floor_hour(value: datetime) -> datetime:
    return value.replace(minute=0, second=0, microsecond=0)


def _ceil_hour(value: datetime) -> datetime:
    floor = _floor_hour(value)
    return floor if floor == value else floor + _HOUR


def _cell_span(partition: str) -> tuple[datetime, datetime] | None:
    """A sweep cell's retrieval interval from its partition key (`start/end`), or None when it names none."""
    try:
        first, last = partition.split("/", 1)
        start, end = datetime.fromisoformat(first), datetime.fromisoformat(last)
    except ValueError:
        return None
    if start.tzinfo is None or end.tzinfo is None or start >= end:
        return None
    return start.astimezone(UTC), end.astimezone(UTC)


def whole_hour_span(start: datetime, end: datetime,
                    _cells: list[tuple[datetime, datetime]]) -> tuple[datetime, datetime] | None:
    """The widest hour-aligned span inside [start, end), or None when the window holds no whole hour.

    Counts and evaluated-record totals are staged per hour, so a source cell may safely straddle either edge.
    """
    low, high = _ceil_hour(start), _floor_hour(end)
    return (low, high) if low < high else None


def _cited_exclusions(repo: Repo, hunt_id: str, targets: set[str], spec_ids: set[str],
                      ) -> tuple[dict[tuple[str, str], set[str]], dict[tuple[str, str], str]]:
    """The keys of every record urgent, high and lead findings cite, per (target, spec), and the (target, spec)
    pairs whose cited keys cannot all be known.

    A finding's context records count: they are often the attack chain itself. A cited record that is not
    retained, or an exec-pair child whose parent cannot be resolved, could hold any key, so its pairs are
    blocked rather than written with the key possibly still inside.
    """
    candidates = repo.candidates(hunt_id, ["urgent", "high", "lead"])
    event_ids = sorted({event_id for row in candidates
                        for event_id in [*(row.get("event_ids") or []), *(row.get("context_event_ids") or [])]})
    found: dict[tuple[str, str], set[str]] = {}
    blocked: dict[tuple[str, str], str] = {}
    hunt = repo.get_hunt(hunt_id)
    _start, horizon = _window(hunt["manifest"] if hunt else {})
    resolvers: dict[tuple[str, str], PendingResolver] = {}
    retained: set[str] = set()
    for row in repo.citation_events(hunt_id, event_ids):
        event = TypedEvent.model_validate(row["event"])
        retained.add(event.id)
        event_targets = sorted({ref.target for ref in event.raw} & targets)
        for spec_id in sorted(spec_ids):
            spec = SPEC_BY_ID.get(spec_id)
            if spec is None or event.family not in spec.families:
                continue
            result = spec.keys(event, KeyContext(is_internal=netdef.current().is_internal))
            for target in event_targets:
                resolved = result
                if isinstance(result, Pending):
                    identity = (target, spec_id)
                    resolver = resolvers.get(identity)
                    if resolver is None:
                        carry = CarryInStore(repo, hunt_id).for_target(target, horizon=horizon)
                        resolver = PendingResolver(carry, spec)
                        resolvers[identity] = resolver
                    resolution = resolver.resolve(result)
                    if resolution.reason is not None:
                        blocked.setdefault(identity, f"cited record {event.id} has no resolvable key "
                                                     f"({resolution.reason})")
                        continue
                    resolved = resolution.keys
                if isinstance(resolved, (list, tuple)):
                    found.setdefault((target, spec_id), set()).update(key.key_digest for key in resolved)
    missing = sorted(set(event_ids) - retained)
    if missing:
        reason = f"{len(missing)} cited record(s) are not retained, so their keys are unknown (first {missing[0]})"
        for target in sorted(targets):
            for spec_id in sorted(spec_ids):
                blocked.setdefault((target, spec_id), reason)
    return found, blocked


def _without_excluded(rows, excluded: set[str]):
    for row in rows:
        if row["key_digest"] not in excluded:
            yield row


def run_hunt_segment_writer(repo: Repo, hunt_id: str, *, hunt_complete: bool) -> dict:
    """Write the hunt-derived baseline cut, or state why a (target, spec) wrote nothing.

    In a complete hunt every (target, spec) reaches one decision: written (or already in the store), or skipped
    with a reason. Its window counter material is then released; a later run of the writer for this hunt states
    that and writes nothing from it. A partial hunt keeps its material for the resumed run that may complete it.
    """
    hunt = repo.get_hunt(hunt_id)
    if hunt is None:
        raise KeyError(hunt_id)
    manifest = hunt["manifest"]
    config = manifest.get("baseline") or {}
    specs = sorted(str(item["id"]) for item in config.get("specs") or [])
    if not specs or not config.get("site"):
        return {
            "status": "disabled", "written": 0, "stale": 0,
            "max_write_seconds": 0.0, "specs": {},
        }
    start, end = _window(manifest)
    targets = sorted(set(manifest.get("targets") or []))
    site = str(config.get("site") or "")
    current_exclusions, blocked = _cited_exclusions(repo, hunt_id, set(targets), set(specs))
    repo.replace_baseline_hunt_exclusions(
        hunt_id, site=site, start=start, end=end, exclusions=current_exclusions,
        spec_versions={spec_id: (SPEC_BY_ID[spec_id].version, SPEC_BY_ID[spec_id].key_version)
                       for spec_id in specs},
    )
    stale = repo.stale_baseline_segments_for_exclusions(site=site, start=start, end=end)
    repo.cleanup_baseline_building(before=utcnow() - timedelta(hours=1))
    if not hunt_complete:
        # The material stays: a resumed hunt that completes writes from it.
        return {
            "status": "skipped",
            "written": 0,
            "stale": stale,
            "max_write_seconds": 0.0,
            "specs": {spec_id: {"written": 0, "reason": "hunt is partial"} for spec_id in specs},
        }
    normalizer = str(manifest.get("normalizer") or "unknown")
    network = manifest.get("internal_networks") or {}
    networks_configured = network.get("source") == "configured"
    summaries: dict[str, dict] = {}
    written = 0
    longest = 0.0
    for spec_id in specs:
        spec = SPEC_BY_ID[spec_id]
        spec_written = 0
        reasons: list[str] = []
        for target in targets:
            reason, count, seconds = _write_target(
                repo, hunt_id, spec, target, site=site, window=(start, end), normalizer=normalizer,
                network_digest=network.get("digest"), networks_configured=networks_configured,
                blocked=blocked.get((target, spec_id)),
            )
            if reason is not None:
                reasons.append(f"{target}: {reason}")
            if repo.baseline_window_release(hunt_id, spec_id, target) is None:
                repo.release_baseline_window_material(
                    hunt_id, spec_id, target, reason or "segment written",
                )
            spec_written += count
            longest = max(longest, seconds)
        written += spec_written
        summaries[spec_id] = {
            "written": spec_written,
            "reason": "; ".join(reasons) if reasons else None,
        }
    return {
        "status": "complete", "written": written, "stale": stale,
        "max_write_seconds": longest, "specs": summaries,
    }


def _write_target(repo: Repo, hunt_id: str, spec, target: str, *, site: str,
                  window: tuple[datetime, datetime], normalizer: str, network_digest: str | None,
                  networks_configured: bool, blocked: str | None) -> tuple[str | None, int, float]:
    """One (target, spec) decision: (the reason nothing was written or None, segments written, write seconds)."""
    released = repo.baseline_window_release(hunt_id, spec.id, target)
    if released is not None:
        # Finish an interrupted release; the material is not used again.
        repo.release_baseline_window_material(hunt_id, spec.id, target, released)
        return f"window counter material was released earlier ({released})", 0, 0.0
    if spec.requires_configured_networks and not networks_configured:
        return "internal networks not configured for this site", 0, 0.0
    if blocked is not None:
        return blocked, 0, 0.0
    cells = [row for row in repo.rule_cells(hunt_id, rule_id=spec.id)
             if row["rule_version"] == spec.version
             if row["target"] == target and row["partition"] != "window"
             and row["state"] != "split"]
    if not cells:
        return "no window cells", 0, 0.0
    bad = [row for row in cells if row["state"] not in _COMPLETE_CELL_STATES]
    if bad:
        return f"{len(bad)} incomplete window cell(s)", 0, 0.0
    spans = {row["partition"]: _cell_span(row["partition"]) for row in cells}
    unplaced = sorted(partition for partition, span in spans.items() if span is None)
    if unplaced:
        return f"window cell {unplaced[0]} names no time interval", 0, 0.0
    span = whole_hour_span(*window, list(spans.values()))
    if span is None:
        return "the window holds no whole hour", 0, 0.0
    if spec.deduplicates_records and any(
            cell_span[0] < span[0] < cell_span[1] for cell_span in spans.values()
    ):
        return "a deduplicated window cell straddles the retained whole-hour span", 0, 0.0
    if span != window and repo.baseline_window_has_unplaced_counts(
            hunt_id, spec.id, spec.version, target
    ):
        return "legacy window count material has no hour; the window cell must be swept again", 0, 0.0
    inside = [row for row in cells
              if span[0] <= spans[row["partition"]][0] and spans[row["partition"]][1] <= span[1]]
    event_total = event_rows = 0
    for item in repo.baseline_window_merged_event_hours(
            hunt_id, spec.id, target, spec_version=spec.version, span=span
    ):
        event_total += int(item["events"])
        event_rows += 1
    if event_rows == 0:
        # Resume compatibility for material staged before migration 0022.
        event_total = sum(int(cell.get("evaluated") or 0) for cell in inside)
    excluded = set(repo.baseline_exclusion_keys(
        site=site, target=target, spec_id=spec.id, spec_version=spec.version,
        key_version=spec.key_version, start=span[0], end=span[1],
    ))
    digest = exclusion_digest(list(excluded))
    base_id = segment_content_id(
        site=site, target=target, spec=spec, start=span[0], end=span[1],
        normalizer=normalizer, exclusion_digest=digest, excluded_keys=sorted(excluded),
        origin="hunt", network_digest=network_digest,
    )
    segment_id = repo.usable_baseline_segment_id(base_id)
    row = {
        "id": segment_id, "site": site, "target": target,
        "spec_id": spec.id, "spec_version": spec.version, "key_version": spec.key_version,
        "normalizer": normalizer, "start": span[0], "end": span[1], "bucket": spec.bucket,
        "origin": "hunt", "source_hunt_id": hunt_id, "built_by_hunt_id": hunt_id,
        "exclusion_digest": digest, "excluded_keys": sorted(excluded), "hunted": 1,
        "network_digest": network_digest if spec.requires_configured_networks else None,
        "events_total": event_total,
        "status": "building", "created_at": utcnow(),
    }
    state = repo.begin_baseline_segment(row, reclaim_owner=True)
    if state == "active":
        return None, 0, 0.0
    if state != "begun":
        return f"segment {segment_id} is {state}", 0, 0.0
    seconds = repo.append_baseline_segment_rows(
        segment_id,
        ({"segment_id": segment_id, **item} for item in _without_excluded(
            repo.baseline_window_merged_counts(
                hunt_id, spec.id, target, spec_version=spec.version, span=span,
            ), excluded,
        )),
        ({"segment_id": segment_id, **item} for item in
         repo.baseline_window_merged_scope_hours(
             hunt_id, spec.id, target, spec_version=spec.version, span=span,
         )),
    )
    repo.finalize_baseline_segment(segment_id)
    return None, 1, seconds
