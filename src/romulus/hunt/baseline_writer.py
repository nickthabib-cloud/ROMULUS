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


def _canonical(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _window(manifest: dict) -> tuple[datetime, datetime]:
    row = manifest["window"]
    return datetime.fromisoformat(row["start"]).astimezone(UTC), datetime.fromisoformat(row["end"]).astimezone(UTC)


def _cited_exclusions(repo: Repo, hunt_id: str, targets: set[str], spec_ids: set[str]) -> dict[tuple[str, str], set[str]]:
    candidates = repo.candidates(hunt_id, ["urgent", "high", "lead"])
    event_ids = sorted({event_id for row in candidates for event_id in row.get("event_ids") or []})
    found: dict[tuple[str, str], set[str]] = {}
    hunt = repo.get_hunt(hunt_id)
    _start, horizon = _window(hunt["manifest"] if hunt else {})
    resolvers: dict[tuple[str, str], PendingResolver] = {}
    for row in repo.citation_events(hunt_id, event_ids):
        event = TypedEvent.model_validate(row["event"])
        event_targets = sorted({ref.target for ref in event.raw} & targets)
        if not event_targets:
            continue
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
                        continue
                    resolved = resolution.keys
                if isinstance(resolved, (list, tuple)):
                    found.setdefault((target, spec_id), set()).update(
                        key.key_digest for key in resolved
                    )
    return found


def _without_excluded(rows, excluded: set[str]):
    for row in rows:
        if row["key_digest"] not in excluded:
            yield row


def run_hunt_segment_writer(repo: Repo, hunt_id: str, *, hunt_complete: bool) -> dict:
    """Write the hunt-derived baseline cut, or state why a partial hunt wrote nothing."""
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
    current_exclusions = _cited_exclusions(repo, hunt_id, set(targets), set(specs))
    repo.replace_baseline_hunt_exclusions(
        hunt_id, site=site, start=start, end=end, exclusions=current_exclusions,
    )
    stale = repo.stale_baseline_segments_for_exclusions(site=site, start=start, end=end)
    repo.cleanup_baseline_building(before=utcnow() - timedelta(hours=1))
    if not hunt_complete:
        return {
            "status": "skipped",
            "written": 0,
            "stale": stale,
            "max_write_seconds": 0.0,
            "specs": {spec_id: {"written": 0, "reason": "hunt is partial"} for spec_id in specs},
        }
    normalizer = str(manifest.get("normalizer") or "unknown")
    network = manifest.get("internal_networks") or {}
    summaries: dict[str, dict] = {}
    written = 0
    longest = 0.0
    for spec_id in specs:
        spec = SPEC_BY_ID[spec_id]
        spec_written = 0
        reasons: list[str] = []
        for target in targets:
            cells = [row for row in repo.rule_cells(hunt_id, rule_id=spec_id)
                     if row["target"] == target and row["partition"] != "window"]
            bad = [row for row in cells if row["state"] not in _COMPLETE_CELL_STATES]
            if not cells:
                reasons.append(f"{target}: no window cells")
                continue
            if bad:
                reasons.append(f"{target}: {len(bad)} incomplete window cell(s)")
                continue
            excluded = set(repo.baseline_exclusion_keys(
                site=site, target=target, spec_id=spec_id, start=start, end=end,
            ))
            digest = exclusion_digest(list(excluded))
            base_id = segment_content_id(
                site=site, target=target, spec=spec, start=start, end=end,
                normalizer=normalizer, exclusion_digest=digest, excluded_keys=sorted(excluded),
                origin="hunt", network_digest=network.get("digest"),
            )
            segment_id = repo.usable_baseline_segment_id(base_id)
            row = {
                "id": segment_id, "site": site, "target": target,
                "spec_id": spec.id, "spec_version": spec.version, "key_version": spec.key_version,
                "normalizer": normalizer, "start": start, "end": end, "bucket": spec.bucket,
                "origin": "hunt", "source_hunt_id": hunt_id, "built_by_hunt_id": hunt_id,
                "exclusion_digest": digest, "excluded_keys": sorted(excluded), "hunted": 1,
                "network_digest": network.get("digest") if spec.requires_configured_networks else None,
                "events_total": sum(int(cell.get("evaluated") or 0) for cell in cells),
                "status": "building", "created_at": utcnow(),
            }
            state = repo.begin_baseline_segment(row, reclaim_owner=True)
            if state == "active":
                continue
            if state != "begun":
                reasons.append(f"{target}: segment {segment_id} is {state}")
                continue
            seconds = repo.append_baseline_segment_rows(
                segment_id,
                ({"segment_id": segment_id, **item} for item in _without_excluded(
                    repo.baseline_window_merged_counts(hunt_id, spec_id, target), excluded,
                )),
                ({"segment_id": segment_id, **item} for item in
                 repo.baseline_window_merged_scope_hours(hunt_id, spec_id, target)),
            )
            longest = max(longest, seconds)
            repo.finalize_baseline_segment(segment_id)
            written += 1
            spec_written += 1
        summaries[spec_id] = {
            "written": spec_written,
            "reason": "; ".join(reasons) if reasons else None,
        }
    return {
        "status": "complete", "written": written, "stale": stale,
        "max_write_seconds": longest, "specs": summaries,
    }
