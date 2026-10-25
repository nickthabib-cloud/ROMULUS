"""Publish a finished hunt's complete window hours as immutable baseline segments.

The write decision is made per (target, spec, hour) from that hour's own sweep cells: an hour whose window cells are
all complete and cover it is written, whatever happened in unrelated stages (expansion, packets, other rules); an
hour with any incomplete input is never written and stays honestly absent from history. Each maximal run of written
hours is one segment.

The hunt's window counter material is released once the writer has run for a finished hunt. A partial (resumable)
hunt keeps it only until its resumed run finishes, charged to one store-wide disk budget that releases the oldest
retained material first, so it is never unbounded.
"""
from __future__ import annotations

import bisect
import json
from collections import defaultdict
from datetime import UTC, datetime, timedelta

from romulus.baseline.carry import CarryInStore, PendingResolver
from romulus.baseline.lookback import exclusion_digest, segment_content_id
from romulus.baseline.spec import SPEC_BY_ID, KeyContext, Pending
from romulus.detect import netdef
from romulus.evidence.typed import TypedEvent
from romulus.hunt.site_networks import contradiction_reason
from romulus.store.db import utcnow
from romulus.store.repo import BASELINE_EVENTS_BASIS, Repo

_HOUR = timedelta(hours=1)
# Window counter material that finished hunts keep for a resume, across all hunts of the store.
DEFAULT_RETAIN_BYTES = 2_000_000_000
# Hunt states no resume can follow: their material serves nothing once their writer has run.
_UNRESUMABLE = {"completed_within_scope", "canceled"}


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


def whole_hour_span(start: datetime, end: datetime) -> tuple[datetime, datetime] | None:
    """The widest hour-aligned span inside [start, end), or None when the window holds no whole hour.

    Counts and evaluated-record totals are staged per hour, so a source cell may safely straddle either edge.
    """
    low, high = _ceil_hour(start), _floor_hour(end)
    return (low, high) if low < high else None


def _runs(hours: list[datetime]) -> list[tuple[datetime, datetime]]:
    """Maximal runs [start, end) of consecutive hours, in order."""
    runs: list[tuple[datetime, datetime]] = []
    for hour in sorted(hours):
        if runs and runs[-1][1] == hour:
            runs[-1] = (runs[-1][0], hour + _HOUR)
        else:
            runs.append((hour, hour + _HOUR))
    return runs


_INCOMPLETE = "an incomplete window cell"
_UNCOVERED = "no complete window cell covers all of it"
_STRADDLE = "a deduplicated window cell straddles the start of its run"


def cell_complete(cell: dict) -> bool:
    """Whether a window cell's inputs were complete. An empty cell of an inapplicable target is complete only when
    its retrieval was: a partial retrieval is never written as complete, empty history. A cell recorded before
    the flag existed counts only if it states no reason."""
    if cell["state"] == "evaluated_complete":
        return True
    if cell["state"] != "not_applicable_no_events":
        return False
    detail = cell.get("detail") or {}
    return bool(detail.get("retrieval_complete", not detail.get("reasons")))


def writable_runs(cells: list[dict], spans: dict[str, tuple[datetime, datetime]], span: tuple[datetime, datetime],
                  *, deduplicates: bool) -> tuple[list[tuple[datetime, datetime]], dict[str, int]]:
    """The runs of whole hours in `span` whose own window inputs are complete, and the hours not written by reason.

    An hour is written only when every window cell overlapping it is complete and those cells cover all of it. For a
    deduplicating spec a counter's dedup tokens are per cell, so a cell that began before a run's first hour may have
    spent a token on a record outside the run and left an in-run record uncounted: every hour of such a cell is held
    back, until no written run starts inside a cell.
    """
    low, high = span
    hours = [low + index * _HOUR for index in range(int((high - low) / _HOUR))]
    bad: dict[datetime, str] = {}
    pieces: dict[datetime, list[tuple[datetime, datetime]]] = defaultdict(list)
    complete_spans: list[tuple[datetime, datetime]] = []
    for cell in cells:
        start, end = spans[cell["partition"]]
        complete = cell_complete(cell)
        if complete:
            complete_spans.append((start, end))
        hour = max(_floor_hour(start), low)
        while hour < min(end, high):
            if complete:
                pieces[hour].append((max(start, hour), min(end, hour + _HOUR)))
            else:
                bad.setdefault(hour, _INCOMPLETE)
            hour += _HOUR
    for hour in hours:
        if hour in bad:
            continue
        cursor = hour
        for first, last in sorted(pieces.get(hour, ())):
            if first > cursor:
                break
            cursor = max(cursor, last)
        if cursor < hour + _HOUR:
            bad[hour] = _UNCOVERED
    if deduplicates:
        complete_spans.sort()
        while True:
            starts = [run[0] for run in _runs([hour for hour in hours if hour not in bad])]
            changed = False
            for start, end in complete_spans:
                index = bisect.bisect_right(starts, start)
                if index < len(starts) and starts[index] < end:
                    hour = max(_floor_hour(start), low)
                    while hour < min(end, high):
                        if hour not in bad:
                            bad[hour] = _STRADDLE
                            changed = True
                        hour += _HOUR
            if not changed:
                break
    skipped: dict[str, int] = defaultdict(int)
    for reason in bad.values():
        skipped[reason] += 1
    return _runs([hour for hour in hours if hour not in bad]), dict(skipped)


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


def _direction_failure(repo: Repo, hunt_id: str) -> str | None:
    """Why the hunt's own hosts leave its internal-network definition unconfirmed, from its sweep summary."""
    audit = repo.latest_audit(hunt_id, "hunt.sweep_summary")
    check = ((audit or {}).get("detail") or {}).get("internal_networks")
    return contradiction_reason(check) if isinstance(check, dict) else None


def run_hunt_segment_writer(repo: Repo, hunt_id: str, *, hunt_partial: bool, baseline_finished: bool = True,
                            retain_budget_bytes: int = DEFAULT_RETAIN_BYTES,
                            now: datetime | None = None) -> dict:
    """Write the hunt-derived baseline cut hour by hour, then settle the window counter material.

    Every (target, spec) reaches one decision: the runs of hours written (or already in the store), and the hours
    not written with their reasons. The material is then released when the hunt finished complete, or when this is
    the finish of a resumed run of a hunt whose material an earlier finish kept; otherwise it is kept for a resume
    and charged to the disk budget. A baseline stage that has not finished keeps it while the budget allows, since its
    resumed judgement reads it.
    """
    hunt = repo.get_hunt(hunt_id)
    if hunt is None:
        raise KeyError(hunt_id)
    now = now or utcnow()
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
    repo.cleanup_baseline_building(before=now - timedelta(hours=1))
    normalizer = str(manifest.get("normalizer") or "unknown")
    network = manifest.get("internal_networks") or {}
    networks_configured = network.get("source") == "configured"
    direction_failure = _direction_failure(repo, hunt_id)
    summaries: dict[str, dict] = {}
    written = 0
    longest = 0.0
    finished = False
    try:
        for spec_id in specs:
            spec = SPEC_BY_ID[spec_id]
            spec_written = 0
            reasons: list[str] = []
            for target in targets:
                target_reasons, count, seconds = _write_target(
                    repo, hunt_id, spec, target, site=site, window=(start, end), normalizer=normalizer,
                    network_digest=network.get("digest"), networks_configured=networks_configured,
                    direction_failure=direction_failure, blocked=blocked.get((target, spec_id)), now=now,
                )
                reasons.extend(f"{target}: {reason}" for reason in target_reasons)
                spec_written += count
                longest = max(longest, seconds)
            written += spec_written
            summaries[spec_id] = {
                "written": spec_written,
                "reason": "; ".join(reasons) if reasons else None,
            }
        finished = True
    finally:
        # The material is always settled and charged to the budget. A writer interrupted part way keeps it (a later
        # finish can still write from it) rather than releasing what it may not have written.
        material = _settle_material(
            repo, hunt_id, specs, targets, hunt_partial=hunt_partial or not finished,
            baseline_finished=baseline_finished, budget=retain_budget_bytes, now=now, keep=not finished,
        )
    return {
        "status": "complete", "written": written, "stale": stale,
        "max_write_seconds": longest, "specs": summaries, "material": material,
    }


def _write_target(repo: Repo, hunt_id: str, spec, target: str, *, site: str,
                  window: tuple[datetime, datetime], normalizer: str, network_digest: str | None,
                  networks_configured: bool, direction_failure: str | None, blocked: str | None,
                  now: datetime) -> tuple[list[str], int, float]:
    """One (target, spec): (why hours were not written, segments written, longest write in seconds)."""
    released = repo.baseline_window_release(hunt_id, spec.id, target)
    if released is not None:
        # Finish an interrupted release; the material is not used again.
        repo.release_baseline_window_material(hunt_id, spec.id, target, released)
        return [f"window counter material was released earlier ({released})"], 0, 0.0
    if spec.requires_configured_networks and not networks_configured:
        return ["internal networks not configured for this site"], 0, 0.0
    if spec.requires_configured_networks and direction_failure:
        return [direction_failure], 0, 0.0
    if blocked is not None:
        return [blocked], 0, 0.0
    cells = [row for row in repo.rule_cells(hunt_id, rule_id=spec.id)
             if row["rule_version"] == spec.version
             if row["target"] == target and row["partition"] != "window"
             and row["state"] != "split"]
    if not cells:
        return ["no window cells"], 0, 0.0
    spans = {row["partition"]: _cell_span(row["partition"]) for row in cells}
    unplaced = sorted(partition for partition, span in spans.items() if span is None)
    if unplaced:
        return [f"window cell {unplaced[0]} names no time interval"], 0, 0.0
    whole = whole_hour_span(*window)
    if whole is None:
        return ["the window holds no whole hour"], 0, 0.0
    runs, skipped = writable_runs(cells, spans, whole, deduplicates=spec.deduplicates_records)
    reasons = [f"{hours} hour(s) not written: {reason}" for reason, hours in sorted(skipped.items())]
    legacy_unplaced = repo.baseline_window_has_unplaced_counts(hunt_id, spec.id, spec.version, target)
    count = 0
    longest = 0.0
    for run in runs:
        hours = int((run[1] - run[0]) / _HOUR)
        if spec.deduplicates_records and repo.baseline_window_dedup_bucket_spans_cells(
                hunt_id, spec.id, spec.version, target, run,
        ):
            reasons.append(f"{hours} hour(s) not written: a deduplicated bucket spans multiple window cells")
            continue
        if legacy_unplaced and run != window:
            reasons.append(f"{hours} hour(s) not written: legacy window count material has no hour; the window "
                           "cell must be swept again")
            continue
        try:
            reason, written, seconds = _write_run(
                repo, hunt_id, spec, target, run, cells, spans, site=site, normalizer=normalizer,
                network_digest=network_digest, now=now,
            )
        except ValueError as error:
            # A refused segment (an id already stored with other content, an invalid row) costs only this run.
            reason, written, seconds = f"segment refused: {error}"[:300], 0, 0.0
        if reason is not None:
            reasons.append(f"{hours} hour(s) not written: {reason}")
        count += written
        longest = max(longest, seconds)
    return reasons, count, longest


def _write_run(repo: Repo, hunt_id: str, spec, target: str, run: tuple[datetime, datetime], cells: list[dict],
               spans: dict[str, tuple[datetime, datetime]], *, site: str, normalizer: str,
               network_digest: str | None, now: datetime) -> tuple[str | None, int, float]:
    """Write one run of complete hours as one segment: (the reason it was not written or None, written, seconds)."""
    event_total = 0
    first_hour: datetime | None = None
    # one row per hour of the run holding records: bounded by the run's hours, never by its keys
    event_hours: list[dict] = []
    for item in repo.baseline_window_merged_event_hours(
            hunt_id, spec.id, target, spec_version=spec.version, span=run
    ):
        events = int(item["events"])
        event_total += events
        if events:
            event_hours.append({"hour": item["hour"], "events": events})
            if first_hour is None:
                first_hour = item["hour"]
    if event_total == 0:
        # Material staged before per-hour event totals existed carries only each cell's evaluated count: it cannot
        # place the run's first record in an hour, so such a run is not written.
        evaluated = sum(int(cell.get("evaluated") or 0) for cell in cells
                        if spans[cell["partition"]][0] < run[1] and spans[cell["partition"]][1] > run[0])
        if evaluated:
            return "window material has no per-hour event totals", 0, 0.0
    excluded = set(repo.baseline_exclusion_keys(
        site=site, target=target, spec_id=spec.id, spec_version=spec.version,
        key_version=spec.key_version, start=run[0], end=run[1],
    ))
    digest = exclusion_digest(list(excluded))
    base_id = segment_content_id(
        site=site, target=target, spec=spec, start=run[0], end=run[1],
        normalizer=normalizer, exclusion_digest=digest, excluded_keys=sorted(excluded),
        origin="hunt", network_digest=network_digest,
    )
    segment_id = repo.usable_baseline_segment_id(base_id)
    row = {
        "id": segment_id, "site": site, "target": target,
        "spec_id": spec.id, "spec_version": spec.version, "key_version": spec.key_version,
        "normalizer": normalizer, "start": run[0], "end": run[1], "bucket": spec.bucket,
        "origin": "hunt", "source_hunt_id": hunt_id, "built_by_hunt_id": hunt_id,
        "exclusion_digest": digest, "excluded_keys": sorted(excluded), "hunted": 1,
        "network_digest": network_digest if spec.requires_configured_networks else None,
        "events_total": event_total, "events_basis": BASELINE_EVENTS_BASIS, "first_event_hour": first_hour,
        "status": "building", "created_at": now,
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
                hunt_id, spec.id, target, spec_version=spec.version, span=run,
            ), excluded,
        )),
        ({"segment_id": segment_id, **item} for item in
         repo.baseline_window_merged_scope_hours(
             hunt_id, spec.id, target, spec_version=spec.version, span=run,
         )),
        event_hours,
    )
    repo.finalize_baseline_segment(segment_id)
    return None, 1, seconds


def _hunt_pairs(repo: Repo, hunt_id: str) -> set[tuple[str, str]]:
    """The (spec, target) pairs a hunt's sweep can stage material under: its manifest's baseline specs and targets.

    Read from the manifest rather than the material, so settling a large hunt never scans its rows."""
    manifest = (repo.get_hunt(hunt_id) or {}).get("manifest") or {}
    specs = {str(item["id"]) for item in (manifest.get("baseline") or {}).get("specs") or []}
    return {(spec_id, str(target)) for spec_id in specs for target in manifest.get("targets") or []}


def _release_hunt(repo: Repo, hunt_id: str, pairs, reason: str) -> int:
    """Release every listed (spec, target) of one hunt and its charge; returns the rows deleted."""
    deleted = 0
    for spec_id, target in sorted(set(pairs)):
        deleted += repo.release_baseline_window_material(hunt_id, spec_id, target, reason)
    repo.drop_baseline_window_retention(hunt_id)
    return deleted


def _lease_active(hunt: dict, now: datetime) -> bool:
    lease = hunt.get("lease_until")
    if lease is None:
        return False
    if lease.tzinfo is None:
        lease = lease.replace(tzinfo=UTC)
    return lease > now


def _settle_material(repo: Repo, hunt_id: str, specs: list[str], targets: list[str], *, hunt_partial: bool,
                     baseline_finished: bool, budget: int, now: datetime, keep: bool = False) -> dict:
    """Release this hunt's window counter material or keep it for a resume, then hold the store to the budget.

    With `keep` (the writer was interrupted) the material is kept and charged whatever the hunt's state."""
    retained = repo.baseline_window_retention(hunt_id)
    pairs = {(spec_id, target) for spec_id in specs for target in targets}
    if keep:
        size = repo.baseline_window_material_bytes(hunt_id)
        why = "kept: the segment writer was interrupted before it decided every hour"
        repo.retain_baseline_window_material(hunt_id, bytes_=size, retained_at=now, reason=why)
        decision = {"kept": True, "reason": why, "bytes": size}
    elif baseline_finished and not hunt_partial:
        _release_hunt(repo, hunt_id, pairs, "the hunt finished complete and its segment writer ran")
        decision = {"kept": False, "reason": "the hunt finished complete"}
    elif baseline_finished and retained is not None:
        _release_hunt(repo, hunt_id, pairs, "the resumed hunt finished and its segment writer ran")
        decision = {"kept": False, "reason": "the resumed hunt finished; material is kept through one resume"}
    else:
        size = repo.baseline_window_material_bytes(hunt_id)
        why = ("kept for a resumed run" if baseline_finished
               else "kept for the resumed baseline stage, which judges from it")
        repo.retain_baseline_window_material(hunt_id, bytes_=size, retained_at=now, reason=why)
        decision = {"kept": True, "reason": why, "bytes": size}
    # Material of other hunts that no finish ever settled (a crashed run, or a store written before this ledger) is
    # charged too, so nothing outside the budget accumulates. A hunt that holds an active lease is still running.
    for other in repo.baseline_window_material_hunts():
        if other == hunt_id or repo.baseline_window_retention(other) is not None:
            continue
        row = repo.get_hunt(other)
        if row is None or row["execution_state"] == "planned" or _lease_active(row, now):
            continue
        if row["execution_state"] not in _UNRESUMABLE:
            since = row.get("ended_at") or row.get("heartbeat_at") or row["created_at"]
            if since.tzinfo is None:
                since = since.replace(tzinfo=UTC)
            repo.retain_baseline_window_material(
                other, bytes_=repo.baseline_window_material_bytes(other), retained_at=since,
                reason="kept from an earlier unsettled finish",
            )
        else:
            _release_hunt(repo, other, _hunt_pairs(repo, other),
                          "the hunt finished; its material outlived the release")
    charges = repo.baseline_window_retentions()
    total = sum(int(item["bytes"]) for item in charges)
    evicted: list[str] = []
    reason = f"retained window material exceeded the disk budget of {budget} bytes; the oldest is released first"
    own = next((item for item in charges if item["hunt_id"] == hunt_id), None)
    if own is not None and int(own["bytes"]) > budget:
        # This hunt's material alone exceeds the budget: it goes first, and older material that fits stays.
        _release_hunt(repo, hunt_id, pairs, f"this hunt's window material alone exceeded the disk budget of "
                                            f"{budget} bytes")
        total -= int(own["bytes"])
        evicted.append(hunt_id)
        charges = [item for item in charges if item["hunt_id"] != hunt_id]
    for item in charges:
        if total <= budget:
            break
        if item["hunt_id"] != hunt_id:
            # A hunt holding an active lease is running (for example, a resumed baseline stage judging from its
            # material): its material is never released under it. Its own finish settles it.
            row = repo.get_hunt(item["hunt_id"])
            if row is not None and _lease_active(row, now):
                continue
        _release_hunt(repo, item["hunt_id"], _hunt_pairs(repo, item["hunt_id"]), reason)
        total -= int(item["bytes"])
        evicted.append(item["hunt_id"])
    if hunt_id in evicted:
        decision = {"kept": False, "reason": f"released: retained window material exceeded the disk budget of "
                                             f"{budget} bytes"}
    return {**decision, "retained_bytes": total, "budget_bytes": budget, "over_budget": total > budget,
            "released_hunts": sorted(item for item in evicted if item != hunt_id)}
