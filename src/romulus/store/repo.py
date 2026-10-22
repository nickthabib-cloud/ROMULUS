"""Idempotent repository operations over the single SQLite authority."""
from __future__ import annotations

import hashlib
import json
import time
import uuid
from collections.abc import Iterable, Iterator
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from itertools import islice
from typing import Any, ClassVar

from sqlalchemy import Engine, and_, func, or_, select, true, tuple_
from sqlalchemy.dialects.sqlite import insert

from romulus.store import schema as t
from romulus.store.db import utcnow, write_txn

# The origin suffix of a boot id a hunt's boot-interval map placed (the normalizer's BOOT_INTERVAL_ORIGIN; the
# store does not import the evidence layer, and a test keeps the two equal).
DERIVED_BOOT_SUFFIX = "#derived:boot-interval"


def is_derived_boot(field: dict | None) -> bool:
    """Whether a stored boot id field was placed by a boot-interval map rather than stated by a record."""
    origin = (field or {}).get("origin")
    return isinstance(origin, str) and origin.endswith(DERIVED_BOOT_SUFFIX)


# Lanes an analyst may join with an asserted link (the report's reportable lanes).
REPORTABLE_LANES = ("urgent", "high", "lead")


# Rows per executemany call: one compiled single-row statement runs over each chunk, so a batch of any size never
# meets SQLite's limit on bind parameters per statement, and the parameter lists stay bounded.
INSERT_CHUNK = 5000


@lru_cache(maxsize=64)          # one entry per (table, key) the store writes
def _insert_ignore(table, keys: tuple[str, ...]):
    """INSERT ... ON CONFLICT DO NOTHING for one row; built once per (table, keys) so SQLAlchemy compiles it once."""
    return insert(table).on_conflict_do_nothing(index_elements=list(keys))


def _upsert_ignore(conn, table, rows: list[dict], keys: list[str]):
    """Insert rows that are not stored yet. A row whose key is stored, or repeats an earlier row of the batch,
    is skipped: the first written wins."""
    if not rows:
        return
    stmt = _insert_ignore(table, tuple(keys))
    for start in range(0, len(rows), INSERT_CHUNK):
        conn.execute(stmt, rows[start:start + INSERT_CHUNK])


def _rule_cell_upsert():
    stmt = insert(t.rule_run)
    return stmt.on_conflict_do_update(
        index_elements=["hunt_id", "rule_id", "rule_version", "target", "partition"],
        set_={name: stmt.excluded[name] for name in ("state", "matched", "evaluated", "detail")})


_RULE_CELL_UPSERT = _rule_cell_upsert()


def raw_id(target: str, native_id: str) -> str:
    return hashlib.sha256(f"{target}/{native_id}".encode()).hexdigest()[:32]


# ---- baseline probes ------------------------------------------------------------------------
# Each probe ranges over a data index and probes the frozen snapshot membership primary key. Snapshot
# membership is data, never a Python-generated SQL IN list, so probe shape stays bounded at mission scale.
def baseline_prevalence_query(key_id: str, scope_kind: str, hunt_id: str):
    """Distinct scopes of `scope_kind` holding `key_id` in one hunt's frozen snapshot."""
    c, m = t.baseline_count.c, t.baseline_snapshot_segment.c
    scopes = (select(c.scope)
              .join(t.baseline_snapshot_segment, and_(m.segment_id == c.segment_id, m.hunt_id == hunt_id))
              .where(c.key_id == key_id, c.scope_kind == scope_kind)
              .group_by(c.scope).subquery())
    return select(func.count()).select_from(scopes)


def baseline_key_history_query(key_id: str, scope_kind: str, scope: str, hunt_id: str):
    """Every count row of one key in one scope across the segments (ix_baseline_count_key)."""
    c, m = t.baseline_count.c, t.baseline_snapshot_segment.c
    return (select(c.segment_id, c.bucket, c.count, c.first_ts, c.last_ts)
            .join(t.baseline_snapshot_segment, and_(m.segment_id == c.segment_id, m.hunt_id == hunt_id))
            .where(c.key_id == key_id, c.scope_kind == scope_kind, c.scope == scope)
            .order_by(c.key_id, c.scope_kind, c.scope, c.segment_id))


def baseline_peer_scopes_query(scope_kind: str, hunt_id: str):
    """Distinct live scopes of `scope_kind` in the segments (ix_baseline_scope_hour_lookup, covering)."""
    c, m = t.baseline_scope_hour.c, t.baseline_snapshot_segment.c
    scopes = (select(c.scope)
              .join(t.baseline_snapshot_segment, and_(m.segment_id == c.segment_id, m.hunt_id == hunt_id))
              .where(c.scope_kind == scope_kind).group_by(c.scope).subquery())
    return select(func.count()).select_from(scopes)


def observation_citations_query(hunt_id: str):
    """(event id, citing hunt) for every event `hunt_id` stored that another hunt's baseline observation cites
    as its first event, the lowest citing hunt id when several do: one walk of the hunt's events in id order,
    each probing ix_baseline_observation_first_event."""
    obs, ev = t.baseline_observation.c, t.typed_event.c
    return (select(ev.id, func.min(obs.hunt_id))
            .join(t.baseline_observation, obs.first_event_id == ev.id)
            .where(ev.hunt_id == hunt_id, obs.hunt_id != hunt_id)
            .group_by(ev.id))


def baseline_scope_series_query(scope_kind: str, scope: str, hunt_id: str):
    """One scope's live hours and event totals across the segments (ix_baseline_scope_hour_lookup)."""
    c, m = t.baseline_scope_hour.c, t.baseline_snapshot_segment.c
    return (select(c.segment_id, c.hour, c.events)
            .join(t.baseline_snapshot_segment, and_(m.segment_id == c.segment_id, m.hunt_id == hunt_id))
            .where(c.scope_kind == scope_kind, c.scope == scope)
            .order_by(c.scope_kind, c.scope, c.segment_id, c.hour))


# ---- baseline rows ---------------------------------------------------------------------------
BASELINE_CHUNK = 5000      # rows per executemany batch while streaming a segment or observations
BASELINE_PAGE = 5000       # rows per keyset page on reads
_BUCKET_WIDTH = {"day": timedelta(days=1), "hour": timedelta(hours=1)}
_SEGMENT_COLUMNS = frozenset(column.name for column in t.baseline_segment.columns) - {"rows_digest"}
_SEGMENT_OPTIONAL = frozenset({"source_hunt_id", "built_by_hunt_id"})
# What makes two writes of one segment id the same segment: everything but its lifecycle status and the time
# this copy was written (the rows are compared through rows_digest).
_SEGMENT_IDENTITY = tuple(sorted(_SEGMENT_COLUMNS - {"status", "created_at"}))
_COUNT_COLUMNS = tuple(column.name for column in t.baseline_count.columns)
_HOUR_COLUMNS = tuple(column.name for column in t.baseline_scope_hour.columns)
_OBSERVATION_COLUMNS = tuple(column.name for column in t.baseline_observation.columns)
_OBSERVATION_KEY = ("hunt_id", "spec_id", "spec_version", "scope", "key_digest")
_OBSERVATION_REQUIRED = frozenset({*_OBSERVATION_KEY, "scope_kind", "key_id", "key", "window_count", "verdict"})


def _utc(value: Any, name: str) -> datetime:
    """A timezone-aware time as UTC; a naive time is refused, never assumed to be UTC."""
    if not isinstance(value, datetime):
        # every invalid baseline row is one error type, so a writer handles a refusal in one place
        raise ValueError(f"baseline {name} must be a datetime, not {type(value).__name__}")  # noqa: TRY004
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"baseline {name} must carry a timezone (naive time refused)")
    return value.astimezone(UTC)


def _stored_utc(value: datetime | None) -> datetime | None:
    """SQLite returns naive values; every baseline time was stored as UTC."""
    return value.replace(tzinfo=UTC) if value is not None and value.tzinfo is None else value


def _with_utc(row, columns: tuple[str, ...]) -> dict:
    out = dict(row)
    for name in columns:
        out[name] = _stored_utc(out.get(name))
    return out


def _columns(row: dict, allowed: frozenset[str] | tuple[str, ...], optional: frozenset[str], what: str) -> None:
    allowed = frozenset(allowed)
    unknown, missing = set(row) - allowed, allowed - optional - set(row)
    if unknown or missing:
        raise ValueError(f"baseline {what} column mismatch: unknown {sorted(unknown)}, missing {sorted(missing)}")


def _text_value(row: dict, name: str, what: str) -> None:
    if not isinstance(row.get(name), str) or not row[name]:
        raise ValueError(f"baseline {what} {name} must be a non-empty string")


def _aligned(value: datetime, width: timedelta) -> bool:
    if (value.minute, value.second, value.microsecond) != (0, 0, 0):
        return False
    return width == _BUCKET_WIDTH["hour"] or value.hour == 0


def _baseline_segment_row(row: dict) -> dict:
    _columns(row, _SEGMENT_COLUMNS, _SEGMENT_OPTIONAL, "segment")
    out = {name: row.get(name) for name in _SEGMENT_COLUMNS}
    for name in ("start", "end", "created_at"):
        out[name] = _utc(row[name], name)
    if not (_aligned(out["start"], _BUCKET_WIDTH["hour"]) and _aligned(out["end"], _BUCKET_WIDTH["hour"])):
        raise ValueError("baseline segment span must be hour-aligned")
    if out["start"] >= out["end"]:
        raise ValueError("baseline segment start before end is required")
    if out["bucket"] not in _BUCKET_WIDTH:
        raise ValueError(f"baseline segment bucket must be day or hour, not {out['bucket']!r}")
    return out


def _baseline_count_row(row: dict, segment: dict) -> dict:
    _columns(row, _COUNT_COLUMNS, frozenset(), "count")
    if row["segment_id"] != segment["id"]:
        raise ValueError("baseline child row belongs to a different segment")
    for name in ("scope_kind", "scope", "key_id", "key_digest"):
        _text_value(row, name, "count")
    if not isinstance(row["key"], dict):
        raise ValueError("baseline count key must be a JSON object")  # noqa: TRY004
    if isinstance(row["count"], bool) or not isinstance(row["count"], int) or row["count"] < 1:
        raise ValueError("baseline count must be a positive integer")
    out = dict(row)
    for name in ("bucket", "first_ts", "last_ts"):
        out[name] = _utc(row[name], name)
    width, start, end = _BUCKET_WIDTH[segment["bucket"]], segment["start"], segment["end"]
    bucket = out["bucket"]
    if not _aligned(bucket, width) or not (bucket < end and bucket + width > start):
        raise ValueError(f"baseline count bucket {bucket.isoformat()} is not a {segment['bucket']} bucket "
                         f"overlapping the segment span")
    if not (max(start, bucket) <= out["first_ts"]):
        raise ValueError("baseline count first_ts is before its bucket or the segment span")
    if out["first_ts"] > out["last_ts"]:
        raise ValueError("baseline count first_ts is after last_ts")
    if not (out["last_ts"] < min(end, bucket + width)):
        raise ValueError("baseline count last_ts is not inside its bucket and the segment span")
    return out


def _baseline_hour_row(row: dict, segment: dict) -> dict:
    _columns(row, _HOUR_COLUMNS, frozenset(), "scope hour")
    if row["segment_id"] != segment["id"]:
        raise ValueError("baseline child row belongs to a different segment")
    for name in ("scope_kind", "scope"):
        _text_value(row, name, "scope hour")
    if isinstance(row["events"], bool) or not isinstance(row["events"], int) or row["events"] < 0:
        raise ValueError("baseline scope hour events must be a non-negative integer")
    out = dict(row)
    out["hour"] = hour = _utc(row["hour"], "hour")
    if not _aligned(hour, _BUCKET_WIDTH["hour"]):
        raise ValueError("baseline scope hour must be hour-aligned")
    if not segment["start"] <= hour < segment["end"]:
        raise ValueError("baseline scope hour must be inside the segment span")
    return out


def _jsonable(value: Any) -> Any:
    return value.isoformat() if isinstance(value, datetime) else value


class _RowsDigest:
    """Order-independent digest of a segment's child rows: a sum of per-row hashes, plus the row counts."""

    def __init__(self) -> None:
        self.total, self.rows = 0, {"count": 0, "hour": 0}

    def add(self, kind: str, columns: tuple[str, ...], rows: list[dict]) -> None:
        for row in rows:
            material = json.dumps([kind, *(_jsonable(row[name]) for name in columns)], sort_keys=True,
                                  separators=(",", ":"), ensure_ascii=False)
            self.total = (self.total + int.from_bytes(hashlib.sha256(material.encode()).digest())) % (1 << 256)
        self.rows[kind] += len(rows)

    def hexdigest(self) -> str:
        return hashlib.sha256(f"{self.rows['count']}|{self.rows['hour']}|{self.total:064x}".encode()).hexdigest()


def _chunks(rows: Iterable[dict], size: int) -> Iterator[list[dict]]:
    if size < 1:
        raise ValueError("chunk size must be positive")
    iterator = iter(rows)
    while chunk := list(islice(iterator, size)):
        yield chunk


class Repo:
    def __init__(self, engine: Engine):
        self.engine = engine

    # ---- hunts ------------------------------------------------------------------------------
    def create_hunt(self, hunt_id: str, manifest: dict, digest_: str, created_by: str, parent: str | None = None):
        with write_txn(self.engine) as c:
            c.execute(t.hunt.insert().values(id=hunt_id, created_at=utcnow(), created_by=created_by, manifest=manifest,
                                             manifest_digest=digest_, parent_hunt_id=parent, execution_state="planned"))
            c.execute(t.audit_event.insert().values(at=utcnow(), actor=created_by, action="hunt.create",
                                                    hunt_id=hunt_id, detail={"digest": digest_}))

    def get_hunt(self, hunt_id: str) -> dict | None:
        with self.engine.connect() as c:
            r = c.execute(select(t.hunt).where(t.hunt.c.id == hunt_id)).mappings().first()
            return dict(r) if r else None

    def list_hunts(self) -> list[dict]:
        with self.engine.connect() as c:
            return [dict(r) for r in c.execute(select(t.hunt).order_by(t.hunt.c.created_at.desc())).mappings()]

    @staticmethod
    def _fence_lease(c, hunt_id: str, owner_token: str | None) -> None:
        """Take SQLite's write lock while proving this worker still owns the hunt lease."""
        if owner_token is None:
            return
        fenced = c.execute(t.hunt.update().where(
            t.hunt.c.id == hunt_id,
            t.hunt.c.execution_state == "running",
            t.hunt.c.lease_owner == owner_token,
        ).values(lease_owner=t.hunt.c.lease_owner))
        if fenced.rowcount != 1:
            raise RuntimeError(f"hunt {hunt_id} lease ownership lost")

    def claim_hunt(self, hunt_id: str, lease_seconds: int, resume: bool = False,
                   now: datetime | None = None, owner_token: str | None = None) -> dict:
        """Claim a planned hunt or safely reclaim a resumable hunt."""
        now = now or utcnow()
        owner_token = owner_token or uuid.uuid4().hex
        lease_until = now + timedelta(seconds=lease_seconds)
        with write_txn(self.engine) as c:
            current = c.execute(select(t.hunt).where(t.hunt.c.id == hunt_id)).mappings().one()
            state = current["execution_state"]
            action = "hunt.claim"
            if resume:
                if state == "running":
                    current_lease = current["lease_until"]
                    if current_lease is not None:
                        if current_lease.tzinfo is None:
                            current_lease = current_lease.replace(tzinfo=UTC)
                        if current_lease > now:
                            raise RuntimeError(f"hunt {hunt_id} has an active lease")
                    action = "hunt.resume_stale"
                elif state in {"partial", "failed"}:
                    action = "hunt.resume"
                else:
                    raise ValueError(f"hunt {hunt_id} in state {state} cannot be resumed")
            elif state != "planned":
                raise ValueError(f"hunt {hunt_id} in state {state} cannot be claimed")

            values: dict[str, Any] = {
                "execution_state": "running",
                "heartbeat_at": now,
                "lease_until": lease_until,
                "lease_owner": owner_token,
                "ended_at": None,
            }
            if state == "planned":
                values["started_at"] = now
            claim_condition = and_(t.hunt.c.id == hunt_id, t.hunt.c.execution_state == state)
            if state == "running":
                claim_condition = and_(
                    claim_condition,
                    or_(t.hunt.c.lease_until.is_(None), t.hunt.c.lease_until <= now),
                )
            updated = c.execute(t.hunt.update().where(claim_condition).values(**values))
            if updated.rowcount != 1:
                raise RuntimeError(f"hunt {hunt_id} state or lease changed while claiming it")
            c.execute(t.audit_event.insert().values(
                at=now, actor="system", action=action, hunt_id=hunt_id,
                detail={"previous_state": state, "lease_seconds": lease_seconds},
            ))
            claimed = c.execute(select(t.hunt).where(t.hunt.c.id == hunt_id)).mappings().one()
            return dict(claimed)

    def heartbeat_hunt(self, hunt_id: str, lease_seconds: int, now: datetime | None = None,
                       *, owner_token: str | None = None) -> dict:
        now = now or utcnow()
        with write_txn(self.engine) as c:
            conditions = [t.hunt.c.id == hunt_id, t.hunt.c.execution_state == "running"]
            if owner_token is not None:
                conditions.append(t.hunt.c.lease_owner == owner_token)
            updated = c.execute(t.hunt.update().where(*conditions).values(
                heartbeat_at=now, lease_until=now + timedelta(seconds=lease_seconds),
            ))
            if updated.rowcount != 1:
                reason = "lease ownership lost" if owner_token is not None else "is not running"
                raise RuntimeError(f"hunt {hunt_id} {reason}")
            row = c.execute(select(t.hunt).where(t.hunt.c.id == hunt_id)).mappings().one()
            return dict(row)

    FINISHED_STATES: ClassVar[set[str]] = {"completed_within_scope", "partial", "failed", "canceled"}

    def delete_hunt(self, hunt_id: str, actor: str, now: datetime | None = None) -> dict[str, int]:
        """Permanently delete one hunt and everything only it owns. Evidence that another hunt still
        cites is kept and handed to that hunt; shared raw copies are kept while any event cites them.
        Refuses a hunt that may still be executing. An audit record of the deletion is kept."""
        now = now or utcnow()
        with write_txn(self.engine) as c:
            # Take SQLite's write lock *before* reading liveness or citations. pysqlite defers BEGIN
            # until the first write, so without this a worker in another process could claim the
            # hunt, or publish a new citation, between our checks and our deletes.
            c.execute(t.hunt.update().where(t.hunt.c.id == hunt_id).values(id=t.hunt.c.id))
            h = c.execute(select(t.hunt).where(t.hunt.c.id == hunt_id)).mappings().first()
            if h is None:
                raise KeyError(hunt_id)
            lease_until = h.get("lease_until")
            if lease_until is not None and lease_until.tzinfo is None:
                lease_until = lease_until.replace(tzinfo=UTC)
            live = lease_until is not None and lease_until > now
            if h["execution_state"] not in self.FINISHED_STATES and live:
                raise ValueError(f"hunt {hunt_id} is {h['execution_state']} with a live worker lease; "
                                 f"let it finish (or wait for the lease to expire) before deleting")

            # Events this hunt stored that ANY other hunt still uses: keep them and reassign ownership.
            # Event IDs are global and the first hunt to store an event owns the row, so other hunts
            # can depend on it through (a) their findings' event_ids, (b) their investigation steps'
            # pivot digests, (c) their own entity links (written by save_evidence per hunt), and (d) their
            # expansion links.
            mine = {r.id for r in c.execute(select(t.typed_event.c.id).where(t.typed_event.c.hunt_id == hunt_id))}
            cited_by: dict[str, str] = {}
            for cid_hunt, eids in c.execute(select(t.candidate.c.hunt_id, t.candidate.c.event_ids)
                                            .where(t.candidate.c.hunt_id != hunt_id)):
                for eid in eids or []:
                    if eid in mine:
                        cited_by.setdefault(eid, cid_hunt)

            def _strings(obj):
                if isinstance(obj, str):
                    yield obj
                elif isinstance(obj, dict):
                    for v in obj.values():
                        yield from _strings(v)
                elif isinstance(obj, list):
                    for v in obj:
                        yield from _strings(v)

            for step_hunt, digest_, decision in c.execute(
                    select(t.case.c.hunt_id, t.case_step.c.result_digest, t.case_step.c.decision)
                    .join(t.case, t.case.c.id == t.case_step.c.case_id).where(t.case.c.hunt_id != hunt_id)):
                for sval in _strings([digest_, decision]):
                    if sval in mine:
                        cited_by.setdefault(sval, step_hunt)
            for ev_id, ent_hunt in c.execute(
                    select(t.event_entity.c.event_id, t.entity.c.hunt_id)
                    .join(t.entity, t.entity.c.id == t.event_entity.c.entity_id)
                    .where(t.entity.c.hunt_id != hunt_id)):
                if ev_id in mine:
                    cited_by.setdefault(ev_id, ent_hunt)
            # (d) other hunts' expansion links cite events they reached and the evidence they rest on
            for link_hunt, link_events, link_evidence in c.execute(
                    select(t.expansion_link.c.hunt_id, t.expansion_link.c.event_ids, t.expansion_link.c.evidence_ids)
                    .where(t.expansion_link.c.hunt_id != hunt_id)):
                for eid in [*(link_events or []), *(link_evidence or [])]:
                    if eid in mine:
                        cited_by.setdefault(eid, link_hunt)
            # (e) other hunts' baseline observations cite their first window event
            for eid, obs_hunt in c.execute(observation_citations_query(hunt_id)):
                cited_by.setdefault(eid, obs_hunt)
            for eid, owner in cited_by.items():
                c.execute(t.typed_event.update().where(t.typed_event.c.id == eid).values(hunt_id=owner))
            drop_events = mine - set(cited_by)

            # raw copies referenced only by the events being dropped
            candidate_raw: set[str] = set()
            for (raw_ids,) in c.execute(select(t.typed_event.c.raw_ids).where(t.typed_event.c.id.in_(drop_events))):
                candidate_raw.update(raw_ids or [])
            still_used: set[str] = set()
            if candidate_raw:
                for (raw_ids,) in c.execute(select(t.typed_event.c.raw_ids).where(
                        t.typed_event.c.id.not_in(drop_events) if drop_events else true())):
                    still_used.update(set(raw_ids or []) & candidate_raw)
            drop_raw = candidate_raw - still_used

            task_ids = select(t.task.c.id).where(t.task.c.hunt_id == hunt_id)
            case_ids = select(t.case.c.id).where(t.case.c.hunt_id == hunt_id)
            cand_ids = select(t.candidate.c.id).where(t.candidate.c.hunt_id == hunt_id)
            ent_ids = select(t.entity.c.id).where(t.entity.c.hunt_id == hunt_id)
            counts: dict[str, int] = {}

            def rm(name, stmt):
                counts[name] = c.execute(stmt).rowcount or 0

            # detach shared rows from this hunt's tasks and children before removing them
            c.execute(t.raw_record.update().where(t.raw_record.c.first_task_id.in_(task_ids))
                      .values(first_task_id=None))
            c.execute(t.hunt.update().where(t.hunt.c.parent_hunt_id == hunt_id).values(parent_hunt_id=None))
            rm("analyst_links", t.analyst_link.delete().where(t.analyst_link.c.hunt_id == hunt_id))
            rm("expansion_links", t.expansion_link.delete().where(t.expansion_link.c.hunt_id == hunt_id))
            rm("expansion_anchors", t.expansion_anchor.delete().where(t.expansion_anchor.c.hunt_id == hunt_id))
            rm("baseline_observations", t.baseline_observation.delete().where(
                t.baseline_observation.c.hunt_id == hunt_id,
            ))
            rm("baseline_snapshots", t.baseline_snapshot.delete().where(t.baseline_snapshot.c.hunt_id == hunt_id))
            rm("baseline_segments_revoked", t.baseline_segment.update().where(or_(
                t.baseline_segment.c.source_hunt_id == hunt_id,
                t.baseline_segment.c.built_by_hunt_id == hunt_id,
            )).values(status="revoked"))
            rm("disposition_events", t.disposition_event.delete().where(t.disposition_event.c.candidate_id.in_(cand_ids)))
            rm("candidates", t.candidate.delete().where(t.candidate.c.hunt_id == hunt_id))
            rm("case_steps", t.case_step.delete().where(t.case_step.c.case_id.in_(case_ids)))
            rm("model_calls", t.model_call.delete().where(t.model_call.c.hunt_id == hunt_id))
            rm("cases", t.case.delete().where(t.case.c.hunt_id == hunt_id))
            rm("entity_links", t.event_entity.delete().where(or_(t.event_entity.c.entity_id.in_(ent_ids),
                                                                 t.event_entity.c.event_id.in_(drop_events))))
            rm("entities", t.entity.delete().where(t.entity.c.hunt_id == hunt_id))
            rm("typed_events", t.typed_event.delete().where(t.typed_event.c.id.in_(drop_events)))
            rm("raw_records", t.raw_record.delete().where(t.raw_record.c.id.in_(drop_raw)))
            rm("normalization_errors", t.normalization_error.delete().where(t.normalization_error.c.hunt_id == hunt_id))
            rm("rule_cells", t.rule_run.delete().where(t.rule_run.c.hunt_id == hunt_id))
            rm("tasks", t.task.delete().where(t.task.c.hunt_id == hunt_id))
            rm("report_revisions", t.report_manifest.delete().where(t.report_manifest.c.hunt_id == hunt_id))
            rm("source_profiles", t.source_profile.delete().where(t.source_profile.c.hunt_id == hunt_id))
            c.execute(t.hunt.delete().where(t.hunt.c.id == hunt_id))
            counts["events_kept_for_other_hunts"] = len(cited_by)
            # the deletion itself stays auditable (audit_event has no foreign key to hunt)
            c.execute(t.audit_event.insert().values(at=now, actor=actor, action="hunt.delete", hunt_id=hunt_id,
                                                    detail={k: str(v) for k, v in counts.items()}))
            return counts

    def deletion_preview(self, hunt_id: str) -> dict[str, int]:
        with self.engine.connect() as c:
            def n(table, col):
                return c.execute(select(func.count()).select_from(table).where(col == hunt_id)).scalar_one()
            return {"candidates": n(t.candidate, t.candidate.c.hunt_id),
                    "typed_events": n(t.typed_event, t.typed_event.c.hunt_id),
                    "tasks": n(t.task, t.task.c.hunt_id), "cases": n(t.case, t.case.c.hunt_id),
                    "report_revisions": n(t.report_manifest, t.report_manifest.c.hunt_id)}

    def latest_audit(self, hunt_id: str, action: str) -> dict | None:
        query = (select(t.audit_event)
                 .where(t.audit_event.c.hunt_id == hunt_id, t.audit_event.c.action == action)
                 .order_by(t.audit_event.c.id.desc()))
        with self.engine.connect() as c:
            row = c.execute(query).mappings().first()
            return dict(row) if row else None

    VALID: ClassVar = {
        "planned": {"running", "canceled"},
        "running": {"paused", "completed_within_scope", "partial", "failed", "canceled"},
        "paused": {"running", "canceled", "partial"},
        "partial": {"running"},
        "failed": {"running"},
    }

    def set_hunt_state(self, hunt_id: str, state: str, actor: str = "system",
                       owner_token: str | None = None, **extra):
        with write_txn(self.engine) as c:
            self._fence_lease(c, hunt_id, owner_token)
            cur = c.execute(select(t.hunt.c.execution_state).where(t.hunt.c.id == hunt_id)).scalar_one()
            if state != cur and state not in self.VALID.get(cur, set()):
                raise ValueError(f"invalid hunt transition {cur} -> {state}")
            vals: dict[str, Any] = {"execution_state": state, **extra}
            if state == "running" and cur == "planned":
                vals["started_at"] = utcnow()
            if state in ("completed_within_scope", "partial", "failed", "canceled"):
                vals["ended_at"] = utcnow()
                vals["lease_until"] = None
                vals["lease_owner"] = None
            c.execute(t.hunt.update().where(t.hunt.c.id == hunt_id).values(**vals))
            c.execute(t.audit_event.insert().values(at=utcnow(), actor=actor, action=f"hunt.{state}", hunt_id=hunt_id,
                                                    detail={k: str(v) for k, v in extra.items()}))

    def save_profile(self, hunt_id: str, profile: dict):
        with write_txn(self.engine) as c:
            _upsert_ignore(c, t.source_profile, [{"id": f"{hunt_id}:{profile['id']}", "hunt_id": hunt_id,
                                                  "target": profile["target"], "kind": profile["kind"],
                                                  "profile": profile, "captured_at": utcnow()}], ["id"])

    # ---- tasks ------------------------------------------------------------------------------
    def upsert_task(self, task_id: str, hunt_id: str, kind: str, owner: str, intent: dict, fp: str,
                    priority=0.0, *, owner_token: str | None = None):
        with write_txn(self.engine) as c:
            self._fence_lease(c, hunt_id, owner_token)
            _upsert_ignore(c, t.task, [{"id": task_id, "hunt_id": hunt_id, "kind": kind, "owner": owner,
                                        "intent": intent, "fingerprint": fp, "state": "planned",
                                        "priority": priority, "attempts": 0, "created_at": utcnow(),
                                        "updated_at": utcnow()}], ["id"])

    def task(self, task_id: str) -> dict | None:
        with self.engine.connect() as c:
            row = c.execute(select(t.task).where(t.task.c.id == task_id)).mappings().first()
            return dict(row) if row else None

    def task_state(self, task_id: str) -> str | None:
        with self.engine.connect() as c:
            return c.execute(select(t.task.c.state).where(t.task.c.id == task_id)).scalar()

    TASK_STATES: ClassVar = {
        "planned", "queued", "leased", "executed", "ingested", "evaluated", "failed", "partial",
        "budget_limited", "unsupported", "not_applicable", "canceled", "split",
    }

    def update_task(self, task_id: str, state: str, outcome: dict | None = None, error: str | None = None,
                    attempt: bool = False, *, owner_token: str | None = None):
        if state not in self.TASK_STATES:
            raise ValueError(f"unknown task state {state}")
        with write_txn(self.engine) as c:
            if owner_token is not None:
                hunt_id = c.execute(select(t.task.c.hunt_id).where(t.task.c.id == task_id)).scalar_one()
                self._fence_lease(c, hunt_id, owner_token)
            vals: dict[str, Any] = {"state": state, "updated_at": utcnow()}
            if outcome is not None:
                vals["outcome"] = outcome
            if error is not None:
                vals["error"] = error
            if attempt:
                vals["attempts"] = t.task.c.attempts + 1
            c.execute(t.task.update().where(t.task.c.id == task_id).values(**vals))

    def record_task_source_query(self, task_id: str, *, owner_token: str | None = None) -> int:
        """Checkpoint one physical source call before I/O so crashes can only under-spend."""
        with write_txn(self.engine) as c:
            hunt_id = c.execute(select(t.task.c.hunt_id).where(t.task.c.id == task_id)).scalar_one()
            self._fence_lease(c, hunt_id, owner_token)
            c.execute(t.task.update().where(t.task.c.id == task_id).values(
                source_queries=t.task.c.source_queries + 1,
                updated_at=utcnow(),
            ))
            return int(c.execute(select(t.task.c.source_queries).where(
                t.task.c.id == task_id,
            )).scalar_one())

    def expansion_source_queries(self, hunt_id: str) -> int:
        """Durable physical-query spend for expansion, including an interrupted link."""
        with self.engine.connect() as c:
            task_spend = int(c.execute(select(func.coalesce(func.sum(t.task.c.source_queries), 0)).where(
                t.task.c.hunt_id == hunt_id, t.task.c.kind == "expansion_link",
            )).scalar_one())
            link_spend = int(c.execute(select(func.coalesce(func.sum(t.expansion_link.c.query_spend), 0)).where(
                t.expansion_link.c.hunt_id == hunt_id,
            )).scalar_one())
        # Completed links and tasks describe the same calls. The max also supports
        # databases upgraded from link-only accounting without double-counting.
        return max(task_spend, link_spend)

    def tasks(self, hunt_id: str) -> list[dict]:
        with self.engine.connect() as c:
            return [dict(r) for r in c.execute(select(t.task).where(t.task.c.hunt_id == hunt_id)
                                               .order_by(t.task.c.created_at)).mappings()]

    # ---- evidence ---------------------------------------------------------------------------
    def save_evidence(self, hunt_id: str, events: Iterable, raw_sources: dict[str, dict], task_id: str | None,
                      *, owner_token: str | None = None):
        """Persist typed events plus retained raw copies for every record they cite."""
        events = list(events)
        with write_txn(self.engine) as c:
            self._fence_lease(c, hunt_id, owner_token)
            # rows this hunt already stored (with their entity rows) need no rebuild; another hunt's rows still
            # get this hunt's entity rows, which deletion relies on to keep events another hunt uses
            ids = sorted({event.id for event in events})
            own_ids: set[str] = set()
            for start in range(0, len(ids), 500):
                own_ids.update(c.execute(select(t.typed_event.c.id).where(
                    t.typed_event.c.id.in_(ids[start:start + 500]), t.typed_event.c.hunt_id == hunt_id,
                )).scalars())
            raw_rows, ev_rows, ent_rows, link_rows = [], [], {}, []
            for e in events:
                for r in e.raw:
                    src = raw_sources.get(r.key)
                    if src is not None:
                        raw_rows.append({"id": raw_id(r.target, r.native_id), "target": r.target,
                                         "native_id": r.native_id, "digest": r.digest, "source": src,
                                         "first_task_id": task_id, "retrieved_at": utcnow()})
                if e.id in own_ids:
                    continue
                ev_rows.append({"id": e.id, "hunt_id": hunt_id, "family": e.family, "ts": e.ts, "host": e.host,
                                "event": e.model_dump(mode="json"), "raw_ids": [raw_id(r.target, r.native_id)
                                                                                for r in e.raw],
                                "normalizer": e.normalizer})
                for kind, value, role in e.entities():
                    eid = f"{hunt_id}:{kind}:{value}"
                    ent_rows.setdefault(eid, {"id": eid, "hunt_id": hunt_id, "kind": kind, "value": value,
                                              "first_seen": e.ts, "last_seen": e.ts, "event_count": 0})
                    link_rows.append({"event_id": e.id, "entity_id": eid, "role": role})
            _upsert_ignore(c, t.raw_record, raw_rows, ["id"])
            _upsert_ignore(c, t.typed_event, ev_rows, ["id"])
            self._fill_boot(c, events)
            _upsert_ignore(c, t.entity, list(ent_rows.values()), ["id"])
            _upsert_ignore(c, t.event_entity, link_rows, ["event_id", "entity_id", "role"])

    @staticmethod
    def _fill_boot(c, events: list) -> None:
        """An audit event's boot id depends on its journald copy being in the same retrieval batch, so one event id
        can be stored first without it (a link fetch) and seen later with it (the sweep). Fill a recorded boot id
        forward onto the stored row when the row has none, or only one a boot-interval map placed (a hunt's
        inference, see `is_derived_boot`); a map-placed boot id is never written forward, and a recorded one is
        never overwritten. Nothing else about the row changes."""
        dumped = {e.id: e.fields["host.boot.id"].model_dump(mode="json") for e in events
                  if e.has("host.boot.id") and e.fields["host.boot.id"].value != ""}
        booted = {event_id: field for event_id, field in dumped.items() if not is_derived_boot(field)}
        ids = sorted(booted)
        for start in range(0, len(ids), 500):
            chunk = ids[start:start + 500]
            for row in c.execute(select(t.typed_event.c.id, t.typed_event.c.event)
                                 .where(t.typed_event.c.id.in_(chunk))).mappings():
                stored = row["event"]
                fields = stored.get("fields") or {}
                current = fields.get("host.boot.id") or {}
                if current.get("value") not in (None, "") and not is_derived_boot(current):
                    continue
                stored = {**stored, "fields": {**fields, "host.boot.id": booted[row["id"]]}}
                c.execute(t.typed_event.update().where(t.typed_event.c.id == row["id"]).values(event=stored))

    def events_by_ids(self, ids: list[str]) -> list[dict]:
        with self.engine.connect() as c:
            return [dict(r) for r in c.execute(select(t.typed_event).where(t.typed_event.c.id.in_(ids))).mappings()]

    def raw_records(self, ids: list[str]) -> list[dict]:
        with self.engine.connect() as c:
            return [dict(r) for r in c.execute(select(t.raw_record).where(t.raw_record.c.id.in_(ids))).mappings()]

    # ---- candidates -------------------------------------------------------------------------
    def save_candidate(self, row: dict, *, owner_token: str | None = None) -> bool:
        """Insert once; returns True if new. Re-evaluation of the same evidence is idempotent."""
        with write_txn(self.engine) as c:
            self._fence_lease(c, row["hunt_id"], owner_token)
            exists = c.execute(select(t.candidate.c.id).where(t.candidate.c.id == row["id"])).scalar()
            if exists:
                return False
            c.execute(t.candidate.insert().values(**row, created_at=utcnow()))
            c.execute(t.disposition_event.insert().values(candidate_id=row["id"], actor="romulus", at=utcnow(),
                                                          status="new", note="machine decision"))
            return True

    def candidates(self, hunt_id: str, lanes: list[str] | None = None) -> list[dict]:
        q = select(t.candidate).where(t.candidate.c.hunt_id == hunt_id)
        if lanes:
            q = q.where(t.candidate.c.lane.in_(lanes))
        with self.engine.connect() as c:
            return [dict(r) for r in c.execute(q).mappings()]

    def candidate(self, cid: str) -> dict | None:
        with self.engine.connect() as c:
            r = c.execute(select(t.candidate).where(t.candidate.c.id == cid)).mappings().first()
            return dict(r) if r else None

    def update_context_candidate(
        self, candidate_id: str, values: dict, *, owner_token: str | None = None,
    ) -> None:
        """Merge repeated context reachability without changing direct-finding identity semantics."""
        allowed = {
            "claim", "event_ids", "severity", "confidence", "lane", "priority",
            "priority_reasons", "gate_results", "source_anchor_id", "source_link_id",
            "predicate_fields", "entities", "ts",
        }
        if not values or not set(values) <= allowed:
            raise ValueError("unsupported context candidate update")
        with write_txn(self.engine) as c:
            hunt_id = c.execute(select(t.candidate.c.hunt_id).where(
                t.candidate.c.id == candidate_id,
            )).scalar_one()
            self._fence_lease(c, hunt_id, owner_token)
            c.execute(t.candidate.update().where(t.candidate.c.id == candidate_id).values(**values))

    # Fields a finalize pass owns on a context candidate. `digest` is the idempotence key.
    _FINALIZE_FIELDS = (
        "claim", "claim_type", "event_ids", "predicate_fields", "entities", "ts", "severity",
        "confidence", "lane", "priority", "priority_reasons", "gate_results",
        "source_anchor_id", "source_link_id",
    )

    def finalize_context_candidate(self, row: dict, digest: str, audit_detail: dict,
                                   *, owner_token: str | None = None) -> bool:
        """Upsert one context candidate and, when it changed, write its audit row in the SAME transaction.
        Idempotent: a candidate whose stored finalize digest already equals `digest` is left untouched and no
        audit row is written. Returns True when a write happened."""
        with write_txn(self.engine) as c:
            self._fence_lease(c, row["hunt_id"], owner_token)
            existing = c.execute(select(t.candidate).where(t.candidate.c.id == row["id"])).mappings().first()
            if existing is not None and existing["gate_results"].get("_finalize_digest") == digest:
                return False
            audit_detail = {**audit_detail,
                            "old_lane": existing["lane"] if existing else None,
                            "old_claim_digest": existing["gate_results"].get("_finalize_digest", "")
                            if existing else ""}
            if existing is None:
                c.execute(t.candidate.insert().values(**row, created_at=utcnow()))
                c.execute(t.disposition_event.insert().values(
                    candidate_id=row["id"], actor="romulus", at=utcnow(), status="new", note="machine decision"))
            else:
                c.execute(t.candidate.update().where(t.candidate.c.id == row["id"]).values(
                    **{field: row[field] for field in self._FINALIZE_FIELDS}))
            c.execute(t.audit_event.insert().values(
                at=utcnow(), actor="system", action="context.finalize", hunt_id=row["hunt_id"],
                detail=audit_detail))
            return True

    def context_candidate_ids(self, hunt_id: str, rule_ids: set[str]) -> list[dict]:
        """Minimal rows for the context candidates of the given rules, to find ones a finalize pass dropped."""
        q = select(t.candidate.c.id, t.candidate.c.rule_id, t.candidate.c.lane, t.candidate.c.group_key,
                   t.candidate.c.event_ids, t.candidate.c.gate_results).where(
            t.candidate.c.hunt_id == hunt_id, t.candidate.c.rule_id.in_(rule_ids))
        with self.engine.connect() as c:
            return [dict(r) for r in c.execute(q).mappings()]

    # ---- deterministic expansion -----------------------------------------------------------
    def save_expansion_anchor(self, row: dict, *, owner_token: str | None = None) -> bool:
        now = utcnow()
        values = {**row, "created_at": now, "updated_at": now}
        with write_txn(self.engine) as c:
            self._fence_lease(c, row["hunt_id"], owner_token)
            result = c.execute(insert(t.expansion_anchor).values(values).on_conflict_do_nothing(
                index_elements=["id"],
            ))
            return bool(result.rowcount)

    def update_expansion_anchor(self, anchor_id: str, status: str, reasons: list[str],
                                *, owner_token: str | None = None) -> None:
        with write_txn(self.engine) as c:
            hunt_id = c.execute(select(t.expansion_anchor.c.hunt_id).where(
                t.expansion_anchor.c.id == anchor_id,
            )).scalar_one()
            self._fence_lease(c, hunt_id, owner_token)
            c.execute(t.expansion_anchor.update().where(t.expansion_anchor.c.id == anchor_id).values(
                status=status, reasons=reasons, updated_at=utcnow(),
            ))

    def expansion_anchors(self, hunt_id: str) -> list[dict]:
        q = (select(t.expansion_anchor).where(t.expansion_anchor.c.hunt_id == hunt_id)
             .order_by(t.expansion_anchor.c.depth, t.expansion_anchor.c.ts, t.expansion_anchor.c.id))
        with self.engine.connect() as c:
            return [dict(row) for row in c.execute(q).mappings()]

    def save_expansion_link(self, row: dict, *, owner_token: str | None = None) -> bool:
        now = utcnow()
        values = {**row, "created_at": now, "updated_at": now}
        with write_txn(self.engine) as c:
            self._fence_lease(c, row["hunt_id"], owner_token)
            result = c.execute(insert(t.expansion_link).values(values).on_conflict_do_nothing(
                index_elements=["id"],
            ))
            return bool(result.rowcount)

    def mark_expansion_link_evaluated(self, link_id: str, *, owner_token: str | None = None) -> None:
        with write_txn(self.engine) as c:
            hunt_id = c.execute(select(t.expansion_link.c.hunt_id).where(
                t.expansion_link.c.id == link_id,
            )).scalar_one()
            self._fence_lease(c, hunt_id, owner_token)
            c.execute(t.expansion_link.update().where(t.expansion_link.c.id == link_id).values(
                evaluated=1, updated_at=utcnow(),
            ))

    def expansion_link(self, link_id: str) -> dict | None:
        with self.engine.connect() as c:
            row = c.execute(select(t.expansion_link).where(t.expansion_link.c.id == link_id)).mappings().first()
            return dict(row) if row else None

    def expansion_link_for(self, anchor_id: str, link_type: str, label: str,
                           start: datetime, end: datetime) -> dict | None:
        q = select(t.expansion_link).where(
            t.expansion_link.c.anchor_id == anchor_id,
            t.expansion_link.c.link_type == link_type,
            t.expansion_link.c.window_label == label,
            t.expansion_link.c.window_start == start,
            t.expansion_link.c.window_end == end,
        )
        with self.engine.connect() as c:
            row = c.execute(q).mappings().first()
            return dict(row) if row else None

    def add_analyst_link(self, hunt_id: str, from_finding: str, to_finding: str, relation: str,
                         note: str | None, actor: str) -> dict:
        """Record an analyst's asserted relation between two findings of this hunt (never an observed link)."""
        relation = " ".join(relation.split())[:200]
        if not relation or from_finding == to_finding:
            raise ValueError("an analyst link needs two different findings and a relation")
        with write_txn(self.engine) as c:
            rows = {row.id: row for row in c.execute(
                select(t.candidate.c.id, t.candidate.c.hunt_id, t.candidate.c.lane)
                .where(t.candidate.c.id.in_([from_finding, to_finding])))}
            if any(item not in rows or rows[item].hunt_id != hunt_id for item in (from_finding, to_finding)):
                raise ValueError("both findings must belong to this hunt")
            if any(rows[item].lane not in REPORTABLE_LANES for item in (from_finding, to_finding)):
                raise ValueError("analyst links join reportable findings (urgent, high or lead)")
            row = {"id": "AL-" + uuid.uuid4().hex[:16], "hunt_id": hunt_id, "from_finding": from_finding,
                   "to_finding": to_finding, "relation": relation, "note": (note or "").strip()[:2000] or None,
                   "actor": actor, "created_at": utcnow()}
            c.execute(t.analyst_link.insert().values(**row))
            c.execute(t.audit_event.insert().values(at=utcnow(), actor=actor, action="analyst_link.add",
                                                    hunt_id=hunt_id, detail={k: str(v) for k, v in row.items()}))
        return row

    def analyst_links(self, hunt_id: str) -> list[dict]:
        q = (select(t.analyst_link).where(t.analyst_link.c.hunt_id == hunt_id)
             .order_by(t.analyst_link.c.created_at, t.analyst_link.c.id))
        with self.engine.connect() as c:
            return [dict(row) for row in c.execute(q).mappings()]

    def expansion_links(self, hunt_id: str) -> list[dict]:
        q = (select(t.expansion_link).where(t.expansion_link.c.hunt_id == hunt_id)
             .order_by(t.expansion_link.c.created_at, t.expansion_link.c.id))
        with self.engine.connect() as c:
            return [dict(row) for row in c.execute(q).mappings()]

    def add_disposition(self, cid: str, actor: str, status: str, note: str | None):
        with write_txn(self.engine) as c:
            c.execute(t.disposition_event.insert().values(candidate_id=cid, actor=actor, at=utcnow(), status=status,
                                                          note=note))

    def dispositions(self, cid: str) -> list[dict]:
        with self.engine.connect() as c:
            return [dict(r) for r in c.execute(select(t.disposition_event).where(
                t.disposition_event.c.candidate_id == cid).order_by(t.disposition_event.c.id)).mappings()]

    # ---- baseline store --------------------------------------------------------------------
    def save_baseline_segment(self, row: dict, counts: Iterable[dict], scope_hours: Iterable[dict], *,
                              chunk_size: int = BASELINE_CHUNK) -> bool:
        """Insert one immutable, complete segment and its rows in one atomic transaction.

        Rows stream from the iterables in chunks and are never collected whole. Every time must be
        timezone-aware (stored as UTC); child buckets, timestamps and scope hours must sit inside the span.
        Any invalid row rolls the whole segment back. Writing an existing id again is a no-op when the content
        is identical (status and created_at aside) and a ValueError when it differs."""
        segment = _baseline_segment_row(row)
        digest = _RowsDigest()
        with write_txn(self.engine) as c:
            existing = c.execute(select(t.baseline_segment).where(
                t.baseline_segment.c.id == segment["id"])).mappings().first()
            if existing is not None:
                stored = _with_utc(existing, ("start", "end", "created_at"))
                if any(stored[name] != segment[name] for name in _SEGMENT_IDENTITY):
                    raise ValueError(f"baseline segment {segment['id']} exists with different content")
            else:
                c.execute(t.baseline_segment.insert().values(**segment, rows_digest=""))
            for table, kind, columns, rows, check in (
                    (t.baseline_count, "count", _COUNT_COLUMNS, counts, _baseline_count_row),
                    (t.baseline_scope_hour, "hour", _HOUR_COLUMNS, scope_hours, _baseline_hour_row)):
                for chunk in _chunks((check(item, segment) for item in rows), chunk_size):
                    digest.add(kind, columns, chunk)
                    if existing is None:
                        c.execute(table.insert(), chunk)
            if existing is not None:
                if existing["rows_digest"] != digest.hexdigest():
                    raise ValueError(f"baseline segment {segment['id']} exists with different content")
                return False
            c.execute(t.baseline_segment.update().where(t.baseline_segment.c.id == segment["id"])
                      .values(rows_digest=digest.hexdigest()))
            return True

    def set_baseline_segment_status(self, segment_id: str, status: str) -> bool:
        if status not in {"active", "stale", "revoked"}:
            raise ValueError(f"invalid baseline segment status: {status}")
        with write_txn(self.engine) as c:
            result = c.execute(t.baseline_segment.update().where(
                t.baseline_segment.c.id == segment_id,
            ).values(status=status))
            return bool(result.rowcount)

    def usable_baseline_segment_id(self, base_id: str) -> str:
        """Return the stable usable generation for content, advancing only after revocation.

        Revocation is permanent: the original id is never reactivated. A rewrite therefore gets ``-rN``;
        retries reuse the first non-revoked generation, while another revocation advances N.
        """
        s = t.baseline_segment.c
        with self.engine.connect() as c:
            rows = list(c.execute(select(s.id, s.status).where(or_(
                s.id == base_id, s.id.like(f"{base_id}-r%"),
            ))).mappings())
        if not rows:
            return base_id
        usable = sorted(row["id"] for row in rows if row["status"] != "revoked")
        if usable:
            return usable[0]
        generations = [0]
        for row in rows:
            suffix = row["id"].removeprefix(f"{base_id}-r")
            if suffix.isdigit():
                generations.append(int(suffix))
        return f"{base_id}-r{max(generations) + 1}"

    def begin_baseline_segment(self, row: dict) -> bool:
        """Create an invisible building segment in a short transaction."""
        segment = _baseline_segment_row(row)
        if segment["status"] != "building":
            raise ValueError("a chunked baseline segment must begin with status building")
        with write_txn(self.engine) as c:
            existing = c.execute(select(t.baseline_segment).where(
                t.baseline_segment.c.id == segment["id"],
            )).mappings().first()
            if existing is not None:
                stored = _with_utc(existing, ("start", "end", "created_at"))
                if any(stored[name] != segment[name] for name in _SEGMENT_IDENTITY):
                    raise ValueError(f"baseline segment {segment['id']} exists with different content")
                return False
            c.execute(t.baseline_segment.insert().values(**segment, rows_digest=""))
            return True

    def append_baseline_segment_rows(self, segment_id: str, counts: Iterable[dict],
                                     scope_hours: Iterable[dict], *,
                                     chunk_size: int = BASELINE_CHUNK) -> float:
        """Append validated rows to a building segment, one bounded write transaction per chunk.

        Returns the longest measured write-lock hold for operational verification; it is never persisted or
        used in content identity.
        """
        if chunk_size < 1:
            raise ValueError("chunk size must be positive")
        with self.engine.connect() as c:
            stored = c.execute(select(t.baseline_segment).where(
                t.baseline_segment.c.id == segment_id,
            )).mappings().first()
        if stored is None or stored["status"] != "building":
            raise ValueError(f"baseline segment {segment_id} is not building")
        segment = _with_utc(stored, ("start", "end", "created_at"))
        longest = 0.0
        for table, rows, check in (
                (t.baseline_count, counts, _baseline_count_row),
                (t.baseline_scope_hour, scope_hours, _baseline_hour_row)):
            for chunk in _chunks((check(item, segment) for item in rows), chunk_size):
                started = time.perf_counter()
                with write_txn(self.engine) as c:
                    state = c.execute(select(t.baseline_segment.c.status).where(
                        t.baseline_segment.c.id == segment_id,
                    )).scalar_one_or_none()
                    if state != "building":
                        raise ValueError(f"baseline segment {segment_id} stopped building")
                    c.execute(table.insert(), chunk)
                longest = max(longest, time.perf_counter() - started)
        return longest

    def finalize_baseline_segment(self, segment_id: str) -> str:
        """Digest a completed build without a write lock, then expose it in one metadata update."""
        digest = _RowsDigest()
        for kind, columns, rows in (
                ("count", _COUNT_COLUMNS, self.baseline_counts(segment_id)),
                ("hour", _HOUR_COLUMNS, self.baseline_scope_hours(segment_id))):
            for chunk in _chunks(rows, BASELINE_PAGE):
                digest.add(kind, columns, chunk)
        value = digest.hexdigest()
        with write_txn(self.engine) as c:
            result = c.execute(t.baseline_segment.update().where(
                t.baseline_segment.c.id == segment_id,
                t.baseline_segment.c.status == "building",
            ).values(rows_digest=value, status="active"))
            if not result.rowcount:
                raise ValueError(f"baseline segment {segment_id} is not building")
        return value

    def cleanup_baseline_building(self, *, before: datetime) -> int:
        """Delete abandoned builds and their cascading child rows before history work resumes."""
        before = _utc(before, "building cleanup time")
        with write_txn(self.engine) as c:
            result = c.execute(t.baseline_segment.delete().where(
                t.baseline_segment.c.status == "building",
                t.baseline_segment.c.created_at < before,
            ))
            return int(result.rowcount or 0)

    def baseline_segments(self, *, site: str | None = None, target: str | None = None,
                          spec_id: str | None = None, statuses: Iterable[str] | None = None) -> list[dict]:
        query = select(t.baseline_segment)
        if site is not None:
            query = query.where(t.baseline_segment.c.site == site)
        if target is not None:
            query = query.where(t.baseline_segment.c.target == target)
        if spec_id is not None:
            query = query.where(t.baseline_segment.c.spec_id == spec_id)
        if statuses is not None:
            query = query.where(t.baseline_segment.c.status.in_(list(statuses)))
        query = query.order_by(
            t.baseline_segment.c.site, t.baseline_segment.c.target, t.baseline_segment.c.spec_id,
            t.baseline_segment.c.start, t.baseline_segment.c.end, t.baseline_segment.c.id,
        )
        with self.engine.connect() as c:
            return [_with_utc(item, ("start", "end", "created_at")) for item in c.execute(query).mappings()]

    def baseline_segments_for_cover(self, *, site: str, target: str, spec_id: str,
                                    spec_version: str, key_version: str, start: datetime,
                                    end: datetime) -> list[dict]:
        """Complete active segments wholly inside a requested history interval, already cover-ordered."""
        start, end = _utc(start, "cover start"), _utc(end, "cover end")
        s = t.baseline_segment.c
        query = (select(t.baseline_segment).where(
            s.site == site, s.target == target, s.spec_id == spec_id,
            s.spec_version == spec_version, s.key_version == key_version,
            s.status == "active", s.start >= start, s.end <= end,
        ).order_by(s.start, s.end, s.id))
        with self.engine.connect() as c:
            return [_with_utc(item, ("start", "end", "created_at")) for item in c.execute(query).mappings()]

    def _keyset(self, table, where, order: tuple[str, ...], times: tuple[str, ...], page_size: int) -> Iterator[dict]:
        """Rows in `order` (a unique key), one page per short-lived read: nothing holds a cursor open."""
        if page_size < 1:
            raise ValueError("page size must be positive")
        columns = [table.c[name] for name in order]
        after = None
        while True:
            query = select(table).where(*where)
            if after is not None:
                query = query.where(tuple_(*columns) > tuple_(*after))
            query = query.order_by(*columns).limit(page_size)
            with self.engine.connect() as c:
                page = [_with_utc(item, times) for item in c.execute(query).mappings()]
            yield from page
            if len(page) < page_size:
                return
            after = [page[-1][name] for name in order]

    def baseline_counts(self, segment_id: str, *, page_size: int = BASELINE_PAGE) -> Iterator[dict]:
        """A segment's count rows in primary-key order (scope, key_digest, bucket), paged."""
        return self._keyset(t.baseline_count, [t.baseline_count.c.segment_id == segment_id],
                            ("scope", "key_digest", "bucket"), ("bucket", "first_ts", "last_ts"), page_size)

    def baseline_scope_hours(self, segment_id: str, *, page_size: int = BASELINE_PAGE) -> Iterator[dict]:
        """A segment's scope hours in primary-key order (scope, hour), paged."""
        return self._keyset(t.baseline_scope_hour, [t.baseline_scope_hour.c.segment_id == segment_id],
                            ("scope", "hour"), ("hour",), page_size)

    def baseline_key_prevalence(self, key_id: str, scope_kind: str, hunt_id: str) -> int:
        """How many distinct scopes hold `key_id` in the hunt's frozen snapshot."""
        with self.engine.connect() as c:
            return int(c.execute(baseline_prevalence_query(key_id, scope_kind, hunt_id)).scalar_one())

    def baseline_peer_scopes(self, scope_kind: str, hunt_id: str) -> int:
        """How many distinct scopes were live in the hunt snapshot (the prevalence denominator)."""
        with self.engine.connect() as c:
            return int(c.execute(baseline_peer_scopes_query(scope_kind, hunt_id)).scalar_one())

    def baseline_key_history(self, key_id: str, scope_kind: str, scope: str,
                             hunt_id: str) -> list[dict]:
        """One key's count rows in one scope; at most one row per segment bucket of the snapshot span."""
        with self.engine.connect() as c:
            return [_with_utc(row, ("bucket", "first_ts", "last_ts")) for row in c.execute(
                baseline_key_history_query(key_id, scope_kind, scope, hunt_id)).mappings()]

    def baseline_scope_series(self, scope_kind: str, scope: str, hunt_id: str) -> list[dict]:
        """One scope's live hours; at most one row per hour of the snapshot span."""
        with self.engine.connect() as c:
            return [_with_utc(row, ("hour",)) for row in c.execute(
                baseline_scope_series_query(scope_kind, scope, hunt_id)).mappings()]

    def save_baseline_snapshot(self, row: dict) -> bool:
        """Atomically freeze the first snapshot and normalized membership for a hunt."""
        row = dict(row)
        segment_ids = sorted(set(row["segment_ids"]))
        row["segment_ids"] = segment_ids
        with write_txn(self.engine) as c:
            result = c.execute(insert(t.baseline_snapshot).values(**row).on_conflict_do_nothing(
                index_elements=["hunt_id"],
            ))
            if not result.rowcount:
                return False
            if segment_ids:
                c.execute(t.baseline_snapshot_segment.insert(), [
                    {"hunt_id": row["hunt_id"], "segment_id": segment_id} for segment_id in segment_ids
                ])
            return True

    def baseline_snapshot(self, hunt_id: str) -> dict | None:
        with self.engine.connect() as c:
            row = c.execute(select(t.baseline_snapshot).where(
                t.baseline_snapshot.c.hunt_id == hunt_id,
            )).mappings().first()
            return dict(row) if row else None

    def baseline_snapshot_segments(self, hunt_id: str) -> list[str]:
        query = (select(t.baseline_snapshot_segment.c.segment_id)
                 .where(t.baseline_snapshot_segment.c.hunt_id == hunt_id)
                 .order_by(t.baseline_snapshot_segment.c.segment_id))
        with self.engine.connect() as c:
            return list(c.execute(query).scalars())

    def baseline_parent_boot(self, hunt_id: str, host: str) -> tuple[str, datetime] | None:
        with self.engine.connect() as c:
            row = c.execute(select(t.baseline_parent_host_boot).where(
                t.baseline_parent_host_boot.c.hunt_id == hunt_id,
                t.baseline_parent_host_boot.c.host == host,
            )).mappings().first()
        if row is None:
            return None
        return row["boot"], _stored_utc(row["latest_ts"])

    def set_baseline_parent_boot(self, hunt_id: str, host: str, boot: str,
                                 latest_ts: datetime) -> bool:
        """Advance one host's carry state; an older different boot is rejected."""
        latest_ts = _utc(latest_ts, "parent boot latest_ts")
        table = t.baseline_parent_host_boot.c
        with write_txn(self.engine) as c:
            current = c.execute(select(t.baseline_parent_host_boot).where(
                table.hunt_id == hunt_id, table.host == host,
            )).mappings().first()
            if current is not None:
                current_ts = _stored_utc(current["latest_ts"])
                if current["boot"] != boot and current_ts >= latest_ts:
                    return False
                if current["boot"] != boot:
                    c.execute(t.baseline_parent_carry.delete().where(
                        t.baseline_parent_carry.c.hunt_id == hunt_id,
                        t.baseline_parent_carry.c.host == host,
                    ))
                elif current_ts > latest_ts:
                    latest_ts = current_ts
            stmt = insert(t.baseline_parent_host_boot).values(
                hunt_id=hunt_id, host=host, boot=boot, latest_ts=latest_ts,
            ).on_conflict_do_update(
                index_elements=["hunt_id", "host"],
                set_={"boot": boot, "latest_ts": latest_ts},
            )
            c.execute(stmt)
            return True

    def upsert_baseline_parents(self, rows: Iterable[dict]) -> None:
        """Keep only the latest observed exec for each live (hunt, host, boot, pid)."""
        stmt = insert(t.baseline_parent_carry)
        stmt = stmt.on_conflict_do_update(
            index_elements=["hunt_id", "host", "boot", "pid"],
            set_={
                "exec_ts": stmt.excluded.exec_ts, "executable": stmt.excluded.executable,
                "parent_pid": stmt.excluded.parent_pid, "raw_id": stmt.excluded.raw_id,
            },
            where=stmt.excluded.exec_ts >= t.baseline_parent_carry.c.exec_ts,
        )
        for chunk in _chunks(rows, BASELINE_CHUNK):
            with write_txn(self.engine) as c:
                c.execute(stmt, chunk)

    def baseline_parent_lookup(self, hunt_id: str, host: str, pid: int, ts: float,
                               boot: str | None) -> tuple | None:
        if isinstance(pid, bool) or not isinstance(pid, int) or pid < 0:
            return None
        at = datetime.fromtimestamp(ts, UTC)
        table = t.baseline_parent_carry.c
        with self.engine.connect() as c:
            row = c.execute(select(t.baseline_parent_carry).where(
                table.hunt_id == hunt_id, table.host == host, table.boot == (boot or ""),
                table.pid == pid, table.exec_ts <= at, table.executable != "",
            )).mappings().first()
        if row is None:
            return None
        exec_ts = _stored_utc(row["exec_ts"])
        return exec_ts.timestamp(), row["executable"], row["parent_pid"], row["raw_id"], boot

    def baseline_parent_count(self, hunt_id: str) -> int:
        with self.engine.connect() as c:
            return int(c.execute(select(func.count()).select_from(t.baseline_parent_carry).where(
                t.baseline_parent_carry.c.hunt_id == hunt_id,
            )).scalar_one())

    def upsert_baseline_observation(self, row: dict) -> None:
        self.upsert_baseline_observations([row])

    def upsert_baseline_observations(self, rows: Iterable[dict], *, chunk_size: int = BASELINE_CHUNK) -> int:
        """Insert or replace window observations in one transaction, streaming in chunks.

        A replacement rewrites every column except `candidate_id`, which a None never clears: once an
        observation is tied to a published candidate, a later pass without one keeps the tie."""
        stmt = insert(t.baseline_observation)
        table = t.baseline_observation.c
        values = {name: stmt.excluded[name] for name in _OBSERVATION_COLUMNS if name not in _OBSERVATION_KEY}
        values["candidate_id"] = func.coalesce(stmt.excluded.candidate_id, table.candidate_id)
        stmt = stmt.on_conflict_do_update(index_elements=list(_OBSERVATION_KEY), set_=values)

        def normalized(row: dict) -> dict:
            _columns(row, _OBSERVATION_COLUMNS, frozenset(_OBSERVATION_COLUMNS) - _OBSERVATION_REQUIRED,
                     "observation")
            out = {name: row.get(name) for name in _OBSERVATION_COLUMNS}
            for name in ("first_ts", "last_ts"):
                if out[name] is not None:
                    out[name] = _utc(out[name], name)
            return out

        written = 0
        with write_txn(self.engine) as c:
            for chunk in _chunks((normalized(row) for row in rows), chunk_size):
                c.execute(stmt, chunk)
                written += len(chunk)
        return written

    def baseline_observations(self, hunt_id: str, *, page_size: int = BASELINE_PAGE) -> Iterator[dict]:
        """A hunt's observations in key order (spec, version, scope, key digest), paged."""
        return self._keyset(t.baseline_observation, [t.baseline_observation.c.hunt_id == hunt_id],
                            ("spec_id", "spec_version", "scope", "key_digest"), ("first_ts", "last_ts"),
                            page_size)

    # ---- investigator state ----------------------------------------------------------------
    def create_case(self, row: dict, *, owner_token: str | None = None) -> bool:
        now = utcnow()
        values = {
            "status": "open", "steps_used": 0, "hypotheses": [],
            "created_at": now, "updated_at": now, **row,
        }
        with write_txn(self.engine) as c:
            self._fence_lease(c, row["hunt_id"], owner_token)
            result = c.execute(insert(t.case).values(**values).on_conflict_do_nothing(index_elements=["id"]))
            return result.rowcount == 1

    def case(self, case_id: str) -> dict | None:
        with self.engine.connect() as c:
            row = c.execute(select(t.case).where(t.case.c.id == case_id)).mappings().first()
            return dict(row) if row else None

    def cases(self, hunt_id: str, statuses: list[str] | None = None) -> list[dict]:
        query = select(t.case).where(t.case.c.hunt_id == hunt_id)
        if statuses:
            query = query.where(t.case.c.status.in_(statuses))
        query = query.order_by(t.case.c.priority.desc(), t.case.c.created_at, t.case.c.id)
        with self.engine.connect() as c:
            return [dict(row) for row in c.execute(query).mappings()]

    def update_case(self, case_id: str, *, owner_token: str | None = None, **values) -> None:
        allowed = {"title", "status", "priority", "entities", "hypotheses", "steps_used", "step_budget", "summary"}
        unknown = set(values) - allowed
        if unknown:
            raise ValueError(f"unknown case fields: {sorted(unknown)}")
        with write_txn(self.engine) as c:
            hunt_id = c.execute(select(t.case.c.hunt_id).where(t.case.c.id == case_id)).scalar_one()
            self._fence_lease(c, hunt_id, owner_token)
            c.execute(t.case.update().where(t.case.c.id == case_id).values(**values, updated_at=utcnow()))

    def repartition_case(self, case_id: str, step_n: int, decision: dict, *, priority: float,
                         entities: list[dict], owner_token: str | None = None) -> None:
        """Atomically update bounded seed metadata and append its durable partition marker."""
        now = utcnow()
        with write_txn(self.engine) as c:
            hunt_id = c.execute(select(t.case.c.hunt_id).where(t.case.c.id == case_id)).scalar_one()
            self._fence_lease(c, hunt_id, owner_token)
            c.execute(t.case.update().where(t.case.c.id == case_id).values(
                priority=priority, entities=entities, updated_at=now,
            ))
            c.execute(t.case_step.insert().values(
                case_id=case_id, n=step_n, decision=decision, accepted=1,
                rejection=None, model_call_id=None, task_id=None, result_digest=None, at=now,
            ))

    def append_case_step(self, case_id: str, n: int, decision: dict, accepted: bool,
                         rejection: str | None = None, model_call_id: str | None = None,
                         task_id: str | None = None, result_digest: dict | None = None,
                         owner_token: str | None = None) -> int:
        values = {
            "case_id": case_id, "n": n, "decision": decision, "accepted": int(accepted),
            "rejection": rejection, "model_call_id": model_call_id, "task_id": task_id,
            "result_digest": result_digest, "at": utcnow(),
        }
        with write_txn(self.engine) as c:
            hunt_id = c.execute(select(t.case.c.hunt_id).where(t.case.c.id == case_id)).scalar_one()
            self._fence_lease(c, hunt_id, owner_token)
            c.execute(insert(t.case_step).values(**values).on_conflict_do_nothing(
                index_elements=["case_id", "n"],
            ))
            return c.execute(select(t.case_step.c.id).where(
                t.case_step.c.case_id == case_id, t.case_step.c.n == n,
            )).scalar_one()

    def update_case_step(self, case_id: str, n: int, *, owner_token: str | None = None,
                         **values) -> None:
        allowed = {"model_call_id", "decision", "accepted", "rejection", "task_id", "result_digest"}
        unknown = set(values) - allowed
        if unknown:
            raise ValueError(f"unknown case step fields: {sorted(unknown)}")
        if "accepted" in values:
            values["accepted"] = int(values["accepted"])
        with write_txn(self.engine) as c:
            hunt_id = c.execute(select(t.case.c.hunt_id).where(t.case.c.id == case_id)).scalar_one()
            self._fence_lease(c, hunt_id, owner_token)
            c.execute(t.case_step.update().where(
                t.case_step.c.case_id == case_id, t.case_step.c.n == n,
            ).values(**values))

    def case_steps(self, case_id: str) -> list[dict]:
        with self.engine.connect() as c:
            return [dict(row) for row in c.execute(select(t.case_step).where(
                t.case_step.c.case_id == case_id,
            ).order_by(t.case_step.c.n)).mappings()]

    def pending_case_steps(self, hunt_id: str) -> list[dict]:
        query = (select(t.case_step)
                 .join(t.case, t.case.c.id == t.case_step.c.case_id)
                 .where(t.case.c.hunt_id == hunt_id, t.case_step.c.accepted == 1,
                        t.case_step.c.task_id.is_not(None), t.case_step.c.result_digest.is_(None))
                 .order_by(t.case_step.c.case_id, t.case_step.c.n))
        with self.engine.connect() as c:
            return [dict(row) for row in c.execute(query).mappings()]

    def save_model_call(self, row: dict, *, owner_token: str | None = None) -> bool:
        values = {"at": utcnow(), **row}
        with write_txn(self.engine) as c:
            self._fence_lease(c, row["hunt_id"], owner_token)
            result = c.execute(insert(t.model_call).values(**values).on_conflict_do_nothing(index_elements=["id"]))
            return result.rowcount == 1

    def model_calls(self, hunt_id: str | None = None, case_id: str | None = None) -> list[dict]:
        query = select(t.model_call)
        if hunt_id is not None:
            query = query.where(t.model_call.c.hunt_id == hunt_id)
        if case_id is not None:
            query = query.where(t.model_call.c.case_id == case_id)
        query = query.order_by(t.model_call.c.at, t.model_call.c.id)
        with self.engine.connect() as c:
            return [dict(row) for row in c.execute(query).mappings()]

    def agent_usage(self, hunt_id: str) -> dict:
        """What the AI agent has spent in a hunt (provider-port calls only), for budgets that survive resume."""
        with self.engine.connect() as c:
            rows = c.execute(select(
                t.model_call.c.prompt_tokens_est, t.model_call.c.prompt_eval_count, t.model_call.c.eval_count,
                t.model_call.c.raw_response, t.model_call.c.cost_usd_est, t.model_call.c.duration_ms,
                t.model_call.c.egress, t.model_call.c.endpoint_host, t.model_call.c.model,
            ).where(t.model_call.c.hunt_id == hunt_id, t.model_call.c.provider.is_not(None))).all()
        tokens, cost, ms, estimated = 0, 0.0, 0, False
        remote: dict[tuple[str, str], int] = {}
        for prompt_est, prompt, completion, raw, row_cost, duration, egress, host, model in rows:
            if egress != "local":
                remote[(host or "unknown", model)] = remote.get((host or "unknown", model), 0) + 1
            if prompt is None or completion is None:
                # unreported usage is charged at the prompt estimate plus the whole response text
                estimated = True
                prompt, completion = prompt_est or 0, int(len(raw or "") / 3.2) + 8
            tokens += int(prompt) + int(completion)
            cost += float(row_cost or 0.0)
            ms += int(duration or 0)
        return {"calls": len(rows), "tokens": tokens, "cost_usd": cost, "model_ms": ms, "estimated": estimated,
                "remote_calls": [{"endpoint_host": h, "model": m, "calls": n} for (h, m), n in sorted(remote.items())]}

    def agent_elapsed_ms(self, hunt_id: str) -> int:
        with self.engine.connect() as c:
            model_ms = c.execute(select(func.coalesce(func.sum(t.model_call.c.duration_ms), 0)).where(
                t.model_call.c.hunt_id == hunt_id,
            )).scalar_one()
            digests = c.execute(select(t.case_step.c.result_digest).join(
                t.case, t.case.c.id == t.case_step.c.case_id,
            ).where(t.case.c.hunt_id == hunt_id, t.case_step.c.result_digest.is_not(None))).scalars()
            pivot_ms = sum(int(digest.get("duration_ms", 0)) for digest in digests if isinstance(digest, dict))
            return int(model_ms) + pivot_ms

    # ---- coverage ---------------------------------------------------------------------------
    def set_rule_cell(self, hunt_id: str, rule_id: str, version: str, target: str, partition: str, state: str,
                      matched: int, evaluated: int, detail: dict | None = None,
                      *, owner_token: str | None = None):
        self.set_rule_cells(hunt_id, [{"rule_id": rule_id, "version": version, "target": target,
                                       "partition": partition, "state": state, "matched": matched,
                                       "evaluated": evaluated, "detail": detail}], owner_token=owner_token)

    def set_rule_cells(self, hunt_id: str, cells: list[dict], *, owner_token: str | None = None) -> None:
        """Write coverage cells in order, in one transaction. Each cell is (rule_id, version, target, partition,
        state, matched, evaluated, detail); an existing cell keeps its row and takes the new state, counts and
        detail."""
        if not cells:
            return
        rows = [{"hunt_id": hunt_id, "rule_id": cell["rule_id"], "rule_version": cell["version"],
                 "target": cell["target"], "partition": cell["partition"], "state": cell["state"],
                 "matched": cell["matched"], "evaluated": cell["evaluated"], "detail": cell.get("detail") or {}}
                for cell in cells]
        with write_txn(self.engine) as c:
            self._fence_lease(c, hunt_id, owner_token)
            for start in range(0, len(rows), INSERT_CHUNK):
                c.execute(_RULE_CELL_UPSERT, rows[start:start + INSERT_CHUNK])

    def rule_cells(self, hunt_id: str, *, rule_id: str | None = None) -> list[dict]:
        query = select(t.rule_run).where(t.rule_run.c.hunt_id == hunt_id)
        if rule_id is not None:
            query = query.where(t.rule_run.c.rule_id == rule_id)
        with self.engine.connect() as c:
            return [dict(r) for r in c.execute(query).mappings()]

    def lane_counts(self, hunt_id: str) -> dict[str, int]:
        with self.engine.connect() as c:
            rows = c.execute(select(t.candidate.c.lane, func.count()).where(t.candidate.c.hunt_id == hunt_id)
                             .group_by(t.candidate.c.lane)).all()
            return {lane: n for lane, n in rows}

    def audit(self, actor: str, action: str, hunt_id: str | None = None, detail: dict | None = None,
              *, owner_token: str | None = None):
        with write_txn(self.engine) as c:
            if hunt_id is not None:
                self._fence_lease(c, hunt_id, owner_token)
            c.execute(t.audit_event.insert().values(at=utcnow(), actor=actor, action=action, hunt_id=hunt_id,
                                                    detail=detail or {}))
