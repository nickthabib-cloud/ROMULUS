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

from sqlalchemy import (
    Engine,
    Integer,
    String,
    and_,
    bindparam,
    case,
    cast,
    func,
    literal,
    literal_column,
    or_,
    select,
    text,
    true,
    tuple_,
)
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
# The actor of records the hunt machinery writes about its own work (summaries, maps), as opposed to people.
SYSTEM_ACTOR = "system"
LANE_STRENGTH = {"suppressed": 0, "context": 1, "lead": 2, "high": 3, "urgent": 4}
SEVERITY_STRENGTH = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
# Page plans are durable model state. These mission-scale ceilings bound repeated or
# adversarial tool calls without constraining any one source result; hunt-sized indexes
# use table high-water marks rather than copied item rows.
AGENT_PAGE_PLAN_LIMIT = 256
AGENT_PAGE_ITEM_LIMIT = 250_000
CANDIDATE_FILTER_SNAPSHOT_LIMIT = 5_000


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


# A stored typed event's boot id field, read in SQL without loading the event body (JSON text; NULL when absent).
_STORED_BOOT = func.json_extract(t.typed_event.c.event, '$.fields."host.boot.id"')


def raw_id(target: str, native_id: str) -> str:
    return hashlib.sha256(f"{target}/{native_id}".encode()).hexdigest()[:32]


# ---- baseline probes ------------------------------------------------------------------------
# Each probe ranges over a data index and probes the frozen snapshot membership primary key. Snapshot
# membership is data, never a Python-generated SQL IN list, so probe shape stays bounded at mission scale.
def _snapshot_member(segment_id, hunt_id: str, spec_id: str):
    """Join condition onto one hunt's frozen membership for one spec (the membership primary key)."""
    m = t.baseline_snapshot_segment.c
    return and_(m.segment_id == segment_id, m.hunt_id == hunt_id, m.spec_id == spec_id)


def baseline_prevalence_query(key_id: str, scope_kind: str, hunt_id: str, spec_id: str):
    """Distinct scopes of `scope_kind` holding `key_id` in one hunt's frozen snapshot of one spec."""
    c = t.baseline_count.c
    return (select(func.count(c.scope.distinct()))
            .join(t.baseline_snapshot_segment, _snapshot_member(c.segment_id, hunt_id, spec_id))
            .where(c.key_id == key_id, c.scope_kind == scope_kind))


def baseline_key_history_query(key_id: str, scope_kind: str, scope: str, hunt_id: str, spec_id: str):
    """Every count row of one key in one scope across the segments (ix_baseline_count_key)."""
    c = t.baseline_count.c
    return (select(c.segment_id, c.bucket, c.count, c.first_ts, c.last_ts)
            .join(t.baseline_snapshot_segment, _snapshot_member(c.segment_id, hunt_id, spec_id))
            .where(c.key_id == key_id, c.scope_kind == scope_kind, c.scope == scope)
            .order_by(c.key_id, c.scope_kind, c.scope, c.segment_id))


def baseline_peer_scopes_query(scope_kind: str, hunt_id: str, spec_id: str):
    """Distinct live scopes of `scope_kind` in one spec's segments (ix_baseline_scope_hour_lookup, covering)."""
    c = t.baseline_scope_hour.c
    return (select(func.count(c.scope.distinct()))
            .join(t.baseline_snapshot_segment, _snapshot_member(c.segment_id, hunt_id, spec_id))
            .where(c.scope_kind == scope_kind))


def observation_citations_query(hunt_id: str):
    """(event id, citing hunt) for every event `hunt_id` stored that another hunt's baseline observation cites
    as its first event, the lowest citing hunt id when several do: one walk of the hunt's events in id order,
    each probing ix_baseline_observation_first_event."""
    obs, ev = t.baseline_observation.c, t.typed_event.c
    return (select(ev.id, func.min(obs.hunt_id))
            .join(t.baseline_observation, obs.first_event_id == ev.id)
            .where(ev.hunt_id == hunt_id, obs.hunt_id != hunt_id)
            .group_by(ev.id))


def baseline_scope_series_query(scope_kind: str, scope: str, hunt_id: str, spec_id: str):
    """One scope's live hours and event totals across one spec's segments (ix_baseline_scope_hour_lookup)."""
    c = t.baseline_scope_hour.c
    return (select(c.segment_id, c.hour, c.events)
            .join(t.baseline_snapshot_segment, _snapshot_member(c.segment_id, hunt_id, spec_id))
            .where(c.scope_kind == scope_kind, c.scope == scope)
            .order_by(c.scope_kind, c.scope, c.segment_id, c.hour))


# ---- baseline rows ---------------------------------------------------------------------------
BASELINE_CHUNK = 5000      # rows per executemany batch while streaming a segment or observations
BASELINE_PAGE = 5000       # rows per keyset page on reads
# Child rows deleted per write transaction when an abandoned build is removed. One chunk is about as costly as
# one append chunk, so the write lock is released every fraction of a second however large the build was.
BASELINE_DELETE_CHUNK = 5000
# The builder recorded on a building segment while cleanup removes it: never a hunt id, so no owner reclaims it.
CLEANUP_OWNER = "\x00cleanup"
_BUCKET_WIDTH = {"day": timedelta(days=1), "hour": timedelta(hours=1)}
_SEGMENT_COLUMNS = frozenset(column.name for column in t.baseline_segment.columns) - {"rows_digest"}
_SEGMENT_OPTIONAL = frozenset({"source_hunt_id", "built_by_hunt_id", "network_digest"})
# What makes two writes of one segment id the same segment: everything but its lifecycle status and the time
# this copy was written (the rows are compared through rows_digest).
# The two hunt ids are provenance rather than content. A twin hunt reuses an immutable segment written by the
# first, while the stored provenance continues to identify that original write.
_SEGMENT_IDENTITY = tuple(sorted(
    _SEGMENT_COLUMNS - {"status", "created_at", "source_hunt_id", "built_by_hunt_id"},
))
_BUILD_CONTENT = _SEGMENT_IDENTITY
_COUNT_COLUMNS = tuple(column.name for column in t.baseline_count.columns)
_HOUR_COLUMNS = tuple(column.name for column in t.baseline_scope_hour.columns)
_OBSERVATION_COLUMNS = tuple(column.name for column in t.baseline_observation.columns)
_OBSERVATION_KEY = ("hunt_id", "spec_id", "spec_version", "scope", "key_digest")
_OBSERVATION_REQUIRED = frozenset({*_OBSERVATION_KEY, "scope_kind", "key_id", "key", "window_count", "verdict"})


def _baseline_observation_row(row: dict) -> dict:
    _columns(row, _OBSERVATION_COLUMNS, frozenset(_OBSERVATION_COLUMNS) - _OBSERVATION_REQUIRED,
             "observation")
    out = {name: row.get(name) for name in _OBSERVATION_COLUMNS}
    out["first_event_refs"] = list(out.get("first_event_refs") or [])
    for name in ("first_ts", "last_ts"):
        if out[name] is not None:
            out[name] = _utc(out[name], name)
    return out


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
        Refuses a hunt that may still be executing. The system's own per-hunt records (summaries, maps) go with
        the hunt; records of what people did, and an audit record of the deletion, are kept."""
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
            # Only ids and raw references: an event body is read below, one at a time, for the few events whose
            # new owner has a differing overlay, so deletion memory stays O(owned events) and never O(their bodies).
            owned_raw = {
                event_id: list(raw_ids or [])
                for event_id, raw_ids in c.execute(select(
                    t.typed_event.c.id, t.typed_event.c.raw_ids,
                ).where(t.typed_event.c.hunt_id == hunt_id))
            }
            mine = set(owned_raw)
            cited_by: dict[str, str] = {}
            users_by: dict[str, set[str]] = {}

            def cite(eid: str, citing_hunt: str) -> None:
                if eid in mine:
                    users_by.setdefault(eid, set()).add(citing_hunt)
                    cited_by.setdefault(eid, citing_hunt)

            for cid_hunt, eids in c.execute(select(t.candidate.c.hunt_id, t.candidate.c.event_ids)
                                            .where(t.candidate.c.hunt_id != hunt_id)):
                for eid in eids or []:
                    cite(eid, cid_hunt)

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
                    cite(sval, step_hunt)
            for ev_id, ent_hunt in c.execute(
                    select(t.event_entity.c.event_id, t.entity.c.hunt_id)
                    .join(t.entity, t.entity.c.id == t.event_entity.c.entity_id)
                    .where(t.entity.c.hunt_id != hunt_id)):
                cite(ev_id, ent_hunt)
            # (d) other hunts' expansion links cite events they reached and the evidence they rest on
            for link_hunt, link_events, link_evidence in c.execute(
                    select(t.expansion_link.c.hunt_id, t.expansion_link.c.event_ids, t.expansion_link.c.evidence_ids)
                    .where(t.expansion_link.c.hunt_id != hunt_id)):
                for eid in [*(link_events or []), *(link_evidence or [])]:
                    cite(eid, link_hunt)
            # (e) a later hunt's scoped citation overlay also keeps the stable typed row it describes
            citation_overlays = {
                (row["event_id"], row["hunt_id"]): dict(row)
                for row in c.execute(select(t.event_citation).join(
                    t.typed_event, t.typed_event.c.id == t.event_citation.c.event_id,
                ).where(
                    t.typed_event.c.hunt_id == hunt_id,
                    t.event_citation.c.hunt_id != hunt_id,
                )).mappings()
            }
            for event_id, citation_hunt in citation_overlays:
                cite(event_id, citation_hunt)
            # (f) every direct observation by another hunt is explicit, including entity-free events and identical
            # observations that deliberately need no citation overlay (the owner's own observation is its row).
            for event_id, observation_hunt in c.execute(select(
                    t.event_observation.c.event_id, t.event_observation.c.hunt_id,
            ).join(t.typed_event, t.typed_event.c.id == t.event_observation.c.event_id).where(
                    t.typed_event.c.hunt_id == hunt_id,
                    t.event_observation.c.hunt_id != hunt_id,
            )):
                cite(event_id, observation_hunt)
            # (g) other hunts' baseline observations cite their first window event
            for eid, obs_hunt in c.execute(observation_citations_query(hunt_id)):
                cite(eid, obs_hunt)
            displaced_raw: set[str] = set()
            for eid, owner in cited_by.items():
                overlay = citation_overlays.get((eid, owner))
                values: dict[str, Any] = {"hunt_id": owner}
                if overlay is not None:
                    # Hunts whose identical observation needed no overlay currently fall through to the stable
                    # row. Preserve that exact old row before replacing it with another hunt's differing overlay.
                    stable = c.execute(select(t.typed_event.c.event, t.typed_event.c.raw_ids).where(
                        t.typed_event.c.id == eid)).mappings().one()
                    for fallback_hunt in sorted(users_by[eid] - {owner}):
                        if (eid, fallback_hunt) in citation_overlays:
                            continue
                        c.execute(t.event_citation.insert().values(
                            hunt_id=fallback_hunt, event_id=eid,
                            event=stable["event"], raw_ids=stable["raw_ids"],
                        ))
                    displaced_raw.update(owned_raw[eid])
                    values.update(event=overlay["event"], raw_ids=overlay["raw_ids"])
                    normalizer = (overlay["event"] or {}).get("normalizer")
                    if isinstance(normalizer, str):
                        values["normalizer"] = normalizer
                c.execute(t.typed_event.update().where(t.typed_event.c.id == eid).values(**values))
                # the new owner observed the event by owning it: its marker row says nothing more
                c.execute(t.event_observation.delete().where(
                    t.event_observation.c.hunt_id == owner,
                    t.event_observation.c.event_id == eid,
                ))
                if overlay is not None:
                    c.execute(t.event_citation.delete().where(
                        t.event_citation.c.hunt_id == owner,
                        t.event_citation.c.event_id == eid,
                    ))
            drop_events = mine - set(cited_by)

            # Raw copies referenced only by this hunt's dropped events or scoped citation overlays.
            # An overlay can cite a duplicate source copy that the stable global event never cited.
            candidate_raw: set[str] = set(displaced_raw)
            for (raw_ids,) in c.execute(select(t.typed_event.c.raw_ids).where(t.typed_event.c.id.in_(drop_events))):
                candidate_raw.update(raw_ids or [])
            for (raw_ids,) in c.execute(select(t.event_citation.c.raw_ids).where(
                    t.event_citation.c.hunt_id == hunt_id)):
                candidate_raw.update(raw_ids or [])
            still_used: set[str] = set()
            if candidate_raw:
                for (raw_ids,) in c.execute(select(t.typed_event.c.raw_ids).where(
                        t.typed_event.c.id.not_in(drop_events) if drop_events else true())):
                    still_used.update(set(raw_ids or []) & candidate_raw)
                for (raw_ids,) in c.execute(select(t.event_citation.c.raw_ids).where(
                        t.event_citation.c.hunt_id != hunt_id)):
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
            rm("agent_page_items", t.agent_page_item.delete().where(t.agent_page_item.c.hunt_id == hunt_id))
            rm("agent_page_plans", t.agent_page_plan.delete().where(t.agent_page_plan.c.hunt_id == hunt_id))
            rm("agent_aliases", t.agent_alias.delete().where(t.agent_alias.c.hunt_id == hunt_id))
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
            rm("event_observations", t.event_observation.delete().where(
                t.event_observation.c.hunt_id == hunt_id,
            ))
            rm("entities", t.entity.delete().where(t.entity.c.hunt_id == hunt_id))
            rm("event_citations", t.event_citation.delete().where(t.event_citation.c.hunt_id == hunt_id))
            rm("typed_events", t.typed_event.delete().where(t.typed_event.c.id.in_(drop_events)))
            rm("raw_records", t.raw_record.delete().where(t.raw_record.c.id.in_(drop_raw)))
            rm("normalization_errors", t.normalization_error.delete().where(t.normalization_error.c.hunt_id == hunt_id))
            rm("rule_cells", t.rule_run.delete().where(t.rule_run.c.hunt_id == hunt_id))
            rm("tasks", t.task.delete().where(t.task.c.hunt_id == hunt_id))
            rm("report_revisions", t.report_manifest.delete().where(t.report_manifest.c.hunt_id == hunt_id))
            rm("source_profiles", t.source_profile.delete().where(t.source_profile.c.hunt_id == hunt_id))
            rm("audit_records", t.audit_event.delete().where(t.audit_event.c.hunt_id == hunt_id,
                                                             t.audit_event.c.actor == SYSTEM_ACTOR))
            c.execute(t.hunt.delete().where(t.hunt.c.id == hunt_id))
            counts["events_kept_for_other_hunts"] = len(cited_by)
            # the deletion itself stays auditable (audit_event has no foreign key to hunt)
            c.execute(t.audit_event.insert().values(at=now, actor=actor, action="hunt.delete", hunt_id=hunt_id,
                                                    detail={k: str(v) for k, v in counts.items()}))
            return counts

    def purge_orphan_audit(self) -> int:
        """Remove the system's per-hunt records whose hunt no longer exists (left by deletions made before
        deletion removed them); records of what people did are kept. Returns how many were removed."""
        with write_txn(self.engine) as c:
            return c.execute(t.audit_event.delete().where(
                t.audit_event.c.actor == SYSTEM_ACTOR, t.audit_event.c.hunt_id.is_not(None),
                t.audit_event.c.hunt_id.not_in(select(t.hunt.c.id)),
            )).rowcount or 0

    def hunts_with_live_lease(self, now: datetime | None = None) -> list[str]:
        """Hunts a worker may still be writing: unfinished, with a lease that has not expired. A hunt left
        'running' by a killed worker has an expired lease and is not live."""
        now = (now or utcnow()).replace(tzinfo=None)
        live = []
        for h in self.list_hunts():
            lease = h.get("lease_until")
            unfinished = h.get("execution_state") not in self.FINISHED_STATES
            if unfinished and lease is not None and lease.replace(tzinfo=None) > now:
                live.append(h["id"])
        return sorted(live)

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

    def create_agent_page_plan(self, hunt_id: str, cursor: str, identity: dict,
                               summary: dict, items: Iterable[dict]) -> dict:
        """Persist a snapshot as bounded rows; never one hunt-sized JSON value."""
        with write_txn(self.engine) as connection:
            existing = connection.execute(select(t.agent_page_plan).where(
                t.agent_page_plan.c.hunt_id == hunt_id,
                t.agent_page_plan.c.cursor == cursor,
            )).mappings().first()
            if existing is not None:
                if existing["identity"] != identity:
                    raise ValueError("page cursor already belongs to a different request")
                return dict(existing)
            existing_items = self._check_agent_page_quota(connection, hunt_id, identity)
            connection.execute(t.agent_page_plan.insert().values(
                hunt_id=hunt_id, cursor=cursor, identity=identity, summary=summary,
                item_count=0, created_at=utcnow(),
            ))
            count = 0
            batch = []
            for payload in items:
                batch.append({
                    "hunt_id": hunt_id, "cursor": cursor, "ordinal": count,
                    "payload": payload,
                })
                count += 1
                if existing_items + count > AGENT_PAGE_ITEM_LIMIT:
                    raise ValueError("agent page item quota exceeded")
                if len(batch) == 500:
                    connection.execute(t.agent_page_item.insert(), batch)
                    batch = []
            if batch:
                connection.execute(t.agent_page_item.insert(), batch)
            connection.execute(t.agent_page_plan.update().where(
                t.agent_page_plan.c.hunt_id == hunt_id,
                t.agent_page_plan.c.cursor == cursor,
            ).values(item_count=count))
        return {"hunt_id": hunt_id, "cursor": cursor, "identity": identity,
                "summary": summary, "item_count": count}

    @staticmethod
    def _plan_session(identity: dict) -> str:
        return str(identity.get("session_id") or "read-only")

    def _check_agent_page_quota(self, connection, hunt_id: str, identity: dict) -> int:
        session = self._plan_session(identity)
        plans = int(connection.execute(select(func.count()).select_from(t.agent_page_plan).where(
            t.agent_page_plan.c.hunt_id == hunt_id,
            func.coalesce(func.json_extract(t.agent_page_plan.c.identity, "$.session_id"), "read-only") == session,
        )).scalar_one())
        items = int(connection.execute(select(func.count()).select_from(
            t.agent_page_item.join(t.agent_page_plan, and_(
                t.agent_page_plan.c.hunt_id == t.agent_page_item.c.hunt_id,
                t.agent_page_plan.c.cursor == t.agent_page_item.c.cursor,
            )),
        ).where(
            t.agent_page_plan.c.hunt_id == hunt_id,
            func.coalesce(func.json_extract(
                t.agent_page_plan.c.identity, "$.session_id",
            ), "read-only") == session,
        )).scalar_one())
        if plans >= AGENT_PAGE_PLAN_LIMIT:
            raise ValueError("agent page plan quota exceeded")
        if items >= AGENT_PAGE_ITEM_LIMIT:
            raise ValueError("agent page item quota exceeded")
        return items

    def agent_page_plan(self, hunt_id: str, cursor: str) -> dict | None:
        query = select(t.agent_page_plan).where(
            t.agent_page_plan.c.hunt_id == hunt_id, t.agent_page_plan.c.cursor == cursor,
        )
        with self.engine.connect() as connection:
            row = connection.execute(query).mappings().first()
            return dict(row) if row else None

    def agent_page_items(self, hunt_id: str, cursor: str, *, offset: int,
                         limit: int) -> list[dict]:
        query = (select(t.agent_page_item.c.payload)
                 .where(t.agent_page_item.c.hunt_id == hunt_id,
                        t.agent_page_item.c.cursor == cursor)
                 .order_by(t.agent_page_item.c.ordinal).offset(offset).limit(limit))
        with self.engine.connect() as connection:
            return [dict(payload) for payload in connection.execute(query).scalars()]

    def agent_page_items_by_kind(self, hunt_id: str, cursor: str, kind: str, *,
                                 offset: int, limit: int) -> list[dict]:
        query = (select(t.agent_page_item.c.payload)
                 .where(t.agent_page_item.c.hunt_id == hunt_id,
                        t.agent_page_item.c.cursor == cursor,
                        func.json_extract(t.agent_page_item.c.payload, "$.kind") == kind)
                 .order_by(t.agent_page_item.c.ordinal).offset(offset).limit(limit))
        with self.engine.connect() as connection:
            return [dict(payload) for payload in connection.execute(query).scalars()]

    def agent_incident_index_item(self, hunt_id: str, alias: str) -> dict | None:
        query = (select(t.agent_page_item.c.payload)
                 .join(t.agent_page_plan, and_(
                     t.agent_page_plan.c.hunt_id == t.agent_page_item.c.hunt_id,
                     t.agent_page_plan.c.cursor == t.agent_page_item.c.cursor,
                 )).where(
                     t.agent_page_plan.c.hunt_id == hunt_id,
                     func.json_extract(t.agent_page_plan.c.identity, "$.kind") == "incident_index",
                     func.json_extract(t.agent_page_item.c.payload, "$.header.alias") == alias,
                 ).order_by(t.agent_page_plan.c.created_at.desc()).limit(1))
        with self.engine.connect() as connection:
            payload = connection.execute(query).scalar()
            return dict(payload) if payload is not None else None

    def create_candidate_page_plan(self, hunt_id: str, cursor: str, identity: dict,
                                   summary: dict, *, lane: str | None = None,
                                   rule_id: str | None = None,
                                   entity: tuple[str, str] | None = None,
                                   lanes: tuple[str, ...] | None = None) -> dict:
        """Snapshot matching candidate ids with a stable SQL sort and bounded Python batches."""
        where = [t.candidate.c.hunt_id == hunt_id]
        if lane is not None:
            where.append(t.candidate.c.lane == lane)
        if lanes is not None:
            where.append(t.candidate.c.lane.in_(lanes))
        if rule_id is not None:
            where.append(t.candidate.c.rule_id == rule_id)
        if entity is not None:
            values = func.json_each(t.candidate.c.entities).table_valued("key", "value").alias("entities")
            where.append(select(1).select_from(values).where(
                func.json_extract(values.c.value, "$[0]") == entity[0],
                func.json_extract(values.c.value, "$[1]") == entity[1],
            ).exists())
        with write_txn(self.engine) as connection:
            existing = connection.execute(select(t.agent_page_plan).where(
                t.agent_page_plan.c.hunt_id == hunt_id,
                t.agent_page_plan.c.cursor == cursor,
            )).mappings().first()
            if existing is not None:
                if existing["identity"] != identity:
                    raise ValueError("page cursor already belongs to a different request")
                return dict(existing)
            high_water = int(connection.execute(select(func.coalesce(func.max(
                literal_column("candidate.rowid"),
            ), 0)).select_from(t.candidate).where(
                t.candidate.c.hunt_id == hunt_id,
            )).scalar_one())
            where.append(literal_column("candidate.rowid") <= high_water)
            count = int(connection.execute(select(func.count()).select_from(t.candidate).where(
                *where,
            )).scalar_one())
            stored_membership = lane is not None or rule_id is not None or entity is not None
            if stored_membership and count > CANDIDATE_FILTER_SNAPSHOT_LIMIT:
                raise ValueError(
                    "filtered candidate snapshot exceeds its bounded membership cap; "
                    "page the unfiltered finding index instead",
                )
            existing_items = self._check_agent_page_quota(connection, hunt_id, identity)
            if stored_membership and existing_items + count > AGENT_PAGE_ITEM_LIMIT:
                raise ValueError("agent page item quota exceeded")
            stored_summary = {**summary, "candidate_snapshot": {
                "rowid_high_water": high_water,
                "lane": lane, "rule_id": rule_id, "entity": list(entity) if entity else None,
                "lanes": list(lanes) if lanes else None,
                "membership": "persisted" if stored_membership else "live_keyset",
            }}
            connection.execute(t.agent_page_plan.insert().values(
                hunt_id=hunt_id, cursor=cursor, identity=identity, summary=stored_summary,
                item_count=count, created_at=utcnow(),
            ))
            if stored_membership:
                batch = []
                for ordinal, candidate_id in enumerate(connection.execute(
                    select(t.candidate.c.id).where(*where).order_by(t.candidate.c.id),
                ).scalars()):
                    batch.append({
                        "hunt_id": hunt_id, "cursor": cursor, "ordinal": ordinal,
                        "payload": {"kind": "candidate_member", "id": candidate_id},
                    })
                    if len(batch) == 500:
                        connection.execute(t.agent_page_item.insert(), batch)
                        batch = []
                if batch:
                    connection.execute(t.agent_page_item.insert(), batch)
        return {"hunt_id": hunt_id, "cursor": cursor, "identity": identity,
                "summary": stored_summary, "item_count": count}

    def candidate_page_plan_rows(self, hunt_id: str, cursor: str, *, offset: int,
                                 limit: int) -> list[dict]:
        plan = self.agent_page_plan(hunt_id, cursor)
        if plan is None or "candidate_snapshot" not in plan["summary"]:
            return []
        snapshot = plan["summary"]["candidate_snapshot"]
        if snapshot.get("membership") == "persisted":
            items = self.agent_page_items(hunt_id, cursor, offset=offset, limit=limit)
            ids = [str(item["id"]) for item in items]
            if not ids:
                return []
            aliases = t.agent_alias.alias("candidate_page_alias")
            query = (select(t.candidate, aliases.c.alias.label("_alias")).outerjoin(
                aliases, and_(
                    aliases.c.hunt_id == t.candidate.c.hunt_id,
                    aliases.c.kind == "F", aliases.c.target_id == t.candidate.c.id,
                ),
            ).where(
                t.candidate.c.hunt_id == hunt_id, t.candidate.c.id.in_(ids),
            ))
            with self.engine.connect() as connection:
                by_id = {str(row["id"]): dict(row) for row in connection.execute(query).mappings()}
            if len(by_id) != len(ids):
                raise ValueError("candidate snapshot membership changed during paging")
            return [by_id[candidate_id] for candidate_id in ids]
        where = [
            t.candidate.c.hunt_id == hunt_id,
            literal_column("candidate.rowid") <= int(snapshot["rowid_high_water"]),
        ]
        if snapshot.get("lane") is not None:
            where.append(t.candidate.c.lane == snapshot["lane"])
        if snapshot.get("lanes") is not None:
            where.append(t.candidate.c.lane.in_(snapshot["lanes"]))
        if snapshot.get("rule_id") is not None:
            where.append(t.candidate.c.rule_id == snapshot["rule_id"])
        entity = snapshot.get("entity")
        if entity is not None:
            values = func.json_each(t.candidate.c.entities).table_valued("key", "value").alias("entities")
            where.append(select(1).select_from(values).where(
                func.json_extract(values.c.value, "$[0]") == entity[0],
                func.json_extract(values.c.value, "$[1]") == entity[1],
            ).exists())
        # Candidate identifiers are immutable. Derive the page boundary once, then
        # fetch with a keyset predicate so lane/priority updates cannot move an item
        # across an OFFSET boundary. A deletion changes the snapshot cardinality and
        # is reported instead of silently skipping a surviving finding.
        with self.engine.connect() as connection:
            current_count = int(connection.execute(
                select(func.count()).select_from(t.candidate).where(*where),
            ).scalar_one())
            if current_count != int(plan["item_count"]):
                raise ValueError("candidate snapshot membership changed during paging")
            if offset:
                boundary = connection.execute(
                    select(t.candidate.c.id).where(*where).order_by(t.candidate.c.id)
                    .offset(offset - 1).limit(1),
                ).scalar()
                if boundary is None:
                    return []
                where.append(t.candidate.c.id > boundary)
            aliases = t.agent_alias.alias("candidate_page_alias")
            query = (select(t.candidate, aliases.c.alias.label("_alias")).outerjoin(
                aliases, and_(
                    aliases.c.hunt_id == t.candidate.c.hunt_id,
                    aliases.c.kind == "F", aliases.c.target_id == t.candidate.c.id,
                ),
            ).where(*where).order_by(t.candidate.c.id).limit(limit))
            return [dict(row) for row in connection.execute(query).mappings()]

    def create_entity_event_page_plan(self, hunt_id: str, cursor: str, identity: dict,
                                      entity_id: str) -> dict:
        with write_txn(self.engine) as connection:
            existing = connection.execute(select(t.agent_page_plan).where(
                t.agent_page_plan.c.hunt_id == hunt_id,
                t.agent_page_plan.c.cursor == cursor,
            )).mappings().first()
            if existing is not None:
                if existing["identity"] != identity:
                    raise ValueError("page cursor already belongs to a different request")
                return dict(existing)
            base = t.typed_event.join(
                t.event_entity, t.event_entity.c.event_id == t.typed_event.c.id,
            )
            high_water = int(connection.execute(select(func.coalesce(func.max(
                literal_column("typed_event.rowid"),
            ), 0)).select_from(base).where(
                t.event_entity.c.entity_id == entity_id,
            )).scalar_one())
            total = int(connection.execute(
                select(func.count()).select_from(base).where(
                    t.event_entity.c.entity_id == entity_id,
                    literal_column("typed_event.rowid") <= high_water,
                ),
            ).scalar_one())
            families = {str(family): int(count) for family, count in connection.execute(
                select(t.typed_event.c.family, func.count()).select_from(base)
                .where(t.event_entity.c.entity_id == entity_id,
                       literal_column("typed_event.rowid") <= high_water)
                .group_by(t.typed_event.c.family).order_by(t.typed_event.c.family),
            )}
            self._check_agent_page_quota(connection, hunt_id, identity)
            summary = {"families": families, "entity_snapshot": {
                "entity_id": entity_id, "rowid_high_water": high_water,
            }}
            connection.execute(t.agent_page_plan.insert().values(
                hunt_id=hunt_id, cursor=cursor, identity=identity, summary=summary,
                item_count=total, created_at=utcnow(),
            ))
        return {"hunt_id": hunt_id, "cursor": cursor, "identity": identity,
                "summary": summary, "item_count": total}

    def entity_event_page_plan_ids(self, hunt_id: str, cursor: str, *, offset: int,
                                   limit: int) -> list[str]:
        plan = self.agent_page_plan(hunt_id, cursor)
        if plan is None or "entity_snapshot" not in plan["summary"]:
            return []
        snapshot = plan["summary"]["entity_snapshot"]
        query = (select(t.typed_event.c.id)
                 .join(t.event_entity, t.event_entity.c.event_id == t.typed_event.c.id)
                 .where(t.event_entity.c.entity_id == snapshot["entity_id"],
                        literal_column("typed_event.rowid") <= int(snapshot["rowid_high_water"]))
                 .order_by(t.typed_event.c.ts, t.typed_event.c.id).offset(offset).limit(limit))
        with self.engine.connect() as connection:
            return [str(value) for value in connection.execute(query).scalars()]

    def entity_event_fingerprint(self, entity_id: str) -> str:
        query = (select(t.typed_event.c.id, t.typed_event.c.ts)
                 .join(t.event_entity, t.event_entity.c.event_id == t.typed_event.c.id)
                 .where(t.event_entity.c.entity_id == entity_id)
                 .order_by(t.typed_event.c.ts, t.typed_event.c.id))
        fingerprint = hashlib.sha256()
        with self.engine.connect() as connection:
            for event_id, event_ts in connection.execution_options(yield_per=500).execute(query):
                fingerprint.update(f"{event_ts!s}\0{event_id}\n".encode())
        return fingerprint.hexdigest()

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

    def agent_source_queries(self, hunt_id: str) -> int:
        """Durable source-call spend reserved by the AI agent across every session and resume."""
        with self.engine.connect() as c:
            return int(c.execute(select(func.count()).select_from(t.audit_event).where(
                t.audit_event.c.hunt_id == hunt_id,
                t.audit_event.c.action == "agent.source_query",
            )).scalar_one())

    def reserve_agent_source_query(self, hunt_id: str, limit: int, task_id: str | None,
                                   *, owner_token: str | None = None) -> int | None:
        """Atomically reserve one query under the per-hunt AI-agent cap; return new spend or None."""
        with write_txn(self.engine) as c:
            self._fence_lease(c, hunt_id, owner_token)
            used = int(c.execute(select(func.count()).select_from(t.audit_event).where(
                t.audit_event.c.hunt_id == hunt_id,
                t.audit_event.c.action == "agent.source_query",
            )).scalar_one())
            if used >= limit:
                return None
            if task_id is not None:
                c.execute(t.task.update().where(
                    t.task.c.id == task_id, t.task.c.hunt_id == hunt_id,
                ).values(source_queries=t.task.c.source_queries + 1, updated_at=utcnow()))
            c.execute(t.audit_event.insert().values(
                at=utcnow(), actor="system", action="agent.source_query", hunt_id=hunt_id,
                detail={"task_id": task_id, "ordinal": used + 1, "limit": limit},
            ))
            return used + 1

    def expansion_source_queries(self, hunt_id: str) -> int:
        """Durable physical-query spend for expansion, including an interrupted link."""
        with self.engine.connect() as c:
            task_spend = int(c.execute(select(func.coalesce(func.sum(t.task.c.source_queries), 0)).where(
                t.task.c.hunt_id == hunt_id, t.task.c.kind == "expansion_link",
            )).scalar_one())
            link_spend = int(c.execute(select(func.coalesce(func.sum(t.expansion_link.c.query_spend), 0)).where(
                t.expansion_link.c.hunt_id == hunt_id,
                t.expansion_link.c.strength != "agent_hypothesis",
                ~t.expansion_link.c.link_type.like("agent_%"),
            )).scalar_one())
        # Completed links and tasks describe the same calls. The max also supports
        # databases upgraded from link-only accounting without double-counting.
        return max(task_spend, link_spend)

    def host_resolution_tasks(self, hunt_id: str) -> list[dict]:
        """The hunt's durable host-address lookups (one per looked-up address and window), oldest first."""
        with self.engine.connect() as c:
            return [dict(r) for r in c.execute(select(t.task).where(
                t.task.c.hunt_id == hunt_id, t.task.c.kind == "expansion_link",
                t.task.c.owner == "host-resolution").order_by(t.task.c.created_at, t.task.c.id)).mappings()]

    def tasks(self, hunt_id: str) -> list[dict]:
        with self.engine.connect() as c:
            return [dict(r) for r in c.execute(select(t.task).where(t.task.c.hunt_id == hunt_id)
                                               .order_by(t.task.c.created_at)).mappings()]

    # ---- evidence ---------------------------------------------------------------------------
    def save_evidence(self, hunt_id: str, events: Iterable, raw_sources: dict[str, dict], task_id: str | None,
                      *, owner_token: str | None = None):
        """Persist typed events plus retained raw copies for every record they cite. A row already stored is never
        written again (the first written wins), so a re-save serializes only what is new: the events and raw copies
        no hunt stored yet, and this hunt's entity rows for events it does not own."""
        events = list(events)
        with write_txn(self.engine) as c:
            self._fence_lease(c, hunt_id, owner_token)
            if owner_token is None:
                # what is stored is read under the write lock: a deletion cannot remove a row between this read
                # and the writes that rely on it being there
                self._lock(c, hunt_id)
            # rows this hunt already stored (with their entity rows) need no rebuild; another hunt's rows still
            # get this hunt's entity rows, which deletion relies on to keep events another hunt uses
            ids = sorted({event.id for event in events})
            existing = self._stored_events(c, ids)
            own_ids = {event_id for event_id, row in existing.items() if row["hunt_id"] == hunt_id}
            raw_rows = self._new_raw_rows(c, events, raw_sources, task_id)
            ev_rows: dict[str, dict] = {}
            ent_rows: dict[str, dict] = {}
            link_rows = []
            for e in events:
                if e.id in own_ids:
                    continue
                if e.id not in existing and e.id not in ev_rows:
                    ev_rows[e.id] = {"id": e.id, "hunt_id": hunt_id, "family": e.family, "ts": e.ts, "host": e.host,
                                     "event": e.model_dump(mode="json"),
                                     "raw_ids": [raw_id(r.target, r.native_id) for r in e.raw],
                                     "normalizer": e.normalizer}
                for kind, value, role in e.entities():
                    eid = f"{hunt_id}:{kind}:{value}"
                    ent_rows.setdefault(eid, {"id": eid, "hunt_id": hunt_id, "kind": kind, "value": value,
                                              "first_seen": e.ts, "last_seen": e.ts, "event_count": 0})
                    link_rows.append({"event_id": e.id, "entity_id": eid, "role": role})
            _upsert_ignore(c, t.raw_record, raw_rows, ["id"])
            _upsert_ignore(c, t.typed_event, list(ev_rows.values()), ["id"])
            if existing:
                self._merge_citation_raw(c, hunt_id, events, existing)
            self._observe(c, hunt_id, ids)
            self._fill_boot(c, events)
            _upsert_ignore(c, t.entity, list(ent_rows.values()), ["id"])
            _upsert_ignore(c, t.event_entity, link_rows, ["event_id", "entity_id", "role"])

    @staticmethod
    def _merge_citation_raw(c, hunt_id: str, events: list, existing: dict[str, dict]) -> None:
        """Keep the stable event immutable and snapshot only hunt-specific raw-reference differences."""
        ids = sorted(existing)
        overlays: dict[str, dict] = {}
        prior_citations: set[str] = set()
        for start in range(0, len(ids), 500):
            chunk = ids[start:start + 500]
            overlays.update((row["event_id"], dict(row)) for row in c.execute(select(t.event_citation).where(
                t.event_citation.c.hunt_id == hunt_id,
                t.event_citation.c.event_id.in_(chunk),
            )).mappings())
            prior_citations.update(c.execute(select(t.event_observation.c.event_id).where(
                t.event_observation.c.hunt_id == hunt_id,
                t.event_observation.c.event_id.in_(chunk),
            )).scalars())
        incoming: dict[str, tuple[Any, list]] = {}
        for event in events:
            if event.id not in existing:
                continue
            state = incoming.setdefault(event.id, (event, []))
            known = {(raw.target, raw.native_id) for raw in state[1]}
            for raw in event.raw:
                key = (raw.target, raw.native_id)
                if key not in known:
                    state[1].append(raw)
                    known.add(key)
        for event_id, (event, incoming_raw) in incoming.items():
            global_row = existing.get(event_id)
            if global_row is None:
                continue
            row = overlays.get(event_id)
            if row:
                stored = dict(row["event"])
                stored_raw = list(stored.get("raw") or [])
                known = {(item.get("target"), item.get("native_id")) for item in stored_raw}
                additions = [raw.model_dump(mode="json") for raw in incoming_raw
                             if (raw.target, raw.native_id) not in known]
                if not additions:
                    continue
                stored["raw"] = [*stored_raw, *additions]
                raw_ids = list(dict.fromkeys([
                    *(row.get("raw_ids") or []),
                    *(raw_id(raw.target, raw.native_id) for raw in incoming_raw),
                ]))
                c.execute(t.event_citation.update().where(
                    t.event_citation.c.hunt_id == hunt_id,
                    t.event_citation.c.event_id == event_id,
                ).values(event=stored, raw_ids=raw_ids))
            else:
                incoming_ids = list(dict.fromkeys(
                    raw_id(raw.target, raw.native_id) for raw in incoming_raw
                ))
                stable_ids = list(global_row.get("raw_ids") or [])
                if set(incoming_ids) == set(stable_ids):
                    continue
                # A prior identical observation needed no overlay; when this hunt later retrieves another copy,
                # its exact history is the stable set plus that copy. A first differing observation starts only
                # from what this hunt actually retrieved, never from the owning hunt's citation set.
                stored = event.model_dump(mode="json")
                stored["raw"] = [raw.model_dump(mode="json") for raw in incoming_raw]
                raw_ids = incoming_ids
                if global_row["hunt_id"] == hunt_id or event_id in prior_citations:
                    # the stable body is read only here, the one case that extends it
                    stable = c.execute(select(t.typed_event.c.event).where(
                        t.typed_event.c.id == event_id)).scalar_one()
                    stable_raw = list((stable or {}).get("raw") or [])
                    known = {(item.get("target"), item.get("native_id")) for item in stable_raw}
                    additions = [raw.model_dump(mode="json") for raw in incoming_raw
                                 if (raw.target, raw.native_id) not in known]
                    stored["raw"] = [*stable_raw, *additions]
                    raw_ids = list(dict.fromkeys([*stable_ids, *incoming_ids]))
                c.execute(t.event_citation.insert().values(
                    hunt_id=hunt_id, event_id=event_id, event=stored, raw_ids=raw_ids,
                ))
            overlays[event_id] = {
                "hunt_id": hunt_id, "event_id": event_id, "event": stored, "raw_ids": raw_ids,
            }

    def merge_evidence_raw(self, hunt_id: str, events: Iterable, raw_sources: dict[str, dict], *,
                           owner_token: str | None = None) -> None:
        """Merge raw copies only when a cited event already exists; never persist an uncited event."""
        events = list(events)
        ids = sorted({event.id for event in events})
        if not ids:
            return
        with write_txn(self.engine) as c:
            self._fence_lease(c, hunt_id, owner_token)
            if owner_token is None:
                self._lock(c, hunt_id)
            existing = self._stored_events(c, ids)
            _upsert_ignore(c, t.raw_record, self._new_raw_rows(
                c, [event for event in events if event.id in existing], raw_sources, None,
            ), ["id"])
            self._merge_citation_raw(c, hunt_id, events, existing)
            self._observe(c, hunt_id, sorted(existing))

    @staticmethod
    def _lock(c, hunt_id: str) -> None:
        """Take SQLite's write lock now (pysqlite defers BEGIN until the first write), so the rows this transaction
        reads next stay as read until it commits. The no-op write touches no key, so no foreign key is checked."""
        c.execute(t.hunt.update().where(t.hunt.c.id == hunt_id).values(lease_owner=t.hunt.c.lease_owner))

    @staticmethod
    def _stored_events(c, ids: list[str]) -> dict[str, dict]:
        """The stored stable rows among `ids`: id, owning hunt and raw references (never the event body)."""
        existing: dict[str, dict] = {}
        for start in range(0, len(ids), 500):
            for row in c.execute(select(
                t.typed_event.c.id, t.typed_event.c.hunt_id, t.typed_event.c.raw_ids,
            ).where(t.typed_event.c.id.in_(ids[start:start + 500]))).mappings():
                existing[row["id"]] = dict(row)
        return existing

    @staticmethod
    def _new_raw_rows(c, events: list, raw_sources: dict[str, dict], task_id: str | None) -> list[dict]:
        """Rows for the raw copies the events reference that no hunt stored yet, one per id with the first reference
        given winning, as an insert that skips stored keys would keep them: a stored copy is never serialized
        again."""
        wanted: dict[str, Any] = {}
        for event in events:
            for raw in event.raw:
                if raw_sources.get(raw.key) is not None:     # a missing copy is not stored, never as null
                    wanted.setdefault(raw_id(raw.target, raw.native_id), raw)
        ids = sorted(wanted)
        stored: set[str] = set()
        for start in range(0, len(ids), 500):
            stored.update(c.execute(select(t.raw_record.c.id).where(
                t.raw_record.c.id.in_(ids[start:start + 500]))).scalars())
        now = utcnow()
        return [{"id": rid, "target": raw.target, "native_id": raw.native_id, "digest": raw.digest,
                 "source": raw_sources[raw.key], "first_task_id": task_id, "retrieved_at": now}
                for rid, raw in wanted.items() if rid not in stored]

    @staticmethod
    def _observe(c, hunt_id: str, ids: list[str]) -> None:
        """Record that this hunt directly observed these stored events. The hunt that owns an event's stable row
        (`typed_event.hunt_id`) observed it by definition, so only an event another hunt owns gets a marker row:
        a hunt observed an event when it owns the row or holds a marker for it. Runs after the batch's own rows are
        written, inside the same write transaction, so ownership is read as it is stored."""
        for start in range(0, len(ids), 500):
            c.execute(insert(t.event_observation).from_select(
                ["hunt_id", "event_id"],
                select(literal(hunt_id), t.typed_event.c.id).where(
                    t.typed_event.c.id.in_(ids[start:start + 500]), t.typed_event.c.hunt_id != hunt_id,
                ),
            ).on_conflict_do_nothing())

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
            # only the stored boot field is read to decide; a row's body is read when it takes the boot id
            unfilled = []
            for event_id, current in c.execute(select(t.typed_event.c.id, _STORED_BOOT)
                                               .where(t.typed_event.c.id.in_(ids[start:start + 500]))):
                current = json.loads(current) if isinstance(current, str) else None
                current = current if isinstance(current, dict) else {}
                if current.get("value") not in (None, "") and not is_derived_boot(current):
                    continue
                unfilled.append(event_id)
            for event_id in unfilled:
                stored = c.execute(select(t.typed_event.c.event).where(t.typed_event.c.id == event_id)).scalar_one()
                fields = stored.get("fields") or {}
                stored = {**stored, "fields": {**fields, "host.boot.id": booted[event_id]}}
                c.execute(t.typed_event.update().where(t.typed_event.c.id == event_id).values(event=stored))

    def events_by_ids(self, ids: list[str]) -> list[dict]:
        with self.engine.connect() as c:
            return [dict(r) for r in c.execute(select(t.typed_event).where(t.typed_event.c.id.in_(ids))).mappings()]

    def citation_events(self, hunt_id: str, ids: list[str]) -> list[dict]:
        """Typed events with the raw provenance retained specifically for this hunt."""
        with self.engine.connect() as c:
            query = select(
                *t.typed_event.c,
                t.event_citation.c.event.label("citation_event"),
                t.event_citation.c.raw_ids.label("citation_raw_ids"),
            ).select_from(t.typed_event.outerjoin(t.event_citation, and_(
                t.event_citation.c.event_id == t.typed_event.c.id,
                t.event_citation.c.hunt_id == hunt_id,
            ))).where(t.typed_event.c.id.in_(ids))
            rows = {}
            for result in c.execute(query).mappings():
                row = dict(result)
                citation_event = row.pop("citation_event")
                citation_raw_ids = row.pop("citation_raw_ids")
                if citation_event is not None:
                    row.update(event=citation_event, raw_ids=citation_raw_ids)
                rows[row["id"]] = row
        return list(rows.values())

    def raw_records(self, ids: list[str]) -> list[dict]:
        with self.engine.connect() as c:
            return [dict(r) for r in c.execute(select(t.raw_record).where(t.raw_record.c.id.in_(ids))).mappings()]

    # ---- candidates -------------------------------------------------------------------------
    def save_candidate(self, row: dict, *, canonicalize_agent: bool = False,
                       owner_token: str | None = None) -> bool:
        """Insert once, except that a deterministic pass may canonicalize an agent-first duplicate."""
        with write_txn(self.engine) as c:
            self._fence_lease(c, row["hunt_id"], owner_token)
            existing = c.execute(select(t.candidate).where(
                t.candidate.c.id == row["id"],
            )).mappings().first()
            if existing:
                if not (canonicalize_agent and existing["source_case_id"] is not None
                        and row.get("source_case_id") is None):
                    return False
                before = dict(existing)
                existing_priority = float(existing["priority"])
                incoming_priority = float(row["priority"])
                lane = max(
                    (str(existing["lane"]), str(row["lane"])),
                    key=lambda value: LANE_STRENGTH.get(value, -1),
                )
                severity = max(
                    (str(existing["severity"]), str(row["severity"])),
                    key=lambda value: SEVERITY_STRENGTH.get(value, -1),
                )
                event_ids = sorted({*(existing["event_ids"] or []), *(row.get("event_ids") or [])})
                # a record the deterministic pass cites only for its statements stays context; an agent-first
                # citation of it keeps it the finding's own
                context = sorted(set(row.get("context_event_ids") or ()) - set(existing["event_ids"] or ()))
                values = {
                    # The later deterministic pass owns canonical wording and provenance. It must
                    # never weaken the machine decision or discard evidence already cited.
                    "rule_version": row["rule_version"],
                    "claim": row["claim"],
                    "claim_type": row["claim_type"],
                    "event_ids": event_ids,
                    "context_event_ids": context,
                    "lane": lane,
                    "severity": severity,
                    "priority": max(existing_priority, incoming_priority),
                    "priority_reasons": (row["priority_reasons"] if incoming_priority > existing_priority
                                         else existing["priority_reasons"]),
                    "source_case_id": None,
                    "source_anchor_id": row.get("source_anchor_id"),
                    "source_link_id": row.get("source_link_id"),
                }
                c.execute(t.candidate.update().where(t.candidate.c.id == row["id"]).values(**values))
                after = {**before, **values}
                audit_fields = (
                    "claim", "claim_type", "event_ids", "lane", "severity", "priority",
                    "source_case_id", "source_anchor_id", "source_link_id",
                )
                c.execute(t.audit_event.insert().values(
                    at=utcnow(), actor="system", action="candidate.canonicalize_agent_first",
                    hunt_id=row["hunt_id"], detail={
                        "candidate_id": row["id"],
                        "before": {field: before[field] for field in audit_fields},
                        "after": {field: after[field] for field in audit_fields},
                    },
                ))
                return True
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

    def candidates_with_finding_aliases(self, hunt_id: str, lanes: list[str]) -> list[dict]:
        aliases = t.agent_alias.alias("finding_alias")
        query = (select(t.candidate, aliases.c.alias.label("_alias"))
                 .join(aliases, and_(
                     aliases.c.hunt_id == t.candidate.c.hunt_id,
                     aliases.c.kind == "F", aliases.c.target_id == t.candidate.c.id,
                 )).where(t.candidate.c.hunt_id == hunt_id, t.candidate.c.lane.in_(lanes)))
        with self.engine.connect() as connection:
            return [dict(row) for row in connection.execute(query).mappings()]

    def candidate_count(self, hunt_id: str, *, lane: str | None = None,
                        rule_id: str | None = None) -> int:
        query = select(func.count()).select_from(t.candidate).where(t.candidate.c.hunt_id == hunt_id)
        if lane is not None:
            query = query.where(t.candidate.c.lane == lane)
        if rule_id is not None:
            query = query.where(t.candidate.c.rule_id == rule_id)
        with self.engine.connect() as connection:
            return int(connection.execute(query).scalar_one())

    def candidate_count_lanes(self, hunt_id: str, lanes: tuple[str, ...]) -> int:
        query = select(func.count()).select_from(t.candidate).where(
            t.candidate.c.hunt_id == hunt_id, t.candidate.c.lane.in_(lanes),
        )
        with self.engine.connect() as connection:
            return int(connection.execute(query).scalar_one())

    def expansion_link_count(self, hunt_id: str) -> int:
        query = select(func.count()).select_from(t.expansion_link).where(
            t.expansion_link.c.hunt_id == hunt_id,
        )
        with self.engine.connect() as connection:
            return int(connection.execute(query).scalar_one())

    def expansion_link_payload_bytes(self, hunt_id: str) -> int:
        """Approximate persisted variable payload bytes before Python JSON materialization."""
        payload = sum(
            func.length(cast(column, String))
            for column in (
                t.expansion_link.c.key, t.expansion_link.c.event_ids,
                t.expansion_link.c.evidence_ids, t.expansion_link.c.task_ids,
                t.expansion_link.c.coverage, t.expansion_link.c.reasons,
            )
        )
        query = select(func.coalesce(func.sum(payload), 0)).where(
            t.expansion_link.c.hunt_id == hunt_id,
        )
        with self.engine.connect() as connection:
            return int(connection.execute(query).scalar_one())

    def entity_count(self, hunt_id: str) -> int:
        with self.engine.connect() as connection:
            return int(connection.execute(select(func.count()).select_from(t.entity).where(
                t.entity.c.hunt_id == hunt_id,
            )).scalar_one())

    def entities_for_keys(self, hunt_id: str, keys: set[tuple[str, str]]) -> list[dict]:
        """Fetch only entity identities cited by the bounded candidate materialization."""
        if not keys:
            return []
        ordered = sorted(keys)
        rows: list[dict] = []
        with self.engine.connect() as connection:
            for offset in range(0, len(ordered), 250):
                batch = ordered[offset:offset + 250]
                query = select(t.entity).where(
                    t.entity.c.hunt_id == hunt_id,
                    tuple_(t.entity.c.kind, t.entity.c.value).in_(batch),
                ).order_by(t.entity.c.kind, t.entity.c.value, t.entity.c.id)
                rows.extend(dict(row) for row in connection.execute(query).mappings())
        return rows

    def rule_cell_count(self, hunt_id: str) -> int:
        query = select(func.count()).select_from(t.rule_run).where(t.rule_run.c.hunt_id == hunt_id)
        with self.engine.connect() as connection:
            return int(connection.execute(query).scalar_one())

    def rule_cell_state_counts(self, hunt_id: str) -> dict[str, int]:
        """Return bounded coverage health aggregates without materializing rule rows."""
        query = (select(t.rule_run.c.state, func.count())
                 .where(t.rule_run.c.hunt_id == hunt_id)
                 .group_by(t.rule_run.c.state))
        with self.engine.connect() as connection:
            return {str(state): int(count) for state, count in connection.execute(query)}

    def rule_cell_coverage_counts(self, hunt_id: str, rule_ids: set[str],
                                  targets: set[str]) -> dict[str, int]:
        """Aggregate expected rule/target coverage without loading individual cells."""
        expected = len(rule_ids) * len(targets)
        if not rule_ids or not targets:
            return {"cells": 0, "expected_rule_targets": expected,
                    "present_rule_targets": 0, "incomplete": 0}
        target = func.replace(t.rule_run.c.target, "arkime-pcap:", "")
        relevant = and_(
            t.rule_run.c.hunt_id == hunt_id,
            t.rule_run.c.state != "split",
            t.rule_run.c.rule_id.in_(sorted(rule_ids)),
            target.in_(sorted(targets)),
        )
        pair = t.rule_run.c.rule_id + literal_column("char(31)") + target
        incomplete = case(
            (or_(
                t.rule_run.c.state.in_(("planned", "failed")),
                t.rule_run.c.state.like("%partial%"),
            ), 1),
            else_=0,
        )
        query = select(
            func.count(), func.count(func.distinct(pair)), func.coalesce(func.sum(incomplete), 0),
        ).where(relevant)
        with self.engine.connect() as connection:
            cells, present, bad = connection.execute(query).one()
        return {
            "cells": int(cells), "expected_rule_targets": expected,
            "present_rule_targets": int(present), "incomplete": int(bad),
        }

    def candidate_page(self, hunt_id: str, *, offset: int, limit: int,
                       lane: str | None = None, rule_id: str | None = None) -> list[dict]:
        """Return one stable finding page without materializing the hunt's candidate table."""
        lane_order = case(
            (t.candidate.c.lane == "urgent", 0), (t.candidate.c.lane == "high", 1),
            (t.candidate.c.lane == "lead", 2), (t.candidate.c.lane == "context", 3),
            (t.candidate.c.lane == "suppressed", 4), else_=99,
        )
        query = select(t.candidate).where(t.candidate.c.hunt_id == hunt_id)
        if lane is not None:
            query = query.where(t.candidate.c.lane == lane)
        if rule_id is not None:
            query = query.where(t.candidate.c.rule_id == rule_id)
        query = query.order_by(
            lane_order, t.candidate.c.priority.desc(), t.candidate.c.ts, t.candidate.c.id,
        ).offset(offset).limit(limit)
        with self.engine.connect() as connection:
            return [dict(row) for row in connection.execute(query).mappings()]

    def candidate_rule_counts(self, hunt_id: str, *, lane: str) -> dict[str, int]:
        query = (select(t.candidate.c.rule_id, func.count())
                 .where(t.candidate.c.hunt_id == hunt_id, t.candidate.c.lane == lane)
                 .group_by(t.candidate.c.rule_id))
        with self.engine.connect() as connection:
            return {str(rule_id): int(count) for rule_id, count in connection.execute(query)}

    def candidate_fingerprint(self, hunt_id: str) -> str:
        """Hash candidate content in stable order without collecting the result set."""
        query = (select(t.candidate.c.id, t.candidate.c.rule_id, t.candidate.c.claim,
                        t.candidate.c.entities, t.candidate.c.ts, t.candidate.c.lane,
                        t.candidate.c.priority, t.candidate.c.source_case_id,
                        t.candidate.c.source_anchor_id, t.candidate.c.source_link_id)
                 .where(t.candidate.c.hunt_id == hunt_id).order_by(t.candidate.c.id))
        fingerprint = hashlib.sha256()
        with self.engine.connect() as connection:
            for row in connection.execution_options(yield_per=500).execute(query).mappings():
                fingerprint.update(json.dumps(dict(row), sort_keys=True, default=str,
                                              separators=(",", ":")).encode())
                fingerprint.update(b"\n")
        return fingerprint.hexdigest()

    def candidate(self, cid: str) -> dict | None:
        with self.engine.connect() as c:
            r = c.execute(select(t.candidate).where(t.candidate.c.id == cid)).mappings().first()
            return dict(r) if r else None

    def candidates_by_ids(self, ids: list[str], *, finding_alias: bool = False) -> list[dict]:
        if not ids:
            return []
        query = select(t.candidate).where(t.candidate.c.id.in_(ids))
        if finding_alias:
            aliases = t.agent_alias.alias("candidate_alias")
            query = (select(t.candidate, aliases.c.alias.label("_alias"))
                     .outerjoin(aliases, and_(
                         aliases.c.hunt_id == t.candidate.c.hunt_id,
                         aliases.c.kind == "F", aliases.c.target_id == t.candidate.c.id,
                     )).where(t.candidate.c.id.in_(ids)))
        with self.engine.connect() as connection:
            return [dict(row) for row in connection.execute(query).mappings()]

    # ---- durable per-hunt aliases -----------------------------------------------------------
    def agent_aliases(self, hunt_id: str) -> list[dict]:
        query = (select(t.agent_alias).where(t.agent_alias.c.hunt_id == hunt_id)
                 .order_by(t.agent_alias.c.kind, t.agent_alias.c.alias))
        with self.engine.connect() as c:
            return [dict(row) for row in c.execute(query).mappings()]

    def agent_alias(self, hunt_id: str, alias: str) -> dict | None:
        query = select(t.agent_alias).where(
            t.agent_alias.c.hunt_id == hunt_id, t.agent_alias.c.alias == alias,
        )
        with self.engine.connect() as c:
            row = c.execute(query).mappings().first()
            return dict(row) if row else None

    def agent_alias_target_hunts(self, kind: str, target_id: str,
                                 *, hunt_id: str | None = None) -> list[str]:
        table = {"F": t.candidate, "E": t.typed_event, "N": t.entity, "L": t.expansion_link}.get(kind)
        if table is None:
            return []
        with self.engine.connect() as c:
            owners = set(c.execute(select(table.c.hunt_id).where(table.c.id == target_id)).scalars())
            # Typed events can be retained once and cited by more than one hunt. Those citing hunts
            # own an E alias even when the physical row remains attributed to its first hunt.
            if kind == "E":
                scoped_hunts = [hunt_id] if hunt_id is not None else sorted(owners)
                for scoped_hunt in scoped_hunts:
                    associated = c.execute(select(1).select_from(t.entity).join(
                        t.event_entity, t.event_entity.c.entity_id == t.entity.c.id,
                    ).where(
                        t.entity.c.hunt_id == scoped_hunt,
                        t.event_entity.c.event_id == target_id,
                    ).limit(1)).scalar()
                    candidate_events = func.json_each(t.candidate.c.event_ids).table_valued(
                        "key", "value",
                    ).alias("candidate_events")
                    cited_candidate = c.execute(select(1).select_from(t.candidate).where(
                        t.candidate.c.hunt_id == scoped_hunt,
                        select(1).select_from(candidate_events).where(
                            candidate_events.c.value == target_id,
                        ).exists(),
                    ).limit(1)).scalar()
                    link_events = func.json_each(t.expansion_link.c.event_ids).table_valued(
                        "key", "value",
                    ).alias("link_events")
                    link_evidence = func.json_each(t.expansion_link.c.evidence_ids).table_valued(
                        "key", "value",
                    ).alias("link_evidence")
                    cited_link = c.execute(select(1).select_from(t.expansion_link).where(
                        t.expansion_link.c.hunt_id == scoped_hunt,
                        or_(
                            select(1).select_from(link_events).where(
                                link_events.c.value == target_id,
                            ).exists(),
                            select(1).select_from(link_evidence).where(
                                link_evidence.c.value == target_id,
                            ).exists(),
                        ),
                    ).limit(1)).scalar()
                    if associated or cited_candidate or cited_link:
                        owners.add(scoped_hunt)
            return sorted(owners)

    def get_or_create_agent_alias(self, hunt_id: str, kind: str, target_id: str) -> dict:
        """Allocate the next alias inside the serialized repository writer."""
        with write_txn(self.engine) as c:
            if c.execute(select(t.hunt.c.id).where(t.hunt.c.id == hunt_id)).scalar() is None:
                raise KeyError(hunt_id)
            existing = c.execute(select(t.agent_alias).where(
                t.agent_alias.c.hunt_id == hunt_id,
                t.agent_alias.c.kind == kind,
                t.agent_alias.c.target_id == target_id,
            )).mappings().first()
            if existing is not None:
                return dict(existing)
            names = c.execute(select(t.agent_alias.c.alias).where(
                t.agent_alias.c.hunt_id == hunt_id, t.agent_alias.c.kind == kind,
            )).scalars()
            number = max((int(name[1:]) for name in names if name[1:].isdigit()), default=0) + 1
            row = {"hunt_id": hunt_id, "alias": f"{kind}{number}", "kind": kind,
                   "target_id": target_id, "created_at": utcnow()}
            c.execute(t.agent_alias.insert().values(**row))
            return row

    def seed_agent_aliases(self, hunt_id: str, targets: list[tuple[str, str]]) -> list[dict]:
        """Assign an ordered seed set atomically, preserving existing aliases."""
        with write_txn(self.engine) as c:
            if c.execute(select(t.hunt.c.id).where(t.hunt.c.id == hunt_id)).scalar() is None:
                raise KeyError(hunt_id)
            existing = [dict(row) for row in c.execute(select(t.agent_alias).where(
                t.agent_alias.c.hunt_id == hunt_id,
            )).mappings()]
            by_target = {(row["kind"], row["target_id"]): row for row in existing}
            next_number: dict[str, int] = {}
            for row in existing:
                suffix = row["alias"][1:]
                if suffix.isdigit():
                    next_number[row["kind"]] = max(next_number.get(row["kind"], 1), int(suffix) + 1)
            created = []
            ordered = []
            for kind, target_id in targets:
                key = (kind, target_id)
                row = by_target.get(key)
                if row is None:
                    number = next_number.get(kind, 1)
                    next_number[kind] = number + 1
                    row = {"hunt_id": hunt_id, "alias": f"{kind}{number}", "kind": kind,
                           "target_id": target_id, "created_at": utcnow()}
                    by_target[key] = row
                    created.append(row)
                ordered.append(row)
            if created:
                c.execute(t.agent_alias.insert(), created)
            return ordered

    def seed_agent_base_aliases(self, hunt_id: str) -> None:
        """Seed finding/entity aliases in SQL so opening a toolbox is mission-scale bounded."""
        lane_order = case(
            (t.candidate.c.lane == "urgent", 0), (t.candidate.c.lane == "high", 1),
            (t.candidate.c.lane == "lead", 2), (t.candidate.c.lane == "context", 3),
            (t.candidate.c.lane == "suppressed", 4), else_=99,
        )
        with write_txn(self.engine) as connection:
            for kind, source, ordering in (
                ("F", t.candidate, (lane_order, t.candidate.c.priority.desc(),
                                     t.candidate.c.ts, t.candidate.c.id)),
                ("N", t.entity, (t.entity.c.kind, t.entity.c.value, t.entity.c.id)),
            ):
                maximum = (select(func.coalesce(func.max(cast(func.substr(
                    t.agent_alias.c.alias, 2), Integer)), 0))
                    .where(t.agent_alias.c.hunt_id == hunt_id,
                           t.agent_alias.c.kind == kind).scalar_subquery())
                missing = ~select(1).where(
                    t.agent_alias.c.hunt_id == hunt_id,
                    t.agent_alias.c.kind == kind,
                    t.agent_alias.c.target_id == source.c.id,
                ).exists()
                numbered = (select(
                    source.c.id.label("target_id"),
                    (maximum + func.row_number().over(order_by=ordering)).label("number"),
                ).where(source.c.hunt_id == hunt_id, missing).subquery())
                values = select(
                    literal(hunt_id), literal(kind) + cast(numbered.c.number, String),
                    literal(kind), numbered.c.target_id, literal(utcnow()),
                )
                connection.execute(t.agent_alias.insert().from_select(
                    ["hunt_id", "alias", "kind", "target_id", "created_at"], values,
                ))

    def entities(self, hunt_id: str) -> list[dict]:
        query = (select(t.entity).where(t.entity.c.hunt_id == hunt_id)
                 .order_by(t.entity.c.kind, t.entity.c.value, t.entity.c.id))
        with self.engine.connect() as c:
            return [dict(row) for row in c.execute(query).mappings()]

    def entity(self, entity_id: str) -> dict | None:
        with self.engine.connect() as c:
            row = c.execute(select(t.entity).where(t.entity.c.id == entity_id)).mappings().first()
            return dict(row) if row else None

    def entity_for(self, hunt_id: str, kind: str, value: str) -> dict | None:
        query = select(t.entity).where(
            t.entity.c.hunt_id == hunt_id, t.entity.c.kind == kind, t.entity.c.value == value,
        )
        with self.engine.connect() as c:
            row = c.execute(query).mappings().first()
            return dict(row) if row else None

    def events_for_entity(self, entity_id: str) -> list[dict]:
        query = (select(t.typed_event)
                 .join(t.event_entity, t.event_entity.c.event_id == t.typed_event.c.id)
                 .where(t.event_entity.c.entity_id == entity_id)
                 .order_by(t.typed_event.c.ts, t.typed_event.c.id))
        with self.engine.connect() as c:
            return [dict(row) for row in c.execute(query).mappings()]

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
    def baseline_store_cut_digest(self, *, site: str, targets: Iterable[str], specs: Iterable[dict],
                                  start: datetime, end: datetime) -> str:
        """Digest active segment identities eligible at hunt creation, streamed in canonical order."""
        start, end = _utc(start, "baseline cut start"), _utc(end, "baseline cut end")
        hasher = hashlib.sha256()
        segment = t.baseline_segment.c
        with self.engine.connect() as connection:
            for target in sorted(set(targets)):
                for spec in sorted(specs, key=lambda item: item["id"]):
                    query = (select(segment.id, segment.status)
                             .where(segment.site == site, segment.target == target,
                                    segment.spec_id == spec["id"],
                                    segment.spec_version == spec["version"],
                                    segment.key_version == spec["key_version"],
                                    segment.status == "active", segment.start < end,
                                    segment.end > start, segment.end <= end)
                             .order_by(segment.id))
                    for segment_id, status in connection.execute(query):
                        material = {"id": segment_id, "status": status, "target": target,
                                    "spec_id": spec["id"]}
                        hasher.update(json.dumps(
                            material, sort_keys=True, separators=(",", ":"),
                        ).encode())
                        hasher.update(b"\n")
        return hasher.hexdigest()

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

    def prune_baseline_segment(self, segment_id: str) -> bool:
        """Delete one stale/revoked segment unless a retained snapshot still references it."""
        segment, member = t.baseline_segment.c, t.baseline_snapshot_segment.c
        with write_txn(self.engine) as connection:
            status = connection.execute(select(segment.status).where(
                segment.id == segment_id,
            )).scalar_one_or_none()
            if status not in {"stale", "revoked"}:
                return False
            retained = connection.execute(select(member.segment_id).where(
                member.segment_id == segment_id,
            ).limit(1)).first()
            if retained is not None:
                return False
            return bool(connection.execute(t.baseline_segment.delete().where(
                segment.id == segment_id, segment.status.in_(("stale", "revoked")),
            )).rowcount)

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

    def begin_baseline_segment(self, row: dict, *, reclaim_owner: bool = False) -> str:
        """Create an invisible building segment, optionally restarting this hunt's crashed build.

        Returns "begun" when the caller now owns an empty building row; "active" when the identical segment
        is already active (another hunt finished it); "building_elsewhere" when another hunt, or cleanup,
        holds it; otherwise the stored status (for example "stale" or "revoked"), which the caller must report.

        The hunt lease serializes one writer per hunt. Reclamation is therefore safe only for the same
        ``built_by_hunt_id``; a building row owned by another hunt, or claimed by cleanup, remains protected.
        Reclaiming first refreshes the row's ``created_at`` so a concurrent cleanup cannot claim it, then drops
        the crashed rows in bounded transactions, then replaces the row.
        """
        segment = _baseline_segment_row(row)
        if segment["status"] != "building":
            raise ValueError("a chunked baseline segment must begin with status building")
        s = t.baseline_segment.c
        owned = and_(s.id == segment["id"], s.status == "building",
                     s.built_by_hunt_id == segment["built_by_hunt_id"])
        with write_txn(self.engine) as c:
            existing = c.execute(select(t.baseline_segment).where(s.id == segment["id"])).mappings().first()
            if existing is None:
                c.execute(t.baseline_segment.insert().values(**segment, rows_digest=""))
                return "begun"
            stored = _with_utc(existing, ("start", "end", "created_at"))
            if any(stored[name] != segment[name] for name in _BUILD_CONTENT):
                raise ValueError(f"baseline segment {segment['id']} exists with different content")
            if stored["status"] != "building":
                return stored["status"]
            if not (reclaim_owner and stored["built_by_hunt_id"] == segment["built_by_hunt_id"]):
                return "building_elsewhere"
            c.execute(t.baseline_segment.update().where(owned).values(created_at=segment["created_at"]))
        self._drop_baseline_children(segment["id"])
        with write_txn(self.engine) as c:
            if not c.execute(t.baseline_segment.delete().where(owned)).rowcount:
                return "building_elsewhere"
            c.execute(t.baseline_segment.insert().values(**segment, rows_digest=""))
            return "begun"

    def _drop_baseline_children(self, segment_id: str) -> None:
        """Delete one segment's child rows, one short write transaction per bounded chunk."""
        chunk = BASELINE_DELETE_CHUNK
        for table in (t.baseline_count, t.baseline_scope_hour):
            statement = text(
                f"DELETE FROM {table.name} WHERE rowid IN "
                f"(SELECT rowid FROM {table.name} WHERE segment_id = :segment_id LIMIT :chunk)"
            )
            while True:
                with write_txn(self.engine) as c:
                    deleted = c.execute(statement, {"segment_id": segment_id, "chunk": chunk}).rowcount
                if deleted < chunk:
                    break

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
        """Delete abandoned builds before history work resumes, never holding the write lock for long.

        Each abandoned row is claimed in one small transaction (its builder becomes ``CLEANUP_OWNER``, so its
        owner can no longer reclaim it), its child rows go in bounded chunks, and the row itself goes last. A
        cleaner that crashes part way leaves a claimed row that the next cleanup finishes.
        """
        before = _utc(before, "building cleanup time")
        s = t.baseline_segment.c
        abandoned = and_(s.status == "building", s.created_at < before)
        removed = 0
        while True:
            with self.engine.connect() as c:
                segment_id = c.execute(select(s.id).where(abandoned).order_by(s.id).limit(1)).scalar_one_or_none()
            if segment_id is None:
                return removed
            with write_txn(self.engine) as c:
                claimed = c.execute(t.baseline_segment.update().where(s.id == segment_id, abandoned)
                                    .values(built_by_hunt_id=CLEANUP_OWNER)).rowcount
            if not claimed:
                continue  # its owner refreshed it between the read and the claim; it is no longer abandoned
            self._drop_baseline_children(segment_id)
            with write_txn(self.engine) as c:
                removed += c.execute(t.baseline_segment.delete().where(
                    s.id == segment_id, s.status == "building", s.built_by_hunt_id == CLEANUP_OWNER,
                )).rowcount

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
                                    end: datetime, network_digest: str | None = None) -> list[dict]:
        """Active segments usable before ``end``, including ones that straddle the left boundary."""
        start, end = _utc(start, "cover start"), _utc(end, "cover end")
        s = t.baseline_segment.c
        query = (select(t.baseline_segment).where(
            s.site == site, s.target == target, s.spec_id == spec_id,
            s.spec_version == spec_version, s.key_version == key_version,
            s.status == "active", s.start < end, s.end > start, s.end <= end,
        ).order_by(s.start, s.end, s.id))
        if network_digest is not None:
            query = query.where(s.network_digest == network_digest)
        with self.engine.connect() as c:
            return [_with_utc(item, ("start", "end", "created_at")) for item in c.execute(query).mappings()]

    def baseline_segment_covers(self, *, site: str, target: str, spec_id: str, spec_version: str,
                                key_version: str, start: datetime, end: datetime,
                                network_digest: str | None = None) -> bool:
        """Whether one active segment of the spec's versions contains [start, end), whatever its width."""
        start, end = _utc(start, "cover start"), _utc(end, "cover end")
        s = t.baseline_segment.c
        query = select(s.id).where(
            s.site == site, s.target == target, s.spec_id == spec_id,
            s.spec_version == spec_version, s.key_version == key_version,
            s.status == "active", s.start <= start, s.end >= end,
        ).limit(1)
        if network_digest is not None:
            query = query.where(s.network_digest == network_digest)
        with self.engine.connect() as c:
            return c.execute(query).first() is not None

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

    def baseline_key_prevalence(self, key_id: str, scope_kind: str, hunt_id: str, spec_id: str) -> int:
        """How many distinct scopes hold `key_id` in the hunt's frozen snapshot of `spec_id`."""
        with self.engine.connect() as c:
            return int(c.execute(baseline_prevalence_query(key_id, scope_kind, hunt_id, spec_id)).scalar_one())

    def baseline_peer_scopes(self, scope_kind: str, hunt_id: str, spec_id: str) -> int:
        """How many distinct scopes were live in one spec's snapshot (the prevalence denominator)."""
        with self.engine.connect() as c:
            return int(c.execute(baseline_peer_scopes_query(scope_kind, hunt_id, spec_id)).scalar_one())

    def baseline_key_history(self, key_id: str, scope_kind: str, scope: str,
                             hunt_id: str, spec_id: str) -> list[dict]:
        """One key's count rows in one scope; at most one row per segment bucket of the snapshot span."""
        with self.engine.connect() as c:
            return [_with_utc(row, ("bucket", "first_ts", "last_ts")) for row in c.execute(
                baseline_key_history_query(key_id, scope_kind, scope, hunt_id, spec_id)).mappings()]

    def baseline_scope_series(self, scope_kind: str, scope: str, hunt_id: str, spec_id: str) -> list[dict]:
        """One scope's live hours in one spec's snapshot; at most one row per hour per target."""
        with self.engine.connect() as c:
            return [_with_utc(row, ("hour",)) for row in c.execute(
                baseline_scope_series_query(scope_kind, scope, hunt_id, spec_id)).mappings()]

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
            # Membership copies each segment's spec and target from the segment row itself, one keyed
            # insert-select per id in bounded chunks; an id with no segment rolls the whole snapshot back.
            s = t.baseline_segment.c
            member = insert(t.baseline_snapshot_segment).from_select(
                ["hunt_id", "spec_id", "segment_id", "target"],
                select(literal(row["hunt_id"]), s.spec_id, s.id, s.target).where(s.id == bindparam("sid")),
            )
            for chunk in _chunks(({"sid": segment_id} for segment_id in segment_ids), BASELINE_CHUNK):
                inserted = c.execute(member, chunk).rowcount
                if inserted != len(chunk):
                    raise ValueError("snapshot names an unknown baseline segment")
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

    def baseline_snapshot_exclusions(self, hunt_id: str, spec_id: str) -> dict:
        """Bounded provenance summary for a spec's frozen segments, without materializing exclusion lists."""
        segment, member = t.baseline_segment.c, t.baseline_snapshot_segment.c
        query = select(
            func.count(),
            func.coalesce(func.sum(func.json_array_length(segment.excluded_keys)), 0),
            func.coalesce(func.sum(segment.hunted), 0),
        ).select_from(t.baseline_segment.join(
            t.baseline_snapshot_segment, member.segment_id == segment.id,
        )).where(
            member.hunt_id == hunt_id, member.spec_id == spec_id,
        )
        with self.engine.connect() as connection:
            segments, excluded, hunted = connection.execute(query).one()
        return {"segments": int(segments), "excluded_keys": int(excluded),
                "hunted_segments": int(hunted)}

    def baseline_parent_boot(self, hunt_id: str, target: str, host: str) -> tuple[str, datetime] | None:
        with self.engine.connect() as c:
            row = c.execute(select(t.baseline_parent_host_boot).where(
                t.baseline_parent_host_boot.c.hunt_id == hunt_id,
                t.baseline_parent_host_boot.c.target == target,
                t.baseline_parent_host_boot.c.host == host,
            )).mappings().first()
        if row is None:
            return None
        return row["boot"], _stored_utc(row["latest_ts"])

    def set_baseline_parent_boot(self, hunt_id: str, target: str, host: str, boot: str,
                                 latest_ts: datetime) -> bool:
        """Advance one host's carry state; an older different boot is rejected."""
        latest_ts = _utc(latest_ts, "parent boot latest_ts")
        table = t.baseline_parent_host_boot.c
        with write_txn(self.engine) as c:
            current = c.execute(select(t.baseline_parent_host_boot).where(
                table.hunt_id == hunt_id, table.target == target, table.host == host,
            )).mappings().first()
            if current is not None:
                current_ts = _stored_utc(current["latest_ts"])
                if current["boot"] != boot and current_ts >= latest_ts:
                    return False
                if current["boot"] != boot:
                    c.execute(t.baseline_parent_carry.delete().where(
                        t.baseline_parent_carry.c.hunt_id == hunt_id,
                        t.baseline_parent_carry.c.target == target,
                        t.baseline_parent_carry.c.host == host,
                    ))
                elif current_ts > latest_ts:
                    latest_ts = current_ts
            stmt = insert(t.baseline_parent_host_boot).values(
                hunt_id=hunt_id, target=target, host=host, boot=boot, latest_ts=latest_ts,
            ).on_conflict_do_update(
                index_elements=["hunt_id", "target", "host"],
                set_={"boot": boot, "latest_ts": latest_ts},
            )
            c.execute(stmt)
            return True

    def source_profiles(self, hunt_id: str) -> dict[str, dict]:
        """Each target's most recently captured source profile for this hunt."""
        table = t.source_profile.c
        with self.engine.connect() as c:
            rows = c.execute(select(table.target, table.profile).where(table.hunt_id == hunt_id)
                             .order_by(table.captured_at, table.id)).all()
        return {str(target): profile for target, profile in rows if isinstance(profile, dict)}

    def baseline_parent_targets(self, hunt_id: str, host: str) -> list[str]:
        """Every target that could deliver this host's execs, including a holder that delivered none.

        Carry rows prove delivery. Source profiles conservatively add host-capable holders whose inventory names
        the host; a target that failed throughout the window therefore still prevents a cross-target parent guess.
        """
        table = t.baseline_parent_host_boot.c
        with self.engine.connect() as c:
            targets = set(c.execute(select(table.target).where(
                table.hunt_id == hunt_id, table.host == host,
            )).scalars())
            profiles = c.execute(select(t.source_profile.c.target, t.source_profile.c.profile).where(
                t.source_profile.c.hunt_id == hunt_id,
            )).all()
        wanted = host.strip().rstrip(".").casefold()
        for target, profile in profiles:
            if not isinstance(profile, dict) or profile.get("role") != "host":
                continue
            datasets = profile.get("datasets") or {}
            fields = profile.get("field_types") or {}
            exec_capable = any(str(name).startswith("linux.audit") for name in datasets) or (
                "process.executable" in fields and "process.pid" in fields
            )
            hosts = profile.get("hosts") or {}
            inventory_truncated = any(
                str(note).startswith("hosts inventory truncated")
                for note in profile.get("notes") or []
            )
            if exec_capable and (inventory_truncated or wanted in {
                str(name).strip().rstrip(".").casefold() for name in hosts
            }):
                targets.add(str(target))
        return sorted(targets)

    def upsert_baseline_parents(self, rows: Iterable[dict]) -> None:
        """Keep the latest two observed exec generations for each live PID, ordered by (time, audit serial).

        An exec at the instant of a held generation is the same exec unless both carry distinct serials (then the
        serial orders them). If it is "the same" instant but a different image, the generation is marked
        ambiguous: without an order the PID's image after that instant is unknown, never guessed.
        """
        stmt = insert(t.baseline_parent_carry)
        table, excluded = t.baseline_parent_carry.c, stmt.excluded

        def ordered(ts_a, serial_a, ts_b, serial_b):
            return and_(ts_a == ts_b, serial_a.is_not(None), serial_b.is_not(None), serial_a > serial_b)

        def same_instant(ts_a, serial_a, ts_b, serial_b):
            return and_(ts_a == ts_b, or_(serial_a.is_(None), serial_b.is_(None), serial_a == serial_b))

        newer = or_(excluded.exec_ts > table.exec_ts,
                    ordered(excluded.exec_ts, excluded.serial, table.exec_ts, table.serial))
        at_current = same_instant(excluded.exec_ts, excluded.serial, table.exec_ts, table.serial)
        older_candidate = and_(
            ~newer, ~at_current,
            or_(table.previous_exec_ts.is_(None), excluded.exec_ts > table.previous_exec_ts,
                ordered(excluded.exec_ts, excluded.serial, table.previous_exec_ts, table.previous_serial)),
        )
        at_previous = and_(~newer, ~at_current, same_instant(
            excluded.exec_ts, excluded.serial, table.previous_exec_ts, table.previous_serial))

        def flag(held, ambiguous, held_executable):
            return case((or_(held == 1, ambiguous == 1, excluded.executable != held_executable), 1), else_=0)

        stmt = stmt.on_conflict_do_update(
            index_elements=["hunt_id", "target", "host", "boot", "pid"],
            set_={
                **{f"previous_{name}": case((newer, table[name]), (older_candidate, excluded[name]),
                                            else_=table[f"previous_{name}"])
                   for name in ("exec_ts", "executable", "parent_pid", "raw_id", "serial")},
                "previous_ambiguous": case(
                    (newer, table.ambiguous), (older_candidate, excluded.ambiguous),
                    (at_previous, flag(table.previous_ambiguous, excluded.ambiguous, table.previous_executable)),
                    else_=table.previous_ambiguous,
                ),
                **{name: case((newer, excluded[name]), else_=table[name])
                   for name in ("exec_ts", "executable", "parent_pid", "raw_id", "serial")},
                "ambiguous": case(
                    (newer, excluded.ambiguous),
                    (at_current, flag(table.ambiguous, excluded.ambiguous, table.executable)),
                    else_=table.ambiguous,
                ),
            },
        )
        for chunk in _chunks(rows, BASELINE_CHUNK):
            with write_txn(self.engine) as c:
                c.execute(stmt, chunk)

    def baseline_parent_generations(self, hunt_id: str, target: str, host: str, pid: int,
                                    boot: str | None) -> list[dict]:
        """The stored generations of `pid` (at most two, newest first); choosing one is the caller's job."""
        if isinstance(pid, bool) or not isinstance(pid, int) or pid < 0:
            return []
        table = t.baseline_parent_carry.c
        with self.engine.connect() as c:
            row = c.execute(select(t.baseline_parent_carry).where(
                table.hunt_id == hunt_id, table.target == target, table.host == host,
                table.boot == (boot or ""), table.pid == pid,
            )).mappings().first()
        if row is None:
            return []
        out = [{"exec_ts": _stored_utc(row["exec_ts"]), "serial": row["serial"], "executable": row["executable"],
                "parent_pid": row["parent_pid"], "raw_id": row["raw_id"], "ambiguous": bool(row["ambiguous"])}]
        if row["previous_exec_ts"] is not None and row["previous_executable"]:
            out.append({
                "exec_ts": _stored_utc(row["previous_exec_ts"]), "serial": row["previous_serial"],
                "executable": row["previous_executable"], "parent_pid": row["previous_parent_pid"],
                "raw_id": row["previous_raw_id"], "ambiguous": bool(row["previous_ambiguous"]),
            })
        return out

    def baseline_parent_count(self, hunt_id: str) -> int:
        with self.engine.connect() as c:
            return int(c.execute(select(func.count()).select_from(t.baseline_parent_carry).where(
                t.baseline_parent_carry.c.hunt_id == hunt_id,
            )).scalar_one())

    def _coalesce_range(self, table, keys: dict, start: datetime, end: datetime) -> None:
        """Add [start, end) to a range ledger keyed by `keys`, merging overlapping or touching rows in the
        same transaction, so the ledger holds one row per continuous run."""
        start, end = _utc(start, "range start"), _utc(end, "range end")
        if end <= start:
            raise ValueError("ledger range must be nonempty")
        columns = table.c
        scope = [columns[name] == value for name, value in keys.items()]
        with write_txn(self.engine) as c:
            touching = c.execute(select(columns.start, columns.end).where(
                *scope, columns.start <= end, columns.end >= start,
            )).all()
            for row in touching:
                start = min(start, _stored_utc(row.start))
                end = max(end, _stored_utc(row.end))
            if touching:
                c.execute(table.delete().where(*scope, columns.start.in_([row.start for row in touching])))
            c.execute(table.insert().values(**keys, start=start, end=end))

    def mark_baseline_parent_observed(self, hunt_id: str, target: str, start: datetime,
                                      end: datetime) -> None:
        """Record that every record of `target` in [start, end) was fed to the carry."""
        self._coalesce_range(t.baseline_parent_observed, {"hunt_id": hunt_id, "target": target}, start, end)

    def mark_baseline_parent_break(self, hunt_id: str, target: str, host: str, start: datetime,
                                   end: datetime) -> None:
        """Record that `host` had an exec in [start, end) whose identity the carry does not hold."""
        self._coalesce_range(t.baseline_parent_break,
                             {"hunt_id": hunt_id, "target": target, "host": host}, start, end)

    def baseline_parent_break_overlaps(self, hunt_id: str, target: str, host: str, start: datetime,
                                       end: datetime) -> bool:
        """Whether any break of `host` intersects [start, end) (a primary-key range search)."""
        start, end = _utc(start, "break start"), _utc(end, "break end")
        table = t.baseline_parent_break.c
        with self.engine.connect() as c:
            row = c.execute(select(table.end).where(
                table.hunt_id == hunt_id, table.target == target, table.host == host, table.start < end,
            ).order_by(table.start.desc()).limit(1)).first()
        return row is not None and _stored_utc(row.end) > start

    def baseline_parent_breaks(self, hunt_id: str, target: str, host: str) -> list[tuple[datetime, datetime]]:
        table = t.baseline_parent_break.c
        with self.engine.connect() as c:
            rows = c.execute(select(table.start, table.end).where(
                table.hunt_id == hunt_id, table.target == target, table.host == host,
            ).order_by(table.start)).all()
        return [(_stored_utc(row.start), _stored_utc(row.end)) for row in rows]

    def baseline_parent_observed_covers(self, hunt_id: str, target: str, start: datetime,
                                        end: datetime) -> bool:
        """Whether one continuous observed run contains [start, end) (a primary-key range search)."""
        start, end = _utc(start, "observed start"), _utc(end, "observed end")
        table = t.baseline_parent_observed.c
        with self.engine.connect() as c:
            row = c.execute(select(table.end).where(
                table.hunt_id == hunt_id, table.target == target, table.start <= start,
            ).order_by(table.start.desc()).limit(1)).first()
        return row is not None and _stored_utc(row.end) >= end

    def baseline_parent_observed_ranges(self, hunt_id: str, target: str) -> list[tuple[datetime, datetime]]:
        table = t.baseline_parent_observed.c
        with self.engine.connect() as c:
            rows = c.execute(select(table.start, table.end).where(
                table.hunt_id == hunt_id, table.target == target,
            ).order_by(table.start)).all()
        return [(_stored_utc(row.start), _stored_utc(row.end)) for row in rows]

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

        written = 0
        with write_txn(self.engine) as c:
            for chunk in _chunks((_baseline_observation_row(row) for row in rows), chunk_size):
                c.execute(stmt, chunk)
                written += len(chunk)
        return written

    def baseline_window_cell_done(self, hunt_id: str, rule_id: str, version: str,
                                  target: str, partition: str) -> bool:
        """Whether one baseline cell was durably merged already (anything other than planned/split)."""
        table = t.rule_run.c
        with self.engine.connect() as c:
            state = c.execute(select(table.state).where(
                table.hunt_id == hunt_id, table.rule_id == rule_id, table.rule_version == version,
                table.target == target, table.partition == partition,
            )).scalar_one_or_none()
        return state is not None and state not in {"planned", "split", "executed_failed"}

    def stage_baseline_window_cell(self, hunt_id: str, cell: dict, execs: Iterable[dict],
                                   observations: Iterable[dict], pendings: Iterable[dict],
                                   counts: Iterable[dict] = (), scope_hours: Iterable[dict] = ()) -> None:
        """Replace one unresolved exec-pair cell with compact durable state."""
        key = (hunt_id, cell["target"], cell["partition"])

        def json_body(value: dict) -> dict:
            return json.loads(json.dumps(value, default=_jsonable))

        with write_txn(self.engine) as connection:
            for table in (t.baseline_window_exec, t.baseline_window_observation,
                          t.baseline_window_pending):
                connection.execute(table.delete().where(
                    table.c.hunt_id == key[0], table.c.target == key[1],
                    table.c.partition == key[2],
                ))
            stmt = insert(t.baseline_window_cell).values(
                hunt_id=hunt_id, target=cell["target"], partition=cell["partition"],
                spec_version=cell["spec_version"], start=_utc(cell["start"], "window start"),
                end=_utc(cell["end"], "window end"),
                target_applicable=int(bool(cell["target_applicable"])),
                source_complete=int(bool(cell["source_complete"])),
                reasons=sorted(set(cell.get("reasons") or [])), task_id=cell.get("task_id"),
                evaluated=int(cell.get("evaluated") or 0),
            ).on_conflict_do_update(
                index_elements=["hunt_id", "target", "partition"],
                set_={
                    "spec_version": cell["spec_version"], "start": _utc(cell["start"], "window start"),
                    "end": _utc(cell["end"], "window end"),
                    "target_applicable": int(bool(cell["target_applicable"])),
                    "source_complete": int(bool(cell["source_complete"])),
                    "reasons": sorted(set(cell.get("reasons") or [])),
                    "task_id": cell.get("task_id"), "evaluated": int(cell.get("evaluated") or 0),
                },
            )
            connection.execute(stmt)
            _upsert_ignore(connection, t.baseline_window_exec, [
                {"hunt_id": hunt_id, "target": key[1], "partition": key[2], "ordinal": ordinal,
                 **row}
                for ordinal, row in enumerate(execs)
            ], ["hunt_id", "target", "partition", "ordinal"])
            _upsert_ignore(connection, t.baseline_window_observation, [
                {"hunt_id": hunt_id, "target": key[1], "partition": key[2], "ordinal": ordinal,
                 "body": json_body(row)}
                for ordinal, row in enumerate(observations)
            ], ["hunt_id", "target", "partition", "ordinal"])
            _upsert_ignore(connection, t.baseline_window_pending, [
                {"hunt_id": hunt_id, "target": key[1], "partition": key[2], "ordinal": ordinal,
                 "body": json_body(row)}
                for ordinal, row in enumerate(pendings)
            ], ["hunt_id", "target", "partition", "ordinal"])
            self._replace_baseline_window_counter_rows(
                connection, hunt_id, "bl.exec_pair", cell["spec_version"], key[1], key[2],
                counts, scope_hours,
            )

    def baseline_window_cells(self, hunt_id: str) -> list[dict]:
        with self.engine.connect() as connection:
            rows = connection.execute(select(t.baseline_window_cell).where(
                t.baseline_window_cell.c.hunt_id == hunt_id,
            ).order_by(
                t.baseline_window_cell.c.target, t.baseline_window_cell.c.start,
                t.baseline_window_cell.c.partition,
            )).mappings()
            return [_with_utc(row, ("start", "end")) for row in rows]

    def _baseline_window_children(self, table, hunt_id: str, target: str, partition: str) -> list[dict]:
        with self.engine.connect() as connection:
            return [dict(row) for row in connection.execute(select(table).where(
                table.c.hunt_id == hunt_id, table.c.target == target, table.c.partition == partition,
            ).order_by(table.c.ordinal)).mappings()]

    def baseline_window_execs(self, hunt_id: str, target: str, partition: str) -> list[dict]:
        return [_with_utc(row, ("ts",)) for row in self._baseline_window_children(
            t.baseline_window_exec, hunt_id, target, partition,
        )]

    def baseline_window_observations(self, hunt_id: str, target: str, partition: str) -> list[dict]:
        rows = self._baseline_window_children(t.baseline_window_observation, hunt_id, target, partition)
        out = []
        for row in rows:
            body = dict(row["body"])
            for name in ("first_ts", "last_ts"):
                if body.get(name):
                    body[name] = datetime.fromisoformat(body[name])
            out.append(body)
        return out

    def baseline_window_pendings(self, hunt_id: str, target: str, partition: str) -> list[dict]:
        rows = self._baseline_window_children(t.baseline_window_pending, hunt_id, target, partition)
        out = []
        for row in rows:
            body = dict(row["body"])
            body["ts"] = datetime.fromisoformat(body["ts"])
            body["raw_refs"] = tuple(tuple(ref) for ref in body.get("raw_refs") or ())
            out.append(body)
        return out

    def drop_baseline_window_cell(self, hunt_id: str, target: str, partition: str) -> None:
        with write_txn(self.engine) as connection:
            connection.execute(t.baseline_window_cell.delete().where(
                t.baseline_window_cell.c.hunt_id == hunt_id,
                t.baseline_window_cell.c.target == target,
                t.baseline_window_cell.c.partition == partition,
            ))

    def clear_baseline_history_stage(self, hunt_id: str) -> None:
        """Forget every staged history hour of a hunt; a fill re-reads hours that hold no segment."""
        with write_txn(self.engine) as connection:
            connection.execute(t.baseline_history_cell.delete().where(t.baseline_history_cell.c.hunt_id == hunt_id))

    def stage_baseline_history_cell(self, hunt_id: str, cell: dict, counts: Iterable[dict],
                                    scope_hours: Iterable[dict], pendings: Iterable[dict]) -> None:
        """Replace one history hour's compact counts, scope hours and Pendings, atomically."""
        start = _utc(cell["start"], "history start")
        key = {"hunt_id": hunt_id, "target": cell["target"], "spec_id": cell["spec_id"], "start": start}

        def rows(kind: str, items: Iterable[dict]):
            for ordinal, item in enumerate(items):
                yield {**key, "kind": kind, "ordinal": ordinal,
                       "body": json.loads(json.dumps(item, default=_jsonable))}

        with write_txn(self.engine) as connection:
            table = t.baseline_history_cell.c
            connection.execute(t.baseline_history_cell.delete().where(
                table.hunt_id == hunt_id, table.target == cell["target"], table.spec_id == cell["spec_id"],
                table.start == start,
            ))
            connection.execute(t.baseline_history_cell.insert().values(
                **key, end=_utc(cell["end"], "history end"), events_total=int(cell["events_total"]),
            ))
            for kind, items in (("count", counts), ("scope_hour", scope_hours), ("pending", pendings)):
                batch: list[dict] = []
                for row in rows(kind, items):
                    batch.append(row)
                    if len(batch) >= 5_000:
                        connection.execute(t.baseline_history_row.insert(), batch)
                        batch = []
                if batch:
                    connection.execute(t.baseline_history_row.insert(), batch)

    def baseline_history_cells(self, hunt_id: str) -> list[dict]:
        """A hunt's staged history hours, oldest first; at most one per target hour and deferring spec."""
        table = t.baseline_history_cell.c
        with self.engine.connect() as connection:
            rows = connection.execute(select(t.baseline_history_cell).where(table.hunt_id == hunt_id).order_by(
                table.target, table.spec_id, table.start,
            )).mappings()
            return [_with_utc(row, ("start", "end")) for row in rows]

    def baseline_history_rows(self, hunt_id: str, target: str, spec_id: str, start: datetime,
                              kind: str) -> Iterator[dict]:
        """One staged hour's rows of one kind, in staging order, keyset-paged."""
        table = t.baseline_history_row.c
        start = _utc(start, "history start")
        after = -1
        while True:
            with self.engine.connect() as connection:
                page = connection.execute(select(table.ordinal, table.body).where(
                    table.hunt_id == hunt_id, table.target == target, table.spec_id == spec_id,
                    table.start == start, table.kind == kind, table.ordinal > after,
                ).order_by(table.ordinal).limit(5_000)).all()
            if not page:
                return
            for ordinal, body in page:
                yield dict(body)
            after = page[-1][0]

    def drop_baseline_history_cell(self, hunt_id: str, target: str, spec_id: str, start: datetime) -> None:
        table = t.baseline_history_cell.c
        with write_txn(self.engine) as connection:
            connection.execute(t.baseline_history_cell.delete().where(
                table.hunt_id == hunt_id, table.target == target, table.spec_id == spec_id,
                table.start == _utc(start, "history start"),
            ))

    def save_baseline_window_cell(self, hunt_id: str, cell: dict, observations: Iterable[dict], *,
                                  counts: Iterable[dict] = (),
                                  scope_hours: Iterable[dict] = ()) -> bool:
        """Atomically add one cell's observations once and close its ordinary rule cell.

        The terminal rule cell is the idempotency marker. A killed or restarted sweep can process its direct
        rules again while baseline counting skips cells already committed; counts therefore never double.
        """
        rows = (_baseline_observation_row(row) for row in observations)
        table = t.baseline_observation.c
        stmt = insert(t.baseline_observation)
        earlier = or_(
            stmt.excluded.first_ts < table.first_ts,
            and_(stmt.excluded.first_ts == table.first_ts,
                 stmt.excluded.first_event_id < table.first_event_id),
        )
        stmt = stmt.on_conflict_do_update(
            index_elements=list(_OBSERVATION_KEY),
            set_={
                "window_count": table.window_count + stmt.excluded.window_count,
                "first_ts": func.min(table.first_ts, stmt.excluded.first_ts),
                "last_ts": func.max(table.last_ts, stmt.excluded.last_ts),
                "first_event_id": case((earlier, stmt.excluded.first_event_id), else_=table.first_event_id),
                "first_event_refs": case(
                    (earlier, stmt.excluded.first_event_refs), else_=table.first_event_refs,
                ),
                # A window merge precedes judgement. Keep all history fields and verdicts at their pending values.
                "history_count": None,
                "history_decayed": None,
                "peer_scopes_with_key": None,
                "peer_scopes": None,
                "threshold": None,
                "mean": None,
                "sigma": None,
                "n_hours": None,
                "verdict": "unresolved",
                "reason": "baseline judgement pending",
            },
        )
        rule = t.rule_run.c
        with write_txn(self.engine) as connection:
            current = connection.execute(select(rule.state).where(
                rule.hunt_id == hunt_id,
                rule.rule_id == cell["rule_id"],
                rule.rule_version == cell["version"],
                rule.target == cell["target"],
                rule.partition == cell["partition"],
            )).scalar_one_or_none()
            if current is not None and current not in {"planned", "split"}:
                return False
            self._replace_baseline_window_counter_rows(
                connection, hunt_id, cell["rule_id"], cell["version"], cell["target"],
                cell["partition"], counts, scope_hours,
            )
            for chunk in _chunks(rows, BASELINE_CHUNK):
                connection.execute(stmt, chunk)
            connection.execute(_RULE_CELL_UPSERT, [{
                "hunt_id": hunt_id,
                "rule_id": cell["rule_id"],
                "rule_version": cell["version"],
                "target": cell["target"],
                "partition": cell["partition"],
                "state": cell["state"],
                "matched": cell["matched"],
                "evaluated": cell["evaluated"],
                "detail": cell.get("detail") or {},
            }])
        return True

    def _replace_baseline_window_counter_rows(self, connection, hunt_id: str, spec_id: str,
                                              spec_version: str, target: str, partition: str,
                                              counts: Iterable[dict], scope_hours: Iterable[dict]) -> None:
        """Replace one cell's segment material inside its caller's transaction."""
        for table in (t.baseline_window_count, t.baseline_window_scope_hour):
            connection.execute(table.delete().where(
                table.c.hunt_id == hunt_id, table.c.spec_id == spec_id,
                table.c.target == target, table.c.partition == partition,
            ))
        count_rows = (
                {
                    "hunt_id": hunt_id,
                    "spec_id": spec_id,
                    "spec_version": spec_version,
                    "target": target,
                    "partition": partition,
                    "ordinal": ordinal,
                    "scope_kind": row["scope_kind"],
                    "scope": row["scope"],
                    "key_id": row["key_id"],
                    "key_digest": row["key_digest"],
                    "key": row["key"],
                    "bucket": _utc(row["bucket"], "window count bucket"),
                    "count": int(row["count"]),
                    "first_ts": _utc(row["first_ts"], "window count first_ts"),
                    "last_ts": _utc(row["last_ts"], "window count last_ts"),
                }
                for ordinal, row in enumerate(counts)
            )
        for chunk in _chunks(count_rows, BASELINE_CHUNK):
            connection.execute(t.baseline_window_count.insert(), chunk)
        hour_rows = (
                {
                    "hunt_id": hunt_id,
                    "spec_id": spec_id,
                    "spec_version": spec_version,
                    "target": target,
                    "partition": partition,
                    "ordinal": ordinal,
                    "scope_kind": row["scope_kind"],
                    "scope": row["scope"],
                    "hour": _utc(row["hour"], "window scope hour"),
                    "events": int(row["events"]),
                }
                for ordinal, row in enumerate(scope_hours)
            )
        for chunk in _chunks(hour_rows, BASELINE_CHUNK):
            connection.execute(t.baseline_window_scope_hour.insert(), chunk)

    def baseline_window_counts(self, hunt_id: str, spec_id: str, target: str, *,
                               partition: str | None = None) -> list[dict]:
        """Compact count rows retained from complete sweep cells, in deterministic cell order."""
        table = t.baseline_window_count.c
        with self.engine.connect() as connection:
            query = select(t.baseline_window_count).where(
                table.hunt_id == hunt_id,
                table.spec_id == spec_id,
                table.target == target,
            )
            if partition is not None:
                query = query.where(table.partition == partition)
            rows = connection.execute(query.order_by(table.partition, table.ordinal)).mappings()
            return [_with_utc(row, ("bucket", "first_ts", "last_ts")) for row in rows]

    def baseline_window_scope_hours(self, hunt_id: str, spec_id: str, target: str, *,
                                    partition: str | None = None) -> list[dict]:
        """Compact scope-hour rows retained from complete sweep cells."""
        table = t.baseline_window_scope_hour.c
        with self.engine.connect() as connection:
            query = select(t.baseline_window_scope_hour).where(
                table.hunt_id == hunt_id,
                table.spec_id == spec_id,
                table.target == target,
            )
            if partition is not None:
                query = query.where(table.partition == partition)
            rows = connection.execute(query.order_by(table.partition, table.ordinal)).mappings()
            return [_with_utc(row, ("hour",)) for row in rows]

    def baseline_window_merged_counts(self, hunt_id: str, spec_id: str, target: str, *,
                                      page_size: int = BASELINE_PAGE) -> Iterator[dict]:
        """Merge a hunt's per-cell count rows in bounded pages, ordered like segment count rows."""
        if page_size < 1:
            raise ValueError("page size must be positive")
        table = t.baseline_window_count.c
        order = (table.scope, table.key_digest, table.bucket)
        after = None
        while True:
            query = (select(
                table.scope_kind, table.scope, table.key_id, table.key_digest, table.key, table.bucket,
                func.sum(table.count).label("count"), func.min(table.first_ts).label("first_ts"),
                func.max(table.last_ts).label("last_ts"),
            ).where(
                table.hunt_id == hunt_id, table.spec_id == spec_id, table.target == target,
            ).group_by(
                table.scope_kind, table.scope, table.key_id, table.key_digest, table.key, table.bucket,
            ))
            if after is not None:
                query = query.having(tuple_(*order) > tuple_(*after))
            query = query.order_by(*order).limit(page_size)
            with self.engine.connect() as connection:
                page = [_with_utc(row, ("bucket", "first_ts", "last_ts"))
                        for row in connection.execute(query).mappings()]
            yield from page
            if len(page) < page_size:
                return
            after = [page[-1]["scope"], page[-1]["key_digest"], page[-1]["bucket"]]

    def baseline_window_merged_scope_hours(self, hunt_id: str, spec_id: str, target: str, *,
                                           page_size: int = BASELINE_PAGE) -> Iterator[dict]:
        """Merge a hunt's per-cell scope-hour rows without collecting the hunt in memory."""
        if page_size < 1:
            raise ValueError("page size must be positive")
        table = t.baseline_window_scope_hour.c
        order = (table.scope, table.hour)
        after = None
        while True:
            query = (select(
                table.scope_kind, table.scope, table.hour, func.sum(table.events).label("events"),
            ).where(
                table.hunt_id == hunt_id, table.spec_id == spec_id, table.target == target,
            ).group_by(table.scope_kind, table.scope, table.hour))
            if after is not None:
                query = query.having(tuple_(*order) > tuple_(*after))
            query = query.order_by(*order).limit(page_size)
            with self.engine.connect() as connection:
                page = [_with_utc(row, ("hour",)) for row in connection.execute(query).mappings()]
            yield from page
            if len(page) < page_size:
                return
            after = [page[-1]["scope"], page[-1]["hour"]]

    def replace_baseline_hunt_exclusions(self, hunt_id: str, *, site: str,
                                         start: datetime, end: datetime,
                                         exclusions: dict[tuple[str, str], set[str]],
                                         spec_versions: dict[str, tuple[str, str]]) -> None:
        """Replace one hunt's cited-key ledger atomically; a resumed finish is idempotent."""
        start, end = _utc(start, "exclusion start"), _utc(end, "exclusion end")
        if start >= end:
            raise ValueError("baseline exclusion start before end is required")
        rows = (
            {
                "hunt_id": hunt_id, "site": site, "target": target, "spec_id": spec_id,
                "spec_version": spec_versions[spec_id][0], "key_version": spec_versions[spec_id][1],
                "key_digest": key_digest, "start": start, "end": end,
            }
            for (target, spec_id), keys in sorted(exclusions.items())
            for key_digest in sorted(keys)
        )
        with write_txn(self.engine) as connection:
            connection.execute(t.baseline_hunt_exclusion.delete().where(
                t.baseline_hunt_exclusion.c.hunt_id == hunt_id,
            ))
            for chunk in _chunks(rows, BASELINE_CHUNK):
                connection.execute(t.baseline_hunt_exclusion.insert(), chunk)

    def baseline_exclusion_keys(self, *, site: str, target: str, spec_id: str,
                                spec_version: str, key_version: str,
                                start: datetime, end: datetime) -> list[str]:
        """Distinct cited keys from every hunt whose half-open window overlaps the span."""
        start, end = _utc(start, "exclusion query start"), _utc(end, "exclusion query end")
        table = t.baseline_hunt_exclusion.c
        query = (select(table.key_digest).where(
            table.site == site, table.target == target, table.spec_id == spec_id,
            table.spec_version == spec_version, table.key_version == key_version,
            table.start < end, table.end > start,
        ).distinct().order_by(table.key_digest))
        with self.engine.connect() as connection:
            return list(connection.execute(query).scalars())

    @staticmethod
    def _baseline_exclusion_digest(keys: list[str]) -> str:
        if not keys:
            return "none"
        return hashlib.sha256(json.dumps(
            keys, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ).encode()).hexdigest()

    def stale_baseline_segments_for_exclusions(self, *, site: str,
                                               start: datetime, end: datetime) -> int:
        """Mark active overlapping segments stale when the durable cited-key union changed."""
        start, end = _utc(start, "staleness start"), _utc(end, "staleness end")
        segment, exclusion = t.baseline_segment.c, t.baseline_hunt_exclusion.c
        with write_txn(self.engine) as connection:
            segments = list(connection.execute(select(t.baseline_segment).where(
                segment.site == site, segment.status == "active",
                segment.start < end, segment.end > start,
            )).mappings())
            stale = 0
            for row in segments:
                keys = list(connection.execute(select(exclusion.key_digest).where(
                    exclusion.site == site, exclusion.target == row["target"],
                    exclusion.spec_id == row["spec_id"], exclusion.start < row["end"],
                    exclusion.spec_version == row["spec_version"],
                    exclusion.key_version == row["key_version"],
                    exclusion.end > row["start"],
                ).distinct().order_by(exclusion.key_digest)).scalars())
                if (keys != sorted(row["excluded_keys"] or [])
                        or self._baseline_exclusion_digest(keys) != row["exclusion_digest"]):
                    stale += connection.execute(t.baseline_segment.update().where(
                        segment.id == row["id"], segment.status == "active",
                    ).values(status="stale")).rowcount
            return stale

    def baseline_observations(self, hunt_id: str, *, page_size: int = BASELINE_PAGE) -> Iterator[dict]:
        """A hunt's observations in key order (spec, version, scope, key digest), paged."""
        return self._keyset(t.baseline_observation, [t.baseline_observation.c.hunt_id == hunt_id],
                            ("spec_id", "spec_version", "scope", "key_digest"), ("first_ts", "last_ts"),
                            page_size)

    def baseline_observations_for_spec(self, hunt_id: str, spec_id: str, spec_version: str, *,
                                       page_size: int = BASELINE_PAGE) -> Iterator[dict]:
        """One spec's observations in scope/key order, keyset-paged for streaming judgement."""
        return self._keyset(
            t.baseline_observation,
            [t.baseline_observation.c.hunt_id == hunt_id,
             t.baseline_observation.c.spec_id == spec_id,
             t.baseline_observation.c.spec_version == spec_version],
            ("scope", "key_digest"), ("first_ts", "last_ts"), page_size,
        )

    def baseline_observation_verdict_counts(self, hunt_id: str) -> dict[str, dict[str, int]]:
        """Bounded report aggregate: verdict counts per spec, independent of observation volume."""
        query = (select(t.baseline_observation.c.spec_id, t.baseline_observation.c.verdict, func.count())
                 .where(t.baseline_observation.c.hunt_id == hunt_id)
                 .group_by(t.baseline_observation.c.spec_id, t.baseline_observation.c.verdict)
                 .order_by(t.baseline_observation.c.spec_id, t.baseline_observation.c.verdict))
        out: dict[str, dict[str, int]] = {}
        with self.engine.connect() as connection:
            for spec_id, verdict, count in connection.execute(query):
                out.setdefault(str(spec_id), {})[str(verdict)] = int(count)
        return out

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

    def rule_cells(self, hunt_id: str, rule_ids: set[str] | None = None,
                   *, rule_id: str | None = None, max_id: int | None = None) -> list[dict]:
        if rule_ids is not None and rule_id is not None:
            raise ValueError("give rule_ids or rule_id, not both")
        if rule_id is not None:
            rule_ids = {rule_id}
        query = select(t.rule_run).where(t.rule_run.c.hunt_id == hunt_id)
        if rule_ids is not None:
            if not rule_ids:
                return []
            query = query.where(t.rule_run.c.rule_id.in_(sorted(rule_ids)))
        if max_id is not None:
            query = query.where(t.rule_run.c.id <= max_id)
        with self.engine.connect() as c:
            return [dict(r) for r in c.execute(query).mappings()]

    def rule_presence_counts(self, hunt_id: str,
                             keys: set[tuple[str, str]]) -> dict[tuple[str, str], int]:
        """Count all distinct rules at selected coverage cells without loading their rows."""
        if not keys:
            return {}
        out: dict[tuple[str, str], int] = {}
        ordered = sorted(keys)
        with self.engine.connect() as connection:
            for offset in range(0, len(ordered), 250):
                batch = ordered[offset:offset + 250]
                query = (select(
                    t.rule_run.c.target, t.rule_run.c.partition,
                    func.count(t.rule_run.c.rule_id.distinct()),
                ).where(
                    t.rule_run.c.hunt_id == hunt_id,
                    tuple_(t.rule_run.c.target, t.rule_run.c.partition).in_(batch),
                ).group_by(t.rule_run.c.target, t.rule_run.c.partition))
                out.update({(str(target), str(partition)): int(count)
                            for target, partition, count in connection.execute(query)})
        return out

    def rule_cell_fingerprint(self, hunt_id: str) -> str:
        query = (select(
            t.rule_run.c.id, t.rule_run.c.rule_id, t.rule_run.c.rule_version,
            t.rule_run.c.target, t.rule_run.c.partition, t.rule_run.c.state,
            t.rule_run.c.matched, t.rule_run.c.evaluated, t.rule_run.c.detail,
        ).where(t.rule_run.c.hunt_id == hunt_id).order_by(t.rule_run.c.id))
        fingerprint = hashlib.sha256()
        with self.engine.connect() as connection:
            for row in connection.execution_options(yield_per=500).execute(query).mappings():
                fingerprint.update(json.dumps(dict(row), sort_keys=True, default=str,
                                              separators=(",", ":")).encode())
                fingerprint.update(b"\n")
        return fingerprint.hexdigest()

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
