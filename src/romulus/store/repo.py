"""Idempotent repository operations over the single SQLite authority."""
from __future__ import annotations

import hashlib
import uuid
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from typing import Any, ClassVar

from sqlalchemy import Engine, and_, func, or_, select, true
from sqlalchemy.dialects.sqlite import insert

from romulus.store import schema as t
from romulus.store.db import utcnow, write_txn

# Lanes an analyst may join with an asserted link (the report's reportable lanes).
REPORTABLE_LANES = ("urgent", "high", "lead")


def _upsert_ignore(conn, table, rows: list[dict], keys: list[str]):
    if not rows:
        return
    stmt = insert(table).values(rows).on_conflict_do_nothing(index_elements=keys)
    conn.execute(stmt)


def raw_id(target: str, native_id: str) -> str:
    return hashlib.sha256(f"{target}/{native_id}".encode()).hexdigest()[:32]


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
            rm("agent_aliases", t.agent_alias.delete().where(t.agent_alias.c.hunt_id == hunt_id))
            rm("expansion_links", t.expansion_link.delete().where(t.expansion_link.c.hunt_id == hunt_id))
            rm("expansion_anchors", t.expansion_anchor.delete().where(t.expansion_anchor.c.hunt_id == hunt_id))
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
            raw_rows, ev_rows, ent_rows, link_rows = [], [], {}, []
            for e in events:
                for r in e.raw:
                    src = raw_sources.get(r.key)
                    if src is not None:
                        raw_rows.append({"id": raw_id(r.target, r.native_id), "target": r.target,
                                         "native_id": r.native_id, "digest": r.digest, "source": src,
                                         "first_task_id": task_id, "retrieved_at": utcnow()})
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
            _upsert_ignore(c, t.entity, list(ent_rows.values()), ["id"])
            _upsert_ignore(c, t.event_entity, link_rows, ["event_id", "entity_id", "role"])

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

    def agent_alias_hunts(self, alias: str) -> list[str]:
        query = (select(t.agent_alias.c.hunt_id).where(t.agent_alias.c.alias == alias)
                 .order_by(t.agent_alias.c.hunt_id))
        with self.engine.connect() as c:
            return list(c.execute(query).scalars())

    def agent_alias_target_hunts(self, kind: str, target_id: str) -> list[str]:
        table = {"F": t.candidate, "E": t.typed_event, "N": t.entity, "L": t.expansion_link}.get(kind)
        if table is None:
            return []
        with self.engine.connect() as c:
            owners = set(c.execute(select(table.c.hunt_id).where(table.c.id == target_id)).scalars())
            # Typed events can be retained once and cited by more than one hunt. Those citing hunts
            # own an E alias even when the physical row remains attributed to its first hunt.
            if kind == "E":
                for hunt_id, event_ids in c.execute(select(t.candidate.c.hunt_id, t.candidate.c.event_ids)):
                    if target_id in (event_ids or []):
                        owners.add(hunt_id)
                for hunt_id, event_ids, evidence_ids in c.execute(select(
                        t.expansion_link.c.hunt_id, t.expansion_link.c.event_ids,
                        t.expansion_link.c.evidence_ids)):
                    if target_id in [*(event_ids or []), *(evidence_ids or [])]:
                        owners.add(hunt_id)
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
        with write_txn(self.engine) as c:
            self._fence_lease(c, hunt_id, owner_token)
            stmt = insert(t.rule_run).values(hunt_id=hunt_id, rule_id=rule_id, rule_version=version, target=target,
                                             partition=partition, state=state, matched=matched, evaluated=evaluated,
                                             detail=detail or {})
            stmt = stmt.on_conflict_do_update(index_elements=["hunt_id", "rule_id", "rule_version", "target",
                                                              "partition"],
                                              set_={"state": state, "matched": matched, "evaluated": evaluated,
                                                    "detail": detail or {}})
            c.execute(stmt)

    def rule_cells(self, hunt_id: str) -> list[dict]:
        with self.engine.connect() as c:
            return [dict(r) for r in c.execute(select(t.rule_run).where(t.rule_run.c.hunt_id == hunt_id)).mappings()]

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
