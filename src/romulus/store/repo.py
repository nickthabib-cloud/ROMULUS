"""Idempotent repository operations over the single SQLite authority."""
from __future__ import annotations

import hashlib
from collections.abc import Iterable
from typing import Any

from sqlalchemy import Engine, func, select
from sqlalchemy.dialects.sqlite import insert

from romulus.store import schema as t
from romulus.store.db import utcnow, write_txn


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

    VALID = {"planned": {"running", "canceled"}, "running": {"paused", "completed_within_scope", "partial", "failed",
                                                             "canceled"},
             "paused": {"running", "canceled", "partial"}, "partial": {"running"}, "failed": {"running"}}

    def set_hunt_state(self, hunt_id: str, state: str, actor: str = "system", **extra):
        with write_txn(self.engine) as c:
            cur = c.execute(select(t.hunt.c.execution_state).where(t.hunt.c.id == hunt_id)).scalar_one()
            if state != cur and state not in self.VALID.get(cur, set()):
                raise ValueError(f"invalid hunt transition {cur} -> {state}")
            vals: dict[str, Any] = {"execution_state": state, **extra}
            if state == "running" and cur == "planned":
                vals["started_at"] = utcnow()
            if state in ("completed_within_scope", "partial", "failed", "canceled"):
                vals["ended_at"] = utcnow()
            c.execute(t.hunt.update().where(t.hunt.c.id == hunt_id).values(**vals))
            c.execute(t.audit_event.insert().values(at=utcnow(), actor=actor, action=f"hunt.{state}", hunt_id=hunt_id,
                                                    detail={k: str(v) for k, v in extra.items()}))

    def save_profile(self, hunt_id: str, profile: dict):
        with write_txn(self.engine) as c:
            _upsert_ignore(c, t.source_profile, [{"id": f"{hunt_id}:{profile['id']}", "hunt_id": hunt_id,
                                                  "target": profile["target"], "kind": profile["kind"],
                                                  "profile": profile, "captured_at": utcnow()}], ["id"])

    # ---- tasks ------------------------------------------------------------------------------
    def upsert_task(self, task_id: str, hunt_id: str, kind: str, owner: str, intent: dict, fp: str, priority=0.0):
        with write_txn(self.engine) as c:
            _upsert_ignore(c, t.task, [{"id": task_id, "hunt_id": hunt_id, "kind": kind, "owner": owner,
                                        "intent": intent, "fingerprint": fp, "state": "planned",
                                        "priority": priority, "attempts": 0, "created_at": utcnow(),
                                        "updated_at": utcnow()}], ["id"])

    def task_state(self, task_id: str) -> str | None:
        with self.engine.connect() as c:
            return c.execute(select(t.task.c.state).where(t.task.c.id == task_id)).scalar()

    def update_task(self, task_id: str, state: str, outcome: dict | None = None, error: str | None = None,
                    attempt: bool = False):
        with write_txn(self.engine) as c:
            vals: dict[str, Any] = {"state": state, "updated_at": utcnow()}
            if outcome is not None:
                vals["outcome"] = outcome
            if error is not None:
                vals["error"] = error
            if attempt:
                vals["attempts"] = t.task.c.attempts + 1
            c.execute(t.task.update().where(t.task.c.id == task_id).values(**vals))

    def tasks(self, hunt_id: str) -> list[dict]:
        with self.engine.connect() as c:
            return [dict(r) for r in c.execute(select(t.task).where(t.task.c.hunt_id == hunt_id)
                                               .order_by(t.task.c.created_at)).mappings()]

    # ---- evidence ---------------------------------------------------------------------------
    def save_evidence(self, hunt_id: str, events: Iterable, raw_sources: dict[str, dict], task_id: str | None):
        """Persist typed events plus retained raw copies for every record they cite."""
        events = list(events)
        with write_txn(self.engine) as c:
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
    def save_candidate(self, row: dict) -> bool:
        """Insert once; returns True if new. Re-evaluation of the same evidence is idempotent."""
        with write_txn(self.engine) as c:
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

    def add_disposition(self, cid: str, actor: str, status: str, note: str | None):
        with write_txn(self.engine) as c:
            c.execute(t.disposition_event.insert().values(candidate_id=cid, actor=actor, at=utcnow(), status=status,
                                                          note=note))

    def dispositions(self, cid: str) -> list[dict]:
        with self.engine.connect() as c:
            return [dict(r) for r in c.execute(select(t.disposition_event).where(
                t.disposition_event.c.candidate_id == cid).order_by(t.disposition_event.c.id)).mappings()]

    # ---- coverage ---------------------------------------------------------------------------
    def set_rule_cell(self, hunt_id: str, rule_id: str, version: str, target: str, partition: str, state: str,
                      matched: int, evaluated: int, detail: dict | None = None):
        with write_txn(self.engine) as c:
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

    def audit(self, actor: str, action: str, hunt_id: str | None = None, detail: dict | None = None):
        with write_txn(self.engine) as c:
            c.execute(t.audit_event.insert().values(at=utcnow(), actor=actor, action=action, hunt_id=hunt_id,
                                                    detail=detail or {}))
