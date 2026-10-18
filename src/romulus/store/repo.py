"""Idempotent repository operations over the single SQLite authority."""
from __future__ import annotations

import hashlib
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from typing import Any, ClassVar

from sqlalchemy import Engine, and_, func, or_, select
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

    def claim_hunt(self, hunt_id: str, lease_seconds: int, resume: bool = False,
                   now: datetime | None = None) -> dict:
        """Claim a planned hunt or safely reclaim a resumable hunt."""
        now = now or utcnow()
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

    def heartbeat_hunt(self, hunt_id: str, lease_seconds: int, now: datetime | None = None) -> dict:
        now = now or utcnow()
        with write_txn(self.engine) as c:
            state = c.execute(select(t.hunt.c.execution_state).where(t.hunt.c.id == hunt_id)).scalar_one()
            if state != "running":
                raise RuntimeError(f"hunt {hunt_id} is not running")
            c.execute(t.hunt.update().where(t.hunt.c.id == hunt_id).values(
                heartbeat_at=now, lease_until=now + timedelta(seconds=lease_seconds),
            ))
            row = c.execute(select(t.hunt).where(t.hunt.c.id == hunt_id)).mappings().one()
            return dict(row)

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
                vals["lease_until"] = None
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

    TASK_STATES: ClassVar = {
        "planned", "queued", "leased", "executed", "ingested", "evaluated", "failed", "partial",
        "budget_limited", "unsupported", "not_applicable", "canceled", "split",
    }

    def update_task(self, task_id: str, state: str, outcome: dict | None = None, error: str | None = None,
                    attempt: bool = False):
        if state not in self.TASK_STATES:
            raise ValueError(f"unknown task state {state}")
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

    # ---- investigator state ----------------------------------------------------------------
    def create_case(self, row: dict) -> bool:
        now = utcnow()
        values = {
            "status": "open", "steps_used": 0, "hypotheses": [],
            "created_at": now, "updated_at": now, **row,
        }
        with write_txn(self.engine) as c:
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

    def update_case(self, case_id: str, **values) -> None:
        allowed = {"title", "status", "priority", "entities", "hypotheses", "steps_used", "step_budget", "summary"}
        unknown = set(values) - allowed
        if unknown:
            raise ValueError(f"unknown case fields: {sorted(unknown)}")
        with write_txn(self.engine) as c:
            c.execute(t.case.update().where(t.case.c.id == case_id).values(**values, updated_at=utcnow()))

    def append_case_step(self, case_id: str, n: int, decision: dict, accepted: bool,
                         rejection: str | None = None, model_call_id: str | None = None,
                         task_id: str | None = None, result_digest: dict | None = None) -> int:
        values = {
            "case_id": case_id, "n": n, "decision": decision, "accepted": int(accepted),
            "rejection": rejection, "model_call_id": model_call_id, "task_id": task_id,
            "result_digest": result_digest, "at": utcnow(),
        }
        with write_txn(self.engine) as c:
            c.execute(insert(t.case_step).values(**values).on_conflict_do_nothing(
                index_elements=["case_id", "n"],
            ))
            return c.execute(select(t.case_step.c.id).where(
                t.case_step.c.case_id == case_id, t.case_step.c.n == n,
            )).scalar_one()

    def update_case_step(self, case_id: str, n: int, **values) -> None:
        allowed = {"model_call_id", "decision", "accepted", "rejection", "task_id", "result_digest"}
        unknown = set(values) - allowed
        if unknown:
            raise ValueError(f"unknown case step fields: {sorted(unknown)}")
        if "accepted" in values:
            values["accepted"] = int(values["accepted"])
        with write_txn(self.engine) as c:
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

    def save_model_call(self, row: dict) -> bool:
        values = {"at": utcnow(), **row}
        with write_txn(self.engine) as c:
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
