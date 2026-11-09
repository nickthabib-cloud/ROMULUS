"""Fenced cleanup of interrupted investigation before an assessment-only run."""
from sqlalchemy import func, select

from romulus.store import schema as t
from romulus.store.db import utcnow, write_txn


def recover_for_reassessment(repo, hunt_id: str, owner_token: str) -> bool:
    """Close stale sessions atomically after the caller acquires the expired lease."""
    if not owner_token:
        raise ValueError("reassessment recovery requires an agent lease")
    now = utcnow()
    with write_txn(repo.engine) as connection:
        repo._fence_agent_lease(connection, hunt_id, owner_token)
        state = connection.execute(select(t.agent_run.c.state).where(
            t.agent_run.c.hunt_id == hunt_id,
        )).scalar_one()
        if state != "running":
            return False
        running = (t.agent_session.c.hunt_id == hunt_id, t.agent_session.c.state == "running")
        count = connection.execute(select(func.count()).select_from(t.agent_session).where(*running)).scalar_one()
        ids = list(connection.execute(select(t.agent_session.c.id).where(*running).order_by(
            t.agent_session.c.id,
        ).limit(100)).scalars())
        connection.execute(t.agent_session.update().where(*running).values(
            state="interrupted", ended_at=now,
            summary="Interrupted investigation recovered before reassessment.",
        ))
        connection.execute(t.agent_run.update().where(t.agent_run.c.hunt_id == hunt_id).values(
            state="partial", reason="interrupted_by_reassessment", ended_at=now, updated_at=now,
        ))
        connection.execute(t.audit_event.insert().values(
            at=now, actor="system", action="agent.recovered_for_reassessment", hunt_id=hunt_id,
            detail={"session_ids": ids, "session_count": count},
        ))
    return True
