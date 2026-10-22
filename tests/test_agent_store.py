"""Durable investigator state, idempotent steps, and hunt lease recovery."""
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from romulus.evidence.typed import RawRef, TypedEvent, fv
from romulus.store import schema as tables
from romulus.store.db import make_engine, migrate
from romulus.store.repo import Repo

T = datetime(2024, 11, 18, 14, 0, tzinfo=UTC)


def _repo() -> Repo:
    engine = make_engine(":memory:")
    migrate(engine)
    repo = Repo(engine)
    repo.create_hunt("h1", {"budgets": {}}, "digest", "test")
    return repo


def _case_row():
    return {
        "id": "case-1", "hunt_id": "h1", "seed_candidate_id": "cand-1", "title": "seed",
        "priority": 50.0, "entities": [["host", "video", "host"]], "hypotheses": [], "step_budget": 8,
    }


def test_existing_evidence_skips_serialization_and_entity_extraction(monkeypatch):
    repo = _repo()
    for task_id in ("task-first", "task-repeat"):
        repo.upsert_task(
            task_id, "h1", "pivot", task_id, {"task": task_id}, task_id,
        )
    event = TypedEvent(
        id="event-existing", family="process_exec", ts=T, host="video",
        fields={"user.name": fv("alice", "raw:user.name")},
        raw=[RawRef(target="host-x", native_id="raw-1", digest="digest")],
        normalizer="test@1",
    )
    sources = {"host-x/raw-1": {"message": "retained"}}
    repo.save_evidence("h1", [event], sources, "task-first")

    def should_not_run(*_args, **_kwargs):
        raise AssertionError("existing evidence was rebuilt")

    monkeypatch.setattr(TypedEvent, "model_dump", should_not_run)
    monkeypatch.setattr(TypedEvent, "entities", should_not_run)
    repo.save_evidence("h1", [event], sources, "task-repeat")

    stored = repo.events_by_ids([event.id])
    raw = repo.raw_records(stored[0]["raw_ids"])
    with repo.engine.connect() as connection:
        links = connection.execute(select(tables.event_entity).where(
            tables.event_entity.c.event_id == event.id,
        )).mappings().all()
    assert stored[0]["event"]["fields"]["user.name"]["value"] == "alice"
    assert raw[0]["source"] == {"message": "retained"}
    assert raw[0]["first_task_id"] == "task-first"
    assert len(links) == 2


def test_active_lease_refuses_resume_and_expired_lease_is_reclaimed():
    repo = _repo()
    claimed = repo.claim_hunt("h1", lease_seconds=60, now=T)
    assert claimed["execution_state"] == "running"
    assert claimed["lease_until"].replace(tzinfo=UTC) == T + timedelta(seconds=60)

    with pytest.raises(RuntimeError, match="active lease"):
        repo.claim_hunt("h1", lease_seconds=60, resume=True, now=T + timedelta(seconds=59))

    reclaimed = repo.claim_hunt("h1", lease_seconds=60, resume=True, now=T + timedelta(seconds=61))
    assert reclaimed["lease_until"].replace(tzinfo=UTC) == T + timedelta(seconds=121)
    assert repo.latest_audit("h1", "hunt.resume_stale")["detail"]["previous_state"] == "running"


def test_displaced_worker_cannot_heartbeat_or_write_investigator_state():
    repo = _repo()
    first = repo.claim_hunt("h1", lease_seconds=60, now=T)
    second = repo.claim_hunt(
        "h1", lease_seconds=60, resume=True, now=T + timedelta(seconds=61),
    )

    assert first["lease_owner"] != second["lease_owner"]
    with pytest.raises(RuntimeError, match="lease ownership lost"):
        repo.heartbeat_hunt("h1", 60, owner_token=first["lease_owner"])
    with pytest.raises(RuntimeError, match="lease ownership lost"):
        repo.create_case(_case_row(), owner_token=first["lease_owner"])

    assert repo.create_case(_case_row(), owner_token=second["lease_owner"]) is True
    repo.append_case_step(
        "case-1", 0, {"action": "seed"}, True, owner_token=second["lease_owner"],
    )
    stale_writes = [
        lambda: repo.update_case("case-1", owner_token=first["lease_owner"], title="stale"),
        lambda: repo.append_case_step(
            "case-1", 1, {"action": "close"}, True, owner_token=first["lease_owner"],
        ),
        lambda: repo.update_case_step(
            "case-1", 0, owner_token=first["lease_owner"], rejection="stale",
        ),
        lambda: repo.save_model_call({
            "id": "stale-call", "hunt_id": "h1", "case_id": "case-1", "purpose": "triage",
            "model": "test", "options": {}, "prompt_digest": "p", "status": "ok",
        }, owner_token=first["lease_owner"]),
        lambda: repo.audit(
            "stale-worker", "hunt.agent_summary", "h1", {},
            owner_token=first["lease_owner"],
        ),
    ]
    for write in stale_writes:
        with pytest.raises(RuntimeError, match="lease ownership lost"):
            write()

    assert repo.case("case-1")["title"] == "seed"
    assert [step["n"] for step in repo.case_steps("case-1")] == [0]
    assert repo.model_calls(hunt_id="h1") == []


@pytest.mark.parametrize("state", ["partial", "failed"])
def test_partial_and_failed_hunts_can_transition_back_to_running(state):
    repo = _repo()
    repo.claim_hunt("h1", 60, now=T)
    repo.set_hunt_state("h1", state, stop_reason="interrupted")

    claimed = repo.claim_hunt("h1", 60, resume=True, now=T + timedelta(minutes=1))

    assert claimed["execution_state"] == "running"
    assert claimed["ended_at"] is None


def test_case_creation_and_steps_are_idempotent_and_pending_work_is_visible():
    repo = _repo()
    assert repo.create_case(_case_row()) is True
    assert repo.create_case(_case_row()) is False
    assert len(repo.cases("h1")) == 1

    sid = repo.append_case_step("case-1", 0, {"action": "seed", "seed_candidate_ids": ["cand-1"]}, True)
    assert repo.append_case_step("case-1", 0, {"action": "seed"}, True) == sid
    repo.append_case_step("case-1", 1, {"action": "pivot", "tool": "entity_timeline"}, True,
                          task_id="task-1")
    assert [s["n"] for s in repo.pending_case_steps("h1")] == [1]

    repo.update_case_step("case-1", 1, result_digest={"event_ids": ["e1"], "duration_ms": 25})
    assert repo.pending_case_steps("h1") == []
    assert repo.case_steps("case-1")[-1]["result_digest"]["event_ids"] == ["e1"]


def test_model_calls_are_ordered_and_elapsed_time_includes_pivots():
    repo = _repo()
    repo.create_case(_case_row())
    repo.append_case_step("case-1", 0, {"action": "seed"}, True,
                          result_digest={"duration_ms": 20})
    base = {
        "hunt_id": "h1", "case_id": "case-1", "purpose": "triage", "model": "test",
        "options": {}, "prompt_digest": "p", "status": "ok",
    }
    repo.save_model_call({**base, "id": "call-2", "duration_ms": 12, "at": T + timedelta(seconds=2)})
    repo.save_model_call({**base, "id": "call-1", "duration_ms": 8, "at": T + timedelta(seconds=1)})

    assert [c["id"] for c in repo.model_calls(case_id="case-1")] == ["call-1", "call-2"]
    assert repo.agent_elapsed_ms("h1") == 40


def test_seed_repartition_rolls_back_metadata_when_the_marker_cannot_be_written():
    repo = _repo()
    repo.create_case(_case_row())
    repo.append_case_step(
        "case-1", 0, {"action": "seed", "seed_candidate_ids": ["cand-1"]}, True,
    )

    with pytest.raises(IntegrityError):
        repo.repartition_case(
            "case-1", None,
            {"action": "seed_partition", "seed_candidate_ids": ["cand-1"]},
            priority=10.0, entities=[],
        )

    assert repo.case("case-1")["priority"] == 50.0
    assert len(repo.case_steps("case-1")) == 1


def test_terminal_state_clears_the_worker_lease():
    repo = _repo()
    repo.claim_hunt("h1", 60, now=T)
    repo.set_hunt_state("h1", "completed_within_scope")

    assert repo.get_hunt("h1")["lease_until"] is None
