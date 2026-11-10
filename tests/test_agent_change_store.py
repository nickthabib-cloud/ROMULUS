"""Transactional change delivery and citation indexes."""
from datetime import timedelta

import pytest
from alembic import command
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from romulus.store import schema as t
from romulus.store.db import make_engine
from romulus.store.repo import Repo
from tests.test_agent_store_r2 import NOW, _agent_rows, _candidate, _repo
from tests.test_local_content_migration import config


def _index(repo):
    with repo.engine.connect() as c:
        return set(c.execute(select(t.candidate_event.c.hunt_id, t.candidate_event.c.candidate_id,
                                    t.candidate_event.c.event_id)))


def _expected(repo):
    with repo.engine.connect() as c:
        return set(c.exec_driver_sql("SELECT c.hunt_id,c.id,j.value FROM candidate c,json_each(c.event_ids) j"))


def test_change_log_follows_mutations_and_index_all_candidate_writers():
    repo = _repo()
    _agent_rows(repo, "h1")
    initial = repo.agent_change_page("h1")
    assert {r["kind"] for r in initial} == {"run", "hypothesis", "session", "tool_call", "finding"}
    cursor = initial[-1]["seq"]
    repo.update_agent_session("h1-session", "h1", {"state": "interrupted", "tool_calls": 2, "ended_at": NOW})
    repo.save_agent_run({"hunt_id": "h1", "state": "partial"})
    with repo.engine.begin() as c:
        c.execute(t.agent_hypothesis.update().values(status="supported", confidence="high"))
        c.execute(t.agent_tool_call.update().values(status="refused"))
    for cid, write in (
        ("saved", lambda r: repo.save_candidate(r)),
        ("revised", lambda r: repo.revise_candidate(r, "test")),
        ("finalized", lambda r: repo.finalize_context_candidate(r, "new", {})),
        ("agent", lambda r: repo.save_candidate(r | {"provenance": "agent"})),
    ):
        write(_candidate(cid, events=["e1", "e1", "e2"]))
        assert _index(repo) == _expected(repo)
    repo.update_context_candidate("saved", {"event_ids": ["replacement"], "lane": "high"})
    repo.revise_candidate(_candidate("revised", events=["e3"]), "changed")
    repo.finalize_context_candidate(_candidate("finalized", events=[]) | {
        "source_anchor_id": None, "source_link_id": None}, "again", {})
    assert _index(repo) == _expected(repo)
    changes = repo.agent_change_page("h1", after_seq=cursor)
    assert {r["kind"] for r in changes} == {"run", "hypothesis", "session", "tool_call", "finding"}
    assert {r["row_id"] for r in changes if r["kind"] == "finding"} == {"saved", "revised", "finalized", "agent"}
    assert repo.agent_change_rows("h1", "session", ["h1-session"])["h1-session"]["tool_calls"] == 2
    assert repo.agent_change_rows("h1", "hypothesis", ["h1-hyp"])["h1-hyp"]["confidence"] == "high"
    assert repo.agent_change_rows("other", "finding", ["saved"]) == {}
    assert "event_ids" not in repo.agent_change_rows("h1", "finding", ["saved"])["saved"]
    with pytest.raises(ValueError):
        repo.agent_change_page("h1", limit=201)


def test_indexes_and_changes_rollback_with_source_write():
    repo = _repo()
    before = repo.agent_change_max_seq("h1")
    with pytest.raises(RuntimeError), repo.engine.begin() as c:
        c.execute(t.candidate.insert().values(**_candidate("abort", events=["e1"]), created_at=NOW))
        assert c.execute(select(t.candidate_event)).first()
        raise RuntimeError("abort")
    assert _index(repo) == set()
    assert repo.agent_change_max_seq("h1") == before
    repo.save_candidate(_candidate("kept", events=["e1"]))
    with repo.engine.begin() as c, pytest.raises(IntegrityError, match="append-only"):
        c.execute(t.agent_change.update().values(kind="run"))
    with repo.engine.begin() as c, pytest.raises(IntegrityError, match="append-only"):
        c.exec_driver_sql("INSERT OR REPLACE INTO agent_change SELECT * FROM agent_change LIMIT 1")


def test_usage_counts_all_calls_but_bounds_visible_groups_and_exact_text_estimate():
    repo = _repo()
    for i in range(205):
        repo.save_model_call({"id": f"call{i:04}", "hunt_id": "h1", "purpose": "investigate",
            "provider": "openai", "model": f"model{i:04}", "model_reported": f"answered{i:04}",
            "options": {}, "prompt_digest": "d", "status": "ok", "prompt_tokens_est": 11,
            "raw_response": "héllo\0world", "egress": "remote", "endpoint_host": "example.invalid",
            "cost_usd_est": 0.0, "duration_ms": 3})
    result = repo.agent_usage("h1", group_limit=50)
    assert result["calls"] == 205
    assert result["tokens"] == 205 * (11 + int(len("héllo\0world") / 3.2) + 8)
    assert result["model_ms"] == 615 and result["estimated"] is True
    assert len(result["remote_calls"]) == len(result["models_reported"]) == 50
    assert result["remote_calls_more"] == result["models_reported_more"] == 155


def test_live_agent_lease_and_reassessment_preflight_use_claim_rules(monkeypatch):
    repo = _repo()
    monkeypatch.setattr("romulus.store.repo.utcnow", lambda: NOW)
    assert repo.agent_reassessment_refusal("h1") is None
    repo.claim_agent_lease("h1", 6, now=NOW, owner_token="owner")
    assert repo.agent_lease_live("h1") is True
    assert "active" in repo.agent_reassessment_refusal("h1")
    monkeypatch.setattr("romulus.store.repo.utcnow", lambda: NOW + timedelta(seconds=7))
    assert repo.agent_lease_live("h1") is False
    assert repo.agent_reassessment_refusal("h1") is None
    with repo.engine.begin() as c:
        c.execute(t.hunt.update().values(execution_state="failed"))
    assert "after detection" in repo.agent_reassessment_refusal("h1")


@pytest.mark.parametrize("foreign_keys", [False, True])
def test_populated_upgrade_downgrade_reupgrade_and_delete(tmp_path, foreign_keys):
    engine = make_engine(tmp_path / "migration.sqlite")
    with engine.begin() as c:
        c.exec_driver_sql(f"PRAGMA foreign_keys={'ON' if foreign_keys else 'OFF'}")
        command.upgrade(config(c), "0035")
    repo = Repo(engine)
    for hunt in ("h1", "h2"):
        repo.create_hunt(hunt, {}, "d", "test")
        _agent_rows(repo, hunt)
    with engine.begin() as c:
        c.execute(t.candidate.insert(), [dict(_candidate(f"f{i:04}", events=["e1", str(i)]), created_at=NOW)
                                         for i in range(1005)])
    for target in ("0036", "0035", "0036"):
        with engine.begin() as c:
            (command.downgrade if target == "0035" else command.upgrade)(config(c), target)
            assert c.exec_driver_sql("PRAGMA foreign_key_check").all() == []
            assert c.exec_driver_sql("PRAGMA quick_check").scalar() == "ok"
        if target == "0036":
            assert _index(repo) == _expected(repo)
            assert repo.agent_change_max_seq("h1") > 1000
    repo.delete_hunt("h1", "test", now=NOW + timedelta(days=1))
    assert repo.agent_change_page("h1") == []
    assert repo.agent_change_page("h2")
    assert _index(repo) == _expected(repo)
    with engine.connect() as c:
        assert c.exec_driver_sql("PRAGMA foreign_key_check").all() == []
    engine.dispose()
