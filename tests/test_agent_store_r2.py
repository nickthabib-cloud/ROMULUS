"""Agent ownership, bounded reads, deletion and migration regressions."""
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Barrier

import pytest
from alembic import command
from sqlalchemy import event, select
from sqlalchemy.exc import IntegrityError

from romulus.agent.investigate import skip_agent_phase
from romulus.config import Settings
from romulus.store import schema as t
from romulus.store.db import maintenance_lease, make_engine, migrate
from romulus.store.repo import Repo
from tests.test_local_content_migration import config
from tests.test_report import _repo_with_finding

NOW = datetime(2030, 1, 1, tzinfo=UTC)
AGENT_TABLES = ("agent_tool_call", "agent_note", "agent_rule_request", "agent_link",
                "agent_hypothesis_cite", "agent_hypothesis_event", "agent_assessment",
                "agent_session", "agent_hypothesis", "agent_run")


def _detection_finished(repo, hunt_id="h1"):
    """The agent works only from a finished detection run."""
    repo.set_hunt_state(hunt_id, "running")
    repo.set_hunt_state(hunt_id, "completed_within_scope", detection_result="leads_only", stop_reason="scope")


def _repo():
    engine = make_engine(":memory:")
    migrate(engine)
    repo = Repo(engine)
    repo.create_hunt("h1", {}, "d", "test")
    repo.set_hunt_state("h1", "running")
    repo.set_hunt_state("h1", "completed_within_scope", detection_result="leads_only", stop_reason="scope")
    return repo


def _candidate(cid, hunt_id="h1", *, lane="lead", provenance="deterministic", events=()):
    return {"id": cid, "hunt_id": hunt_id, "rule_id": "test.rule", "rule_version": "1",
            "claim": "A retained finding", "claim_type": "observed_action", "event_ids": list(events),
            "context_event_ids": [], "predicate_fields": [], "entities": [], "ts": NOW,
            "severity": "high", "confidence": "high", "lane": lane, "priority": 1.0,
            "priority_reasons": [], "gate_results": {}, "benign_alternatives": [], "next_checks": [],
            "group_key": cid, "provenance": provenance}


def _agent_rows(repo, hunt_id):
    sid, hid = hunt_id + "-session", hunt_id + "-hyp"
    repo.save_agent_run({"hunt_id": hunt_id, "state": "completed"})
    repo.save_agent_hypothesis({"id": hid, "hunt_id": hunt_id, "statement": "Investigate retained evidence",
                                "techniques": [], "entity_ids": [], "status": "open", "confidence": "low",
                                "questions": [], "sessions_run": 1, "created_at": NOW, "updated_at": NOW})
    repo.save_agent_session({"id": sid, "hunt_id": hunt_id, "hypothesis_id": hid,
                             "purpose": "investigate", "state": "finished", "started_at": NOW})
    repo.save_model_call({"id": hunt_id + "-call", "hunt_id": hunt_id, "session_id": sid,
                          "purpose": "investigate", "model": "test", "options": {},
                          "prompt_digest": "d", "status": "ok"})
    with repo.engine.begin() as c:
        c.execute(t.agent_hypothesis_event.insert().values(id=hunt_id + "-event", hunt_id=hunt_id,
                  hypothesis_id=hid, session_id=sid, kind="opened", payload={}, created_at=NOW))
        c.execute(t.agent_hypothesis_cite.insert().values(hunt_id=hunt_id, hypothesis_id=hid,
                  role="support", target_kind="finding", target_id="f"))
    repo.save_agent_tool_call({"id": hunt_id + "-tool", "hunt_id": hunt_id, "session_id": sid,
                               "seq": 1, "name": "get_finding", "arguments": {}, "status": "ok",
                               "result_digest": "d", "model_call_id": hunt_id + "-call", "created_at": NOW})
    for name, values in (("agent_note", {"target_kind": "finding", "target_id": "f", "text": "Retained note"}),
                         ("agent_link", {"hypothesis_id": hid, "from_kind": "finding", "from_id": "f",
                          "to_kind": "finding", "to_id": "f2", "relation": "related", "rationale": "Test"}),
                         ("agent_rule_request", {"hypothesis_id": hid, "pattern_description": "Review pattern"})):
        repo.save_agent_output(name, {"id": hunt_id + name, "hunt_id": hunt_id, "session_id": sid,
                                     "cites": [], "created_at": NOW, **values})
    repo.save_agent_assessment({"id": hunt_id + "-assess", "hunt_id": hunt_id, "revision": 1,
                                "source": "agent", "model": {}, "body": {}, "checker": {}, "created_at": NOW})
    repo.save_candidate({**_candidate(hunt_id + "-finding", hunt_id, provenance="agent"),
                         "agent_hypothesis_id": hid})


def test_probe_delete_agent_off_hunt_removes_template_and_run():
    # Reproduces the supplied probe_delete.py against the real skip path.
    repo, _ = _repo_with_finding()
    skip_agent_phase(Settings(), repo, "h1", "not_requested")
    repo.delete_hunt("h1", "test")
    with repo.engine.connect() as c:
        assert c.exec_driver_sql("PRAGMA foreign_key_check").all() == []
        assert all(c.execute(select(getattr(t, name))).first() is None for name in AGENT_TABLES)


def test_delete_agent_history_child_first_and_preserves_other_hunt(tmp_path):
    engine = make_engine(tmp_path / "delete.sqlite")
    migrate(engine)
    repo = Repo(engine)
    for hunt_id in ("h1", "h2"):
        repo.create_hunt(hunt_id, {}, "d", "test")
        _agent_rows(repo, hunt_id)
    repo.delete_hunt("h1", "test")
    with engine.connect() as c:
        for name in AGENT_TABLES:
            table = getattr(t, name)
            assert c.execute(select(table).where(table.c.hunt_id == "h1")).first() is None
            assert c.execute(select(table).where(table.c.hunt_id == "h2")).first() is not None
        assert c.exec_driver_sql("PRAGMA foreign_key_check").all() == []
        with pytest.raises(IntegrityError, match="append-only"):
            c.exec_driver_sql("UPDATE agent_hypothesis_event SET payload='{}' WHERE hunt_id='h2'")


def test_agent_lease_is_independent_live_and_fences_expired_writers(monkeypatch):
    repo = _repo()
    monkeypatch.setattr("romulus.store.repo.utcnow", lambda: NOW)
    claimed = repo.claim_agent_lease("h1", 6, now=NOW, owner_token="agent")
    assert claimed["lease_owner"] == "agent"
    assert repo.get_hunt("h1")["execution_state"] == "completed_within_scope"
    assert repo.hunts_with_live_lease(now=NOW) == ["h1"]
    with pytest.raises(RuntimeError, match="active lease"):
        repo.claim_agent_lease("h1", 6, now=NOW, owner_token="other")
    with pytest.raises(ValueError, match="live.*lease"):
        repo.delete_hunt("h1", "test", now=NOW)
    repo.audit("test", "pivot", "h1", {}, owner_token="agent")
    monkeypatch.setattr("romulus.store.repo.utcnow", lambda: NOW + timedelta(seconds=7))
    with pytest.raises(RuntimeError, match="lease ownership lost"):
        repo.save_agent_run({"hunt_id": "h1", "state": "running"}, owner_token="agent")
    with pytest.raises(RuntimeError, match="lease ownership lost"):
        repo.audit("test", "pivot", "h1", {}, owner_token="agent")
    with pytest.raises(RuntimeError, match="lease ownership lost"):
        repo.heartbeat_agent_lease("h1", 6, now=NOW + timedelta(seconds=7), owner_token="agent")
    assert repo.claim_agent_lease("h1", 6, now=NOW + timedelta(seconds=7), owner_token="new")["lease_owner"] == "new"


def test_detection_and_agent_claims_exclude_each_other_and_maintenance():
    repo = _repo()
    repo.claim_agent_lease("h1", 6, now=NOW)
    with repo.engine.begin() as c:
        c.execute(t.hunt.update().where(t.hunt.c.id == "h1").values(execution_state="partial"))
    with pytest.raises(RuntimeError, match="AI agent phase is running"):
        repo.claim_hunt("h1", 6, resume=True, now=NOW)
    repo.claim_hunt("h1", 6, resume=True, now=NOW + timedelta(seconds=7))
    with pytest.raises(RuntimeError, match="active.*lease"):
        repo.claim_agent_lease("h1", 6, now=NOW + timedelta(seconds=8))
    with maintenance_lease(repo.engine), pytest.raises(RuntimeError, match="maintenance"):
        repo.claim_agent_lease("h1", 6, now=NOW + timedelta(seconds=14))


def test_pending_claim_is_atomic_with_detection_finish(monkeypatch):
    repo = _repo()
    with repo.engine.begin() as c:
        c.execute(t.hunt.update().where(t.hunt.c.id == "h1").values(execution_state="partial"))
    repo.claim_hunt("h1", 6, resume=True, now=NOW, owner_token="detect")
    monkeypatch.setattr("romulus.store.repo.utcnow", lambda: NOW)
    with repo.engine.begin() as c:
        c.exec_driver_sql("CREATE TRIGGER fail_pending BEFORE INSERT ON agent_run BEGIN SELECT RAISE(ABORT,'crash'); END")
    with pytest.raises(IntegrityError, match="crash"):
        repo.set_hunt_state("h1", "completed_within_scope", owner_token="detect", detection_result="leads_only",
                            pending_agent_owner_token="agent", pending_agent_lease_seconds=6)
    assert repo.get_hunt("h1")["execution_state"] == "running"
    assert repo.agent_run("h1") is None
    with repo.engine.begin() as c:
        c.exec_driver_sql("DROP TRIGGER fail_pending")
    repo.set_hunt_state("h1", "completed_within_scope", owner_token="detect", detection_result="leads_only",
                        pending_agent_owner_token="agent", pending_agent_lease_seconds=6)
    assert repo.agent_run("h1")["state"] == "pending"
    with pytest.raises(RuntimeError, match="active lease"):
        repo.claim_agent_lease("h1", 6, now=NOW + timedelta(seconds=1))
    repo.claim_agent_lease("h1", 6, now=NOW + timedelta(seconds=7), owner_token="resumed")
    assert repo.get_hunt("h1")["detection_result"] == "leads_only"


def test_finalization_refreshes_only_deterministic_result_and_releases_atomically(monkeypatch):
    repo = _repo()
    monkeypatch.setattr("romulus.store.repo.utcnow", lambda: NOW)
    repo.claim_agent_lease("h1", 6, now=NOW, owner_token="agent")
    repo.save_agent_run({"hunt_id": "h1", "state": "running", "provider": {"model": "keep"}}, owner_token="agent")
    repo.save_candidate(_candidate("agent-high", lane="high", provenance="agent"), owner_token="agent")
    assert repo.lane_counts("h1") == {}
    repo.save_candidate(_candidate("pivot-high", lane="high"), owner_token="agent")
    with repo.engine.begin() as c:
        c.exec_driver_sql("CREATE TRIGGER fail_terminal BEFORE UPDATE OF state ON agent_run "
                          "WHEN NEW.state='completed' BEGIN SELECT RAISE(ABORT,'crash'); END")
    with pytest.raises(IntegrityError, match="crash"):
        repo.finalize_agent_run("h1", {"state": "completed"}, owner_token="agent")
    assert repo.get_hunt("h1")["detection_result"] == "leads_only"
    assert repo.agent_run("h1")["state"] == "running"
    assert repo.agent_run("h1")["lease_owner"] == "agent"
    with repo.engine.begin() as c:
        c.exec_driver_sql("DROP TRIGGER fail_terminal")
    with pytest.raises(RuntimeError, match="lease ownership lost"):
        repo.finalize_agent_run("h1", {"state": "completed"}, owner_token="lost")
    result = repo.finalize_agent_run("h1", {"state": "completed"}, owner_token="agent")
    assert result == {"detection_result": "reportable_findings", "lane_counts": {"high": 1}}
    assert repo.get_hunt("h1")["execution_state"] == "completed_within_scope"
    assert repo.get_hunt("h1")["stop_reason"] == "scope"
    assert repo.agent_run("h1")["lease_owner"] is None
    assert repo.agent_run("h1")["provider"] == {"model": "keep"}


def test_duplicate_scan_streams_only_matching_candidates_and_counts_in_sql():
    repo = _repo()
    with repo.engine.begin() as c:
        # Include a high-overlap negative case, where the full subset never matches.
        c.execute(t.candidate.insert(), [{**_candidate(f"f{i:06d}", lane="high", events=["e1"]), "created_at": NOW}
                                         for i in range(100_000)])
        c.execute(t.candidate.insert(), [{**_candidate("unrelated", lane="high", events=["other"]), "created_at": NOW},
                                        {**_candidate("context", lane="context", events=["e1", "e2"]), "created_at": NOW},
                                        {**_candidate("agent", lane="high", provenance="agent", events=["e3"]), "created_at": NOW}])
    queries = []
    def before(_conn, _cursor, statement, _parameters, _context, _many):
        queries.append(statement)
    event.listen(repo.engine, "before_cursor_execute", before)
    try:
        batches = repo.candidate_duplicate_batches("h1", ["e1", "e2"], ["high", "urgent"])
        count = peak = 0
        for rows in batches:
            peak = max(peak, len(rows))
            count += len(rows)
            assert all(set(row["event_ids"]) == {"e1"} for row in rows)
        assert count == 100_000
        assert peak <= 500
        assert len(queries) <= 201
        queries.clear()
        assert repo.agent_cap_count("h1", "agent_finding") == 1
        assert len(queries) == 1 and "count(" in queries[0].lower()
        assert [row["id"] for row in repo.candidates_by_ids("h1", ["agent"])] == ["agent"]
    finally:
        event.remove(repo.engine, "before_cursor_execute", before)


@pytest.mark.parametrize("foreign_keys", [True, False])
def test_downgrade_discards_agent_candidates_and_preserves_deterministic_rows(tmp_path, foreign_keys):
    engine = make_engine(tmp_path / "downgrade.sqlite")
    migrate(engine)
    repo = Repo(engine)
    repo.create_hunt("h1", {}, "d", "test")
    repo.save_candidate(_candidate("deterministic"))
    repo.save_candidate(_candidate("agent", provenance="agent"))
    with engine.begin() as c:
        c.execute(t.candidate_host.insert(), [
            {"candidate_id": cid, "host": "host", "first_event_id": "event"}
            for cid in ("agent", "deterministic")
        ])
        c.execute(t.zeek_link_budget.insert().values(hunt_id="h1", anchor_id="agent",
                  link_type="test", window_label="window", body={}))
    if not foreign_keys:
        with engine.connect() as c:
            c.exec_driver_sql("PRAGMA foreign_keys=OFF")
            c.commit()
    with engine.begin() as c:
        command.downgrade(config(c), "0034")
        assert c.exec_driver_sql("SELECT id FROM candidate").scalars().all() == ["deterministic"]
        assert c.exec_driver_sql("SELECT candidate_id FROM candidate_host").scalars().all() == ["deterministic"]
        assert c.exec_driver_sql("SELECT * FROM zeek_link_budget").all() == []
        assert c.exec_driver_sql("PRAGMA foreign_key_check").all() == []
        assert c.exec_driver_sql("PRAGMA quick_check").scalar_one() == "ok"
    with engine.begin() as c:
        command.upgrade(config(c), "0035")
        assert c.exec_driver_sql("SELECT id,provenance FROM candidate").all() == [("deterministic", "deterministic")]
        assert {row[1] for row in c.exec_driver_sql("PRAGMA table_info(agent_run)")} >= {"lease_owner", "lease_until"}
        assert c.exec_driver_sql("PRAGMA foreign_key_check").all() == []
        assert c.exec_driver_sql("PRAGMA quick_check").scalar_one() == "ok"


def test_agent_source_query_reservation_is_shared_at_concurrent_limit(tmp_path):
    engine = make_engine(tmp_path / "source-reservations.sqlite")
    migrate(engine)
    repo = Repo(engine)
    repo.create_hunt("h1", {}, "d", "test")
    _detection_finished(repo, "h1")
    repo.claim_agent_lease("h1", 60, owner_token="agent")
    barrier = Barrier(2)
    def reserve():
        barrier.wait(timeout=5)
        return repo.reserve_agent_source_query("h1", 1, None, owner_token="agent")
    with ThreadPoolExecutor(max_workers=2) as pool:
        attempts = [pool.submit(reserve), pool.submit(reserve)]
        assert sorted((attempt.result() for attempt in attempts), key=lambda value: value is None) == [1, None]
    assert repo.agent_source_queries("h1") == 1


def test_duplicate_scan_chunks_cites_and_keeps_interleaved_matches_bounded():
    repo = _repo()
    with repo.engine.begin() as c:
        c.execute(t.candidate.insert(), [
            {**_candidate(f"match{i:04d}", events=["e0" if i % 2 else "e899"]), "created_at": NOW}
            for i in range(1_200)
        ])
    batches = repo.candidate_duplicate_batches("h1", [f"e{i}" for i in range(900)], ["lead"])
    ids = []
    for rows in batches:
        assert len(rows) <= 500
        ids.extend(row["id"] for row in rows)
    assert ids == [f"match{i:04d}" for i in range(1_200)]


def test_agent_page_and_alias_writers_refuse_stale_tokens(monkeypatch):
    repo = _repo()
    monkeypatch.setattr("romulus.store.repo.utcnow", lambda: NOW)
    repo.claim_agent_lease("h1", 6, now=NOW, owner_token="agent")
    calls = [
        lambda token: repo.get_or_create_agent_alias("h1", "F", "f", owner_token=token),
        lambda token: repo.seed_agent_aliases("h1", [("F", "f")], owner_token=token),
        lambda token: repo.seed_agent_base_aliases("h1", owner_token=token),
        lambda token: repo.create_agent_page_plan("h1", "page", {}, {}, [], owner_token=token),
        lambda token: repo.create_candidate_page_plan("h1", "candidates", {}, {}, owner_token=token),
        lambda token: repo.create_entity_event_page_plan("h1", "events", {}, "entity", owner_token=token),
    ]
    for call in calls:
        with pytest.raises(RuntimeError, match="lease ownership lost"):
            call("stale")
        call("agent")
    assert repo.agent_run("h1")["lease_owner"] == "agent"


def test_release_and_terminal_summary_commit_preserve_run_progress(monkeypatch):
    repo = _repo()
    repo.audit("system", "hunt.agent_summary", "h1", {"status": "disabled"})
    monkeypatch.setattr("romulus.store.repo.utcnow", lambda: NOW)
    repo.claim_agent_lease("h1", 6, now=NOW, owner_token="agent")
    repo.save_agent_run({"hunt_id": "h1", "state": "partial", "reason": "budget:tokens",
                         "prompt_digests": {"orient": "retained"}, "provider": {"model": "retained"}},
                        owner_token="agent")
    repo.release_agent_lease("h1", owner_token="agent")
    assert repo.agent_run("h1")["state"] == "partial"
    assert repo.agent_run("h1")["reason"] == "budget:tokens"
    assert repo.agent_run("h1")["lease_owner"] is None
    repo.claim_agent_lease("h1", 6, now=NOW, owner_token="resumed")
    repo.finalize_agent_run("h1", {"state": "completed", "reason": None}, owner_token="resumed",
                            summary={"state": "completed", "tool_calls": 3})
    assert repo.agent_run("h1")["prompt_digests"] == {"orient": "retained"}
    assert repo.latest_audit("h1", "hunt.ai_agent_summary")["detail"] == {"state": "completed", "tool_calls": 3}
    assert repo.latest_audit("h1", "hunt.agent_summary")["detail"] == {"status": "disabled"}
