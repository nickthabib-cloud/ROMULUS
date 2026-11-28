"""Deleting a hunt never holds SQLite's write lock for a time that grows with other hunts' data.

A hunt is deleted in short transactions of a bounded number of rows each, every lookup served by an index, so a hunt
running at the same time in another process waits for one batch at most. The hunt is marked deleting first (readers
treat it as gone, workers cannot claim it), and a deletion that stops part way is finished by deleting it again.
Lock hold is measured by instrumentation (SQLite virtual-machine steps per write transaction), never by wall clock.
"""
from __future__ import annotations

import contextlib
import sqlite3
from datetime import UTC, datetime

import pytest
from sqlalchemy import event as sa_event
from sqlalchemy import func, select

from romulus.evidence.typed import RawRef, TypedEvent, fv
from romulus.store import repo as repo_module
from romulus.store import schema as t
from romulus.store.db import make_engine, migrate
from romulus.store.repo import Repo
from tests.test_delete import _csrf, _login, env  # noqa: F401 - the web deletion fixture

TS = datetime(2026, 1, 1, tzinfo=UTC)
GONE = "gone"
GONE_EVENTS = 1_200                 # more than two deletion batches
STEP_GRANULE = 50                   # VM steps between two progress-handler calls


def _event(event_id: str, native_id: str, host: str | None = "web01") -> TypedEvent:
    return TypedEvent(id=event_id, family="process_exec", ts=TS, host=host,
                      fields={"process.executable": fv("/bin/true", "x")},
                      raw=[RawRef(target="idx", native_id=native_id, digest="d")], normalizer="test@1")


def _save(repo: Repo, hunt_id: str, events: list[TypedEvent]) -> None:
    for start in range(0, len(events), 500):
        chunk = events[start:start + 500]
        repo.save_evidence(hunt_id, chunk, {f"idx/{e.raw[0].native_id}": {"n": e.raw[0].native_id} for e in chunk},
                           None)


def _candidate(repo: Repo, cid: str, hunt_id: str, event_ids: list[str]) -> None:
    repo.save_candidate({
        "id": cid, "hunt_id": hunt_id, "rule_id": "host.web_shell", "rule_version": "1", "claim": "c",
        "claim_type": "observed_action", "event_ids": event_ids, "predicate_fields": [], "entities": [],
        "ts": TS, "severity": "high", "confidence": "high", "lane": "high", "priority": 1.0, "priority_reasons": [],
        "gate_results": {}, "benign_alternatives": [], "next_checks": [], "source_case_id": None,
        "source_anchor_id": None, "source_link_id": None})


def _hunt_data(repo: Repo, hunt_id: str, n: int) -> list[str]:
    """One finished hunt with `n` events and the rows a hunt holds around them: findings, entities, an investigation
    step, an expansion link, tasks, raw copies and its own audit records."""
    repo.create_hunt(hunt_id, {}, hunt_id, "test")
    repo.set_hunt_state(hunt_id, "running")
    repo.set_hunt_state(hunt_id, "completed_within_scope", detection_result="leads_only")
    ids = [f"{hunt_id}-ev-{i}" for i in range(n)]
    _save(repo, hunt_id, [_event(eid, f"{hunt_id}-doc-{i}", host=f"host{i % 50}") for i, eid in enumerate(ids)])
    for k in range(0, n, 20):
        _candidate(repo, f"{hunt_id}-F{k}", hunt_id, ids[k:k + 20])
    repo.create_case({"id": f"{hunt_id}-case", "hunt_id": hunt_id, "title": "pivot", "priority": 1.0,
                      "entities": [], "step_budget": 4})
    repo.append_case_step(f"{hunt_id}-case", 1, {"tool": "entity_timeline", "evidence_ids": ids[:5]}, True,
                          result_digest={"status": "complete", "event_ids": ids[:50]})
    repo.save_expansion_anchor({"id": f"{hunt_id}-F0", "hunt_id": hunt_id, "candidate_id": f"{hunt_id}-F0",
                                "depth": 0, "parent_anchor_id": None, "host": "web1", "lane": "high",
                                "severity": "high", "ts": TS, "status": "expanded_complete", "reasons": []})
    repo.save_expansion_link({
        "id": f"{hunt_id}-L", "hunt_id": hunt_id, "anchor_id": f"{hunt_id}-F0", "link_type": "host_after_anchor",
        "window_label": "anchor 5 min", "window_start": TS, "window_end": TS, "strength": "inferred",
        "key": {}, "status": "complete", "event_ids": ids[:50], "evidence_ids": ids[:5], "task_ids": [],
        "coverage": [], "reasons": [], "duration_ms": 1, "query_spend": 1, "evaluated": 1})
    for k in range(5):
        repo.upsert_task(f"{hunt_id}-task-{k}", hunt_id, "sweep", "pb", {}, f"fp{k}")
    for k in range(20):
        repo.audit("system", "hunt.note", hunt_id, {"k": k})
    return ids


def _store(path, other_events: int) -> tuple[Repo, list[str], list[str]]:
    """Two other hunts of `other_events` events each, and the hunt to delete: it owns GONE_EVENTS events, observes
    some of another hunt's (one with a differing raw copy, so it holds an overlay), and another hunt observes some
    of its own (identical copies, and differing copies whose overlay becomes the new stable row)."""
    repo = Repo(make_engine(path))
    migrate(repo.engine)
    keep_a = _hunt_data(repo, "keep-a", other_events)
    _hunt_data(repo, "keep-b", other_events)
    gone = _hunt_data(repo, GONE, GONE_EVENTS)
    # the deleted hunt observes another hunt's events, once with a copy of its own
    _save(repo, GONE, [_event(eid, f"keep-a-doc-{i}") for i, eid in enumerate(keep_a[:30])])
    _save(repo, GONE, [_event(keep_a[40], "gone-own-copy-of-keep-a-40")])
    # another hunt observes some of the deleted hunt's events: identical copies, then differing copies
    _save(repo, "keep-a", [_event(eid, f"{GONE}-doc-{i}") for i, eid in enumerate(gone[:40])])
    _save(repo, "keep-a", [_event(eid, f"keep-a-copy-of-{eid}") for eid in gone[40:60]])
    return repo, keep_a, gone


class _Probe:
    """Counts SQLite VM steps in every write transaction the repository opens, and after each one checks that
    another connection (another process's hunt) can take the write lock at once."""

    def __init__(self, monkeypatch, path):
        self.steps: list[int] = []
        self.other_writes: list[str] = []
        self.after_commit = None
        real = repo_module.write_txn
        probe = self

        @contextlib.contextmanager
        def counted(engine):
            count = [0]
            with real(engine) as connection:
                raw = connection.connection.driver_connection

                def tick():
                    count[0] += 1
                    return 0
                raw.set_progress_handler(tick, STEP_GRANULE)
                try:
                    yield connection
                finally:
                    raw.set_progress_handler(None, 0)
            probe.steps.append(count[0] * STEP_GRANULE)
            other = sqlite3.connect(str(path), timeout=0)
            try:
                other.execute("BEGIN IMMEDIATE")
                other.execute("ROLLBACK")
                probe.other_writes.append("written")
            except sqlite3.OperationalError as error:
                probe.other_writes.append(str(error))
            finally:
                other.close()
            if probe.after_commit is not None:
                hook, probe.after_commit = probe.after_commit, None
                hook()

        monkeypatch.setattr(repo_module, "write_txn", counted)


def _remaining(repo: Repo) -> dict[str, int]:
    with repo.engine.connect() as c:
        return {table.name: c.execute(select(func.count()).select_from(table)).scalar_one()
                for table in (t.typed_event, t.raw_record, t.event_citation, t.event_observation, t.candidate,
                              t.entity, t.event_entity, t.case_step, t.expansion_link, t.task, t.event_raw_ref)}


def _deletion_steps(tmp_path, monkeypatch, other_events: int) -> tuple[list[int], _Probe]:
    path = tmp_path / f"store-{other_events}.db"
    repo, _keep_a, _gone = _store(path, other_events)
    probe = _Probe(monkeypatch, path)
    repo.delete_hunt(GONE, actor="test")
    monkeypatch.undo()
    return probe.steps, probe


def test_deletion_lock_hold_does_not_grow_with_other_hunts_data(tmp_path, monkeypatch):
    small, probe_small = _deletion_steps(tmp_path, monkeypatch, 1_500)
    large, probe_large = _deletion_steps(tmp_path, monkeypatch, 6_000)
    # many short transactions, and another connection could write after every one of them
    assert len(small) > 10 and len(large) > 10
    assert set(probe_small.other_writes) == {"written"} == set(probe_large.other_writes)
    # four times the other hunts' data: the longest transaction is no longer (an index may grow one level deeper);
    # one transaction over the whole store grows by about half here
    assert max(large) <= 1.1 * max(small), (max(small), max(large))


def test_deletion_keeps_what_other_hunts_use_and_removes_the_rest(tmp_path):
    repo, keep_a, gone = _store(tmp_path / "store.db", 300)
    counts = repo.delete_hunt(GONE, actor="test")
    assert repo.get_hunt(GONE) is None and repo.get_hunt(GONE, include_deleting=True) is None
    kept = {row["id"]: row for row in repo.events_by_ids(gone[:60])}
    assert set(kept) == set(gone[:60]) and {row["hunt_id"] for row in kept.values()} == {"keep-a"}
    assert counts["events_kept_for_other_hunts"] == 60 and counts["typed_events"] == GONE_EVENTS - 60
    assert repo.events_by_ids(gone[60:61]) == []
    # a differing copy's overlay became the stable row; the deleted hunt's own copy of the kept event is gone
    assert [r["native_id"] for r in kept[gone[45]]["event"]["raw"]] == [f"keep-a-copy-of-{gone[45]}"]
    assert repo.raw_records([repo_module.raw_id("idx", f"{GONE}-doc-45")]) == []
    assert repo.raw_records([repo_module.raw_id("idx", "gone-own-copy-of-keep-a-40")]) == []
    assert repo.raw_records([repo_module.raw_id("idx", f"{GONE}-doc-10")])          # identical copy: kept
    assert repo.events_by_ids([keep_a[40]])[0]["hunt_id"] == "keep-a"
    with repo.engine.connect() as c:
        assert c.exec_driver_sql("PRAGMA foreign_key_check").fetchall() == []
        for table in (t.candidate, t.entity, t.task, t.event_citation, t.event_observation, t.expansion_link):
            assert c.execute(select(func.count()).select_from(table).where(table.c.hunt_id == GONE)).scalar_one() == 0
        # the raw-reference index agrees with what the stored rows cite
        dangling = c.exec_driver_sql(
            "SELECT count(*) FROM event_raw_ref r WHERE NOT EXISTS (SELECT 1 FROM typed_event e WHERE e.id=r.event_id"
            " AND r.holder='') AND NOT EXISTS (SELECT 1 FROM event_citation x WHERE x.event_id=r.event_id"
            " AND x.hunt_id=r.holder)").scalar_one()
        assert dangling == 0
        uncited = c.exec_driver_sql(
            "SELECT count(*) FROM raw_record w WHERE NOT EXISTS (SELECT 1 FROM event_raw_ref r WHERE r.raw_id=w.id)"
        ).scalar_one()
        assert uncited == 0
    assert repo.latest_audit(GONE, "hunt.delete")["actor"] == "test"


def test_a_citation_committed_between_batches_keeps_the_event(tmp_path, monkeypatch):
    """Another hunt observes one of the deleted hunt's events after the deletion began: the batch that reaches it
    decides under the write lock, sees the new marker and hands the event over."""
    path = tmp_path / "store.db"
    repo, _keep_a, _gone = _store(path, 100)
    probe = _Probe(monkeypatch, path)
    late: list[str] = []

    def observe_one():
        with repo.engine.connect() as c:
            event_id = c.execute(select(t.typed_event.c.id).where(t.typed_event.c.hunt_id == GONE)
                                 .order_by(t.typed_event.c.id.desc()).limit(1)).scalar_one()
        late.append(event_id)
        index = int(event_id.rsplit("-", 1)[1])
        repo.save_evidence("keep-b", [_event(event_id, f"{GONE}-doc-{index}")], {f"idx/{GONE}-doc-{index}": {}},
                           None)

    calls = [0]

    def second_commit():
        calls[0] += 1
        if calls[0] < 2:
            probe.after_commit = second_commit
        else:
            observe_one()
    probe.after_commit = second_commit
    repo.delete_hunt(GONE, actor="test")
    monkeypatch.undo()
    assert late and repo.events_by_ids(late)[0]["hunt_id"] == "keep-b"


class _Stop(Exception):
    pass


def test_an_interrupted_deletion_is_hidden_unclaimable_and_finished_by_deleting_again(tmp_path, monkeypatch):
    repo, _keep_a, _gone = _store(tmp_path / "store.db", 100)
    reference, _, _ = _store(tmp_path / "reference.db", 100)
    reference.delete_hunt(GONE, actor="test")

    def stop(*_args, **_kwargs):
        raise _Stop
    monkeypatch.setattr(Repo, "_delete_own_overlays", stop)
    with pytest.raises(_Stop):
        repo.delete_hunt(GONE, actor="test")
    monkeypatch.undo()

    assert repo.get_hunt(GONE) is None                                       # readers: gone
    assert repo.get_hunt(GONE, include_deleting=True)["execution_state"] == "deleting"
    assert repo.deleting_hunts() == [GONE]
    assert repo.candidate(f"{GONE}-F0") is None
    with pytest.raises(ValueError):
        repo.claim_hunt(GONE, 60, resume=True)
    with pytest.raises(ValueError):
        repo.set_hunt_state(GONE, "running")

    repo.delete_hunt(GONE, actor="test")
    assert repo.get_hunt(GONE, include_deleting=True) is None and repo.deleting_hunts() == []
    assert _remaining(repo) == _remaining(reference)


def test_every_column_a_deletion_selects_or_checks_a_foreign_key_on_leads_an_index(tmp_path):
    """A deletion batch is bounded only if its lookups are: every hunt column it deletes by, and every foreign key
    SQLite checks when a parent row goes, leads an index (in a migrated store and in a metadata-built one)."""
    for engine in (make_engine(tmp_path / "migrated.db"), make_engine(":memory:")):
        migrate(engine)
        with engine.connect() as c:
            raw = c.connection.driver_connection
            tables = [row[0] for row in raw.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]
            missing = []
            for table in tables:
                indexed = [[row[2] for row in raw.execute(f"PRAGMA index_info('{name}')")]
                           for _seq, name, *_rest in raw.execute(f"PRAGMA index_list('{table}')")]
                key = [row[1] for row in sorted(raw.execute(f"PRAGMA table_info('{table}')"), key=lambda r: r[5])
                       if row[5]]
                indexed.append(key)
                keys: dict[int, list[str]] = {}
                for row in raw.execute(f"PRAGMA foreign_key_list('{table}')"):
                    keys.setdefault(row[0], []).append(row[3])
                for columns in keys.values():
                    if not any(index[:len(columns)] == columns for index in indexed):
                        missing.append(f"{table}{columns}")
                names = [row[1] for row in raw.execute(f"PRAGMA table_info('{table}')")]
                if "hunt_id" in names and not any(index[:1] == ["hunt_id"] for index in indexed):
                    missing.append(f"{table}.hunt_id")
            assert missing == [], missing


def test_every_deletion_statement_is_index_served(tmp_path):
    """No statement of a deletion scans a whole table or sorts: each reads through an index."""
    path = tmp_path / "store.db"
    repo, _keep_a, _gone = _store(path, 50)
    statements: list[tuple[str, tuple]] = []

    def capture(_conn, _cursor, statement, parameters, _context, many):
        if not many:                                    # a multi-row INSERT ... VALUES reads nothing
            statements.append((statement, tuple(parameters or ())))
    sa_event.listen(repo.engine, "before_cursor_execute", capture)
    try:
        repo.delete_hunt(GONE, actor="test")
    finally:
        sa_event.remove(repo.engine, "before_cursor_execute", capture)
    other = sqlite3.connect(str(path))
    try:
        offenders = set()
        for statement, parameters in statements:
            head = statement.lstrip().split(None, 1)[0].upper()
            if head not in {"SELECT", "UPDATE", "DELETE", "INSERT"}:
                continue
            for row in other.execute("EXPLAIN QUERY PLAN " + statement, parameters):
                detail = row[-1]
                words = detail.split()
                if (words[:1] == ["SCAN"] and words[1] not in {"json_each", "CONSTANT"}) or "TEMP B-TREE" in detail:
                    offenders.add(f"{detail} :: {' '.join(statement.split())[:160]}")
        assert sorted(offenders) == []
    finally:
        other.close()


def test_an_investigation_step_citing_another_hunts_event_keeps_it_without_an_observation_marker(tmp_path):
    """Citing an event id in a step or link is not retrieving a copy of it: no observation marker is written, yet
    deleting the owner keeps the event and hands it to the citing hunt."""
    repo = Repo(make_engine(tmp_path / "store.db"))
    migrate(repo.engine)
    for hunt_id in ("owner", "citer"):
        repo.create_hunt(hunt_id, {}, hunt_id, "test")
    _save(repo, "owner", [_event("ev-1", "doc-1", host=None)])
    repo.create_case({"id": "case-c", "hunt_id": "citer", "title": "pivot", "priority": 1.0, "entities": [],
                      "step_budget": 4})
    repo.append_case_step("case-c", 1, {"tool": "entity_timeline"}, True,
                          result_digest={"status": "complete", "event_ids": ["ev-1"]})
    with repo.engine.connect() as c:
        assert c.execute(select(func.count()).select_from(t.event_observation)).scalar_one() == 0
    repo.delete_hunt("owner", actor="test")
    assert repo.events_by_ids(["ev-1"])[0]["hunt_id"] == "citer"
    repo.delete_hunt("citer", actor="test")
    assert repo.events_by_ids(["ev-1"]) == []
    with repo.engine.connect() as c:
        assert c.execute(select(func.count()).select_from(t.event_step_ref)).scalar_one() == 0


def test_the_web_finishes_an_interrupted_deletion(env, monkeypatch):  # noqa: F811
    client, repo, _s, pw = env

    def stop(*_args, **_kwargs):
        raise _Stop
    monkeypatch.setattr(Repo, "_delete_own_overlays", stop)
    with pytest.raises(_Stop):
        repo.delete_hunt("h1", actor="test")
    monkeypatch.undo()
    _login(client, "lead1", pw)
    assert client.get("/hunts/h1").status_code == 404
    assert "/hunts/h1/delete" in client.get("/").text                  # listed, linked to finishing it
    page = client.get("/hunts/h1/delete")
    assert page.status_code == 200
    done = client.post("/hunts/h1/delete", data={"csrf": _csrf(page.text), "confirm": "h1"}, follow_redirects=False)
    assert done.status_code == 303
    assert repo.get_hunt("h1", include_deleting=True) is None and repo.deleting_hunts() == []
