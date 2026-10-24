"""Batched store writes: one compiled statement executed over many rows, the same conflict rules, any batch size;
one transaction for a partition's coverage cells; each staged event serialized once per partition."""
import time
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select

from romulus.detect.base import Match
from romulus.detect.bounded import StateBudget
from romulus.evidence.typed import Outcome, RawRef, TypedEvent, fv
from romulus.hunt import stage as stage_mod
from romulus.hunt import sweep as sw
from romulus.sources.models import Completeness, SearchOutcome, Window
from romulus.store import schema as t
from romulus.store.db import make_engine, migrate, write_txn
from romulus.store.repo import Repo, _upsert_ignore, raw_id

T0 = datetime(2024, 11, 18, 14, 0, tzinfo=UTC)
# SQLite's default limit on bind parameters in one statement (SQLITE_MAX_VARIABLE_NUMBER since 3.32)
SQLITE_BIND_LIMIT = 32_766


def _repo(tmp_path=None) -> Repo:
    engine = make_engine(":memory:" if tmp_path is None else tmp_path / "r.db")
    migrate(engine)
    repo = Repo(engine)
    repo.create_hunt("h1", {"targets": ["romulus-host-x"]}, "d", "t")
    return repo


def _entity(n: int, kind="ip") -> dict:
    return {"id": f"h1:{kind}:{n}", "hunt_id": "h1", "kind": kind, "value": str(n), "first_seen": T0,
            "last_seen": T0, "event_count": 0}


def test_a_batch_over_the_bind_parameter_limit_is_written_whole():
    repo = _repo()
    rows = [_entity(n) for n in range(SQLITE_BIND_LIMIT + 7_234)]       # 40,000 rows, 280,000 values
    with write_txn(repo.engine) as c:
        _upsert_ignore(c, t.entity, rows, ["id"])
    with repo.engine.connect() as c:
        assert c.execute(select(func.count()).select_from(t.entity)).scalar_one() == len(rows)


def test_conflicts_keep_the_stored_row_and_the_first_of_a_batch():
    repo = _repo()
    with write_txn(repo.engine) as c:
        _upsert_ignore(c, t.entity, [{**_entity(1), "value": "stored"}], ["id"])
    with write_txn(repo.engine) as c:
        _upsert_ignore(c, t.entity, [{**_entity(1), "value": "later"}, {**_entity(2), "value": "first"},
                                     {**_entity(2), "value": "second"}], ["id"])
    with repo.engine.connect() as c:
        values = dict(c.execute(select(t.entity.c.id, t.entity.c.value)).all())
    assert values == {"h1:ip:1": "stored", "h1:ip:2": "first"}


def _event(n: int, ts=T0) -> TypedEvent:
    refs = [RawRef(target="romulus-host-x", native_id=f"r{n}-{k}", digest="d") for k in range(3)]
    return TypedEvent(id=f"e{n:06d}", family="process_exec", ts=ts, host="web1", outcome=Outcome.success,
                      fields={"process.executable": fv("/bin/sh", f"r{n}-0:exe"),
                              "source.ip": fv(f"10.{n // 65536 % 256}.{n // 256 % 256}.{n % 256}", f"r{n}-0:ip"),
                              "user.name": fv(f"user{n % 50}", f"r{n}-0:user")},
                      raw=refs, normalizer="test@1")


def test_save_evidence_takes_a_batch_larger_than_one_statement_can_bind(tmp_path):
    repo = _repo(tmp_path)
    events = [_event(n) for n in range(12_000)]                       # 36,000 raw rows, 252,000 values
    raw = {r.key: {"n": r.native_id} for e in events for r in e.raw}
    repo.save_evidence("h1", events, raw, None)
    with repo.engine.connect() as c:
        def count(table):
            return c.execute(select(func.count()).select_from(table)).scalar_one()

        assert count(t.typed_event) == 12_000 and count(t.raw_record) == 36_000
        assert count(t.event_entity) == 12_000 * 3
    assert repo.events_by_ids(["e000042"])[0]["event"] == events[42].model_dump(mode="json")


def test_linux_save_evidence_stays_close_to_the_no_overlay_write_path(monkeypatch):
    events = [_event(n) for n in range(8_000)]
    raw = {ref.key: {"n": ref.native_id} for event in events for ref in event.raw}

    with monkeypatch.context() as patch:
        patch.setattr(Repo, "_merge_citation_raw", staticmethod(lambda *_args: None))
        baseline_repo = _repo()
        started = time.perf_counter()
        baseline_repo.save_evidence("h1", events, raw, None)
        baseline = time.perf_counter() - started

    repo = _repo()
    started = time.perf_counter()
    repo.save_evidence("h1", events, raw, None)
    elapsed = time.perf_counter() - started
    with repo.engine.connect() as connection:
        overlays = connection.execute(select(func.count()).select_from(t.event_citation)).scalar_one()

    assert overlays == 0
    assert elapsed <= baseline * 1.5 + 0.1, (baseline, elapsed)


def test_windows_dedup_stage_stores_only_bounded_ids_and_leaves_linux_untracked(tmp_path):
    stage = stage_mod.EventStage(tmp_path)
    linux = _event(0)
    first = _event(1).model_copy(update={
        "raw": [RawRef(target="a", native_id="1", digest="a")],
        "normalizer": "windows-ecs@1",
    })
    later = first.model_copy(update={"raw": [RawRef(target="b", native_id="2", digest="b")]})

    assert stage.unique_windows([linux]) == ([linux], [])
    assert stage.unique_windows([first]) == ([first], [])
    fresh, duplicates = stage.unique_windows([later])
    counts = {
        "windows_seen": stage.windows_db.execute("SELECT count(*) FROM windows_seen").fetchone()[0],
        **{table: stage.db.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
           for table in ("event", "raw")},
    }

    assert fresh == [] and len(duplicates) == 1
    assert counts == {"windows_seen": 1, "event": 0, "raw": 0}
    stage.close()


def test_windows_dedup_has_its_own_budget_account_and_refuses_growth_honestly(tmp_path):
    budget = StateBudget(tmp_path, disk_total=64 * 1024, reserve=0)
    budget.plan(2)
    account = budget.account("windows_seen")
    stage = stage_mod.EventStage(tmp_path, budget=budget, windows_account=account)
    first = _event(1).model_copy(update={"normalizer": "windows-ecs@2"})
    refused = _event(2).model_copy(update={"normalizer": "windows-ecs@2"})

    assert stage.unique_windows([first]) == ([first], [])
    assert account.used > 0
    budget.force_full("Windows dedup floor spent (test)", lambda candidate: candidate is account)
    # a refused dedup write never withholds the event; a later copy of it is then delivered again
    assert stage.unique_windows([refused]) == ([refused], [])
    assert stage.unique_windows([refused]) == ([refused], [])

    assert stage.windows_refused == 1
    assert "Windows dedup floor spent" in stage.windows_refusal_reason
    assert stage.windows_db.execute("SELECT count(*) FROM windows_seen").fetchone()[0] == 1
    stage.close()


def _written(repo: Repo) -> dict[str, int]:
    """Rows handed to INSERT statements per table while the returned counter is live."""
    from sqlalchemy import event as sa_event
    counts: dict[str, int] = {}

    @sa_event.listens_for(repo.engine, "before_cursor_execute")
    def _count(_conn, _cursor, statement, parameters, _context, executemany):
        if statement.lstrip().upper().startswith("INSERT"):
            table = statement.split()[2] if statement.split()[1].upper() == "INTO" else statement.split()[4]
            counts[table] = counts.get(table, 0) + (len(parameters) if executemany else 1)
    return counts


def test_a_re_save_writes_no_stored_event_or_raw_copy_again_and_the_first_written_wins(tmp_path):
    repo = _repo(tmp_path)
    repo.create_hunt("h2", {"targets": ["other"]}, "d2", "t")
    for task_id, hunt_id in (("task-1", "h1"), ("task-2", "h1"), ("task-3", "h2")):
        repo.upsert_task(task_id, hunt_id, "sweep", "sweep", {}, task_id)
    events = [_event(n) for n in range(300)]
    raw = {r.key: {"n": r.native_id} for e in events for r in e.raw}
    repo.save_evidence("h1", events, raw, "task-1")
    with repo.engine.connect() as c:
        before = {name: [dict(r) for r in c.execute(select(table).order_by(table.c.id)).mappings()]
                  for name, table in (("raw", t.raw_record), ("events", t.typed_event))}
    written = _written(repo)
    # the same records again, by this hunt and by another one, with another task and changed raw bodies
    repo.save_evidence("h1", events + events[:10], {k: {"changed": True} for k in raw}, "task-2")
    repo.save_evidence("h2", events, {k: {"changed": True} for k in raw}, "task-3")
    assert written.get("raw_record", 0) == 0 and written.get("typed_event", 0) == 0
    with repo.engine.connect() as c:
        after = {name: [dict(r) for r in c.execute(select(table).order_by(table.c.id)).mappings()]
                 for name, table in (("raw", t.raw_record), ("events", t.typed_event))}
    assert after == before
    assert {row["first_task_id"] for row in after["raw"]} == {"task-1"}
    # the other hunt still gets its own entity rows and an observation marker per event; the owner none
    assert written.get("event_entity", 0) == 300 * 3
    with repo.engine.connect() as c:
        markers = c.execute(select(t.event_observation.c.hunt_id, func.count()).group_by(
            t.event_observation.c.hunt_id)).all()
    assert markers == [("h2", 300)]


def test_a_batch_writes_each_new_raw_copy_once_with_the_first_reference_given():
    repo = _repo()
    ref = RawRef(target="a", native_id="1", digest="first")
    first = _event(1).model_copy(update={"raw": [ref]})
    second = _event(2).model_copy(update={"raw": [ref.model_copy(update={"digest": "second"})]})
    repo.upsert_task("task-1", "h1", "sweep", "sweep", {}, "task-1")
    written = _written(repo)
    repo.save_evidence("h1", [first, second], {"a/1": {"copy": 1}}, "task-1")
    assert written["raw_record"] == 1
    [stored] = repo.raw_records([raw_id("a", "1")])
    assert stored["digest"] == "first" and stored["source"] == {"copy": 1}


def test_a_stored_boot_id_is_filled_forward_reading_only_the_boot_field():
    """A row stored without a boot id, or with one a boot-interval map placed, takes a recorded boot id; a recorded
    one is never overwritten; nothing else in the row changes."""
    from romulus.store.repo import DERIVED_BOOT_SUFFIX
    repo = _repo()
    bare, derived, recorded = _event(1), _event(2), _event(3)
    derived = derived.model_copy(update={"fields": {**derived.fields,
                                                    "host.boot.id": fv("old", "map" + DERIVED_BOOT_SUFFIX)}})
    recorded = recorded.model_copy(update={"fields": {**recorded.fields, "host.boot.id": fv("kept", "rec")}})
    repo.save_evidence("h1", [bare, derived, recorded], {}, None)
    boot = fv("new", "journald:_BOOT_ID")
    later = [e.model_copy(update={"fields": {**e.fields, "host.boot.id": boot}}) for e in (bare, derived, recorded)]
    repo.save_evidence("h1", later, {}, None)
    stored = {row["id"]: row["event"] for row in repo.events_by_ids([bare.id, derived.id, recorded.id])}
    assert stored[bare.id] == later[0].model_dump(mode="json")
    assert stored[derived.id] == later[1].model_dump(mode="json")
    assert stored[recorded.id] == recorded.model_dump(mode="json")


def test_same_event_seen_by_another_hunt_scopes_raw_provenance_without_reownership():
    repo = _repo()
    repo.create_hunt("h2", {"targets": ["other"]}, "d2", "t")
    first = _event(2).model_copy(update={"raw": [RawRef(target="a", native_id="1", digest="a")]})
    later = first.model_copy(update={"raw": [
        RawRef(target="a", native_id="1", digest="a"),
        RawRef(target="b", native_id="2", digest="b"),
    ]})

    repo.save_evidence("h1", [first], {"a/1": {"copy": 1}}, None)
    repo.save_evidence("h2", [later], {"b/2": {"copy": 2}}, None)
    stored = repo.events_by_ids([first.id])[0]
    second_citation = repo.citation_events("h2", [first.id])[0]

    assert stored["hunt_id"] == "h1"
    raw_ids = {raw_id("a", "1"), raw_id("b", "2")}
    assert set(stored["raw_ids"]) == {raw_id("a", "1")}
    assert set(second_citation["raw_ids"]) == raw_ids
    assert {raw["id"] for raw in repo.raw_records(sorted(raw_ids))} == raw_ids


def test_aggregate_stage_keeps_main_branch_event_and_raw_behavior(tmp_path):
    sweep = object.__new__(sw.Sweep)
    sweep.stage_dir = tmp_path
    first = _event(3).model_copy(update={"raw": [RawRef(target="a", native_id="1", digest="a")]})
    later = first.model_copy(update={"raw": [RawRef(target="b", native_id="2", digest="b")]})
    stage = sweep._event_stage()
    stage.put([first], {"a/1": {"copy": 1}})
    stage.put([later], {"b/2": {"copy": 2}})
    match = Match(
        "aggregate", "claim", "aggregate_observation", [first], [], T0,
        "medium", "lead", "medium",
    )

    raw_sources = sweep._merge_staged_match_raw(match)

    assert {raw.key for raw in match.events[0].raw} == {"a/1"}
    assert raw_sources == {"a/1": {"copy": 1}}
    sweep.close_stage()


def test_rule_cells_written_together_match_cells_written_one_by_one():
    one, many = _repo(), _repo()
    cells = [("r1", "1", "x", "p1", "planned", 0, 0, None), ("r2", "1", "x", "p1", "planned", 0, 0, {}),
             ("r1", "1", "x", "p1", "matched", 2, 9, {"reasons": ["a"]}), ("r3", "2", "*", "w", "split", 0, 0,
                                                                         {"children": ["a", "b"]})]
    for cell in cells:
        one.set_rule_cell("h1", *cell)
    many.set_rule_cells("h1", [dict(zip(("rule_id", "version", "target", "partition", "state", "matched",
                                         "evaluated", "detail"), cell, strict=True)) for cell in cells])
    assert one.rule_cells("h1") == many.rule_cells("h1")
    assert [c["rule_id"] for c in many.rule_cells("h1", rule_id="r1")] == ["r1"]


def _flows(n: int) -> list[dict]:
    import json
    out = []
    for i in range(n):
        ts = T0 + timedelta(seconds=i)
        eve = {"timestamp": ts.isoformat(), "event_type": "flow", "src_ip": "203.0.113.8", "src_port": 40000 + i,
               "dest_ip": "10.0.0.20", "dest_port": 22, "proto": "TCP", "flow_id": i, "community_id": f"1:{i}=",
               "flow": {"start": ts.isoformat(), "end": (ts + timedelta(seconds=2)).isoformat(),
                        "pkts_toserver": 4, "pkts_toclient": 3, "bytes_toserver": 400, "bytes_toclient": 900,
                        "state": "closed"}}
        out.append({"_index": "romulus-network-x", "_id": f"f{i}", "_source": {
            "@timestamp": ts.isoformat(), "event": {"dataset": "suricata.eve.flow", "original": json.dumps(eve)},
            "host": {"name": "fw1"}}})
    return out


def test_a_partition_is_staged_once_and_its_cells_written_in_one_transaction(monkeypatch, tmp_path):
    records = _flows(40)

    def execute(client, intent, contract):
        now = datetime.now(UTC)
        return SearchOutcome(target=intent.target, fingerprint="f", started_at=now, ended_at=now,
                             completeness=Completeness.complete, total=len(records), total_relation="eq",
                             returned=len(records), records=records)

    monkeypatch.setattr(sw, "execute", execute)
    puts, serialized = [], []
    real_put, real_dump = stage_mod.EventStage.put, TypedEvent.model_dump_json
    monkeypatch.setattr(stage_mod.EventStage, "put", lambda self, events, raw: puts.append(list(events))
                        or real_put(self, events, raw))
    monkeypatch.setattr(TypedEvent, "model_dump_json", lambda self, **kw: serialized.append(self.id)
                        or real_dump(self, **kw))
    repo = _repo()
    batches, singles, baseline_cells = [], [], []
    real_cells, real_cell = repo.set_rule_cells, repo.set_rule_cell
    real_baseline_cell = repo.save_baseline_window_cell
    monkeypatch.setattr(repo, "set_rule_cells", lambda *a, **k: batches.append(a[1]) or real_cells(*a, **k))
    monkeypatch.setattr(repo, "set_rule_cell", lambda *a, **k: singles.append(a) or real_cell(*a, **k))
    monkeypatch.setattr(repo, "save_baseline_window_cell",
                        lambda *a, **k: baseline_cells.append(a[1]) or real_baseline_cell(*a, **k))
    w = Window(start=T0, end=T0 + timedelta(minutes=5))
    sweep = sw.Sweep(repo, None, "h1", w, {"romulus-network-x": None}, stage_dir=tmp_path)
    assert sum(pb.staged for pb in sweep.pack) >= 2       # several joining playbooks stage the same flows
    sweep.run_partition("romulus-network-x", None, [], w, est=len(records))
    assert len(puts) == 1 and puts[0] and len({e.id for e in puts[0]}) == len(puts[0])
    assert len(serialized) == len(set(serialized))
    ordinary = [playbook for playbook in sweep.pack if playbook.kind != "baseline"]
    assert singles == [] and len(batches) == 1 and len(batches[0]) == len(ordinary)
    # A baseline cell and its window observations are one idempotent transaction. An exec_pair cell with no
    # execs has no parent dependency and closes immediately; cells with execs remain compact-staged for replay.
    assert {cell["rule_id"] for cell in baseline_cells} == {
        playbook.id for playbook in sweep.pack if playbook.kind == "baseline"
    }
    sweep.close_stage()


def test_save_evidence_reads_what_is_stored_under_the_write_lock(tmp_path):
    """Without a lease token the store still takes SQLite's write lock before it reads which rows exist, so a deletion
    in another process cannot remove a row it then skips writing."""
    import sqlite3

    import pytest
    repo = _repo(tmp_path)
    with write_txn(repo.engine) as c:
        Repo._lock(c, "h1")
        other = sqlite3.connect(tmp_path / "r.db", timeout=0)
        try:
            with pytest.raises(sqlite3.OperationalError, match="locked"):
                other.execute("BEGIN IMMEDIATE")
        finally:
            other.close()


def test_saving_and_merging_evidence_take_the_write_lock_before_reading_what_is_stored(monkeypatch):
    """Both write paths lock before they read existing rows, with or without a lease token."""
    repo = _repo()
    calls = []
    real_lock, real_stored = Repo._lock, Repo._stored_events
    monkeypatch.setattr(Repo, "_lock", staticmethod(lambda c, hunt: calls.append("lock") or real_lock(c, hunt)))
    monkeypatch.setattr(Repo, "_stored_events",
                        staticmethod(lambda c, ids: calls.append("read") or real_stored(c, ids)))
    event = _event(1)
    repo.save_evidence("h1", [event], {}, None)
    assert calls and calls[0] == "lock" and "read" in calls
    calls.clear()
    repo.merge_evidence_raw("h1", [event], {})
    assert calls and calls[0] == "lock"
