"""Batched store writes: one compiled statement executed over many rows, the same conflict rules, any batch size;
one transaction for a partition's coverage cells; each staged event serialized once per partition."""
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select

from romulus.evidence.typed import Outcome, RawRef, TypedEvent, fv
from romulus.hunt import stage as stage_mod
from romulus.hunt import sweep as sw
from romulus.sources.models import Completeness, SearchOutcome, Window
from romulus.store import schema as t
from romulus.store.db import make_engine, migrate, write_txn
from romulus.store.repo import Repo, _upsert_ignore

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
    batches, singles = [], []
    real_cells, real_cell = repo.set_rule_cells, repo.set_rule_cell
    monkeypatch.setattr(repo, "set_rule_cells", lambda *a, **k: batches.append(a[1]) or real_cells(*a, **k))
    monkeypatch.setattr(repo, "set_rule_cell", lambda *a, **k: singles.append(a) or real_cell(*a, **k))
    w = Window(start=T0, end=T0 + timedelta(minutes=5))
    sweep = sw.Sweep(repo, None, "h1", w, {"romulus-network-x": None}, stage_dir=tmp_path)
    assert sum(pb.staged for pb in sweep.pack) >= 2       # several joining playbooks stage the same flows
    sweep.run_partition("romulus-network-x", None, [], w, est=len(records))
    assert len(puts) == 1 and puts[0] and len({e.id for e in puts[0]}) == len(puts[0])
    assert len(serialized) == len(set(serialized))
    assert singles == [] and len(batches) == 1 and len(batches[0]) == len(sweep.pack)
    sweep.close_stage()
