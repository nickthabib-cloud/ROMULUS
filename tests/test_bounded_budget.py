"""The hunt's state budget: disk total, free-space reserve, failed writes, memory-sized hot sets, canonical keys and
first-insertion order. Reaching any disk limit makes coverage partial with the reason named; the hunt completes."""
import os
import sqlite3
import time
from datetime import UTC, datetime, timedelta
from typing import NamedTuple

import pytest

from romulus.detect import bounded
from romulus.detect.base import Playbook
from romulus.detect.bounded import KeyedStore, Spill, SpillList, StateBudget, StateExhausted
from romulus.evidence.typed import RawRef, TypedEvent, fv
from romulus.hunt import sweep as sw
from romulus.sources.models import Completeness, SearchOutcome, Window
from romulus.store.db import make_engine, migrate
from romulus.store.repo import Repo

START = datetime(2024, 11, 18, 14, 0, tzinfo=UTC)


class _Owner(Playbook):
    id = "test.owner"
    title = "test"
    families = ()


class _Growing(Playbook):
    """Keeps every record's text under its host, hot set 1, so state moves to disk at every batch end and an
    existing host's state grows; finalize reads every state back."""
    id = "test.growing"
    title = "test"
    kind = "aggregate"
    families = ("process_exec",)

    def __init__(self):
        super().__init__()
        self.notes = KeyedStore(self, "notes", 1)

    def consume(self, events):
        for e in self.applicable(events):
            state = self.notes.setdefault(e.host, list)
            state.append(e.id + "x" * 2000)          # distinct strings (pickle would share one object)
        self.notes.trim()
        return []

    def finalize(self):
        self.held = sum(len(v) for _k, v in self.notes.items())
        return []


class _Stateless(Playbook):
    id = "test.stateless"
    title = "test"
    families = ("process_exec",)


def _event(i: int, host: str) -> TypedEvent:
    return TypedEvent(id=f"e{i}", family="process_exec", ts=START + timedelta(seconds=i), host=host,
                      fields={"process.pid": fv(i, "test")}, raw=[RawRef(target="i", native_id=f"r{i}")],
                      normalizer="test")


def _sweep(monkeypatch, tmp_path, pack, batches, budget: StateBudget):
    engine = make_engine(":memory:")
    migrate(engine)
    repo = Repo(engine)
    repo.create_hunt("h1", {"targets": ["romulus-host-x"]}, "d", "t")
    now = datetime.now(UTC)
    monkeypatch.setattr(sw, "execute", lambda client, intent, contract: SearchOutcome(
        target=intent.target, fingerprint="f", started_at=now, ended_at=now, completeness=Completeness.complete,
        total=0, total_relation="eq", returned=0, records=[]))
    feed = iter(batches)
    monkeypatch.setattr(sw, "normalize_hits", lambda records, boots: (next(feed), {}, []))
    monkeypatch.setattr(sw, "state_budget", lambda settings, stage_dir: budget)
    sweep = sw.Sweep(repo, object(), "h1", Window(start=START, end=START + timedelta(hours=1)),
                     {"romulus-host-x": None}, stage_dir=tmp_path)
    sweep.pack = pack
    for pb in pack:
        pb.spill_dir, pb.budget = tmp_path, budget
    for n in range(len(batches)):
        start = START + timedelta(minutes=5 * n)
        sweep.run_partition("romulus-host-x", None, [], Window(start=start, end=start + timedelta(minutes=5)), est=1)
    sweep.finalize()
    cells = repo.rule_cells("h1")
    return sweep, cells


def _batches(n: int, per: int = 20):
    return [[_event(b * per + i, f"host{i % 3}") for i in range(per)] for b in range(n)]


def test_an_exhausted_disk_total_refuses_later_records_and_the_hunt_completes(monkeypatch, tmp_path):
    budget = StateBudget(tmp_path, disk_total=60_000, reserve=0)
    growing, stateless = _Growing(), _Stateless()
    sweep, cells = _sweep(monkeypatch, tmp_path, [growing, stateless], _batches(8), budget)
    assert budget.over_total and budget.disk_used >= 60_000      # growth of existing states counted it
    mine = sorted((c for c in cells if c["rule_id"] == growing.id and c["target"] != "*"),
                  key=lambda c: c["partition"])
    assert mine[0]["state"] == "evaluated_complete"
    assert mine[-1]["state"] == "evaluated_partial" and mine[-1]["evaluated"] == 0
    assert any("state budget is spent" in r for r in mine[-1]["detail"]["reasons"])
    window = next(c for c in cells if c["rule_id"] == growing.id and c["target"] == "*")
    assert window["state"] in ("evaluated_partial", "match_on_partial")
    # a rule that keeps no state is not touched
    assert all(c["state"] == "no_match_complete" for c in cells if c["rule_id"] == stateless.id)
    assert any("state budget" in r for r in sweep.partial_reasons)
    assert sweep.stats["state_budget"]["spent"].startswith("detector state on disk reached")


def test_free_space_below_the_reserve_at_preflight_evaluates_no_stateful_record(monkeypatch, tmp_path):
    monkeypatch.setattr(StateBudget, "free", lambda self: 10)
    budget = StateBudget(tmp_path, disk_total=2**30, reserve=2**30)
    growing = _Growing()
    sweep, cells = _sweep(monkeypatch, tmp_path, [growing, _Stateless()], _batches(2), budget)
    assert any("below the reserve" in r for r in sweep.partial_reasons)
    mine = [c for c in cells if c["rule_id"] == growing.id and c["target"] != "*"]
    assert mine and all(c["state"] == "evaluated_partial" and c["evaluated"] == 0 for c in mine)
    assert all(c["state"] == "no_match_complete" for c in cells if c["rule_id"] == "test.stateless")


def test_free_space_falling_below_the_reserve_during_the_sweep_is_partial_not_a_crash(monkeypatch, tmp_path):
    free = {"bytes": 10 * 2**30}
    monkeypatch.setattr(StateBudget, "free", lambda self: free["bytes"])
    monkeypatch.setattr(bounded, "FREE_CHECK_BYTES", 1)
    budget = StateBudget(tmp_path, disk_total=2**40, reserve=2**30)
    growing = _Growing()
    original = growing.consume

    def consume(events):
        out = original(events)
        if events and events[0].id == "e40":
            free["bytes"] = 100             # the volume fills while the hunt runs
        return out
    growing.consume = consume
    _unused, cells = _sweep(monkeypatch, tmp_path, [growing], _batches(5), budget)
    assert budget.low_space
    mine = sorted((c for c in cells if c["rule_id"] == growing.id and c["target"] != "*"),
                  key=lambda c: c["partition"])
    assert mine[-1]["evaluated"] == 0 and mine[-1]["state"] == "evaluated_partial"
    window = next(c for c in cells if c["rule_id"] == growing.id and c["target"] == "*")
    assert any("finalize stopped" in r or "state limit" in r for r in window["detail"]["reasons"])


class _FullDisk:
    """A connection whose writes fail as SQLite's do on a full volume."""

    def __init__(self, db):
        self._db = db

    def executemany(self, sql, rows):
        raise sqlite3.OperationalError("database or disk is full")

    def __getattr__(self, name):
        return getattr(self._db, name)


def test_a_failed_write_keeps_state_in_memory_and_later_records_are_refused(monkeypatch, tmp_path):
    budget = StateBudget(tmp_path, disk_total=2**40, reserve=0)
    growing = _Growing()
    original = growing.consume

    def consume(events):
        if events and events[0].id == "e20":
            spill = growing.spill()
            spill.db = _FullDisk(spill.db)
        return original(events)
    growing.consume = consume
    _unused, cells = _sweep(monkeypatch, tmp_path, [growing], _batches(4), budget)
    assert budget.broken and "disk is full" in budget.broken
    mine = sorted((c for c in cells if c["rule_id"] == growing.id and c["target"] != "*"),
                  key=lambda c: c["partition"])
    assert [c["evaluated"] for c in mine] == [20, 20, 0, 0]
    assert growing.held == 40                       # what was evaluated is all still held: nothing dropped
    window = next(c for c in cells if c["rule_id"] == growing.id and c["target"] == "*")
    assert window["state"] == "evaluated_partial"
    assert any("state budget is spent" in r for r in window["detail"]["reasons"])


def test_a_store_whose_disk_write_failed_stops_finalize_instead_of_reading_a_partial_table(tmp_path):
    owner = _Owner()
    owner.spill_dir = tmp_path
    owner.budget = StateBudget(tmp_path, disk_total=2**40, reserve=0)
    store = KeyedStore(owner, "b", hot=1)
    for key in ("a", "b", "c"):
        store.put(key, [key])
        store.trim()                                    # "a" and "b" on disk
    spill = owner.spill()
    spill.db = _FullDisk(spill.db)
    store.put("d", ["d"])
    store.trim()                                        # the write fails: "c" and "d" stay in memory
    assert len(store.hot) == 2 and store.broken and owner.budget.broken
    owner.budget.finalizing = True
    with pytest.raises(StateExhausted, match="disk is full"):
        list(store.items())
    owner.close_spill()


def test_finalize_tables_are_charged_and_stop_at_the_reserve(monkeypatch, tmp_path):
    from romulus.detect.correlation import ProcessNetworkLink
    from tests.test_bounded_correlation import T0, flow, sock
    rule = ProcessNetworkLink()
    rule.spill_dir = tmp_path
    rule.budget = StateBudget(tmp_path, disk_total=2**40, reserve=2**30)
    events = [sock(T0 + timedelta(seconds=i), 100 + i, "198.51.100.7", 443) for i in range(50)]
    events += [flow(T0 + timedelta(seconds=i), "10.0.0.5", 40000 + i, "198.51.100.7", 443) for i in range(50)]
    monkeypatch.setattr(StateBudget, "free", lambda self: 10 * 2**30)
    rule.consume(events)
    rule.budget.finalizing = True
    monkeypatch.setattr(StateBudget, "free", lambda self: 10)
    with pytest.raises(StateExhausted, match="below the reserve"):
        rule.finalize()
    rule.release_state()


def test_disk_use_is_the_spill_files_real_growth(tmp_path):
    owner = _Owner()
    owner.spill_dir = tmp_path
    owner.budget = StateBudget(tmp_path, disk_total=2**40, reserve=0)
    store = KeyedStore(owner, "s", hot=1)
    for i in range(2000):
        store.put(f"k{i}", "v" * 100)
        store.trim()
    owner.spill().db.commit()
    size = os.path.getsize(owner.spill().path)
    assert owner.budget.disk_used == size > 200_000
    owner.close_spill()


def test_a_live_spill_written_by_add_is_never_stale(tmp_path):
    from romulus.hunt.stage import clear_stale_stages
    spill = Spill(tmp_path, StateBudget(tmp_path, reserve=0))
    spill.table("t", "a, b")
    old = time.time() - 7 * 3600
    os.utime(spill._dir, (old, old))
    for i in range(bounded.SPILL_BATCH):                # a full batch is written by add
        spill.add("t", (i, "x"))
    assert clear_stale_stages(tmp_path) == 0 and spill.path.exists()
    spill.close()


def test_the_sweep_heartbeat_marks_every_spill_live(monkeypatch, tmp_path):
    from romulus.hunt.stage import clear_stale_stages
    sweep, _cells = _sweep(monkeypatch, tmp_path, [_Growing()], _batches(1), StateBudget(tmp_path, reserve=0))
    owner = _Growing()
    owner.spill_dir = tmp_path
    sweep.pack = [owner]
    spill = owner.spill()
    old = time.time() - 7 * 3600
    os.utime(spill._dir, (old, old))
    sweep.heartbeat()
    assert clear_stale_stages(tmp_path) == 0 and spill.path.exists()
    owner.close_spill()


# ---- keys, order, memory -------------------------------------------------------------------------------------------
class _Pair(NamedTuple):
    host: str
    pid: int


def test_equal_keys_meet_on_disk_whatever_their_identity_or_numeric_type(tmp_path):
    owner = _Owner()
    owner.spill_dir = tmp_path
    store = KeyedStore(owner, "k", hot=1)
    shared = "host-" + "x" * 40
    store.put((shared, shared, 2), "a")                 # the same string object twice: pickle would memoize it
    store.put(("filler", 0), "f")
    store.trim()
    assert store.on_disk == 1
    distinct = ("host-" + "x" * 40, "".join(["host-", "x" * 40]), 2.0)
    assert distinct[0] is not distinct[1]
    assert store.get(distinct) == "a"
    store.put(_Pair("h", 7), "nt")
    store.put(("filler2", 0), "f2")
    store.trim(0)
    assert store.peek(("h", 7)) == "nt" and store.peek(("h", 7.0)) == "nt" and ("h", True) not in store
    assert bounded.key_bytes(("a", 1)) == bounded.key_bytes(("a", True)) == bounded.key_bytes(("a", 1.0))
    assert bounded.key_bytes("('a', 1)") != bounded.key_bytes(("a", 1))
    owner.close_spill()


def test_a_key_never_on_disk_costs_no_query(tmp_path):
    owner = _Owner()
    owner.spill_dir = tmp_path
    store = KeyedStore(owner, "q", hot=10)
    for i in range(100):
        store.put(f"old{i}", i)
    store.trim()
    queries = []
    owner.spill().db.set_trace_callback(queries.append)
    misses = sum(store.get(f"new{i}") is None for i in range(10_000))
    assert misses == 10_000
    assert sum(q.startswith("SELECT") for q in queries) < 300          # Bloom false positives only (about 1%)
    owner.close_spill()


def test_replacing_a_key_held_on_disk_is_not_a_new_key_under_a_spent_budget(tmp_path):
    owner = _Owner()
    owner.spill_dir = tmp_path
    store = KeyedStore(owner, "r", hot=1, disk_budget=1)
    store.put("a", [1])
    store.put("b", [2])
    store.trim()                                        # "a" on disk; the budget is now spent
    assert not store.put("c", [3])                      # a new key is refused
    assert store.put("a", [1, 4]) and store.get("a") == [1, 4]      # an existing one is replaced, not lost
    owner.close_spill()


def test_items_and_keys_keep_first_insertion_order_whatever_the_hot_size(tmp_path):
    def run(hot):
        owner = _Owner()
        owner.spill_dir = tmp_path / str(hot)
        store = KeyedStore(owner, "o", hot=hot)
        for i in range(300):
            key = f"k{(i * 37) % 101}"
            state = store.setdefault(key, list)
            state.append(i)
            store.trim()
        out = (list(store.items()), store.keys(), [k for k, _v in store.items(candidates=True)])
        owner.close_spill()
        return out
    small, large = run(1), run(10_000)
    assert small == large
    assert [k for k, _v in large[0]] == list(dict.fromkeys(f"k{(i * 37) % 101}" for i in range(300)))


def test_the_memory_budget_moves_a_large_hot_set_to_disk_and_keeps_it_exact(tmp_path):
    owner = _Owner()
    owner.spill_dir = tmp_path
    owner.budget = StateBudget(tmp_path, disk_total=2**40, reserve=0, memory_total=2 * 2**20)
    store = KeyedStore(owner, "m", hot=bounded.HOT_COUNT)
    for i in range(20_000):
        store.put(f"k{i}", "v" * 200)
        if i % 1000 == 999:
            store.trim()
    assert store.on_disk > 0 and len(store.hot) < 20_000
    assert owner.budget.mem_used <= 2 * 2**20 * 1.1
    assert len(store) == 20_000 and store.get("k0") == "v" * 200
    owner.close_spill()


def test_spill_list_measures_its_buffer_against_the_memory_budget(tmp_path):
    owner = _Owner()
    owner.spill_dir = tmp_path
    owner.budget = StateBudget(tmp_path, disk_total=2**40, reserve=0, memory_total=2**20)
    records = SpillList(owner, "l", hot=bounded.HOT_COUNT)
    for i in range(20_000):
        records.append(("r", i, "z" * 100))
        if i % 1000 == 999:
            records.trim()
    assert records.on_disk > 0
    assert [r[1] for r in records] == list(range(20_000))
    owner.close_spill()


def test_the_pack_shares_one_exec_lineage_and_observes_each_record_once():
    from romulus.detect.host import ProcessLineage
    from romulus.detect.registry import fresh_pack
    pack = fresh_pack()
    lineages = {id(pb.lineage) for pb in pack if isinstance(getattr(pb, "lineage", None), ProcessLineage)}
    assert len(lineages) == 1
    holders = [pb for pb in pack if isinstance(getattr(pb, "lineage", None), ProcessLineage)]
    assert len(holders) >= 4 and holders[0].lineage.members == holders


def test_settings_reach_the_state_budget(tmp_path):
    from romulus.config import load_settings
    s = load_settings(env_file=tmp_path / "none.env", environ={
        "ROMULUS_HOME": str(tmp_path), "ROMULUS_STATE_DISK_GB": "3", "ROMULUS_STATE_DISK_RESERVE_GB": "0.5",
        "ROMULUS_STATE_MEMORY_MB": "256"})
    budget = sw.state_budget(s, tmp_path)
    assert (budget.disk_total, budget.reserve, budget.memory_total) == (3 * 2**30, 2**29, 256 * 2**20)
    auto = sw.state_budget(load_settings(env_file=tmp_path / "none.env", environ={"ROMULUS_HOME": str(tmp_path)}),
                           tmp_path)
    assert auto.disk_total >= 2**30 and auto.reserve == 2 * 2**30


def _exec(event_id: str, pid: int, seconds: int) -> TypedEvent:
    return TypedEvent(id=event_id, family="process_exec", ts=START + timedelta(seconds=seconds), host="h",
                      fields={"process.pid": fv(pid, "test"), "process.executable": fv("/usr/bin/bash", "test")},
                      raw=[RawRef(target="i", native_id=event_id)], normalizer="test")


def test_an_existing_process_keeps_its_lineage_when_the_disk_budget_is_spent(tmp_path):
    from romulus.detect.host import ProcessLineage
    owner = _Owner()
    owner.spill_dir = tmp_path
    lineage = ProcessLineage(owner)
    lineage.records.hot_size, lineage.records.disk_budget = 1, 1
    lineage.observe(_exec("x1", 100, 0))
    lineage.observe(_exec("y1", 200, 1))
    lineage.observe(_exec("w1", 400, 2))
    lineage.trim()                                      # pids 100 and 200 on disk: the disk budget is spent
    lineage.observe(_exec("x2", 100, 10))               # an existing process: updated, not refused
    assert [a.event_id for a in lineage.records.get(("h", 100))] == ["x1", "x2"]
    assert lineage.parent("h", 100, START.timestamp() + 5).event_id == "x1"
    lineage.observe(_exec("z1", 300, 20))               # a new process is refused, and said
    assert lineage.records.get(("h", 300)) is None and "lineage" in owner.limits
    owner.close_spill()


def test_doctor_reports_a_stage_volume_at_its_reserve(monkeypatch, tmp_path):
    from romulus.config import load_settings
    from romulus.doctor import check_state_budget
    s = load_settings(env_file=tmp_path / "none.env", environ={"ROMULUS_HOME": str(tmp_path)})
    assert check_state_budget(s).status == "ok"
    monkeypatch.setattr(StateBudget, "free", lambda self: 10)
    check = check_state_budget(s)
    assert check.status == "fail" and "below the reserve" in check.detail
