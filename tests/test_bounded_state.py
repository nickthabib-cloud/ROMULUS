"""Bounded detector state: the re-delivery guard, and how a reached state budget reaches the coverage ledger."""
from datetime import UTC, datetime, timedelta

from romulus.detect.base import Playbook
from romulus.detect.bounded import RecentIds
from romulus.evidence.typed import RawRef, TypedEvent, fv
from romulus.hunt import sweep as sw
from romulus.sources.models import Completeness, SearchOutcome, Window
from romulus.store.db import make_engine, migrate
from romulus.store.repo import Repo

START = datetime(2024, 11, 18, 14, 0, tzinfo=UTC)


def test_recent_ids_recognise_a_redelivered_batch_and_stay_bounded():
    guard = RecentIds(limit=1000)
    batch = [f"e{i}" for i in range(800)]
    for key in batch:
        guard.add(key)
    assert all(key in guard for key in batch)           # the same batch handed over again is recognised
    for i in range(1_000_000):
        guard.add(f"x{i}")
        assert len(guard) <= 2 * guard.limit
    assert "x999999" in guard and "e0" not in guard


class _Capped(Playbook):
    """An aggregate that can only hold two keys: every record of a third key is refused."""
    id = "test.capped"
    title = "test"
    kind = "aggregate"
    families = ("process_exec",)
    assures_negative = True

    def __init__(self):
        super().__init__()
        self.keys: set[str] = set()

    def consume(self, events):
        for e in self.applicable(events):
            key = e.host or ""
            if key not in self.keys and len(self.keys) >= 2:
                self.evaluated -= 1
                self.refuse("keys", "at most 2 hosts are tracked")
                continue
            self.keys.add(key)
        return []


class _FinalizeLimited(_Capped):
    id = "test.finalize_limited"

    def consume(self, events):
        self.applicable(events)
        return []

    def finalize(self):
        self.note_limit("history", "older history was released; a count is a lower bound")
        return []


def _event(i: int, host: str) -> TypedEvent:
    return TypedEvent(id=f"e{i}", family="process_exec", ts=START + timedelta(seconds=i), host=host,
                      fields={"process.pid": fv(i, "test")}, raw=[RawRef(target="i", native_id=f"r{i}")],
                      normalizer="test")


def _run(monkeypatch, playbook: Playbook, events: list[TypedEvent]):
    engine = make_engine(":memory:")
    migrate(engine)
    repo = Repo(engine)
    repo.create_hunt("h1", {"targets": ["romulus-host-x"]}, "d", "t")
    now = datetime.now(UTC)
    monkeypatch.setattr(sw, "execute", lambda client, intent, contract: SearchOutcome(
        target=intent.target, fingerprint="f", started_at=now, ended_at=now, completeness=Completeness.complete,
        total=0, total_relation="eq", returned=0, records=[]))
    monkeypatch.setattr(sw, "normalize_hits", lambda records, boots: (events, {}, []))
    window = Window(start=START, end=START + timedelta(minutes=5))
    sweep = sw.Sweep(repo, object(), "h1", window, {"romulus-host-x": None})
    sweep.pack = [playbook]
    sweep.run_partition("romulus-host-x", None, [], window, est=1)
    sweep.finalize()
    return {(c["target"], c["partition"]): c for c in repo.rule_cells("h1")}


def test_a_refused_record_makes_the_partition_and_the_window_partial_and_names_the_limit(monkeypatch):
    cells = _run(monkeypatch, _Capped(), [_event(i, f"host{i % 3}") for i in range(9)])
    part = next(c for (target, _p), c in cells.items() if target == "romulus-host-x")
    window = cells[("*", "window")]
    assert part["state"] == "evaluated_partial" and part["evaluated"] == 6
    assert part["detail"]["state_capped"] == 3
    assert any("at most 2 hosts are tracked (3 record(s) not evaluated)" in r for r in part["detail"]["reasons"])
    assert window["state"] == "evaluated_partial"
    assert any("at most 2 hosts are tracked" in r for r in window["detail"]["reasons"])


def test_a_limit_reached_at_finalize_makes_the_window_partial(monkeypatch):
    cells = _run(monkeypatch, _FinalizeLimited(), [_event(i, "host") for i in range(3)])
    part = next(c for (target, _p), c in cells.items() if target == "romulus-host-x")
    window = cells[("*", "window")]
    assert part["state"] == "evaluated_complete" and "state_capped" not in part["detail"]
    assert window["state"] == "evaluated_partial"
    assert "state limit: older history was released; a count is a lower bound" in window["detail"]["reasons"]


def test_without_a_reached_limit_cells_are_unchanged(monkeypatch):
    cells = _run(monkeypatch, _Capped(), [_event(i, f"host{i % 2}") for i in range(4)])
    window = cells[("*", "window")]
    assert window["state"] == "no_match_complete" and window["detail"]["reasons"] == []


# ---- the disk-backed keyed store --------------------------------------------------------------------------------
class _Owner(Playbook):
    id = "test.owner"
    title = "test"
    families = ()


def test_keyed_store_moves_cold_state_to_disk_and_reads_it_back_exactly(tmp_path):
    from romulus.detect.bounded import KeyedStore
    owner = _Owner()
    owner.spill_dir = tmp_path
    store = KeyedStore(owner, "s", hot=10, candidate=lambda state: state["n"] >= 3)
    for i in range(5000):
        state = store.setdefault(f"k{i % 1000}", lambda: {"n": 0, "seen": []})
        state["n"] += 1
        state["seen"].append(i)
        if i % 100 == 99:
            store.trim()
            assert len(store.hot) <= 10
    store.trim()
    assert len(store) == 1000 and store.on_disk >= 990
    assert store.get("k7") == {"n": 5, "seen": [7, 1007, 2007, 3007, 4007]}       # never forgotten
    assert "k999" in store and "nope" not in store
    assert sum(1 for _ in store.items()) == 1000
    assert sum(1 for _ in store.items(candidates=True)) == 1000                    # every key reached n >= 3
    owner.close_spill()
    assert not list(tmp_path.glob("romulus-stage-spill-*"))


def test_only_the_disk_budget_refuses_a_new_key(tmp_path):
    from romulus.detect.bounded import KeyedStore
    owner = _Owner()
    owner.spill_dir = tmp_path
    store = KeyedStore(owner, "s", hot=1, disk_budget=200)
    accepted = 0
    for i in range(100):
        if store.put(f"k{i}", {"payload": "x" * 50}):
            accepted += 1
        store.trim()
    assert 1 < accepted < 100 and store.disk_bytes >= 200
    assert store.get("k0") == {"payload": "x" * 50}                               # what was held is kept
    owner.close_spill()


def test_grouped_reads_a_group_together_and_spill_list_keeps_order(tmp_path):
    from romulus.detect.bounded import KeyedStore, SpillList
    owner = _Owner()
    owner.spill_dir = tmp_path
    store = KeyedStore(owner, "g", hot=2, group=lambda key: key[0])
    for i in range(30):
        store.put((f"g{i % 3}", i), i)
        store.trim()
    groups = [key[0] for key, _value in store.grouped()]
    assert groups == sorted(groups) and len(groups) == 30
    records = SpillList(owner, "l", hot=5)
    for i in range(53):
        records.append(i)
        records.trim()
    assert list(records) == list(range(53)) and records.on_disk >= 48
    owner.close_spill()


def test_a_live_spill_is_marked_fresh_for_the_stale_stage_cleanup(tmp_path):
    import os
    import time

    from romulus.hunt.stage import clear_stale_stages
    owner = _Owner()
    owner.spill_dir = tmp_path
    spill = owner.spill()
    old = time.time() - 7 * 3600
    os.utime(spill._dir, (old, old))
    spill.flush()                                    # any write marks it live again
    assert clear_stale_stages(tmp_path) == 0 and owner.spill() is spill
    owner.close_spill()


def test_each_partition_names_only_its_own_refused_records(monkeypatch):
    engine = make_engine(":memory:")
    migrate(engine)
    repo = Repo(engine)
    repo.create_hunt("h1", {"targets": ["romulus-host-x"]}, "d", "t")
    now = datetime.now(UTC)
    monkeypatch.setattr(sw, "execute", lambda client, intent, contract: SearchOutcome(
        target=intent.target, fingerprint="f", started_at=now, ended_at=now, completeness=Completeness.complete,
        total=0, total_relation="eq", returned=0, records=[]))
    batches = iter([[_event(i, f"host{i % 3}") for i in range(6)],          # host2 refused: 2 records
                    [_event(i, f"host{i % 4}") for i in range(6, 14)]])     # host2 and host3 refused: 4 records
    monkeypatch.setattr(sw, "normalize_hits", lambda records, boots: (next(batches), {}, []))
    sweep = sw.Sweep(repo, object(), "h1", Window(start=START, end=START + timedelta(minutes=10)),
                     {"romulus-host-x": None})
    sweep.pack = [_Capped()]
    for minutes in (0, 5):
        start = START + timedelta(minutes=minutes)
        sweep.run_partition("romulus-host-x", None, [], Window(start=start, end=start + timedelta(minutes=5)), est=1)
    sweep.finalize()
    cells = repo.rule_cells("h1")
    parts = sorted((c for c in cells if c["target"] == "romulus-host-x"), key=lambda c: c["partition"])
    assert [c["detail"]["state_capped"] for c in parts] == [2, 4]
    assert any("at most 2 hosts are tracked (2 record(s) not evaluated)" in r for r in parts[0]["detail"]["reasons"])
    assert any("at most 2 hosts are tracked (4 record(s) not evaluated)" in r for r in parts[1]["detail"]["reasons"])
    window = next(c for c in cells if c["target"] == "*")
    assert any("(6 record(s) not evaluated)" in r for r in window["detail"]["reasons"])
