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
