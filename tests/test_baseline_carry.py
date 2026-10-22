"""Disk-backed, boot-safe process parent carry-in."""
from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta

import pytest

from romulus.baseline.carry import CarryInStore, ParentExec, PendingResolver
from romulus.baseline.spec import Pending
from romulus.store.db import make_engine, migrate
from romulus.store.repo import Repo

START = datetime(2026, 1, 1, tzinfo=UTC)


def _store() -> tuple[Repo, CarryInStore]:
    repo = Repo(make_engine(":memory:"))
    migrate(repo.engine)
    repo.create_hunt("hunt", {}, "d", "test")
    store = CarryInStore(repo, "hunt")
    # The fixtures' execs and children share this hour, which the store has fully observed.
    store.mark_observed(START, START + timedelta(hours=1))
    return repo, store


def _row(pid, seconds, executable, *, boot="boot-a", ppid=1):
    return ParentExec("host", boot, pid, START + timedelta(seconds=seconds), executable, ppid, f"raw-{seconds}")


def test_pid_reuse_across_reboot_never_resolves_old_boot():
    repo, store = _store()
    store.observe_rows([_row(10, 1, "/old", boot="boot-a"), _row(10, 2, "/new", boot="boot-b")])

    assert store.lookup("host", 10, (START + timedelta(seconds=3)).timestamp(), "boot-a") is None
    assert store.lookup("host", 10, (START + timedelta(seconds=3)).timestamp(), "boot-b")[1] == "/new"
    assert repo.baseline_parent_count("hunt") == 1


def test_pid_reuse_within_boot_returns_latest_nonempty_exec_before_child():
    _repo, store = _store()
    store.observe_rows([_row(10, 1, "/old"), _row(10, 2, "/new")])
    between = store.lookup("host", 10, (START + timedelta(seconds=1.5)).timestamp(), "boot-a")
    parent = store.lookup("host", 10, (START + timedelta(seconds=3)).timestamp(), "boot-a")
    assert between[1] == "/old"
    assert parent[1] == "/new" and parent[0] == (START + timedelta(seconds=2)).timestamp()
    store.observe_rows([_row(11, 2, "")])
    assert store.lookup("host", 11, (START + timedelta(seconds=3)).timestamp(), "boot-a") is None


def test_newest_first_observation_does_not_roll_back_to_an_older_boot():
    repo, store = _store()
    store.observe_rows([_row(10, 20, "/new", boot="boot-b"), _row(10, 10, "/old", boot="boot-a")])
    assert repo.baseline_parent_count("hunt") == 1
    assert store.lookup("host", 10, (START + timedelta(seconds=30)).timestamp(), "boot-b")[1] == "/new"


def test_marker_cache_overflow_persists_advances_before_reboot_comparison(monkeypatch):
    from romulus.baseline import carry as module

    monkeypatch.setattr(module, "MARKER_CACHE_CAP", 1)
    repo, store = _store()
    store.observe_rows([_row(1, 1, "/cached")])
    store.observe_rows([
        ParentExec("overflow", "boot-a", 10, START + timedelta(seconds=1), "/a1", 1, "a1"),
        ParentExec("overflow", "boot-a", 10, START + timedelta(seconds=3), "/a3", 1, "a3"),
        ParentExec("overflow", "boot-b", 10, START + timedelta(seconds=2), "/b2", 1, "b2"),
    ])

    assert repo.baseline_parent_boot("hunt", "", "overflow") == ("boot-a", START + timedelta(seconds=3))
    assert store.lookup("overflow", 10, (START + timedelta(seconds=4)).timestamp(), "boot-a")[1] == "/a3"
    assert store.lookup("overflow", 10, (START + timedelta(seconds=4)).timestamp(), "boot-b") is None


def test_deleting_hunt_cascades_its_disk_carry_state():
    repo, store = _store()
    store.observe_rows([_row(10, 1, "/parent")])
    repo.set_hunt_state("hunt", "canceled")
    repo.delete_hunt("hunt", actor="test")
    assert repo.baseline_parent_count("hunt") == 0


def test_pending_resolver_produces_key_or_explicit_unresolved_reason():
    _repo, store = _store()
    store.observe_rows([_row(10, 1, "/parent")])
    resolver = PendingResolver(store)
    resolved = resolver.resolve(Pending("host", "boot-a", 10, START + timedelta(seconds=2), "child", "/bin/sh"))
    assert resolved.reason is None
    assert resolved.keys[0].key == {"child_executable": "/bin/sh", "parent_executable": "/parent"}

    before = resolver.resolve(Pending("host", "boot-a", 99, START, "missing", "/bin/sh"))
    init = resolver.resolve(Pending("host", "boot-a", 1, START, "init", "/bin/sh"))
    kthreadd = resolver.resolve(Pending("host", "boot-a", 2, START, "kthreadd", "/bin/sh"))
    assert before.reason == "parent exec before history" and before.keys == ()
    assert init.reason == kthreadd.reason == "parent pid 1/2 out of scope"


@pytest.mark.slow
def test_ten_million_exec_history_is_bounded_by_live_pids():
    repo, store = _store()

    def history():
        for index in range(10_000_000):
            yield _row(index % 1000, index, f"/bin/tool-{index % 7}", ppid=(index - 1) % 1000)

    started = time.perf_counter()
    maximum = store.observe_rows(history(), chunk_size=100_000)
    elapsed = time.perf_counter() - started
    print(f"10m parent execs in {elapsed:.1f}s; max stored live pids {maximum}")
    assert maximum == 1000 and repo.baseline_parent_count("hunt") == 1000
    assert elapsed < 180


def test_lookup_requires_continuous_observation_from_parent_exec_to_child():
    _repo, store = _store()
    store.observe_rows([_row(10, 1, "/old")])
    store.mark_observed(START + timedelta(hours=2), START + timedelta(hours=3))
    child = START + timedelta(hours=2, minutes=5)
    # The hour between the parent's exec and the child was never observed: the PID may have been reused there.
    assert store.lookup("host", 10, child.timestamp(), "boot-a") is None
    explained = PendingResolver(store).resolve(Pending("host", "boot-a", 10, child, "child", "/bin/sh"))
    assert explained.keys == () and explained.reason == "parent exec in an unobserved hour"

    store.mark_observed(START + timedelta(hours=1), START + timedelta(hours=2))
    assert store.lookup("host", 10, child.timestamp(), "boot-a")[1] == "/old"


def test_observed_ledger_stores_ranges_not_hours():
    repo, store = _store()
    for offset in reversed(range(200)):
        hour = START + timedelta(hours=offset)
        store.mark_observed(hour, hour + timedelta(hours=1))
    store.mark_observed(START + timedelta(hours=300), START + timedelta(hours=301))
    assert repo.baseline_parent_observed_ranges("hunt", "") == [
        (START, START + timedelta(hours=200)),
        (START + timedelta(hours=300), START + timedelta(hours=301)),
    ]


def test_host_with_carry_state_in_two_targets_is_never_resolved_from_one():
    repo, store = _store()
    other = CarryInStore(repo, "hunt", target="second-index")
    other.mark_observed(START, START + timedelta(hours=1))
    store.observe_rows([_row(10, 1, "/a")])
    other.observe_rows([_row(10, 2, "/b")])
    child = START + timedelta(seconds=5)
    explained = PendingResolver(store).resolve(Pending("host", "boot-a", 10, child, "child", "/bin/sh"))
    assert explained.keys == () and explained.reason == "host exec history spans targets"


def test_flush_writes_only_the_host_markers_that_changed():
    repo, store = _store()
    store.observe_rows([
        ParentExec(f"host{index}", "boot-a", 100, START, "/bin/x", 1, "r") for index in range(500)
    ])
    writes: list[str] = []
    real = repo.set_baseline_parent_boot

    def counted(hunt_id, target, host, boot, latest_ts):
        writes.append(host)
        return real(hunt_id, target, host, boot, latest_ts)

    repo.set_baseline_parent_boot = counted
    started = time.perf_counter()
    store.observe_rows([ParentExec("host1", "boot-a", 200, START + timedelta(seconds=5), "/bin/y", 1, "r")])
    elapsed = time.perf_counter() - started
    assert writes == ["host1"]
    assert repo.baseline_parent_boot("hunt", "", "host1") == ("boot-a", START + timedelta(seconds=5))
    store.observe_rows([ParentExec("host1", "boot-a", 201, START + timedelta(seconds=4), "/bin/z", 1, "r")])
    assert writes == ["host1"], "an exec that does not advance the marker writes no marker"
    assert elapsed < 0.5
