"""Disk-backed, boot-safe process parent carry-in."""
from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta

import pytest

from romulus.baseline.carry import CarryInStore, ParentExec, ParentObservation, PendingResolver
from romulus.baseline.spec import Pending
from romulus.evidence.typed import Outcome, TypedEvent, fv
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
    store.observe_observation_rows([_observed(11, 2, "/observed")])
    repo.set_hunt_state("hunt", "canceled")
    repo.delete_hunt("hunt", actor="test")
    assert repo.baseline_parent_count("hunt") == 0
    assert repo.baseline_parent_observation_count("hunt") == 0


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
    assert init.reason is None and init.keys[0].key["parent_executable"] == "init"
    assert kthreadd.reason is None and kthreadd.keys[0].key["parent_executable"] == "kthreadd"


def _observed(pid: int, seconds: float, executable: str, *, ppid: int = 1,
              boot: str = "boot-a", serial: int | None = None, session: int | None = 9) -> ParentObservation:
    return ParentObservation(
        "host", boot, pid, START + timedelta(seconds=seconds), executable, ppid,
        session, f"observed-{pid}-{seconds}-{executable}", serial,
    )


def _unknown_exec(pid: int, seconds: float) -> TypedEvent:
    return TypedEvent(
        id=f"unknown-{pid}-{seconds}", family="process_exec",
        ts=START + timedelta(seconds=seconds), host="host", outcome=Outcome.unknown,
        fields={
            "process.pid": fv(pid, "fixture"), "process.ppid": fv(1, "fixture"),
            "process.executable": fv("/unknown", "fixture"), "host.boot.id": fv("boot-a", "fixture"),
        },
        raw=[], normalizer="fixture@1",
    )


def test_long_lived_parent_resolves_from_a_same_boot_observed_image():
    repo, store = _store()
    store.observe_observation_rows([_observed(10, 1, "/usr/sbin/nginx")])

    resolved = PendingResolver(store).resolve(Pending(
        "host", "boot-a", 10, START + timedelta(seconds=20), "child", "/bin/sh",
    ))

    assert resolved.reason is None
    assert resolved.keys[0].key == {
        "child_executable": "/bin/sh", "parent_executable": "/usr/sbin/nginx",
    }
    assert repo.baseline_parent_observation_count("hunt") == 1


def test_an_observed_image_without_a_recorded_boot_is_never_used_as_carry_in():
    repo, store = _store()
    store.observe_observation_rows([_observed(10, 1, "/usr/sbin/nginx", boot="")])

    resolved = PendingResolver(store).resolve(Pending(
        "host", None, 10, START + timedelta(seconds=20), "child", "/bin/sh",
    ))

    assert repo.baseline_parent_observation_count("hunt") == 0
    assert resolved.keys == () and resolved.reason == "parent boot is not recorded"


def test_a_successful_exec_supersedes_an_older_observed_image():
    _repo, store = _store()
    store.observe_observation_rows([_observed(10, 1, "/usr/sbin/nginx")])
    store.observe_rows([_row(10, 10, "/usr/bin/reloaded")])

    resolved = PendingResolver(store).resolve(Pending(
        "host", "boot-a", 10, START + timedelta(seconds=20), "child", "/bin/sh",
    ))

    assert resolved.reason is None
    assert resolved.keys[0].key["parent_executable"] == "/usr/bin/reloaded"


def test_an_unknown_exec_between_observation_and_child_keeps_the_parent_unresolved():
    _repo, store = _store()
    store.observe_observation_rows([_observed(10, 1, "/usr/sbin/nginx")])
    store.observe_events([_unknown_exec(10, 10)])
    uncarried, _hostless = store.take_uncarried()
    store.record_breaks(uncarried)

    resolved = PendingResolver(store).resolve(Pending(
        "host", "boot-a", 10, START + timedelta(seconds=20), "child", "/bin/sh",
    ))

    assert resolved.keys == () and "not carried" in resolved.reason


def test_observed_parent_pid_reuse_is_ambiguous_never_joined_to_the_old_process():
    _repo, store = _store()
    store.observe_observation_rows([
        _observed(10, 1, "/usr/sbin/nginx", ppid=1, session=9),
        _observed(10, 30, "/usr/bin/unrelated", ppid=20, session=10),
    ])

    resolved = PendingResolver(store).resolve(Pending(
        "host", "boot-a", 10, START + timedelta(seconds=20), "child", "/bin/sh",
    ))

    assert resolved.keys == () and "ambiguous" in resolved.reason


def test_observed_parent_same_instant_tie_without_serials_is_unresolved():
    _repo, store = _store()
    store.observe_observation_rows([
        _observed(10, 20, "/usr/sbin/nginx"),
        _observed(10, 20, "/usr/bin/unrelated"),
    ])

    resolved = PendingResolver(store).resolve(Pending(
        "host", "boot-a", 10, START + timedelta(seconds=20), "child", "/bin/sh",
    ))

    assert resolved.keys == () and "ambiguous" in resolved.reason


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


def test_resolved_pending_key_is_the_spec_extractor_key_under_its_own_key_version():
    from dataclasses import replace

    from romulus.baseline.spec import SPEC_BY_ID, KeyContext
    from romulus.evidence.typed import Outcome, TypedEvent, fv

    _repo, store = _store()
    store.observe_rows([_row(10, 1, "/parent")])
    spec = replace(SPEC_BY_ID["bl.exec_pair"], key_version="7")
    child_ts = START + timedelta(seconds=2)
    resolved = PendingResolver(store, spec).resolve(Pending("host", "boot-a", 10, child_ts, "child", "/bin/sh"))
    child = TypedEvent(
        id="child", family="process_exec", ts=child_ts, host="host", outcome=Outcome.success,
        fields={"process.executable": fv("/bin/sh", "f"), "process.ppid": fv(10, "f"),
                "host.boot.id": fv("boot-a", "f")}, raw=[], normalizer="f@1",
    )

    class Parents:
        def lookup(self, host, pid, ts, boot=None):
            return (0.0, "/parent", 1, "r", boot)

    direct = spec.keys(child, KeyContext(pid_table=Parents()))
    assert resolved.keys == tuple(direct)


@pytest.mark.parametrize("chunk_size", [1, 100], ids=["store-upsert", "buffer"])
def test_equal_time_generations_order_by_serial_or_stay_ambiguous(chunk_size):
    def parent_at(store, seconds):
        return store.parent("host", 10, START + timedelta(seconds=seconds), "boot-a")

    def exec_(seconds, executable, serial):
        return ParentExec("host", "boot-a", 10, START + timedelta(seconds=seconds), executable, 1, executable, serial)

    _repo, ordered = _store()
    ordered.observe_rows([exec_(1, "/usr/bin/python3", 101), exec_(1, "/usr/bin/env", 100)], chunk_size=chunk_size)
    assert parent_at(ordered, 2)[0][1] == "/usr/bin/python3"

    _repo, unordered = _store()
    unordered.observe_rows([exec_(1, "/usr/bin/env", None), exec_(1, "/usr/bin/python3", None)],
                           chunk_size=chunk_size)
    assert parent_at(unordered, 2) == (None, "an exec of the host between parent and child was not carried")
    # Ambiguity follows the generation when a newer exec pushes it to the previous slot.
    unordered.observe_rows([exec_(5, "/usr/bin/later", None)], chunk_size=chunk_size)
    assert parent_at(unordered, 3) == (None, "an exec of the host between parent and child was not carried")
    assert parent_at(unordered, 6)[0][1] == "/usr/bin/later"

    _repo, refed = _store()
    for _ in range(2):
        refed.observe_rows([exec_(1, "/usr/bin/env", None)], chunk_size=chunk_size)
    assert parent_at(refed, 2)[0][1] == "/usr/bin/env"


def test_pending_resolver_over_a_pid_table_orders_the_parents_execs_at_the_childs_instant_by_serial():
    """A resolver over an in-memory pid table asks with the child's serial: the parent's exec before it (a lower
    serial at the same instant) is the parent, not the exec that replaced it after the child started."""
    from romulus.detect.correlation import PidTable
    from romulus.evidence.typed import Outcome, RawRef, TypedEvent, fv

    def exec_(event_id, executable, serial):
        fields = {"process.pid": 10, "process.ppid": 1, "process.executable": executable, "audit.serial": serial,
                  "host.boot.id": "boot-a"}
        return TypedEvent(id=event_id, family="process_exec", ts=START, host="host", outcome=Outcome.success,
                          fields={name: fv(value, f"{event_id}:{name}") for name, value in fields.items()},
                          raw=[RawRef(target="t", native_id=event_id, digest="d")], normalizer="test@1")

    table = PidTable()
    table.add(exec_("bash", "/usr/bin/bash", 100))
    table.add(exec_("cat", "/usr/bin/cat", 102))
    resolved = PendingResolver(table).resolve(Pending("host", "boot-a", 10, START, "child", "/bin/sh", 101))

    assert resolved.reason is None
    assert resolved.keys[0].key == {"child_executable": "/bin/sh", "parent_executable": "/usr/bin/bash"}
