"""Parent carry across hours another hunt already covered: the kept per-hour carry input makes a built store resolve
exec-pair children exactly as an empty store does."""
from __future__ import annotations

import random
import time
from datetime import UTC, datetime, timedelta

import pytest

from romulus.baseline import CarryInStore, PendingResolver
from romulus.baseline.carry import BEFORE_HISTORY
from romulus.baseline.lookback import LookbackBudget, LookbackWriter
from romulus.baseline.spec import SPEC_BY_ID, Pending
from romulus.evidence.typed import Outcome, RawRef, TypedEvent, fv
from romulus.store.db import make_engine, migrate
from romulus.store.repo import Repo
from tests.test_baseline_lookback import FakeHistory

START = datetime(2026, 2, 3, tzinfo=UTC)
H = timedelta(hours=1)
PAIR = SPEC_BY_ID["bl.exec_pair"]


def _repo() -> Repo:
    repo = Repo(make_engine(":memory:"))
    migrate(repo.engine)
    return repo


def _exec(event_id, ts, pid, ppid, executable, *, host="web01", boot="boot-a", outcome=Outcome.success,
          serial=None):
    fields = {"process.pid": fv(pid, "fixture"), "process.ppid": fv(ppid, "fixture"),
              "process.executable": fv(executable, "fixture")}
    if boot is not None:
        fields["host.boot.id"] = fv(boot, "fixture")
    if serial is not None:
        fields["audit.serial"] = fv(serial, "fixture")
    return TypedEvent(id=event_id, family="process_exec", ts=ts, host=host, outcome=outcome, fields=fields,
                      raw=[RawRef(target="host-index", native_id=event_id)], normalizer="fixture@1")


def _observed(event_id, ts, pid, ppid, executable, *, host="web01", boot="boot-a", session=7):
    native = f"n-{event_id}"
    origin = f"{native}:event.original#auditd:SYSCALL"
    return TypedEvent(
        id=event_id, family="process_observed", ts=ts, host=host, outcome=Outcome.success,
        fields={"process.pid": fv(pid, f"{origin}.pid"), "process.ppid": fv(ppid, f"{origin}.ppid"),
                "process.executable": fv(executable, f"{origin}.exe"), "host.boot.id": fv(boot, "fixture"),
                "process.session_id": fv(session, "fixture")},
        raw=[RawRef(target="host-index", native_id=native)], normalizer="fixture@1",
    )


def _writer(repo, source, carry, *, queries=500):
    return LookbackWriter(
        repo, source, site="site", specs=[PAIR], normalizer="fixture@1",
        budget=LookbackBudget(queries=queries, records=1_000_000, seconds=600), parent_carry=carry,
        now=lambda: START,
    )


def _resolve(repo, hunt_id, events, pendings, *, hours, queries=500):
    repo.create_hunt(hunt_id, {}, f"manifest-{hunt_id}", "test")
    root = CarryInStore(repo, hunt_id)
    source = FakeHistory(events)
    result = _writer(repo, source, root, queries=queries).fill(
        hunt_id=hunt_id, targets=["host-index"], start=START - hours * H, end=START)
    carry = root.for_target("host-index", horizon=START + H)
    carry.mark_observed(START, START + H)   # the window hour, as the window cells mark it
    resolver = PendingResolver(carry, PAIR)
    out = []
    for pending in pendings:
        resolution = resolver.resolve(pending)
        out.append((pending.event_id, tuple(key.key_digest for key in resolution.keys), resolution.reason))
    return out, source, result


def _scenario():
    """History hours START-6h .. START on two hosts, with the cases that make carry input order-sensitive."""
    t = lambda hours, minutes=0: START - hours * H + timedelta(minutes=minutes)
    events = [
        # a long-lived parent exec'd early, then three execs of one pid in one hour (two kept, one evicted)
        _exec("p-apache", t(6, 5), 100, 1, "/usr/sbin/apache2"),
        _exec("r1", t(5, 1), 200, 1, "/bin/a"), _exec("r2", t(5, 2), 200, 1, "/bin/b"),
        _exec("r3", t(5, 3), 200, 1, "/bin/c"),
        # pid reuse across the seam between the history hours
        _exec("reuse-old", t(4, 10), 300, 1, "/usr/bin/old"), _exec("reuse-new", t(1, 10), 300, 1, "/usr/bin/new"),
        # one instant, two images, no serials: ambiguous
        _exec("amb1", t(3, 20), 400, 1, "/bin/x"), _exec("amb2", t(3, 20), 400, 1, "/bin/y"),
        # an exec of unknown outcome breaks its own host in its hour (and leaves that hour's exec pairs unknown)
        _exec("unknown", t(2, 30), 500, 1, "/bin/z", host="misc01", outcome=Outcome.unknown),
        _exec("misc", t(4, 30), 500, 1, "/bin/w", host="misc01"),
        # the second host reboots inside the history
        _exec("db-old", t(5, 0), 10, 1, "/usr/sbin/postgres", host="db01", boot="boot-1"),
        _exec("db-new", t(2, 0), 10, 1, "/usr/sbin/postgres", host="db01", boot="boot-2"),
        # a long-lived parent seen only through process observations
        _observed("obs1", t(3, 5), 600, 1, "/usr/sbin/sshd"), _observed("obs2", t(3, 6), 600, 1, "/usr/sbin/sshd"),
        _observed("obs3", t(1, 6), 600, 1, "/usr/sbin/sshd"),
    ]
    child = lambda index, host, boot, ppid: Pending(host, boot, ppid, START + timedelta(minutes=index),
                                                    f"child-{index}", "/bin/sh")
    pendings = [
        child(1, "web01", "boot-a", 100),   # long-lived parent: resolves
        child(2, "web01", "boot-a", 200),   # the latest of three execs
        child(3, "web01", "boot-a", 300),   # the reused pid's newer image
        child(4, "web01", "boot-a", 400),   # ambiguous
        child(5, "misc01", "boot-a", 500),  # behind an unknown-outcome exec
        child(6, "db01", "boot-2", 10),     # current boot
        child(7, "db01", "boot-1", 10),     # former boot
        child(8, "web01", "boot-a", 600),   # observed long-lived parent
        child(9, "web01", "boot-a", 999),   # never exec'd in history
    ]
    return events, pendings


def test_a_second_hunt_on_a_built_store_resolves_exec_pair_children_like_an_empty_store():
    events, pendings = _scenario()
    built = _repo()
    first, _source, _result = _resolve(built, "hunt-1", events, pendings, hours=6)
    second, second_source, _ = _resolve(built, "hunt-2", events, pendings, hours=6)
    empty, _source, _ = _resolve(_repo(), "hunt-e", events, pendings, hours=6)

    # the second hunt read again only the hour no segment covers (its unknown-outcome exec leaves exec pairs
    # unresolved there); every covered hour fed its carry from the kept input
    assert [start for _target, start in second_source.plans] == [START - 2 * H]
    assert second == empty == first
    resolved = {event_id for event_id, keys, _reason in empty if keys}
    assert {"child-1", "child-2", "child-3", "child-6"} <= resolved
    assert "child-4" not in resolved and "child-7" not in resolved and "child-9" not in resolved


def _covered_without_carry_input(events, pendings):
    """A store whose hours are covered by segments but hold no carry input (as hunt-derived hours do)."""
    from romulus.store import schema

    store = _repo()
    _resolve(store, "builder", events, pendings, hours=6)
    with store.engine.begin() as connection:
        connection.execute(schema.baseline_carry_hour.delete())
    assert store.baseline_segments(statuses=["active"])
    return store


def test_a_covered_hour_without_kept_carry_input_is_read_again_for_the_carry_alone():
    events, pendings = _scenario()
    store = _covered_without_carry_input(events, pendings)

    later, source, result = _resolve(store, "hunt-2", events, pendings, hours=6)
    empty, _source, empty_result = _resolve(_repo(), "hunt-e", events, pendings, hours=6)

    assert len(source.plans) == 6 and result.gaps == empty_result.gaps
    assert later == empty


def test_a_covered_hour_the_budget_cannot_read_again_stays_unobserved_honestly():
    events, pendings = _scenario()
    store = _covered_without_carry_input(events, pendings)

    later, source, result = _resolve(store, "hunt-2", events, pendings, hours=6, queries=2)

    # one hour (a planning and a fetch query) is read again for the carry; the older ones stay unobserved; the
    # only gap is the uncovered hour's, which the budget left unread
    assert len(source.plans) == 1
    assert [(gap.start, gap.state) for gap in result.gaps] == [(START - 2 * H, "omitted_budget")]
    # the parent's hour was never fed: the child stays unresolved, never resolved to an older generation
    resolved = {event_id: (keys, reason) for event_id, keys, reason in later}
    assert resolved["child-1"] == ((), BEFORE_HISTORY)


def test_carry_input_of_another_normalizer_is_never_replayed():
    events, pendings = _scenario()
    store = _repo()
    _resolve(store, "hunt-1", events, pendings, hours=6)
    store.create_hunt("hunt-2", {}, "manifest-hunt-2", "test")
    source = FakeHistory(events)
    LookbackWriter(
        store, source, site="site", specs=[PAIR], normalizer="fixture@2",
        budget=LookbackBudget(queries=500, records=1_000_000, seconds=600),
        parent_carry=CarryInStore(store, "hunt-2"), now=lambda: START,
    ).fill(hunt_id="hunt-2", targets=["host-index"], start=START - 6 * H, end=START)

    # a new normalizer has no segments or carry input yet, so every hour is read
    assert len(source.plans) == 6


@pytest.mark.slow
def test_many_hosts_and_pids_over_two_days_resolve_alike_on_built_and_empty_stores():
    rng = random.Random(11)
    hours = 48
    events, pendings = [], []
    for host_index in range(12):
        host = f"host{host_index:02d}"
        boot = "boot-a"
        for hour in range(hours, 0, -1):
            if host_index % 5 == 0 and hour == 20:
                boot = "boot-b"   # some hosts reboot inside the history
            for _ in range(60):
                pid = rng.randrange(100, 400)
                minute = rng.randrange(60)
                events.append(_exec(f"{host}-{hour}-{len(events)}", START - hour * H + timedelta(minutes=minute),
                                    pid, 1, f"/opt/{rng.randrange(40)}", host=host, boot=boot,
                                    serial=len(events)))
        for index in range(40):
            pendings.append(Pending(host, boot, rng.randrange(100, 400), START + timedelta(seconds=index * 30),
                                    f"{host}-child-{index}", "/bin/sh"))
    built = _repo()
    _resolve(built, "hunt-1", events, pendings, hours=hours)
    began = time.perf_counter()
    second, source, _ = _resolve(built, "hunt-2", events, pendings, hours=hours)
    replayed_in = time.perf_counter() - began
    empty, _source, _ = _resolve(_repo(), "hunt-e", events, pendings, hours=hours)

    assert source.fetches == []
    assert second == empty
    assert sum(1 for _, keys, _reason in empty if keys) > len(pendings) // 2
    print(f"carry replay: {len(events)} execs over {hours} hours replayed in {replayed_in:.1f}s")
