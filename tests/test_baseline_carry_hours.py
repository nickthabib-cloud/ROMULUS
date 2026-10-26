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


def _writer(repo, source, carry, *, queries=500, **bounds):
    return LookbackWriter(
        repo, source, site="site", specs=[PAIR], normalizer="fixture@1",
        budget=LookbackBudget(queries=queries, records=1_000_000, seconds=600), parent_carry=carry,
        now=lambda: START, **bounds,
    )


def _resolve(repo, hunt_id, events, pendings, *, hours, queries=500, window=START, **bounds):
    repo.create_hunt(hunt_id, {}, f"manifest-{hunt_id}", "test")
    root = CarryInStore(repo, hunt_id)
    source = FakeHistory(events)
    result = _writer(repo, source, root, queries=queries, **bounds).fill(
        hunt_id=hunt_id, targets=["host-index"], start=window - hours * H, end=window)
    carry = root.for_target("host-index", horizon=window + H)
    carry.mark_observed(window, window + H)   # the window hour, as the window cells mark it
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


# ---- bounded carry input: typed rows, a retention horizon and a disk budget --------------------------------------

def _hours_kept(repo) -> list[datetime]:
    from sqlalchemy import select

    from romulus.store import schema

    with repo.engine.connect() as connection:
        return sorted(row[0].replace(tzinfo=UTC) for row in connection.execute(
            select(schema.baseline_carry_hour.c.hour)))


def test_carry_input_rows_are_typed_and_compact():
    events, pendings = _scenario()
    repo = _repo()
    _resolve(repo, "hunt-1", events, pendings, hours=6)

    execs = sum(1 for event in events if event.family == "process_exec")
    # the estimate charged to the budget stays near the measured size of a typed row, not a JSON body
    assert repo.baseline_carry_bytes() < 120 * (execs + 20)
    from romulus.store import schema
    assert {column.name for column in schema.baseline_carry_exec.columns} >= {
        "ref", "pid", "ts_us", "serial", "executable", "parent_pid", "raw_id", "ambiguous",
        "evicted_earliest_us", "evicted_latest_us"}


def test_carry_hours_past_the_retention_horizon_are_pruned_and_read_again_alike():
    events, pendings = _scenario()
    store = _repo()
    _resolve(store, "hunt-1", events, pendings, hours=6)
    old_hours = _hours_kept(store)
    later = START + 48 * H
    shifted = [event.model_copy(update={"ts": event.ts + 48 * H}) for event in events]
    _later, _source, result = _resolve(store, "hunt-2", shifted, [], hours=6, window=later)

    # newest kept hour minus (the 6-hour lookback plus a day): every hour of the first history is past it
    assert result.carry_hours_pruned == len(old_hours)
    assert not set(old_hours) & set(_hours_kept(store))
    # a hunt over the old span reads those hours again and resolves exactly as an empty store does
    again, source, _ = _resolve(store, "hunt-3", events, pendings, hours=6)
    empty, _source, _ = _resolve(_repo(), "hunt-e", events, pendings, hours=6)
    assert len(source.plans) == 6 and again == empty


def test_a_configured_longer_lookback_keeps_carry_hours_longer():
    events, pendings = _scenario()
    store = _repo()
    _resolve(store, "hunt-1", events, pendings, hours=6)
    kept = _hours_kept(store)
    shifted = [event.model_copy(update={"ts": event.ts + 48 * H}) for event in events]

    _later, _source, result = _resolve(store, "hunt-2", shifted, [], hours=6, window=START + 48 * H,
                                       carry_retention=timedelta(days=7))

    assert result.carry_hours_pruned == 0 and set(kept) <= set(_hours_kept(store))


def test_carry_input_over_the_disk_budget_drops_the_oldest_hours_which_are_then_read_again():
    events, pendings = _scenario()
    store = _repo()
    _resolve(store, "hunt-1", events, pendings, hours=6)
    kept = _hours_kept(store)
    total = store.baseline_carry_bytes()

    _again, _source, result = _resolve(store, "hunt-2", events, pendings, hours=6, carry_budget_bytes=total // 2)

    remaining = _hours_kept(store)
    assert result.carry_hours_trimmed > 0 and store.baseline_carry_bytes() <= total // 2
    # the oldest go first
    assert remaining == kept[len(kept) - len(remaining):]
    later, source, _ = _resolve(store, "hunt-3", events, pendings, hours=6)
    empty, _source, _ = _resolve(_repo(), "hunt-e", events, pendings, hours=6)
    assert later == empty and len(source.plans) >= len(kept) - len(remaining)


def test_a_pruned_hour_reads_as_absent_never_partial():
    events, pendings = _scenario()
    store = _repo()
    _resolve(store, "hunt-1", events, pendings, hours=6)
    hour = _hours_kept(store)[0]
    assert store.baseline_carry_hour(site="site", target="host-index", hour=hour, normalizer="fixture@1",
                                     format_=2) is not None

    store.prune_baseline_carry_hours(site="site", target="host-index", before=hour + H)

    from sqlalchemy import func, select

    from romulus.store import schema
    assert store.baseline_carry_hour(site="site", target="host-index", hour=hour, normalizer="fixture@1",
                                     format_=2) is None
    with store.engine.connect() as connection:
        orphans = connection.execute(select(func.count()).select_from(schema.baseline_carry_exec).where(
            schema.baseline_carry_exec.c.carry_seq.not_in(select(schema.baseline_carry_hour.c.seq)))).scalar_one()
    assert orphans == 0


# ---- atomic carry-hour reads -----------------------------------------------------------------------------------

def _two_engines(tmp_path):
    from romulus.baseline.carry import CarryHour, ParentExec, save_carry_hour

    path = tmp_path / "race.db"
    reader = Repo(make_engine(path))
    migrate(reader.engine)
    writer = Repo(make_engine(path))
    carry = CarryHour((ParentExec("web01", "b1", 100, START + timedelta(minutes=5), "/usr/bin/bash", 1, "r1", 7),),
                      (), {}, False)
    save_carry_hour(writer, site="s", target="t", hour=START, normalizer="n", carry=carry)
    return reader, writer


def _prune_between_header_and_rows(reader, writer):
    from sqlalchemy import event

    fired = []

    @event.listens_for(reader.engine, "before_cursor_execute")
    def interleave(_conn, _cursor, statement, *_args):
        if "FROM baseline_carry_host" in statement and not fired:
            fired.append(writer.prune_baseline_carry_hours(site="s", target="t", before=START + H))

    return fired


def test_a_prune_between_the_header_and_its_rows_never_yields_an_empty_observed_hour(tmp_path):
    from romulus.baseline.carry import load_carry_hour

    reader, writer = _two_engines(tmp_path)
    fired = _prune_between_header_and_rows(reader, writer)

    loaded = load_carry_hour(reader, site="s", target="t", hour=START, normalizer="n")

    assert [hours for hours, _bytes in fired] == [1]
    # the read saw one snapshot: the whole hour as it was when the header was read
    assert loaded is not None and [item.executable for item in loaded.execs] == ["/usr/bin/bash"]
    assert load_carry_hour(reader, site="s", target="t", hour=START, normalizer="n") is None


def test_an_hour_read_back_with_other_row_counts_is_not_kept(tmp_path, monkeypatch):
    """Defence in depth: even without a snapshot, the header's row counts expose an hour read short."""
    from contextlib import contextmanager

    from romulus.baseline.carry import load_carry_hour
    from romulus.store import repo as repo_module

    reader, writer = _two_engines(tmp_path)

    @contextmanager
    def no_snapshot(engine):
        with engine.connect() as connection:
            yield connection

    monkeypatch.setattr(repo_module, "read_snapshot", no_snapshot)
    _prune_between_header_and_rows(reader, writer)

    assert load_carry_hour(reader, site="s", target="t", hour=START, normalizer="n") is None


def test_an_hour_with_no_execs_still_loads():
    from romulus.baseline.carry import CarryHour, load_carry_hour, save_carry_hour

    repo = _repo()
    save_carry_hour(repo, site="s", target="t", hour=START, normalizer="n",
                    carry=CarryHour((), (), {"web01": frozenset({(START, START + H)})}, False))

    loaded = load_carry_hour(repo, site="s", target="t", hour=START, normalizer="n")

    assert loaded is not None and loaded.execs == () and loaded.breaks == {"web01": frozenset({(START, START + H)})}


# ---- unrecorded boots are breaks, never silent supersessions -------------------------------------------------

def _child_of(events, pid, *, host="db01", boot="b1"):
    from romulus.baseline.spec import exec_pair_key

    child = Pending(host, boot, pid, START + timedelta(minutes=10), "child", "/bin/sh")
    results = []
    for ordered in (events, list(reversed(events))):
        built = _repo()
        _resolve(built, "hunt-1", ordered, [child], hours=2)
        second, _source, _ = _resolve(built, "hunt-2", ordered, [child], hours=2)
        empty, _source, _ = _resolve(_repo(), "hunt-e", ordered, [child], hours=2)
        assert second == empty
        results.append(empty[0])
    return results, exec_pair_key


def test_an_unknown_boot_reuse_of_a_pid_is_a_break_never_the_pre_reuse_image():
    t = lambda hours, minutes=0: START - hours * H + timedelta(minutes=minutes)
    events = [
        _exec("old-image", t(2, 0), 300, 1, "/usr/bin/old", host="db01", boot="b1"),
        # pid 300 exec'd again by a record whose boot was not recorded: it may be a reuse in boot b1
        _exec("reuse-unknown-boot", t(1, 5), 300, 1, "/tmp/implant", host="db01", boot=None),
        _exec("later", t(1, 59), 400, 1, "/usr/bin/id", host="db01", boot="b1"),
    ]

    results, exec_pair_key = _child_of(events, 300)

    old = exec_pair_key(PAIR, "db01", "/usr/bin/old", "/bin/sh").key_digest
    for _event_id, keys, reason in results:
        assert old not in keys and keys == ()
        assert reason == "an exec of the host between parent and child was not carried"


@pytest.mark.parametrize("first_boot, second_boot", [(None, "b1"), ("b1", None), (None, None)],
                         ids=["unknown-then-known", "known-then-unknown", "unknown-on-both-sides"])
def test_an_unrecorded_boot_on_either_side_never_proves_continuity(first_boot, second_boot):
    t = lambda hours, minutes=0: START - hours * H + timedelta(minutes=minutes)
    events = [
        _exec("parent", t(2, 0), 300, 1, "/usr/bin/old", host="db01", boot=first_boot),
        _exec("other", t(1, 30), 400, 1, "/usr/bin/id", host="db01", boot=second_boot),
    ]

    results, _key = _child_of(events, 300, boot=second_boot)

    # an unknown boot never resolves through the carry; a known parent resolves only when no unknown-boot exec of
    # the host lies between it and the child
    for _event_id, keys, _reason in results:
        assert keys == ()


def test_a_process_image_in_an_unrecorded_boot_is_a_break_for_its_host():
    t = lambda hours, minutes=0: START - hours * H + timedelta(minutes=minutes)
    events = [
        _exec("parent", t(2, 0), 300, 1, "/usr/bin/old", host="db01", boot="b1"),
        _observed("image", t(1, 20), 300, 1, "/tmp/implant", host="db01", boot=None),
    ]

    results, _key = _child_of(events, 300)

    for _event_id, keys, reason in results:
        assert keys == () and reason == "an exec of the host between parent and child was not carried"



# ---- prune anchor and the longest configured lookback -------------------------------------------------------

def test_a_future_dated_kept_hour_never_anchors_the_prune_of_real_input():
    from romulus.baseline.carry import CarryHour, save_carry_hour

    events, pendings = _scenario()
    store = _repo()
    _resolve(store, "hunt-1", events, pendings, hours=6)
    kept = _hours_kept(store)
    # a bogus window kept an hour a year ahead
    save_carry_hour(store, site="site", target="host-index", hour=START + 24 * 365 * H, normalizer="fixture@1",
                    carry=CarryHour((), (), {}, False))

    _again, _source, result = _resolve(store, "hunt-2", events, pendings, hours=6)

    assert result.carry_hours_pruned == 0 and set(kept) <= set(_hours_kept(store))


def test_the_longest_lookback_is_read_without_loading_manifests():
    store = _repo()
    for index, days in enumerate((3, 14, None)):
        baseline = {"specs": [{"id": "bl.exec_pair"}]}
        if days is not None:
            baseline["history_days"] = days
        store.create_hunt(f"h{index}", {"baseline": baseline}, f"m{index}", "test")
    store.create_hunt("no-baseline", {"baseline": {"history_days": 90}}, "m-x", "test")

    assert store.longest_baseline_history_days(default=7) == 14


# ---- breaks block only the parent-to-child intervals they can fall inside -------------------------------------

def _t(hours, minutes=0, seconds=0):
    return START - hours * H + timedelta(minutes=minutes, seconds=seconds)


def _keys_on_both_stores(events, pendings, hours=6):
    built = _repo()
    _resolve(built, "hunt-1", events, pendings, hours=hours)
    second, _source, _ = _resolve(built, "hunt-2", events, pendings, hours=hours)
    empty, _source, _ = _resolve(_repo(), "hunt-e", events, pendings, hours=hours)
    assert second == empty
    return {event_id: (keys, reason) for event_id, keys, reason in empty}


def test_an_old_unknown_boot_break_in_a_prior_boot_never_blocks_a_current_boot_child():
    """The lab shape: an exec of unrecorded boot in an earlier boot, records of that boot after it, then the current
    boot whose long-lived parent is known only from process observations."""
    from romulus.baseline.spec import exec_pair_key

    events = [
        _exec("old-1", _t(6, 0), 50, 1, "/usr/sbin/cron", host="video", boot="b-old"),
        _exec("unknown", _t(5, 30), 60, 1, "/bin/x", host="video", boot=None),
        _exec("old-2", _t(5, 50), 70, 1, "/usr/bin/id", host="video", boot="b-old"),
        _observed("apache", _t(2, 10), 700, 1, "/usr/sbin/apache2", host="video", boot="b-new"),
        _observed("apache-again", _t(1, 10), 700, 1, "/usr/sbin/apache2", host="video", boot="b-new"),
    ]
    child = Pending("video", "b-new", 700, START + timedelta(minutes=5), "child", "/bin/dash")

    result = _keys_on_both_stores(events, [child])

    assert result["child"][0] == (exec_pair_key(PAIR, "video", "/usr/sbin/apache2", "/bin/dash").key_digest,)


def test_a_break_between_the_parent_and_the_child_still_blocks():
    events = [
        _exec("parent", _t(3, 0), 300, 1, "/usr/bin/old", host="db01", boot="b1"),
        _exec("unknown", _t(2, 0), 300, 1, "/tmp/implant", host="db01", boot=None),
        _observed("seen-before", _t(3, 30), 700, 1, "/usr/sbin/sshd", host="db01", boot="b1"),
    ]
    children = [Pending("db01", "b1", 300, START + timedelta(minutes=5), "via-exec", "/bin/sh"),
                Pending("db01", "b1", 700, START + timedelta(minutes=6), "via-observation", "/bin/sh")]

    result = _keys_on_both_stores(events, children)

    assert result["via-exec"] == ((), "an exec of the host between parent and child was not carried")
    # the parent seen only before the break, the child after it: blocked
    assert result["via-observation"] == ((), "an exec of the host between parent and child was not carried")


def test_a_parent_observed_after_a_break_resolves():
    from romulus.baseline.spec import exec_pair_key

    events = [
        _exec("unknown", _t(3, 0), 300, 1, "/tmp/x", host="db01", boot=None),
        _observed("seen-after", _t(2, 30), 700, 1, "/usr/sbin/sshd", host="db01", boot="b1"),
    ]
    child = Pending("db01", "b1", 700, START + timedelta(minutes=6), "child", "/bin/sh")

    result = _keys_on_both_stores(events, [child])

    assert result["child"][0] == (exec_pair_key(PAIR, "db01", "/usr/sbin/sshd", "/bin/sh").key_digest,)


def test_records_naming_no_boot_at_a_boot_boundary_block_only_the_intervals_spanning_them():
    """The corpdns shape: a burst of records without a boot id around the reboot. A parent exec'd after the burst
    resolves its child; one exec'd before the burst, with its child after, does not."""
    from romulus.baseline.spec import exec_pair_key

    burst = [_exec(f"boundary-{index}", _t(2, 0, index), 900 + index, 1, "/usr/lib/systemd", host="dns",
                   boot=None) for index in range(10)]
    events = [
        _exec("before-burst", _t(2, 0, 0) - timedelta(seconds=30), 400, 1, "/usr/sbin/named", host="dns",
              boot="b2"),
        *burst,
        _exec("after-burst", _t(2, 5), 500, 1, "/usr/sbin/sshd", host="dns", boot="b2"),
    ]
    children = [Pending("dns", "b2", 500, START + timedelta(minutes=5), "after", "/bin/sh"),
                Pending("dns", "b2", 400, START + timedelta(minutes=6), "spanning", "/bin/sh")]

    result = _keys_on_both_stores(events, children)

    assert result["after"][0] == (exec_pair_key(PAIR, "dns", "/usr/sbin/sshd", "/bin/sh").key_digest,)
    assert result["spanning"] == ((), "an exec of the host between parent and child was not carried")


def _truth(events, child, hidden):
    """The parent image a child of (host, boot, ppid) truly had, or None when it is not knowable even with every
    true boot: the latest record of that pid in the child's true boot before it."""
    candidates = [event for event in events if event.host == child.host and event.ts < child.ts
                  and event.get("process.pid") == child.ppid and hidden.get(event.id, event.get("host.boot.id"))
                  == child.boot and event.outcome != Outcome.failure]
    if not candidates:
        return None
    latest = max(candidates, key=lambda event: event.ts)
    if latest.outcome == Outcome.unknown:
        return None
    return latest.get("process.executable")


def _differential(seeds):
    from romulus.baseline.spec import exec_pair_key

    wrong = []
    for seed in seeds:
        rnd = random.Random(seed)
        events, hidden = [], {}
        # images change only by exec: an observation shows the image of its pid's latest successful exec in its
        # boot (or any image when none was recorded)
        plan = sorted((_t(hour, rnd.randrange(60), index % 60), index, hour)
                      for index, hour in enumerate(rnd.randrange(1, 7) for _ in range(rnd.randint(10, 50))))
        images: dict[tuple, str] = {}
        for ts, index, hour in plan:
            host = rnd.choice(["web01", "db01"])
            boot = "b1" if hour >= 4 else "b2"
            pid = rnd.choice([100, 200, 300])
            exe = rnd.choice(["/a", "/b", "/c"])
            hide = rnd.random() < 0.15
            event_id = f"r{index}"
            if rnd.random() < 0.2:
                exe = images.get((host, boot, pid), exe)
                event = _observed(event_id, ts, pid, 1, exe, host=host, boot=None if hide else boot)
            else:
                event = _exec(event_id, ts, pid, 1, exe, host=host, boot=None if hide else boot,
                              outcome=rnd.choice([Outcome.success] * 8 + [Outcome.failure, Outcome.unknown]),
                              serial=index)
                if event.outcome == Outcome.success:
                    images[(host, boot, pid)] = exe
            if hide:
                hidden[event_id] = boot
            events.append(event)
        children = [Pending(rnd.choice(["web01", "db01"]), "b2", rnd.choice([100, 200, 300]),
                            START + timedelta(minutes=minute), f"child-{minute}", "/bin/sh")
                    for minute in range(10)]
        result = _keys_on_both_stores(events, children)
        for child in children:
            keys, _reason = result[child.event_id]
            if not keys:
                continue
            truth = _truth(events, child, hidden)
            if truth is None or keys != (exec_pair_key(PAIR, child.host, truth, "/bin/sh").key_digest,):
                wrong.append((seed, child.event_id, truth, keys))
    return wrong


def test_randomized_breaks_never_give_a_looser_or_wrong_parent():
    assert _differential(range(40)) == []


@pytest.mark.slow
def test_randomized_breaks_never_give_a_looser_or_wrong_parent_over_many_seeds():
    assert _differential(range(40, 340)) == []
