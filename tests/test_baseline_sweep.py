"""Sweep integration for bounded window observations and parent continuity."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from romulus.baseline.carry import SPANS_TARGETS, CarryInStore, ParentExec
from romulus.baseline.count import KeyCounter
from romulus.baseline.lookback import LookbackBudget, LookbackWriter
from romulus.baseline.playbook import ExecPairBaseline, ExecPathBaseline, ExternalDestinationBaseline
from romulus.baseline.spec import SPEC_BY_ID, KeyContext
from romulus.detect import netdef
from romulus.detect.netdef import SiteNetworks
from romulus.evidence.typed import Outcome, TypedEvent, fv
from romulus.hunt import sweep as sweep_module
from romulus.hunt.baseline_stage import resolve_window_exec_pairs
from romulus.hunt.stage import EventStage
from romulus.sources.models import Completeness, SearchOutcome, Window
from romulus.sources.profile import contract_from_types
from romulus.store.db import make_engine, migrate
from romulus.store.repo import Repo
from tests.test_baseline_lookback import FakeHistory

START = datetime(2026, 1, 8, 12, tzinfo=UTC)
END = START + timedelta(hours=1)


class FakeClient:
    version = "test"

    class settings:
        es_flavor = "elasticsearch"


def _repo(targets: list[str] | None = None) -> Repo:
    engine = make_engine(":memory:")
    migrate(engine)
    repo = Repo(engine)
    repo.create_hunt("h1", {"targets": targets or ["x"]}, "digest", "tester")
    return repo


def _exec(event_id: str, ts: datetime, *, host: str = "web01", pid: int = 20, ppid: int = 10,
          executable: str = "/bin/sh", serial: int | None = None,
          outcome: Outcome = Outcome.success) -> TypedEvent:
    values = {
        "process.pid": pid,
        "process.ppid": ppid,
        "process.executable": executable,
        "process.exec_file.path": executable,
        "process.user": "www-data",
        "host.boot.id": "boot-1",
    }
    if serial is not None:
        values["audit.serial"] = serial
    return TypedEvent(
        id=event_id,
        family="process_exec",
        ts=ts,
        host=host,
        outcome=outcome,
        fields={name: fv(value, f"fixture:{name}") for name, value in values.items()},
        raw=[],
        normalizer="fixture@1",
    )


def _contract(target: str = "x", hosts: tuple[str, ...] = ("web01",), os_family: str = "linux"):
    return contract_from_types(
        target,
        {"@timestamp": "date", "process.executable": "keyword", "process.pid": "long"},
        role="host",
        os_family=os_family,
        hosts=hosts,
    )


def _install_partition(monkeypatch, events: list[TypedEvent], *, window: Window) -> None:
    records = [{"_index": "fixture", "_id": event.id, "_source": {}} for event in events]
    by_id = {event.id: event for event in events}

    def execute(_client, intent, _contract):
        now = datetime.now(UTC)
        return SearchOutcome(
            target=intent.target,
            fingerprint="fixture",
            started_at=now,
            ended_at=now,
            completeness=Completeness.complete,
            total=len(records),
            total_relation="eq",
            returned=len(records),
            records=records,
        )

    monkeypatch.setattr(sweep_module, "execute", execute)
    monkeypatch.setattr(
        sweep_module,
        "normalize_hits",
        lambda fetched, _boots=None: ([by_id[row["_id"]] for row in fetched], {}, []),
    )
    monkeypatch.setattr(sweep_module, "plan_partitions", lambda *_args, **_kwargs: [(window, len(records))])


def test_window_cells_sort_events_persist_first_citations_and_are_idempotent(monkeypatch, tmp_path):
    window = Window(start=START, end=START + timedelta(days=2))
    events = [_exec("later", START + timedelta(days=1)), _exec("earlier", START + timedelta(minutes=1))]
    _install_partition(monkeypatch, events, window=window)
    repo = _repo()
    sweep = sweep_module.Sweep(repo, FakeClient(), "h1", window, {"x": _contract()}, stage_dir=tmp_path)
    sweep.pack = [ExecPathBaseline()]

    sweep.run_target("x")
    sweep.run_target("x")

    observations = list(repo.baseline_observations("h1"))
    assert len(observations) == 2
    assert {row["window_count"] for row in observations} == {2}
    assert {row["first_event_id"] for row in observations} == {"earlier"}
    cell = next(row for row in repo.rule_cells("h1") if row["partition"] == window.key())
    assert cell["state"] == "evaluated_complete"
    assert not cell["detail"]["reasons"]
    sweep.close_stage()


def test_sweep_crash_resumes_to_the_same_window_observations(monkeypatch, tmp_path):
    window = Window(start=START, end=START + timedelta(days=2))
    events = [_exec("later", START + timedelta(days=1)), _exec("earlier", START + timedelta(minutes=1))]
    _install_partition(monkeypatch, events, window=window)

    interrupted = _repo()
    first = sweep_module.Sweep(
        interrupted, FakeClient(), "h1", window, {"x": _contract()}, stage_dir=tmp_path / "first",
    )
    first.pack = [ExecPathBaseline()]
    save = interrupted.save_baseline_window_cell

    def crash_before_commit(*_args, **_kwargs):
        raise RuntimeError("injected sweep crash")

    monkeypatch.setattr(interrupted, "save_baseline_window_cell", crash_before_commit)
    try:
        try:
            first.run_target("x")
        except RuntimeError as error:
            assert str(error) == "injected sweep crash"
        else:
            raise AssertionError("injected crash did not fire")
    finally:
        first.close_stage()
    monkeypatch.setattr(interrupted, "save_baseline_window_cell", save)

    resumed = sweep_module.Sweep(
        interrupted, FakeClient(), "h1", window, {"x": _contract()}, stage_dir=tmp_path / "resumed",
    )
    resumed.pack = [ExecPathBaseline()]
    resumed.run_target("x")
    resumed.close_stage()

    uninterrupted = _repo()
    fresh = sweep_module.Sweep(
        uninterrupted, FakeClient(), "h1", window, {"x": _contract()}, stage_dir=tmp_path / "fresh",
    )
    fresh.pack = [ExecPathBaseline()]
    fresh.run_target("x")
    fresh.close_stage()

    assert list(interrupted.baseline_observations("h1")) == list(
        uninterrupted.baseline_observations("h1"),
    )
    assert interrupted.rule_cells("h1") == uninterrupted.rule_cells("h1")
    assert interrupted.events_by_ids(["earlier", "later"]) == uninterrupted.events_by_ids(
        ["earlier", "later"],
    )


def test_failed_baseline_window_cell_is_recounted_on_resume(monkeypatch, tmp_path):
    window = Window(start=START, end=END)
    event = _exec("event", START + timedelta(minutes=1))
    _install_partition(monkeypatch, [event], window=window)
    repo = _repo()
    repo.set_rule_cell(
        "h1", "bl.exec_path", SPEC_BY_ID["bl.exec_path"].version, "x", window.key(),
        "executed_failed", 0, 0, {"error": "source offline"},
    )
    sweep = sweep_module.Sweep(
        repo, FakeClient(), "h1", window, {"x": _contract()}, stage_dir=tmp_path,
    )
    sweep.pack = [ExecPathBaseline()]

    sweep.run_target("x")

    assert next(repo.baseline_observations("h1"))["window_count"] == 1
    cell = next(row for row in repo.rule_cells("h1") if row["partition"] == window.key())
    assert cell["state"] == "evaluated_complete"
    sweep.close_stage()


def test_split_partition_resume_does_not_double_count_completed_child(monkeypatch, tmp_path):
    window = Window(start=START, end=END)
    midpoint = START + (END - START) / 2
    first_window = Window(start=START, end=midpoint)
    second_window = Window(start=midpoint, end=END)
    by_window = {
        first_window.key(): _exec("first", START + timedelta(minutes=1)),
        second_window.key(): _exec("second", midpoint + timedelta(minutes=1)),
    }

    def execute(_client, intent, _contract):
        event = by_window[intent.window.key()]
        records = [] if intent.kind == "histogram" else [
            {"_index": "fixture", "_id": event.id, "_source": {}},
        ]
        now = datetime.now(UTC)
        return SearchOutcome(
            target=intent.target, fingerprint="fixture", started_at=now, ended_at=now,
            completeness=Completeness.complete, total=1, total_relation="eq",
            returned=len(records), records=records,
        )

    monkeypatch.setattr(sweep_module, "execute", execute)
    monkeypatch.setattr(
        sweep_module, "normalize_hits",
        lambda records, _boots=None: ([next(event for event in by_window.values()
                                             if event.id == row["_id"]) for row in records], {}, []),
    )
    monkeypatch.setattr(
        sweep_module, "plan_partitions",
        lambda *_args, **_kwargs: [(window, sweep_module.PARTITION_MAX_DOCS + 1)],
    )
    repo = _repo()
    real_save = repo.save_baseline_window_cell
    crashed = False

    def crash_second(hunt_id, cell, observations):
        nonlocal crashed
        if cell["partition"] == second_window.key() and not crashed:
            crashed = True
            raise RuntimeError("injected second-child crash")
        return real_save(hunt_id, cell, observations)

    monkeypatch.setattr(repo, "save_baseline_window_cell", crash_second)
    first = sweep_module.Sweep(
        repo, FakeClient(), "h1", window, {"x": _contract()}, stage_dir=tmp_path / "first",
    )
    first.pack = [ExecPathBaseline()]
    with pytest.raises(RuntimeError, match="second-child"):
        first.run_target("x")
    first.close_stage()

    monkeypatch.setattr(repo, "save_baseline_window_cell", real_save)
    resumed = sweep_module.Sweep(
        repo, FakeClient(), "h1", window, {"x": _contract()}, stage_dir=tmp_path / "resumed",
    )
    resumed.pack = [ExecPathBaseline()]
    resumed.run_target("x")
    resumed.close_stage()

    assert {row["window_count"] for row in repo.baseline_observations("h1")} == {2}
    cells = {row["partition"]: row["state"] for row in repo.rule_cells("h1")}
    assert cells[window.key()] == "split"
    assert cells[first_window.key()] == cells[second_window.key()] == "evaluated_complete"


def test_missing_window_record_keeps_positive_keys_but_makes_the_cell_partial(monkeypatch, tmp_path):
    window = Window(start=START, end=END)
    valid = _exec("valid", START + timedelta(minutes=1))
    missing = valid.model_copy(update={"id": "missing", "fields": {}})
    _install_partition(monkeypatch, [missing, valid], window=window)
    repo = _repo()
    sweep = sweep_module.Sweep(repo, FakeClient(), "h1", window, {"x": _contract()}, stage_dir=tmp_path)
    sweep.pack = [ExecPathBaseline()]

    sweep.run_target("x")

    assert {row["first_event_id"] for row in repo.baseline_observations("h1")} == {"valid"}
    cell = next(row for row in repo.rule_cells("h1") if row["partition"] == window.key())
    assert cell["state"] == "evaluated_partial"
    assert any("process.executable is absent" in reason for reason in cell["detail"]["reasons"])
    sweep.close_stage()


def test_window_and_lookback_counters_are_equal_at_retrieval_edges(monkeypatch, tmp_path):
    window = Window(start=START, end=END)
    events = [
        _exec("before", START - timedelta(seconds=1)),
        _exec("after", END + timedelta(seconds=1)),
    ]
    _install_partition(monkeypatch, events, window=window)
    repo = _repo()
    sweep = sweep_module.Sweep(repo, FakeClient(), "h1", window, {"x": _contract()}, stage_dir=tmp_path)
    sweep.pack = [ExecPathBaseline()]

    sweep.run_target("x")

    direct = KeyCounter("segment", SPEC_BY_ID["bl.exec_path"], span=(START, END))
    for event in sorted(events, key=lambda item: (item.ts, item.id)):
        direct.consume(event, KeyContext())
    expected = {
        (row["scope_kind"], row["scope"], row["key_digest"]):
        (row["count"], row["first_ts"], row["last_ts"])
        for row in direct.count_rows()
    }
    actual = {
        (row["scope_kind"], row["scope"], row["key_digest"]):
        (row["window_count"], row["first_ts"], row["last_ts"])
        for row in repo.baseline_observations("h1")
    }
    assert actual == expected
    sweep.close_stage()


def test_window_child_resolves_to_a_pre_window_parent(monkeypatch, tmp_path):
    window = Window(start=START, end=END)
    child = _exec("child", START + timedelta(minutes=5), ppid=10, executable="/bin/curl")
    _install_partition(monkeypatch, [child], window=window)
    repo = _repo()
    carry = CarryInStore(repo, "h1").for_target("x", horizon=END)
    carry.observe_rows([
        ParentExec("web01", "boot-1", 10, START - timedelta(minutes=30), "/usr/sbin/sshd", 1, "parent"),
    ])
    carry.mark_observed(START - timedelta(hours=1), START)
    sweep = sweep_module.Sweep(repo, FakeClient(), "h1", window, {"x": _contract()}, stage_dir=tmp_path)
    sweep.pack = [ExecPairBaseline()]

    sweep.run_target("x")
    resolve_window_exec_pairs(repo, "h1", window)

    observation = next(repo.baseline_observations("h1"))
    assert observation["key"] == {
        "child_executable": "/bin/curl",
        "parent_executable": "/usr/sbin/sshd",
    }
    assert observation["first_event_id"] == "child"
    cell = next(row for row in repo.rule_cells("h1") if row["partition"] == window.key())
    assert cell["state"] == "evaluated_complete"
    sweep.close_stage()


def test_window_child_resolves_after_history_fill_in_production_order(monkeypatch, tmp_path):
    window = Window(start=START, end=END)
    child = _exec("child", START + timedelta(minutes=5), ppid=10, executable="/bin/curl")
    _install_partition(monkeypatch, [child], window=window)
    repo = _repo()
    sweep = sweep_module.Sweep(repo, FakeClient(), "h1", window, {"x": _contract()}, stage_dir=tmp_path)
    sweep.pack = [ExecPairBaseline()]

    sweep.run_target("x")
    assert list(repo.baseline_observations("h1")) == []

    parent = _exec(
        "parent", START - timedelta(minutes=30), pid=10, ppid=1, executable="/usr/sbin/sshd",
    )
    writer = LookbackWriter(
        repo, FakeHistory([parent]), site="site", specs=[SPEC_BY_ID["bl.exec_pair"]],
        normalizer="fixture@1", budget=LookbackBudget(queries=10, records=10, seconds=10),
        parent_carry=CarryInStore(repo, "h1"), now=lambda: START,
    )
    writer.fill(hunt_id="h1", targets=["x"], start=START - timedelta(hours=1), end=START)
    resolve_window_exec_pairs(repo, "h1", window)

    observation = next(repo.baseline_observations("h1"))
    assert observation["key"] == {
        "child_executable": "/bin/curl",
        "parent_executable": "/usr/sbin/sshd",
    }
    assert observation["first_event_id"] == "child"
    cell = next(row for row in repo.rule_cells("h1") if row["partition"] == window.key())
    assert cell["state"] == "evaluated_complete"
    sweep.close_stage()


def test_exec_pair_staging_failure_is_an_explicit_partial_cell(monkeypatch, tmp_path):
    import sqlite3

    window = Window(start=START, end=END)
    events = [
        _exec("parent", START + timedelta(minutes=1), pid=10, ppid=1, executable="/usr/bin/bash"),
        _exec("child", START + timedelta(minutes=2), pid=20, ppid=10, executable="/bin/curl"),
    ]
    _install_partition(monkeypatch, events, window=window)

    def fail_compact_stage(self, **_kwargs):
        raise sqlite3.OperationalError("database or disk is full")

    monkeypatch.setattr(EventStage, "record_baseline_cell", fail_compact_stage)
    repo = _repo()
    sweep = sweep_module.Sweep(repo, FakeClient(), "h1", window, {"x": _contract()}, stage_dir=tmp_path)
    sweep.pack = [ExecPairBaseline()]

    sweep.run_target("x")
    resolve_window_exec_pairs(repo, "h1", window)

    cell = next(row for row in repo.rule_cells("h1") if row["partition"] == window.key())
    assert cell["state"] == "evaluated_partial"
    assert cell["evaluated"] == 2
    assert any("compact baseline stage failed" in reason for reason in cell["detail"]["reasons"])
    assert any("compact baseline stage failed" in reason for reason in sweep.partial_reasons)
    sweep.close_stage()


def test_exec_pair_stage_keeps_compact_rows_not_event_bodies(monkeypatch, tmp_path):
    window = Window(start=START, end=END)
    events = [
        _exec(f"exec-{index}", START + timedelta(seconds=index), pid=index + 10, ppid=1,
              executable="/usr/bin/" + "x" * 200)
        for index in range(100)
    ]
    _install_partition(monkeypatch, events, window=window)
    repo = _repo()
    sweep = sweep_module.Sweep(repo, FakeClient(), "h1", window, {"x": _contract()}, stage_dir=tmp_path)
    sweep.pack = [ExecPairBaseline()]

    sweep.run_target("x")

    stage = sweep._event_stage()
    assert stage.db.execute("SELECT COUNT(*) FROM event").fetchone()[0] == 0
    assert stage.db.execute("SELECT COUNT(*) FROM raw").fetchone()[0] == 0
    assert stage.baseline_compact_bytes() / len(events) < 500
    sweep.close_stage()


def test_exec_pair_empty_incompatible_target_is_not_applicable_not_partial(monkeypatch, tmp_path):
    window = Window(start=START, end=END)
    _install_partition(monkeypatch, [], window=window)
    repo = _repo()
    sweep = sweep_module.Sweep(
        repo, FakeClient(), "h1", window,
        {"x": _contract(os_family="windows")}, stage_dir=tmp_path,
    )
    sweep.pack = [ExecPairBaseline()]

    sweep.run_target("x")
    resolve_window_exec_pairs(repo, "h1", window)

    cell = next(row for row in repo.rule_cells("h1") if row["partition"] == window.key())
    assert cell["state"] == "not_applicable_no_events"
    sweep.close_stage()


def test_external_destination_uses_the_installed_site_network(monkeypatch, tmp_path):
    window = Window(start=START, end=END)
    event = TypedEvent(
        id="public-space-source", family="net_flow", ts=START, host="sensor",
        outcome=Outcome.unknown,
        fields={
            "source.ip": fv("198.51.100.10", "fixture:source.ip"),
            "destination.ip": fv("8.8.8.8", "fixture:destination.ip"),
        },
        raw=[], normalizer="fixture@1",
    )
    _install_partition(monkeypatch, [event], window=window)
    netdef.install(SiteNetworks.from_lists(["198.51.100.0/24"]))
    repo = _repo()
    sweep = sweep_module.Sweep(
        repo, FakeClient(), "h1", window, {"x": _contract()}, stage_dir=tmp_path,
    )
    sweep.pack = [ExternalDestinationBaseline()]

    sweep.run_target("x")

    observations = list(repo.baseline_observations("h1"))
    assert {row["key"]["kind"] for row in observations} == {"dest_ip", "dest_network"}
    assert {row["scope"] for row in observations} == {"internal_ip:198.51.100.10"}
    sweep.close_stage()


def test_window_child_resolves_to_a_parent_from_an_earlier_cell(monkeypatch, tmp_path):
    first = Window(start=START, end=START + timedelta(minutes=30))
    second = Window(start=first.end, end=END)
    parent = _exec("parent", START + timedelta(minutes=5), pid=10, ppid=1, executable="/usr/bin/bash")
    child = _exec("child", START + timedelta(minutes=35), pid=20, ppid=10, executable="/bin/curl")
    by_id = {event.id: event for event in (parent, child)}

    def execute(_client, intent, _contract):
        selected = [event for event in (parent, child) if intent.window.start <= event.ts < intent.window.end]
        records = [{"_index": "fixture", "_id": event.id, "_source": {}} for event in selected]
        now = datetime.now(UTC)
        return SearchOutcome(
            target=intent.target, fingerprint="fixture", started_at=now, ended_at=now,
            completeness=Completeness.complete, total=len(records), total_relation="eq",
            returned=len(records), records=records,
        )

    monkeypatch.setattr(sweep_module, "execute", execute)
    monkeypatch.setattr(
        sweep_module, "normalize_hits",
        lambda records, _boots=None: ([by_id[row["_id"]] for row in records], {}, []),
    )
    monkeypatch.setattr(sweep_module, "plan_partitions", lambda *_args, **_kwargs: [(first, 1), (second, 1)])
    repo = _repo()
    sweep = sweep_module.Sweep(repo, FakeClient(), "h1", Window(start=START, end=END),
                               {"x": _contract()}, stage_dir=tmp_path)
    sweep.pack = [ExecPairBaseline()]

    sweep.run_target("x")
    resolve_window_exec_pairs(repo, "h1", Window(start=START, end=END))

    assert any(row["key"] == {
        "child_executable": "/bin/curl",
        "parent_executable": "/usr/bin/bash",
    } for row in repo.baseline_observations("h1"))
    child_cell = next(row for row in repo.rule_cells("h1") if row["partition"] == second.key())
    assert child_cell["state"] == "evaluated_complete"
    sweep.close_stage()


def test_window_out_of_retrieval_hour_exec_breaks_both_hours(monkeypatch, tmp_path):
    window = Window(start=START, end=END)
    outside = _exec("outside", START - timedelta(hours=2), pid=30)
    _install_partition(monkeypatch, [outside], window=window)
    repo = _repo()
    sweep = sweep_module.Sweep(repo, FakeClient(), "h1", window, {"x": _contract()}, stage_dir=tmp_path)
    sweep.pack = [ExecPairBaseline()]

    sweep.run_target("x")
    resolve_window_exec_pairs(repo, "h1", window)

    assert repo.baseline_parent_breaks("h1", "x", "web01") == [
        (START - timedelta(hours=2), START - timedelta(hours=1)),
        (START, START + timedelta(hours=1)),
    ]
    sweep.close_stage()


def test_same_instant_parent_images_without_serials_leave_the_child_unresolved(monkeypatch, tmp_path):
    window = Window(start=START, end=END)
    instant = START + timedelta(minutes=5)
    events = [
        _exec("parent-a", instant, pid=10, executable="/bin/a"),
        _exec("parent-b", instant, pid=10, executable="/bin/b"),
        _exec("child", instant, pid=20, ppid=10, executable="/bin/c"),
    ]
    _install_partition(monkeypatch, events, window=window)
    repo = _repo()
    sweep = sweep_module.Sweep(repo, FakeClient(), "h1", window, {"x": _contract()}, stage_dir=tmp_path)
    sweep.pack = [ExecPairBaseline()]

    sweep.run_target("x")
    resolve_window_exec_pairs(repo, "h1", window)

    assert list(repo.baseline_observations("h1")) == []
    cell = next(row for row in repo.rule_cells("h1") if row["partition"] == window.key())
    assert cell["state"] == "evaluated_partial"
    assert any("not carried" in reason for reason in cell["detail"]["reasons"])
    sweep.close_stage()


def test_profile_holders_include_a_split_host_even_when_one_target_delivered_no_exec():
    repo = _repo(["a", "b"])
    base = {
        "kind": "es_index",
        "role": "host",
        "os_family": "linux",
        "field_types": {"process.executable": "keyword", "process.pid": "long"},
        "datasets": {"linux.audit": 1},
        "hosts": {"web01": 1},
    }
    repo.save_profile("h1", {"id": "pa", "target": "a", **base})
    repo.save_profile("h1", {"id": "pb", "target": "b", **base})
    carry = CarryInStore(repo, "h1").for_target("a")
    carry.observe_rows([
        ParentExec("web01", "boot-1", 10, START, "/bin/a", 1, "parent"),
    ])

    assert repo.baseline_parent_targets("h1", "web01") == ["a", "b"]
    assert carry.parent("web01", 10, START + timedelta(minutes=1), "boot-1") == (
        None, SPANS_TARGETS,
    )


def test_truncated_exec_capable_profile_is_a_holder_of_every_host():
    repo = _repo(["observed", "truncated"])
    repo.save_profile("h1", {
        "id": "observed-profile", "target": "observed", "kind": "es_index", "role": "host",
        "os_family": "linux", "field_types": {"process.executable": "keyword", "process.pid": "long"},
        "datasets": {"linux.audit": 1}, "hosts": {"web99": 1}, "notes": [],
    })
    repo.save_profile("h1", {
        "id": "truncated-profile", "target": "truncated", "kind": "es_index", "role": "host",
        "os_family": "linux", "field_types": {"process.executable": "keyword", "process.pid": "long"},
        "datasets": {"linux.audit": 1}, "hosts": {"web01": 1},
        "notes": ["hosts inventory truncated (composite page budget 1 exceeded)"],
    })

    assert repo.baseline_parent_targets("h1", "web99") == ["observed", "truncated"]

