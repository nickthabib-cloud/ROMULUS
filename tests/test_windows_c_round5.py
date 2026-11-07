"""Detection admission and citation failures through native records and real sweep state."""
import sqlite3
from datetime import timedelta

import pytest

from romulus.detect.bounded import KeyedStore, StateBudget
from romulus.hunt import sweep as sw
from romulus.hunt.publish import SourceCitationFetcher
from romulus.sources.es import SourceError
from romulus.sources.models import Window
from tests.test_bounded_budget import _owner
from tests.test_bounded_starvation import _Listed
from tests.test_sweep import _complete, _repo
from tests.test_windows_c_burst_review import START
from tests.test_windows_c_round4 import dns


def _native_sweep(tmp_path, monkeypatch, total=512*1024):
    rule = _Listed()
    budget = StateBudget(tmp_path, disk_total=total, reserve=0)
    monkeypatch.setattr(sw, "fresh_pack", lambda: [rule])
    monkeypatch.setattr(sw, "state_budget", lambda settings, stage_dir: budget)
    sweep = sw.Sweep(_repo(), None, "h1", Window(start=START, end=START+timedelta(hours=1)), {}, stage_dir=tmp_path)
    return rule, sweep


def _feed(sweep, pairs, monkeypatch):
    monkeypatch.setattr(sw, "execute", lambda client, intent, contract:
                        _complete(intent, [hit for _, hit in pairs]))
    sweep.run_partition(pairs[0][1]["_index"], None, [], Window(start=pairs[0][0].ts,
                        end=pairs[-1][0].ts+timedelta(seconds=1)), est=len(pairs))


def test_detection_reclaims_native_citation_bodies_before_physical_refusal(tmp_path, monkeypatch):
    _rule, sweep = _native_sweep(tmp_path, monkeypatch)
    pairs = [dns(n, f"priority{n}.c2.test", pad=3500) for n in range(18)]
    _feed(sweep, pairs, monkeypatch)
    stage = sweep._event_stage()
    assert stage.db.execute("SELECT COUNT(*) FROM raw").fetchone()[0]
    owner = _owner(tmp_path, sweep.budget, "late_detection", strong=True)
    store = KeyedStore(owner, "keys", hot=0)
    try:
        for n in range(256):
            assert store.put(str(n), bytes([n % 256])*4000)
            store.trim()
            if stage.db.execute("SELECT COUNT(*) FROM raw").fetchone()[0] < len(pairs):
                break
        else:
            pytest.fail("fixture did not reach citation pressure")
        assert len(store) == n+1 and not owner.limits
        assert 0 < stage.db.execute("SELECT COUNT(*) FROM raw").fetchone()[0] < len(pairs)
        retained = stage.load([event.id for event, _ in pairs])
        assert {event.id for event in retained} == {event.id for event, _ in pairs}
        assert sum(path.stat().st_size for path in tmp_path.rglob("*") if path.is_file()) <= sweep.budget.disk_total
        sweep.finalize()
        assert len(sweep.repo.candidates("h1")) == len(pairs)
    finally:
        owner.close_spill()
        sweep.close_stage()


def test_idle_detection_floors_do_not_refuse_accepted_native_state(tmp_path, monkeypatch):
    rule, sweep = _native_sweep(tmp_path, monkeypatch, 2*2**20)
    sweep.budget.plan(2000)
    idle = sweep.budget.account("idle")
    busy = sweep.budget.account("busy")
    sweep.budget.charge(busy, sweep.budget.pool*2)
    assert not sweep.budget.new_key_reason(busy) and not sweep.budget.new_key_reason(idle)
    assert sweep.budget.physical_allowance(busy) > sweep.budget.pool
    _feed(sweep, [dns(1, "quiet.c2.test")], monkeypatch)
    sweep.finalize()
    [candidate] = sweep.repo.candidates("h1")
    assert candidate["lane"] == "high" and not rule.limits


@pytest.mark.parametrize("compact_first", [False, True])
def test_large_native_baseline_batch_retries_after_citation_reclamation(tmp_path, monkeypatch, compact_first):
    from romulus.evidence.normalize import normalize_hits
    from tests.test_kernel_records import cwd, execve, hit, path, syscall
    _rule, sweep = _native_sweep(tmp_path, monkeypatch, 2**20)
    pairs = [dns(n, f"baseline{n}.c2.test", pad=3500) for n in range(30)]
    _feed(sweep, pairs, monkeypatch)
    stage = sweep._event_stage()
    if compact_first:
        stage._ensure_baseline()
        while stage._evict_citations(4096):
            pass
        assert {event.id for event in stage.load([event.id for event, _hit in pairs])} == {
            event.id for event, _hit in pairs}
        assert stage._text_rows == 0
        assert stage.db.execute("SELECT COUNT(*) FROM raw").fetchone()[0] == 0
    owner = _owner(tmp_path, sweep.budget, "baseline_pressure", strong=True)
    store = KeyedStore(owner, "keys", hot=0)
    try:
        n = 0
        while sweep.budget.physical_used < sweep.budget.disk_total-48*1024:
            assert store.put(str(n), bytes([n % 256])*12000)
            store.trim()
            n += 1
        assert stage.db.execute("SELECT COUNT(*) FROM raw").fetchone()[0] == (0 if compact_first else 30)
        connection, full = stage.db, []
        class RecordedFull:
            def __getattr__(self, name):
                return getattr(connection, name)
            def __enter__(self):
                return connection.__enter__()
            def __exit__(self, *args):
                return connection.__exit__(*args)
            def execute(self, sql, *args):
                try:
                    return connection.execute(sql, *args)
                except sqlite3.OperationalError as exc:
                    if "full" in str(exc).lower():
                        full.append(sql)
                    raise
            def executemany(self, sql, rows):
                try:
                    return connection.executemany(sql, rows)
                except sqlite3.OperationalError as exc:
                    if "full" in str(exc).lower():
                        full.append(sql)
                    raise
        stage.db = RecordedFull()
        reclaimed = []
        evict_references = stage._citation_account.evict_references
        def references(needed):
            assert full, "compact references must survive preflight; only actual FULL permits reclamation"
            reclaimed.append(needed)
            return evict_references(needed)
        stage._citation_account.evict_references = references
        records = []
        event_count = 275 if compact_first else 350
        for n in range(event_count):
            serial = 2000+n
            executable = f"/opt/example/program{n}"
            lines = [execve(serial, executable), syscall(serial, 59, "execve", exe=executable),
                     path(serial, 0, executable, "NORMAL"), cwd(serial)]
            records.extend(hit(f"baseline-exec-{n}-{i}", line) for i, line in enumerate(lines))
        events, _skips, errors = normalize_hits(records)
        assert not errors and len(events) == event_count
        kwargs = {"target": "romulus-host-x", "partition": "large-cell", "start": events[0].ts,
                  "end": events[-1].ts+timedelta(hours=1), "target_applicable": True,
                  "source_complete": True, "reasons": [], "task_id": None, "events": events}
        if compact_first:
            # Each IOC group has only one witness. The large cell must refuse locally rather than erase them.
            with pytest.raises(sqlite3.OperationalError, match="physical whole-hunt"):
                stage.record_baseline_cell(**kwargs)
            assert stage.db.execute("SELECT COUNT(*) FROM baseline_exec WHERE partition='large-cell'").fetchone()[0] == 0
        else:
            stage.record_baseline_cell(**kwargs)
            assert stage.db.execute("SELECT COUNT(*) FROM baseline_exec WHERE partition='large-cell'").fetchone()[0] == event_count
            assert not stage.refusal_reason
            assert 0 < stage.db.execute("SELECT COUNT(*) FROM raw").fetchone()[0] < len(pairs)
        assert {event.id for event in stage.load([e.id for e, _ in pairs])} == {e.id for e, _ in pairs}
        assert sweep.budget.physical_used <= sweep.budget.disk_total
        assert full
        if compact_first:
            assert reclaimed and stage.count() == len(pairs)
        sweep.finalize()
        assert len(sweep.repo.candidates("h1")) == len(pairs)
    finally:
        owner.close_spill()
        sweep.close_stage()


@pytest.mark.parametrize(("error", "word"), [(SourceError("HTTP 403 forbidden"), "authorization"),
    (SourceError("HTTP 400 mapping field incompatible"), "mapping/query"),
    (SourceError("HTTP 404 source document missing"), "retrieval")])
def test_native_citation_retrieval_errors_are_named_and_keep_positive(tmp_path, monkeypatch, error, word):
    rule, sweep = _native_sweep(tmp_path, monkeypatch)
    pair = dns(1, "retrieval.c2.test")
    _feed(sweep, [pair], monkeypatch)
    stage = sweep._event_stage()
    stage._compact_cache([pair[0]], (sweep._stage_owner_accounts[rule.id],), drop_raw=True)
    class Client:
        def search(self, index, body):
            raise error
    rule.citation_fetcher = SourceCitationFetcher(Client())
    sweep.finalize()
    [candidate] = sweep.repo.candidates("h1")
    assert candidate["lane"] == "high"
    assert f"Citation {word} error" in candidate["claim"] and "partial" in candidate["claim"]


def test_unexpected_citation_code_error_is_not_disguised_as_rolloff(tmp_path, monkeypatch):
    rule, sweep = _native_sweep(tmp_path, monkeypatch)
    pair = dns(1, "unexpected.c2.test")
    _feed(sweep, [pair], monkeypatch)
    stage = sweep._event_stage()
    stage._compact_cache([pair[0]], (sweep._stage_owner_accounts[rule.id],), drop_raw=True)
    class Client:
        def search(self, index, body):
            raise ValueError("invalid adapter response")
    rule.citation_fetcher = SourceCitationFetcher(Client())
    try:
        with pytest.raises(ValueError, match="invalid adapter response"):
            sweep.finalize()
    finally:
        sweep.close_stage()


def test_native_stage_admission_work_is_per_batch(tmp_path, monkeypatch):
    _rule, sweep = _native_sweep(tmp_path, monkeypatch, 64*2**20)
    stage = sweep._event_stage()
    calls = []
    original = sweep.budget.new_key_reason
    def admission(account):
        calls.append(account.name)
        return original(account)
    monkeypatch.setattr(sweep.budget, "new_key_reason", admission)
    try:
        for batch in range(4):
            pairs = [dns(100*batch+n, f"work{100*batch+n}.c2.test", pad=4000) for n in range(100)]
            before = len(calls)
            _feed(sweep, pairs, monkeypatch)
            assert len(calls)-before <= 4
        assert stage.count() == 400
        sweep.finalize()
        assert len(sweep.repo.candidates("h1")) == 400
    finally:
        sweep.close_stage()


def test_refused_baseline_row_is_local_and_other_detection_keeps_growing(tmp_path, monkeypatch):
    from romulus.hunt.stage import EventStage
    from tests import throughput_fixture as tf
    tf.patched_sizes(monkeypatch)
    monkeypatch.setattr(sw, "state_budget", lambda settings, stage_dir: StateBudget(stage_dir,disk_total=64*2**20,reserve=0))
    original = EventStage.record_baseline_cell
    refused = []
    def write(self, **kwargs):
        if not refused and kwargs.get("events"):
            refused.append((kwargs["target"], kwargs["partition"]))
            raise sqlite3.OperationalError("injected baseline-cell physical refusal")
        return original(self, **kwargs)
    monkeypatch.setattr(EventStage, "record_baseline_cell", write)
    snapshot = tf.run_stack(tmp_path, docs=tf.build(1))
    from tests.test_throughput_equality import GOLDEN_STACK
    assert refused and len(snapshot["candidates"]) == 44
    assert tf.digests(snapshot)["candidates"] == GOLDEN_STACK["candidates"]
    partial = [row for row in snapshot["rule_cells"] if "injected baseline-cell" in str(row.get("detail"))]
    assert partial and all(row["rule_id"] == "bl.exec_pair" for row in partial)
    assert all(row["state"] != "executed_failed" for row in snapshot["rule_cells"])


def test_native_persistence_missing_root_citation_keeps_both_computed_groups(tmp_path, monkeypatch):
    from datetime import UTC, datetime

    from romulus.detect.kernel_files import PersistencePathChange
    from romulus.evidence.normalize import normalize_hits
    from tests.test_kernel_records import cwd, hit, path, syscall
    rule = PersistencePathChange()
    records = []
    for n, uid in enumerate(("0", "33")):
        serial = 800+n
        lines = [syscall(serial, 257, "openat", a2="80241", uid=uid, exe="/usr/bin/editor"),
                 path(serial, 0, f"/etc/cron.d/group{n}", "CREATE", ouid=uid, ogid=uid), cwd(serial)]
        records.extend(hit(f"persist-{n}-{i}", line) for i, line in enumerate(lines))
    events, _skips, errors = normalize_hits(records)
    assert not errors and len(events) == 2
    cited_rule = PersistencePathChange()
    cited_rule.consume(events)
    cited_events = {event.id: event for event in cited_rule.drain_staged()}
    cited_rule.bind_loader(lambda ids: [cited_events[identity] for identity in ids if identity in cited_events])
    expected = sorted((match.group_key, match.proposed_lane, match.ts) for match in cited_rule.finalize())
    missing = next(event.id for event in events if event.get("process.uid") == "0")
    monkeypatch.setattr(sw, "fresh_pack", lambda: [rule])
    monkeypatch.setattr(sw, "execute", lambda client, intent, contract: _complete(intent, records))
    start = datetime(2030, 1, 6, 9, tzinfo=UTC)
    window = Window(start=start, end=start+timedelta(hours=1))
    sweep = sw.Sweep(_repo(), None, "h1", window, {}, stage_dir=tmp_path)
    sweep.run_partition("romulus-host-x", None, [], window, est=len(records))
    stage = sweep._event_stage()
    load = stage.load
    monkeypatch.setattr(stage, "load", lambda ids: [event for event in load(ids) if event.id != missing])
    sweep.finalize()
    candidates = sweep.repo.candidates("h1")
    assert sorted(row["lane"] for row in candidates) == ["high", "lead"]
    assert sorted((row["group_key"], row["lane"], row["ts"]) for row in candidates) == [
        (key, lane, stamp.replace(tzinfo=None)) for key, lane, stamp in expected]
    [uncited] = [row for row in candidates if not row["event_ids"]]
    assert uncited["lane"] == "lead" and "/etc/cron.d/group0" in uncited["claim"]
    assert "no citation could be retained" in uncited["claim"]


def test_tight_native_linux_fallbacks_preserve_the_computed_lanes(tmp_path, monkeypatch):
    from tests import throughput_fixture as tf
    tf.patched_sizes(monkeypatch)
    monkeypatch.setattr(sw, "state_budget", lambda settings, stage_dir:
                        StateBudget(stage_dir, disk_total=400000, reserve=0))
    snapshot = tf.run_stack(tmp_path, docs=tf.build(1))
    lanes = {}
    for row in snapshot["candidates"]:
        lanes.setdefault(row["rule_id"], []).append(row["lane"])
    assert lanes["host.interpreter_external_connection"] == ["high"]
    assert lanes["host.shell_spawned_by_connected_process"] == ["lead"]
    assert sorted(lanes["host.web_service_spawns_interpreter"]) == ["lead", "lead"]
