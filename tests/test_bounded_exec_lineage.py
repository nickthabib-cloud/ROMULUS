"""One exec store for every rule that reads process ancestry: each exec record is held once, compactly, and every
rule's view of it answers as its own history did, across pid reuse and reboots."""
import hashlib
import json
from datetime import UTC, datetime, timedelta

from romulus.detect import bounded
from romulus.detect.auth import AccountOrGroupChange
from romulus.detect.bounded import KeyedStore, SpillList
from romulus.detect.correlation import InterpreterExternalConnection
from romulus.detect.hijack import NonRootWriteRootExecutedFile
from romulus.detect.host import DAEMON, ExecLineage, share_lineage
from romulus.detect.kernel_files import PersistencePathChange
from romulus.detect.lineage import ReverseShellByLineage
from romulus.detect.linux_sequences import CLOCK_BIN, LinuxSequence
from romulus.detect.registry import fresh_pack
from romulus.evidence.typed import Outcome, RawRef, TypedEvent, fv

T0 = datetime(2024, 11, 18, 10, 0, tzinfo=UTC)
OLD_EXEC_STORES = {"process_lineage", "pid_table", "persistence_execs", "hijack_daemons"}


def benign_exec(i: int, ts: datetime) -> TypedEvent:
    """A realistic benign exec: a long event id, a long raw id, a helper path."""
    eid = "process_exec-" + hashlib.sha256(str(i).encode()).hexdigest()[:40]
    fields = {"process.pid": 10000 + i % 400000, "process.ppid": 900 + i % 50, "process.uid": "1000",
              "process.user": "alice", "process.executable": f"/usr/lib/x86_64-linux-gnu/helper{i % 40}",
              "process.argv": [f"/usr/lib/x86_64-linux-gnu/helper{i % 40}", "--opt", str(i)]}
    return TypedEvent(id=eid, family="process_exec", ts=ts, host=f"ws-{i % 2000:04d}.corp.example",
                      outcome=Outcome.success, fields={k: fv(v, f"{eid}:{k}") for k, v in fields.items()},
                      raw=[RawRef(target="logs-auditd-default", native_id=hashlib.md5(str(i).encode()).hexdigest()[:20])],
                      normalizer="fixture")


def _stores(pack):
    """Every KeyedStore and SpillList reachable from the pack's rules (one level into their views)."""
    found = {}
    for pb in pack:
        for holder in (pb, *vars(pb).values()):
            for value in getattr(holder, "__dict__", {}).values():
                target = value.store if isinstance(value, ExecLineage) else value
                if isinstance(target, (KeyedStore, SpillList)):
                    found[id(target)] = target
    return list(found.values())


def test_the_pack_holds_each_exec_once_in_one_compact_store(monkeypatch, tmp_path):
    keyed = KeyedStore.__init__
    monkeypatch.setattr(KeyedStore, "__init__", lambda self, owner, name, hot, **kw: keyed(self, owner, name, 1, **kw))
    pack = fresh_pack()
    for pb in pack:
        pb.spill_dir = tmp_path
    n, per = 12_000, 3_000
    clock_edges = {}
    try:
        for b in range(n // per):
            batch = [benign_exec(b * per + i, T0 + timedelta(minutes=b, milliseconds=i)) for i in range(per)]
            raw = {event.raw[0].key: {"@timestamp": event.ts.isoformat(), "message": "synthetic exec"}
                   for event in batch}
            for event in batch:
                when = event.ts.timestamp()
                key = (event.host, event.family, int(when // CLOCK_BIN))
                edge = (when, event.id)
                first, last = clock_edges.get(key, (edge, edge))
                clock_edges[key] = min(first, edge), max(last, edge)
            for pb in pack:
                pb.bind_raw(raw, "host-target")
                pb.consume(batch)
                if pb.staged:
                    drained = pb.drain_staged()
                    if isinstance(pb, LinuxSequence):
                        assert drained == []
                        if pb._spill is not None:
                            assert all(not rows for _sql, rows in pb._spill._buffers.values())
                        assert pb.retained_events() == [] and pb.pending_count == 0
        stores = _stores(pack)
        lineage = [s for s in stores if s.name == "exec_lineage"]
        records = [s for s in stores if s.name == "exec_records"]
        linux = [pb for pb in pack if isinstance(pb, LinuxSequence)]
        witnesses = {id(pb.witnesses): pb.witnesses for pb in linux}
        original_spills = {id(pb._spill): pb._spill for pb in pack
                           if pb._spill is not None and not isinstance(pb, LinuxSequence)}
        spills = {id(pb._spill): pb._spill for pb in pack if pb._spill is not None}
        for pb in linux:
            for spill in (pb.witnesses._spill, pb.shared_rows.database if pb.shared_rows is not None else None):
                if spill is not None:
                    spills[id(spill)] = spill
        physical = []
        for spill in spills.values():
            spill.flush()
            pages = spill.db.execute("PRAGMA page_count").fetchone()[0]
            actual = pages * spill._page
            assert actual == spill.path.stat().st_size
            assert spill.budget._physical[("spill", id(spill))][0] == actual
            assert spill.budget.physical_used <= spill.budget.disk_total
            tables = [name for (name,) in spill.db.execute("SELECT name FROM sqlite_master WHERE type='table'")]
            counts = {name: spill.db.execute('SELECT COUNT(*) FROM "' + name.replace('"', '""') + '"').fetchone()[0]
                      for name in tables}
            physical.append({"owners": [pb.id for pb in pack if pb._spill is spill],
                             "original": id(spill) in original_spills, "pages": pages,
                             "page_size": spill._page, "bytes": actual, "rows": counts})
        assert {spill.path for spill in spills.values()} == set(tmp_path.rglob("spill.db"))
        original_bytes = sum(row["bytes"] for row in physical if row["original"])
        total_bytes = sum(row["bytes"] for row in physical)
        print(f"\n{n:,} execs; original spill bytes {original_bytes}, new scalar/clock/witness bytes "
              f"{total_bytes - original_bytes}, total physical bytes {total_bytes}; "
              f"{total_bytes / n:.3f} B per exec")
        print(json.dumps({"execs": n, "original_bytes": original_bytes, "total_bytes": total_bytes,
                          "bytes_per_exec": total_bytes / n, "spills": physical}, sort_keys=True))
        assert len(lineage) == 1 and not [s for s in stores if s.name in OLD_EXEC_STORES]
        readers = [pb for pb in pack if any(isinstance(v, ExecLineage) for holder in (pb, *vars(pb).values())
                                            for v in getattr(holder, "__dict__", {}).values())]
        assert len(readers) >= 8
        per_exec = lineage[0].disk_bytes / lineage[0].on_disk
        assert lineage[0].on_disk >= n - 50 and per_exec <= 300, per_exec
        assert len(records) == 1 and records[0].on_disk >= n - 50
        citation_per_exec = records[0].disk_bytes / records[0].on_disk
        assert citation_per_exec <= 250, citation_per_exec
        sequence_readers = [pb for pb in linux if hasattr(pb, "execs")]
        assert {pb.id for pb in sequence_readers} == {
            "host.download_then_execute", "host.tool_cleanup", "host.web_shell_chain",
            "host.unbrokered_privilege_transition", "host.discovery_burst", "corr.alert_then_host_execution"}
        assert len({id(pb.execs) for pb in sequence_readers}) == 1
        assert all(pb.execs.store is lineage[0] for pb in sequence_readers)
        assert len(witnesses) == 1
        [witness] = witnesses.values()
        assert witness.count() == 0 and not witness.pending  # raw-bound execs reuse lineage citation pointers
        shared_readers = [pb for pb in linux if pb.shared_rows is not None]
        assert {pb.id for pb in shared_readers} == {
            "host.download_then_execute", "host.tool_cleanup", "corr.alert_then_host_execution"}
        assert len({id(pb.shared_rows) for pb in shared_readers}) == 1
        shared_spill = shared_readers[0].shared_rows.database
        assert all(pb.spill() is shared_spill for pb in shared_readers)
        assert list(shared_spill.db.execute("SELECT role,COUNT(*),COUNT(DISTINCT id) FROM records GROUP BY role")) \
            == [("execute", n, n)]
        for pb in linux:
            if pb not in shared_readers and pb._tables:
                assert pb.query("SELECT COUNT(*) FROM records").fetchone()[0] == 0
        [clock] = [pb for pb in linux if pb.id == "host.telemetry_gap_after_tamper"]
        actual_edges = {}
        for host, family, bin_id, first_id, first_ts, first_body, last_id, last_ts, last_body in clock.query(
                "SELECT host,key,bin,first_id,first_ts,first_body,last_id,last_ts,last_body FROM clock"):
            assert first_body[:1] == last_body[:1] == b"P"
            actual_edges[(host, family, bin_id)] = ((first_ts, first_id), (last_ts, last_id))
        assert len(actual_edges) == 2_000 and actual_edges == clock_edges
        # The full ingest footprint includes the original stores, the one shared execute table and clock edges.
        # 1,200 B/exec is about 1.5x the prior 773 B/exec pack, with SQLite page rounding at this fixture size.
        assert total_bytes / n <= 1200, physical
    finally:
        for pb in pack:
            if isinstance(pb, LinuxSequence):
                pb.release_state()
            else:
                pb.close_spill()


def _exec(eid, pid, ppid, exe, ts, *, boot=None, user="root", uid="0", auid=None, host="h1"):
    fields = {"process.pid": pid, "process.ppid": ppid, "process.executable": exe, "process.argv": [exe],
              "process.user": user, "process.uid": uid}
    if auid is not None:
        fields["process.auid"] = auid
    if boot is not None:
        fields["host.boot.id"] = boot
    return TypedEvent(id=eid, family="process_exec", ts=ts, host=host, outcome=Outcome.success,
                      fields={k: fv(v, "fixture") for k, v in fields.items()},
                      raw=[RawRef(target="t", native_id=f"raw-{eid}")], normalizer="fixture")


def test_every_view_reads_the_one_store_and_answers_across_pid_reuse_and_reboots(tmp_path):
    account, iec, persistence = AccountOrGroupChange(), InterpreterExternalConnection(), PersistencePathChange()
    hijack, shells = NonRootWriteRootExecutedFile(), ReverseShellByLineage()
    pack = [account, iec, persistence, hijack, shells]
    for pb in pack:
        pb.spill_dir = tmp_path
    share_lineage(pack)
    shared = account.lineage.execs
    assert iec.pids.execs is shared and shells.pids.execs is shared
    assert persistence.execs is shared and hijack.daemons is shared
    t1, t2 = T0 + timedelta(hours=1), T0 + timedelta(hours=2)
    batch = [_exec("a", 500, 1, "/usr/sbin/apache2", T0, boot="A", user="www-data", uid="33"),
             _exec("b", 500, 1, "/usr/bin/python3", t1, boot="B"),
             _exec("c", 600, 1, "/usr/sbin/cron", t1, boot="B", auid="1000"),       # a login's root exec
             _exec("d", 700, 1, "/usr/sbin/cron", t1, boot="B")]                    # a daemon's
    batch[2].fields["process.euid"] = fv("0", "fixture")
    for pb in pack:                         # each rule reads the batch; the store holds each record once
        pb.consume(batch)
    assert len(shared) == 3 and len(shared.entries("h1", 500)) == 2
    at_t1, at_t2 = t1.timestamp() + 1, t2.timestamp()
    # the account/tamper view
    assert account.lineage.parent("h1", 500, at_t1, "B").name == "python3"
    assert account.lineage.parent("h1", 500, at_t1, "A") is None              # the boot A exec is older
    assert account.lineage.parent("h1", 500, T0.timestamp() + 1, "A").user == "www-data"
    # the socket-lineage view
    assert iec.pids.lookup("h1", 500, at_t2, "B")[1] == "/usr/bin/python3"
    assert iec.pids.exec_before("h1", 500, t1.timestamp(), "B") is None       # apache2 was another boot
    assert iec.pids.exec_before("h1", 500, t1.timestamp(), None)[1] == "/usr/sbin/apache2"
    assert iec.pids.lookup(None, 500, at_t2) is None                          # a record without a host
    # the package-lineage view
    assert persistence.execs.latest("h1", 500, at_t2, where=lambda record: bool(record.exe)).exe \
        == "/usr/bin/python3"
    # the root-job daemon view: root, outside any login, with a program identity
    flags = {r.event_id: r.flags & DAEMON for pid in (500, 600, 700) for r in shared.entries("h1", pid)}
    assert flags == {"a": 0, "b": DAEMON, "c": 0, "d": DAEMON}
    login = shared.entries("h1", 600)[0]
    assert (login.uid, login.euid, login.auid) == ("0", "0", "1000")


def test_a_record_handed_over_again_is_held_once(tmp_path):
    lineage = ExecLineage()
    record = _exec("x", 42, 1, "/usr/bin/true", T0)
    for _ in range(3):
        lineage.observe(record)
    assert len(lineage.entries("h1", 42)) == 1


def test_the_exec_store_alone_is_memory_only_without_an_owner():
    lineage = ExecLineage(capacity=bounded.HOT_COUNT)
    for i in range(100):
        lineage.observe(_exec(f"e{i}", 1000 + i, 1, "/usr/bin/true", T0 + timedelta(seconds=i)))
    lineage.trim()
    assert lineage.evicted == 0 and len(lineage) == 100
