"""One exec store for every rule that reads process ancestry: each exec record is held once, compactly, and every
rule's view of it answers as its own history did, across pid reuse and reboots."""
import hashlib
from datetime import UTC, datetime, timedelta

from romulus.detect import bounded
from romulus.detect.auth import AccountOrGroupChange
from romulus.detect.bounded import KeyedStore, SpillList
from romulus.detect.correlation import InterpreterExternalConnection
from romulus.detect.hijack import NonRootWriteRootExecutedFile
from romulus.detect.host import DAEMON, ExecLineage, share_lineage
from romulus.detect.kernel_files import PersistencePathChange
from romulus.detect.lineage import ReverseShellByLineage
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
    for b in range(n // per):
        batch = [benign_exec(b * per + i, T0 + timedelta(minutes=b, milliseconds=i)) for i in range(per)]
        for pb in pack:
            pb.consume(batch)
            if pb.staged:
                pb.drain_staged()
    stores = _stores(pack)
    lineage = [s for s in stores if s.name == "exec_lineage"]
    assert len(lineage) == 1 and not [s for s in stores if s.name in OLD_EXEC_STORES]
    readers = [pb for pb in pack if any(isinstance(v, ExecLineage) for holder in (pb, *vars(pb).values())
                                        for v in getattr(holder, "__dict__", {}).values())]
    assert len(readers) >= 8                # account, 3 tamper, interpreter, reverse shell, persistence, hijack
    per_exec = lineage[0].disk_bytes / lineage[0].on_disk
    assert lineage[0].on_disk >= n - 50 and per_exec <= 300, per_exec          # the pickled record: ~210 B
    # each exec is also kept once for citation (the compressed typed record, in the same shared lineage), so a claim
    # that names an exec ancestor cites it
    records = [s for s in stores if s.name == "exec_records"]
    assert len(records) == 1 and records[0].on_disk >= n - 50
    # the real database bytes of every rule's spill per exec (record, both key forms and the key index, and the record
    # kept for citation): ~1 KB, the citation copy about 600 B of it
    spilled = 0
    for pb in pack:
        if pb._spill is not None:
            spilled += pb._spill.db.execute("PRAGMA page_count").fetchone()[0] * pb._spill._page
    assert spilled / n <= 1200, spilled / n
    for pb in pack:
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
    assert persistence._parent("h1", 500, at_t2).exe == "/usr/bin/python3"
    # the root-job daemon view: root, outside any login, with a program identity
    flags = {r.event_id: r.flags & DAEMON for pid in (500, 600, 700) for r in shared.entries("h1", pid)}
    assert flags == {"a": 0, "b": DAEMON, "c": 0, "d": DAEMON}


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
