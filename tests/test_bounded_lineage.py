"""Mission-scale exec history and per-key tallies of the host rules: bounded, honest when exceeded, and a cited
record's lineage survives the release of its processes."""
from datetime import UTC, datetime, timedelta

import pytest

from romulus.detect.correlation import InterpreterExternalConnection, PidTable
from romulus.detect.host import ProcessLineage
from romulus.evidence.typed import Outcome, RawRef, TypedEvent, fv

T0 = datetime(2024, 11, 4, 0, 0, tzinfo=UTC)


def ev(event_id, family, ts, host="web1", outcome=Outcome.success, **fields):
    return TypedEvent(id=event_id, family=family, ts=ts, host=host, outcome=outcome,
                      fields={k.replace("__", "."): fv(v, f"{event_id}:{k}") for k, v in fields.items()},
                      raw=[RawRef(target="host-x", native_id=event_id, digest="d")], normalizer="test@1")


def syscall_ev(event_id, family, ts, **fields):
    """A record whose process fields come from an audit SYSCALL record (process lineage reads it)."""
    event = ev(event_id, family, ts, **fields)
    for name in ("process.pid", "process.ppid", "process.executable"):
        if name in event.fields:
            event.fields[name] = fv(event.fields[name].value, f"{event_id}:event.original#auditd:SYSCALL.{name[8:]}")
    return event


def execd(pid, ppid, exe, ts, **fields):
    fields.setdefault("process__argv", [exe])
    return ev(f"exec-{pid}-{ts.timestamp()}", "process_exec", ts, process__pid=pid, process__ppid=ppid,
              process__executable=exe, **fields)


class _Owner:
    """A stand-in playbook owner for a store (its spill under tmp_path)."""

    def __init__(self, directory):
        from romulus.detect.base import Playbook

        class Holder(Playbook):
            id = "test.holder"
            title = "test"
            families = ()
        self.playbook = Holder()
        self.playbook.spill_dir = directory


@pytest.mark.slow
def test_pid_table_memory_holds_its_capacity_and_every_lookup_stays_exact(tmp_path):
    owner = _Owner(tmp_path).playbook
    table = PidTable(capacity=10_000, owner=owner)
    for pid in range(1_000_000):
        table.add(execd(pid, pid - 1, "/usr/bin/true", T0 + timedelta(milliseconds=pid)))
        if pid % 10_000 == 9_999:
            table.trim()
            assert len(table.execs.store.hot) <= 10_000
    table.trim()
    assert len(table.execs) == 1_000_000 and table.execs.store.on_disk >= 990_000
    late = (T0 + timedelta(hours=1)).timestamp()
    assert table.lookup("web1", 3, late)[2] == 2                     # read back from disk, exact
    assert [pid for pid, *_rest in table.lineage_entries("web1", 500_000, late)] == list(range(500_000, 499_994, -1))
    owner.close_spill()


def _iec_run(events, capacity, directory):
    from romulus.detect import correlation
    old = correlation.PidTable.CAPACITY
    correlation.PidTable.CAPACITY = capacity
    try:
        rule = InterpreterExternalConnection()
        rule.spill_dir = directory
        stage = {}
        for batch in events:
            rule.consume(batch)
            stage.update({e.id: e for e in rule.drain_staged()})
        rule.bind_loader(lambda ids: [stage[i] for i in ids if i in stage])
        return [(m.claim, m.proposed_lane, [e.id for e in m.events]) for m in rule.finalize()], rule
    finally:
        correlation.PidTable.CAPACITY = old


def test_pid_reuse_after_release_gives_the_unbounded_answer(tmp_path):
    """apache2 on pid 500, then python3 (a service the service manager started) reuses pid 500 and connects out from
    a child; churn moves pid 500 to disk. The lineage walk must see python3 (the latest exec of 500 before the call),
    never the older apache2."""
    spawned = syscall_ev("spawn-500", "process_observed", T0 + timedelta(minutes=5, milliseconds=-3), process__pid=500,
                         process__ppid=1, process__executable="/usr/lib/systemd/systemd")
    batches = [[execd(500, 1, "/usr/sbin/apache2", T0)],
               [spawned, execd(500, 1, "/usr/bin/python3", T0 + timedelta(minutes=5))],
               [syscall_ev("s1", "net_socket", T0 + timedelta(minutes=6), socket__syscall="connect",
                           process__executable="/usr/bin/perl", process__user="www-data", process__pid=600,
                           process__ppid=500, destination__ip="203.0.113.5", destination__port=443)],
               [execd(1000 + i, 1, "/usr/bin/true", T0 + timedelta(minutes=7, seconds=i)) for i in range(500)]]
    bounded, rule = _iec_run(batches, 20, tmp_path / "small")
    unbounded, _ = _iec_run(batches, 10**9, tmp_path / "big")
    assert rule.pids.execs.store.on_disk > 0                             # pid 500 really was moved to disk
    assert bounded == unbounded
    # python3, which the service manager started, is not a web server: the web account's call is lowered to lead, as
    # without bounds
    assert "ancestry includes the web server" not in bounded[0][0] and bounded[0][1] == "lead"


def test_process_lineage_never_forgets_an_inactive_parent(tmp_path, monkeypatch):
    monkeypatch.setattr(ProcessLineage, "CAPACITY", 20)
    owner = _Owner(tmp_path).playbook
    lineage = ProcessLineage(owner)
    lineage.observe(execd(50, 1, "/usr/bin/dpkg", T0))
    lineage.trim()
    for i in range(2000):                                   # 2,000 unrelated processes push dpkg to disk
        lineage.observe(execd(5000 + i, 1, "/usr/bin/true", T0 + timedelta(seconds=1 + i / 1000)))
        lineage.trim()
    child = execd(9999, 50, "/bin/sh", T0 + timedelta(seconds=10))
    assert lineage.classify(child).kind == "package"
    assert len(lineage.records.hot) <= 21
    owner.close_spill()


@pytest.mark.slow
def test_reverse_shell_memory_stays_bounded_without_pins_and_results_match(tmp_path, monkeypatch):
    """259,200 cron shells and an agent's sockets over nine days (the reviewer's volume): memory holds the hot sets
    only (there are no pins), and the findings equal an unbounded run's."""
    from romulus.detect.lineage import ReverseShellByLineage

    def batches():
        pid = 10_000
        for hour in range(216):
            start = T0 + timedelta(hours=hour)
            batch = []
            for k in range(1200):
                ts = start + timedelta(seconds=3 * k)
                pid += 2
                batch.append(execd(pid, 1, "/usr/bin/dash", ts, process__argv=["sh", "-c", "true"]))
                if k % 20 == 0:
                    batch.append(ev(f"agent-{pid}", "net_socket", ts, socket__syscall="connect",
                                    process__executable="/opt/agent/agent", process__pid=pid + 1,
                                    process__user="root", destination__ip="198.51.100.20", destination__port=443))
            if hour == 150:
                ts = start + timedelta(minutes=30, seconds=10)
                batch += [execd(777, 1, "/usr/bin/python3", ts),
                          ev("rs-sock", "net_socket", ts + timedelta(seconds=2), socket__syscall="connect",
                             process__executable="/usr/bin/python3", process__pid=777, process__user="root",
                             destination__ip="203.0.113.66", destination__port=4444),
                          execd(778, 777, "/bin/sh", ts + timedelta(seconds=3))]
            yield batch

    def run(hot, directory):
        monkeypatch.setattr(ReverseShellByLineage, "HOT", hot)
        monkeypatch.setattr(PidTable, "CAPACITY", hot)
        rule = ReverseShellByLineage()
        rule.spill_dir = directory
        stage, peak = {}, 0
        for batch in batches():
            rule.consume(batch)
            stage.update({e.id: e for e in rule.drain_staged()})
            peak = max(peak, len(rule.pids.execs.store.hot), len(rule.shells.buffer), len(rule.sockets.hot))
        rule.bind_loader(lambda ids: [stage[i] for i in ids if i in stage])
        out = [(m.group_key, m.claim, m.proposed_lane) for m in rule.finalize()]
        rule.close_spill()
        return out, peak, rule

    bounded, peak, rule = run(5_000, tmp_path / "small")
    assert peak <= 5_000 + 1_300 and not hasattr(rule.pids.execs, "pinned")
    assert [(key, lane) for key, _claim, lane in bounded] == [("web1|None|777|203.0.113.66", "high")]
    unbounded, _peak, _rule = run(10**9, tmp_path / "big")
    assert bounded == unbounded


def test_package_lineage_of_a_root_change_survives_exec_history_release(monkeypatch, tmp_path):
    from romulus.detect.kernel_files import PersistencePathChange
    from tests.test_kernel_files import change, pexec
    monkeypatch.setattr(PersistencePathChange, "EXEC_CAPACITY", 50)
    rule = PersistencePathChange()
    rule.spill_dir = tmp_path
    rule.consume([pexec("/usr/bin/dpkg", 100, 90, ts=T0)])
    rule.consume([change("/etc/cron.d/a", uid="0", exe="/usr/bin/dash", pid=101, ppid=100,
                         ts=T0 + timedelta(seconds=1))])
    rule.consume([pexec("/usr/bin/true", 1000 + i, 1, ts=T0 + timedelta(seconds=2 + i)) for i in range(500)])
    staged = {e.id: e for e in rule.drain_staged()}
    assert len(rule.execs.store.hot) <= 50 and rule.execs.evicted > 0       # dpkg's exec is on disk, not lost
    rule.bind_loader(lambda ids: [staged[i] for i in ids if i in staged])
    [m] = rule.finalize()
    assert m.group_key == "app01|package:dpkg" and rule.limit_reasons() == []


@pytest.mark.slow
def test_root_job_series_and_scheduler_sessions_stay_bounded_over_weeks(monkeypatch, tmp_path):
    """A root cron job runs a script every 10 minutes for two weeks, each in a new cron session; on day 9 the web
    account edits it. Every scheduler session is held for the whole hunt, memory holds only the hot set, held run
    times stay bounded, and the counts in the claim are exact."""
    from romulus.detect.hijack import NonRootWriteRootExecutedFile
    from tests.test_hijack_root_job import JOB, VI, cron_runs, web
    monkeypatch.setattr(NonRootWriteRootExecutedFile, "HOT", 20)
    rule = NonRootWriteRootExecutedFile()
    rule.spill_dir = tmp_path
    stage = {}
    write_at = T0 + timedelta(days=9, hours=4, minutes=5)
    for hour in range(24 * 14):
        start = T0 + timedelta(hours=hour)
        batch = []
        for k in range(6):
            ts = start + timedelta(minutes=10 * k)
            batch += cron_runs(ts, ses=hour * 6 + k + 10, pid=50_000 + (hour * 6 + k) * 3)
        if start <= write_at < start + timedelta(hours=1):
            batch.append(web(*VI, ts=write_at))
        rule.consume(batch)
        stage.update({e.id: e for e in rule.drain_staged()})
        for store in (rule.files, rule.sessions, rule.session_pids):
            assert len(store.hot) <= 20
        for series in (s for state in rule.files.hot.values() for s in state.runs.values()):
            assert len(series.ok_ts.kept) <= series.ok_ts.KEPT
    runs = 6 * 24 * 14                                                 # each run has two exec records naming JOB
    assert len(rule.sessions) == runs and rule.sessions.on_disk >= runs - 20   # none released, most on disk
    rule.bind_loader(lambda ids: [stage[i] for i in ids if i in stage])
    [m] = rule.finalize()
    after = runs - (6 * (24 * 9 + 4) + 1)                              # runs that began after the write
    assert f"{2 * runs} root exec record(s) in the window execute {JOB}" in m.claim
    assert f"; {2 * after} of them began after the first write-capable command" in m.claim
    assert m.proposed_lane == "high" and rule.limit_reasons() == []
    rule.close_spill()
