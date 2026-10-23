"""Mission-scale state of the non-root-write / root-run rule: scheduler sessions are held for the whole hunt, per-file
state spills to disk and is read back exactly, and only a disk budget refuses a record."""
from datetime import timedelta

from romulus.detect.hijack import NonRootWriteRootExecutedFile
from tests.test_hijack_root_job import JOB, T0, VI, cron_open, cron_runs, ex, web


def _run(partitions, tmp_path, hot=None, budget=None, monkeypatch=None):
    if hot is not None:
        monkeypatch.setattr(NonRootWriteRootExecutedFile, "HOT", hot)
    pb = NonRootWriteRootExecutedFile()
    pb.spill_dir = tmp_path
    if budget is not None:
        pb.files.disk_budget = budget
    store = {}
    for part in partitions:
        assert pb.consume(list(part)) == []
        store.update({e.id: e for e in pb.drain_staged()})
    pb.bind_loader(lambda ids: [store[i] for i in ids if i in store])
    out = pb.finalize()
    return pb, out


def _other_sessions(start, n, base=20_000):
    """n other cron sessions on the host, each running a different script (filler that moves time and state)."""
    out = []
    for i in range(n):
        out += cron_runs(start + timedelta(seconds=40 * i), path=f"/srv/other/job{i}.sh", ses=base + i,
                         pid=100_000 + 3 * i)
    return out


def test_a_long_running_cron_job_is_still_attributed_to_its_scheduler_session(monkeypatch, tmp_path):
    """A cron session opens; the web account edits the script; 20 hours later, after thousands of other cron
    sessions, a root process in that same session runs the script: the scheduler class and its session record."""
    opened = cron_open(T0, ses=77, pid=6000)
    writer = web(*VI, ts=T0 + timedelta(hours=1))
    filler = _other_sessions(T0 + timedelta(hours=2), 1_500)
    late = ex(["/bin/bash", JOB], "/usr/bin/bash", 0, T0 + timedelta(hours=20), auid=0, ses=77, pid=6001,
              ppid=6000, cwd="/root")
    pb, out = _run([[opened, writer], filler[:2_000], filler[2_000:], [late]], tmp_path, hot=50,
                   monkeypatch=monkeypatch)
    [m] = out
    assert "T1053.003" in m.notes and "the scheduler 'cron'" in m.claim
    assert opened.id in {e.id for e in m.events} and late.id in {e.id for e in m.events}
    assert pb.sessions.on_disk > 0 and pb.limit_reasons() == []


def test_file_state_on_disk_reads_back_to_the_same_finding(monkeypatch, tmp_path):
    """The written file's state goes to disk under thousands of later files and comes back exact."""
    writer = web(*VI)
    first = cron_runs(T0 + timedelta(minutes=5))
    filler = _other_sessions(T0 + timedelta(minutes=10), 600)
    later = cron_runs(T0 + timedelta(hours=10), ses=13, pid=7000)
    parts = [[writer, *first], filler[:900], filler[900:], later]
    pb, small = _run(parts, tmp_path / "small", hot=5, monkeypatch=monkeypatch)
    assert pb.files.on_disk > 0 and len(pb.files.hot) <= 5
    monkeypatch.setattr(NonRootWriteRootExecutedFile, "HOT", 10**6)
    _pb, big = _run(parts, tmp_path / "big")
    shape = [(m.group_key, m.claim, m.proposed_lane, sorted(e.id for e in m.events)) for m in small]
    assert shape == [(m.group_key, m.claim, m.proposed_lane, sorted(e.id for e in m.events)) for m in big]
    assert "2 root exec record(s) in the window execute" not in small[0].claim     # all four runs counted
    assert "4 root exec record(s) in the window execute" in small[0].claim


def test_only_the_disk_budget_refuses_a_new_file_and_the_record_is_not_evaluated(monkeypatch, tmp_path):
    writer = web(*VI)
    filler = _other_sessions(T0 + timedelta(minutes=1), 50)
    runs = cron_runs(T0 + timedelta(hours=1))
    new_file = cron_runs(T0 + timedelta(hours=2), path="/srv/other/new.sh", ses=14, pid=8000)
    pb, out = _run([[writer], filler, runs], tmp_path / "a", hot=2, budget=1, monkeypatch=monkeypatch)
    evaluated = pb.evaluated
    [m] = out                                       # a file already held is read back from disk, never refused
    assert m.group_key == f"app01|www-data|{JOB}" and pb.capped == 0
    pb, out = _run([[writer], filler, runs, new_file], tmp_path / "b", hot=2, budget=1, monkeypatch=monkeypatch)
    [m] = out
    assert m.group_key == f"app01|www-data|{JOB}"
    # the new file's two root runs are refused; its session record is still evaluated
    assert pb.capped == 2 and pb.evaluated == evaluated + 1
    assert any("disk budget" in reason for reason in pb.limit_reasons())
