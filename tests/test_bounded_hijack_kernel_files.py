"""Mission-scale state of the kernel file-record rules: files, session runs, owners' own sessions, persistence
changes and their groups spill to disk and read back exactly; only a disk budget refuses a record."""
from datetime import timedelta

from romulus.detect.kernel_files import PersistencePathChange, RootExecNonRootModifiableFile
from tests.test_kernel_files import JOB, T0, change, pexec, root_exec, user_exec


def _staged_run(cls, partitions, directory, hot=None, monkeypatch=None, budgets=None, published=None):
    """Drive a rule as the sweep does; matches it publishes while reading go to `published` (none is expected
    unless a list is given)."""
    if hot is not None:
        monkeypatch.setattr(cls, "HOT", hot)
    pb = cls()
    pb.spill_dir = directory
    for name, budget in (budgets or {}).items():
        getattr(pb, name).disk_budget = budget
    store = {}
    for part in partitions:
        found = pb.consume(list(part))
        if published is None:
            assert found == []
        else:
            published += found
        store.update({e.id: e for e in pb.drain_staged()})
    pb.bind_loader(lambda ids: [store[i] for i in ids if i in store])
    out = pb.finalize()
    return pb, out


def _shape(out):
    return [(m.group_key, m.claim, m.proposed_lane, m.notes, sorted(e.id for e in m.events),
             [(p.field, p.value) for p in m.predicate]) for m in out]


def _root_exec_hunt():
    """Alice's own session 7 at the start; then a root job runs the web account's script in a new session every
    minute for two days, with 300 other web-owned files run once each; root later runs alice's file in session 7."""
    parts = [[user_exec("1000", ses=7), root_exec(path="/home/alice/own.sh", owner="1000", auid="1001", ses=7,
                                                  ts=T0 + timedelta(seconds=30))]]
    minute = 0
    for _day in range(2):
        for _hour in range(24):
            parts.append([root_exec(ts=T0 + timedelta(minutes=minute + k), auid="0", ses=1000 + minute + k)
                          for k in range(60)])
            minute += 60
    parts.append([root_exec(path=f"/srv/other/f{i}.sh", ts=T0 + timedelta(hours=1, seconds=i)) for i in range(300)])
    parts.append([root_exec(path="/home/alice/own.sh", owner="1000", auid="1001", ses=7,
                            ts=T0 + timedelta(days=2, minutes=1))])
    return parts


def test_root_exec_runs_spill_to_disk_and_finalize_matches_the_unbounded_result(monkeypatch, tmp_path):
    parts = _root_exec_hunt()
    small, small_out = _staged_run(RootExecNonRootModifiableFile, parts, tmp_path / "small", hot=5,
                                   monkeypatch=monkeypatch)
    assert small.runs.on_disk > 2_000 and small.owner_sessions.on_disk + len(small.owner_sessions.hot) >= 1
    monkeypatch.setattr(RootExecNonRootModifiableFile, "HOT", 10**6)
    _big, big_out = _staged_run(RootExecNonRootModifiableFile, parts, tmp_path / "big")
    assert _shape(small_out) == _shape(big_out)
    keys = [m.group_key for m in small_out]
    assert f"app01|33|{JOB}" in keys and "app01|own:1000" in keys and len(keys) == 302
    [job] = [m for m in small_out if m.group_key == f"app01|33|{JOB}"]
    assert f"{2 * 24 * 60} times" in job.claim and "10 of these runs are cited" in job.claim
    [own] = [m for m in small_out if m.group_key == "app01|own:1000"]
    assert "2 time(s)" in own.claim and small.limit_reasons() == []


def test_root_exec_disk_budget_refuses_a_new_session_and_says_so(monkeypatch, tmp_path):
    first = [root_exec(ts=T0, ses=1), root_exec(path="/srv/other/a.sh", ts=T0, ses=1)]
    filler = [root_exec(path=f"/srv/other/f{i}.sh", ts=T0 + timedelta(seconds=i), ses=2) for i in range(20)]
    later = [root_exec(ts=T0 + timedelta(hours=1), ses=3)]
    pb, out = _staged_run(RootExecNonRootModifiableFile, [first, filler, later], tmp_path, hot=2,
                          monkeypatch=monkeypatch, budgets={"runs": 1})
    # which runs are refused depends on how many reached disk (the hot size); every refused run is not evaluated,
    # and the run of the next hour, a new session, is refused
    assert pb.capped >= 1 and pb.evaluated + pb.capped == len(first) + len(filler) + len(later)
    assert any("disk budget" in reason for reason in pb.limit_reasons())
    [job] = [m for m in out if m.group_key == f"app01|33|{JOB}"]
    assert "executed /srv/tasks/rotate.sh as the #! script once" in job.claim      # its session-1 run is kept


def _persistence_hunt():
    """A dpkg upgrade writes 3,000 files; 500 root agent writes by distinct processes; one web-account cron file."""
    parts = [[pexec("/usr/bin/dpkg", 100, 90)]]
    parts.append([change(f"/etc/init.d/svc{i}.dpkg-new", ts=T0 + timedelta(seconds=1 + i / 100), uid="0",
                         exe="/usr/bin/dpkg", pid=100, ppid=90) for i in range(3_000)])
    parts.append([change(f"/etc/cron.d/agent{i}", ts=T0 + timedelta(minutes=10 + i), uid="0", exe="/usr/bin/agent",
                         pid=10_000 + i, ppid=1) for i in range(500)])
    parts.append([change("/etc/cron.d/evil", ts=T0 + timedelta(hours=12), uid="33", pid=4000, ppid=3999)])
    return parts


def test_persistence_changes_and_groups_spill_and_match_the_unbounded_result(monkeypatch, tmp_path):
    parts = _persistence_hunt()
    monkeypatch.setattr(PersistencePathChange, "TRIM_EVERY", 7)
    small, small_out = _staged_run(PersistencePathChange, parts, tmp_path / "small", hot=5, monkeypatch=monkeypatch)
    assert small.changes.on_disk == 3_500 and len(small.changes) == 3_501
    monkeypatch.setattr(PersistencePathChange, "HOT", 10**6)
    _big, big_out = _staged_run(PersistencePathChange, parts, tmp_path / "big")
    assert _shape(small_out) == _shape(big_out) and len(small_out) == 502
    assert small_out[0].group_key == "app01|0|/etc/cron.d|pid 10000|/usr/bin/agent|2030-01-06T09:10:00+00:00"
    [pkg] = [m for m in small_out if m.group_key == "app01|package:dpkg"]
    assert "3000 kernel file-change record(s) on 3000 file(s)" in pkg.claim
    [evil] = [m for m in small_out if "/etc/cron.d/evil" in m.notes[-1]]
    assert evil.proposed_lane == "high" and small.limit_reasons() == []


def test_persistence_disk_budget_publishes_a_later_change_on_its_own_and_says_so(monkeypatch, tmp_path):
    parts = _persistence_hunt()
    alone = []
    pb, out = _staged_run(PersistencePathChange, parts, tmp_path, hot=5, monkeypatch=monkeypatch,
                          budgets={"changes": 1}, published=alone)
    # the first partition of changes reached disk; every later change is a finding on its own, published as read
    assert pb.capped == 0 and any("published as they are read" in reason for reason in pb.limit_reasons())
    assert [m.group_key for m in out] == ["app01|package:dpkg"]
    assert len(alone) == 501 and all(m.group_key.endswith("|unheld") for m in alone)
    [evil] = [m for m in alone if "/etc/cron.d/evil" in m.claim + " ".join(m.notes)]
    assert evil.proposed_lane == "high"
