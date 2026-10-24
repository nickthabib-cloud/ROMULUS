"""Process lineage from non-exec observations.

A process that forked without exec has no exec record, but every system call the audit rules record for it names its
executable, its parent and its audit session. The lineage learns those states (one entry per change, never one per
record) and walks through the parent each process had when it was forked. A parent of pid 1 never proves a start by
the service manager: only the process's own earliest record running the service manager's image does. Addresses are
documentation ranges; the lab shape keeps the lab's pids, times and programs.
"""
import itertools
from datetime import UTC, datetime

import pytest

from romulus.detect.bounded import StateBudget
from romulus.detect.correlation import (
    PROCESSES_JUDGED,
    InterpreterExternalConnection,
    PidTable,
    ProcessNetworkLink,
)
from romulus.detect.host import ExecLineage
from romulus.detect.observed import REPARENT_GAP, Observed, process_view
from romulus.evidence.normalize import normalize_hits
from romulus.evidence.typed import RawRef, TypedEvent, fv

HOST = "videoserver"
EXT = "203.0.113.65"             # stands in for an address outside the site's internal networks
SADDR_EXT_554 = "0200022ACB007141" + "0" * 16      # AF_INET, port 554, 203.0.113.65
SADDR_LOCAL = "01002F72756E2F73797374656D642F6A6F75726E616C2F73746465727200"   # /run/systemd/journal/stderr
T = 1731925281.941               # 2024-11-18T10:21:21.941Z


def _iso(t: float) -> str:
    return datetime.fromtimestamp(t, UTC).isoformat().replace("+00:00", "Z")


def _hit(_id, raw, t):
    return {"_id": _id, "_index": "host-logs-x", "_source": {
        "@timestamp": _iso(t), "message": raw, "host": {"name": HOST},
        "event": {"dataset": "linux.audit", "original": raw}}}


def _syscall(t, serial, *, nr, name, pid, ppid, exe, comm, uid="0", user="root", success="yes", exit_code="0",
             ses="4294967295", a2="80000"):
    auid = "4294967295" if ses == "4294967295" else "1000"
    return (f"type=SYSCALL msg=audit({t:.3f}:{serial}): arch=c000003e syscall={nr} success={success} exit={exit_code} "
            f"a0=ffffff9c a1=7f52fd14e176 a2={a2} a3=0 items=0 ppid={ppid} pid={pid} auid={auid} uid={uid} gid={uid} "
            f"euid={uid} suid={uid} fsuid={uid} egid={uid} sgid={uid} fsgid={uid} tty=(none) ses={ses} comm=\"{comm}\" "
            f"exe=\"{exe}\" subj==unconfined key=\"k\"\x1dARCH=x86_64 SYSCALL={name} AUID=\"unset\" UID=\"{user}\" "
            f"EUID=\"{user}\"")


def observe(t, serial, pid, ppid, exe, comm="x", uid="0", user="root", ses="4294967295"):
    """A read-only open that failed: no typed event of its own family, so a process_observed record."""
    return [_hit(f"o{serial}", _syscall(t, serial, nr=257, name="openat", pid=pid, ppid=ppid, exe=exe, comm=comm,
                                        uid=uid, user=user, success="no", exit_code="-13", ses=ses), t)]


def spawn(t, serial, pid, comm="(service)"):
    """systemd's spawn child (the service manager's image) connecting to journald before it execs the service."""
    raw = _syscall(t, serial, nr=42, name="connect", pid=pid, ppid=1, exe="/usr/lib/systemd/systemd", comm=comm,
                   a2="1e")
    return [_hit(f"s{serial}", raw, t),
            _hit(f"k{serial}", f"type=SOCKADDR msg=audit({t:.3f}:{serial}): saddr={SADDR_LOCAL}", t)]


def execd(t, serial, pid, ppid, exe, argv, uid="0", user="root", ses="4294967295"):
    execve = f"type=EXECVE msg=audit({t:.3f}:{serial}): argc={len(argv)} " + " ".join(
        f'a{i}="{a}"' for i, a in enumerate(argv))
    return [_hit(f"e{serial}", execve, t),
            _hit(f"x{serial}", _syscall(t, serial, nr=59, name="execve", pid=pid, ppid=ppid, exe=exe,
                                        comm=argv[0].rsplit("/", 1)[-1][:15], uid=uid, user=user, ses=ses), t)]


def connect(t, serial, pid, ppid, exe, comm, uid="33", user="www-data", saddr=SADDR_EXT_554, success="no",
            exit_code="-115", ses="4294967295"):
    raw = _syscall(t, serial, nr=42, name="connect", pid=pid, ppid=ppid, exe=exe, comm=comm, uid=uid, user=user,
                   success=success, exit_code=exit_code, a2="10", ses=ses)
    return [_hit(f"c{serial}", raw, t),
            _hit(f"a{serial}", f"type=SOCKADDR msg=audit({t:.3f}:{serial}): saddr={saddr}", t)]


def normalized(*groups):
    hits = [hit for group in groups for hit in group]
    events, _skips, errors = normalize_hits(hits)
    assert errors == []
    return events, {f"{h['_index']}/{h['_id']}": h["_source"] for h in hits}


def drive(rule, events, raw_sources=None):
    """Consume, stage and finalize the way the sweep does (raw copies bound while the rule reads the batch)."""
    stage = {}
    rule.bind_raw(raw_sources or {})
    rule.consume([e for e in events if e.family in rule.families])
    rule.bind_raw({})
    stage.update({e.id: e for e in rule.drain_staged()})
    rule.bind_loader(lambda ids: [stage[i] for i in ids if i in stage])
    return rule.finalize()


def table(events) -> PidTable:
    pids = PidTable(observing=True)
    for event in events:
        pids.add(event)
    return pids


# ---- the lab shape: zmc under a daemonized zmdc.pl, under a service the service manager started --------------------
def lab_zmc():
    """videoserver: systemd forks pid 817 ('(zmpkg.pl)', the service manager's image) and it execs zmpkg.pl; zmpkg.pl
    runs sudo (871), which runs zmdc.pl (872, www-data); zmdc.pl forks 874, which never execs and is reparented to
    pid 1 when 872 exits; 874 forks 905, which execs zmc, and zmc connects out."""
    return normalized(
        spawn(T, 843, 817, comm="(zmpkg.pl)"),
        execd(T, 846, 817, 1, "/usr/bin/perl", ["/usr/bin/perl", "-wT", "/usr/bin/zmpkg.pl", "start"]),
        execd(1731925282.333, 916, 871, 817, "/usr/bin/sudo", ["sudo", "-u", "www-data", "/usr/bin/zmdc.pl",
                                                               "startup"]),
        execd(1731925282.345, 924, 872, 871, "/usr/bin/perl", ["/usr/bin/perl", "-wT", "/usr/bin/zmdc.pl", "startup"],
              uid="33", user="www-data"),
        observe(1731925282.521, 927, 872, 871, "/usr/bin/perl", "zmdc.pl", "33", "www-data"),
        observe(1731925282.525, 928, 874, 872, "/usr/bin/perl", "zmdc.pl", "33", "www-data"),
        observe(1731925283.893, 971, 874, 1, "/usr/bin/perl", "zmdc.pl", "33", "www-data"),
        observe(1731925283.893, 972, 905, 874, "/usr/bin/perl", "zmdc.pl", "33", "www-data"),
        execd(1731925283.901, 975, 905, 874, "/usr/bin/zmc", ["/usr/bin/zmc", "-m", "1"], uid="33", user="www-data"),
        observe(1731925284.049, 987, 874, 1, "/usr/bin/perl", "zmdc.pl", "33", "www-data"),
        connect(1731925284.097, 1000, 905, 874, "/usr/bin/zmc", "zmc"),
    )


def test_the_lab_zmc_lineage_reaches_the_service_manager_and_its_lane_is_lowered_for_that_reason():
    events, raw = lab_zmc()
    assert sum(e.family == "process_observed" for e in events) == 6      # the spawn child's connect and five opens
    [m] = drive(InterpreterExternalConnection(), events, raw)
    assert m.proposed_lane == "lead"
    assert "'/usr/bin/zmc' (pid 905, user 'www-data')" in m.claim
    assert "Its ancestry reaches the service manager with no web server." in m.claim
    [note] = [n for n in m.notes if n.startswith("lane lowered to lead")]
    # the chain: zmdc.pl's forked child (observed), zmdc.pl, sudo, zmpkg.pl, and zmpkg.pl's spawn record
    assert (note.index("/usr/bin/perl (pid 874, observed, record o971; forked under pid 872, record o928)")
            < note.index("/usr/bin/perl (pid 872, exec"))
    assert "/usr/bin/sudo (pid 871, exec" in note and "/usr/bin/perl (pid 817, exec" in note
    assert note.endswith("/usr/lib/systemd/systemd (pid 817, its image before its exec, observed, record s843))")
    # every observed record the lineage rests on is cited, with its raw copy
    cited = {e.raw[0].native_id for e in m.events if e.family == "process_observed"}
    assert {"s843", "o928", "o971", "o972"} <= cited
    assert all(r.key in m.raw_copies for e in m.events if e.family == "process_observed" for r in e.raw)


def test_the_lab_zmc_lineage_without_the_spawn_record_stays_unknown_and_high():
    events, raw = lab_zmc()
    events = [e for e in events if e.raw[0].native_id != "s843"]
    [m] = drive(InterpreterExternalConnection(), events, raw)
    assert m.proposed_lane == "high" and "not fully recorded" in m.claim
    assert any("pid 817" in n and "parent pid 1" in n for n in m.notes)


def test_the_lab_zmc_network_join_is_lowered_by_the_same_lineage():
    from tests.test_network_correlation import flow, history
    events, raw = lab_zmc()
    hs, hn = history(saddr="0200022ACB007141")          # earlier unique joins establish the host's address
    net = normalize_hits([flow("z1", dst=EXT, dport=554, cid="1:zmc=", start="2024-11-18T10:21:24.090000+0000",
                               end="2024-11-18T10:30:00.000000+0000")])[0]
    rule = ProcessNetworkLink()
    matches = drive(rule, [*hs, *hn, *events, *net], raw)
    [m] = [m for m in matches if "/usr/bin/zmc" in m.claim]
    assert m.proposed_lane == "lead" and "reaches the service manager with no web server" in m.claim
    assert any(n.startswith("lane lowered to lead") and "s843" in n for n in m.notes)
    assert "s843" in {e.raw[0].native_id for e in m.events}


# ---- the brief's cases --------------------------------------------------------------------------------------------
def _service(pid=400, t=T, serial=10, exe="/usr/bin/perl", argv=("/usr/bin/perl", "/usr/sbin/daemon.pl")):
    """A service the service manager started: its spawn child's record, then its exec."""
    return [spawn(t, serial, pid), execd(t + 0.002, serial + 1, pid, 1, exe, list(argv))]


def test_a_forked_daemon_child_reaches_the_service_manager():
    events, _ = normalized(*_service(), observe(T + 5, 20, 401, 400, "/usr/bin/perl", uid="33", user="www-data"))
    found = table(events).ancestry_of(HOST, 401, T + 6, None, 30)
    assert found.verdict == "service_manager", found.why
    assert [(link.pid, link.observed, link.start) for link in found.chain] == [(400, False, False), (400, True, True)]


def test_a_forked_apache_worker_makes_its_childs_ancestry_the_web_server():
    events, raw = normalized(
        *_service(500, exe="/usr/sbin/apache2", argv=("/usr/sbin/apache2", "-k", "start")),
        observe(T + 5, 20, 501, 500, "/usr/sbin/apache2", "apache2", "33", "www-data"),     # a worker: no exec
        execd(T + 6, 21, 502, 501, "/usr/bin/dash", ["sh", "-c", "id"], "33", "www-data"),
        connect(T + 7, 22, 502, 501, "/usr/bin/dash", "sh", saddr="0200115CCB007141" + "0" * 16))
    found = table(events).ancestry_of(HOST, 502, T + 7, None, 22)
    assert found.verdict == "web_server"
    assert found.chain[-1].exe == "/usr/sbin/apache2" and found.chain[-1].observed
    [m] = drive(InterpreterExternalConnection(), events, raw)
    assert m.proposed_lane == "high" and "ancestry includes the web server '/usr/sbin/apache2'" in m.claim
    assert "o20" in {e.raw[0].native_id for e in m.events}             # the worker's record is cited
    # exec records alone stop at the worker
    execs = [e for e in events if e.family != "process_observed"]
    assert table(execs).ancestry_of(HOST, 502, T + 7, None, 22).verdict == "unknown"


def _web_shell(*, pre_exec: bool, reparent_gap: float | None = None):
    """apache2 (service) -> worker 501 -> sh 510 -> forked 511, which execs perl after 510 exits (ppid 1) and
    connects out. `pre_exec`: 511 was recorded before 510 exited. `reparent_gap`: 511 is recorded running sh under
    510, then (that many seconds later) under pid 1, before its exec."""
    groups = [*_service(500, exe="/usr/sbin/apache2", argv=("/usr/sbin/apache2", "-k", "start")),
              observe(T + 5, 20, 501, 500, "/usr/sbin/apache2", "apache2", "33", "www-data"),
              execd(T + 6, 21, 510, 501, "/usr/bin/dash", ["sh", "-c", "payload"], "33", "www-data")]
    if pre_exec:
        groups.append(observe(T + 6.5, 22, 511, 510, "/usr/bin/dash", "sh", "33", "www-data"))
    if reparent_gap is not None:
        groups.append(observe(T + 6.5, 22, 511, 510, "/usr/bin/dash", "sh", "33", "www-data"))
        groups.append(observe(T + 6.5 + reparent_gap, 23, 511, 1, "/usr/bin/dash", "sh", "33", "www-data"))
    late = T + 8 + (reparent_gap or 0)
    groups += [execd(late, 30, 511, 1, "/usr/bin/perl", ["perl", "-e", "payload"], "33", "www-data"),
               connect(late + 1, 31, 511, 1, "/usr/bin/perl", "perl", saddr="0200115CCB007141" + "0" * 16)]
    return normalized(*groups)


def test_a_daemonized_web_shell_is_unknown_and_keeps_its_lane():
    events, raw = _web_shell(pre_exec=False)
    found = table(events).ancestry_of(HOST, 511, T + 9, None, 31)
    assert found.verdict == "unknown" and "parent pid 1" in found.why and "no record shows which" in found.why
    [m] = drive(InterpreterExternalConnection(), events, raw)
    assert m.proposed_lane == "high" and "not fully recorded" in m.claim
    assert any("lineage of pid 511 not established" in n for n in m.notes)


def test_a_daemonized_web_shell_recorded_before_its_parent_exited_reaches_the_web_server():
    events, _ = _web_shell(pre_exec=True)
    assert table(events).ancestry_of(HOST, 511, T + 9, None, 31).verdict == "web_server"


def test_a_reparent_seen_in_the_processs_own_records_counts_the_parent_at_fork():
    events, _ = _web_shell(pre_exec=False, reparent_gap=1.0)
    assert table(events).ancestry_of(HOST, 511, T + 10, None, 31).verdict == "web_server"


def test_a_parent_change_to_pid_1_long_after_the_last_record_is_not_joined():
    events, _ = _web_shell(pre_exec=False, reparent_gap=REPARENT_GAP + 50)
    found = table(events).ancestry_of(HOST, 511, T + 70, None, 31)
    assert found.verdict == "unknown" and "parent pid 1" in found.why


def test_an_exec_with_parent_pid_1_after_the_intermediate_exited_is_unknown():
    # the double fork's grandchild execs under pid 1; a service the service manager started looks the same in its
    # exec record, and only the spawn child's record tells them apart
    events, _ = normalized(execd(T, 10, 700, 1, "/usr/bin/perl", ["perl", "x.pl"], "33", "www-data"),
                           observe(T + 1, 11, 701, 700, "/usr/bin/perl", uid="33", user="www-data"))
    found = table(events).ancestry_of(HOST, 701, T + 1, None, 11)
    assert found.verdict == "unknown" and "pid 700" in found.why and "parent pid 1" in found.why
    events, _ = normalized(*_service(700), observe(T + 1, 20, 701, 700, "/usr/bin/perl", uid="33", user="www-data"))
    assert table(events).ancestry_of(HOST, 701, T + 1, None, 20).verdict == "service_manager"


def test_a_reused_pid_is_never_joined_to_the_earlier_process():
    service = _service()
    # pid 900 was a forked child of the service (perl); later the pid shows python with no exec between: between the
    # two the image is ambiguous, and after them the python process is another process (its parent is pid 1)
    events, _ = normalized(*service, observe(T + 5, 20, 900, 400, "/usr/bin/perl"),
                           observe(T + 500, 21, 900, 1, "/usr/bin/python3"))
    found = table(events).ancestry_of(HOST, 900, T + 100, None, None)
    assert found.verdict == "unknown" and "different executables" in found.why
    found = table(events).ancestry_of(HOST, 900, T + 501, None, 22)
    assert found.verdict == "unknown" and "parent pid 1" in found.why
    # the same image under another parent: another process, whose own parent decides (here: not recorded)
    events, _ = normalized(*service, observe(T + 5, 20, 900, 400, "/usr/bin/perl"),
                           observe(T + 500, 21, 900, 2000, "/usr/bin/perl"))
    found = table(events).ancestry_of(HOST, 900, T + 501, None, 22)
    assert found.verdict == "unknown" and "pid 2000" in found.why
    # the same image under pid 1 long after: not the earlier process reparented
    events, _ = normalized(*service, observe(T + 5, 20, 900, 400, "/usr/bin/perl"),
                           observe(T + 500, 21, 900, 1, "/usr/bin/perl"))
    found = table(events).ancestry_of(HOST, 900, T + 501, None, 22)
    assert found.verdict == "unknown" and "parent pid 1" in found.why
    # an audit session, once set, never changes: a different session is another process
    events, _ = normalized(*service, observe(T + 5, 20, 900, 400, "/usr/bin/perl", ses="7"),
                           observe(T + 5.5, 21, 900, 1, "/usr/bin/perl", ses="9"))
    found = table(events).ancestry_of(HOST, 900, T + 6, None, 22)
    assert found.verdict == "unknown" and "parent pid 1" in found.why


_FIXTURES = itertools.count(1)


def _fixture(pid, ppid, exe, ts, family="process_observed", serial=None):
    """A record without an audit serial (its order at one instant is unknown)."""
    n = next(_FIXTURES)
    origin = f"f{n}:event.original#auditd:SYSCALL"
    fields = {"process.pid": fv(pid, f"{origin}.pid"), "process.ppid": fv(ppid, f"{origin}.ppid"),
              "process.executable": fv(exe, f"{origin}.exe")}
    if serial is not None:
        fields["audit.serial"] = fv(serial, "f:serial")
    return TypedEvent(id=f"f{n}", family=family, ts=datetime.fromtimestamp(ts, UTC), host=HOST, fields=fields,
                      raw=[RawRef(target="fx", native_id=f"f{n}")], normalizer="fixture")


def test_records_of_one_instant_without_serials_that_disagree_are_ambiguous():
    # an exec and an observation of pid 800 at one instant, no serials: which image held the pid there is unknown
    pids = table([_fixture(800, 799, "/usr/bin/perl", T, family="process_exec"),
                  _fixture(800, 799, "/usr/bin/python3", T)])
    found = pids.ancestry_of(HOST, 800, T, None, None)
    assert found.verdict == "unknown" and "ambiguous" in found.why
    # two observations at one instant with different parents
    pids = table([_fixture(810, 400, "/usr/bin/perl", T), _fixture(810, 1, "/usr/bin/perl", T)])
    found = pids.ancestry_of(HOST, 810, T, None, None)
    assert found.verdict == "unknown" and "ambiguous" in found.why
    # with serials they are ordered
    pids = table([_fixture(820, 1, "/usr/lib/systemd/systemd", T, serial=5),
                  _fixture(820, 1, "/usr/bin/perl", T, family="process_exec", serial=6)])
    assert pids.ancestry_of(HOST, 820, T, None, 6).verdict == "service_manager"


def test_one_entry_per_change_of_state_never_one_per_record():
    events, _ = normalized(*_service(), *[observe(T + 5 + i, 20 + i, 401, 400, "/usr/bin/perl") for i in range(50)],
                           *[observe(T + 60 + i, 80 + i, 401, 1, "/usr/bin/perl") for i in range(50)],
                           *[observe(T + 0.003 + i, 200 + i, 400, 1, "/usr/bin/perl") for i in range(20)])
    pids = table(events)
    held = pids.execs.observed.peek((HOST, 401))
    assert [(o.ppid, o.ts, o.last) for o in held] == [(400, T + 5, T + 54), (1, T + 60, T + 109)]
    # pid 400's records repeat its exec's state: nothing beyond its spawn record is held
    assert [o.exe for o in pids.execs.observed.peek((HOST, 400))] == ["/usr/lib/systemd/systemd"]
    assert len(pids.execs.citations) == 3


def test_a_refused_observation_makes_every_service_manager_verdict_unknown(tmp_path):
    rule = InterpreterExternalConnection()
    rule.spill_dir = tmp_path
    rule.budget = StateBudget(tmp_path, disk_total=2**40, reserve=0)
    events, raw = lab_zmc()
    first, rest = events[:3], events[3:]
    drive_events = list(first)
    rule.consume([e for e in drive_events if e.family in rule.families])
    rule.budget.force_full("the observed states' store is past its floor (test)",
                           lambda account: account.name.endswith("proc_observed"))
    [m] = drive(rule, rest, raw)
    assert rule.pids.execs.observed_incomplete
    assert m.proposed_lane == "high" and "not fully recorded" in m.claim
    assert any("lineage of pid 905 not established" in n for n in m.notes)
    assert "lineage_observed" in rule.limits
    # a refusal anywhere in the hunt: a lineage whose own records were all held is no longer proof either
    rule = InterpreterExternalConnection()
    rule.spill_dir = tmp_path / "second"
    rule.budget = StateBudget(tmp_path, disk_total=2**40, reserve=0)
    rule.consume([e for e in events if e.family in rule.families])
    rule.budget.force_full("the observed states' store is past its floor (test)",
                           lambda account: account.name.endswith("proc_observed"))
    unrelated, _ = normalized(observe(T + 9, 5000, 9999, 9998, "/usr/bin/true"))
    [m] = drive(rule, unrelated, raw)
    assert m.proposed_lane == "high" and "not fully recorded" in m.claim
    assert any("lineage stores refused records" in n for n in m.notes)


def test_a_record_not_kept_for_citation_makes_its_lineage_unknown(tmp_path):
    rule = InterpreterExternalConnection()
    rule.spill_dir = tmp_path
    rule.budget = StateBudget(tmp_path, disk_total=2**40, reserve=0)
    rule.budget.force_full("the observed records' store is past its floor (test)",
                           lambda account: account.name.endswith("proc_observed_records"))
    events, raw = lab_zmc()
    [m] = drive(rule, events, raw)
    assert m.proposed_lane == "high"
    assert any("not kept for citation" in n for n in m.notes)
    assert "lineage_records" in rule.limits


# ---- a group of processes -----------------------------------------------------------------------------------------
def test_a_group_names_every_pid_and_judges_each_process():
    groups = list(_service())
    for i, pid in enumerate((937, 941)):
        groups += [observe(T + 10 + i, 40 + 10 * i, pid, 400, "/usr/bin/perl", "zmdc.pl", "33", "www-data"),
                   connect(T + 11 + i, 41 + 10 * i, pid, 400, "/usr/bin/perl", "perl", success="yes", exit_code="0")]
    events, raw = normalized(*groups)
    [m] = drive(InterpreterExternalConnection(), events, raw)
    assert "'/usr/bin/perl' (pids 937, 941, user 'www-data')" in m.claim
    assert "pid 937's ancestry reaches the service manager" in m.claim
    assert "pid 941's ancestry reaches the service manager" in m.claim
    assert m.proposed_lane == "lead" and sum(n.startswith("lane lowered to lead") for n in m.notes) == 2
    # a third process whose lineage is unknown keeps the whole group's lane
    events, raw = normalized(*groups, connect(T + 20, 90, 950, 1, "/usr/bin/perl", "perl", success="yes",
                                              exit_code="0"))
    [m] = drive(InterpreterExternalConnection(), events, raw)
    assert m.proposed_lane == "high" and "pids 937, 941, 950" in m.claim
    assert "pid 950's ancestry is not fully recorded" in m.claim


def test_a_group_with_more_processes_than_are_judged_keeps_its_lane_and_says_so():
    groups = list(_service())
    count = PROCESSES_JUDGED + 2
    for i in range(count):
        groups += [observe(T + 10 + i, 1000 + 10 * i, 3000 + i, 400, "/usr/bin/perl", uid="33", user="www-data"),
                   connect(T + 10.5 + i, 1001 + 10 * i, 3000 + i, 400, "/usr/bin/perl", "perl", success="yes",
                           exit_code="0")]
    events, raw = normalized(*groups)
    [m] = drive(InterpreterExternalConnection(), events, raw)
    assert m.proposed_lane == "high"
    assert f"pids 3000, 3001, 3002, 3003, 3004, 3005, 3006, 3007 and {count - 8} more" in m.claim
    assert f"2 further process(es) were not judged (the lineage of the first {PROCESSES_JUDGED} by time was)" in m.claim


# ---- the view itself ----------------------------------------------------------------------------------------------
def test_an_observation_after_the_instant_with_no_exec_between_gives_the_image():
    later = Observed(T + 10, 7, "/usr/bin/perl", 400, None, None, "e1", "r1", T + 10)
    view = process_view([], [later], T + 5, 3, None, inclusive=True, pid=9, host=HOST)
    assert view.image is not None and view.image.exe == "/usr/bin/perl" and view.used == [later]


def test_the_windows_guid_path_is_untouched_by_observations():
    """Windows records never become observations (their process fields are not audit SYSCALL fields), so the exec
    lineage a Windows host builds is exactly what it was."""
    event = _fixture(4242, 4000, "C:\\Windows\\System32\\cmd.exe", T)
    event.fields["process.pid"] = fv(4242, "winlog:event_data.ProcessId")
    lineage = ExecLineage(observing=True)
    lineage.observe_process(event)
    assert len(lineage.observed) == 0


@pytest.mark.slow
def test_mission_scale_observations_hold_one_entry_per_change_on_bounded_memory(tmp_path):
    """About 10M syscall records across 5,000 hosts with heavy pid reuse (each host cycles through 400 pids; each
    process makes records under its first parent, may be reparented to pid 1, and its pid is reused by a process with
    another parent). The store holds exactly one entry per change of state, moves cold processes to disk under a
    small memory budget, and every record is handled in bounded time."""
    import time

    from tests.test_bounded_lineage import _Owner
    owner = _Owner(tmp_path).playbook
    owner.budget = StateBudget(tmp_path, disk_total=2**40, reserve=0, memory_total=64 * 2**20)
    lineage = ExecLineage(owner, observing=True)
    hosts, pids_per_host, records_per_process = 5000, 400, 10
    total, changes, kept = 0, 0, [0]

    def cite():
        kept[0] += 1
        return True
    started = time.perf_counter()
    t = T
    generation = 0
    while total < 10_000_000:
        for host_index in range(hosts):
            host = f"h{host_index:04d}"
            for slot in range(0, pids_per_host, 100):          # a quarter of each host's pids per round
                pid = 1000 + (slot + generation) % pids_per_host
                parent = 500 + generation % 7                  # each reuse of the pid has another parent
                for r in range(records_per_process):
                    reparented = r >= records_per_process - 2 and generation % 3 == 0
                    entry = Observed(t, None, "/usr/bin/worker", 1 if reparented else parent, None, None,
                                     f"{host}-{pid}-{generation}-{r}", "raw", t)
                    lineage.hold_observed(host, pid, entry, cite)
                    t += 0.0001
                    total += 1
                changes += 2 if generation % 3 == 0 else 1
            if host_index % 50 == 49:
                lineage.trim()                                 # the sweep trims when a batch ends
        generation += 1
    lineage.trim()
    elapsed = time.perf_counter() - started
    stored = sum(len(state) for _key, state in lineage.observed.items())
    assert stored == changes == kept[0] and stored < total / 4
    assert lineage.observed.on_disk > 0                        # the memory budget moved processes to disk
    assert len(lineage.observed.hot) < len(lineage.observed)
    assert elapsed < 1800, elapsed
    print(f"\n{total:,} records, {stored:,} entries ({stored / total:.1%}), {elapsed:.0f} s, "
          f"{lineage.observed.on_disk:,} processes on disk, {len(lineage.observed.hot):,} in memory")
