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

from romulus.detect.auth import AccountOrGroupChange
from romulus.detect.bounded import StateBudget
from romulus.detect.correlation import (
    PROCESSES_JUDGED,
    InterpreterExternalConnection,
    PidTable,
    ProcessNetworkLink,
)
from romulus.detect.host import ExecLineage
from romulus.detect.kernel_files import PersistencePathChange
from romulus.detect.lineage import ReverseShellByLineage
from romulus.detect.observed import REPARENT_GAP, Observed, process_view
from romulus.detect.tamper import SecurityOrLoggingServiceStop
from romulus.evidence.normalize import normalize_hits
from romulus.evidence.typed import RawRef, TypedEvent, fv
from romulus.hunt.publish import LineageCitationFetcher
from tests.lineage_citation_fixture import source_copies

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


class _CitationSource:
    def __init__(self, raw_sources):
        self.hits = [
            {"_index": key.split("/", 1)[0], "_id": key.split("/", 1)[1], "_source": source}
            for key, source in raw_sources.items()
        ]

    def search(self, _target, body):
        filters = body["query"]["bool"]["filter"]
        ids = set(next(item["ids"]["values"] for item in filters if "ids" in item))
        indices = set(next(item["terms"]["_index"] for item in filters if "terms" in item))
        return {"hits": {"hits": [
            hit for hit in self.hits if hit["_id"] in ids and hit["_index"] in indices
        ]}}


def drive(rule, events, raw_sources=None):
    """Consume, stage and finalize the way the sweep does (raw copies bound while the rule reads the batch)."""
    stage = {}
    raw_sources = raw_sources or {}
    rule.bind_raw(raw_sources, "host-target")
    accepted = set(rule.families) | set(rule.context_families)
    rule.consume([e for e in events if e.family in accepted])
    rule.bind_raw({})
    stage.update({e.id: e for e in rule.drain_staged()})
    rule.bind_loader(lambda ids: [stage[i] for i in ids if i in stage])
    from romulus.detect.host import bind_lineage_citation_loader
    bind_lineage_citation_loader(
        [rule], LineageCitationFetcher(_CitationSource(raw_sources), {"host-target": object()}).load,
    )
    return rule.finalize()


def test_account_change_uses_a_no_exec_package_parent_and_cites_its_observation():
    events, raw = normalized(
        observe(T, 10, 100, 90, "/usr/bin/dpkg", "dpkg"),
        execd(T + 1, 11, 101, 100, "/usr/sbin/useradd", ["useradd", "svc"]),
    )

    [match] = drive(AccountOrGroupChange(), events, raw)

    assert match.proposed_lane == "lead" and "under package management" in match.claim
    assert "o10" in {event.raw[0].native_id for event in match.events}
    assert any(event.family == "process_observed" and event.id in match.context_ids for event in match.events)
    assert all(ref.key in match.raw_copies for event in match.events if event.family == "process_observed"
               for ref in event.raw)


def test_tamper_change_uses_a_no_exec_package_parent_and_cites_its_observation():
    events, raw = normalized(
        observe(T, 20, 200, 190, "/usr/bin/dpkg", "dpkg"),
        execd(T + 1, 21, 201, 200, "/usr/bin/systemctl", ["systemctl", "stop", "auditd"]),
    )

    [match] = drive(SecurityOrLoggingServiceStop(), events, raw)

    assert match.proposed_lane == "lead" and "package management" in match.claim
    assert "o20" in {event.raw[0].native_id for event in match.events}
    assert any(event.family == "process_observed" and event.id in match.context_ids for event in match.events)


def test_tamper_no_exec_parent_keeps_its_parent_at_fork_after_reparenting():
    events, raw = normalized(
        observe(T, 22, 220, 210, "/usr/bin/dpkg", "dpkg"),
        observe(T + 0.5, 23, 220, 1, "/usr/bin/dpkg", "dpkg"),
        execd(T + 1, 24, 221, 220, "/usr/bin/systemctl", ["systemctl", "stop", "auditd"]),
    )

    [match] = drive(SecurityOrLoggingServiceStop(), events, raw)

    assert match.proposed_lane == "lead" and "package management" in match.claim
    assert "o22" in {event.raw[0].native_id for event in match.events}


def test_refused_no_exec_lineage_is_partial_and_never_lowers_tamper(tmp_path):
    rule = SecurityOrLoggingServiceStop()
    rule.spill_dir = tmp_path
    rule.budget = StateBudget(tmp_path, disk_total=2**40, reserve=0)
    rule.budget.force_full(
        "the observed states' store is past its floor (test)",
        lambda account: account.name.endswith("proc_observed"),
    )
    events, raw = normalized(
        observe(T, 25, 250, 240, "/usr/bin/dpkg", "dpkg"),
        execd(T + 1, 26, 251, 250, "/usr/bin/systemctl", ["systemctl", "stop", "auditd"]),
    )

    [match] = drive(rule, events, raw)

    assert match.proposed_lane == "high" and "package management" not in match.claim
    assert "lineage_observed" in rule.limits


def test_reverse_shell_walks_a_no_exec_owner_and_cites_its_observation():
    events, raw = normalized(
        observe(T, 30, 300, 290, "/usr/bin/python3", "python3", "33", "www-data"),
        connect(T + 1, 31, 300, 290, "/usr/bin/python3", "python3", success="yes", exit_code="0"),
        execd(T + 2, 32, 301, 300, "/usr/bin/dash", ["sh"], "33", "www-data"),
    )

    [match] = drive(ReverseShellByLineage(), events, raw)

    assert match.proposed_lane == "high" and "descendant" in match.claim
    assert "o30" in {event.raw[0].native_id for event in match.events}
    assert any(event.family == "process_observed" and event.id in match.context_ids for event in match.events)


def test_reverse_shell_survives_when_its_owner_observation_cannot_be_cited():
    events, raw = normalized(
        observe(T, 50, 500, 490, "/usr/sbin/apache2", "apache2", "33", "www-data"),
        execd(T + 0.5, 51, 500, 490, "/usr/bin/python3", ["python3", "-c", "x"], "33", "www-data"),
        connect(T + 1, 52, 500, 490, "/usr/bin/python3", "python3", success="yes", exit_code="0"),
        execd(T + 2, 53, 501, 500, "/usr/bin/dash", ["sh"], "33", "www-data"),
    )
    rule = ReverseShellByLineage()
    rule.pids.execs.citations.put = lambda *_args, **_kwargs: False

    [match] = drive(rule, events, raw)

    assert match.proposed_lane == "high"
    assert "203.0.113.65:554" in match.claim
    assert not any(event.family == "process_observed" for event in match.events)
    assert "lineage_records" in rule.limits


def test_unrelated_observation_refusal_does_not_hide_web_lineage(tmp_path):
    rule = AccountOrGroupChange()
    rule.spill_dir = tmp_path
    rule.budget = StateBudget(tmp_path, disk_total=2**40, reserve=0)
    rule.budget.force_full(
        "the observed states' store is past its floor (test)",
        lambda account: account.name.endswith("proc_observed"),
    )
    events, raw = normalized(
        observe(T - 5, 59, 999, 998, "/usr/bin/foo", "foo"),
        execd(T, 60, 600, 590, "/usr/sbin/php-fpm8.2", ["php-fpm"], "33", "www-data"),
        execd(T + 1, 61, 601, 600, "/usr/bin/dash", ["sh", "-c", "x"], "33", "www-data"),
        execd(T + 2, 62, 602, 601, "/usr/sbin/useradd", ["useradd", "backdoor"]),
    )

    [match] = drive(rule, events, raw)

    assert match.proposed_lane == "high"
    assert "web-service account" in match.claim
    assert "lineage_observed" in rule.limits
    assert "no lineage lowers a lane anywhere" not in " ".join(str(value) for value in rule.limits.values())


def test_process_lineage_consumers_bump_versions_for_ambiguous_tie_semantics():
    assert InterpreterExternalConnection.version == "8"
    assert ProcessNetworkLink.version == "9"


def test_persistence_change_uses_a_no_exec_package_parent_and_cites_its_observation():
    from tests.lineage_citation_fixture import source_copies
    from tests.test_kernel_files import change

    observed, raw = normalized(observe(T, 40, 400, 390, "/usr/bin/dpkg", "dpkg"))
    changed = change(
        "/etc/cron.d/pkg", ts=datetime.fromtimestamp(T + 1, UTC), uid="0",
        exe="/usr/bin/cp", pid=401, ppid=400, host=HOST,
    )
    raw.update(source_copies([changed]))

    [match] = drive(PersistencePathChange(), [*observed, changed], raw)

    assert match.proposed_lane == "lead" and match.group_key.endswith("|package:dpkg")
    assert "o40" in {event.raw[0].native_id for event in match.events}
    assert any(event.family == "process_observed" and event.id in match.context_ids for event in match.events)


def test_persistence_does_not_lower_from_an_uncited_no_exec_package_parent():
    from tests.test_kernel_files import change

    observed, raw = normalized(observe(T, 41, 410, 390, "/usr/bin/dpkg", "dpkg"))
    changed = change(
        "/etc/cron.d/pkg", ts=datetime.fromtimestamp(T + 1, UTC), uid="0",
        exe="/usr/bin/cp", pid=411, ppid=410, host=HOST,
    )
    raw.update(source_copies([changed]))
    rule = PersistencePathChange()
    rule.lineage.execs.citations.put = lambda *_args, **_kwargs: False

    [match] = drive(rule, [*observed, changed], raw)

    assert match.group_key.endswith("|pid 411|/usr/bin/cp|2024-11-18T10:21:22.941000+00:00")
    assert "package activity" not in match.claim
    assert "lineage_records" in rule.limits


def test_unrelated_observation_refusal_does_not_hide_an_exact_exec_package_parent(tmp_path):
    from tests.test_kernel_files import change

    rule = PersistencePathChange()
    rule.spill_dir = tmp_path
    rule.budget = StateBudget(tmp_path, disk_total=2**40, reserve=0)
    rule.budget.force_full(
        "the observed states' store is past its floor (test)",
        lambda account: account.name.endswith("proc_observed"),
    )
    unrelated, raw = normalized(observe(T - 1, 42, 999, 998, "/usr/bin/true", "true"))
    manager, manager_raw = normalized(execd(T, 43, 420, 390, "/usr/bin/dnf-3", ["dnf-3"]))
    changed = change(
        "/etc/cron.d/pkg", ts=datetime.fromtimestamp(T + 1, UTC), uid="0",
        exe="/usr/bin/cp", pid=421, ppid=420, host=HOST,
    )
    raw.update(manager_raw)
    raw.update(source_copies([changed]))

    [match] = drive(rule, [*unrelated, *manager, changed], raw)

    assert match.group_key.endswith("|package:dnf-3")
    assert "package activity" in match.claim
    assert "lineage_observed" in rule.limits


def table(events, raw=None) -> PidTable:
    """A lineage over these records (with `raw`, their raw copies, as a sweep hands them over)."""
    pids = PidTable(observing=True)
    raw = raw or source_copies(events)
    for event in events:
        pids.add(event, {r.key: raw[r.key] for r in event.raw if r.key in raw}, "host-target")
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
    assert ("(/usr/bin/perl (pid 874, parent pid 872, observed record o928) <- /usr/bin/perl (pid 872, parent pid 871, "
            "exec record e924) <- /usr/bin/sudo (pid 871, parent pid 817, exec record e916) <- /usr/bin/perl (pid 817, "
            "parent pid 1, exec record e846) <- /usr/lib/systemd/systemd (pid 817, running the service manager's own "
            "executable as a child of pid 1, before its exec, observed record s843))") in note
    assert "a unit started on request (for example with systemd-run" in note
    # the earliest record of each process the lineage names is cited, rebuilt from its raw copy, which is kept
    cited = {e.raw[0].native_id for e in m.events if e.family == "process_observed"}
    assert cited == {"s843", "o928", "o972"}
    assert all(r.key in m.raw_copies for e in m.events if e.family == "process_observed" for r in e.raw)
    rebuilt = next(e for e in m.events if e.raw[0].native_id == "o928")
    original = next(e for e in events if e.raw[0].native_id == "o928")
    assert rebuilt.model_dump() == original.model_dump()


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
    # only an entry that can begin a process keeps its record for citation (the reparent continues pid 401's process)
    assert len(pids.execs.citations) == 2


def test_a_refused_observation_makes_every_service_manager_verdict_unknown(tmp_path):
    rule = InterpreterExternalConnection()
    rule.spill_dir = tmp_path
    rule.budget = StateBudget(tmp_path, disk_total=2**40, reserve=0)
    events, raw = lab_zmc()
    first, rest = events[:3], events[3:]
    drive_events = list(first)
    rule.bind_raw(raw, "host-target")
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
    rule.bind_raw(raw, "host-target")
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
    assert any("not held for citation" in n for n in m.notes)
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


# ---- what never proves a service start ---------------------------------------------------------------------------
def _web_child():
    """apache2 (a service) -> worker 501 (www-data, forked) -> sh 502 (exec, a web shell)."""
    return [*_service(500, exe="/usr/sbin/apache2", argv=("/usr/sbin/apache2", "-k", "start")),
            observe(T + 5, 20, 501, 500, "/usr/sbin/apache2", "apache2", "33", "www-data"),
            execd(T + 6, 21, 502, 501, "/usr/bin/dash", ["sh", "-c", "x"], "33", "www-data")]


@pytest.mark.parametrize("payload, forks", [
    ("/tmp/systemd-executor", False),           # named like the spawn helper, exec'd by the web shell
    ("/tmp/systemd", True),                     # named like the manager; its forked child connects out
    ("/dev/shm/init", True),                    # named like init; the same
    ("/usr/lib/systemd/systemd", True),         # the real manager run by the web shell: its child is not pid 1's
])
def test_a_program_named_or_run_like_the_service_manager_under_a_web_shell_stays_high(payload, forks):
    asking = 504 if forks else 503
    groups = [*_web_child(), execd(T + 7, 23, 503, 502, payload, [payload], "33", "www-data")]
    if forks:
        groups.append(observe(T + 8, 24, 504, 503, payload, "x", "33", "www-data"))
    groups.append(connect(T + 9, 25, asking, 503 if forks else 502, payload, "x"))
    events, raw = normalized(*groups)
    found = table(events, raw).ancestry_of(HOST, asking, T + 9, None, 25)
    assert found.verdict == "web_server" and found.chain[-1].exe == "/usr/sbin/apache2"
    [m] = drive(InterpreterExternalConnection(), events, raw)
    assert m.proposed_lane == "high" and "ancestry includes the web server '/usr/sbin/apache2'" in m.claim
    assert not any(n.startswith("lane lowered") for n in m.notes)


def test_the_spawn_helpers_exec_proves_a_start_and_the_note_names_it_as_an_exec():
    events, raw = normalized(execd(T, 10, 800, 1, "/usr/lib/systemd/systemd-executor",
                                   ["/usr/lib/systemd/systemd-executor", "--deserialize", "3"]),
                             execd(T + 0.002, 11, 800, 1, "/usr/bin/perl", ["/usr/bin/perl", "/usr/sbin/d.pl"]),
                             observe(T + 5, 20, 801, 800, "/usr/bin/perl", uid="33", user="www-data"),
                             connect(T + 6, 21, 801, 800, "/usr/bin/perl", "perl"))
    [m] = drive(InterpreterExternalConnection(), events, raw)
    assert m.proposed_lane == "lead"
    [note] = [n for n in m.notes if n.startswith("lane lowered")]
    assert ("/usr/lib/systemd/systemd-executor (pid 800, exec of the service manager's spawn helper as a child of "
            "pid 1, exec record e10)") in note
    # the same helper exec'd by anything but pid 1 proves nothing
    events, raw = normalized(execd(T, 10, 800, 77, "/usr/lib/systemd/systemd-executor", ["x"]),
                             observe(T + 5, 20, 801, 800, "/usr/lib/systemd/systemd-executor", uid="33",
                                     user="www-data"))
    assert table(events, raw).ancestry_of(HOST, 801, T + 5, None, 20).verdict == "unknown"


# ---- the parent at fork needs proof of the fork --------------------------------------------------------------------
def test_a_child_recorded_under_a_parent_whose_image_it_does_not_run_may_have_been_adopted():
    """A daemonized child is adopted by its nearest subreaper (a container's init under any name): its earliest record
    under that adopter shows its own image, not the adopter's, so the adopter is not its parent at fork."""
    groups = [*_service(400, exe="/usr/local/bin/appinit", argv=("/usr/local/bin/appinit",)),
              observe(T + 5, 20, 410, 400, "/usr/bin/dash", "sh", "33", "www-data"),
              connect(T + 6, 21, 410, 400, "/usr/bin/dash", "sh")]
    events, raw = normalized(*groups)
    found = table(events, raw).ancestry_of(HOST, 410, T + 6, None, 21)
    assert found.verdict == "unknown" and "may have been adopted by pid 400" in found.why
    [m] = drive(InterpreterExternalConnection(), events, raw)
    assert m.proposed_lane == "high"


def test_an_exec_under_a_parent_recorded_before_it_resolves_and_under_a_known_subreaper_does_not():
    # an ordinary exec chain: a service's bash runs python3 as www-data
    events, raw = normalized(*_service(400, exe="/usr/bin/bash", argv=("/usr/bin/bash", "/usr/sbin/job.sh")),
                             execd(T + 5, 20, 401, 400, "/usr/bin/python3", ["python3", "x.py"], "33", "www-data"),
                             connect(T + 6, 21, 401, 400, "/usr/bin/python3", "python3"))
    assert table(events, raw).ancestry_of(HOST, 401, T + 6, None, 21).verdict == "service_manager"
    [m] = drive(InterpreterExternalConnection(), events, raw)
    assert m.proposed_lane == "lead"
    # the same exec under tini (it adopts orphans): it may have been reparented there
    events, raw = normalized(*_service(400, exe="/usr/bin/tini", argv=("/usr/bin/tini", "--", "app")),
                             execd(T + 5, 20, 401, 400, "/usr/bin/python3", ["python3", "x.py"], "33", "www-data"))
    found = table(events, raw).ancestry_of(HOST, 401, T + 5, None, 20)
    assert found.verdict == "unknown" and "adopts orphaned processes" in found.why


def test_a_web_server_above_an_unproved_fork_is_still_in_the_ancestry():
    # the recorded parent is the parent at fork or an ancestor that adopted the child: either way its web server
    # is an ancestor (a raise, never a lowering)
    events, raw = normalized(*_web_child()[:-1], observe(T + 7, 30, 520, 501, "/usr/bin/perl", uid="33",
                                                         user="www-data"))
    assert table(events, raw).ancestry_of(HOST, 520, T + 7, None, 30).verdict == "web_server"


# ---- order within a boot -------------------------------------------------------------------------------------------
def _booted(groups, boot):
    for group in groups:
        for hit in group:
            hit["_source"]["host"]["boot"] = {"id": boot}
    return groups


def test_records_of_one_boot_are_ordered_by_audit_serial_not_by_a_skewed_time():
    """The exec's time is the shipper's and here lags its audit header by three seconds: by time, the child's record
    would precede its parent's exec and show an image the parent did not yet run."""
    exec_group = execd(T + 0.002, 11, 400, 1, "/usr/bin/perl", ["/usr/bin/perl", "/usr/sbin/d.pl"])
    for hit in exec_group:
        hit["_source"]["@timestamp"] = _iso(T + 3)
    groups = [spawn(T, 10, 400), exec_group, observe(T + 1, 12, 401, 400, "/usr/bin/perl", uid="33", user="www-data")]
    boot = "0d" * 16
    events, raw = normalized(*_booted(groups, boot))
    assert table(events, raw).ancestry_of(HOST, 401, T + 1, boot, 12).verdict == "service_manager"
    # without boot identity the serials of two boots cannot be compared: ordered by time, it is unknown
    events, raw = normalized(spawn(T, 10, 400), execd(T + 0.002, 11, 400, 1, "/usr/bin/perl", ["perl"]),
                             observe(T + 1, 12, 401, 400, "/usr/bin/perl"))
    for event in events:
        if event.family == "process_exec":
            event.ts = datetime.fromtimestamp(T + 3, UTC)
    assert table(events, raw).ancestry_of(HOST, 401, T + 1, None, 12).verdict == "unknown"


# ---- normalization and coverage ------------------------------------------------------------------------------------
def test_an_unreadable_observed_group_is_one_error_and_the_rest_normalize(monkeypatch):
    from romulus.evidence import normalize
    from romulus.hunt.sweep import DATASET_FAMILIES
    real = normalize.normalize_observed_group

    def flaky(host, members):
        if members[0][0]["_id"] == "o21":
            raise ValueError("unreadable")
        return real(host, members)
    monkeypatch.setattr(normalize, "normalize_observed_group", flaky)
    hits = [hit for group in (observe(T, 20, 401, 400, "/usr/bin/perl"), observe(T + 1, 21, 402, 400, "/usr/bin/perl"),
                              observe(T + 2, 22, 403, 400, "/usr/bin/perl")) for hit in group]
    events, _skips, errors = normalize_hits(hits)
    assert [e.raw[0].native_id for e in events] == ["o20", "o22"]
    assert errors == [("o21", "linux.audit.observed: unreadable")]
    assert DATASET_FAMILIES["linux.audit.observed"] == {"process_observed"}


def _sweep_cells(monkeypatch, tmp_path, pack, events, budget):
    from tests.test_bounded_starvation import run_sweep
    _published, cells = run_sweep(monkeypatch, tmp_path, pack, [events], budget)
    return cells


def test_a_refused_observation_store_is_stated_on_the_rules_window_cell(monkeypatch, tmp_path):
    budget = StateBudget(tmp_path, disk_total=2**40, reserve=0)
    budget.force_full("the observed states' store is past its floor (test)",
                      lambda account: account.name.endswith("proc_observed"))
    events, _raw = lab_zmc()
    cells = _sweep_cells(monkeypatch, tmp_path, [InterpreterExternalConnection()], events, budget)
    window = next(c for c in cells if c["rule_id"] == InterpreterExternalConnection.id and c["target"] == "*")
    assert window["state"] == "match_on_partial"
    assert any("took no new process from the record of 2024-11-18T10:21:21.941000+00:00 on" in r
               and "recorded exec lineage is still used for attack-associated raises" in r
               and "cannot lower a lane anywhere in this hunt" in r for r in window["detail"]["reasons"])


def test_the_network_join_is_not_evaluated_by_a_partition_of_lineage_records_only(monkeypatch, tmp_path):
    budget = StateBudget(tmp_path, disk_total=2**40, reserve=0)
    events, _raw = normalized(*_service(), observe(T + 5, 20, 401, 400, "/usr/bin/perl"))
    cells = _sweep_cells(monkeypatch, tmp_path, [ProcessNetworkLink()], events, budget)
    [cell] = [c for c in cells if c["rule_id"] == ProcessNetworkLink.id and c["target"] != "*"]
    assert cell["state"] == "not_applicable_no_events"


@pytest.mark.slow
def test_mission_scale_observations_hold_one_entry_per_change_on_bounded_memory(tmp_path):
    """About 10M syscall records across 5,000 hosts with heavy pid reuse (each host cycles through 400 pids; each
    process makes records under its first parent, may be reparented to pid 1, and its pid is reused by a process with
    another parent). The store holds exactly one entry per change of state, keeps a compact source pointer only for
    each process's earliest record, moves cold state to disk under a small memory budget, and every record is handled
    in bounded time."""
    import time
    from types import SimpleNamespace

    from romulus.detect.observed import citation
    from tests.test_bounded_lineage import _Owner
    owner = _Owner(tmp_path).playbook
    owner.budget = StateBudget(tmp_path, disk_total=2**40, reserve=0, memory_total=64 * 2**20)
    lineage = ExecLineage(owner, observing=True)
    hosts, pids_per_host, records_per_process = 5000, 400, 10
    total, changes, processes = 0, 0, 0
    bare = SimpleNamespace(fields={})

    def source(host, pid, ppid, t, serial):
        line = _syscall(t, serial, nr=257, name="openat", pid=pid, ppid=ppid, exe="/usr/bin/worker", comm="worker",
                        uid="33", user="www-data", success="no", exit_code="-13")
        return {"@timestamp": _iso(t), "message": line, "host": {"name": host, "hostname": host},
                "event": {"dataset": "linux.audit", "original": line, "module": "auditd", "kind": "event"},
                "agent": {"type": "filebeat", "version": "8.15.0", "name": host, "id": f"agent-{host}"},
                "ecs": {"version": "8.11.0"}, "input": {"type": "log"},
                "log": {"file": {"path": "/var/log/audit/audit.log"}, "offset": serial * 431}}
    started = time.perf_counter()
    t, serial, generation = T, 0, 0
    while total < 10_000_000:
        for host_index in range(hosts):
            host = f"h{host_index:04d}"
            for slot in range(0, pids_per_host, 100):          # a quarter of each host's pids per round
                pid = 1000 + (slot + generation) % pids_per_host
                parent = 500 + generation % 7                  # each reuse of the pid has another parent
                processes += 1
                for r in range(records_per_process):
                    reparented = r >= records_per_process - 2 and generation % 3 == 0
                    ppid = 1 if reparented else parent
                    serial += 1
                    entry = Observed(t, None, "/usr/bin/worker", ppid, None, None, f"{host}-{serial}", f"r{serial}", t)
                    ref = RawRef(target="host-logs-x", native_id=f"r{serial}")
                    lineage.hold_observed(host, pid, entry, lambda entry=entry, ref=ref, host=host, pid=pid, ppid=ppid,
                                          t=t, serial=serial: lineage._cite(
                                              entry, citation(bare, ref, source(host, pid, ppid, t, serial))))
                    t += 0.0001
                    total += 1
                changes += 2 if generation % 3 == 0 else 1
            if host_index % 50 == 49:
                lineage.trim()                                 # the sweep trims when a batch ends
        generation += 1
    lineage.observed.trim(0)
    lineage.citations.trim(0)
    elapsed = time.perf_counter() - started
    stored = sum(len(state) for _key, state in lineage.observed.items())
    cited = len(lineage.citations)
    assert stored == changes and stored < total / 4
    assert cited == processes                                  # one record per process: a reparent cites nothing
    assert lineage.observed.on_disk > 0 and len(lineage.observed.hot) == 0
    entries_bytes, citation_bytes = lineage.observed.disk_bytes, lineage.citations.disk_bytes
    assert citation_bytes / cited < 180                        # the compact pointer, compressed
    assert elapsed < 1800, elapsed
    print(f"\n{total:,} records, {stored:,} entries ({stored / total:.1%}) in {len(lineage.observed):,} pid keys, "
          f"{cited:,} cited records; entries {entries_bytes / 2**20:.0f} MiB ({entries_bytes / stored:.0f} B per entry "
          f"on disk, pickled per pid), citations {citation_bytes / 2**20:.0f} MiB ({citation_bytes / cited:.0f} B "
          f"each); {elapsed:.0f} s")
