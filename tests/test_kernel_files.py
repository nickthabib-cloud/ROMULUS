"""Fixtures for the kernel file-record rules: root runs of non-root-modifiable files, persistence-location changes,
memory-backed or deleted executables, and the write/run rule's use of kernel file-change records.

Hosts, accounts and paths are invented; addresses are not used."""
import gzip
import json
import random
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from romulus.detect.hijack import NonRootWriteRootExecutedFile
from romulus.detect.host import UnbackedExecutable, unbacked_executable
from romulus.detect.kernel_files import (
    PersistencePathChange,
    RootExecNonRootModifiableFile,
    persistence_location,
)
from romulus.detect.registry import ALL_PLAYBOOKS, fresh_pack
from romulus.evidence.typed import Outcome, RawRef, TypedEvent, fv

T0 = datetime(2030, 1, 6, 9, 0, tzinfo=UTC)
JOB = "/srv/tasks/rotate.sh"
NAMES = {"0": "root", "33": "www-data", "1000": "alice", "1001": "bob", "1002": "deploy"}
_n = 0


def ev(family, ts, outcome=Outcome.success, host="app01", **fields):
    global _n
    _n += 1
    f = {k.replace("__", "."): fv(v, f"fixture{_n}:{k}") for k, v in fields.items() if v is not None}
    return TypedEvent(id=f"k{_n:05d}", family=family, ts=ts, host=host, outcome=outcome, fields=f,
                      raw=[RawRef(target="fx", native_id=f"r{_n}")], normalizer="fixture")


def root_exec(path=JOB, ts=T0, owner="33", mode="0100755", group=None, role="script", auid=None, ses=None,
              host="app01", outcome=Outcome.success, uid="0", euid="0", interp=None, owner_name="default", **kw):
    owner_name = NAMES.get(owner) if owner_name == "default" else owner_name
    fields = {"process__argv": ["/bin/sh", path] if role == "script" else [path],
                  "process__executable": "/usr/bin/dash" if role == "script" else path,
                  "process__uid": uid, "process__euid": euid, "process__user": NAMES.get(uid),
                  "process__auid": auid, "process__session_id": ses, "process__pid": 5001, "process__ppid": 5000,
                  "process__exec_file__path": path, "process__exec_file__owner__id": owner,
                  "process__exec_file__owner__name": owner_name, "process__exec_file__group__id": group or owner,
                  "process__exec_file__mode": mode, "process__exec_file__inode": 4242, "process__exec_file__role": role}
    if interp:
        fields.update(process__interpreter_file__path=interp[0], process__interpreter_file__owner__id=interp[1],
                      process__interpreter_file__mode=interp[2], process__interpreter_file__group__id=interp[1],
                      process__interpreter_file__owner__name=NAMES.get(interp[1]))
    fields.update(kw)
    return ev("process_exec", ts, outcome=outcome, host=host, **fields)


def user_exec(uid, ts=T0, ses=None, host="app01"):
    return ev("process_exec", ts, host=host, process__argv=["ls"], process__executable="/usr/bin/ls",
              process__uid=uid, process__euid=uid, process__user=NAMES.get(uid), process__auid=uid,
              process__session_id=ses, process__exec_file__owner__id="0", process__exec_file__mode="0100755")


def run_root(*partitions):
    pb = RootExecNonRootModifiableFile()
    for part in partitions:
        assert pb.consume(list(part)) == []
    return pb, pb.finalize()


# =============================================================================================================
# host.root_exec_nonroot_modifiable_file
# =============================================================================================================
def test_root_cron_run_of_a_web_owned_script_is_high_and_restrained():
    runs = [root_exec(ts=T0 + timedelta(minutes=i)) for i in range(3)]
    pb, out = run_root(runs)
    assert len(out) == 1
    m = out[0]
    assert m.proposed_lane == "high" and m.severity == "high" and m.confidence == "high"
    assert "executed /srv/tasks/rotate.sh as the #! script 3 times" in m.claim
    assert "owner uid 33 ('www-data'), a web-service account" in m.claim and "mode 0100755" in m.claim
    assert "outside any login session" in m.claim
    assert "they do not show whether the file was changed" in m.claim
    assert "modified" not in m.claim and "compromised" not in m.claim
    assert m.group_key == f"app01|33|{JOB}"
    assert {p.field for p in m.predicate} >= {"process.uid", "process.exec_file.owner.id", "process.exec_file.mode"}
    assert all(p.origin for p in m.predicate)
    assert {e.id for e in pb.retained_events()} == {e.id for e in runs}


def test_world_writable_root_owned_program_is_high():
    _pb, out = run_root([root_exec(path="/opt/tool/bin/run", owner="0", mode="0100777", role="executable")])
    assert out[0].proposed_lane == "high"
    assert "world-writable" in out[0].claim and "as the executed program" in out[0].claim


def test_other_non_root_owner_is_a_lead_and_group_writable_needs_a_non_root_group():
    _pb, out = run_root([root_exec(owner="1002", owner_name="deploy")])
    assert out[0].proposed_lane == "lead" and "it is owned by a non-root account" in out[0].claim
    _pb, out = run_root([root_exec(owner="0", mode="0100775", group="1002")])
    assert out[0].proposed_lane == "lead" and "writable by group id 1002" in out[0].claim
    _pb, out = run_root([root_exec(owner="0", mode="0100775", group="0")])
    assert out == []


def test_root_owned_not_writable_and_non_root_execs_are_not_matched():
    pb, out = run_root([root_exec(owner="0", mode="0100755"), user_exec("1000")])
    assert out == [] and pb.evaluated == 2 and pb.missing_required == 0
    _pb, out = run_root([root_exec(uid="1000", euid="1000")])               # a user running their own file
    assert out == []


def test_effective_root_counts_as_root():
    _pb, out = run_root([root_exec(uid="1000", euid="0", auid="1000", ses=4)])
    assert len(out) == 1


def test_owner_running_their_own_file_through_sudo_is_excluded():
    # alice's file, run as root under alice's login uid: the owner elevating their own file
    _pb, out = run_root([root_exec(owner="1000", auid="1000", ses=7)])
    assert out == []
    # another account's root login running it is reported
    _pb, out = run_root([root_exec(owner="1000", auid="1001", ses=8)])
    assert len(out) == 1 and "audit login uid(s) 1001" in out[0].claim


def test_owner_session_exclusion_follows_the_write_run_rule():
    # bob's session 9: alice's account was used in it (su), then root ran alice's file there
    _pb, out = run_root([user_exec("1000", ses=9), root_exec(owner="1000", auid="1001", ses=9,
                                                             ts=T0 + timedelta(minutes=1))])
    assert out == []
    # order does not matter: the owner's activity in the session is known at finalize
    _pb, out = run_root([root_exec(owner="1000", auid="1001", ses=9)], [user_exec("1000", ses=9,
                                                                                  ts=T0 + timedelta(minutes=1))])
    assert out == []


def test_web_owner_and_world_writable_files_are_never_excluded():
    _pb, out = run_root([root_exec(owner="33", auid="33", ses=3)])
    assert len(out) == 1 and out[0].proposed_lane == "high"
    _pb, out = run_root([root_exec(owner="1000", mode="0100777", auid="1000", ses=7)])
    assert len(out) == 1 and out[0].proposed_lane == "high"


def test_script_interpreter_owned_by_another_account_is_reported_as_the_interpreter():
    run = root_exec(owner="0", mode="0100755", interp=("/opt/venv/bin/python3", "1002", "0100755"))
    _pb, out = run_root([run])
    assert len(out) == 1 and "/opt/venv/bin/python3 as the interpreter of the #! script" in out[0].claim
    assert out[0].group_key == "app01|1002|/opt/venv/bin/python3"


def test_same_basename_in_another_directory_is_a_separate_file():
    _pb, out = run_root([root_exec(path="/srv/a/run.sh", owner="33"), root_exec(path="/srv/b/run.sh", owner="0")])
    assert [m.group_key for m in out] == ["app01|33|/srv/a/run.sh"]


def test_missing_ownership_is_counted_missing_not_a_clean_no_match():
    bare = ev("process_exec", T0, process__uid="0", process__euid="0", process__executable="/usr/bin/x",
              process__argv=["x"])
    pb, out = run_root([bare])
    assert out == [] and pb.missing_required == 1
    no_uid = ev("process_exec", T0, process__executable="/usr/bin/x", process__argv=["x"])
    pb, out = run_root([no_uid])
    assert out == [] and pb.missing_required == 1


def test_only_owner_or_only_mode_still_decides_what_it_can():
    _pb, out = run_root([root_exec(owner="33", mode=None)])
    assert len(out) == 1
    _pb, out = run_root([root_exec(owner=None, mode="0100777", owner_name=None)])
    assert len(out) == 1 and "world-writable" in out[0].claim


def test_a_mode_change_between_runs_is_stated_and_raises_the_lane_whatever_the_order():
    early = root_exec(owner="1002", owner_name="deploy", mode="0100755")
    late = root_exec(owner="1002", owner_name="deploy", mode="0100777", ts=T0 + timedelta(minutes=5))
    for order in ([early, late], [late, early]):
        _pb, out = run_root(order)
        assert len(out) == 1 and out[0].proposed_lane == "high"
        assert "mode 0100755, 0100777" in out[0].claim and "world-writable" in out[0].claim


def test_unplaced_path_names_the_inode():
    _pb, out = run_root([root_exec(owner="33", process__exec_file__path=None)])
    assert "inode 4242" in out[0].claim


def test_every_run_failed_lowers_to_lead_and_says_so():
    _pb, out = run_root([root_exec(outcome=Outcome.failure)])
    assert out[0].proposed_lane == "lead" and "every recorded exec of the file failed" in out[0].notes[0]


def test_many_runs_cite_ten_and_give_exact_totals_and_boundary_times():
    runs = [root_exec(ts=T0 + timedelta(seconds=i)) for i in range(25)]
    _pb, out = run_root(runs[:12], runs[12:])
    m = out[0]
    assert len(m.events) == 10 and "25 times" in m.claim and "10 of these runs are cited" in m.claim
    assert f"from {T0.isoformat()} to {(T0 + timedelta(seconds=24)).isoformat()}" in m.claim
    _pb, out = run_root([root_exec(ts=T0)])
    assert f"once at {T0.isoformat()}" in out[0].claim


def test_root_exec_output_is_deterministic_and_rereads_count_once():
    runs = [root_exec(ts=T0 + timedelta(seconds=i), owner=o) for i, o in enumerate(["33", "1002", "33", "1000"])]
    _pb, a = run_root(runs)
    shuffled = runs[:]
    random.Random(7).shuffle(shuffled)
    _pb, b = run_root(shuffled[:2], shuffled[2:], shuffled)               # a resumed re-read of every record
    assert [(m.group_key, m.claim, m.proposed_lane, [e.id for e in m.events]) for m in a] == \
           [(m.group_key, m.claim, m.proposed_lane, [e.id for e in m.events]) for m in b]


# =============================================================================================================
# host.persistence_path_change
# =============================================================================================================
def change(path, ts=T0, uid="33", change_="create", exe="/usr/bin/dash", pid=4000, ppid=3999, auid=None, tty=None,
           owner="default", outcome=Outcome.success, host="app01", user="default", **kw):
    owner = uid if owner == "default" else owner
    user = NAMES.get(uid) if user == "default" else user
    return ev("file_change", ts, outcome=outcome, host=host, file__path=path, file__change=change_,
              file__owner__id=owner, process__uid=uid, process__user=user, process__executable=exe,
              process__pid=pid, process__ppid=ppid, process__auid=auid, process__tty=tty, **kw)


def pexec(exe, pid, ppid, ts=T0, host="app01", uid="0"):
    return ev("process_exec", ts, host=host, process__executable=exe, process__argv=[exe], process__pid=pid,
              process__ppid=ppid, process__uid=uid)


def run_persist(*partitions):
    pb = PersistencePathChange()
    store = {}
    for part in partitions:
        assert pb.consume(list(part)) == []
        for event in pb.drain_staged():
            store[event.id] = event
    pb.bind_loader(lambda ids: [store[i] for i in ids if i in store])
    return pb, pb.finalize()


def test_web_account_creating_a_cron_file_is_high():
    record = change("/etc/cron.d/job")
    _pb, out = run_persist([record])
    assert len(out) == 1
    m = out[0]
    assert m.proposed_lane == "high" and m.severity == "high" and m.confidence == "high"
    assert "account 'www-data' (uid 33), a web-service account," in m.claim
    assert "a file in a system cron table directory (/etc/cron.d)" in m.claim
    assert "/etc/cron.d/job: created it" in m.claim and "not the content written" in m.claim
    assert "T1053.003" in m.notes and m.group_key == "app01|33|/etc/cron.d"
    assert [e.id for e in m.events] == [record.id] and all(p.origin for p in m.predicate)


def test_root_editor_in_an_interactive_login_is_one_grouped_lead():
    kw = {"uid": "0", "exe": "/usr/bin/vim.basic", "auid": "1001", "tty": "pts0"}
    records = [change("/etc/pam.d/.sshd.swp", change_="create", **kw),
               change("/etc/pam.d/sshd", ts=T0 + timedelta(seconds=40), change_="rename_target", **kw)]
    _pb, out = run_persist(records)
    assert len(out) == 1
    m = out[0]
    assert m.proposed_lane == "lead" and "root (uid 0)" in m.claim
    assert "in an interactive login session (audit login uid 1001 on terminal pts0)" in m.claim
    assert "T1556.003" in m.notes


def test_root_daemon_write_is_a_lead_outside_any_login_session():
    _pb, out = run_persist([change("/etc/systemd/system/x.service", uid="0", exe="/usr/bin/python3.11")])
    assert out[0].proposed_lane == "lead" and "outside any login session" in out[0].claim
    assert "T1543.002" in out[0].notes


def test_package_manager_lineage_is_one_batched_lead_worded_as_package_activity():
    lineage = [pexec("/usr/bin/dpkg", 100, 90), pexec("/usr/bin/dash", 101, 100, ts=T0 + timedelta(seconds=1)),
               pexec("/usr/bin/cp", 102, 101, ts=T0 + timedelta(seconds=2))]
    writes = [change("/etc/cron.daily/apt-compat", ts=T0 + timedelta(seconds=2), uid="0", exe="/usr/bin/cp",
                     pid=102, ppid=101),
              change("/etc/cron.daily/dpkg", ts=T0 + timedelta(seconds=3), uid="0", exe="/usr/bin/dpkg",
                     pid=100, ppid=90, change_="rename_target"),
              change("/etc/cron.daily/man-db", ts=T0 + timedelta(seconds=4), uid="0", exe="/usr/bin/dpkg",
                     pid=100, ppid=90, change_="rename_target")]
    _pb, out = run_persist(lineage, writes)
    assert len(out) == 1
    m = out[0]
    assert m.proposed_lane == "lead" and m.group_key == "app01|package:dpkg|/etc/cron.daily"
    assert "package activity" in m.claim and "3 kernel file-change record(s) on 3 file(s)" in m.claim
    assert "a malicious or tampered package" in m.claim


def test_package_lineage_needs_the_parent_exec_at_or_before_the_write():
    # the boundary: a parent exec at the same instant counts; one recorded after the write does not
    same = [pexec("/usr/bin/dpkg", 100, 90, ts=T0), change("/etc/init.d/x", ts=T0, uid="0", exe="/usr/bin/cp",
                                                           pid=102, ppid=100)]
    _pb, out = run_persist(same)
    assert out[0].group_key.startswith("app01|package:dpkg")
    later = [pexec("/usr/bin/dpkg", 100, 90, ts=T0 + timedelta(microseconds=1)),
             change("/etc/init.d/x", ts=T0, uid="0", exe="/usr/bin/cp", pid=102, ppid=100)]
    _pb, out = run_persist(later)
    assert out[0].group_key == "app01|0|/etc/init.d"


def test_a_package_manager_name_outside_system_directories_is_not_package_activity():
    _pb, out = run_persist([change("/etc/cron.d/x", uid="0", exe="/tmp/dpkg", pid=7, ppid=1)])
    assert out[0].group_key == "app01|0|/etc/cron.d" and "package activity" not in out[0].claim


def test_non_root_changes_mixed_with_package_activity_stay_separate_and_high():
    writes = [pexec("/usr/bin/dpkg", 100, 90),
              change("/etc/profile.d/a.sh", uid="0", exe="/usr/bin/dpkg", pid=100, ppid=90),
              change("/etc/profile.d/b.sh", ts=T0 + timedelta(seconds=5), uid="1002", user="deploy",
                     exe="/usr/bin/tee")]
    _pb, out = run_persist(writes)
    assert sorted((m.group_key, m.proposed_lane) for m in out) == [
        ("app01|1002|/etc/profile.d", "high"), ("app01|package:dpkg|/etc/profile.d", "lead")]


def test_failed_attempts_only_are_a_lead_and_any_success_keeps_high():
    _pb, out = run_persist([change("/etc/cron.d/job", outcome=Outcome.failure)])
    assert out[0].proposed_lane == "lead" and "these are attempts" in out[0].claim
    assert "every recorded call failed" in out[0].notes[0]
    _pb, out = run_persist([change("/etc/cron.d/job", outcome=Outcome.failure),
                            change("/etc/cron.d/job2", ts=T0 + timedelta(seconds=1))])
    assert out[0].proposed_lane == "high"


def test_an_accounts_own_per_account_files_are_a_lead_and_anothers_are_high():
    _pb, out = run_persist([change("/home/alice/.bashrc", uid="1000", change_="content")])
    assert out[0].proposed_lane == "lead" and "the account's own" in out[0].claim
    _pb, out = run_persist([change("/var/spool/cron/crontabs/alice", uid="1000", change_="rename_target")])
    assert out[0].proposed_lane == "lead"
    _pb, out = run_persist([change("/home/bob/.ssh/authorized_keys", uid="1000", owner="1001")])
    assert out[0].proposed_lane == "high"
    # a web-service account is never "routine" even in its own home
    _pb, out = run_persist([change("/var/www/.ssh/authorized_keys", uid="33")])
    assert out[0].proposed_lane == "high" and "T1098.004" in out[0].notes


def test_deletes_moves_away_and_other_paths_are_not_matched():
    records = [change("/etc/cron.d/job", change_="delete"), change("/etc/cron.d/job.tmp", change_="rename_source"),
               change("/var/log/syslog", change_="content")]
    pb, out = run_persist(records)
    assert out == [] and pb.evaluated == 3 and pb.missing_required == 0


@pytest.mark.parametrize("path", ["/tmp/cron.d/job", "/etc/cron.d.bak/job", "/etc/cron.d", "/srv/www/authorized_keys.bak",
                                  "/home/alice/notes/.bashrc.txt", "/etc/sudoers.bak", "/etc/pam.d.old/sshd",
                                  "/usr/lib/security-tools/x.so", "/etc/ld.so.preload.d/x"])
def test_lookalike_paths_are_not_persistence_locations(path):
    assert persistence_location(path) is None


@pytest.mark.parametrize("path,technique", [
    ("/etc/crontab", "T1053.003"), ("/var/spool/cron/atjobs/a0001", "T1053.002"),
    ("/etc/rc.local", "T1037.004"), ("/etc/rc2.d/S01x", "T1037.004"), ("/etc/ld.so.preload", "T1574.006"),
    ("/etc/ld.so.conf.d/x.conf", "T1574.006"), ("/etc/sudoers.d/x", "T1548.003"), ("/etc/update-motd.d/99-x", "T1037"),
    ("/root/.ssh/authorized_keys2", "T1098.004"), ("/home/a/.config/systemd/user/x.service", "T1543.002"),
    ("/usr/lib/x86_64-linux-gnu/security/pam_x.so", "T1556.003"), ("/etc/udev/rules.d/99.rules", "T1546.017"),
    ("/etc/xdg/autostart/x.desktop", "T1547.013"), ("/etc/modules-load.d/x.conf", "T1547.006"),
])
def test_persistence_locations_and_techniques(path, technique):
    assert persistence_location(path)[2] == technique


def test_missing_path_uid_or_change_are_counted_missing():
    records = [ev("file_change", T0, file__change="content", process__uid="33"),
               ev("file_change", T0, file__path="/etc/cron.d/x", file__change="content"),
               ev("file_change", T0, file__path="/etc/cron.d/x", process__uid="33")]
    pb, out = run_persist(records)
    assert out == [] and pb.missing_required == 3


def test_many_changes_cite_ten_with_exact_totals():
    records = [change(f"/etc/cron.d/j{i:02d}", ts=T0 + timedelta(seconds=i)) for i in range(14)]
    _pb, out = run_persist(records)
    m = out[0]
    assert len(m.events) == 10 and "14 kernel file-change record(s)" in m.claim
    assert "The earliest 10 records are cited" in m.claim and "and 4 more" in m.claim


def test_persistence_output_is_deterministic_across_partition_order_and_rereads():
    records = [pexec("/usr/bin/dpkg", 100, 90),
               change("/etc/cron.d/a", uid="0", exe="/usr/bin/dpkg", pid=100, ppid=90, ts=T0 + timedelta(seconds=1)),
               change("/etc/cron.d/b", ts=T0 + timedelta(seconds=2)),
               change("/etc/init.d/c", uid="0", ts=T0 + timedelta(seconds=3), auid="1001", tty="pts1")]
    _pb, a = run_persist(records)
    shuffled = records[:]
    random.Random(3).shuffle(shuffled)
    _pb, b = run_persist(shuffled[:2], shuffled[2:], shuffled)
    assert [(m.group_key, m.claim, m.proposed_lane) for m in a] == [(m.group_key, m.claim, m.proposed_lane)
                                                                     for m in b]


# =============================================================================================================
# host.unbacked_or_deleted_executable
# =============================================================================================================
def run_unbacked(*partitions):
    pb = UnbackedExecutable()
    for part in partitions:
        assert pb.consume(list(part)) == []
    return pb, pb.finalize()


def test_memfd_exec_is_a_lead_naming_the_known_benign_runtime():
    e = ev("process_exec", T0, process__executable="/memfd:x (deleted)", process__argv=["x"], process__uid="0")
    _pb, out = run_unbacked([e])
    m = out[0]
    assert m.proposed_lane == "lead" and m.severity == "high"
    assert "memory-backed file (memfd)" in m.claim and "runc" in m.claim
    assert m.notes == ["executable class: memfd"] and m.group_key == "app01|/memfd:x (deleted)"


def test_deleted_daemon_binary_is_grouped_across_record_families_and_worded_honestly():
    exe = "/usr/sbin/sshd (deleted)"
    records = [ev("net_socket", T0 + timedelta(seconds=i), process__executable=exe, process__uid="0")
               for i in range(3)] + [ev("file_change", T0 + timedelta(seconds=5), process__executable=exe,
                                        process__uid="0", file__path="/var/log/x")]
    _pb, out = run_unbacked(records[:2], records[2:])
    assert len(out) == 1
    m = out[0]
    assert "4 audit record(s)" in m.claim and "3 socket call record(s), 1 file-change call record(s)" in m.claim
    assert "package-managed directory" in m.claim and "deletes itself" in m.claim
    assert m.proposed_lane == "lead"


@pytest.mark.parametrize("exe,cls", [("/run/user/1000/x", "run_user"), ("/dev/shm/.x", "shm"),
                                     ("/home/a/tool (deleted)", "deleted")])
def test_in_memory_directories_and_deleted_user_files(exe, cls):
    assert unbacked_executable(exe)[0] == cls
    assert "package-managed" not in unbacked_executable("/home/a/tool (deleted)")[1]


@pytest.mark.parametrize("exe", ["/usr/bin/python3", "/tmp/memfd:x", "/opt/deleted", "/opt/x (deleted).bak",
                                 "/run/users/x", "/dev/shmx/y"])
def test_lookalike_executables_are_not_matched(exe):
    assert unbacked_executable(exe) is None


def test_missing_executable_is_counted_missing_and_many_records_cite_ten():
    pb, out = run_unbacked([ev("net_socket", T0, process__uid="0")])
    assert out == [] and pb.missing_required == 1
    records = [ev("net_socket", T0 + timedelta(seconds=i), process__executable="/dev/shm/x") for i in range(12)]
    _pb, out = run_unbacked(records)
    assert len(out[0].events) == 10 and "12 audit record(s)" in out[0].claim
    assert "10 of these records are cited" in out[0].claim


# =============================================================================================================
# host.nonroot_write_root_executed_file with kernel file-change records
# =============================================================================================================
def cron_runs(ts, path=JOB, ses=12, pid=5000):
    return [ev("auth", ts, auth__service="cron", auth__phase="session_open", process__session_id=ses,
               process__pid=pid, user__name="root", process__auid="0"),
            ev("process_exec", ts + timedelta(seconds=1), process__argv=["/bin/bash", path],
               process__executable="/usr/bin/bash", process__uid="0", process__user="root", process__auid="0",
               process__session_id=ses, process__pid=pid + 1, process__ppid=pid, process__cwd="/root")]


def run_hijack(*partitions):
    pb = NonRootWriteRootExecutedFile()
    store = {}
    for part in partitions:
        assert pb.consume(list(part)) == []
        for event in pb.drain_staged():
            store[event.id] = event
    pb.bind_loader(lambda ids: [store[i] for i in ids if i in store])
    return pb, pb.finalize()


def kchange(change_="content", uid="33", ts=T0, path=JOB, **kw):
    return ev("file_change", ts, file__path=path, file__change=change_, process__uid=uid,
              process__user=NAMES.get(uid), process__euid=kw.pop("euid", uid), **kw)


def test_kernel_change_alone_then_a_root_run_is_urgent_for_a_web_account():
    record = kchange()
    _pb, out = run_hijack([record, *cron_runs(T0 + timedelta(minutes=5))])
    assert len(out) == 1
    m = out[0]
    assert m.proposed_lane == "urgent" and m.confidence == "high"
    assert "kernel file-change records show account 'www-data'" in m.claim
    assert "acting on /srv/tasks/rotate.sh at" in m.claim and ": opened it for writing;" in m.claim
    assert "changed" not in m.claim.split("no write-capable")[0]            # an open for writing is not a proven edit
    assert "no write-capable command on the file was recorded" in m.claim
    assert "began after the first kernel file-change record" in m.claim
    assert record.id in {e.id for e in m.events}


def test_kernel_change_without_a_later_root_run_is_high_not_urgent():
    _pb, out = run_hijack([*cron_runs(T0 - timedelta(minutes=5)), kchange()])
    assert out[0].proposed_lane == "high"
    _pb, out = run_hijack([kchange(), *cron_runs(T0 + timedelta(minutes=5))[:1]])     # session only, no run
    assert out == []


def test_kernel_change_by_another_account_is_raised_to_high_by_a_later_run():
    _pb, out = run_hijack([kchange(uid="1002"), *cron_runs(T0 + timedelta(minutes=5))])
    assert out[0].proposed_lane == "high"


def test_deletes_moves_away_setuid_writers_and_failures_are_not_writes():
    for record in (kchange("delete"), kchange("rename_source"), kchange(euid="0"),
                   kchange(outcome=Outcome.failure)):
        pb, out = run_hijack([record, *cron_runs(T0 + timedelta(minutes=5))])
        assert out == [], record.fields
        assert pb.file_change_records == 1


def test_kernel_change_without_a_change_kind_is_missing():
    pb, out = run_hijack([ev("file_change", T0, file__path=JOB, process__uid="33")])
    assert out == [] and pb.missing_required == 1 and pb.file_change_records == 0


def test_kernel_change_to_root_schedule_without_a_run_is_left_to_the_persistence_rule():
    _pb, out = run_hijack([kchange(path="/etc/cron.d/job", change_="create")])
    assert out == []


def test_kernel_writer_elevating_its_own_file_in_its_own_session_is_not_matched():
    own = kchange(uid="1000", process__session_id=7)
    run = ev("process_exec", T0 + timedelta(minutes=1), process__argv=["/bin/bash", JOB],
             process__executable="/usr/bin/bash", process__uid="0", process__auid="1000", process__session_id=7,
             process__pid=900, process__ppid=899)
    _pb, out = run_hijack([own, run])
    assert out == []


# =============================================================================================================
# Registry, pack and end-to-end through the sweep (raw audit lines)
# =============================================================================================================
def _stix_ids():
    with gzip.open(Path(__file__).resolve().parents[1] / "content/attack/enterprise-attack-20.0.json.gz") as fh:
        stix = json.load(fh)
    return {ref["external_id"] for obj in stix["objects"] if obj.get("type") == "attack-pattern"
            and not obj.get("revoked") and not obj.get("x_mitre_deprecated")
            for ref in obj.get("external_references", []) if ref.get("source_name") == "mitre-attack"}


@pytest.mark.parametrize("cls", [RootExecNonRootModifiableFile, PersistencePathChange, UnbackedExecutable])
def test_rules_are_registered_positive_only_carded_and_attack_ids_exist(cls):
    assert cls in ALL_PLAYBOOKS and not cls.assures_negative and cls.positive_only_reason
    assert any(isinstance(pb, cls) for pb in fresh_pack())
    assert cls.kind == "aggregate" and cls.lane in ("high", "lead") and cls.severity == "high"
    assert set(cls.attack) <= _stix_ids()
    assert {"behavior", "telemetry", "fidelity", "benign_and_cost", "query_cost", "next_pivot", "adds",
            "research_basis", "retrieval"} <= set(cls.card)
    from romulus.detect.kernel_files import _DIRS, _FILES
    assert {t for _p, _d, t in _DIRS} | {t for _d, t in _FILES.values()} <= _stix_ids()


def _audit_hit(i, ts_iso, line):
    return {"_id": f"k{i}", "_index": "romulus-host-x", "_source": {
        "@timestamp": ts_iso, "message": line, "host": {"name": "app01"},
        "event": {"dataset": "linux.audit", "original": line}}}


def test_sweep_end_to_end_web_write_then_root_cron_run(monkeypatch):
    from romulus.hunt import sweep as sw
    from romulus.sources.models import Completeness, SearchOutcome, Window
    from romulus.store.db import make_engine, migrate
    from romulus.store.repo import Repo

    t1, t2 = 1893920400, 1893920400 + 600
    web_enrich = '\x1dARCH=x86_64 SYSCALL=openat AUID="unset" UID="www-data" EUID="www-data"'
    root_enrich = '\x1dARCH=x86_64 SYSCALL=execve AUID="root" UID="root" EUID="root"'
    part1 = [
        _audit_hit(1, "2030-01-06T09:00:00Z",
                   f"type=SYSCALL msg=audit({t1}.100:501): arch=c000003e syscall=257 success=yes exit=3 "
                   f"a0=ffffff9c a1=7ffd a2=441 a3=0 items=1 ppid=3999 pid=4000 auid=4294967295 uid=33 euid=33 "
                   f'ses=4294967295 tty=pts0 comm="bash" exe="/usr/bin/bash" subj=unconfined (enforce) key=(null)'
                   + web_enrich),
        _audit_hit(2, "2030-01-06T09:00:00Z",
                   f'type=PATH msg=audit({t1}.100:501): item=0 name="rotate.sh" inode=42 dev=fd:01 mode=0100755 '
                   'ouid=33 ogid=33 rdev=00:00 nametype=NORMAL\x1dOUID="www-data" OGID="www-data"'),
        _audit_hit(3, "2030-01-06T09:00:00Z", f'type=CWD msg=audit({t1}.100:501): cwd="/srv/tasks"'),
    ]
    part2 = [
        _audit_hit(4, "2030-01-06T09:10:00Z",
                   f"type=USER_START msg=audit({t2}.000:900): pid=5000 uid=0 auid=0 ses=12 msg='op=PAM:session_open "
                   'grantors=pam_loginuid acct="root" exe="/usr/sbin/cron" hostname=? addr=? terminal=cron '
                   "res=success'"),
        _audit_hit(5, "2030-01-06T09:10:01Z",
                   f'type=EXECVE msg=audit({t2 + 1}.000:901): argc=2 a0="/bin/bash" a1="{JOB}"'),
        _audit_hit(6, "2030-01-06T09:10:01Z",
                   f"type=SYSCALL msg=audit({t2 + 1}.000:901): arch=c000003e syscall=59 success=yes exit=0 "
                   f"items=3 ppid=5000 pid=5001 auid=0 uid=0 euid=0 ses=12 comm=\"rotate.sh\" exe=\"/usr/bin/bash\""
                   + root_enrich),
        _audit_hit(7, "2030-01-06T09:10:01Z",
                   f'type=PATH msg=audit({t2 + 1}.000:901): item=0 name="{JOB}" inode=42 dev=fd:01 mode=0100755 '
                   'ouid=33 ogid=33 rdev=00:00 nametype=NORMAL\x1dOUID="www-data" OGID="www-data"'),
        _audit_hit(8, "2030-01-06T09:10:01Z",
                   f'type=PATH msg=audit({t2 + 1}.000:901): item=1 name="/bin/bash" inode=7 dev=fd:01 '
                   'mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL\x1dOUID="root" OGID="root"'),
        _audit_hit(9, "2030-01-06T09:10:01Z", f'type=CWD msg=audit({t2 + 1}.000:901): cwd="/root"'),
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
    by_rule = {c["rule_id"]: c for c in repo.candidates("h1")}
    hijack = by_rule[NonRootWriteRootExecutedFile.id]
    assert hijack["lane"] == "urgent" and "opened it for writing" in hijack["claim"]
    owned = by_rule[RootExecNonRootModifiableFile.id]
    assert owned["lane"] == "high" and "owner uid 33 ('www-data'), a web-service account" in owned["claim"]
    assert PersistencePathChange.id not in by_rule                   # not a persistence location
    cells = {c["rule_id"]: c["state"] for c in repo.rule_cells("h1") if c["target"] == "*"}
    assert cells[RootExecNonRootModifiableFile.id] == "matched"
    assert cells[PersistencePathChange.id] == "positive_only"
    assert sweep.stats["errors"] == 0
