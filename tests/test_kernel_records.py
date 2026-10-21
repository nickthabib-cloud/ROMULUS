"""Kernel audit records beyond exec and socket calls: the tokenizer, file-change groups and exec-file ownership.

Record shapes follow auditd's ENRICHED x86_64 output (one record per document, the typed values in the raw text).
Hosts, accounts and paths are invented."""
import pytest

from romulus.evidence.auditd import parse_record
from romulus.evidence.normalize import normalize_hits
from romulus.evidence.typed import Outcome

ENRICH = '\x1dARCH=x86_64 SYSCALL={name} AUID="{auid_name}" UID="{uid_name}" EUID="{uid_name}"'
NAMES = {"0": "root", "33": "www-data", "1000": "alice", "4294967295": "unset"}


def hit(_id, line, ts="2030-01-06T09:00:00.000Z", host="app01"):
    return {"_id": _id, "_index": "romulus-host-x", "_source": {
        "@timestamp": ts, "message": line, "host": {"name": host},
        "event": {"dataset": "linux.audit", "original": line}}}


def syscall(serial, number, name, *, a0="ffffff9c", a1="7ffd0000", a2="0", a3="0", success="yes", exit_="3",
            uid="0", auid="4294967295", ses="4294967295", items=2, exe="/usr/bin/vim.basic", comm="vim",
            tty="(none)", ts="1893920400.100", extra=""):
    enrich = ENRICH.format(name=name, auid_name=NAMES.get(auid, auid), uid_name=NAMES.get(uid, uid))
    return (f"type=SYSCALL msg=audit({ts}:{serial}): arch=c000003e syscall={number} success={success} "
            f"exit={exit_} a0={a0} a1={a1} a2={a2} a3={a3} items={items} ppid=900 pid=901 auid={auid} uid={uid} "
            f"gid={uid} euid={uid} suid={uid} fsuid={uid} egid={uid} sgid={uid} fsgid={uid} tty={tty} ses={ses} "
            f'comm="{comm}" exe="{exe}"{extra} key="persist"' + enrich)


def path(serial, item, name, nametype, *, inode="1001", mode="0100644", ouid="0", ogid="0", ts="1893920400.100"):
    owner = NAMES.get(ouid, ouid)
    if nametype == "UNKNOWN":
        return f'type=PATH msg=audit({ts}:{serial}): item={item} name="{name}" nametype=UNKNOWN cap_fp=0'
    return (f'type=PATH msg=audit({ts}:{serial}): item={item} name="{name}" inode={inode} dev=fd:01 mode={mode} '
            f"ouid={ouid} ogid={ogid} rdev=00:00 nametype={nametype} cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 "
            f'cap_frootid=0\x1dOUID="{owner}" OGID="{owner}"')


def cwd(serial, directory="/root", ts="1893920400.100"):
    return f'type=CWD msg=audit({ts}:{serial}): cwd="{directory}"'


def group(*lines):
    return [hit(f"r{i}", line) for i, line in enumerate(lines)]


# ---------------------------------------------------------------- tokenizer
def test_apparmor_subject_with_a_mode_suffix_keeps_the_following_fields():
    line = ('type=SYSCALL msg=audit(1893920400.100:7): arch=c000003e syscall=59 success=yes exit=0 uid=0 '
            'comm="cron" exe="/usr/sbin/cron" subj=/usr/sbin/cron (enforce) key="exec-root"'
            '\x1dARCH=x86_64 SYSCALL=execve UID="root"')
    rec = parse_record(line)
    assert rec.fields["subj"] == "/usr/sbin/cron (enforce)"
    assert rec.fields["key"] == "exec-root"
    assert rec.enriched["UID"] == "root"


def test_word_without_a_value_after_a_quoted_field_is_not_a_key():
    rec = parse_record('type=SYSCALL msg=audit(1.0:8): comm="x" (complain) key="k" exe="/bin/x"')
    assert rec.fields["key"] == "k" and rec.fields["exe"] == "/bin/x" and rec.fields["comm"] == "x"
    assert not [k for k in rec.fields if " " in k or "(" in k]


def test_double_equals_unconfined_subject_still_parses():
    rec = parse_record('type=SYSCALL msg=audit(1.0:9): subj==unconfined key=(null)')
    assert rec.fields["subj"] == "=unconfined" and rec.fields["key"] == "(null)"


# ---------------------------------------------------------------- file_change: opens
def test_write_open_that_creates_a_cron_file_is_one_create_event_with_owner_fields():
    events, skips, errors = normalize_hits(group(
        syscall(10, 257, "openat", a2="80241", uid="33", exe="/usr/bin/dash", comm="sh"),
        path(10, 0, "/etc/cron.d/", "PARENT", inode="200", mode="040755"),
        path(10, 1, "/etc/cron.d/job", "CREATE", inode="201", ouid="33", ogid="33"),
        cwd(10, "/var/www/html"),
        'type=PROCTITLE msg=audit(1893920400.100:10): proctitle=7368002D63',
    ))
    assert errors == [] and skips == {} and len(events) == 1
    e = events[0]
    assert e.family == "file_change" and e.outcome == Outcome.success
    assert e.get("file.path") == "/etc/cron.d/job" and e.get("file.change") == "create"
    assert e.get("file.syscall") == "openat" and e.get("file.open_flags") == "80241"
    assert e.get("file.inode") == 201 and e.get("file.owner.id") == "33" and e.get("file.owner.name") == "www-data"
    assert e.get("file.mode") == "0100644" and e.get("file.nametype") == "CREATE"
    assert e.get("process.uid") == "33" and e.get("process.user") == "www-data"
    assert e.get("audit.key") == "persist" and e.get("process.executable") == "/usr/bin/dash"
    assert e.ts.timestamp() == pytest.approx(1893920400.1)
    assert {r.native_id for r in e.raw} == {"r0", "r2", "r4"}     # SYSCALL, the CREATE item, PROCTITLE
    assert all(fv.origin for fv in e.fields.values())


@pytest.mark.parametrize("flags", ["80000", "0", "88000", "80040"])     # read-only, with O_CLOEXEC / O_CREAT
def test_read_only_open_is_not_a_file_change(flags):
    events, skips, errors = normalize_hits(group(
        syscall(11, 257, "openat", a2=flags),
        path(11, 0, "/etc/crontab", "NORMAL"),
        cwd(11),
    ))
    assert events == [] and errors == [] and skips == {"audit open without write intent": 1}


def test_write_open_of_an_existing_file_is_a_content_change():
    events, _skips, errors = normalize_hits(group(
        syscall(12, 2, "open", a1="441"),                  # O_WRONLY|O_CREAT|O_APPEND on an existing file
        path(12, 0, "/etc/profile.d/x.sh", "NORMAL"),
        cwd(12),
    ))
    assert errors == [] and [e.get("file.change") for e in events] == ["content"]


def test_read_write_open_and_truncating_open_are_write_intent():
    for flags in ("2", "200"):                          # O_RDWR; O_RDONLY|O_TRUNC
        events, _, _ = normalize_hits(group(syscall(13, 257, "openat", a2=flags),
                                            path(13, 0, "/etc/ld.so.preload", "NORMAL"), cwd(13)))
        assert [e.get("file.change") for e in events] == ["content"], flags


def test_creat_is_always_write_intent():
    events, _, _ = normalize_hits(group(syscall(14, 85, "creat", a1="1a4"),
                                        path(14, 0, "/root/.ssh/", "PARENT"),
                                        path(14, 1, "/root/.ssh/authorized_keys", "CREATE"), cwd(14)))
    assert [e.get("file.change") for e in events] == ["create"]
    assert "file.open_flags" not in events[0].fields


def test_unnamed_temporary_file_is_skipped_with_a_reason():
    events, skips, _ = normalize_hits(group(syscall(15, 257, "openat", a2="410002"),
                                            path(15, 0, "/tmp", "NORMAL", mode="041777"), cwd(15)))
    assert events == [] and skips == {"audit open of an unnamed temporary file (O_TMPFILE)": 1}


def test_openat2_records_no_flags_so_the_change_is_absent_not_guessed():
    events, _, errors = normalize_hits(group(syscall(16, 437, "openat2"), path(16, 0, "/etc/pam.d/sshd", "NORMAL"),
                                             cwd(16)))
    assert errors == [] and len(events) == 1
    assert not events[0].has("file.change") and events[0].get("file.path") == "/etc/pam.d/sshd"
    assert any("open flags" in c for c in events[0].caveats)


def test_failed_write_open_is_kept_as_an_attempt():
    events, _, _ = normalize_hits(group(
        syscall(17, 257, "openat", a2="241", success="no", exit_="-13", uid="33"),
        path(17, 0, "/etc/cron.d/", "PARENT"),
        path(17, 1, "/etc/cron.d/job", "UNKNOWN"),
        cwd(17),
    ))
    assert len(events) == 1
    e = events[0]
    assert e.outcome == Outcome.failure and e.get("file.exit") == "-13"
    assert e.get("file.change") == "create" and e.get("file.path") == "/etc/cron.d/job"
    assert not e.has("file.owner.id") and not e.has("file.inode")


# ---------------------------------------------------------------- file_change: names and placement
def test_relative_name_is_resolved_against_the_working_directory():
    events, _, _ = normalize_hits(group(syscall(20, 257, "openat", a2="241"),
                                        path(20, 0, "../.bashrc", "NORMAL"), cwd(20, "/home/alice/src")))
    assert events[0].get("file.path") == "/home/alice/.bashrc"
    assert events[0].fields["file.path"].origin.endswith("+CWD.cwd")
    assert {r.native_id for r in events[0].raw} == {"r0", "r1", "r2"}


def test_relative_name_under_a_directory_descriptor_is_a_typed_partial():
    events, _, errors = normalize_hits(group(syscall(21, 263, "unlinkat", a0="3"),
                                             path(21, 0, "/var/spool/cron/crontabs", "PARENT"),
                                             path(21, 1, "root", "DELETE"), cwd(21, "/")))
    assert errors == [] and len(events) == 1
    assert not events[0].has("file.path") and events[0].get("file.change") == "delete"
    assert any("directory descriptor" in c for c in events[0].caveats)


def test_bare_name_without_cwd_is_placed_under_an_absolute_parent():
    events, _, _ = normalize_hits(group(syscall(22, 87, "unlink"), path(22, 0, "/etc/cron.d", "PARENT"),
                                        path(22, 1, "job", "DELETE")))
    assert events[0].get("file.path") == "/etc/cron.d/job"
    assert events[0].fields["file.path"].origin.endswith("+PATH(PARENT).name")


def test_relative_name_without_cwd_or_parent_is_unresolved():
    events, _, _ = normalize_hits(group(syscall(23, 87, "unlink"), path(23, 0, "sub/job", "DELETE")))
    assert not events[0].has("file.path") and events[0].get("file.change") == "delete"


# ---------------------------------------------------------------- file_change: other calls
def test_rename_to_a_new_name_is_a_source_and_a_target_event():
    events, _, errors = normalize_hits(group(
        syscall(30, 82, "rename", exe="/usr/bin/dpkg", comm="dpkg"),
        path(30, 0, "/etc/cron.d/", "PARENT"), path(30, 1, "/etc/cron.d/", "PARENT"),
        path(30, 2, "/etc/cron.d/job.dpkg-new", "DELETE", inode="300"),
        path(30, 3, "/etc/cron.d/job", "CREATE", inode="300"), cwd(30)))
    assert errors == []
    got = {(e.get("file.change"), e.get("file.path")) for e in events}
    assert got == {("rename_source", "/etc/cron.d/job.dpkg-new"), ("rename_target", "/etc/cron.d/job")}
    assert len({e.id for e in events}) == 2


def test_rename_over_an_existing_file_drops_the_replaced_entry_or_orders_two_deletes():
    replaced = group(syscall(31, 316, "renameat2", a0="ffffffffffffff9c", a2="ffffffffffffff9c"),
                     path(31, 0, "/etc/", "PARENT"), path(31, 1, "/etc/", "PARENT"),
                     path(31, 2, "/etc/sudoers.tmp", "DELETE", inode="1"),
                     path(31, 3, "/etc/sudoers", "DELETE", inode="2"),
                     path(31, 4, "/etc/sudoers", "CREATE", inode="1"), cwd(31))
    events, _, _ = normalize_hits(replaced)
    assert sorted((e.get("file.change"), e.get("file.path")) for e in events) == [
        ("rename_source", "/etc/sudoers.tmp"), ("rename_target", "/etc/sudoers")]
    two = group(syscall(32, 82, "rename"), path(32, 0, "/etc/", "PARENT"), path(32, 1, "/etc/", "PARENT"),
                path(32, 2, "/etc/a", "DELETE"), path(32, 3, "/etc/b", "DELETE"), cwd(32))
    events, _, _ = normalize_hits(two)
    assert sorted((e.get("file.change"), e.get("file.path")) for e in events) == [
        ("rename_source", "/etc/a"), ("rename_target", "/etc/b")]


def test_link_symlink_mkdir_and_unlink_kinds():
    cases = [(86, "link", "link"), (88, "symlink", "link"), (83, "mkdir", "create"), (87, "unlink", "delete")]
    for number, name, change in cases:
        nametype = "DELETE" if change == "delete" else "CREATE"
        events, _, _ = normalize_hits(group(syscall(33, number, name), path(33, 0, "/etc/init.d/", "PARENT"),
                                            path(33, 1, "/etc/init.d/svc", nametype), cwd(33)))
        assert [(e.get("file.change"), e.get("file.path")) for e in events] == [(change, "/etc/init.d/svc")], name


def test_chmod_and_chown_carry_the_requested_mode_and_owner():
    events, _, _ = normalize_hits(group(syscall(34, 90, "chmod", a1="9ed"), path(34, 0, "/usr/bin/find", "NORMAL"),
                                        cwd(34)))
    assert events[0].get("file.change") == "attributes" and events[0].get("file.new_mode") == "4755"
    events, _, _ = normalize_hits(group(syscall(35, 260, "fchownat", a2="21", a3="ffffffff"),
                                        path(35, 0, "/srv/job.sh", "NORMAL"), cwd(35)))
    assert events[0].get("file.new_owner.id") == "33" and not events[0].has("file.new_group.id")


def test_descriptor_calls_have_no_path_and_say_why():
    events, _, errors = normalize_hits(group(syscall(36, 91, "fchmod", a0="3", a1="1ff", items=0), cwd(36)))
    assert errors == [] and len(events) == 1
    e = events[0]
    assert e.get("file.change") == "attributes" and not e.has("file.path") and e.get("file.new_mode") == "0777"
    assert any("open file descriptor" in c for c in e.caveats)


def test_missing_path_records_are_counted_in_a_caveat():
    events, _, _ = normalize_hits(group(syscall(37, 87, "unlink", items=2), path(37, 0, "/etc/cron.d/", "PARENT"),
                                        cwd(37)))
    assert len(events) == 1 and not events[0].has("file.path")
    assert any("1 of the 2 PATH records" in c for c in events[0].caveats)


def test_duplicate_path_items_are_a_file_family_error():
    events, _, errors = normalize_hits(group(syscall(38, 87, "unlink"), path(38, 1, "/etc/a", "DELETE"),
                                             path(38, 1, "/etc/b", "DELETE"), cwd(38)))
    assert events == [] and errors and errors[0][1].startswith("linux.audit.file:")
    from romulus.hunt.sweep import DATASET_FAMILIES
    assert DATASET_FAMILIES["linux.audit.file"] == {"file_change"}
    assert "file_change" in DATASET_FAMILIES["linux.audit"]


def test_unrelated_syscalls_are_still_counted_skips():
    events, skips, _ = normalize_hits(group(syscall(39, 105, "setuid", items=0)))
    assert events == [] and skips == {"audit group without EXECVE, socket or file-change syscall": 1}


def test_aarch64_openat_decodes_by_its_own_number():
    line = syscall(40, 56, "openat", a2="241").replace("arch=c000003e", "arch=c00000b7")
    events, _, _ = normalize_hits(group(line, path(40, 0, "/etc/rc.local", "NORMAL"), cwd(40)))
    assert [e.get("file.change") for e in events] == ["content"]


# ---------------------------------------------------------------- exec-file ownership
def execve(serial, *args, ts="1893920400.100"):
    parts = " ".join(f'a{i}="{a}"' for i, a in enumerate(args))
    return f"type=EXECVE msg=audit({ts}:{serial}): argc={len(args)} {parts}"


def test_exec_of_a_program_carries_its_owner_and_mode():
    events, _, errors = normalize_hits(group(
        execve(50, "/opt/app/bin/run"),
        syscall(50, 59, "execve", exe="/opt/app/bin/run", comm="run", a0="55d0", a2="0"),
        path(50, 0, "/opt/app/bin/run", "NORMAL", inode="77", mode="0100777", ouid="1000", ogid="1000"),
        path(50, 1, "/lib64/ld-linux-x86-64.so.2", "NORMAL", inode="78", mode="0100755"),
        cwd(50, "/")))
    assert errors == []
    e = events[0]
    assert e.get("process.exec_file.path") == "/opt/app/bin/run" and e.get("process.exec_file.role") == "executable"
    assert e.get("process.exec_file.owner.id") == "1000" and e.get("process.exec_file.mode") == "0100777"
    assert e.get("process.exec_file.inode") == 77 and e.get("process.exec_file.owner.name") == "alice"
    assert not e.has("process.interpreter_file.path")
    assert "r2" in {r.native_id for r in e.raw}


def test_exec_of_a_script_carries_the_script_and_its_interpreter():
    events, _, _ = normalize_hits(group(
        execve(51, "/bin/sh", "./job.sh", "--now"),
        syscall(51, 59, "execve", exe="/usr/bin/dash", comm="job.sh"),
        path(51, 0, "./job.sh", "NORMAL", inode="90", mode="0100755", ouid="33", ogid="33"),
        path(51, 1, "/bin/sh", "NORMAL", inode="91", mode="0100755"),
        path(51, 2, "/lib64/ld-linux-x86-64.so.2", "NORMAL", inode="78"),
        cwd(51, "/srv/tasks")))
    e = events[0]
    assert e.get("process.exec_file.role") == "script" and e.get("process.exec_file.path") == "/srv/tasks/job.sh"
    assert e.get("process.exec_file.owner.id") == "33"
    assert e.get("process.interpreter_file.path") == "/bin/sh"
    assert e.get("process.interpreter_file.owner.id") == "0"


def test_a_file_operand_named_like_the_program_is_not_mistaken_for_a_script():
    events, _, _ = normalize_hits(group(
        execve(52, "cat", "/usr/bin/cat"),
        syscall(52, 59, "execve", exe="/usr/bin/cat", comm="cat"),
        path(52, 0, "/usr/bin/cat", "NORMAL"), path(52, 1, "/lib64/ld-linux-x86-64.so.2", "NORMAL"), cwd(52)))
    assert events[0].get("process.exec_file.role") == "executable"


def test_exec_without_path_records_keeps_ownership_absent_with_a_caveat():
    events, _, _ = normalize_hits(group(execve(53, "/bin/true"), syscall(53, 59, "execve", exe="/usr/bin/true"),
                                        cwd(53)))
    e = events[0]
    assert not e.has("process.exec_file.owner.id")
    assert any("PATH record of the executed file" in c for c in e.caveats)


def test_exec_path_without_owner_fields_leaves_them_absent():
    events, _, _ = normalize_hits(group(execve(54, "/bin/true"), syscall(54, 59, "execve", exe="/usr/bin/true"),
                                        path(54, 0, "/bin/true", "UNKNOWN"), cwd(54)))
    e = events[0]
    assert e.get("process.exec_file.path") == "/bin/true"
    assert not e.has("process.exec_file.owner.id") and not e.has("process.exec_file.mode")
