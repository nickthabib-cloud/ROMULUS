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
