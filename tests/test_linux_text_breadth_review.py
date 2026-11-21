"""Review follow-ups for the Linux daemon families: honest writer wording, split sudo records, broker success after
refusals, and the account, kernel and BIND statement forms the first pass missed.

Statement sources as in tests/test_linux_text_breadth.py; in addition sudo's lib/eventlog do_syslog (records longer
than syslog_maxlen are split at a space into "user : (command continued) ..." lines), BIND 9 lib/ns/client.c
(client-context prefix with /key and view) and kernel/module/main.c (staging, livepatch and license summary notes).
Hosts, accounts and addresses are invented.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest

from romulus.detect.privilege_brokers import (
    PkexecEnvironmentRejection,
    PrivilegeBrokerRefusal,
    PrivilegeBrokerSuspiciousSuccess,
)
from romulus.evidence.linux_service_text import parse_service
from romulus.evidence.normalize import SUDO_UNJOINED, normalize_hits
from romulus.evidence.typed import Outcome
from tests.test_linux_text_breadth import _account_run, doc, one

T0 = datetime(2026, 11, 9, 12, tzinfo=UTC)
PWNKIT = ("alice: The value for the SHELL variable was not found the /etc/shells file [USER=root] [TTY=/dev/pts/0] "
          "[CWD=/tmp/p] [COMMAND=GCONV_PATH=./pwnkit.so:. SHELL=/x CHARSET=PWNKIT]")


def at(seconds: float) -> str:
    return (T0 + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")


def journal_doc(record: dict, nid: str, seconds: float = 0, host: str = "app01") -> dict:
    """The dev importer's journal JSON shape with an explicit journal record."""
    record = {"_HOSTNAME": host, **record}
    return {"_index": "host-logs", "_id": nid, "_source": {
        "@timestamp": at(seconds), "host": {"name": host}, "message": record.get("MESSAGE", ""),
        "event": {"dataset": "systemd.journal", "original": json.dumps(record)}}}


def run(rule_class, events):
    rule = rule_class()
    try:
        return rule, list(rule.consume(events))
    finally:
        rule.close_spill()


# ---------------------------------------------------------------------------------------------- I1: writer wording
@pytest.mark.parametrize("shape,comm,expected", [
    ("journal", "logger", ("a line logged under the identifier 'pkexec' (journald shows another program, 'logger', "
                          "wrote it) says that pkexec run by")),
    ("raw", None, ("a line logged under the identifier 'pkexec' (writer not verifiable from plain syslog) says that "
                  "pkexec run by")),
    ("journal", "pkexec", "On app01, pkexec run by 'alice'"),
])
def test_pkexec_trace_claim_names_the_writer_without_losing_its_lane(shape, comm, expected):
    event = one(shape, "pkexec", PWNKIT, comm=comm)
    _rule, [match] = run(PkexecEnvironmentRejection, [event])
    assert match.proposed_lane == "high" and expected in match.claim
    if comm == "pkexec":
        assert "logged under the identifier" not in match.claim


def test_forged_and_genuine_traces_fold_apart():
    forged = one("journal", "pkexec", PWNKIT, comm="logger", nid="f")
    genuine = one("journal", "pkexec", PWNKIT, comm="pkexec", nid="g")
    _rule, matches = run(PkexecEnvironmentRejection, [forged, genuine])
    assert len({m.group_key for m in matches}) == 2


@pytest.mark.parametrize("comm,sentence", [
    ("logger", ("The record(s) are a line logged under the identifier 'gpasswd' (journald shows another program, "
               "'logger', wrote it).")),
    (None, "(writer not verifiable from this record, which carries no journald process identity)"),
])
def test_high_account_claim_from_a_tool_line_names_its_writer(comm, sentence):
    event = one("journal", "gpasswd", "user mallory added by root to group sudo", pid=9001, comm=comm)
    [match] = _account_run([event])
    assert match.proposed_lane == "high" and sentence in match.claim


def test_high_account_claim_from_a_confirmed_tool_line_keeps_its_wording():
    event = one("journal", "gpasswd", "user mallory added by root to group sudo", pid=9001, comm="gpasswd")
    [match] = _account_run([event])
    assert match.proposed_lane == "high" and "logged under the identifier" not in match.claim


# ---------------------------------------------------------------------------------------------- I2: pkexec newlines
def test_pkexec_working_directory_with_a_newline_is_read():
    event = one("journal", "pkexec", "alice: Executing command [USER=root] [TTY=/dev/pts/0] [CWD=/tmp/a\nb] "
                "[COMMAND=/usr/bin/id\n-u]", comm="pkexec")
    assert event.outcome == Outcome.success
    assert event.get("process.cwd") == "/tmp/a\nb" and event.get("privilege.command") == "/usr/bin/id\n-u"


def test_pkexec_newline_does_not_move_the_decision():
    # the decision text is anchored before the working directory: a forged decision inside it is the directory
    event = parse_service("pkexec", "alice: Executing command [USER=root] [TTY=/dev/pts/0] [CWD=/x\nalice: The value "
                          "for the SHELL variable was not found the /etc/shells file] [COMMAND=/bin/id]")
    assert event.outcome == Outcome.success and "privilege.rejected_variable" not in event.fields


# ---------------------------------------------------------------------------------------------- I4: sudo reasons
@pytest.mark.parametrize("line,reason,target", [
    ("www-data : no tty ; TTY=unknown ; PWD=/var/www ; USER=root ; COMMAND=/bin/sh", "no tty", "root"),
    ("bob : user not allowed to change directory to /root ; TTY=pts/1 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/ls",
     "user not allowed to change directory to /root", "root"),
    ("bob : unknown user nosuch ; TTY=pts/1 ; PWD=/home/bob ; USER=nosuch ; COMMAND=/bin/ls", "unknown user nosuch",
     "nosuch"),
    ("bob : setid command rejected in intercept mode ; TTY=pts/1 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/passwd",
     "setid command rejected in intercept mode", "root"),
])
def test_sudo_refusal_reasons(line, reason, target):
    event = one("journal", "sudo", line)
    assert event.outcome == Outcome.failure and event.get("privilege.denial_reason") == reason
    assert event.get("auth.target_user") == target


def test_web_service_no_tty_refusal_is_a_named_lead():
    event = one("journal", "sudo", "www-data : no tty ; TTY=unknown ; PWD=/var/www ; USER=root ; COMMAND=/bin/sh")
    _rule, [match] = run(PrivilegeBrokerRefusal, [event])
    assert match.proposed_lane == "lead" and "(no tty)" in match.claim and "web-service account" in match.claim


# ---------------------------------------------------------------------------------------------- M1: split sudo records
LONG_PWD = "/srv/" + "a" * 995


def split_sudo(pids=(4100, 4100, 4100)):
    """The three lines sudo writes for a refusal whose working directory is about 1,000 characters: the first part
    ends at the last space within the line limit, the second is cut inside the directory (no space there), the
    third holds the rest."""
    body = f"user NOT in sudoers ; TTY=pts/0 ; PWD={LONG_PWD} ; USER=root ; COMMAND=/bin/bash"
    first, rest = body[:body.index("PWD=") - 1], body[body.index("PWD="):]
    second, third = rest[:960], rest[960:]
    lines = [f"mallory : {first}", f"mallory : (command continued) {second}", f"mallory : (command continued) {third}"]
    return [journal_doc({"MESSAGE": line, "SYSLOG_IDENTIFIER": "sudo", "_COMM": "sudo", "_PID": str(pid)},
                        f"s{n}", seconds=n * 0.001) for n, (line, pid) in enumerate(zip(lines, pids))]


def test_split_sudo_record_is_joined_into_one_cited_refusal():
    events, skips, errors = normalize_hits(split_sudo())
    assert not errors and not skips and len(events) == 1
    [event] = events
    assert event.get("auth.target_user") == "root" and event.get("privilege.denial_reason") == "user NOT in sudoers"
    assert event.get("sudo.command") == "/bin/bash" and not event.has("sudo.chunk")
    assert event.get("process.cwd").replace(" ", "") == LONG_PWD
    assert len(event.raw) == 3 and any("Joined from the lines" in caveat for caveat in event.caveats)
    _rule, [match] = run(PrivilegeBrokerRefusal, [event])
    assert "acting as 'root'" in match.claim


def test_unjoinable_split_sudo_record_is_a_refusal_with_an_unknown_target():
    events, skips, errors = normalize_hits(split_sudo(pids=(4100, 4200, 4200)))
    assert not errors and skips == {SUDO_UNJOINED: 2}
    [event] = events
    assert event.outcome == Outcome.failure and not event.has("auth.target_user")
    assert event.get("sudo.chunk") == "head"
    _rule, [match] = run(PrivilegeBrokerRefusal, [event])
    assert "an unrecorded account" in match.claim and "run-as account is unknown" in match.claim


# ---------------------------------------------------------------------------------------------- M2, M3: writer checks
def test_sudo_journal_line_from_another_writer_keeps_its_event_with_a_caveat():
    events, _skips, _errors = normalize_hits([journal_doc({
        "MESSAGE": "alice : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/id", "SYSLOG_IDENTIFIER": "sudo",
        "_COMM": "logger", "_PID": "77"}, "w1")])
    [event] = events
    assert any("disagrees" in caveat for caveat in event.caveats) and event.get("log.writer") == "logger"


def test_kernel_transport_is_a_verified_kernel_writer():
    events, _skips, _errors = normalize_hits([journal_doc({
        "MESSAGE": "rk: loading out-of-tree module taints kernel.", "SYSLOG_IDENTIFIER": "kernel",
        "_TRANSPORT": "kernel"}, "k1")])
    [event] = events
    assert event.get("module.taint") == "out_of_tree"
    assert not any("not verifiable" in caveat or "disagrees" in caveat for caveat in event.caveats)


# ---------------------------------------------------------------------------------------------- M4, M5, M9, M10
@pytest.mark.parametrize("program,body,privilege", [
    ("gpasswd", "members of group sudo set by root to alice,bob", "the members of privileged group sudo set"),
    ("gpasswd", "administrators of group wheel set by root to alice", "the administrators of privileged group wheel set"),
    ("usermod", "change user 'bob' GID from '1001' to '0'", "primary group id 0"),
    ("groupmod", "group changed in /etc/group (changing /etc/group; group devs/1001, new gid: 0)",
     "group id 0 given to a group"),
])
def test_root_equivalent_group_changes_are_high(program, body, privilege):
    [match] = _account_run([one("journal", program, body, pid=9300, comm=program)])
    assert match.proposed_lane == "high" and privilege in match.claim


def test_ordinary_gid_and_member_list_changes_stay_leads():
    [match] = _account_run([one("journal", "gpasswd", "members of group devs set by root to alice", pid=9301,
                                comm="gpasswd")])
    assert match.proposed_lane == "lead"


@pytest.mark.parametrize("body,taint,odd", [
    ("rk: module license taints kernel.", "license", False),
    ("rtl8723bs: module is from the staging directory, the quality is unknown, you have been warned.", "staging",
     False),
    ("livepatch_fix: tainting kernel with TAINT_LIVEPATCH", "livepatch", False),
    ("rk.mod!: loading out-of-tree module taints kernel.", "out_of_tree", True),
])
def test_more_kernel_taint_notes_and_unusual_module_names(body, taint, odd):
    event = one("journal", "kernel", body)
    assert event.get("module.taint") == taint
    assert any("characters kernel module names" in caveat for caveat in event.caveats) == odd


@pytest.mark.parametrize("program,body,action,fields,outcome", [
    ("gpasswd", "root failed to add user mallory to group sudo", "modify_user",
     {"account.group": "sudo", "account.op": "add-user-to-group", "account.name": "mallory"}, Outcome.failure),
    ("gpasswd", "bob failed to remove user alice from group wheel: Permission denied", "modify_user",
     {"account.op": "delete-user-from-group", "user.name": "bob"}, Outcome.failure),
    ("usermod", "change 'old' to 'new' in group 'sudo'", "modify_user",
     {"account.previous_name": "old", "account.name": "new", "account.op": "rename-group-member"}, Outcome.success),
])
def test_gpasswd_failures_and_usermod_member_renames(program, body, action, fields, outcome):
    event = one("journal", program, body)
    assert event.get("account.action") == action and event.outcome == outcome
    for key, value in fields.items():
        assert event.get(key) == value


def test_their_second_database_lines_are_skips():
    for program, body in (("gpasswd", "root failed to add user mallory to group sudo in /etc/gshadow"),
                          ("usermod", "change 'old' to 'new' in shadow group 'sudo'")):
        events, skips, _errors = normalize_hits([doc("raw", program, body)])
        assert not events and sum(skips.values()) == 1


@pytest.mark.parametrize("shape", ["raw", "syslog"])
def test_useradd_syslog_paths_carry_the_primary_group_id(shape):
    event = one(shape, "useradd", "new user: name=svc, UID=990, GID=991, home=/srv, shell=/bin/sh, from=none")
    assert event.get("account.group_id") == "991"


@pytest.mark.parametrize("program,body,action", [("userdel", "delete user 'x1'\n", "delete_user"),
                                                 ("groupdel", "group 'old' removed\n", "delete_group")])
def test_statements_written_with_a_trailing_newline(program, body, action):
    event = one("journal", program, body)
    assert event.get("account.action") == action


# ---------------------------------------------------------------------------------------------- I5: broker success
def sudo_line(seconds, line, *, comm="sudo", nid=None, host="app01"):
    return normalize_hits([journal_doc({"MESSAGE": line, "SYSLOG_IDENTIFIER": "sudo", "_COMM": comm, "_PID": "5"},
                                       nid or f"b{seconds}", seconds, host)])[0][0]


def refused(seconds, reason="3 incorrect password attempts", actor="mallory", host="app01"):
    return sudo_line(seconds, f"{actor} : {reason} ; TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/bash",
                     nid=f"r{seconds}{actor}{host}", host=host)


def allowed(seconds, actor="mallory", comm="sudo", host="app01"):
    return sudo_line(seconds, f"{actor} : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/bash", comm=comm,
                     nid=f"a{seconds}{actor}{host}", host=host)


def test_success_after_three_failed_attempts_is_high_and_cites_the_refusals():
    first, success = refused(0), allowed(120)
    _rule, matches = run(PrivilegeBrokerSuspiciousSuccess, [success, first])
    [match] = matches
    assert match.proposed_lane == "high" and "3 failed password attempt(s)" in match.claim
    assert {e.id for e in match.events} == {first.id, success.id}


def test_success_after_a_policy_refusal_is_high():
    _rule, [match] = run(PrivilegeBrokerSuspiciousSuccess, [refused(0, "user NOT in sudoers"), allowed(300)])
    assert match.proposed_lane == "high" and "refusal of the account's right" in match.claim


def test_a_single_mistyped_password_then_success_is_a_lead():
    # one wrong password is the common benign case: still reported, as a lead
    _rule, [match] = run(PrivilegeBrokerSuspiciousSuccess, [refused(0, "1 incorrect password attempt"), allowed(20)])
    assert match.proposed_lane == "lead" and "mistyped password" in match.claim


def test_success_outside_the_window_or_without_refusal_is_not_a_finding():
    _rule, out = run(PrivilegeBrokerSuspiciousSuccess, [refused(0), allowed(901)])
    assert out == []
    _rule, out = run(PrivilegeBrokerSuspiciousSuccess, [allowed(5, actor="alice")])
    assert out == []


def test_service_account_success_is_high_even_without_refusals():
    _rule, [match] = run(PrivilegeBrokerSuspiciousSuccess, [allowed(0, actor="www-data")])
    assert match.proposed_lane == "high" and "service account" in match.claim


@pytest.mark.parametrize("comm,expected", [
    ("logger", ("a line logged under the identifier 'sudo' (journald shows another program, 'logger', wrote it) says "
               "that sudo let 'www-data'")),
    ("sudo", "On app01, sudo logged that it let 'www-data' act as 'root'."),
])
def test_success_claim_names_a_forged_writer(comm, expected):
    _rule, [match] = run(PrivilegeBrokerSuspiciousSuccess, [allowed(0, actor="www-data", comm=comm)])
    assert match.proposed_lane == "high" and expected in match.claim


def test_refusals_in_an_earlier_partition_are_held_for_a_later_success():
    rule = PrivilegeBrokerSuspiciousSuccess()
    try:
        assert rule.consume([refused(0)]) == []
        [match] = rule.consume([allowed(60)])
        assert match.proposed_lane == "high"
    finally:
        rule.close_spill()


# ---------------------------------------------------------------------------------------------- spill at scale
class SmallRefusal(PrivilegeBrokerRefusal):
    HOT = 8


class SmallSuccess(PrivilegeBrokerSuspiciousSuccess):
    HOT = 8


def test_refusal_folds_spill_to_disk_and_keep_counting():
    rule = SmallRefusal()
    try:
        first = [refused(i, actor=f"u{i}", host=f"h{i % 7}") for i in range(200)]
        for start in range(0, 200, 25):
            rule.consume(first[start:start + 25])
        assert rule.folds.on_disk > 0
        [again] = rule.consume([refused(500, actor="u0", host="h0")])
        assert again.aggregate_summary["count"] == 2
    finally:
        rule.close_spill()


def test_success_rule_holds_spilled_refusals():
    rule = SmallSuccess()
    try:
        refusals = [refused(i, actor=f"u{i}") for i in range(120)]
        for start in range(0, 120, 20):
            assert rule.consume(refusals[start:start + 20]) == []
        assert rule.refusals.on_disk > 0
        found = []
        for start in range(0, 120, 20):
            found += rule.consume([allowed(600 + i, actor=f"u{i}") for i in range(start, start + 20)])
        assert len(found) == 120 and all(m.proposed_lane == "high" for m in found)
    finally:
        rule.close_spill()
