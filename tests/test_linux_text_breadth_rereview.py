"""Second review round: broker success by account class, order-independent refusal joins, forged refusals, and the
joining of split sudo records. Sources as in tests/test_linux_text_breadth_review.py. Hosts and accounts are invented."""
from __future__ import annotations

import json

import pytest

from romulus.detect.privilege_brokers import PrivilegeBrokerRefusal, PrivilegeBrokerSuspiciousSuccess
from romulus.evidence.linux_service_text import parse_service
from romulus.evidence.normalize import normalize_hits
from romulus.evidence.typed import Outcome
from tests.test_linux_text_breadth import doc, one
from tests.test_linux_text_breadth_review import (
    LONG_PWD,
    T0,
    allowed,
    journal_doc,
    refused,
    run,
    split_sudo,
    sudo_line,
)


def app_sudo(seconds, actor, command, tty="unknown", host="app01"):
    return sudo_line(seconds, f"{actor} : TTY={tty} ; PWD=/ ; USER=root ; COMMAND={command}",
                     nid=f"app{seconds}{actor}{host}{tty}", host=host)


# ---------------------------------------------------------------------------------------------- B1: account classes
def test_routine_monitoring_sudo_is_one_folded_lead():
    checks = [app_sudo(300 * n, "nagios", "/usr/lib/nagios/plugins/check_raid -w 80") for n in range(12)]
    _rule, matches = run(PrivilegeBrokerSuspiciousSuccess, checks)
    assert {m.proposed_lane for m in matches} == {"lead"} and len({m.group_key for m in matches}) == 1
    assert matches[-1].aggregate_summary["count"] == 12
    assert "scheduled job's NOPASSWD sudo command" in matches[-1].claim


@pytest.mark.parametrize("actor,command,tty,why", [
    ("nagios", "/bin/bash", "pts/2", "it ran from terminal pts/2"),
    ("zabbix", "/usr/bin/python3 -c x", "unknown", "a shell, interpreter or account switch"),
    ("jenkins", "/bin/su - root", "unknown", "a shell, interpreter or account switch"),
    ("postgres", "/usr/bin/id", "pts/1", "it ran from terminal pts/1"),
])
def test_application_account_success_with_what_a_job_never_shows_is_high(actor, command, tty, why):
    _rule, [match] = run(PrivilegeBrokerSuspiciousSuccess, [app_sudo(0, actor, command, tty)])
    assert match.proposed_lane == "high" and why in match.claim


def test_application_account_su_and_refusal_first_are_high():
    su = normalize_hits([journal_doc({"MESSAGE": "(to root) jenkins on none", "SYSLOG_IDENTIFIER": "su",
                                      "_COMM": "su", "_PID": "8"}, "su1")])[0][0]
    _rule, [match] = run(PrivilegeBrokerSuspiciousSuccess, [su])
    assert match.proposed_lane == "high" and "used su to become the account" in match.claim
    routine = app_sudo(60, "mysql", "/usr/bin/mysqladmin status")
    _rule, [match] = run(PrivilegeBrokerSuspiciousSuccess,
                         [refused(0, "1 incorrect password attempt", "mysql"), routine])
    assert match.proposed_lane == "high" and "refusals came first" in match.claim


@pytest.mark.parametrize("actor", ["nobody", "daemon", "systemd-network", "www-data"])
def test_web_and_never_broker_accounts_are_high(actor):
    _rule, [match] = run(PrivilegeBrokerSuspiciousSuccess, [app_sudo(0, actor, "/usr/bin/id")])
    assert match.proposed_lane == "high"


# ---------------------------------------------------------------------------------------------- B2, I1: ordering
@pytest.mark.parametrize("order", ["refusal-first", "success-first"])
def test_refusal_and_success_in_the_same_second_are_joined_in_one_batch(order):
    refusal, success = refused(0), allowed(0)
    batch = [refusal, success] if order == "refusal-first" else [success, refusal]
    _rule, matches = run(PrivilegeBrokerSuspiciousSuccess, batch)
    assert [m.proposed_lane for m in matches] == ["high"]


@pytest.mark.parametrize("gap", [0, 90])
def test_a_success_read_before_its_refusals_is_judged_when_they_arrive(gap):
    rule = PrivilegeBrokerSuspiciousSuccess()
    try:
        assert rule.consume([allowed(gap)]) == []               # another target, read first
        [match] = rule.consume([refused(0)])
        assert match.proposed_lane == "high" and "3 counted failed password attempt(s)" in match.claim
        assert rule.consume([refused(1, "user NOT in sudoers", actor="other")]) == []
    finally:
        rule.close_spill()


def test_a_success_is_reported_again_only_when_its_judgment_changes():
    rule = PrivilegeBrokerSuspiciousSuccess()
    try:
        assert len(rule.consume([refused(0, "1 incorrect password attempt"), allowed(60)])) == 1   # a lead
        [raised] = rule.consume([refused(10, "2 incorrect password attempts")])                    # now 3: high
        assert raised.proposed_lane == "high"
        assert rule.consume([refused(20, "1 incorrect password attempt")]) == []                  # still high
    finally:
        rule.close_spill()


def test_match_each_reads_a_refusal_before_a_success_of_the_same_instant():
    refusal, success = refused(0), allowed(0)
    rule = PrivilegeBrokerSuspiciousSuccess()
    try:
        matches = rule.match_each([success, refusal], {success.id, refusal.id})
        assert [m.proposed_lane for m in matches] == ["high"]
    finally:
        rule.close_spill()


# ---------------------------------------------------------------------------------------------- I2: forged refusals
def test_a_forged_refusal_does_not_raise_a_genuine_success():
    forged = sudo_line(0, "mallory : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/sh",
                       comm="logger", nid="forged")
    _rule, [match] = run(PrivilegeBrokerSuspiciousSuccess, [forged, allowed(30)])
    assert match.proposed_lane == "lead"
    assert "journald shows another program wrote; they are not counted toward the lane" in match.claim


def test_an_unverified_refusal_is_named_in_the_claim():
    plain = one("raw", "sudo", "mallory : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/ ; USER=root ; "
                "COMMAND=/bin/sh", nid="plain")
    plain.ts = T0
    _rule, [match] = run(PrivilegeBrokerSuspiciousSuccess, [plain, allowed(30)])
    assert ("The refusal record(s) are a line logged under the identifier 'sudo' (writer not verifiable from plain "
            "syslog)") in match.claim


# ---------------------------------------------------------------------------------------------- I3: split sudo joins
def test_a_continuation_joins_the_split_success_not_the_same_second_refusal():
    refusal = "mallory : user NOT in sudoers ; TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/ls"
    body = f"TTY=pts/0 ; PWD={LONG_PWD} ; USER=root ; COMMAND=/bin/bash"
    first, rest = body[:body.index("PWD=") - 1], body[body.index("PWD="):]
    lines = [refusal, f"mallory : {first}", f"mallory : (command continued) {rest}"]
    docs = [journal_doc({"MESSAGE": line, "SYSLOG_IDENTIFIER": "sudo", "_COMM": "sudo", "_PID": "4100"}, f"q{n}")
            for n, line in enumerate(lines)]
    events, skips, errors = normalize_hits(docs)
    assert not errors and not skips and len(events) == 2
    refusal_event = next(e for e in events if e.outcome == Outcome.failure)
    success = next(e for e in events if e.outcome == Outcome.success)
    assert refusal_event.get("sudo.command") == "/bin/ls" and len(refusal_event.raw) == 1
    assert success.get("auth.target_user") == "root" and success.get("sudo.command") == "/bin/bash"
    assert len(success.raw) == 2 and not success.has("sudo.chunk")


def test_a_raw_syslog_continuation_is_joined_with_its_writer_caveats():
    body = f"user NOT in sudoers ; TTY=pts/0 ; PWD={LONG_PWD} ; USER=root ; COMMAND=/bin/bash"
    first, rest = body[:body.index("PWD=") - 1], body[body.index("PWD="):]
    docs = [doc("raw", "sudo", f"mallory : {first}", nid="h1"),
            doc("raw", "sudo", f"mallory : (command continued) {rest}", nid="h2")]
    events, skips, errors = normalize_hits(docs)
    assert not errors and not skips
    [event] = events
    assert event.get("auth.target_user") == "root"
    assert any("pid the writer chose" in caveat for caveat in event.caveats)
    assert any("Writer identity" in caveat for caveat in event.caveats)


def test_a_continuation_journald_says_another_program_wrote_is_not_joined():
    docs = split_sudo()
    record = json.loads(docs[2]["_source"]["event"]["original"])
    record["_COMM"] = "logger"
    docs[2]["_source"]["event"]["original"] = json.dumps(record)
    events, skips, _errors = normalize_hits(docs)
    assert any("another program wrote" in reason for reason in skips)
    assert not any(e.get("auth.target_user") == "root" for e in events)


# ---------------------------------------------------------------------------------------------- minors
def test_a_separator_inside_a_refused_directory_is_an_ambiguous_refusal_not_a_split():
    event = one("journal", "sudo", "bob : user not allowed to change directory to /srv/a ; b ; TTY=pts/1 ; PWD=/ ; "
                "USER=root ; COMMAND=/bin/ls")
    assert event.outcome == Outcome.failure and not event.has("sudo.chunk") and not event.has("auth.target_user")
    _rule, [match] = run(PrivilegeBrokerRefusal, [event])
    assert "The record is ambiguous" in match.claim and "split" not in match.claim


def test_pkexec_command_framing_after_a_newline_is_ambiguous():
    event = parse_service("pkexec", "alice: Executing command [USER=root] [TTY=/dev/pts/0] [CWD=/x] "
                          "[COMMAND=/bin/id]\n[COMMAND=/bin/sh]")
    assert "privilege.command" not in event.fields and any("neither is typed" in c for c in event.caveats)
