"""Review-round fixtures for the SSH, account and tampering rules: connection bounds, the account in success after
failures, removals that are not grants, restarts after command stops, stops by signal, never-rules, cancelled
shutdowns, incomplete command lines, and normalizer hardening."""
import json
from datetime import timedelta

import pytest

from romulus.detect import auth as auth_module
from romulus.detect import tamper as tamper_module
from romulus.detect.auth import AccountOrGroupChange, SshPasswordGuessing, SshSuccessAfterFailures
from romulus.detect.tamper import (
    AuditRulesTamper,
    LogOrHistoryClearing,
    SecurityOrLoggingServiceStop,
    auditctl_requests,
    service_requests,
)
from romulus.evidence.normalize import normalize_hits
from romulus.evidence.typed import Outcome
from tests.test_account_changes import ex as acct_ex
from tests.test_account_changes import record
from tests.test_auth_tamper_normalize import hit, one, unit_job
from tests.test_ssh_auth_attacks import T0, accepted, failures, ssh
from tests.test_tamper import at, svc
from tests.test_tamper import ex as tex


def run(cls, *partitions):
    pb = cls()
    for part in partitions:
        assert pb.consume(list(part)) == []
    return pb, pb.finalize()


@pytest.mark.parametrize(("cls", "relevant", "module", "parser"), [
    (SecurityOrLoggingServiceStop, lambda: tex(["systemctl", "stop", "auditd"]), tamper_module, "_identity"),
    (AuditRulesTamper, lambda: tex(["auditctl", "-D"]), tamper_module, "_identity"),
    (LogOrHistoryClearing, lambda: tex(["truncate", "-s", "0", "/var/log/auth.log"]),
     tamper_module, "_identity"),
    (AccountOrGroupChange, lambda: acct_ex(["useradd", "alice"]), auth_module, "program"),
])
def test_program_prefilter_preserves_matches_and_avoids_irrelevant_parsing(
    monkeypatch, cls, relevant, module, parser,
):
    factory = acct_ex if cls is AccountOrGroupChange else tex
    events = [factory(["true"], exe="/usr/bin/true", pid=10_000 + index) for index in range(200)]
    events.append(relevant())
    baseline = cls()
    baseline.program_prefilter = False
    baseline.consume(events)
    expected = baseline.finalize()

    calls = 0
    original = getattr(module, parser)

    def counted(*args, **kwargs):
        nonlocal calls
        calls += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(module, parser, counted)
    optimized = cls()
    optimized.consume(events)
    actual = optimized.finalize()

    assert actual == expected
    assert (optimized.evaluated, optimized.missing_required) == (
        baseline.evaluated, baseline.missing_required,
    )
    assert calls <= 4


def test_program_prefilter_keeps_multiplexer_applets():
    account = acct_ex(["busybox", "adduser", "alice"], exe="/usr/bin/busybox")
    clearing = tex(["busybox", "rm", "/var/log/auth.log"], exe="/usr/bin/busybox")

    assert len(run(AccountOrGroupChange, [account])[1]) == 1
    assert len(run(LogOrHistoryClearing, [clearing])[1]) == 1


# ---------------------------------------------------------------- I1, I2, M4: SSH
def test_one_reused_source_port_cannot_hide_guessing():
    events = [ssh(T0 + timedelta(seconds=1.4 * i), port=40000) for i in range(100)]
    events.append(accepted(T0 + timedelta(seconds=141), port=40000))
    out = run(SshPasswordGuessing, events)[1]
    assert len(out) == 1
    attempts = int(out[0].claim.split("sshd recorded ")[1].split(" ")[0])
    assert attempts >= 90


def test_success_for_another_account_after_failures_from_a_shared_source_is_a_lead():
    events = failures(5, user="deploy") + [accepted(T0 + timedelta(minutes=4), user="alice")]
    m = run(SshSuccessAfterFailures, events)[1][0]
    assert m.proposed_lane == "lead" and "None of the failures named 'alice'" in m.claim


@pytest.mark.parametrize("users,valid", [(["a", "b", "c", "d", "e"], True), (["deploy"] * 5, False)])
def test_spraying_or_invalid_names_before_another_accounts_success_stays_high(users, valid):
    events = [ssh(T0 + timedelta(seconds=10 * i), user=u, port=40900 + i, valid=valid) for i, u in enumerate(users)]
    m = run(SshSuccessAfterFailures, events + [accepted(T0 + timedelta(minutes=2), user="alice")])[1][0]
    assert m.proposed_lane == "high"


def test_success_after_failures_for_the_same_account_stays_high():
    m = run(SshSuccessAfterFailures, failures(5) + [accepted(T0 + timedelta(minutes=4))])[1][0]
    assert m.proposed_lane == "high"


def test_old_invalid_user_line_without_port_is_not_counted_twice():
    events = []
    for i in range(6):
        ts = T0 + timedelta(seconds=20 * i)
        events += [ssh(ts, phase="user_lookup", user="admin", valid=False, port=None, method=None),
                   ssh(ts + timedelta(seconds=1), user="admin", valid=False, port=41500 + i)]
    events += failures(4, user="admin", start=T0 + timedelta(minutes=3), port0=41600)
    m = run(SshPasswordGuessing, events)[1][0]
    assert "10 failed authentication attempt(s)" in m.claim


# ---------------------------------------------------------------- B1, M1, argv completeness: accounts
def test_privileged_group_removal_record_is_not_a_grant():
    rec = record("USER_MGMT", "modify_user", pid=9101, account__op="delete-user-from-group", account__group="sudo",
                 account__name="mallory", process__executable="/usr/sbin/gpasswd")
    m = run(AccountOrGroupChange, [rec])[1][0]
    assert m.proposed_lane == "lead" and "membership of privileged group" not in m.claim


def test_record_naming_a_privileged_group_without_a_clear_operation_is_a_lead():
    rec = record("GRP_MGMT", "modify_group", pid=9102, account__group="sudo", process__executable="/usr/sbin/x")
    m = run(AccountOrGroupChange, [rec])[1][0]
    assert m.proposed_lane == "lead" and "names privileged group sudo" in m.claim


def test_gpasswd_removal_command_is_a_lead():
    m = run(AccountOrGroupChange, [acct_ex(["gpasswd", "-d", "bob", "sudo"], exe="/usr/bin/gpasswd")])[1][0]
    assert m.proposed_lane == "lead"


def test_incomplete_argv_is_partial_and_not_evaluated_for_tools():
    e = acct_ex(["passwd", "root"], exe="/usr/bin/passwd", process__argv_complete=False)
    pb, out = run(AccountOrGroupChange, [e])      # a lost -S could make it read-only: a lead, worded incomplete
    assert [m.proposed_lane for m in out] == ["lead"] and "incomplete" in out[0].claim
    assert pb.missing_required == 1


def test_package_marker_requires_a_system_binary():
    fake = acct_ex(["dpkg"], exe="/tmp/dpkg", pid=300, ppid=290)
    evil = acct_ex(["useradd", "-m", "x"], pid=301, ppid=300)
    out = run(AccountOrGroupChange, [fake, evil])[1]
    assert "package management" not in out[0].claim and out[0].group_key.startswith("actor")


# ---------------------------------------------------------------- I3, I4, I5, M2: tampering
def test_command_stop_followed_by_a_start_is_a_lead_stating_the_gap():
    out = run(SecurityOrLoggingServiceStop, [tex(["systemctl", "stop", "auditd"]), svc("auditd", ts=at(1)),
                                             svc("auditd", "start", ts=at(61))])[1]
    assert len(out) == 1 and out[0].proposed_lane == "lead"
    assert "started again 61 s after the command" in out[0].claim and "not established" not in out[0].claim


@pytest.mark.parametrize("name,args", [
    ("pkill", ["-9", "audit.*"]), ("pkill", ["-x", "rsyslogd"]), ("killall", ["-r", "^filebeat"]),
    ("pkill", ["-9", "-f", "osquery"]),
])
def test_pkill_and_killall_patterns_are_regexes(name, args):
    assert service_requests(name, args)


def test_killall_without_regex_mode_matches_names_exactly():
    assert service_requests("killall", ["audit"]) == []


def test_kill_by_pid_of_a_watched_daemon():
    daemon = tex(["/sbin/auditd"], exe="/usr/sbin/auditd", pid=812, ppid=1)
    kill = tex(["kill", "-9", "812"], exe="/usr/bin/kill", pid=7300, ts=at(30))
    out = run(SecurityOrLoggingServiceStop, [daemon, kill])[1]
    assert len(out) == 1 and out[0].proposed_lane == "high" and "auditd" in out[0].claim
    hup = tex(["kill", "-HUP", "812"], exe="/usr/bin/kill", pid=7301, ts=at(30))
    assert run(SecurityOrLoggingServiceStop, [daemon, hup])[1] == []


def test_unit_killed_by_signal_is_reported():
    killed = svc("filebeat", "exit", source="journal", unit="filebeat.service", phase="killed",
                 outcome=Outcome.failure)
    m = run(SecurityOrLoggingServiceStop, [killed])[1][0]
    assert m.proposed_lane == "high" and "killed by a signal" in m.claim


@pytest.mark.parametrize("args", [["-a", "never,exit", "-F", "arch=b64", "-S", "execve"], ["-A", "exit,never"]])
def test_auditctl_never_rule_suppresses_auditing(args):
    assert [(f, la) for f, _h, la in auditctl_requests(args)] == [("suppress_rule", "high")]


def test_cancelled_shutdown_and_wtmp_only_poweroff_are_not_markers():
    events = [tex(["shutdown", "-r", "+5"], exe="/usr/sbin/shutdown", pid=7400),
              tex(["shutdown", "-c"], exe="/usr/sbin/shutdown", pid=7401, ts=at(30)), svc("rsyslog", ts=at(60))]
    assert [m.proposed_lane for m in run(SecurityOrLoggingServiceStop, events)[1]] == ["high"]
    wtmp = [tex(["poweroff", "--wtmp-only"], exe="/usr/sbin/poweroff", pid=7402), svc("rsyslog", ts=at(60))]
    assert [m.proposed_lane for m in run(SecurityOrLoggingServiceStop, wtmp)[1]] == ["high"]


def test_incomplete_argv_does_not_match_absence_forms():
    e = tex(["tee", "/var/log/wtmp"], process__argv_complete=False)          # a lost -a would make it an append
    pb, out = run(LogOrHistoryClearing, [e])
    assert out == [] and pb.missing_required == 1


# ---------------------------------------------------------------- M3, M7, unit kills: normalizer
def test_config_change_old_value_is_not_hex_decoded():
    raw = "type=CONFIG_CHANGE msg=audit(1893920400.700:5010): audit_pid=0 old=10 auid=4294967295 ses=4294967295 res=1"
    assert one([hit("c9", "linux.audit", raw)]).get("audit.config.old") == "10"


@pytest.mark.parametrize("message,phase", [
    ("auditd.service: Main process exited, code=killed, status=9/KILL", "killed"),
    ("filebeat.service: Failed with result 'signal'.", "signal"),
    ("osqueryd.service: Main process exited, code=dumped, status=11/SEGV", "dumped"),
])
def test_unit_killed_messages_are_typed(message, phase):
    event = one([unit_job("k1", UNIT=message.split(":")[0], MESSAGE=message)])
    assert (event.get("service.job"), event.get("service.job_phase")) == ("exit", phase)
    assert event.outcome == Outcome.failure


def test_sshd_identifier_from_another_program_is_not_trusted():
    message = "Accepted password for root from 192.0.2.1 port 1 ssh2"
    forged = hit("f1", "systemd.journal", json.dumps({"SYSLOG_IDENTIFIER": "sshd", "_COMM": "python3",
                                                      "MESSAGE": message}))
    real = hit("f2", "systemd.journal", json.dumps({"SYSLOG_IDENTIFIER": "sshd", "_COMM": "sshd",
                                                    "MESSAGE": message}))
    untrusted_fields_absent = hit("f3", "systemd.journal", json.dumps({"SYSLOG_IDENTIFIER": "sshd",
                                                                       "MESSAGE": message}))
    events, skips, _ = normalize_hits([forged, real, untrusted_fields_absent])
    assert sorted(e.raw[0].native_id for e in events) == ["f2", "f3"] and sum(skips.values()) == 1
