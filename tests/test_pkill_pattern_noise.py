"""pkill/killall patterns that only partly match watched daemon names, process-name to unit mapping, and account
commands whose argv was truncated."""

from romulus.detect.auth import AccountOrGroupChange
from romulus.detect.tamper import SecurityOrLoggingServiceStop
from tests.test_account_changes import ex as acct_ex
from tests.test_tamper import at, svc
from tests.test_tamper import ex as tex


def run(cls, *partitions):
    pb = cls()
    for part in partitions:
        assert pb.consume(list(part)) == []
    return pb, pb.finalize()


def test_partial_pattern_without_a_running_match_is_one_lead():
    out = run(SecurityOrLoggingServiceStop, [tex(["pkill", "agent"], exe="/usr/bin/pkill")])[1]
    assert len(out) == 1 and out[0].proposed_lane == "lead"
    assert "pattern 'agent'" in out[0].claim and "'elastic-agent'" in out[0].claim


def test_very_broad_pattern_is_still_one_lead():
    out = run(SecurityOrLoggingServiceStop, [tex(["pkill", "-9", "d"], exe="/usr/bin/pkill")])[1]
    assert [m.proposed_lane for m in out] == ["lead"]


def test_partial_pattern_confirmed_by_an_exec_record_is_high_for_that_daemon_only():
    daemon = tex(["/usr/bin/elastic-agent", "run"], exe="/usr/bin/elastic-agent", pid=900, ppid=1, ts=at(-60))
    out = run(SecurityOrLoggingServiceStop, [daemon, tex(["pkill", "agent"], exe="/usr/bin/pkill", pid=7500)])[1]
    lanes = sorted((m.proposed_lane, "elastic-agent" in m.claim) for m in out)
    assert ("high", True) in lanes and all(lane == "lead" for lane, named in lanes if not named)


def test_exact_and_whole_patterns_stay_high():
    for argv in (["pkill", "auditd"], ["pkill", "-x", "rsyslogd"], ["pkill", "^filebeat$"], ["killall", "osqueryd"]):
        out = run(SecurityOrLoggingServiceStop, [tex(argv, exe=f"/usr/bin/{argv[0]}")])[1]
        assert [m.proposed_lane for m in out] == ["high"], argv


def test_process_name_maps_to_its_unit_for_restart_and_records():
    out = run(SecurityOrLoggingServiceStop, [tex(["pkill", "rsyslogd"], exe="/usr/bin/pkill"),
                                             svc("rsyslog", ts=at(1)), svc("rsyslog", "start", ts=at(31))])[1]
    assert len(out) == 1 and out[0].proposed_lane == "lead" and "started again 31 s" in out[0].claim


def test_truncated_account_command_is_a_lead_worded_as_incomplete():
    e = acct_ex(["useradd", "-o", "-u", "0", "backdoor"], process__argv_complete=False)
    pb, out = run(AccountOrGroupChange, [e])
    assert len(out) == 1 and out[0].proposed_lane == "lead" and pb.missing_required == 1
    assert "incomplete" in out[0].claim and "user id 0" in out[0].claim


def test_truncated_read_only_prefix_still_yields_nothing():
    e = acct_ex(["chage", "-l"], exe="/usr/bin/chage", process__argv_complete=False)
    assert run(AccountOrGroupChange, [e])[1] == []


def test_partial_pattern_lead_is_deterministic():
    events = [tex(["pkill", "agent"], exe="/usr/bin/pkill", pid=7600 + i, ts=at(i)) for i in range(3)]
    a = [(m.group_key, m.claim) for m in run(SecurityOrLoggingServiceStop, events)[1]]
    b = [(m.group_key, m.claim) for m in run(SecurityOrLoggingServiceStop, list(reversed(events)))[1]]
    assert a == b and len(a) == 1
