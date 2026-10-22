"""A partial pkill pattern confirmed by the service manager's stop record, alias names of a confirmed daemon, and
multi-unit daemon names."""
from romulus.detect.tamper import SecurityOrLoggingServiceStop, units_of
from tests.test_tamper import at, svc
from tests.test_tamper import ex as tex


def run(events):
    pb = SecurityOrLoggingServiceStop()
    assert pb.consume(list(events)) == []
    return pb.finalize()


def test_stop_record_after_a_partial_pattern_confirms_it():
    out = run([tex(["pkill", "audit"], exe="/usr/bin/pkill"), svc("auditd", ts=at(2))])
    high = [m for m in out if m.proposed_lane == "high"]
    assert len(high) == 1 and "'auditd'" in high[0].claim and "recorded 'auditd' stopping" in high[0].claim
    assert all("auditd" not in m.claim.split("could match")[-1] for m in out if m.proposed_lane == "lead")


def test_stop_record_outside_the_link_window_does_not_confirm():
    out = run([tex(["pkill", "audit"], exe="/usr/bin/pkill"), svc("auditd", ts=at(121))])
    pattern = [m for m in out if m.group_key.startswith("cmd|")]
    assert [m.proposed_lane for m in pattern] == ["lead"]


def test_unconfirmed_lead_says_a_pre_window_daemon_cannot_be_confirmed():
    m = run([tex(["pkill", "agent"], exe="/usr/bin/pkill")])[0]
    assert m.proposed_lane == "lead" and "started before the window" in m.claim


def test_alias_names_of_a_confirmed_daemon_leave_no_misleading_lead():
    daemon = tex(["/usr/sbin/rsyslogd", "-n"], exe="/usr/sbin/rsyslogd", pid=600, ppid=1, ts=at(-30))
    out = run([daemon, tex(["pkill", "rsyslog"], exe="/usr/bin/pkill", pid=7700)])
    assert [m.proposed_lane for m in out] == ["high"]


def test_multi_unit_daemon_names():
    assert set(units_of("ossec-agentd")) == {"wazuh-agent", "ossec-hids", "ossec"}
    assert set(units_of("splunkd")) == {"splunkforwarder", "splunkd"}
    assert units_of("rsyslogd") == ("rsyslog",)
