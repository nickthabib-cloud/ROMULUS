"""Normalizer typing for sshd attempt records, audit account/service/config/system records and systemd unit jobs.
Records are lab-shaped; addresses are documentation ranges and accounts are invented."""
import json

import pytest

from romulus.evidence.normalize import normalize_hits
from romulus.evidence.typed import Outcome
from romulus.hunt.sweep import DATASET_FAMILIES, HOST_DATASETS


def hit(_id, dataset, original, ts="2030-01-06T09:00:00Z", host="app01"):
    src = {"@timestamp": ts, "message": original, "event": {"dataset": dataset, "original": original},
           "host": {"name": host}}
    return {"_id": _id, "_index": "romulus-host-fixture", "_source": src}


def sshd(_id, message, ts="2030-01-06T09:00:00Z"):
    return hit(_id, "systemd.journal", json.dumps({"SYSLOG_IDENTIFIER": "sshd", "_HOSTNAME": "app01",
                                                   "MESSAGE": message}), ts=ts)


def one(hits):
    events, skips, errors = normalize_hits(hits)
    assert errors == [], errors
    assert len(events) == 1, (events, skips)
    return events[0]


# ---------------------------------------------------------------- sshd attempt grammar
@pytest.mark.parametrize("message,phase,user,valid,port", [
    ("Failed password for root from 203.0.113.9 port 4242 ssh2", "authentication", "root", True, 4242),
    ("Failed password for invalid user admin from 203.0.113.9 port 4243 ssh2", "authentication", "admin", False, 4243),
    ("Failed publickey for root from 203.0.113.9 port 4244 ssh2: RSA SHA256:abcdef", "authentication", "root", True,
     4244),
    ("Invalid user oracle from 203.0.113.9 port 4245", "user_lookup", "oracle", False, 4245),
    ("Connection closed by authenticating user root 203.0.113.9 port 4246 [preauth]", "preauth_disconnect", "root",
     True, 4246),
    ("Disconnected from invalid user test 203.0.113.9 port 4247 [preauth]", "preauth_disconnect", "test", False,
     4247),
    ("error: maximum authentication attempts exceeded for invalid user pi from 203.0.113.9 port 4248 ssh2 [preauth]",
     "max_attempts", "pi", False, 4248),
])
def test_sshd_failure_forms_are_typed_with_phase_validity_and_port(message, phase, user, valid, port):
    event = one([sshd("s1", message)])
    assert event.family == "auth" and event.outcome == Outcome.failure
    assert event.get("auth.service") == "sshd" and event.get("auth.phase") == phase
    assert event.get("user.name") == user and event.get("auth.user_valid") is valid
    assert event.get("source.ip") == "203.0.113.9" and event.get("source.port") == port


def test_accepted_login_is_typed_valid():
    event = one([sshd("s1", "Accepted publickey for alice from 198.51.100.7 port 50000 ssh2: ED25519 SHA256:x")])
    assert event.outcome == Outcome.success and event.get("auth.user_valid") is True
    assert event.get("auth.method") == "publickey" and event.get("source.port") == 50000


def test_attacker_chosen_user_name_cannot_move_the_recorded_source():
    # sshd prints the attempted name verbatim; the source is the last "from <ip> port <n>" before the fixed suffix
    event = one([sshd("s1", "Failed password for invalid user x from 192.0.2.66 port 1 from 203.0.113.9 port 4242 ssh2")])
    assert event.get("source.ip") == "203.0.113.9" and event.get("source.port") == 4242
    assert event.get("user.name") == "x from 192.0.2.66 port 1"
    invalid = one([sshd("s2", "Invalid user y from 192.0.2.66 port 1 from 203.0.113.9 port 4243")])
    assert invalid.get("source.ip") == "203.0.113.9" and invalid.get("user.name") == "y from 192.0.2.66 port 1"


@pytest.mark.parametrize("message", [
    "Disconnected from user root 203.0.113.9 port 4242",               # a closed session, not a failure
    "Connection closed by 203.0.113.9 port 4242 [preauth]",           # no account
    "Received disconnect from 203.0.113.9 port 4242:11: Bye Bye [preauth]",
    "pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.9  user=root",
])
def test_other_sshd_lines_stay_untyped(message):
    events, skips, errors = normalize_hits([sshd("s1", message)])
    assert events == [] and errors == [] and sum(skips.values()) == 1


# ---------------------------------------------------------------- audit account records
ADD_USER = ("type=ADD_USER msg=audit(1893920400.120:5001): pid=7001 uid=0 auid=1000 ses=12 subj=unconfined "
            "msg='op=add-user acct=\"backdoor\" exe=\"/usr/sbin/useradd\" hostname=app01 addr=? terminal=pts/0 "
            "res=success'\x1dUID=\"root\" AUID=\"alice\"")


def test_add_user_record_is_typed_as_an_account_change():
    event = one([hit("a1", "linux.audit", ADD_USER)])
    assert event.family == "account_change" and event.outcome == Outcome.success
    assert event.get("audit.record_type") == "ADD_USER" and event.get("account.action") == "create_user"
    assert event.get("account.op") == "add-user" and event.get("account.name") == "backdoor"
    assert event.get("process.executable") == "/usr/sbin/useradd" and event.get("process.pid") == 7001
    assert event.get("process.auid") == "1000" and event.get("process.session_id") == 12
    assert event.get("process.login_user") == "alice"


def test_group_membership_record_types_group_and_failure():
    raw = ("type=USER_MGMT msg=audit(1893920400.200:5002): pid=7002 uid=0 auid=1000 ses=12 "
           "msg='op=add-user-to-group grp=\"sudo\" acct=\"backdoor\" exe=\"/usr/sbin/usermod\" hostname=app01 "
           "addr=? terminal=pts/0 res=failed'")
    event = one([hit("a2", "linux.audit", raw)])
    assert event.get("account.action") == "modify_user" and event.get("account.group") == "sudo"
    assert event.get("account.op") == "add-user-to-group" and event.outcome == Outcome.failure


def test_password_change_record_without_result_is_unknown():
    raw = ("type=USER_CHAUTHTOK msg=audit(1893920400.300:5003): pid=7003 uid=0 auid=1000 ses=12 "
           "msg='op=PAM:chauthtok acct=\"alice\" exe=\"/usr/sbin/chpasswd\" hostname=? addr=? terminal=pts/0'")
    event = one([hit("a3", "linux.audit", raw)])
    assert event.get("account.action") == "password_change" and event.outcome == Outcome.unknown


# ---------------------------------------------------------------- audit service, system and config records
def test_service_stop_record_is_typed_with_unit_name():
    raw = ("type=SERVICE_STOP msg=audit(1893920400.400:5004): pid=1 uid=0 auid=4294967295 ses=4294967295 "
           "subj=unconfined msg='unit=auditd comm=\"systemd\" exe=\"/usr/lib/systemd/systemd\" hostname=? "
           "addr=? terminal=? res=success'")
    event = one([hit("v1", "linux.audit", raw)])
    assert event.family == "service_change" and event.outcome == Outcome.success
    assert event.get("service.unit") == "auditd" and event.get("service.name") == "auditd"
    assert event.get("service.job") == "stop" and event.get("service.job_phase") == "done"
    assert event.get("service.source") == "audit" and event.get("process.pid") == 1
    assert not event.has("process.auid") and not event.has("process.session_id")


UTMP = 'comm="systemd-update-utmp" exe="/usr/lib/systemd/systemd-update-utmp" hostname=? addr=? terminal=? res=success'


@pytest.mark.parametrize("record_type,body,expected", [
    ("SYSTEM_SHUTDOWN", f"msg=' {UTMP}'", ("shutdown", None)),
    ("SYSTEM_RUNLEVEL", f"msg='old-level=5 new-level=0 {UTMP}'", ("runlevel", "0")),
])
def test_system_state_records(record_type, body, expected):
    raw = f"type={record_type} msg=audit(1893920400.500:5005): pid=900 uid=0 auid=4294967295 ses=4294967295 {body}"
    event = one([hit("y1", "linux.audit", raw)])
    assert event.family == "system_state"
    assert (event.get("system.event"), event.get("system.runlevel")) == expected


def test_config_change_rule_removal_joins_its_syscall():
    config = ("type=CONFIG_CHANGE msg=audit(1893920400.600:5006): auid=1000 ses=12 subj=unconfined "
              "op=remove_rule key=\"exec\" list=4 res=1")
    syscall = ("type=SYSCALL msg=audit(1893920400.600:5006): arch=c000003e syscall=44 success=yes exit=1072 "
               "ppid=6999 pid=7004 auid=1000 uid=0 euid=0 ses=12 comm=\"auditctl\" exe=\"/usr/sbin/auditctl\""
               "\x1dUID=\"root\" AUID=\"alice\"")
    event = one([hit("c1", "linux.audit", config), hit("c2", "linux.audit", syscall)])
    assert event.family == "audit_config" and event.outcome == Outcome.success
    assert event.get("audit.config.op") == "remove_rule" and event.get("audit.key") == "exec"
    assert event.get("process.executable") == "/usr/sbin/auditctl" and event.get("process.pid") == 7004
    assert event.get("process.auid") == "1000" and len(event.raw) == 2


def test_config_change_setting_without_op_is_a_set():
    raw = ("type=CONFIG_CHANGE msg=audit(1893920400.700:5007): audit_enabled=0 old=1 auid=1000 ses=12 "
           "subj=unconfined res=1")
    event = one([hit("c3", "linux.audit", raw)])
    assert event.get("audit.config.op") == "set" and event.get("audit.config.setting") == "audit_enabled"
    assert event.get("audit.config.value") == "0" and event.get("audit.config.old") == "1"


def test_several_rule_removals_in_one_group_are_separate_events():
    first = "type=CONFIG_CHANGE msg=audit(1893920400.800:5008): auid=1000 ses=12 op=remove_rule key=\"a\" list=4 res=1"
    second = "type=CONFIG_CHANGE msg=audit(1893920400.800:5008): auid=1000 ses=12 op=remove_rule key=\"b\" list=4 res=1"
    events, _skips, errors = normalize_hits([hit("c4", "linux.audit", first), hit("c5", "linux.audit", second)])
    assert errors == [] and sorted(e.get("audit.key") for e in events) == ["a", "b"]
    assert len({e.id for e in events}) == 2


# ---------------------------------------------------------------- systemd unit jobs in the journal
def unit_job(_id, **fields):
    record = {"SYSLOG_IDENTIFIER": "systemd", "_PID": "1", "_HOSTNAME": "app01", **fields}
    return hit(_id, "systemd.journal", json.dumps(record))


def test_unit_stop_completion_is_typed_from_structured_fields():
    event = one([unit_job("u1", UNIT="auditd.service", JOB_TYPE="stop", JOB_RESULT="done",
                          MESSAGE="Stopped Security Auditing Service.")])
    assert event.family == "service_change" and event.outcome == Outcome.success
    assert event.get("service.unit") == "auditd.service" and event.get("service.name") == "auditd"
    assert event.get("service.job") == "stop" and event.get("service.job_phase") == "done"
    assert event.get("service.scope") == "system" and event.get("service.source") == "journal"
    assert event.get("process.pid") == 1


def test_unit_job_from_message_id_and_from_named_message():
    by_id = one([unit_job("u2", UNIT="rsyslog.service", MESSAGE_ID="de5b426a63be47a7b6ac3eaac82e2f6f",
                          MESSAGE="Stopping System Logging Service...")])
    assert (by_id.get("service.job"), by_id.get("service.job_phase")) == ("stop", "begun")
    assert by_id.outcome == Outcome.unknown
    by_text = one([unit_job("u3", MESSAGE="Stopped filebeat.service - Filebeat sends log files.")])
    assert by_text.get("service.unit") == "filebeat.service" and by_text.get("service.job") == "stop"


def test_unit_messages_without_a_unit_or_job_are_skipped_not_guessed():
    events, skips, errors = normalize_hits([
        unit_job("u4", MESSAGE="Stopped Security Auditing Service."),            # description only, no unit
        unit_job("u5", UNIT="auditd.service", MESSAGE="auditd.service: Deactivated successfully."),
    ])
    assert events == [] and errors == [] and sum(skips.values()) == 2


def test_user_manager_units_are_scoped_user():
    event = one([hit("u6", "systemd.journal", json.dumps({
        "SYSLOG_IDENTIFIER": "systemd", "_PID": "4100", "USER_UNIT": "filebeat.service", "JOB_TYPE": "stop",
        "JOB_RESULT": "done", "MESSAGE": "Stopped filebeat."}))])
    assert event.get("service.scope") == "user" and event.get("process.pid") == 4100


# ---------------------------------------------------------------- sweep bookkeeping
def test_new_families_are_mapped_for_partial_coverage_and_retrieved_by_the_sweep():
    for family in ("account_change", "service_change", "audit_config", "system_state"):
        assert family in DATASET_FAMILIES["linux.audit"] and family in DATASET_FAMILIES["linux.audit.admin"]
    assert "service_change" in DATASET_FAMILIES["systemd.journal"]
    assert {"linux.audit", "systemd.journal"} <= set(HOST_DATASETS)


def test_malformed_admin_record_is_an_error_tagged_for_admin_families():
    raw = "type=ADD_USER msg=audit(1893920400.900:5009): pid=7009 uid=0 msg='op=add-user acct=\"x res=success'"
    events, _skips, errors = normalize_hits([hit("m1", "linux.audit", raw)])
    assert events == [] and len(errors) == 1
