"""Fixtures for audit and log tampering: service stops, audit rule changes, log and history clearing. Hosts,
accounts and paths are invented; addresses are documentation ranges."""
import json
from datetime import UTC, datetime, timedelta

import pytest

from romulus.detect.registry import ALL_PLAYBOOKS, fresh_pack
from romulus.detect.tamper import (
    AuditRulesTamper,
    LogOrHistoryClearing,
    SecurityOrLoggingServiceStop,
    auditctl_requests,
    log_requests,
    service_requests,
    shell_segments,
)
from romulus.evidence.typed import Outcome, RawRef, TypedEvent, fv

T0 = datetime(2030, 1, 6, 9, 0, tzinfo=UTC)
_n = 0
USERS = {"0": "root", "33": "www-data", "1000": "alice"}


def ev(family, ts=T0, outcome=Outcome.success, host="app01", **fields):
    global _n
    _n += 1
    f = {k.replace("__", "."): fv(v, f"fixture{_n}:{k}") for k, v in fields.items() if v is not None}
    return TypedEvent(id=f"t{_n:05d}", family=family, ts=ts, host=host, outcome=outcome, fields=f,
                      raw=[RawRef(target="fx", native_id=f"r{_n}")], normalizer="fixture")


def ex(argv, exe=None, uid="0", pid=7001, ppid=7000, ts=T0, outcome=Outcome.success, cwd="/root", **kw):
    exe = exe if exe is not None else f"/usr/bin/{argv[0].rsplit('/', 1)[-1]}"
    return ev("process_exec", ts, outcome, process__argv=argv, process__executable=exe or None, process__uid=uid,
              process__user=USERS.get(uid), process__pid=pid, process__ppid=ppid, process__cwd=cwd, **kw)


def svc(name, job="stop", ts=T0, source="audit", phase="done", outcome=Outcome.success, pid=1, scope="system",
        unit=None):
    return ev("service_change", ts, outcome, service__unit=unit or name, service__name=name, service__job=job,
              service__job_phase=phase, service__scope=scope, service__source=source, process__pid=pid)


def cfg(op, ts=T0, setting=None, value=None, old=None, pid=None, auid="1000", ses=12, outcome=Outcome.success,
        key=None):
    return ev("audit_config", ts, outcome, audit__config__op=op, audit__config__setting=setting,
              audit__config__value=value, audit__config__old=old, process__pid=pid, process__auid=auid,
              process__session_id=ses, audit__key=key)


def run(cls, *partitions):
    pb = cls()
    for part in partitions:
        assert pb.consume(list(part)) == []
    return pb, pb.finalize()


def at(seconds):
    return T0 + timedelta(seconds=seconds)


# ================================================================ service stops
@pytest.mark.parametrize("name,args,expected", [
    ("systemctl", ["stop", "auditd"], ("stop", "auditd")),
    ("systemctl", ["--no-block", "stop", "auditd.service"], ("stop", "auditd")),
    ("systemctl", ["disable", "--now", "rsyslog"], ("disable --now", "rsyslog")),
    ("systemctl", ["mask", "systemd-journald.service"], ("mask", "systemd-journald")),
    ("systemctl", ["kill", "-s", "KILL", "falco-modern-bpf"], ("kill", "falco-modern-bpf")),
    ("systemctl", ["kill", "--signal=SIGTERM", "osqueryd"], ("kill", "osqueryd")),
    ("service", ["auditd", "stop"], ("stop", "auditd")),
    ("invoke-rc.d", ["filebeat", "stop"], ("stop", "filebeat")),
    ("update-rc.d", ["rsyslog", "disable"], ("disable", "rsyslog")),
    ("chkconfig", ["auditd", "off"], ("disable", "auditd")),
    ("pkill", ["-9", "auditd"], ("kill", "auditd")),
    ("killall", ["-s", "TERM", "rsyslogd"], ("kill", "rsyslogd")),
    ("pkill", ["-f", "^filebeat$"], ("kill", "filebeat")),
    ("pkill", ["-f", "/usr/share/filebeat/bin/filebeat -c /etc/filebeat.yml"], ("kill", "filebeat")),
    ("sh", ["/etc/init.d/auditd", "stop"], ("stop", "auditd")),
])
def test_stop_request_grammar(name, args, expected):
    assert [(verb, unit) for verb, unit, _how in service_requests(name, args)] == [expected]


@pytest.mark.parametrize("name,args", [
    ("systemctl", ["status", "auditd"]), ("systemctl", ["restart", "auditd"]), ("systemctl", ["start", "auditd"]),
    ("systemctl", ["kill", "-s", "HUP", "rsyslog.service"]), ("systemctl", ["kill", "--signal=SIGUSR1", "rsyslog"]),
    ("pkill", ["-HUP", "rsyslogd"]), ("killall", ["-0", "auditd"]), ("systemctl", ["stop", "nginx"]),
    ("systemctl", ["--user", "stop", "filebeat"]), ("service", ["--status-all"]),
    ("systemctl", ["stop", "ufw"]), ("deb-systemd-invoke", ["restart", "rsyslog.service"]),
    ("invoke-rc.d", ["rsyslog", "rotate"]), ("pkill", ["-f", "python3 /opt/filebeat-report.py"]),
    ("grep", ["auditd", "/etc/passwd"]), ("systemctl", ["is-active", "auditd"]),
])
def test_non_stop_requests(name, args):
    assert service_requests(name, args) == []


def test_command_with_linked_service_record_is_high_and_restrained():
    cmd = ex(["systemctl", "stop", "auditd"], process__login_user="alice")
    record = svc("auditd", ts=at(1))
    out = run(SecurityOrLoggingServiceStop, [cmd, record])[1]
    assert len(out) == 1
    m = out[0]
    assert (m.proposed_lane, m.severity, m.confidence) == ("high", "high", "high")
    assert "account 'root' ran 1 command(s) to 'systemctl stop auditd' (audit service)" in m.claim
    assert "recorded 'auditd' stopping 1 time(s)" in m.claim and "linked by unit name and time" in m.claim
    assert {e.id for e in m.events} == {cmd.id, record.id} and "T1685.004" in m.notes


def test_command_without_a_record_says_the_stop_is_not_established():
    m = run(SecurityOrLoggingServiceStop, [ex(["service", "rsyslog", "stop"], exe="/usr/sbin/service")])[1][0]
    assert m.proposed_lane == "high" and "whether it stopped is not established" in m.claim


@pytest.mark.parametrize("argv,exe", [
    (["systemctl", "status", "auditd"], None), (["systemctl", "restart", "auditd"], None),
    (["systemctl", "kill", "-s", "HUP", "rsyslog.service"], None), (["pkill", "-HUP", "rsyslogd"], None),
    (["grep", "auditd", "/etc/passwd"], None), (["man", "auditctl"], None),
    (["echo", "systemctl", "stop", "auditd"], None), (["journalctl", "-u", "auditd"], None),
    (["bash", "-c", "grep 'systemctl stop auditd' notes.txt"], "/usr/bin/bash"),
    (["vi", "/etc/systemd/system/auditd.service"], "/usr/bin/vim.basic"),
])
def test_mentions_and_non_stopping_commands_are_not_findings(argv, exe):
    assert run(SecurityOrLoggingServiceStop, [ex(argv, exe=exe)])[1] == []


def test_package_maintainer_stop_during_upgrade_is_a_lead_with_the_record():
    dpkg = ex(["dpkg", "--unpack", "auditd.deb"], exe="/usr/bin/dpkg", pid=100, ppid=90)
    prerm = ex(["/bin/sh", "/var/lib/dpkg/info/auditd.prerm", "upgrade", "1:3.1"], exe="/usr/bin/dash", pid=101,
               ppid=100, ts=at(1))
    stop = ex(["invoke-rc.d", "auditd", "stop"], exe="/usr/sbin/invoke-rc.d", pid=102, ppid=101, ts=at(2))
    out = run(SecurityOrLoggingServiceStop, [dpkg, prerm, stop, svc("auditd", ts=at(3)),
                                             svc("auditd", "start", ts=at(40))])[1]
    assert len(out) == 1
    m = out[0]
    assert m.proposed_lane == "lead" and "package management" in m.claim
    assert "lane lowered: started under package lineage" in m.notes


def test_stop_followed_by_a_reboot_command_is_a_lead_naming_the_marker():
    out = run(SecurityOrLoggingServiceStop, [ex(["systemctl", "stop", "filebeat"]),
                                             ex(["systemctl", "reboot"], pid=7002, ts=at(30))])[1]
    assert len(out) == 1 and out[0].proposed_lane == "lead"
    assert "a 'systemctl reboot' command" in out[0].claim and "30 s after the first command" in out[0].claim


def test_web_service_lineage_stays_high_even_near_a_shutdown():
    shell = ex(["sh", "-c", "sudo systemctl stop auditd"], exe="/usr/bin/dash", uid="33", pid=4000, ppid=3999)
    sudo = ex(["sudo", "systemctl", "stop", "auditd"], exe="/usr/bin/sudo", uid="33", pid=4001, ppid=4000)
    stop = ex(["systemctl", "stop", "auditd"], pid=4002, ppid=4001, ts=at(1))
    out = run(SecurityOrLoggingServiceStop, [shell, sudo, stop, ex(["reboot"], exe="/usr/sbin/reboot", ts=at(60))])[1]
    high = [m for m in out if m.proposed_lane == "high"]
    assert high and all("web-service account 'www-data'" in m.claim for m in high)


def test_record_only_stop_without_restart_or_shutdown_is_high_and_counted_once_across_sources():
    out = run(SecurityOrLoggingServiceStop, [svc("filebeat", ts=at(0)),
                                             svc("filebeat", ts=at(0.4), source="journal", unit="filebeat.service")])[1]
    assert len(out) == 1
    m = out[0]
    assert m.proposed_lane == "high" and "'filebeat' stopping at least 1 time(s)" in m.claim
    assert "1 audit SERVICE_STOP record(s); 1 journal unit stop record(s)" in m.claim
    assert "No start of the unit within 300 s and no shutdown marker were recorded" in m.claim


@pytest.mark.parametrize("gap,expected", [(10, []), (120, ["lead"]), (301, ["high"])])
def test_record_only_restart_gaps(gap, expected):
    out = run(SecurityOrLoggingServiceStop, [svc("auditd"), svc("auditd", "start", ts=at(gap))])[1]
    assert [m.proposed_lane for m in out] == expected


@pytest.mark.parametrize("marker,lane", [
    (ev("system_state", at(-20), system__event="runlevel", system__runlevel="0"), "lead"),
    (ev("system_state", at(60), system__event="shutdown"), "lead"),
    (svc("shutdown.target", "start", ts=at(30), source="journal", unit="shutdown.target"), "lead"),
    (svc("shutdown.target", "start", ts=at(30), source="journal", unit="shutdown.target", pid=4242), "high"),
    (ev("system_state", at(-901), system__event="shutdown"), "high"),
])
def test_record_only_stop_near_a_trusted_shutdown_marker_is_a_lead(marker, lane):
    out = run(SecurityOrLoggingServiceStop, [marker, svc("rsyslog")])[1]
    assert [m.proposed_lane for m in out] == [lane]


def test_failed_unit_is_a_lead_worded_as_possible_crash():
    m = run(SecurityOrLoggingServiceStop, [svc("osqueryd", outcome=Outcome.failure)])[1][0]
    assert m.proposed_lane == "lead" and "may be a crash" in m.claim


def test_unwatched_units_user_units_and_journal_entries_not_from_the_manager_are_ignored():
    forged = svc("auditd", source="journal", unit="auditd.service", pid=4242)
    assert run(SecurityOrLoggingServiceStop, [svc("nginx"), svc("filebeat", scope="user"), forged])[1] == []


def test_selinux_permissive_and_apparmor_forms():
    out = run(SecurityOrLoggingServiceStop, [ex(["setenforce", "0"], exe="/usr/sbin/setenforce"),
                                             ex(["aa-teardown"], exe="/usr/sbin/aa-teardown", pid=7002)])[1]
    lanes = {m.group_key.rsplit("|", 1)[-1]: m.proposed_lane for m in out}
    assert lanes == {"selinux_permissive": "lead", "apparmor_unload": "high"}


def test_shell_text_stop_is_found_and_says_so():
    out = run(SecurityOrLoggingServiceStop, [ex(["bash", "-c", "systemctl stop auditd; id"], exe="/usr/bin/bash")])[1]
    assert len(out) == 1 and "(some as shell command text)" in out[0].claim


def test_missing_fields_are_partial():
    pb, out = run(SecurityOrLoggingServiceStop, [ev("process_exec", process__user="root"),
                                                 ev("service_change", service__job="stop")])
    assert out == [] and pb.missing_required == 2


# ================================================================ audit rules and configuration
@pytest.mark.parametrize("args,forms", [
    (["-D"], ["delete_all_rules"]),
    (["-e", "0"], ["disable_auditing"]),
    (["-e0"], ["disable_auditing"]),
    (["-D", "-e", "2"], ["delete_all_rules"]),
    (["-d", "always,exit", "-F", "arch=b64", "-S", "execve"], ["delete_rule"]),
    (["-W", "/etc/passwd", "-p", "wa"], ["delete_watch"]),
    (["--signal", "TERM"], ["stop_daemon"]),
    (["-r", "1"], ["rate_limit"]),
])
def test_auditctl_grammar(args, forms):
    assert [f for f, _how, _lane in auditctl_requests(args)] == forms


@pytest.mark.parametrize("args", [["-l"], ["-s"], ["-e", "2"], ["-e", "1"], ["-R", "/etc/audit/audit.rules"],
                                  ["-m", "-D test message"], ["-w", "/etc/passwd", "-p", "wa", "-k", "identity"],
                                  ["-r", "0"], ["-h"], ["--signal", "HUP"]])
def test_auditctl_read_only_and_additive_forms(args):
    assert auditctl_requests(args) == []


def test_delete_all_rules_with_kernel_records_from_the_same_process_is_high():
    cmd = ex(["auditctl", "-D"], exe="/usr/sbin/auditctl", pid=7004)
    records = [cfg("remove_rule", ts=at(0.01 * i), pid=7004, key=f"k{i}") for i in range(3)]
    m = run(AuditRulesTamper, [cmd, *records])[1]
    assert len(m) == 1
    m = m[0]
    assert m.proposed_lane == "high" and "delete every audit rule (-D)" in m.claim
    assert "3 kernel CONFIG_CHANGE record(s) from the same process(es) show the change" in m.claim
    assert "3 applied" in m.claim and len(m.events) == 4


def test_command_without_kernel_record_says_so_and_lock_is_named():
    m = run(AuditRulesTamper, [ex(["auditctl", "-D", "-e", "2"], exe="/usr/sbin/auditctl")])[1][0]
    assert "lock the configuration until reboot (-e 2)" in m.claim
    assert "whether the change was applied is not established" in m.claim


@pytest.mark.parametrize("argv,exe", [
    (["auditctl", "-l"], "/usr/sbin/auditctl"), (["auditctl", "-e", "2"], "/usr/sbin/auditctl"),
    (["auditctl", "-R", "/etc/audit/audit.rules"], "/usr/sbin/auditctl"), (["augenrules", "--load"], None),
    (["grep", "--", "-D", "/etc/audit/audit.rules"], None), (["cat", "/etc/audit/auditd.conf"], None),
    (["auditctl", "-m", "-D test"], "/usr/sbin/auditctl"), (["man", "auditctl"], None),
])
def test_audit_hard_negatives(argv, exe):
    assert run(AuditRulesTamper, [ex(argv, exe=exe)])[1] == []


def test_kernel_record_of_auditing_switched_off_is_high_and_refusal_is_lead():
    on = run(AuditRulesTamper, [cfg("set", setting="audit_enabled", value="0", old="1")])[1][0]
    assert on.proposed_lane == "high" and "auditing being switched off (audit_enabled=0)" in on.claim
    refused = run(AuditRulesTamper, [cfg("set", setting="audit_enabled", value="0", old="1",
                                         outcome=Outcome.failure)])[1][0]
    assert refused.proposed_lane == "lead" and "0 applied" in refused.claim


@pytest.mark.parametrize("readd,lane", [(None, "high"), (30, "lead"), (121, "high")])
def test_rules_removed_then_readded_by_the_same_session_is_a_reload(readd, lane):
    events = [cfg("remove_rule", ts=at(i), key=f"k{i}") for i in range(3)]
    if readd is not None:
        events.append(cfg("add_rule", ts=at(2 + readd)))
    out = run(AuditRulesTamper, events)[1]
    assert [m.proposed_lane for m in out] == [lane]


@pytest.mark.parametrize("extra,lanes", [
    ([cfg("set", ts=at(5), setting="audit_pid", value="913", old="0", auid=None, ses=None)], []),
    ([cfg("set", ts=at(60), setting="audit_pid", value="913", old="0", auid=None, ses=None)], ["lead"]),
    ([ev("system_state", at(20), system__event="shutdown")], ["lead"]),
    ([], ["high"]),
])
def test_audit_daemon_unregistering(extra, lanes):
    gone = cfg("set", setting="audit_pid", value="0", old="812", auid=None, ses=None)
    assert [m.proposed_lane for m in run(AuditRulesTamper, [gone, *extra])[1]] == lanes


def test_boot_time_configuration_records_are_not_findings():
    boot = [cfg("add_rule", ts=at(i), auid=None, ses=None) for i in range(5)]
    boot += [cfg("set", setting="audit_backlog_limit", value="8192", old="64", auid=None, ses=None),
             cfg("set", setting="audit_enabled", value="1", old="1", auid=None, ses=None),
             cfg("set", setting="audit_pid", value="812", old="0", auid=None, ses=None)]
    assert run(AuditRulesTamper, boot)[1] == []


def test_audit_configuration_file_writes_are_leads():
    out = run(AuditRulesTamper, [
        ex(["sed", "-i", "/execve/d", "/etc/audit/rules.d/audit.rules"]),
        ex(["bash", "-c", "echo '-e 0' > /etc/audit/rules.d/99-off.rules"], exe="/usr/bin/bash", pid=7002),
    ])[1]
    assert [m.proposed_lane for m in out] == ["lead"]
    assert "write audit configuration file /etc/audit/rules.d/audit.rules" in out[0].claim
    assert "with a shell redirect" in out[0].claim


# ================================================================ logs and history
@pytest.mark.parametrize("name,args,category,lane", [
    ("rm", ["-f", "/var/log/wtmp"], "log_wipe", "high"),
    ("shred", ["-u", "-n", "3", "/var/log/auth.log"], "log_wipe", "high"),
    ("truncate", ["-s", "0", "/var/log/btmp"], "log_wipe", "high"),
    ("truncate", ["--size=0", "/var/log/audit/audit.log"], "log_wipe", "high"),
    ("cp", ["/dev/null", "/var/log/lastlog"], "log_wipe", "high"),
    ("dd", ["if=/dev/zero", "of=/var/log/syslog", "bs=1M"], "log_wipe", "high"),
    ("ln", ["-sf", "/dev/null", "/root/.bash_history"], "history_file", "high"),
    ("rm", ["/home/alice/.bash_history"], "history_file", "high"),
    ("rm", ["-rf", "/var/log"], "log_wipe", "high"),
    ("rm", ["-r", "/var/log/journal/abc"], "log_wipe", "high"),
    ("mv", ["/var/log/auth.log", "/tmp/a"], "log_wipe", "high"),
    ("journalctl", ["--vacuum-time=1s"], "journal_vacuum", "high"),
    ("journalctl", ["--rotate", "--vacuum-size", "500M"], "journal_vacuum", "high"),
    ("journalctl", ["--vacuum-time=7d"], "journal_vacuum", "lead"),
    ("find", ["/var/log", "-type", "f", "-delete"], "log_wipe", "high"),
    ("find", ["/var/log", "-name", "*.gz", "-mtime", "+30", "-delete"], "log_change", "lead"),
    ("rm", ["/var/log/apt/history.log.3.gz"], "log_change", "lead"),
    ("sed", ["-i", "/203.0.113.9/d", "/var/log/auth.log"], "log_edit", "lead"),
    ("truncate", ["-s", "1M", "/var/log/syslog"], "log_edit", "lead"),
    ("vi", ["/var/log/auth.log"], "log_editor", "lead"),
    ("tee", ["/var/log/wtmp"], "log_wipe", "high"),
])
def test_log_request_grammar(name, args, category, lane):
    found = log_requests(name, args, "/root")
    assert [(c, la) for c, _t, _h, la in found] == [(category, lane)]


@pytest.mark.parametrize("name,args", [
    ("cat", ["/var/log/wtmp"]), ("last", ["-f", "/var/log/wtmp"]), ("tail", ["-f", "/var/log/syslog"]),
    ("grep", ["rm -rf /var/log", "notes.txt"]), ("echo", ["rm", "/var/log/wtmp"]), ("logrotate", ["/etc/logrotate.conf"]),
    ("tee", ["-a", "/var/log/app.log"]), ("rm", ["/tmp/x.log"]), ("man", ["shred"]),
    ("journalctl", ["-u", "ssh", "--since", "today"]), ("cp", ["/var/log/syslog", "/tmp/syslog.copy"]),
    ("history", []), ("export", ["PATH=/usr/bin"]), ("unset", ["PATH"]),
])
def test_log_hard_negatives(name, args):
    assert log_requests(name, args, "/root") == []


def test_shell_segments_keep_assignments_redirects_and_quoting():
    segments, incomplete = shell_segments("bash", ["-c", "HISTFILE=/dev/null; grep 'rm /var/log/wtmp' x > /tmp/o"])
    assert not incomplete
    assert segments[0].assignments == ["HISTFILE=/dev/null"] and segments[0].argv == []
    assert segments[1].argv == ["grep", "rm /var/log/wtmp", "x"] and segments[1].redirects == [(">", "/tmp/o")]


@pytest.mark.parametrize("script,lane,text", [
    ("unset HISTFILE; history -c", "lead", "unset HISTFILE"),
    ("export HISTFILE=/dev/null", "lead", "set HISTFILE=/dev/null"),
    ("HISTSIZE=0 bash", "lead", "set HISTSIZE=0"),
    ("set +o history", "lead", "switch history recording off"),
    ("cat /dev/null > /var/log/wtmp", "high", "with a shell redirect ('>')"),
    (": > ~/.bash_history", "high", "shell history file ~/.bash_history"),
])
def test_shell_text_forms_are_script_content(script, lane, text):
    out = run(LogOrHistoryClearing, [ex(["bash", "-c", script], exe="/usr/bin/bash")])[1]
    assert out and {m.proposed_lane for m in out} == {lane}
    assert any(text in m.claim for m in out) and all(m.claim_type == "script_content" for m in out)
    assert all("whether it ran is not established" in m.claim for m in out)


@pytest.mark.parametrize("script", ["echo hi >> /var/log/app.log", "history | tail -5",
                                    "grep HISTFILE ~/.bashrc", "echo 'unset HISTFILE'"])
def test_shell_text_hard_negatives(script):
    assert run(LogOrHistoryClearing, [ex(["bash", "-c", script], exe="/usr/bin/bash")])[1] == []


def test_unmodelled_text_is_partial_not_a_clean_no_match():
    pb, out = run(LogOrHistoryClearing, [ex(["bash", "-c", "rm -rf /var/log/*"], exe="/usr/bin/bash")])
    assert out == [] and pb.missing_required == 1


def test_wiping_commands_by_one_actor_are_one_grouped_high_finding():
    events = [ex(["rm", "-f", path], pid=7100 + i, ts=at(i)) for i, path in
              enumerate(["/var/log/wtmp", "/var/log/btmp", "/var/log/lastlog"])]
    out = run(LogOrHistoryClearing, events)[1]
    assert len(out) == 1 and out[0].proposed_lane == "high" and "ran 3 command(s)" in out[0].claim
    assert "Whether the files changed is not established by exec records" in out[0].claim
    assert "T1685.006" in out[0].notes


def test_package_purge_removing_its_logs_is_a_lead():
    dpkg = ex(["dpkg", "--purge", "app"], exe="/usr/bin/dpkg", pid=100, ppid=90)
    postrm = ex(["/bin/sh", "/var/lib/dpkg/info/app.postrm", "purge"], exe="/usr/bin/dash", pid=101, ppid=100)
    rm = ex(["rm", "-rf", "/var/log/audit"], pid=102, ppid=101)
    out = run(LogOrHistoryClearing, [dpkg, postrm, rm])[1]
    assert [m.proposed_lane for m in out] == ["lead"] and "package management" in out[0].claim


def test_web_service_account_removing_a_web_log_is_high():
    m = run(LogOrHistoryClearing, [ex(["rm", "/var/log/apache2/access.log"], uid="33")])[1][0]
    assert m.proposed_lane == "high" and "web-service account 'www-data'" in m.claim


def test_every_exec_failed_lowers_to_lead():
    m = run(LogOrHistoryClearing, [ex(["rm", "/var/log/wtmp"], outcome=Outcome.failure)])[1][0]
    assert m.proposed_lane == "lead" and "lane lowered: every recorded exec failed" in m.notes


# ================================================================ registry
@pytest.mark.parametrize("cls", [SecurityOrLoggingServiceStop, AuditRulesTamper, LogOrHistoryClearing])
def test_registered_positive_only_with_cards_and_valid_attack_ids(cls):
    import gzip
    from pathlib import Path
    assert cls in ALL_PLAYBOOKS and any(isinstance(pb, cls) for pb in fresh_pack())
    assert cls.kind == "aggregate" and not cls.assures_negative and cls.positive_only_reason
    assert {"behavior", "telemetry", "fidelity", "lanes", "research_basis", "retrieval"} <= set(cls.card)
    with gzip.open(Path(__file__).resolve().parents[1] / "content/attack/enterprise-attack-20.0.json.gz") as fh:
        stix = json.load(fh)
    ids = {ref["external_id"] for obj in stix["objects"] if obj.get("type") == "attack-pattern"
           and not obj.get("revoked") and not obj.get("x_mitre_deprecated")
           for ref in obj.get("external_references", []) if ref.get("source_name") == "mitre-attack"}
    assert set(cls.attack) <= ids


# ================================================================ end to end through the sweep (raw records)
def _hit(i, ts_iso, dataset, original):
    return {"_id": f"h{i}", "_index": "romulus-host-x", "_source": {
        "@timestamp": ts_iso, "message": original, "host": {"name": "app01"},
        "event": {"dataset": dataset, "original": original}}}


def _sshd(i, ts_iso, message):
    return _hit(i, ts_iso, "systemd.journal", json.dumps({"SYSLOG_IDENTIFIER": "sshd", "_HOSTNAME": "app01",
                                                          "MESSAGE": message}))


def test_sweep_publishes_tampering_and_ssh_findings_with_resolvable_citations(monkeypatch):
    from romulus.hunt import sweep as sw
    from romulus.sources.models import Completeness, SearchOutcome, Window
    from romulus.store.db import make_engine, migrate
    from romulus.store.repo import Repo

    t = 1893920400                                     # 2030-01-06 09:00Z
    part1 = [_sshd(i, f"2030-01-06T09:0{i}:00Z", f"Failed password for root from 203.0.113.9 port {41000 + i} ssh2")
             for i in range(6)]
    part2 = [
        _sshd(10, "2030-01-06T09:07:00Z", "Accepted password for root from 203.0.113.9 port 42000 ssh2"),
        _hit(11, "2030-01-06T09:08:00Z", "linux.audit", f'type=EXECVE msg=audit({t + 480}.000:900): argc=2 '
                                                         'a0="auditctl" a1="-D"'),
        _hit(12, "2030-01-06T09:08:00Z", "linux.audit",
             f'type=SYSCALL msg=audit({t + 480}.000:900): arch=c000003e syscall=59 success=yes exit=0 ppid=6999 '
             'pid=7004 auid=0 uid=0 euid=0 ses=40 comm="auditctl" exe="/usr/sbin/auditctl"\x1dUID="root" AUID="root"'),
        _hit(13, "2030-01-06T09:08:00Z", "linux.audit",
             f'type=CONFIG_CHANGE msg=audit({t + 480}.010:901): auid=0 ses=40 op=remove_rule key="exec" list=4 res=1'),
        _hit(14, "2030-01-06T09:08:00Z", "linux.audit",
             f'type=SYSCALL msg=audit({t + 480}.010:901): arch=c000003e syscall=44 success=yes exit=1072 ppid=6999 '
             'pid=7004 auid=0 uid=0 euid=0 ses=40 comm="auditctl" exe="/usr/sbin/auditctl"'),
    ]
    start = datetime(2030, 1, 6, 9, 0, tzinfo=UTC)
    windows = [Window(start=start, end=start + timedelta(minutes=6)),
               Window(start=start + timedelta(minutes=6), end=start + timedelta(minutes=15))]
    assert {h["_source"]["event"]["dataset"] for h in part1 + part2} <= set(sw.HOST_DATASETS)   # retrieval superset
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
    found = {c["rule_id"]: c for c in repo.candidates("h1")}
    audit = found["host.audit_rules_tamper"]
    assert audit["lane"] == "high" and "1 kernel CONFIG_CHANGE record(s)" in audit["claim"]
    assert len(audit["event_ids"]) == 2
    ssh = found["host.ssh_success_after_failures"]
    assert ssh["lane"] == "high" and len(ssh["event_ids"]) == 7
    cells = {c["rule_id"]: c["state"] for c in repo.rule_cells("h1") if c["target"] == "*"}
    assert cells["host.audit_rules_tamper"] == "matched" and cells["host.ssh_success_after_failures"] == "matched"
    assert cells["host.ssh_password_guessing"] == "positive_only"
