"""Linux daemon families typed from their own log statements, in every shipper shape, and the rules that read them.

Synthetic lines follow the upstream statements, never collected telemetry:
- sudo: sudoers(5) EVENT LOGGING (https://www.sudo.ws/docs/man/sudoers.man/) and the Elastic System integration's
  auth pipeline test logs (packages/system/data_stream/auth/_dev/test/pipeline/test-sudo-optional-fields.log,
  test-sudo-no-tty.log);
- su/runuser: util-linux login-utils/su-common.c log_syslog; shadow-utils lib/sulog.c and src/su.c;
- pkexec: polkit src/programs/pkexec.c log_message; https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt;
- shadow-utils: src/useradd.c, usermod.c, userdel.c, groupadd.c, groupdel.c, groupmod.c, gpasswd.c, chage.c and the
  Elastic test logs test-gpasswd.log, test-usermod-group.log, test-userdel.log;
- kernel: linux kernel/module/main.c (module_augment_kernel_taints, module_sig_check);
- BIND 9: lib/ns/xfrout.c ("transfer of '%s/%s': %s", "%s started%s%s (serial %u)") and client.c's ACL message;
- OpenVPN under Debian's openvpn@.service template (`--daemon ovpn-%i`).
Hosts, accounts and addresses are invented.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest

from romulus.detect.auth import AccountOrGroupChange
from romulus.detect.linux_direct import KernelModuleLoad
from romulus.detect.privilege_brokers import PkexecEnvironmentRejection, PrivilegeBrokerRefusal
from romulus.detect.registry import ALL_PLAYBOOKS
from romulus.evidence.linux_service_text import parse_service, service_skip_reason
from romulus.evidence.normalize import normalize_hits
from romulus.evidence.typed import Outcome, fv
from tests.lineage_citation_fixture import bind_lineage
from tests.test_account_changes import ex

SHAPES = ("raw", "syslog", "journal", "journal-fields")
STAMP = "2026-11-09T12:00:00Z"


def doc(shape, program, body, *, pid=4242, comm=None, nid="t-1", host="app01", stamp=STAMP):
    """One log line of `program` in a Linux shipper shape: a raw syslog line, the System integration's syslog/auth
    dataset (indexed program and pid), the dev importer's journal JSON, or Elastic Agent's journald fields."""
    source = {"@timestamp": stamp, "host": {"name": host}, "event": {}}
    if shape == "raw":
        source.update(message=f"Nov  9 12:00:00 {host} {program}[{pid}]: {body}", event={"dataset": "custom.log"})
    elif shape == "syslog":
        source.update(message=body, event={"dataset": "system.auth"}, process={"name": program, "pid": pid})
    elif shape == "journal":
        record = {"MESSAGE": body, "SYSLOG_IDENTIFIER": program, "_PID": str(pid), "_HOSTNAME": host}
        if comm:
            record["_COMM"] = comm
        source.update(message=body, event={"dataset": "systemd.journal", "original": json.dumps(record)})
    else:
        journald = {"pid": pid, **({"process": {"name": comm}} if comm else {})}
        source.update(message=body, event={"dataset": "journald.logs"}, syslog={"identifier": program},
                      journald=journald)
    return {"_index": "host-logs", "_id": nid, "_source": source}


def one(shape, program, body, **kw):
    events, skips, errors = normalize_hits([doc(shape, program, body, **kw)])
    assert not errors and not skips, (skips, errors)
    assert len(events) == 1
    return events[0]


# ---------------------------------------------------------------------------------------------- parsers, all shapes
SUDO_GROUP_ENV = "alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; GROUP=wheel ; ENV=FOO=bar BAZ=1 ; COMMAND=/usr/bin/id -G"


@pytest.mark.parametrize("shape", ["journal", "journal-fields", "syslog"])
def test_sudo_optional_fields_are_typed(shape):
    event = one(shape, "sudo", SUDO_GROUP_ENV)
    assert event.family == "privilege_use" and event.outcome == Outcome.success
    assert (event.get("user.name"), event.get("auth.target_user")) == ("alice", "root")
    assert event.get("sudo.run_group") == "wheel" and event.get("sudo.env") == "FOO=bar BAZ=1"
    assert event.get("sudo.command") == "/usr/bin/id -G" and event.get("process.tty") == "pts/0"


@pytest.mark.parametrize("line,reason,tty", [
    ("tsg : user NOT in sudoers ; TTY=pts/1 ; PWD=/home/tsg ; USER=root ; COMMAND=/bin/ls", "user NOT in sudoers", "pts/1"),
    ("alice : command not allowed ; HOST=server01 ; TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/id",
     "command not allowed", "pts/0"),
    ("alice : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/id",
     "3 incorrect password attempts", "pts/0"),
    ("alice : a password is required ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/id", "a password is required", None),
    ("alice : user NOT authorized on host ; TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/sh", "user NOT authorized on host",
     "pts/0"),
])
def test_sudo_rejections_name_their_reason(line, reason, tty):
    event = one("journal", "sudo", line)
    assert event.outcome == Outcome.failure and event.get("privilege.denial_reason") == reason
    assert event.get("process.tty") == tty


def test_sudo_without_tty_and_chroot_still_types():
    event = one("journal", "sudo", "alice : TTY=pts/0 ; CHROOT=/srv/jail ; PWD=/ ; USER=root ; COMMAND=/bin/true")
    assert event.get("sudo.chroot") == "/srv/jail" and event.get("sudo.command") == "/bin/true"
    event = one("journal", "sudo", "alice : PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/id")
    assert not event.has("process.tty") and event.outcome == Outcome.success


def test_sudo_working_directory_with_forged_fields_is_flagged():
    event = one("journal", "sudo", "bob : TTY=pts/0 ; PWD=/tmp/x ; USER=root ; COMMAND=y ; USER=bob ; COMMAND=/bin/id")
    assert any("misattributed" in caveat for caveat in event.caveats)


@pytest.mark.parametrize("shape", SHAPES)
@pytest.mark.parametrize("program,body,outcome,actor,target", [
    ("su", "(to root) alice on pts/0", Outcome.success, "alice", "root"),
    ("su", "FAILED SU (to root) alice on pts/1", Outcome.failure, "alice", "root"),
    ("su", "FAILED su for root by alice", Outcome.failure, "alice", "root"),
    ("runuser", "FAILED RUNUSER (to postgres) alice on none", Outcome.failure, "alice", "postgres"),
    ("pkexec", "alice: Executing command [USER=root] [TTY=/dev/pts/0] [CWD=/home/alice] [COMMAND=/usr/bin/id]",
     Outcome.success, "alice", "root"),
    ("pkexec", ("alice: Error executing command as another user: Not authorized [USER=root] [TTY=/dev/pts/0] "
                "[CWD=/home/alice] [COMMAND=/bin/bash]"), Outcome.failure, "alice", "root"),
])
def test_privilege_brokers_in_every_shape(shape, program, body, outcome, actor, target):
    event = one(shape, program, body, pid=777)
    assert event.family == "privilege_use" and event.outcome == outcome
    assert (event.get("auth.service"), event.get("user.name"), event.get("auth.target_user")) == (program, actor, target)
    assert event.get("process.pid") == 777
    assert event.fields["process.pid"].origin.startswith("t-1:")


def test_pkexec_framing_inside_the_working_directory_types_neither_text_field():
    body = ("alice: Executing command [USER=root] [TTY=/dev/pts/0] [CWD=/tmp/a] [COMMAND=/bin/x] "
            "[COMMAND=/usr/bin/id]")
    event = parse_service("pkexec", body)
    assert event.fields["user.name"] == "alice"
    assert "process.cwd" not in event.fields and "privilege.command" not in event.fields
    assert any("neither is typed" in caveat for caveat in event.caveats)


@pytest.mark.parametrize("shape", SHAPES)
@pytest.mark.parametrize("program,body,action,name,extra", [
    ("useradd", "new user: name=backdoor, UID=1005, GID=1005, home=/home/backdoor, shell=/bin/bash, from=/dev/pts/0",
     "create_user", "backdoor", {"account.id": "1005"}),
    ("groupadd", "new group: name=apache, GID=48", "create_group", "apache", {"account.id": "48"}),
    ("useradd", "add 'backdoor' to group 'sudo'", "modify_user", "backdoor",
     {"account.group": "sudo", "account.op": "add-user-to-group"}),
    ("usermod", "add 'testuser' to group 'wheel'", "modify_user", "testuser",
     {"account.group": "wheel", "account.op": "add-user-to-group"}),
    ("gpasswd", "user alice added by root to group sudo", "modify_user", "alice",
     {"account.group": "sudo", "user.name": "root"}),
    ("gpasswd", "user alice removed by root from group sudo", "modify_user", "alice",
     {"account.op": "delete-user-from-group"}),
    ("userdel", "delete 'siem_test' from group 'tcpdump'", "modify_user", "siem_test",
     {"account.op": "delete-user-from-group"}),
    ("userdel", "removed group 'siem_group' owned by 'siem_test'", "delete_group", "siem_group", {}),
    ("groupdel", "group 'old' removed", "delete_group", "old", {}),
    ("groupmod", "group changed in /etc/group (group devs/1001, new name: ops)", "modify_group", "ops",
     {"account.previous_name": "devs"}),
    ("gpasswd", "members of group sudo set by root to alice,bob", "modify_group", "sudo",
     {"account.op": "set-group-members", "user.name": "root"}),
    ("chage", "changed password expiry for alice", "modify_user", "alice", {"account.op": "change-password-expiry"}),
    ("usermod", "change user 'bob' password", "password_change", "bob", {}),
    ("useradd", "failed adding user 'x1', exit code: 9", "create_user", "x1", {}),
])
def test_shadow_utils_lines_in_every_shape(shape, program, body, action, name, extra):
    event = one(shape, program, body)
    assert event.family == "account_change"
    assert (event.get("account.action"), event.get("account.name")) == (action, name)
    for key, value in extra.items():
        assert event.get(key) == value
    assert event.outcome == (Outcome.failure if body.startswith("failed") else Outcome.success)
    assert event.get("process.pid") == 4242


@pytest.mark.parametrize("program,body", [
    ("usermod", "add 'testuser' to shadow group 'shadow'"),
    ("userdel", "delete 'siem_test' from shadow group 'tcpdump'"),
    ("userdel", "removed shadow group 'siem_group'"),
    ("groupadd", "group added to /etc/group: name=apache, GID=48"),
    ("groupadd", "group added to /etc/gshadow: name=apache"),
    ("groupdel", "group 'old' removed from /etc/group"),
    ("groupmod", "group changed in /etc/gshadow (group devs, new name: ops)"),
    ("gpasswd", "user alice added by root to group sudo in /etc/group"),
    ("gpasswd", "members of group sudo set by root to alice,bob in /etc/group"),
    ("su", "+ pts/0 alice:root"),
])
def test_the_same_changes_other_database_line_is_a_named_skip(program, body):
    events, skips, errors = normalize_hits([doc("raw", program, body)])
    assert not events and not errors and sum(skips.values()) == 1
    reason = next(iter(skips))
    assert "is not normalized" in reason and "(" in reason and "no recognized format" not in reason


@pytest.mark.parametrize("program,body", [
    # a quoted or mentioned action is not the action: only the program's own anchored statement is typed
    ("CRON", "(root) CMD (echo 'FAILED SU (to root) alice on pts/0')"),
    ("bash", "FAILED SU (to root) alice on pts/1"),
    ("myapp", "diamorphine: loading out-of-tree module taints kernel."),
    ("logger", "user alice added by root to group sudo"),
    ("su", "(to root) alice on pts/0 trailing text"),
    ("su", "FAILED RUNUSER (to root) alice on pts/0"),
    ("usermod", "add 'alice' to group 'sudo' (requested)"),
    ("kernel", "audit: module verification failed: signature and/or required key missing - tainting kernel extra"),
    ("kernel", "my module: loading out-of-tree module taints kernel."),
    ("pkexec", "alice: The value for the SHELL variable was not found the /etc/shells file"),
])
def test_mentions_are_not_actions(program, body):
    events, _skips, _errors = normalize_hits([doc("raw", program, body)])
    assert not [event for event in events if event.family in {"privilege_use", "account_change", "kernel_module"}]


def test_sudo_command_quoting_a_pkexec_rejection_is_a_sudo_record_only():
    line = ("alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/grep The value for the SHELL "
            "variable was not found the /etc/shells file /var/log/auth.log")
    event = one("journal", "sudo", line)
    assert event.get("auth.service") == "sudo" and not event.has("privilege.rejected_variable")
    assert PkexecEnvironmentRejection().consume([event]) == []


@pytest.mark.parametrize("shape", SHAPES)
@pytest.mark.parametrize("body,taint", [
    ("diamorphine: loading out-of-tree module taints kernel.", "out_of_tree"),
    ("rk: module verification failed: signature and/or required key missing - tainting kernel", "unsigned"),
    ("nvidia: module license 'NVIDIA' taints kernel.", "proprietary_license"),
])
def test_kernel_taint_notices_are_kernel_module_loads(shape, body, taint):
    event = one(shape, "kernel", body)
    assert event.family == "kernel_module" and event.outcome == Outcome.unknown
    assert event.get("module.taint") == taint and event.get("module.op") == "load"
    assert not event.has("process.pid") and not event.has("module.path")


def test_kernel_taint_with_kernel_timestamp_prefix():
    event = one("raw", "kernel", "[   12.345678] diamorphine: loading out-of-tree module taints kernel.")
    assert event.get("module.name") == "diamorphine"


def test_firewall_lines_still_win_for_the_kernel():
    event = one("raw", "kernel", "[UFW BLOCK] IN=eth0 OUT= SRC=192.0.2.4 DST=192.0.2.8 PROTO=TCP SPT=1 DPT=22")
    assert event.family == "net_flow"


@pytest.mark.parametrize("shape", SHAPES)
@pytest.mark.parametrize("body,qtype,result,outcome", [
    ("client @0x7f8b1c0e1f68 198.51.100.7#41346 (example.test): zone transfer 'example.test/AXFR/IN' denied",
     "AXFR", "denied", Outcome.failure),
    (("client @0x7f8b1c0e1f68 198.51.100.7#41346 (example.test): transfer of 'example.test/IN': AXFR started "
      "(serial 2026110901)"), "AXFR", "started", Outcome.success),
    (("client 198.51.100.7#41346: transfer of 'example.test/IN': AXFR-style IXFR started, TSIG xfr-key "
      "(serial 7)"), "IXFR", "started", Outcome.success),
])
def test_bind_transfer_lines_are_typed_zone_transfer_requests(shape, body, qtype, result, outcome):
    event = one(shape, "named", body)
    assert event.family == "dns_query" and event.outcome == outcome
    assert (event.get("dns.question.type"), event.get("dns.transfer.result")) == (qtype, result)
    assert event.get("source.ip") == "198.51.100.7" and event.get("dns.question.name") == "example.test"
    assert event.get("dns.server_logged") is True


def test_bind_query_log_and_transfer_end_lines_keep_their_meaning():
    assert parse_service("named", "client @0x1 192.0.2.5#5353 (a.test): query: a.test IN A + (192.0.2.53)") \
        .fields["dns.question.type"] == "A"
    ended = ("client @0x1 198.51.100.7#41346 (example.test): transfer of 'example.test/IN': AXFR ended: 1 messages, "
             "12 records, 365 bytes, 0.001 secs (365000 bytes/sec) (serial 2026110901)")
    assert parse_service("named", ended) is None
    assert "completion line" in service_skip_reason("named", ended)
    # a zone name with a quote cannot shift the client
    assert parse_service("named", "client 198.51.100.7#1: zone transfer 'a'b/AXFR/IN' denied") is None


@pytest.mark.parametrize("shape", SHAPES)
def test_debian_openvpn_instance_identifier_is_openvpn(shape):
    body = "alice/192.0.2.2:51234 TLS: Username/Password authentication succeeded for username 'alice'"
    event = one(shape, "ovpn-VPNSERVER", body, comm="openvpn")
    assert event.family == "auth" and event.get("auth.service") == "openvpn"
    assert event.get("source.ip") == "192.0.2.2" and event.outcome == Outcome.success
    assert not any("disagrees" in caveat for caveat in event.caveats)


def test_journal_writer_mismatch_is_kept_with_a_caveat():
    event = one("journal", "pkexec", "alice: Executing command [USER=root] [TTY=/dev/pts/0] [CWD=/] [COMMAND=/bin/id]",
                comm="logger")
    assert any("disagrees" in caveat for caveat in event.caveats)


def test_raw_header_pid_is_the_writers_choice_with_its_own_origin():
    event = one("raw", "su", "(to root) alice on pts/0", pid=31337)
    assert event.get("process.pid") == 31337
    assert event.fields["process.pid"].origin.endswith("#syslog-header:pid")


# ---------------------------------------------------------------------------------------------- rules
def refusal(service="sudo", actor="alice", target="root", reason="user NOT in sudoers", outcome=Outcome.failure,
            ts_offset=0, host="app01", nid=None):
    body = {"sudo": f"{actor} : {reason} ; TTY=pts/0 ; PWD=/home/{actor} ; USER={target} ; COMMAND=/bin/bash",
            "su": f"FAILED SU (to {target}) {actor} on pts/0"}[service]
    stamp = (datetime(2026, 11, 9, 12, tzinfo=UTC) + timedelta(seconds=ts_offset)).isoformat().replace("+00:00", "Z")
    event = one("journal", service, body, host=host, nid=nid or f"r-{service}-{actor}-{ts_offset}-{host}", stamp=stamp)
    event.outcome = outcome
    return event


@pytest.fixture
def refusals():
    rule = PrivilegeBrokerRefusal()
    yield rule
    rule.close_spill()


def test_refusal_is_a_lead_citing_the_brokers_fields(refusals):
    [match] = refusals.consume([refusal()])
    assert (match.proposed_lane, match.severity) == ("lead", "medium")
    assert "sudo logged that it refused 'alice' acting as 'root' (user NOT in sudoers)" in match.claim
    fields = {p.field: p.value for p in match.predicate}
    assert fields["privilege.denial_reason"] == "user NOT in sudoers" and fields["auth.service"] == "sudo"
    assert "sudo.command" in fields             # cited as the caller's text, never read as executed


def test_web_service_account_refusal_is_named_and_grouped_apart(refusals):
    [match] = refusals.consume([refusal("su", actor="www-data")])
    assert match.proposed_lane == "lead" and "web-service account" in match.claim
    [other] = refusals.consume([refusal("su", actor="alice", nid="other")])
    assert other.group_key != match.group_key and "web-service" not in other.claim


def test_retries_fold_into_one_finding_with_their_count_across_partitions(refusals):
    first = refusals.consume([refusal(ts_offset=i) for i in range(3)])
    later = refusals.consume([refusal(ts_offset=3600)])      # the next partition, at its boundary
    assert len(first) == 1 and len(later) == 1
    assert later[0].aggregate_summary["count"] == 4 and later[0].group_key == first[0].group_key


def test_success_failure_and_unknown_outcomes(refusals):
    ok = refusal(outcome=Outcome.success, nid="ok")
    unknown = refusal(outcome=Outcome.unknown, nid="unknown")
    assert refusals.consume([ok, unknown]) == []
    assert refusals.evaluated == 2 and refusals.missing_required == 1


def test_missing_broker_is_unresolved_not_a_no_match(refusals):
    event = refusal()
    del event.fields["auth.service"]
    assert refusals.consume([event]) == []
    assert refusals.missing_required == 1 and refusals.evaluated == 0


def test_pkexec_environment_rejection_is_high_and_not_a_plain_refusal(refusals):
    rule = PkexecEnvironmentRejection()
    try:
        for n, message in enumerate(("The value for the SHELL variable was not found the /etc/shells file",
                        "The value for the SHELL variable was not found in the /etc/shells file",
                        "The value for environment variable XAUTHORITY contains suscipious content",
                        "The value for environment variable LANG contains suspicious content")):
            event = one("journal", "pkexec", f"alice: {message} [USER=root] [TTY=/dev/pts/0] [CWD=/tmp/x] "
                        "[COMMAND=GCONV_PATH=./pwnkit.so:. PATH=GCONV_PATH=. SHELL=/x CHARSET=PWNKIT]",
                        nid=f"pk-{n}")
            [match] = rule.consume([event])
            assert match.proposed_lane == "high" and "CVE-2021-4034" in match.claim
            assert "whether an exploit payload ran is not shown" in match.claim
            assert refusals.consume([event]) == []
        executing = one("journal", "pkexec", "alice: Executing command [USER=root] [TTY=/dev/pts/0] [CWD=/] "
                        "[COMMAND=/bin/id]", nid="exec")
        assert rule.consume([executing]) == []
    finally:
        rule.close_spill()


def test_refusals_at_mission_scale_stay_bounded_and_counted(refusals):
    events = [refusal(actor=f"u{i % 50}", host=f"h{i % 20}", ts_offset=i, nid=f"bulk-{i}") for i in range(4000)]
    for start in range(0, len(events), 500):
        out = refusals.consume(events[start:start + 500])
        assert len(out) <= 500
    groups = {key for key, _state in refusals.folds.items()}
    assert len(groups) == 100                      # (host, account) pairs: i % 20 and i % 50 repeat every 100
    assert refusals.evaluated == 4000 and refusals.missing_required == 0


def test_new_rules_are_registered_with_valid_cards():
    ids = {rule.id for rule in ALL_PLAYBOOKS}
    assert {"host.privilege_broker_refusal", "host.pkexec_environment_rejection"} <= ids
    for rule in (PrivilegeBrokerRefusal, PkexecEnvironmentRejection, KernelModuleLoad):
        for key in ("behavior", "telemetry", "fidelity", "benign_and_cost", "query_cost", "next_pivot", "adds",
                    "research_basis", "retrieval", "lanes"):
            assert rule.card.get(key), (rule.id, key)
        assert rule.assures_negative is False


def _account_run(events):
    rule = AccountOrGroupChange()
    raw = bind_lineage(rule, events)
    rule.bind_raw({ref.key: raw[ref.key] for event in events for ref in event.raw}, "fixture-target")
    assert rule.consume(events) == []
    rule.bind_raw({})
    try:
        return rule.finalize()
    finally:
        rule.close_spill()


def test_text_group_grant_to_sudo_is_high():
    event = one("journal", "gpasswd", "user mallory added by root to group sudo", pid=9001)
    [match] = _account_run([event])
    assert match.proposed_lane == "high" and "membership of privileged group sudo" in match.claim
    assert "account tool log line action=modify_user op=add-user-to-group acct=mallory grp=sudo" in match.claim


def test_text_uid_zero_assignment_is_high_and_an_ordinary_group_is_a_lead():
    [high] = _account_run([one("journal", "usermod", "change user 'bob' UID from '1001' to '0'", pid=9002)])
    assert high.proposed_lane == "high" and "assignment of user id 0" in high.claim
    [lead] = _account_run([one("journal", "usermod", "add 'bob' to group 'users'", pid=9003)])
    assert lead.proposed_lane == "lead"


def test_command_audit_record_and_text_line_of_one_change_are_one_finding():
    when = datetime(2026, 11, 9, 12, tzinfo=UTC)
    command = ex(["usermod", "-aG", "sudo", "mallory"], pid=9100, ts=when)
    command.host = "app01"
    line = one("journal", "usermod", "add 'mallory' to group 'sudo'", pid=9100)
    out = _account_run([command, line])
    assert len(out) == 1 and out[0].proposed_lane == "high"
    assert {event.id for event in out[0].events} >= {command.id, line.id}
    assert "1 account-management record(s) from the same process(es) report the change" in out[0].claim


def test_kernel_taint_notice_is_a_lead_and_does_not_claim_module_auditing():
    event = one("journal", "kernel", "diamorphine: loading out-of-tree module taints kernel.")
    rule = KernelModuleLoad()
    [match] = rule.consume([event])
    assert match.proposed_lane == "lead"
    assert "loaded module 'diamorphine', an out-of-tree module" in match.claim
    assert "first such module after boot only" in match.claim
    assert rule.partition_coverage_notes() == [
        "No module-load auditing records were present in this partition; unaudited module loading is unresolved."]


def test_kernel_audit_record_still_counts_as_module_auditing():
    event = one("journal", "kernel", "diamorphine: loading out-of-tree module taints kernel.")
    audited = one("journal", "kernel", "rk: loading out-of-tree module taints kernel.", nid="t-2")
    del audited.fields["module.taint"]
    audited.fields["module.path"] = fv("/tmp/rk.ko", "fixture:module.path")
    rule = KernelModuleLoad()
    rule.consume([event, audited])
    assert rule.partition_coverage_notes() == []


# ---------------------------------------------------------------------------------------------- review additions
@pytest.mark.parametrize("shape", SHAPES)
def test_sudo_in_every_shape_carries_the_writers_pid(shape):
    event = one(shape, "sudo", SUDO_GROUP_ENV, pid=5150)
    assert event.family == "privilege_use" and event.get("sudo.run_group") == "wheel"
    assert event.get("process.pid") == 5150 and event.fields["process.pid"].origin.startswith("t-1:")


def test_text_account_with_user_id_zero_is_high():
    created = one("journal", "useradd", "new user: name=toor, UID=0, GID=0, home=/root, shell=/bin/bash, from=none",
                  pid=9200)
    [match] = _account_run([created])
    assert match.proposed_lane == "high" and "a new account with user id 0" in match.claim
    [lead] = _account_run([one("journal", "useradd", "new user: name=svc, UID=990, GID=990, home=/srv, "
                               "shell=/usr/sbin/nologin, from=none", pid=9201, nid="t-2")])
    assert lead.proposed_lane == "lead"


def _zone_rule(events):
    from romulus.detect.dns import DnsZoneTransferOrAnyRequest
    rule = DnsZoneTransferOrAnyRequest()
    stage = {}
    out = list(rule.consume(events))
    stage.update({event.id: event for event in rule.drain_staged()})
    rule.bind_loader(lambda ids: [stage[i] for i in ids if i in stage])
    try:
        return rule, out + rule.finalize()
    finally:
        rule.close_spill()


BIND_DENIED = "client @0x7f1 198.51.100.7#41346 (example.test): zone transfer 'example.test/AXFR/IN' denied"
BIND_STARTED = ("client @0x7f1 198.51.100.7#41346 (example.test): transfer of 'example.test/IN': AXFR started "
                "(serial 2026110901)")
BIND_QUERY = "client @0x7f1 198.51.100.7#41346 (example.test): query: example.test IN AXFR -T (192.0.2.53)"


def test_bind_denial_alone_reaches_the_zone_transfer_rule_as_the_servers_decision():
    _rule, [match] = _zone_rule([one("journal", "named", BIND_DENIED, host="ns1")])
    assert match.proposed_lane == "lead"
    assert "host ns1" in match.claim and "198.51.100.7" in match.claim and "'example.test'" in match.claim
    assert "1 zone-transfer decision(s)" in match.claim and "AXFR denied" in match.claim
    assert "Whether the server answered is not established" not in match.claim


def test_bind_started_alone_says_the_server_began_sending_the_zone():
    _rule, [match] = _zone_rule([one("journal", "named", BIND_STARTED, host="ns1")])
    assert "AXFR started" in match.claim and "began sending the zone" in match.claim


def test_a_logged_question_and_its_started_line_are_never_two_questions():
    # BIND's query log names the address the question arrived on, its transfer line only the logging host, so the
    # two land in separate groups: one question to 192.0.2.53, one decision by host ns1, never two questions
    question = one("journal", "named", BIND_QUERY, host="ns1", nid="q-1")
    started = one("journal", "named", BIND_STARTED, host="ns1", nid="s-1")
    _rule, matches = _zone_rule([question, started])
    claims = sorted(match.claim for match in matches)
    assert len(claims) == 2
    assert any("sent 1 DNS question record(s)" in claim and "192.0.2.53" in claim for claim in claims)
    assert any("1 zone-transfer decision(s)" in claim and "host ns1" in claim and "sent" not in claim.split(".")[0]
               for claim in claims)


def test_brokers_accounts_and_taint_notices_reach_findings_through_the_sweep(tmp_path, monkeypatch):
    from tests import test_linux_text_stack_r2 as stack
    from tests import throughput_fixture as tf

    builder = tf.Builder(23)

    def add(n, body):
        when = tf.T0 + timedelta(seconds=n)
        line = f"Nov 18 {when:%H:%M:%S} web1 {body}"
        builder._doc("web1", when, "custom.auth", None, message=line)

    add(1, "sudo[4100]: mallory : user NOT in sudoers ; TTY=pts/3 ; PWD=/home/mallory ; USER=root ; COMMAND=/bin/bash")
    add(2, "pkexec[4101]: mallory: The value for the SHELL variable was not found the /etc/shells file [USER=root] "
           "[TTY=/dev/pts/3] [CWD=/tmp/p] [COMMAND=GCONV_PATH=./pwnkit.so:. SHELL=/x CHARSET=PWNKIT]")
    add(3, "gpasswd[4102]: user mallory added by root to group sudo")
    add(4, "kernel: diamorphine: loading out-of-tree module taints kernel.")
    monkeypatch.setattr(stack, "text_documents",
                        lambda: {tf.HOST_TARGET: builder.host, tf.NETWORK_TARGET: [], tf.ARKIME_TARGET: []})
    snapshot, _trace, _docs = stack.run_text_stack(tmp_path, monkeypatch)
    assert snapshot["stats"]["errors"] == 0 and not snapshot["stats"].get("rule_failures")
    found = {row["rule_id"]: row for row in snapshot["candidates"]}
    assert {"host.privilege_broker_refusal", "host.pkexec_environment_rejection", "host.account_or_group_change",
            "host.kernel_module_load"} <= set(found)
    assert found["host.pkexec_environment_rejection"]["lane"] == "high"
    assert found["host.account_or_group_change"]["lane"] == "high"
    assert found["host.privilege_broker_refusal"]["lane"] == "lead"
    assert found["host.kernel_module_load"]["lane"] == "lead"
    # the module rule never takes a taint notice for module-load auditing
    module_cells = [row for row in snapshot["rule_cells"] if row["rule_id"] == "host.kernel_module_load"]
    assert any("No module-load auditing records" in str(row["detail"]) for row in module_cells)
