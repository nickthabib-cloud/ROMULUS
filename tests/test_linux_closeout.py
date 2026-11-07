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


@pytest.mark.parametrize("logging", [
    ["-o", "/tmp/download.log"],
    ["-o/tmp/download.log"],
    ["-qo/tmp/download.log"],
    ["--output-file", "/tmp/download.log"],
    ["--output-file=/tmp/download.log"],
    ["-a", "/tmp/download.log"],
    ["--append-output=/tmp/download.log"],
])
@pytest.mark.parametrize("executed,expected", [("/tmp/download.log", False), ("/tmp/payload", True)])
def test_wget_log_options_are_not_payload_destinations(logging, executed, expected, tmp_path):
    download = ex(path="/usr/bin/wget", process__cwd="/tmp")
    download.fields["process.argv"].value = ["wget", *logging, "https://example.test/payload"]
    execution = ex(20, executed)
    _, findings = staged_run(rule("host.download_then_execute"), [[execution], [download]], tmp_path)
    assert bool(findings) is expected
    if expected:
        assert {event.id for event in findings[0].events} == {download.id, execution.id}


@pytest.mark.parametrize("options,expected_path", [
    (["-o", "/tmp/download.log", "-O", "/opt/content"], "/opt/content"),
    (["-qo/tmp/download.log", "-O/opt/content"], "/opt/content"),
    (["--output-file=/tmp/download.log", "--output-document=/opt/content"], "/opt/content"),
    (["-o", "/tmp/download.log", "-P", "/opt"], "/opt/payload"),
])
def test_wget_content_and_directory_options_keep_their_own_destinations(options, expected_path, tmp_path):
    download = ex(path="/usr/bin/wget", process__cwd="/tmp")
    download.fields["process.argv"].value = ["wget", *options, "https://example.test/payload"]
    _, findings = staged_run(rule("host.download_then_execute"), [[download], [ex(20, expected_path)]], tmp_path)
    assert len(findings) == 1


@pytest.mark.parametrize("reverse", [False, True])
def test_later_web_request_retains_the_strongest_supported_chain(reverse, tmp_path):
    write = change(path="/var/www/html/a.php", user="www-data")
    early = ev("http_access", T0 + timedelta(seconds=20), url__path="/a.php", http__response__status_code=200)
    late = ev("http_access", T0 + timedelta(seconds=7200), url__path="/a.php", http__response__status_code=200)
    execution = ex(7210, "/bin/bash", user="www-data")
    events = [write, early, late, execution]
    if reverse:
        events.reverse()
    _, findings = staged_run(rule("host.web_shell_chain"), [[event] for event in events], tmp_path)
    [finding] = findings
    assert finding.proposed_lane == "urgent"
    assert {write.id, late.id, execution.id} <= {event.id for event in finding.events}
    assert "inferred" in finding.claim


@pytest.mark.parametrize("reverse", [False, True])
def test_later_service_account_discovery_window_retains_high(reverse, tmp_path):
    first = [ex(i, "/usr/bin/" + command, process__auid="1000", process__session_id=9)
             for i, command in enumerate(("whoami", "uname", "ss", "ps", "tree"))]
    later = [ex(7200 + i, "/usr/bin/" + command, user="www-data",
                process__auid="1000", process__session_id=9)
             for i, command in enumerate(("whoami", "uname", "ss", "ps", "tree"))]
    events = first + later
    if reverse:
        events.reverse()
    _, findings = staged_run(rule("host.discovery_burst"), [[event] for event in events], tmp_path)
    [finding] = findings
    assert finding.proposed_lane == "high"
    assert {event.id for event in later} <= {event.id for event in finding.events}
    assert not {event.id for event in first} & {event.id for event in finding.events}


def test_web_discovery_outside_every_qualifying_window_does_not_raise_lane(tmp_path):
    events = [ex(i, "/usr/bin/" + command, process__auid="1000", process__session_id=9)
              for i, command in enumerate(("whoami", "uname", "ss", "ps", "tree"))]
    events.append(ex(7200, "/usr/bin/whoami", user="www-data",
                     process__auid="1000", process__session_id=9))
    _, [finding] = staged_run(rule("host.discovery_burst"), [[event] for event in reversed(events)], tmp_path)
    assert finding.proposed_lane == "lead"


def test_wget_watched_log_write_is_not_downloaded_content(tmp_path):
    download = ex(path="/usr/bin/wget", process__cwd="/tmp")
    download.fields["process.argv"].value = ["wget", "-o", "/tmp/download.log", "https://example.test/payload"]
    logfile = change(10, "/tmp/download.log", process__pid=42)
    _, findings = staged_run(rule("host.download_then_execute"),
                            [[ex(20, "/tmp/download.log")], [logfile], [download]], tmp_path)
    assert not findings


def test_discovery_high_lane_cites_the_web_account_even_for_a_repeated_class(tmp_path):
    events = [ex(i, "/usr/bin/" + command, process__auid="1000", process__session_id=9)
              for i, command in enumerate(("whoami", "uname", "ss", "ps", "tree"))]
    web_witness = ex(5, "/usr/bin/whoami", user="www-data", process__auid="1000", process__session_id=9)
    events.append(web_witness)
    _, [finding] = staged_run(rule("host.discovery_burst"), [[event] for event in reversed(events)], tmp_path)
    assert finding.proposed_lane == "high" and web_witness.id in {event.id for event in finding.events}
    assert len(finding.events) <= 6 and finding.aggregate_summary["count"] == 5


@pytest.mark.parametrize("name,expected_lane", [
    ("host.web_shell_chain", "urgent"), ("host.discovery_burst", "high")])
def test_stronger_late_windows_survive_many_hosts_on_disk(name, expected_lane, tmp_path):
    detector, stage = rule(name)(), {}
    detector.spill_dir = tmp_path
    for i in range(1000):
        host = f"late-host{i}"
        if name == "host.web_shell_chain":
            events = [
                change(path="/var/www/html/a.php", user="www-data"),
                ev("http_access", T0 + timedelta(seconds=20), url__path="/a.php", http__response__status_code=200),
                ev("http_access", T0 + timedelta(seconds=7200), url__path="/a.php", http__response__status_code=200),
                ex(7210, "/bin/bash", user="www-data"),
            ]
        else:
            events = [ex(start + n, "/usr/bin/" + command, user=user,
                         process__auid="1000", process__session_id=9)
                      for start, user in ((0, "alice"), (7200, "www-data"))
                      for n, command in enumerate(("whoami", "uname", "ss", "ps", "tree"))]
        for event in events:
            event.host = host
        detector.consume(list(reversed(events)))
        stage.update({event.id: event for event in detector.drain_staged()})
        assert detector.pending_count == 0
    detector.bind_loader(lambda ids: [stage[identity] for identity in ids])
    output = detector.finalize()
    assert not isinstance(output, list)
    count = 0
    for finding in output:
        count += 1
        assert finding.proposed_lane == expected_lane
        assert len(finding.events) <= 6
        assert any(event.ts >= T0 + timedelta(seconds=7200) for event in finding.events)
    assert count == 1000 and detector.capped == 0
    assert detector.rows_on_disk >= 4000 and detector.retained_events() == []


def test_linux_join_witnesses_are_shared_lossless_and_survive_earlier_rule_release(tmp_path):
    from romulus.detect.linux_sequences import share_linux_witnesses
    first, second = rule("host.download_then_execute")(), rule("host.tool_cleanup")()
    for detector in (first, second):
        detector.spill_dir = tmp_path
    share_linux_witnesses([first, second])
    events = [downloader(), ex(20)]
    for detector in (first, second):
        detector.consume(events)
        assert detector.drain_staged() == []
    assert first.witnesses is second.witnesses
    assert first.witnesses.count() == len(events)
    assert first.events([event.id for event in events]) == events
    first.release_state()
    assert second.events([event.id for event in events]) == events
    second.release_state()
    assert second.witnesses.closed


def test_alert_address_rows_coalesce_to_the_existing_minimum_id_witness(tmp_path):
    detector = rule("corr.alert_then_host_execution")()
    detector.spill_dir = tmp_path
    from romulus.evidence.typed import fv
    events = [ev("auth", T0 + timedelta(seconds=i), user__name="alice") for i in range(2000)]
    for event in reversed(events):
        event.fields["host.ip"] = fv(["10.0.0.9"], "native:host.ip")
        detector.consume([event])
        detector.drain_staged()
    rows = list(detector.query("SELECT id FROM records WHERE role='address'"))
    assert rows == [(min(event.id for event in events),)]
    plan = list(detector.query("EXPLAIN QUERY PLAN SELECT uid,id FROM records WHERE role='address' "
                               "AND host=? AND key=? ORDER BY id LIMIT 1", ("web1", "10.0.0.9")))
    assert any("records_address" in row[3] and "SEARCH" in row[3] for row in plan)


def test_compact_linux_witness_hydrates_native_body_without_changing_any_typed_field(tmp_path):
    from romulus.evidence.normalize import raw_digest
    from romulus.hunt.citations import COMPACT_CITATION_NOTE
    from romulus.hunt.publish import SourceCitationFetcher
    download, execution = downloader(), ex(20)
    raw = {event.raw[0].key: {"native": event.id, "argv": event.get("process.argv")} for event in (download, execution)}
    for event in (download, execution):
        event.raw[0].digest = raw_digest(raw[event.raw[0].key])
    detector, [finding] = staged_run(rule("host.download_then_execute"), [[execution], [download]], tmp_path)
    original = {event.id: event.model_dump(mode="json") for event in (download, execution)}
    for event in finding.events:
        event.caveats.append(COMPACT_CITATION_NOTE)

    class Source:
        def search(self, index, body):
            identities = body["query"]["bool"]["filter"][0]["ids"]["values"]
            return {"hits": {"hits": [{"_index": index, "_id": identity, "_source": raw[f"{index}/{identity}"]}
                                     for identity in identities]}}

    SourceCitationFetcher(Source()).hydrate(finding)
    assert {event.id: event.model_dump(mode="json") for event in finding.events} == original
    assert finding.raw_copies == raw
    assert detector.drain_staged() == []


def test_telemetry_clock_retains_every_late_timestamp_and_source_id_in_narrow_rows(tmp_path):
    detector = rule("host.telemetry_gap_after_tamper")()
    detector.spill_dir = tmp_path
    events = [ev("process_observed", T0 + timedelta(seconds=i), audit__serial=i) for i in range(1000)]
    for event in reversed(events):
        detector.consume([event])
        assert detector.drain_staged() == []
    assert detector.query("SELECT 1 FROM sqlite_master WHERE type='table' AND name='clock'").fetchone()
    assert list(detector.query("SELECT id,ts FROM clock ORDER BY ts,id")) == [
        (event.id, event.ts.timestamp()) for event in events]
    assert len(list(detector.query("PRAGMA table_info(clock)"))) == 4
    assert not detector.query("SELECT 1 FROM sqlite_master WHERE type='table' AND name='records'").fetchone()


def test_linux_witnesses_have_no_detection_floor_and_keep_mandatory_references_under_cache_pressure(tmp_path):
    from romulus.detect.bounded import StateBudget, live_stores
    from romulus.detect.linux_sequences import share_linux_witnesses
    detector = rule("host.download_then_execute")()
    detector.spill_dir = tmp_path
    detector.budget = budget = StateBudget(tmp_path, disk_total=4 * 2**20, reserve=0)
    floors = live_stores([detector])
    share_linux_witnesses([detector])
    witness = detector.witnesses
    assert live_stores([detector]) == floors
    first, second, refused = downloader(), ex(20), ex(40)
    witness.hold(first)
    witness.flush()
    assert witness.account().yields and witness.account().weight == 0
    assert budget.pool_used == 0 and budget.yield_used == witness.account().used > 0
    detection = budget.account("test_detection")
    budget.charge(detection, budget.disk_total)
    assert budget.new_key_reason(witness.account())
    witness.hold(second)
    assert {event.id: event for event in witness.load([first.id, second.id])} == {
        event.id: event for event in (first, second)}
    assert budget.physical_used <= budget.disk_total
    budget.broken = "test physical volume refusal"
    witness.hold(refused)
    assert witness.load([refused.id]) == []
    assert "linux_witnesses" in detector.limits
    detector.release_state()


def _linux_pressure(detector):
    from romulus.detect.bounded import Spill
    pressure = Spill(detector.spill_dir, detector.budget)
    pressure.table("pressure", "body BLOB")
    pressure.write("INSERT INTO pressure VALUES (?)", [(b"x" * (3 * 2**18),)])
    return pressure


def _large_linux_witness(t):
    import hashlib

    from romulus.evidence.typed import fv
    event = ex(t)
    event.fields["test.payload"] = fv("".join(
        hashlib.sha256(f"{t}-{i}".encode()).hexdigest() for i in range(8192)), "fixture:payload")
    return event


def test_scalar_flush_full_retains_accepted_rows_and_recovers_after_real_room_release(tmp_path):
    from romulus.detect.bounded import StateBudget
    detector = rule("host.download_then_execute")()
    detector.spill_dir = tmp_path
    detector.budget = StateBudget(tmp_path, disk_total=2**20, reserve=0)
    first, pending, refused = ex(), ex(20), ex(40)
    assert detector.add(first, "execute", "/tmp/first")
    detector.drain_staged()
    assert detector.add(pending, "execute", "/tmp/pending", data={"payload": "x" * (2**19)})
    pressure = _linux_pressure(detector)
    buffered = list(detector._spill._buffers["records"][1])
    try:
        assert detector.drain_staged() == []
        assert detector._spill._buffers["records"][1] == buffered
        assert list(detector.query("SELECT id FROM records")) == [(first.id,)]
        assert "linux_join_rows" in detector.limits and detector.capped == 0
        assert not detector.add(refused, "execute", "/tmp/refused")
        assert detector.capped == 1 and detector.rows_on_disk == 2
        assert detector._spill._buffers["records"][1] == buffered
        assert not detector.budget.broken
        assert detector.budget.physical_used <= detector.budget.disk_total
    finally:
        pressure.close()
    assert detector.drain_staged() == []
    assert not detector._spill._buffers["records"][1]
    assert {row[0] for row in detector.query("SELECT id FROM records")} == {first.id, pending.id}
    assert detector.add(refused, "execute", "/tmp/refused")
    detector.drain_staged()
    assert detector.query("SELECT COUNT(*) FROM records").fetchone()[0] == 3
    detector.release_state()


def test_shared_witness_flush_full_keeps_committed_citations_and_recovers_without_duplicates(tmp_path):
    from romulus.detect.bounded import StateBudget
    from romulus.detect.linux_sequences import share_linux_witnesses
    detector = rule("host.download_then_execute")()
    detector.spill_dir = tmp_path
    detector.budget = StateBudget(tmp_path, disk_total=2**20, reserve=0)
    share_linux_witnesses([detector])
    first, pending, refused = ex(), _large_linux_witness(20), ex(40)
    witness = detector.witnesses
    witness.hold(first)
    detector.drain_staged()
    witness.hold(pending)
    pressure = _linux_pressure(detector)
    buffered = list(witness._spill._buffers["witnesses"][1])
    charged = witness.account().used
    try:
        assert detector.drain_staged() == []
        assert witness._spill._buffers["witnesses"][1] == buffered
        assert witness.load([first.id]) == [first]
        witness.hold(pending)
        witness.hold(refused)
        assert witness.account().used == charged
        assert witness.pending == {pending.id}
        assert witness._spill._buffers["witnesses"][1] == buffered
        assert "linux_witnesses" in detector.limits and detector.capped == 0
        assert not detector.budget.broken
        assert detector.budget.physical_used <= detector.budget.disk_total
    finally:
        pressure.close()
    detector.drain_staged()
    assert witness.load([pending.id]) == [pending]
    assert not witness.pending
    witness.hold(refused)
    assert witness.count() == 3
    detector.release_state()


@pytest.mark.parametrize("kind", ["scalar", "witness"])
def test_linux_failed_auto_flush_retains_the_triggering_row_once_and_bounds_later_admission(kind, tmp_path, monkeypatch):
    from romulus.detect import bounded
    from romulus.detect.linux_sequences import share_linux_witnesses
    detector = rule("host.download_then_execute")()
    detector.spill_dir = tmp_path
    detector.budget = bounded.StateBudget(tmp_path, disk_total=2**20, reserve=0)
    share_linux_witnesses([detector])
    first, second, third = ((_large_linux_witness if kind == "witness" else ex)(i) for i in (0, 20, 40))
    pressure = _linux_pressure(detector)
    monkeypatch.setattr(bounded, "SPILL_BATCH", 2)
    try:
        if kind == "scalar":
            assert detector.add(first, "execute", "/tmp/first", data={"payload": "x" * (2**18)})
            assert detector.add(second, "execute", "/tmp/second", data={"payload": "x" * (2**18)})
            assert detector.rows_on_disk == 2 and detector.capped == 0
            rows = list(detector._spill._buffers["records"][1])
            assert len(rows) == 2
            assert not detector.add(third, "execute", "/tmp/third")
            assert detector._spill._buffers["records"][1] == rows
            assert detector.capped == 1
        else:
            witness = detector.witnesses
            witness.hold(first)
            witness.hold(second)
            assert witness.pending == {first.id, second.id}
            rows = list(witness._spill._buffers["witnesses"][1])
            charged = witness.account().used
            witness.hold(second)
            witness.hold(third)
            assert len(rows) == 2 and witness._spill._buffers["witnesses"][1] == rows
            assert witness.account().used == charged
        assert detector.budget.physical_used <= detector.budget.disk_total
        assert not detector.budget.broken
    finally:
        pressure.close()
    detector.drain_staged()
    if kind == "scalar":
        assert detector.query("SELECT COUNT(*) FROM records").fetchone()[0] == 2
    else:
        assert detector.witnesses.count() == 2
        assert {e.id: e for e in detector.witnesses.load([first.id, second.id])} == {
            e.id: e for e in (first, second)}
    detector.release_state()


def _linux_reclaim_pack(tmp_path):
    from romulus.detect.bounded import StateBudget
    from romulus.detect.linux_sequences import share_linux_witnesses
    pack = [rule(name)() for name in ("host.download_then_execute", "corr.alert_then_host_execution",
                                     "host.telemetry_gap_after_tamper")]
    budget = StateBudget(tmp_path, disk_total=4 * 2**20, reserve=0)
    for detector in pack:
        detector.spill_dir, detector.budget = tmp_path, budget
    share_linux_witnesses(pack)
    return pack


def _reclaim_linux_references(pack):
    witness = pack[0].witnesses
    callback = witness.account().evict_references
    assert callback is not None
    with pack[0].budget.reclamation_write():
        return callback(4096)


def test_linux_clock_bodies_yield_only_through_reference_protocol_and_keep_nonclock_events(tmp_path):
    pack = _linux_reclaim_pack(tmp_path)
    execution, clock_only = ex(), ev("auth", T0, user__name="alice")
    for detector in pack:
        detector.consume([execution, clock_only])
        detector.drain_staged()
    witness = pack[0].witnesses
    assert witness._spill.db.execute("PRAGMA auto_vacuum").fetchone()[0] == 2
    assert witness.account().evict is None
    pack[0].budget.reclaim_citations(pack[0].budget.disk_total * 2)
    assert witness.count() == 2
    _reclaim_linux_references(pack)
    assert witness.load([execution.id]) == [execution]
    assert witness.load([clock_only.id]) == []
    assert pack[-1].query("SELECT COUNT(*) FROM clock").fetchone()[0] == 2
    assert "linux_clock_witnesses" in pack[-1].limits
    for detector in pack:
        detector.release_state()


def test_linux_reclaimer_protects_pending_rows_and_current_replaced_address_witness(tmp_path):
    from romulus.evidence.typed import fv
    pack = _linux_reclaim_pack(tmp_path)
    old, replacement, pending, spare = [ev("auth", T0, user__name="alice") for _ in range(4)]
    old.id, replacement.id = "z-address", "a-address"
    for event in (old, replacement):
        event.fields["host.ip"] = fv(["10.0.0.9"], "fixture:host.ip")
    for detector in pack:
        detector.consume([old, replacement, pending, spare])
        detector.drain_staged()
    assert pack[0].add(pending, "pending")
    [address] = list(pack[1].query("SELECT uid,id FROM records WHERE role='address'"))
    assert address[1] == replacement.id and old.id in address[0]
    assert pack[0].query("SELECT COUNT(*) FROM records").fetchone()[0] == 0
    _reclaim_linux_references(pack)
    witness = pack[0].witnesses
    assert witness.load([replacement.id]) == [replacement]
    assert witness.load([pending.id]) == [pending]
    assert witness.load([spare.id]) == []
    plan = list(pack[1].query("EXPLAIN QUERY PLAN SELECT 1 FROM records WHERE role='address' "
                            "AND host=? AND key=? AND id=? LIMIT 1", ("web1", "10.0.0.9", replacement.id)))
    assert any("SEARCH" in row[3] and "records_address" in row[3] for row in plan)
    for detector in pack:
        detector.release_state()


def test_linux_reclaimer_protects_actual_tamper_hosts_with_indexed_membership(tmp_path):
    from romulus.detect.base import Match
    pack = _linux_reclaim_pack(tmp_path)
    affected, unrelated = [ev("auth", T0, user__name="alice") for _ in range(2)]
    unrelated.host = "other-host"
    tamper = ex(20, "/usr/bin/systemctl")
    tamper.fields["process.argv"].value = ["systemctl", "stop", "auditd"]
    for detector in pack:
        detector.consume([affected, unrelated, tamper])
        detector.drain_staged()
    clock = pack[-1]
    clock.observe_tamper_match(Match("host.security_or_logging_service_stop", "tamper", "observed_action",
                                   [tamper], [], tamper.ts, "high", "high", "high"))
    clock.drain_staged()
    _reclaim_linux_references(pack)
    assert pack[0].witnesses.load([affected.id]) == [affected]
    assert pack[0].witnesses.load([unrelated.id]) == []
    plan = list(clock.query("EXPLAIN QUERY PLAN SELECT 1 FROM records "
                            "WHERE role='tamper' AND host=? LIMIT 1", (affected.host,)))
    assert any("SEARCH" in row[3] and "records_tamper_host" in row[3] for row in plan)
    for detector in pack:
        detector.release_state()


def test_linux_reclaimer_scans_admission_order_once_and_accepts_later_low_id_after_emptying(tmp_path):
    pack = _linux_reclaim_pack(tmp_path)
    clock = pack[-1]
    events = [ev("auth", T0 + timedelta(seconds=i), user__name="alice") for i in range(97)]
    for event, i in zip(events, reversed(range(len(events))), strict=True):
        event.id = f"clock-{i:04}"
    clock.consume(events)
    clock.drain_staged()
    witness, queries = pack[0].witnesses, []
    witness._spill.db.set_trace_callback(queries.append)
    for _ in range(10):
        if not _reclaim_linux_references(pack):
            break
    else:
        pytest.fail("bounded reclamation did not exhaust its monotonic scan")
    assert witness.count() == 0
    scans = [query for query in queries if query.startswith("SELECT rowid,id,body FROM witnesses WHERE rowid>")]
    assert len(scans) == 5 and all("LIMIT 32" in query for query in scans)
    late = ev("auth", T0, user__name="alice")
    late.id = "000-earlier-than-all-lexical-IDs"
    clock.consume([late])
    clock.drain_staged()
    assert witness.count() == 1
    _reclaim_linux_references(pack)
    assert witness.count() == 0
    assert witness._spill.budget.physical_used <= witness._spill.budget.disk_total
    for detector in pack:
        detector.release_state()


def test_linux_reclaimer_delete_refusal_rolls_back_rows_accounting_and_scan_cursor(tmp_path):
    pack = _linux_reclaim_pack(tmp_path)
    event = ev("auth", T0, user__name="alice")
    pack[-1].consume([event])
    pack[-1].drain_staged()
    witness = pack[0].witnesses
    charged = witness.account().used
    witness._spill.write("CREATE TRIGGER no_clock_delete BEFORE DELETE ON witnesses "
                        "BEGIN SELECT RAISE(ABORT,'test delete refusal'); END", [()])
    assert _reclaim_linux_references(pack) == 0
    assert witness.load([event.id]) == [event] and witness.account().used == charged
    assert not pack[0].budget.broken
    witness._spill.write("DROP TRIGGER no_clock_delete", [()])
    _reclaim_linux_references(pack)
    assert witness.count() == 0
    for detector in pack:
        detector.release_state()
