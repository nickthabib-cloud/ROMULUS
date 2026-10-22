"""Fixtures for account and group creation or modification. Hosts, accounts and paths are invented."""
from datetime import UTC, datetime, timedelta

import pytest

from romulus.detect.auth import AccountOrGroupChange, account_command
from romulus.detect.registry import ALL_PLAYBOOKS
from romulus.evidence.typed import Outcome, RawRef, TypedEvent, fv

T0 = datetime(2030, 1, 6, 9, 0, tzinfo=UTC)
_n = 0
USERS = {"0": "root", "33": "www-data", "1000": "alice"}


def ev(family, ts=T0, outcome=Outcome.success, host="app01", **fields):
    global _n
    _n += 1
    f = {k.replace("__", "."): fv(v, f"fixture{_n}:{k}") for k, v in fields.items() if v is not None}
    return TypedEvent(id=f"a{_n:05d}", family=family, ts=ts, host=host, outcome=outcome, fields=f,
                      raw=[RawRef(target="fx", native_id=f"r{_n}")], normalizer="fixture")


def ex(argv, exe=None, uid="0", pid=7001, ppid=7000, ts=T0, outcome=Outcome.success, login=None, **kw):
    exe = exe if exe is not None else f"/usr/sbin/{argv[0].rsplit('/', 1)[-1]}"
    return ev("process_exec", ts, outcome, process__argv=argv, process__executable=exe or None, process__uid=uid,
              process__user=USERS.get(uid), process__pid=pid, process__ppid=ppid, process__login_user=login, **kw)


def record(record_type, action, ts=T0, pid=7001, outcome=Outcome.success, **kw):
    return ev("account_change", ts, outcome, audit__record_type=record_type, account__action=action,
              process__pid=pid, **kw)


def run(*partitions):
    pb = AccountOrGroupChange()
    for part in partitions:
        assert pb.consume(list(part)) == []
    return pb, pb.finalize()


# ---------------------------------------------------------------- grammar
@pytest.mark.parametrize("name,args,action,accounts,groups,privileged", [
    ("useradd", ["-o", "-u", "0", "-m", "backdoor"], "create_user", ("backdoor",), (), "user id 0"),
    ("useradd", ["-ou0", "backdoor"], "create_user", ("backdoor",), (), "user id 0"),
    ("useradd", ["--uid=0", "--non-unique", "backdoor"], "create_user", ("backdoor",), (), "user id 0"),
    ("useradd", ["-m", "-s", "/bin/bash", "alice"], "create_user", ("alice",), (), ""),
    ("useradd", ["-G", "sudo,adm", "eve"], "add_to_group", ("eve",), ("sudo", "adm"), "privileged group(s) sudo"),
    ("usermod", ["-aG", "sudo", "bob"], "add_to_group", ("bob",), ("sudo",), "sudo"),
    ("usermod", ["-a", "-G", "wheel", "bob"], "add_to_group", ("bob",), ("wheel",), "wheel"),
    ("usermod", ["--append", "--gro=docker", "bob"], "add_to_group", ("bob",), ("docker",), "docker"),
    ("usermod", ["-aG", "video", "bob"], "add_to_group", ("bob",), ("video",), ""),
    ("usermod", ["-u", "0", "-o", "bob"], "modify_user", ("bob",), (), "user id 0"),
    ("usermod", ["-L", "carol"], "modify_user", ("carol",), (), ""),
    ("userdel", ["-r", "dave"], "delete_user", ("dave",), (), ""),
    ("groupadd", ["-g", "0", "-o", "rootish"], "create_group", (), ("rootish",), "primary group root"),
    ("gpasswd", ["-a", "bob", "sudo"], "add_to_group", ("bob",), ("sudo",), "sudo"),
    ("gpasswd", ["-d", "bob", "sudo"], "remove_from_group", ("bob",), ("sudo",), ""),
    ("passwd", ["root"], "password_change", ("root",), (), ""),
    ("passwd", ["-d", "svc"], "password_change", ("svc",), (), ""),
    ("chpasswd", [], "password_change", (), (), ""),
    ("chage", ["-E", "-1", "svc"], "expiry_change", ("svc",), (), ""),
    ("adduser", ["bob", "sudo"], "add_to_group", ("bob",), ("sudo",), "sudo"),
    ("adduser", ["--system", "--group", "svc"], "create_user", ("svc",), (), ""),
    ("adduser", ["--uid", "0", "evil"], "create_user", ("evil",), (), "user id 0"),
    ("addgroup", ["bob", "lxd"], "add_to_group", ("bob",), ("lxd",), "lxd"),
    ("deluser", ["bob", "sudo"], "remove_from_group", ("bob",), ("sudo",), ""),
    ("vipw", ["-s"], "account_db_edit", (), (), ""),
])
def test_account_tool_grammar(name, args, action, accounts, groups, privileged):
    forms, uncertain = account_command(name, args)
    form = next(f for f in forms if f.action == action)
    assert form.accounts == accounts and form.groups == groups and not uncertain
    assert (privileged in form.privileged) if privileged else form.privileged == ""


def test_busybox_adduser_grammar_differs_from_debian():
    forms, _ = account_command("adduser", ["-h", "/home/x", "-u", "0", "x"], busybox=True)
    assert forms[0].action == "create_user" and "user id 0" in forms[0].privileged
    assert account_command("adduser", ["-h"])[0] == []                  # Debian adduser: help


@pytest.mark.parametrize("name,args", [
    ("useradd", ["--help"]), ("useradd", ["-h"]), ("useradd", ["-D"]), ("passwd", ["-S", "root"]),
    ("passwd", ["--status", "root"]), ("chage", ["-l", "bob"]), ("usermod", ["bob"]), ("adduser", ["--version"]),
    ("grep", ["useradd", "/var/log/auth.log"]),
])
def test_read_only_and_unrelated_invocations_ask_for_nothing(name, args):
    assert account_command(name, args)[0] == []


def test_useradd_defaults_change_is_a_form():
    forms, _ = account_command("useradd", ["-D", "-s", "/bin/sh"])
    assert [f.action for f in forms] == ["defaults_change"]


def test_flag_value_cannot_hide_the_login_or_fake_one():
    forms, _ = account_command("useradd", ["-c", "-u 0 not-a-flag", "carol"])
    assert forms[0].accounts == ("carol",) and forms[0].privileged == ""


# ---------------------------------------------------------------- rule: lanes and claims
def test_uid0_account_creation_is_high_and_says_command_not_change():
    out = run([ex(["useradd", "-o", "-u", "0", "-m", "backdoor"], login="alice")])[1]
    assert len(out) == 1
    m = out[0]
    assert (m.proposed_lane, m.severity) == ("high", "high")
    assert "account 'root' (audit login user 'alice') ran 1 command(s) to create account 'backdoor'" in m.claim
    assert "user id 0" in m.claim and "whether the account database changed is not established" in m.claim
    assert "T1136.001" in m.notes


def test_tool_audit_record_of_the_same_process_reports_the_change():
    cmd = ex(["useradd", "-m", "alice2"], pid=7101)
    rec = record("ADD_USER", "create_user", ts=T0 + timedelta(milliseconds=40), pid=7101, account__op="add-user",
                 account__name="alice2", process__executable="/usr/sbin/useradd")
    out = run([cmd, rec])[1]
    assert len(out) == 1 and out[0].proposed_lane == "lead" and out[0].confidence == "high"
    assert "ADD_USER op=add-user acct=alice2 res=success" in out[0].claim
    assert {e.id for e in out[0].events} == {cmd.id, rec.id}


def test_record_only_privileged_group_add_is_high():
    rec = record("USER_MGMT", "modify_user", pid=9001, account__op="add-user-to-group", account__group="sudo",
                 account__name="mallory", process__executable="/usr/sbin/usermod", process__login_user="alice")
    m = run([rec])[1][0]
    assert m.proposed_lane == "high" and "membership of privileged group sudo" in m.claim
    assert "written by '/usr/sbin/usermod' as alice" in m.claim


def test_lab_like_password_changes_from_chpasswd_are_a_lead():
    recs = [record("USER_CHAUTHTOK", "password_change", ts=T0 + timedelta(minutes=i), pid=8000 + i,
                   account__op="PAM:chauthtok", account__name="svc", process__executable="/usr/sbin/chpasswd",
                   process__user="root") for i in range(4)]
    out = run(recs)[1]
    assert len(out) == 1 and out[0].proposed_lane == "lead" and "4 account-management audit record(s)" in out[0].claim


def test_web_service_lineage_raises_an_ordinary_creation_to_high():
    shell = ex(["sh", "-c", "sudo useradd helper"], exe="/usr/bin/dash", uid="33", pid=4000, ppid=3999)
    sudo = ex(["sudo", "useradd", "helper"], exe="/usr/bin/sudo", uid="33", pid=4001, ppid=4000,
              ts=T0 + timedelta(milliseconds=5))
    child = ex(["useradd", "helper"], pid=4002, ppid=4001, ts=T0 + timedelta(milliseconds=10))
    out = run([shell, sudo, child])[1]
    assert len(out) == 1
    m = out[0]
    assert m.proposed_lane == "high" and "web-service account 'www-data'" in m.claim
    assert m.events == [child]                          # the parent shell's text and the sudo wrapper are not actions


def test_package_lineage_is_one_grouped_lead_per_host():
    dpkg = ex(["dpkg", "--configure", "-a"], exe="/usr/bin/dpkg", pid=100, ppid=90)
    script = ex(["/bin/sh", "/var/lib/dpkg/info/svc.postinst", "configure"], exe="/usr/bin/dash", pid=101, ppid=100)
    adduser = ex(["adduser", "--system", "--group", "svc"], exe="/usr/sbin/adduser", pid=102, ppid=101)
    useradd = ex(["useradd", "-r", "-M", "svc"], pid=103, ppid=102)
    groupadd = ex(["groupadd", "-r", "svc"], pid=104, ppid=102)
    out = run([dpkg, script, adduser, useradd, groupadd])[1]
    assert len(out) == 1
    m = out[0]
    assert m.proposed_lane == "lead" and "made under package management" in m.claim and "'svc'" in m.claim
    assert m.group_key == "lineage|app01|package"


def test_privileged_request_under_package_lineage_is_not_grouped_away():
    dpkg = ex(["dpkg", "-i", "x.deb"], exe="/usr/bin/dpkg", pid=200, ppid=190)
    evil = ex(["useradd", "-o", "-u", "0", "pkgroot"], pid=201, ppid=200)
    out = run([dpkg, evil])[1]
    assert [m.proposed_lane for m in out] == ["high"] and "package management" in out[0].claim


@pytest.mark.parametrize("argv,exe", [
    (["grep", "useradd", "/var/log/auth.log"], "/usr/bin/grep"),
    (["man", "useradd"], "/usr/bin/man"),
    (["echo", "useradd", "-u", "0", "x"], "/usr/bin/echo"),
    (["useradd", "--help"], None),
    (["useradd", "-D"], None),
    (["passwd", "-S", "root"], "/usr/bin/passwd"),
    (["chage", "-l", "bob"], "/usr/bin/chage"),
    (["apt", "list", "--installed", "passwd"], "/usr/bin/apt"),
    (["sudo", "useradd", "x"], "/usr/bin/sudo"),
    (["sh", "-c", "useradd -o -u 0 x"], "/usr/bin/dash"),
    (["less", "/usr/share/doc/passwd/README"], "/usr/bin/less"),
])
def test_mentions_read_only_runs_and_wrappers_are_not_changes(argv, exe):
    assert run([ex(argv, exe=exe)])[1] == []


def test_failed_privileged_command_is_lowered_to_lead():
    m = run([ex(["usermod", "-aG", "sudo", "bob"], outcome=Outcome.failure)])[1][0]
    assert m.proposed_lane == "lead" and "1 failed" in m.claim
    assert "lane lowered: every recorded exec or tool result failed" in m.notes


def test_missing_fields_are_partial_not_silent():
    pb, out = run([ex(["useradd", "x"], exe=""), ev("process_exec", process__user="root"),
                   record("ADD_USER", None, pid=1)])
    assert pb.missing_required == 3
    assert len(out) == 1 and "create account 'x'" in out[0].claim     # argv[0] identity still yields the lead


def test_record_outside_the_join_window_is_its_own_finding():
    cmd = ex(["useradd", "late"], pid=7201)
    rec = record("ADD_USER", "create_user", ts=T0 + timedelta(seconds=10.5), pid=7201, account__name="late")
    out = run([cmd, rec])[1]
    assert len(out) == 2
    rec_in = record("ADD_USER", "create_user", ts=T0 + timedelta(seconds=10), pid=7201, account__name="late")
    assert len(run([cmd, rec_in])[1]) == 1


def test_cloud_init_run_by_its_python_interpreter_marks_the_lineage_of_its_password_tool():
    agent = ex(["/usr/bin/python3", "/usr/bin/cloud-init", "modules", "--mode=config"], exe="/usr/bin/python3.12",
               pid=500, ppid=1)
    tool = ex(["chpasswd", "-e"], pid=501, ppid=500, ts=T0 + timedelta(seconds=3))
    recs = [record("USER_CHAUTHTOK", "password_change", ts=T0 + timedelta(seconds=3, milliseconds=i), pid=501,
                   account__op="PAM:chauthtok", account__name=name, process__executable="/usr/sbin/chpasswd")
            for i, name in enumerate(("root", "ops"))]
    out = run([agent, tool, *recs])[1]
    assert [m.group_key for m in out] == ["lineage|app01|cloud-init"]
    assert "made under cloud-init" in out[0].claim and out[0].proposed_lane == "lead"
    # the same program name outside the system directories marks nothing
    fake = ex(["/usr/bin/python3", "/tmp/cloud-init", "modules"], exe="/usr/bin/python3.12", pid=600, ppid=1)
    out = run([fake, ex(["chpasswd"], pid=601, ppid=600, ts=T0 + timedelta(seconds=3))])[1]
    assert [m.group_key.split("|")[0] for m in out] == ["actor"]


# ---------------------------------------------------------------- boot-time provisioning (no exec lineage)
def boot(ts=T0, host="app01"):
    return ev("system_state", ts, host=host, audit__record_type="SYSTEM_BOOT", system__event="boot")


def first_boot_passwords(start=T0 + timedelta(seconds=40), host="app01", accounts=("root", "ops"), **kw):
    """A provisioning agent's bulk password tool at first boot, before exec auditing was in place: the tool's own
    records arrive, its exec records do not."""
    return [record("USER_CHAUTHTOK", "password_change", ts=start + timedelta(seconds=i), pid=900 + i, host=host,
                   account__op="PAM:chauthtok", account__name=name, process__executable="/usr/sbin/chpasswd",
                   process__user="root", **kw) for i, name in enumerate(accounts)]


def test_boot_time_changes_outside_any_login_are_one_lead_per_host_and_boot_worded_as_provisioning():
    marker = boot()
    out = run([marker, *first_boot_passwords()])[1]
    assert len(out) == 1
    m = out[0]
    assert m.proposed_lane == "lead" and m.severity == "high" and m.group_key == f"boot|app01|{marker.id}"
    assert ("On app01, 2 account or group change(s) were made from 40 s to 41 s after the host's recorded boot at "
            "2030-01-06T09:00:00+00:00 (audit SYSTEM_BOOT), with no audit login uid recorded on any of them") in m.claim
    assert "a password was changed (account 'root'); a password was changed (account 'ops')" in m.claim
    assert "written by '/usr/sbin/chpasswd'" in m.claim
    assert "No exec record of the changing process was retrieved" in m.claim
    assert "Boot-time provisioning (cloud-init or a first-boot script setting initial passwords" in m.claim
    assert "so does a job an intruder set to run at boot" in m.claim
    assert marker.id in {e.id for e in m.events}


def test_each_host_and_each_boot_is_its_own_group():
    late_boot = boot(T0 + timedelta(hours=3))
    out = run([boot(), boot(host="app02"), late_boot, *first_boot_passwords(),
               *first_boot_passwords(host="app02"),
               *first_boot_passwords(start=T0 + timedelta(hours=3, seconds=30), accounts=("ops",))])[1]
    assert sorted(m.group_key.rsplit("|", 1)[0] for m in out) == ["boot|app01", "boot|app01", "boot|app02"]


def test_boot_window_is_half_open_and_far_or_missing_boots_keep_the_ordinary_findings():
    edge = first_boot_passwords(start=T0 + timedelta(seconds=AccountOrGroupChange.BOOT_SECONDS), accounts=("ops",))
    out = run([boot(), *edge])[1]
    assert [m.group_key.split("|")[0] for m in out] == ["actor"]
    inside = first_boot_passwords(start=T0 + timedelta(seconds=AccountOrGroupChange.BOOT_SECONDS)
                                  - timedelta(microseconds=1), accounts=("ops",))
    assert [m.group_key.split("|")[0] for m in run([boot(), *inside])[1]] == ["boot"]
    # no boot record at all: one finding per account, worded with what is and is not known
    out = run(first_boot_passwords())[1]
    assert len(out) == 2 and all(m.group_key.startswith("actor|") for m in out)
    assert all("No exec record of the changing process was retrieved, so what started it is unknown" in m.claim
               and "no audit login uid is recorded on it" in m.claim for m in out)


def test_a_login_sessions_change_at_boot_is_not_grouped_as_boot_time():
    recs = first_boot_passwords(process__login_user="alice", process__auid="1000")
    out = run([boot(), *recs])[1]
    assert len(out) == 2 and all(m.group_key.startswith("actor|") for m in out)
    assert all("Boot-time provisioning" not in m.claim for m in out)


def test_privileged_or_web_changes_at_boot_are_never_grouped_away():
    uid0 = ex(["useradd", "-o", "-u", "0", "-m", "backdoor"], pid=950, ts=T0 + timedelta(seconds=50))
    web_shell = ex(["sh", "-c", "sudo useradd helper"], exe="/usr/bin/dash", uid="33", pid=960, ppid=959,
                   ts=T0 + timedelta(seconds=60))
    web_child = ex(["useradd", "helper"], pid=961, ppid=960, ts=T0 + timedelta(seconds=60, milliseconds=5))
    out = run([boot(), *first_boot_passwords(), uid0, web_shell, web_child])[1]
    lanes = sorted((m.group_key.split("|")[0], m.proposed_lane) for m in out)
    assert lanes == [("actor", "high"), ("actor", "high"), ("boot", "lead")]
    backdoor = next(m for m in out if "backdoor" in m.claim)
    assert "user id 0" in backdoor.claim and "Boot-time" not in backdoor.claim


@pytest.mark.parametrize("argv,exe,lane,text", [
    (["bash", "-c", "echo 'evil:x:0:0::/root:/bin/bash' >> /etc/passwd"], "/usr/bin/bash", "high",
     "write /etc/passwd with a shell redirect ('>>')"),
    (["bash", "-c", "echo 'svc:x:999:999::/srv:/usr/sbin/nologin' >> /etc/passwd"], "/usr/bin/bash", "lead",
     "write /etc/passwd with a shell redirect"),
    (["bash", "-c", "printf 'sudo:x:27:alice,evil\\n' > /etc/group"], "/usr/bin/bash", "high",
     "membership of privileged group sudo"),
    (["sed", "-i", "s/^bob:x:1001:/bob:x:0:/", "/etc/passwd"], "/usr/bin/sed", "lead", "write /etc/passwd directly"),
    (["cp", "/tmp/passwd.new", "/etc/passwd"], "/usr/bin/cp", "lead", "write /etc/passwd directly"),
    (["tee", "-a", "/etc/group"], "/usr/bin/tee", "lead", "write /etc/group directly"),
    (["vi", "/etc/shadow"], "/usr/bin/vim.basic", "lead", "write /etc/shadow directly"),
])
def test_direct_writes_to_account_files(argv, exe, lane, text):
    out = run([ex(argv, exe=exe)])[1]
    assert len(out) == 1 and out[0].proposed_lane == lane and text in out[0].claim
    assert "whether the account database changed is not established" in out[0].claim


@pytest.mark.parametrize("argv,exe", [
    (["cat", "/etc/passwd"], "/usr/bin/cat"), (["grep", "root", "/etc/shadow"], "/usr/bin/grep"),
    (["cp", "/etc/passwd", "/tmp/p"], "/usr/bin/cp"), (["bash", "-c", "getent passwd > /tmp/users"], "/usr/bin/bash"),
    (["bash", "-c", "echo x >> /etc/passwd.bak"], "/usr/bin/bash"), (["chmod", "644", "/etc/passwd"], "/usr/bin/chmod"),
    (["bash", "-c", "echo 'echo x >> /etc/passwd'"], "/usr/bin/bash"),
])
def test_reads_copies_out_and_mentions_of_account_files_are_not_writes(argv, exe):
    assert run([ex(argv, exe=exe)])[1] == []


def test_registered_with_card_and_valid_attack_ids():
    import gzip
    import json
    from pathlib import Path
    cls = AccountOrGroupChange
    assert cls in ALL_PLAYBOOKS and not cls.assures_negative and cls.positive_only_reason
    assert {"behavior", "telemetry", "fidelity", "lanes", "research_basis", "retrieval"} <= set(cls.card)
    with gzip.open(Path(__file__).resolve().parents[1] / "content/attack/enterprise-attack-20.0.json.gz") as fh:
        stix = json.load(fh)
    ids = {ref["external_id"] for obj in stix["objects"] if obj.get("type") == "attack-pattern"
           and not obj.get("revoked") and not obj.get("x_mitre_deprecated")
           for ref in obj.get("external_references", []) if ref.get("source_name") == "mitre-attack"}
    assert set(cls.attack) <= ids
