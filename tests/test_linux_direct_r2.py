"""Direct Linux regressions for bounded positives and honest watched-read coverage."""
from datetime import timedelta

import pytest

from romulus.decide.policy import candidate_id
from romulus.detect.linux_argv import program
from romulus.detect.linux_direct import CredentialMaterialAccess, KernelModuleLoad, MasqueradingBinary
from romulus.detect.registry import fresh_direct_pack
from romulus.evidence.typed import Outcome
from tests.test_bounded_host import T0, ev


def read(path="/etc/shadow", executable="/usr/bin/python3", uid="0", t=0, host="web1", **fields):
    return ev("file_access", T0 + timedelta(seconds=t), host_name=host, file__path=path,
              file__access="read", audit__key="credential_watch", process__executable=executable,
              process__uid=uid, **fields)


def execute(path, t=0, host="web1", argv=None, **fields):
    return ev("process_exec", T0 + timedelta(seconds=t), host_name=host,
              process__executable=path, process__argv=argv or [path], **fields)


@pytest.mark.parametrize("path", [
    "/usr/sbin/cron", "/usr/sbin/crond", "/usr/sbin/anacron", "/usr/sbin/atd",
    "/usr/sbin/sshd", "/usr/lib/openssh/sshd-session", "/usr/lib/openssh/sshd-auth",
    "/usr/sbin/unix_chkpwd", "/usr/lib/polkit-1/polkit-agent-helper-1",
    "/usr/lib64/polkit-1/polkit-agent-helper-1", "/usr/bin/login", "/bin/su",
    "/usr/bin/sudo", "/usr/bin/passwd", "/usr/bin/chage", "/usr/sbin/useradd",
    "/usr/sbin/usermod", "/usr/sbin/userdel", "/usr/sbin/chpasswd", "/usr/sbin/newusers",
    "/usr/lib/systemd/systemd", "/usr/lib/systemd/systemd-userdbd", "/usr/sbin/nscd",
    "/usr/sbin/sssd", "/usr/libexec/sssd/sssd_pam",
])
def test_packaged_root_shadow_daemons_need_no_username(path):
    assert CredentialMaterialAccess().consume([read(executable=path)]) == []


@pytest.mark.parametrize("path,uid", [
    ("/usr/sbin/cron", "1000"), ("/usr/sbin/cron", None), ("/tmp/cron", "0"),
    ("/tmp/usr/sbin/sshd", "0"), ("/usr/sbin/subdir/sshd", "0"),
    ("/usr/bin/python3", "0"), ("/usr/bin/perl", "0"), ("/bin/bash", "0"),
])
def test_shadow_exclusions_cannot_hide_unprivileged_displaced_or_interpreter_reads(path, uid):
    [finding] = CredentialMaterialAccess().consume([read(executable=path, uid=uid, process__user="root")])
    assert finding.proposed_lane == "high"


@pytest.mark.parametrize("path", ["/usr/bin/tar", "/usr/bin/rsync", "/usr/bin/cmp", "/bin/cp"])
def test_packaged_root_backup_shadow_reads_remain_leads_without_write_visibility(path):
    [finding] = CredentialMaterialAccess().consume([read(executable=path)])
    assert finding.proposed_lane == "lead"
    assert "write" in " ".join(finding.notes).lower()
    assert CredentialMaterialAccess().consume([read(executable=path, uid="1000")])[0].proposed_lane == "high"


def test_shadow_lab_shaped_reads_are_bounded_and_interpreter_stays_high(tmp_path):
    detector = CredentialMaterialAccess()
    detector.spill_dir = tmp_path
    candidates = {}
    for host in ("alpha", "beta", "gamma"):
        for i in range(100):
            path = ("/usr/sbin/cron", "/usr/sbin/sshd", "/usr/sbin/unix_chkpwd")[i % 3]
            for match in detector.consume([read(executable=path, t=i, host=host)]):
                candidates[candidate_id(match, "hunt")] = match
        for i in range(50):
            for match in detector.consume([read(t=200 + i, host=host)]):
                candidates[candidate_id(match, "hunt")] = match
    assert len(candidates) == 3
    for finding in candidates.values():
        assert finding.proposed_lane == "high"
        assert finding.aggregate_summary == {"count": 50, "peak": 50, "episodes": 1, "first": (T0 + timedelta(seconds=200)).timestamp(),
                                             "last": (T0 + timedelta(seconds=249)).timestamp()}
        assert len(finding.events) == 2
        assert {event.ts for event in finding.events} == {T0 + timedelta(seconds=200), T0 + timedelta(seconds=249)}
        assert finding.bounded_revision and finding.revision_reason
    assert len(detector.folds) == 3
    detector.release_state()


def test_credential_fold_separates_host_executable_path_and_lane():
    detector = CredentialMaterialAccess()
    events = [read(), read(host="other"), read(executable="/bin/bash"), read(path="/etc/gshadow"),
              read(outcome=Outcome.failure)]
    findings = detector.consume(events)
    assert len({candidate_id(finding, "hunt") for finding in findings}) == 5
    assert sorted(finding.proposed_lane for finding in findings) == ["high"] * 4 + ["lead"]


def test_file_access_always_positive_only_and_names_watch_inventory_and_hardlinks():
    detector = CredentialMaterialAccess()
    unrelated = read(path="/etc/hosts")
    assert not detector.assures_negative_for([unrelated])
    assert detector.consume([unrelated]) == []
    reasons = " ".join([detector.positive_only_reason, *detector.partition_coverage_notes()]).lower()
    assert "watch" in reasons and "hard link" in reasons
    assert detector.consume([read()])[0].proposed_lane == "high"


@pytest.mark.parametrize("applet", ["insmod", "modprobe", "rmmod", "lsmod", "depmod", "modinfo"])
def test_kmod_dispatches_recorded_applet(applet):
    p = program(execute("/usr/bin/kmod", argv=["/sbin/" + applet, "/tmp/rk.ko"]))
    assert p.name == applet and p.args == ["/tmp/rk.ko"] and p.name_from_argv0


@pytest.mark.parametrize("executable,argv,path,lane", [
    ("/usr/bin/kmod", ["insmod", "/tmp/rk.ko"], None, "high"),
    ("/usr/sbin/insmod", ["insmod", "/tmp/rk.ko"], None, "high"),
    ("/usr/bin/kmod", ["insmod", "/lib/modules/rk.ko"], "/lib/modules/rk.ko", "lead"),
    ("/usr/bin/kmod", ["modprobe", "ext4"], None, "context"),
    ("/usr/bin/kmod", ["modprobe", "/tmp/rk.ko"], None, "high"),
    ("/tmp/modprobe", ["modprobe", "ext4"], "/lib/modules/ext4.ko", "lead"),
    ("/usr/lib/systemd/systemd-modules-load", ["systemd-modules-load"], None, "context"),
    ("/usr/lib/systemd/systemd-udevd", ["systemd-udevd"], "/usr/lib/modules/ext4.ko", "context"),
    ("/usr/bin/python3", ["python3"], None, "lead"),
    (None, None, "/lib/modules/ext4.ko", "lead"),
    ("/usr/bin/kmod", None, None, "lead"),
])
def test_module_load_needs_a_recorded_packaged_loader_for_context(executable, argv, path, lane):
    event = ev("kernel_module", T0, module__op="load", module__path=path,
               process__executable=executable, process__argv=argv)
    [finding] = KernelModuleLoad().consume([event])
    assert finding.proposed_lane == lane
    if path is None and lane == "lead":
        assert "module file not recorded" in finding.claim.lower()


@pytest.mark.parametrize("session,lane", [({}, "context"), ({"process__auid": "1000"}, "lead"),
                                          ({"process__session_id": "7"}, "lead")])
def test_a_module_an_operator_loads_from_the_package_tree_is_a_lead(session, lane):
    """A module copied into the module tree and loaded with modprobe from a login session (a planted rootkit) is the
    operator's load; only a load outside any session is the kernel's or the boot's own."""
    event = ev("kernel_module", T0, module__op="load", module__path="/lib/modules/6.1.0/extra/rk.ko",
               process__executable="/usr/bin/kmod", process__argv=["modprobe", "rk"], **session)
    [finding] = KernelModuleLoad().consume([event])
    assert finding.proposed_lane == lane


@pytest.mark.parametrize("argv,lane", [(["insmod", "/tmp/rk.ko"], "high"),
                                      (["insmod", "/lib/modules/rk.ko"], "lead"),
                                      (["modprobe", "/tmp/rk.ko"], "high")])
def test_module_argv_positive_arm_preserves_outside_path_lane(argv, lane):
    [finding] = KernelModuleLoad().consume([execute("/usr/bin/kmod", argv=argv)])
    assert finding.proposed_lane == lane and "load not proved" in finding.claim


def test_module_unload_is_unchanged():
    assert KernelModuleLoad().consume([ev("kernel_module", T0, module__op="unload")]) == []
    assert KernelModuleLoad().consume([execute("/usr/bin/kmod", argv=["rmmod", "rk"])]) == []


@pytest.mark.parametrize("path,lane", [
    ("/usr/local/sbin/sshd", "lead"), ("/usr/local/bin/bash", "lead"), ("/opt/vendor/bin/sshd", "lead"),
    ("/nix/store/abc-bash-5.2/bin/bash", None), ("/gnu/store/abc-openssh-9.1/sbin/sshd", None),
    ("/nix/store/abc-openssh/libexec/sshd", None),
    ("/nix/store/fake/bin/bash", "high"), ("/tmp/sshd", "high"), ("/dev/shm/bash", "high"),
    ("/home/alice/.cache/sshd", "high"), ("/run/user/1000/sshd", "high"),
])
def test_masquerade_admin_and_package_store_paths(path, lane):
    assert [m.proposed_lane for m in MasqueradingBinary().consume([execute(path)])] == ([lane] if lane else [])


@pytest.mark.parametrize("from_pack", [False, True])
def test_masquerade_fold_immediately_revises_same_candidate_in_sweep_and_direct_pack(from_pack, tmp_path):
    detector = (next(rule for rule in fresh_direct_pack() if rule.id == MasqueradingBinary.id)
                if from_pack else MasqueradingBinary())
    detector.spill_dir = tmp_path
    candidates = {}
    findings = []
    for i in range(20):
        [finding] = detector.consume([execute("/usr/local/sbin/sshd", t=19-i)])
        findings.append(finding)
        candidates[candidate_id(finding, "hunt")] = finding
    assert len(candidates) == 1
    final = next(iter(candidates.values()))
    assert final.proposed_lane == "lead" and final.aggregate_summary["count"] == 20
    assert {event.ts for event in final.events} == {T0, T0 + timedelta(seconds=19)}
    assert len(final.events) == 2 and final.bounded_revision and final.revision_reason
    assert not findings[0].revision_reason
    assert detector.finalize() == []
    detector.release_state()


def test_fold_keys_spill_and_reload_without_duplicate_candidates(tmp_path, monkeypatch):
    monkeypatch.setattr(MasqueradingBinary, "HOT", 2, raising=False)
    detector = MasqueradingBinary()
    detector.spill_dir = tmp_path
    candidates = {}
    for t in range(3):
        for host in range(20):
            for finding in detector.consume([execute("/tmp/sshd", t=t, host=f"host-{host}")]):
                candidates[candidate_id(finding, "hunt")] = finding
    assert detector.folds.on_disk > 0
    assert len(candidates) == 20
    assert all(finding.proposed_lane == "high" and finding.aggregate_summary["count"] == 3
               and len(finding.events) == 2 for finding in candidates.values())
    assert detector.capped == 0
    detector.release_state()


@pytest.mark.parametrize("argv", [["bash", "-c", "whoami"], ["kmod", "bash", "-c", "whoami"]])
def test_kmod_does_not_dispatch_an_unrecognized_applet(argv):
    assert program(execute("/usr/bin/kmod", argv=argv)).name == "kmod"


def test_folded_sweep_publication_replaces_witnesses_and_counts_one_candidate(monkeypatch, tmp_path):
    from romulus.hunt import sweep as sw
    from romulus.sources.models import Window
    from tests.test_sweep import FakeClient, _repo
    detector = MasqueradingBinary()
    monkeypatch.setattr(sw, "fresh_pack", lambda: [detector])
    repo = _repo()
    sweep = sw.Sweep(repo, FakeClient(), "h1", Window(start=T0, end=T0 + timedelta(minutes=5)),
                     {"host-x": None}, stage_dir=tmp_path)
    try:
        for i in range(20):
            [match] = detector.consume([execute("/tmp/sshd", t=i)])
            sweep._publish(match, None, {ref.key: {"native": event.id}
                                       for event in match.events for ref in event.raw})
        [candidate] = repo.candidates("h1")
        assert candidate["lane"] == "high"
        assert candidate["gate_results"]["aggregate_summary"]["count"] == 20
        assert len(candidate["event_ids"]) == 2
        assert sweep.stats["candidates"] == 1
    finally:
        detector.release_state()
        sweep.close_stage()
        repo.engine.dispose()


def test_watched_only_sweep_partition_is_positive_only_with_reason(monkeypatch):
    from datetime import UTC, datetime

    from romulus.hunt import sweep as sw
    from romulus.sources.models import Completeness, SearchOutcome, Window
    from tests.test_kernel_records import cwd, group, path, syscall
    from tests.test_sweep import FakeClient, _repo
    records = group(syscall(501, 257, "openat", a2="0"), path(501, 0, "/etc/hosts", "NORMAL"), cwd(501))
    def fetch(client, intent, contract):
        now = datetime.now(UTC)
        return SearchOutcome(target=intent.target, fingerprint="f", started_at=now, ended_at=now,
                             completeness=Completeness.complete, total=len(records), total_relation="eq",
                             returned=len(records), records=records)
    monkeypatch.setattr(sw, "execute", fetch)
    monkeypatch.setattr(sw, "fresh_pack", lambda: [CredentialMaterialAccess()])
    repo = _repo()
    start = datetime(2030, 1, 6, 9, 0, tzinfo=UTC)
    window = Window(start=start, end=start + timedelta(minutes=5))
    sweep = sw.Sweep(repo, FakeClient(), "h1", window, {"romulus-host-x": None})
    try:
        sweep.run_partition("romulus-host-x", None, [], window, est=len(records))
        [cell] = repo.rule_cells("h1")
        assert cell["state"] == "positive_only"
        reason = " ".join(cell["detail"]["reasons"]).lower()
        assert "watch inventories" in reason and "hard links" in reason
        assert not repo.candidates("h1")
    finally:
        sweep.close_stage()
        repo.engine.dispose()
