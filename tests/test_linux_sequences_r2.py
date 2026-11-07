"""Temporal findings retain their evidence without turning routine sessions into floods."""
from datetime import timedelta

import pytest

from romulus.detect.linux_sequences import SCRIPT_SUFFIXES
from romulus.evidence.typed import fv
from romulus.hunt.sweep import Sweep
from tests.test_bounded_host import T0, ev
from tests.test_linux_closeout import change, downloader, rule


def execution(t=0, path="/usr/bin/ls", host="h", pid=42, ppid=1, uid="1000", **fields):
    return ev("process_exec", T0 + timedelta(seconds=t), host_name=host,
              process__executable=path, process__argv=[path], process__pid=pid, process__ppid=ppid,
              process__uid=uid, process__euid=fields.pop("euid", uid), **fields)


def detector(name, events, tmp_path):
    r = rule(name)()
    r.spill_dir = tmp_path
    r.consume(events)
    r.drain_staged()
    r.bind_loader(lambda ids: [])
    return r


@pytest.mark.parametrize("missing", ["anchor", "support", "all"])
def test_missing_citation_isolated_to_computed_group(missing, tmp_path):
    pairs = [[downloader(host=h), execution(20, "/tmp/payload", host=h)] for h in ("a", "b", "c")]
    r = detector("host.download_then_execute", [event for pair in pairs for event in pair], tmp_path)
    gone = pairs[0] if missing == "all" else [pairs[0][missing == "support"]]
    r.witnesses._spill.db.executemany("DELETE FROM witnesses WHERE id=?", [(e.id,) for e in gone])
    out = list(Sweep._finalize_rule(r))
    assert len(out) == 3
    assert {m.proposed_lane for m in out} == {"high"}
    assert sum(m.citation_unavailable for m in out) == 1
    assert all(len(m.events) == 2 for m in out if not m.citation_unavailable)
    assert all(e.id in out[0].claim for e in gone)


def test_uncited_revision_retains_group_and_lane(tmp_path):
    events = [downloader(host="h"), execution(20, "/tmp/payload")]
    r = detector("host.download_then_execute", events, tmp_path)
    first = next(iter(r.finalize()))
    r.witnesses._spill.db.execute("DELETE FROM witnesses")
    revision = next(iter(r.finalize()))
    assert revision.citation_unavailable and revision.bounded_revision
    assert revision.group_key == first.group_key and revision.proposed_lane == "high"


def test_deploy_rewrites_do_not_use_unrelated_sendmail_as_urgent(tmp_path):
    writes = [change(path=p, kind="content", user="deploy") for p in
              ("/var/www/html/index.php", "/var/www/html/plugins/a/index.php", "/var/www/html/themes/b/index.php")]
    request = ev("http_access", T0 + timedelta(seconds=300), url__path="/index.php", http__response__status_code=200)
    mail = execution(600, "/bin/sh", process__user="www-data")
    mail.fields["process.argv"].value = ["sh", "-c", "/usr/sbin/sendmail -t -i"]
    r = detector("host.web_shell_chain", [*writes, request, mail], tmp_path)
    assert {m.proposed_lane for m in r.finalize()} == {"lead"}


def test_web_upload_exact_docroot_and_fpm_lineage(tmp_path):
    write = change(path="/srv/www/site-a/uploads/shell.php", user="www-data")
    write.fields["http.document_root"] = fv("/srv/www/site-a", "fixture")
    request = ev("http_access", T0 + timedelta(seconds=10), url__path="/uploads/shell.php",
                 http__document_root="/srv/www/site-a", http__response__status_code=200)
    master = execution(-10, "/usr/sbin/php-fpm8.2", host="web1", pid=10, uid="0")
    worker = execution(-5, "/usr/sbin/php-fpm8.2", host="web1", pid=11, ppid=10, uid="33")
    child = execution(20, "/bin/bash", host="web1", pid=12, ppid=11, uid="33", process__user="www-data")
    r = detector("host.web_shell_chain", [master, worker, write, request, child], tmp_path)
    out = list(r.finalize())
    assert len(out) == 1 and out[0].proposed_lane == "urgent"
    assert {worker.id, child.id} <= {e.id for e in out[0].events}


def test_web_basename_fallback_is_lead_and_static_requests_not_stored(tmp_path):
    write = change(path="/var/www/html/shell.php", user="www-data")
    requests = [ev("http_access", T0 + timedelta(seconds=10), url__path=p, http__response__status_code=200)
                for p in ("/other/shell.php", "/theme.css", "/photo.jpg")]
    r = detector("host.web_shell_chain", [write, *requests], tmp_path)
    assert [m.proposed_lane for m in r.finalize()] == ["lead"]
    assert r.query("SELECT COUNT(*) FROM records WHERE role='request'").fetchone()[0] == 1
    assert ".sh" in SCRIPT_SUFFIXES


def test_ssh_ancestor_does_not_broker_later_writable_lpe(tmp_path):
    events = [execution(0, "/usr/sbin/sshd", pid=10, uid="0"),
              execution(1, "/bin/bash", pid=11, ppid=10),
              execution(2, "/tmp/exploit", pid=12, ppid=11),
              execution(3, "/bin/bash", pid=13, ppid=12, uid="0", process__auid="1000")]
    r = detector("host.unbrokered_privilege_transition", events, tmp_path)
    assert [m.proposed_lane for m in r.finalize()] == ["high"]


def test_prewindow_root_commands_fold_by_host_and_session(tmp_path):
    events = [execution(i, host=h, pid=1000+i, ppid=500, uid="0", process__auid="1000")
              for h in ("a", "b", "c") for i in range(2000)]
    r = detector("host.unbrokered_privilege_transition", events, tmp_path)
    out = list(r.finalize())
    assert len(out) == 3 and {m.proposed_lane for m in out} == {"lead"}
    assert all(m.aggregate_summary["count"] == 2000 and "before the window" in m.claim for m in out)


@pytest.mark.parametrize("unset", [None, "4294967295"])
def test_web_daemon_discovery_without_login_session_is_high(unset, tmp_path):
    events = [execution(i, f"/usr/bin/{name}", uid="33", process__user="www-data",
                        process__session_id=unset, process__auid=unset)
              for i, name in enumerate(("whoami", "uname", "ss", "ps", "tree", "id"))]
    r = detector("host.discovery_burst", events, tmp_path)
    assert [m.proposed_lane for m in r.finalize()] == ["high"]
    assert r.missing_required == 0


def test_ansible_cleanup_is_context_and_folded(tmp_path):
    events = []
    for i in range(30):
        path = f"/home/ansible/.ansible/tmp/ansible-tmp-{i}/AnsiballZ_setup.py"
        e = execution(i * 60, "/usr/bin/python3", host="web1", process__user="ansible")
        e.fields["process.argv"].value = ["python3", path]
        events += [e, change(i * 60 + 5, path, "delete", user="ansible")]
    out = list(detector("host.tool_cleanup", events, tmp_path).finalize())
    assert len(out) == 1 and out[0].proposed_lane == "context" and out[0].aggregate_summary["count"] == 30


def test_host_time_web_account_alert_is_folded_lead(tmp_path):
    alert = ev("net_alert", T0, source__ip="8.8.8.8", destination__ip="10.0.0.9",
               destination__port=80, alert__severity=1, alert__signature="probe")
    events = [alert]
    for i in range(20):
        events.append(execution(i + 1, "/usr/bin/worker", process__user="www-data", host__ip=["10.0.0.9"]))
    out = list(detector("corr.alert_then_host_execution", events, tmp_path).finalize())
    assert len(out) == 1 and out[0].proposed_lane == "lead"


def test_clock_is_binned_and_retains_only_edge_sources(tmp_path):
    r = detector("host.telemetry_gap_after_tamper", [execution(i / 10) for i in range(2000)], tmp_path)
    assert r.query("SELECT COUNT(*) FROM clock").fetchone()[0] == 1
    assert r.witnesses is None or r.witnesses.count() == 0


@pytest.mark.parametrize("kind", ["before", "wrong_root", "wrong_url"])
def test_web_request_must_follow_and_belong_to_the_written_site(kind, tmp_path):
    write = change(path="/srv/www/a/shell.php", user="www-data", http__document_root="/srv/www/a")
    request = ev("http_access", T0 + timedelta(seconds=-1 if kind == "before" else 20),
                 url__path="/other/shell.php" if kind == "wrong_url" else "/shell.php",
                 http__document_root="/srv/www/b" if kind == "wrong_root" else "/srv/www/a",
                 http__response__status_code=200)
    out = list(detector("host.web_shell_chain", [request, write], tmp_path).finalize())
    assert not any(m.proposed_lane in {"high", "urgent"} for m in out)
    assert all(request.id not in {e.id for e in m.events} for m in out)


def test_two_vhosts_without_request_site_identity_cannot_both_be_high(tmp_path):
    writes = [change(path=f"/srv/www/{site}/shell.php", user="www-data", http__document_root=f"/srv/www/{site}")
              for site in ("a", "b")]
    request = ev("http_access", T0 + timedelta(seconds=20), url__path="/shell.php", http__response__status_code=200)
    out = list(detector("host.web_shell_chain", [*writes, request], tmp_path).finalize())
    assert {m.proposed_lane for m in out} == {"lead"}


@pytest.mark.parametrize("broker", ["sudo", "su", "pkexec", "doas", "run0", "cron", "systemd", "sshd"])
def test_immediate_packaged_broker_root_shell_and_children_are_not_lpe(broker, tmp_path):
    events = [execution(0, f"/usr/bin/{broker}", pid=10, uid="0"),
              execution(1, "/bin/bash", pid=11, ppid=10, uid="0", process__auid="1000"),
              execution(2, "/usr/bin/id", pid=12, ppid=11, uid="0", process__auid="1000")]
    # The helper itself is an observed elevation helper, rather than an unexplained root shell.
    r = detector("host.unbrokered_privilege_transition", events, tmp_path)
    assert not list(r.finalize())


def test_packaged_passwd_effective_root_is_not_a_root_shell_transition(tmp_path):
    event = execution(0, "/usr/bin/passwd", euid="0", process__auid="1000")
    assert not list(detector("host.unbrokered_privilege_transition", [event], tmp_path).finalize())


def gap_detector(events, tmp_path):
    from romulus.detect.base import Match
    tamper = ev("audit_config", T0, audit__serial=1, audit__config__op="remove_rule")
    r = detector("host.telemetry_gap_after_tamper", [tamper, *events], tmp_path)
    r.observe_tamper_match(Match("host.audit_rules_tamper", "recorded tamper", "observed_action",
                               [tamper], [], T0, "high", "high", "high"))
    r.drain_staged()
    return r


def test_other_family_only_after_resumption_does_not_prove_gap_continuity(tmp_path):
    resumed = ev("process_observed", T0 + timedelta(minutes=20), audit__serial=2)
    outside = ev("auth", T0 + timedelta(hours=1), journal__identifier="sshd")
    assert not list(gap_detector([resumed, outside], tmp_path).finalize())


def test_gap_missing_edge_citation_keeps_uncited_positive(tmp_path):
    continued = ev("auth", T0 + timedelta(minutes=20), journal__identifier="sshd")
    r = gap_detector([continued], tmp_path)
    [first] = list(r.finalize())
    r.query("DELETE FROM clock WHERE key='journald'")
    # Detection state still knows the edge times; only its source body is unavailable.
    r.query("INSERT INTO clock VALUES(?,?,?,?,?,?,?,?,?)", ("web1", "journald", 1, continued.id,
            continued.ts.timestamp(), b"Pmissing", continued.id, continued.ts.timestamp(), b"Pmissing"))
    [revision] = list(r.finalize())
    assert first.proposed_lane == revision.proposed_lane == "lead"
    assert revision.citation_unavailable and revision.group_key == first.group_key


def test_uncited_revision_is_actually_published_without_retracting_original(monkeypatch, tmp_path):
    from romulus.hunt import sweep as sw
    from romulus.sources.models import Window
    from tests.test_sweep import FakeClient, _repo
    r = detector("host.download_then_execute", [downloader(host="h"), execution(20, "/tmp/payload")], tmp_path)
    monkeypatch.setattr(sw, "fresh_pack", lambda: [r])
    repo = _repo()
    sweep = sw.Sweep(repo, FakeClient(), "h1", Window(start=T0, end=T0 + timedelta(minutes=5)),
                     {"host-x": None}, stage_dir=tmp_path)
    try:
        [first] = list(r.finalize())
        sweep._publish(first, None, {ref.key: {"native": e.id} for e in first.events for ref in e.raw})
        r.witnesses._spill.db.execute("DELETE FROM witnesses")
        r.bind_loader(lambda ids: [])
        r.persisted_loader = lambda ids: []
        [revision] = list(r.finalize())
        sweep._publish(revision, None, {})
        [candidate] = repo.candidates("h1")
        assert candidate["lane"] == "high" and "Citation coverage is partial" in candidate["claim"]
        assert candidate["gate_results"]["_revision"]["count"] == 1
    finally:
        r.release_state()
        sweep.close_stage()
        repo.engine.dispose()


def test_clock_edge_pointer_rehydrates_typed_nonexec_and_verifies_source_digest(tmp_path):
    from romulus.detect.host import bind_lineage_citation_loader
    from romulus.evidence.normalize import normalize_hits
    from romulus.hunt.publish import LineageCitationFetcher
    from tests.test_kernel_records import cwd, group, path, syscall
    from tests.test_lineage_citation_pointers import _Source
    hits = group(syscall(901, 257, "openat", a2="0"), path(901, 0, "/etc/hosts", "NORMAL"), cwd(901))
    events, _skips, errors = normalize_hits(hits)
    assert not errors
    event = next(e for e in events if e.family == "file_access")
    r = rule("host.telemetry_gap_after_tamper")()
    r.spill_dir = tmp_path
    r.bind_raw({f"{hit['_index']}/{hit['_id']}": hit["_source"] for hit in hits}, "clock-target")
    r.consume([event])
    r.drain_staged()
    source = _Source(hits)
    bind_lineage_citation_loader([r], LineageCitationFetcher(source, {"clock-target": object()}).load)
    assert r.clock_event(event.id) == [event]
    assert r.witnesses is None
    assert len(source.calls) == 1
    hits[0]["_source"]["extra"] = "changed after pointer capture"
    assert not r.clock_event(event.id)


@pytest.mark.parametrize("broker", ["systemd", "sshd", "cron", "crond", "sshd-session", "polkitd"])
def test_nonroot_service_name_cannot_broker_root_gain(broker, tmp_path):
    events = [execution(0, f"/usr/bin/{broker}", pid=10),
              execution(1, "/tmp/exploit", pid=11, ppid=10, uid="0", process__auid="1000")]
    assert [m.proposed_lane for m in detector("host.unbrokered_privilege_transition", events, tmp_path).finalize()] == ["high"]


@pytest.mark.parametrize("leaf", ["payload", "backdoor.py", ".payload"])
def test_ansible_staging_exclusion_requires_an_actual_module_leaf(leaf, tmp_path):
    path = f"/home/alice/.ansible/tmp/ansible-tmp-123/{leaf}"
    out = list(detector("host.tool_cleanup", [execution(1, path, host="web1"), change(2, path, "delete")], tmp_path).finalize())
    assert [m.proposed_lane for m in out] == ["lead"]
