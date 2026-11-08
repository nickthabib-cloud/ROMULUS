"""Hash-file reads by package maintenance and provisioning: a narrow, typed route to the lead lane.

Every arm of the route has a positive and a negative here: each lineage shape seen on Debian/Ubuntu hosts goes to the
lead lane, and a login session, a non-package interpreter or script, a non-root reader, an argv operand, a private key
and every unresolved lineage stay where they were (high for a hash read).
"""
import json
from datetime import timedelta

import pytest

from romulus.detect.host import ProcessLineage
from romulus.detect.linux_direct import (
    PROVISIONER_DEPTH,
    CredentialMaterialAccess,
    interpreter_script,
    packaged_script,
)
from romulus.evidence.typed import Outcome
from tests.test_bounded_host import T0, ev

_serial = [1000]


def _next_serial():
    _serial[0] += 1
    return _serial[0]


def exec_(t, pid, ppid, argv, exe=None, host="deb1", uid="0", **fields):
    exe = exe or argv[0]
    return ev("process_exec", T0 + timedelta(seconds=t), host_name=host, process__executable=exe,
              process__argv=list(argv), process__pid=pid, process__ppid=ppid, process__uid=uid,
              process__user="root" if uid == "0" else "alice", audit__serial=_next_serial(), **fields)


def read(t, pid, ppid, exe="/usr/bin/perl", path="/etc/shadow", host="deb1", uid="0",
         outcome=Outcome.success, **fields):
    return ev("file_access", T0 + timedelta(seconds=t), outcome=outcome, host_name=host, file__path=path,
              file__access="read", audit__key="shadow", process__executable=exe, process__pid=pid,
              process__ppid=ppid, process__uid=uid, process__user="root" if uid == "0" else "alice",
              audit__serial=_next_serial(), **fields)


def cloud_init(host="deb1"):
    return exec_(0, 100, 1, ["/usr/bin/python3", "/usr/bin/cloud-init", "modules", "--mode=config"], host=host)


def run(events, rule=None):
    rule = rule or CredentialMaterialAccess()
    return rule, rule.consume(events)


def only(out):
    assert len(out) == 1, [m.claim for m in out]
    return out[0]


def lane_of(out):
    return only(out).proposed_lane


# ---- each lineage shape seen during provisioning, upgrades and boot ----

def shape_debconf_set_selections():
    return [cloud_init(),
            exec_(5, 200, 100, ["/usr/bin/perl", "-w", "/usr/bin/debconf-set-selections"]),
            read(6, 200, 100)]


def shape_dpkg_preconfigure():
    return [cloud_init(),
            exec_(10, 300, 100, ["/usr/bin/apt-get", "install", "-y", "nginx"]),
            exec_(11, 301, 300, ["/bin/sh", "-c", "/usr/sbin/dpkg-preconfigure --apt || true"]),
            exec_(12, 302, 301, ["/usr/bin/perl", "-w", "/usr/sbin/dpkg-preconfigure", "--apt"]),
            read(13, 302, 301)]


def shape_unattended_frontend():
    return [exec_(0, 400, 1, ["/usr/bin/python3", "/usr/bin/unattended-upgrade"]),
            exec_(20, 401, 400, ["/usr/bin/dpkg", "--status-fd", "10", "--configure", "libc-bin"]),
            exec_(21, 402, 401, ["/bin/sh", "/var/lib/dpkg/info/libc-bin.postinst", "configure"]),
            exec_(22, 403, 402, ["/usr/bin/perl", "-w", "/usr/share/debconf/frontend",
                                 "/var/lib/dpkg/info/libc-bin.postinst", "configure"]),
            read(23, 403, 402)]


def shape_man_db_trigger(session):
    extra = {"process__auid": "1000", "process__session_id": 7} if session else {}
    return [exec_(0, 500, 1, ["/usr/bin/apt", "upgrade"], **extra),
            exec_(1, 501, 500, ["/usr/bin/dpkg", "--triggers-only", "-a"], **extra),
            exec_(2, 502, 501, ["/bin/sh", "/var/lib/dpkg/info/man-db.postinst", "triggered"], **extra),
            exec_(3, 503, 502, ["/usr/bin/perl", "-w", "/usr/share/debconf/frontend",
                                "/var/lib/dpkg/info/man-db.postinst", "triggered"], **extra),
            read(4, 503, 502, **extra)]


def shape_service_script():
    return [exec_(0, 600, 1, ["/usr/bin/perl", "-wT", "/usr/bin/zmpkg.pl", "start"]),
            read(1, 600, 1)]


@pytest.mark.parametrize("shape,kind", [
    (shape_debconf_set_selections, "package maintenance"),
    (shape_dpkg_preconfigure, "package maintenance"),
    (shape_unattended_frontend, "package maintenance"),
    (lambda: shape_man_db_trigger(False), "package maintenance"),
    (shape_service_script, "service manager"),
])
def test_dev_lineage_shapes_route_to_lead_with_the_route_stated(shape, kind):
    _rule, out = run(shape())
    match = only(out)
    assert match.proposed_lane == "lead"
    assert kind in match.claim and "←" in match.claim
    assert any(note.endswith("kept as a lead, not excluded.") for note in match.notes)
    from tests.claim_citations import finding_problems
    assert finding_problems(match.claim, match.notes, match.events) == []
    _host, exe, path, script, lane = json.loads(match.group_key)
    assert (exe, path, lane) == ("/usr/bin/perl", "/etc/shadow", "lead") and script.startswith("/usr/")


def test_route_note_names_the_lineage_from_the_reader_up():
    _rule, out = run(shape_dpkg_preconfigure())
    note = next(n for n in only(out).notes if "kept as a lead" in n)
    assert note.startswith("Root interpreter under package maintenance (perl /usr/sbin/dpkg-preconfigure ← sh ← "
                           "apt-get) read the hash file with no login session")


def test_the_same_batch_read_before_its_lineage_records_is_still_routed():
    events = shape_dpkg_preconfigure()
    assert lane_of(run([events[-1], *events[:-1]])[1]) == "lead"


def test_lineage_read_in_an_earlier_batch_is_used():
    events = shape_unattended_frontend()
    rule, first = run(events[:-1])
    assert first == []
    assert lane_of(rule.consume([events[-1]])) == "lead"


# ---- negatives: what never goes to the lead lane ----

def test_apt_inside_an_interactive_root_ssh_session_stays_high():
    assert lane_of(run(shape_man_db_trigger(True))[1]) == "high"


@pytest.mark.parametrize("fields", [{"process__auid": "0"}, {"process__session_id": 3},
                                    {"process__login_user": "root"}])
def test_any_login_session_marker_on_the_read_keeps_it_high(fields):
    events = shape_debconf_set_selections()
    events[-1] = read(6, 200, 100, **fields)
    assert lane_of(run(events)[1]) == "high"


def test_a_login_session_on_the_readers_exec_keeps_it_high():
    events = shape_debconf_set_selections()
    events[1] = exec_(5, 200, 100, ["/usr/bin/perl", "-w", "/usr/bin/debconf-set-selections"], process__auid="1000")
    assert lane_of(run(events)[1]) == "high"


@pytest.mark.parametrize("exe", ["/tmp/perl", "/dev/shm/python3", "/usr/local/bin/perl", "/home/u/bin/perl"])
def test_interpreter_outside_package_directories_stays_high(exe):
    events = [cloud_init(), exec_(5, 200, 100, [exe, "-w", "/usr/bin/debconf-set-selections"]), read(6, 200, 100, exe=exe)]
    assert lane_of(run(events)[1]) == "high"


@pytest.mark.parametrize("argv", [
    ["/usr/bin/perl", "/tmp/x.pl"],
    ["/usr/bin/perl", "-w", "/var/tmp/x.pl"],
    ["/usr/bin/perl", "-e", "getpwnam('root')"],
    ["/usr/bin/perl"],
    ["/usr/bin/perl", "-I", "/usr/share/perl5", "/tmp/x.pl"],
    ["/usr/bin/perl", "x.pl"],
    ["/usr/bin/perl", "/usr/local/bin/x.pl"],
    ["/usr/bin/perl", "/usr/share/x.pl"],
])
def test_script_outside_package_locations_under_dpkg_stays_high(argv):
    events = [exec_(0, 700, 1, ["/usr/bin/dpkg", "--configure", "-a"]),
              exec_(1, 701, 700, argv), read(2, 701, 700)]
    assert lane_of(run(events)[1]) == "high"


def test_non_root_reader_stays_high():
    events = [cloud_init(), exec_(5, 200, 100, ["/usr/bin/perl", "-w", "/usr/bin/debconf-set-selections"], uid="1000"),
              read(6, 200, 100, uid="1000")]
    assert lane_of(run(events)[1]) == "high"


def test_argv_operand_read_under_package_maintenance_is_unchanged():
    events = [cloud_init(), exec_(5, 200, 100, ["/usr/bin/cat", "/etc/shadow"])]
    match = only(run(events)[1])
    assert match.proposed_lane == "high" and "kept as a lead" not in " ".join(match.notes)


def test_private_key_read_by_a_routed_shape_is_never_routed():
    events = shape_debconf_set_selections()
    events[-1] = read(6, 200, 100, path="/home/alice/.ssh/id_rsa", file__owner__name="alice", file__owner__id="1000")
    match = only(run(events)[1])
    assert match.proposed_lane == "high" and "kept as a lead" not in " ".join(match.notes)


def test_no_provisioner_up_to_the_service_manager_stays_high():
    events = [exec_(0, 800, 1, ["/usr/sbin/cron", "-f"]),
              exec_(1, 801, 800, ["/bin/sh", "-c", "/usr/bin/perl -w /usr/bin/debconf-set-selections"]),
              exec_(2, 802, 801, ["/usr/bin/perl", "-w", "/usr/bin/debconf-set-selections"]),
              read(3, 802, 801)]
    assert lane_of(run(events)[1]) == "high"


def test_provisioner_name_outside_its_package_directory_is_not_a_provisioner():
    events = [exec_(0, 900, 1, ["/tmp/dpkg", "--configure"]),
              exec_(1, 901, 900, ["/usr/bin/perl", "-w", "/usr/bin/debconf-set-selections"]), read(2, 901, 900)]
    assert lane_of(run(events)[1]) == "high"


def test_interpreter_hosted_provisioner_needs_its_exact_script():
    events = [exec_(0, 100, 1, ["/usr/bin/python3", "/tmp/cloud-init"]),
              exec_(5, 200, 100, ["/usr/bin/perl", "-w", "/usr/bin/debconf-set-selections"]), read(6, 200, 100)]
    assert lane_of(run(events)[1]) == "high"


def test_service_arm_needs_a_packaged_script():
    events = [exec_(0, 600, 1, ["/usr/bin/perl", "-wT", "/opt/zm/zmpkg.pl", "start"]), read(1, 600, 1)]
    assert lane_of(run(events)[1]) == "high"


# ---- unknown lineage stays high ----

def test_reader_exec_not_recorded_stays_high():
    assert lane_of(run([cloud_init(), read(6, 200, 100)])[1]) == "high"


def test_missing_ancestor_stays_high():
    events = shape_dpkg_preconfigure()
    del events[1]                               # apt-get's exec is not recorded: the walk stops at sh's parent
    assert lane_of(run(events)[1]) == "high"


def test_exec_store_refusal_anywhere_in_the_hunt_stays_high():
    rule = CredentialMaterialAccess()
    rule.lineage.execs.incomplete = True
    assert lane_of(run(shape_debconf_set_selections(), rule)[1]) == "high"


def test_script_store_refusal_stays_high(monkeypatch):
    rule = CredentialMaterialAccess()
    monkeypatch.setattr(rule.scripts, "put", lambda key, state: False)
    rule2, out = run(shape_debconf_set_selections(), rule)
    assert lane_of(out) == "high" and "interpreter_scripts" in rule2.limits


def test_provisioner_beyond_the_depth_limit_stays_high():
    events = [cloud_init()]
    pid = 100
    for depth in range(PROVISIONER_DEPTH):
        events.append(exec_(1 + depth, 1000 + depth, pid, ["/bin/sh", "-c", "next"]))
        pid = 1000 + depth
    events += [exec_(20, 2000, pid, ["/usr/bin/perl", "-w", "/usr/bin/debconf-set-selections"]), read(21, 2000, pid)]
    assert lane_of(run(events)[1]) == "high"
    events = [cloud_init()]
    pid = 100
    for depth in range(PROVISIONER_DEPTH - 1):
        events.append(exec_(1 + depth, 1000 + depth, pid, ["/bin/sh", "-c", "next"]))
        pid = 1000 + depth
    events += [exec_(20, 2000, pid, ["/usr/bin/perl", "-w", "/usr/bin/debconf-set-selections"]), read(21, 2000, pid)]
    assert lane_of(run(events)[1]) == "lead"


def test_other_boot_lineage_is_not_joined():
    events = [exec_(0, 100, 1, ["/usr/bin/python3", "/usr/bin/cloud-init"], host__boot__id="boot-a"),
              exec_(5, 200, 100, ["/usr/bin/perl", "-w", "/usr/bin/debconf-set-selections"], host__boot__id="boot-b"),
              read(6, 200, 100, host__boot__id="boot-b")]
    assert lane_of(run(events)[1]) == "high"


# ---- outcomes, timestamp boundaries and missing fields ----

def test_failed_and_unknown_outcomes():
    events = shape_debconf_set_selections()
    events[-1] = read(6, 200, 100, outcome=Outcome.failure)
    assert lane_of(run(events)[1]) == "lead"            # a failed read was a lead before the route
    events[-1] = read(6, 200, 100, outcome=Outcome.unknown)
    match = only(run(events)[1])
    assert match.proposed_lane == "lead" and "recorded outcome unknown" in match.claim


def test_read_at_the_exec_instant_orders_by_audit_serial():
    exec_rec = exec_(5, 200, 100, ["/usr/bin/perl", "-w", "/usr/bin/debconf-set-selections"])
    same_instant = read(5, 200, 100)            # a later audit serial at the same second
    assert lane_of(run([cloud_init(), exec_rec, same_instant])[1]) == "lead"
    before = read(4.999, 200, 100)              # before the exec: the pid's image then is unknown
    assert lane_of(run([cloud_init(), exec_(5, 200, 100, ["/usr/bin/perl", "-w",
                                                           "/usr/bin/debconf-set-selections"]), before])[1]) == "high"


def test_read_without_a_path_is_counted_missing_not_a_no_match():
    rule = CredentialMaterialAccess()
    blank = ev("file_access", T0, host_name="deb1", file__access="read", process__executable="/usr/bin/perl")
    assert rule.consume([blank]) == [] and rule.missing_required == 1


def test_read_without_a_pid_stays_high():
    events = shape_debconf_set_selections()
    bare = ev("file_access", T0 + timedelta(seconds=6), host_name="deb1", file__path="/etc/shadow",
              process__executable="/usr/bin/perl", process__uid="0")
    assert lane_of(run([*events[:-1], bare])[1]) == "high"


# ---- grouping and lanes ----

def test_lead_and_high_reads_of_one_file_are_separate_groups():
    events = [*shape_debconf_set_selections(), *shape_man_db_trigger(True)]
    out = run(events)[1]
    assert sorted(json.loads(m.group_key)[-1] for m in out) == ["high", "lead"]


def test_routed_lead_cites_its_lineage_as_context_when_kept():
    rule = CredentialMaterialAccess()
    events = shape_dpkg_preconfigure()
    by_id = {e.id: e for e in events}
    rule.lineage.execs.cited = lambda ids: ({i: by_id[i] for i in ids if i in by_id}, {})
    match = only(rule.consume(events))
    subjects = [e for e in match.events if e.id not in match.context_ids]
    assert [e.family for e in subjects] == ["file_access"]
    assert {by_id[i].get("process.executable") for i in match.context_ids} == {
        "/usr/bin/perl", "/bin/sh", "/usr/bin/apt-get"}
    assert "1 cited" in match.claim


def test_interpreter_script_parsing():
    assert interpreter_script("perl", ["/usr/bin/perl", "-w", "/usr/bin/x"]) == "/usr/bin/x"
    assert interpreter_script("perl", ["/usr/bin/perl", "-wT", "/usr/bin/x"]) == "/usr/bin/x"
    assert interpreter_script("python", ["/usr/bin/python3", "-Es", "/usr/bin/x"]) == "/usr/bin/x"
    assert interpreter_script("python", ["/usr/bin/python3", "-c", "/usr/bin/x"]) == ""
    assert interpreter_script("python", ["/usr/bin/python3", "-m", "x"]) == ""
    assert interpreter_script("python", ["/usr/bin/python3", "-X", "/usr/bin/cloud-init", "/tmp/e.py"]) == ""
    assert interpreter_script("perl", ["/usr/bin/perl", "-e", "1", "/usr/bin/x"]) == ""
    assert interpreter_script("perl", ["/usr/bin/perl", "/usr/bin/../../tmp/x"]) == "/tmp/x"
    assert packaged_script("/usr/share/debconf/frontend") and packaged_script("/usr/lib/foo/bar.pl")
    assert not packaged_script("/usr/share/x.pl") and not packaged_script("/usr/lib/x.pl")
    assert not packaged_script("/usr/local/bin/x") and not packaged_script("/tmp/x")


# ---- mission scale ----

def test_ten_thousand_maintenance_reads_on_fifty_hosts_stay_bounded(monkeypatch, tmp_path):
    hot = 16
    monkeypatch.setattr(CredentialMaterialAccess, "HOT", hot)
    monkeypatch.setattr(ProcessLineage, "CAPACITY", hot)
    rule = CredentialMaterialAccess()
    rule.spill_dir = tmp_path
    published: dict[str, object] = {}
    reads = 0
    for host_no in range(50):
        host = f"deb{host_no:02d}"
        lineage = [exec_(0, 100, 1, ["/usr/bin/python3", "/usr/bin/cloud-init"], host=host),
                   exec_(1, 300, 100, ["/usr/bin/apt-get", "install", "-y", "pkg"], host=host)]
        batch = list(lineage)
        for proc in range(4):
            pid = 400 + proc
            batch.append(exec_(2 + proc, pid, 300, ["/usr/bin/perl", "-w", "/usr/sbin/dpkg-preconfigure"], host=host))
            for n in range(50):
                batch.append(read(3 + proc + n / 100, pid, 300, host=host))
                reads += 1
        for start in range(0, len(batch), 37):
            for match in rule.consume(batch[start:start + 37]):
                published[match.group_key] = match
        assert len(rule.folds.hot) <= hot and len(rule.scripts.hot) <= hot
        assert len(rule.lineage.execs.store.hot) <= hot
    assert reads == 10_000
    assert len(published) == 50
    assert {json.loads(key)[-1] for key in published} == {"lead"}
    assert all(m.aggregate_summary["count"] == 200 for m in published.values())
    assert rule.folds.on_disk > 0 and rule.lineage.execs.store.on_disk > 0


# ---- publication: one finding per group key across the sweep and expansion ----

def _repo():
    from romulus.store.db import make_engine, migrate
    from romulus.store.repo import Repo
    engine = make_engine(":memory:")
    migrate(engine)
    repo = Repo(engine)
    repo.create_hunt("h1", {"targets": []}, "digest", "test")
    return repo


def _publish(repo, rule, events, anchor=None):
    from romulus.hunt.publish import mark_hypothesis_relation, publish_match
    for match in rule.consume(events):
        if anchor is None:
            publish_match(repo, "h1", rule, match, None, {})
            continue
        reach = {"anchor_id": anchor, "link_id": f"L-{anchor}", "link_type": "host_after_anchor",
                 "strength": "inferred"}
        mark_hypothesis_relation(match, anchor_id=anchor, link_id=reach["link_id"], link_type=reach["link_type"],
                                 strength=reach["strength"])
        publish_match(repo, "h1", rule, match, None, {}, source_anchor_id=anchor, source_link_id=reach["link_id"],
                      context_reach=reach)


def test_expansion_reaching_more_records_of_the_same_process_folds_into_the_sweep_finding():
    repo = _repo()
    _publish(repo, CredentialMaterialAccess(), shape_man_db_trigger(True))
    later = [read(5 + n, 503, 502, process__auid="1000", process__session_id=7) for n in range(3)]
    for anchor in ("F-one", "F-two"):
        _publish(repo, CredentialMaterialAccess(), later, anchor=anchor)    # a fresh evaluator per reach
    rows = [row for row in repo.candidates("h1") if row["rule_id"] == CredentialMaterialAccess.id]
    assert len(rows) == 1
    row = rows[0]
    assert row["lane"] == "high" and row["source_anchor_id"] is None
    assert row["gate_results"]["aggregate_summary"]["count"] == 1
    fold = row["gate_results"]["_expansion_fold"]
    # The first reach's three records are beyond the sweep's citation; the second reach's cited first and latest are
    # now known repeats, and only its middle record may be new.
    assert fold["reaches_total"] == 2 and fold["records"] == 4
    assert {reach["anchor_id"] for reach in row["gate_results"]["_context_reaches"]} == {"F-one", "F-two"}
    assert ("Expansion also reached this group through 2 reach(es) and read 4 matching record(s) not cited "
            "above") in row["claim"]
    from romulus.evidence.typed import TypedEvent
    from tests.claim_citations import finding_problems
    cited = [TypedEvent.model_validate(item["event"]) for item in repo.citation_events("h1", row["event_ids"])]
    assert finding_problems(row["claim"], row["gate_results"]["_notes"], cited) == []
    assert {later[0].id, later[-1].id} <= set(row["event_ids"])     # each reach cites its first and latest


# ---- expansion over records the sweep already evaluated: the sweep's verdict stands ----

def _swept_hunt(cell_state="matched", cell_seconds=30, session_read=True):
    """A hunt whose sweep read [T0, T0 + cell_seconds) of target host-x with full lineage, published its groups and
    wrote the rule's partition cell, and an anchor whose reach will carry reads without their lineage."""
    from romulus.hunt.publish import publish_match
    from romulus.store.db import make_engine, migrate
    from romulus.store.repo import Repo
    engine = make_engine(":memory:")
    migrate(engine)
    repo = Repo(engine)
    end = T0 + timedelta(hours=1)
    repo.create_hunt("h1", {"window": {"start": T0.isoformat(), "end": end.isoformat()}, "targets": ["host-x"]},
                     "digest", "test")
    sweep = CredentialMaterialAccess()
    lineage = shape_dpkg_preconfigure()
    later = [read(20, 302, 301), read(21, 302, 301)]
    session = read(22, 503, 502, process__auid="1000", process__session_id=7)
    repo.upsert_task("T-sweep", "h1", "sweep", "sweep", {}, "T-sweep")
    for match in sweep.consume([*lineage, *later, *([session] if session_read else [])]):
        # the sweep stores the records its findings cite (each group's first and latest), under its task
        publish_match(repo, "h1", sweep, match, "T-sweep", {e.key: {"doc": e.native_id} for ev in match.events
                                                            for e in ev.raw})
    partition = f"{T0.isoformat()}/{(T0 + timedelta(seconds=cell_seconds)).isoformat()}"
    repo.set_rule_cell("h1", sweep.id, sweep.version, "host-x", partition, cell_state, 1, 10)
    repo.save_candidate({
        "id": "F-anchor", "hunt_id": "h1", "rule_id": "host.web_shell", "rule_version": "1", "claim": "an anchor",
        "claim_type": "observed_action", "event_ids": [], "predicate_fields": [], "entities": [], "ts": T0,
        "severity": "high", "confidence": "high", "lane": "high", "priority": 50.0, "priority_reasons": [],
        "gate_results": {}, "benign_alternatives": [], "next_checks": [], "source_case_id": None,
        "source_anchor_id": None, "source_link_id": None})
    return repo, later, session


class LineageFetcher:
    """Stands in for the link fetcher's process_lineage fetch: stores and returns the given lineage records."""

    def __init__(self, repo, lineage, status="complete"):
        self.repo, self.lineage, self.status, self.calls = repo, lineage, status, []

    def fetch(self, anchor, link_type, window, *, query_cap=None):
        from romulus.hunt.links import LinkResult
        self.calls.append((anchor.events[0].get("process.pid"), link_type, query_cap))
        self.repo.save_evidence("h1", self.lineage, {}, None)
        return LinkResult(id=f"L-lineage-{len(self.calls)}", anchor_id=anchor.finding_id, link_type=link_type,
                          window=window, strength="observed", key={}, status=self.status,
                          event_ids=[e.id for e in self.lineage] if self.status == "complete" else [],
                          reasons=[] if self.status == "complete" else ["expansion_link_query_cap:2"],
                          query_spend=2)


def _reach(repo, events, fetcher=None, engine_hook=None, **engine_args):
    from romulus.hunt.expansion import ExpansionEngine
    from romulus.hunt.links import LinkResult, LinkWindow
    from romulus.sources.models import Window
    repo.save_evidence("h1", events, {}, None)
    engine = ExpansionEngine(repo, "h1", Window(start=T0, end=T0 + timedelta(hours=1)),
                             fetcher=fetcher or object(), **engine_args)
    if engine_hook is not None:
        engine_hook(engine)
    result = LinkResult(id="L-reach", anchor_id="F-anchor", link_type="host_after_anchor",
                        window=LinkWindow(label="anchor ±5 min", start=T0, end=T0 + timedelta(minutes=5)),
                        strength="inferred", key={}, status="complete", event_ids=[e.id for e in events])
    engine._persist_link(result)
    return engine._evaluate(repo.candidate("F-anchor"), result)


def _credential_rows(repo):
    return {row["lane"]: row for row in repo.candidates("h1") if row["rule_id"] == CredentialMaterialAccess.id}


def test_a_swept_read_reached_without_its_lineage_folds_into_the_sweeps_lead_group():
    repo, later, _session = _swept_hunt()
    before = _credential_rows(repo)
    assert set(before) == {"lead", "high"}
    assert later[-1].id in before["lead"]["event_ids"]               # the sweep stored it: proof it judged it
    assert _reach(repo, [later[-1]]) == []
    rows = _credential_rows(repo)
    assert set(rows) == {"lead", "high"} and rows["high"]["id"] == before["high"]["id"]
    assert rows["high"]["claim"] == before["high"]["claim"]          # the session read's group is untouched
    fold = rows["lead"]["gate_results"]["_expansion_fold"]
    assert fold["reaches_total"] == 1 and rows["lead"]["lane"] == "lead"
    assert "A reach's own evaluation" not in rows["lead"]["claim"]


def test_b_a_record_outside_every_swept_partition_is_judged_by_expansion_and_fails_toward_high():
    repo, _later, _session = _swept_hunt()
    outside = [read(40, 302, 301), read(41, 302, 301)]            # after the cell's end: never evaluated by the sweep
    _reach(repo, outside)
    high = _credential_rows(repo)["high"]
    assert {outside[0].id, outside[-1].id} <= set(high["event_ids"])
    assert "A reach's own evaluation" not in high["claim"] and high["gate_results"]["_expansion_fold"]


def test_c_a_partial_sweep_cell_leaves_its_records_to_expansion():
    repo, later, _session = _swept_hunt(cell_state="match_on_partial")
    _reach(repo, later)
    rows = _credential_rows(repo)
    assert "_expansion_fold" not in rows["lead"]["gate_results"]
    assert {later[0].id, later[-1].id} <= set(rows["high"]["event_ids"])


def test_d_a_different_event_computing_high_still_publishes_high():
    repo, later, session = _swept_hunt()
    unswept = read(45, 503, 502, process__auid="1000", process__session_id=7)     # outside the swept partition
    _reach(repo, [*later, session, unswept])
    rows = _credential_rows(repo)
    assert rows["lead"]["lane"] == "lead" and rows["lead"]["gate_results"]["_expansion_fold"]["reaches_total"] == 1
    assert rows["high"]["lane"] == "high" and unswept.id in rows["high"]["event_ids"]


def test_d_without_a_sweep_group_the_new_high_event_publishes_its_own_finding():
    repo, later, _session = _swept_hunt(session_read=False)
    assert set(_credential_rows(repo)) == {"lead"}
    unswept = read(45, 503, 502, process__auid="1000", process__session_id=7)
    published = _reach(repo, [later[-1], unswept])      # the sweep stored later[-1]; it never saw the other
    rows = _credential_rows(repo)
    assert rows["high"]["event_ids"] == [unswept.id] and [row["id"] for row in published] == [rows["high"]["id"]]
    assert rows["lead"]["gate_results"]["_expansion_fold"]["reaches_total"] == 1


def test_sweep_targets_and_partitions_are_matched_by_typed_pattern_and_time():
    from romulus.hunt.expansion import _cell_span, _target_names
    assert _target_names("host-x", "host-x") and not _target_names("host-x", "host-xy")
    assert _target_names("logs-*,audit-1", "logs-2024.11.18") and _target_names("logs-*,audit-1", "audit-1")
    assert not _target_names("logs-*,-logs-old*", "logs-old-1") and not _target_names("alias-name", "backing-index")
    assert _cell_span("window") is None and _cell_span("anchor:F|link:L") is None
    start, end = _cell_span(f"{T0.isoformat()}/{(T0 + timedelta(minutes=5)).isoformat()}")
    assert (start, end) == (T0, T0 + timedelta(minutes=5))


def test_a_split_parent_or_unsupported_cell_is_not_a_sweep_evaluation():
    repo, later, _session = _swept_hunt(cell_state="split")
    _reach(repo, later)
    assert {later[0].id, later[-1].id} <= set(_credential_rows(repo)["high"]["event_ids"])
    repo, later, _session = _swept_hunt(cell_state="not_applicable_no_events")
    _reach(repo, later)
    assert "_expansion_fold" not in _credential_rows(repo)["lead"]["gate_results"]


@pytest.mark.parametrize("late", [True, False])
def test_a_record_the_sweep_never_stored_is_judged_by_expansion_even_inside_a_complete_cell(late):
    """Late ingestion: a record inside a complete swept cell that the sweep never stored has no proof the sweep saw
    it. Expansion judges it and may publish high; a swept but uncited record is judged the same way."""
    repo, later, _session = _swept_hunt(session_read=False)
    record = read(25, 302, 301) if late else later[0]
    assert not repo.citation_events("h1", [record.id])
    published = _reach(repo, [record])
    rows = _credential_rows(repo)
    assert rows["high"]["event_ids"] == [record.id] and [row["id"] for row in published] == [rows["high"]["id"]]
    assert "_expansion_fold" not in rows["lead"]["gate_results"]


# ---- expansion fetches a routable read's missing lineage before judging it ----

def _dpkg_lineage():
    """apt-get (300) <- sh -c (301) <- perl dpkg-preconfigure (302): the records a process_lineage fetch returns."""
    return shape_dpkg_preconfigure()[1:4]


def _unrouted_lineage():
    return [exec_(10, 300, 1, ["/usr/sbin/cron", "-f"]),
            exec_(11, 301, 300, ["/bin/sh", "-c", "job"]),
            exec_(12, 302, 301, ["/usr/bin/perl", "-w", "/usr/sbin/dpkg-preconfigure", "--apt"])]


@pytest.mark.parametrize("sweep_group", [True, False])
def test_a_reached_read_without_lineage_is_judged_with_its_fetched_lineage(sweep_group):
    """The read alone cannot be routed; its fetched lineage shows dpkg-preconfigure <- sh <- apt-get, so it joins
    (or creates) the lead group and no high sibling appears."""
    repo = _swept_hunt(session_read=False)[0] if sweep_group else _fresh_hunt_without_sweep_groups()
    record = read(25, 302, 301)
    fetcher = LineageFetcher(repo, _dpkg_lineage())
    _reach(repo, [record], fetcher=fetcher)
    rows = _credential_rows(repo)
    assert set(rows) == {"lead"} and len(fetcher.calls) == 1
    assert fetcher.calls[0][1:] == ("process_lineage", 2)
    assert record.id in rows["lead"]["event_ids"]
    if sweep_group:
        assert rows["lead"]["gate_results"]["_expansion_fold"]["reaches_total"] == 1


def _fresh_hunt_without_sweep_groups():
    from romulus.store.db import make_engine, migrate
    from romulus.store.repo import Repo
    engine = make_engine(":memory:")
    migrate(engine)
    repo = Repo(engine)
    repo.create_hunt("h1", {"window": {"start": T0.isoformat(), "end": (T0 + timedelta(hours=1)).isoformat()},
                            "targets": ["host-x"]}, "digest", "test")
    repo.save_candidate({
        "id": "F-anchor", "hunt_id": "h1", "rule_id": "host.web_shell", "rule_version": "1", "claim": "an anchor",
        "claim_type": "observed_action", "event_ids": [], "predicate_fields": [], "entities": [], "ts": T0,
        "severity": "high", "confidence": "high", "lane": "high", "priority": 50.0, "priority_reasons": [],
        "gate_results": {}, "benign_alternatives": [], "next_checks": [], "source_case_id": None,
        "source_anchor_id": None, "source_link_id": None})
    return repo


def test_fetched_lineage_without_a_provisioner_stays_high():
    repo = _fresh_hunt_without_sweep_groups()
    fetcher = LineageFetcher(repo, _unrouted_lineage())
    _reach(repo, [read(25, 302, 301)], fetcher=fetcher)
    assert set(_credential_rows(repo)) == {"high"} and len(fetcher.calls) == 1


@pytest.mark.parametrize("why,setup,status", [
    ("lookups are spent", lambda engine: engine._lineage_fetches.__setitem__("F-anchor", 16), "complete"),
    ("budget exhausted", None, "complete"),
    ("lineage lookup was partial", None, "partial"),
])
def test_unavailable_lineage_stays_high_and_says_why(why, setup, status):
    repo = _fresh_hunt_without_sweep_groups()
    fetcher = LineageFetcher(repo, _dpkg_lineage(), status=status)
    _reach(repo, [read(25, 302, 301)], fetcher=fetcher, engine_hook=setup,
           **({"max_source_queries": 0} if why == "budget exhausted" else {}))
    rows = _credential_rows(repo)
    assert set(rows) == {"high"}
    assert any(note.startswith("Lineage for the reader (pid 302 on deb1) was not available to expansion")
               and why in note for note in rows["high"]["gate_results"]["_notes"])
    assert len(fetcher.calls) == (1 if status == "partial" else 0)


@pytest.mark.parametrize("record", [
    read(25, 302, 301, exe="/tmp/perl"),
    read(25, 302, 301, process__auid="1000"),
    read(25, 302, 301, process__session_id=4),
    read(25, 302, 301, uid="1000"),
    read(25, 302, 301, path="/home/alice/.ssh/id_rsa", file__owner__name="alice", file__owner__id="1000"),
])
def test_a_read_without_the_routable_shape_never_costs_a_lineage_lookup(record):
    repo = _fresh_hunt_without_sweep_groups()
    fetcher = LineageFetcher(repo, _dpkg_lineage())
    _reach(repo, [record], fetcher=fetcher)
    assert fetcher.calls == [] and set(_credential_rows(repo)) == {"high"}


def test_one_lookup_per_reader_process_and_a_held_lineage_needs_none():
    repo = _fresh_hunt_without_sweep_groups()
    fetcher = LineageFetcher(repo, _dpkg_lineage())
    _reach(repo, [read(25, 302, 301), read(26, 302, 301)], fetcher=fetcher)
    assert len(fetcher.calls) == 1
    repo2 = _fresh_hunt_without_sweep_groups()
    fetcher2 = LineageFetcher(repo2, _dpkg_lineage())
    _reach(repo2, [*_dpkg_lineage(), read(25, 302, 301)], fetcher=fetcher2)
    assert fetcher2.calls == [] and set(_credential_rows(repo2)) == {"lead"}


# ---- the routed group is per script; the service arm checks the script and the parent ----

def change(t, path, kind="content", host="deb1"):
    return ev("file_change", T0 + timedelta(seconds=t), host_name=host, file__path=path, file__change=kind,
              process__executable="/usr/bin/cp", process__uid="0", process__pid=990, process__ppid=1)


def test_another_packaged_script_under_dpkg_never_shares_the_upgrade_group():
    events = [exec_(0, 700, 1, ["/usr/bin/dpkg", "--configure", "-a"]),
              exec_(1, 701, 700, ["/usr/bin/perl", "-w", "/usr/share/debconf/frontend"]), read(2, 701, 700),
              exec_(3, 702, 700, ["/usr/bin/perl", "/usr/share/evil/x.pl"]), read(4, 702, 700)]
    out = run(events)[1]
    assert len(out) == 2 and {m.proposed_lane for m in out} == {"lead"}
    assert {json.loads(m.group_key)[3] for m in out} == {"/usr/share/debconf/frontend", "/usr/share/evil/x.pl"}


def test_service_script_changed_during_the_hunt_stays_high():
    events = [change(-30, "/usr/bin/zmpkg.pl"), *shape_service_script()]
    assert lane_of(run(events)[1]) == "high"


def test_service_script_with_unrelated_changes_routes_and_was_checked():
    match = only(run([change(-30, "/usr/bin/other.pl"), *shape_service_script()])[1])
    assert match.proposed_lane == "lead" and not any("origin was not checked" in n for n in match.notes)


def test_service_script_without_file_change_records_routes_with_a_note():
    match = only(run(shape_service_script())[1])
    assert match.proposed_lane == "lead"
    assert "the script's origin was not checked (no file-change records)" in match.notes


def test_service_script_change_after_the_read_does_not_matter():
    match = only(run([*shape_service_script(), change(30, "/usr/bin/zmpkg.pl")])[1])
    assert match.proposed_lane == "lead"


def test_service_read_whose_parent_differs_from_its_exec_stays_high():
    events = [exec_(0, 600, 1, ["/usr/bin/perl", "-wT", "/usr/bin/zmpkg.pl", "start"]), read(1, 600, 4242)]
    assert lane_of(run(events)[1]) == "high"
