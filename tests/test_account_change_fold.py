"""Views of one account change and runs of changes: one change per tool action, one item per host per run.

A tool's audit record and its own syslog line of one change are one change citing both; a host's run of account and
group changes naming several accounts or groups (provisioning) is one item with the lane of its strongest change.
Hosts, accounts and addresses are invented."""
from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta

import pytest

from romulus.detect.auth import AccountOrGroupChange, _view_fit
from romulus.evidence.typed import Outcome, fv
from tests.storage_capacity_fixture import refuse_configured_stores
from tests.test_account_changes import ex, record, run
from tests.test_bounded_host import same_small_and_unbounded, staged_run
from tests.test_linux_text_breadth import one

T0 = datetime(2030, 3, 4, 9, 0, tzinfo=UTC)
GAP = AccountOrGroupChange.BURST_GAP
SPAN = AccountOrGroupChange.BURST_SPAN
_k = 0


def line(program, body, ts, *, host="prov01", pid=None):
    """A shadow-utils syslog line typed by the real normalizer (journald shape, no exec record of its process)."""
    global _k
    _k += 1
    return one("journal", program, body, pid=pid if pid is not None else 20000 + _k, nid=f"fold-{_k}", host=host,
               stamp=ts.strftime("%Y-%m-%dT%H:%M:%S.%fZ"))


def audit(record_type, action, ts, *, host="prov01", pid, **kw):
    return record(record_type, action, ts=ts, pid=pid, host=host, process__user="root",
                  process__executable=kw.pop("exe", "/usr/sbin/usermod"), **kw)


def provisioning(start=T0, host="prov01", users=60, step=2.0, admin_groups=("adm", "cdrom", "sudo", "dip", "plugdev",
                                                                             "lxd"), passwords=14):
    """A provisioning script's run as the tools log it (no exec auditing): each user's private group, the user and
    its password expiry; the administrator added to its groups; some passwords set. 3 * users + groups + passwords
    distinct changes, `step` seconds apart."""
    events, t = [], start

    def at():
        nonlocal t
        t += timedelta(seconds=step)
        return t
    for i in range(users):
        events.append(line("useradd", f"new group: name=u{i:03d}, GID={2000 + i}", at(), host=host))
        events.append(line("useradd", f"new user: name=u{i:03d}, UID={2000 + i}, GID={2000 + i}, home=/home/u{i:03d}, "
                                      "shell=/bin/bash, from=none", at(), host=host))
        events.append(line("chage", f"changed password expiry for u{i:03d}", at(), host=host))
    for group in admin_groups:
        events.append(line("usermod", f"add 'admin' to group '{group}'", at(), host=host))
    for i in range(passwords):
        events.append(line("passwd", f"password for 'u{i:03d}' changed by 'root'", at(), host=host))
    return events


def bursts(out):
    return [m for m in out if m.group_key.startswith("burst|")]


# ---------------------------------------------------------------- one run, one item
def test_a_provisioning_run_of_200_changes_is_one_item_with_the_lane_of_its_strongest_change():
    events = provisioning()
    assert len(events) == 200
    _pb, out = run(events)
    assert len(out) == 1
    [m] = out
    assert m.group_key.startswith("burst|prov01|") and (m.proposed_lane, m.severity) == ("high", "high")
    assert "On prov01, 200 account or group change(s) were recorded close together in time" in m.claim
    assert "naming 67 distinct account and group name(s)" in m.claim     # 60 users, admin and its 6 groups
    assert ("60 group(s) added, 60 account(s) added, 60 password aging or expiry change(s), 14 password change(s), "
            "6 group membership grant(s)") in m.claim
    assert "Made as 'an unrecorded account' (200)." in m.claim
    assert "a line logged under the identifier 'usermod'" in m.claim and "'useradd'" not in m.claim
    # every privileged change is named in the claim and the notes, and cited
    assert "2 of them request or report privileged access" in m.claim
    for group in ("sudo", "lxd"):
        assert f"membership of privileged group {group}" in m.claim
        assert any(n.startswith("privileged change:") and f"(group '{group}')" in n for n in m.notes)
        assert any(e.get("account.group") == group for e in m.events)
    # every change is named once (all 200 are distinct)
    assert sum(n.startswith(("change:", "privileged change:")) for n in m.notes) == 200
    assert "The records of 64 of the 200 changes are cited: the privileged ones first, then the earliest." in m.claim
    assert {"T1136.001", "T1098"} <= set(m.notes)
    assert "so does an intruder creating an account and granting it a privileged group inside such a run" in m.claim
    # the entity list stays bounded: the host and the accounts of the cited changes only
    assert len(m.entities) <= 1 + 64


def test_a_run_without_a_privileged_change_is_one_lead():
    _pb, out = run(provisioning(admin_groups=("adm", "cdrom")))
    assert [(m.group_key.split("|")[0], m.proposed_lane) for m in out] == [("burst", "lead")]


def test_a_failed_grant_is_lead_on_its_own_and_a_successful_one_keeps_the_run_high():
    base = provisioning(users=3, admin_groups=(), passwords=0)
    failed = audit("USER_MGMT", "modify_user", T0 + timedelta(seconds=30), pid=9300, outcome=Outcome.failure,
                   account__op="add-user-to-group", account__name="admin", account__group="sudo")
    [m] = run([*base, failed])[1]
    assert m.proposed_lane == "lead" and "(every recorded result failed)" in m.claim
    assert "Every recorded result failed for 1 of them." in m.claim
    granted = audit("USER_MGMT", "modify_user", T0 + timedelta(seconds=40), pid=9301,
                    account__op="add-user-to-group", account__name="admin", account__group="lxd")
    [m] = run([*base, failed, granted])[1]
    assert m.proposed_lane == "high" and "2 of them request or report privileged access" in m.claim


# ---------------------------------------------------------------- two views of one change
def test_audit_record_and_tool_line_of_one_change_are_one_change_citing_both():
    rec = audit("USER_MGMT", "modify_user", T0, pid=9001, account__op="add-user-to-group", account__name="mallory",
                account__group="sudo")
    text = line("usermod", "add 'mallory' to group 'sudo'", T0 + timedelta(milliseconds=400), host="app01", pid=9001)
    rec.host = "app01"
    _pb, out = run([rec, text])
    assert len(out) == 1
    [m] = out
    assert m.proposed_lane == "high" and {e.id for e in m.events} == {rec.id, text.id}
    # the actor is the audit record's (the line names none), and the writer is the audit record's executable
    assert "2 account-management record(s) (audit records or the tool's own log lines)" in m.claim
    assert "written by '/usr/sbin/usermod' as root" in m.claim
    assert m.group_key.startswith("actor|app01|root|")


@pytest.mark.parametrize("offset,merged", [(10.0, True), (10.001, False)])
def test_views_pair_within_ten_seconds_inclusive(offset, merged):
    rec = audit("ADD_USER", "create_user", T0, host="app01", pid=9002, account__name="svc1", exe="/usr/sbin/useradd")
    text = line("useradd", "new user: name=svc1, UID=990, GID=990, home=/srv, shell=/usr/sbin/nologin, from=none",
                T0 + timedelta(seconds=offset), host="app01", pid=9002)
    assert len(run([rec, text])[1]) == (1 if merged else 2)


@pytest.mark.parametrize("change", ["other pid", "same view", "grant vs removal", "other account", "outcomes differ"])
def test_records_that_are_not_two_views_of_one_change_stay_apart(change):
    rec = audit("USER_MGMT", "modify_user", T0, host="app01", pid=9010, account__op="add-user-to-group",
                account__name="bob", account__group="video")
    body, pid = "add 'bob' to group 'video'", 9010
    if change == "other pid":
        pid = 9011
    elif change == "grant vs removal":
        body = "delete 'bob' from group 'video'"
    elif change == "other account":
        body = "add 'carol' to group 'video'"
    if change == "same view":
        other = audit("USER_MGMT", "modify_user", T0 + timedelta(seconds=1), host="app01", pid=9010,
                      account__op="add-user-to-group", account__name="bob", account__group="video")
    else:
        other = line("usermod", body, T0 + timedelta(seconds=1), host="app01", pid=pid)
    if change == "outcomes differ":
        rec.outcome = Outcome.failure
    assert _view_fit(rec, other) is None and _view_fit(other, rec) is None
    pb = AccountOrGroupChange()
    views = list(pb._views(sorted([rec, other], key=lambda e: (e.ts, e.id))))
    assert sorted(len(v) for v in views) == [1, 1]
    if change in ("other pid", "outcomes differ"):
        # two changes of the same account, action and names: one finding stating both records, or two findings
        # by actor; never one change
        out = run([rec, other])[1]
        assert sum(len([e for e in m.events if e.family == "account_change"]) for m in out) == 2


def test_a_line_without_a_pid_pairs_only_when_it_names_the_same_account():
    rec = audit("ADD_USER", "create_user", T0, host="app01", pid=9020, account__name="svc2", exe="/usr/sbin/useradd")
    text = line("useradd", "new user: name=svc2, UID=991, GID=991, home=/srv, shell=/usr/sbin/nologin, from=none",
                T0 + timedelta(seconds=1), host="app01")
    del text.fields["process.pid"]
    assert len(run([rec, text])[1]) == 1
    nameless = audit("ADD_USER", "create_user", T0, host="app01", pid=9021, exe="/usr/sbin/useradd")
    assert len(run([nameless, text])[1]) == 2


def test_an_unknown_outcome_pairs_and_is_not_counted_as_failed():
    rec = audit("ADD_USER", "create_user", T0, host="app01", pid=9030, account__name="svc3", exe="/usr/sbin/useradd",
                outcome=Outcome.unknown)
    text = line("useradd", "new user: name=svc3, UID=992, GID=992, home=/srv, shell=/usr/sbin/nologin, from=none",
                T0, host="app01", pid=9030)
    [m] = run([rec, text])[1]
    assert {e.id for e in m.events} == {rec.id, text.id} and "res=unrecorded" in m.claim


# ---------------------------------------------------------------- what stays apart
def test_an_intruders_lone_account_and_sudo_grant_stay_high_and_separate_from_a_provisioning_run():
    night = T0 + timedelta(hours=18, minutes=12)        # 03:12 the next morning, hours after the run
    attacker = [
        line("useradd", "new group: name=backdoor, GID=1337", night, pid=31337),
        line("useradd", "new user: name=backdoor, UID=1337, GID=1337, home=/home/backdoor, shell=/bin/bash, "
                        "from=/dev/pts/3", night + timedelta(milliseconds=20), pid=31337),
        audit("ADD_USER", "create_user", night + timedelta(milliseconds=25), pid=31337, account__name="backdoor",
              exe="/usr/sbin/useradd"),
        line("usermod", "add 'backdoor' to group 'sudo'", night + timedelta(seconds=9), pid=31340),
    ]
    out = run([*provisioning(), *attacker])[1]
    assert len(bursts(out)) == 1 and all(e.ts < night for e in bursts(out)[0].events)
    alone = [m for m in out if not m.group_key.startswith("burst|")]
    assert sorted((m.group_key.split("|")[0], m.proposed_lane) for m in alone) == [
        ("actor", "high"), ("actor", "lead"), ("actor", "lead")]
    grant = next(m for m in alone if m.proposed_lane == "high")
    assert "membership of privileged group sudo" in grant.claim and "backdoor" in grant.claim
    # the audit record and the line of the creation are one change with both records
    created = next(m for m in alone if "an account was added" in m.claim)
    assert len([e for e in created.events if e.family == "account_change"]) == 2


def test_an_intruders_grant_inside_a_provisioning_run_is_named_and_cited_and_keeps_the_run_high():
    # the counter-case of the fold: the grant shares the run's item, never losing its lane, name or citation
    events = provisioning(admin_groups=("adm",))
    grant = line("usermod", "add 'backdoor' to group 'sudo'", T0 + timedelta(seconds=150), pid=31341)
    [m] = run([*events, grant])[1]
    assert m.proposed_lane == "high"
    assert "1 of them request or report privileged access: an account was modified (account 'backdoor') (group " \
           "'sudo'): membership of privileged group sudo" in m.claim
    assert grant.id in {e.id for e in m.events}


def test_a_web_service_lineage_inside_a_run_stays_its_own_high_item():
    shell = ex(["sh", "-c", "sudo useradd helper"], exe="/usr/bin/dash", uid="33", pid=4000, ppid=3999,
               ts=T0 + timedelta(seconds=100))
    sudo = ex(["sudo", "useradd", "helper"], exe="/usr/bin/sudo", uid="33", pid=4001, ppid=4000,
              ts=T0 + timedelta(seconds=100, milliseconds=5))
    child = ex(["useradd", "helper"], pid=4002, ppid=4001, ts=T0 + timedelta(seconds=100, milliseconds=10))
    for e in (shell, sudo, child):
        e.host = "prov01"
    out = run([*provisioning(admin_groups=("adm",)), shell, sudo, child])[1]
    assert sorted((m.group_key.split("|")[0], m.proposed_lane) for m in out) == [("actor", "high"), ("burst", "lead")]


# ---------------------------------------------------------------- windows and hosts
@pytest.mark.parametrize("pause,items", [(GAP - 0.001, 1), (GAP, 2), (GAP + 60, 2)])
def test_two_runs_more_than_the_gap_apart_are_two_items_half_open(pause, items):
    first = provisioning(users=3, admin_groups=(), passwords=0, step=1.0)
    start = first[-1].ts + timedelta(seconds=pause) - timedelta(seconds=1.0)
    second = provisioning(start=start, users=3, admin_groups=(), passwords=0, step=1.0)
    out = run([*first, *second])[1]
    assert len(bursts(out)) == items and len(out) == items
    assert sum(int(m.claim.split(", ", 1)[1].split(" ", 1)[0]) for m in out) == 18


def test_runs_on_two_hosts_are_two_items():
    out = run([*provisioning(users=5, host="prov01"), *provisioning(users=5, host="prov02")])[1]
    assert sorted(m.group_key.split("|")[1] for m in out) == ["prov01", "prov02"]
    assert all(m.proposed_lane == "high" for m in out)


def test_a_run_longer_than_the_span_goes_on_in_a_second_item_and_both_say_so():
    # a change every five minutes for 100 minutes: the gap never breaks it, the hour does
    events = []
    for i in range(21):
        events.append(line("useradd", f"new user: name=s{i:02d}, UID={3000 + i}, GID={3000 + i}, home=/srv, "
                                      "shell=/usr/sbin/nologin, from=none", T0 + timedelta(minutes=5 * i)))
    out = sorted(run(events)[1], key=lambda m: m.ts)
    assert [m.group_key.split("|")[0] for m in out] == ["burst", "burst"]
    first, second = out
    assert "The run goes on past this item" in first.claim and "The run began earlier" not in first.claim
    assert "The run began earlier" in second.claim and "goes on past" not in second.claim
    assert "12 account or group change(s)" in first.claim and "9 account or group change(s)" in second.claim
    assert second.ts - first.ts == timedelta(hours=1)


def test_a_small_run_keeps_the_per_actor_findings():
    # two names (the account and one group) are one account's setup, not a run of several
    events = [line("usermod", "add 'ops' to group 'video'", T0),
              line("passwd", "password for 'ops' changed by 'root'", T0 + timedelta(seconds=5))]
    out = run(events)[1]
    assert sorted(m.group_key.split("|")[0] for m in out) == ["actor", "actor"]
    # a third name makes it a run
    out = run([*events, line("usermod", "add 'ops' to group 'audio'", T0 + timedelta(seconds=9))])[1]
    assert [m.group_key.split("|")[0] for m in out] == ["burst"] and "3 account or group change(s)" in out[0].claim


def test_boot_and_package_groups_are_unchanged_beside_a_run():
    from tests.test_account_changes import boot, first_boot_passwords
    marker = boot(T0 - timedelta(hours=2), host="prov01")
    early = first_boot_passwords(start=T0 - timedelta(hours=2) + timedelta(seconds=40), host="prov01")
    out = run([marker, *early, *provisioning(users=4, admin_groups=())])[1]
    assert sorted(m.group_key.split("|")[0] for m in out) == ["boot", "burst"]


# ---------------------------------------------------------------- caps, spill and volume
def test_caps_on_names_and_citations_make_the_item_say_what_it_does_not_list(monkeypatch):
    monkeypatch.setattr(AccountOrGroupChange, "NAMED", 10)
    monkeypatch.setattr(AccountOrGroupChange, "PRIVILEGED_NAMED", 3)
    monkeypatch.setattr(AccountOrGroupChange, "BURST_CITE", 5)
    events = provisioning(users=20, admin_groups=("sudo", "lxd", "docker", "wheel", "disk", "adm"), passwords=0)
    pb, [m] = run(events)
    assert "66 account or group change(s)" in m.claim and m.proposed_lane == "high"
    assert "5 of them request or report privileged access" in m.claim
    assert "and 0 more" not in m.claim
    assert sum(n.startswith("privileged change:") for n in m.notes) == 3
    assert "2 further privileged change(s) are counted, not named (the first 3 are)" in m.notes
    assert "51 further change(s) are counted by kind, not named (the first 10 distinct changes are)" in m.notes
    assert "The records of 5 of the 66 changes are cited" in m.claim
    cited_groups = {e.get("account.group") for e in m.events if e.get("account.group")}
    assert len(cited_groups & {"sudo", "lxd", "docker", "wheel", "disk"}) == 4    # privileged first, one slot kept
    assert any("more than 10 distinct changes" in r for r in pb.limit_reasons())
    assert any("more than 3 privileged changes" in r for r in pb.limit_reasons())


def test_a_run_straddling_the_change_budget_is_honest_about_what_it_does_not_count(tmp_path, monkeypatch):
    events = sorted(provisioning(users=30), key=lambda e: (e.ts, e.id))
    parts = [events[:60], events[60:]]
    _unbounded, whole = staged_run(AccountOrGroupChange, parts, tmp_path / "big", hot=10**6, monkeypatch=monkeypatch)
    monkeypatch.setattr(AccountOrGroupChange, "HOT", 1)
    rule = AccountOrGroupChange()
    rule.spill_dir = tmp_path / "small"
    stage, out = {}, []
    out += rule.consume(list(parts[0]))
    stage.update({e.id: e for e in rule.drain_staged()})
    rule.records.disk_budget = 1                     # the budget is spent mid-run
    refuse_configured_stores(rule)
    out += rule.consume(list(parts[1]))
    stage.update({e.id: e for e in rule.drain_staged()})
    rule.bind_loader(lambda ids: [stage[i] for i in ids if i in stage])
    out += rule.finalize()
    [run_item] = bursts(out)
    alone = [m for m in out if m.group_key.endswith("|unheld")]
    assert alone and any("published as they are read" in r for r in rule.limit_reasons())
    held = int(run_item.claim.split(", ", 1)[1].split(" ", 1)[0])
    unheld = sum(int(n.split(" ", 1)[0]) for n in run_item.notes
                 if n.endswith("they are not counted in this item"))
    # nothing lost: the run's count plus the changes published alone is every change
    assert held + unheld == 30 * 3 + 6 + 14 == int(bursts(whole)[0].claim.split(", ", 1)[1].split(" ", 1)[0])
    assert run_item.proposed_lane == "high" or any(m.proposed_lane == "high" for m in alone)


def _fleet(hosts, users, *, start=T0):
    """Record-only provisioning on many hosts, built without the normalizer (fast): an audit ADD_USER and a tool
    line for each new account, an expiry change, and the administrator added to sudo."""
    events, pid = [], 50000
    for h in range(hosts):
        host = f"node{h:04d}"
        t = start + timedelta(seconds=h % 600)
        for u in range(users):
            pid += 1
            t += timedelta(seconds=1)
            name = f"u{u:04d}"
            events.append(record("ADD_USER", "create_user", ts=t, pid=pid, host=host, account__name=name,
                                 process__user="root", process__executable="/usr/sbin/useradd"))
            text = record("ADD_USER", "create_user", ts=t + timedelta(milliseconds=3), pid=pid, host=host,
                          account__name=name)
            del text.fields["audit.record_type"]            # the tool's own line: same typed fields, no audit type
            events.append(text)
            events.append(record("USER_MGMT", "modify_user", ts=t + timedelta(milliseconds=500), pid=pid + 10**6,
                                 host=host, account__name=name, account__op="change-password-expiry"))
        events.append(record("USER_MGMT", "modify_user", ts=t + timedelta(seconds=2), pid=pid + 2 * 10**6, host=host,
                             account__name="admin", account__group="sudo", account__op="add-user-to-group",
                             process__user="root"))
    return events


def _count(m) -> int:
    return int(m.claim.split(", ", 1)[1].split(" ", 1)[0])


def test_spilled_and_unspilled_fleets_are_identical(tmp_path, monkeypatch):
    events = sorted(_fleet(12, 40), key=lambda e: (e.ts, e.id))
    parts = [events[i:i + 250] for i in range(0, len(events), 250)]
    _small, out = same_small_and_unbounded(AccountOrGroupChange, parts, tmp_path, monkeypatch, "records")
    [m] = out
    assert m.group_key.startswith("burst-fleet|") and m.proposed_lane == "high" and m.fleet_host_count == 12
    hosts = list(m.fleet_hosts)
    _big, [big] = staged_run(AccountOrGroupChange, parts, tmp_path / "again", hot=10**6, monkeypatch=monkeypatch)
    assert hosts == list(big.fleet_hosts) and sorted(h for h, _ in hosts) == [f"node{h:04d}" for h in range(12)]
    assert "each host's run made the same 81 distinct change(s)" in m.claim     # 40 accounts, 40 expiries, 1 grant


def test_a_large_fleet_is_one_item_and_every_host_is_listed(tmp_path, monkeypatch):
    hosts, users = 200, 120
    events = sorted(_fleet(hosts, users), key=lambda e: (e.ts, e.id))
    parts = [events[i:i + 5000] for i in range(0, len(events), 5000)]
    monkeypatch.setattr(AccountOrGroupChange, "FLEET_CHUNK", 7)            # many chunks of the member list
    began = time.perf_counter()
    rule, out = staged_run(AccountOrGroupChange, parts, tmp_path, hot=500, monkeypatch=monkeypatch)
    elapsed = time.perf_counter() - began
    assert rule.records.on_disk > 0 and rule.capped == 0 and rule.limit_reasons() == []
    [m] = out
    assert m.fleet_host_count == hosts and m.fleet_hosts_complete and m.proposed_lane == "high"
    listed = list(m.fleet_hosts)
    assert sorted(h for h, _ in listed) == [f"node{h:04d}" for h in range(hosts)]
    assert f"each host's run made the same {users * 2 + 1} distinct change(s)" in m.claim
    assert f"and {hosts - 12} more (all {hosts} are in the paged host list)" in m.claim
    assert len({e.host for e in m.events}) == AccountOrGroupChange.FLEET_CITE_RUNS
    assert len(m.events) <= AccountOrGroupChange.FLEET_CITE
    assert elapsed < 180, elapsed


# ---------------------------------------------------------------- the same run on several hosts
def _hosts(n, users=10, start=T0, admin_groups=("adm", "sudo", "lxd"), prefix="node"):
    events = []
    for h in range(n):
        events += provisioning(start=start + timedelta(minutes=h), host=f"{prefix}{h:02d}", users=users,
                               admin_groups=admin_groups, passwords=2)
    return events


def test_twelve_hosts_with_the_same_run_are_one_fleet_item():
    out = run(_hosts(12))[1]
    [m] = out
    assert m.group_key.startswith("burst-fleet|") and (m.proposed_lane, m.severity) == ("high", "high")
    assert m.fleet_host_count == 12 and m.fleet_hosts_complete
    assert sorted(h for h, _ in m.fleet_hosts) == [f"node{h:02d}" for h in range(12)]
    assert "On 12 hosts, the same run of account and group changes was recorded" in m.claim
    assert "it does not show that the runs share an origin" in m.claim
    assert "On every host the run requests or reports privileged access" in m.claim
    assert "membership of privileged group sudo" in m.claim and "membership of privileged group lxd" in m.claim
    assert "Hosts: node00, node01" in m.claim and "and" not in m.claim.split("Hosts: ", 1)[1].split(".", 1)[0]
    assert len({e.host for e in m.events}) == 8                     # exemplar records from several hosts' runs
    assert any(n.startswith("fleet change:") and "group 'sudo'" in n for n in m.notes)


def test_a_host_with_an_extra_sudo_grant_stays_its_own_high_item_and_the_fleet_names_it():
    events = _hosts(12)
    events += provisioning(start=T0 + timedelta(minutes=12), host="node12", users=10, admin_groups=("adm", "sudo",
                                                                                                    "lxd"), passwords=2)
    events.append(line("usermod", "add 'backdoor' to group 'sudo'", T0 + timedelta(minutes=13), host="node12"))
    out = run(events)[1]
    fleet = next(m for m in out if m.group_key.startswith("burst-fleet|"))
    alone = [m for m in out if not m.group_key.startswith("burst-fleet|")]
    assert fleet.fleet_host_count == 12 and "node12" not in {h for h, _ in fleet.fleet_hosts}
    assert [(m.group_key.split("|")[:2], m.proposed_lane) for m in alone] == [(["burst", "node12"], "high")]
    assert "'backdoor'" in alone[0].claim
    assert ("1 similar host run(s) differ from this shape and keep their own items: node12 (1 change(s) the fleet's "
            "runs do not make: group membership grant (account 'backdoor', group 'sudo'): membership of privileged "
            "group sudo)") in fleet.claim
    assert any(n.startswith("excluded: node12") for n in fleet.notes)


def test_two_hosts_are_below_the_fleet_minimum():
    out = run(_hosts(2))[1]
    assert sorted(m.group_key.split("|")[0] for m in out) == ["burst", "burst"]
    out = run(_hosts(3))[1]
    assert [m.group_key.split("|")[0] for m in out] == ["burst-fleet"]


def test_runs_that_differ_by_actor_are_not_merged_and_are_named():
    events = _fleet(4, 5)
    for e in events:
        if e.host == "node0003" and e.get("process.user") == "root" and e.get("account.action") == "create_user":
            e.fields["process.user"] = fv("alice", "fixture:process.user")
    out = run(events)[1]
    fleet = next(m for m in out if m.group_key.startswith("burst-fleet|"))
    assert fleet.fleet_host_count == 3
    [own] = [m for m in out if m is not fleet]
    assert own.group_key.startswith("burst|node0003|") and own.proposed_lane == "high"
    assert ("node0003 (recorded as 'alice', 'an unrecorded account', 'root' rather than 'an unrecorded account', "
            "'root')") in fleet.claim



def test_the_same_run_at_an_odd_moment_stays_its_own_item_and_is_named():
    late = T0 + timedelta(hours=10)
    events = _hosts(5) + provisioning(start=late, host="late01", users=10, admin_groups=("adm", "sudo", "lxd"),
                                      passwords=2)
    out = run(events)[1]
    fleet = next(m for m in out if m.group_key.startswith("burst-fleet|"))
    own = [m for m in out if m is not fleet]
    assert fleet.fleet_host_count == 5 and [m.group_key.split("|")[1] for m in own] == ["late01"]
    assert own[0].proposed_lane == "high"
    assert "late01 (started at 2030-03-04T19:00:02+00:00, outside the fleet window)" in fleet.claim


@pytest.mark.parametrize("offset,merged", [(AccountOrGroupChange.FLEET_WINDOW - 1, True),
                                           (AccountOrGroupChange.FLEET_WINDOW, False)])
def test_the_fleet_window_is_half_open(offset, merged):
    events = _hosts(3, users=3)
    events += provisioning(start=T0 + timedelta(seconds=offset), host="edge", users=3,
                           admin_groups=("adm", "sudo", "lxd"), passwords=2)
    out = run(events)[1]
    fleet = next(m for m in out if m.group_key.startswith("burst-fleet|"))
    assert fleet.fleet_host_count == (4 if merged else 3)


def test_a_fleet_item_is_published_through_the_sweep_with_its_host_list(tmp_path, monkeypatch):
    from tests import test_linux_text_stack_r2 as stack
    from tests import throughput_fixture as tf

    builder = tf.Builder(29)
    for h, host in enumerate(("web1", "db1", "fw1")):
        for n, body in enumerate(("useradd[{pid}]: new group: name=svc, GID=990",
                                  ("useradd[{pid}]: new user: name=svc, UID=990, GID=990, home=/srv, "
                                   "shell=/usr/sbin/nologin, from=none"),
                                  "usermod[{pid}]: add 'admin' to group 'sudo'",
                                  "usermod[{pid}]: add 'admin' to group 'adm'")):
            when = tf.T0 + timedelta(minutes=h, seconds=n)
            builder._doc(host, when, "custom.auth", None,
                         message=f"Nov 18 {when:%H:%M:%S} {host} {body.format(pid=4200 + 10 * h + n)}")
    monkeypatch.setattr(stack, "text_documents",
                        lambda: {tf.HOST_TARGET: builder.host, tf.NETWORK_TARGET: [], tf.ARKIME_TARGET: []})
    snapshot, _trace, _docs = stack.run_text_stack(tmp_path, monkeypatch)
    assert snapshot["stats"]["errors"] == 0 and not snapshot["stats"].get("rule_failures")
    [row] = [row for row in snapshot["candidates"] if row["rule_id"] == "host.account_or_group_change"]
    assert row["lane"] == "high" and row["group_key"].startswith("burst-fleet|")
    gates = row["gate_results"]
    assert gates["_fleet_host_count"] == 3 and gates["_fleet_hosts_complete"] is True


def test_gpasswd_audit_record_and_its_line_pair():
    # shadow-utils gpasswd -a: audit_logger_with_group(AUDIT_USER_MGMT, "add-user-to-group", user, ..., "grp", group)
    # and syslog "user %s added by %s to group %s"
    rec = audit("USER_MGMT", "modify_user", T0, host="app01", pid=9500, account__op="add-user-to-group",
                account__name="mallory", account__group="sudo", exe="/usr/bin/gpasswd")
    text = line("gpasswd", "user mallory added by root to group sudo", T0 + timedelta(milliseconds=200),
                host="app01", pid=9500)
    [m] = run([rec, text])[1]
    assert {e.id for e in m.events} == {rec.id, text.id} and m.proposed_lane == "high"


def test_real_shipper_shapes_of_one_useradd_pair_into_one_change():
    """The audit ADD_USER line as auditd writes it and useradd's own System-integration syslog line, both typed by
    the normalizer: one change citing both, the actor from the audit record."""
    from romulus.evidence.normalize import normalize_hits
    from tests import linux_shipper_fixtures as fx
    hits = [*fx.dev_audit(fx.useradd_lines()),
            fx.syslog("useradd", 1264, "new user: name=eve, UID=1001, GID=1001, home=/home/eve, shell=/bin/bash, "
                                       "from=/dev/pts/0", "sl-eve", ts=fx.T0 + 6.2)]
    events, _skips, errors = normalize_hits(hits)
    assert not errors
    changes = [e for e in events if e.family == "account_change"]
    assert len(changes) == 2 and {e.has("audit.record_type") for e in changes} == {True, False}
    [m] = run(changes)[1]
    assert {e.id for e in m.events} == {e.id for e in changes}
    assert "2 account-management record(s)" in m.claim and "an account was added (account 'eve')" in m.claim
    assert "an unrecorded account" not in m.claim


def test_a_nameless_record_pairs_whichever_view_comes_first():
    for nameless_first in (True, False):
        nameless = audit("ADD_USER", "create_user", T0 + timedelta(seconds=0 if nameless_first else 2), host="app01",
                         pid=9040, exe="/usr/sbin/useradd")
        text = line("useradd", "new user: name=svc4, UID=993, GID=993, home=/srv, shell=/usr/sbin/nologin, "
                               "from=none", T0 + timedelta(seconds=1), host="app01", pid=9040)
        pb = AccountOrGroupChange()
        views = list(pb._views(sorted([nameless, text], key=lambda e: (e.ts, e.id))))
        assert [len(v) for v in views] == [2], nameless_first


def test_a_full_pairing_window_takes_the_oldest_alone_and_says_so(monkeypatch):
    monkeypatch.setattr(AccountOrGroupChange, "VIEW_OPEN", 2)
    records = [audit("ADD_USER", "create_user", T0 + timedelta(milliseconds=i), host="app01", pid=9100 + i,
                     account__name=f"x{i}", exe="/usr/sbin/useradd") for i in range(5)]
    pb = AccountOrGroupChange()
    views = list(pb._views(records))
    assert sorted(len(v) for v in views) == [1] * 5            # nothing lost, nothing paired
    assert any("more than 2 account tool records of one host were unpaired" in r for r in pb.limit_reasons())


def test_more_distinct_names_than_counted_is_a_lower_bound(monkeypatch):
    monkeypatch.setattr(AccountOrGroupChange, "BURST_TARGET_NAMES", 5)
    [m] = run(provisioning(users=8, admin_groups=(), passwords=0))[1]             # eight names
    assert "24 account or group change(s)" in m.claim and "naming more than 5 distinct" in m.claim
    assert "more than 5 distinct account and group names: the count is a lower bound" in m.notes


def test_a_run_item_is_admitted_with_its_lane():
    from romulus.decide.policy import decide
    [m] = run(provisioning(users=10))[1]
    decision = decide(m, "h1")
    assert decision.admitted and decision.lane == "high" and decision.severity == "high"
    assert all(not verdict.startswith("fail") for verdict in decision.gates.values())


# ---------------------------------------------------------------- ranking: one run counts once
def _ranked(account_items: int):
    from romulus.hunt.rank import PASS_FINAL, compute_rank_pass
    from tests.test_evidence_rank import START, _insert, _ranks, _repo, _row
    repo = _repo()
    rows = [_row(f"acct{i:03d}", "host.account_or_group_change", lane="high", host="prov", attack=["T1136.001"],
                 ts=START + timedelta(seconds=i)) for i in range(account_items)]
    rows.append(_row("prov-cred", "r.cred", host="prov", attack=["T1003"], ts=START + timedelta(hours=2)))
    rows += [_row(f"atk{i}", rule, host="atk", attack=[technique], ts=START + timedelta(hours=3, minutes=i))
             for i, (rule, technique) in enumerate((("r.exec", "T1059"), ("r.cred", "T1003"), ("r.c2", "T1071")))]
    _insert(repo, rows)
    compute_rank_pass(repo, "h1", PASS_FINAL)
    _findings, entities = _ranks(repo)
    top = [row["candidate_id"] for row in repo.finding_ranks_page("h1", PASS_FINAL, reported=True, limit=10)]
    return entities, top


def test_separate_changes_crowd_the_top_and_one_run_counts_once():
    """Entity evidence counts a rule once whatever its item count (so the host's score is the same), but every item
    is ranked: 200 per-change items fill the top ten, one run item takes one place."""
    separate_entities, separate_top = _ranked(200)
    folded_entities, folded_top = _ranked(1)
    assert separate_entities[("host", "prov")]["score"] == folded_entities[("host", "prov")]["score"]
    # each high per-change item ranks above the other host's lead findings: they take the whole top ten
    assert sum(cid.startswith("acct") for cid in separate_top) == 10
    assert sum(cid.startswith("acct") for cid in folded_top) == 1
    assert {"atk0", "atk1", "atk2", "prov-cred"} <= set(folded_top)


def test_a_provisioned_fleet_ranks_as_one_item_and_no_longer_buries_an_attacked_host():
    """Twelve freshly provisioned hosts, each meeting the evidence bar (the account change and a privilege-use lead
    of another tactic), and one attacked host with three tactics. Per-host run items take twelve reported places
    above the attacked host's leads; the fleet item takes one (its member hosts are the hunt's hosts and the rule's
    prevalence, as for every fleet-grouped finding, but its evidence counts once, on the host it cites)."""
    from romulus.hunt.rank import PASS_FINAL, compute_rank_pass
    from tests.test_evidence_rank import START, _insert, _repo, _row

    def ranked(fleet: bool) -> list[str]:
        repo = _repo()
        if fleet:
            rows = [_row("acct-fleet", "host.account_or_group_change", lane="high", host="node00",
                         attack=["T1136.001"], ts=START)]
        else:
            rows = [_row(f"acct{h:02d}", "host.account_or_group_change", lane="high", host=f"node{h:02d}",
                         attack=["T1136.001"], ts=START + timedelta(minutes=h)) for h in range(12)]
        rows += [_row(f"priv{h:02d}", "r.priv", host=f"node{h:02d}", attack=["T1548.003"],
                      ts=START + timedelta(minutes=h, seconds=40)) for h in range(12)]
        rows += [_row(f"atk{i}", rule, host="atk", attack=[technique], ts=START + timedelta(hours=3, minutes=i))
                 for i, (rule, technique) in enumerate((("r.exec", "T1059"), ("r.cred", "T1003"),
                                                         ("r.c2", "T1071")))]
        _insert(repo, rows)
        if fleet:
            repo.save_candidate_hosts("acct-fleet", "h1", [(f"node{h:02d}", f"e{h}") for h in range(12)],
                                      replace=True, expected_count=12)
        compute_rank_pass(repo, "h1", PASS_FINAL)
        return [row["candidate_id"] for row in repo.finding_ranks_page("h1", PASS_FINAL, reported=True, limit=40)]

    per_host, merged = ranked(False), ranked(True)
    assert per_host[:12] == [f"acct{h:02d}" for h in range(12)] and per_host.index("atk0") >= 12
    assert merged[0] == "acct-fleet" and set(merged[1:4]) == {"atk0", "atk1", "atk2"}
