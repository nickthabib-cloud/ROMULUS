"""Mission-scale state of the tamper and indicator rules: command matches, routine records and indicator groups
spill to disk and read back exactly; routine records and listed-subdomain floods can never use up the room a later
strong match needs; only a disk budget refuses, and a refused record is not counted as evaluated."""
from datetime import timedelta

from romulus.detect import tamper
from romulus.detect.indicators import Indicator, IndicatorMatch, IndicatorSet
from tests.test_bounded_host import T0, ev, same_small_and_unbounded, staged_run
from tests.test_tamper import cfg, ex

# ---------------------------------------------------------------- tamper


def unit_stop(ts, host_name, name="rsyslog"):
    return ev("service_change", ts, host_name=host_name, service__unit=name, service__name=name, service__job="stop",
              service__job_phase="done", service__scope="system", service__source="audit", process__pid=1)


def unit_start(ts, host_name, name="rsyslog"):
    return ev("service_change", ts, host_name=host_name, service__unit=name, service__name=name,
              service__job="start", service__job_phase="done", service__scope="system", service__source="audit",
              process__pid=1)


def fleet_config(ts, host_name, i):
    rec = cfg("remove_rule", ts=ts, pid=4000 + i, auid="4294967295", ses=4294967295, key=f"k{i}")
    rec.host = host_name
    return rec


def fleet_reboot(hosts=200):
    """A patch reboot of a fleet: every host's logging units stop and its audit rules are reloaded."""
    parts = []
    for wave in range(4):
        part = []
        for h in range(hosts):
            ts = T0 + timedelta(minutes=wave, seconds=h % 60)
            part += [unit_stop(ts, f"node{h}"), unit_stop(ts, f"node{h}", "auditd"),
                     fleet_config(ts, f"node{h}", h), fleet_config(ts + timedelta(seconds=1), f"node{h}", h)]
        parts.append(part)
    return parts


def strong(rule_cls, command, tmp_path, monkeypatch, *, flood):
    """The command's findings, read after a fleet reboot whose routine records spent their list's disk budget."""
    parts = (fleet_reboot() if flood else []) + [[command]]
    monkeypatch.setattr(rule_cls, "HOT", 5)
    monkeypatch.setattr(rule_cls, "ROUTINE_DISK", 1)
    rule, out = staged_run(rule_cls, parts, tmp_path / ("flood" if flood else "alone"))
    return rule, [m for m in out if command.id in {e.id for e in m.events}]


def test_a_fleet_reboot_cannot_starve_a_later_auditd_stop_command(tmp_path, monkeypatch):
    command = ex(["systemctl", "stop", "auditd"], ts=T0 + timedelta(hours=2))
    command.host = "node7"
    rule, found = strong(tamper.SecurityOrLoggingServiceStop, command, tmp_path, monkeypatch, flood=True)
    assert rule.capped > 0 and any("unit stop list's disk budget is spent" in r for r in rule.limit_reasons())
    _alone_rule, alone = strong(tamper.SecurityOrLoggingServiceStop, command, tmp_path, monkeypatch, flood=False)
    [m] = found
    assert m.proposed_lane == alone[0].proposed_lane == "high" and m.claim == alone[0].claim


def test_a_fleet_reboot_cannot_starve_a_later_delete_all_audit_rules_command(tmp_path, monkeypatch):
    command = ex(["auditctl", "-D"], exe="/usr/sbin/auditctl", pid=7004, ts=T0 + timedelta(hours=2))
    command.host = "node7"
    rule, found = strong(tamper.AuditRulesTamper, command, tmp_path, monkeypatch, flood=True)
    assert rule.capped > 0 and any("audit configuration list's disk budget is spent" in r
                                   for r in rule.limit_reasons())
    _alone_rule, alone = strong(tamper.AuditRulesTamper, command, tmp_path, monkeypatch, flood=False)
    [m] = found
    assert m.proposed_lane == alone[0].proposed_lane and m.claim == alone[0].claim
    assert "delete every audit rule (-D)" in m.claim


def test_tamper_records_and_per_key_times_spill_and_read_back_exactly(tmp_path, monkeypatch):
    """Stops with and without restarts and commands with linked records on 40 hosts, a hot set of two."""
    parts = []
    for p in range(6):
        part = []
        for h in range(40):
            ts = T0 + timedelta(hours=p, seconds=h)
            part += [unit_stop(ts, f"node{h}"), unit_start(ts + timedelta(seconds=30 if h % 2 else 900), f"node{h}")]
            if h % 5 == 0:
                command = ex(["systemctl", "stop", "auditd"], ts=ts + timedelta(seconds=40), pid=9000 + h)
                command.host = f"node{h}"
                part += [command, unit_stop(ts + timedelta(seconds=41), f"node{h}", "auditd")]
        parts.append(part)
    rule, out = same_small_and_unbounded(tamper.SecurityOrLoggingServiceStop, parts, tmp_path, monkeypatch, "stops")
    assert len(rule.starts) == 40 and len({m.group_key for m in out}) == len(out)


def test_audit_configuration_spills_and_reads_back_exactly(tmp_path, monkeypatch):
    parts = []
    for p in range(5):
        part = []
        for h in range(30):
            ts = T0 + timedelta(hours=p, seconds=h)
            command = ex(["auditctl", "-D"], exe="/usr/sbin/auditctl", pid=7000 + h, ts=ts)
            command.host = f"node{h}"
            records = [fleet_config(ts + timedelta(milliseconds=10 * k), f"node{h}", h) for k in range(3)]
            for r in records:
                r.fields["process.pid"] = command.fields["process.pid"]
            part += [command, *records, fleet_config(ts + timedelta(minutes=5), f"node{h}", 100 + h)]
        parts.append(part)
    same_small_and_unbounded(tamper.AuditRulesTamper, parts, tmp_path, monkeypatch, "configs")


# ---------------------------------------------------------------- indicators
LISTED = IndicatorSet([
    Indicator(id="C2-DOM", kind="domain", values=("c2.test",), label="test C2 domain", severity="high", lane="high",
              source="unit"),
    Indicator(id="C2-IP", kind="ip", values=("198.51.100.7",), label="test C2 address", severity="high", lane="high",
              source="unit"),
])


class _Listed(IndicatorMatch):
    def __init__(self):
        super().__init__(LISTED)


def query(ts, name, host_name="sensor"):
    return ev("dns_query", ts, host_name=host_name, source__ip="10.0.0.5", dns__question__name=name)


def contact(ts, host_name="sensor"):
    return ev("net_flow", ts, host_name=host_name, source__ip="10.0.0.5", destination__ip="198.51.100.7")


def test_a_listed_subdomain_flood_cannot_starve_a_later_indicator_hit(tmp_path, monkeypatch):
    """DNS tunnelling to a listed C2 domain: every query names a new subdomain, so every query is a new value. Once
    the per-value groups' disk budget is spent, later values join one overflow group; a later contact with a listed
    address is still found at its indicator's lane, and nothing is refused."""
    flood = [[query(T0 + timedelta(seconds=100 * p + i), f"x{p}-{i}.c2.test") for i in range(100)] for p in range(5)]
    hit = contact(T0 + timedelta(hours=1))
    rule, out = staged_run(_Listed, [*flood, [hit]], tmp_path, hot=2, monkeypatch=monkeypatch,
                           budgets={"groups": 1})
    assert rule.capped == 0 and rule.evaluated == 501
    [ip] = [m for m in out if m.group_key.startswith("C2-IP|")]
    assert ip.proposed_lane == "high" and [e.id for e in ip.events] == [hit.id] and "198.51.100.7" in ip.claim
    domains = [m for m in out if m.group_key.startswith("C2-DOM|")]
    [overflow] = [m for m in domains if m.group_key.endswith("|*")]
    assert all(m.proposed_lane == "high" for m in domains)
    assert "per-value groups' disk budget was spent" in overflow.claim and "more value(s)" in overflow.claim
    counts = [int(m.claim.split(" ", 1)[0]) for m in domains]
    assert sum(counts) == 500                   # every flood record is counted in exactly one group
    assert any("grouped per indicator, role and host" in r for r in rule.limit_reasons())


def test_indicator_groups_spill_and_read_back_exactly(tmp_path, monkeypatch):
    parts = [[query(T0 + timedelta(minutes=p, seconds=i), f"h{i}.c2.test", f"s{i % 3}") for i in range(40)]
             + [contact(T0 + timedelta(minutes=p), f"s{p % 3}")] for p in range(6)]
    rule, out = same_small_and_unbounded(_Listed, parts, tmp_path, monkeypatch, "groups")
    assert len(out) == 43 and all(item[1] is None for _k, state in rule.groups.items() for item in state[2].items)


def test_an_indicator_hit_with_no_room_for_a_group_is_published_on_its_own(tmp_path, monkeypatch):
    parts = [[query(T0, f"a{i}.c2.test", f"s{i}") for i in range(4)],
             [query(T0 + timedelta(minutes=1), f"b{i}.c2.test", f"t{i}") for i in range(4)],
             [query(T0 + timedelta(minutes=2), f"c{i}.c2.test", f"u{i}") for i in range(4)]]
    rule, out = staged_run(_Listed, parts, tmp_path, hot=1, monkeypatch=monkeypatch,
                           budgets={"groups": 1, "overflow": 1})
    alone = [m for m in out if m.group_key.endswith("|unheld")]
    assert len(out) == 12 and len(alone) == 4 and rule.capped == 0 and rule.evaluated == 12
    assert all(len(m.events) == 1 and "1 dns_query record(s)" in m.claim for m in alone)
    assert any("published one record at a time" in r for r in rule.limit_reasons())
