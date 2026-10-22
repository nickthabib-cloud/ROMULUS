"""Flow rules keep cross-sensor per-connection state for the whole window (the sensors' records of one connection
arrive in different targets). It is budgeted: a record needing new state beyond a budget is refused and coverage
says so, and per-destination connection identities are counted as hashes."""
import pytest

from romulus.detect import flows
from tests.test_flow_rules import eve, events, run


@pytest.mark.parametrize("cls, attr, make", [
    (flows.HorizontalSweep, "MAX_DESTINATIONS", lambda i: eve(f"h{i}", dst=f"10.0.1.{i}", dport=445)),
    (flows.HorizontalSweep, "MAX_GROUPS", lambda i: eve(f"g{i}", src=f"10.0.0.{i}", dport=445)),
    (flows.OutboundVolumeAsymmetry, "MAX_PAIRS", lambda i: eve(f"o{i}", dst=f"198.51.100.{i}", dport=443, s2c=10,
                                                               pkts_s=1)),
    (flows.OutboundVolumeAsymmetry, "MAX_CONNECTIONS", lambda i: eve(f"c{i}", dst="198.51.100.9", dport=443,
                                                                     sport=40000 + i, s2c=10, pkts_s=1)),
    (flows.LongUnidentifiedSession, "PIECES_BUDGET", lambda i: eve(f"p{i}", dst="198.51.100.9", dport=7000,
                                                                   sport=40000 + i, c2s=4000, s2c=4000, pkts_c=3,
                                                                   pkts_s=3, seconds=60)),
    (flows.ProtocolPortMismatch, "MAX_MISMATCHES", lambda i: eve(f"m{i}", dst=f"198.51.100.{i}", dport=443,
                                                                 app_proto="ssh", c2s=4000, s2c=9000, pkts_s=12)),
])
def test_flow_budgets_refuse_and_make_coverage_partial(monkeypatch, cls, attr, make):
    monkeypatch.setattr(cls, attr, 3)
    rule = cls()
    rule.consume(events(*[make(i) for i in range(1, 8)]))
    assert rule.capped == 4, (cls.id, rule.capped)
    assert any("4 record(s) not evaluated" in r for r in rule.limit_reasons())


def test_destination_connections_are_counted_as_hashes_and_claims_are_unchanged():
    hits = [eve(f"s{i}", dst=f"10.0.1.{i}", sport=50000 + i) for i in range(30)]
    rule = flows.HorizontalSweep()
    [m] = run(rule, events(*hits))
    assert "contacted 30 distinct internal addresses" in m.claim and "30 distinct connection(s)" in m.claim
    assert all(isinstance(c, int) for g in rule.sweeps.values() for d in g.destinations.values()
               for c in d.connections)


def test_identified_budget_keeps_more_leads_never_fewer(monkeypatch):
    monkeypatch.setattr(flows.ProtocolPortMismatch, "IDENTIFIED_BUDGET", 0)
    hits = [eve("i1", dst="198.51.100.9", dport=443, app_proto="tls", c2s=4000, s2c=9000, pkts_c=3, pkts_s=12)]
    rule = flows.ProtocolPortMismatch()
    run(rule, events(*hits))
    assert rule.identified == {} and any("more leads" in r for r in rule.limit_reasons())
