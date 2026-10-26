"""Flow rules keep cross-sensor per-connection state for the whole window (the sensors' records of one connection
arrive in different targets). Every structure is a keyed store: a hot set in memory, the rest on disk, so a hot set
far smaller than the data changes no result. Only the disk budget refuses a record, and coverage says so."""
from datetime import UTC, datetime, timedelta

import pytest

from romulus.detect import bounded, flows
from tests.test_flow_rules import ark, eve, events, run

T0 = datetime(2024, 11, 18, 14, 0, 0, tzinfo=UTC)
MIB = 2**20
HOTS = {flows.HorizontalSweep: ("HOT_GROUPS", "HOT_DESTINATIONS"),
        flows.IcmpEchoTunnel: ("HOT",),
        flows.ProtocolPortMismatch: ("HOT", "HOT_GROUPS"),
        flows.LongUnidentifiedSession: ("HOT",),
        flows.OutboundVolumeAsymmetry: ("HOT_PAIRS", "HOT_CONNECTIONS")}


def at(seconds):
    return T0 + timedelta(seconds=seconds)


def sweep_hits():
    hits = [eve(f"sw{i}", dst=f"10.0.1.{i}", sport=50000 + i, start=at(i)) for i in range(1, 70)]
    hits += [eve(f"sx{i}", src="10.0.0.6", dst=f"203.0.113.{i}", dport=443, sport=40000 + i, start=at(3 * i))
             for i in range(1, 60)]
    hits += [eve(f"sy{i}", src=f"10.0.0.{i % 9 + 10}", dst=f"10.0.2.{i % 13 + 1}", dport=22, start=at(10 * i),
                 sport=30000 + i) for i in range(200)]
    return hits


def mismatch_hits():
    hits = [eve(f"mm{i}", dst=f"198.51.100.{i % 7 + 1}", src=f"10.0.0.{i % 5 + 1}", sport=41000 + i, dport=443,
                app_proto="ssh", c2s=4000, s2c=9000, pkts_s=12, start=at(i)) for i in range(60)]
    hits += [eve(f"mu{i}", dst=f"198.51.100.{i % 4 + 20}", sport=42000 + i, dport=443, c2s=9000, s2c=9000,
                 pkts_c=5, pkts_s=5, start=at(i)) for i in range(40)]
    hits += [eve(f"mi{i}", dst="198.51.100.30", sport=43000 + i, dport=443, app_proto="tls", c2s=9000, s2c=9000,
                 pkts_c=5, pkts_s=5, start=at(i)) for i in range(40)]
    return hits


def long_hits():
    hits = []
    for c in range(12):
        for k in range(8):
            hits.append(eve(f"lu{c}-{k}", src=f"10.0.0.{c % 4 + 1}", sport=44000 + c, dst=f"198.51.100.{c % 3 + 1}",
                            dport=7000, c2s=4000, s2c=4000, pkts_c=3, pkts_s=3, start=at(600 * k + c),
                            seconds=600))
    hits += [eve(f"ls{i}", sport=45000 + i, dst="198.51.100.1", dport=7000, c2s=4000, s2c=4000, pkts_c=3, pkts_s=3,
                 start=at(5 * i), seconds=60) for i in range(30)]
    return hits


def volume_hits():
    hits = [eve(f"ov{i}", src=f"10.0.0.{i % 3 + 1}", dst=f"198.51.100.{i % 5 + 1}", sport=46000 + i, dport=443,
                c2s=30 * MIB if i % 5 == 0 else 2000, s2c=50_000, pkts_s=40, start=at(i)) for i in range(150)]
    hits += [ark(f"oa{i}", src=f"10.0.0.{i % 3 + 1}", dst=f"198.51.100.{i % 5 + 1}", sport=46000 + i, dport=443,
                 c2s=31 * MIB if i % 5 == 0 else 2100, s2c=51_000, pkts_s=41, start=at(i)) for i in range(150)]
    return hits


def icmp_hits():
    hits = [eve(f"ic{i}", src=f"10.0.0.{i % 8 + 1}", sport=None, dst=f"198.51.100.{i % 7 + 1}", dport=None,
                proto="ICMP", c2s=12 * MIB, s2c=0, pkts_c=12_000, pkts_s=0, icmp_type=8, icmp_code=0,
                start=at(i)) for i in range(90)]
    return hits


SCENARIOS = [(flows.HorizontalSweep, sweep_hits), (flows.IcmpEchoTunnel, icmp_hits),
             (flows.ProtocolPortMismatch, mismatch_hits),
             (flows.LongUnidentifiedSession, long_hits), (flows.OutboundVolumeAsymmetry, volume_hits)]


def shape(matches):
    return sorted((m.group_key, m.claim, m.proposed_lane, tuple(e.id for e in m.events), tuple(m.notes))
                  for m in matches)


def chunks(evs, size):
    return [evs[i:i + size] for i in range(0, len(evs), size)]


def stores(rule):
    return [value for value in vars(rule).values() if isinstance(value, bounded.KeyedStore)]


@pytest.mark.parametrize("cls, make", SCENARIOS)
def test_flow_stores_spill_to_disk_and_change_nothing(monkeypatch, cls, make):
    evs = events(*make())
    full = run(cls(), *chunks(evs, 17))
    for name in HOTS[cls]:
        monkeypatch.setattr(cls, name, 1)
    rule = cls()
    stage = {}
    for batch in chunks(evs, 17):
        rule.consume(batch)
        stage.update({e.id: e for e in rule.drain_staged()})
        assert all(len(store.hot) <= 1 for store in stores(rule))
    assert sum(store.on_disk for store in stores(rule)) > 0
    rule.bind_loader(lambda ids: [stage[i] for i in ids if i in stage])
    small = rule.finalize()
    assert full and shape(full) == shape(small)
    assert rule.capped == 0 and rule.limit_reasons() == []


@pytest.mark.parametrize("cls, make", SCENARIOS)
def test_flow_disk_budget_refuses_and_makes_coverage_partial(monkeypatch, cls, make):
    monkeypatch.setattr(bounded, "DISK_BUDGET", 1)
    for name in HOTS[cls]:
        monkeypatch.setattr(cls, name, 1)
    rule = cls()
    for batch in chunks(events(*make()), 5):
        rule.consume(batch)
        rule.drain_staged()
    assert rule.capped > 0, cls.id
    assert any("disk budget is spent" in r and f"{rule.capped} record(s) not evaluated" in r
               for r in rule.limit_reasons())


def test_destination_connections_are_counted_as_hashes_and_claims_are_unchanged():
    hits = [eve(f"s{i}", dst=f"10.0.1.{i}", sport=50000 + i) for i in range(30)]
    rule = flows.HorizontalSweep()
    [m] = run(rule, events(*hits))
    assert "contacted 30 distinct internal addresses" in m.claim and "30 distinct connection(s)" in m.claim
    assert all(isinstance(c, int) for _key, d in rule.destinations.items() for c in d.connections)


def test_every_identified_connection_is_kept_so_no_extra_lead(monkeypatch):
    """A connection Suricata identified clears Arkime's unidentified record of it, however many identified
    connections were read before and however small the hot set."""
    monkeypatch.setattr(flows.ProtocolPortMismatch, "HOT", 1)
    identified = [eve(f"id{i}", dst="198.51.100.9", sport=47000 + i, dport=443, app_proto="tls", c2s=4000,
                      s2c=9000, pkts_c=3, pkts_s=12) for i in range(50)]
    unidentified = [ark(f"ar{i}", dst="198.51.100.9", sport=47000 + i, dport=443, c2s=4000, s2c=9000, pkts_c=3,
                        pkts_s=12, data_c=500, data_s=900) for i in range(50)]
    rule = flows.ProtocolPortMismatch()
    out = run(rule, *chunks(events(*identified), 7), *chunks(events(*unidentified), 7))
    assert out == [] and rule.identified.on_disk > 0 and rule.limit_reasons() == []


@pytest.mark.slow
def test_mission_scale_flow_state_holds_a_bounded_hot_set_and_finds_what_an_unbounded_run_finds(monkeypatch):
    hits = [eve(f"big{i}", src=f"10.{i % 50}.0.{i % 200 + 1}",
                dst=f"203.0.113.{i % 250 + 1}" if i % 4 == 1 else f"10.9.{i // 250 % 250}.{i % 250 + 1}",
                sport=30000 + i % 30000, dport=(445, 443, 3389, 7000)[i % 4], c2s=4000, s2c=4000 if i % 3 else 0,
                pkts_c=3, pkts_s=3 if i % 3 else 0, start=at(i * 0.5), seconds=900 if i % 4 == 3 else 1)
            for i in range(60_000)]
    hits += sweep_hits() + long_hits() + volume_hits()
    evs = events(*hits)
    for cls in (flows.HorizontalSweep, flows.LongUnidentifiedSession, flows.OutboundVolumeAsymmetry):
        full = run(cls(), *chunks(evs, 5000))
        for name in HOTS[cls]:
            monkeypatch.setattr(cls, name, 200)
        rule = cls()
        small = run(rule, *chunks(evs, 5000))
        assert shape(full) == shape(small) and sum(store.on_disk for store in stores(rule)) > 1000, cls.id
