"""Mission-scale state of the grouped network rules: examples on the stage, idle small groups released, and key
budgets that make coverage partial instead of growing without end."""
from datetime import UTC, datetime, timedelta

import pytest

from romulus.detect import network
from romulus.evidence.typed import RawRef, TypedEvent, fv

T0 = datetime(2024, 11, 4, 0, 0, tzinfo=UTC)
_n = 0


def event(family, ts, **fields):
    global _n
    _n += 1
    return TypedEvent(id=f"w{_n:09d}", family=family, ts=ts, host="sensor",
                      fields={k.replace("__", "."): fv(v, "fixture") for k, v in fields.items()},
                      raw=[RawRef(target="fx", native_id=f"w{_n}")], normalizer="fixture")


def flow(src, sport, dst, dport, ts):
    return event("net_flow", ts, source__ip=src, source__port=sport, destination__ip=dst, destination__port=dport)


def run_batches(rule, batches):
    stage = {}
    peak = 0
    for batch in batches:
        rule.consume(batch)
        stage.update({e.id: e for e in rule.drain_staged()})
        peak = max(peak, len(rule.counts))
    rule.bind_loader(lambda ids: [stage[i] for i in ids if i in stage])
    return rule.finalize(), peak


def test_grouped_rules_stage_their_examples_and_hold_only_ids():
    rule = network.PortScan()
    rule.consume([flow("10.0.0.66", 40000 + p, "10.0.0.9", p, T0 + timedelta(seconds=p)) for p in range(1, 40)])
    assert rule.staged and rule.retained_events() == []
    staged = rule.drain_staged()
    assert len(staged) == network.EXAMPLE_LIMIT
    assert all(isinstance(i, str) for ids in rule.groups.values() for i in ids)      # once staged, only ids
    rule.bind_loader(lambda ids: [e for e in staged if e.id in ids])
    [m] = rule.finalize()
    assert m.proposed_lane == "lead" and len(m.events) == network.EXAMPLE_LIMIT


def client_days(clients, servers, days, scan_day):
    """Each client opens one connection an hour to each of a few servers (one port each), in hourly partitions;
    every day the servers change. One scanner probes 200 ports of one host on `scan_day`."""
    for day in range(days):
        for hour in range(24):
            ts = T0 + timedelta(days=day, hours=hour)
            batch = [flow(f"10.1.{c // 250}.{c % 250 + 1}", 40000 + hour, f"10.9.{day}.{s + 1}", 443, ts)
                     for c in range(clients) for s in range(servers)]
            if day == scan_day and hour == 9:
                batch += [flow("10.1.200.1", 50000 + p, "10.9.99.1", p, ts + timedelta(seconds=p))
                          for p in range(1, 201)]
            yield batch


@pytest.mark.slow
def test_port_scan_holds_a_day_of_pairs_and_still_finds_the_scan():
    clients, servers, days = 200, 10, 7
    out, peak = run_batches(network.PortScan(), client_days(clients, servers, days, scan_day=4))
    assert peak <= clients * servers * 2 + 1, peak                    # about two days of pairs, not the hunt's
    leads = [m for m in out if m.proposed_lane == "lead"]
    assert [m.group_key for m in leads] == ["10.1.200.1|10.9.99.1"]
    assert "200 distinct destination ports" in leads[0].claim


def test_port_scan_counts_ports_of_one_activity_period():
    """A pair silent for more than a day with fewer than MIN_PORTS ports starts again: its ports of the earlier
    period are not added to the later one."""
    early = [flow("10.0.0.66", 40000 + p, "10.0.0.9", p, T0 + timedelta(seconds=p)) for p in range(1, 15)]
    filler = [flow("10.0.0.1", 40000, "10.0.0.2", 80, T0 + timedelta(days=2))]
    late = [flow("10.0.0.66", 41000 + p, "10.0.0.9", p, T0 + timedelta(days=3, seconds=p)) for p in range(15, 30)]
    out, _ = run_batches(network.PortScan(), [early, filler, late])
    assert [m.group_key for m in out if m.proposed_lane == "lead"] == []
    out, _ = run_batches(network.PortScan(), [early + filler + late])      # one batch: no release in between
    assert len(out) == 1 and out[0].group_key == "10.0.0.66|10.0.0.9"


def dns_question(client, name, ts):
    return event("dns_query", ts, source__ip=client, destination__ip="10.20.0.53", dns__type="query",
                 dns__question__name=name)


@pytest.mark.slow
def test_subdomain_enumeration_holds_a_day_of_pairs():
    def days():
        for day in range(6):
            for hour in range(24):
                ts = T0 + timedelta(days=day, hours=hour)
                batch = [dns_question(f"10.2.0.{c + 1}", f"www.d{day}h{hour}x{d}.test", ts)
                         for c in range(100) for d in range(5)]
                if day == 3 and hour == 2:
                    batch += [dns_question("10.2.9.9", f"h{i}.target.test", ts) for i in range(150)]
                yield batch
    out, peak = run_batches(network.DnsSubdomainEnumeration(), days())
    assert peak <= 100 * 5 * 24 * 2 + 1, peak
    assert [m.group_key for m in out] == ["10.2.9.9|target.test"]


@pytest.mark.parametrize("cls, make", [
    (network.SuricataAlertStack,
     lambda i: event("net_alert", T0 + timedelta(seconds=i), source__ip=f"10.3.0.{i}", destination__ip="10.3.1.1",
                     alert__signature="x", alert__severity=2, alert__category="c")),
    (network.WebScanBurst,
     lambda i: event("http_access", T0 + timedelta(seconds=i), source__ip=f"10.3.0.{i}",
                     http__response__status_code=404, url__original="/x")),
    (network.ToolUserAgentHttp,
     lambda i: event("http_tx", T0 + timedelta(seconds=i), source__ip=f"10.3.0.{i}", destination__ip="10.3.1.1",
                     user_agent__original="curl/8.0")),
    (network.PortScan, lambda i: flow(f"10.3.0.{i}", 40000, "10.3.1.1", 80, T0 + timedelta(seconds=i))),
    (network.DnsSubdomainEnumeration, lambda i: dns_question(f"10.3.0.{i}", "www.a.test", T0 + timedelta(seconds=i))),
])
def test_key_budget_refuses_new_groups_and_makes_coverage_partial(monkeypatch, cls, make):
    monkeypatch.setattr(cls, "MAX_KEYS", 3)
    rule = cls()
    rule.consume([make(i) for i in range(1, 8)])
    assert len(rule.counts) == 3 and rule.capped == 4 and rule.evaluated == 3
    assert any("4 record(s) not evaluated" in reason for reason in rule.limit_reasons())


def test_web_scan_url_budget_makes_the_url_count_a_lower_bound(monkeypatch):
    monkeypatch.setattr(network.WebScanBurst, "URLS_BUDGET", 50)
    events = [event("http_access", T0 + timedelta(seconds=i), source__ip="198.51.100.4",
                    http__response__status_code=404, url__original=f"/a{i}") for i in range(250)]
    out, _ = run_batches(rule := network.WebScanBurst(), [events])
    assert len(out) == 1 and "across 50+ distinct URLs" in out[0].claim
    assert any("lower bound" in reason for reason in rule.limit_reasons())
