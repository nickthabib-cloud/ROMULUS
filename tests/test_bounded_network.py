"""Mission-scale state of the grouped network rules: examples on the stage, group states beyond a small hot set on
the rule's disk spill and never released, so slow activity spread over days is found exactly as in one pass, and
only the disk budget can refuse a record (stated on coverage)."""
from datetime import UTC, datetime, timedelta

import pytest

from romulus.detect import bounded, network
from romulus.evidence.typed import RawRef, TypedEvent, fv

T0 = datetime(2024, 11, 4, 0, 0, tzinfo=UTC)
SCANNER, TARGET = "10.0.0.66", "10.0.0.9"
_n = 0


def event(family, ts, **fields):
    global _n
    _n += 1
    return TypedEvent(id=f"w{_n:09d}", family=family, ts=ts, host="sensor",
                      fields={k.replace("__", "."): fv(v, "fixture") for k, v in fields.items()},
                      raw=[RawRef(target="fx", native_id=f"w{_n}")], normalizer="fixture")


def flow(src, sport, dst, dport, ts):
    return event("net_flow", ts, source__ip=src, source__port=sport, destination__ip=dst, destination__port=dport)


def dns_question(client, name, ts):
    return event("dns_query", ts, source__ip=client, destination__ip="10.20.0.53", source__port=40000,
                 destination__port=53, dns__type="query",
                 dns__question__name=name)


def run_batches(rule, batches, check=None):
    stage = {}
    for batch in batches:
        rule.consume(batch)
        stage.update({e.id: e for e in rule.drain_staged()})
        if check is not None:
            check(rule)
    rule.bind_loader(lambda ids: [stage[i] for i in ids if i in stage])
    return rule.finalize()


def shape(out):
    return [(m.group_key, m.proposed_lane, m.severity, m.claim, [e.id for e in m.events]) for m in out]


def small(monkeypatch, cls, tmp_path, hot=1):
    """The rule with its hot sets forced to `hot` states, spilling under tmp_path."""
    monkeypatch.setattr(cls, "HOT", hot)
    if cls is network.PortScan:
        monkeypatch.setattr(cls, "REQUESTS_HOT", hot)
    rule = cls()
    rule.spill_dir = tmp_path
    return rule


def hot_bounded(rule):
    assert len(rule.groups.hot) <= rule.HOT
    assert not rule._fresh
    assert all(isinstance(x, str) for item in rule.groups.items() for x in item[1].held)     # once staged, only ids


def noise(ts, n=3):
    """Other pairs' records in the same batch, so a quiet group is pushed out of the hot set."""
    return [flow(f"10.5.0.{i + 1}", 40000 + i, "10.5.1.1", 443, ts) for i in range(n)]


def test_grouped_rules_stage_their_examples_and_hold_only_ids():
    rule = network.PortScan()
    rule.consume([flow(SCANNER, 40000 + p, TARGET, p, T0 + timedelta(seconds=p)) for p in range(1, 40)])
    assert rule.staged and rule.retained_events() == []
    staged = rule.drain_staged()
    # the first examples (the named ports' records are among them), and the record that bounds the span's end, held
    held, released = rule.drain_bounds()
    assert len({e.id for e in staged}) == network.EXAMPLE_LIMIT + 1 and released == []
    assert sorted(held) == sorted({staged[0].id, staged[-1].id}) and staged[-1].get("destination.port") == 39
    assert all(isinstance(i, str) for _key, state in rule.groups.items() for i in state.held)
    rule.bind_loader(lambda ids: [e for e in staged if e.id in ids])
    [m] = rule.finalize()
    # the first examples (what the finding is about) and the span's last record, cited for the span
    assert m.proposed_lane == "lead" and len(m.events) == network.EXAMPLE_LIMIT + 1
    assert m.context_ids == {staged[-1].id}
    assert "21 of the 39 flow records are cited, including the first and the last." in m.claim


def scenario_slow_probes():
    """One probe every 26 hours across 30 ports, each in its own partition with other traffic."""
    for p in range(1, 31):
        ts = T0 + timedelta(hours=26 * p)
        yield [flow(SCANNER, 40000 + p, TARGET, p, ts)] + noise(ts)


def scenario_bursts():
    """20-port bursts every 25 hours, 5 bursts, each burst's ports new."""
    for b in range(5):
        ts = T0 + timedelta(hours=25 * b)
        yield [flow(SCANNER, 41000 + p, TARGET, 20 * b + p, ts + timedelta(seconds=p)) for p in range(1, 21)]
        yield noise(ts + timedelta(hours=1))


@pytest.mark.parametrize("scenario, ports", [(scenario_slow_probes, 30), (scenario_bursts, 100)])
def test_slow_port_scan_is_found_as_in_one_pass_with_a_small_hot_set(monkeypatch, tmp_path, scenario, ports):
    batches = list(scenario())
    whole = run_batches(network.PortScan(), [[e for batch in batches for e in batch]])
    rule = small(monkeypatch, network.PortScan, tmp_path)
    spilled = []
    streamed = run_batches(rule, batches, check=lambda r: (hot_bounded(r), spilled.append(r.groups.on_disk)))
    assert max(spilled) > 0                                                      # the spill path was exercised
    assert shape(streamed) == shape(whole)
    leads = [m for m in streamed if m.proposed_lane == "lead"]
    assert [m.group_key for m in leads] == [f"{SCANNER}|{TARGET}"]
    assert f"covering {ports} distinct destination ports" in leads[0].claim
    assert rule.limit_reasons() == [] and rule.capped == 0
    rule.release_state()


@pytest.mark.parametrize("batches", [1, 3])
def test_port_scan_counts_ports_across_pauses_in_one_or_three_batches(monkeypatch, tmp_path, batches):
    """Ports of a pair are counted over the whole hunt window: a pause of days does not split the scan, however the
    records are partitioned."""
    early = [flow(SCANNER, 40000 + p, TARGET, p, T0 + timedelta(seconds=p)) for p in range(1, 15)]
    filler = [flow("10.0.0.1", 40000, "10.0.0.2", 80, T0 + timedelta(days=2))]
    late = [flow(SCANNER, 41000 + p, TARGET, p, T0 + timedelta(days=3, seconds=p)) for p in range(15, 30)]
    parts = [early + filler + late] if batches == 1 else [early, filler, late]
    out = run_batches(small(monkeypatch, network.PortScan, tmp_path), parts)
    assert [m.group_key for m in out if m.proposed_lane == "lead"] == [f"{SCANNER}|{TARGET}"]
    assert "covering 29 distinct destination ports" in out[0].claim


def test_reply_index_on_disk_still_tells_answers_from_probes(monkeypatch, tmp_path):
    """A service answering a client from port 443: the client's request is on disk by the time the answers are
    judged, and still marks them as answers (context, not a lead)."""
    client, server = "10.6.0.5", "10.6.0.80"
    requests = [flow(client, 50000 + i, server, 443, T0 + timedelta(seconds=i)) for i in range(30)]
    answers = [flow(server, 443, client, 50000 + i, T0 + timedelta(seconds=i, milliseconds=5)) for i in range(30)]
    rule = small(monkeypatch, network.PortScan, tmp_path)
    out = run_batches(rule, [requests] + [noise(T0 + timedelta(minutes=1 + k), 4) for k in range(3)] + [answers])
    assert rule.requests.on_disk > 0
    reverse = next(m for m in out if m.group_key == f"{server}|{client}")
    assert reverse.proposed_lane == "context" and "on 30 a flow" in reverse.claim


def test_subdomain_enumeration_in_bursts_a_day_apart_is_found(monkeypatch, tmp_path):
    """60 names per burst every 25 hours, 4 bursts: 240 distinct names under one domain."""
    def bursts():
        for b in range(4):
            ts = T0 + timedelta(hours=25 * b)
            yield [dns_question("10.2.9.9", f"h{b}x{i}.target.test", ts + timedelta(seconds=i)) for i in range(60)]
            yield [dns_question(f"10.2.0.{c + 1}", f"www.other{c}.test", ts + timedelta(hours=2)) for c in range(5)]
    batches = list(bursts())
    whole = run_batches(network.DnsSubdomainEnumeration(), [[e for batch in batches for e in batch]])
    rule = small(monkeypatch, network.DnsSubdomainEnumeration, tmp_path)
    streamed = run_batches(rule, batches, check=hot_bounded)
    assert shape(streamed) == shape(whole)
    assert [m.group_key for m in streamed] == ["10.2.9.9|target.test"]
    assert "240 distinct names under 'target.test'" in streamed[0].claim


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
def test_port_scan_keeps_a_week_of_pairs_on_disk_with_a_bounded_hot_set(monkeypatch, tmp_path):
    clients, servers, days = 200, 10, 7
    rule = small(monkeypatch, network.PortScan, tmp_path, hot=500)
    out = run_batches(rule, client_days(clients, servers, days, scan_day=4),
                      check=lambda r: (len(r.groups.hot) <= 500 and len(r.requests.hot) <= 500) or pytest.fail("hot"))
    assert len(rule.groups) == clients * servers * days + 1                    # every pair kept, none released
    leads = [m for m in out if m.proposed_lane == "lead"]
    assert [m.group_key for m in leads] == ["10.1.200.1|10.9.99.1"]
    assert "200 distinct destination ports" in leads[0].claim
    rule.release_state()


@pytest.mark.slow
def test_subdomain_enumeration_keeps_every_pair_with_a_bounded_hot_set(monkeypatch, tmp_path):
    def days():
        for day in range(6):
            for hour in range(24):
                ts = T0 + timedelta(days=day, hours=hour)
                batch = [dns_question(f"10.2.0.{c + 1}", f"www.d{day}h{hour}x{d}.test", ts)
                         for c in range(100) for d in range(5)]
                if day == 3 and hour == 2:
                    batch += [dns_question("10.2.9.9", f"h{i}.target.test", ts) for i in range(150)]
                yield batch
    rule = small(monkeypatch, network.DnsSubdomainEnumeration, tmp_path, hot=300)
    out = run_batches(rule, days(), check=lambda r: len(r.groups.hot) <= 300 or pytest.fail("hot"))
    assert len(rule.groups) == 100 * 5 * 24 * 6 + 1
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
def test_only_the_disk_budget_refuses_new_groups_and_coverage_says_so(monkeypatch, tmp_path, cls, make):
    """Groups beyond the hot set go to disk; once the disk budget is spent a record of a new group is refused (not
    evaluated, coverage partial), while records of groups already held are still counted."""
    monkeypatch.setattr(bounded, "DISK_BUDGET", 1)
    rule = small(monkeypatch, cls, tmp_path)
    run_batches(rule, [[make(1)], [make(2)], [make(i) for i in range(3, 8)] + [make(1), make(2)]])
    assert len(rule.groups) == 2 and rule.capped == 5
    assert sorted(rule.counts.values()) == [2, 2] and rule.evaluated == 4
    assert any("5 record(s) not evaluated" in reason for reason in rule.limit_reasons())
    rule.release_state()


def test_web_scan_counts_every_url_group_without_a_shared_budget(monkeypatch, tmp_path):
    """No budget shared across sources: a later scanner's distinct URLs are counted as fully as an earlier one's."""
    events = []
    for k, src in enumerate(("198.51.100.4", "198.51.100.5")):
        events += [event("http_access", T0 + timedelta(minutes=k, seconds=i), source__ip=src,
                         http__response__status_code=404, url__original=f"/{k}/a{i}") for i in range(250)]
    rule = small(monkeypatch, network.WebScanBurst, tmp_path)
    out = run_batches(rule, [events[:250], events[250:]])
    assert [m.claim.split("across ")[1] for m in out] == [
        "250+ distinct URLs. 21 of the 250 requests are cited, including the first and the last."] * 2
    assert rule.limit_reasons() == []
