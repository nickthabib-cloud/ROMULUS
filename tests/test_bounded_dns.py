"""Mission-scale DNS state: weeks of answers from many clients keep bounded state, and detection is unchanged."""
from datetime import UTC, datetime, timedelta

import pytest

from romulus.detect import dns
from romulus.evidence.typed import RawRef, TypedEvent, fv

T0 = datetime(2024, 11, 4, 0, 0, tzinfo=UTC)
RESOLVER = "10.20.0.53"
_n = 0


def answer(client, ts, rcode="NXDOMAIN", name=None, server=RESOLVER):
    global _n
    _n += 1
    fields = {"source.ip": server, "destination.ip": client, "dns.type": "answer",
              "dns.question.name": name or f"n{_n}.example.test", "dns.response_code": rcode,
              "network.transport": "udp", "suricata.flow_id": _n}
    return TypedEvent(id=f"v{_n:09d}", family="dns_query", ts=ts, host="sensor",
                      fields={k: fv(v, "fixture") for k, v in fields.items()},
                      raw=[RawRef(target="fx", native_id=f"r{_n}")], normalizer="fixture")


def question(client, name, ts, qtype="A"):
    global _n
    _n += 1
    fields = {"source.ip": client, "destination.ip": RESOLVER, "dns.type": "query", "dns.question.name": name,
              "dns.question.type": qtype, "network.transport": "udp", "suricata.flow_id": _n}
    return TypedEvent(id=f"q{_n:09d}", family="dns_query", ts=ts, host="sensor",
                      fields={k: fv(v, "fixture") for k, v in fields.items()},
                      raw=[RawRef(target="fx", native_id=f"q{_n}")], normalizer="fixture")


def run_batches(rule, batches):
    stage = {}
    for batch in batches:
        rule.consume(batch)
        stage.update({event.id: event for event in rule.drain_staged()})
    rule.bind_loader(lambda ids: [stage[i] for i in ids if i in stage])
    return rule.finalize(), stage


def held_times(rule) -> int:
    return sum(len(times) for times in rule.times.values())


def held_buckets(rule) -> int:
    return sum(len(buckets) for buckets in rule.buckets.values())


def nx_weeks(clients: int, days: int, burst_client: str, burst_at: datetime):
    """One NXDOMAIN answer per client every ten minutes for `days` days, in hourly partitions; one client gets a
    300-answer burst inside one ten-minute interval."""
    hours = days * 24
    for hour in range(hours):
        start = T0 + timedelta(hours=hour)
        batch = [answer(f"10.30.{c // 250}.{c % 250 + 1}", start + timedelta(minutes=10 * k, seconds=c % 60))
                 for c in range(clients) for k in range(6)]
        if start <= burst_at < start + timedelta(hours=1):
            batch += [answer(burst_client, burst_at + timedelta(seconds=i)) for i in range(300)]
        yield batch


@pytest.mark.slow
def test_nxdomain_state_stays_bounded_over_two_weeks_and_the_burst_is_still_found():
    rule = dns.DnsNxdomainBurst()
    burst_client = "10.30.0.7"
    burst_at = T0 + timedelta(days=9, hours=13, minutes=21)
    clients, days = 150, 14
    peak_times = peak_buckets = 0
    stage = {}
    for batch in nx_weeks(clients, days, burst_client, burst_at):
        rule.consume(batch)
        stage.update({event.id: event for event in rule.drain_staged()})
        peak_times = max(peak_times, held_times(rule))
        peak_buckets = max(peak_buckets, held_buckets(rule))
    total = clients * 6 * 24 * days + 300
    assert rule.evaluated == total
    # Held state is the settle horizon (about an hour and two buckets per client) plus the burst's buckets, not
    # two weeks of answers: the growth law is O(clients), not O(answers).
    assert peak_times <= clients * 12 + 310, peak_times
    assert peak_buckets <= clients * 12 + 4, peak_buckets
    rule.bind_loader(lambda ids: [stage[i] for i in ids if i in stage])
    out = rule.finalize()
    assert [m.group_key for m in out] == [burst_client]
    m = out[0]
    assert "at most 301 of them fell within one ten-minute interval" in m.claim
    assert f"was sent {6 * 24 * days + 300} NXDOMAIN answer(s)" in m.claim
    window = timedelta(minutes=10)
    assert len(m.events) == 20 and all(burst_at - window < e.ts < burst_at + window for e in m.events)
    assert "lower bound" not in m.claim and rule.limit_reasons() == []


def test_nxdomain_released_intervals_never_change_a_burst_found_in_one_pass():
    """The same records in one batch and in hourly batches give the same finding."""
    burst_client, burst_at = "10.30.0.9", T0 + timedelta(hours=7, minutes=3)
    batches = list(nx_weeks(20, 1, burst_client, burst_at))
    whole, _ = run_batches(dns.DnsNxdomainBurst(), [[e for b in batches for e in b]])
    streamed, _ = run_batches(dns.DnsNxdomainBurst(), batches)
    assert [(m.claim, [e.id for e in m.events]) for m in whole] == \
           [(m.claim, [e.id for e in m.events]) for m in streamed]
    assert len(whole) == 1


def test_records_arriving_after_their_interval_was_released_are_stated():
    """A second sensor target read after the first: its records land in intervals already released. The finding
    says its peak may be a lower bound, and coverage names the limit."""
    client = "10.30.0.11"
    first = [answer(client, T0 + timedelta(minutes=10 * k)) for k in range(6 * 30)]                # 30 hours
    late = [answer(client, T0 + timedelta(hours=2, seconds=i)) for i in range(60)]                  # a burst, read late
    out, _ = run_batches(rule := dns.DnsNxdomainBurst(), [first, late])
    assert len(out) == 1
    assert "may be a lower bound" in out[0].claim
    assert any("released" in reason for reason in rule.limit_reasons())


HEX = "0123456789abcdef"


def browsing_days(clients: int, domains: int, days: int, tunnel_client: str, tunnel_day: int):
    """Each client queries `domains` new registered domains a day (three names each), in hourly partitions; one
    client runs a TXT/CNAME/MX tunnel for ten minutes on `tunnel_day`."""
    import random
    rng = random.Random(5)
    for day in range(days):
        for hour in range(24):
            start = T0 + timedelta(days=day, hours=hour)
            batch = []
            for c in range(clients):
                client = f"10.40.{c // 250}.{c % 250 + 1}"
                for d in range(domains * hour // 24, domains * (hour + 1) // 24):
                    for label in ("www", "api", "cdn"):
                        batch.append(question(client, f"{label}.d{day}x{d}.example{c % 7}.test",
                                              start + timedelta(seconds=d)))
            if day == tunnel_day and hour == 13:
                for i in range(400):
                    name = (f"{''.join(rng.choice(HEX) for _ in range(60))}."
                            f"{''.join(rng.choice(HEX) for _ in range(30))}.tun.example.test")
                    batch.append(question(tunnel_client, name, start + timedelta(seconds=i),
                                          qtype=("TXT", "CNAME", "MX")[i % 3]))
            yield batch


@pytest.mark.slow
def test_tunnel_shape_holds_a_day_of_keys_not_the_whole_hunt():
    rule = dns.DnsTunnelShape()
    clients, domains, days = 120, 40, 8
    peak = 0
    stage = {}
    for batch in browsing_days(clients, domains, days, "10.40.0.9", tunnel_day=5):
        rule.consume(batch)
        stage.update({event.id: event for event in rule.drain_staged()})
        peak = max(peak, len(rule.keys))
    # every registered domain is a key; a key silent for a day with fewer than 50 names is released, so about two
    # days of keys are held at most, not the whole hunt's
    total = clients * domains * days
    assert peak <= clients * domains * 2 + clients * 7 + 10, (peak, total)
    rule.bind_loader(lambda ids: [stage[i] for i in ids if i in stage])
    out = rule.finalize()
    assert [(m.group_key, m.proposed_lane) for m in out] == [("10.40.0.9|example.test", "high")]
    assert rule.limit_reasons() == []


def test_tunnel_shape_key_budget_refuses_new_keys_and_says_so(monkeypatch):
    monkeypatch.setattr(dns.DnsTunnelShape, "MAX_KEYS", 10)
    rule = dns.DnsTunnelShape()
    rule.consume([question("10.40.0.1", f"www.d{i}.test", T0 + timedelta(seconds=i)) for i in range(30)])
    assert len(rule.keys) == 10 and rule.capped == 20
    assert any("10" in reason and "not evaluated" in reason for reason in rule.limit_reasons())


def ptr_question(client, address, ts):
    name = ".".join(reversed(address.split("."))) + ".in-addr.arpa"
    return question(client, name, ts, qtype="PTR")


@pytest.mark.slow
def test_reverse_lookup_state_grows_with_distinct_names_not_with_lookups():
    """Servers resolving the same peers all day: the held names are the distinct names, whatever the volume."""
    rule = dns.DnsReverseLookupSweep()
    clients, peers, rounds = 100, 40, 60
    for r in range(rounds):
        batch = [ptr_question(f"10.50.0.{c + 1}", f"192.0.2.{p + 1}", T0 + timedelta(minutes=r, seconds=p))
                 for c in range(clients) for p in range(peers)]
        rule.consume(batch)
        rule.drain_staged()
        assert sum(len(names) for names in rule.names.values()) <= clients * peers
        assert sum(len(stores) for stores in rule.block_examples.values()) <= clients
    assert sum(rule.queries.values()) == clients * peers * rounds


def test_reverse_lookup_budgets_refuse_new_clients_and_make_counts_lower_bounds(monkeypatch):
    monkeypatch.setattr(dns.DnsReverseLookupSweep, "MAX_CLIENTS", 2)
    monkeypatch.setattr(dns.DnsReverseLookupSweep, "NAMES_BUDGET", 160)
    events = [ptr_question("10.50.0.1", f"10.60.0.{i}", T0 + timedelta(seconds=i)) for i in range(120)]
    events += [ptr_question("10.50.0.2", f"10.60.1.{i}", T0 + timedelta(seconds=i)) for i in range(120)]
    events += [ptr_question("10.50.0.3", f"10.60.2.{i}", T0 + timedelta(seconds=i)) for i in range(5)]
    rule = dns.DnsReverseLookupSweep()
    out, _ = run_batches(rule, [events])
    assert set(rule.names) == {"10.50.0.1", "10.50.0.2"} and rule.capped == 5
    assert sum(len(n) for n in rule.names.values()) == 160
    second = next(m for m in out if m.group_key == "10.50.0.2")
    assert "for at least 40 distinct" in second.claim
    reasons = " ".join(rule.limit_reasons())
    assert "5 record(s) not evaluated" in reasons and "lower bound" in reasons


def test_zone_transfer_key_budget(monkeypatch):
    monkeypatch.setattr(dns.DnsZoneTransferOrAnyRequest, "MAX_KEYS", 3)
    events = [question(f"10.50.1.{i}", "corp.example.test", T0 + timedelta(seconds=i), qtype="AXFR")
              for i in range(5)]
    rule = dns.DnsZoneTransferOrAnyRequest()
    out, _ = run_batches(rule, [events])
    assert len(out) == 3 and rule.capped == 2 and rule.evaluated == 3
    assert any("not evaluated" in reason for reason in rule.limit_reasons())
