"""Mission-scale DNS state: weeks of answers from many clients keep a bounded hot set, every group is kept (on the
rule's disk spill when it is not hot), slow activity is found exactly as in one pass, and only the disk budget can
refuse a record."""
import random
from datetime import UTC, datetime, timedelta

import pytest

from romulus.detect import bounded, dns
from romulus.evidence.typed import RawRef, TypedEvent, fv

T0 = datetime(2024, 11, 4, 0, 0, tzinfo=UTC)
RESOLVER = "10.20.0.53"
HEX = "0123456789abcdef"
_n = 0


def answer(client, ts, rcode="NXDOMAIN", name=None, server=RESOLVER):
    global _n
    _n += 1
    fields = {"source.ip": server, "destination.ip": client, "source.port": 53, "destination.port": 40000,
              "dns.type": "answer",
              "dns.question.name": name or f"n{_n}.example.test", "dns.response_code": rcode,
              "network.transport": "udp", "suricata.flow_id": _n}
    return TypedEvent(id=f"v{_n:09d}", family="dns_query", ts=ts, host="sensor",
                      fields={k: fv(v, "fixture") for k, v in fields.items()},
                      raw=[RawRef(target="fx", native_id=f"r{_n}")], normalizer="fixture")


def question(client, name, ts, qtype="A"):
    global _n
    _n += 1
    fields = {"source.ip": client, "destination.ip": RESOLVER, "source.port": 40000, "destination.port": 53,
              "dns.type": "query", "dns.question.name": name,
              "dns.question.type": qtype, "network.transport": "udp", "suricata.flow_id": _n}
    return TypedEvent(id=f"q{_n:09d}", family="dns_query", ts=ts, host="sensor",
                      fields={k: fv(v, "fixture") for k, v in fields.items()},
                      raw=[RawRef(target="fx", native_id=f"q{_n}")], normalizer="fixture")


def run_batches(rule, batches, check=None):
    stage = {}
    for batch in batches:
        rule.consume(batch)
        stage.update({event.id: event for event in rule.drain_staged()})
        if check is not None:
            check(rule)
    rule.bind_loader(lambda ids: [stage[i] for i in ids if i in stage])
    return rule.finalize(), stage


def shape(out):
    return [(m.group_key, m.proposed_lane, m.severity, m.claim, [e.id for e in m.events]) for m in out]


def small(monkeypatch, cls, tmp_path, hot=1):
    """The rule with every keyed store's hot set forced to `hot` states, spilling under tmp_path."""
    for name in ("HOT", "ASKERS_HOT"):
        if hasattr(cls, name):
            monkeypatch.setattr(cls, name, hot)
    rule = cls()
    rule.spill_dir = tmp_path
    return rule


def hot_within(limit):
    def check(rule):
        for store in rule._stores():
            assert len(store.hot) <= limit, (store.name, len(store.hot))
    return check


def on_disk(rule) -> int:
    return sum(store.on_disk for store in rule._stores())


def held_times(rule) -> int:
    return sum(len(state.times) for _address, state in rule.addresses.items())


def held_buckets(rule) -> int:
    return sum(len(state.buckets) for _address, state in rule.addresses.items())


# ------------------------------------------------------------------------------------------------ the reviewer's scenarios
def tunnel_beacons(client="10.40.0.9", beacons=30):
    """A DNS tunnel beacon every 25 hours, 3 long TXT names each, in its own partition with other clients' lookups."""
    rng = random.Random(11)
    for b in range(beacons):
        ts = T0 + timedelta(hours=25 * b)
        batch = [question(client, f"{''.join(rng.choice(HEX) for _ in range(48))}.c2.example.test",
                          ts + timedelta(seconds=i), qtype="TXT") for i in range(3)]
        batch += [question(f"10.41.0.{c + 1}", f"www.site{b}x{c}.test", ts + timedelta(minutes=5)) for c in range(4)]
        yield batch


def test_slow_tunnel_beacons_are_found_as_in_one_pass_with_a_small_hot_set(monkeypatch, tmp_path):
    batches = list(tunnel_beacons())
    whole, _ = run_batches(dns.DnsTunnelShape(), [[e for b in batches for e in b]])
    rule = small(monkeypatch, dns.DnsTunnelShape, tmp_path)
    disk = []
    streamed, _ = run_batches(rule, batches, check=lambda r: (hot_within(1)(r), disk.append(on_disk(r))))
    assert max(disk) > 0
    assert shape(streamed) == shape(whole)
    assert [(m.group_key, m.proposed_lane) for m in streamed] == [("10.40.0.9|example.test", "lead")]
    assert "for 90 distinct subdomain(s)" in streamed[0].claim
    assert rule.limit_reasons() == [] and rule.capped == 0
    rule.release_state()


def test_nxdomain_burst_found_as_in_one_pass_with_a_small_hot_set(monkeypatch, tmp_path):
    burst_client, burst_at = "10.30.0.9", T0 + timedelta(hours=7, minutes=3)
    batches = list(nx_weeks(20, 1, burst_client, burst_at))
    whole, _ = run_batches(dns.DnsNxdomainBurst(), [[e for b in batches for e in b]])
    rule = small(monkeypatch, dns.DnsNxdomainBurst, tmp_path, hot=3)
    streamed, _ = run_batches(rule, batches, check=hot_within(3))
    assert rule.addresses.on_disk > 0
    assert shape(streamed) == shape(whole) and len(whole) == 1


def test_resolver_wording_reads_the_server_side_from_disk(monkeypatch, tmp_path):
    """A forwarder with a burst of its own: the clients it answered in the peak interval are listed from its record,
    which was on disk while those clients' records were hot."""
    forwarder, upstream = "10.20.0.53", "192.0.2.53"
    ts = T0 + timedelta(hours=1)
    batches = [[answer(f"10.31.0.{i % 60 + 1}", ts + timedelta(seconds=i), server=forwarder) for i in range(120)],
               [answer(f"10.32.0.{i + 1}", ts, rcode="NOERROR", server=f"10.32.0.{i + 1}") for i in range(4)],
               [answer(forwarder, ts + timedelta(seconds=i, milliseconds=1), server=upstream) for i in range(120)]]
    whole, _ = run_batches(dns.DnsNxdomainBurst(), [[e for b in batches for e in b]])
    streamed, _ = run_batches(small(monkeypatch, dns.DnsNxdomainBurst, tmp_path, hot=2), batches)
    assert shape(streamed) == shape(whole)
    [m] = [m for m in streamed if m.group_key == forwarder]
    assert "also appears as the answering server" in m.claim and "to 60 client(s)" in m.claim


def test_reverse_sweep_and_zone_transfer_found_as_in_one_pass_with_a_small_hot_set(monkeypatch, tmp_path):
    def batches():
        for k in range(8):
            ts = T0 + timedelta(hours=25 * k)
            batch = [ptr_question("10.50.0.7", f"10.60.0.{32 * (k % 8) + i}", ts + timedelta(seconds=i))
                     for i in range(32)]
            batch += [question(f"10.50.1.{k + 1}", "corp.example.test", ts, qtype="AXFR")]
            batch += [ptr_question(f"10.50.2.{c + 1}", f"192.0.2.{k + 1}", ts) for c in range(3)]
            yield batch
    made = list(batches())
    for cls in (dns.DnsReverseLookupSweep, dns.DnsZoneTransferOrAnyRequest):
        whole, _ = run_batches(cls(), [[e for b in made for e in b]])
        rule = small(monkeypatch, cls, tmp_path)
        streamed, _ = run_batches(rule, made, check=hot_within(1))
        assert on_disk(rule) > 0
        assert shape(streamed) == shape(whole) and whole, cls
        rule.release_state()


# ------------------------------------------------------------------------------------------------ NXDOMAIN volume
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
def test_nxdomain_state_stays_bounded_over_two_weeks_and_the_burst_is_still_found(monkeypatch, tmp_path):
    burst_client = "10.30.0.7"
    burst_at = T0 + timedelta(days=9, hours=13, minutes=21)
    clients, days = 150, 14
    rule = small(monkeypatch, dns.DnsNxdomainBurst, tmp_path, hot=40)
    peak_times = peak_buckets = 0
    stage = {}
    for batch in nx_weeks(clients, days, burst_client, burst_at):
        rule.consume(batch)
        stage.update({event.id: event for event in rule.drain_staged()})
        assert len(rule.addresses.hot) <= 40
        peak_times = max(peak_times, held_times(rule))
        peak_buckets = max(peak_buckets, held_buckets(rule))
    total = clients * 6 * 24 * days + 300
    assert rule.evaluated == total
    # Held state, in memory and on disk, is the settle horizon (about an hour and two buckets per client) plus the
    # burst's buckets, not two weeks of answers: the growth law is O(clients), not O(answers).
    assert peak_times <= clients * 12 + 310, peak_times
    assert peak_buckets <= clients * 12 + 4, peak_buckets
    rule.bind_loader(lambda ids: [stage[i] for i in ids if i in stage])
    out = rule.finalize()
    assert [m.group_key for m in out] == [burst_client]
    m = out[0]
    assert "at most 301 of them fell within one ten-minute interval" in m.claim
    assert f"was sent {6 * 24 * days + 300} NXDOMAIN answer(s)" in m.claim
    window = timedelta(minutes=10)
    # the peak's records, beside the records bounding the span and those the names and servers come from
    assert len([e for e in m.events if burst_at - window < e.ts < burst_at + window]) >= 20
    assert "lower bound" not in m.claim and rule.limit_reasons() == []
    rule.release_state()


def test_nxdomain_released_intervals_never_change_a_burst_found_in_one_pass():
    """The same records in one batch and in hourly batches give the same finding."""
    burst_client, burst_at = "10.30.0.9", T0 + timedelta(hours=7, minutes=3)
    batches = list(nx_weeks(20, 1, burst_client, burst_at))
    whole, _ = run_batches(dns.DnsNxdomainBurst(), [[e for b in batches for e in b]])
    streamed, _ = run_batches(dns.DnsNxdomainBurst(), batches)
    assert shape(whole) == shape(streamed)
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


# ------------------------------------------------------------------------------------------------ tunnel volume
def browsing_days(clients: int, domains: int, days: int, tunnel_client: str, tunnel_day: int):
    """Each client queries `domains` new registered domains a day (three names each), in hourly partitions; one
    client runs a TXT/CNAME/MX tunnel for ten minutes on `tunnel_day`."""
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
def test_tunnel_shape_keeps_every_pair_with_a_bounded_hot_set(monkeypatch, tmp_path):
    clients, days = 120, 8
    rule = small(monkeypatch, dns.DnsTunnelShape, tmp_path, hot=20)
    out, _ = run_batches(rule, browsing_days(clients, 40, days, "10.40.0.9", tunnel_day=5), check=hot_within(20))
    # every (client, registered domain) is kept, none released, most of them on disk; each client's names fall under
    # one registered domain, and the tunnel's under another
    assert len(rule.pairs) == clients + 1 and rule.pairs.on_disk >= clients + 1 - 20
    assert [(m.group_key, m.proposed_lane) for m in out] == [("10.40.0.9|example.test", "high")]
    assert rule.limit_reasons() == []
    rule.release_state()


# ------------------------------------------------------------------------------------------------ reverse lookups
def ptr_question(client, address, ts):
    name = ".".join(reversed(address.split("."))) + ".in-addr.arpa"
    return question(client, name, ts, qtype="PTR")


@pytest.mark.slow
def test_reverse_lookup_state_grows_with_distinct_names_not_with_lookups(monkeypatch, tmp_path):
    """Servers resolving the same peers all day: the held names are the distinct names, whatever the volume."""
    rule = small(monkeypatch, dns.DnsReverseLookupSweep, tmp_path, hot=20)
    clients, peers, rounds = 100, 40, 60
    for r in range(rounds):
        batch = [ptr_question(f"10.50.0.{c + 1}", f"192.0.2.{p + 1}", T0 + timedelta(minutes=r, seconds=p))
                 for c in range(clients) for p in range(peers)]
        rule.consume(batch)
        rule.drain_staged()
        assert len(rule.clients.hot) <= 20
        if r % 20 == 19:
            states = [state for _client, state in rule.clients.items()]
            assert sum(len(state.names) for state in states) <= clients * peers
            assert sum(len(state.block_examples) for state in states) <= clients
    assert sum(state.queries for _client, state in rule.clients.items()) == clients * peers * rounds
    rule.release_state()


# ------------------------------------------------------------------------------------------------ disk budget
@pytest.mark.parametrize("cls, make", [
    (dns.DnsTunnelShape, lambda i: question(f"10.40.0.{i}", f"www.d{i}.test", T0 + timedelta(seconds=i))),
    (dns.DnsReverseLookupSweep, lambda i: ptr_question(f"10.50.0.{i}", "10.60.0.1", T0 + timedelta(seconds=i))),
    (dns.DnsZoneTransferOrAnyRequest,
     lambda i: question(f"10.50.1.{i}", "corp.example.test", T0 + timedelta(seconds=i), qtype="AXFR")),
    (dns.DnsNxdomainBurst, lambda i: answer(f"10.30.0.{i}", T0 + timedelta(seconds=i), server=f"10.30.0.{i}")),
])
def test_only_the_disk_budget_refuses_and_coverage_says_so(monkeypatch, tmp_path, cls, make):
    """States beyond the hot set go to disk; once the disk budget is spent a record needing a new state is refused
    (not evaluated, coverage partial), while records of states already held are still evaluated."""
    monkeypatch.setattr(bounded, "DISK_BUDGET", 1)
    rule = small(monkeypatch, cls, tmp_path)
    run_batches(rule, [[make(1)], [make(2)], [make(i) for i in range(3, 8)] + [make(1), make(2)]])
    assert rule.capped == 5 and rule.evaluated == 4
    assert any("5 record(s) not evaluated" in reason for reason in rule.limit_reasons())
    rule.release_state()


def test_examples_and_names_views_read_the_whole_store(monkeypatch, tmp_path):
    rule = small(monkeypatch, dns.DnsReverseLookupSweep, tmp_path)
    run_batches(rule, [[ptr_question(f"10.50.0.{c}", "10.60.0.1", T0)] for c in range(1, 4)])
    assert set(rule.names) == {"10.50.0.1", "10.50.0.2", "10.50.0.3"} and rule.clients.on_disk == 2
    assert all(store.ids() for store in rule.examples.values())
    rule.release_state()
    assert rule.names == {} and rule.examples == {}
