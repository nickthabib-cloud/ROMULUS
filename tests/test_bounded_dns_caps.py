"""DNS distinct-name state never caps a match: the tunnel-shape indicators and the reverse-lookup block densities
are counted over every distinct name of the whole hunt (small per-group sets in memory, larger ones on the rule's
disk spill), so activity that starts after many ordinary names is found exactly as an unbounded run finds it."""
import random
from datetime import timedelta

from romulus.detect import bounded, dns
from tests.test_bounded_dns import HEX, T0, hot_within, ptr_question, question, run_batches, shape, small

UNBOUNDED = 10**9


def unbounded(monkeypatch, cls):
    """The rule with every distinct-name set held in memory: the reference an unbounded run would give."""
    monkeypatch.setattr(cls, "NAMES_INLINE", UNBOUNDED, raising=False)
    monkeypatch.setattr(cls, "BLOCKS_INLINE", UNBOUNDED, raising=False)
    return cls()


def ordinary_then_tunnel(client="10.40.0.9", ordinary=25_000, tunnel=400):
    """`ordinary` distinct short A names under example.test, then a TXT tunnel under the same registered domain."""
    rng = random.Random(5)
    for b in range(ordinary // 1000):
        start = T0 + timedelta(hours=b)
        yield [question(client, f"host{b * 1000 + i}.corp.example.test", start + timedelta(seconds=i))
               for i in range(1000)]
    start = T0 + timedelta(days=2)
    yield [question(client, f"{''.join(rng.choice(HEX) for _ in range(60))}."
                            f"{''.join(rng.choice(HEX) for _ in range(30))}.tun.example.test",
                    start + timedelta(seconds=i), qtype="TXT") for i in range(tunnel)]
    # the ordinary names asked again: repeats are not new distinct names
    yield [question(client, f"host{i}.corp.example.test", start + timedelta(hours=1, seconds=i)) for i in range(500)]


def test_a_tunnel_that_starts_after_25k_ordinary_names_of_the_same_domain_is_found(monkeypatch, tmp_path):
    batches = list(ordinary_then_tunnel())
    whole, _ = run_batches(unbounded(monkeypatch, dns.DnsTunnelShape), [[e for b in batches for e in b]])
    monkeypatch.undo()
    rule = small(monkeypatch, dns.DnsTunnelShape, tmp_path, hot=50)
    streamed, _ = run_batches(rule, batches, check=hot_within(50))
    assert sum(store.on_disk for store in rule._stores()) > 0
    assert shape(streamed) == shape(whole)
    [m] = streamed
    assert m.group_key == "10.40.0.9|example.test"
    assert "for 25400 distinct subdomain(s)" in m.claim and "at least" not in m.claim
    assert "400 of the distinct names have a label" in m.claim
    assert "Indicators met: high entropy, volume" in m.claim
    assert rule.limit_reasons() == [] and rule.capped == 0
    rule.release_state()


def test_distinct_names_moved_to_disk_count_exactly_as_in_memory(monkeypatch, tmp_path):
    """A pair's names beyond the in-memory set go to the disk spill; a name asked again in a later batch, after it
    went to disk, is still recognised, so every count and the mean entropy equal the in-memory run's."""
    rng = random.Random(9)
    names = [f"{''.join(rng.choice(HEX) for _ in range(40))}.x.example.test" for _ in range(120)]
    batches = [[question("10.40.0.7", names[(b * 37 + i) % len(names)], T0 + timedelta(minutes=b, seconds=i),
                         qtype=("TXT", "A")[i % 2]) for i in range(60)] for b in range(12)]
    whole, _ = run_batches(unbounded(monkeypatch, dns.DnsTunnelShape), [[e for b in batches for e in b]])
    monkeypatch.undo()
    monkeypatch.setattr(dns.DnsTunnelShape, "NAMES_INLINE", 8)
    rule = small(monkeypatch, dns.DnsTunnelShape, tmp_path, hot=4)
    streamed, _ = run_batches(rule, batches, check=hot_within(4))
    assert rule.names.on_disk > 0
    assert shape(streamed) == shape(whole) and len(streamed) == 1
    assert "for 120 distinct subdomain(s)" in streamed[0].claim
    rule.release_state()


def test_the_running_entropy_sum_equals_the_builtin_sum_bit_for_bit():
    rng = random.Random(3)
    for _ in range(3000):
        values = [rng.choice((rng.random() * 6, rng.uniform(-1e9, 1e9), 1e-17 * rng.random(), 3.5))
                  for _ in range(rng.randrange(0, 60))]
        acc = dns._FloatSum()
        for v in values:
            acc.add(v)
        assert acc.total() == sum(values) and str(acc.total()) == str(sum(values))


def test_a_name_refused_by_the_disk_budget_is_not_counted_and_coverage_says_so(monkeypatch, tmp_path):
    monkeypatch.setattr(bounded, "DISK_BUDGET", 1)
    monkeypatch.setattr(dns.DnsTunnelShape, "NAMES_INLINE", 2)
    rule = small(monkeypatch, dns.DnsTunnelShape, tmp_path)
    ask = [question("10.40.0.8", f"n{i}.example.test", T0 + timedelta(seconds=i)) for i in range(5)]
    run_batches(rule, [ask[:3], [ask[3], ask[0]]])
    record = rule.pairs.peek(("10.40.0.8", "example.test"))
    assert record.unique == 3 and record.queries == 4          # n3 refused; the repeat of n0 evaluated
    assert rule.capped == 1 and any("1 record(s) not evaluated" in r for r in rule.limit_reasons())
    rule.release_state()


# ------------------------------------------------------------------------------------------------ reverse lookups
def scattered_then_dense(client="10.50.0.9", scattered=20_500, dense=40):
    """`scattered` reverse names one per /24 (no dense block), then `dense` addresses packed into one /24."""
    batch = []
    for i in range(scattered):
        batch.append(ptr_question(client, f"10.{i // 256}.{i % 256}.1", T0 + timedelta(seconds=i)))
        if len(batch) == 2000:
            yield batch
            batch = []
    yield batch
    start = T0 + timedelta(days=1)
    yield [ptr_question(client, f"10.200.7.{i + 1}", start + timedelta(seconds=i)) for i in range(dense)]


def test_reverse_density_is_exact_after_20k_scattered_names(monkeypatch, tmp_path):
    batches = list(scattered_then_dense())
    whole, _ = run_batches(unbounded(monkeypatch, dns.DnsReverseLookupSweep), [[e for b in batches for e in b]])
    monkeypatch.undo()
    rule = small(monkeypatch, dns.DnsReverseLookupSweep, tmp_path, hot=20)
    streamed, _ = run_batches(rule, batches, check=hot_within(20))
    assert sum(store.on_disk for store in rule._stores()) > 0
    assert shape(streamed) == shape(whole)
    [m] = streamed
    assert "for 20540 distinct reverse-lookup name(s)" in m.claim and "at least" not in m.claim
    # the dense block came after the blocks that keep citation candidates: it is named, with a record in it cited,
    # and its address range is not stated as cited
    assert "Densest: 10.200.7.0/24 (40 address(es); its range is not cited)" in m.claim
    assert any(e.get("dns.question.name").endswith(".7.200.10.in-addr.arpa") for e in m.events)
    assert "reverse-DNS sweep (host discovery by name)" in m.claim and "No block holds" not in m.claim
    assert "20540 of the names stand for single addresses in 20501 block(s)" in m.claim
    rule.release_state()


def test_reverse_no_dense_block_statement_holds_over_every_name(monkeypatch, tmp_path):
    """Without a dense block the claim says no block holds 32 or more: true over every distinct name, not a cap."""
    batches = list(scattered_then_dense(scattered=21_000, dense=31))
    rule = small(monkeypatch, dns.DnsReverseLookupSweep, tmp_path, hot=20)
    [m], _ = run_batches(rule, batches)
    assert "No block holds 32 or more of them" in m.claim
    assert "Densest: 10.200.7.0/24 (31 address(es)" in m.claim
    rule.release_state()


def test_reverse_names_asked_again_after_moving_to_disk_are_not_counted_twice(monkeypatch, tmp_path):
    monkeypatch.setattr(dns.DnsReverseLookupSweep, "NAMES_INLINE", 8)
    monkeypatch.setattr(dns.DnsReverseLookupSweep, "BLOCKS_INLINE", 4)
    addresses = [f"10.70.{i % 6}.{i + 1}" for i in range(60)]
    batches = [[ptr_question("10.50.0.3", addresses[(b * 13 + i) % 60], T0 + timedelta(minutes=b, seconds=i))
                for i in range(30)] for b in range(10)]
    whole, _ = run_batches(unbounded(monkeypatch, dns.DnsReverseLookupSweep), [[e for b in batches for e in b]])
    monkeypatch.undo()
    monkeypatch.setattr(dns.DnsReverseLookupSweep, "NAMES_INLINE", 8)
    monkeypatch.setattr(dns.DnsReverseLookupSweep, "BLOCKS_INLINE", 4)
    monkeypatch.setattr(dns.DnsReverseLookupSweep, "MIN_DISTINCT", 50)
    rule = small(monkeypatch, dns.DnsReverseLookupSweep, tmp_path, hot=2)
    streamed, _ = run_batches(rule, batches, check=hot_within(2))
    assert rule.names_seen.on_disk > 0 and rule.blocks.on_disk > 0
    monkeypatch.undo()
    monkeypatch.setattr(dns.DnsReverseLookupSweep, "MIN_DISTINCT", 50)
    reference, _ = run_batches(unbounded(monkeypatch, dns.DnsReverseLookupSweep), [[e for b in batches for e in b]])
    assert shape(streamed) == shape(reference) and len(streamed) == 1
    assert "for 60 distinct reverse-lookup name(s)" in streamed[0].claim
    assert whole == []                                  # under the default thresholds it is not reported at all
    rule.release_state()
