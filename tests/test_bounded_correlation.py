"""The host-network join is disk-backed: memory holds no per-record state however many socket calls and network
records the sweep reads, the join gives the same findings, and the spill is removed on every exit path."""
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from romulus.detect.correlation import ProcessNetworkLink
from romulus.evidence.typed import Outcome, RawRef, TypedEvent, fv

T0 = datetime(2024, 11, 4, 0, 0, tzinfo=UTC)
_n = 0


def ev(family, ts, host, outcome=Outcome.success, **fields):
    global _n
    _n += 1
    return TypedEvent(id=f"c{_n:09d}", family=family, ts=ts, host=host, outcome=outcome,
                      fields={k.replace("__", "."): fv(v, f"c{_n}:{k}") for k, v in fields.items()},
                      raw=[RawRef(target="t", native_id=f"c{_n}", digest="d")], normalizer="test@1")


def sock(ts, pid, dst, dport, exe="/usr/bin/curl"):
    return ev("net_socket", ts, "web1", socket__syscall="connect", destination__ip=dst, destination__port=dport,
              process__executable=exe, process__user="root", process__pid=pid)


def flow(ts, src, sport, dst, dport, family="net_flow", **extra):
    return ev(family, ts, "sensor", source__ip=src, source__port=sport, destination__ip=dst,
              destination__port=dport, flow__start=ts.isoformat(), network__community_id=f"1:{src}:{sport}", **extra)


def _deep_size(rule) -> int:
    return sum(sys.getsizeof(value) for value in vars(rule).values())


@pytest.mark.slow
def test_join_holds_no_per_record_state_and_finds_the_alerted_connection(tmp_path):
    rule = ProcessNetworkLink()
    rule.spill_dir = tmp_path
    stage = {}
    sizes = []
    for hour in range(48):
        start = T0 + timedelta(hours=hour)
        batch = []
        for i in range(3000):                                   # network records nobody connects to
            batch.append(flow(start + timedelta(seconds=i), f"10.9.{i % 200}.5", 40000 + i % 20000,
                              f"198.51.100.{i % 250}", 443))
        for i in range(300):                                    # connect() calls with a matching flow
            ts = start + timedelta(seconds=10 * i)
            batch.append(sock(ts, 5000 + i, "203.0.113.10", 8443))
            batch.append(flow(ts + timedelta(seconds=1), "10.1.0.5", 50000 + i, "203.0.113.10", 8443))
        if hour == 30:
            ts = start + timedelta(minutes=20)
            batch += [sock(ts, 777, "203.0.113.66", 4444, exe="/usr/bin/nc"),
                      flow(ts + timedelta(seconds=1), "10.1.0.5", 45555, "203.0.113.66", 4444),
                      flow(ts + timedelta(seconds=2), "10.1.0.5", 45555, "203.0.113.66", 4444, family="net_alert",
                           alert__severity=1, alert__signature="ET backdoor", alert__category="Trojan")]
        rule.consume(batch)
        stage.update({e.id: e for e in rule.drain_staged()})
        sizes.append(_deep_size(rule))
    assert max(sizes) < 50_000, max(sizes)                      # no list or map that grows with the records read
    rule.bind_loader(lambda ids: [stage[i] for i in ids if i in stage])
    out = rule.finalize()
    alerted = [m for m in out if "203.0.113.66" in m.group_key]
    assert len(alerted) == 1 and alerted[0].proposed_lane == "high" and "ET backdoor" in alerted[0].claim
    spill_dirs = list(Path(tmp_path).glob("romulus-stage-spill-*"))
    assert len(spill_dirs) == 1
    rule.release_state()
    assert not list(Path(tmp_path).glob("romulus-stage-spill-*"))


SIGS = [f"ET beacon variant {k}" for k in range(5)]


def _beacon(hours: int, every: int = 10):
    """One process beaconing to one endpoint every `every` seconds for `hours`: one (host, program, account,
    endpoint) group. Every call has its flow; every 500th has an IDS alert on it; every 7th failed."""
    events = []
    for i in range(hours * 3600 // every):
        ts = T0 + timedelta(seconds=every * i)
        call = sock(ts, 4000 + i % 30000, "203.0.113.99", 443)
        if i % 7 == 3:
            call = call.model_copy(update={"outcome": Outcome.failure})
        events += [call, flow(ts + timedelta(seconds=1), "10.1.0.5", 1024 + i, "203.0.113.99", 443)]
        if i % 500 == 0:
            events.append(flow(ts + timedelta(seconds=2), "10.1.0.5", 1024 + i, "203.0.113.99", 443,
                               family="net_alert", alert__severity=1, alert__signature=SIGS[i // 500 % 5],
                               alert__category="Trojan"))
    return events


def _expected(events) -> dict:
    """What the join must say of the beacon, worked out directly from the records held in memory."""
    calls = [e for e in events if e.family == "net_socket"]
    network = [e for e in events if e.family != "net_socket"]
    alerts = [e for e in network if e.family == "net_alert"]
    cited = sorted(network, key=lambda e: (e.family != "net_alert", e.ts, e.id))[:20]
    failed = sum(e.outcome == Outcome.failure for e in calls)
    # the calls bounding the span, then the group's first calls; the earliest network records, alerts first
    calls_cited = list(dict.fromkeys([calls[0].id, calls[-1].id, *(e.id for e in calls[:20])]))
    return {"calls": len(calls), "flows": len(network) - len(alerts), "alerts": len(alerts),
            "connections": len(calls), "failed": failed, "succeeded": len(calls) - failed,
            "cited": calls_cited + [e.id for e in cited], "calls_cited": len(calls_cited),
            "sigs": sorted({str(e.get("alert.signature")) for e in cited if e.family == "net_alert"}),
            "all_sigs": len({str(e.get("alert.signature")) for e in alerts})}


def _join(events, tmp_path):
    import tracemalloc
    rule = ProcessNetworkLink()
    rule.spill_dir = tmp_path
    stage = {}
    for start in range(0, len(events), 5000):
        rule.consume(events[start:start + 5000])
        stage.update({e.id: e for e in rule.drain_staged()})
    rule.bind_loader(lambda ids: [stage[i] for i in ids if i in stage])
    tracemalloc.start()
    try:
        out = rule.finalize()
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
        rule.release_state()
    return out, peak


def _check(match, want) -> None:
    sigs = want["sigs"]
    assert match.proposed_lane == "high"
    assert [e.id for e in match.events] == want["cited"]
    assert (f"made {want['calls']} connect() call(s) to 203.0.113.99 port 443" in match.claim
            and f"{want['succeeded']} succeeded, {want['failed']} failed" in match.claim)
    assert (f"{want['flows']} flow or session record(s) across {want['connections']} connection(s)" in match.claim
            and f"{want['alerts']} IDS alert(s) on those connections, among them "
                f"{'; '.join(repr(sig) for sig in sigs[:3])} and {want['all_sigs'] - 3} more." in match.claim)
    assert (f"Of these, {want['calls_cited']} of the {want['calls']} connect() records and 20 of the "
            f"{want['flows'] + want['alerts']} network records are cited." in match.claim)


@pytest.mark.slow
def test_a_week_long_beacon_streams_one_huge_group_with_bounded_memory(tmp_path):
    day = _beacon(24)
    (small,), small_peak = _join(day, tmp_path / "day")
    _check(small, _expected(day))
    week = _beacon(24 * 7)
    (large,), large_peak = _join(week, tmp_path / "week")
    _check(large, _expected(week))
    # seven times the records in the one group, but finalize holds only a bounded sample of it
    assert large_peak < small_peak * 1.5 + 2_000_000, (small_peak, large_peak)


def test_non_scalar_telemetry_values_are_bound_as_text(tmp_path):
    rule = ProcessNetworkLink()
    rule.spill_dir = tmp_path
    call = sock(T0, [1, 2], "203.0.113.7", 4444, exe="/usr/bin/nc")
    alert = flow(T0 + timedelta(seconds=1), "10.1.0.5", 45555, "203.0.113.7", 4444, family="net_alert",
                 alert__severity=1, alert__signature=["ET a", "ET b"], alert__category={"name": "Trojan"})
    rule.consume([call, alert])
    stage = {e.id: e for e in rule.drain_staged()}
    rule.bind_loader(lambda ids: [stage[i] for i in ids if i in stage])
    (match,) = rule.finalize()
    rule.release_state()
    assert '["ET a", "ET b"]' in match.claim and rule.evaluated == 2


def test_only_the_disk_budget_refuses_a_record(tmp_path):
    rule = ProcessNetworkLink()
    rule.spill_dir = tmp_path
    rule.DISK_BUDGET = 2_000
    events = [flow(T0 + timedelta(seconds=i), "10.1.0.5", 30000 + i, "198.51.100.1", 443) for i in range(40)]
    rule.consume(events)
    rule.release_state()
    refused = rule.limits["disk"].records
    assert 0 < refused < 40 and rule.capped == refused and rule.evaluated == 40 - refused
    assert "disk budget" in rule.limit_reasons()[0]


def test_the_sweep_closes_the_spill_on_a_failure_path(tmp_path):
    from romulus.hunt import sweep as sw
    rule = ProcessNetworkLink()
    rule.spill_dir = tmp_path
    rule.consume([sock(T0, 1, "203.0.113.10", 443)])
    assert list(Path(tmp_path).glob("romulus-stage-spill-*"))
    holder = sw.Sweep.__new__(sw.Sweep)
    holder.pack = [rule]
    holder.close_stage()
    assert not list(Path(tmp_path).glob("romulus-stage-spill-*"))
