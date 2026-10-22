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
