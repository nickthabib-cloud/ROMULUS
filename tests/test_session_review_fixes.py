"""Cross-sensor UDP timing, bounded reused-tuple history, and zero-duration Zeek records."""
import json
import random
from datetime import timedelta

import pytest

from romulus.detect.flows import flow_view, sensor_of
from romulus.detect.sessions import Beaconing, LongExternalConnection
from romulus.evidence.normalize import normalize_hits
from romulus.evidence.typed import fv
from tests.fixtures.zeek_factory import SHAPES, WRITERS, Conn
from tests.test_arkime_sessions import T0, events, run, session
from tests.test_zeek_conn import normalize


def suricata(nid, start, seconds, *, port=40000):
    end = start + timedelta(seconds=seconds)
    record = {"timestamp": start.isoformat(), "event_type": "flow", "flow_id": 1000 + nid,
              "src_ip": "172.17.100.121", "src_port": port, "dest_ip": "192.0.2.174", "dest_port": 9999,
              "proto": "UDP", "flow": {"start": start.isoformat(), "end": end.isoformat(), "state": "new",
              "bytes_toserver": 100, "bytes_toclient": 0, "pkts_toserver": 1, "pkts_toclient": 0}}
    [row], skips, errors = normalize_hits([{"_index": "logs-suricata.eve-default", "_id": f"s{nid}",
        "_source": {"@timestamp": start.isoformat(), "host": {"name": "suricata"},
                    "event": {"dataset": "suricata.eve.flow", "original": json.dumps(record)}}}])
    assert not skips and not errors
    return row


def udp_rows(*, period=60, skew=0.0, seconds=0.0, third=False, offsets=None, count=10):
    arkime, sur, zeek = [], [], []
    for i in range(count):
        first = T0 + timedelta(seconds=period * i + (offsets or {}).get(i, 0), microseconds=400)
        arkime.extend(events(session(f"a{i}", first=first, seconds=seconds, sport=40000, dport=9999,
                                    proto=17, cid="1:fixed=")))
        sur.append(suricata(i, first + timedelta(seconds=skew), seconds))
        if third:
            zeek.append(normalize(WRITERS["plain"](Conn(uid=f"udp-{i}", ts=first.timestamp() + 0.002,
                orig_h="172.17.100.121", orig_p=40000, resp_h="192.0.2.174", resp_p=9999,
                proto="udp", ip_proto=17, duration=seconds, service=None, history="D"), f"z{i}")))
    return arkime, sur, zeek


@pytest.mark.parametrize(("skew", "seconds", "third"), [(0.0, 0.0, False), (0.01, 0.005, False),
                                                        (2.0, 0.005, False), (2.0, 0.005, True)])
def test_udp_precision_and_sensor_skew_count_one_start_per_exchange(skew, seconds, third):
    arkime, sur, zeek = udp_rows(skew=skew, seconds=seconds, third=third)
    [match] = run(Beaconing(), sur, zeek, arkime)
    assert "10 separate udp connections" in match.claim and "starting every 60 s" in match.claim
    assert "10 Arkime session records" in match.claim and "10 Suricata flow records" in match.claim


@pytest.mark.parametrize(("period", "offsets"), [(10, {}), (12, {4: 4})])
def test_short_reportable_udp_periods_are_not_merged(period, offsets):
    arkime, sur, _ = udp_rows(period=period, offsets=offsets)
    [match] = run(Beaconing(), arkime, sur)
    assert "10 separate udp connections" in match.claim and f"starting every {period} s" in match.claim


def test_adjacent_arkime_udp_splits_are_one_long_exchange():
    rows = events(*[session(f"split-{i}", first=T0 + timedelta(seconds=100 * i, milliseconds=20),
                   seconds=99.98, sport=16384, dport=3478, proto=17, cid="1:rtp=") for i in range(36)])
    assert run(Beaconing(), rows) == []


def test_out_of_order_copies_and_late_bridge_reconcile_closed_stretches():
    batches = udp_rows(skew=2.0, seconds=0.005, third=True)
    shuffled = [row for batch in batches for row in batch]
    random.Random(17).shuffle(shuffled)
    [match] = run(Beaconing(), *[shuffled[i:i + 7] for i in range(0, len(shuffled), 7)])
    assert "10 separate udp connections" in match.claim
    bridge = events(session("bridge", first=T0, seconds=600, sport=40000, dport=9999, proto=17,
                            cid="1:fixed="))
    assert run(Beaconing(), *batches, bridge) == []


def single_packets(proto, *, count=10, first=T0, period=60, shape="plain"):
    return [normalize(WRITERS[shape](Conn(uid=f"one-{proto}-{i}", ts=(first + timedelta(seconds=period*i)).timestamp(),
        orig_h="172.17.100.121", orig_p=40000 + i, resp_h="192.0.2.174", resp_p=9999,
        proto=proto, ip_proto=17 if proto == "udp" else 6, duration=None, service=None,
        orig_bytes=None, resp_bytes=None, conn_state="S0", history="D" if proto == "udp" else "S",
        orig_pkts=1, resp_pkts=0), f"one-{proto}-{i}")) for i in range(count)]


@pytest.mark.parametrize("proto", ["tcp", "udp"])
@pytest.mark.parametrize("shape", SHAPES)
def test_durationless_zeek_start_is_evaluated_without_mutating_typed_event(proto, shape):
    rows = single_packets(proto, shape=shape)
    before = rows[0].model_dump()
    view = flow_view(rows[0], "flow")
    assert view is not None and view.timed and view.end == view.start
    rule = Beaconing()
    [match] = run(rule, rows)
    assert rule.evaluated == 10 and rule.missing_required == 0 and not rule.limit_reasons()
    assert "Zeek recorded no duration (a single packet or no reply)" in match.claim
    assert rows[0].model_dump() == before and not rows[0].has("flow.end")


@pytest.mark.parametrize("point_first", [True, False])
def test_durationless_zeek_record_never_extends_a_long_span(point_first):
    [point] = single_packets("tcp", count=1, first=T0 + timedelta(hours=2))
    timed = normalize(WRITERS["plain"](Conn(uid="timed", ts=T0.timestamp(), orig_h="172.17.100.121",
        orig_p=40000, resp_h="192.0.2.174", resp_p=9999, duration=900), "timed"))
    rule = LongExternalConnection()
    assert run(rule, *([[point], [timed]] if point_first else [[timed], [point]])) == []
    assert rule.missing_required == 0 and rule.evaluated == 2


@pytest.mark.parametrize("shape", SHAPES)
def test_malformed_zeek_duration_is_still_missing_instead_of_an_omitted_duration(shape):
    hit = WRITERS[shape](Conn(duration=None), "bad-duration")
    path = {"plain": ("duration",), "malcolm": ("zeek", "conn", "duration"),
            "elastic": ("event", "duration"), "security_onion": ("event", "duration")}[shape]
    target = hit["_source"]
    for name in path[:-1]:
        target = target.setdefault(name, {})
    target[path[-1]] = "unreadable"
    row = normalize(hit)
    assert row.get("parse.malformed")
    view = flow_view(row, "flow")
    assert view is not None and not view.timed
    rule = Beaconing()
    assert run(rule, [row]) == [] and rule.missing_required == 1


def test_beacon_citations_prefer_arkime_and_keep_other_sensor_examples():
    arkime, sur, zeek = udp_rows(third=True, seconds=0.005)
    [match] = run(Beaconing(), sur, zeek, arkime)
    assert len(match.events) <= 20 and sensor_of(match.events[0]) == "arkime"
    assert {sensor_of(row) for row in match.events} == {"arkime", "suricata", "zeek"}
    assert "0 of the 10 Arkime" not in match.claim


def test_arkime_preference_preserves_exact_first_and_last_start_witnesses_under_negative_skew():
    arkime, sur, zeek = udp_rows(count=30, skew=-2.0, third=True, seconds=0.005)
    [match] = run(Beaconing(), sur, zeek, arkime)
    cited = {event.id for event in match.events}
    assert {sur[0].id, sur[-1].id} <= cited
    assert sensor_of(match.events[0]) == "arkime" and len(match.events) <= 20
    assert sur[0].get("flow.start") in match.claim and sur[-1].get("flow.start") in match.claim


def test_fifty_thousand_ntp_polls_on_one_tuple_keep_bounded_open_parts_and_exact_count(monkeypatch):
    monkeypatch.setattr(Beaconing, "HOT", 8)
    rule, stage = Beaconing(), {}
    [template] = events(session("ntp", first=T0, seconds=0, sport=123, dport=123, proto=17, cid="1:ntp="))
    count = 50_000
    for offset in range(0, count, 256):
        batch = []
        for i in range(offset, min(offset + 256, count)):
            start = T0 + timedelta(seconds=64 * i)
            fields = {**template.fields, "flow.start": fv(start.isoformat(), "fixture"),
                      "flow.end": fv(start.isoformat(), "fixture"), "network.protocols": fv(["ntp"], "fixture")}
            batch.append(template.model_copy(update={"id": f"ntp-{i}", "ts": start, "fields": fields}))
        rule.consume(batch)
        stage.update({row.id: row for row in rule.drain_staged()})
        assert all(len(conn["parts"]) <= 1 for _key, conn in rule.conns.items())
        if hasattr(rule, "stretches"):
            assert len(rule.stretches.buffer) <= rule.stretches.hot_size
    rule.bind_loader(lambda ids: [stage[key] for key in ids if key in stage])
    [match] = rule.finalize()
    assert "50000 separate udp connections" in match.claim and "starting every 64 s" in match.claim
    assert match.proposed_lane == "context" and rule.capped == 0
    assert len(match.events) <= 20
