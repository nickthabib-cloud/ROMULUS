"""Session timing rules share bidirectional flow identity across the three sensors."""
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from romulus.detect import bounded
from romulus.detect.sessions import Beaconing, LongExternalConnection
from romulus.evidence.normalize import normalize_hits
from romulus.evidence.typed import RawRef, TypedEvent, fv
from tests.fixtures.zeek_factory import SHAPES, T0, WRITERS, Conn
from tests.test_arkime_sessions import IRREGULAR, run
from tests.test_zeek_conn import normalize
from tests.test_zeek_flow_rules import eve_twin


def zeek(conn, shape="plain", name="z", **kwargs):
    return normalize(WRITERS[shape](conn, name, **kwargs))


def observed(event, sensor, *, reverse=False, cid=None, **extra):
    fields = {name: field.value for name, field in event.fields.items()}
    if sensor == "arkime":
        fields.update({"source.bytes": 100, "destination.bytes": 500, "tcp.flags.syn": 1})
        fields.pop("observer.product", None)
    else:
        fields.update({"observer.product": "suricata", "flow.state": "closed",
                       "tcp.tcp_flags_ts": "02", "flow.bytes_toserver": 100,
                       "flow.bytes_toclient": 500})
    if reverse:
        for first, second in (("source.ip", "destination.ip"), ("source.port", "destination.port")):
            fields[first], fields[second] = fields[second], fields[first]
    if cid is None:
        fields.pop("network.community_id", None)
    else:
        fields["network.community_id"] = cid
    fields.update(extra)
    return TypedEvent(id=f"{sensor}-{event.id}", family="net_session" if sensor == "arkime" else "net_flow",
                      ts=event.ts, host=sensor, fields={k: fv(v, "fixture") for k, v in fields.items()},
                      raw=[RawRef(target="fixture", native_id=f"{sensor}-{event.id}")], normalizer="fixture")


def beacons(shape="plain", offsets=None, **kwargs):
    return [zeek(Conn(uid=f"beacon-{kwargs.get('orig_h', 'default')}-{i}", ts=T0 + offset,
                      orig_p=40000 + i, duration=1, **kwargs),
                 shape, f"z-{kwargs.get('orig_h', 'default')}-{i}")
            for i, offset in enumerate(offsets or range(0, 600, 60))]


@pytest.mark.parametrize("shape", SHAPES)
def test_zeek_only_beacon_and_sensor_record_claim(shape):
    [match] = run(Beaconing(), beacons(shape))
    assert "10 separate tcp connections" in match.claim
    assert "Zeek" in match.claim and "conn record" in match.claim
    assert "Arkime" not in match.claim


def test_cross_sensor_identity_does_not_depend_on_community_id_or_direction():
    rows = beacons()
    arkime = [observed(row, "arkime", cid=f"different-{i}") for i, row in enumerate(rows)]
    suricata = [observed(row, "suricata", reverse=True, **{"tcp.tcp_flags_ts": "10"}) for row in rows]
    [baseline] = run(Beaconing(), arkime)
    [mixed] = run(Beaconing(), suricata, rows, arkime)
    assert "10 separate tcp connections" in baseline.claim and "10 separate tcp connections" in mixed.claim
    assert mixed.group_key == baseline.group_key
    assert "10 Suricata flow records" in mixed.claim and "10 Zeek conn records" in mixed.claim
    assert "10 Arkime session records" in mixed.claim


def test_suricata_only_beacon_and_long_connection_use_real_eve_flow_records():
    records = [eve_twin(Conn(uid=f"s-{i}", ts=T0 + 60 * i, orig_p=40000 + i), f"s-{i}") for i in range(10)]
    rows, skips, errors = normalize_hits(records)
    assert not skips and not errors
    [beacon] = run(Beaconing(), rows)
    assert "10 separate tcp connections" in beacon.claim and "Suricata flow record" in beacon.claim
    rows, skips, errors = normalize_hits([eve_twin(Conn(duration=2400), "long")])
    assert not skips and not errors
    [long] = run(LongExternalConnection(), rows)
    assert "spanning 40 minutes" in long.claim
    assert any(p.field == "tcp.tcp_flags_ts" for p in long.predicate)


def test_different_tuples_with_same_written_community_id_stay_separate():
    first = zeek(Conn(duration=2400, community="shared"), name="first")
    second = zeek(Conn(uid="other", duration=2400, orig_p=52000, community="shared"), name="second")
    matches = run(LongExternalConnection(), [first, second])
    assert len(matches) == 2 and len({match.group_key for match in matches}) == 2


def test_arkime_long_finding_keeps_its_identity_when_another_sensor_arrives_first():
    row = zeek(Conn(duration=2400))
    arkime = observed(row, "arkime", cid="1:arkime-written")
    [baseline] = run(LongExternalConnection(), [arkime])
    [mixed] = run(LongExternalConnection(), [row], [arkime])
    assert baseline.group_key == mixed.group_key == "1:arkime-written"


def test_jittered_zeek_connections_stay_negative():
    assert run(Beaconing(), beacons(offsets=IRREGULAR)) == []


def test_zeek_ntp_is_context_even_with_other_sensors():
    rows = beacons(proto="udp", service="ntp", resp_p=123, ip_proto=17)
    [match] = run(Beaconing(), rows, [observed(row, "suricata", **{"network.app_proto": "ntp"}) for row in rows])
    assert match.proposed_lane == "context"
    assert "identified every connection as ntp" in match.claim


@pytest.mark.parametrize("rule_cls", [Beaconing, LongExternalConnection])
def test_unidirectional_netflow_is_suppressed_only_for_same_sensor_batch(rule_cls):
    row = observed(zeek(Conn(duration=2000)), "suricata")
    fields = {key: value for key, value in row.fields.items()
              if key not in ("flow.state", "flow.bytes_toserver", "flow.bytes_toclient",
                             "flow.pkts_toserver", "flow.pkts_toclient")}
    fields["flow.bytes"] = fv(100, "fixture")
    net = row.model_copy(update={"id": "netflow", "fields": fields})
    rule = rule_cls()
    run(rule, [net, row])
    assert rule.evaluated == 1 and rule.missing_required == 0
    missing = rule_cls()
    run(missing, [net], [row])
    assert missing.evaluated == 1 and missing.missing_required == 1
    another = rule_cls()
    run(another, [net.model_copy(update={"host": "another"}), row])
    assert another.missing_required == 1


@pytest.mark.parametrize("shape", SHAPES)
def test_long_zeek_connection_uses_real_start_before_window_and_history_opener(shape):
    row = zeek(Conn(ts=T0 - 7200, duration=8000), shape)
    # Retrieval's lookback delivers the overlap; its typed start is never clipped to row-write time.
    row = row.model_copy(update={"ts": row.ts + timedelta(seconds=8000)})
    [match] = run(LongExternalConnection(), [row])
    assert "spanning 133 minutes" in match.claim and "10.0.0.5:51000 opened" in match.claim
    assert "Zeek conn record" in match.claim and "started inside the hunt window" not in match.claim
    assert any(p.field == "tcp.opened_by_orig" for p in match.predicate)


def test_reversed_midstream_record_then_opener_uses_proven_client_without_byte_inflation():
    row = zeek(Conn(duration=2000, orig_bytes=100, resp_bytes=500))
    reverse = observed(row, "suricata", reverse=True, **{"tcp.tcp_flags_ts": "10",
                       "flow.bytes_toserver": 500, "flow.bytes_toclient": 100})
    arkime = observed(row, "arkime")
    [match] = run(LongExternalConnection(), [reverse], [row], [arkime])
    assert "10.0.0.5:51000 opened to 203.0.113.10:443" in match.claim
    assert "100 bytes from the client and 500 bytes from the server" in match.claim
    assert "Suricata flow record" in match.claim and "Arkime session record" in match.claim
    assert "Zeek conn record" in match.claim


def test_interim_and_final_zeek_rows_form_one_connection_and_cumulative_bytes_once():
    conn = Conn(duration=1900, orig_bytes=70, resp_bytes=300)
    interim = zeek(conn, "malcolm", "interim", interim=True)
    final = zeek(replace(conn, duration=2400, orig_bytes=100, resp_bytes=500), "malcolm", "final")
    [match] = run(LongExternalConnection(), [interim], [final])
    assert "one TCP connection" in match.claim and "spanning 40 minutes" in match.claim
    assert "100 bytes from the client and 500 bytes from the server" in match.claim


def test_batch_supersede_keeps_one_final_zeek_record_for_the_long_connection():
    conn = Conn(duration=1900)
    rows, skips, errors = normalize_hits([WRITERS["malcolm"](conn, "interim", interim=True),
        WRITERS["malcolm"](replace(conn, duration=2400), "final")])
    assert not errors and len(rows) == 1 and sum(skips.values()) == 1
    [match] = run(LongExternalConnection(), rows)
    assert "1 Zeek conn record" in match.claim and "spanning 40 minutes" in match.claim


def test_history_without_opening_never_calls_zeek_originator_client():
    [match] = run(LongExternalConnection(), [zeek(Conn(duration=2000, history="Dd"))])
    assert "Which side opened it is not known" in match.claim
    assert "bytes from the client" not in match.claim and "Arkime picked" not in match.claim


def test_many_flow_identities_spill_without_losing_beacon_counts(monkeypatch):
    monkeypatch.setattr(Beaconing, "HOT", 2)
    rule, stage = Beaconing(), {}
    for client in range(1, 41):
        batch = beacons(orig_h=f"10.1.0.{client}")
        rule.consume(batch)
        stage.update({row.id: row for row in rule.drain_staged()})
        assert all(len(store.hot) <= 2 for store in vars(rule).values() if isinstance(store, bounded.KeyedStore))
    rule.bind_loader(lambda ids: [stage[key] for key in ids if key in stage])
    matches = rule.finalize()
    assert len(matches) == 40 and all("10 separate tcp connections" in match.claim for match in matches)
    assert rule.conns.on_disk > 0 and rule.capped == 0


def test_one_large_beacon_pair_uses_disk_order_statistics_with_bounded_buffers(monkeypatch):
    monkeypatch.setattr(Beaconing, "HOT", 4)
    rule, stage = Beaconing(), {}
    first = zeek(Conn())
    count, peak = 4096, 0
    original = rule.starts.append

    def append(record, order):
        nonlocal peak
        result = original(record, order)
        peak = max(peak, len(rule.starts.buffer))
        return result

    monkeypatch.setattr(rule.starts, "append", append)
    for offset in range(0, count, 128):
        batch = []
        for i in range(offset, min(offset + 128, count)):
            start = datetime.fromtimestamp(T0 + 60 * i, UTC)
            fields = {**first.fields, "source.port": fv(10000 + i, "fixture"),
                      "flow.start": fv(start.isoformat(), "fixture"),
                      "flow.end": fv((start + timedelta(seconds=1)).isoformat(), "fixture")}
            batch.append(first.model_copy(update={"id": f"large-{i}", "ts": start, "fields": fields}))
        rule.consume(batch)
        stage.update({event.id: event for event in rule.drain_staged()})
    rule.bind_loader(lambda ids: [stage[key] for key in ids if key in stage])
    [match] = rule.finalize()
    assert f"{count} separate tcp connections" in match.claim and "starting every 60 s" in match.claim
    assert peak <= rule.HOT and rule.capped == 0 and len(match.events) == 20
