"""Flow-shape rules: horizontal sweep, protocol/port disagreement, long unidentified sessions, outbound asymmetry.

Fixtures go through the real normalizer (Suricata EVE flow and netflow records, Arkime SPI sessions)."""
import gzip
import json
import random
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from romulus.detect.flows import (
    FLOW_PLAYBOOKS,
    HorizontalSweep,
    LongUnidentifiedSession,
    OutboundVolumeAsymmetry,
    ProtocolPortMismatch,
    port_ranges,
)
from romulus.detect.registry import ALL_PLAYBOOKS, PACK_VERSION, fresh_pack
from romulus.evidence.normalize import normalize_hits

T0 = datetime(2024, 11, 18, 14, 0, 0, tzinfo=UTC)
ATTACKER = "203.0.113.50"
MIB = 2**20


def _eve_time(t: datetime) -> str:
    return t.strftime("%Y-%m-%dT%H:%M:%S.%f+0000")


def eve(_id, *, src="10.0.0.5", sport=50000, dst="10.0.1.1", dport=445, proto="TCP", start=T0, seconds=1.0,
        app_proto=None, c2s=200, s2c=0, pkts_c=2, pkts_s=0, state="new", event_type="flow", observer="sensor1",
        community_id=None, drop=()):
    """One Suricata EVE flow (bidirectional) or netflow (unidirectional) record."""
    end = start + timedelta(seconds=seconds)
    record = {"timestamp": _eve_time(end), "event_type": event_type, "src_ip": src, "dest_ip": dst, "proto": proto}
    if sport is not None:
        record["src_port"] = sport
    if dport is not None:
        record["dest_port"] = dport
    if app_proto is not None:
        record["app_proto"] = app_proto
    if community_id:
        record["community_id"] = community_id
    if event_type == "flow":
        record["flow"] = {"start": _eve_time(start), "end": _eve_time(end), "bytes_toserver": c2s,
                          "bytes_toclient": s2c, "pkts_toserver": pkts_c, "pkts_toclient": pkts_s, "state": state}
    else:
        record["netflow"] = {"start": _eve_time(start), "end": _eve_time(end), "bytes": c2s, "pkts": pkts_c}
    for name in drop:
        if name in record.get("flow", {}):
            del record["flow"][name]
        record.pop(name, None)
    return {"_id": _id, "_index": "romulus-network-logs", "_source": {
        "@timestamp": _eve_time(end)[:19] + "Z", "host": {"name": observer},
        "event": {"dataset": f"suricata.eve.{event_type}", "original": json.dumps(record)}}}


def ark(_id, *, src="10.0.0.5", sport=50000, dst="10.0.1.1", dport=445, proto=6, start=T0, seconds=1.0,
        protocols=None, c2s=200, s2c=0, pkts_c=2, pkts_s=0, data_c=None, data_s=None, drop=()):
    """One Arkime SPI session record."""
    transport = {6: "tcp", 17: "udp", 1: "icmp"}[proto]
    doc = {"firstPacket": int(start.timestamp() * 1000),
           "lastPacket": int((start + timedelta(seconds=seconds)).timestamp() * 1000),
           "ipProtocol": proto, "node": "arkime1",
           "source": {"ip": src, "bytes": c2s, "packets": pkts_c},
           "destination": {"ip": dst, "bytes": s2c, "packets": pkts_s},
           "protocol": [transport] + list(protocols or [])}
    if sport is not None:
        doc["source"]["port"] = sport
    if dport is not None:
        doc["destination"]["port"] = dport
    if data_c is not None:
        doc["client"] = {"bytes": data_c}
    if data_s is not None:
        doc["server"] = {"bytes": data_s}
    for name in drop:
        if name in ("source.bytes", "destination.bytes"):
            del doc[name.split(".")[0]]["bytes"]
        else:
            doc.pop(name, None)
    return {"_id": _id, "_index": "arkime_sessions3-241118", "_source": doc}


def events(*hits):
    evs, skips, errors = normalize_hits(list(hits))
    assert errors == [] and skips == {}
    return evs


def run(rule, *batches):
    """Drive a staged playbook the way the sweep does."""
    stage = {}
    for batch in batches:
        rule.consume(batch)
        stage.update({e.id: e for e in rule.drain_staged()})
    assert rule.retained_events() == []
    rule.bind_loader(lambda ids: [stage[i] for i in ids if i in stage])
    return rule.finalize()


# ---- registry, ATT&CK and cards ----------------------------------------------------------------

CARD_KEYS = {"behavior", "telemetry", "fidelity", "benign_and_cost", "query_cost", "next_pivot", "adds",
             "research_basis", "retrieval", "lanes"}


def _attack_ids():
    with gzip.open(Path(__file__).resolve().parents[1] / "content/attack/enterprise-attack-20.0.json.gz") as fh:
        stix = json.load(fh)
    return {ref["external_id"] for obj in stix["objects"] if obj.get("type") == "attack-pattern"
            and not obj.get("revoked") and not obj.get("x_mitre_deprecated")
            for ref in obj.get("external_references", []) if ref.get("source_name") == "mitre-attack"}


def test_flow_rules_are_registered_with_cards_and_existing_attack_ids():
    ids = _attack_ids()
    pack = {type(pb) for pb in fresh_pack()}
    assert PACK_VERSION == "pack@6"
    for cls in FLOW_PLAYBOOKS:
        assert cls in ALL_PLAYBOOKS and cls in pack
        assert cls.kind == "aggregate" and cls.staged and cls.anchor_class == "network_observation"
        assert set(cls.card) == CARD_KEYS, cls.id
        assert cls.attack and set(cls.attack) <= ids, cls.id
        assert cls.assures_negative or cls.positive_only_reason
    assert HorizontalSweep.assures_negative
    assert not ProtocolPortMismatch.assures_negative and not LongUnidentifiedSession.assures_negative
    assert not OutboundVolumeAsymmetry.assures_negative
    assert OutboundVolumeAsymmetry.severity == "high" and OutboundVolumeAsymmetry.lane == "lead"


def test_port_ranges_compress_runs():
    assert port_ranges({22}) == "22" and port_ranges({5900, 5901, 5902, 6000}) == "5900-5902, 6000"


# ---- horizontal sweep --------------------------------------------------------------------------

def sweep_flows(n, *, prefix="10.0.1.", dport=445, step=1.0, answered=0, sensor="suricata", start=T0, src="10.0.0.5",
                proto="TCP", first_id=0):
    out = []
    for i in range(n):
        reply = i < answered
        kw = {"src": src, "sport": 40000 + i, "dst": f"{prefix}{i + 1}", "dport": dport,
              "start": start + timedelta(seconds=i * step), "pkts_s": 2 if reply else 0, "s2c": 120 if reply else 0}
        if sensor == "suricata":
            out.append(eve(f"s{first_id + i}", proto=proto, **kw))
        else:
            out.append(ark(f"a{first_id + i}", proto={"TCP": 6, "UDP": 17, "ICMP": 1}[proto], **kw))
    return out


def test_internal_sweep_is_one_grouped_lead_with_denominators():
    rule = HorizontalSweep()
    [m] = run(rule, events(*sweep_flows(30, answered=5)))
    assert m.proposed_lane == "lead" and m.severity == "medium"
    assert "10.0.0.5 (internal address) contacted 30 distinct internal addresses on tcp/445" in m.claim
    assert "up to 30 within 5 minutes" in m.claim
    assert "25 never sent a packet back on any recorded connection, 5 answered and 0 have no typed packet count" \
        in m.claim
    assert "10.0.1.1 (1 connection, answered)" in m.claim and "10.0.1.30 (1 connection, no reply)" in m.claim
    assert len(m.events) == 20 and m.group_key == "10.0.0.5|tcp|445|internal"
    assert rule.evaluated == 30 and rule.missing_required == 0


def test_large_mostly_silent_internal_sweep_is_high():
    hits = [eve(f"s{i}", sport=40000 + i, dst=f"10.0.{i // 200}.{i % 200 + 1}", start=T0 + timedelta(seconds=i))
            for i in range(100)]
    [m] = run(HorizontalSweep(), events(*hits))
    assert m.proposed_lane == "high" and m.severity == "medium"
    assert "in the busiest hour 100 of 100 never answered" in m.claim


def test_large_internal_sweep_that_mostly_answers_stays_a_lead():
    hits = [eve(f"s{i}", sport=40000 + i, dst=f"10.0.{i // 200}.{i % 200 + 1}", start=T0 + timedelta(seconds=i),
                pkts_s=3 if i < 80 else 0, s2c=500 if i < 80 else 0) for i in range(100)]
    [m] = run(HorizontalSweep(), events(*hits))
    assert m.proposed_lane == "lead" and "80 answered" in m.claim


def test_external_source_sweeping_internal_addresses_is_a_lead_with_reconnaissance_context():
    [m] = run(HorizontalSweep(), events(*sweep_flows(100, src=ATTACKER, step=1.0)))
    assert m.proposed_lane == "lead" and "(external address)" in m.claim
    assert any("T1595.001" in note for note in m.notes)


def test_external_fan_out_needs_the_higher_threshold():
    below = sweep_flows(40, prefix="198.51.100.", dport=443)
    assert run(HorizontalSweep(), events(*below)) == []
    [m] = run(HorizontalSweep(), events(*sweep_flows(60, prefix="198.51.100.", dport=443)))
    assert m.proposed_lane == "lead" and "60 distinct external addresses on tcp/443" in m.claim


def test_below_threshold_is_no_match_and_evaluated():
    rule = HorizontalSweep()
    assert run(rule, events(*sweep_flows(19))) == []
    assert rule.evaluated == 19 and rule.missing_required == 0


def test_half_open_window_boundary():
    nineteen = [eve(f"s{i}", sport=40000 + i, dst=f"10.0.1.{i + 1}", start=T0) for i in range(19)]
    at_edge = eve("edge", sport=41000, dst="10.0.1.99", start=T0 + timedelta(seconds=300))
    inside = eve("inside", sport=41000, dst="10.0.1.99", start=T0 + timedelta(seconds=299))
    assert run(HorizontalSweep(), events(*nineteen, at_edge)) == []
    [m] = run(HorizontalSweep(), events(*nineteen, inside))
    assert "up to 20 within 5 minutes" in m.claim


def test_an_address_reached_exactly_one_hour_later_is_not_listed_in_the_busiest_hour():
    burst = [eve(f"s{i}", sport=40000 + i, dst=f"10.0.1.{i + 1}", start=T0) for i in range(40)]
    late = eve("late", sport=41000, dst="10.0.1.200", start=T0 + timedelta(seconds=3600))
    [m] = run(HorizontalSweep(), events(*burst, late))
    assert "contacted 41 distinct internal addresses" in m.claim and "up to 40 within 60 minutes" in m.claim
    assert "10.0.1.200" not in m.claim and m.claim.endswith("10.0.1.30 (1 connection, no reply) and 10 more.")


def test_slow_sweep_is_caught_by_the_hour_window():
    [m] = run(HorizontalSweep(), events(*sweep_flows(45, step=80.0)))
    assert "up to 4 within 5 minutes" in m.claim and "up to 45 within 60 minutes" in m.claim


def test_the_same_connections_seen_by_both_sensors_are_counted_once():
    both = sweep_flows(20) + sweep_flows(20, sensor="arkime")
    [m] = run(HorizontalSweep(), events(*both))
    assert "contacted 20 distinct internal addresses" in m.claim
    assert "20 distinct connection(s), each counted once across sensors (20 Suricata flow records and 20 Arkime " \
           "session records)" in m.claim


def test_netflow_answers_on_ephemeral_ports_never_form_a_sweep():
    # A busy server answering 60 clients: each netflow answer has the client's ephemeral port as dest_port.
    answers = [eve(f"n{i}", event_type="netflow", src="10.0.0.80", sport=80, dst=f"10.0.2.{i + 1}", dport=50000)
               for i in range(60)]
    requests = [eve(f"q{i}", event_type="netflow", src=f"10.0.2.{i + 1}", sport=50000, dst="10.0.0.80", dport=80)
                for i in range(60)]
    rule = HorizontalSweep()
    assert run(rule, events(*answers, *requests)) == []
    # the sensor wrote only netflow records in this batch: its traffic is unevaluated, never a clean negative
    assert rule.evaluated == 0 and rule.missing_required == 120


def test_netflow_records_beside_flow_records_are_skipped_without_double_counting():
    flows = sweep_flows(25)
    netflows = [eve(f"n{i}", event_type="netflow", sport=40000 + i, dst=f"10.0.1.{i + 1}") for i in range(25)]
    rule = HorizontalSweep()
    [m] = run(rule, events(*flows, *netflows))
    assert "25 distinct connection(s)" in m.claim and "(25 Suricata flow records)" in m.claim
    assert rule.evaluated == 25 and rule.missing_required == 0


def test_missing_port_or_counters_are_counted_missing_not_no_match():
    rule = HorizontalSweep()
    no_port = eve("np", dport=None)
    no_counters = eve("nc", drop=("bytes_toserver", "bytes_toclient", "pkts_toserver", "pkts_toclient", "state",
                                  "start", "end"))
    assert run(rule, events(no_port, no_counters)) == []
    assert rule.evaluated == 0 and rule.missing_required == 2


def test_icmp_sweep_is_grouped_without_a_port():
    hits = [eve(f"i{i}", proto="ICMP", sport=None, dport=None, dst=f"10.0.1.{i + 1}", start=T0 + timedelta(seconds=i))
            for i in range(25)]
    [m] = run(HorizontalSweep(), events(*hits))
    assert "25 distinct internal addresses on icmp" in m.claim and m.group_key == "10.0.0.5|icmp|None|internal"


def test_multicast_and_broadcast_destinations_are_not_hosts_reached():
    hits = [eve(f"m{i}", proto="UDP", dst=f"239.255.{i}.250", dport=1900, sport=40000 + i) for i in range(30)]
    hits.append(eve("b", proto="UDP", dst="255.255.255.255", dport=67, sport=68))
    rule = HorizontalSweep()
    assert run(rule, events(*hits)) == []
    assert rule.evaluated == 31


def test_sweep_spanning_partitions_and_reread_records_count_once():
    hits = sweep_flows(30)
    rule = HorizontalSweep()
    [m] = run(rule, events(*hits[:15]), events(*hits[10:]), events(*hits[:5]))
    assert "contacted 30 distinct internal addresses" in m.claim and "30 distinct connection(s)" in m.claim


def test_sweep_output_is_independent_of_record_order():
    hits = events(*sweep_flows(40, answered=7), *sweep_flows(30, prefix="198.51.100.", dport=53, proto="UDP",
                                                              first_id=100))
    shuffled = list(hits)
    random.Random(7).shuffle(shuffled)
    first = [(m.claim, m.proposed_lane, [e.id for e in m.events]) for m in run(HorizontalSweep(), hits)]
    second = [(m.claim, m.proposed_lane, [e.id for e in m.events]) for m in run(HorizontalSweep(), shuffled)]
    assert first == second and len(first) == 1


# ---- protocol and port disagreement --------------------------------------------------------------

def test_ssh_on_the_tls_port_is_a_mismatch_lead():
    hit = eve("x", src="10.0.0.5", dst=ATTACKER, dport=443, app_proto="ssh", c2s=4000, s2c=9000, pkts_s=12)
    [m] = run(ProtocolPortMismatch(), events(hit))
    assert m.proposed_lane == "lead" and m.claim_type == "network_observation"
    assert f"Suricata identified ssh on 1 connection from 10.0.0.5 to {ATTACKER} on tcp/443" in m.claim
    assert "tcp/443 is registered here for tls; ssh is registered on tcp 22" in m.claim
    assert "parser's judgement" in m.claim


def test_http_on_an_unregistered_port_is_a_mismatch_and_both_sensors_count_one_connection():
    flow = eve("x", dst=ATTACKER, dport=4444, app_proto="http", c2s=4000, s2c=9000, pkts_s=12)
    session = ark("y", dst=ATTACKER, dport=4444, protocols=["http"], c2s=4100, s2c=9100, pkts_s=12)
    [m] = run(ProtocolPortMismatch(), events(flow, session))
    assert "Arkime and Suricata identified http on 1 connection" in m.claim
    assert "tcp/4444 is not registered here for any protocol" in m.claim
    assert "1 Suricata flow record and 1 Arkime session record" in m.claim


@pytest.mark.parametrize("hit", [
    eve("http80", dport=80, app_proto="http", c2s=900, s2c=5000),
    eve("tls443", dport=443, app_proto="tls", c2s=900, s2c=5000),
    eve("proxy", dport=8080, app_proto="http", c2s=900, s2c=5000),
    # an NTP server's answer recorded by Arkime as its own session to the client's ephemeral port
    ark("ntp", proto=17, src="198.51.100.123", sport=123, dst="10.0.0.5", dport=51234, protocols=["ntp"],
        c2s=90, s2c=90),
    ark("rtsp", dport=554, protocols=["rtsp"], c2s=900, s2c=90000, data_c=400, data_s=80000),
    # an HTTP CONNECT proxy: Arkime lists both the outer HTTP and the inner TLS
    ark("connect", dport=3128, protocols=["http", "tls"], c2s=900, s2c=9000, data_c=500, data_s=8000),
    # STARTTLS on submission
    ark("starttls", dport=587, protocols=["smtp", "tls"], c2s=900, s2c=9000, data_c=500, data_s=8000),
    # RPC on a dynamic port negotiated through the endpoint mapper
    eve("rpc", dport=49712, app_proto="dcerpc", c2s=900, s2c=5000),
])
def test_consistent_protocol_and_port_shapes_are_not_mismatches(hit):
    rule = ProtocolPortMismatch()
    assert run(rule, events(hit)) == [] and rule.evaluated == 1


def test_data_carrying_flow_to_a_registered_port_with_no_protocol_is_a_lead():
    hits = [eve(f"u{i}", sport=50000 + i, dst=ATTACKER, dport=80, c2s=3000, s2c=8000, pkts_s=8,
                start=T0 + timedelta(minutes=i)) for i in range(3)]
    hits.append(eve("ok", sport=50100, dst=ATTACKER, dport=80, app_proto="http", c2s=900, s2c=5000))
    [m] = run(ProtocolPortMismatch(), events(*hits))
    assert f"3 connections from 10.0.0.5 to {ATTACKER} on tcp/80" in m.claim
    assert "Suricata recorded no app_proto on 3 flow records" in m.claim
    assert "registered here for http, which Suricata can parse" in m.claim
    assert "Suricata wrote 4 flow records between them on this port, identified as http 1" in m.claim
    assert "not proof that a different protocol was used" in m.claim and len(m.events) == 3


def test_failed_detection_on_the_dns_port_is_reported_as_failed():
    hit = eve("f", proto="UDP", dst="198.51.100.53", dport=53, app_proto="failed", c2s=4000, s2c=4000, pkts_s=10)
    [m] = run(ProtocolPortMismatch(), events(hit))
    assert "reported protocol detection 'failed' on 1 flow record" in m.claim


def test_other_sensor_identifying_the_same_connection_clears_the_unidentified_view():
    flow = eve("x", dst=ATTACKER, dport=80, c2s=3000, s2c=8000, pkts_s=8)
    session = ark("y", dst=ATTACKER, dport=80, protocols=["http"], c2s=3000, s2c=8000, data_c=200, data_s=7000)
    assert run(ProtocolPortMismatch(), events(flow, session)) == []
    assert run(ProtocolPortMismatch(), events(session, flow)) == []


def test_handshake_only_connections_to_registered_ports_are_not_unidentified_traffic():
    hit = eve("h", dst=ATTACKER, dport=80, c2s=280, s2c=200, pkts_s=2, state="closed")
    rule = ProtocolPortMismatch()
    assert run(rule, events(hit)) == [] and rule.evaluated == 1


def test_kafka_without_a_suricata_parser_is_silent_and_partial_arkime_recognition_is_grouped():
    suricata = [eve(f"k{i}", sport=50000 + i, dst="10.0.3.9", dport=9092, c2s=5000, s2c=9000, pkts_s=20)
                for i in range(30)]
    rule = ProtocolPortMismatch()
    assert run(rule, events(*suricata)) == [] and rule.evaluated == 30
    arkime = [ark(f"a{i}", sport=51000 + i, dst="10.0.3.9", dport=9092, protocols=["kafka"] if i < 2 else None,
                  c2s=5000, s2c=9000, data_c=3000, data_s=7000) for i in range(30)]
    [m] = run(ProtocolPortMismatch(), events(*arkime))
    assert "28 connections from 10.0.0.5 to 10.0.3.9 on tcp/9092" in m.claim
    assert "Arkime wrote 30 session records between them on this port, identified as kafka 2" in m.claim
    assert m.proposed_lane == "lead"


def test_mdns_failed_detection_to_the_multicast_group_is_not_unidentified_traffic():
    hits = [eve(f"m{i}", proto="UDP", src=f"10.0.0.{i + 10}", sport=5353, dst="224.0.0.251", dport=5353,
                app_proto="failed", c2s=600, s2c=0, pkts_s=0) for i in range(5)]
    rule = ProtocolPortMismatch()
    assert run(rule, events(*hits)) == [] and rule.evaluated == 5


def test_missing_protocol_field_or_byte_counters_are_partial_not_no_match():
    rule = ProtocolPortMismatch()
    no_protocols = ark("np", dport=80, protocols=None, c2s=3000, s2c=8000)
    no_protocols["_source"].pop("protocol")
    no_bytes = eve("nb", dst=ATTACKER, dport=80, drop=("bytes_toserver",))
    assert run(rule, events(no_protocols, no_bytes)) == []
    assert rule.evaluated == 0 and rule.missing_required == 2


# ---- long unidentified sessions ----------------------------------------------------------------

def chunks(n, *, minutes=12, dport=4444, protocols=None, prefix="c", dst=ATTACKER, start=T0, sport=51000, **kw):
    return [ark(f"{prefix}{i}", sport=sport, dst=dst, dport=dport, start=start + timedelta(minutes=minutes * i),
                seconds=minutes * 60 - 1, protocols=protocols, c2s=4000, s2c=9000, data_c=2000, data_s=7000, **kw)
            for i in range(n)]


def test_long_unidentified_connection_is_stitched_and_references_the_long_connection_rule():
    rule = LongUnidentifiedSession()
    [m] = run(rule, events(*chunks(4)))
    assert m.proposed_lane == "lead" and m.severity == "medium"
    assert f"1 connection from 10.0.0.5 to {ATTACKER} on tcp/4444 lasted at least 30 minutes" in m.claim
    assert "the longest ran 48 minutes" in m.claim and "(4 Arkime session records)" in m.claim
    assert any("net.long_external_connection" in note for note in m.notes)
    assert len(m.events) == 4


def test_the_same_long_connection_from_both_sensors_is_one_connection():
    flow = eve("f", sport=51000, dst=ATTACKER, dport=4444, seconds=48 * 60, c2s=40000, s2c=90000, pkts_s=300)
    [m] = run(LongUnidentifiedSession(), events(*chunks(4), flow))
    assert "1 connection from" in m.claim and "1 unidentified data-carrying connection between them" in m.claim
    assert "1 Suricata flow record and 4 Arkime session records" in m.claim


def test_short_unidentified_connections_are_counted_only_beside_a_long_one():
    short = chunks(1, prefix="s", sport=52000, start=T0 + timedelta(hours=2))
    assert run(LongUnidentifiedSession(), events(*short)) == []
    [m] = run(LongUnidentifiedSession(), events(*chunks(4), *short))
    assert "2 unidentified data-carrying connections between them on this port in total" in m.claim


@pytest.mark.parametrize("hits", [
    chunks(4, protocols=["ssh"]),                       # identified: judged by the mismatch rule instead
    chunks(4, dport=9092),                              # a registered port
    chunks(4, dport=40000, sport=80),                   # a web server's answer to a client's ephemeral port
])
def test_identified_registered_or_reversed_long_sessions_are_not_matched(hits):
    rule = LongUnidentifiedSession()
    assert run(rule, events(*hits)) == [] and rule.evaluated == 4


def test_a_reused_five_tuple_hours_later_is_not_stitched_into_one_long_connection():
    early = chunks(2, prefix="e")
    late = chunks(2, prefix="l", start=T0 + timedelta(hours=3))
    assert run(LongUnidentifiedSession(), events(*early, *late)) == []


def test_internal_long_unidentified_udp_session_has_no_boundary_note():
    hits = chunks(4, proto=17, dst="10.0.4.4", dport=31337)
    [m] = run(LongUnidentifiedSession(), events(*hits))
    assert "on udp/31337" in m.claim
    assert not any("net.long_external_connection" in note for note in m.notes)


def test_long_session_missing_payload_counters_or_times_is_partial():
    rule = LongUnidentifiedSession()
    no_payload = ark("np", dport=4444, drop=("source.bytes",))
    no_times = eve("nt", dport=4444, drop=("start", "end"), c2s=4000, s2c=9000)
    assert run(rule, events(no_payload, no_times)) == []
    assert rule.evaluated == 0 and rule.missing_required == 2


# ---- outbound volume asymmetry -----------------------------------------------------------------

def upload(_id, *, out=60 * MIB, back=MIB, sensor="suricata", src="10.0.0.5", dst=ATTACKER, sport=50000, dport=443,
           start=T0):
    if sensor == "suricata":
        return eve(_id, src=src, sport=sport, dst=dst, dport=dport, start=start, seconds=600, app_proto="tls",
                   c2s=out, s2c=back, pkts_s=100)
    return ark(_id, src=src, sport=sport, dst=dst, dport=dport, start=start, seconds=600, protocols=["tls"],
               c2s=out, s2c=back, pkts_s=100)


def test_large_asymmetric_upload_is_a_high_severity_lead_with_denominators():
    other = upload("o", out=40 * MIB, back=40 * MIB, dst="198.51.100.7")
    peer = upload("p", src="10.0.0.6", out=MIB, back=MIB, sport=50001)
    [m] = run(OutboundVolumeAsymmetry(), events(upload("u"), other, peer))
    assert m.proposed_lane == "lead" and m.severity == "high"
    assert f"10.0.0.5 sent 62,914,560 bytes (60.0 MiB) to {ATTACKER} and received 1,048,576 bytes back" in m.claim
    assert "60.0:1 outbound to inbound" in m.claim and "ports tcp/443 (1)" in m.claim
    assert "That is 60% of the 104,857,600 bytes 10.0.0.5 sent to external addresses" in m.claim
    assert "1 other internal address also sent data" in m.claim
    assert "not proof that data was stolen" in m.claim


def test_the_same_upload_seen_by_both_sensors_is_not_doubled():
    [m] = run(OutboundVolumeAsymmetry(), events(upload("u"), upload("v", sensor="arkime", out=59 * MIB)))
    assert "sent 62,914,560 bytes" in m.claim and "1 Suricata flow record and 1 Arkime session record" in m.claim


def test_upload_split_over_connections_adds_up():
    hits = [upload(f"u{i}", out=20 * MIB, back=MIB // 2, sport=50000 + i, start=T0 + timedelta(minutes=i))
            for i in range(3)]
    [m] = run(OutboundVolumeAsymmetry(), events(*hits))
    assert "over 3 connections it initiated" in m.claim


@pytest.mark.parametrize("hit", [
    upload("in", src=ATTACKER, dst="10.0.0.5"),               # initiated from outside
    upload("lan", dst="10.0.9.9"),                             # internal to internal
    upload("sym", out=60 * MIB, back=30 * MIB),                # below the ratio
    upload("small", out=49 * MIB, back=0),                     # below the volume
])
def test_upload_negatives(hit):
    rule = OutboundVolumeAsymmetry()
    assert run(rule, events(hit)) == [] and rule.evaluated == 1


def test_nothing_back_is_worded_without_a_ratio():
    [m] = run(OutboundVolumeAsymmetry(), events(upload("u", back=0)))
    assert "nothing came back" in m.claim


def test_missing_byte_counters_are_partial_and_netflow_is_not_read():
    rule = OutboundVolumeAsymmetry()
    no_bytes = eve("nb", dst=ATTACKER, dport=443, drop=("bytes_toclient",))
    netflow = eve("nf", event_type="netflow", dst=ATTACKER, dport=443, c2s=900 * MIB)
    assert run(rule, events(no_bytes, upload("u", out=MIB), netflow)) == []
    assert rule.evaluated == 1 and rule.missing_required == 1


def test_upload_boundary_at_exactly_the_volume_and_ratio():
    [m] = run(OutboundVolumeAsymmetry(), events(upload("u", out=50 * MIB, back=5 * MIB)))
    assert "10.0:1" in m.claim
