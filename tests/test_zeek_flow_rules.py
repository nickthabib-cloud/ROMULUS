"""The existing flow rules, called directly, read Zeek conn records as they read the Suricata flow records of the same
connections.

Each case builds the same connections twice: as Zeek conn rows (Malcolm and Elastic layouts) and as their Suricata EVE
flow twins. A rule must report the same items (group, lane, severity) and say the same thing in them, apart from the
sensor's name. Each twin carries the counters that make the two readings comparable: for TCP and UDP the byte counts
Zeek recorded as payload (the rules state counts as recorded), for ICMP the whole frames whose estimated payload is
Zeek's payload (the echo rule estimates payload from Suricata's frames).

Where the rules read the two differently, the case is a strict xfail naming the change it waits for, so that change
cannot land unnoticed.
"""
import json
import re
from dataclasses import replace

import pytest

from romulus.detect.flows import (
    HorizontalSweep,
    IcmpEchoTunnel,
    LongUnidentifiedSession,
    OutboundVolumeAsymmetry,
    ProtocolPortMismatch,
)
from romulus.detect.network import PortScan
from romulus.evidence.normalize import normalize_hits
from romulus.evidence.zeek import ZEEK_NORMALIZER
from tests.fixtures import zeek_factory as zf

ICMP_FRAME_HEADER = 42                  # Ethernet + IPv4 + ICMP: what the echo rule subtracts from Suricata's frames
EVE_PROTOCOLS = {"ssl": "tls"}
PARSERS_GAP = ("detect/flows.py PARSERS has no entry for the Zeek sensor: the flow rules' Zeek reading (sweep and "
               "profile slice) adds Zeek's analyzer set")
OPENER_GAP = ("detect/flows.py flow_view does not read tcp.opened_by_orig, so a Zeek record never shows who opened a "
              "connection: the flow rules' Zeek reading (sweep and profile slice) reads it")


def run_rule(rule, events):
    stage = {}
    rule.consume(events)
    stage.update({e.id: e for e in rule.drain_staged()})
    rule.bind_loader(lambda ids: [stage[i] for i in ids if i in stage])
    return rule.finalize()


def eve_twin(conn: zf.Conn, nid: str) -> dict:
    """The Suricata EVE flow record of the same connection, with the opening SYN in the directional flags when the
    Zeek history shows the originator's SYN. Its timestamp is the connection's start, as Zeek's ts is (the rules
    that place a record by its time then place both alike)."""
    end = conn.ts + (conn.duration or 0.0)
    if conn.proto == "icmp":
        sent = (conn.orig_bytes or 0) + ICMP_FRAME_HEADER * (conn.orig_pkts or 0)
        received = (conn.resp_bytes or 0) + ICMP_FRAME_HEADER * (conn.resp_pkts or 0)
    else:
        sent, received = conn.orig_bytes or 0, conn.resp_bytes or 0
    record = {"timestamp": zf.iso_ms(conn.ts).replace("Z", "+0000"), "flow_id": abs(hash(nid)) % 10**15,
              "event_type": "flow", "src_ip": conn.orig_h, "dest_ip": conn.resp_h, "proto": conn.proto.upper(),
              "flow": {"bytes_toserver": sent, "bytes_toclient": received,
                       "pkts_toserver": conn.orig_pkts or 0, "pkts_toclient": conn.resp_pkts or 0,
                       "start": zf.iso_ms(conn.ts).replace("Z", "+0000"),
                       "end": zf.iso_ms(end).replace("Z", "+0000"), "state": "closed"}}
    if conn.proto == "icmp":
        record.update(icmp_type=conn.orig_p, icmp_code=0)
    else:
        record.update(src_port=conn.orig_p, dest_port=conn.resp_p)
    if conn.service:
        record["app_proto"] = EVE_PROTOCOLS.get(conn.service, conn.service)
    if conn.proto == "tcp" and (conn.history or "").startswith("S"):
        record["tcp"] = {"syn": True, "tcp_flags_ts": "02" if conn.history == "S" else "1b"}
    return {"_id": nid, "_index": "logs-suricata.eve-default", "_source": {
        "@timestamp": zf.iso_ms(conn.ts), "host": {"name": "suricata-01"},
        "event": {"dataset": "suricata.eve.flow", "original": json.dumps(record)}}}


def both(conns: list[zf.Conn], shape: str = "malcolm") -> tuple[list, list]:
    zeek_hits = [zf.WRITERS[shape](conn, f"z{i}") for i, conn in enumerate(conns)]
    eve_hits = [eve_twin(conn, f"s{i}") for i, conn in enumerate(conns)]
    zeek, skips, errors = normalize_hits(zeek_hits)
    assert (skips, errors) == ({}, []) and len(zeek) == len(conns)
    assert all(e.normalizer == ZEEK_NORMALIZER for e in zeek)
    suricata, skips, errors = normalize_hits(eve_hits)
    assert (skips, errors) == ({}, []) and len(suricata) == len(conns)
    return zeek, suricata


def items(matches) -> list[tuple]:
    return sorted((m.group_key, m.proposed_lane, m.severity) for m in matches)


_SENSOR_WORDS = re.compile(r"Zeek conn records?|Suricata flow records?|Zeek|Suricata")


def claim_text(match) -> str:
    """A claim with the sensor's name and record kind replaced, so two sensors' claims compare word for word."""
    return _SENSOR_WORDS.sub(lambda m: "<records>" if "record" in m.group(0) else "<sensor>", match.claim)


def run_twins(rule_class, conns, shape="malcolm"):
    zeek, suricata = both(conns, shape)
    return run_rule(rule_class(), zeek), run_rule(rule_class(), suricata)


def assert_twins(rule_class, conns, shape="malcolm", expected=1):
    from_zeek, from_suricata = run_twins(rule_class, conns, shape)
    assert len(from_zeek) == expected and items(from_zeek) == items(from_suricata)
    assert [claim_text(m) for m in from_zeek] == [claim_text(m) for m in from_suricata]
    return from_zeek


def tcp(i: int, **changes) -> zf.Conn:
    return replace(zf.Conn(uid=f"Cflow{i:012d}", ts=zf.T0 + i), **changes)


@pytest.mark.parametrize("shape", ["malcolm", "elastic"])
def test_port_scan(shape):
    conns = [tcp(i, resp_h="10.0.1.20", resp_p=port, service=None, conn_state="REJ", history="Sr", duration=0.001,
                 orig_bytes=0, resp_bytes=0, orig_pkts=1, resp_pkts=1, orig_ip_bytes=44, resp_ip_bytes=40)
             for i, port in enumerate(range(20, 50))]
    [match] = assert_twins(PortScan, conns, shape)
    assert "30 distinct destination ports" in match.claim


@pytest.mark.parametrize("shape", ["malcolm", "elastic"])
def test_horizontal_sweep(shape):
    conns = [tcp(i, resp_h=f"10.0.2.{i + 1}", resp_p=445, service=None, conn_state="S0", history="S",
                 duration=None, orig_bytes=0, resp_bytes=0, orig_pkts=1, resp_pkts=0, orig_ip_bytes=60,
                 resp_ip_bytes=0) for i in range(25)]
    [match] = assert_twins(HorizontalSweep, conns, shape)
    assert "25 distinct internal addresses on tcp/445" in match.claim and "25 Zeek conn records" in match.claim


def test_protocol_port_mismatch_on_an_identified_protocol():
    conns = [tcp(i, resp_h="10.0.1.21", resp_p=443, service="ssh") for i in range(3)]
    [match] = assert_twins(ProtocolPortMismatch, conns)
    assert match.group_key == "10.0.1.21|tcp/443|ssh" and "Zeek identified ssh" in match.claim


def test_icmp_echo_tunnel():
    payload, packets = 10 * 2**20, 20000
    conns = [replace(zf.ICMP_ECHO, uid="Cicmp", duration=1800.0, orig_bytes=payload, resp_bytes=payload,
                     orig_pkts=packets, resp_pkts=packets, orig_ip_bytes=payload + 28 * packets,
                     resp_ip_bytes=payload + 28 * packets)]
    [match] = assert_twins(IcmpEchoTunnel, conns)
    assert match.group_key == "10.0.0.5|203.0.113.10|icmp" and "according to Zeek" in match.claim


SENT = 60 * 2**20


def upload(**changes) -> list[zf.Conn]:
    """60 MiB from an internal address to an external one, opened by the internal side (history starts with S)."""
    fields = {"resp_h": "198.51.100.10", "resp_p": 443, "duration": 600.0, "orig_bytes": SENT, "resp_bytes": 2**20,
              "orig_pkts": 45000, "resp_pkts": 20000, "orig_ip_bytes": SENT + 45000 * 52,
              "resp_ip_bytes": 2**20 + 20000 * 52}
    return [tcp(0, **{**fields, **changes})]


@pytest.mark.parametrize("shape", ["malcolm", "elastic"])
def test_outbound_volume_asymmetry_reports_the_same_item(shape):
    from_zeek, from_suricata = run_twins(OutboundVolumeAsymmetry, upload(), shape)
    assert len(from_zeek) == 1 and items(from_zeek) == items(from_suricata)
    assert from_zeek[0].claim.startswith("10.0.0.5 sent 62,914,560 bytes (60.0 MiB) to 198.51.100.10")


@pytest.mark.xfail(strict=True, reason=OPENER_GAP)
def test_outbound_volume_asymmetry_states_the_opener_zeek_recorded():
    """Zeek's history shows 10.0.0.5's SYN opened the connection, as Suricata's flags do; the claim should say so
    rather than 'picked up mid-stream'."""
    assert_twins(OutboundVolumeAsymmetry, upload())


@pytest.mark.xfail(strict=True, reason=OPENER_GAP)
def test_outbound_volume_asymmetry_reads_an_upload_zeek_shows_opened_from_a_low_port():
    """An upload the internal host opened from a low source port to a high external port: without the opener the
    port shape reads as an internal server answering, so the Zeek record is not read as an upload."""
    assert_twins(OutboundVolumeAsymmetry, upload(orig_p=1500, resp_p=50000, service=None))


@pytest.mark.xfail(strict=True, raises=KeyError, reason=PARSERS_GAP)
def test_long_unidentified_session():
    conns = [tcp(0, resp_h="198.51.100.10", resp_p=7000, service=None, duration=3600.0, orig_bytes=500000,
                 resp_bytes=900000, orig_pkts=4000, resp_pkts=5000, orig_ip_bytes=708000,
                 resp_ip_bytes=1160000)]
    assert_twins(LongUnidentifiedSession, conns)


@pytest.mark.xfail(strict=True, raises=KeyError, reason=PARSERS_GAP)
def test_protocol_port_mismatch_on_an_unidentified_data_carrying_connection():
    conns = [tcp(i, resp_h="10.0.1.22", resp_p=22, service=None) for i in range(3)]
    assert_twins(ProtocolPortMismatch, conns)
