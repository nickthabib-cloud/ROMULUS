"""The existing flow rules, called directly, read Zeek conn records as they read the Suricata flow records of the same
connections.

Each case builds the same connections twice: as Zeek conn rows (Malcolm and Elastic layouts) and as their Suricata EVE
flow twins. A rule must report the same items (group, lane, severity) from either. Suricata counts whole frames and
Zeek payload bytes, so each twin carries the frame bytes its own sensor would count for the same traffic.
"""
import json
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

ETHERNET = 14
EVE_PROTOCOLS = {"ssl": "tls"}


def run_rule(rule, events):
    stage = {}
    rule.consume(events)
    stage.update({e.id: e for e in rule.drain_staged()})
    rule.bind_loader(lambda ids: [stage[i] for i in ids if i in stage])
    return rule.finalize()


def eve_twin(conn: zf.Conn, nid: str) -> dict:
    """The Suricata EVE flow record of the same connection: whole-frame bytes, the opening SYN in the directional
    flags when the Zeek history shows the originator's SYN."""
    end = conn.ts + (conn.duration or 0.0)
    record = {"timestamp": zf.iso_ms(end).replace("Z", "+0000"), "flow_id": abs(hash(nid)) % 10**15,
              "event_type": "flow", "src_ip": conn.orig_h, "dest_ip": conn.resp_h, "proto": conn.proto.upper(),
              "flow": {"bytes_toserver": (conn.orig_ip_bytes or 0) + ETHERNET * (conn.orig_pkts or 0),
                       "bytes_toclient": (conn.resp_ip_bytes or 0) + ETHERNET * (conn.resp_pkts or 0),
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
        "@timestamp": zf.iso_ms(end), "host": {"name": "suricata-01"},
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


def assert_twins(rule_class, conns, shape="malcolm", expected=1):
    zeek, suricata = both(conns, shape)
    from_zeek, from_suricata = run_rule(rule_class(), zeek), run_rule(rule_class(), suricata)
    assert len(from_zeek) == expected and items(from_zeek) == items(from_suricata)
    return from_zeek, from_suricata


def tcp(i: int, **changes) -> zf.Conn:
    return replace(zf.Conn(uid=f"Cflow{i:012d}", ts=zf.T0 + i), **changes)


@pytest.mark.parametrize("shape", ["malcolm", "elastic"])
def test_port_scan(shape):
    conns = [tcp(i, resp_h="10.0.1.20", resp_p=port, service=None, conn_state="REJ", history="Sr", duration=0.001,
                 orig_bytes=0, resp_bytes=0, orig_pkts=1, resp_pkts=1, orig_ip_bytes=44, resp_ip_bytes=40)
             for i, port in enumerate(range(20, 50))]
    from_zeek, _ = assert_twins(PortScan, conns, shape)
    assert "30 distinct destination ports" in from_zeek[0].claim


@pytest.mark.parametrize("shape", ["malcolm", "elastic"])
def test_horizontal_sweep(shape):
    conns = [tcp(i, resp_h=f"10.0.2.{i + 1}", resp_p=445, service=None, conn_state="S0", history="S",
                 duration=None, orig_bytes=0, resp_bytes=0, orig_pkts=1, resp_pkts=0, orig_ip_bytes=60,
                 resp_ip_bytes=0) for i in range(25)]
    from_zeek, _ = assert_twins(HorizontalSweep, conns, shape)
    assert "25 distinct internal addresses on tcp/445" in from_zeek[0].claim


def test_protocol_port_mismatch_on_an_identified_protocol():
    conns = [tcp(i, resp_h="10.0.1.21", resp_p=443, service="ssh") for i in range(3)]
    from_zeek, _ = assert_twins(ProtocolPortMismatch, conns)
    assert from_zeek[0].group_key == "10.0.1.21|tcp/443|ssh" and "Zeek identified ssh" in from_zeek[0].claim


@pytest.mark.parametrize("shape", ["malcolm", "elastic"])
def test_outbound_volume_asymmetry(shape):
    sent = 60 * 2**20
    conns = [tcp(0, resp_h="198.51.100.10", resp_p=443, duration=600.0, orig_bytes=sent, resp_bytes=2**20,
                 orig_pkts=45000, resp_pkts=20000, orig_ip_bytes=sent + 45000 * 52,
                 resp_ip_bytes=2**20 + 20000 * 52)]
    assert_twins(OutboundVolumeAsymmetry, conns, shape)


def test_icmp_echo_tunnel():
    payload, packets = 10 * 2**20, 20000
    conns = [replace(zf.ICMP_ECHO, uid="Cicmp", duration=1800.0, orig_bytes=payload, resp_bytes=payload,
                     orig_pkts=packets, resp_pkts=packets, orig_ip_bytes=payload + 28 * packets,
                     resp_ip_bytes=payload + 28 * packets)]
    from_zeek, _ = assert_twins(IcmpEchoTunnel, conns)
    assert from_zeek[0].group_key == "10.0.0.5|203.0.113.10|icmp"


# The flow rules' parser table (detect/flows.py PARSERS) names Suricata's and Arkime's parsers but not Zeek's, so the
# two rules that judge an unidentified record against the parsers of its sensor stop with a KeyError on a Zeek
# record. These cases flip to passing once the table names Zeek's analyzers; the xfail is strict so that change
# cannot go unnoticed.

@pytest.mark.xfail(strict=True, raises=KeyError,
                   reason="detect/flows.py PARSERS has no entry for the Zeek sensor")
def test_long_unidentified_session():
    conns = [tcp(0, resp_h="198.51.100.10", resp_p=7000, service=None, duration=3600.0, orig_bytes=500000,
                 resp_bytes=900000, orig_pkts=4000, resp_pkts=5000, orig_ip_bytes=708000,
                 resp_ip_bytes=1160000)]
    assert_twins(LongUnidentifiedSession, conns)


@pytest.mark.xfail(strict=True, raises=KeyError,
                   reason="detect/flows.py PARSERS has no entry for the Zeek sensor")
def test_protocol_port_mismatch_on_an_unidentified_data_carrying_connection():
    conns = [tcp(i, resp_h="10.0.1.22", resp_p=22, service=None) for i in range(3)]
    assert_twins(ProtocolPortMismatch, conns)
