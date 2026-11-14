"""Direction-dependent network rules read who opened a connection, and whether both sides took part, from typed
per-side evidence, never from a record's source/destination orientation alone.

Backscatter (an unsolicited SYN-ACK from an outside host, which Arkime records with the internal address as the
source because it swaps the sides of a session whose first packet is a SYN-ACK) and connections an outside client
opened to an internal server are not outbound channels. Each case runs through the real normalizers of the three
sensors: Arkime SPI sessions, Suricata EVE flow records and Zeek conn records."""
import json
from datetime import UTC, datetime, timedelta

import pytest

from romulus.detect import bounded, flows, netdef
from romulus.detect.flows import (
    EXCHANGED,
    INSIDE_HALF_ONLY,
    ONE_SIDED_INSIDE_SILENT,
    OPENED_BY_INSIDE,
    OPENED_BY_OUTSIDE,
    OPENERS_DISAGREE,
    OUTSIDE_HALF_ONLY,
    SIDE_BARE,
    SIDE_SILENT,
    SIDE_SPOKE,
    SIDE_UNKNOWN,
    UNJUDGED,
    flow_view,
    judge_connection,
    record_kind,
    side_states,
    zeek_history_kinds,
)
from romulus.detect.linux_sequences import OutboundSSHExternal
from romulus.detect.sessions import (
    Beaconing,
    LongExternalConnection,
    LongInboundRemoteAccess,
    LongInboundSession,
)
from romulus.evidence.normalize import normalize_hits
from romulus.evidence.typed import RawRef, TypedEvent, fv
from romulus.site import absent_site_facts
from tests.fixtures import zeek_factory as zf
from tests.test_arkime_sessions import run
from tests.test_zeek_conn import normalize

T0 = datetime(2024, 11, 18, 14, 0, tzinfo=UTC)
INSIDE, OUTSIDE = "10.0.0.5", "203.0.113.10"
_n = 0


def _id(prefix):
    global _n
    _n += 1
    return f"{prefix}{_n}"


# ---- the three sensors' records, through their real normalizers ----------------------------------------------------

def arkime(src, sport, dst, dport, *, first=T0, seconds=60.0, src_pkts=10, dst_pkts=12, flags=None, c2s=None,
           s2c=None, protocols=("tcp",), cid=None, app_bytes=True, doc_id=None, root=None):
    """An Arkime SPI session. `flags` is Arkime's tcpflags counters (None: the session carries none). `root` is the
    rootId Arkime writes on every record of a session it saved in several pieces (the first piece's own id)."""
    doc = {"firstPacket": int(first.timestamp() * 1000),
           "lastPacket": int((first + timedelta(seconds=seconds)).timestamp() * 1000),
           "ipProtocol": 6, "node": "arkime-01",
           "network": {"community_id": cid or f"1:{src}:{sport}:{dst}:{dport}="},
           "source": {"ip": src, "port": sport, "bytes": 60 * src_pkts, "packets": src_pkts},
           "destination": {"ip": dst, "port": dport, "bytes": 60 * dst_pkts, "packets": dst_pkts},
           "protocol": list(protocols)}
    if root is not None:
        doc["rootId"] = root
    # Arkime writes application-byte counts on every session; `app_bytes=False` leaves them out (older shapes)
    if c2s is not None or app_bytes:
        doc["client"] = {"bytes": c2s or 0}
    if s2c is not None or app_bytes:
        doc["server"] = {"bytes": s2c or 0}
    if flags is not None:
        # typed names (syn_ack) as Arkime writes them (syn-ack)
        doc["tcpflags"] = {"syn": 0, "syn-ack": 0, "ack": 0, "psh": 0, "fin": 0, "rst": 0, "urg": 0,
                           **{name.replace("_", "-"): count for name, count in flags.items()}}
    events, skips, errors = normalize_hits([{"_id": doc_id or _id("a"), "_index": "arkime_sessions3-241118",
                                             "_source": doc}])
    assert (skips, errors) == ({}, []) and len(events) == 1
    return events[0]


def suricata(src, sport, dst, dport, *, first=T0, seconds=60.0, pkts=(10, 12), sizes=None, flags=None,
             app_proto=None):
    """A Suricata EVE flow record. `flags` is (tcp_flags_ts, tcp_flags_tc) as EVE writes them (None: no tcp block)."""
    end = first + timedelta(seconds=seconds)
    sizes = sizes or (66 * pkts[0], 66 * pkts[1])
    record = {"timestamp": first.isoformat().replace("+00:00", "+0000"), "flow_id": abs(hash(_id("f"))) % 10**15,
              "event_type": "flow", "src_ip": src, "src_port": sport, "dest_ip": dst, "dest_port": dport,
              "proto": "TCP", "flow": {"bytes_toserver": sizes[0], "bytes_toclient": sizes[1],
                                       "pkts_toserver": pkts[0], "pkts_toclient": pkts[1],
                                       "start": first.isoformat().replace("+00:00", "+0000"),
                                       "end": end.isoformat().replace("+00:00", "+0000"), "state": "closed"}}
    if app_proto:
        record["app_proto"] = app_proto
    if flags is not None:
        record["tcp"] = {"tcp_flags_ts": flags[0], "tcp_flags_tc": flags[1]}
    hit = {"_id": _id("s"), "_index": "logs-suricata.eve-default", "_source": {
        "@timestamp": first.isoformat().replace("+00:00", "Z"), "host": {"name": "suricata-01"},
        "event": {"dataset": "suricata.eve.flow", "original": json.dumps(record)}}}
    events, skips, errors = normalize_hits([hit])
    assert (skips, errors) == ({}, []) and len(events) == 1
    return events[0]


def zeek(orig, orig_p, resp, resp_p, *, first=T0, seconds=60.0, history="ShADadFf", pkts=(14, 16),
         payload=(1200, 18000), service="ssl", shape="malcolm"):
    """A Zeek conn record (the originator is the source)."""
    conn = zf.Conn(uid=_id("C"), ts=first.timestamp(), orig_h=orig, orig_p=orig_p, resp_h=resp, resp_p=resp_p,
                   service=service, duration=seconds, history=history, orig_pkts=pkts[0], resp_pkts=pkts[1],
                   orig_bytes=payload[0], resp_bytes=payload[1], orig_ip_bytes=40 * pkts[0] + payload[0],
                   resp_ip_bytes=40 * pkts[1] + payload[1], conn_state="OTH")
    return normalize(zf.WRITERS[shape](conn, conn.uid))


def chunks(make, n=4, minutes=12, **kw):
    """One connection written as `n` save-interval records (Arkime), spanning n * minutes. As Arkime writes them,
    every piece carries the first piece's id as its rootId."""
    root = _id("a")
    return [make(first=T0 + timedelta(minutes=minutes * i), seconds=minutes * 60 - 1, root=root,
                 **({"doc_id": root} if i == 0 else {}), **kw) for i in range(n)]


def typed(family, **fields):
    """A typed record built directly (for the per-record predicate)."""
    return TypedEvent(id=_id("t"), family=family, ts=T0, host="fixture",
                      fields={k.replace("__", "."): fv(v, "fixture") for k, v in fields.items()},
                      raw=[RawRef(target="fixture", native_id=_id("r"))], normalizer="fixture")


def states(event):
    return side_states(event, flow_view(event, record_kind(event)))


def ssh(*batches, tmp_path, management=()):
    """The outbound SSH rule over the given records."""
    from dataclasses import replace
    detector = OutboundSSHExternal()
    detector.spill_dir = tmp_path
    detector.site_facts = replace(absent_site_facts(), management_hosts=management)
    stage = {}
    for batch in batches:
        detector.consume(list(batch))
        stage.update({e.id: e for e in detector.drain_staged()})
    detector.bind_loader(lambda ids: [stage[i] for i in ids if i in stage])
    return list(detector.finalize()), detector


# Arkime backscatter: an outside host's SYN-ACKs to an internal address that never sent a SYN. Arkime swaps the sides
# so the internal address is the source; it sent nothing, or one reset per SYN-ACK.
SYN_ACKS = {"syn_ack": 3}
BACKSCATTER_ARKIME = {"silent": {"src_pkts": 0, "dst_pkts": 3, "flags": SYN_ACKS, "c2s": 0, "s2c": 0},
                      "reset": {"src_pkts": 3, "dst_pkts": 3, "flags": {"syn_ack": 3, "rst": 3}, "c2s": 0, "s2c": 0}}
# Suricata: the to-server side carries resets only, the to-client side SYN-ACKs; and the same record not swapped
BACKSCATTER_SURICATA = {"swapped": {"pkts": (1, 2), "flags": ("04", "12")},
                        "silent": {"pkts": (0, 2), "flags": (None, "12")}}


# ---- the predicate ---------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("fields,expected", [
    # Arkime: the internal source sent nothing; the outside host sent SYN-ACKs only
    ({"source__packets": 0, "destination__packets": 3, "tcp__flags__syn": 0, "tcp__flags__syn_ack": 3, "tcp__flags__rst": 0,
      "client__bytes": 0, "server__bytes": 0}, (SIDE_SILENT, SIDE_BARE)),
    # ... or one reset per SYN-ACK: every packet of either side may be a reset or a SYN-ACK
    ({"source__packets": 3, "destination__packets": 3, "tcp__flags__syn": 0, "tcp__flags__syn_ack": 3, "tcp__flags__rst": 3,
      "client__bytes": 0, "server__bytes": 0}, (SIDE_BARE, SIDE_BARE)),
    # without application-byte counts, only the reset count may settle a side, and frame bytes can show data
    ({"source__packets": 3, "destination__packets": 3, "tcp__flags__syn": 0, "tcp__flags__syn_ack": 3, "tcp__flags__rst": 3,
      "source__bytes": 162, "destination__bytes": 222}, (SIDE_BARE, SIDE_BARE)),
    ({"source__packets": 6, "destination__packets": 3, "tcp__flags__syn": 0, "tcp__flags__syn_ack": 5, "tcp__flags__rst": 2,
      "source__bytes": 360, "destination__bytes": 222}, (SIDE_UNKNOWN, SIDE_UNKNOWN)),
    ({"source__packets": 6, "destination__packets": 3, "tcp__flags__syn": 0, "tcp__flags__syn_ack": 0, "tcp__flags__rst": 9,
      "source__bytes": 3000, "destination__bytes": 162}, (SIDE_SPOKE, SIDE_BARE)),
    # mid-stream with traffic both ways: each side sent more packets than the session's SYNs, SYN-ACKs and resets
    ({"source__packets": 40, "destination__packets": 50, "tcp__flags__syn": 0, "tcp__flags__syn_ack": 0, "tcp__flags__rst": 1},
     (SIDE_SPOKE, SIDE_SPOKE)),
    # application bytes settle it whatever the flags
    ({"source__packets": 1, "destination__packets": 1, "tcp__flags__syn": 0, "tcp__flags__syn_ack": 0, "tcp__flags__rst": 1,
          "client__bytes": 10, "server__bytes": 0}, (SIDE_SPOKE, SIDE_BARE)),
    # packets without flag counts: only a silent side is settled
    ({"source__packets": 0, "destination__packets": 12}, (SIDE_SILENT, SIDE_UNKNOWN)),
    ({"source__packets": 10, "destination__packets": 12}, (SIDE_UNKNOWN, SIDE_UNKNOWN)),
    ({}, (SIDE_UNKNOWN, SIDE_UNKNOWN)),
])
def test_arkime_side_states(fields, expected):
    event = typed("net_session", source__ip=INSIDE, source__port=51000, destination__ip=OUTSIDE,
                  destination__port=22, network__transport="tcp", **fields)
    assert states(event) == expected


@pytest.mark.parametrize("ts,tc,pkts,sizes,expected", [
    ("04", "12", (1, 2), (54, 132), (SIDE_BARE, SIDE_BARE)),           # reset answering SYN-ACKs
    (None, "12", (0, 2), (0, 132), (SIDE_SILENT, SIDE_BARE)),
    ("18", "18", (20, 30), (2000, 9000), (SIDE_SPOKE, SIDE_SPOKE)),   # PSH|ACK both ways
    ("10", "1a", (5, 5), (330, 330), (SIDE_SPOKE, SIDE_SPOKE)),       # bare ACKs; data push the other way
    ("14", "18", (1, 9), (54, 4000), (SIDE_BARE, SIDE_SPOKE)),        # one RST|ACK packet only
    ("14", "18", (9, 9), (594, 4000), (SIDE_UNKNOWN, SIDE_SPOKE)),    # ACKs and a reset over several packets
    ("02", "04", (1, 1), (66, 54), (SIDE_UNKNOWN, SIDE_BARE)),        # opened (lone SYN): not an exchange judgement
    ("04", "12", (6, 6), (324, 396), (SIDE_BARE, SIDE_BARE)),         # six SYN-ACKs: one handshake's retransmissions
    ("04", "12", (7, 7), (378, 462), (SIDE_BARE, SIDE_UNKNOWN)),      # more may hide pure acknowledgements
    ("00", "00", (1, 1), (60, 60), (SIDE_UNKNOWN, SIDE_UNKNOWN)),     # flagless probes settle nothing
    (None, None, (5, 5), (330, 330), (SIDE_UNKNOWN, SIDE_UNKNOWN)),   # no tcp block
    (None, None, (5, 5), (5000, 9000), (SIDE_SPOKE, SIDE_SPOKE)),     # data both ways without flags
])
def test_suricata_side_states(ts, tc, pkts, sizes, expected):
    fields = {"tcp.tcp_flags_ts": ts, "tcp.tcp_flags_tc": tc}
    event = typed("net_flow", source__ip=INSIDE, source__port=51000, destination__ip=OUTSIDE, destination__port=22,
                  network__transport="tcp", flow__pkts_toserver=pkts[0], flow__pkts_toclient=pkts[1],
                  flow__bytes_toserver=sizes[0], flow__bytes_toclient=sizes[1], flow__state="closed",
                  **{k.replace(".", "__"): v for k, v in fields.items() if v is not None})
    assert states(event) == expected


@pytest.mark.parametrize("history,pkts,payload,expected", [
    ("^hR", (1, 2), (0, 0), (SIDE_BARE, SIDE_BARE)),          # Zeek flipped a SYN-ACK first; the reset answered it
    ("^h", (0, 2), (0, 0), (SIDE_SILENT, SIDE_BARE)),
    ("Dd", (10, 12), (500, 900), (SIDE_SPOKE, SIDE_SPOKE)),    # picked up mid-stream, data both ways
    ("Aa", (3, 3), (0, 0), (SIDE_SPOKE, SIDE_SPOKE)),          # keepalives both ways
    ("Dr", (5, 1), (300, 0), (SIDE_SPOKE, SIDE_BARE)),         # the outside answered data with a reset
    ("D", (5, None), (300, None), (SIDE_SPOKE, SIDE_UNKNOWN)),
])
def test_zeek_side_states(history, pkts, payload, expected):
    fields = {"flow__pkts_toserver": pkts[0], "flow__bytes_toserver": payload[0]}
    if pkts[1] is not None:
        fields.update(flow__pkts_toclient=pkts[1], flow__bytes_toclient=payload[1])
    event = typed("net_flow", source__ip=INSIDE, source__port=51000, destination__ip=OUTSIDE, destination__port=22,
                  network__transport="tcp", observer__product="zeek", flow__bytes_are_payload=True,
                  conn__history=history, **fields)
    assert states(event) == expected


def test_non_tcp_records_are_never_judged():
    event = typed("net_session", source__ip=INSIDE, source__port=5353, destination__ip=OUTSIDE,
                  destination__port=53, network__transport="udp", source__packets=0, destination__packets=4)
    assert states(event) == (SIDE_UNKNOWN, SIDE_UNKNOWN)


@pytest.mark.parametrize("openers,inside_state,outside_state,expected", [
    ([(INSIDE, 51000)], SIDE_SILENT, SIDE_SILENT, OPENED_BY_INSIDE),
    ([(OUTSIDE, 443)], SIDE_SPOKE, SIDE_SPOKE, OPENED_BY_OUTSIDE),
    ([(INSIDE, 51000), (OUTSIDE, 443)], SIDE_SPOKE, SIDE_SPOKE, OPENERS_DISAGREE),
    ([], SIDE_SPOKE, SIDE_SPOKE, EXCHANGED),
    ([], SIDE_BARE, SIDE_BARE, ONE_SIDED_INSIDE_SILENT),
    ([], SIDE_SILENT, SIDE_BARE, ONE_SIDED_INSIDE_SILENT),         # backscatter: SYN-ACKs, nothing back
    ([], SIDE_SILENT, SIDE_SILENT, ONE_SIDED_INSIDE_SILENT),
    ([], SIDE_BARE, SIDE_SPOKE, ONE_SIDED_INSIDE_SILENT),          # the inside only reset what it was sent
    ([], SIDE_SILENT, SIDE_SPOKE, OUTSIDE_HALF_ONLY),              # one-way capture of the outside's half
    ([], SIDE_SILENT, SIDE_UNKNOWN, OUTSIDE_HALF_ONLY),
    ([], SIDE_SPOKE, SIDE_SILENT, INSIDE_HALF_ONLY),               # one-way capture of the inside's half
    ([], SIDE_SPOKE, SIDE_BARE, INSIDE_HALF_ONLY),
    ([], SIDE_UNKNOWN, SIDE_BARE, UNJUDGED),           # the internal packets may be an unanswered opening's SYNs
    ([], SIDE_UNKNOWN, SIDE_SILENT, UNJUDGED),
    ([], SIDE_UNKNOWN, SIDE_SPOKE, UNJUDGED),
    ([], SIDE_SPOKE, SIDE_UNKNOWN, UNJUDGED),
])
def test_judge_connection(openers, inside_state, outside_state, expected):
    inside, outside = (INSIDE, 51000), (OUTSIDE, 443)
    assert judge_connection(openers, {inside: inside_state, outside: outside_state}, inside, outside) == expected


def test_a_side_no_record_names_is_unknown():
    assert judge_connection([], {}, (INSIDE, 51000), (OUTSIDE, 443)) == UNJUDGED


# ---- net.long_external_connection ------------------------------------------------------------------------------------

@pytest.mark.parametrize("variant", sorted(BACKSCATTER_ARKIME))
def test_arkime_backscatter_is_not_a_long_connection(variant):
    rule = LongExternalConnection()
    records = chunks(lambda **kw: arkime(INSIDE, 51000, OUTSIDE, 80, **kw, **BACKSCATTER_ARKIME[variant]))
    assert run(rule, records) == []
    [note] = rule.coverage_notes()
    assert note.startswith("not reported (informational): unsolicited response packets, not connections")
    assert "(1 connection(s))" in note and f"{INSIDE}:51000 and {OUTSIDE}:80, 48 minutes" in note
    assert rule.limit_reasons() == []


@pytest.mark.parametrize("variant", sorted(BACKSCATTER_SURICATA))
def test_suricata_backscatter_is_not_a_long_connection(variant):
    rule = LongExternalConnection()
    assert run(rule, [suricata(INSIDE, 51000, OUTSIDE, 80, seconds=2400, **BACKSCATTER_SURICATA[variant])]) == []
    assert any("unsolicited response packets" in note for note in rule.coverage_notes())


def test_unswapped_suricata_backscatter_reads_the_outside_sender_as_opening_it_and_is_not_reported():
    # Suricata's to-server flags carry the SYN bit of the SYN-ACKs: the outside sender is read as opening it
    rule = LongExternalConnection()
    assert run(rule, [suricata(OUTSIDE, 80, INSIDE, 51000, seconds=2400, pkts=(2, 1), flags=("12", "04"))]) == []
    assert any(note.startswith("not reported (informational): connections a recorded TCP opening shows an external")
               for note in rule.coverage_notes())


def test_zeek_backscatter_is_not_a_long_connection():
    rule = LongExternalConnection()
    row = zeek(INSIDE, 51000, OUTSIDE, 80, seconds=2400, history="^hR", pkts=(1, 2), payload=(0, 0), service=None)
    assert run(rule, [row]) == []
    assert any("unsolicited response packets" in note for note in rule.coverage_notes())


@pytest.mark.parametrize("make", ["arkime", "suricata", "zeek"])
def test_internal_opened_long_connection_is_still_reported(make):
    record = {"arkime": lambda: chunks(lambda **kw: arkime(INSIDE, 51000, OUTSIDE, 4444, flags={"syn": 1}, **kw)),
              "suricata": lambda: [suricata(INSIDE, 51000, OUTSIDE, 4444, seconds=2400, flags=("1b", "1b"))],
              "zeek": lambda: [zeek(INSIDE, 51000, OUTSIDE, 4444, seconds=2400)]}[make]()
    rule = LongExternalConnection()
    [match] = run(rule, record)
    assert f"{INSIDE}:51000 opened to {OUTSIDE}:4444 (a record shows its SYN)" in match.claim
    assert rule.coverage_notes() == [] and rule.limit_reasons() == []


@pytest.mark.parametrize("make", ["arkime", "suricata", "zeek"])
def test_inbound_long_session_to_an_internal_server_is_served_not_a_channel(make):
    record = {"arkime": lambda: chunks(lambda **kw: arkime(OUTSIDE, 51000, INSIDE, 22, flags={"syn": 1}, **kw)),
              "suricata": lambda: [suricata(OUTSIDE, 51000, INSIDE, 22, seconds=2400, flags=("1b", "1b"))],
              "zeek": lambda: [zeek(OUTSIDE, 51000, INSIDE, 22, seconds=2400, service="ssh")]}[make]()
    rule = LongExternalConnection()
    assert run(rule, record) == []
    [note] = rule.coverage_notes()
    assert note.startswith("not reported (informational): connections a recorded TCP opening shows an external "
                           "address opened to an internal service (judged as inbound sessions by")
    assert f"{INSIDE}:22 and {OUTSIDE}:51000" in note and "(1 connection(s))" in note
    # the inbound remote-access rule reports it instead, and the grouped service rule leaves it alone
    assert run(LongInboundSession(), record) == []
    inbound = LongInboundRemoteAccess()
    [match] = run(inbound, record)
    assert f"{OUTSIDE} held 1 TCP session(s) of at least 30 minutes open to {INSIDE} port 22 (SSH)" in match.claim
    assert f"A record shows {OUTSIDE} opened the session (its SYN)." in match.claim
    assert "not that a logon succeeded" in match.claim
    # under the RFC 1918 defaults the direction is assumed: medium, said so, never "outside the site"
    assert match.proposed_lane == "lead" and match.severity == "medium"
    assert "outside the site" not in match.claim and netdef.DIRECTION_ASSUMED_REASON in match.notes


@pytest.mark.parametrize("port", [80, 443, 8080, 8443])
def test_inbound_long_session_to_a_web_port_is_reported_by_the_session_rule(port):
    record = chunks(lambda **kw: arkime(OUTSIDE, 51000, INSIDE, port, flags={"syn": 1}, **kw))
    rule = LongExternalConnection()
    assert run(rule, record) == []
    [note] = rule.coverage_notes()                      # one served reading, handed to the inbound rules
    assert note.startswith("not reported (informational): connections a recorded TCP opening shows an external "
                           "address opened to an internal service (judged as inbound sessions by")
    [match] = run(LongInboundSession(), record)
    assert match.group_key == f"service|{INSIDE}|{port}" and match.proposed_lane == "lead"
    assert run(LongInboundRemoteAccess(), record) == []


def _dev_shape(sensor):
    """An outside address held a session to the web server it had compromised: opened to inside:80 with the SYN
    recorded, 121 minutes, about 1.4 KB from the client and 272 bytes back."""
    if sensor == "arkime":
        return [arkime(OUTSIDE, 35983, INSIDE, 80, first=T0 + timedelta(minutes=11 * i), seconds=11 * 60 - (i < 10),
                       src_pkts=3, dst_pkts=2, c2s=128, s2c=25, flags={"syn": int(i == 0), "ack": 4, "psh": 1},
                       protocols=("tcp", "http"), cid="1:dev=") for i in range(11)]
    return [suricata(OUTSIDE, 35983, INSIDE, 80, seconds=121 * 60, pkts=(20, 12), sizes=(1409 + 66 * 20, 272 + 66 * 12),
                     flags=("1b", "1b"), app_proto="http")]


@pytest.mark.parametrize("sensor", ["arkime", "suricata"])
def test_a_session_held_to_a_compromised_web_server_is_one_lead_citing_its_records(sensor):
    records = _dev_shape(sensor)
    [match] = run(LongInboundSession(), records)
    assert match.playbook_id == "net.long_inbound_session" and match.proposed_lane == "lead"
    assert f"1 distinct outside address(es) held 1 TCP session(s) of at least 30 minutes open to {INSIDE} port 80" \
        in match.claim
    assert "the longest lasted 121 minutes" in match.claim and "identified as http" in match.claim
    assert "Records show the outside address opened 1 of the 1 (its SYN)." in match.claim
    assert "Every one of the 1 session(s) is cited" in match.claim
    cited = {e.id for e in match.events}
    assert {records[0].id, records[-1].id} <= cited          # the session's opening and its bounding records
    assert ("ip", OUTSIDE, "src") in match.entities and list(match.fleet_hosts) == [(OUTSIDE, "")]
    assert not any(note.startswith("citation is partial") for note in match.notes)
    # the outbound-channel rule hands it over, and it is not remote access
    assert run(LongExternalConnection(), records) == [] and run(LongInboundRemoteAccess(), records) == []


def _held(outside, sport, port, *, start=T0, minutes=48, cid=None):
    """One continuous session of `minutes` in four Arkime save-interval records, the SYN on the first."""
    step = minutes / 4
    return [arkime(outside, sport, INSIDE, port, first=start + timedelta(minutes=step * i), seconds=step * 60 - 1,
                   flags={"syn": int(i == 0), "ack": 20, "psh": 5}, cid=cid or f"1:{outside}:{sport}:{port}=")
            for i in range(4)]


def test_every_session_of_a_small_group_is_cited():
    # three long sessions from one outside address
    one = (_held(OUTSIDE, 40001, 443) + _held(OUTSIDE, 40002, 443, start=T0 + timedelta(hours=2), minutes=60)
           + _held(OUTSIDE, 40003, 443, start=T0 + timedelta(hours=5), minutes=90))
    [match] = run(LongInboundSession(), one)
    assert f"1 distinct outside address(es) held 3 TCP session(s) of at least 30 minutes open to {INSIDE} port 443" \
        in match.claim
    assert "Every one of the 3 session(s) is cited" in match.claim
    cited = {e.id for e in match.events}
    for session in (one[0:4], one[4:8], one[8:12]):
        assert {session[0].id, session[-1].id} <= cited
    assert match.aggregate_summary["cited_session_count"] == 3
    # two outside addresses, one session each
    two = _held(OUTSIDE, 40001, 8443) + _held("198.51.100.7", 40001, 8443, minutes=70)
    [match] = run(LongInboundSession(), two)
    assert "2 distinct outside address(es) held 2 TCP session(s)" in match.claim
    assert "Every one of the 2 session(s) is cited" in match.claim
    assert {two[0].id, two[3].id, two[4].id, two[7].id} <= {e.id for e in match.events}
    assert sorted(match.fleet_hosts) == [("198.51.100.7", ""), (OUTSIDE, "")]


def test_a_member_with_more_sessions_than_the_budget_says_its_others_are_not_cited():
    # 12 four-record sessions from one address: each cited session needs two records, so ten fit
    rows = [e for k in range(12) for e in _held(OUTSIDE, 41000 + k, 443, start=T0 + timedelta(hours=k),
                                                minutes=40 + k)]
    [match] = run(LongInboundSession(), rows)
    assert ("10 of the 12 session(s), from 1 of the 1 outside address(es), are cited by the records bounding them and "
            "the record showing their opening: each address's longest session before any second one, longest first. "
            "The other 2 session(s) are not cited; 1 of the cited address(es) have further long sessions that are "
            "not cited.") in match.claim
    assert "citation is partial: 10 of 12 sessions (1 of 1 outside addresses) are cited; the member list names " \
           "every outside address" in match.notes
    assert len(match.events) == 20
    # the two not cited are the shortest
    assert not {rows[0].id, rows[4].id} & {e.id for e in match.events}


def test_a_busy_web_server_is_one_item_with_exact_members_and_a_stated_partial_citation(monkeypatch):
    monkeypatch.setattr(LongInboundSession, "HOT", 2)
    monkeypatch.setattr(LongInboundSession, "MEMBER_BATCH", 50)
    rule = LongInboundSession()
    [match] = run(rule, _clients(443, 3000, attacker="203.0.113.66", longest=300))
    assert rule.conns.on_disk > 0
    assert match.group_key == f"service|{INSIDE}|443"
    assert match.fleet_host_count == 3001 and len(list(match.fleet_hosts)) == 3001 and match.fleet_hosts_complete
    assert f"3001 distinct outside address(es) held 3001 TCP session(s) of at least 30 minutes open to {INSIDE} " \
           "port 443" in match.claim
    assert "The outside addresses with the longest sessions: 203.0.113.66 (1 session(s), longest 300 minutes)" \
        in match.claim and "; and 2981 more (the item's member list holds every one)." in match.claim
    assert ("20 of the 3001 session(s), from 20 of the 3001 outside address(es), are cited" in match.claim
            and "The other 2981 session(s) are not cited; 2981 address(es) have no cited session." in match.claim)
    assert any(note.startswith("citation is partial: 20 of 3001 sessions (20 of 3001 outside addresses)")
               for note in match.notes)
    assert len(match.events) == 20 and "203.0.113.66" in {str(e.get("source.ip")) for e in match.events}
    assert match.aggregate_summary == {"outside_address_count": 3001, "session_count": 3001,
                                       "continuous_session_count": 3001, "cited_session_count": 20,
                                       "longest_session_seconds": 18000.0, "members_complete": 1}


def _visit(outside, sport, port, start, *, cid):
    """One short, complete visit (opened and closed within the record)."""
    return arkime(outside, sport, INSIDE, port, first=start, seconds=3, src_pkts=6, dst_pkts=5, c2s=400, s2c=3000,
                  flags={"syn": 1, "ack": 6, "psh": 2, "fin": 2}, cid=cid)


def test_a_client_port_reused_hours_later_is_a_span_with_gaps_never_a_held_session():
    # the same outside address and port visit inside:443 twice, three hours apart
    visits = [_visit("198.51.100.9", 44000, 443, T0, cid="1:reuse="),
              _visit("198.51.100.9", 44000, 443, T0 + timedelta(hours=3), cid="1:reuse=")]
    [match] = run(LongInboundSession(), visits)
    assert f"1 distinct outside address(es) reached {INSIDE} port 443" in match.claim
    assert "over 1 span(s) of at least 30 minutes" in match.claim and "none held continuously" in match.claim
    assert "one session that slept or separate visits that reused a client port" in match.claim
    assert "the longest span covers 180 minutes" in match.claim and " held 1 TCP session(s)" not in match.claim
    assert "198.51.100.9 (1 span(s) with gaps, longest 180 minutes)" in match.claim
    assert match.aggregate_summary["continuous_session_count"] == 0
    # beside a session really held, the held session is counted, named and cited first
    held = _held(OUTSIDE, 40001, 443)
    [match] = run(LongInboundSession(), visits + held)
    assert f"1 distinct outside address(es) held 1 TCP session(s) of at least 30 minutes open to {INSIDE} port 443" \
        in match.claim and "the longest lasted 48 minutes" in match.claim
    assert "1 further span(s) of at least 30 minutes, from 1 outside address(es), were not held continuously" \
        in match.claim and "In all 2 distinct outside addresses are members of this item." in match.claim
    assert match.claim.index(f"{OUTSIDE} (1 session(s), longest 48 minutes)") \
        < match.claim.index("198.51.100.9 (1 span(s) with gaps, longest 180 minutes)")
    assert "Every one of the 2 session(s) is cited" in match.claim
    assert sorted(match.fleet_hosts) == [("198.51.100.9", ""), (OUTSIDE, "")]


def test_spans_with_gaps_never_take_the_citation_budget_from_held_sessions():
    reuse = [v for k in range(30) for v in (
        _visit(f"198.51.101.{k + 1}", 44000, 443, T0, cid=f"1:reuse{k}="),
        _visit(f"198.51.101.{k + 1}", 44000, 443, T0 + timedelta(hours=4), cid=f"1:reuse{k}="))]
    held = [e for k in range(3) for e in _held(f"203.0.113.{k + 1}", 40001, 443, minutes=40 + k)]
    [match] = run(LongInboundSession(), reuse + held)
    assert "3 distinct outside address(es) held 3 TCP session(s)" in match.claim
    assert "30 further span(s)" in match.claim and "In all 33 distinct outside addresses" in match.claim
    cited = {e.id for e in match.events}
    assert {e.id for e in held if e.id in cited} >= {held[0].id, held[3].id, held[4].id, held[8].id, held[11].id}
    assert match.aggregate_summary["continuous_session_count"] == 3


def test_a_remote_access_protocol_identified_only_later_is_not_lost_between_the_rules():
    # the first record of a session to inside:443 names no protocol; a later record identifies SSH
    rows = [arkime(OUTSIDE, 51000, INSIDE, 443, first=T0 + timedelta(minutes=12 * i), seconds=12 * 60 - 1,
                   flags={"syn": int(i == 0), "ack": 20, "psh": 5}, cid="1:late=",
                   protocols=("tcp", "ssh") if i >= 2 else ("tcp",)) for i in range(4)]
    assert run(LongExternalConnection(), rows) == []                # served: handed to the inbound rules
    found = run(LongInboundSession(), rows) + run(LongInboundRemoteAccess(), rows)
    assert found, "a served long session must be reported by at least one inbound rule"
    assert any("identified as ssh" in m.claim and "the longest lasted 48 minutes" in m.claim for m in found)


@pytest.mark.parametrize("port,protocols", [(80, ("tcp", "http")), (443, ("tcp",)), (443, ("tcp", "ssh")),
                                            (22, ("tcp",)), (2222, ("tcp", "ssh")), (1433, ("tcp",)),
                                            (51000, ("tcp",))])
def test_every_served_long_session_is_reported_by_an_inbound_rule(port, protocols):
    rows = chunks(lambda **kw: arkime(OUTSIDE, 52000, INSIDE, port, flags={"syn": 1}, protocols=protocols, **kw))
    long_rule = LongExternalConnection()
    assert run(long_rule, rows) == [] and long_rule.limit_reasons() == []
    assert len(run(LongInboundSession(), rows)) + len(run(LongInboundRemoteAccess(), rows)) == 1


def test_an_internal_clients_long_session_out_to_a_web_server_is_still_the_outbound_rules():
    rows = chunks(lambda **kw: arkime(INSIDE, 51000, OUTSIDE, 443, flags={"syn": 1}, **kw))
    [match] = run(LongExternalConnection(), rows)
    assert f"{INSIDE}:51000 opened to {OUTSIDE}:443 (a record shows its SYN)" in match.claim
    assert run(LongInboundSession(), rows) == [] and run(LongInboundRemoteAccess(), rows) == []


@pytest.mark.parametrize("port,service", [(1433, None), (3306, "mysql"), (5432, None), (445, "smb"), (389, None),
                                          (1194, None), (9443, None)])
def test_long_inbound_session_to_any_other_service_is_reported(port, service):
    # the S5 shape and its kin: an outside address held an exposed database, SMB, LDAP, VPN or webshell port for 2 hours
    record = chunks(lambda **kw: arkime(OUTSIDE, 51000, INSIDE, port, flags={"syn": 1}, cid=f"1:{port}=",
                                        protocols=("tcp", service) if service else ("tcp",), **kw), n=10)
    [match] = run(LongInboundSession(), record)
    assert f"1 distinct outside address(es) held 1 TCP session(s) of at least 30 minutes open to {INSIDE} port {port}" \
        in match.claim
    assert "the longest lasted 120 minutes" in match.claim and match.group_key == f"service|{INSIDE}|{port}"
    assert ("ip", OUTSIDE, "src") in match.entities
    assert match.severity == "medium" and match.proposed_lane == "lead"
    assert match.fleet_member_kind == "external_address"
    assert run(LongExternalConnection(), record) == []
    assert run(LongInboundRemoteAccess(), record) == []


def test_s5_mssql_two_hours_with_the_syn_recorded_is_surfaced():
    record = chunks(lambda **kw: arkime(OUTSIDE, 51000, INSIDE, 1433, flags={"syn": 1}, **kw), n=10)
    [match] = run(LongInboundSession(), record)
    assert "port 1433 (no protocol identified on the cited sessions)" in match.claim


def test_remote_access_is_high_under_configured_networks_and_groups_sessions():
    previous = netdef.current()
    netdef.install(netdef.SiteNetworks("configured", netdef.parse_networks(["10.0.0.0/8"], "test")))
    try:
        sessions = []
        for k in range(3):
            start = T0 + timedelta(hours=3 * k)
            sessions += [arkime(OUTSIDE, 51000 + k, INSIDE, 22, first=start + timedelta(minutes=12 * i),
                                seconds=12 * 60 - 1, flags={"syn": int(i == 0), "ack": 20, "psh": 5},
                                cid=f"1:ssh{k}=") for i in range(4)]
        [match] = run(LongInboundRemoteAccess(), sessions)
        assert f"{OUTSIDE} held 3 TCP session(s) of at least 30 minutes open to {INSIDE} port 22 (SSH)" in match.claim
        assert f"Records show {OUTSIDE} opened 3 of them (its SYN)." in match.claim
        assert f"{OUTSIDE} is outside the site's configured internal networks" in match.claim
        assert match.severity == "high" and match.proposed_lane == "lead" and match.notes == []
        assert match.group_key == f"{OUTSIDE}|{INSIDE}|22"
    finally:
        netdef.install(previous)


def test_a_declared_management_source_keeps_the_lead_lane_with_a_note():
    from dataclasses import replace
    rule = LongInboundRemoteAccess()
    rule.site_facts = replace(absent_site_facts(), management_hosts=(OUTSIDE,))
    record = chunks(lambda **kw: arkime(OUTSIDE, 51000, INSIDE, 22, flags={"syn": 1}, **kw))
    [match] = run(rule, record)
    assert match.proposed_lane == "lead"
    assert any("declared management source" in note for note in match.notes)


def test_ssh_identified_on_a_web_port_is_reported_as_remote_access():
    record = chunks(lambda **kw: arkime(OUTSIDE, 51000, INSIDE, 443, flags={"syn": 1}, protocols=("tcp", "ssh"),
                                        **kw))
    [match] = run(LongInboundRemoteAccess(), record)
    assert "port 443 (SSH)" in match.claim
    assert run(LongInboundSession(), record) == []           # never in the web server's service group


@pytest.mark.parametrize("make", ["arkime", "suricata", "zeek"])
def test_midstream_exchanged_client_shaped_connection_is_reported_with_the_opener_unknown(make):
    # recorded with the outside address first (the sensor picked the connection up on a server's packet)
    record = {"arkime": lambda: chunks(lambda **kw: arkime(OUTSIDE, 443, INSIDE, 51000, src_pkts=50, dst_pkts=40,
                                                            flags={"ack": 60, "psh": 20}, **kw)),
              "suricata": lambda: [suricata(OUTSIDE, 443, INSIDE, 51000, seconds=2400, pkts=(50, 40),
                                            sizes=(40000, 9000), flags=("18", "18"))],
              "zeek": lambda: [zeek(OUTSIDE, 443, INSIDE, 51000, seconds=2400, history="Dd")]}[make]()
    [match] = run(LongExternalConnection(), record)
    assert "Which side opened it is not known" in match.claim
    assert (f"{INSIDE} used port 51000 (at or above 32768, where common systems pick client ports) while {OUTSIDE} "
            f"used port 443: the port shape of {INSIDE} as the client.") in match.claim
    assert "opened to" not in match.claim


def test_exchanged_connection_with_the_inside_on_a_server_port_makes_the_cell_partial():
    record = chunks(lambda **kw: arkime(INSIDE, 8443, OUTSIDE, 51000, src_pkts=50, dst_pkts=40,
                                        flags={"ack": 60, "psh": 20}, **kw))
    rule = LongExternalConnection()
    assert run(rule, record) == []
    [reason] = rule.limit_reasons()
    assert reason.startswith("not reported: connections with no recorded opening on which both sides exchanged")
    assert "the port shape of an internal server" in reason
    assert f"{INSIDE}:8443 and {OUTSIDE}:51000, 48 minutes" in reason and reason.endswith("(1 connection(s))")


def _outside_half(make, port=443, *, beacon=None):
    """A channel whose sensor saw only the outside address's half: the inside sent no packets on the records."""
    ssh = port == 22
    if make == "arkime-swapped":
        # Arkime swapped on the server's SYN-ACK: the inside is the source and sent nothing
        return lambda **kw: arkime(INSIDE, 51000, OUTSIDE, port, src_pkts=0, dst_pkts=40, s2c=9000,
                                   flags={"syn_ack": 1, "ack": 30, "psh": 10},
                                   protocols=("tcp", "ssh") if ssh else ("tcp",), **kw)
    if make == "suricata":
        # recorded with the outside first, no tcp block
        return lambda **kw: suricata(OUTSIDE, port, INSIDE, 51000, pkts=(40, 0), sizes=(9000, 0), flags=None,
                                     app_proto="ssh" if ssh else None, **kw)
    if make == "suricata-swapped":
        return lambda **kw: suricata(INSIDE, 51000, OUTSIDE, port, pkts=(0, 40), sizes=(0, 9000), flags=None,
                                     app_proto="ssh" if ssh else None, **kw)
    return lambda **kw: zeek(INSIDE, 51000, OUTSIDE, port, history="d", pkts=(0, 40), payload=(0, 9000),
                             service="ssh" if ssh else "ssl", **kw)


ONE_WAY = ["arkime-swapped", "suricata", "suricata-swapped", "zeek"]


@pytest.mark.parametrize("make", ONE_WAY)
def test_one_way_capture_of_a_channel_is_reported_with_only_the_external_half_recorded(make):
    record = chunks(_outside_half(make), minutes=12) if make == "arkime-swapped" else [
        _outside_half(make)(seconds=2880)]
    rule = LongExternalConnection()
    [match] = run(rule, record)
    assert "Only the external half was recorded" in match.claim and "Which side opened it is not known" in match.claim
    assert rule.coverage_notes() == [] and rule.limit_reasons() == []


def test_arkime_48_minute_channel_with_the_inside_silent_is_reported():
    # the reviewer's shape: 10.0.0.5:51000 -> 203.0.113.10:443, inside 0 packets, outside 40 per record
    record = chunks(_outside_half("arkime-swapped"))
    [match] = run(LongExternalConnection(), record)
    assert f"{INSIDE}:51000 and {OUTSIDE}:443 spanning 48 minutes" in match.claim


@pytest.mark.parametrize("make", ["arkime", "suricata", "zeek"])
def test_one_way_capture_of_the_inside_half_is_reported(make):
    record = {"arkime": lambda: chunks(lambda **kw: arkime(INSIDE, 51000, OUTSIDE, 443, src_pkts=40, dst_pkts=0,
                                                            c2s=9000, flags={"ack": 40, "psh": 10}, **kw)),
              "suricata": lambda: [suricata(INSIDE, 51000, OUTSIDE, 443, seconds=2400, pkts=(40, 0),
                                            sizes=(9000, 0), flags=("18", None))],
              "zeek": lambda: [zeek(INSIDE, 51000, OUTSIDE, 443, seconds=2400, history="D", pkts=(40, 0),
                                    payload=(9000, 0))]}[make]()
    rule = LongExternalConnection()
    [match] = run(rule, record)
    assert "Only the internal half was recorded" in match.claim
    assert rule.limit_reasons() == [] and rule.coverage_notes() == []


def test_true_backscatter_with_the_outside_bare_stays_a_note_beside_one_way_capture():
    bare = chunks(lambda **kw: arkime(INSIDE, 51001, OUTSIDE, 443, **kw, **BACKSCATTER_ARKIME["silent"]))
    half = chunks(_outside_half("arkime-swapped"))
    rule = LongExternalConnection()
    [match] = run(rule, bare + half)
    assert f"{INSIDE}:51000" in match.claim
    [note] = rule.coverage_notes()
    assert "unsolicited response packets" in note and f"{INSIDE}:51001" in note


@pytest.mark.parametrize("ports", [(51000, 50050), (1024, 2048)], ids=["both-high", "both-low"])
def test_exchanged_connection_whose_ports_mark_neither_side_is_reported(ports):
    # a channel opened before the window on an outside port at or above 32768, and one between two low ports
    inside_port, outside_port = ports
    record = chunks(lambda **kw: arkime(INSIDE, inside_port, OUTSIDE, outside_port, src_pkts=50, dst_pkts=40,
                                        flags={"ack": 60, "psh": 20}, **kw))
    rule = LongExternalConnection()
    [match] = run(rule, record)
    assert "mark neither side as the client" in match.claim
    assert rule.limit_reasons() == []


def test_sensors_that_disagree_about_the_opener_stay_unknown_and_reported():
    # Arkime counted a SYN from the internal side; Suricata's record of the same connection, oriented the other way,
    # carries a SYN in its to-server flags
    ark = chunks(lambda **kw: arkime(INSIDE, 51000, OUTSIDE, 443, flags={"syn": 1, "ack": 30, "psh": 10}, **kw))
    sur = suricata(OUTSIDE, 443, INSIDE, 51000, seconds=2400, flags=("1b", "1b"))
    [match] = run(LongExternalConnection(), ark, [sur])
    assert "its records disagree about which side opened it" in match.claim
    assert run(LongInboundSession(), ark, [sur]) == []


def test_records_without_counters_stay_reported_as_before():
    record = [suricata(OUTSIDE, 443, INSIDE, 51000, seconds=2400, pkts=(5, 5), sizes=(330, 330), flags=None)]
    rule = LongExternalConnection()
    [match] = run(rule, record)
    assert "Which side opened it is not known" in match.claim and "port shape" not in match.claim
    assert rule.limit_reasons() == [] and rule.coverage_notes() == []


@pytest.mark.parametrize("seconds,reported", [(1800, True), (1799, False)])
def test_the_thirty_minute_boundary_holds_for_an_exchanged_connection(seconds, reported):
    record = [suricata(OUTSIDE, 443, INSIDE, 51000, seconds=seconds, pkts=(50, 40), sizes=(40000, 9000),
                       flags=("18", "18"))]
    assert len(run(LongExternalConnection(), record)) == int(reported)


def test_exchanged_inbound_session_on_server_ports_is_reported_by_the_inbound_rule_from_its_port_shape():
    record = [suricata(INSIDE, 3389, OUTSIDE, 51000, seconds=2400, pkts=(50, 40), sizes=(40000, 9000),
                       flags=("18", "18"), app_proto="rdp")]
    [match] = run(LongInboundRemoteAccess(), record)
    assert (f"It has no recorded opening, but both sides sent traffic beyond resets and handshake answers with "
            f"{OUTSIDE} on a port of 32768 or above (seen: 51000) facing port 3389") in match.claim
    assert "port 3389 (RDP)" in match.claim


def test_inbound_rule_reads_an_identified_protocol_on_a_nonstandard_port():
    record = chunks(lambda **kw: arkime(OUTSIDE, 51000, INSIDE, 2222, flags={"syn": 1}, protocols=("tcp", "ssh"),
                                        **kw))
    [match] = run(LongInboundRemoteAccess(), record)
    assert "port 2222 (SSH)" in match.claim


def test_inbound_backscatter_to_a_remote_access_port_is_not_a_session():
    # SYN-ACKs from an outside SSH server to an internal address that never sent a SYN
    record = chunks(lambda **kw: arkime(INSIDE, 51000, OUTSIDE, 22, **kw, **BACKSCATTER_ARKIME["silent"]))
    assert run(LongInboundRemoteAccess(), record) == []


# ---- net.beaconing ---------------------------------------------------------------------------------------------------

def _every_minute(make, n=10):
    return [make(i, T0 + timedelta(seconds=60 * i)) for i in range(n)]


@pytest.mark.parametrize("make", [
    lambda i, t: arkime(INSIDE, 40000 + i, OUTSIDE, 80, first=t, seconds=5, **BACKSCATTER_ARKIME["silent"]),
    lambda i, t: arkime(INSIDE, 40000 + i, OUTSIDE, 80, first=t, seconds=5, **BACKSCATTER_ARKIME["reset"]),
    lambda i, t: suricata(INSIDE, 40000 + i, OUTSIDE, 80, first=t, seconds=5, **BACKSCATTER_SURICATA["swapped"]),
    lambda i, t: zeek(INSIDE, 40000 + i, OUTSIDE, 80, first=t, seconds=5, history="^hR", pkts=(1, 2),
                      payload=(0, 0), service=None),
], ids=["arkime-silent", "arkime-reset", "suricata", "zeek"])
def test_periodic_backscatter_is_not_beaconing(make):
    rule = Beaconing()
    assert run(rule, _every_minute(make)) == []
    [note] = rule.coverage_notes()
    assert "unsolicited response packets" in note and "(10 connection(s))" in note


@pytest.mark.parametrize("make", [
    lambda i, t: arkime(INSIDE, 40000 + i, OUTSIDE, 443, first=t, seconds=5, flags={"syn": 1, "psh": 2}),
    lambda i, t: suricata(INSIDE, 40000 + i, OUTSIDE, 443, first=t, seconds=5, flags=("1b", "1b")),
    lambda i, t: zeek(INSIDE, 40000 + i, OUTSIDE, 443, first=t, seconds=5),
], ids=["arkime", "suricata", "zeek"])
def test_internal_opened_beacon_is_still_reported(make):
    rule = Beaconing()
    [match] = run(rule, _every_minute(make))
    assert f"10 separate tcp connections from {INSIDE} to {OUTSIDE} port 443" in match.claim
    assert "do not show" not in match.claim and rule.coverage_notes() == []


def test_exchanged_beacon_recorded_server_first_is_read_from_the_port_shape():
    # each connection picked up mid-stream on the server's packet: before, the recorded sides read outside-in
    rows = _every_minute(lambda i, t: suricata(OUTSIDE, 443, INSIDE, 40000 + i, first=t, seconds=5, pkts=(6, 5),
                                               sizes=(3000, 900), flags=("18", "18")))
    [match] = run(Beaconing(), rows)
    assert f"10 separate tcp connections from {INSIDE} to {OUTSIDE} port 443" in match.claim
    assert f"The records do not show that {INSIDE} opened every connection" in match.claim


def test_inbound_polling_of_an_internal_server_is_served_not_beaconing():
    rows = _every_minute(lambda i, t: arkime(OUTSIDE, 40000 + i, INSIDE, 443, first=t, seconds=5,
                                             flags={"syn": 1, "psh": 2}))
    rule = Beaconing()
    assert run(rule, rows) == []
    assert any(note.startswith("not reported (informational): connections a recorded TCP opening shows")
               for note in rule.coverage_notes())


@pytest.mark.parametrize("make", ONE_WAY)
def test_one_way_captured_beacon_is_reported(make):
    rows = [_outside_half(make)(first=T0 + timedelta(seconds=60 * i), seconds=5) for i in range(10)]
    if make.startswith("arkime"):
        rows = [arkime(INSIDE, 40000 + i, OUTSIDE, 443, first=T0 + timedelta(seconds=60 * i), seconds=5, src_pkts=0,
                       dst_pkts=40, s2c=9000, flags={"syn_ack": 1, "ack": 30, "psh": 10},
                       cid=f"1:beacon-{i}") for i in range(10)]
    elif make == "suricata":
        rows = [suricata(OUTSIDE, 443, INSIDE, 40000 + i, first=T0 + timedelta(seconds=60 * i), seconds=5,
                         pkts=(40, 0), sizes=(9000, 0), flags=None) for i in range(10)]
    elif make == "suricata-swapped":
        rows = [suricata(INSIDE, 40000 + i, OUTSIDE, 443, first=T0 + timedelta(seconds=60 * i), seconds=5,
                         pkts=(0, 40), sizes=(0, 9000), flags=None) for i in range(10)]
    else:
        rows = [zeek(INSIDE, 40000 + i, OUTSIDE, 443, first=T0 + timedelta(seconds=60 * i), seconds=5, history="d",
                     pkts=(0, 40), payload=(0, 9000)) for i in range(10)]
    rule = Beaconing()
    [match] = run(rule, rows)
    assert f"10 separate tcp connections from {INSIDE} to {OUTSIDE} port 443" in match.claim
    assert "For 10 of the connections the records show only one side's half" in match.claim
    assert rule.coverage_notes() == [] and rule.limit_reasons() == []


# ---- net.outbound_ssh_external ----------------------------------------------------------------------------------------

@pytest.mark.parametrize("record", [
    lambda: arkime(INSIDE, 51000, OUTSIDE, 22, protocols=("tcp",), **BACKSCATTER_ARKIME["silent"]),
    lambda: arkime(INSIDE, 51000, OUTSIDE, 22, protocols=("tcp",), **BACKSCATTER_ARKIME["reset"]),
    lambda: suricata(INSIDE, 51000, OUTSIDE, 22, **BACKSCATTER_SURICATA["swapped"]),
    lambda: suricata(INSIDE, 51000, OUTSIDE, 22, **BACKSCATTER_SURICATA["silent"]),
    lambda: zeek(INSIDE, 51000, OUTSIDE, 22, history="^hR", pkts=(1, 2), payload=(0, 0), service=None),
], ids=["arkime-silent", "arkime-reset", "suricata-swapped", "suricata-silent", "zeek"])
def test_ssh_backscatter_is_not_outbound_ssh(record, tmp_path):
    found, rule = ssh([record()], tmp_path=tmp_path)
    assert found == []
    [note] = rule.coverage_notes()
    assert note.startswith("not reported (informational): unsolicited response packets") and "(1 SSH record(s))" in note


@pytest.mark.parametrize("record", [
    lambda: arkime(INSIDE, 51000, OUTSIDE, 22, flags={"syn": 1, "psh": 4}, protocols=("tcp", "ssh")),
    lambda: suricata(INSIDE, 51000, OUTSIDE, 22, flags=("1b", "1b"), app_proto="ssh"),
    lambda: zeek(INSIDE, 51000, OUTSIDE, 22, service="ssh"),
], ids=["arkime", "suricata", "zeek"])
def test_internal_opened_ssh_is_reported_from_the_opening(record, tmp_path):
    found, rule = ssh([record()], tmp_path=tmp_path)
    [match] = found
    assert json.loads(match.group_key) == [INSIDE, OUTSIDE]
    assert "a recorded TCP opening shows the internal source opened the connection" in match.claim
    assert rule.coverage_notes() == [] and rule.limit_reasons() == []


def test_opening_evidence_overrides_the_port_swap(tmp_path):
    # an SSH-identified record from an internal client on a low port to an outside service on a high port: the old
    # port test read the outside address as the client; the recorded SYN shows the internal side opened it
    record = arkime(INSIDE, 2222, OUTSIDE, 40022, flags={"syn": 1, "psh": 4}, protocols=("tcp", "ssh"))
    [match] = ssh([record], tmp_path=tmp_path)[0]
    assert json.loads(match.group_key) == [INSIDE, OUTSIDE]


@pytest.mark.parametrize("record", [
    lambda: arkime(OUTSIDE, 51000, INSIDE, 22, flags={"syn": 1, "psh": 4}, protocols=("tcp", "ssh")),
    lambda: suricata(OUTSIDE, 51000, INSIDE, 22, flags=("1b", "1b"), app_proto="ssh"),
    lambda: zeek(OUTSIDE, 51000, INSIDE, 22, service="ssh"),
], ids=["arkime", "suricata", "zeek"])
def test_inbound_ssh_is_a_served_note_not_outbound_ssh(record, tmp_path):
    found, rule = ssh([record()], tmp_path=tmp_path)
    assert found == []
    assert rule.coverage_notes()[0].startswith("not reported (informational): connections a recorded TCP opening")


@pytest.mark.parametrize("record", [
    lambda: arkime(OUTSIDE, 22, INSIDE, 51000, src_pkts=30, dst_pkts=25, flags={"ack": 40, "psh": 12},
                   protocols=("tcp", "ssh")),
    lambda: suricata(OUTSIDE, 22, INSIDE, 51000, pkts=(30, 25), sizes=(9000, 4000), flags=("18", "18"),
                     app_proto="ssh"),
    lambda: zeek(OUTSIDE, 22, INSIDE, 51000, history="Dd", service="ssh"),
], ids=["arkime", "suricata", "zeek"])
def test_midstream_exchanged_ssh_is_reported_with_the_client_from_the_port_shape(record, tmp_path):
    [match] = ssh([record()], tmp_path=tmp_path)[0]
    assert json.loads(match.group_key) == [INSIDE, OUTSIDE]
    assert ("no opening is recorded, both sides sent traffic beyond resets and handshake answers, and the internal "
            "source used a port of 32768 or above") in match.claim


@pytest.mark.parametrize("record", [
    lambda: arkime(INSIDE, 51000, OUTSIDE, 22, src_pkts=0, dst_pkts=30, flags={"ack": 30, "psh": 9},
                   protocols=("tcp", "ssh")),
    lambda: suricata(INSIDE, 51000, OUTSIDE, 22, pkts=(0, 30), sizes=(0, 9000), flags=(None, "18"), app_proto="ssh"),
    lambda: zeek(INSIDE, 51000, OUTSIDE, 22, history="d", pkts=(0, 30), payload=(0, 9000), service="ssh"),
], ids=["arkime", "suricata", "zeek"])
def test_midstream_ssh_with_only_the_outside_half_is_reported(record, tmp_path):
    [match] = ssh([record()], tmp_path=tmp_path)[0]
    assert json.loads(match.group_key) == [INSIDE, OUTSIDE]


@pytest.mark.parametrize("make", ONE_WAY)
def test_one_way_captured_ssh_is_reported(make, tmp_path):
    found, rule = ssh([_outside_half(make, 22)()], tmp_path=tmp_path)
    [match] = found
    assert json.loads(match.group_key) == [INSIDE, OUTSIDE]
    assert "the record shows only one side's half of the connection" in match.claim
    assert rule.limit_reasons() == []


def test_ssh_records_without_counters_keep_the_port_reading(tmp_path):
    # host socket and counter-less records: the side on 22 is the server, as before
    record = typed("net_flow", source__ip=OUTSIDE, source__port=22, destination__ip=INSIDE, destination__port=51515,
                   network__transport="tcp", network__app_proto="ssh")
    [match] = ssh([record], tmp_path=tmp_path)[0]
    assert json.loads(match.group_key) == [INSIDE, OUTSIDE]
    assert "Of the" not in match.claim


def test_unanswered_ssh_without_an_opening_is_reported_with_the_inside_half(tmp_path):
    record = arkime(INSIDE, 51000, OUTSIDE, 22, src_pkts=12, dst_pkts=0, flags={"ack": 12, "psh": 6},
                    protocols=("tcp", "ssh"))
    [match], rule = ssh([record], tmp_path=tmp_path)
    assert "only one side's half" in match.claim and rule.limit_reasons() == []


def test_exchanged_ssh_with_the_inside_on_the_server_port_is_inbound_and_partial(tmp_path):
    record = arkime(INSIDE, 22, OUTSIDE, 51000, src_pkts=30, dst_pkts=25, flags={"ack": 40, "psh": 12},
                    protocols=("tcp", "ssh"))
    found, rule = ssh([record], tmp_path=tmp_path)
    assert found == []
    [reason] = rule.limit_reasons()
    assert "the port shape of an internal server" in reason and reason.endswith("(1 SSH record(s))")


# ---- mission scale ---------------------------------------------------------------------------------------------------

def test_a_large_backscatter_flood_reports_nothing_and_keeps_bounded_state(monkeypatch):
    """Twenty thousand backscatter connections over a day, every one stitched to 30 minutes, beside one real channel:
    the hot set is two connections, the unreported tallies are four counters and ten listed names, and only the
    real channel is reported."""
    monkeypatch.setattr(LongExternalConnection, "HOT", 2)
    events = []
    for k in range(20_000):
        start = T0 + timedelta(seconds=4 * k)
        port = 32768 + k % 30000
        victim = f"198.51.100.{k % 250 + 1}"
        for part in range(3):
            events.append(typed("net_session", source__ip=f"10.9.{k % 200}.{k % 250 + 1}", source__port=port,
                                destination__ip=victim, destination__port=80, network__transport="tcp",
                                flow__start=(start + timedelta(minutes=15 * part)).isoformat(),
                                flow__end=(start + timedelta(minutes=15 * part, seconds=1)).isoformat(),
                                network__community_id=f"1:bs{k}", source__packets=0, destination__packets=2,
                                tcp__flags__syn=0, tcp__flags__syn_ack=2, tcp__flags__rst=0, client__bytes=0,
                                server__bytes=0))
    channel = [typed("net_session", source__ip=INSIDE, source__port=51000, destination__ip=OUTSIDE,
                     destination__port=4444, network__transport="tcp", network__community_id="1:c2",
                     flow__start=(T0 + timedelta(minutes=12 * i)).isoformat(),
                     flow__end=(T0 + timedelta(minutes=12 * i + 11)).isoformat(), source__packets=40,
                     destination__packets=30, tcp__flags__syn=int(i == 0), tcp__flags__syn_ack=int(i == 0),
                     tcp__flags__rst=0, client__bytes=4000, server__bytes=3000) for i in range(4)]
    rule = LongExternalConnection()
    batches = [events[i:i + 5000] for i in range(0, len(events), 5000)] + [channel]
    stage, peak = {}, 0
    for batch in batches:
        rule.consume(batch)
        stage.update({e.id: e for e in rule.drain_staged()})
        peak = max(peak, len(rule.conns.hot))
    rule.bind_loader(lambda ids: [stage[i] for i in ids if i in stage])
    [match] = rule.finalize()
    assert peak <= 2 and rule.conns.on_disk > 0
    assert f"{INSIDE}:51000 opened to {OUTSIDE}:4444" in match.claim
    [note] = rule.coverage_notes()
    assert "(20000 connection(s))" in note and "; and 19990 more" in note
    assert sum(len(heap) for heap in rule._unreported.top.values()) == 10
    assert rule.limit_reasons() == []


def test_the_shared_predicate_is_bounded_per_connection():
    opening = flows.Opening()
    view_event = typed("net_session", source__ip=INSIDE, source__port=51000, destination__ip=OUTSIDE,
                       destination__port=443, network__transport="tcp", source__packets=5, destination__packets=5,
                       tcp__flags__syn=0, tcp__flags__syn_ack=0, tcp__flags__rst=0,
                       flow__start=T0.isoformat(), flow__end=T0.isoformat())
    view = flow_view(view_event, "session")
    for _ in range(1000):
        opening.add(view_event, view)
    assert len(opening.states) == 2 and opening.openers == []
    assert opening.judge((INSIDE, 51000), (OUTSIDE, 443)) == EXCHANGED
    assert bounded.HOT_COUNT > 0


def test_an_unanswered_sender_whose_packets_cannot_be_judged_stays_reported():
    # flag counts absent: the internal side's two packets may be the SYNs of an opening the outside never answered
    record = chunks(lambda **kw: arkime(INSIDE, 51000, OUTSIDE, 4444, src_pkts=2, dst_pkts=0, **kw))
    rule = LongExternalConnection()
    [match] = run(rule, record)
    assert "no record of it carries TCP flag counts" in match.claim
    assert rule.limit_reasons() == [] and rule.coverage_notes() == []


@pytest.mark.parametrize("history,originator,expected", [
    ("^hR", True, {"R"}), ("^hR", False, {"H"}),
    # Zeek saw the outside's SYN-ACK (as its originator, upper case), then flipped the roles
    ("H^R", True, {"R"}), ("H^R", False, {"H"}),
    ("Dd^Aa", True, {"D", "A"}), ("Dd^Aa", False, {"D", "A"}),
])
def test_zeek_history_reads_letters_before_a_flip_with_the_roles_reversed(history, originator, expected):
    assert zeek_history_kinds(history, originator) == expected


def test_zeek_backscatter_with_a_late_flip_is_unsolicited():
    rule = LongExternalConnection()
    row = zeek(INSIDE, 51000, OUTSIDE, 80, seconds=2400, history="H^R", pkts=(1, 2), payload=(0, 0), service=None)
    assert run(rule, [row]) == []
    assert any("unsolicited response packets" in note for note in rule.coverage_notes())


# ---- net.long_inbound_session: exposed services are grouped, members kept --------------------------------------------

def _clients(port, n, *, attacker=None, longest=None, protocols=("tcp",)):
    """`n` outside clients, each holding one 40-minute session to INSIDE:port; `attacker` holds `longest` minutes."""
    rows = []
    for k in range(n):
        client = f"198.51.{100 + k // 250}.{k % 250 + 1}"
        rows.append(arkime(client, 40000 + k % 20000, INSIDE, port, first=T0 + timedelta(seconds=k), seconds=2400,
                           flags={"syn": 1, "ack": 20, "psh": 5}, protocols=protocols, cid=f"1:{port}:{k}="))
    if attacker is not None:
        rows.append(arkime(attacker, 51515, INSIDE, port, first=T0, seconds=longest * 60,
                           flags={"syn": 1, "ack": 20, "psh": 5}, protocols=protocols, cid=f"1:{port}:attacker="))
    return rows


def test_many_clients_of_one_exposed_service_are_one_item_with_every_member():
    rule = LongInboundSession()
    [match] = run(rule, _clients(993, 30, attacker="203.0.113.66", longest=300, protocols=("tcp", "imap")))
    assert match.group_key == f"service|{INSIDE}|993" and match.severity == "medium" and match.proposed_lane == "lead"
    assert f"31 distinct outside address(es) held 31 TCP session(s) of at least 30 minutes open to {INSIDE} port 993" \
        in match.claim
    assert "the longest lasted 300 minutes" in match.claim
    assert "The outside addresses with the longest sessions: 203.0.113.66 (1 session(s), longest 300 minutes)" \
        in match.claim
    assert "; and 11 more (the item's member list holds every one)." in match.claim
    # the attacker's address reaches the item's typed entities, so it can still be correlated
    named = [value for kind, value, role in match.entities if kind == "ip" and role == "src"]
    assert "203.0.113.66" in named and len(set(named)) >= 20
    members = list(match.fleet_hosts)
    assert len(members) == 31 == match.fleet_host_count and match.fleet_hosts_complete
    assert ("203.0.113.66", "") in members
    assert match.aggregate_summary == {"outside_address_count": 31, "session_count": 31,
                                       "continuous_session_count": 31, "cited_session_count": 20,
                                       "longest_session_seconds": 18000.0, "members_complete": 1}
    assert "20 of the 31 session(s), from 20 of the 31 outside address(es), are cited" in match.claim
    assert any(note.startswith("citation is partial: 20 of 31 sessions") for note in match.notes)


def test_a_member_outside_the_named_twenty_stays_in_the_member_list():
    [match] = run(LongInboundSession(), _clients(1883, 25, attacker="203.0.113.77", longest=31))
    assert "203.0.113.77" not in match.claim
    assert ("203.0.113.77", "") in list(match.fleet_hosts)


def test_one_rare_client_is_not_split_out_by_any_volume_threshold():
    rows = _clients(5222, 1) + _clients(5223, 40)
    found = {m.group_key: m for m in run(LongInboundSession(), rows)}
    assert set(found) == {f"service|{INSIDE}|5222", f"service|{INSIDE}|5223"}
    assert found[f"service|{INSIDE}|5223"].fleet_host_count == 40


def test_remote_access_stays_one_item_per_outside_address():
    rows = [arkime(f"203.0.113.{k}", 51000, INSIDE, 22, first=T0, seconds=2400, flags={"syn": 1}, cid=f"1:ssh{k}=")
            for k in (5, 6)]
    found = run(LongInboundRemoteAccess(), rows)
    assert sorted(m.group_key for m in found) == [f"203.0.113.5|{INSIDE}|22", f"203.0.113.6|{INSIDE}|22"]


def test_service_members_scale_on_disk_with_exact_counts(monkeypatch):
    monkeypatch.setattr(LongInboundSession, "HOT", 2)
    monkeypatch.setattr(LongInboundSession, "MEMBER_BATCH", 50)
    rule = LongInboundSession()
    [match] = run(rule, _clients(10443, 3000))
    assert rule.conns.on_disk > 0
    assert match.fleet_host_count == 3000 and len(list(match.fleet_hosts)) == 3000
    assert "3000 distinct outside address(es) held 3000 TCP session(s)" in match.claim
    assert "; and 2980 more" in match.claim


def test_a_spent_member_budget_is_honest(monkeypatch):
    from romulus.detect import bounded as bounded_module
    original = bounded_module.Spill.write

    def refuse(self, sql, rows, **kwargs):
        if sql.startswith("INSERT OR REPLACE INTO inbound_sessions"):
            raise bounded_module.StateExhausted("injected disk refusal")
        return original(self, sql, rows, **kwargs)
    monkeypatch.setattr(bounded_module.Spill, "write", refuse)
    rule = LongInboundSession()
    assert run(rule, _clients(1194, 3)) == []
    assert any("inbound sessions' disk budget is spent" in reason for reason in rule.limit_reasons())


def test_a_declared_management_member_is_counted_in_a_note():
    from dataclasses import replace
    rule = LongInboundSession()
    rule.site_facts = replace(absent_site_facts(), management_hosts=("198.51.100.1",))
    [match] = run(rule, _clients(2598, 3))
    assert match.proposed_lane == "lead"
    assert any(note.startswith("1 of the outside addresses are declared management hosts") for note in match.notes)


def test_the_served_elsewhere_note_names_the_inbound_rule_conditionally():
    rule = LongExternalConnection()
    assert run(rule, _clients(1433, 1)) == []
    [note] = rule.coverage_notes()
    assert ("judged as inbound sessions by net.long_inbound_remote_access or net.long_inbound_session; their own "
            "cells state their coverage") in note


def test_remote_access_and_grouped_services_never_share_an_item():
    rows = _clients(1433, 3) + [arkime("203.0.113.9", 51000, INSIDE, 3389, first=T0, seconds=2400,
                                       flags={"syn": 1}, cid="1:rdp=")]
    remote, grouped = run(LongInboundRemoteAccess(), rows), run(LongInboundSession(), rows)
    assert [m.group_key for m in remote] == [f"203.0.113.9|{INSIDE}|3389"]
    assert [m.group_key for m in grouped] == [f"service|{INSIDE}|1433"]
    assert remote[0].fleet_member_kind == "host" and not remote[0].fleet_host_count


def test_arkime_sessions_without_application_bytes_are_named_on_the_cell(tmp_path):
    # backscatter without client.bytes/server.bytes cannot be told from one-way capture: reported, and said so
    rows = chunks(lambda **kw: arkime(INSIDE, 51000, OUTSIDE, 80, src_pkts=0, dst_pkts=3, flags=SYN_ACKS,
                                      app_bytes=False, **kw))
    rule = LongExternalConnection()
    assert len(run(rule, rows)) == 1
    [note] = rule.coverage_notes()
    assert note.startswith("4 Arkime TCP session record(s) carried no application-byte counts")
    beacon = Beaconing()
    run(beacon, [arkime(INSIDE, 40000 + i, OUTSIDE, 443, first=T0 + timedelta(seconds=60 * i), seconds=5,
                        flags={"syn": 1}, app_bytes=False) for i in range(10)])
    assert any(n.startswith("10 Arkime TCP session record(s)") for n in beacon.coverage_notes())
    _found, ssh_rule = ssh([arkime(INSIDE, 51000, OUTSIDE, 22, flags={"syn": 1}, protocols=("tcp", "ssh"),
                                   app_bytes=False)],
                           tmp_path=tmp_path)
    assert any(n.startswith("1 Arkime TCP session record(s)") for n in ssh_rule.coverage_notes())


# ---- mission scale: inbound web traffic -------------------------------------------------------------------------------

def _web_record(n, src, sport, dst, start, seconds, *, syn, fin, cid=None, packets=(6, 5)):
    fields = {"source.ip": src, "source.port": sport, "destination.ip": dst, "destination.port": 443,
              "network.transport": "tcp", "flow.start": start.isoformat(),
              "flow.end": (start + timedelta(seconds=seconds)).isoformat(),
              "network.community_id": cid or f"1:w{n}", "source.bytes": 900, "destination.bytes": 4000,
              "source.packets": packets[0], "destination.packets": packets[1], "client.bytes": 400,
              "server.bytes": 3500, "tcp.flags.syn": syn, "tcp.flags.syn_ack": syn, "tcp.flags.ack": 6,
              "tcp.flags.psh": 2, "tcp.flags.fin": fin, "tcp.flags.rst": 0}
    return TypedEvent(id=f"w{n:09d}", family="net_session", ts=start, host="arkime",
                      fields={k: fv(v, "fixture") for k, v in fields.items()},
                      raw=[RawRef(target="fixture", native_id=f"w{n}")], normalizer="fixture")


def web_traffic(short, long, batch=5000):
    """Batches of `short` short web connections from 100,000 outside addresses to 50 servers, every 5-tuple distinct,
    then `long` 48-minute sessions (four records each) spread over the servers."""
    rows, n = [], 0
    for k in range(short):
        client, turn = k % 100_000, k // 100_000
        rows.append(_web_record(n, f"198.{18 + client // 62500}.{client // 250 % 250}.{client % 250 + 1}",
                                32768 + turn, f"10.20.0.{k % 50 + 1}", T0 + timedelta(seconds=k * 0.6), 3,
                                syn=1, fin=2))
        n += 1
        if len(rows) >= batch:
            yield rows
            rows = []
    for k in range(long):
        for part in range(4):
            rows.append(_web_record(n, f"203.0.{113 + k // 250}.{k % 250 + 1}", 40000 + k % 20000,
                                    f"10.20.0.{k % 50 + 1}", T0 + timedelta(seconds=k, minutes=12 * part), 12 * 60 - 1,
                                    syn=int(part == 0), fin=2 * int(part == 3), cid=f"1:long{k}", packets=(40, 40)))
            n += 1
        if len(rows) >= batch:
            yield rows
            rows = []
    if rows:
        yield rows


def _run_web_volume(short, long, tmp_path):
    from romulus.detect.bounded import StateBudget
    rule = LongInboundSession()
    rule.spill_dir = tmp_path
    rule.budget = StateBudget(tmp_path, memory_total=64 * 2**20)        # a small share of a hunt's memory
    stage, hot = {}, 0
    for rows in web_traffic(short, long):
        rule.consume(rows)
        for event in rule.drain_staged():
            if str(event.get("network.community_id")).startswith("1:long"):
                stage[event.id] = event                                 # the stage is on disk in a sweep
        rule.drain_bounds()
        hot = max(hot, len(rule.conns.hot))
    rule.bind_loader(lambda ids: [stage[i] for i in ids if i in stage])
    found = list(rule.finalize())
    return rule, found, hot


def _assert_web_volume(rule, found, short, long):
    assert rule.limit_reasons() == []
    assert len(found) == 50 and {m.group_key.split("|")[2] for m in found} == {"443"}
    assert sum(m.fleet_host_count for m in found) == long
    assert sum(m.aggregate_summary["session_count"] for m in found) == long
    assert all(m.aggregate_summary["continuous_session_count"] == m.aggregate_summary["session_count"] for m in found)
    assert rule.conns.on_disk > 0                           # held on disk, not in memory


def test_inbound_web_traffic_is_held_on_disk_and_only_long_sessions_are_reported(tmp_path):
    rule, found, hot = _run_web_volume(20_000, 200, tmp_path)
    _assert_web_volume(rule, found, 20_000, 200)
    assert hot < 20_000


@pytest.mark.slow
def test_a_million_short_web_connections_and_two_thousand_long_sessions(tmp_path):
    rule, found, hot = _run_web_volume(1_000_000, 2_000, tmp_path)
    _assert_web_volume(rule, found, 1_000_000, 2_000)
    assert hot < 200_000                                    # the hot set stays a fraction of the million held


# ---- a client port opened more than once ----------------------------------------------------------------------------

def test_separate_visits_reusing_a_client_port_within_the_hour_are_never_a_held_session():
    # two complete visits 45 minutes apart from one outside address and port: Arkime, then Suricata
    arkime_visits = [_visit("198.51.100.9", 44000, 443, T0, cid="1:r="),
                     _visit("198.51.100.9", 44000, 443, T0 + timedelta(minutes=45), cid="1:r=")]
    suricata_visits = [suricata("198.51.100.9", 44000, INSIDE, 443, first=T0 + timedelta(minutes=45 * k), seconds=3,
                                pkts=(6, 5), sizes=(800, 3400), flags=("1b", "1b")) for k in range(2)]
    for visits in (arkime_visits, suricata_visits):
        for rows in (visits, visits[::-1]):
            [match] = run(LongInboundSession(), rows)
            assert f"1 distinct outside address(es) reached {INSIDE} port 443" in match.claim
            assert "none held continuously" in match.claim and " held 1 TCP session(s)" not in match.claim
            assert "the records show that client port opened more than once" in match.claim
            assert match.aggregate_summary["continuous_session_count"] == 0


def test_a_chain_of_visits_never_outranks_the_session_really_held_beside_it():
    chain = [_visit("198.51.100.20", 45000, 80, T0 + timedelta(minutes=50 * k), cid="1:chain=") for k in range(10)]
    dev = _dev_shape("arkime")
    for rows in (chain + dev, (dev + chain)[::-1]):
        [match] = run(LongInboundSession(), rows)
        assert (f"1 distinct outside address(es) held 1 TCP session(s) of at least 30 minutes open to {INSIDE} port 80"
                in match.claim and "the longest lasted 121 minutes" in match.claim)
        assert match.claim.index(f"{OUTSIDE} (1 session(s), longest 121 minutes)") \
            < match.claim.index("198.51.100.20 (1 span(s) with gaps")
        assert {dev[0].id, dev[-1].id} <= {e.id for e in match.events}


def test_arkime_pieces_of_one_session_are_one_opening_even_when_each_shows_a_syn():
    # each saved piece carries the first piece's rootId: a continuation repeats its session's opening
    rows = chunks(lambda **kw: arkime(OUTSIDE, 51000, INSIDE, 1433, flags={"syn": 1}, cid="1:pieces=", **kw), n=10)
    for order in (rows, rows[::-1]):
        [match] = run(LongInboundSession(), order)
        assert "held 1 TCP session(s)" in match.claim and "the longest lasted 120 minutes" in match.claim


def test_a_held_session_on_a_client_port_that_was_opened_before_is_still_a_cited_member():
    # the stated cost of reading openings per client port: a visit, then a session held on the same port, is worded
    # as separate visits (never as one held session), and stays a member whose records are cited
    rows = [_visit(OUTSIDE, 47000, 443, T0, cid="1:then="),
            *_held(OUTSIDE, 47000, 443, start=T0 + timedelta(minutes=10), minutes=60, cid="1:then=")]
    [match] = run(LongInboundSession(), rows)
    assert "none held continuously" in match.claim and "opened more than once" in match.claim
    assert list(match.fleet_hosts) == [(OUTSIDE, "")] and ("ip", OUTSIDE, "src") in match.entities
    assert {rows[0].id, rows[-1].id} <= {e.id for e in match.events}


def test_remote_access_identified_later_on_a_busy_service_is_named_and_cited_first():
    later = []
    for k in range(3):
        later += [arkime(f"203.0.113.{k + 1}", 52000, INSIDE, 443, first=T0 + timedelta(minutes=12 * i),
                         seconds=12 * 60 - 1, flags={"syn": int(i == 0), "ack": 20, "psh": 5}, cid=f"1:ssh{k}=",
                         protocols=("tcp", "ssh") if i >= 2 else ("tcp",)) for i in range(4)]
    rows = _clients(443, 200, attacker="198.51.120.1", longest=300) + later
    [match] = run(LongInboundSession(), rows)
    assert ("A sensor identified ssh on a later record of 3 of these session(s), from 3 outside address(es) "
            "(203.0.113.1, 203.0.113.2, 203.0.113.3); those sessions are cited first.") in match.claim
    cited = {e.id for e in match.events}
    assert {later[0].id, later[4].id, later[8].id} <= cited
    assert {("ip", f"203.0.113.{k + 1}", "src") for k in range(3)} <= set(match.entities)


@pytest.mark.parametrize("other", ["suricata", "zeek"])
def test_one_session_seen_by_sensors_whose_clocks_differ_by_under_a_minute_is_still_held(other):
    pieces = chunks(lambda **kw: arkime(OUTSIDE, 51000, INSIDE, 1433, flags={"syn": 1, "ack": 20}, cid="1:skew=",
                                        **kw), n=10)
    twin = (suricata(OUTSIDE, 51000, INSIDE, 1433, first=T0 + timedelta(seconds=45), seconds=7200, flags=("1b", "1b"))
            if other == "suricata" else
            zeek(OUTSIDE, 51000, INSIDE, 1433, first=T0 - timedelta(seconds=40), seconds=7200, service=None))
    for rows in (pieces + [twin], [twin] + pieces[::-1]):
        [match] = run(LongInboundSession(), rows)
        assert "held 1 TCP session(s)" in match.claim, match.claim[:300]
