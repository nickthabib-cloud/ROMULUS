"""Flow and session claims state only what the records show.

- Which side opened a connection comes from a record that shows the opening (an Arkime session that counted a SYN, or
  Suricata directional flags with a SYN toward the server), never from the side a sensor happened to record first: a
  session picked up mid-stream is recorded with whichever side spoke first as its source.
- The records cited for a claim include the records that bound every interval it states, however many records the
  claim rests on, and the claim says how many it rests on and how many are cited.

Fixtures go through the real normalizer (Suricata EVE flow records, Arkime SPI sessions)."""
import json
import random
from collections import Counter
from datetime import timedelta

import pytest

from romulus.detect import flows
from romulus.detect.flows import (
    EXAMPLE_LIMIT,
    HorizontalSweep,
    LongUnidentifiedSession,
    OutboundVolumeAsymmetry,
    ProtocolPortMismatch,
    flow_view,
    record_kind,
)
from romulus.detect.sessions import ArkimeSshReverseShellTag, Beaconing, LongExternalConnection
from tests.test_arkime_sessions import session
from tests.test_flow_rules import MIB, T0, ark, eve, events, run
from tests.test_session_fingerprints import ssh_session

INSIDE, OUTSIDE = "10.0.0.5", "203.0.113.50"


def flagged(hit, syn=0, syn_ack=0):
    """An Arkime session hit with its TCP flag counts."""
    hit["_source"]["tcpflags"] = {"syn": syn, "syn-ack": syn_ack, "ack": 9, "psh": 3, "fin": 0, "rst": 0, "urg": 0}
    return hit


def suricata_tcp(hit, **fields):
    """Add the EVE TCP summary object to a Suricata fixture."""
    record = json.loads(hit["_source"]["event"]["original"])
    record["tcp"] = fields
    hit["_source"]["event"]["original"] = json.dumps(record)
    return hit


def view(hit):
    [event] = events(hit)
    return flow_view(event, record_kind(event))


# ---- which side opened a connection ----------------------------------------------------------------------------

def test_an_arkime_session_that_counted_a_syn_shows_its_source_opened_it():
    assert view(flagged(ark("a"), syn=1, syn_ack=1)).opened
    assert view(flagged(ark("b"), syn=2)).opened                      # a retransmitted SYN


@pytest.mark.parametrize("hit", [
    flagged(ark("mid"), syn=0, syn_ack=0),                            # picked up mid-stream
    flagged(ark("sa"), syn=0, syn_ack=1),                             # a SYN-ACK alone can land on an older session
    ark("none"),                                                      # no flag counts recorded
    flagged(ark("udp", proto=17), syn=1),                             # flags on a non-TCP record are not read
])
def test_an_arkime_session_without_a_counted_syn_does_not_show_the_opener(hit):
    assert not view(hit).opened


@pytest.mark.parametrize("state", ["established", "closed", "new", "bypassed"])
def test_a_suricata_tcp_flow_state_without_a_syn_leaves_the_opener_unknown(state):
    assert not view(eve("s", state=state)).opened
    assert not view(suricata_tcp(eve("u", proto="UDP", dport=53, state=state),
                                 syn=True, tcp_flags_ts="02", tcp_flags_tc="12")).opened


@pytest.mark.parametrize("tcp", [
    {"syn": True, "tcp_flags_ts": "02", "tcp_flags_tc": "12"},
    {"syn": True, "tcp_flags_ts": "12", "tcp_flags_tc": "12"},
    # The aggregate SYN is sufficient only when the recorded to-client flags prove it did not come that way.
    {"syn": True, "tcp_flags_tc": "10"},
])
def test_a_suricata_syn_toward_the_server_shows_the_source_opened_the_flow(tcp):
    opened = view(suricata_tcp(eve("s", src=INSIDE, sport=50123, dst=OUTSIDE, dport=443,
                                         state="established"), **tcp))
    assert opened.opened and (opened.src, opened.dst) == (INSIDE, OUTSIDE)


@pytest.mark.parametrize("tcp", [
    {"syn": True, "tcp_flags_tc": "12"},
    {"syn": False, "tcp_flags_ts": "10", "tcp_flags_tc": "12"},
    {"tcp_flags_ts": "10", "tcp_flags_tc": "10"},
])
def test_a_suricata_syn_not_proved_toward_the_server_leaves_the_opener_unknown(tcp):
    assert not view(suricata_tcp(eve("s", state="closed"), **tcp)).opened


# ---- outbound volume asymmetry: the lab case and the populations ------------------------------------------------

def _ssh_download(*, root=True, records=17):
    """An outside client's SSH download from an internal server, as Arkime recorded it in the lab: the session that
    saw the SYN (outside client to the server's port 22), then a second session Arkime picked up mid-stream on the
    same traffic, recorded from the server's side (port 22 to the client's port 37840) with no SYN."""
    hits = []
    if root:
        hits.append(flagged(ark("root", src=OUTSIDE, sport=37840, dst=INSIDE, dport=22, start=T0, seconds=2,
                                c2s=108_236, s2c=12_494_784, pkts_c=1551, pkts_s=8449), syn=1, syn_ack=1))
    hits += [flagged(ark(f"mid{i}", src=INSIDE, sport=22, dst=OUTSIDE, dport=37840,
                         start=T0 + timedelta(seconds=48), seconds=2 + i, c2s=12_500_000, s2c=100_000,
                         pkts_c=8500, pkts_s=1500)) for i in range(records)]
    return hits


def test_an_internal_servers_answers_picked_up_mid_stream_are_not_an_upload_and_coverage_names_them():
    # the old reading took Arkime's mid-stream orientation as the opener and reported "a connection it initiated"
    rule = OutboundVolumeAsymmetry()
    assert run(rule, events(*_ssh_download())) == []
    # the root's SYN shows the outside client opened it: an internal server answering, named as information only
    assert rule.limit_reasons() == []
    sent = 12_494_784 + 17 * 12_500_000
    assert rule.coverage_notes() == [
        ("not read as uploads (informational): connections an Arkime session shows an external address opened (it "
        "counted the SYN), so the internal address answered as a server: the internal addresses sent "
        f"{sent:,} bytes on them, the most from one pair {sent:,} bytes from {INSIDE} to {OUTSIDE} (1 connection(s))")]


def test_mid_stream_records_with_no_opening_and_a_servers_port_shape_are_not_an_upload_and_are_named():
    rule = OutboundVolumeAsymmetry()
    assert run(rule, events(*_ssh_download(root=False))) == []
    [reason] = rule.limit_reasons()
    assert reason.startswith("not read as uploads: connections whose opener is not recorded, with the internal "
                             "address on a port below 32768 and the external address on one at or above it (the port "
                             "shape of an internal server answering an outside client): the internal addresses sent "
                             f"{17 * 12_500_000:,} bytes on them")
    assert reason.endswith("(1 connection(s))")


def test_an_upload_the_internal_address_opened_says_so_and_cites_the_opening():
    hits = [flagged(ark("open", src=INSIDE, sport=50123, dst=OUTSIDE, dport=443, start=T0, seconds=30,
                        c2s=30 * MIB, s2c=MIB // 2), syn=1, syn_ack=1)]
    # the rest of the same connection, picked up mid-stream by a later session from the outside side
    hits += [flagged(ark(f"rest{i}", src=OUTSIDE, sport=443, dst=INSIDE, dport=50123,
                         start=T0 + timedelta(minutes=1 + i), seconds=50, c2s=MIB // 4, s2c=10 * MIB))
             for i in range(3)]
    [m] = run(OutboundVolumeAsymmetry(), events(*hits))
    # each address's bytes are its own side's counter, whichever side each record names as its source
    assert f"{INSIDE} sent {60 * MIB:,} bytes (60.0 MiB) to {OUTSIDE} and received {MIB // 2 + 3 * MIB // 4:,}" in m.claim
    assert (f"A recorded TCP opening shows {INSIDE} opened the connection, to server port tcp/443 (1 connection) on "
            f"{OUTSIDE} (Arkime counted the SYN).") in m.claim
    assert "not recorded" not in m.claim and "All 4 records are cited." in m.claim
    assert {p.field: p.value for p in m.predicate}["tcp.flags.syn"] == 1


def test_an_opening_shown_by_a_suricata_directional_syn_says_exactly_what_it_shows():
    flow = suricata_tcp(eve("s", sport=50001, dst=OUTSIDE, dport=443, state="established",
                              c2s=60 * MIB, s2c=MIB, pkts_s=10),
                          syn=True, tcp_flags_ts="02", tcp_flags_tc="12")
    [m] = run(OutboundVolumeAsymmetry(), events(flow))
    assert (f"shows {INSIDE} opened the connection, to server port tcp/443 (1 connection) on {OUTSIDE} (the only "
            "record of the opening is a Suricata directional TCP flag summary that records a SYN toward the "
            "server).") in m.claim
    assert "directional TCP flags record a SYN toward the server" in OutboundVolumeAsymmetry.positive_only_reason


def test_an_upload_with_no_recorded_opening_is_read_from_its_ports_and_says_the_opener_is_unknown():
    hits = [flagged(ark(f"m{i}", src=OUTSIDE, sport=443, dst=INSIDE, dport=50123, start=T0 + timedelta(minutes=i),
                        seconds=50, c2s=MIB // 4, s2c=20 * MIB)) for i in range(3)]
    [m] = run(OutboundVolumeAsymmetry(), events(*hits))
    assert f"{INSIDE} sent {60 * MIB:,} bytes" in m.claim
    assert ("Which side opened the connection is not recorded: it is TCP with no record of the opening (picked up "
            f"mid-stream, or opened before the hunt window). On it {INSIDE} used a port of 32768 or above and "
            f"{OUTSIDE} used tcp/443 (1 connection), the port shape of {INSIDE} as the client.") in m.claim
    assert f"shows {INSIDE} opened" not in m.claim and "initiated" not in m.claim


def test_a_suricata_flow_an_outside_client_opened_to_an_internal_server_is_not_an_upload_and_is_named():
    download = suricata_tcp(eve("dl", src=OUTSIDE, sport=51000, dst=INSIDE, dport=443, state="closed", seconds=60,
                                  c2s=MIB, s2c=600 * MIB, pkts_c=900, pkts_s=9000),
                              syn=True, tcp_flags_ts="02", tcp_flags_tc="12")
    rule = OutboundVolumeAsymmetry()
    assert run(rule, events(download)) == []
    assert rule.limit_reasons() == []
    [note] = rule.coverage_notes()
    assert note.startswith("not read as uploads (informational): connections whose only record of the opening, by "
                           "an external address, is a Suricata directional TCP flag summary that records a SYN toward "
                           "the server, so the internal address answered as a server: the internal addresses sent "
                           f"{600 * MIB:,} bytes on them")


def test_a_servers_answers_from_its_service_port_with_no_recorded_opening_are_not_an_upload():
    answers = eve("srv", src=INSIDE, sport=443, dst=OUTSIDE, dport=51000, state="new", c2s=600 * MIB, s2c=MIB,
                  pkts_s=10)
    rule = OutboundVolumeAsymmetry()
    assert run(rule, events(answers)) == [] and rule.evaluated == 1
    assert f"the internal addresses sent {600 * MIB:,} bytes on them" in rule.limit_reasons()[0]


def test_an_unanswered_inbound_probe_sent_nothing_from_inside_so_nothing_is_named():
    # a scanner's SYN to an internal port: Suricata never saw the handshake (state 'new'), the internal side sent 0
    probe = eve("scan", src=OUTSIDE, sport=60000, dst=INSIDE, dport=22, state="new", c2s=60, s2c=0, pkts_s=0)
    rule = OutboundVolumeAsymmetry()
    assert run(rule, events(probe)) == [] and rule.limit_reasons() == []


# Channels an attacker can choose: no recorded opening and no port shape of a client. They are still read, and the
# claim says the bytes may be a server's answers.
@pytest.mark.parametrize("name,hit,wording", [
    ("icmp tunnel", eve("i", proto="ICMP", sport=None, dport=None, dst=OUTSIDE, c2s=200 * MIB, s2c=5 * MIB, pkts_c=10,
                        pkts_s=10),
     (f"The connection is ICMP, with no ports and no opening the sensors record, so nothing marks a client: what "
     f"{INSIDE} sent on it may be a server's answers.")),
    ("udp wireguard", eve("w", proto="UDP", sport=40000, dst=OUTSIDE, dport=51820, c2s=200 * MIB, s2c=5 * MIB,
                          pkts_s=10),
     (f"Which side opened the connection is not recorded: it is UDP, which has no opening to record. The ports do not "
     f"mark a client either: {INSIDE} used udp/40000 (1 connection) and {OUTSIDE} used udp/51820 (1 connection), so "
     f"what {INSIDE} sent on it may be a server's answers.")),
    ("tcp c2 port, suricata only, state new", eve("c", sport=50001, dst=OUTSIDE, dport=50050, state="new",
                                                  c2s=200 * MIB, s2c=5 * MIB, pkts_s=10),
     (f"{INSIDE} used tcp/50001 (1 connection) and {OUTSIDE} used tcp/50050 (1 connection), so what {INSIDE} sent on "
     f"it may be a server's answers.")),
    ("arkime from a low client port, no flag counts", ark("d", sport=5000, dst=OUTSIDE, dport=443, c2s=200 * MIB,
                                                          s2c=5 * MIB),
     (f"{INSIDE} used tcp/5000 (1 connection) and {OUTSIDE} used tcp/443 (1 connection), so what {INSIDE} sent on it "
     f"may be a server's answers.")),
])
def test_uploads_with_no_recorded_opener_and_no_client_port_shape_are_still_reported(name, hit, wording):
    rule = OutboundVolumeAsymmetry()
    [m] = run(rule, events(hit))
    assert f"{INSIDE} sent {200 * MIB:,} bytes (200.0 MiB) to {OUTSIDE} and received {5 * MIB:,}" in m.claim, name
    assert wording in m.claim and f"shows {INSIDE} opened" not in m.claim, name
    assert rule.limit_reasons() == [], name


def test_a_udp_upload_from_a_client_port_is_read_and_says_udp_has_no_opening():
    quic = eve("q", proto="UDP", src=INSIDE, sport=55000, dst=OUTSIDE, dport=443, c2s=70 * MIB, s2c=MIB, pkts_s=10)
    [m] = run(OutboundVolumeAsymmetry(), events(quic))
    assert "it is UDP, which has no opening to record" in m.claim and "udp/443 (1 connection)" in m.claim


def test_records_that_disagree_about_the_opener_are_read_as_unknown():
    both = [flagged(ark("a", src=INSIDE, sport=50123, dst=OUTSIDE, dport=443, c2s=60 * MIB, s2c=MIB), syn=1),
            flagged(ark("b", src=OUTSIDE, sport=443, dst=INSIDE, dport=50123, start=T0 + timedelta(minutes=1),
                        c2s=MIB // 2, s2c=10 * MIB), syn=1)]
    [m] = run(OutboundVolumeAsymmetry(), events(*both))
    assert "it is TCP whose records disagree about which side opened it" in m.claim
    assert "shows 10.0.0.5 opened" not in m.claim


def test_a_mixed_pair_counts_each_reading_apart_and_names_the_served_connection():
    hits = [suricata_tcp(eve("o", sport=50001, dst=OUTSIDE, dport=443, state="closed",
                               c2s=40 * MIB, s2c=MIB, pkts_s=10),
                           syn=True, tcp_flags_ts="02", tcp_flags_tc="12"),
            eve("n", sport=50002, dst=OUTSIDE, dport=8443, state="new", start=T0 + timedelta(minutes=5),
                c2s=30 * MIB, s2c=MIB, pkts_s=10),
            eve("u", proto="UDP", sport=40000, dst=OUTSIDE, dport=51820, start=T0 + timedelta(minutes=6),
                c2s=10 * MIB, s2c=0, pkts_s=0),
            suricata_tcp(eve("s", src=OUTSIDE, sport=50003, dst=INSIDE, dport=22, state="closed", c2s=MIB,
                               s2c=900 * MIB, pkts_s=10),
                           syn=True, tcp_flags_ts="02", tcp_flags_tc="12")]
    rule = OutboundVolumeAsymmetry()
    [m] = run(rule, events(*hits))
    assert f"{INSIDE} sent {80 * MIB:,} bytes" in m.claim and "over 3 connections" in m.claim
    assert "shows 10.0.0.5 opened 1 connection, to server port tcp/443 (1 connection)" in m.claim
    assert "Which side opened 1 connection is not recorded: 1 is TCP" in m.claim and "tcp/8443 (1 connection)" in m.claim
    assert "Which side opened 1 connection is not recorded: 1 is UDP" in m.claim and "udp/51820" in m.claim
    assert "tcp/22" not in m.claim
    assert rule.limit_reasons() == []
    [note] = rule.coverage_notes()
    assert f"sent {900 * MIB:,} bytes on them" in note and note.endswith("(1 connection(s))")


def test_outbound_citations_bound_the_stated_interval_beyond_the_example_limit():
    hits = [eve(f"u{i:02d}", sport=50000 + i, dst=OUTSIDE, dport=443, state="closed", start=T0 + timedelta(minutes=i),
                seconds=30, c2s=2 * MIB, s2c=1000, pkts_s=10) for i in range(40)]
    evs = events(*hits)
    batches = [evs[i:i + 7] for i in range(0, len(evs), 7)]
    [m] = run(OutboundVolumeAsymmetry(), *batches)
    assert len(m.events) == EXAMPLE_LIMIT
    assert "20 of the 40 records are cited, including the first and the last." in m.claim
    starts = sorted(e.get("flow.start") for e in m.events)
    ends = sorted(e.get("flow.end") for e in m.events)
    assert starts[0].startswith("2024-11-18T14:00:00.") and ends[-1].startswith("2024-11-18T14:39:30.")
    assert "(2024-11-18T14:00:00+00:00 – 2024-11-18T14:39:30+00:00;" in m.claim


def test_outbound_claims_and_citations_do_not_depend_on_record_order():
    hits = ([eve(f"u{i:02d}", sport=50000 + i, dst=OUTSIDE, dport=443, state="closed",
                 start=T0 + timedelta(minutes=i), seconds=30, c2s=2 * MIB, s2c=1000, pkts_s=10) for i in range(30)]
            + _ssh_download())
    evs = events(*hits)
    shuffled = list(evs)
    random.Random(5).shuffle(shuffled)

    def shape(batches):
        return [(m.claim, [e.id for e in m.events]) for m in run(OutboundVolumeAsymmetry(), *batches)]

    one_batch = shape([evs])
    assert one_batch == shape([shuffled])
    # across batches the examples after the bounds follow arrival, but the claim and its bounding records do not
    [(claim, cited)] = one_batch
    uploads = events(*hits[:30])                    # the counted connections: the SSH download is not an upload
    first, last = min(uploads, key=lambda e: e.get("flow.start")).id, max(uploads, key=lambda e: e.get("flow.end")).id
    for batches in ([evs[i:i + 9] for i in range(0, len(evs), 9)],
                    [shuffled[i:i + 9] for i in range(0, len(shuffled), 9)]):
        [(other_claim, other_cited)] = shape(batches)
        assert other_claim == claim and {first, last} <= set(other_cited) and {first, last} <= set(cited)


# ---- long external connection: the cited records bound the claim ------------------------------------------------

def _long(n, *, first_id=0, reversed_from=None, syn=True, **kw):
    """n Arkime save-interval records of one connection, 12 minutes apart, each carrying the root's first packet time
    as Arkime writes it; from `reversed_from` on, a session Arkime picked up mid-stream records the other side first."""
    hits = []
    for i in range(n):
        kw_i = dict(kw)
        if reversed_from is not None and i >= reversed_from:
            kw_i.update(src="192.0.2.174", sport=4444, dst="172.17.100.121", dport=51000, c2s=5000, s2c=1000)
        hit = session(f"r{first_id + i:03d}", first=T0, seconds=12 * 60 * (i + 1) - 1, **kw_i)
        hit["_source"]["tcpflags"] = {"syn": int(syn and i == 0), "syn-ack": int(syn and i == 0), "ack": 5}
        hits.append(hit)
    return hits


def test_a_long_connection_with_more_records_than_the_example_limit_cites_its_first_and_last_record():
    hits = _long(47)
    evs = events(*hits)
    [m] = run(LongExternalConnection(), *[evs[i:i + 5] for i in range(0, len(evs), 5)])
    assert len(m.events) == EXAMPLE_LIMIT and m.events[0].get("flow.start") == T0.isoformat()
    last_end = max(e.get("flow.end") for e in evs)
    assert last_end in {e.get("flow.end") for e in m.events}
    assert f"– {last_end})" in m.claim and "spanning 564 minutes" in m.claim
    assert "Arkime recorded 47 session record(s)" in m.claim
    assert "20 of the 47 records are cited, including the first and the last." in m.claim
    by_field = {p.field: p.value for p in m.predicate}
    assert by_field["flow.end"] == last_end and by_field["tcp.flags.syn"] == 1
    assert ("one TCP connection that 172.17.100.121:51000 opened to 192.0.2.174:4444 (a record shows its SYN)"
            in m.claim) and "1000 bytes from the client" not in m.claim


def test_a_long_connections_last_record_is_cited_when_records_arrive_newest_first():
    evs = events(*_long(30))
    newest_first = sorted(evs, key=lambda e: e.get("flow.end"), reverse=True)
    [m] = run(LongExternalConnection(), *[newest_first[i:i + 4] for i in range(0, len(evs), 4)])
    assert max(e.get("flow.end") for e in evs) in {e.get("flow.end") for e in m.events}
    assert "including the first and the last" in m.claim


def test_a_long_connection_holds_a_bounded_number_of_records_on_the_stage_however_many_it_has(tmp_path):
    evs = events(*_long(400))
    rule = LongExternalConnection()
    [m], sizes = staged_live(rule, [evs[i:i + 2] for i in range(0, len(evs), 2)], tmp_path)
    # its first records, and the two records bounding its span: the same with 200 batches as with one
    assert max(sizes) <= EXAMPLE_LIMIT + 2
    held = rule.conns.peek(next(iter(rule.conns.keys()))) if rule.conns else None
    assert held is None or len(held["events"]) <= EXAMPLE_LIMIT + 1
    assert "20 of the 400 records are cited, including the first and the last." in m.claim


def test_a_long_connection_arkime_reopened_mid_stream_keeps_each_sides_bytes_and_its_opener():
    # the lab's case: Arkime split one connection and recorded the second part from the other side first
    [m] = run(LongExternalConnection(), events(*_long(6, reversed_from=3)))
    assert "opened to 192.0.2.174:4444" in m.claim
    # three records from each side: summing source.bytes regardless of side would give 18000 and 18000
    assert "6000 bytes from the client and 30000 bytes from the server" in m.claim


def test_a_long_connection_with_no_recorded_syn_names_no_client():
    [m] = run(LongExternalConnection(), events(*_long(6, reversed_from=3, syn=False)))
    assert ("one TCP connection between 172.17.100.121:51000 and 192.0.2.174:4444 spanning 72 minutes" in m.claim)
    assert ("Which side opened it is not known: no record of it shows a SYN (Arkime picked it up mid-stream, or it "
            "opened before the hunt window).") in m.claim
    assert "client" not in m.claim and "server" not in m.claim


def test_without_a_community_id_both_orientations_of_one_connection_are_one_connection():
    hits = _long(6, reversed_from=3, cid=None)
    for hit in hits:
        del hit["_source"]["network"]
    [m] = run(LongExternalConnection(), events(*hits))
    assert "Arkime recorded 6 session record(s)" in m.claim


# ---- the other aggregate rules that state a span ------------------------------------------------------------------

def test_beaconing_cites_the_first_and_the_last_connection_of_the_stated_span():
    beacons = [session(f"b{i:02d}", first=T0 + timedelta(seconds=60 * i), seconds=1, sport=40000 + i, dport=443,
                       cid=f"1:b{i}=") for i in range(30)]
    [m] = run(Beaconing(), events(*beacons))
    starts = sorted(e.ts for e in m.events)
    assert len(m.events) == EXAMPLE_LIMIT and starts[0] == T0 and starts[-1] == T0 + timedelta(seconds=60 * 29)


def test_ssh_tag_cites_the_first_and_last_tagged_record_beyond_the_example_limit():
    tagged = [ssh_session(f"t{i:02d}", ["ssh-reverse-shell"], first=T0 + timedelta(minutes=i)) for i in range(30)]
    [m] = run(ArkimeSshReverseShellTag(), events(*tagged))
    times = sorted(e.ts for e in m.events)
    assert len(m.events) == EXAMPLE_LIMIT and times[0] == T0 and times[-1] == T0 + timedelta(minutes=29)


def test_protocol_mismatch_cites_the_groups_last_record_beyond_the_example_limit():
    hits = [eve(f"h{i:02d}", sport=50000 + i, dst=OUTSIDE, dport=4444, app_proto="http", c2s=4000, s2c=9000,
                pkts_s=12, start=T0 + timedelta(minutes=i)) for i in range(30)]
    [m] = run(ProtocolPortMismatch(), events(*hits))
    assert len(m.events) == EXAMPLE_LIMIT
    assert max(e.get("flow.end") for e in m.events).startswith("2024-11-18T14:29:01.")


def test_unidentified_traffic_cites_the_groups_last_record_beyond_the_example_limit():
    hits = [eve(f"u{i:02d}", sport=50000 + i, dst=OUTSIDE, dport=80, c2s=3000, s2c=8000, pkts_s=8,
                start=T0 + timedelta(minutes=i)) for i in range(30)]
    [m] = run(ProtocolPortMismatch(), events(*hits))
    assert len(m.events) == EXAMPLE_LIMIT
    assert max(e.get("flow.end") for e in m.events).startswith("2024-11-18T14:29:01.")


def test_long_unidentified_session_cites_the_longest_connections_last_record():
    hits = [ark(f"c{i:02d}", sport=51000, dst=OUTSIDE, dport=4444, start=T0 + timedelta(minutes=12 * i),
                seconds=12 * 60 - 1, c2s=4000, s2c=9000, data_c=2000, data_s=7000) for i in range(12)]
    [m] = run(LongUnidentifiedSession(), events(*hits))
    assert max(e.get("flow.end") for e in m.events) == max(e.get("flow.end") for e in events(*hits))


def test_sweep_citations_include_the_last_record_of_the_hunt_window_span():
    sweep = [eve(f"w{i:03d}", sport=30000 + i, dst=f"10.0.100.{i + 1}", start=T0 + timedelta(seconds=i))
             for i in range(60)]
    [m] = run(HorizontalSweep(), events(*sweep))
    assert len(m.events) == EXAMPLE_LIMIT
    assert {e.get("destination.ip") for e in m.events} >= {"10.0.100.1", "10.0.100.60"}


def test_bound_note_names_a_bound_that_was_not_kept():
    ends = flows.Ends((1.0, "a"), (9.0, "b"))
    assert flows.bound_note(set(), ends) == ""
    assert flows.bound_note({"b"}, ends) == (" The record that ends this interval was not kept for citation; the "
                                             "interval is computed from every record.")


# ---- the stage holds what can still be cited, however long the hunt ------------------------------------------------

def staged_live(rule, batches, tmp_path):
    """Drive a staged rule the way the sweep stages its records on the real event stage: citations kept to the end,
    interval bounds held and released. Returns the findings and the number of events on the stage after each batch."""
    from romulus.hunt.stage import EventStage
    stage, sizes = EventStage(tmp_path), []
    try:
        for batch in batches:
            rule.consume(batch)
            drained = rule.drain_staged()
            held_ids, released = rule.drain_bounds()
            holds, copies = Counter(held_ids), Counter(e.id for e in drained)
            unique = {e.id: e for e in drained}
            stage.put([e for i, e in unique.items() if copies[i] > holds[i]], {})
            stage.hold([(rule.id, e) for i, e in unique.items() for _ in range(holds[i])], {})
            stage.release(rule.id, released)
            sizes.append(stage.count())
        rule.bind_loader(stage.load)
        return rule.finalize(), sizes
    finally:
        stage.close()


def test_identified_traffic_that_can_never_be_reported_stages_nothing(tmp_path):
    identified = [eve(f"l{i}", sport=40000 + i, dst=f"10.0.{1 + i // 250}.{1 + i % 250}", dport=9999,
                      app_proto="tls", c2s=5000, s2c=9000, pkts_c=5, pkts_s=5, state="closed",
                      start=T0 + timedelta(seconds=i)) for i in range(2000)]
    evs = events(*identified)
    found, sizes = staged_live(LongUnidentifiedSession(), [evs[i:i + 250] for i in range(0, len(evs), 250)], tmp_path)
    assert found == [] and max(sizes) == 0


def test_a_pair_that_never_qualifies_stages_only_its_first_records(tmp_path):
    small = [eve(f"o{i}", sport=40000 + i, dst=OUTSIDE, dport=443, state="closed", c2s=5000, s2c=9000, pkts_s=5,
                 start=T0 + timedelta(seconds=30 * i)) for i in range(400)]
    evs = events(*small)
    found, sizes = staged_live(OutboundVolumeAsymmetry(), [evs[i:i + 2] for i in range(0, len(evs), 2)], tmp_path)
    assert found == [] and sizes[-1] == OutboundVolumeAsymmetry.FIRST_CITES


def test_a_qualifying_pair_holds_its_citations_and_two_bounds_however_many_batches(tmp_path):
    big = [eve(f"b{i:03d}", sport=40000 + i, dst=OUTSIDE, dport=443, state="closed", c2s=MIB, s2c=1000, pkts_s=5,
               start=T0 + timedelta(seconds=30 * i)) for i in range(300)]
    evs = events(*big)
    [m], sizes = staged_live(OutboundVolumeAsymmetry(), [evs[i:i + 2] for i in range(0, len(evs), 2)], tmp_path)
    assert max(sizes) <= EXAMPLE_LIMIT + 2
    assert "20 of the 300 records are cited, including the first and the last." in m.claim


def test_a_sweep_group_that_never_qualifies_stages_no_bounds(tmp_path):
    resolver = [eve(f"s{i}", proto="UDP", sport=40000 + i, dst="10.0.1.1", dport=53, c2s=80, s2c=120, pkts_s=1,
                    start=T0 + timedelta(seconds=30 * i)) for i in range(400)]
    evs = events(*resolver)
    found, sizes = staged_live(HorizontalSweep(), [evs[i:i + 2] for i in range(0, len(evs), 2)], tmp_path)
    assert found == [] and sizes[-1] <= 2


def test_a_qualifying_sweep_still_cites_its_last_record_through_the_stage(tmp_path):
    sweep = [eve(f"w{i:03d}", sport=30000 + i, dst=f"10.0.100.{i + 1}", start=T0 + timedelta(seconds=i))
             for i in range(60)]
    evs = events(*sweep)
    [m], _sizes = staged_live(HorizontalSweep(), [evs[i:i + 3] for i in range(0, len(evs), 3)], tmp_path)
    assert {e.get("destination.ip") for e in m.events} >= {"10.0.100.1", "10.0.100.60"}


def test_the_event_stage_releases_a_held_event_only_when_no_one_keeps_or_holds_it(tmp_path):
    from romulus.evidence.typed import RawRef
    from romulus.hunt.stage import EventStage
    a, b, c = events(eve("a"), eve("b", sport=50001), eve("c", sport=50002))
    raw = {r.key: {"doc": r.native_id} for e in (a, b, c) for r in e.raw}
    stage = EventStage(tmp_path)
    try:
        stage.hold([("r1", a), ("r1", a), ("r2", b), ("r1", c)], raw)
        stage.put([c], raw)                                   # kept by someone: a release never removes it
        stage.release("r1", [a.id])
        assert {e.id for e in stage.load([a.id, b.id, c.id])} == {a.id, b.id, c.id}   # a is still held once
        stage.release("r1", [a.id, c.id])
        stage.release("r2", [b.id])
        assert [e.id for e in stage.load([a.id, b.id, c.id])] == [c.id]
        assert set(stage.raw_sources([a, b, c])) == {r.key for r in c.raw}             # only c's raw copy is left
        assert isinstance(c.raw[0], RawRef)
    finally:
        stage.close()


def test_ssh_tag_names_the_opener_only_for_the_tagged_connections_that_show_it():
    opened = ssh_session("o1", ["ssh-reverse-shell"], cid="1:o1=", tcpflags={"syn": 1})
    unopened = ssh_session("o2", ["ssh-reverse-shell"], cid="1:o2=", first=T0 + timedelta(minutes=3))
    [m] = run(ArkimeSshReverseShellTag(), events(opened, unopened))
    assert ("Tagged records show the SYN from 172.17.100.121 on 1 of the 2 tagged connections, so 172.17.100.121 "
            "opened those; for the others, which end opened them is not recorded.") in m.claim
    assert "The client" not in m.claim and "from the client" not in m.claim


def test_the_sweep_holds_a_long_connections_bounds_and_releases_the_superseded_ones(monkeypatch, tmp_path):
    from datetime import UTC, datetime

    from romulus.hunt import sweep as sw
    from romulus.sources.models import Completeness, SearchOutcome, Window
    from romulus.store.db import make_engine, migrate
    from romulus.store.repo import Repo

    hits = _long(120)
    batches = [hits[i:i + 4] for i in range(0, len(hits), 4)]
    served = iter(batches)

    def execute(client, intent, contract):
        now, records = datetime.now(UTC), next(served)
        return SearchOutcome(target=intent.target, fingerprint="f", started_at=now, ended_at=now,
                             completeness=Completeness.complete, total=len(records), total_relation="eq",
                             returned=len(records), records=records)

    monkeypatch.setattr(sw, "execute", execute)
    engine = make_engine(":memory:")
    migrate(engine)
    repo = Repo(engine)
    repo.create_hunt("h1", {"targets": ["arkime_sessions3-x"]}, "d", "t")
    sweep = sw.Sweep(repo, None, "h1", Window(start=T0, end=T0 + timedelta(days=1)), {"arkime_sessions3-x": None},
                     stage_dir=tmp_path)
    try:
        for i in range(len(batches)):
            w = Window(start=T0 + timedelta(hours=i), end=T0 + timedelta(hours=i + 1))
            sweep.run_partition("arkime_sessions3-x", None, [], w, est=4)
        stage = sweep._event_stage()
        last = max(events(*hits), key=lambda e: e.get("flow.end"))
        assert stage.load([last.id])                        # the record ending the span is on the stage
        # held bounds: two per rule that states this connection's span, however many partitions it crossed (every
        # superseded bound was released); the rest of the stage is citations rules keep to the end
        holds = stage.db.execute("SELECT owner, SUM(n) FROM hold GROUP BY owner").fetchall()
        assert holds and all(n <= 2 for _owner, n in holds)
        assert stage.db.execute("SELECT COUNT(*) FROM event WHERE kept = 0").fetchone()[0] <= 2 * len(holds)
    finally:
        sweep.close_stage()


# ---- the stage at mission scale, and what the window cell names ------------------------------------------------------

def test_releasing_holds_costs_the_same_however_many_holds_the_stage_has(tmp_path):
    import time

    from romulus.hunt import stage as stage_mod
    stage = stage_mod.EventStage(tmp_path)
    try:
        db = stage.db
        n = 200_000
        db.executemany("INSERT INTO event VALUES (?, '{}', 0)", [(f"e{i}",) for i in range(n)])
        db.executemany("INSERT INTO hold VALUES (?, 'rule', 1)", [(f"e{i}",) for i in range(n)])
        db.executemany("INSERT INTO event_raw VALUES (?, ?)", [(f"e{i}", f"k{i}") for i in range(n)])
        db.executemany("INSERT INTO raw VALUES (?, '{}', 0)", [(f"k{i}",) for i in range(n)])
        db.commit()
        started = time.perf_counter()
        stage.release("rule", [f"e{i}" for i in range(0, n, 20)])                  # 10,000 releases
        elapsed = time.perf_counter() - started
        assert stage.count() == n - n // 20 and elapsed < 5.0, elapsed
        # every statement a release or a keep runs looks rows up by a key: none scans a table
        for sql in stage_mod.INDEXED_STATEMENTS:
            args = tuple("x" for _ in range(sql.count("?")))
            plan = [row[3] for row in db.execute(f"EXPLAIN QUERY PLAN {sql}", args)]
            assert not [step for step in plan if step.startswith("SCAN")], (sql, plan)
    finally:
        stage.close()


def test_a_held_event_that_becomes_kept_drops_its_release_bookkeeping(tmp_path):
    from romulus.hunt.stage import EventStage
    [a] = events(eve("a"))
    raw = {r.key: {"doc": r.native_id} for r in a.raw}
    stage = EventStage(tmp_path)
    try:
        stage.hold([("r1", a)], raw)
        assert stage.db.execute("SELECT COUNT(*) FROM event_raw").fetchone()[0] == len(a.raw)
        stage.put([a], raw)
        assert stage.db.execute("SELECT COUNT(*) FROM event_raw").fetchone()[0] == 0
        stage.release("r1", [a.id])
        assert stage.load([a.id]) and set(stage.raw_sources([a])) == {r.key for r in a.raw}
    finally:
        stage.close()


def test_a_bound_taken_by_an_unstaged_record_releases_the_hold_it_replaces():
    bounds, ends = flows.BoundStage(), flows.Ends()
    a, b, c = events(eve("a"), eve("b", sport=50001, start=T0 + timedelta(minutes=1)),
                     eve("c", sport=50002, start=T0 + timedelta(minutes=2)))
    bounds.offer("g", ends, 1.0, 1.0, a)
    bounds.offer("g", ends, 2.0, 2.0, b)
    bounds.drain()
    assert ends.held == [a.id, b.id]
    bounds.offer("g", ends, 3.0, 3.0, c, stage=False)     # c is the latest now, and is not held
    bounds.drain()
    assert bounds.last == ([], [b.id]) and ends.held == [a.id, None]


def test_single_record_unidentified_candidates_hold_no_bounds(tmp_path):
    candidates = [eve(f"u{i}", sport=40000 + i, dst=f"198.51.{100 + i // 250}.{1 + i % 250}", dport=80, c2s=3000,
                      s2c=8000, pkts_s=8, start=T0 + timedelta(seconds=i)) for i in range(2000)]
    evs = events(*candidates)
    rule, held = ProtocolPortMismatch(), 0
    for i in range(0, len(evs), 250):
        rule.consume(evs[i:i + 250])
        rule.drain_staged()
        held += len(rule.drain_bounds()[0])
    assert held == 0


def test_server_shaped_pairs_that_meet_the_thresholds_are_listed_by_name():
    low = [eve("dns", src=INSIDE, sport=53, dst=OUTSIDE, dport=40000, state="new", c2s=200 * MIB, s2c=MIB,
               pkts_c=150_000, pkts_s=10),
           eve("ntp", proto="UDP", src="10.0.0.6", sport=123, dst="198.51.100.7", dport=45000, c2s=150 * MIB, s2c=0,
               pkts_c=110_000, pkts_s=0)]
    rule = OutboundVolumeAsymmetry()
    assert run(rule, events(*low)) == []
    [reason] = rule.limit_reasons()
    assert ("2 pairs met the upload thresholds (at least 50 MiB sent and at least 10 times what came back) on these "
            "connections and were not read as uploads only because of the port shape: "
            f"{INSIDE} to {OUTSIDE}, {200 * MIB:,} bytes sent and {MIB:,} back, from tcp/53; "
            f"10.0.0.6 to 198.51.100.7, {150 * MIB:,} bytes sent and 0 back, from udp/123") in reason


def test_the_server_shaped_list_is_bounded_and_says_how_many_more():
    low = [eve(f"s{i:02d}", src=f"10.0.1.{i + 1}", sport=1000 + i, dst=OUTSIDE, dport=40000 + i, state="new",
               c2s=(60 + i) * MIB, s2c=0, pkts_c=50_000, pkts_s=0) for i in range(13)]
    rule = OutboundVolumeAsymmetry()
    run(rule, events(*low))
    [reason] = rule.limit_reasons()
    assert "13 pairs met the upload thresholds" in reason and reason.count(" bytes sent and ") == 10
    assert "; and 3 more" in reason and "10.0.1.13 to" in reason and "10.0.1.1 to" not in reason


def test_a_servers_handshake_answer_to_a_scanner_is_not_named():
    # Arkime saw the scanner's SYN; the internal server answered with a SYN-ACK and a reset, headers only
    answered = flagged(ark("syn", src=OUTSIDE, sport=60000, dst=INSIDE, dport=22, c2s=74, s2c=74 + 54, pkts_c=1,
                           pkts_s=2), syn=1, syn_ack=1)
    rule = OutboundVolumeAsymmetry()
    assert run(rule, events(answered)) == []
    assert rule.limit_reasons() == [] and rule.coverage_notes() == []
