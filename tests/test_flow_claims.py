"""Flow and session claims state only what the records show.

- Which side opened a connection comes from a record that shows the opening (an Arkime session that counted a SYN, a
  Suricata TCP flow its engine tracked from the handshake), never from the side a sensor happened to record first: a
  session picked up mid-stream is recorded with whichever side spoke first as its source.
- The records cited for a claim include the records that bound every interval it states, however many records the
  claim rests on, and the claim says how many it rests on and how many are cited.

Fixtures go through the real normalizer (Suricata EVE flow records, Arkime SPI sessions)."""
import random
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


@pytest.mark.parametrize("state,opened", [("established", True), ("closed", True), ("new", False),
                                          ("bypassed", False)])
def test_a_suricata_tcp_flow_shows_the_opener_only_when_its_engine_tracked_the_handshake(state, opened):
    assert view(eve("s", state=state)).opened is opened
    assert not view(eve("u", proto="UDP", dport=53, state=state)).opened


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


def test_an_internal_servers_answers_picked_up_mid_stream_are_not_an_upload():
    # the old reading took Arkime's mid-stream orientation as the opener and reported "a connection it initiated"
    rule = OutboundVolumeAsymmetry()
    assert run(rule, events(*_ssh_download())) == []
    assert rule.evaluated == 18 and rule.limit_reasons() == []        # the root shows who opened it: judged, served


def test_mid_stream_records_with_no_opening_and_a_servers_port_are_not_evaluated_and_coverage_says_so():
    rule = OutboundVolumeAsymmetry()
    assert run(rule, events(*_ssh_download(root=False))) == []
    [reason] = rule.limit_reasons()
    assert reason.startswith("not evaluated: which side opened these connections between internal and external "
                             "addresses is not recorded, and their ports do not mark the internal address as the "
                             "client (1 with both ports ephemeral or the internal port the lower, 0 on transports "
                             "without ports)")
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
    assert (f"A recorded TCP opening (an Arkime session that counted the SYN, or a Suricata flow whose handshake it "
            f"tracked) shows {INSIDE} opened the connection, to server port tcp/443 (1 connection) on {OUTSIDE}.") \
        in m.claim
    assert "not recorded" not in m.claim and "All 4 records are cited." in m.claim
    assert {p.field: p.value for p in m.predicate}["tcp.flags.syn"] == 1


def test_an_upload_with_no_recorded_opening_is_read_from_its_ports_and_says_the_opener_is_unknown():
    hits = [flagged(ark(f"m{i}", src=OUTSIDE, sport=443, dst=INSIDE, dport=50123, start=T0 + timedelta(minutes=i),
                        seconds=50, c2s=MIB // 4, s2c=20 * MIB)) for i in range(3)]
    [m] = run(OutboundVolumeAsymmetry(), events(*hits))
    assert f"{INSIDE} sent {60 * MIB:,} bytes" in m.claim
    assert ("Which side opened the connection is not recorded: it is TCP with no record of the opening (picked up "
            f"mid-stream, or opened before the hunt window). On it {INSIDE} used a port of 32768 or above and "
            f"{OUTSIDE} used tcp/443 (1 connection), the port shape of {INSIDE} as the client.") in m.claim
    assert f"shows {INSIDE} opened" not in m.claim and "initiated" not in m.claim


def test_a_suricata_flow_an_outside_client_opened_to_an_internal_server_is_not_an_upload():
    download = eve("dl", src=OUTSIDE, sport=51000, dst=INSIDE, dport=443, state="closed", seconds=60,
                   c2s=MIB, s2c=600 * MIB, pkts_c=900, pkts_s=9000)
    rule = OutboundVolumeAsymmetry()
    assert run(rule, events(download)) == [] and rule.limit_reasons() == []


@pytest.mark.parametrize("hit", [
    # a server answering from its service port, picked up mid-stream (state 'new')
    eve("srv", src=INSIDE, sport=443, dst=OUTSIDE, dport=51000, state="new", c2s=600 * MIB, s2c=MIB, pkts_s=10),
    # both ports ephemeral (media, peer-to-peer): no shape to tell the client
    eve("p2p", proto="UDP", src=INSIDE, sport=40000, dst=OUTSIDE, dport=50000, c2s=600 * MIB, s2c=MIB, pkts_s=10),
])
def test_connections_whose_opener_and_client_side_are_unknown_are_not_evaluated(hit):
    rule = OutboundVolumeAsymmetry()
    assert run(rule, events(hit)) == [] and rule.evaluated == 1
    assert rule.limit_reasons()[0].startswith("not evaluated:")


def test_an_unanswered_inbound_probe_sent_nothing_from_inside_so_nothing_is_left_unread():
    # a scanner's SYN to an internal port: Suricata never saw the handshake (state 'new'), the internal side sent 0
    probe = eve("scan", src=OUTSIDE, sport=60000, dst=INSIDE, dport=22, state="new", c2s=60, s2c=0, pkts_s=0)
    rule = OutboundVolumeAsymmetry()
    assert run(rule, events(probe)) == [] and rule.limit_reasons() == []


def test_the_unread_bytes_are_named_on_coverage():
    rule = OutboundVolumeAsymmetry()
    run(rule, events(eve("srv", src=INSIDE, sport=443, dst=OUTSIDE, dport=51000, state="new", c2s=600 * MIB,
                         s2c=MIB, pkts_s=10)))
    assert f"so the {600 * MIB:,} bytes the internal addresses sent on them were not read as uploads" in \
        rule.limit_reasons()[0]


def test_traffic_on_a_transport_without_ports_is_not_evaluated_and_counted_as_such():
    icmp = ark("icmp", proto=1, sport=None, dport=None, dst=OUTSIDE, c2s=600 * MIB, s2c=MIB, pkts_s=10)
    rule = OutboundVolumeAsymmetry()
    assert run(rule, events(icmp)) == []
    assert "(0 with both ports ephemeral or the internal port the lower, 1 on transports without ports)" in \
        rule.limit_reasons()[0]


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


def test_a_mixed_pair_counts_the_opened_and_the_port_shaped_connections_apart():
    hits = [eve("o", sport=50001, dst=OUTSIDE, dport=443, state="closed", c2s=40 * MIB, s2c=MIB, pkts_s=10),
            eve("n", sport=50002, dst=OUTSIDE, dport=8443, state="new", start=T0 + timedelta(minutes=5),
                c2s=30 * MIB, s2c=MIB, pkts_s=10),
            eve("s", src=OUTSIDE, sport=50003, dst=INSIDE, dport=22, state="closed", c2s=MIB, s2c=900 * MIB,
                pkts_s=10)]
    [m] = run(OutboundVolumeAsymmetry(), events(*hits))
    assert f"{INSIDE} sent {70 * MIB:,} bytes" in m.claim and "over 2 connections" in m.claim
    assert "shows 10.0.0.5 opened 1 of them, to server port tcp/443 (1 connection)" in m.claim
    assert "Which side opened the other 1 connection is not recorded: 1 is TCP" in m.claim
    assert "tcp/8443 (1 connection)" in m.claim and "tcp/22" not in m.claim


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


def test_a_long_connection_stages_a_bounded_number_of_records_however_many_it_has():
    evs = events(*_long(400))
    rule, staged = LongExternalConnection(), {}
    batches = [evs[i:i + 25] for i in range(0, len(evs), 25)]
    for batch in batches:
        rule.consume(batch)
        staged.update({e.id: e for e in rule.drain_staged()})
    # the first records, plus at most the two bounding records per batch
    assert len(staged) <= EXAMPLE_LIMIT + 2 * len(batches)
    held = rule.conns.peek(next(iter(rule.conns.keys())))
    assert len(held["events"]) <= EXAMPLE_LIMIT + 1
    rule.bind_loader(lambda ids: [staged[i] for i in ids if i in staged])
    [m] = rule.finalize()
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
