"""Arkime SPI session indices as a hunt target: schema detection, normalization, session rules."""
from datetime import UTC, datetime, timedelta

import pytest

from romulus.detect.correlation import ProcessNetworkLink
from romulus.detect.sessions import Beaconing, LongExternalConnection, RareClientFingerprint
from romulus.evidence.normalize import normalize_hits
from romulus.hunt import sweep as sw
from romulus.sources.models import Completeness, SearchOutcome, Window
from romulus.sources.profile import contract_from_types, schema_of
from romulus.store.db import make_engine, migrate
from romulus.store.repo import Repo

T0 = datetime(2024, 11, 18, 14, 26, 40, tzinfo=UTC)
INDEX = "arkime_sessions3-241118"


def session(_id, *, first=T0, seconds=60.0, src="172.17.100.121", sport=51000, dst="192.0.2.174", dport=4444,
            proto=6, cid="1:abc=", ja3=None, hassh=None, c2s=1000, s2c=5000):
    src_doc = {"firstPacket": int(first.timestamp() * 1000),
               "lastPacket": int((first + timedelta(seconds=seconds)).timestamp() * 1000),
               "ipProtocol": proto, "node": "server", "network": {"community_id": cid},
               "source": {"ip": src, "port": sport, "bytes": c2s, "packets": 10},
               "destination": {"ip": dst, "port": dport, "bytes": s2c, "packets": 12},
               "protocol": ["tcp"] if proto == 6 else ["udp"]}
    if ja3:
        src_doc["tls"] = {"ja3": [ja3]}
    if hassh:
        src_doc["ssh"] = {"hassh": [hassh]}
    return {"_id": _id, "_index": INDEX, "_source": src_doc}


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


# ---- schema and normalization ----------------------------------------------------------------

def test_arkime_mapping_is_detected_from_fields_and_timed_by_first_packet():
    types = {"firstPacket": "date", "lastPacket": "date", "network.community_id": "keyword", "source.ip": "ip"}
    assert schema_of(types) == "arkime_sessions"
    assert contract_from_types(INDEX, types).time_field == "firstPacket"
    assert contract_from_types("lab", {"@timestamp": "date"}).time_field == "@timestamp"


def test_session_record_becomes_typed_net_session_with_lineage():
    e = events(session("x1", ja3="abc123"))[0]
    assert e.family == "net_session" and e.ts == T0 and e.host == "server"
    assert (e.get("source.ip"), e.get("destination.port"), e.get("network.transport")) == \
        ("172.17.100.121", 4444, "tcp")
    assert e.get("network.community_id") == "1:abc=" and e.get("tls.ja3") == ["abc123"]
    assert e.get("session.duration_s") == 60.0 and e.get("flow.start") == T0.isoformat()
    assert e.fields["destination.ip"].origin == "x1:destination.ip"
    assert ("host", "server", "observer") in e.entities()


def test_session_with_bad_packet_time_is_an_error_not_a_skip():
    bad = session("x1")
    bad["_source"]["firstPacket"] = "yesterday"
    _, _, errors = normalize_hits([bad])
    assert errors and errors[0][1].startswith("arkime.session:")


# ---- long connections ------------------------------------------------------------------------

def _chunks(n, *, minutes=12, **kw):
    return [session(f"c{i}", first=T0 + timedelta(minutes=minutes * i), seconds=minutes * 60 - 1, **kw)
            for i in range(n)]


def test_chunked_long_connection_is_stitched_into_one_finding():
    m = run(LongExternalConnection(), events(*_chunks(4)))
    assert len(m) == 1
    assert "4 session record(s) for one TCP connection 172.17.100.121:51000 -> 192.0.2.174:4444" in m[0].claim
    assert "spanning 48 minutes" in m[0].claim and len(m[0].events) == 4


@pytest.mark.parametrize("kw", [{"dst": "10.0.0.9"}, {"proto": 17}])
def test_internal_or_udp_long_connections_do_not_match(kw):
    assert run(LongExternalConnection(), events(*_chunks(4, **kw))) == []


def test_short_connection_does_not_match():
    assert run(LongExternalConnection(), events(*_chunks(2))) == []


# ---- beaconing -------------------------------------------------------------------------------

IRREGULAR = [0, 31, 140, 152, 290, 303, 400, 520, 547, 700]   # human-like, uneven gaps


def _beacons(n, offsets=None):
    offsets = offsets or [60 * i for i in range(n)]
    return [session(f"b{i}", first=T0 + timedelta(seconds=offsets[i]), seconds=1,
                    sport=40000 + i, dport=443, cid=f"1:b{i}=") for i in range(n)]


def test_regular_connections_are_beaconing():
    m = run(Beaconing(), events(*_beacons(10)))
    assert len(m) == 1 and "10 separate tcp connections from 172.17.100.121 to 192.0.2.174 port 443" in m[0].claim
    assert "every 60 s (median)" in m[0].claim


def test_irregular_or_few_connections_are_not_beaconing():
    assert run(Beaconing(), events(*_beacons(10, IRREGULAR))) == []
    assert run(Beaconing(), events(*_beacons(5))) == []


# ---- rare client fingerprints ----------------------------------------------------------------

def test_fingerprint_from_one_internal_address_is_context():
    m = run(RareClientFingerprint(), events(session("r1", ja3="deadbeef")))
    assert len(m) == 1 and m[0].proposed_lane == "context" and "JA3 client fingerprint deadbeef" in m[0].claim


def test_fingerprint_shared_by_two_addresses_is_not_rare():
    two = events(session("r1", hassh="h1"), session("r2", hassh="h1", src="172.17.100.122", cid="1:r2="))
    assert run(RareClientFingerprint(), two) == []


# ---- correlation with host sockets -------------------------------------------------------------

def test_arkime_session_and_suricata_flow_of_one_connection_join_a_host_socket():
    from tests.test_network_correlation import SSHD, _sock, alert, flow
    host = [_sock(**SSHD)]
    net = normalize_hits([flow(src="172.17.100.121"), alert(src="172.17.100.121")])[0]
    ark = events(session("x1", first=T0, seconds=1800))
    m = run(ProcessNetworkLink(), host, net, ark)
    assert len(m) == 1
    assert "2 flow or session record(s) across 1 connection(s)" in m[0].claim
    assert "inetfw, server" in m[0].claim


# ---- through the sweep -----------------------------------------------------------------------

class _Client:
    version = "test"

    class settings:
        es_flavor = "elasticsearch"


def test_session_rule_citations_resolve_after_a_sweep(monkeypatch):
    from romulus.report import manifest as rm
    records = _chunks(4)
    monkeypatch.setattr(sw, "execute", lambda client, intent, contract: SearchOutcome(
        target=intent.target, fingerprint="f", started_at=datetime.now(UTC), ended_at=datetime.now(UTC),
        completeness=Completeness.complete, total=len(records), total_relation="eq", returned=len(records),
        records=records))
    engine = make_engine(":memory:")
    migrate(engine)
    repo = Repo(engine)
    repo.create_hunt("h1", {"targets": [INDEX]}, "d", "t")
    w = Window(start=T0 - timedelta(hours=1), end=T0 + timedelta(hours=2))
    s = sw.Sweep(repo, _Client(), "h1", w, {INDEX: None})
    s.run_partition(INDEX, None, [], w, est=4)
    s.finalize()
    long_conn = [c for c in repo.candidates("h1") if c["rule_id"] == "net.long_external_connection"]
    assert len(long_conn) == 1
    cites = rm._citations(repo, long_conn[0])
    assert len(cites) == 4 and all(c["status"] == "retained" for c in cites), cites
    assert not s.partial_reasons
