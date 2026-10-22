"""Mission-scale state of the session and certificate rules: connections are held while they can still change, a
series keeps compact starts, popular fingerprints and certificates stop collecting, and citations are ids."""
from datetime import UTC, datetime, timedelta

import pytest

from romulus.detect import sessions, tls
from romulus.evidence.typed import RawRef, TypedEvent, fv

T0 = datetime(2024, 11, 4, 0, 0, tzinfo=UTC)
_n = 0


def session(src, sport, dst, dport, first, seconds=20.0, cid=None, **extra):
    global _n
    _n += 1
    fields = {"source.ip": src, "source.port": sport, "destination.ip": dst, "destination.port": dport,
              "network.transport": "tcp", "flow.start": first.isoformat(),
              "flow.end": (first + timedelta(seconds=seconds)).isoformat(),
              "network.community_id": cid or f"1:{src}:{sport}:{dst}:{dport}", "source.bytes": 500,
              "destination.bytes": 900}
    fields.update({k.replace("__", "."): v for k, v in extra.items()})
    return TypedEvent(id=f"s{_n:09d}", family="net_session", ts=first, host="arkime",
                      fields={k: fv(v, "fixture") for k, v in fields.items()},
                      raw=[RawRef(target="fx", native_id=f"s{_n}")], normalizer="fixture")


def drive(rule, batches, probe):
    stage, peak = {}, 0
    for batch in batches:
        rule.consume(batch)
        stage.update({e.id: e for e in rule.drain_staged()})
        peak = max(peak, probe(rule))
    rule.bind_loader(lambda ids: [stage[i] for i in ids if i in stage])
    return rule.finalize(), peak, stage


def browsing(hours, clients, per_hour, beacon=None, long=None):
    """Each client opens `per_hour` short external connections an hour, each on a new source port. Optionally one
    client beacons every 60 s and one holds a two-hour connection in 10-minute Arkime records."""
    for hour in range(hours):
        start = T0 + timedelta(hours=hour)
        batch = [session(f"10.5.0.{c + 1}", 1024 + (hour * per_hour + k) % 60000, f"198.51.100.{k % 200 + 1}", 443,
                         start + timedelta(seconds=k * 3600 // per_hour))
                 for c in range(clients) for k in range(per_hour)]
        if beacon is not None:
            batch += [session(beacon, 30000 + (hour * 60 + m) % 30000, "203.0.113.50", 8443,
                              start + timedelta(minutes=m)) for m in range(60)]
        if long is not None and long[0] <= hour < long[0] + 2:
            batch += [session(long[1], 45555, "203.0.113.9", 22, start + timedelta(minutes=10 * k), seconds=600,
                              cid="1:long") for k in range(6)]
        yield batch


@pytest.mark.slow
def test_long_connection_rule_holds_open_connections_only():
    rule = sessions.LongExternalConnection()
    out, peak, _ = drive(rule, browsing(72, 60, 40, long=(30, "10.5.9.9")), lambda r: len(r.conns))
    assert peak <= 60 * 40 * 2 + 1, peak
    assert [m.group_key for m in out] == ["1:long"]
    assert "spanning 120 minutes" in out[0].claim and "12 session record(s)" in out[0].claim


@pytest.mark.slow
def test_beaconing_series_hold_compact_starts_and_the_beacon_is_found():
    rule = sessions.Beaconing()
    out, peak, _ = drive(rule, browsing(72, 60, 40, beacon="10.5.8.8"), lambda r: len(r.conns))
    assert peak <= 60 * 40 * 2 + 60 * 2, peak
    beacons = [m for m in out if m.group_key.startswith("10.5.8.8|")]
    assert len(beacons) == 1 and "4320 separate tcp connections" in beacons[0].claim
    assert all(isinstance(series.starts[0], float) for series in rule.series.values())


def test_beaconing_starts_budget_refuses_new_connections_and_says_so(monkeypatch):
    monkeypatch.setattr(sessions.Beaconing, "STARTS_BUDGET", 5)
    rule = sessions.Beaconing()
    _out, _peak, _ = drive(rule, [[session("10.5.0.1", 30000 + i, "203.0.113.50", 443, T0 + timedelta(minutes=i))
                                  for i in range(9)]], lambda r: 0)
    assert rule.capped == 4 and any("4 record(s) not evaluated" in r for r in rule.limit_reasons())


def test_popular_fingerprint_stops_collecting_once_it_cannot_be_rare():
    rule = sessions.RareClientFingerprint()
    batch = [session(f"10.6.{i // 250}.{i % 250 + 1}", 40000, "198.51.100.7", 443, T0 + timedelta(seconds=i),
                     tls__ja3="ja3-popular") for i in range(3000)]
    out, _peak, stage = drive(rule, [batch], lambda r: 0)
    p = rule.prints[("JA3", "ja3-popular")]
    assert len(p["sources"]) <= 2 and len(p["conns"]) <= rule.MAX_CONNECTIONS + 1 and not p["events"]
    assert out == [] and len(stage) <= sessions.EXAMPLE_LIMIT


def tls_record(src, dst, ts, cid):
    global _n
    _n += 1
    cert = {"subject": "CN=self", "issuer": "CN=self", "serial": "01", "self_issued": True,
            "not_before": "2024-01-01T00:00:00+00:00", "not_after": "2034-01-01T00:00:00+00:00",
            "fingerprint": "ab:cd"}
    fields = {"source.ip": src, "destination.ip": dst, "destination.port": 443, "network.community_id": cid,
              "tls.server.certificates": [cert], "network.protocols": ["tls"]}
    return TypedEvent(id=f"t{_n:09d}", family="tls_session", ts=ts, host="sensor",
                      fields={k: fv(v, "fixture") for k, v in fields.items()},
                      raw=[RawRef(target="fx", native_id=f"t{_n}")], normalizer="fixture")


def test_certificate_rules_hold_ids_and_cap_connections_with_lower_bound_wording(monkeypatch):
    monkeypatch.setattr(tls._CertificateRule, "CONNS_PER_GROUP", 50)
    rule = tls.SelfSignedCertificateOutbound()
    batch = [tls_record("10.7.0.1", "203.0.113.70", T0 + timedelta(seconds=i), f"1:c{i}") for i in range(200)]
    out, _peak, stage = drive(rule, [batch], lambda r: 0)
    assert rule.staged and rule.retained_events() == []
    assert all(isinstance(i, str) for group in rule.groups.values() for i in group.ids())
    assert len(out) == 1 and "at least 50 outbound TLS connection(s)" in out[0].claim
    assert len(stage) <= tls.EXAMPLE_LIMIT
