"""Mission-scale state of the session and certificate rules: every connection, fingerprint, SSH pair and certificate
group is held for the whole window in a keyed store (a hot set in memory, the rest on disk), so a hot set far
smaller than the data changes no result. Only the disk budget refuses, and coverage says so."""
import random
from datetime import UTC, datetime, timedelta

import pytest

from romulus.detect import bounded, sessions, tls
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


def drive(rule, batches, probe=lambda rule: 0):
    stage, peak = {}, 0
    for batch in batches:
        rule.consume(batch)
        stage.update({e.id: e for e in rule.drain_staged()})
        peak = max(peak, probe(rule))
    rule.bind_loader(lambda ids: [stage[i] for i in ids if i in stage])
    return rule.finalize(), peak, stage


def shape(matches):
    return sorted((m.group_key, m.claim, m.proposed_lane, tuple(e.id for e in m.events), tuple(m.notes))
                  for m in matches)


def batches_of(events, size):
    events = sorted(events, key=lambda e: (e.ts, e.id))
    return [events[i:i + size] for i in range(0, len(events), size)]


def browsing(hours, clients, per_hour):
    """Each client opens `per_hour` short external connections an hour, each on a new source port."""
    return [session(f"10.5.0.{c + 1}", 1024 + (hour * per_hour + k) % 60000, f"198.51.100.{k % 200 + 1}", 443,
                    T0 + timedelta(hours=hour, seconds=k * 3600 // per_hour))
            for hour in range(hours) for c in range(clients) for k in range(per_hour)]


def persistent_c2(seed=7):
    """One C2 socket (one community id) over two days: bursts of records every five minutes, separated by irregular
    sleeps of two to six hours. Returns the records and the number of sleeps."""
    rng, t, records, sleeps = random.Random(seed), T0, [], 0
    while t < T0 + timedelta(days=2):
        for _ in range(rng.randint(3, 8)):
            records.append(session("10.5.7.7", 51515, "203.0.113.66", 443, t, seconds=300, cid="1:c2"))
            t += timedelta(minutes=5)
        t += timedelta(hours=rng.uniform(2, 6))
        sleeps += 1
    return records, sleeps - 1


def both(cls, monkeypatch, events, size, hot=2):
    """The rule's findings with an unbounded hot set, then with `hot` (so nearly every state spills to disk)."""
    full, _peak, _stage = drive(cls(), batches_of(events, size))
    monkeypatch.setattr(cls, "HOT", hot)
    rule = cls()
    small, peak, _stage = drive(rule, batches_of(events, size), lambda r: max(
        len(store.hot) for store in vars(r).values() if isinstance(store, bounded.KeyedStore)))
    assert peak <= hot
    return full, small, rule


def test_persistent_c2_with_irregular_sleeps_is_one_long_lived_channel(monkeypatch):
    c2, sleeps = persistent_c2()
    full, small, rule = both(sessions.LongExternalConnection, monkeypatch, c2 + browsing(48, 4, 6), 50)
    assert shape(full) == shape(small)
    assert rule.conns.on_disk > 0                               # the channel's state went to disk and came back
    [m] = small
    span = (max(e.ts for e in c2) + timedelta(seconds=300) - c2[0].ts).total_seconds() / 60
    assert m.group_key == "1:c2" and f"spanning {span:.0f} minutes" in m.claim
    assert f"{len(c2)} session record(s)" in m.claim
    assert f"show {sleeps} gap(s) of more than 1 hour(s)" in m.claim and "same 5-tuple reused" in m.claim
    assert m.notes == [] or all("stretch" not in n for n in m.notes)


def test_beaconing_still_separates_a_reused_five_tuple(monkeypatch):
    reused = [session("10.5.8.8", 40404, "203.0.113.50", 8443, T0 + timedelta(hours=2 * k), seconds=30,
                      cid="1:reused") for k in range(20)]
    full, small, _rule = both(sessions.Beaconing, monkeypatch, reused + browsing(40, 3, 5), 25)
    assert shape(full) == shape(small)
    [m] = [m for m in small if m.group_key.startswith("10.5.8.8|")]
    assert "20 separate tcp connections" in m.claim and "starting every 7200 s" in m.claim
    assert [e.id for e in m.events] == [e.id for e in reused]          # each stretch cited by its first record
    # the long-connection rule reports the same identity once, over its whole span, and says it may be reused
    [long] = drive(sessions.LongExternalConnection(), batches_of(reused, 5))[0]
    assert "show 19 gap(s)" in long.claim and "spanning 2280 minutes" in long.claim


def test_a_record_bridging_two_stretches_merges_them_and_keeps_the_first_read_citation():
    early = session("10.5.8.9", 40405, "203.0.113.51", 8443, T0, cid="1:bridge")
    late = session("10.5.8.9", 40405, "203.0.113.51", 8443, T0 + timedelta(seconds=5000), cid="1:bridge")
    bridge = session("10.5.8.9", 40405, "203.0.113.51", 8443, T0 + timedelta(seconds=2500), cid="1:bridge")
    rule = sessions.Beaconing()
    _out, _peak, stage = drive(rule, [[late], [early], [bridge]])
    parts = rule.conns.peek("1:bridge")["parts"]
    assert len(parts) == 1 and parts[0][3] == late.id                 # read first, so it is the stretch's citation
    assert set(stage) == {late.id, early.id}                          # each record that opened a stretch is staged


def test_session_disk_budget_refuses_new_connections_and_says_so(monkeypatch):
    monkeypatch.setattr(bounded, "DISK_BUDGET", 1)
    monkeypatch.setattr(sessions.LongExternalConnection, "HOT", 1)
    rule = sessions.LongExternalConnection()
    drive(rule, [[session("10.5.0.1", 30000 + i, "203.0.113.50", 443, T0 + timedelta(minutes=i))] for i in range(6)])
    assert rule.capped == 4 and any("disk budget is spent" in r and "4 record(s) not evaluated" in r
                                    for r in rule.limit_reasons())


def test_popular_fingerprint_stops_collecting_once_it_cannot_be_rare():
    rule = sessions.RareClientFingerprint()
    batch = [session(f"10.6.{i // 250}.{i % 250 + 1}", 40000, "198.51.100.7", 443, T0 + timedelta(seconds=i),
                     tls__ja3="ja3-popular") for i in range(3000)]
    out, _peak, stage = drive(rule, [batch])
    p = rule.prints.peek(("JA3", "ja3-popular"))
    assert len(p["sources"]) <= 2 and len(p["conns"]) <= rule.MAX_CONNECTIONS + 1 and not p["events"]
    assert out == [] and len(stage) <= sessions.EXAMPLE_LIMIT


def test_rare_fingerprints_spill_to_disk_and_change_nothing(monkeypatch):
    records = [session(f"10.6.0.{i % 60 % 30 + 1}", 40000 + i, "198.51.100.7", 443, T0 + timedelta(seconds=i),
                       tls__ja3=f"ja3-{i % 60}", tls__ja4=f"ja4-{i % 7}") for i in range(300)]
    full, small, rule = both(sessions.RareClientFingerprint, monkeypatch, records, 37)
    assert full and shape(full) == shape(small) and rule.prints.on_disk > 0


def test_ssh_tag_pairs_spill_to_disk_and_change_nothing(monkeypatch):
    records = []
    for pair in range(12):
        client, server = f"10.8.0.{pair + 1}", f"10.8.1.{pair % 3 + 1}"
        for k in range(15):
            tags = ["ssh-reverse-shell"] if pair % 4 == 0 and k % 5 == 0 else ["other"]
            records.append(session(client, 50000 + k, server, 22, T0 + timedelta(minutes=pair + 13 * k),
                                   network__protocols=["ssh"], arkime__tags=tags, ssh__version=["SSH-2.0-x"]))
    full, small, rule = both(sessions.ArkimeSshReverseShellTag, monkeypatch, records, 11, hot=1)
    assert len(full) == 3 and shape(full) == shape(small) and rule.pairs.on_disk > 0
    assert all("12 other SSH connection(s)" in m.claim for m in small)


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
    out, _peak, stage = drive(rule, [batch])
    assert rule.staged and rule.retained_events() == []
    assert all(isinstance(i, str) for _key, state in rule.groups.items() for i in state["examples"].ids())
    assert len(out) == 1 and "at least 50 outbound TLS connection(s)" in out[0].claim
    assert len(stage) <= tls.EXAMPLE_LIMIT + 1          # the earliest records and the one ending the span (held)


@pytest.mark.parametrize("cls", [tls.SelfSignedCertificateOutbound, tls.ShortLivedOrNewCertificateOutbound])
def test_certificate_groups_spill_to_disk_and_change_nothing(monkeypatch, cls):
    records = [tls_record(f"10.7.0.{i % 9 + 1}", f"203.0.113.{i % 30 + 1}", T0 + timedelta(seconds=i), f"1:c{i}")
               for i in range(400)]
    for e in records:
        e.fields["tls.server.certificates"] = fv([{**e.get("tls.server.certificates")[0],
                                                   "not_after": "2024-01-10T00:00:00+00:00"}], "fixture")
    full, small, rule = both(cls, monkeypatch, records, 23, hot=1)
    assert len(full) == 30 and shape(full) == shape(small) and rule.groups.on_disk > 0


@pytest.mark.slow
def test_mission_scale_sessions_hold_a_bounded_hot_set_and_find_what_an_unbounded_run_finds(monkeypatch):
    c2, _sleeps = persistent_c2(seed=11)
    beacon = [session("10.5.8.8", 30000 + m % 30000, "203.0.113.50", 8443, T0 + timedelta(minutes=m))
              for m in range(72 * 60)]
    noise = browsing(72, 40, 30)                        # 86,400 short connections over three days
    for cls in (sessions.LongExternalConnection, sessions.Beaconing):
        full, small, rule = both(cls, monkeypatch, c2 + beacon + noise, 2000, hot=500)
        assert shape(full) == shape(small) and rule.conns.on_disk > 80_000
    beacons = [m for m in small if m.group_key.startswith("10.5.8.8|")]
    assert len(beacons) == 1 and "4320 separate tcp connections" in beacons[0].claim
