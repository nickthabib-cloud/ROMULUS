"""Certificate rules over outbound TLS sessions: self-issued, short-lived and recently issued certificates."""
import json
from datetime import timedelta

import pytest

from romulus.detect.tls import SelfSignedCertificateOutbound, ShortLivedOrNewCertificateOutbound
from romulus.evidence.normalize import normalize_hits
from tests.test_network_normalizers import DAY_MS, INTERMEDIATE, LEAF, MS, ROOT, SELF_SIGNED, T0, arkime, eve


def events(*hits):
    evs, skips, errors = normalize_hits(list(hits))
    assert errors == [] and skips == {}, (errors, skips)
    return evs


def run(rule, *batches):
    for batch in batches:
        rule.consume(batch)
    return rule.finalize()


def suri_tls(_id="t1", *, subject="CN=c2.example, O=Acme", issuer="CN=c2.example, O=Acme",
             notbefore="2024-10-01T00:00:00", notafter="2025-10-01T00:00:00", src="172.17.100.121",
             dst="192.0.2.174", ts="2024-11-18T14:26:40.100000+0000", **extra):
    tls = {"subject": subject, "issuerdn": issuer, "notbefore": notbefore, "notafter": notafter,
           "fingerprint": f"fp:{_id}", "version": "TLS 1.2", **extra}
    return eve(_id, {"event_type": "tls", "src_ip": src, "dest_ip": dst, "timestamp": ts,
                     "community_id": f"1:{_id}=", "tls": {k: v for k, v in tls.items() if v is not None}})


# ---- self-issued -----------------------------------------------------------------------------------------------

def test_self_signed_certificate_on_an_outbound_suricata_session_is_a_lead():
    rule = SelfSignedCertificateOutbound()
    m = run(rule, events(suri_tls()))
    assert len(m) == 1 and m[0].proposed_lane == "lead" and m[0].severity == "medium"
    assert m[0].confidence == "high"                      # whole distinguished names were compared
    assert "subject name equals its issuer name" in m[0].claim and "signature was not verified" in m[0].claim
    assert "172.17.100.121" in m[0].claim and "192.0.2.174" in m[0].claim
    assert [p.field for p in m[0].predicate] == ["tls.server.certificates", "source.ip", "destination.ip"]
    assert rule.evaluated == 1 and rule.missing_required == 0


def test_self_signed_certificate_from_arkime_compares_cn_and_o():
    m = run(SelfSignedCertificateOutbound(), events(arkime(cert=[SELF_SIGNED])))
    assert len(m) == 1 and m[0].confidence == "medium" and "Compared by CN and O" in m[0].claim


def test_one_certificate_seen_by_both_sensors_is_one_finding():
    ark = arkime(cert=[{**SELF_SIGNED, "hash": "fp:t1"}], network={"community_id": "1:t1="})
    m = run(SelfSignedCertificateOutbound(), events(ark, suri_tls()))
    assert len(m) == 1 and "2 record(s) of 1 outbound TLS connection(s)" in m[0].claim


def test_root_ca_sent_with_its_chain_is_not_self_signed():
    rule = SelfSignedCertificateOutbound()
    assert run(rule, events(arkime(cert=[ROOT, LEAF, INTERMEDIATE]))) == []
    assert rule.evaluated == 1 and rule.missing_required == 0


@pytest.mark.parametrize("kw", [{"issuer": "CN=R3, O=Let's Encrypt"},
                                {"subject": "CN=svc, O=Acme, OU=Web", "issuer": "CN=svc, O=Acme, OU=CA"}])
def test_ca_issued_or_near_name_certificates_do_not_match(kw):
    assert run(SelfSignedCertificateOutbound(), events(suri_tls(**kw))) == []


@pytest.mark.parametrize("kw", [{"src": "192.0.2.10", "dst": "192.0.2.174"},   # public to public
                                {"src": "172.17.100.121", "dst": "10.0.0.5"},  # internal to internal
                                {"src": "192.0.2.174", "dst": "172.17.100.121"}])  # inbound
def test_non_outbound_sessions_are_not_matched(kw):
    rule = SelfSignedCertificateOutbound()
    assert run(rule, events(suri_tls(**kw))) == []
    assert rule.missing_required == 0


def test_tls13_session_without_certificate_is_missing_not_a_negative():
    rule = SelfSignedCertificateOutbound()
    tls13 = eve("t9", {"event_type": "tls", "tls": {"sni": "x.example", "version": "TLS 1.3"}})
    assert run(rule, events(tls13, arkime(_id="s9", tls={"version": ["TLSv1.3"]}))) == []
    assert rule.evaluated == 0 and rule.missing_required == 2


def test_malformed_certificate_block_is_missing():
    rule = SelfSignedCertificateOutbound()
    assert run(rule, events(arkime(cert="garbage"))) == []
    assert rule.missing_required == 1


def test_certificate_without_names_is_missing():
    rule = SelfSignedCertificateOutbound()
    assert run(rule, events(arkime(cert=[{"hash": "aa", "notBefore": MS, "notAfter": MS + DAY_MS}]))) == []
    assert rule.missing_required == 1


def test_arkime_continuation_and_non_tls_records_are_not_counted_missing():
    rule = SelfSignedCertificateOutbound()
    later = arkime(_id="s2", rootId="s1")                    # handshake lives on s1
    plain = arkime(_id="s3", protocol=["tcp"])               # not a TLS session
    assert run(rule, events(later, plain)) == []
    assert rule.missing_required == 0 and rule.evaluated == 2


def test_record_without_addresses_is_missing():
    rule = SelfSignedCertificateOutbound()
    hit = suri_tls()
    raw = json.loads(hit["_source"]["event"]["original"])
    del raw["dest_ip"]
    hit["_source"]["event"]["original"] = json.dumps(raw)
    assert run(rule, events(hit)) == [] and rule.missing_required == 1


def test_mention_of_a_self_signed_name_elsewhere_is_not_a_match():
    """The same name in SNI and alt names, with a CA-issued certificate, is not a self-issued certificate."""
    m = run(SelfSignedCertificateOutbound(), events(suri_tls(issuer="CN=c2.example CA, O=Acme", sni="c2.example")))
    assert m == []


# ---- short-lived and recently issued ---------------------------------------------------------------------------

def test_short_lived_certificate_matches():
    m = run(ShortLivedOrNewCertificateOutbound(),
            events(suri_tls(issuer="CN=R3, O=Let's Encrypt", notbefore="2024-11-10T00:00:00",
                            notafter="2024-11-16T23:59:59", ts="2024-11-18T14:26:40.100000+0000")))
    # expired by the session too, but the rule only claims what it checks
    assert len(m) == 1 and "validity period is 7.0 days (at most 14)" in m[0].claim


def test_recently_issued_certificate_matches_with_its_age():
    m = run(ShortLivedOrNewCertificateOutbound(),
            events(arkime(cert=[{**LEAF, "notBefore": MS - 6 * 3_600_000, "notAfter": MS + 89 * DAY_MS}])))
    assert len(m) == 1 and "notBefore is 6.0 hours before the first such session" in m[0].claim
    assert "validity period" not in m[0].claim


def test_certificate_not_yet_valid_at_the_session_matches():
    m = run(ShortLivedOrNewCertificateOutbound(),
            events(suri_tls(issuer="CN=R3", notbefore="2024-11-18T16:26:40", notafter="2025-02-16T16:26:40")))
    assert len(m) == 1 and "not yet valid when first presented (2.0 hours before its notBefore)" in m[0].claim


def test_boundaries_are_exclusive_for_age_and_inclusive_for_validity():
    rule = ShortLivedOrNewCertificateOutbound()
    exactly_two_days = suri_tls("b1", issuer="CN=R3", notbefore="2024-11-16T14:26:40.100000",
                                notafter="2025-02-14T14:26:40")
    fourteen_days = suri_tls("b2", issuer="CN=R3", notbefore="2024-11-01T00:00:00", notafter="2024-11-15T00:00:00")
    fifteen_days = suri_tls("b3", issuer="CN=R3", notbefore="2024-11-01T00:00:00", notafter="2024-11-16T00:00:00")
    m = run(rule, events(exactly_two_days, fourteen_days, fifteen_days))
    assert [g.group_key.split("|")[0] for g in m] == ["fp:b2"]


def test_ordinary_ca_certificate_does_not_match():
    rule = ShortLivedOrNewCertificateOutbound()
    assert run(rule, events(arkime(cert=[ROOT, LEAF, INTERMEDIATE]))) == []
    assert rule.evaluated == 1 and rule.missing_required == 0


def test_short_lived_intermediate_is_not_the_server_certificate():
    short_ca = {**INTERMEDIATE, "notBefore": MS - 30 * DAY_MS, "notAfter": MS - 20 * DAY_MS}
    assert run(ShortLivedOrNewCertificateOutbound(), events(arkime(cert=[LEAF, short_ca]))) == []


def test_validity_from_arkime_valid_days_when_bounds_are_missing():
    rule = ShortLivedOrNewCertificateOutbound()
    m = run(rule, events(arkime(cert=[{**LEAF, "notBefore": None, "notAfter": None, "validDays": 7}])))
    assert len(m) == 1 and "validity period is 7.0 days" in m[0].claim


def test_missing_validity_bounds_are_missing_not_a_negative():
    rule = ShortLivedOrNewCertificateOutbound()
    assert run(rule, events(suri_tls(notbefore=None, notafter=None, issuer="CN=R3"))) == []
    assert rule.missing_required == 1 and rule.evaluated == 0


def test_rules_are_deterministic_across_reading_order():
    hits = [suri_tls(f"d{i}", ts=(T0 + timedelta(minutes=i)).isoformat(), fingerprint="same") for i in range(25)]
    a = run(SelfSignedCertificateOutbound(), events(*hits))
    b = run(SelfSignedCertificateOutbound(), events(*reversed(hits)))
    assert [(m.group_key, m.claim, [e.id for e in m.events]) for m in a] == \
        [(m.group_key, m.claim, [e.id for e in m.events]) for m in b]


def test_same_certificate_to_many_sources_is_one_group_per_server():
    hits = [suri_tls(f"g{i}", src=f"172.17.100.{10 + i}", fingerprint="same") for i in range(3)]
    m = run(SelfSignedCertificateOutbound(), events(*hits))
    assert len(m) == 1 and "3 outbound TLS connection(s) from 172.17.100.10, 172.17.100.11, 172.17.100.12" in m[0].claim


# ---- through the sweep -----------------------------------------------------------------------------------------

class _Client:
    version = "test"

    class settings:
        es_flavor = "elasticsearch"


def test_certificate_finding_survives_the_sweep_and_tls13_makes_the_cell_partial(monkeypatch):
    from datetime import UTC, datetime

    from romulus.hunt import sweep as sw
    from romulus.report import manifest as rm
    from romulus.sources.models import Completeness, SearchOutcome, Window
    from romulus.store.db import make_engine, migrate
    from romulus.store.repo import Repo
    from tests.test_network_normalizers import INDEX

    records = [arkime("c1", cert=[SELF_SIGNED]),
               arkime("c2", tls={"version": ["TLSv1.3"]}, network={"community_id": "1:c2="})]
    monkeypatch.setattr(sw, "execute", lambda client, intent, contract: SearchOutcome(
        target=intent.target, fingerprint="f", started_at=datetime.now(UTC), ended_at=datetime.now(UTC),
        completeness=Completeness.complete, total=len(records), total_relation="eq", returned=len(records),
        records=records))
    engine = make_engine(":memory:")
    migrate(engine)
    repo = Repo(engine)
    repo.create_hunt("h1", {"targets": [INDEX]}, "d", "t")
    w = Window(start=T0 - timedelta(hours=1), end=T0 + timedelta(hours=1))
    s = sw.Sweep(repo, _Client(), "h1", w, {INDEX: None})
    s.run_partition(INDEX, None, [], w, est=2)
    s.finalize()
    found = [c for c in repo.candidates("h1") if c["rule_id"] == SelfSignedCertificateOutbound.id]
    assert len(found) == 1
    cites = rm._citations(repo, found[0])
    assert len(cites) == 1 and all(c["status"] == "retained" for c in cites), cites
    cells = [c for c in repo.rule_cells("h1") if c["rule_id"] == SelfSignedCertificateOutbound.id]
    assert {c["state"] for c in cells if c["target"] != "*"} == {"evaluated_partial"}   # the TLS 1.3 record
    assert [c["state"] for c in cells if c["target"] == "*"] == ["match_on_partial"]
