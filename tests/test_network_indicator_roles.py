"""Domain indicators over the shared DNS/TLS contract: every question name, answer names and targets, and SNI."""
import pytest

from romulus.detect.indicators import IndicatorMatch, load_indicators
from romulus.evidence.normalize import normalize_hits
from tests.test_network_normalizers import arkime, dns_obj, eve

LIST = """schema_version: 1
indicators:
  - {id: t.dom, kind: domain, values: [evil.example], label: bad domain, severity: high, lane: lead}
"""


@pytest.fixture()
def rule(tmp_path):
    (tmp_path / "list.yaml").write_text(LIST, encoding="utf-8")
    return IndicatorMatch(load_indicators(tmp_path))


def events(*hits):
    evs, skips, errors = normalize_hits(list(hits))
    assert errors == [] and skips == {}, (errors, skips)
    return evs


def run(rule, evs):
    rule.consume(evs)
    return rule.finalize()


@pytest.mark.parametrize("dns", [[dns_obj(["benign.example"]), dns_obj(["c2.evil.example"])],
                                 {"host": ["benign.example", "c2.evil.example"], "qt": ["A"]}])
def test_listed_name_inside_a_multi_name_arkime_session_matches(rule, dns):
    e = events(arkime(dns=dns))[0]
    assert e.get("dns.question.name") is None
    m = run(rule, [e])
    assert len(m) == 1 and "name 'c2.evil.example'" in m[0].claim
    assert m[0].predicate[0].field == "dns.question.names"


def test_single_name_session_is_counted_once_not_per_field(rule):
    m = run(rule, events(arkime(dns=[dns_obj(["evil.example"])])))
    assert len(m) == 1 and m[0].claim.startswith("1 net_session record(s)")


def test_multi_name_session_gets_a_domain_entity_per_name():
    e = events(arkime(dns=[dns_obj(["b.example"]), dns_obj(["A.example"])]))[0]
    assert {v for k, v, _r in e.entities() if k == "domain"} == {"a.example", "b.example"}


def test_cname_target_in_a_v1_answer_matches_as_an_answer(rule):
    hit = eve("v1", {"event_type": "dns", "dns": {"type": "answer", "rrname": "www.shop.example",
                                                  "rrtype": "CNAME", "ttl": 20, "rdata": "edge.evil.example"}})
    m = run(rule, events(hit))
    assert len(m) == 1 and "a DNS answer names 'edge.evil.example'" in m[0].claim
    assert m[0].predicate[0].field == "dns.answers"


def test_answer_owner_name_matches_and_address_data_is_not_a_name(rule):
    hit = eve("v1b", {"event_type": "dns", "dns": {"type": "answer", "rrname": "evil.example", "rrtype": "A",
                                                   "ttl": 20, "rdata": "192.0.2.1"}})
    m = run(rule, events(hit))
    assert len(m) == 1 and "a DNS answer names 'evil.example'" in m[0].claim


def test_txt_answer_text_is_not_read_as_a_name(rule):
    hit = eve("v2t", {"event_type": "dns", "dns": {"version": 2, "type": "answer", "rrname": "ok.example",
                                                   "rrtype": "TXT",
                                                   "answers": [{"rrname": "ok.example", "rrtype": "TXT",
                                                                "rdata": "evil.example"}]}})
    assert run(rule, events(hit)) == []


def test_plain_lookup_with_an_a_answer_is_one_finding(rule):
    ark = arkime(dns=[dns_obj(["evil.example"], answers=[{"type": "A", "class": "IN", "ttl": 30,
                                                          "name": "evil.example", "ip": "192.0.2.9"}])])
    suri = eve("v2a", {"event_type": "dns", "dns": {"version": 2, "type": "answer", "rrname": "evil.example",
                                                    "rrtype": "A",
                                                    "answers": [{"rrname": "evil.example", "rrtype": "A",
                                                                 "rdata": "192.0.2.9"}]}})
    for hit in (ark, suri):
        r = IndicatorMatch(rule.set)
        m = run(r, events(hit))
        assert [x.group_key.split("|")[1] for x in m] == ["domain"]


def test_cname_target_beside_the_question_is_still_an_answer_match(rule):
    hit = eve("v2c", {"event_type": "dns", "dns": {"version": 2, "type": "answer", "rrname": "www.shop.example",
                                                   "rrtype": "A",
                                                   "answers": [{"rrname": "www.shop.example", "rrtype": "CNAME",
                                                                "rdata": "edge.evil.example"}]}})
    m = run(rule, events(hit))
    assert len(m) == 1 and "a DNS answer names 'edge.evil.example'" in m[0].claim


def test_sni_matches_with_its_own_wording(rule):
    hit = eve("s1", {"event_type": "tls", "tls": {"sni": "login.evil.example", "version": "TLS 1.3"}})
    m = run(rule, events(hit))
    assert len(m) == 1 and "the TLS SNI names 'login.evil.example'" in m[0].claim
    assert m[0].predicate[0].field == "tls.client.server_name"


def test_lookalike_names_do_not_match(rule):
    hits = [eve("n1", {"event_type": "tls", "tls": {"sni": "notevil.example"}}),
            eve("n2", {"event_type": "dns", "dns": {"type": "query", "rrname": "evil.example.org", "rrtype": "A"}})]
    assert run(rule, events(*hits)) == []
