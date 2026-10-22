"""One installed internal-network definition drives every detector's address test.

A public-space site: the site is 198.51.100.0/24 plus 10.0.0.0/8, and the partner range 10.50.0.0/16 inside
it is carved out. Under that definition an "internal" public address is internal and the carved-out RFC 1918
partner range is external, through rules of several families; under the default the same records read the
other way. Documentation and private ranges only.
"""
import ipaddress
from datetime import UTC, datetime, timedelta

import pytest

from romulus.baseline.spec import SPEC_BY_ID, KeyContext, NotApplicable
from romulus.detect import correlation, dns, flows, host, netdef, sessions, tls
from romulus.detect.netdef import SiteNetworks
from romulus.evidence.normalize import normalize_hits
from romulus.evidence.typed import Outcome, RawRef, TypedEvent, fv
from tests.test_dns_rules import rec

SITE = SiteNetworks.from_lists(["198.51.100.0/24", "10.0.0.0/8"], ["10.50.0.0/16"])
INSIDE_PUBLIC, PARTNER, ELSEWHERE = "198.51.100.20", "10.50.0.9", "203.0.113.50"
T0 = datetime(2024, 11, 18, 14, 0, tzinfo=UTC)
_n = 0


def ev(family, outcome=Outcome.success, host_name="web01", ts=None, **fields):
    global _n
    _n += 1
    return TypedEvent(id=f"s{_n}", family=family, ts=ts or T0, host=host_name, outcome=outcome,
                      fields={k.replace("__", "."): fv(v, f"fixture{_n}:{k}") for k, v in fields.items()},
                      raw=[RawRef(target="fx", native_id=f"r{_n}")], normalizer="fixture")


def run(rule, events):
    stage = {}
    out = rule.consume(events)
    if rule.staged:
        stage.update({e.id: e for e in rule.drain_staged()})
        rule.bind_loader(lambda ids: [stage[i] for i in ids if i in stage])
    return out + rule.finalize()


@pytest.fixture
def configured():
    netdef.install(SITE)
    yield SITE


# ---- the definition reaches every address test -----------------------------------------------------------

def test_installing_a_definition_resets_the_address_caches():
    assert correlation.external(INSIDE_PUBLIC) and not correlation.external(PARTNER)    # cached under default
    netdef.install(SITE)
    assert not correlation.external(INSIDE_PUBLIC) and correlation.external(PARTNER)
    assert host.is_internal(ipaddress.ip_address(INSIDE_PUBLIC))
    assert flows.internal_address(INSIDE_PUBLIC) and not flows.internal_address(PARTNER)
    assert not sessions._public(INSIDE_PUBLIC) and sessions._public(PARTNER)
    netdef.install(SiteNetworks.default())
    assert correlation.external(INSIDE_PUBLIC) and not correlation.external(PARTNER)


def test_the_baseline_key_context_reads_the_installed_definition(configured):
    flow = ev("net_flow", source__ip=INSIDE_PUBLIC, destination__ip=PARTNER)
    keys = SPEC_BY_ID["bl.ext_dest"].keys(flow, KeyContext())
    assert {key.scope for key in keys} == {f"internal_ip:{INSIDE_PUBLIC}"}
    netdef.install(SiteNetworks.default())
    assert isinstance(SPEC_BY_ID["bl.ext_dest"].keys(flow, KeyContext()), NotApplicable)


# ---- a public-space site through rules of several families ------------------------------------------------

def _arkime(_id, src, dst, *, seconds=1900, dport=443):
    ms = int(T0.timestamp() * 1000)
    return {"_id": _id, "_index": "arkime_sessions3-241118", "_source": {
        "firstPacket": ms, "lastPacket": ms + seconds * 1000, "ipProtocol": 6, "node": "sensor",
        "network": {"community_id": f"1:{_id}="}, "protocol": ["tcp"],
        "source": {"ip": src, "port": 51000, "bytes": 900, "packets": 9},
        "destination": {"ip": dst, "port": dport, "bytes": 4000, "packets": 8}}}


def _sessions(*hits):
    events, skips, errors = normalize_hits(list(hits))
    assert errors == [] and skips == {}
    return events


def test_session_rule_long_boundary_connection_follows_the_site(configured):
    hits = [_arkime("a1", INSIDE_PUBLIC, PARTNER), _arkime("a2", INSIDE_PUBLIC, ELSEWHERE),
            _arkime("a3", INSIDE_PUBLIC, "198.51.100.30"), _arkime("a4", PARTNER, ELSEWHERE)]
    got = {m.group_key for m in run(sessions.LongExternalConnection(), _sessions(*hits))}
    assert got == {"1:a1=", "1:a2="}           # site to partner, site to internet; not east-west, not transit
    netdef.install(SiteNetworks.default())
    got = {m.group_key for m in run(sessions.LongExternalConnection(), _sessions(*hits))}
    assert got == {"1:a1=", "1:a4="}           # the default reads the site as public and the partner as ours


def test_dns_rule_zone_transfer_from_the_partner_range_to_a_site_server_is_high(configured):
    server = "198.51.100.53"
    question = rec("query", client=PARTNER, server=server, name="corp.example", qtype="AXFR", transport="tcp")
    answer = rec("answer", client=PARTNER, server=server, name="corp.example", qtype="AXFR", rcode="NOERROR",
                 ts=T0 + timedelta(milliseconds=3), flow=question.get("suricata.flow_id"), transport="tcp")
    [match] = run(dns.DnsZoneTransferOrAnyRequest(), [question, answer])
    assert match.proposed_lane == "high" and "outside the internal address ranges" in match.claim
    netdef.install(SiteNetworks.default())
    [match] = run(dns.DnsZoneTransferOrAnyRequest(), [question, answer])
    assert match.proposed_lane == "lead"       # under the default the partner client reads as internal


def _login(ip):
    return ev("auth", auth__service="sshd", source__ip=ip, user__name="admin")


def test_ssh_login_rule_reports_the_partner_range_and_not_the_site(configured):
    found = {m.group_key for m in run(host.SshLoginFromExternal(), [_login(PARTNER), _login(INSIDE_PUBLIC)])}
    assert found == {f"web01|admin|{PARTNER}"}
    netdef.install(SiteNetworks.default())
    found = {m.group_key for m in run(host.SshLoginFromExternal(), [_login(PARTNER), _login(INSIDE_PUBLIC)])}
    assert found == {f"web01|admin|{INSIDE_PUBLIC}"}


def _connect(ip):
    return ev("net_socket", socket__syscall="connect", process__executable="/usr/bin/bash", process__user="root",
              process__pid=4242, process__ppid=1, destination__ip=ip, destination__port=4444)


def test_correlation_rule_shell_connect_to_the_partner_range_is_external(configured):
    found = run(correlation.InterpreterExternalConnection(), [_connect(PARTNER), _connect(INSIDE_PUBLIC)])
    assert len(found) == 1 and PARTNER in found[0].claim and INSIDE_PUBLIC not in found[0].claim
    netdef.install(SiteNetworks.default())
    found = run(correlation.InterpreterExternalConnection(), [_connect(PARTNER), _connect(INSIDE_PUBLIC)])
    assert len(found) == 1 and INSIDE_PUBLIC in found[0].claim and PARTNER not in found[0].claim


def test_tls_outbound_follows_the_site(configured):
    to_partner = ev("tls_session", source__ip=INSIDE_PUBLIC, destination__ip=PARTNER)
    from_partner = ev("tls_session", source__ip=PARTNER, destination__ip=INSIDE_PUBLIC)
    assert tls.outbound(to_partner) is True and tls.outbound(from_partner) is False
    netdef.install(SiteNetworks.default())
    assert tls.outbound(to_partner) is False


def test_flow_rule_horizontal_sweep_of_site_addresses_uses_the_internal_threshold(configured):
    # 25 site addresses within five minutes, all answering: internal sweep threshold 20, external 50 and mostly silent
    def flow(i):
        return ev("net_flow", host_name="sensor", ts=T0 + timedelta(seconds=i), source__ip="198.51.100.5",
                  source__port=40000 + i, destination__ip=f"198.51.100.{100 + i}", destination__port=22,
                  network__transport="tcp", flow__start=(T0 + timedelta(seconds=i)).isoformat(),
                  flow__pkts_toclient=3, suricata__flow_id=i, observer__type="suricata", event__kind="flow")
    events = [flow(i) for i in range(25)]
    found = run(flows.HorizontalSweep(), events)
    assert [m.group_key for m in found] == ["198.51.100.5|tcp|22|internal"]
    netdef.install(SiteNetworks.default())
    assert run(flows.HorizontalSweep(), events) == []
