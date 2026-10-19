"""Host sockets from auditd, and their correlation with network-sensor records."""
import json
from datetime import UTC, datetime, timedelta

import pytest

from romulus.decide.policy import decide
from romulus.detect.correlation import InterpreterExternalConnection, ProcessNetworkLink
from romulus.evidence.auditd import AuditParseError, parse_sockaddr
from romulus.evidence.normalize import normalize_hits
from romulus.evidence.typed import Outcome
from romulus.hunt import sweep as sw
from romulus.sources.models import Completeness, SearchOutcome, Window
from romulus.store.db import make_engine, migrate
from romulus.store.repo import Repo

T0 = 1731940000.100                                   # 2024-11-18T14:26:40.100Z
TS = "2024-11-18T14:26:40.100Z"
ATTACKER, C2_PORT = "192.0.2.174", 4444               # documentation range stands in for an external peer
SADDR_C2 = "0200115CC00002AE0000000000000000"          # AF_INET, port 4444, 192.0.2.174


def syscall(serial=500, *, nr=42, arch="c000003e", success="yes", exit_code="0", exe="/usr/bin/perl",
            comm="perl", uid="33", user="www-data"):
    return (f"type=SYSCALL msg=audit({T0}:{serial}): arch={arch} syscall={nr} success={success} exit={exit_code} "
            f"a0=3 a1=7ffc a2=10 a3=0 items=0 ppid=100 pid=200 auid=4294967295 uid={uid} gid={uid} euid={uid} "
            f"tty=(none) ses=4294967295 comm=\"{comm}\" exe=\"{exe}\" subj==unconfined "
            f"key=\"T1043_Commonly_Used_Port\"\x1dARCH=x86_64 SYSCALL=connect AUID=\"unset\" UID=\"{user}\" "
            f"EUID=\"{user}\"")


def sockaddr(serial=500, saddr=SADDR_C2):
    return f"type=SOCKADDR msg=audit({T0}:{serial}): saddr={saddr}"


def audit_hit(_id, raw, host="videoserver", ts=TS):
    return {"_id": _id, "_index": "romulus-host-logs", "_source": {
        "@timestamp": ts, "message": raw, "host": {"name": host},
        "event": {"dataset": "linux.audit", "original": raw}}}


def eve_hit(_id, eve, ts=TS):
    raw = json.dumps(eve)
    return {"_id": _id, "_index": "romulus-network-logs", "_source": {
        "@timestamp": ts, "host": {"name": "inetfw"},
        "event": {"dataset": f"suricata.eve.{eve['event_type']}", "original": raw}}}


def flow(_id="f1", *, src="198.51.100.10", start="2024-11-18T14:26:40.050000+0000", cid="1:abc=",
         end="2024-11-18T14:59:00.000000+0000"):
    return eve_hit(_id, {"timestamp": end, "event_type": "flow", "src_ip": src, "src_port": 51000,
                         "dest_ip": ATTACKER, "dest_port": C2_PORT, "proto": "TCP", "community_id": cid,
                         "flow": {"start": start, "end": end, "bytes_toserver": 9000, "bytes_toclient": 120000}},
                   ts="2024-11-18T14:59:00Z")


def alert(_id="a1", *, severity=1, cid="1:abc=", ts="2024-11-18T14:31:00.000000+0000"):
    return eve_hit(_id, {"timestamp": ts, "event_type": "alert", "src_ip": "198.51.100.10", "src_port": 51000,
                         "dest_ip": ATTACKER, "dest_port": C2_PORT, "proto": "TCP", "community_id": cid,
                         "alert": {"signature": "ET POLICY Meterpreter-like reverse shell", "signature_id": 1,
                                   "category": "Trojan", "severity": severity}},
                   ts="2024-11-18T14:31:00Z")


# ---- sockaddr --------------------------------------------------------------------------------

def test_sockaddr_decodes_inet_inet6_and_mapped_addresses():
    a = parse_sockaddr(SADDR_C2)
    assert (a.family, a.ip, a.port) == ("inet", ATTACKER, 4444)
    v6 = parse_sockaddr("0A000050" + "00000000" + "20010DB8000000000000000000000001" + "00000000")
    assert (v6.family, v6.ip, v6.port) == ("inet6", "2001:db8::1", 80)
    mapped = parse_sockaddr("0A0001BB" + "00000000" + "00000000000000000000FFFFC0000201" + "00000000")
    assert (mapped.ip, mapped.port) == ("192.0.2.1", 443)
    local = parse_sockaddr("01002F72756E00")
    assert (local.family, local.ip) == ("local", None)


@pytest.mark.parametrize("bad", ["", "zz", "0200", "0A00005000"])
def test_malformed_sockaddr_is_an_error(bad):
    with pytest.raises(AuditParseError):
        parse_sockaddr(bad)


# ---- normalization ---------------------------------------------------------------------------

def test_connect_group_becomes_a_typed_net_socket_event():
    events, skips, errors = normalize_hits([audit_hit("s1", syscall()), audit_hit("k1", sockaddr())])
    assert errors == [] and skips == {} and len(events) == 1
    e = events[0]
    assert e.family == "net_socket" and e.outcome == Outcome.success
    assert (e.get("socket.syscall"), e.get("socket.family")) == ("connect", "inet")
    assert (e.get("destination.ip"), e.get("destination.port")) == (ATTACKER, C2_PORT)
    assert e.get("process.executable") == "/usr/bin/perl" and e.get("process.user") == "www-data"
    assert e.get("process.pid") == 200 and e.get("audit.key") == "T1043_Commonly_Used_Port"
    assert e.fields["destination.ip"].origin.startswith("k1:")
    assert {r.native_id for r in e.raw} == {"s1", "k1"}
    assert ("ip", ATTACKER, "dst") in e.entities() and ("host", "videoserver", "host") in e.entities()


def test_einprogress_connect_is_unknown_not_failed_and_other_failures_fail():
    started, _, _ = normalize_hits([audit_hit("s1", syscall(success="no", exit_code="-115")),
                                    audit_hit("k1", sockaddr())])
    assert started[0].outcome == Outcome.unknown and any("EINPROGRESS" in c for c in started[0].caveats)
    refused, _, _ = normalize_hits([audit_hit("s1", syscall(success="no", exit_code="-111")),
                                    audit_hit("k1", sockaddr())])
    assert refused[0].outcome == Outcome.failure


def test_non_ip_sockets_and_non_socket_syscalls_are_counted_skips():
    events, skips, errors = normalize_hits([
        audit_hit("s1", syscall(serial=1)), audit_hit("k1", sockaddr(serial=1, saddr="01002F72756E00")),
        audit_hit("s2", syscall(serial=2, nr=0)),                      # read(): not a socket call
        audit_hit("s3", syscall(serial=3, arch="40000003", nr=102)),   # i386 socketcall: not decoded
    ])
    assert events == [] and errors == []
    assert sum(skips.values()) == 3 and any("non-IP socket family (local)" in k for k in skips)


def test_connect_without_sockaddr_keeps_an_explicit_unknown_destination():
    events, _, errors = normalize_hits([audit_hit("s1", syscall())])
    assert errors == [] and events[0].family == "net_socket"
    assert not events[0].has("destination.ip") and events[0].caveats
    rule = InterpreterExternalConnection()
    assert rule.consume(events) == [] and rule.missing_required == 1     # unresolved, never a no-match


def test_duplicate_sockaddr_in_one_group_is_ambiguous_error():
    _, _, errors = normalize_hits([audit_hit("s1", syscall()), audit_hit("k1", sockaddr()),
                                   audit_hit("k2", sockaddr(saddr="0200005001020304"))])
    assert errors and "ambiguous" in errors[0][1]


# ---- host rule -------------------------------------------------------------------------------

def _socket_to(saddr, **kw):
    events, _, _ = normalize_hits([audit_hit("s1", syscall(**kw)), audit_hit("k1", sockaddr(saddr=saddr))])
    return events[0]


@pytest.mark.parametrize("kw, lane", [
    ({}, "high"),                                                              # web-service interpreter
    ({"exe": "/usr/bin/bash", "comm": "bash", "uid": "0", "user": "root"}, "high"),   # shell
    ({"exe": "/usr/bin/ncat", "comm": "ncat", "uid": "0", "user": "root"}, "high"),   # relay tool
    ({"exe": "/usr/bin/python3.12", "comm": "python3", "uid": "1000", "user": "alice"}, "lead"),
])
def test_notable_process_external_connect_matches_with_kernel_identity(kw, lane):
    e = _socket_to(SADDR_C2, **kw)
    matches = InterpreterExternalConnection().consume([e])
    assert len(matches) == 1 and matches[0].proposed_lane == lane
    assert "connect()" in matches[0].claim and "the call succeeded" in matches[0].claim


@pytest.mark.parametrize("saddr, kw", [
    ("0200115C0A000005" + "0" * 16, {}),                                        # internal destination
    (SADDR_C2, {"exe": "/usr/sbin/sshd", "comm": "sshd", "uid": "0", "user": "root"}),   # ordinary daemon
    ("0200115C7F000001" + "0" * 16, {"exe": "/usr/bin/bash", "comm": "bash"}),  # loopback
])
def test_internal_or_ordinary_connections_do_not_match(saddr, kw):
    assert InterpreterExternalConnection().consume([_socket_to(saddr, **kw)]) == []


def test_failed_connect_is_worded_as_failed_and_lowered_by_policy():
    e = _socket_to(SADDR_C2, success="no", exit_code="-111")
    m = InterpreterExternalConnection().consume([e])[0]
    assert "the call failed" in m.claim
    assert decide(m, "h1").lane == "lead"


# ---- correlation -----------------------------------------------------------------------------

def _network(*hits):
    events, _, errors = normalize_hits(list(hits))
    assert errors == []
    return events


@pytest.mark.parametrize("network_first", [False, True])
def test_alert_on_joined_flow_is_attributed_to_the_process_in_either_order(network_first):
    host = [_socket_to(SADDR_C2, exe="/usr/sbin/sshd", comm="sshd", uid="0", user="root")]
    net = _network(flow(), alert())
    rule = ProcessNetworkLink()
    for batch in ([net, host] if network_first else [host, net]):
        rule.consume(batch)
    retained = {e.id for e in rule.retained_events()}
    matches = rule.finalize()
    assert len(matches) == 1
    m = matches[0]
    assert m.claim_type == "correlated_observation" and m.proposed_lane == "high"
    assert "inferred" in m.claim and "not itself observed" in m.claim
    assert "Meterpreter-like" in m.claim and "198.51.100.10" in m.claim
    assert {e.family for e in m.events} == {"net_socket", "net_flow", "net_alert"}
    assert all(e.id in retained for e in m.events)                 # every citation has a retained raw copy
    assert any("inferred, not an asset record" in n for n in m.notes)


def test_notable_process_gets_its_network_evidence_without_an_alert():
    rule = ProcessNetworkLink()
    rule.consume([_socket_to(SADDR_C2)] + _network(flow()))
    matches = rule.finalize()
    assert len(matches) == 1 and matches[0].proposed_lane == "high"
    assert "web-service account" in matches[0].claim


def test_ordinary_process_without_alert_is_not_published():
    rule = ProcessNetworkLink()
    rule.consume([_socket_to(SADDR_C2, exe="/usr/sbin/sshd", comm="sshd", uid="0", user="root")]
                 + _network(flow()))
    assert rule.finalize() == []


def test_flow_outside_the_join_window_is_not_linked():
    rule = ProcessNetworkLink()
    rule.consume([_socket_to(SADDR_C2)] + _network(flow(start="2024-11-18T14:27:10.000000+0000")))
    assert rule.finalize() == []


def test_two_matching_source_addresses_are_called_ambiguous():
    rule = ProcessNetworkLink()
    rule.consume([_socket_to(SADDR_C2)] + _network(flow("f1"), flow("f2", src="198.51.100.11", cid="1:def=")))
    m = rule.finalize()[0]
    assert "ambiguous" in m.claim and "198.51.100.10, 198.51.100.11" in m.claim


def test_low_severity_alert_with_ordinary_process_is_a_lead():
    rule = ProcessNetworkLink()
    rule.consume([_socket_to(SADDR_C2, exe="/usr/sbin/sshd", comm="sshd", uid="0", user="root")]
                 + _network(flow(), alert(severity=2)))
    assert rule.finalize()[0].proposed_lane == "lead"


# ---- end to end through the sweep: citations resolve whichever target is swept first -----------

class _Client:
    version = "test"

    class settings:
        es_flavor = "elasticsearch"


def _outcome(intent, records):
    now = datetime.now(UTC)
    return SearchOutcome(target=intent.target, fingerprint="f", started_at=now, ended_at=now,
                         completeness=Completeness.complete, total=len(records), total_relation="eq",
                         returned=len(records), records=records)


@pytest.mark.parametrize("order", [("romulus-host-logs", "romulus-network-logs"),
                                   ("romulus-network-logs", "romulus-host-logs")])
def test_correlated_candidate_citations_are_all_retained(monkeypatch, order):
    from romulus.report import manifest as rm
    by_target = {"romulus-host-logs": [audit_hit("s1", syscall()), audit_hit("k1", sockaddr())],
                 "romulus-network-logs": [flow(), alert()]}
    monkeypatch.setattr(sw, "execute", lambda client, intent, contract: _outcome(intent, by_target[intent.target]))
    engine = make_engine(":memory:")
    migrate(engine)
    repo = Repo(engine)
    repo.create_hunt("h1", {"targets": list(order)}, "d", "t")
    start = datetime(2024, 11, 18, 14, 0, tzinfo=UTC)
    w = Window(start=start, end=start + timedelta(hours=1))
    s = sw.Sweep(repo, _Client(), "h1", w, {t: None for t in order})
    for target in order:
        s.run_partition(target, None, [], w, est=2)
    s.finalize()
    linked = [c for c in repo.candidates("h1") if c["rule_id"] == "corr.process_network_link"]
    direct = [c for c in repo.candidates("h1") if c["rule_id"] == "host.interpreter_external_connection"]
    assert len(linked) == 1 and len(direct) == 1
    cites = rm._citations(repo, linked[0])
    assert len(cites) == 4 and all(c["status"] == "retained" for c in cites), cites
    window = {c["rule_id"]: c["state"] for c in repo.rule_cells("h1") if c["target"] == "*"}
    assert window["corr.process_network_link"] == "matched"
