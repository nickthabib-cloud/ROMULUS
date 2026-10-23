"""Host sockets from auditd, and their correlation with network-sensor records."""
import json
from datetime import UTC, datetime, timedelta

import pytest

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
SSHD = {"exe": "/usr/sbin/sshd", "comm": "sshd", "uid": "0", "user": "root"}


def syscall(serial=500, *, nr=42, arch="c000003e", success="yes", exit_code="0", exe="/usr/bin/perl",
            comm="perl", uid="33", user="www-data", t0=T0, pid=200, session_id="4294967295"):
    return (f"type=SYSCALL msg=audit({t0:.3f}:{serial}): arch={arch} syscall={nr} success={success} "
            f"exit={exit_code} a0=3 a1=7ffc a2=10 a3=0 items=0 ppid=100 pid={pid} auid=4294967295 uid={uid} "
            f"gid={uid} euid={uid} tty=(none) ses={session_id} comm=\"{comm}\" exe=\"{exe}\" subj==unconfined "
            f"key=\"T1043_Commonly_Used_Port\"\x1dARCH=x86_64 SYSCALL=connect AUID=\"unset\" UID=\"{user}\" "
            f"EUID=\"{user}\"")


def sockaddr(serial=500, saddr=SADDR_C2, t0=T0):
    return f"type=SOCKADDR msg=audit({t0:.3f}:{serial}): saddr={saddr}"


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
         end="2024-11-18T14:59:00.000000+0000", dst=ATTACKER, dport=C2_PORT, sport=51000, event_type="flow"):
    key = "netflow" if event_type == "netflow" else "flow"
    return eve_hit(_id, {"timestamp": end, "event_type": event_type, "src_ip": src, "src_port": sport,
                         "dest_ip": dst, "dest_port": dport, "proto": "TCP", "community_id": cid,
                         key: {"start": start, "end": end, "bytes": 9000, "pkts": 30}},
                   ts="2024-11-18T14:59:00Z")


def alert(_id="a1", *, severity=1, cid="1:abc=", ts="2024-11-18T14:31:00.000000+0000", category="Trojan",
          src="198.51.100.10"):
    return eve_hit(_id, {"timestamp": ts, "event_type": "alert", "src_ip": src, "src_port": 51000,
                         "dest_ip": ATTACKER, "dest_port": C2_PORT, "proto": "TCP", "community_id": cid,
                         "alert": {"signature": "ET POLICY Meterpreter-like reverse shell", "signature_id": 1,
                                   "category": category, "severity": severity}},
                   ts=ts[:19] + "Z")


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
    assert not e.has("process.session_id")


def test_connect_group_keeps_set_audit_session_id():
    events, _, errors = normalize_hits([
        audit_hit("s1", syscall(session_id="42")), audit_hit("k1", sockaddr()),
    ])

    assert errors == []
    assert events[0].get("process.session_id") == 42


def test_socket_time_is_the_audit_header_epoch():
    e = normalize_hits([audit_hit("s1", syscall(), ts="2024-11-18T15:00:00Z"), audit_hit("k1", sockaddr())])[0][0]
    assert e.ts == datetime.fromtimestamp(T0, UTC)


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
    assert skips["audit syscall on an arch whose socket calls are not decoded (40000003)"] == 1


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


def test_socket_parse_errors_are_tagged_for_socket_rules_only():
    _, _, errors = normalize_hits([audit_hit("s1", syscall()), audit_hit("k1", sockaddr(saddr="0200"))])
    assert errors and errors[0][1].startswith("linux.audit.socket:")


# ---- host rule -------------------------------------------------------------------------------

def _sock(serial=500, saddr=SADDR_C2, host="videoserver", t0=T0, **kw):
    events, _, errors = normalize_hits([audit_hit(f"s{serial}{host}", syscall(serial, t0=t0, **kw), host=host),
                                        audit_hit(f"k{serial}{host}", sockaddr(serial, saddr, t0=t0), host=host)])
    assert errors == []
    return events[0]


def iec(*events):
    rule = InterpreterExternalConnection()
    rule.consume(list(events))
    return rule.finalize()


def execd(pid, ppid, exe, t0=T0 - 60, host="videoserver"):
    """A process_exec event, as the auditd exec normalizer would produce it."""
    from romulus.evidence.typed import RawRef, TypedEvent, fv
    return TypedEvent(id=f"x{host}{pid}", family="process_exec", ts=datetime.fromtimestamp(t0, UTC), host=host,
                      outcome=Outcome.success,
                      fields={"process.pid": fv(pid, "fixture"), "process.ppid": fv(ppid, "fixture"),
                              "process.executable": fv(exe, "fixture")},
                      raw=[RawRef(target="romulus-host-logs", native_id=f"exec-{pid}")], normalizer="fixture")


@pytest.mark.parametrize("kw, lane", [
    ({}, "high"),                                                              # web-service interpreter
    ({"exe": "/usr/bin/bash", "comm": "bash", "uid": "0", "user": "root"}, "high"),   # shell
    ({"exe": "/usr/bin/ncat", "comm": "ncat", "uid": "0", "user": "root"}, "high"),   # relay tool
    ({"exe": "/usr/bin/python3.12", "comm": "python3", "uid": "1000", "user": "alice"}, "lead"),
])
def test_notable_process_external_connect_matches_with_kernel_identity(kw, lane):
    matches = iec(_sock(**kw))
    assert len(matches) == 1 and matches[0].proposed_lane == lane
    assert "1 succeeded" in matches[0].claim


def test_claim_says_connect_call_and_states_the_socket_type_caveat():
    m = iec(_sock())[0]
    assert "making 1 connect() call(s) to 1 address(es) outside the site's internal networks on port 4444" in m.claim
    assert "UDP socket sends no packets" in m.claim
    assert "connected" not in InterpreterExternalConnection.title


@pytest.mark.parametrize("saddr, kw", [
    ("0200115C0A000005" + "0" * 16, {}),                                        # internal destination
    (SADDR_C2, SSHD),                                                           # ordinary daemon
    ("0200115C7F000001" + "0" * 16, {"exe": "/usr/bin/bash", "comm": "bash"}),  # loopback
    ("020000005DB8D822" + "0" * 16, {}),                                        # port 0 route probe
    ("0200115CFFFFFFFF" + "0" * 16, {}),                                        # broadcast
    ("0200115CF0000001" + "0" * 16, {}),                                        # reserved 240/4
])
def test_internal_ordinary_and_non_connection_calls_do_not_match(saddr, kw):
    assert iec(_sock(saddr=saddr, **kw)) == []


def test_all_failed_connects_are_a_lead_and_say_so():
    m = iec(_sock(success="no", exit_code="-111"))[0]
    assert "1 failed" in m.claim and m.proposed_lane == "lead"
    assert any("every connect() call failed" in n for n in m.notes)


def test_success_after_failure_keeps_the_high_lane_and_counts_both():
    m = iec(_sock(1, success="no", exit_code="-111"), _sock(2, t0=T0 + 300))[0]
    assert m.proposed_lane == "high" and "1 succeeded, 1 failed" in m.claim


def test_many_destinations_on_one_port_are_one_item():
    socks = [_sock(i, saddr=f"020001BBC00002{i:02X}" + "0" * 16, t0=T0 + i,
                   exe="/usr/bin/python3.10", comm="python3", uid="0", user="root") for i in range(1, 6)]
    matches = iec(*socks)
    assert len(matches) == 1
    assert "5 connect() call(s) to 5 address(es) outside the site's internal networks on port 443" in matches[0].claim


def test_web_account_daemon_started_by_the_service_manager_is_lowered_to_lead():
    tree = [execd(150, 1, "/usr/bin/perl"), execd(100, 150, "/usr/bin/perl", t0=T0 - 30)]
    m = iec(*tree, _sock())[0]
    assert m.proposed_lane == "lead" and "reaches the service manager with no web server" in m.claim
    assert any("exec-100" in n and "exec-150" in n for n in m.notes)


def test_web_account_child_of_the_web_server_stays_high():
    tree = [execd(90, 1, "/usr/sbin/apache2"), execd(100, 90, "/usr/bin/dash", t0=T0 - 40)]
    m = iec(*tree, _sock())[0]
    assert m.proposed_lane == "high" and "ancestry includes the web server '/usr/sbin/apache2'" in m.claim


def test_unknown_lineage_never_lowers_the_lane():
    m = iec(execd(100, 77, "/usr/bin/perl"), _sock())[0]          # pid 77's exec is not in the window
    assert m.proposed_lane == "high" and "not fully recorded" in m.claim


def test_reused_pid_uses_the_exec_in_force_at_connect_time():
    tree = [execd(100, 90, "/usr/sbin/apache2", t0=T0 - 3600),     # pid 100 was the web server an hour ago
            execd(100, 1, "/usr/bin/perl", t0=T0 - 30)]            # now it is a daemon started by pid 1
    m = iec(*tree, _sock())[0]
    assert m.proposed_lane == "lead"


# ---- correlation -----------------------------------------------------------------------------

def _network(*hits):
    events, _, errors = normalize_hits(list(hits))
    assert errors == []
    return events


def link(*batches):
    """Drive the staged join the way the sweep does: consume, stage, then finalize with a loader."""
    rule, stage = ProcessNetworkLink(), {}
    for batch in batches:
        rule.consume(batch)
        stage.update({e.id: e for e in rule.drain_staged()})
    assert rule.retained_events() == []                    # nothing is held in memory for citation
    rule.bind_loader(lambda ids: [stage[i] for i in ids if i in stage])
    return rule.finalize()


def history(n=4, host="videoserver", local="198.51.100.10", observer_port=443, saddr="020001BBC00002AE"):
    """n earlier, uniquely joined connects from host whose flows show `local` as its address."""
    socks, nets = [], []
    for i in range(1, n + 1):
        t0 = T0 - 300 * i
        start = datetime.fromtimestamp(t0, UTC).isoformat()
        end = datetime.fromtimestamp(t0 + 10, UTC).isoformat()
        socks.append(_sock(900 + i, saddr=saddr + "0" * 16, t0=t0, host=host, **SSHD))
        nets += _network(flow(f"h{host}{i}", src=local, dport=observer_port, cid=f"1:{host}{i}=",
                              sport=52000 + i, start=start, end=end))
    return socks, nets


@pytest.mark.parametrize("network_first", [False, True])
def test_alert_on_joined_flow_is_attributed_to_the_process_in_either_order(network_first):
    hs, hn = history()
    host, net = hs + [_sock(**SSHD)], hn + _network(flow(), alert())
    matches = [m for m in link(*([net, host] if network_first else [host, net])) if "port 4444" in m.claim]
    assert len(matches) == 1
    m = matches[0]
    assert m.claim_type == "correlated_observation" and m.proposed_lane == "high" and m.severity == "high"
    assert "inferred from address, port and time; it is not itself observed" in m.claim
    assert "1 IDS alert(s) on those connections: ET POLICY Meterpreter-like" in m.claim
    assert "with local address(es) 198.51.100.10," in m.claim and "capped" not in m.claim
    assert {e.family for e in m.events} == {"net_socket", "net_flow", "net_alert"}
    assert any("IPv4 connections from 198.51.100.10 in 5 of 5 joins" in n for n in m.notes)


def test_without_an_established_host_address_the_link_is_stated_and_capped():
    m = link([_sock(**SSHD)] + _network(flow(), alert()))[0]
    assert m.proposed_lane == "lead"
    assert "own address on sensor(s) inetfw is not established" in m.claim
    assert "could belong to another machine" in m.claim and "not established, the lane is capped" in m.claim


def test_notable_process_gets_its_network_evidence_without_an_alert():
    hs, hn = history()
    m = [m for m in link(hs + [_sock()] + hn + _network(flow())) if "port 4444" in m.claim]
    assert len(m) == 1 and m[0].proposed_lane == "high"
    assert "notable as an interpreter 'perl' running as web-service account 'www-data'" in m[0].claim


def test_ordinary_process_without_alert_is_not_published():
    assert link([_sock(**SSHD)] + _network(flow())) == []


def test_flow_outside_the_join_window_is_not_linked():
    assert link([_sock()] + _network(flow(start="2024-11-18T14:27:10.000000+0000"))) == []


def test_two_local_addresses_are_called_ambiguous_and_capped():
    m = link([_sock()] + _network(flow("f1"), flow("f2", src="198.51.100.11", cid="1:def=", sport=51001)))[0]
    assert "It is ambiguous: more than one local address matched" in m.claim
    assert "local address(es) 198.51.100.10, 198.51.100.11" in m.claim and m.proposed_lane == "lead"


def test_low_severity_alert_with_ordinary_process_is_a_lead():
    assert link([_sock(**SSHD)] + _network(flow(), alert(severity=2)))[0].proposed_lane == "lead"


def test_reverse_netflow_is_the_same_connection_not_another_source():
    fwd = flow("n1", event_type="netflow")
    rev = flow("n2", event_type="netflow", src=ATTACKER, sport=C2_PORT, dst="198.51.100.10", dport=51000)
    m = link([_sock()] + _network(fwd, rev))[0]
    assert "2 flow or session record(s) across 1 connection(s)" in m.claim
    assert "with local address(es) 198.51.100.10." in m.claim and "ambiguous" not in m.claim


def test_reused_community_id_hours_later_is_not_pulled_in():
    near = flow(end="2024-11-18T14:27:00.000000+0000")
    later_flow = flow("f9", start="2024-11-18T18:00:00.000000+0000", end="2024-11-18T18:05:00.000000+0000")
    later_alert = alert("a9", ts="2024-11-18T18:01:00.000000+0000")
    assert link([_sock(**SSHD)] + _network(near, later_flow, later_alert)) == []


def test_alert_joined_by_two_hosts_is_shared_and_capped_at_lead():
    a = _sock(host="hostA", exe="/usr/bin/python3", comm="python3", uid="1000", user="alice")
    b = _sock(host="hostB", t0=T0 + 2, **SSHD)
    matches = link([a, b] + _network(flow(), alert()))
    assert len(matches) == 2 and all(m.proposed_lane == "lead" for m in matches)
    assert all("also join connect() calls by 1 other process(es)" in m.claim for m in matches)
    assert all("attribution is shared" in m.claim for m in matches)


def test_record_from_another_hosts_established_address_is_never_linked():
    ha, na = history(host="videoserver", local="198.51.100.10")
    hb, nb = history(host="corpdns", local="198.51.100.99", observer_port=53, saddr="02000035C00002AE")
    elsewhere = _network(flow(src="198.51.100.99"), alert(src="198.51.100.99"))
    matches = link(ha + hb + [_sock(**SSHD)] + na + nb + elsewhere)
    assert [m for m in matches if "port 4444" in m.claim] == []      # corpdns's alert is not pinned here


def test_unfamiliar_local_address_is_linked_but_stated_and_capped():
    hs, hn = history(local="198.51.100.10")
    m = next(m for m in link(hs + [_sock(**SSHD)] + hn + _network(flow(src="198.51.100.99"),
                                                                 alert(src="198.51.100.99")))
         if "port 4444" in m.claim)
    assert m.proposed_lane == "lead"
    assert "198.51.100.99 differ from the address usually seen for videoserver" in m.claim


def test_dual_stack_host_keeps_its_ipv6_records():
    hs, hn = history(n=9)
    saddr6 = "0A00115C" + "00000000" + "20010DB800000000000000000000BAD0" + "00000000"
    v6 = _network(flow("v6", src="2001:db8::7", dst="2001:db8::bad0", cid="1:v6="))
    m = [m for m in link(hs + [_sock(saddr=saddr6, exe="/usr/bin/bash", comm="bash", uid="0", user="root")]
                         + hn + v6) if "2001:db8::bad0" in m.claim]
    assert len(m) == 1 and m[0].proposed_lane == "lead"
    assert "not established" in m[0].claim                        # no IPv6 history yet for this host


def test_alert_without_severity_adds_no_lane():
    no_sev = alert()
    raw = json.loads(no_sev["_source"]["event"]["original"])
    del raw["alert"]["severity"]
    no_sev["_source"]["event"]["original"] = json.dumps(raw)
    assert link([_sock(**SSHD)] + _network(flow(), no_sev)) == []


def test_re_reading_a_partition_counts_each_record_once():
    rule, stage = ProcessNetworkLink(), {}
    batch = [_sock()] + _network(flow())
    for _ in range(2):
        rule.consume(batch)
        stage.update({e.id: e for e in rule.drain_staged()})
    rule.bind_loader(lambda ids: [stage[i] for i in ids if i in stage])
    assert "made 1 connect() call(s)" in rule.finalize()[0].claim


def test_a_cited_event_missing_from_the_stage_fails_loudly():
    from romulus.detect.correlation import StageMissing
    rule = ProcessNetworkLink()
    rule.consume([_sock()] + _network(flow()))
    rule.drain_staged()
    rule.bind_loader(lambda ids: [])
    with pytest.raises(StageMissing):
        rule.finalize()


def test_stage_is_removed_on_failure_and_stale_stages_are_cleared(tmp_path):
    import os

    from romulus.hunt.stage import PREFIX, EventStage, clear_stale_stages
    stage = EventStage(tmp_path)
    stage.put([_sock()], {"romulus-host-logs/s500videoserver": {"x": 1}})
    stage_dir = next(tmp_path.glob(f"{PREFIX}*"))
    stage.close()
    assert not stage_dir.exists()
    old = tmp_path / f"{PREFIX}old"
    old.mkdir()
    os.utime(old, (0, 0))
    fresh = tmp_path / f"{PREFIX}fresh"
    fresh.mkdir()
    assert clear_stale_stages(tmp_path) == 1 and not old.exists() and fresh.exists()


def test_web_account_to_internal_destination_has_no_process_component():
    assert link([_sock(saddr="0200115C0A000005" + "0" * 16)] + _network(flow(dst="10.0.0.5"))) == []


def test_context_level_alert_stays_context():
    m = link([_sock(**SSHD)] + _network(flow(), alert(severity=3, category="Not Suspicious Traffic")))[0]
    assert m.proposed_lane == "context" and m.severity == "low"


def test_failed_notable_connect_is_a_lead():
    m = link([_sock(success="no", exit_code="-111")] + _network(flow()))[0]
    assert m.proposed_lane == "lead" and "1 failed" in m.claim


def test_expanded_ipv6_in_sensor_records_joins_compressed_socket_address():
    saddr = "0A00115C" + "00000000" + "20010DB8000000000000000000000005" + "00000000"
    ev = flow(dst="2001:0db8:0000:0000:0000:0000:0000:0005", src="2001:0db8::10", cid="1:v6=")
    assert len(link([_sock(saddr=saddr)] + _network(ev))) == 1


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
    assert getattr(s, "_stage", None) is None                       # the disk stage is removed after finalize
    linked = [c for c in repo.candidates("h1") if c["rule_id"] == "corr.process_network_link"]
    direct = [c for c in repo.candidates("h1") if c["rule_id"] == "host.interpreter_external_connection"]
    assert len(linked) == 1 and len(direct) == 1
    cites = rm._citations(repo, linked[0])
    assert len(cites) == 4 and all(c["status"] == "retained" for c in cites), cites
    window = {c["rule_id"]: c["state"] for c in repo.rule_cells("h1") if c["target"] == "*"}
    assert window["corr.process_network_link"] == "matched"


def test_sweep_lineage_never_uses_an_exec_after_the_socket(monkeypatch):
    future = T0 + 0.5
    future_ts = datetime.fromtimestamp(future, UTC).isoformat().replace("+00:00", "Z")
    records = [
        audit_hit("s1", syscall()),
        audit_hit("k1", sockaddr()),
        audit_hit(
            "e1",
            f'type=EXECVE msg=audit({future:.3f}:900): argc=1 a0="/usr/bin/perl"',
            ts=future_ts,
        ),
        audit_hit(
            "e2",
            (f'type=SYSCALL msg=audit({future:.3f}:900): arch=c000003e syscall=59 success=yes exit=0 '
             'ppid=1 pid=100 auid=4294967295 uid=33 gid=33 euid=33 comm="perl" '
             'exe="/usr/bin/perl" AUID="unset" UID="www-data" EUID="www-data"'),
            ts=future_ts,
        ),
    ]
    monkeypatch.setattr(sw, "execute", lambda client, intent, contract: _outcome(intent, records))
    engine = make_engine(":memory:")
    migrate(engine)
    repo = Repo(engine)
    repo.create_hunt("h1", {"targets": ["romulus-host-logs"]}, "d", "t")
    start = datetime(2024, 11, 18, 14, 0, tzinfo=UTC)
    window = Window(start=start, end=start + timedelta(hours=1))

    sweep = sw.Sweep(repo, _Client(), "h1", window, {"romulus-host-logs": None})
    sweep.run_partition("romulus-host-logs", None, [], window, est=len(records))
    sweep.finalize()

    finding = next(c for c in repo.candidates("h1")
                   if c["rule_id"] == "host.interpreter_external_connection")
    assert finding["lane"] == "high"
    assert "ancestry is not fully recorded" in finding["claim"]
