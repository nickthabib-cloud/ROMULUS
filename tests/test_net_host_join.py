"""Administration sessions cited by network findings, joined to the destination host's logon and what ran in it.

Addresses are documentation ranges, hosts and accounts are invented, and no host record carries the host's own
address (the lab shape the join is keyed around)."""
from datetime import UTC, datetime, timedelta

import pytest

from romulus.detect.bounded import StateBudget
from romulus.detect.net_host_join import (
    NetworkAdminLogonJoin,
    admin_session,
    canon_session,
    logon_account,
)
from romulus.evidence.typed import FieldValue, Outcome, RawRef, TypedEvent
from romulus.evidence.windows_catalog import SECURITY, SYSMON, SYSMON_CHANNEL
from romulus.hunt.citations import COMPACT_CITATION_NOTE
from tests.test_windows_c_burst_review import START, native_event

CLIENT, CLIENT2 = "198.51.100.10", "198.51.100.11"
SERVER, SERVER2 = "10.20.0.20", "10.20.0.21"            # site servers (private range, inside the default site)
OUTSIDE = "192.0.2.20"                                  # a documentation address, outside the default site
T = START.timestamp()


def ev(eid, family, offset, host, fields, *, outcome=Outcome.unknown, normalizer="test-linux@1"):
    return TypedEvent(id=eid, family=family, ts=datetime.fromtimestamp(T + offset, UTC), host=host, outcome=outcome,
                      fields={name: FieldValue(value=value, origin=f"{eid}:{name}")
                              for name, value in fields.items() if value is not None},
                      raw=[RawRef(target="idx", native_id=eid)], normalizer=normalizer)


def iso(offset):
    return datetime.fromtimestamp(T + offset, UTC).isoformat()


def flow(eid, *, client=CLIENT, cport=51022, server=SERVER, sport=22, start=0.0, duration=60.0, family="net_flow",
         protocols=None, transport="tcp", end=True):
    return ev(eid, family, start, "sensor1", {
        "source.ip": client, "source.port": cport, "destination.ip": server, "destination.port": sport,
        "network.transport": transport, "flow.start": iso(start),
        "flow.end": iso(start + duration) if end else None, "network.protocols": protocols},
        normalizer="test-net@1")


def sshd(eid, offset, *, client=CLIENT, port=51022, host="web01", user="root", outcome=Outcome.success, boot="b1"):
    return ev(eid, "auth", offset, host, {"auth.service": "sshd", "auth.phase": "authentication",
                                          "auth.method": "publickey", "source.ip": client, "source.port": port,
                                          "user.name": user, "host.boot.id": boot}, outcome=outcome)


def audit_login(eid, offset, *, client=CLIENT, session=7, host="web01", user="root", service="sshd", boot="b1"):
    return ev(eid, "auth", offset, host, {"auth.service": service, "auth.phase": "login", "auth.method": "user_login",
                                          "source.ip": client, "process.session_id": session, "user.name": user,
                                          "host.boot.id": boot}, outcome=Outcome.success)


def execve(eid, offset, exe, *, session=7, host="web01", boot="b1"):
    return ev(eid, "process_exec", offset, host, {"process.executable": exe, "process.session_id": session,
                                                  "process.pid": 4000 + offset, "host.boot.id": boot},
              outcome=Outcome.success)


def logon4624(offset, *, ltype=3, port=None, logon_id="0x1a2b", client=CLIENT, host="srv01.example.test",
              code=4624, user="alice", record=None):
    data = {"TargetUserName": user, "TargetDomainName": "EXAMPLE", "SubjectUserName": "SRV01$",
            "IpAddress": client, "IpPort": str(port) if port is not None else "-", "LogonType": str(ltype),
            "TargetLogonId": logon_id, "LogonProcessName": "NtLmSsp", "AuthenticationPackageName": "NTLM"}
    if code == 4625:
        data.update(Status="0xc000006d", SubStatus="0xc000006a")
    return native_event(code, data, host=host, offset=offset, record=record)


def process4688(offset, image, *, logon_id="0x1a2b", host="srv01.example.test"):
    return native_event(4688, {"NewProcessName": image, "SubjectLogonId": logon_id, "SubjectUserName": "alice",
                               "SubjectDomainName": "EXAMPLE", "NewProcessId": hex(4000 + int(offset)),
                               "ProcessId": "0x100", "ParentProcessName": "C:\\Windows\\System32\\wsmprovhost.exe"},
                        host=host, offset=offset)


def sysmon1(offset, image, *, logon_id="0x1a2b", host="srv01.example.test"):
    return native_event(1, {"Image": image, "LogonId": logon_id, "ProcessId": str(5000 + int(offset)),
                            "ProcessGuid": f"{{00000000-0000-0000-0000-{5000 + int(offset):012d}}}",
                            "User": "EXAMPLE\\alice", "CommandLine": image},
                        host=host, offset=offset, channel=SYSMON_CHANNEL, provider=SYSMON)


def sysmon3(offset, *, client=CLIENT, cport=50100, server=SERVER, sport=3389, host="srv01.example.test"):
    return native_event(3, {"SourceIp": client, "SourcePort": str(cport), "DestinationIp": server,
                            "DestinationPort": str(sport), "Protocol": "tcp", "Initiated": "false",
                            "Image": "C:\\Windows\\System32\\svchost.exe",
                            "ProcessGuid": "{00000000-0000-0000-0000-000000000003}", "ProcessId": "900"},
                        host=host, offset=offset, channel=SYSMON_CHANNEL, provider=SYSMON)


def share5140(offset, *, port=50000, logon_id="0x1a2b", host="srv01.example.test", share="\\\\*\\ADMIN$"):
    return native_event(5140, {"SubjectUserName": "alice", "SubjectDomainName": "EXAMPLE",
                               "SubjectLogonId": logon_id, "IpAddress": CLIENT, "IpPort": str(port),
                               "ShareName": share, "AccessMask": "0x1"}, host=host, offset=offset)


def finding(cid, events, *, lane="lead", rule="net.test_rule", provenance="deterministic"):
    return {"id": cid, "rule_id": rule, "lane": lane, "event_ids": [event.id for event in events],
            "provenance": provenance}


def run(batches, findings, *, rule=None, targets=None, bind=True):
    rule = rule or NetworkAdminLogonJoin()
    store = {}
    for index, batch in enumerate(batches):
        for event in batch:
            store[event.id] = event
        if targets is not None:
            rule.bind_raw({}, targets[index])
        rule.consume(batch)
    if bind:
        def pages(lane, offset, limit):
            rows = [row for row in findings if row["lane"] == lane]
            return rows[offset:offset + limit]
        rule.bind_published(pages, lambda ids: [store[i] for i in ids if i in store])
    matches = list(rule.finalize())
    return rule, matches


def ssh_case():
    session = flow("f1", start=0.0, duration=120.0)
    host = [sshd("acc", 0.4), audit_login("ul", 0.6), execve("x1", 2, "/bin/bash"), execve("x2", 3, "/usr/bin/id"),
            execve("x3", 5, "/usr/bin/curl")]
    return session, host


# ---- positives, one per protocol -----------------------------------------------------------------------------------

def test_ssh_session_joins_sshd_line_by_client_endpoint_and_names_what_ran():
    session, host = ssh_case()
    rule, matches = run([host, [session]], [finding("F1", [session])])
    assert len(matches) == 1
    m = matches[0]
    assert m.playbook_id == "corr.network_admin_logon" and m.claim_type == "correlated_observation"
    assert m.proposed_lane == "lead" and m.severity == "high" and m.confidence == "medium"
    assert "Inferred join (a hypothesis, not an observed link)" in m.claim
    assert "host web01" in m.claim and "client address and client port" in m.claim
    assert "net.test_rule (lead)" in m.claim and "+0.4 s" in m.claim
    assert "3 process or share record(s)" in m.claim and "bash, id, curl" in m.claim
    ids = {event.id for event in m.events}
    assert {"f1", "acc", "ul", "x1", "x2", "x3"} <= ids
    assert m.context_ids == {"f1"}
    assert {"T1021", "T1021.004", "T1078"} == set(m.attack)
    assert all(COMPACT_CITATION_NOTE in event.caveats for event in m.events if event.id != "f1")
    assert {(item.field, item.value) for item in m.predicate} >= {("source.port", 51022)}
    assert any("inferred, not observed" in note for note in m.notes)
    assert any("1 by endpoint" in note for note in rule.coverage_notes())


def test_smb_session_joins_4624_by_ip_port_with_share_and_process_in_the_logon_session():
    session = flow("smb", cport=50000, sport=445, start=0.0, duration=30.0, protocols=["smb"])
    logon = logon4624(0.5, port=50000)
    host = [logon, share5140(0.7), sysmon1(2, "C:\\Windows\\System32\\cmd.exe"),
            process4688(3, "C:\\Windows\\System32\\whoami.exe"),
            process4688(4, "C:\\Windows\\System32\\notepad.exe", logon_id="0x9999")]
    _rule, matches = run([[session], host], [finding("F1", [session], lane="high")])
    assert len(matches) == 1
    m = matches[0]
    assert "host srv01 wrote" in m.claim and "SMB connection(s)" in m.claim
    assert "logon session 0x1a2b" in m.claim and "(session 0x1a2b)" in m.claim
    assert "example\\alice" in m.claim and "logon type 3" in m.claim
    assert "3 process or share record(s)" in m.claim and "notepad" not in m.claim
    assert "T1021.002" in m.attack and m.proposed_lane == "lead"


def test_rdp_portless_logon_joins_through_the_hosts_own_connection_record():
    session = flow("rdp", cport=50100, sport=3389, start=0.0, duration=900.0)
    host = [sysmon3(0.2), logon4624(4.0, ltype=10), sysmon1(9, "C:\\Windows\\explorer.exe")]
    rule, matches = run([[session], host], [finding("F1", [session])])
    assert len(matches) == 1 and "host recorded this connection itself" in matches[0].claim
    assert matches[0].confidence == "medium" and "T1021.001" in matches[0].attack
    assert any("1 by host_connection" in note for note in rule.coverage_notes())


def test_winrm_portless_logon_on_the_only_host_is_an_address_join_stated_as_such():
    session = flow("winrm", cport=50200, sport=5985, start=0.0, duration=40.0)
    host = [logon4624(1.0), process4688(2, "C:\\Windows\\System32\\wsmprovhost.exe")]
    _rule, matches = run([[session], host], [finding("F1", [session])])
    assert len(matches) == 1
    m = matches[0]
    assert m.confidence == "low" and "only this host logged a logon" in m.claim
    assert any(note.startswith("Address-only join") for note in m.notes)
    assert "T1021.006" in m.attack


def test_an_address_only_join_to_a_server_outside_the_site_is_refused_and_named():
    session = flow("out", cport=50200, sport=5985, server=OUTSIDE, start=0.0)
    rule, matches = run([[session], [logon4624(1.0)]], [finding("F1", [session])])
    assert matches == []
    assert any("outside the site's internal networks" in note for note in rule.coverage_notes())
    assert any("assumed" in note.lower() for note in rule.coverage_notes())
    _rule, matches = run([[session], [logon4624(1.0, port=50200)]], [finding("F1", [session])])
    assert len(matches) == 1                            # a port ties the logon to this connection wherever it went


def test_rpc_on_a_dynamic_port_known_by_the_sensor_protocol_joins_a_network_logon():
    session = flow("rpc", cport=50300, sport=49712, start=0.0, duration=10.0, family="rpc_tx",
                   protocols=["dce_rpc"])
    host = [logon4624(0.3), sysmon1(1, "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe")]
    _rule, matches = run([[session], host], [finding("F1", [session])])
    assert len(matches) == 1 and "RPC" in matches[0].claim and "T1021.003" in matches[0].attack


def test_telnet_login_record_joins_its_session():
    session = flow("tel", cport=40000, sport=23, start=0.0)
    host = [audit_login("tl", 3.0, service="login", session=12), execve("tx", 5, "/bin/sh", session=12)]
    _rule, matches = run([[session], host], [finding("F1", [session])])
    assert len(matches) == 1 and "Telnet" in matches[0].claim and matches[0].confidence == "low"


def test_vnc_is_unresolved_by_name_never_a_negative():
    session = flow("vnc", cport=40001, sport=5900, start=0.0)
    rule, matches = run([[session], [sshd("acc", 1, port=40001)]], [finding("F1", [session])])
    assert matches == []
    assert any("VNC, X11" in note for note in rule.coverage_notes())
    assert not rule.assures_negative


# ---- adversarial negatives ------------------------------------------------------------------------------------------

def test_logon_from_the_same_source_outside_the_clock_allowance_is_not_joined():
    session = flow("f1", start=0.0, duration=60.0)
    rule, matches = run([[session], [sshd("late", 60 + 300.5)]], [finding("F1", [session])])
    assert matches == []
    assert any("no host logged a logon from the client address" in note for note in rule.coverage_notes())


def test_timestamp_boundary_is_inclusive_at_the_allowance():
    session = flow("f1", start=0.0, duration=60.0)
    _rule, matches = run([[session], [sshd("edge", 60 + 300.0)]], [finding("F1", [session])])
    assert len(matches) == 1 and "+360.0 s" in matches[0].claim
    _rule, early = run([[session], [sshd("early", -300.0)]], [finding("F1", [session])])
    assert len(early) == 1
    _rule, before = run([[session], [sshd("before", -300.5)]], [finding("F1", [session])])
    assert before == []


def test_open_ended_record_reads_its_own_time_plus_the_allowance():
    session = flow("alert", start=0.0, end=False, family="net_alert")
    _rule, matches = run([[session], [sshd("acc", 250.0)]], [finding("F1", [session])])
    assert len(matches) == 1


def test_a_logon_type_the_protocol_does_not_produce_is_not_joined():
    session = flow("smb", cport=50000, sport=445, start=0.0)
    rule, matches = run([[session], [logon4624(1.0, ltype=10)]], [finding("F1", [session])])
    assert matches == []
    assert any("types the protocol does not produce" in note for note in rule.coverage_notes())


def test_shared_source_with_ports_joins_each_session_to_its_own_host_and_without_ports_is_ambiguous():
    one = flow("s1", cport=50001, sport=445, server=SERVER, start=0.0)
    two = flow("s2", cport=50002, sport=445, server=SERVER2, start=1.0)
    hosts = [logon4624(0.5, port=50001, host="srv01.example.test", logon_id="0x11"),
             logon4624(1.5, port=50002, host="srv02.example.test", logon_id="0x22")]
    _rule, matches = run([[one, two], hosts], [finding("F1", [one, two])])
    assert sorted(m.group_key.split("|")[1] for m in matches) == ["srv01", "srv02"]
    portless = [logon4624(0.5, host="srv01.example.test", logon_id="0x11"),
                logon4624(1.5, host="srv02.example.test", logon_id="0x22")]
    rule, matches = run([[one, two], portless], [finding("F1", [one, two])])
    assert matches == []
    assert any("several hosts logged a portless logon" in note for note in rule.coverage_notes())


def test_two_hosts_naming_the_same_client_endpoint_is_ambiguous():
    session = flow("s1", cport=50001, sport=445)
    hosts = [logon4624(0.5, port=50001, host="srv01.example.test"),
             logon4624(0.6, port=50001, host="srv02.example.test")]
    rule, matches = run([[session], hosts], [finding("F1", [session])])
    assert matches == []
    assert any("same client endpoint" in note for note in rule.coverage_notes())


def test_source_with_sessions_to_several_servers_cannot_pair_a_portless_logon():
    cited = flow("s1", cport=50001, sport=445, server=SERVER, start=0.0)
    other = flow("s2", cport=50002, sport=445, server=SERVER2, start=2.0)      # to a host with no telemetry
    rule, matches = run([[cited, other], [logon4624(1.0)]], [finding("F1", [cited])])
    assert matches == []
    assert any("cannot be paired" in note for note in rule.coverage_notes())


def test_logons_naming_other_client_ports_belong_to_other_connections():
    session = flow("s1", cport=50001, sport=445)
    rule, matches = run([[session], [logon4624(0.5, port=50999)]], [finding("F1", [session])])
    assert matches == []
    assert any("name other client ports" in note for note in rule.coverage_notes())


def test_a_busy_jump_host_still_joins_by_port_and_is_an_honest_partial_without_one():
    session = flow("s1", start=0.0, duration=200.0)
    busy = [ev(f"b{n}", "auth", n * 0.04, f"h{n % 50}", {"auth.service": "sshd", "auth.phase": "login",
                                                        "source.ip": CLIENT, "process.session_id": n},
               outcome=Outcome.success) for n in range(4200)]
    _rule, matches = run([busy, [sshd("acc", 1.0)], [session]], [finding("F1", [session])])
    assert len(matches) == 1 and "host web01" in matches[0].claim
    rule, matches = run([busy, [session]], [finding("F1", [session])])
    assert matches == []
    assert any("more logons in the window than one lookup reads" in note for note in rule.coverage_notes())


def test_client_side_and_domain_controller_records_never_place_the_logon():
    session = flow("s1", cport=50001, sport=445)
    dc = native_event(4769, {"TargetUserName": "alice@EXAMPLE.TEST", "ServiceName": "cifs/srv01",
                             "IpAddress": "::ffff:" + CLIENT, "IpPort": "50001", "Status": "0x0"},
                      host="dc01.example.test", offset=0.2)
    explicit = native_event(4648, {"SubjectUserName": "alice", "TargetUserName": "admin", "IpAddress": CLIENT,
                                   "IpPort": "50001", "TargetServerName": "srv01"}, host="ws01.example.test",
                            offset=0.1)
    rule, matches = run([[session], [dc, explicit]], [finding("F1", [session])])
    assert matches == []


def test_a_session_no_network_finding_cites_is_never_joined():
    session, host = ssh_case()
    _rule, matches = run([host, [session]], [finding("F1", [host[0]], rule="host.something", lane="high")])
    assert matches == []


def test_agent_findings_and_the_rules_own_items_are_not_leads():
    session, host = ssh_case()
    _rule, matches = run([host, [session]], [finding("A1", [session], provenance="agent"),
                                             finding("J1", [session], rule="corr.network_admin_logon")])
    assert matches == []


def test_a_process_in_another_boot_with_the_same_session_id_is_not_joined():
    session = flow("f1")
    host = [sshd("acc", 0.4), audit_login("ul", 0.6), execve("x1", 2, "/bin/bash"),
            execve("x2", 3, "/usr/bin/id", boot="b2")]
    _rule, matches = run([host, [session]], [finding("F1", [session])])
    assert "1 process or share record(s)" in matches[0].claim and "x2" not in {e.id for e in matches[0].events}


def test_failed_logon_only_is_a_medium_severity_lead_with_no_activity():
    session = flow("smb", cport=50000, sport=445)
    host = [logon4624(0.5, port=50000, code=4625, logon_id="0x0")]
    _rule, matches = run([[session], host], [finding("F1", [session])])
    assert len(matches) == 1
    m = matches[0]
    assert m.severity == "medium" and "(failed" in m.claim and "T1078" not in m.attack
    assert "process or share record" not in m.claim


# ---- missing fields and unknowns -----------------------------------------------------------------------------------

def test_admin_record_without_ports_is_counted_missing_never_matched():
    broken = ev("nop", "ssh_session", 0, "sensor1", {"source.ip": CLIENT, "destination.ip": SERVER},
                normalizer="test-net@1")
    rule, matches = run([[broken], [sshd("acc", 1)]], [finding("F1", [broken])])
    assert matches == [] and rule.missing_required == 1


def test_without_published_findings_the_rule_states_it_joined_nothing():
    session, host = ssh_case()
    rule, matches = run([host, [session]], [], bind=False)
    assert matches == []
    assert any("were not available" in note for note in rule.coverage_notes())


def test_ambiguous_audit_companions_leave_activity_unjoined_and_say_so():
    session = flow("f1")
    host = [sshd("acc", 0.4), audit_login("u1", 0.6, session=7), audit_login("u2", 0.7, session=8),
            execve("x1", 2, "/bin/bash")]
    rule, matches = run([host, [session]], [finding("F1", [session])])
    assert len(matches) == 1 and "process or share record(s) in" not in matches[0].claim
    assert any("several audit login sessions" in note for note in rule.coverage_notes())


# ---- lanes ---------------------------------------------------------------------------------------------------------

def test_lane_rises_only_on_a_typed_host_finding_in_the_joined_session():
    session, host = ssh_case()
    flagged = finding("H1", [host[4]], rule="host.download_cradle", lane="high")
    _rule, matches = run([host, [session]], [finding("F1", [session]), flagged])
    m = matches[0]
    assert m.proposed_lane == "high" and "host.download_cradle (high)" in m.claim
    elsewhere = execve("y1", 4, "/usr/bin/curl", session=99)
    _rule, matches = run([host + [elsewhere], [session]],
                         [finding("F1", [session]), finding("H2", [elsewhere], rule="host.x", lane="urgent")])
    assert matches[0].proposed_lane == "lead"


def test_the_join_never_lowers_or_replaces_the_network_finding_and_is_never_urgent():
    session, host = ssh_case()
    flagged = finding("H1", [host[2]], rule="host.reverse_shell", lane="urgent")
    _rule, matches = run([host, [session]], [finding("F1", [session], lane="urgent"), flagged])
    assert matches[0].proposed_lane == "high"
    assert "net.test_rule (urgent)" in matches[0].claim


# ---- order, state and scale ----------------------------------------------------------------------------------------

@pytest.mark.parametrize("network_first", [False, True])
def test_result_does_not_depend_on_which_target_is_read_first(network_first):
    session, host = ssh_case()
    batches = [[session], host] if network_first else [host, [session]]
    _rule, matches = run(batches, [finding("F1", [session])])
    assert len(matches) == 1 and "3 process or share record(s)" in matches[0].claim


def test_process_records_read_before_their_logon_are_named_not_silently_lost():
    session = flow("f1")
    host_processes = [execve("x1", 2, "/bin/bash")]
    host_logons = [sshd("acc", 0.4), audit_login("ul", 0.6)]
    _rule, matches = run([host_processes, [session], host_logons], [finding("F1", [session])],
                         targets=["sysmon-like", "net", "auth-like"])
    m = matches[0]
    assert any("read before a remote logon naming their session" in note for note in m.notes)


def test_activity_keeps_the_earliest_records_whatever_their_order_and_counts_them_all():
    session = flow("f1")
    execs = [execve(f"x{n}", 10 + n, f"/bin/p{n}") for n in range(20)]
    _rule, matches = run([[sshd("acc", 0.4), audit_login("ul", 0.6)], list(reversed(execs)), [session]],
                         [finding("F1", [session])])
    m = matches[0]
    assert "20 process or share record(s)" in m.claim
    assert {f"x{n}" for n in range(8)} <= {e.id for e in m.events} and "x8" not in {e.id for e in m.events}


def test_one_item_per_host_client_and_service_across_findings_and_sensors():
    first = flow("f1", start=0.0)
    copy = flow("f1-arkime", start=0.01, family="net_session")       # the same connection from another sensor
    second = flow("f2", cport=51023, start=30.0)
    host = [sshd("a1", 0.4), audit_login("u1", 0.6), sshd("a2", 30.4, port=51023),
            audit_login("u2", 30.6, session=8)]
    _rule, matches = run([host, [first, copy, second]],
                         [finding("F1", [first, copy], rule="net.a"), finding("F2", [second], rule="net.b")])
    assert len(matches) == 1
    assert "2 SSH connection(s) (3 network record(s))" in matches[0].claim
    assert "net.a (lead)" in matches[0].claim and "net.b (lead)" in matches[0].claim


def test_large_synthetic_volume_spills_and_still_finds_the_needle(tmp_path):
    rule = NetworkAdminLogonJoin()
    rule.spill_dir = tmp_path
    rule.budget = StateBudget(tmp_path)
    rule.remote.hot_size = rule.activity.hot_size = 256
    batches, needle = [], None
    for chunk in range(20):
        batch = []
        for n in range(2500):
            i = chunk * 2500 + n
            client = f"10.{(i >> 16) & 255}.{(i >> 8) & 255}.{i & 255}"
            offset = i * 0.05
            batch.append(sshd(f"a{i}", offset, client=client, port=40000 + i % 20000, host=f"h{i % 300}",
                              boot="b"))
            batch.append(audit_login(f"u{i}", offset + 0.1, client=client, session=i, host=f"h{i % 300}", boot="b"))
            batch.append(execve(f"x{i}", offset + 0.2, "/bin/true", session=i, host=f"h{i % 300}", boot="b"))
        rule.consume(batch)
        batches.append(len(batch))
        assert len(rule.remote.hot) <= 256 and len(rule.activity.hot) <= 256
    needle_i = 31_337
    needle_client = f"10.{(needle_i >> 16) & 255}.{(needle_i >> 8) & 255}.{needle_i & 255}"
    needle = flow("needle", client=needle_client, cport=40000 + needle_i % 20000, start=needle_i * 0.05 - 0.5)
    rule.consume([needle])
    store = {"needle": needle}
    rule.bind_published(lambda lane, offset, limit: [finding("F1", [needle])][offset:offset + limit]
                        if lane == "lead" else [], lambda ids: [store[i] for i in ids if i in store])
    matches = list(rule.finalize())
    assert sum(batches) == 150_000 and rule.remote.on_disk > 0
    assert len(matches) == 1 and f"host h{needle_i % 300}" in matches[0].claim
    assert "1 process or share record(s)" in matches[0].claim
    rule.release_state()


# ---- typed helpers ------------------------------------------------------------------------------------------------

def test_admin_session_orients_server_side_records_and_ignores_udp_and_non_admin():
    reverse = flow("r", client=SERVER, cport=22, server=CLIENT, sport=51022)
    session = admin_session(reverse)
    assert (session.client, session.cport, session.server, session.sport) == (CLIENT, 51022, SERVER, 22)
    assert admin_session(flow("u", sport=3389, transport="udp")) is None
    assert admin_session(flow("w", sport=443)) is None
    assert admin_session(flow("p", sport=443, protocols=["rdp"])).service == "rdp"
    assert admin_session(flow("s", sport=8022, family="ssh_session")).service == "ssh"


@pytest.mark.parametrize("value,expected", [("0x1A2B", "6699"), ("6699", "6699"), (6699, "6699"), ("0x0", None),
                                            (4294967295, None), ("-", None), (None, None), (True, None)])
def test_logon_session_ids_have_one_spelling(value, expected):
    assert canon_session(value) == expected


def test_windows_logon_account_is_the_target_not_the_writing_service():
    assert logon_account(logon4624(0)) == "example\\alice"
    assert logon_account(sshd("a", 0)) == "root"


def test_rule_is_registered_positive_only_with_verified_attack_ids():
    from romulus.catalog.attack import load_attack_bundle
    from romulus.detect.registry import ALL_PLAYBOOKS
    assert NetworkAdminLogonJoin in ALL_PLAYBOOKS
    attack = load_attack_bundle()
    from romulus.detect.net_host_join import SERVICE_ATTACK
    for technique in {*NetworkAdminLogonJoin.attack, *SERVICE_ATTACK.values()}:
        assert attack.technique(technique) is not None, technique
    card = NetworkAdminLogonJoin.card
    assert {"behavior", "telemetry", "fidelity", "benign_and_cost", "query_cost", "next_pivot", "adds",
            "research_basis", "retrieval", "lanes", "window", "state"} <= set(card)
    assert NetworkAdminLogonJoin.lane == "lead" and not NetworkAdminLogonJoin.assures_negative


# ---- through the sweep: published network finding -> host logon -> what ran, every citation retained ---------------

def test_sweep_joins_a_published_network_finding_to_the_host_logon_and_retains_every_citation(monkeypatch):
    import json as _json

    from romulus.hunt import sweep as sw
    from romulus.report import manifest as rm
    from romulus.sources.models import Window
    from romulus.store.db import make_engine, migrate
    from romulus.store.repo import Repo
    from tests.test_network_correlation import _Client, _outcome, eve_hit

    base = datetime(2024, 11, 18, 14, 0, tzinfo=UTC)
    t0 = base.timestamp() + 600
    client, server = "192.168.100.222", "172.17.100.121"

    def stamp(offset):
        return datetime.fromtimestamp(t0 + offset, UTC).isoformat().replace("+00:00", "Z")

    alert = eve_hit("al1", {"timestamp": datetime.fromtimestamp(t0 + 1, UTC).isoformat(), "event_type": "alert",
                            "src_ip": client, "src_port": 51022, "dest_ip": server, "dest_port": 22, "proto": "TCP",
                            "app_proto": "ssh",
                            "alert": {"signature": "ET SCAN Potential SSH Scan", "signature_id": 2001219,
                                      "category": "Attempted Information Leak", "severity": 1}}, ts=stamp(1))
    message = f"Accepted password for root from {client} port 51022 ssh2"
    sshd_line = {"_id": "j1", "_index": "romulus-host-logs", "_source": {
        "@timestamp": stamp(2), "message": message, "host": {"name": "videoserver"},
        "event": {"dataset": "systemd.journal", "original": _json.dumps({
            "SYSLOG_IDENTIFIER": "sshd", "_HOSTNAME": "videoserver", "MESSAGE": message})}}}
    login = (f"type=USER_LOGIN msg=audit({t0 + 2.5:.3f}:700): pid=900 uid=0 auid=0 ses=11 "
             f"msg='op=login id=0 exe=\"/usr/sbin/sshd\" hostname=? addr={client} terminal=/dev/pts/0 res=success'")
    execve = f'type=EXECVE msg=audit({t0 + 4:.3f}:701): argc=1 a0="id"'
    syscall = (f"type=SYSCALL msg=audit({t0 + 4:.3f}:701): arch=c000003e syscall=59 success=yes exit=0 ppid=950 "
               f'pid=951 auid=0 uid=0 euid=0 ses=11 comm="id" exe="/usr/bin/id" key=(null)')

    def audit(_id, raw, offset):
        return {"_id": _id, "_index": "romulus-host-logs", "_source": {
            "@timestamp": stamp(offset), "message": raw, "host": {"name": "videoserver"},
            "event": {"dataset": "linux.audit", "original": raw}}}

    by_target = {"romulus-host-logs": [sshd_line, audit("l1", login, 2.5), audit("e1", execve, 4),
                                       audit("e2", syscall, 4)],
                 "romulus-network-logs": [alert]}
    monkeypatch.setattr(sw, "execute", lambda client_, intent, contract: _outcome(intent, by_target[intent.target]))
    engine = make_engine(":memory:")
    migrate(engine)
    repo = Repo(engine)
    order = ("romulus-host-logs", "romulus-network-logs")
    repo.create_hunt("h1", {"targets": list(order)}, "d", "t")
    window = Window(start=base, end=base + timedelta(hours=1))
    sweep = sw.Sweep(repo, _Client(by_target), "h1", window, {target: None for target in order})
    for target in order:
        sweep.run_partition(target, None, [], window, est=4)
    sweep.finalize()
    candidates = repo.candidates("h1")
    joined = [c for c in candidates if c["rule_id"] == "corr.network_admin_logon"]
    assert any(c["rule_id"].startswith("net.") for c in candidates), [c["rule_id"] for c in candidates]
    assert len(joined) == 1, [(c["rule_id"], c["lane"]) for c in candidates]
    item = joined[0]
    assert item["lane"] == "lead" and "host videoserver" in item["claim"]
    assert "client address and client port" in item["claim"] and "1 process or share record(s)" in item["claim"]
    cites = rm._citations(repo, item)
    assert cites and all(c["status"] == "retained" for c in cites), cites
    cells = {c["rule_id"]: c for c in repo.rule_cells("h1") if c["target"] == "*"}
    assert cells["corr.network_admin_logon"]["state"] == "matched"
