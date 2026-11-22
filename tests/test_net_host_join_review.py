"""Adversarial joins from the network-to-host join's review: each must stay unresolved, or be joined at the lane its
key supports. Addresses are private or documentation ranges, hosts and accounts are invented."""
from tests.test_net_host_join import (
    SERVER,
    SERVER2,
    audit_login,
    execve,
    finding,
    flow,
    logon4624,
    process4688,
    run,
    sshd,
)


def _notes(rule):
    return " ".join(rule.coverage_notes())


# ---- B1: a false join must not reach high --------------------------------------------------------------------------

def test_a_reused_client_port_toward_another_server_never_joins_the_cited_ssh_session():
    # the cited server keeps no host telemetry; the client reused its source port toward web02 half an hour later
    cited = flow("f1", cport=51022, server=SERVER, sport=22, start=0.0, duration=7200.0)
    other = flow("f2", cport=51022, server=SERVER2, sport=22, start=1800.0, duration=60.0)
    host = [sshd("acc2", 1800.3, host="web02"), audit_login("ul2", 1800.5, host="web02", session=9),
            execve("x9", 1802, "/usr/bin/curl", host="web02", session=9)]
    rule, matches = run([[cited, other], host], [finding("F1", [cited])])
    assert matches == []
    rule, matches = run([[cited, other], host], [finding("F1", [cited]),
                                                 finding("H1", [host[2]], lane="high", rule="host.test_high")])
    assert matches == []
    assert "cannot be paired" in _notes(rule)


def test_an_ssh_logon_long_after_the_opening_is_not_the_sessions_own():
    cited = flow("f1", cport=51022, server=SERVER, sport=22, start=0.0, duration=7200.0)
    _rule, matches = run([[cited], [sshd("late", 1800.3, host="web02")]], [finding("F1", [cited])])
    assert matches == []


def test_a_reused_endpoint_toward_another_server_is_unresolved_for_a_lifetime_protocol():
    cited = flow("s1", cport=50001, server=SERVER, sport=445, start=0.0, duration=7200.0)
    other = flow("s2", cport=50001, server=SERVER2, sport=445, start=1800.0, duration=60.0)
    rule, matches = run([[cited, other], [logon4624(1800.3, port=50001, host="srv02.example.test")]],
                        [finding("F1", [cited])])
    assert matches == []
    assert "same port toward another server" in _notes(rule)


def test_an_address_only_join_never_rises_above_lead_and_says_so():
    session = flow("w1", cport=50200, sport=5985, start=0.0, duration=40.0)
    logon = logon4624(1.0, host="srv02.example.test")
    process = process4688(2, "C:\\Windows\\System32\\cmd.exe", host="srv02.example.test")
    _rule, matches = run([[session], [logon, process]],
                         [finding("F1", [session]), finding("H1", [process], lane="high", rule="win.test_high")])
    assert len(matches) == 1
    m = matches[0]
    assert m.proposed_lane == "lead" and m.confidence == "low"
    assert "win.test_high (high)" in m.claim and "an address-only join never raises the lane" in m.claim


def _refusing(after: int):
    """A join whose state budget refuses every row after the first `after`."""
    from romulus.detect.net_host_join import NetworkAdminLogonJoin
    rule = NetworkAdminLogonJoin()
    original, calls = rule._room, {"n": 0}

    def room(rows):
        calls["n"] += 1
        if calls["n"] > after:
            rule.refuse("state_disk", "simulated refusal")
            return False
        return original(rows)
    rule._room = room
    return rule


# ---- I1: refused host rows make "only this host" unknown ----------------------------------------------------------

def test_a_refused_logon_row_stops_an_address_only_join():
    session = flow("w1", cport=50200, sport=5985, start=0.0, duration=40.0)
    first, second = logon4624(1.0, host="srv02.example.test"), logon4624(1.5, host="srv01.example.test")
    rule, matches = run([[session], [first, second]], [finding("F1", [session])])
    assert matches == [] and "several hosts logged a portless logon" in _notes(rule)
    # the session row and the first logon are kept, the second (another host's) refused
    rule, matches = run([[session], [first, second]], [finding("F1", [session])], rule=_refusing(2))
    assert matches == []
    assert "this host being the only one with a fitting portless logon is not known" in _notes(rule)
    assert any("host logon or connection record(s)" in reason for reason in rule.limit_reasons())


def test_a_refused_row_leaves_an_endpoint_join_standing_with_its_uniqueness_unchecked():
    session = flow("s1", cport=50000, sport=445, start=0.0)
    logons = [logon4624(0.5, port=50000), logon4624(0.6, port=50000, host="srv02.example.test")]
    _rule, matches = run([[session], logons], [finding("F1", [session])], rule=_refusing(2))
    assert len(matches) == 1 and "uniqueness" not in matches[0].claim
    assert "being the only one naming the client endpoint or connection is unchecked" in matches[0].claim


# ---- I2: only the server's record of a connection places it ------------------------------------------------------

def _sysmon3_client(offset, *, cport=50100, sport=3389, host="wks01.example.test"):
    from romulus.evidence.windows_catalog import SYSMON, SYSMON_CHANNEL
    from tests.test_net_host_join import CLIENT
    from tests.test_windows_c_burst_review import native_event
    return native_event(3, {"SourceIp": CLIENT, "SourcePort": str(cport), "DestinationIp": SERVER,
                            "DestinationPort": str(sport), "Protocol": "tcp", "Initiated": "true",
                            "Image": "C:\\Windows\\System32\\mstsc.exe",
                            "ProcessGuid": "{00000000-0000-0000-0000-000000000004}", "ProcessId": "901"},
                        host=host, offset=offset, channel=SYSMON_CHANNEL, provider=SYSMON)


def test_sysmon_on_the_server_only_places_the_rdp_logon():
    from tests.test_net_host_join import sysmon3
    session = flow("rdp", cport=50100, sport=3389, start=0.0, duration=900.0)
    _rule, matches = run([[session], [sysmon3(0.2), logon4624(4.0, ltype=10)]], [finding("F1", [session])])
    assert len(matches) == 1 and "host recorded this connection itself" in matches[0].claim


def test_sysmon_on_both_ends_still_places_the_rdp_logon_on_the_server():
    from tests.test_net_host_join import sysmon3
    session = flow("rdp", cport=50100, sport=3389, start=0.0, duration=900.0)
    host = [sysmon3(0.2), _sysmon3_client(0.1), logon4624(4.0, ltype=10)]
    rule, matches = run([[session], host], [finding("F1", [session])])
    assert len(matches) == 1 and "host srv01 wrote" in matches[0].claim
    assert "several hosts recorded the same connection" not in _notes(rule)


def test_sysmon_on_the_client_only_does_not_stand_in_for_the_server():
    session = flow("rdp", cport=50100, sport=3389, start=0.0, duration=900.0)
    rule, matches = run([[session], [_sysmon3_client(0.1), logon4624(4.0, ltype=10)]], [finding("F1", [session])])
    # the client's own record places nothing; the server's portless logon is then an address-only join
    assert len(matches) == 1 and matches[0].confidence == "low"
    assert "host recorded this connection itself" not in matches[0].claim
    assert "recorded the connection logged no portless logon" not in _notes(rule)


# ---- I3: keeping the rows can fail without ending the sweep ------------------------------------------------------

def test_rows_that_cannot_be_kept_end_nothing_and_are_named(tmp_path):
    from romulus.detect.bounded import StateBudget
    from romulus.detect.net_host_join import NetworkAdminLogonJoin
    from tests.test_net_host_join import ssh_case
    blocker = tmp_path / "join"
    blocker.write_bytes(b"not a folder")                 # the rows' folder cannot be made
    rule = NetworkAdminLogonJoin()
    rule.spill_dir = tmp_path / "spill"
    rule.budget = StateBudget(tmp_path)
    rule.persist_path = blocker / "h1.db"
    session, host = ssh_case()
    _rule, matches = run([host, [session]], [finding("F1", [session])], rule=rule)
    assert len(matches) == 1                             # the sweep's own join stands
    assert any("could not be kept" in reason for reason in rule.limit_reasons())
    assert not list(tmp_path.glob("**/*.part"))


# ---- I4: a Windows logon id's span ends at its logoff or its reuse -----------------------------------------------

def test_a_logon_id_reused_after_a_reboot_never_lends_its_activity_or_flag_to_the_joined_logon():
    from tests.test_windows_c_burst_review import native_event
    session = flow("s1", cport=50000, sport=445, start=0.0)
    joined = [logon4624(0.5, port=50000), process4688(2, "C:\\Windows\\System32\\whoami.exe")]
    console = native_event(4624, {"TargetUserName": "bob", "TargetDomainName": "EXAMPLE", "IpAddress": "-",
                                  "IpPort": "-", "LogonType": "2", "TargetLogonId": "0x1a2b"},
                           host="srv01.example.test", offset=5000)
    later = process4688(5002, "C:\\Windows\\System32\\cmd.exe")
    _rule, matches = run([[session], [*joined, console, later]],
                         [finding("F1", [session]), finding("H1", [later], lane="high", rule="win.test_high")])
    m = matches[0]
    assert m.proposed_lane == "lead" and "win.test_high" not in m.claim
    assert "1 process or share record(s)" in m.claim and "cmd.exe" not in m.claim


def test_activity_and_flags_after_the_logoff_are_not_the_joined_logons():
    from tests.test_windows_c_burst_review import native_event
    session = flow("s1", cport=50000, sport=445, start=0.0)
    logoff = native_event(4634, {"TargetUserName": "alice", "TargetDomainName": "EXAMPLE", "LogonType": "3",
                                 "TargetLogonId": "0x1a2b"}, host="srv01.example.test", offset=100)
    after = process4688(200, "C:\\Windows\\System32\\cmd.exe")
    host = [logon4624(0.5, port=50000), process4688(2, "C:\\Windows\\System32\\whoami.exe"), logoff, after]
    _rule, matches = run([[session], host],
                         [finding("F1", [session]), finding("H1", [after], lane="high", rule="win.test_high")])
    m = matches[0]
    assert m.proposed_lane == "lead" and "1 process or share record(s)" in m.claim and "cmd.exe" not in m.claim


# ---- minors -------------------------------------------------------------------------------------------------------

def test_a_dual_stack_sshds_mapped_client_address_meets_the_sensors_ipv4_one():
    from tests.test_net_host_join import CLIENT
    session = flow("f1")
    _rule, matches = run([[session], [sshd("acc", 0.4, client="::ffff:" + CLIENT)]], [finding("F1", [session])])
    assert len(matches) == 1 and "client address and client port" in matches[0].claim


def test_a_session_only_a_later_stage_read_is_never_paired_by_address():
    from romulus.detect.net_host_join import NetworkAdminLogonJoin
    rule = NetworkAdminLogonJoin()
    rule.later_rules = frozenset({"pcap.test_rule"})
    unread = flow("p1", cport=50200, sport=5985, start=0.0, duration=40.0)   # the sweep never read it
    store = {unread.id: unread}
    host = [logon4624(1.0, host="srv02.example.test")]
    rule.consume(host)
    for event in host:
        store[event.id] = event
    pages = [finding("P1", [unread], rule="pcap.test_rule")]
    rule.bind_published(lambda lane, offset, limit: pages[offset:offset + limit] if lane == "lead" else [],
                        lambda ids: [store[i] for i in ids if i in store])
    assert list(rule.finalize()) == []
    assert "read by a later stage, not the sweep" in _notes(rule)
    # a port still ties a later stage's session to its own logon
    rule = NetworkAdminLogonJoin()
    rule.later_rules = frozenset({"pcap.test_rule"})
    rule.consume([logon4624(1.0, port=50200, host="srv02.example.test")])
    rule.bind_published(lambda lane, offset, limit: pages[offset:offset + limit] if lane == "lead" else [],
                        lambda ids: [store[i] for i in ids if i in store])
    assert len(list(rule.finalize())) == 1
