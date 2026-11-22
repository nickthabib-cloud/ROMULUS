"""Adversarial joins from the network-to-host join's review: each must stay unresolved, or be joined at the lane its
key supports. Addresses are private or documentation ranges, hosts and accounts are invented."""
from tests.test_net_host_join import (
    CLIENT,
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
    rule, matches = run([[cited], [sshd("late", 1800.3, host="web02")]], [finding("F1", [cited])])
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
