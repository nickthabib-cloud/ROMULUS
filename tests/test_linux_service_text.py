"""Synthetic service lines from upstream log statements, never collected telemetry.

Mail: https://www.exim.org/exim-html-current/doc/html/spec_html/ch-log_files.html
https://github.com/vdukhovni/postfix/blob/master/postfix/src/global/log_adhoc.c
https://www.postfix.org/ETRN_README.html (qmgr queue-active record)
https://github.com/vdukhovni/postfix/blob/master/postfix/src/smtpd/smtpd.c
DNS: https://github.com/imp/dnsmasq/blob/master/src/cache.c (log_query)
https://bind9.readthedocs.io/en/stable/reference.html (queries category)
https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html (log-queries)
VPN: https://github.com/OpenVPN/openvpn/blob/master/src/openvpn/multi.c
https://github.com/OpenVPN/openvpn/blob/release/2.6/src/openvpn/socket.c#L2394
https://github.com/strongswan/strongswan/blob/5.9.14/src/libcharon/sa/ikev2/tasks/child_create.c#L746
https://github.com/strongswan/strongswan/blob/master/src/libcharon/sa/ikev2/tasks/child_delete.c
Proxy: https://wiki.squid-cache.org/Features/LogFormat
Firewall: https://github.com/torvalds/linux/blob/master/net/netfilter/nf_log_syslog.c
https://github.com/jbq/ufw/blob/master/src/backend_iptables.py#L1048
Cron: https://github.com/cronie-crond/cronie/blob/master/src/do_command.c
https://github.com/cronie-crond/cronie/blob/master/src/crontab.c
Accounts: https://github.com/shadow-maint/shadow/blob/master/src/usermod.c
https://github.com/shadow-maint/shadow/blob/master/src/userdel.c
https://github.com/shadow-maint/shadow/blob/master/src/passwd.c
https://github.com/linux-pam/linux-pam/blob/master/modules/pam_unix/pam_unix_passwd.c
"""
from __future__ import annotations

import importlib
from datetime import UTC, datetime

import pytest

from romulus.evidence.typed import FieldValue, Outcome, TypedEvent


def _module():
    assert importlib.util.find_spec("romulus.evidence.linux_service_text") is not None
    return importlib.import_module("romulus.evidence.linux_service_text")


def parse(program, line):
    return _module().parse_service(program, line)


@pytest.mark.parametrize("mark,direction", [("<=", "received"), ("=>", "delivered"),
                                          ("->", "delivered"), ("**", "bounced"), ("==", "deferred")])
def test_exim_queue_markers(mark, direction):
    event = parse("exim4", f"1abcDE-000123-Ab {mark} sender@example.test H=mx.example.test [2001:db8::2] S=123")
    assert event.family == "mail_message"
    assert event.fields["mail.message_id"] == "1abcDE-000123-Ab"
    assert event.fields["mail.direction"] == direction
    if mark == "<=":
        assert event.fields["source.ip"] == "2001:db8::2"
        assert event.fields["mail.from"] == "sender@example.test"
    else:
        assert event.fields["mail.to"] == ["sender@example.test"]
        assert event.fields["destination.host"] == "mx.example.test"


def test_exim_logged_metadata_and_recipient_cap():
    recipients = " ".join(f"person{n}@example.test" for n in range(40))
    event = parse("exim", '1abcDE-000123-Ab <= sender@example.test H=mx.example.test [192.0.2.2]:51234 '
                  'P=esmtpsa X=TLS1.3:TLS_AES_256_GCM_SHA384 A=plain:alice S=350 T="A subject" for ' + recipients)
    assert event.fields["mail.to_count"] == 40
    assert len(event.fields["mail.to"]) == 32
    assert event.fields["mail.authenticated_user"] == "alice"
    assert event.fields["mail.tls"] is True
    assert event.fields["mail.subject"] == "A subject"
    assert event.fields["source.port"] == 51234
    assert event.caveats and "32" in event.caveats[0]
    assert "mail.attachment_names" not in event.fields


def test_exim_rejection_has_no_invented_queue_or_sender():
    event = parse("exim", 'H=mx.example.test [192.0.2.9] F=<a@example.test> rejected RCPT <b@example.test>: denied')
    assert event.fields["mail.direction"] == "rejected"
    assert event.fields["mail.to"] == ["b@example.test"]
    assert "mail.message_id" not in event.fields


@pytest.mark.parametrize("program,line,direction", [
    ("postfix/qmgr", "ABC123: from=<a@example.test>, size=203, nrcpt=4 (queue active)", "received"),
    ("postfix/smtp", "ABC123: to=<b@example.test>, relay=mx.example.test[2001:db8::4]:25, delay=1, dsn=2.0.0, status=sent (250 ok)", "delivered"),
    ("postfix/smtp", "ABC123: to=<b@example.test>, relay=none, delay=1, dsn=4.0.0, status=deferred (timeout)", "deferred"),
    ("postfix/smtp", "ABC123: to=<b@example.test>, relay=none, delay=1, dsn=5.0.0, status=bounced (no user)", "bounced"),
])
def test_postfix_per_line_queue_events(program, line, direction):
    event = parse(program, line)
    assert event.fields["mail.message_id"] == "ABC123"
    assert event.fields["mail.direction"] == direction
    assert "mail.authenticated_user" not in event.fields


def test_postfix_metadata_is_not_delivery_or_header_id_as_queue_id():
    event = parse("postfix/smtpd", "ABC123: client=client.example.test[192.0.2.8], sasl_method=PLAIN, sasl_username=alice")
    assert event.fields["mail.authenticated_user"] == "alice"
    assert "mail.direction" not in event.fields
    event = parse("postfix/cleanup", "ABC123: message-id=<header@example.test>")
    assert event.fields["mail.message_id"] == "ABC123"
    assert event.fields["mail.header_message_id"] == "header@example.test"


@pytest.mark.parametrize("program,line,fields", [
    ("dnsmasq", "query[AAAA] example.test from 2001:db8::2", {"dns.type": "query", "dns.question.type": "AAAA", "source.ip": "2001:db8::2"}),
    ("dnsmasq", "forwarded example.test to 192.0.2.53", {"dns.type": "query", "destination.ip": "192.0.2.53"}),
    ("dnsmasq", "reply example.test is NXDOMAIN", {"dns.type": "answer", "dns.response_code": "NXDOMAIN"}),
    ("dnsmasq", "cached example.test is 192.0.2.2", {"dns.type": "answer"}),
    ("dnsmasq", "config example.test is NXDOMAIN", {"dns.type": "answer", "dns.response_code": "NXDOMAIN"}),
    ("dnsmasq", "/etc/hosts example.test is 192.0.2.2", {"dns.type": "answer"}),
    ("named", "client @0xabc 2001:db8::2#51234 (example.test): query: example.test IN AAAA +E(0) (2001:db8::53)",
     {"dns.type": "query", "dns.question.type": "AAAA", "source.ip": "2001:db8::2", "source.port": 51234}),
    ("unbound", "info: 2001:db8::2 example.test. AAAA IN", {"dns.type": "query", "dns.question.type": "AAAA", "source.ip": "2001:db8::2"}),
])
def test_resolver_fields_match_dns_contract(program, line, fields):
    event = parse(program, line)
    assert event.family == "dns_query"
    assert event.fields["dns.question.name"].rstrip(".") == "example.test"
    assert all(event.fields[k] == v for k, v in fields.items())
    assert "destination.port" not in event.fields  # no port in these source formats
    assert "network.community_id" not in event.fields


def test_dnsmasq_extra_prefix_does_not_become_a_network_dns_id():
    event = parse("dnsmasq", "51 192.0.2.9/51200 query[A] example.test from 192.0.2.9")
    assert event.fields["source.ip"] == "192.0.2.9"
    assert event.fields["source.port"] == 51200
    assert "dns.id" not in event.fields


def test_dns_answer_uses_existing_resource_record_shape():
    event = parse("dnsmasq", "reply example.test is 2001:db8::5")
    assert event.fields["dns.answers"] == [{"name": "example.test", "type": "AAAA", "ttl": None, "data": "2001:db8::5"}]
    assert "source.ip" not in event.fields


@pytest.mark.parametrize("line,action", [
    ("alice/192.0.2.2:51234 MULTI_sva: pool returned IPv4=10.8.0.2, IPv6=(Not enabled)", "assign"),
    ("[alice] Peer Connection Initiated with [AF_INET6][2001:db8::2]:51234", "connect"),
    ("alice/192.0.2.2:51234 SIGTERM[soft,remote-exit] received, client-instance exiting", "disconnect"),
])
def test_openvpn_lifecycle(line, action):
    event = parse("openvpn", line)
    assert event.family == "vpn_session"
    assert event.fields["vpn.action"] == action
    assert event.fields["user.name"] == "alice"
    assert "vpn.session_id" not in event.fields
    assert "event.duration" not in event.fields
    if action == "assign":
        assert event.fields["vpn.assigned_ip"] == "10.8.0.2"
    assert event.caveats


@pytest.mark.parametrize("line,action", [
    ("12[IKE] CHILD_SA tunnel{4} established with SPIs c1_i c2_o and TS 10.0.0.0/24 === 10.1.0.0/24", "connect"),
    ("12[IKE] closing CHILD_SA tunnel{4} with SPIs c1_i (123 bytes) c2_o (456 bytes) and TS 10.0.0.0/24 === 10.1.0.0/24", "disconnect"),
])
def test_strongswan_native_child_id_is_not_a_user(line, action):
    event = parse("charon", line)
    assert event.fields["vpn.session_id"] == "4"
    assert event.fields["vpn.action"] == action
    assert "user.name" not in event.fields
    assert "source.ip" not in event.fields  # selectors are not remote peer addresses


def test_squid_native_connect_status_and_ipv6():
    event = parse("squid", "1794168000.001 20 2001:db8::2 TCP_TUNNEL/200 1024 CONNECT example.test:443 alice HIER_DIRECT/192.0.2.5 -")
    assert event.family == "http_access"
    assert event.fields["http.request.method"] == "CONNECT"
    assert event.fields["http.response.status_code"] == 200
    assert event.fields["source.ip"] == "2001:db8::2"
    assert event.fields["url.original"] == "example.test:443"
    assert event.outcome == Outcome.success


@pytest.mark.parametrize("prefix,action", [("[UFW BLOCK]", "block"), ("[UFW ALLOW]", "allow"),
                                         ("[UFW AUDIT]", "audit"), ("DENY suspicious", "logged")])
def test_firewall_only_explicit_action(prefix, action):
    event = parse("kernel", f"{prefix} IN=eth0 OUT= MAC=aa:bb SRC=2001:db8::2 DST=2001:db8::3 LEN=60 PROTO=TCP SPT=1234 DPT=443 SYN")
    assert event.family == "net_flow"
    assert event.fields["firewall.action"] == action
    assert event.fields["source.ip"] == "2001:db8::2"
    assert event.fields["destination.port"] == 443
    assert event.fields["network.transport"] == "tcp"
    assert event.outcome == Outcome.unknown
    assert not any(k.startswith("flow.") for k in event.fields)


def test_cron_scheduler_observation_and_changes():
    event = parse("CRON", '(alice) CMD (echo "Login successful"; id)')
    assert event.family == "process_observed"
    assert event.fields["process.command_line"] == 'echo "Login successful"; id'
    assert event.fields["process.user"] == "alice"
    assert "process.uid" not in event.fields and event.caveats
    for marker, action in (("REPLACE", "replace"), ("BEGIN EDIT", "begin_edit")):
        event = parse("crontab", f"(alice) {marker} (root)")
        assert event.family == "service_change"
        assert event.fields["service.action"] == action
        assert event.fields["account.name"] == "root"
        assert "file.path" not in event.fields


@pytest.mark.parametrize("program,line,action,name", [
    ("usermod", "add 'alice' to group 'sudo'", "add_user_to_group", "alice"),
    ("usermod", "lock user 'alice' password", "lock_user", "alice"),
    ("usermod", "unlock user 'alice' password", "unlock_user", "alice"),
    ("userdel", "delete user 'alice'", "delete_user", "alice"),
    ("passwd", "password for 'alice' changed by 'root'", "change_password", "alice"),
    ("chpasswd", "pam_unix(chpasswd:chauthtok): password changed for alice", "change_password", "alice"),
])
def test_account_change_native_fields(program, line, action, name):
    event = parse(program, line)
    assert event.family == "account_change"
    assert event.fields["account.action"] == action
    assert event.fields["account.name"] == name
    assert "account.id" not in event.fields


@pytest.mark.parametrize("program,line", [
    ("exim", "a user mentioned 1abcDE-000123-Ab <= x@example.test"),
    ("exim", '1abcDE-000123-Ab <= sender@example.test T="A=plain:injected for attacker@evil.test"'),
    ("postfix/smtp", "ABC123: warning: user to=<x@example.test> status=sent"),
    ("postfix/smtp", "ABC123: to=<status=sent@example.test>, relay=none, status=deferred (failure)"),
    ("dnsmasq", "user query[A] example.test from 192.0.2.2"),
    ("dnsmasq", "query[A] example.test from not-an-address"),
    ("named", "client user query: example.test IN A + (192.0.2.53)"),
    ("unbound", "info: user example.test A IN"),
    ("squid", "1794168000.001 20 user TCP_TUNNEL/200 5 CONNECT x:443 - HIER_DIRECT/192.0.2.5 -"),
    ("kernel", "application says SRC=192.0.2.2 DST=192.0.2.3 PROTO=TCP"),
    ("kernel", "[UFW BLOCK] IN=eth0 OUT= SRC=not-ip DST=192.0.2.3 PROTO=TCP"),
    ("CRON", "(alice CMD (id)) session opened"),
    ("crontab", "(alice) LIST (root)"),
    ("usermod", "error: add 'alice' to group 'sudo'"),
    ("userdel", "failed to delete user 'alice'"),
    ("passwd", "password for 'alice changed by root' cannot be changed"),
    ("openvpn", "alice Peer Connection Initiated with not-an-address"),
    ("charon", "username CHILD_SA tunnel{4} established"),
])
def test_adversarial_lines_do_not_invent_actions(program, line):
    event = parse(program, line)
    if program == "exim" and line.startswith("1abc"):
        assert event.fields["mail.subject"] == "A=plain:injected for attacker@evil.test"
        assert "mail.authenticated_user" not in event.fields and "mail.to" not in event.fields
    elif program == "postfix/smtp" and line.startswith("ABC123: to="):
        assert event.fields["mail.direction"] == "deferred"
    else:
        assert event is None


@pytest.mark.parametrize("program,line", [
    ("exim", "2026-11-09 12:00:00 [42] 1abcDE-000123-Ab <= a@example.test S=12"),
    ("dnsmasq", "Nov  9 12:00:00 dnsmasq[42]: query[A] example.test from 192.0.2.2"),
    ("squid", "1794168000.001 20 192.0.2.2 TCP_TUNNEL/200 1024 CONNECT example.test:443 - HIER_DIRECT/192.0.2.5 -"),
    ("openvpn", "Mon Nov  9 12:00:00 2026 [alice] Peer Connection Initiated with [AF_INET]192.0.2.2:51234"),
])
def test_fixed_application_identification(program, line):
    identified = _module().identify_service(line)
    assert identified and identified[0] == program
    assert parse(*identified) is not None


def test_unrecognized_and_oversize_lines_are_not_guessed():
    assert parse("application", "query[A] example.test from 192.0.2.2") is None
    assert _module().identify_service("error query[A] example.test from 192.0.2.2") is None
    assert parse("exim", "x" * 65537) is None
    assert _module().identify_service("x" * 65537) is None
    for program in ("dpkg", "apt", "yum", "dnf"):
        assert parse(program, "installed something") is None


def test_large_numeric_fields_are_skipped_without_exception():
    assert parse("squid", "1794168000.001 20 192.0.2.2 TCP_TUNNEL/200 " + "9" * 5000
                 + " CONNECT example.test:443 - HIER_DIRECT/192.0.2.5 -") is None


def test_exim_unverified_host_still_has_logged_peer_address():
    event = parse("exim", "1abcDE-000123-Ab <= a@example.test H=(unverified) [2001:db8::8] S=12")
    assert event.fields["source.ip"] == "2001:db8::8"
    assert "source.host" not in event.fields


def test_exim_status_words_inside_sender_and_subject_never_authenticate():
    event = parse("exim", '1abcDE-000123-Ab <= success@example.test T="Login successful A=plain:root" S=12')
    assert event.family == "mail_message"
    assert event.fields["mail.from"] == "success@example.test"
    assert "mail.authenticated_user" not in event.fields


def test_strongswan_closing_counters():
    event = parse("charon", "12[IKE] closing CHILD_SA tunnel{4} with SPIs c1_i (123 bytes) c2_o (456 bytes) and TS 10.0.0.0/24 === 10.1.0.0/24")
    assert event.fields["vpn.action"] == "disconnect"
    assert event.fields["vpn.bytes_received"] == 123
    assert event.fields["vpn.bytes_sent"] == 456


def test_openvpn_learn_is_address_assignment_not_authentication():
    event = parse("openvpn", "alice/192.0.2.2:51234 MULTI: Learn: 10.8.0.2 -> alice/192.0.2.2:51234")
    assert event.family == "vpn_session"
    assert event.fields["vpn.action"] == "assign"
    assert event.fields["vpn.assigned_ip"] == "10.8.0.2"
    assert event.fields["user.name"] == "alice"


@pytest.mark.parametrize("line,program", [
    # Source: vsftpd logging.c, vsf_log_do_log_wuftpd_format and native formatter.
    ("Mon Nov  9 12:00:00 2026 1 192.0.2.2 100 /pub/test.txt b _ o r alice ftp 0 * c", "ftp-xferlog"),
    ('Mon Nov  9 12:00:00 2026 [pid 42] [alice] OK DOWNLOAD: Client "192.0.2.2", "/pub/test.txt", 100 bytes, 1.00Kbyte/sec', "vsftpd"),
    # Source: Samba lib/util/debug.c, dbghdrclass; ModSecurity 2 Data Formats, audit sections.
    ("[2026/11/09 12:00:00.000000,  2] source3/auth/auth.c:123(auth_check_ntlm_password)", "smbd"),
    ("--c7036611-A--", "modsecurity-audit"),
    ("--c7036611-B--", "modsecurity-audit"),
    ("--c7036611-F--", "modsecurity-audit"),
])
def test_known_untyped_application_envelopes_get_named_skips(line, program):
    assert _module().identify_service(line) == (program, line)
    assert parse(program, line) is None


@pytest.mark.parametrize("line", ["--user-A--", "[2026/11/09 12:00:00] Login successful", "GET / HTTP/1.1",
                                "Mon Nov  9 12:00:00 2026 1 username 100 /f b _ o r alice ftp 0 * c"])
def test_lookalike_application_envelopes_are_not_identified(line):
    assert _module().identify_service(line) is None


@pytest.mark.parametrize("line,field,value", [
    ("change user 'alice' UID from '1000' to '0'", "account.id", "0"),
    ("change user 'alice' shell from '/bin/sh' to '/bin/bash'", "account.shell", "/bin/bash"),
    ("change user name 'alice' to 'bob'", "account.name", "bob"),
    ("change user 'alice' GID from '1000' to '0'", "group.id", "0"),
])
def test_usermod_updates_are_typed_only_from_structured_log_values(line, field, value):
    event = parse("usermod", line)
    assert event.family == "account_change"
    assert event.fields[field] == value
    assert "process.uid" not in event.fields


def _typed(program, line):
    parsed = parse(program, line)
    return TypedEvent(id="service-1", family=parsed.family, ts=datetime(2026, 1, 1, tzinfo=UTC),
                      host="resolver.example.test", outcome=parsed.outcome,
                      fields={key: FieldValue(value=value, origin="synthetic:message")
                              for key, value in parsed.fields.items()}, raw=[], normalizer="test")


def test_resolver_queries_reach_existing_dns_rules_without_field_translation():
    from romulus.detect.dns import DnsTunnelShape, DnsZoneTransferOrAnyRequest

    tunnel = DnsTunnelShape()
    zone = DnsZoneTransferOrAnyRequest()
    try:
        tunnel.consume([_typed("dnsmasq", "query[TXT] encoded.example.org from 192.0.2.2")])
        assert tunnel.evaluated == 1 and tunnel.missing_required == 0
        zone.consume([_typed("named", "client @0xabc 192.0.2.2#51234 (example.org): query: example.org IN AXFR + (192.0.2.53)")])
        assert zone.evaluated == 1 and zone.missing_required == 0
        # dnsmasq query format does not identify the local server: no fabricated server.
        zone.consume([_typed("dnsmasq", "query[AXFR] example.org from 192.0.2.2")])
        assert zone.missing_required == 1
    finally:
        tunnel.release_state()
        zone.release_state()


def test_firewall_reaches_port_scan_but_not_bidirectional_flow_sweep():
    from romulus.detect.flows import HorizontalSweep
    from romulus.detect.network import PortScan

    event = _typed("kernel", "[UFW BLOCK] IN=eth0 OUT= SRC=192.0.2.2 DST=192.0.2.3 PROTO=TCP SPT=12345 DPT=443")
    ports = PortScan()
    sweep = HorizontalSweep()
    try:
        ports.consume([event])
        assert ports.missing_required == 0
        assert ports.groups.peek(("192.0.2.2", "192.0.2.3")).bag("ports") == {443}
        sweep.consume([event])
        assert sweep.missing_required == 1 and sweep.evaluated == 0
    finally:
        ports.release_state()
        sweep.release_state()


@pytest.mark.parametrize("metadata", [
    "H=(hello A=plain:admin) [192.0.2.8] P=esmtp S=12",
    "H=(hello A=plain:admin) [192.0.2.8] P=esmtpa S=12",
    "H=(hello for attacker@example.test) [192.0.2.8] P=esmtp S=12",
    'H=mx.example.test [192.0.2.8] P=esmtp S=12 T="A=plain:admin"',
    "H=mx.example.test [192.0.2.8] P=esmtp A=plain:admin S=12",
])
def test_exim_helo_and_subject_cannot_supply_authenticated_sender_or_recipients(metadata):
    event = parse("exim", "1abcDE-000123-Ab <= a@example.test " + metadata)
    assert event.family == "mail_message"
    assert "mail.authenticated_user" not in event.fields
    assert "mail.to" not in event.fields


def test_raw_exim_authenticator_failure_is_identified_without_queue_id():
    line = "2026-11-09 12:00:00 plain authenticator failed for (client) [192.0.2.2]: 535 Incorrect authentication data (set_id=alice)"
    assert _module().identify_service(line) == ("exim", line[20:])


def test_numeric_lookalikes_never_raise_or_become_values():
    event = parse("exim", "1abcDE-000123-Ab <= a@example.test S=²")
    assert "mail.size" not in event.fields
    assert parse("kernel", "IN=eth0 OUT= SRC=192.0.2.2 DST=192.0.2.3 PROTO=²") is None


def test_unverified_lifecycle_phrase_is_not_guessed():
    assert parse("charon", "12[IKE] deleting CHILD_SA tunnel{4} with SPIs c1_i c2_o") is None


def test_service_entry_points_enforce_utf8_byte_limit():
    message = '1abcDE-000123-Ab <= a@example.test T="' + "\u00e9" * 33000 + '"'
    assert len(message) < 65536 < len(message.encode("utf-8"))
    assert parse("exim", message) is None
    assert _module().identify_service("2026-11-09 12:00:00 " + message) is None


@pytest.mark.parametrize("prefix,user", [("192.0.2.2:51234", "client1"),
                                         ("client1/192.0.2.2:51234", "client1")])
def test_openvpn_real_context_prefix_precedes_peer_connection(prefix, user):
    # multi.c multi_instance_string + error.c x_msg_va prefix socket.c's connection message.
    event = parse("openvpn", prefix + " [client1] Peer Connection Initiated with [AF_INET]192.0.2.2:51234")
    assert event is not None and event.family == "vpn_session"
    assert event.fields == {"vpn.service": "openvpn", "vpn.action": "connect", "user.name": user,
                            "source.ip": "192.0.2.2", "source.port": 51234}
    assert "common name" in event.caveats[0]


@pytest.mark.parametrize("prefix,user", [("192.0.2.2:51234", None),
                                         ("client1/192.0.2.2:51234", "client1")])
def test_openvpn_context_without_body_common_name_does_not_invent_an_account(prefix, user):
    event = parse("openvpn", prefix + " Peer Connection Initiated with [AF_INET]192.0.2.2:51234")
    assert event is not None
    assert event.fields.get("user.name") == user
    assert event.fields["source.ip"] == "192.0.2.2" and event.fields["source.port"] == 51234


def test_openvpn_connect_peer_comes_from_statement_not_stale_context():
    event = parse("openvpn", "old/192.0.2.9:11111 [client1] Peer Connection Initiated with [AF_INET]192.0.2.2:51234")
    assert event is not None
    assert event.fields["user.name"] == "client1"
    assert event.fields["source.ip"] == "192.0.2.2" and event.fields["source.port"] == 51234
    partial = parse("openvpn", "client1/192.0.2.9:11111 [client1] Peer Connection Initiated with 192.0.2.2")
    assert partial is not None and partial.fields["source.ip"] == "192.0.2.2"
    assert "source.port" not in partial.fields


@pytest.mark.parametrize("line", [
    "message: 192.0.2.2:51234 [client1] Peer Connection Initiated with [AF_INET]192.0.2.2:51234",
    "client1/not-an-ip:51234 [client1] Peer Connection Initiated with [AF_INET]192.0.2.2:51234",
    "client1/192.0.2.2:99999 [client1] Peer Connection Initiated with [AF_INET]192.0.2.2:51234",
    "192.0.2.2:51234 [client1] Peer Connection Initiated with [AF_INET]192.0.2.2:51234 trailing text",
    "192.0.2.2:51234 notice: [client1] Peer Connection Initiated with [AF_INET]192.0.2.2:51234",
])
def test_openvpn_context_does_not_unanchor_connection_grammar(line):
    assert parse("openvpn", line) is None
