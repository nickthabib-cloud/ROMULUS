"""OpenVPN's own log file, read without a syslog envelope.

The line layout follows OpenVPN's source (release/2.6): error.c x_msg_va writes "<time> <prefix> <message>", otime.c
time_string formats the time as "%Y-%m-%d %H:%M:%S" with " us=<n>" at high verbosity (2.4 and earlier wrote ctime's
"Www Mmm dd hh:mm:ss yyyy"), and a server's client context prefixes "common-name/address:port" (or "address:port"
before the certificate is read). The messages are those of multi.c (MULTI: Learn, MULTI_sva), ssl.c and ssl_verify.c
(TLS: Initial packet, VERIFY, TLS Error, TLS Auth Error, Username/Password authentication), socket.c (Peer Connection
Initiated), forward.c (Inactivity timeout) and sig.c print_signal (client-instance exiting/restarting). Every line
below is synthetic.
"""
from __future__ import annotations

from datetime import timedelta

import pytest

from romulus.detect.vpn import VpnConcurrentSessions
from romulus.evidence.linux_text import classify
from romulus.evidence.normalize import normalize_hits
from romulus.evidence.typed import Outcome

ISO, CTIME = "2024-11-18 14:00:03", "Mon Nov 18 14:00:03 2024"
PEER, OTHER = "203.0.113.9", "198.51.100.8"


def typed(lines, dataset="openvpn.log"):
    hits = [{"_index": "i", "_id": f"v{n}", "_source": {"@timestamp": f"2024-11-18T14:{n:02d}:03Z", "message": line,
                                                       "event": {"dataset": dataset}, "host": {"name": "vpn1"},
                                                       "input": {"type": "log"}}}
            for n, line in enumerate(lines)]
    events, skips, errors = normalize_hits(hits)
    assert not errors
    return events, skips


def values(event, *names):
    return {name: event.get(name) for name in names}


@pytest.mark.parametrize("stamp", [ISO, f"{ISO} us=412233", CTIME])
def test_session_lifecycle_lines_are_typed_in_every_time_format(stamp):
    events, skips = typed([
        f"{stamp} {PEER}:51234 TLS: Initial packet from [AF_INET]{PEER}:51234, sid=1a2b3c4d 5e6f7a8b",
        f"{stamp} {PEER}:51234 VERIFY OK: depth=0, CN=alice-laptop",
        f"{stamp} {PEER}:51234 TLS: Username/Password authentication succeeded for username 'alice'",
        f"{stamp} alice-laptop/{PEER}:51234 Peer Connection Initiated with [AF_INET]{PEER}:51234",
        f"{stamp} alice-laptop/{PEER}:51234 MULTI_sva: pool returned IPv4=10.8.0.6, IPv6=(Not enabled)",
        f"{stamp} alice-laptop/{PEER}:51234 MULTI: Learn: 10.8.0.6 -> alice-laptop/{PEER}:51234",
        f"{stamp} alice-laptop/{PEER}:51234 [alice-laptop] Inactivity timeout (--ping-restart), restarting",
        f"{stamp} alice-laptop/{PEER}:51234 SIGUSR1[soft,ping-restart] received, client-instance restarting",
    ])
    assert not skips
    attempt, verify, login, connect, pool, learn, timeout, closed = events
    assert attempt.family == "vpn_session" and values(attempt, "vpn.action", "source.ip", "source.port") == {
        "vpn.action": "attempt", "source.ip": PEER, "source.port": 51234}
    assert attempt.outcome == Outcome.unknown
    # the certificate check is not a password decision, and its common name is not an account
    assert verify.family == "auth" and values(verify, "auth.phase", "auth.method", "user.name") == {
        "auth.phase": "certificate_verification", "auth.method": "certificate", "user.name": None}
    assert login.family == "auth" and login.outcome == Outcome.success
    assert values(login, "auth.service", "auth.phase", "user.name", "source.ip", "source.port") == {
        "auth.service": "openvpn", "auth.phase": "authentication", "user.name": "alice", "source.ip": PEER,
        "source.port": 51234}
    assert values(connect, "vpn.action", "user.name", "source.ip", "source.port") == {
        "vpn.action": "connect", "user.name": "alice-laptop", "source.ip": PEER, "source.port": 51234}
    assert pool.get("vpn.assigned_ip") == "10.8.0.6" and learn.get("vpn.assigned_ip") == "10.8.0.6"
    assert ("ip", "10.8.0.6", "assigned") in learn.entities()
    # the timeout gives the reason; the signal line is the one boundary that closes the instance
    assert values(timeout, "vpn.action", "vpn.reason") == {"vpn.action": "timeout", "vpn.reason": "--ping-restart"}
    assert values(closed, "vpn.action", "vpn.reason") == {"vpn.action": "disconnect",
                                                          "vpn.reason": "soft,ping-restart"}
    assert all(e.get("log.inline_timestamp") for e in events)


@pytest.mark.parametrize("message,expected", [
    ("TLS Auth Error: Auth Username/Password verification failed for peer",
     {"auth.phase": "authentication", "auth.method": "tls"}),
    ("TLS Error: TLS handshake failed", {"auth.phase": "tls_handshake"}),
    ("TLS Error: TLS key negotiation failed to occur within 60 seconds (check your network connectivity)",
     {"auth.phase": "tls_handshake"}),
    ("VERIFY ERROR: depth=0, error=certificate has expired: CN=alice-laptop, serial=4",
     {"auth.phase": "certificate_verification", "auth.method": "certificate"}),
    ("AUTH: Received control message: AUTH_FAILED", {"auth.phase": "authentication"}),
])
def test_failures_are_typed_without_inventing_a_user(message, expected):
    [event], skips = typed([f"{ISO} {PEER}:51234 {message}"])
    assert not skips and event.family == "auth" and event.outcome == Outcome.failure
    assert values(event, *expected) == expected
    assert event.get("source.ip") == PEER and event.get("user.name") is None


def test_a_packet_authentication_failure_names_its_sender():
    [event], _skips = typed([f"{ISO} TLS Error: incoming packet authentication failed from [AF_INET]{OTHER}:40000"])
    assert values(event, "auth.phase", "source.ip", "source.port") == {
        "auth.phase": "packet_authentication", "source.ip": OTHER, "source.port": 40000}


@pytest.mark.parametrize("line,reason", [
    (f"{ISO} Initialization Sequence Completed",
     "OpenVPN status, channel or configuration line (not an authentication decision or session boundary)"),
    (f"{ISO} alice-laptop/{PEER}:51234 SENT CONTROL [alice-laptop]: 'PUSH_REPLY,route 10.8.0.1' (status=1)",
     "OpenVPN status, channel or configuration line (not an authentication decision or session boundary)"),
    (f"{ISO} {PEER}:51234 SENT CONTROL [UNDEF]: 'AUTH_FAILED' (status=1)",
     "OpenVPN AUTH_FAILED notice sent to the client (the decision is its TLS Auth Error line)"),
])
def test_other_openvpn_lines_are_counted_skips_with_precise_reasons(line, reason):
    events, skips = typed([line])
    assert not events
    assert skips == {f"text format application, program 'openvpn' ({reason}) is not normalized: openvpn.log": 1}


@pytest.mark.parametrize("line", [
    # an analyst searching the log: the search is the action
    "Nov 18 14:00:05 analyst1 bash[812]: grep 'Peer Connection Initiated' /var/log/openvpn.log",
    # an OpenVPN line echoed by another program's syslog record
    f"Nov 18 14:00:05 web1 logger: {ISO} alice/{PEER}:51234 Peer Connection Initiated with [AF_INET]{PEER}:51234",
    # another application's line with the same time layout
    f"{ISO} worker[3]: job finished, peer {PEER}:51234 connected",
])
def test_mentions_are_never_vpn_or_auth_events(line):
    events, _skips = typed([line], dataset="custom.log")
    assert not [e for e in events if e.family in ("vpn_session", "auth")]


def shipped(line, **source):
    hit = {"_index": "i", "_id": "f1", "_source": {"@timestamp": "2026-11-09T12:00:00Z", "message": line,
                                                   "host": {"name": "vpn1"}, "input": {"type": "log"}, **source}}
    events, skips, errors = normalize_hits([hit])
    assert not errors
    return events, skips


FAILED_LINE = "2026-11-09 12:00:00 AUTH: Received control message: AUTH_FAILED"


@pytest.mark.parametrize("source", [
    {"event": {"dataset": "openvpn.log"}},
    {"event": {"dataset": "custom.text"}, "log": {"file": {"path": "/var/log/openvpn.log"}}},
    {"event": {"dataset": "custom.text", "module": "openvpn"}},
    {"data_stream": {"dataset": "openvpn.server"}},
], ids=["dataset", "file", "module", "data-stream"])
def test_an_iso_stamped_line_is_openvpn_when_the_record_says_it_came_from_an_openvpn_log(source):
    [event], skips = shipped(FAILED_LINE, **source)
    assert not skips and event.family == "auth" and event.get("auth.service") == "openvpn"
    assert event.outcome == Outcome.failure


@pytest.mark.parametrize("line", [FAILED_LINE, "2026-11-09 12:00:00 MULTI: worker pool resized",
                                  f"2026-11-09 12:00:00 {PEER}:51234 WARNING: retrying the upload"])
def test_an_iso_stamped_line_from_another_programs_file_is_never_openvpn(line):
    events, skips = shipped(line, event={"dataset": "app.log"}, log={"file": {"path": "/var/log/app.log"}})
    assert events == [] and list(skips) == ["text line in no recognized format: app.log"]


def test_an_untyped_openvpn_phrase_in_a_ctime_line_needs_the_openvpn_file():
    line = f"{CTIME} Initialization Sequence Completed"
    assert classify(line).format == "unknown"
    _events, skips = shipped(line, event={"dataset": "openvpn.log"})
    assert list(skips) == [("text format application, program 'openvpn' (OpenVPN status, channel or configuration "
                            "line (not an authentication decision or session boundary)) is not normalized: openvpn.log")]


@pytest.mark.parametrize("line", [f"{ISO} worker[3]: job finished", f"{ISO} Connection reset by peer",
                                  f"{ISO} NOTE: the cache was rebuilt", f"{CTIME} Timers: 3 pending"])
def test_unrelated_stamped_lines_are_not_identified_as_openvpn(line):
    # generic openers identify OpenVPN only behind its client-context prefix
    assert classify(line).format == "unknown"


def test_a_generic_opener_behind_the_client_prefix_is_an_openvpn_skip():
    _events, skips = typed([f"{ISO} alice-laptop/{PEER}:51234 Connection reset, restarting [0]"])
    assert list(skips) == [("text format application, program 'openvpn' (OpenVPN status, channel or configuration "
                            "line (not an authentication decision or session boundary)) is not normalized: openvpn.log")]


def test_a_timeout_and_its_signal_close_one_session():
    lines = [f"{ISO} alice-laptop/{PEER}:51234 Peer Connection Initiated with [AF_INET]{PEER}:51234",
             f"{ISO} alice-laptop/{PEER}:51234 Inactivity timeout (--inactive), exiting",
             f"{ISO} alice-laptop/{PEER}:51234 SIGTERM[soft,inactive] received, client-instance exiting"]
    events, _skips = typed(lines)
    rule = VpnConcurrentSessions()
    try:
        rule.consume(events)
        assert list(rule.finalize()) == []
        # the connect and its one disconnect form a closed interval; the timeout line is not a second boundary
        assert rule.missing_required == 0 and rule.evaluated == 2
    finally:
        rule.release_state()


def test_native_openvpn_lines_reach_the_concurrent_session_rule_through_the_sweep(tmp_path, monkeypatch):
    """Two overlapping sessions of one common name from distinct addresses, in the 2.5+ time format, on a Linux host
    target: the concurrency rule reports them. A line at the window end is outside the half-open window."""
    from tests import throughput_fixture as tf
    from tests.test_dataset_reconciliation import FILEBEAT_TYPES, _profile

    builder = tf.Builder(23)
    plan = [(0, PEER, 51234, "connect"), (60, OTHER, 40001, "connect"), (600, PEER, 51234, "disconnect"),
            (900, OTHER, 40001, "disconnect")]
    messages = []
    for offset, address, port, action in plan:
        when = tf.T0 + timedelta(seconds=offset)
        stamp = when.strftime("%Y-%m-%d %H:%M:%S")
        body = (f"Peer Connection Initiated with [AF_INET]{address}:{port}" if action == "connect"
                else "SIGTERM[soft,remote-exit] received, client-instance exiting")
        line = f"{stamp} alice-laptop/{address}:{port} {body}"
        messages.append(line)
        builder._doc("web1", when, "openvpn.log", None, message=line, input={"type": "log"},
                     log={"file": {"path": "/var/log/openvpn/openvpn.log"}})
    late = (f"{tf.WINDOW_END.strftime('%Y-%m-%d %H:%M:%S')} alice-laptop/192.0.2.77:1 Peer Connection Initiated "
            f"with [AF_INET]192.0.2.77:1")
    builder._doc("web1", tf.WINDOW_END, "openvpn.log", None, message=late, input={"type": "log"},
                 log={"file": {"path": "/var/log/openvpn/openvpn.log"}})
    docs = {tf.HOST_TARGET: builder.host, tf.NETWORK_TARGET: [], tf.ARKIME_TARGET: []}
    with monkeypatch.context() as patch:
        tf.patched_sizes(patch)
        patch.setattr(tf, "HOST_TYPES", FILEBEAT_TYPES)
        snapshot = tf.run_stack(tmp_path, docs=docs,
                                profiles={tf.HOST_TARGET: _profile(FILEBEAT_TYPES, {"openvpn.log": messages})})
    assert snapshot["stats"]["linux_shapes"][tf.HOST_TARGET] == {"linux.text:openvpn.log": 4}
    [candidate] = [row for row in snapshot["candidates"]
                   if row["rule_id"] == "vpn.concurrent_sessions_same_user_distinct_sources"]
    assert PEER in candidate["claim"] and OTHER in candidate["claim"] and "alice-laptop" in candidate["claim"]
    assert "192.0.2.77" not in candidate["claim"]
