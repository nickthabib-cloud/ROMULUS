"""Synthetic real-shape OpenVPN server logs, including its per-client log prefix.

Official release/2.6 source:
https://github.com/OpenVPN/openvpn/blob/release/2.6/src/openvpn/multi.c#L432-L474
https://github.com/OpenVPN/openvpn/blob/release/2.6/src/openvpn/error.c#L286-L321
https://github.com/OpenVPN/openvpn/blob/release/2.6/src/openvpn/socket.c#L2236-L2244
https://github.com/OpenVPN/openvpn/blob/release/2.6/src/openvpn/multi.c#L1394-L1400
https://github.com/OpenVPN/openvpn/blob/release/2.6/src/openvpn/multi.c#L3006-L3012
https://github.com/OpenVPN/openvpn/blob/release/2.6/src/openvpn/ssl_verify.c#L1646-L1654
"""
from datetime import UTC, datetime, timedelta

import pytest

from romulus.detect.vpn import VpnConcurrentSessions
from romulus.evidence.linux_auth_text import parse_auth
from romulus.evidence.linux_service_text import parse_service
from romulus.evidence.normalize import normalize_hits
from romulus.evidence.typed import Outcome

T0 = datetime(2026, 11, 10, 12, tzinfo=UTC)


def hit(n, body, envelope="syslog"):
    stamp = T0 + timedelta(seconds=n)
    source = {"@timestamp": stamp.isoformat(), "host": {"name": "vpn01"},
              "event": {"dataset": "custom.openvpn"}}
    if envelope == "syslog":
        source["message"] = f"Nov 10 {stamp:%H:%M:%S} vpn01 openvpn[42]: {body}"
    elif envelope == "native":
        source["message"] = f"Tue Nov 10 {stamp:%H:%M:%S} 2026 {body}"
    else:
        source.update({"event": {"dataset": "system.syslog"}, "process": {"name": "openvpn"}, "message": body})
    return {"_index": "fixture-vpn", "_id": f"vpn-{n}", "_source": source}


@pytest.mark.parametrize("envelope", ["syslog", "native", "structured"])
@pytest.mark.parametrize("context", ["192.0.2.2:51234", "client1/192.0.2.2:51234"])
def test_real_context_and_lifecycle_body_normalize_without_auth_promotion(envelope, context):
    bodies = [f"{context} [client1] Peer Connection Initiated with [AF_INET]192.0.2.2:51234",
              f"{context} MULTI_sva: pool returned IPv4=10.8.0.2, IPv6=(Not enabled)",
              f"{context} SIGTERM[soft,remote-exit] received, client-instance exiting"]
    events, skips, errors = normalize_hits([hit(n, body, envelope) for n, body in enumerate(bodies)])
    assert not skips and not errors and len(events) == 3
    assert [event.get("vpn.action") for event in events] == ["connect", "assign", "disconnect"]
    assert all(event.family == "vpn_session" and event.get("source.ip") == "192.0.2.2"
               and event.get("source.port") == 51234 for event in events)
    assert all(not event.has("vpn.session_id") and not event.has("event.duration") for event in events)
    assert events[0].get("user.name") == "client1"
    assert events[1].get("vpn.assigned_ip") == "10.8.0.2"
    assert events[1].get("vpn.assigned_ipv6") is None
    assert events[2].get("user.name") == ("client1" if "/" in context else None)
    assert all(parse_auth("openvpn", body) is None for body in bodies)


@pytest.mark.parametrize("context", ["192.0.2.2:51234", "certificate-cn/192.0.2.2:51234"])
@pytest.mark.parametrize("envelope", ["syslog", "structured"])
def test_existing_auth_prefix_uses_explicit_username_not_context_common_name(context, envelope):
    success = context + " TLS: Username/Password authentication succeeded for username 'alice' [CN SET]"
    failure = context + " TLS Auth Error: Auth Username/Password verification failed for peer"
    events, skips, errors = normalize_hits([hit(0, success, envelope), hit(1, failure, envelope)])
    assert not skips and not errors and len(events) == 2
    assert all(event.family == "auth" and event.get("auth.service") == "openvpn"
               and event.get("source.ip") == "192.0.2.2" and event.get("source.port") == 51234 for event in events)
    assert events[0].get("user.name") == "alice" and events[0].outcome == Outcome.success
    assert events[1].get("user.name") is None and events[1].outcome == Outcome.failure
    assert parse_service("openvpn", success) is None and parse_service("openvpn", failure) is None


@pytest.mark.parametrize("mode,expected", [("overlap", 1), ("unclosed", 0), ("duplicate_open", 0), ("touching", 0)])
@pytest.mark.parametrize("envelope", ["syslog", "native", "structured"])
def test_concurrency_consumes_real_prefixed_normalized_lifecycles(envelope, mode, expected):
    lines = [(0, "192.0.2.2:51234 [client1] Peer Connection Initiated with [AF_INET]192.0.2.2:51234"),
             (20 if mode == "touching" else 5,
              "client1/198.51.100.8:51235 [client1] Peer Connection Initiated with [AF_INET]198.51.100.8:51235"),
             (30, "client1/198.51.100.8:51235 SIGTERM[soft,remote-exit] received, client-instance exiting")]
    if mode != "unclosed":
        lines.append((20, "client1/192.0.2.2:51234 SIGTERM[soft,remote-exit] received, client-instance exiting"))
    if mode == "duplicate_open":
        lines.append((10, "client1/192.0.2.2:51234 [client1] Peer Connection Initiated with [AF_INET]192.0.2.2:51234"))
    docs = [hit(n, body, envelope) for n, body in lines]
    # Timestamp equality does not imply native identity equality.
    for n, doc in enumerate(docs):
        doc["_id"] = f"boundary-{n}"
    events, skips, errors = normalize_hits(docs)
    assert not skips and not errors and len(events) == len(lines)
    assert all(event.family == "vpn_session" and not event.has("vpn.session_id") for event in events)
    rule = VpnConcurrentSessions()
    try:
        assert rule.consume_partition(events) == []
        findings = list(rule.finalize())
        assert len(findings) == expected
        if expected:
            assert findings[0].proposed_lane == "lead" and "overlap" in findings[0].claim
            assert {event.id for event in findings[0].events} == {event.id for event in events}
            assert all(field.origin for field in findings[0].predicate)
        elif mode in {"unclosed", "duplicate_open"}:
            assert rule.missing_required > 0
    finally:
        rule.release_state()
        rule.close_spill()
