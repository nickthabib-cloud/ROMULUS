"""Synthetic host fields from RFC 3164 section 4.1.2 and RFC 5424 section 6.2.4.

https://www.rfc-editor.org/rfc/rfc3164#section-4.1.2
https://www.rfc-editor.org/rfc/rfc5424#section-6.2.4
"""
from datetime import UTC, datetime, timedelta

import pytest

from romulus.detect.auth import SshPasswordGuessing
from romulus.evidence.normalize import normalize_hits

T0 = datetime(2030, 1, 6, 9, tzinfo=UTC)


def hit(host="APP01.example.test", *, indexed=None, n=0, rfc5424=False, original=False):
    stamp = T0 + timedelta(seconds=n)
    body = f"Failed password for root from 192.0.2.9 port {40000+n} ssh2"
    prefix = (f"<34>1 {stamp.isoformat()} {host} sshd {100+n} ID - " if rfc5424 else
              f"Jan  6 {stamp:%H:%M:%S} {host} sshd[{100+n}]: ")
    source = {"@timestamp": stamp.isoformat(), "message": prefix + body,
              "log": {"file": {"path": "/var/log/auth.log"}, "offset": n}}
    if indexed is not None:
        source["host"] = {"name": indexed}
    if original:
        source["event"] = {"original": source.pop("message")}
    return {"_index": "syslog-fixture", "_id": f"line-{n}", "_source": source}


@pytest.mark.parametrize("rfc5424", [False, True])
@pytest.mark.parametrize("indexed", [None, "", "   "])
def test_header_names_supply_missing_host_with_native_origin(indexed, rfc5424):
    events, skips, errors = normalize_hits([hit(indexed=indexed, rfc5424=rfc5424)])
    assert not skips and not errors
    event = events[0]
    assert event.host == event.get("host.name") == "app01"
    assert event.fields["host.name"].origin == "line-0:message#syslog-header"
    assert event.get("log.syslog.hostname") == "APP01.example.test"
    assert any("host" in note.lower() and "own header" in note.lower() for note in event.caveats)


def test_original_payload_origin_names_the_actual_field():
    event = normalize_hits([hit(original=True)])[0][0]
    assert event.host == "app01"
    assert event.fields["host.name"].origin == "line-0:event.original#syslog-header"


@pytest.mark.parametrize("header", ["APP01.example.test", "another.example.test"])
def test_indexed_host_wins_and_header_is_still_recorded(header):
    event = normalize_hits([hit(header, indexed="app01")])[0][0]
    assert event.host == "app01" and event.get("log.syslog.hostname") == header
    assert not any("own header" in note.lower() or "host mismatch" in note.lower() for note in event.caveats)


@pytest.mark.parametrize("header", ["-", "localhost", "LOCALHOST", "localhost.", "localhost.localdomain"])
def test_nonidentity_header_never_becomes_host(header):
    event = normalize_hits([hit(header, rfc5424=True)])[0][0]
    assert event.host is None and not event.has("host.name") and not event.has("host.ip")


@pytest.mark.parametrize("header", ["192.0.2.8", "2001:db8::8"])
def test_ip_literal_is_a_typed_host_address_not_a_hostname(header):
    event = normalize_hits([hit(header, rfc5424=True)])[0][0]
    assert event.host is None and not event.has("host.name")
    assert event.get("host.ip") == header
    assert event.fields["host.ip"].origin == "line-0:message#syslog-header"


def test_empty_header_is_counted_as_unrecognized_without_inventing_host():
    events, skips, errors = normalize_hits([hit("")])
    assert not events and not errors and sum(skips.values()) == 1


def test_per_host_ssh_guessing_groups_header_only_records():
    events, skips, errors = normalize_hits([hit(n=n) for n in range(12)])
    assert not skips and not errors
    assert {event.host for event in events} == {"app01"}
    rule = SshPasswordGuessing()
    matches = [*rule.consume(events), *rule.finalize()]
    assert len(matches) == 1 and matches[0].proposed_lane == "lead"
    assert all(event.host == "app01" for event in matches[0].events)
