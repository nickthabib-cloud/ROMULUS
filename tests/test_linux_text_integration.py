"""Synthetic documented service records through actual shipper dispatch."""
import json

import pytest

from romulus.evidence.normalize import normalize_hits
from tests.test_linux_text import hit


@pytest.mark.parametrize("shape", ["raw", "syslog", "journal", "journal-fields"])
def test_cron_is_typed_from_each_supported_envelope(shape):
    body = "(root) CMD (run-parts /etc/cron.hourly)"
    if shape == "raw":
        doc = hit("Nov  9 12:00:00 origin CRON[42]: " + body)
    elif shape == "syslog":
        doc = hit(body, "system.syslog", process={"name": "CRON"})
    elif shape == "journal-fields":
        doc = hit(body, "journald.logs", syslog={"identifier": "CRON"})
    else:
        doc = hit("", "systemd.journal")
        doc["_source"]["event"]["original"] = json.dumps({"MESSAGE": body, "SYSLOG_IDENTIFIER": "CRON"})
    events, skips, errors = normalize_hits([doc])
    assert not skips and not errors
    assert len(events) == 1 and events[0].family == "process_observed"
    assert events[0].get("process.command_line") == "run-parts /etc/cron.hourly"
    assert any("not a kernel audit exec" in note for note in events[0].caveats)


def test_one_exim_arrival_preserves_authentication_and_mail_flow():
    line = ("2026-11-09 12:00:00 1a2B3c-4d5E6f-7g <= alice@example.test "
            "H=mail.example.test [2001:db8::5] P=esmtpsa A=plain:alice S=12 for bob@example.net")
    events, skips, errors = normalize_hits([hit(line, "exim.log")])
    assert not skips and not errors
    assert {event.family for event in events} == {"auth", "mail_message"}
    assert len({event.id for event in events}) == 2
    assert events[0].raw == events[1].raw
    mail = next(event for event in events if event.family == "mail_message")
    assert mail.get("mail.authenticated_user") == "alice"
    assert mail.get("mail.to") == ["bob@example.net"]


def test_unknown_dataset_with_indexed_program_uses_anchored_body_grammar():
    doc = hit('pam_unix(su:auth): authentication failure; logname= uid=1000 euid=0 tty=pts/0 '
              'ruser=alice rhost=2001:db8::4  user=bob', process={"name": "su"})
    events, skips, errors = normalize_hits([doc])
    assert not skips and not errors and events[0].get("auth.service") == "su"
    assert events[0].get("source.ip") == "2001:db8::4"


def test_native_dovecot_header_is_not_misidentified_as_a_syslog_host():
    line = 'Nov  9 12:00:00 imap-login: Login: user=<alice>, method=PLAIN, rip=2001:db8::4, lip=2001:db8::8'
    events, skips, errors = normalize_hits([hit(line)])
    assert not skips and not errors and events[0].get("auth.service") == "dovecot"
    assert events[0].host == "shipper"


def test_recognized_untyped_multiline_audit_fragment_is_counted_by_program():
    fed = {}
    events, skips, errors = normalize_hits([hit("--a1b2c3-A--", "waf.log")], skip_families=fed)
    assert not events and not errors and sum(skips.values()) == 1
    assert "modsecurity-audit" in next(iter(skips))
    assert "no recognized format" not in next(iter(skips))


def test_vpn_assignment_exposes_logged_internal_address_for_entity_links():
    line = ("Nov  9 12:00:00 vpn openvpn: alice/192.0.2.2:51234 "
            "MULTI_sva: pool returned IPv4=10.8.0.2, IPv6=2001:db8::2")
    events, skips, errors = normalize_hits([hit(line)])
    assert not skips and not errors
    event = events[0]
    assert event.family == "vpn_session"
    assert ("account", "alice", "actor") in event.entities()
    assert ("ip", "10.8.0.2", "assigned") in event.entities()
    assert ("ip", "2001:db8::2", "assigned") in event.entities()
    assert not event.has("destination.ip")


def test_squid_epoch_time_is_preserved_and_compared_without_retiming():
    line = "1794225600.000 20 192.0.2.2 TCP_TUNNEL/200 1024 CONNECT example.test:443 alice HIER_DIRECT/192.0.2.5 -"
    doc = hit(line)
    doc["_source"]["@timestamp"] = "2026-11-09T12:00:01Z"
    events, skips, errors = normalize_hits([doc])
    assert not skips and not errors
    event = events[0]
    assert event.ts.isoformat() == "2026-11-09T12:00:01+00:00"
    assert event.get("log.inline_timestamp") == "1794225600.000"
    assert event.get("log.clock_offset_seconds") == -1
    assert any("Clock offset" in note for note in event.caveats)


@pytest.mark.parametrize("shape", ["syslog-message", "syslog-original", "journal-custom"])
def test_service_fallback_reads_all_existing_envelope_paths(shape):
    body = 'imap-login: Login: user=<alice>, method=PLAIN, rip=192.0.2.4'
    if shape == "journal-custom":
        doc = hit("", "journald.logs", journald={"custom": {"message": body, "syslog_identifier": "dovecot"}})
        del doc["_source"]["message"]
    else:
        doc = hit("Nov  9 12:00:00 origin dovecot: " + body, "system.syslog")
        if shape == "syslog-original":
            doc["_source"]["event"]["original"] = doc["_source"].pop("message")
    events, skips, errors = normalize_hits([doc])
    assert not skips and not errors
    assert len(events) == 1 and events[0].get("auth.service") == "dovecot"
    assert events[0].get("user.name") == "alice"
    assert events[0].host == "shipper"


@pytest.mark.parametrize("stamp,line", [
    ("09-Nov-2026 10:20:30 +0000", ("[09-Nov-2026 10:20:30 +0000]: <a1b2c3d4> Failed login for alice "
     "from 2001:db8::10 in session s (error: 0)")),
    ("2026-11-09 10:20:30,123", ("2026-11-09 10:20:30,123 ftp.example proftpd[7] "
     "ftp.example (peer.example[2001:db8::10]): USER alice: Login successful.")),
    ("2026-11-09 10:20:30 +0000", ("2026-11-09 10:20:30 +0000 1a2B3c-4d5E6f-7g <= alice@example.test "
     "H=mail.example.test [2001:db8::5] P=esmtpsa A=plain:alice S=12 for bob@example.net")),
])
def test_native_application_timestamps_keep_their_logged_representation(stamp, line):
    events, skips, errors = normalize_hits([hit(line)])
    assert not skips and not errors
    for event in events:
        assert event.get("log.inline_timestamp") == stamp
        assert event.get("log.clock_offset_seconds") == -5970
        assert event.ts.hour == 12


@pytest.mark.parametrize("shape", ["journal", "journal-fields"])
@pytest.mark.parametrize("boot", ["0a" * 16, None, "not-a-boot-id"])
def test_new_service_events_preserve_only_valid_recorded_journal_boots(shape, boot):
    # A boot ID mentioned in command text is never boot identity.
    body = "(root) CMD (echo _BOOT_ID=" + "0a" * 16 + ")"
    if shape == "journal":
        doc = hit("", "systemd.journal")
        record = {"MESSAGE": body, "SYSLOG_IDENTIFIER": "CRON"}
        if boot is not None:
            record["_BOOT_ID"] = boot
        doc["_source"]["event"]["original"] = json.dumps(record)
        origin = "line-1:event.original#journal:_BOOT_ID"
    else:
        doc = hit(body, "journald.logs", syslog={"identifier": "CRON"})
        if boot is not None:
            doc["_source"]["journald"] = {"host": {"boot_id": boot}}
        origin = "line-1:journald.host.boot_id"
    events, skips, errors = normalize_hits([doc])
    assert not skips and not errors and len(events) == 1
    assert events[0].family == "process_observed"
    if boot == "0a" * 16:
        assert events[0].get("host.boot.id") == boot
        assert events[0].fields["host.boot.id"].origin == origin
    else:
        assert not events[0].has("host.boot.id")
