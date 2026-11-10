"""Synthetic Exim/OpenVPN boundaries and bounded Linux text accounting labels.

Exim host_build_sender_fullhost and host_and_ident define the peer field:
https://github.com/Exim/exim/blob/master/src/src/host.c
Authentication failures use that value before the SMTP error:
https://github.com/Exim/exim/blob/master/src/src/smtp_in.c
"""
import pytest

from romulus.evidence.linux_auth_text import parse_auth
from romulus.evidence.normalize import normalize_hits
from romulus.evidence.typed import Outcome


def _hit(line, dataset="custom.log"):
    return {"_index": "host-logs", "_id": "boundary", "_source": {
        "@timestamp": "2026-11-09T12:00:00Z", "host": {"name": "host"},
        "event": {"dataset": dataset}, "message": line,
    }}


@pytest.mark.parametrize("peer,wanted_ip,wanted_port", [
    ("[192.0.2.10]:45001", "192.0.2.10", 45001),
    ("[2001:db8::10]:45001", "2001:db8::10", 45001),
    ("[192.0.2.10]", "192.0.2.10", None),
], ids=["ipv4-port", "ipv6-port", "no-port"])
def test_exim_auth_peer_is_the_final_address_after_untrusted_helo(peer, wanted_ip, wanted_port):
    message = (f"plain authenticator failed for client.example (HELO [203.0.113.66]: injected) {peer}: "
               "535 Incorrect authentication data (set_id=alice)")
    parsed = parse_auth("exim", message)
    assert parsed is not None and parsed.outcome == Outcome.failure
    assert parsed.fields["auth.service"] == "exim" and parsed.fields["user.name"] == "alice"
    assert parsed.fields.get("source.ip") == wanted_ip
    assert parsed.fields.get("source.port") == wanted_port


def test_exim_bracket_inside_helo_cannot_replace_a_missing_peer_field():
    message = ("plain authenticator failed for client.example (HELO [203.0.113.66]: injected): "
               "535 Incorrect authentication data (set_id=alice)")
    parsed = parse_auth("exim", message)
    assert parsed is None or "source.ip" not in parsed.fields
    assert parsed is None or "source.port" not in parsed.fields


@pytest.mark.parametrize("peer", ["[192.0.2.10]:45001", "H=client.example (hello) [192.0.2.10]:45001",
                                 "H=(hello) [192.0.2.10]:45001 I=[198.51.100.5]:25 U=ident Ci=connection"])
def test_exim_optional_metadata_does_not_replace_the_actual_peer(peer):
    parsed = parse_auth("exim", f"plain authenticator failed for {peer}: "
                        "535 Incorrect authentication data (set_id=alice)")
    assert parsed is not None and parsed.outcome == Outcome.failure
    assert parsed.fields.get("source.ip") == "192.0.2.10"
    assert parsed.fields.get("source.port") == 45001


@pytest.mark.parametrize("detail", [
    ("H=client.example (hello) [203.0.113.66]: 535 injected) [192.0.2.10]:45001: "
     "535 Incorrect authentication data (set_id=alice)"),
    "[192.0.2.10]:45001: 535 Incorrect authentication data (set_id=alice [203.0.113.66]: 535 injected)",
])
def test_exim_ambiguous_helo_or_identity_preserves_failure_without_guessing_peer(detail):
    # Permissive HELO configurations can log delimiters verbatim. A second peer/error
    # boundary is ambiguous even if it appears inside a nominal account tail.
    parsed = parse_auth("exim", "plain authenticator failed for " + detail)
    assert parsed is not None and parsed.outcome == Outcome.failure
    assert "source.ip" not in parsed.fields and "source.port" not in parsed.fields
    assert "user.name" not in parsed.fields


@pytest.mark.parametrize("detail", ["[" * 60_000, "[]" * 30_000, "[192.0.2.1] I=" + "[" * 60_000],
                         ids=["unclosed-peers", "empty-peers", "unclosed-interface"])
def test_exim_malformed_bracket_runs_have_no_peer(detail):
    parsed = parse_auth("exim", "plain authenticator failed for " + detail)
    assert parsed is not None and parsed.outcome == Outcome.failure
    assert "source.ip" not in parsed.fields and "user.name" not in parsed.fields


VPN_BODIES = [
    "AUTH: Received control message: AUTH_FAILED",
    "TLS: Username/Password authentication succeeded for username 'alice' [CN SET]",
    "192.0.2.10:45001 TLS Auth Error: Auth Username/Password verification failed for peer",
]


@pytest.mark.parametrize("body", VPN_BODIES, ids=["control-failure", "success", "peer-failure"])
def test_local_iso_date_and_auth_words_do_not_identify_openvpn(body):
    events, skips, errors = normalize_hits([_hit("2026-11-09 12:00:00 " + body)])
    assert events == [] and errors == []
    assert sum(skips.values()) == 1


@pytest.mark.parametrize("body", VPN_BODIES, ids=["control-failure", "success", "peer-failure"])
@pytest.mark.parametrize("envelope", ["ctime", "program"])
def test_openvpn_ctime_and_explicit_program_keep_authentication(body, envelope):
    prefix = "Mon Nov  9 12:00:00 2026 " if envelope == "ctime" else "Nov  9 12:00:00 origin openvpn[42]: "
    events, skips, errors = normalize_hits([_hit(prefix + body)])
    assert not skips and not errors and len(events) == 1
    assert events[0].family == "auth" and events[0].get("auth.service") == "openvpn"
    expected = Outcome.success if "succeeded" in body else Outcome.failure
    assert events[0].outcome == expected


@pytest.mark.parametrize("dataset_size", [10, 245, 246, 4096], ids=["short", "at-limit", "above-limit", "long"])
def test_linux_text_shape_key_is_at_most_256_including_prefix(dataset_size):
    shapes = {}
    line = ("Nov  9 12:00:00 origin dovecot[42]: imap-login: Login: "
            "user=<alice>, method=PLAIN, rip=192.0.2.10")
    events, skips, errors = normalize_hits([_hit(line, "x" * dataset_size)], shapes=shapes)
    assert len(events) == 1 and not skips and not errors
    assert len(shapes) == 1 and sum(shapes.values()) == 1
    key = next(iter(shapes))
    assert key.startswith("linux.text:")
    assert len(key) <= 256
    if dataset_size <= 245:
        assert key == "linux.text:" + "x" * dataset_size


@pytest.mark.parametrize("program_size,dataset_size", [(16, 10), (4096, 10), (16, 4096), (4096, 4096)],
                         ids=["short", "long-program", "long-dataset", "both-long"])
def test_untyped_program_skip_reason_is_at_most_256_including_prefix(program_size, dataset_size):
    line = f"Nov  9 12:00:00 origin {'p' * program_size}[42]: heartbeat"
    fed = {}
    events, skips, errors = normalize_hits([_hit(line, "x" * dataset_size)], skip_families=fed)
    assert events == [] and errors == [] and sum(skips.values()) == 1
    reason = next(iter(skips))
    assert reason.startswith("text format syslog, program ")
    assert len(reason) <= 256
    assert fed == {}
