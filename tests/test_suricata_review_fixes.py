"""Protocol facts remain usable without guessing outcomes or packet direction."""
import pytest

from romulus.evidence.normalize import normalize_hits
from tests.test_suricata_protocols import hit


@pytest.mark.parametrize("shape", ["original", "message", "filebeat", "agent", "malcolm"])
@pytest.mark.parametrize("cipher", ["RC4_HMAC_OLD", "FUTURE_CIPHER"])
def test_unknown_response_cipher_keeps_known_issued_ticket(shape, cipher):
    block = {"msg_type": "KRB_TGS_REP", "cname": "alice", "sname": "cifs/server",
             "ticket_encryption": "RC4_HMAC", "encryption": cipher}
    events, skips, errors = normalize_hits([hit("krb5", block, shape)])
    assert not skips and not errors and len(events) == 1
    event = events[0]
    assert event.get("auth.encryption_type") == 23
    assert event.get("kerberos.client_name") == "alice"
    assert any("cipher" in note and "unknown" in note.casefold() for note in event.caveats)
    assert "ticket_encryption" in event.fields["auth.encryption_type"].origin


def test_unknown_response_cipher_does_not_supply_missing_ticket_cipher():
    events, skips, errors = normalize_hits([hit("krb5", {
        "msg_type": "KRB_TGS_REP", "cname": "alice", "encryption": "RC4_HMAC_OLD"})])
    assert not skips and not errors and len(events) == 1
    assert events[0].get("auth.encryption_type") is None
    assert events[0].caveats


def test_unknown_ticket_cipher_remains_a_counted_normalization_error():
    events, skips, errors = normalize_hits([hit("krb5", {
        "msg_type": "KRB_TGS_REP", "ticket_encryption": "FUTURE_CIPHER", "encryption": "RC4_HMAC"})])
    assert not events and not skips and len(errors) == 1
