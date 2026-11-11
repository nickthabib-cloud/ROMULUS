"""SMB authentication status is meaningful only on the same session setup."""
import pytest

from romulus.evidence.normalize import normalize_hits
from romulus.evidence.zeek import normalize_plain_zeek
from tests.fixtures import zeek_logs as zl
from tests.test_suricata_protocols import hit


FAILURES = ["STATUS_LOGON_FAILURE", "STATUS_ACCOUNT_LOCKED_OUT", "STATUS_PASSWORD_EXPIRED",
            "STATUS_ACCOUNT_DISABLED", "STATUS_ACCOUNT_RESTRICTION", "STATUS_INVALID_LOGON_HOURS",
            "STATUS_INVALID_WORKSTATION", "STATUS_ACCOUNT_EXPIRED", "STATUS_PASSWORD_MUST_CHANGE",
            "STATUS_NO_SUCH_USER", "STATUS_WRONG_PASSWORD", "STATUS_LOGON_TYPE_NOT_GRANTED"]


@pytest.mark.parametrize("command", ["SMB2_COMMAND_SESSION_SETUP", "SMB1_COMMAND_SESSION_SETUP_ANDX"])
@pytest.mark.parametrize("status,success", [("STATUS_SUCCESS", True), *[(s, False) for s in FAILURES],
                                         (None, None), ("STATUS_MORE_PROCESSING_REQUIRED", None),
                                         ("STATUS_ACCESS_DENIED", None), ("STATUS_FUTURE", None)])
def test_ntlm_outcome_uses_only_explicit_session_logon_status(command, status, success):
    block = {"command": command, "ntlmssp": {"user": "alice", "domain": "EXAMPLE", "host": "WS01"}}
    if status is not None:
        block["status"] = status
    events, skips, errors = normalize_hits([hit("smb", block)])
    assert not skips and not errors
    auth = next(e for e in events if e.family == "ntlm_tx")
    assert auth.get("ntlm.success") is success
    assert auth.outcome == ("unknown" if success is None else "success" if success else "failure")
    if success is not None:
        assert ".smb.status" in auth.fields["ntlm.success"].origin


@pytest.mark.parametrize("status", ["STATUS_SUCCESS", "STATUS_LOGON_FAILURE"])
def test_another_commands_status_cannot_supply_ntlm_outcome(status):
    events, skips, errors = normalize_hits([hit("smb", {
        "command": "SMB2_COMMAND_CREATE", "status": status, "ntlmssp": {"user": "alice"}})])
    assert not skips and not errors
    auth = next(e for e in events if e.family == "ntlm_tx")
    assert auth.get("ntlm.success") is None and auth.outcome == "unknown"


@pytest.mark.parametrize("success", [True, False])
@pytest.mark.parametrize("shape", ["original", "message", "filebeat", "agent", "malcolm"])
def test_zeek_and_suricata_logon_twins_agree_in_mixed_batch(success, shape):
    zeek = normalize_plain_zeek(zl.plain(zl.NTLM.with_(success=success)), sensor=zl.SENSOR)
    events, skips, errors = normalize_hits([hit("smb", {
        "command": "SMB2_COMMAND_SESSION_SETUP", "status": "STATUS_SUCCESS" if success else "STATUS_LOGON_FAILURE",
        "ntlmssp": {"user": "alice", "domain": "EXAMPLE", "host": "WS01"}}, shape)])
    assert not skips and not errors
    batch = [zeek, *(e for e in events if e.family == "ntlm_tx")]
    assert len(batch) == 2
    assert {e.get("ntlm.success") for e in batch} == {success}
    assert len({e.outcome for e in batch}) == 1
    assert len({e.get("auth.target_account") for e in batch}) == 1
