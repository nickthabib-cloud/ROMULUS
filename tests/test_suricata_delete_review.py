"""Only explicit SMB2 deletion flags establish requested file deletion."""
import pytest

from romulus.evidence.normalize import normalize_hits
from tests.test_suricata_protocols import hit


@pytest.mark.parametrize("shape", ["original", "message", "filebeat", "agent", "malcolm"])
@pytest.mark.parametrize("command", ["SMB2_COMMAND_CREATE", "SMB2_COMMAND_SET_INFO"])
def test_explicit_delete_on_close_maps_requested_deletion(shape, command):
    events, skips, errors = normalize_hits([hit("smb", {
        "command": command, "filename": "docs/report.txt", "access": "delete on close",
        "status": "STATUS_SUCCESS", "disposition": "FILE_OPEN"}, shape)])
    assert not skips and not errors and len(events) == 1
    assert events[0].get("smb.action") == "FILE_DELETE"
    assert "access" in events[0].fields["smb.action"].origin
    assert any("requested" in note and "success" in note for note in events[0].caveats)


@pytest.mark.parametrize("access", [None, "normal"])
def test_disposition_class_without_delete_flag_does_not_infer_deletion(access):
    block = {"command": "SMB2_COMMAND_SET_INFO", "filename": "docs/report.txt",
             "set_info": {"class": "FILE_INFO", "info_level": "SMB2_FILE_DISPOSITION_INFO"}}
    if access is not None:
        block["access"] = access
    events, skips, errors = normalize_hits([hit("smb", block)])
    assert not skips and not errors
    assert events[0].get("smb.action") is None


def test_delete_flag_from_unrelated_command_does_not_infer_deletion():
    events, skips, errors = normalize_hits([hit("smb", {
        "command": "SMB2_COMMAND_READ", "filename": "docs/report.txt", "access": "delete on close"})])
    assert not skips and not errors
    assert events[0].get("smb.action") is None
