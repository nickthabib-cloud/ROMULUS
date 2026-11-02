"""Windows link consumers cite actual GUID/session equality without inventing causality."""
from romulus.detect.base import ContextAnchor, ContextLink
from romulus.detect.windows_linked import WindowsKerberosLogonLink, WindowsProcessSessionLink
from tests.windows_link_support import event

GUID = "00112233-4455-6677-8899-aabbccddeeff"

def anchor(item):
    return ContextAnchor("anchor", "execution", "high", "source finding", [item], "win.source", item.ts)

def link(kind):
    return ContextLink("link", kind, "observed", {}, [], "complete")


def test_kerberos_link_requires_nonzero_matching_guid_and_opposite_event_class():
    ticket = event("auth", 4769, **{"auth.logon_guid": GUID})
    logon = event("auth", 4624, host="server2", **{"auth.logon_guid": "{" + GUID.upper() + "}"})
    matches = WindowsKerberosLogonLink().consume_linked(anchor(ticket), link("kerberos_logon"), [logon])
    assert len(matches) == 1 and "kerberos_logon" in matches[0].claim
    assert {item.id for item in matches[0].events} == {ticket.id, logon.id}
    wrong = event("auth", 4624, **{"auth.logon_guid": "00000000-0000-0000-0000-000000000000"})
    assert not WindowsKerberosLogonLink().consume_linked(anchor(ticket), link("kerberos_logon"), [wrong])
    assert not WindowsKerberosLogonLink().consume_linked(anchor(ticket), link("kerberos_logon"), [ticket])


def test_process_session_link_numeric_equivalence_same_host_and_boot_qualification():
    process = event("process_exec", 4688, **{"process.subject_session_id": "0x000044", "host.boot.id": "boot1"})
    logon = event("auth", 4624, offset=-2, **{"auth.session_id": "68", "host.boot.id": "boot1"})
    matches = WindowsProcessSessionLink().consume_linked(anchor(process), link("process_session"), [logon])
    assert len(matches) == 1 and "process_session" in matches[0].claim
    assert any("#parsed:" in item.origin for item in matches[0].predicate)
    logon.host = "other"
    assert not WindowsProcessSessionLink().consume_linked(anchor(process), link("process_session"), [logon])
    logon.host = process.host
    logon.fields["host.boot.id"].value = "different"
    assert not WindowsProcessSessionLink().consume_linked(anchor(process), link("process_session"), [logon])


def test_partial_boot_context_is_stated_instead_of_asserting_same_session():
    process = event("process_exec", 4688, **{"process.subject_session_id": "0x44"})
    logon = event("auth", 4624, **{"auth.session_id": "0x44"})
    reach = link("process_session")
    reach.status, reach.reasons = "partial", ["same-boot boundary unavailable"]
    matches = WindowsProcessSessionLink().consume_linked(anchor(process), reach, [logon])
    assert matches and "unresolved" in matches[0].claim


def test_process_session_link_uses_the_target_role_when_that_is_the_selected_scope():
    process = event("process_exec", 4688, **{"process.subject_session_id": "0x44", "process.target_session_id": "0x55"})
    logon = event("auth", 4624, **{"auth.session_id": "0x55"})
    reach = link("process_session")
    reach.key = {"process.session_id": "0x55", "process.target_session_id": "0x55"}
    matches = WindowsProcessSessionLink().consume_linked(anchor(process), reach, [logon])
    assert len(matches) == 1
    assert any(item.field == "process.target_session_id" and "#parsed:" in item.origin for item in matches[0].predicate)


def test_linux_or_wrong_link_does_not_create_windows_link_claims():
    process = event("process_exec", 4688, **{"process.subject_session_id": "0x44", "host.os.family": "linux"})
    logon = event("auth", 4624, **{"auth.session_id": "0x44", "host.os.family": "linux"})
    assert not WindowsProcessSessionLink().consume_linked(anchor(process), link("process_session"), [logon])
    assert not WindowsProcessSessionLink().consume_linked(anchor(process), link("kerberos_logon"), [logon])
