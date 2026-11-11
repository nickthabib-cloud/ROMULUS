"""Protocol datasets enter sweep selection and normalization-error accounting."""
import pytest

from romulus.hunt import sweep


@pytest.mark.parametrize("event_type,family", [
    ("smb", "smb_tx"), ("dcerpc", "rpc_tx"), ("krb5", "kerberos_tx"), ("rdp", "remote_session"),
    ("ldap", "ldap_tx"), ("smtp", "app_tx"), ("ftp", "app_tx"), ("ftp_data", "app_tx"),
    ("dhcp", "address_assignment"), ("snmp", "app_tx"), ("tftp", "app_tx"),
])
def test_protocol_dataset_is_retrievable_and_delivers_its_family(event_type, family):
    dataset = f"suricata.eve.{event_type}"
    assert dataset in sweep.DATASET_FAMILIES
    assert family in sweep.delivered_families({"role": "network", "datasets": {dataset: 1}}, None)
    assert family in sweep.DATASET_FAMILIES["suricata.eve"]


def test_smb_auth_child_is_included_in_coverage():
    assert "ntlm_tx" in sweep.DATASET_FAMILIES["suricata.eve.smb"]


def test_unmapped_protocol_is_still_an_unknown_error_family():
    assert "suricata.eve.nfs" not in sweep.DATASET_FAMILIES
