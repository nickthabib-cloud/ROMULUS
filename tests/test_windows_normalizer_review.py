"""Reviewed provider spellings survive real shipper normalization."""
import pytest

from romulus.evidence.typed import Outcome
from romulus.evidence.windows import normalize_windows
from romulus.evidence.windows_catalog import SECURITY, SYSMON, SYSMON_CHANNEL, WMI_CHANNEL, WMI_PROVIDER
from tests.windows_fixtures import SHAPES, LogicalWindowsEvent, windows_hit


def native(code, data, *, channel="Security", provider=SECURITY, shipper="winlogbeat_8"):
    return windows_hit(LogicalWindowsEvent(channel, provider, code, "ws01.example.test", code,
                                          "2026-11-02T12:00:00Z", data), shipper)


@pytest.mark.parametrize("shipper", SHAPES)
def test_sysmon_uppercase_guid_names_have_typed_roles(shipper):
    item = normalize_windows(native(10, {"SourceProcessGUID": "{11111111-2222-3333-4444-555555555555}",
                                         "TargetProcessGUID": "{99999999-2222-3333-4444-555555555555}"},
                                    channel=SYSMON_CHANNEL, provider=SYSMON, shipper=shipper))
    assert item.get("source.guid") == "11111111-2222-3333-4444-555555555555"
    assert item.get("target.guid") == "99999999-2222-3333-4444-555555555555"


def test_wmi_5861_native_user_data_and_trust_native_tdo_fields():
    hit = native(5861, {"ESS": "filter", "CONSUMER": "consumer", "Namespace": "root\\subscription"},
                 channel=WMI_CHANNEL, provider=WMI_PROVIDER)
    hit["_source"]["winlog"]["user_data"] = hit["_source"]["winlog"].pop("event_data")
    item = normalize_windows(hit)
    assert item.get("wmi.filter") == "filter"
    assert item.get("wmi.consumer") == "consumer"
    assert item.get("wmi.namespace") == "root\\subscription"
    for code in (4706, 4716):
        trust = normalize_windows(native(code, {"DomainName": "partner.test", "DomainSid": "S-1-5-21-1-2-3",
                                               "TdoType": "2", "TdoDirection": "3", "TdoAttributes": "8"}))
        assert trust.family == "directory_change"
        assert trust.get("directory.trust.domain_name") == "partner.test"
        assert trust.get("directory.trust.type") == 2


def test_native_failed_account_audit_cannot_be_normalized_as_success():
    hit = native(4732, {"TargetSid": "S-1-5-32-544", "MemberSid": "S-1-5-21-1-2-3-1001"})
    hit["_source"].setdefault("event", {})["outcome"] = "failure"
    assert normalize_windows(hit).outcome == Outcome.failure
