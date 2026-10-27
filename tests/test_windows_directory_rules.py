"""Private direct AD rule proof; imports target the eventual product module."""
from dataclasses import replace

import pytest

from romulus.catalog.attack import load_attack_bundle
from romulus.detect.windows_directory_events import (
    WINDOWS_DIRECTORY_PLAYBOOKS,
    AdminSdHolderChange,
    DirectoryReplicationAccess,
    GroupPolicyDirectoryChange,
    KerberosNoPreauthentication,
    TrustDirectoryChange,
    WeakKerberosTicketEncryption,
    parse_dn,
)
from romulus.evidence.typed import fv
from romulus.evidence.windows import normalize_windows
from romulus.evidence.windows_catalog import SECURITY
from romulus.site import SiteFacts, absent_site_facts
from tests.windows_event_support import event, run
from tests.windows_fixtures import SHAPES, LogicalWindowsEvent, windows_hit

REPLICATION = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
ACTOR = {"SubjectUserSid": "S-1-5-21-11-22-33-1101", "SubjectUserName": "analyst",
         "SubjectDomainName": "EXAMPLE"}
DC_SYNC = {**ACTOR, "ObjectServer": "DS", "ObjectName": "DC=example,DC=test",
           "AccessMask": "0x100", "Properties": f"%%7688\n{{{REPLICATION}}}"}
RC4 = {"TargetUserName": "analyst", "TargetDomainName": "EXAMPLE", "ServiceName": "svc_database",
       "TicketEncryptionType": "0x17", "Status": "0", "IpAddress": "192.0.2.9"}
ASREP = {**RC4, "ServiceName": "krbtgt", "PreAuthType": "0"}
ADMIN = {**ACTOR, "ObjectDN": "CN=AdminSDHolder,CN=System,DC=example,DC=test", "ObjectClass": "container",
         "AttributeLDAPDisplayName": "nTSecurityDescriptor", "AttributeValue": "D:example",
         "OperationType": "%%14674"}
GPO = {**ACTOR, "ObjectDN": "CN={11111111-2222-3333-4444-555555555555},CN=Policies,CN=System,DC=example,DC=test",
       "ObjectClass": "groupPolicyContainer", "AttributeLDAPDisplayName": "versionNumber", "AttributeValue": "7"}
TRUST = {**ACTOR, "ObjectDN": "CN=partner.test,CN=System,DC=example,DC=test", "ObjectClass": "trustedDomain",
         "AttributeLDAPDisplayName": "trustDirection", "AttributeValue": "3"}
FACTS = SiteFacts(True, "private-test-facts", {}, (), ("dc01.example.test",), ("name:example\\syncsvc",))
CASES = ((DirectoryReplicationAccess, 4662, DC_SYNC), (WeakKerberosTicketEncryption, 4769, RC4),
         (KerberosNoPreauthentication, 4768, ASREP), (AdminSdHolderChange, 5136, ADMIN),
         (GroupPolicyDirectoryChange, 5137, GPO), (TrustDirectoryChange, 5136, TRUST))


def native(code, data, *, shape="elastic_agent", host="dc01.example.test", record=1, failure=False):
    source = LogicalWindowsEvent("Security", SECURITY, code, host, record, "2026-01-02T03:00:00Z", data)
    hit = windows_hit(source, shape)
    if failure:
        hit["_source"]["event"]["outcome"] = "failure"
        hit["_source"]["winlog"]["keywords"] = ["Audit Failure"]
    return normalize_windows(hit)


def replication_rule(facts=FACTS):
    instance = DirectoryReplicationAccess()
    instance.site_facts = facts
    return instance


@pytest.mark.parametrize("shape", SHAPES)
@pytest.mark.parametrize("rule,code,data", CASES)
def test_native_positives_cite_typed_fields_and_publish_immediately(rule, code, data, shape):
    instance = replication_rule() if rule is DirectoryReplicationAccess else rule()
    observation = native(code, data, shape=shape)
    matches = instance.consume([observation])
    assert len(matches) == 1 and matches[0].events == [observation]
    assert matches[0].proposed_lane == ("high" if rule is DirectoryReplicationAccess else "lead")
    assert matches[0].predicate and all(item.origin for item in matches[0].predicate)
    assert "forged" not in matches[0].claim.lower()


@pytest.mark.parametrize("rule,code,data", CASES)
def test_new_host_and_distinguishing_payload_always_publish_immediately(rule, code, data):
    instance = replication_rule() if rule is DirectoryReplicationAccess else rule()
    assert len(instance.consume([native(code, data)])) == 1
    assert len(instance.consume([native(code, data, host="dc02.example.test")])) == 1
    payload_key = ("Properties" if rule is DirectoryReplicationAccess else "ServiceName" if code in {4768, 4769}
                   else "AttributeValue")
    for record, suffix in enumerate(("first", "second"), start=2):
        changed = {**data, payload_key: (data[payload_key] + "x" * 500 + suffix)}
        if payload_key == "Properties":
            changed[payload_key] = data[payload_key] + "\n{89e95b76-444d-4c62-991a-0facbeda640c}"
            changed["ObjectName"] = "DC=" + "x" * 500 + suffix + ",DC=test"
        assert len(instance.consume([native(code, changed, record=record)])) == 1


@pytest.mark.parametrize("guid", [REPLICATION, "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",
                                 "89e95b76-444d-4c62-991a-0facbeda640c"])
@pytest.mark.parametrize("mask", ["0x100", "0x10100"])
def test_exact_replication_rights_and_control_access_bits_high_when_site_lists_are_configured(guid, mask):
    matches = run(replication_rule(), [native(4662, {**DC_SYNC, "Properties": "{" + guid.upper() + "}",
                                                    "AccessMask": mask})])
    assert len(matches) == 1 and matches[0].proposed_lane == "high"
    assert "replication" in matches[0].claim.lower()
    assert "dumped" not in matches[0].claim.lower()


@pytest.mark.parametrize("facts", [None, absent_site_facts(), replace(FACTS, domain_controllers=()),
                                  replace(FACTS, directory_sync_accounts=())])
def test_missing_site_lists_remain_explicit_not_configured_leads(facts):
    matches = run(replication_rule(facts), [native(4662, DC_SYNC)])
    assert len(matches) == 1 and matches[0].proposed_lane == "lead"
    assert "not configured" in " ".join([matches[0].claim, *matches[0].notes])


@pytest.mark.parametrize("actor", [{"SubjectUserName": "dc01$"}, {"SubjectUserName": "syncsvc"},
                                  {"SubjectUserSid": "S-1-5-21-11-22-33-2200"}])
def test_listed_principals_still_surface_as_leads(actor):
    facts = replace(FACTS, directory_sync_accounts=(*FACTS.directory_sync_accounts, "sid:s-1-5-21-11-22-33-2200"))
    matches = run(replication_rule(facts), [native(4662, {**DC_SYNC, **actor})])
    assert len(matches) == 1 and matches[0].proposed_lane == "lead"
    assert "listed" in " ".join(matches[0].notes)


@pytest.mark.parametrize("missing", ["SubjectUserSid", "SubjectUserName", "SubjectDomainName", "ObjectServer", "AccessMask"])
def test_replication_missing_positive_qualifiers_do_not_become_high(missing):
    data = {key: value for key, value in DC_SYNC.items() if key != missing}
    matches = run(replication_rule(), [native(4662, data)])
    assert len(matches) == 1
    expected = "high" if missing == "SubjectUserSid" else "lead"
    assert matches[0].proposed_lane == expected


@pytest.mark.parametrize("data", [
    {**DC_SYNC, "Properties": "{00299570-246d-11d0-a768-00aa006e0529}"},
    {**DC_SYNC, "Properties": "replication-get-changes-all"},
    {**DC_SYNC, "Properties": "x1131f6ad-9c07-11d1-f79f-00c04fc2dcd2x"},
    {**DC_SYNC, "Properties": "not a GUID", "ObjectName": "CN=" + REPLICATION + ",DC=example"},
])
def test_replication_mentions_and_unrelated_guid_are_hard_negatives(data):
    assert run(replication_rule(), [native(4662, data)]) == []


def test_replication_names_mapping_without_guid_is_not_enough():
    observation = event("directory_access", 4662, **{"directory.rights.names": ["ds-replication-get-changes-all"],
                                                      "directory.object.server": "DS", "directory.access.access_mask": 256})
    assert run(replication_rule(), [observation]) == []


def test_failed_replication_access_is_lead_and_does_not_claim_completed_replication():
    matches = run(replication_rule(), [native(4662, DC_SYNC, failure=True)])
    assert len(matches) == 1 and matches[0].proposed_lane == "lead"
    assert "failed" in matches[0].claim.lower()


@pytest.mark.parametrize("code", [4768, 4769, 4770])
@pytest.mark.parametrize("encryption", [1, 3, 23, 24])
def test_all_supported_weak_kerberos_encryption_types_are_leads(code, encryption):
    matches = run(WeakKerberosTicketEncryption(), [native(code, {**RC4, "TicketEncryptionType": hex(encryption)})])
    assert len(matches) == 1 and matches[0].proposed_lane == "lead"


@pytest.mark.parametrize("service", ["svc_db$", "server$", "krbtgt", "krbtgt/EXAMPLE", "-"])
def test_attacker_controlled_machine_style_service_names_do_not_suppress_weak_ticket_activity(service):
    matches = run(WeakKerberosTicketEncryption(), [native(4769, {**RC4, "ServiceName": service})])
    assert len(matches) == 1 and matches[0].proposed_lane == "lead"
    assert "user-service-like" not in matches[0].claim


@pytest.mark.parametrize("etype", [0, 17, 18, 0xffffffff])
def test_aes_or_failure_sentinel_is_not_a_weak_encryption_anomaly(etype):
    assert run(WeakKerberosTicketEncryption(), [native(4769, {**RC4, "TicketEncryptionType": hex(etype),
                                                           "Status": "0x1f" if etype == 0xffffffff else "0"})]) == []


def test_rc4_user_service_name_is_qualified_not_asserted_account_type():
    match = run(WeakKerberosTicketEncryption(), [native(4769, RC4)])[0]
    assert "user-service-like" in match.claim
    assert "not proof" in " ".join(match.notes)


def test_failed_rc4_request_is_not_presented_as_successful_ticket_issuance():
    match = run(WeakKerberosTicketEncryption(), [native(4769, {**RC4, "Status": "0x1f"})])[0]
    assert "failed" in match.claim.lower() and "issued" not in match.claim.lower()


def test_preauth_zero_success_has_precise_success_wording():
    match = run(KerberosNoPreauthentication(), [native(4768, ASREP)])[0]
    assert "successful" in match.claim.lower() and "not used" in match.claim.lower()
    assert "cracked" not in match.claim.lower()


def test_preauth_zero_result_code_success_is_supported():
    data = {key: value for key, value in ASREP.items() if key != "Status"}
    match = run(KerberosNoPreauthentication(), [native(4768, {**data, "ResultCode": "0"})])[0]
    assert "successful" in match.claim.lower()


def test_preauth_zero_without_result_is_only_unconfirmed_request_observation():
    data = {key: value for key, value in ASREP.items() if key != "Status"}
    match = run(KerberosNoPreauthentication(), [native(4768, data)])[0]
    assert "unconfirmed" in match.claim.lower() and not match.claim.startswith("A successful")


@pytest.mark.parametrize("code,data", [(4768, {**ASREP, "Status": "0x19"}),
                                       (4768, {**ASREP, "PreAuthType": "2"}), (4769, ASREP)])
def test_failed_or_preauthenticated_request_is_not_asrep_signal(code, data):
    assert run(KerberosNoPreauthentication(), [native(code, data)]) == []


@pytest.mark.parametrize("dn", ["CN=AdminSDHolder,CN=System,DC=example,DC=test",
                              r"CN=\41dminSDHolder,CN=\53ystem,DC=example,DC=test"])
def test_adminsdholder_exact_and_hex_escaped_rdns(dn):
    assert run(AdminSdHolderChange(), [native(5136, {**ADMIN, "ObjectDN": dn})])


@pytest.mark.parametrize("dn", ["CN=AdminSDHolder-Copy,CN=System,DC=example,DC=test",
                              "CN=AdminSDHolder,OU=Users,DC=example,DC=test",
                              r"CN=AdminSDHolder\,CN=System,OU=Users,DC=example,DC=test",
                              r"CN=AdminSDHolder\2cCN=System,OU=Users,DC=example,DC=test",
                              "CN=AdminSDHolder+OU=Fake,CN=System,DC=example,DC=test",
                              "CN=Other,CN=System,DC=example,DC=test"])
def test_deceptive_adminsdholder_dn_shapes_are_hard_negatives(dn):
    assert run(AdminSdHolderChange(), [native(5136, {**ADMIN, "ObjectDN": dn})]) == []


def test_multivalued_and_unicode_escaped_rdn_parser_is_structured():
    assert parse_dn(r"CN=User\, One+UID=\c3\a9,OU=People,DC=example") == (
        (("cn", "user, one"), ("uid", "é")), (("ou", "people"),), (("dc", "example"),))
    assert parse_dn("CN=Broken\\") is None


@pytest.mark.parametrize("dn", ["CN=Broken\\", r"CN=Bad\zz,DC=example", r"CN=Bad\ff,DC=example",
                              "CN=Bad\ud800,DC=example", "CN=User,,DC=example", "not a DN"])
def test_malformed_dn_values_do_not_crash_or_select_adminsdholder(dn):
    assert parse_dn(dn) is None
    assert run(AdminSdHolderChange(), [native(5136, {**ADMIN, "ObjectDN": dn})]) == []


@pytest.mark.parametrize("attribute", ["gPLink", "gPOptions"])
def test_gpo_link_attributes_are_signaled_on_non_gpo_objects(attribute):
    data = {**ADMIN, "ObjectDN": "OU=Workstations,DC=example,DC=test", "ObjectClass": "organizationalUnit",
            "AttributeLDAPDisplayName": attribute}
    assert run(GroupPolicyDirectoryChange(), [native(5136, data)])


def test_gpo_exact_container_path_qualifies_without_class():
    data = {key: value for key, value in GPO.items() if key != "ObjectClass"}
    assert run(GroupPolicyDirectoryChange(), [native(5137, data)])


@pytest.mark.parametrize("rule,data,attribute", [(GroupPolicyDirectoryChange, GPO, "gPLink-copy"),
                                               (TrustDirectoryChange, TRUST, "trustDirection-copy")])
def test_attribute_and_value_mentions_do_not_replace_exact_object_or_attribute_selection(rule, data, attribute):
    data = {**data, "ObjectDN": "CN=Ordinary,OU=Users,DC=example,DC=test", "ObjectClass": "user",
            "AttributeLDAPDisplayName": attribute, "AttributeValue": str(data)}
    assert run(rule(), [native(5136, data)]) == []


@pytest.mark.parametrize("attribute", ["trustAttributes", "trustDirection", "trustType", "trustPartner",
                                     "trustAuthIncoming", "trustAuthOutgoing", "msDS-TrustForestTrustInfo"])
def test_exact_trust_attributes_qualify_without_object_class(attribute):
    data = {key: value for key, value in TRUST.items() if key != "ObjectClass"}
    data["AttributeLDAPDisplayName"] = attribute
    assert run(TrustDirectoryChange(), [native(5136, data)])


@pytest.mark.parametrize("rule,data", [(AdminSdHolderChange, ADMIN), (GroupPolicyDirectoryChange, GPO),
                                      (TrustDirectoryChange, TRUST)])
@pytest.mark.parametrize("code,verb", [(5136, "modification"), (5137, "creation"), (5138, "restoration"),
                                      (5139, "move"), (5141, "deletion")])
def test_sensitive_directory_change_actions_remain_exact(rule, data, code, verb):
    matches = run(rule(), [native(code, data)])
    assert len(matches) == 1 and verb in matches[0].claim.lower()


@pytest.mark.parametrize("shape", SHAPES)
@pytest.mark.parametrize("rule,data", [(AdminSdHolderChange, ADMIN), (GroupPolicyDirectoryChange, GPO),
                                      (TrustDirectoryChange, TRUST)])
@pytest.mark.parametrize("sensitive_side", ["old", "new"])
def test_real_native_move_fields_select_sensitive_objects_and_keep_both_raw_and_parsed_provenance(
        shape, rule, data, sensitive_side):
    ordinary = "CN=Other,OU=Staging,DC=example,DC=test"
    old_dn = data["ObjectDN"] if sensitive_side == "old" else ordinary
    new_dn = data["ObjectDN"] if sensitive_side == "new" else ordinary
    move = {**ACTOR, "ObjectClass": data["ObjectClass"], "OldObjectDN": old_dn, "NewObjectDN": new_dn}
    observation = native(5139, move, shape=shape)
    assert observation.get("directory.object.dn") is None
    matches = run(rule(), [observation])
    assert len(matches) == 1 and matches[0].proposed_lane == "lead"
    assert "move" in matches[0].claim and " from " in matches[0].claim and " to " in matches[0].claim
    for field, value in (("OldObjectDN", old_dn), ("NewObjectDN", new_dn)):
        name = "windows.event_data." + field
        predicates = [item for item in matches[0].predicate if item.field == name]
        assert any(item.value == value and "#parsed:" not in item.origin for item in predicates)
        assert any(item.value == parse_dn(value) and item.origin.endswith("#parsed:directory-rdns")
                   for item in predicates)


@pytest.mark.parametrize("shape", SHAPES)
def test_native_move_hex_escaped_adminsdholder_path_is_selected(shape):
    data = {**ACTOR, "ObjectClass": "container", "OldObjectDN": r"CN=\41dminSDHolder,CN=\53ystem,DC=example,DC=test",
            "NewObjectDN": "CN=Other,OU=Staging,DC=example,DC=test"}
    assert run(AdminSdHolderChange(), [native(5139, data, shape=shape)])


@pytest.mark.parametrize("shape", SHAPES)
@pytest.mark.parametrize("old_dn", [r"CN=AdminSDHolder\,CN=System,OU=Users,DC=example,DC=test",
                                  r"CN=AdminSDHolder\2cCN=System,OU=Users,DC=example,DC=test",
                                  "CN=AdminSDHolder,CN=System,DC=example\\"])
def test_native_move_escaped_or_malformed_name_cannot_fake_adminsdholder(shape, old_dn):
    data = {**ACTOR, "ObjectClass": "container", "OldObjectDN": old_dn,
            "NewObjectDN": "CN=Other,OU=Staging,DC=example,DC=test"}
    assert run(AdminSdHolderChange(), [native(5139, data, shape=shape)]) == []


@pytest.mark.parametrize("shape", SHAPES)
@pytest.mark.parametrize("rule", [GroupPolicyDirectoryChange, TrustDirectoryChange])
@pytest.mark.parametrize("old_dn", [r"CN={11111111-2222-3333-4444-555555555555}\,CN=Policies\,CN=System,OU=Users,DC=example",
                                  "CN=trustedDomain,OU=Users,DC=example", "CN=Broken\\"])
def test_native_move_dn_mentions_and_malformed_paths_without_relevant_class_are_negative(shape, rule, old_dn):
    data = {**ACTOR, "ObjectClass": "user", "OldObjectDN": old_dn,
            "NewObjectDN": "CN=Other,OU=Staging,DC=example,DC=test"}
    assert run(rule(), [native(5139, data, shape=shape)]) == []


@pytest.mark.parametrize("rule,data", [(AdminSdHolderChange, ADMIN), (GroupPolicyDirectoryChange, GPO),
                                      (TrustDirectoryChange, TRUST)])
@pytest.mark.parametrize("other_endpoint", [None, "CN=Broken\\", r"CN=Bad\ff,DC=example"])
def test_move_retains_sensitive_observation_without_inventing_missing_or_malformed_endpoint(rule, data, other_endpoint):
    move = {**ACTOR, "ObjectClass": data["ObjectClass"], "OldObjectDN": data["ObjectDN"]}
    if other_endpoint is not None:
        move["NewObjectDN"] = other_endpoint
    matches = run(rule(), [native(5139, move)])
    assert len(matches) == 1 and "move" in matches[0].claim
    assert " from " not in matches[0].claim and " to " not in matches[0].claim
    assert "unrecorded or malformed" in " ".join(matches[0].notes)


def test_real_native_restoration_fields_also_select_new_adminsdholder_dn():
    restore = {**ACTOR, "ObjectClass": "container", "OldObjectDN": "CN=Deleted,CN=Deleted Objects,DC=example,DC=test",
               "NewObjectDN": ADMIN["ObjectDN"]}
    matches = run(AdminSdHolderChange(), [native(5138, restore)])
    assert len(matches) == 1 and "restoration" in matches[0].claim


@pytest.mark.parametrize("rule,code,data", CASES)
def test_wrong_os_or_event_class_never_matches(rule, code, data):
    observation = native(code, data)
    observation.fields["host.os.family"] = fv("linux", "test:os")
    assert run(rule(), [observation]) == []
    observation = native(code, data)
    observation.fields["event.code"] = fv(999, "test:code")
    assert run(rule(), [observation]) == []


def test_all_rule_metadata_attack_ids_and_assurance_are_valid():
    knowledge = load_attack_bundle()
    assert len(WINDOWS_DIRECTORY_PLAYBOOKS) == 6
    for rule in WINDOWS_DIRECTORY_PLAYBOOKS:
        assert rule.benign and rule.next_checks and rule.research and rule.windows_event_classes
        assert rule.assures_negative is False and rule.positive_only_reason and rule.card
        for attack_id in rule.attack:
            technique = knowledge.technique(attack_id)
            assert not technique.revoked and not technique.deprecated
