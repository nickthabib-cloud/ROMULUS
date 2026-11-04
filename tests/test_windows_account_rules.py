"""Direct account signals, tested through all three normalized Windows shipper shapes."""
import gzip
import json
from pathlib import Path

import pytest

from romulus.detect.windows_account_events import (
    WINDOWS_ACCOUNT_PLAYBOOKS,
    AccountCreation,
    ComputerAccountConfiguration,
    DsrmPasswordAttempt,
    PrivilegedGroupAddition,
    SidHistoryChange,
    creation_target_sid,
    privileged_group_sid,
)
from romulus.evidence.windows import normalize_windows
from romulus.evidence.windows_catalog import SECURITY
from tests.test_windows_c_identity_review import event
from tests.windows_event_support import run
from tests.windows_fixtures import SHAPES, LogicalWindowsEvent, windows_hit

DOMAIN = "S-1-5-21-111-222-333"
MEMBER = DOMAIN + "-1100"
ACTOR = DOMAIN + "-1001"


def native(code, data, *, shape="elastic_agent", host="dc01.example.test", ordinal=1, failure=False):
    data = {"SubjectUserSid": ACTOR, "SubjectUserName": "operator", "SubjectDomainName": "EXAMPLE", **data}
    logical = LogicalWindowsEvent("Security", SECURITY, code, host, ordinal, "2026-01-02T03:00:00Z", data)
    hit = windows_hit(logical, shape)
    if failure:
        hit["_source"]["event"] = {"outcome": "failure"}
        hit["_source"]["winlog"]["keywords"] = ["Audit Failure"]
    return normalize_windows(hit)


@pytest.mark.parametrize("shape", SHAPES)
@pytest.mark.parametrize("code", [4728, 4732, 4756])
@pytest.mark.parametrize("group", ["S-1-5-32-544", DOMAIN + "-512", DOMAIN + "-519"])
def test_sensitive_additions_are_immediate_without_creation_context(shape, code, group):
    ev = native(code, {"TargetSid": group, "MemberSid": MEMBER, "TargetUserName": "renamed-group"}, shape=shape)
    instance = PrivilegedGroupAddition()
    matches = instance.consume([ev])
    assert len(matches) == 1 and matches[0].proposed_lane == "high"
    assert "added" in matches[0].claim and MEMBER.casefold() in matches[0].claim
    assert ev.get("account.group_id") == group
    assert all(match.events == [ev] for match in matches)


@pytest.mark.parametrize("rid", [512, 516, 517, 518, 519, 520, 521, 526, 527])
def test_domain_privileged_rids_use_complete_sid_structure(rid):
    sid = DOMAIN + f"-{rid}"
    assert privileged_group_sid(sid) == sid.casefold()
    assert privileged_group_sid("untrusted-" + sid) is None
    assert privileged_group_sid("S-1-5-999-111-222-333-" + str(rid)) is None


@pytest.mark.parametrize("rid", [544, 548, 549, 550, 551, 552, 555, 580])
def test_builtin_sensitive_groups_have_exact_scoped_sids(rid):
    sid = f"S-1-5-32-{rid}"
    assert privileged_group_sid(sid) == sid.casefold()
    assert privileged_group_sid("S-1-5-21-32-" + str(rid)) is None


@pytest.mark.parametrize("sid", [DOMAIN + "-525", DOMAIN + "-513", DOMAIN + "-1100", "S-1-5-32-545"])
def test_valid_ordinary_and_protective_groups_are_hard_negatives_even_with_admin_name(sid):
    ev = native(4732, {"TargetSid": sid, "TargetUserName": "Domain Admins", "MemberSid": MEMBER})
    assert privileged_group_sid(sid) is None
    assert not run(PrivilegedGroupAddition(), [ev])


@pytest.mark.parametrize("fake", [None, "", "Domain Admins", "xS-1-5-32-544", "S-1-5-32-544-extra",
                                 "S-1-5-21-1-2-512", "S-1-5-21-1-2-3-4294967296", "S-1-0-0"])
def test_names_and_malformed_sids_cannot_establish_group_privilege(fake):
    ev = event("account_change", 4732, **{"account.group_id": fake, "account.group_name": "administrators",
                                        "account.member_id": MEMBER})
    matches = run(PrivilegedGroupAddition(), [ev])
    assert not any(match.proposed_lane == "high" for match in matches)
    if matches:
        assert "unknown" in matches[0].claim


@pytest.mark.parametrize("member", [None, "CN=Alice,OU=Users,DC=example,DC=test", "S-1-0-0", "sid:" + MEMBER])
def test_member_name_cannot_substitute_for_validated_member_sid(member):
    ev = event("account_change", 4732, **{"account.group_id": "S-1-5-32-544", "account.member_id": member,
                                        "account.member_name": "CN=Alice,DC=example,DC=test"})
    matches = run(PrivilegedGroupAddition(), [ev])
    assert len(matches) == 1 and matches[0].proposed_lane == "lead" and "member SID" in matches[0].claim


@pytest.mark.parametrize("code", [4729, 4733, 4757, 4741])
def test_removals_and_unrelated_codes_do_not_claim_group_addition(code):
    assert not run(PrivilegedGroupAddition(), [native(code, {"TargetSid": "S-1-5-32-544", "MemberSid": MEMBER})])


@pytest.mark.parametrize("outcome", ["failure", "unknown"])
def test_unsuccessful_membership_record_is_an_attempt(outcome):
    ev = event("account_change", 4732, outcome=outcome,
               **{"account.group_id": "S-1-5-32-544", "account.member_id": MEMBER})
    matches = run(PrivilegedGroupAddition(), [ev])
    assert len(matches) == 1 and matches[0].proposed_lane == "lead"
    assert "attempt" in matches[0].claim and "member " + MEMBER.casefold() + " added" not in matches[0].claim


@pytest.mark.parametrize("shape", SHAPES)
@pytest.mark.parametrize("code,lane,word", [(4765, "high", "added"), (4766, "lead", "failed attempt")])
def test_sid_history_success_and_failed_attempt_are_distinct(shape, code, lane, word):
    ev = native(code, {"TargetSid": MEMBER, "TargetUserName": "new", "SidHistory": DOMAIN + "-512"}, shape=shape)
    matches = run(SidHistoryChange(), [ev])
    assert len(matches) == 1 and matches[0].proposed_lane == lane and word in matches[0].claim
    assert ev.get("account.sid_history") == [DOMAIN + "-512"]


def test_sid_history_event_survives_missing_target_and_source_list():
    ev = native(4765, {"SidList": DOMAIN + "-512"})
    assert ev.get("account.sid_history") is None
    matches = run(SidHistoryChange(), [ev])
    assert len(matches) == 1 and matches[0].proposed_lane == "high"
    assert "unresolved" in matches[0].claim


@pytest.mark.parametrize("shape", SHAPES)
@pytest.mark.parametrize("status", [None, "0x0", "0xc0000022"])
def test_dsrm_event_always_claims_only_attempt_including_audit_failure_gap(shape, status):
    data = {"Workstation": "dc02", "SubjectLogonId": "0x44"}
    if status is not None:
        data["Status"] = status
    ev = native(4794, data, shape=shape, failure=True)
    matches = run(DsrmPasswordAttempt(), [ev])
    assert len(matches) == 1 and matches[0].proposed_lane == "lead"
    assert "password-setting attempt" in matches[0].claim
    assert "success" not in matches[0].claim and "password was changed" not in matches[0].claim


@pytest.mark.parametrize("shape", SHAPES)
@pytest.mark.parametrize("code", [4720, 4741])
@pytest.mark.parametrize("actor_name", ["ordinary", "Administrator", "machine$", "unfamiliar.exe"])
def test_account_creation_targetsid_and_actor_claims_are_precise(shape, code, actor_name):
    ev = native(code, {"TargetSid": MEMBER, "TargetUserName": "new$", "TargetDomainName": "EXAMPLE",
                       "SubjectUserName": actor_name}, shape=shape)
    assert ev.get("auth.target_account") == "name:example\\new$"
    assert creation_target_sid(ev) == MEMBER.casefold()
    matches = run(AccountCreation(), [ev])
    assert len(matches) == 1 and matches[0].proposed_lane == "lead"
    assert MEMBER.casefold() in matches[0].claim and ACTOR.casefold() in matches[0].claim
    assert "ordinary user" not in matches[0].claim and "non-administrator" not in matches[0].claim


def test_creation_identity_fallback_and_conflict_refuse_name_or_wrong_account_join():
    def ev(**fields):
        return event("account_change", 4720, **fields)
    assert creation_target_sid(ev(**{"auth.target_account": "sid:" + MEMBER})) == MEMBER.casefold()
    assert creation_target_sid(ev(**{"auth.target_account": "name:EXAMPLE\\alice"})) is None
    assert creation_target_sid(ev(**{"account.group_id": MEMBER, "auth.target_account": "sid:" + ACTOR})) is None
    assert creation_target_sid(ev(**{"account.group_id": "malformed", "auth.target_account": "sid:" + MEMBER})) is None
    assert creation_target_sid(event("account_change", 4742, **{"account.group_id": MEMBER})) is None


def test_new_member_on_same_host_is_a_new_immediate_strong_finding():
    instance = PrivilegedGroupAddition()
    for index in [1100, 1101]:
        member = DOMAIN + f"-{index}"
        ev = native(4732, {"TargetSid": "S-1-5-32-544", "MemberSid": member}, ordinal=index)
        matches = instance.consume([ev])
        assert matches and any(match.proposed_lane == "high" and member.casefold() in match.claim for match in matches)


# These are SAMR values; the AD userAccountControl masks differ.
FLAGS = [(0x4, "%%2082", "password-not-required"), (0x200, "%%2089", "password-never-expires"),
         (0x800, "%%2091", "reversible password storage"), (0x2000, "%%2093", "trusted-for-delegation"),
         (0x8000, "%%2095", "DES-only"), (0x10000, "%%2096", "preauthentication exemption"),
         (0x40000, "%%2098", "protocol-transition delegation"), (0x80000, "%%2099", "authorization-data exclusion")]


@pytest.mark.parametrize("shape", SHAPES)
@pytest.mark.parametrize("mask,token,word", FLAGS)
def test_samr_enabled_transitions_normalize_and_match_every_shipper(shape, mask, token, word):
    ev = native(4742, {"TargetSid": MEMBER, "OldUacValue": "0x80", "NewUacValue": hex(0x80 | mask),
                       "UserAccountControl": token}, shape=shape)
    assert ev.get("account.old_uac") == 128
    assert ev.get("account.new_uac") == 128 | mask
    matches = run(ComputerAccountConfiguration(), [ev])
    assert len(matches) == 1 and matches[0].proposed_lane == "high" and word in matches[0].claim
    assert "enabled" in matches[0].claim


@pytest.mark.parametrize("mask,token,word", FLAGS)
def test_samr_numeric_only_transition_is_sufficient_but_unchanged_flags_are_not(mask, token, word):
    fields = {"account.old_uac": 128, "account.new_uac": 128 | mask}
    matches = run(ComputerAccountConfiguration(), [event("account_change", 4742, **fields)])
    assert len(matches) == 1 and matches[0].proposed_lane == "high" and word in matches[0].claim
    assert not run(ComputerAccountConfiguration(), [event("account_change", 4742,
                   **{"account.old_uac": 128 | mask, "account.new_uac": 128 | mask})])


@pytest.mark.parametrize("mask,token,word", FLAGS)
def test_new_flag_without_old_state_only_establishes_unknown_transition(mask, token, word):
    matches = run(ComputerAccountConfiguration(), [event("account_change", 4742, **{"account.new_uac": 128 | mask})])
    assert len(matches) == 1 and matches[0].proposed_lane == "lead" and "unknown" in matches[0].claim


@pytest.mark.parametrize("shape", SHAPES)
def test_exact_enabled_token_without_numeric_values_is_valid_but_disabled_is_not_enablement(shape):
    enabled = native(4742, {"UserAccountControl": "%%2093"}, shape=shape)
    disabled = native(4742, {"UserAccountControl": "%%2061"}, shape=shape)
    assert run(ComputerAccountConfiguration(), [enabled])[0].proposed_lane == "high"
    matches = run(ComputerAccountConfiguration(), [disabled])
    assert len(matches) == 1 and matches[0].proposed_lane == "lead" and "disabled" in matches[0].claim


@pytest.mark.parametrize("fields", [
    {"account.uac_changes": ["trusted_for_delegation_enabled", "trusted_for_delegation_disabled"]},
    {"account.uac_changes": ["trusted_for_delegation_enabled"], "account.old_uac": 0x2080, "account.new_uac": 0x2080},
    {"account.uac_changes": ["trusted_for_delegation_enabled"], "account.old_uac": 0x80, "account.new_uac": 0x80},
    {"account.uac_changes": ["trusted_for_delegation_enabled"], "account.old_uac": "bad", "account.new_uac": 0x2080},
    {"account.uac_changes": ["TRUSTED_FOR_DELEGATION"]},
    {"account.old_uac": -1, "account.new_uac": 0x2080}, {"account.new_uac": True},
])
def test_inconsistent_malformed_and_ambiguous_uac_data_never_claims_enabled_high(fields):
    matches = run(ComputerAccountConfiguration(), [event("account_change", 4742, **fields)])
    assert matches and all(match.proposed_lane == "lead" for match in matches)
    assert any("unknown" in match.claim for match in matches)


def test_ad_uac_masks_are_not_misread_as_samr_delegation_or_preauth_flags():
    # AD's TRUSTED_FOR_DELEGATION bit is SAMR's authorization-data exclusion bit.
    ev = event("account_change", 4742, **{"account.old_uac": 0x80, "account.new_uac": 0x80080})
    matches = run(ComputerAccountConfiguration(), [ev])
    assert len(matches) == 1 and "authorization-data exclusion" in matches[0].claim
    assert "trusted-for-delegation" not in matches[0].claim
    # AD's no-preauth mask is not a SAMR no-preauth transition.
    assert not run(ComputerAccountConfiguration(), [event("account_change", 4742,
                   **{"account.old_uac": 0x80, "account.new_uac": 0x400080})])


@pytest.mark.parametrize("fields,qualifiers", [
    ({"account.allowed_to_delegate_to": ["<value not set>"], "account.old_uac": 0, "account.new_uac": 0x2000},
     ["delegation target list was recorded cleared", "trusted-for-delegation was recorded enabled"]),
    ({"account.allowed_to_delegate_to": ["%%1793"], "account.old_uac": 0, "account.new_uac": 0x2000},
     ["its effect is unknown", "trusted-for-delegation was recorded enabled"]),
    ({"account.uac_changes": ["unrecognized_flag", "trusted_for_delegation_enabled"]},
     ["security effect is unknown", "trusted-for-delegation was recorded enabled"]),
    ({"account.old_uac": 0x200, "account.new_uac": 0x2000},
     ["password-never-expires was recorded disabled", "trusted-for-delegation was recorded enabled"]),
    ({"account.old_uac": 0, "account.new_uac": 0x2800},
     ["reversible password storage was recorded enabled", "trusted-for-delegation was recorded enabled"]),
])
def test_one_stored_event_result_preserves_later_high_and_all_qualifiers(fields, qualifiers):
    ev = event("account_change", 4742, **fields)
    # run() applies stored(), mirroring the publisher's one-candidate identity per rule/raw record.
    matches = run(ComputerAccountConfiguration(), [ev])
    assert len(matches) == 1 and matches[0].proposed_lane == "high"
    assert all(qualifier in matches[0].claim for qualifier in qualifiers)
    assert matches[0].events == [ev]


def test_combined_configuration_keeps_new_host_and_changed_content_immediate():
    instance = ComputerAccountConfiguration()
    for index, (host, flags) in enumerate([("first", 0x2000), ("second", 0x2000), ("first", 0x2800)]):
        ev = event("account_change", 4742, host=host, native=f"combined-{index}",
                   **{"account.allowed_to_delegate_to": ["<value not set>"],
                      "account.old_uac": 0, "account.new_uac": flags})
        matches = instance.consume([ev])
        assert len(matches) == 1 and matches[0].proposed_lane == "high"
        assert matches[0].events == [ev]
        assert "cleared" in matches[0].claim and "trusted-for-delegation was recorded enabled" in matches[0].claim
        if flags == 0x2800:
            assert "reversible password storage was recorded enabled" in matches[0].claim


@pytest.mark.parametrize("shape", SHAPES)
def test_allowed_delegation_is_new_full_list_not_addition_or_rbcd(shape):
    ev = native(4742, {"TargetSid": MEMBER, "AllowedToDelegateTo": "cifs/host.example.test\r\nhttp/web.example.test"}, shape=shape)
    matches = run(ComputerAccountConfiguration(), [ev])
    assert len(matches) == 1 and matches[0].proposed_lane == "high"
    assert "new full delegation target list" in matches[0].claim and "added" not in matches[0].claim
    assert "resource-based" not in matches[0].claim


@pytest.mark.parametrize("shape", SHAPES)
@pytest.mark.parametrize("value", ["%%1793", "<value not set>", "%%9999", "arbitrary", "cifs/host\r\n%%1793"])
def test_clear_or_unknown_delegation_list_does_not_become_an_spn_high(shape, value):
    ev = native(4742, {"AllowedToDelegateTo": value}, shape=shape)
    matches = run(ComputerAccountConfiguration(), [ev])
    assert len(matches) == 1 and matches[0].proposed_lane == "lead"
    assert "cleared" in matches[0].claim or "unknown" in matches[0].claim


@pytest.mark.parametrize("value", [{}, ["%%1793/host"], ["cifs//host"], ["cifs/host with spaces"]])
def test_malformed_native_delegation_values_are_uncertainty_leads(value):
    matches = run(ComputerAccountConfiguration(), [event("account_change", 4742,
                   **{"account.allowed_to_delegate_to": value})])
    assert len(matches) == 1 and matches[0].proposed_lane == "lead" and "unknown" in matches[0].claim


def test_attacker_controlled_dollar_tokens_do_not_suppress_a_valid_delegation_change():
    ev = native(4742, {"TargetUserName": "unknown$", "AllowedToDelegateTo": "arbitrary$/host.example.test"})
    matches = run(ComputerAccountConfiguration(), [ev])
    assert len(matches) == 1 and matches[0].proposed_lane == "high"


@pytest.mark.parametrize("shape", SHAPES)
def test_unchanged_or_unshown_computer_attributes_are_not_reported_as_enablement(shape):
    assert not run(ComputerAccountConfiguration(), [native(4742, {"AllowedToDelegateTo": "-", "OldUacValue": "0x80",
                                                               "NewUacValue": "0x80", "UserAccountControl": "-"}, shape=shape)])


@pytest.mark.parametrize("rule,code,fields", [
    (PrivilegedGroupAddition, 4732, {"account.group_id": "S-1-5-32-544", "account.member_id": MEMBER}),
    (SidHistoryChange, 4765, {}), (DsrmPasswordAttempt, 4794, {}),
    (AccountCreation, 4741, {"account.group_id": MEMBER}),
    (ComputerAccountConfiguration, 4742, {"account.old_uac": 128, "account.new_uac": 0x2080}),
])
def test_each_new_host_is_published_immediately_and_wrong_os_family_are_excluded(rule, code, fields):
    instance = rule()
    for host in ["first", "second"]:
        ev = event("account_change", code, host=host, **fields)
        matches = instance.consume([ev])
        assert matches and any(ev in match.events for match in matches)
    assert not run(rule(), [event("account_change", code, **{"host.os.family": "linux", **fields})])
    wrong_family = event("account_change", code, **fields)
    wrong_family.family = "auth"
    assert not run(rule(), [wrong_family])


def test_metadata_is_positive_only_selective_and_active_attack20():
    root = next(parent for parent in Path(__file__).resolve().parents
                if (parent / "content/attack/enterprise-attack-20.0.json.gz").is_file())
    with gzip.open(root / "content/attack/enterprise-attack-20.0.json.gz", "rt", encoding="utf-8") as stream:
        objects = json.load(stream)["objects"]
    active = {ref["external_id"] for obj in objects if obj.get("type") == "attack-pattern"
              and not obj.get("revoked") and not obj.get("x_mitre_deprecated")
              for ref in obj.get("external_references", []) if "external_id" in ref}
    for rule in WINDOWS_ACCOUNT_PLAYBOOKS:
        assert rule.assures_negative is False and rule.positive_only_reason
        assert rule.families == ("account_change",) and rule.os_families == ("windows",)
        assert rule.windows_event_classes and all(item[:2] == ("Security", SECURITY) for item in rule.windows_event_classes)
        assert rule.attack and set(rule.attack) <= active
        assert rule.benign and rule.next_checks and rule.research
