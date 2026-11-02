"""Production native records and persisted site declarations for review regressions."""
import pytest
from starlette.datastructures import FormData

from romulus.detect.windows_directory_events import DirectoryReplicationAccess
from romulus.detect.windows_registration_events import (
    ScheduledTaskRegistration,
    ServiceRegistration,
    WindowsAuditTamper,
)
from romulus.evidence.windows_catalog import EVENTLOG, SYSMON, SYSMON_CHANNEL, TASK_CHANNEL, TASK_PROVIDER
from romulus.site import COLLECTION_SCHEMA, load_site_facts, save_site_facts, validate_site_content
from romulus.web import site_form
from tests.test_windows_c_identity_review import REPLICATION, native
from tests.windows_fixtures import SHAPES


@pytest.mark.parametrize("declared,accounts,actor,lane", [
    (False, [], "MSOL_1234", "lead"), (True, [], "MSOL_1234", "high"),
    (True, ["EXAMPLE\\MSOL_1234"], "MSOL_1234", "lead"),
])
def test_sync_declaration_survives_validation_saved_yaml_and_unchanged_form(tmp_path, declared, accounts, actor, lane):
    content = {"schema": COLLECTION_SCHEMA, "domain_controllers": ["dc01.example.test"]}
    if declared:
        content["directory_sync_accounts"] = accounts
    validated = validate_site_content(content)
    assert ("directory_sync_accounts" in validated.content) is declared
    save_site_facts(tmp_path, content, "")
    facts = load_site_facts(tmp_path)
    shown = site_form.view(facts.content)
    fields = [("group_count", "0"), ("domain_controllers", shown["domain_controllers"]),
              ("directory_sync_accounts", shown["directory_sync_accounts"])]
    if shown["directory_sync_accounts_declared"]:
        fields.append(("directory_sync_accounts_declared", "1"))
    parsed = site_form.parse_form(FormData(fields))
    assert validate_site_content(parsed).digest == facts.digest
    save_site_facts(tmp_path, parsed, facts.digest)
    rule = DirectoryReplicationAccess()
    rule.site_facts = load_site_facts(tmp_path)
    [hit] = rule.consume([native(4662, {**REPLICATION, "SubjectUserName": actor, "SubjectDomainName": "EXAMPLE"})])
    assert hit.proposed_lane == lane
    assert ("not configured" in " ".join(hit.notes)) is (not declared)


@pytest.mark.parametrize("shape", SHAPES)
@pytest.mark.parametrize("dc,domain,user,lane", [
    ("dc01", "", "DC01$", "lead"), ("dc01", "EXAMPLE", "DC01$", "lead"),
    ("dc01.corp.example.com", "EXAMPLE", "DC01$", "lead"),
    ("dc01.example.test", "EXAMPLE", "DC01$", "lead"),
    ("dc01.example.test", "evil.test", "DC01$", "high"),
    ("dc01", "EXAMPLE", "unlisted$", "high"), ("dc01", "EXAMPLE", "analyst", "high"),
])
def test_dc_name_hint_requires_positive_domain_contradiction_for_a_high(shape, dc, domain, user, lane):
    rule = DirectoryReplicationAccess()
    rule.site_facts = validate_site_content({"schema": COLLECTION_SCHEMA, "domain_controllers": [dc],
                                             "directory_sync_accounts": []})
    [hit] = rule.consume([native(4662, {**REPLICATION, "SubjectUserName": user, "SubjectDomainName": domain}, shape=shape)])
    assert hit.proposed_lane == lane


@pytest.mark.parametrize("shape", SHAPES)
def test_native_com_handler_action_is_not_an_outside_executable(shape):
    rule = ScheduledTaskRegistration()
    event = native(200, {"TaskName": "\\Microsoft\\Windows\\CertificateServicesClient\\UserTask",
                         "ActionName": "{47E30D54-DAC1-473A-AFF7-2355BF78881F}"}, shape=shape,
                   channel=TASK_CHANNEL, provider=TASK_PROVIDER)
    [hit] = rule.consume([event])
    assert hit.proposed_lane == "lead"
    assert "COM handler action, no executable path in this record" in hit.claim
    assert "outside standard" not in hit.claim


def test_native_system32_service_image_is_an_immediate_lead():
    [hit] = ServiceRegistration().consume([native(7045, {"ServiceName": "random-service",
        "ImagePath": r"C:\Windows\System32\aBcDeFgH.exe", "ServiceType": "user mode service"},
        channel="System", provider="Service Control Manager")])
    assert hit.proposed_lane == "lead"


def test_shutdown_context_is_only_cited_within_the_stated_proximity():
    rule = WindowsAuditTamper()
    rule.consume([native(1100, {}, channel="Security", provider=EVENTLOG)])
    [hit] = rule.consume([native(4, {"State": "Stopped"}, offset=3600, channel=SYSMON_CHANNEL, provider=SYSMON)])
    assert len(hit.events) == 1
    assert "within 5 minutes" in hit.claim
    assert "unresolved" in hit.claim


def test_mixed_rendered_audit_changes_use_each_token_result():
    [hit] = WindowsAuditTamper().consume([native(4719, {"AuditPolicyChanges": "Success removed, Failure added"})])
    assert hit.proposed_lane == "high"


@pytest.mark.parametrize("shape", SHAPES)
def test_recorded_thread_module_marker_is_preserved_and_missing_stays_missing(shape):
    absent = native(8, {}, shape=shape, channel=SYSMON_CHANNEL, provider=SYSMON)
    marker = native(8, {"StartModule": "-"}, shape=shape, channel=SYSMON_CHANNEL, provider=SYSMON)
    assert absent.get("thread.start_module") is None
    assert marker.get("thread.start_module") == "-"
