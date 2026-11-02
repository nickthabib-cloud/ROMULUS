"""Service/task/tamper predicates and restrained claims, independent of registry wiring."""
import gzip
import json
from pathlib import Path

import pytest

from romulus.detect.windows_registration_events import (
    WINDOWS_REGISTRATION_PLAYBOOKS,
    ScheduledTaskRegistration,
    ServiceRegistration,
    WindowsAuditTamper,
)
from romulus.evidence.windows import normalize_windows
from romulus.evidence.windows_catalog import SECURITY
from tests.test_windows_c_identity_review import event
from tests.windows_event_support import run
from tests.windows_fixtures import LogicalWindowsEvent, windows_hit


def _judge(rule, family, code, **fields):
    hits = rule().judge(event(family, code, **fields))
    assert len(hits) == 1
    return hits[0]


@pytest.mark.parametrize("code", [4697, 7045])
@pytest.mark.parametrize("image", ['"C:\\Users\\Jane Doe\\payload.exe" --service',
                                  "C:\\Windows\\Temp\\payload.exe", "%TEMP%\\svc.exe", "cmd.exe /c sample",
                                  "C:\\Windows\\System32\\wscript.exe test.vbs", "powershell.exe -enc ZQB4AGkAdAA="])
def test_service_risky_configuration_is_high_before_finalize(code, image):
    ev = event("service_change", code, **{"service.image_path": image, "service.name": "ConfiguredService",
                                         "service.type": "16"})
    matches = ServiceRegistration().consume([ev])
    assert len(matches) == 1 and matches[0].proposed_lane == "high"
    assert "installation record registered" in matches[0].claim
    assert "executed" not in matches[0].claim
    assert any(field.field == "service.image_path" and field.value == image for field in matches[0].predicate)


@pytest.mark.parametrize("name", ["PSEXESVC", "RemComSvc", "PAExec"])
def test_exact_remote_service_default_is_lead(name):
    hit = _judge(ServiceRegistration, "service_change", 7045,
                 **{"service.name": name, "service.image_path": '"C:\\Program Files\\Acme\\svc.exe"'})
    assert hit.lane == "lead" and "matches a documented" in hit.text


@pytest.mark.parametrize("image", ["C:\\Program Files\\Acme\\svc.exe --run", '"C:\\Temp\\svc.exe',
                                  '"C:\\Temp\\svc.exe"suffix', None])
def test_service_ambiguous_or_missing_image_is_uncertain_lead(image):
    hit = _judge(ServiceRegistration, "service_change", 4697, **{"service.image_path": image})
    assert hit.lane == "lead"
    assert "ambiguous" in hit.text or "missing" in hit.text


@pytest.mark.parametrize("name,image", [("NotPSEXESVC", "C:\\Windows\\System32\\svchost.exe -k netsvcs"),
                                       ("Acme", '"C:\\Program Files\\Acme\\svc.exe" --mention cmd.exe'),
                                       ("RemComSvcExtra", '"C:\\Program Files\\Acme\\cmd.exe.backup"'),
                                       ("Acme", '"C:\\Program Files\\Acme\\svc.exe"')])
def test_service_hard_negatives(name, image):
    hits = ServiceRegistration().judge(event("service_change", 7045,
                                           **{"service.name": name, "service.image_path": image}))
    if image.startswith("C:\\Windows\\System32\\"):
        assert len(hits) == 1 and hits[0].lane == "lead"
    else:
        assert hits == []


def _task(command="cmd.exe", args="/c example", **extra):
    escaped = command.replace("&", "&amp;").replace("<", "&lt;")
    xml = ("<Task><Actions><Exec><Command>" + escaped + "</Command><Arguments>" + args
           + "</Arguments></Exec></Actions></Task>")
    return {"task.name": "\\Example", "task.xml": xml, "task.xml_parse": "success",
            "task.actions": [{"kind": "exec", "command": command, "arguments": args}], **extra}


@pytest.mark.parametrize("code", [4698, 4702, 106, 140])
@pytest.mark.parametrize("command,args", [("cmd.exe", "/c example"), ("powershell.exe", "-enc ZQB4AGkAdAA="),
                                         ("wscript.exe", "script.vbs"), ("C:\\Users\\Jane Doe\\payload.exe", ""),
                                         ("%TEMP%\\payload.exe", "")])
def test_task_risky_parsed_actions_are_high_with_structural_support(code, command, args):
    fields = _task(command, args)
    if not args:
        fields["task.actions"][0].pop("arguments")
    hit = _judge(ScheduledTaskRegistration, "scheduled_task", code, **fields)
    assert hit.lane == "high" and "parsed Exec Command" in hit.text
    assert "executed" not in hit.text


def test_task_reads_all_actions_not_only_first():
    fields = _task("C:\\Tools\\inventory.exe", "--daily")
    fields["task.xml"] = fields["task.xml"].replace("</Actions>", "<Exec><Command>cmd.exe</Command></Exec></Actions>")
    fields["task.actions"].append({"kind": "exec", "command": "cmd.exe"})
    assert _judge(ScheduledTaskRegistration, "scheduled_task", 4698, **fields).lane == "high"


@pytest.mark.parametrize("fields", [{"task.hidden": True}, {"task.principal.user_id": "S-1-5-18"},
                                    {"task.principal.user_id": "NT AUTHORITY\\SYSTEM"}])
def test_hidden_and_system_without_risky_action_remain_leads(fields):
    hit = _judge(ScheduledTaskRegistration, "scheduled_task", 4698,
                 **_task("C:\\Tools\\inventory.exe", "--daily", **fields))
    assert hit.lane == "lead"


@pytest.mark.parametrize("args,encoded", [("-enc ZQB4AGkAdAA=", True), ("-e ZQB4AGkAdAA=", True),
                                          ("-ExecutionPolicy Bypass", False), ("-EncodedArguments AAAA", False),
                                          ("-File example.ps1 -enc AAAA", False)])
def test_encoded_powershell_uses_host_switch_grammar(args, encoded):
    hit = _judge(ScheduledTaskRegistration, "scheduled_task", 4698, **_task("powershell.exe", args))
    assert ("encoded-command argument" in hit.text) is encoded


@pytest.mark.parametrize("xml", [
    "<Task><RegistrationInfo><Exec><Command>cmd.exe</Command></Exec></RegistrationInfo></Task>",
    "<Metadata><Actions><Exec><Command>cmd.exe</Command></Exec></Actions></Metadata>",
    "<Task><Actions><Exec><Command>cmd.exe</Command><Command>other.exe</Command></Exec></Actions></Task>",
])
def test_task_metadata_xml_never_becomes_strong_executable_action(xml):
    native = LogicalWindowsEvent("Security", SECURITY, 4698, "ws01.example.test", 910000,
                                 "2026-01-02T03:00:00Z", {"TaskName": "\\Metadata", "TaskContent": xml})
    ev = normalize_windows(windows_hit(native, "winlogbeat_8"))
    hit = ScheduledTaskRegistration().judge(ev)[0]
    assert hit.lane == "lead" and "uncertain" in hit.text
    assert "executed" not in hit.text


@pytest.mark.parametrize("fields", [{}, {"task.xml_parse": "failed", "task.xml_parse_reason": "oversized XML"},
                                    {"task.actions": [{"kind": "exec", "command": "cmd.exe"}]},
                                    {"task.actions": []}, {"task.actions": ["invalid action"]},
                                    {"task.xml": "<Task>\ud800</Task>", "task.actions": []}])
def test_task_unknown_and_incomplete_configuration_is_lead(fields):
    assert _judge(ScheduledTaskRegistration, "scheduled_task", 106, **fields).lane == "lead"


@pytest.mark.parametrize("code", [4699, 4700, 4701, 141, 129, 201])
def test_task_nonregistration_classes_do_not_claim_new_persistence(code):
    assert ScheduledTaskRegistration().judge(event("scheduled_task", code, **_task())) == []


@pytest.mark.parametrize("command", ["C:\\Program Files\\Acme\\inventory.exe", "C:\\Windows\\System32\\inventory.exe",
                                    "C:\\Program Files\\Acme\\cmd.exe.backup"])
def test_task_normal_action_and_argument_mentions_do_not_match(command):
    assert ScheduledTaskRegistration().judge(event("scheduled_task", 4698,
                                                  **_task(command, "--description cmd.exe powershell.exe -enc"))) == []


@pytest.mark.parametrize("name", ["C:\\Windows\\System32\\cmd.exe", "C:\\Windows\\System32\\powershell.exe",
                                 "C:\\Temp\\payload.exe"])
def test_task_action_started_name_has_distinct_restrained_claim(name):
    hit = _judge(ScheduledTaskRegistration, "scheduled_task", 200, **{"task.action_name": name})
    assert hit.lane == "lead" and "action-started record named" in hit.text
    assert "registered" not in hit.text and "executed" not in hit.text


@pytest.mark.parametrize("code,fields,phrase", [
    (1102, {}, "event log cleared"), (104, {"event.channel": "System"}, "event log cleared"),
    (4719, {"audit.config.changes": "Success added"}, "audit policy change"),
    (4719, {"audit.config.changes": "unknown localized value"}, "audit policy change"),
    (1100, {}, "logging service shutting down"), (16, {}, "configuration change"),
    (4, {"audit.config.state": "Stopped"}, "service stopped"),
])
def test_strong_logging_records_are_immediate(code, fields, phrase):
    ev = event("audit_config", code, **fields)
    matches = WindowsAuditTamper().consume([ev])
    assert len(matches) == 1 and matches[0].proposed_lane == ("high" if code in {1102, 104} else "lead")
    assert phrase in matches[0].claim
    if code == 104:
        assert "System log" not in matches[0].claim
    if code == 4719:
        assert "does not establish disabled" in matches[0].claim


@pytest.mark.parametrize("code,fields", [(1104, {}), (1108, {}), (255, {}), (4, {}),
                                        (4, {"audit.config.state": "Restarted"}),
                                        (4, {"audit.config.state": "NotStopped"})])
def test_error_and_unrecognized_sysmon_state_records_stay_leads(code, fields):
    assert _judge(WindowsAuditTamper, "audit_config", code, **fields).lane == "lead"


@pytest.mark.parametrize("state", ["Started", "started", "STARTED"])
def test_sysmon_started_does_not_claim_stopped(state):
    assert WindowsAuditTamper().judge(event("audit_config", 4, **{"audit.config.state": state})) == []


@pytest.mark.parametrize("rule,family,code,fields,changed", [
    (ServiceRegistration, "service_change", 7045, {"service.image_path": "cmd.exe /c first"},
     {"service.image_path": "cmd.exe /c second"}),
    (ScheduledTaskRegistration, "scheduled_task", 4698, _task(), _task("powershell.exe", "-File second.ps1")),
    (WindowsAuditTamper, "audit_config", 4719, {"audit.config.changes": "first"}, {"audit.config.changes": "second"}),
])
def test_new_host_and_content_publish_immediately_with_fleet_folding(rule, family, code, fields, changed):
    rows = [event(family, code, native="first", **fields), event(family, code, native="repeat", offset=1, **fields),
            event(family, code, native="newhost", host="ws02", offset=2, **fields),
            event(family, code, native="content", offset=3, **changed)]
    instance = rule()
    instance.load = lambda ids: [row for row in rows if row.id in ids]
    for row in rows:
        matches = instance.consume([row])
        assert matches
        if row.id in {"newhost", "content"}:
            assert any(any(ev.id == row.id for ev in match.events) for match in matches)
        instance.drain_staged()
    assert run(rule(), rows)


def test_metadata_positive_only_and_active_attack_ids():
    root = Path.cwd()
    with gzip.open(root / "content/attack/enterprise-attack-20.0.json.gz", "rt", encoding="utf-8") as stream:
        bundle = json.load(stream)
    active = {ref["external_id"] for obj in bundle["objects"] if obj.get("type") == "attack-pattern"
              and not obj.get("revoked") and not obj.get("x_mitre_deprecated")
              for ref in obj.get("external_references", []) if ref.get("source_name") == "mitre-attack"}
    for rule in WINDOWS_REGISTRATION_PLAYBOOKS:
        assert not rule.assures_negative and rule.positive_only_reason
        assert rule.attack and set(rule.attack) <= active
        assert rule.benign and rule.next_checks and rule.research and rule.windows_event_classes
        assert rule().judge(event(rule.families[0], 99999)) == []


def test_untyped_mentions_do_not_establish_shell_service_or_task_configuration():
    hit = _judge(ServiceRegistration, "service_change", 7045,
                 **{"windows.event_data.Message": "ImagePath=cmd.exe /c example"})
    assert hit.lane == "lead" and "missing" in hit.text
    hit = _judge(ScheduledTaskRegistration, "scheduled_task", 4698,
                 **{"windows.event_data.Message": "Exec cmd.exe"})
    assert hit.lane == "lead" and "uncertain" in hit.text
