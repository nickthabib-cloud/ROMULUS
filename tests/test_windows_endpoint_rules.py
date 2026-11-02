"""Endpoint rules retain typed evidence, narrow claims and immediate per-host publication."""
import gzip
import json
from pathlib import Path

import pytest

from romulus.detect.windows_endpoint_events import (
    WINDOWS_ENDPOINT_PLAYBOOKS,
    AdminShareTransfer,
    DefenderProtection,
    DefenderThreat,
    GppPolicyFileAccess,
    RemoteManagementPipe,
    ToolNamedPipe,
    WmiSubscription,
)
from romulus.evidence.windows import normalize_windows
from romulus.evidence.windows_catalog import DEFENDER_CHANNEL, DEFENDER_PROVIDER, SYSMON, SYSMON_CHANNEL
from tests.windows_event_support import event, run
from tests.windows_fixtures import LogicalWindowsEvent, windows_hit


def _hit(rule, family, code, **fields):
    hits = rule().judge(event(family, code, **fields))
    assert len(hits) == 1
    return hits[0]


@pytest.mark.parametrize("code,fields,words", [
    (19, {"wmi.query": "SELECT * FROM Win32_ProcessStartTrace", "wmi.name": "watch"}, "filter activity"),
    (20, {"wmi.type": "LogFileEventConsumer", "wmi.destination": "c:\\log.txt"}, "consumer activity"),
    (21, {"wmi.consumer": "Consumer.Name=one", "wmi.filter": "Filter.Name=two"}, "binding activity"),
    (5861, {"wmi.binding": "recorded binding"}, "permanent-subscription activity"),
])
def test_wmi_component_claims(code, fields, words):
    hit = _hit(WmiSubscription, "wmi_subscription", code, **fields)
    assert hit.lane == "lead" and words in hit.text
    assert "executed" not in hit.text and "installed" not in hit.text
    assert all(any(item.field == name and item.value == value for item in hit.predicate)
               for name, value in fields.items())


@pytest.mark.parametrize("kind", ["Script", "Command Line", "CommandLineEventConsumer", "ActiveScriptEventConsumer"])
def test_wmi_script_consumer_is_immediately_high(kind):
    ev = event("wmi_subscription", 20, **{"wmi.type": kind, "wmi.destination": "c:\\payload.ps1"})
    rule = WmiSubscription()
    matches = rule.consume([ev])
    assert len(matches) == 1 and matches[0].proposed_lane == "high"
    assert "payload.ps1" in matches[0].claim


@pytest.mark.parametrize("fields", [{}, {"wmi.type": "Script"},
                                    {"wmi.type": "ScriptConsumerLookalike", "wmi.destination": "evil"},
                                    {"wmi.type": "Script", "wmi.destination": "evil", "wmi.operation": "Deleted"}])
def test_wmi_missing_unknown_and_removed_components_stay_leads(fields):
    assert _hit(WmiSubscription, "wmi_subscription", 20, **fields).lane == "lead"


@pytest.mark.parametrize("name", ["\\PSEXESVC", "\\\\.\\pipe\\PSEXESVC", "\\RemCom_communicaton",
                                 "\\RemCom_stdoutAbCd1234", "\\RemCom_stdinXyZz9", "\\RemCom_stderrabcd99",
                                 "\\MSSE-01f-server", "\\status_a9", "\\msagent_f0", "\\postex_ab12",
                                 "\\postex_ssh_a0f9", "\\Device\\NamedPipe\\postex_1234"])
@pytest.mark.parametrize("code", [17, 18])
def test_documented_full_pipe_names_are_leads(name, code):
    hit = _hit(ToolNamedPipe, "pipe_event", code, **{"pipe.name": name})
    assert hit.lane == "lead"
    assert "default name" in hit.text
    assert "attacker-controllable" in hit.notes[0]


@pytest.mark.parametrize("name", ["\\safe-PSEXESVC", "\\PSEXESVC-extra", "\\psexesvc\\child",
                                 "c:\\temp\\PSEXESVC", "\\postex_123", "\\postex_12345", "\\postex_zzzz",
                                 "\\postex_1234.txt", "\\foo_postex_1234", "\\postex_ssh_ab12_more",
                                 "\\status_abcd", "\\msagent_zz", "\\RemCom_communication",
                                 "\\RemCom_stdoutABCD", "\\RemCom_stdoutABCDE123", "\\MSSE-abc-serverx"])
def test_pipe_name_substring_and_suffix_traps(name):
    assert ToolNamedPipe().judge(event("pipe_event", 17, **{"pipe.name": name})) == []


def _share_fields(share="ADMIN$", target="Temp\\payload.exe", mask=2):
    return {"share.name": "\\\\*\\" + share, "share.relative_target": target, "share.access_mask": mask}


@pytest.mark.parametrize("mask", [2, 4, 6, 0x100002, 0x12019F, "0x100004"])
@pytest.mark.parametrize("share", ["ADMIN$", "C$", "D$", "Z$"])
def test_admin_share_write_bits_not_mask_allowlist(mask, share):
    hit = _hit(AdminShareTransfer, "share_access", 5145, **_share_fields(share=share, mask=mask))
    assert hit.lane == "lead" and "write/append" in hit.text
    assert "does not establish a completed file write" in hit.text


@pytest.mark.parametrize("fields", [
    _share_fields(mask=1), _share_fields(mask=0x120089),
    _share_fields(share="ADMIN$backup"), _share_fields(share="IPC$"),
    _share_fields(share="AA$"), _share_fields(share="notadmin$"), _share_fields(share="publicshare"),
    _share_fields(target=""),
])
def test_admin_share_hard_negatives(fields):
    assert AdminShareTransfer().judge(event("share_access", 5145, **fields)) == []


@pytest.mark.parametrize("name", ["svcctl", "atsvc", "drsuapi", "\\PIPE\\SVCCTL"])
def test_ipc_management_pipe_lead(name):
    hit = _hit(RemoteManagementPipe, "share_access", 5145, **_share_fields("IPC$", name, 1))
    assert hit.lane == "lead" and "management RPC pipe" in hit.text


@pytest.mark.parametrize("share,name", [("C$", "svcctl"), ("IPC$", "svcctl_extra"), ("IPC$", "prefixsvcctl"),
                                        ("IPC$", "directory\\svcctl"), ("IPC$", "svcctl\\child")])
def test_ipc_pipe_hard_negatives(share, name):
    assert RemoteManagementPipe().judge(event("share_access", 5145, **_share_fields(share, name))) == []


@pytest.mark.parametrize("name", ["Groups.xml", "Services.xml", "ScheduledTasks.xml", "DataSources.xml",
                                 "Printers.xml", "Drives.xml"])
def test_gpp_policy_file_access_claim_does_not_assert_content(name):
    hit = _hit(GppPolicyFileAccess, "share_access", 5145,
               **_share_fields("SYSVOL", "domain\\Policies\\id\\Machine\\Preferences\\Group\\" + name, 1))
    assert hit.lane == "lead" and name in hit.text
    assert "password" not in hit.text and "credential" not in hit.text
    assert "does not show file contents" in hit.notes[0]


@pytest.mark.parametrize("share,path", [("NETLOGON", "Groups.xml"), ("SYSVOL", "Groups.xml.bak"),
                                        ("SYSVOL", "MyGroups.xml"), ("SYSVOL", "Groups.xml\\child")])
def test_gpp_hard_negatives(share, path):
    assert GppPolicyFileAccess().judge(event("share_access", 5145, **_share_fields(share, path))) == []


@pytest.mark.parametrize("code", [1006, 1007, 1008, 1015, 1116, 1117, 1118, 1119])
def test_defender_threat_and_remediation_high_without_context(code):
    ev = event("defender_event", code, **{"defender.threat.name": "Trojan:Test", "defender.path": "c:\\bad.exe"})
    matches = DefenderThreat().consume([ev])
    assert len(matches) == 1 and matches[0].proposed_lane == "high"
    assert "Trojan:Test" in matches[0].claim
    assert "eradicated" not in matches[0].claim and "executed" not in matches[0].claim
    if code in {1118, 1119, 1008}:
        assert "error" in matches[0].claim or "failed" in matches[0].claim


@pytest.mark.parametrize("code,phrase", [(5001, "real-time protection disabled"), (5010, "scanning disabled"),
                                        (5012, "virus scanning disabled"), (5013, "blocked a settings change")])
def test_defender_recorded_status_is_high(code, phrase):
    hit = _hit(DefenderProtection, "defender_event", code)
    assert hit.lane == "high" and phrase in hit.text
    if code == 5013:
        assert "disabled" not in hit.text


_DEFENDER_KEY = "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\"


@pytest.mark.parametrize("tail,value", [
    ("DisableAntiSpyware", "0x1"), ("Real-Time Protection\\DisableRealtimeMonitoring", "1"),
    ("Real-Time Protection\\DisableBehaviorMonitoring", "0x00000001"),
    ("Exclusions\\Paths\\C:\\", "0x0"), ("Exclusions\\Processes\\bad.exe", "0"),
    ("Exclusions\\Extensions\\exe", "0x00000000"),
])
def test_defender_5007_known_unsafe_new_values(tail, value):
    hit = _hit(DefenderProtection, "defender_event", 5007,
               **{"defender.old_value": _DEFENDER_KEY + tail + " = (null)",
                  "defender.new_value": _DEFENDER_KEY + tail + " = " + value})
    assert hit.lane == "high"
    assert "protection-disable" in hit.text or "exclusion entry" in hit.text


@pytest.mark.parametrize("old,new", [
    ("", _DEFENDER_KEY + "DisableAntiSpyware = false"),
    ("", _DEFENDER_KEY + "DisableAntiSpyware = true"),
    ("", _DEFENDER_KEY + "Unexpected\\DisableAntiSpyware = 1"),
    ("", _DEFENDER_KEY + "NotDisableAntiSpyware = 1"),
    ("", "HKLM\\SOFTWARE\\Acme\\Windows Defender\\DisableAntiSpyware = 1"),
    ("", _DEFENDER_KEY + "DisableAntiSpyware = 0xzz"),
    ("", "DisableAntiSpyware = 1"), ("", "unparsed value"), ("", ""),
    ("", _DEFENDER_KEY + "Exclusions\\Paths\\bad = (null)"),
    ("", _DEFENDER_KEY + "Exclusions\\Paths\\bad = 1"),
    (_DEFENDER_KEY + "Exclusions\\Extensions\\exe = 0", _DEFENDER_KEY + "Exclusions\\Extensions\\exe = 0"),
])
def test_defender_5007_safe_unknown_malformed_and_removals_are_leads(old, new):
    hit = _hit(DefenderProtection, "defender_event", 5007,
               **{"defender.old_value": old, "defender.new_value": new})
    assert hit.lane == "lead" and "setting effect is unknown" in hit.text


@pytest.mark.parametrize("value", ["2", "0x2", "0xffffffff", "4294967295", "0x100000001", "4294967296",
                                  "-1", "+1", "1.0", "true", "false", "0b1", "1_0", "'1'", "1 extra",
                                  "DWORD (0x100000001)", "REG_DWORD 1", "DWORD (1) extra", "0x000000001"])
def test_defender_disable_unknown_dword_semantics_remain_effect_unknown_leads(value):
    hit = _hit(DefenderProtection, "defender_event", 5007,
               **{"defender.new_value": _DEFENDER_KEY + "DisableAntiSpyware = " + value})
    assert hit.lane == "lead" and "setting effect is unknown" in hit.text
    assert "was set" not in hit.text


@pytest.mark.parametrize("value", ["1", "0x1", "0x00000001", "DWORD (0x00000001)", "DWORD (1)"])
def test_defender_disable_supported_boolean_dword_one_is_high(value):
    assert _hit(DefenderProtection, "defender_event", 5007,
                **{"defender.new_value": _DEFENDER_KEY + "DisableAntiSpyware = " + value}).lane == "high"


@pytest.mark.parametrize("old,value,word", [("1", "0", "restored"), ("0x1", "0x00000000", "restored"),
                                          (None, "0", "changed"), ("bad", "DWORD (0)", "changed")])
def test_defender_disable_zero_wording_describes_safe_restoration_or_change(old, value, word):
    fields = {"defender.new_value": _DEFENDER_KEY + "DisableAntiSpyware = " + value}
    if old is not None:
        fields["defender.old_value"] = _DEFENDER_KEY + "DisableAntiSpyware = " + old
    hit = _hit(DefenderProtection, "defender_event", 5007, **fields)
    assert hit.lane == "lead" and word in hit.text and "safe zero value" in hit.text
    assert "protection-disable value was set" not in hit.text


@pytest.mark.parametrize("code", [5000, 5009, 5011, 3007, 1116, 9999])
def test_protection_rule_ignores_enabled_restored_and_unrelated_events(code):
    assert DefenderProtection().judge(event("defender_event", code)) == []


def test_threat_rule_ignores_setting_and_unknown_events():
    for code in (5007, 5013, 9999):
        assert DefenderThreat().judge(event("defender_event", code)) == []


@pytest.mark.parametrize("rule,family,code,fields", [
    (WmiSubscription, "wmi_subscription", 20, {"wmi.type": "Script", "wmi.destination": "payload"}),
    (ToolNamedPipe, "pipe_event", 17, {"pipe.name": "\\PSEXESVC"}),
    (AdminShareTransfer, "share_access", 5145, _share_fields()),
    (RemoteManagementPipe, "share_access", 5145, _share_fields("IPC$", "samr")),
    (GppPolicyFileAccess, "share_access", 5145, _share_fields("SYSVOL", r"domain\Policies\id\Machine\Preferences\Groups\Groups.xml", 1)),
    (DefenderThreat, "defender_event", 1116, {"defender.threat.name": "ThreatA"}),
    (DefenderProtection, "defender_event", 5007,
     {"defender.new_value": _DEFENDER_KEY + "DisableAntiSpyware = 1"}),
])
def test_fleet_repeat_does_not_hide_new_host_or_content(rule, family, code, fields):
    first = event(family, code, native="first", **fields)
    repeat = event(family, code, native="repeat", offset=1, **fields)
    new_host = event(family, code, native="newhost", host="ws02", offset=2, **fields)
    instance = rule()
    records = [first, repeat, new_host]
    instance.load = lambda ids: [ev for ev in records if ev.id in ids]
    assert instance.consume([first])
    instance.drain_staged()
    instance.consume([repeat])
    instance.drain_staged()
    published = instance.consume([new_host])
    assert any(match.events[0].id == "newhost" for match in published)
    field = next(iter(fields))
    changed = {**fields, field: str(fields[field]) + " changed"}
    # Use a valid changed content shape for name-based rules.
    if rule is ToolNamedPipe:
        changed = {"pipe.name": "\\postex_12ab"}
    elif rule is AdminShareTransfer:
        changed = _share_fields(target="Temp\\another.ps1")
    elif rule is RemoteManagementPipe:
        changed = _share_fields("IPC$", "svcctl")
    elif rule is GppPolicyFileAccess:
        changed = _share_fields("SYSVOL", r"domain\Policies\id\Machine\Preferences\Services\Services.xml", 1)
    elif rule is WmiSubscription:
        changed = {**fields, "wmi.destination": "another-payload"}
    elif rule is DefenderProtection:
        changed = {"defender.new_value": _DEFENDER_KEY + "DisableAntivirus = 1"}
    content = event(family, code, native="newcontent", offset=3, **changed)
    assert instance.consume([content])


def test_normalized_real_native_shapes_feed_endpoint_rules():
    cases = [
        (SYSMON_CHANNEL, SYSMON, 20, {"Type": "Command Line", "Destination": "cmd.exe /c example"},
         WmiSubscription),
        (DEFENDER_CHANNEL, DEFENDER_PROVIDER, 5007,
         {"Old Value": _DEFENDER_KEY + "DisableAntivirus = 0", "New Value": _DEFENDER_KEY + "DisableAntivirus = 1"},
         DefenderProtection),
    ]
    for index, (channel, provider, code, data, rule) in enumerate(cases):
        fixture = LogicalWindowsEvent(channel, provider, code, "ws01.example.test", 80000 + index,
                                      "2026-01-02T03:00:00Z", data)
        ev = normalize_windows(windows_hit(fixture, "winlogbeat_8"))
        assert run(rule(), [ev])[0].proposed_lane == "high"


def test_all_rules_metadata_and_attack_ids_are_active():
    attack_path = Path(__file__).resolve().parents[1] / "content/attack/enterprise-attack-20.0.json.gz"
    with gzip.open(attack_path, "rt", encoding="utf-8") as stream:
        bundle = json.load(stream)
    active = {ref["external_id"] for obj in bundle["objects"]
              if obj.get("type") == "attack-pattern" and not obj.get("revoked") and not obj.get("x_mitre_deprecated")
              for ref in obj.get("external_references", []) if ref.get("source_name") == "mitre-attack"}
    assert len(WINDOWS_ENDPOINT_PLAYBOOKS) == 7
    for rule in WINDOWS_ENDPOINT_PLAYBOOKS:
        assert not rule.assures_negative and rule.positive_only_reason
        assert rule.attack and set(rule.attack) <= active
        assert rule.benign and rule.next_checks and rule.research and rule.windows_event_classes
        assert rule().judge(event(rule.families[0], 99999)) == []


def test_untyped_mentions_do_not_satisfy_endpoint_predicates():
    fields = {"windows.event_data.Message": "PSEXESVC svcctl Groups.xml Script payload DisableAntivirus = 1"}
    assert ToolNamedPipe().judge(event("pipe_event", 17, **fields)) == []
    for rule in (AdminShareTransfer, RemoteManagementPipe, GppPolicyFileAccess):
        assert rule().judge(event("share_access", 5145, **fields)) == []
    assert _hit(WmiSubscription, "wmi_subscription", 20, **fields).lane == "lead"
    assert _hit(DefenderProtection, "defender_event", 5007, **fields).lane == "lead"


@pytest.mark.parametrize("rule,target", [(AdminShareTransfer, "payload.exe"),
                                       (RemoteManagementPipe, "svcctl"),
                                       (GppPolicyFileAccess, r"domain\Policies\id\Machine\Preferences\Groups\Groups.xml")])
def test_failed_share_checks_never_claim_completed_activity(rule, target):
    share = {AdminShareTransfer: "ADMIN$", RemoteManagementPipe: "IPC$", GppPolicyFileAccess: "SYSVOL"}[rule]
    hit = rule().judge(event("share_access", 5145, outcome="failure", **_share_fields(share, target)))[0]
    assert "access check failed" in hit.text and hit.lane == "lead"
