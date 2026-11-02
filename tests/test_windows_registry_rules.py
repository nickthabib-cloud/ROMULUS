"""Exact registry key/value semantics, action wording and immediate publication."""
import gzip
import json
from pathlib import Path

import pytest

from romulus.detect.windows_registry_events import (
    WINDOWS_REGISTRY_PLAYBOOKS,
    RegistryAppCert,
    RegistryAppInit,
    RegistryCredentialProtection,
    RegistryDefender,
    RegistryImageExecution,
    RegistryLsaPackages,
    RegistryRdp,
    RegistryRunKeys,
    RegistryServiceCommand,
    RegistryUserCom,
    RegistryWinlogon,
)
from romulus.evidence.windows import normalize_windows, registry_path_key
from romulus.evidence.windows_catalog import SECURITY, SYSMON, SYSMON_CHANNEL
from tests.windows_event_support import event, run
from tests.windows_fixtures import LogicalWindowsEvent, windows_hit

LM = "HKLM\\"
SOFT = LM + r"Software\Microsoft\Windows NT\CurrentVersion" + "\\"
SYSTEM = LM + r"System\CurrentControlSet" + "\\"
CLSID = r"HKCU\Software\Classes\CLSID\{11111111-2222-3333-4444-555555555555}"
DEFENDER = LM + r"Software\Policies\Microsoft\Windows Defender"


def change(key, name, value=r"C:\ProgramData\unfamiliar.dll", *, code=13, **fields):
    numeric_names = {"globalflag", "reportingmode", "loadappinit_dlls", "uselogoncredential",
                     "runasppl", "fdenytsconnections"}
    if (name.casefold() in numeric_names or name.casefold().startswith("disable")
            or "\\exclusions\\" in key.casefold()):
        fields = {"registry.value_type": "REG_DWORD", **fields}
    fields = {"registry.action": "value_set", "registry.value": value, **fields}
    path = key if code == 4657 else key + "\\" + name
    if code == 4657:
        fields["registry.value_name"] = name
    return event("registry_change", code, **{"registry.path_key": registry_path_key(path), **fields})


# Every supported value shape is exercised in both native representations.
CASES = [
    (RegistryRunKeys, r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "UnknownVendor", "payload.exe", "lead"),
    (RegistryRunKeys, r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce", "Update", "payload.exe", "lead"),
    (RegistryRunKeys, r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnceEx", "Title", "installer", "lead"),
    (RegistryRunKeys, r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnceEx\0001", "1", "payload.exe", "lead"),
    (RegistryRunKeys, r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnceEx\0001\Depend", "1", "payload.dll", "lead"),
    (RegistryRunKeys, r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnceEx\NamedSection", "Run", "payload.exe", "lead"),
    (RegistryRunKeys, r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnceEx\NamedSection\Depend", "DLL", "payload.dll", "lead"),
    (RegistryWinlogon, SOFT + "Winlogon", "Shell", "explorer.exe,payload.exe", "high"),
    (RegistryWinlogon, SOFT + "Winlogon", "Userinit", "userinit.exe,payload.exe", "high"),
    (RegistryWinlogon, SOFT + r"Winlogon\Notify\Vendor", "DLLName", "payload.dll", "high"),
    (RegistryImageExecution, SOFT + r"Image File Execution Options\app.exe", "Debugger", "anything.exe", "high"),
    (RegistryImageExecution, SOFT + r"Image File Execution Options\app.exe\filter", "Debugger", "anything.exe", "high"),
    (RegistryImageExecution, SOFT + r"Image File Execution Options\app.exe", "GlobalFlag", "DWORD (0x00000200)", "lead"),
    (RegistryImageExecution, SOFT + r"SilentProcessExit\app.exe", "MonitorProcess", "anything.exe", "high"),
    (RegistryImageExecution, SOFT + r"SilentProcessExit\app.exe", "ReportingMode", "0x3", "lead"),
    (RegistryAppInit, SOFT + "Windows", "AppInit_DLLs", "unknown.dll", "high"),
    (RegistryAppInit, SOFT + "Windows", "LoadAppInit_DLLs", "DWORD (0x00000001)", "lead"),
    (RegistryAppCert, SYSTEM + r"Control\Session Manager\AppCertDlls", "anything", "unknown.dll", "high"),
    (RegistryUserCom, CLSID + r"\InprocServer32", "(Default)", "unknown.dll", "lead"),
    (RegistryUserCom, CLSID + r"\LocalServer32", "", "unknown.exe /start", "lead"),
    (RegistryLsaPackages, SYSTEM + r"Control\Lsa", "Authentication Packages", "unknown", "high"),
    (RegistryLsaPackages, SYSTEM + r"Control\Lsa", "Security Packages", ["kerberos", "unknown"], "high"),
    (RegistryLsaPackages, SYSTEM + r"Control\Lsa", "Notification Packages", "unknown", "high"),
    (RegistryLsaPackages, SYSTEM + r"Control\Lsa\OSConfig", "Security Packages", "unknown", "high"),
    (RegistryCredentialProtection, SYSTEM + r"Control\SecurityProviders\WDigest", "UseLogonCredential", "1", "high"),
    (RegistryCredentialProtection, SYSTEM + r"Control\Lsa", "RunAsPPL", "0x00000000", "high"),
    (RegistryDefender, DEFENDER, "DisableAntiSpyware", "1", "high"),
    (RegistryDefender, DEFENDER, "DisableAntiVirus", "1", "high"),
    (RegistryDefender, DEFENDER + r"\Real-Time Protection", "DisableRealtimeMonitoring", "1", "high"),
    (RegistryDefender, DEFENDER + r"\Real-Time Protection", "DisableBehaviorMonitoring", "1", "high"),
    (RegistryDefender, DEFENDER + r"\Real-Time Protection", "DisableOnAccessProtection", "1", "high"),
    (RegistryDefender, DEFENDER + r"\Real-Time Protection", "DisableScanOnRealtimeEnable", "1", "high"),
    (RegistryDefender, DEFENDER + r"\Real-Time Protection", "DisableIOAVProtection", "1", "high"),
    (RegistryDefender, DEFENDER + r"\Real-Time Protection", "DisableScriptScanning", "1", "high"),
    (RegistryDefender, DEFENDER + r"\SpyNet", "DisableBlockAtFirstSeen", "1", "high"),
    (RegistryDefender, DEFENDER + r"\Exclusions\Paths", r"C:\Temp\payload", "0", "high"),
    (RegistryDefender, DEFENDER + r"\Exclusions\Processes", "arbitrary.exe", "0", "high"),
    (RegistryDefender, DEFENDER + r"\Exclusions\Extensions", ".xyz", "0", "high"),
    (RegistryDefender, DEFENDER + r"\Exclusions\IpAddresses", "192.0.2.3", "0", "high"),
    (RegistryRdp, SYSTEM + r"Control\Terminal Server", "fDenyTSConnections", "0", "lead"),
    (RegistryServiceCommand, SYSTEM + r"Services\Unknown", "ImagePath", "unknown.exe", "lead"),
    (RegistryServiceCommand, SYSTEM + r"Services\Unknown", "FailureCommand", "unknown.exe /run", "lead"),
]


@pytest.mark.parametrize("code", [13, 4657])
@pytest.mark.parametrize("rule,key,name,value,lane", CASES)
def test_each_subshape_uses_exact_native_value_representation(rule, key, name, value, lane, code):
    ev = change(key, name, value, code=code, **{"process.executable_key": r"c:\windows\trusted.exe"})
    matches = run(rule(), [ev])
    assert len(matches) == 1
    assert matches[0].proposed_lane == lane
    assert "written" in matches[0].claim
    assert any(field.field == "registry.path_key" for field in matches[0].predicate)
    assert "executed" not in matches[0].claim


@pytest.mark.parametrize("rule,key,name,value,lane", CASES)
@pytest.mark.parametrize("malformed", [None, {"opaque": "payload"}, True])
def test_missing_or_malformed_data_is_explicit_uncertainty(rule, key, name, value, lane, malformed):
    matches = run(rule(), [change(key, name, malformed)])
    assert len(matches) == 1
    assert matches[0].proposed_lane == "lead"
    assert "unknown" in matches[0].claim


@pytest.mark.parametrize("rule,key,name,value,lane", CASES)
def test_truncation_preserves_recorded_winlogon_signal_without_asserting_complete_payload(rule, key, name, value, lane):
    matches = run(rule(), [change(key, name, value, **{"registry.details_truncated": True})])
    assert len(matches) == 1 and matches[0].proposed_lane == ("high" if rule is RegistryWinlogon else "lead")
    assert "truncated" in matches[0].claim


@pytest.mark.parametrize("rule,key,name,value,lane", CASES)
def test_path_component_substring_traps(rule, key, name, value, lane):
    # Inserting a plausible-looking parent must not match an anchored key grammar.
    bad = key.replace("\\Software\\", "\\Software\\Backup\\").replace("\\System\\", "\\System\\Backup\\")
    assert not run(rule(), [change(bad, name, value)])


@pytest.mark.parametrize("rule,key,name,value,lane", CASES)
@pytest.mark.parametrize("code,extra,verb", [
    (12, {"registry.event_type": "DeleteValue"}, "deleted"),
    (4657, {"registry.operation_type": "registry_value_deleted"}, "deleted"),
    (14, {"registry.action": "object_renamed", "registry.new_path": r"HKLM\Unrelated"}, "renamed"),
])
def test_deletion_and_rename_claim_only_the_change(rule, key, name, value, lane, code, extra, verb):
    matches = run(rule(), [change(key, name, value, code=code, **extra)])
    assert len(matches) == 1 and matches[0].proposed_lane == "lead"
    assert verb in matches[0].claim and "unknown" in matches[0].claim
    assert "install" not in matches[0].claim and "was written" not in matches[0].claim


NUMERIC = [(rule, key, name, value) for rule, key, name, value, _ in CASES
           if name.casefold() in {"uselogoncredential", "runasppl", "fdenytsconnections", "loadappinit_dlls",
                                  "globalflag", "reportingmode"} or rule is RegistryDefender]


@pytest.mark.parametrize("rule,key,name,value", NUMERIC)
@pytest.mark.parametrize("bad", ["DWORD (?)", "junk", "-1", "0x100000000", "0x1 trailing", ""])
def test_numeric_garbage_is_a_lead_with_unknown_effect(rule, key, name, value, bad):
    if rule is RegistryDefender and "Exclusions" in key and bad == "":
        assert not run(rule(), [change(key, name, bad)])
        return
    matches = run(rule(), [change(key, name, bad)])
    assert len(matches) == 1 and matches[0].proposed_lane == "lead"
    assert "unknown" in matches[0].claim


@pytest.mark.parametrize("rule,key,name,value", NUMERIC)
def test_safe_numeric_value_never_claims_unsafe_configuration(rule, key, name, value):
    if rule is RegistryDefender and "Exclusions" in key:
        # A numeric write other than the documented enabled value does not prove removal.
        matches = run(rule(), [change(key, name, "1")])
        assert len(matches) == 1 and matches[0].proposed_lane == "lead" and "unknown" in matches[0].claim
        return
    safe = "DWORD (0x00000001)" if name.casefold() in {"runasppl", "fdenytsconnections"} else "0x00000000"
    assert not run(rule(), [change(key, name, safe)])


@pytest.mark.parametrize("name,value", [
    ("Shell", "explorer.exe"), ("Shell", r"C:\Windows\explorer.exe"),
    ("Shell", r"%SystemRoot%\explorer.exe"), ("Shell", '"explorer.exe"'),
    ("Userinit", r"C:\Windows\System32\userinit.exe,"), ("Userinit", "userinit.exe"),
])
def test_only_exact_default_winlogon_grammar_is_safe(name, value):
    assert not run(RegistryWinlogon(), [change(SOFT + "Winlogon", name, value)])
    for bad in [value + ",attacker.exe", value + " attacker.exe", "C:\\Temp\\" + value]:
        matches = run(RegistryWinlogon(), [change(SOFT + "Winlogon", name, bad)])
        assert len(matches) == 1 and matches[0].proposed_lane == "high"


@pytest.mark.parametrize("root", [r"D:\Windows", r"Z:\Windows", r"\\?\D:\Windows", r"\??\D:\Windows",
                                  r"\Device\HarddiskVolume3\Windows", r"\SystemRoot", "%WinDir%",
                                  "%SystemRoot%", r"%SystemDrive%\Windows",
                                  r"\\?\Volume{11111111-2222-3333-4444-555555555555}\Windows"])
@pytest.mark.parametrize("name,tail", [("Shell", r"\explorer.exe"), ("Userinit", r"\System32\userinit.exe")])
def test_default_winlogon_on_each_system_volume_grammar(root, name, tail):
    value = root + tail
    for safe in [value, '"' + value + '"', value + "," if name == "Userinit" else value]:
        assert not run(RegistryWinlogon(), [change(SOFT + "Winlogon", name, safe)])
        for bad in [safe + " /extra", safe + ",payload.exe", safe + "&payload.exe"]:
            matches = run(RegistryWinlogon(), [change(SOFT + "Winlogon", name, bad)])
            assert len(matches) == 1 and matches[0].proposed_lane == "high"


@pytest.mark.parametrize("value", [r"D:\Untrusted\explorer.exe", r"D:\WindowsBackup\explorer.exe",
                                   r"\\server\Windows\explorer.exe", r"D:\Windows\Subdir\explorer.exe",
                                   r"\Device\UnknownVolume\Windows\explorer.exe"])
def test_familiar_basename_cannot_make_arbitrary_winlogon_path_safe(value):
    matches = run(RegistryWinlogon(), [change(SOFT + "Winlogon", "Shell", value)])
    assert len(matches) == 1 and matches[0].proposed_lane == "high"


@pytest.mark.parametrize("event_type", ["NotDeleteValue", "DeleteValueBackup", "RenameValueExtra", "UndeleteKey"])
def test_event_type_substrings_cannot_relabel_a_recorded_write(event_type):
    matches = run(RegistryCredentialProtection(), [change(SYSTEM + r"Control\Lsa", "RunAsPPL", "0",
                                                        **{"registry.event_type": event_type})])
    assert len(matches) == 1 and matches[0].proposed_lane == "high"
    assert "was written" in matches[0].claim and "deleted" not in matches[0].claim


@pytest.mark.parametrize("event_type,verb", [("CreateKey", "changed"), ("DeleteKey", "deleted"), ("RenameKey", "renamed")])
def test_key_event_enums_preserve_whole_key_path(event_type, verb):
    ev = event("registry_change", 14 if event_type == "RenameKey" else 12,
               **{"registry.path_key": registry_path_key(r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnceEx"),
                  "registry.event_type": event_type, "registry.action": "object"})
    matches = run(RegistryRunKeys(), [ev])
    assert len(matches) == 1 and matches[0].proposed_lane == "lead" and verb in matches[0].claim


@pytest.mark.parametrize("rule,key,name", [
    (RegistryRunKeys, r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunBackup", "v"),
    (RegistryRunKeys, r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnceExBackup\0001\Depend", "1"),
    (RegistryRunKeys, r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnceEx\0001\DependBackup", "1"),
    (RegistryRunKeys, r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnceEx\0001\Depend\Nested", "1"),
    (RegistryWinlogon, SOFT + "Winlogon", "ShellBackup"),
    (RegistryImageExecution, SOFT + r"Image File Execution Options\a.exe", "DebuggerBackup"),
    (RegistryImageExecution, SOFT + r"SilentProcessExit\a.exe", "MonitorProcessBackup"),
    (RegistryAppInit, SOFT + "Windows", "AppInit_DLLsBackup"),
    (RegistryAppInit, SOFT + "Windows", "LoadAppInit_DLLsBackup"),
    (RegistryAppCert, SYSTEM + r"Control\Session Manager\AppCertDllsBackup", "v"),
    (RegistryUserCom, CLSID + r"\InprocServer32", "ThreadingModel"),
    (RegistryUserCom, CLSID.replace("11111111", "notaguid") + r"\LocalServer32", ""),
    (RegistryUserCom, CLSID.replace("HKCU", "HKLM") + r"\LocalServer32", ""),
    (RegistryLsaPackages, SYSTEM + r"Control\Lsa", "Security PackagesBackup"),
    (RegistryCredentialProtection, SYSTEM + r"Control\Lsa", "RunAsPPLBackup"),
    (RegistryCredentialProtection, SYSTEM + r"Control\SecurityProviders\WDigest", "UseLogonCredentialBackup"),
    (RegistryRdp, SYSTEM + r"Control\Terminal Server", "fDenyTSConnectionsBackup"),
    (RegistryServiceCommand, SYSTEM + r"Services\x\Parameters", "ImagePath"),
    (RegistryServiceCommand, SYSTEM + r"Services\x", "FailureCommandBackup"),
])
def test_similar_keys_or_unrelated_value_names_are_not_targets(rule, key, name):
    assert not run(rule(), [change(key, name)])


@pytest.mark.parametrize("root", ["HKCU", r"HKU\S-1-5-21-1-2-3-1001", r"\Registry\User\S-1-5-21-1-2-3-1001"])
def test_per_user_native_hive_forms(root):
    matches = run(RegistryUserCom(), [change(CLSID.replace("HKCU", root) + r"\InprocServer32", "(Default)")])
    assert len(matches) == 1 and matches[0].proposed_lane == "lead"


@pytest.mark.parametrize("control", ["CurrentControlSet", "ControlSet001", "ControlSet009"])
@pytest.mark.parametrize("root", ["HKLM", "HKEY_LOCAL_MACHINE", r"\Registry\Machine"])
def test_native_hive_and_control_set_aliases(control, root):
    key = SYSTEM.replace("HKLM", root).replace("CurrentControlSet", control) + r"Control\Lsa"
    assert len(run(RegistryCredentialProtection(), [change(key, "RunAsPPL", 0)])) == 1


def test_wow6432node_and_case_are_compared_without_losing_recorded_identity():
    key = SOFT.replace("Software", r"SOFTWARE\Wow6432Node") + r"Image File Execution Options\App.EXE"
    matches = run(RegistryImageExecution(), [change(key, "DeBuGgEr")])
    assert len(matches) == 1
    assert "wow6432node" in next(p.value for p in matches[0].predicate if p.field == "registry.path_key")


@pytest.mark.parametrize("rule,key,name,value,lane", CASES)
def test_wrong_os_and_wrong_family_do_not_match(rule, key, name, value, lane):
    assert not run(rule(), [change(key, name, value, **{"host.os.family": "linux"})])
    ev = change(key, name, value)
    ev.family = "process_exec"
    assert not run(rule(), [ev])


@pytest.mark.parametrize("rule", WINDOWS_REGISTRY_PLAYBOOKS)
def test_each_new_host_and_payload_publishes_during_consume(rule):
    _, key, name, value, _ = next(case for case in CASES if case[0] is rule)
    first = change(key, name, value, host="first", native="first")
    second = change(key, name, value, host="second", native="second")
    # A genuinely new payload is separate even on an already represented host.
    third = change(key, name, value, host="first", native="third", **{"registry.details_truncated": True})
    instance = rule()
    for ev in [first, second, third]:
        matches = instance.consume([ev])
        assert matches and any(ev.id in {item.id for item in match.events} for match in matches)


@pytest.mark.parametrize("code", [13, 4657])
def test_real_normalizer_targetobject_vs_objectvaluename(code):
    key = r"\REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\Lsa"
    data = ({"TargetObject": key + r"\RunAsPPL", "Details": "DWORD (0x00000000)"} if code == 13 else
            {"ObjectName": key, "ObjectValueName": "RunAsPPL", "NewValue": "0", "NewValueType": "REG_DWORD",
             "OperationType": "%%1905"})
    logical = LogicalWindowsEvent(SYSMON_CHANNEL if code == 13 else "Security", SYSMON if code == 13 else SECURITY,
                                  code, "ws01", 12345, "2026-01-02T03:00:00Z", data)
    ev = normalize_windows(windows_hit(logical, "elastic_agent"))
    matches = run(RegistryCredentialProtection(), [ev])
    assert len(matches) == 1 and matches[0].proposed_lane == "high"


@pytest.mark.parametrize("value_type", ["REG_SZ", "%%1873", "REG_EXPAND_SZ", "REG_QWORD", "%%1883", "REG_BINARY",
                                       "REG_DWORD_BIG_ENDIAN", "%%18760", "x%%1876", "REG_DWORDextra", "1876", "4",
                                       "0x4", "unknown", "", None, True, 1, 8, {"type": "REG_DWORD"}])
@pytest.mark.parametrize("value", ["0", "1", "DWORD (0x00000000)", 0])
def test_wrong_or_unknown_recorded_type_never_assigns_numeric_effect(value_type, value):
    matches = run(RegistryCredentialProtection(), [change(SYSTEM + r"Control\Lsa", "RunAsPPL", value,
                                                        **{"registry.value_type": value_type})])
    assert len(matches) == 1 and matches[0].proposed_lane == "lead"
    assert "unknown" in matches[0].claim and "supported DWORD type" in matches[0].claim


@pytest.mark.parametrize("rule,key,name,value", NUMERIC)
def test_every_numeric_subshape_honors_recorded_string_type(rule, key, name, value):
    matches = run(rule(), [change(key, name, value, **{"registry.value_type": "REG_SZ"})])
    assert len(matches) == 1 and matches[0].proposed_lane == "lead" and "unknown" in matches[0].claim


@pytest.mark.parametrize("value_type", ["REG_DWORD", "reg_dword", "REG_DWORD_LITTLE_ENDIAN", "Dword", "%%1876", 4])
@pytest.mark.parametrize("value,lane", [("0", "high"), ("0x00000000", "high"), (0, "high"), ("1", None), ("2", None)])
def test_exact_supported_dword_aliases_preserve_unsafe_and_safe_semantics(value_type, value, lane):
    matches = run(RegistryCredentialProtection(), [change(SYSTEM + r"Control\Lsa", "RunAsPPL", value,
                                                        **{"registry.value_type": value_type})])
    if lane is None:
        assert not matches
    else:
        assert len(matches) == 1 and matches[0].proposed_lane == lane


@pytest.mark.parametrize("code,value,lane", [(13, "DWORD (0x00000000)", "high"),
                                           (13, "DWORD (0x00000001)", None), (13, 0, "high"),
                                           (13, "0", "lead"), (13, "0x0", "lead"), (13, "DWORD (0)", "lead"),
                                           (4657, "DWORD (0x00000000)", "lead"), (4657, "0", "lead"),
                                           (4657, 0, "high")])
def test_absent_type_requires_native_integer_or_exact_sysmon_dword_grammar(code, value, lane):
    ev = change(SYSTEM + r"Control\Lsa", "RunAsPPL", value, code=code)
    ev.fields.pop("registry.value_type", None)
    matches = run(RegistryCredentialProtection(), [ev])
    if lane is None:
        assert not matches
    else:
        assert len(matches) == 1 and matches[0].proposed_lane == lane
        if lane == "lead":
            assert "unknown" in matches[0].claim


@pytest.mark.parametrize("value_type,lane", [("REG_SZ", "lead"), ("%%1873", "lead"), ("REG_DWORD", "high"),
                                           ("%%1876", "high"), ("%%18760", "lead")])
def test_native_4657_value_type_is_preserved_and_controls_numeric_judgment(value_type, lane):
    data = {"ObjectName": r"\REGISTRY\MACHINE\SYSTEM\CurrentControlSet\Control\Lsa",
            "ObjectValueName": "RunAsPPL", "NewValue": "0", "NewValueType": value_type,
            "OperationType": "%%1905"}
    logical = LogicalWindowsEvent("Security", SECURITY, 4657, "ws01", 98765, "2026-01-02T03:00:00Z", data)
    ev = normalize_windows(windows_hit(logical, "elastic_agent"))
    assert ev.get("registry.value_type") == value_type
    matches = run(RegistryCredentialProtection(), [ev])
    assert len(matches) == 1 and matches[0].proposed_lane == lane
    if lane == "lead":
        assert "unknown" in matches[0].claim


def test_defender_unknown_policy_is_only_an_explicit_impact_unknown_lead():
    matches = run(RegistryDefender(), [change(DEFENDER, "FuturePolicy", "anything")])
    assert len(matches) == 1 and matches[0].proposed_lane == "lead"
    assert "unknown" in matches[0].claim
    assert not run(RegistryDefender(), [change(DEFENDER + "Backup", "DisableAntiVirus", "1")])


@pytest.mark.parametrize("key,name", [(DEFENDER + r"\SpyNet", "DisableSBlockAtFirstSeen"),
                                     (DEFENDER + r"\Real-Time Protection", "DisableScriptScanningBackup")])
def test_misspelled_defender_setting_is_only_generic_impact_unknown_lead(key, name):
    matches = run(RegistryDefender(), [change(key, name, "1", **{"registry.value_type": "REG_DWORD"})])
    assert len(matches) == 1 and matches[0].proposed_lane == "lead"
    assert "effective protection impact unknown" in matches[0].claim
    assert "disablement request" not in matches[0].claim


@pytest.mark.parametrize("rule,key,name,value,lane", CASES)
def test_malformed_multi_string_cannot_claim_a_payload(rule, key, name, value, lane):
    matches = run(rule(), [change(key, name, ["payload", {"unparsed": 1}])])
    assert len(matches) == 1 and matches[0].proposed_lane == "lead"
    assert "unknown" in matches[0].claim


def test_two_distinct_payloads_on_same_host_publish_immediately():
    instance = RegistryServiceCommand()
    for index, payload in enumerate(["first.exe", "second.exe"]):
        matches = instance.consume([change(SYSTEM + r"Services\Name", "ImagePath", payload, native=f"p-{index}")])
        assert matches and any(payload in match.claim for match in matches)


@pytest.mark.parametrize("value", ["2", "0x7fffffff"])
def test_semantically_unknown_dword_is_not_dropped(value):
    matches = run(RegistryCredentialProtection(), [change(SYSTEM + r"Control\SecurityProviders\WDigest",
                                                       "UseLogonCredential", value)])
    assert len(matches) == 1 and matches[0].proposed_lane == "lead" and "unknown" in matches[0].claim


def test_ppl_mode_two_is_safe_and_cleared_exclusions_never_claim_disable():
    assert not run(RegistryCredentialProtection(), [change(SYSTEM + r"Control\Lsa", "RunAsPPL", "2")])
    assert not run(RegistryDefender(), [change(DEFENDER + r"\Exclusions\Paths", "anything", "")])
    matches = run(RegistryDefender(), [change(DEFENDER + r"\Exclusions\Paths", "anything", "", code=12,
                                            **{"registry.event_type": "DeleteValue"})])
    assert len(matches) == 1 and matches[0].proposed_lane == "lead" and "deleted" in matches[0].claim


@pytest.mark.parametrize("path", [None, "", "hkey_local_machine", "hkey_current_user", "hkey_users", "hkey_users\\invalid"])
def test_incomplete_target_never_crashes_any_registry_rule(path):
    for rule in WINDOWS_REGISTRY_PLAYBOOKS:
        assert not run(rule(), [event("registry_change", 13, **{"registry.path_key": path})])


def test_metadata_is_positive_only_and_uses_active_vendored_techniques():
    path = Path(__file__).resolve().parents[1] / "content/attack/enterprise-attack-20.0.json.gz"
    with gzip.open(path, "rt", encoding="utf-8") as stream:
        objects = json.load(stream)["objects"]
    active = {ref["external_id"] for obj in objects if obj.get("type") == "attack-pattern"
              and not obj.get("revoked") and not obj.get("x_mitre_deprecated")
              for ref in obj.get("external_references", []) if "external_id" in ref}
    for rule in WINDOWS_REGISTRY_PLAYBOOKS:
        assert rule.families == ("registry_change",)
        assert rule.assures_negative is False and rule.positive_only_reason
        assert set(rule.attack) <= active
        assert rule.benign and rule.next_checks and all(url.startswith("https://") for url in rule.research)
