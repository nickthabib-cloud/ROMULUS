"""Exact typed Windows observations and adversarial operand lookalikes."""
from __future__ import annotations

import importlib
import itertools

import pytest

from romulus.evidence.typed import fv
from romulus.evidence.windows import normalize_windows
from romulus.evidence.windows_catalog import (
    BITS_CHANNEL,
    BITS_PROVIDER,
    SECURITY,
    SYSMON,
    SYSMON_CHANNEL,
    WINRM_CHANNEL,
    WINRM_PROVIDER,
    lookup_event_class,
)
from tests.windows_fixtures import LogicalWindowsEvent, windows_hit
from tests.windows_process_support import run, sysmon1

IDS = itertools.count(780000)
SAM = r"HKLM\SAM\SAM\Domains\Account\Users\Names\quiet$"
RUNMRU = r"HKU\S-1-5-21-1-2-3-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
POLICY = r"HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell\ExecutionPolicy"
SHARE = r"HKLM\System\CurrentControlSet\Services\LanmanServer\Shares\staging"


def event(code, data, *, channel=SYSMON_CHANNEL, provider=SYSMON, shape="winlogbeat_8"):
    logical = LogicalWindowsEvent(channel, provider, code, "ws01.example.test", next(IDS),
                                  "2026-01-02T03:00:00Z", data)
    return normalize_windows(windows_hit(logical, shape))


def matches(name, record):
    instance = getattr(importlib.import_module("romulus.detect.windows_housekeeping"), name)()
    try:
        return run(instance, [record])
    finally:
        instance.release_state()


@pytest.mark.parametrize("code,suffix,data", [(12, "", {"EventType": "CreateKey"}),
                                                (13, r"\(Default)", {"EventType": "SetValue", "Details": "Binary Data"})])
@pytest.mark.parametrize("root", ["HKLM", "HKEY_LOCAL_MACHINE", r"\REGISTRY\MACHINE"])
def test_hidden_sam_mapping_creation_or_default_write(code, suffix, data, root):
    record = event(code, {**data, "TargetObject": root + SAM[4:] + suffix})
    [match] = matches("HiddenSamAccount", record)
    assert match.proposed_lane == "high" and "T1564.002" in " ".join(match.notes)
    assert "mapping" in match.claim.lower() and "account was created" not in match.claim.lower()


@pytest.mark.parametrize("code,path,kind", [
    (12, SAM, "DeleteKey"), (12, SAM, "RenameKey"), (12, SAM.replace("quiet$", "quiet"), "CreateKey"),
    (12, SAM + r"\extra", "CreateKey"), (12, SAM.replace("Domains", "Other"), "CreateKey"),
    (13, SAM + r"\Comment", "SetValue"), (13, SAM + r"\(Default)", "DeleteValue"),
])
def test_hidden_sam_near_matches_are_negative(code, path, kind):
    assert not matches("HiddenSamAccount", event(code, {"TargetObject": path, "EventType": kind, "Details": "x"}))


@pytest.mark.parametrize("address", ["127.0.0.1", "127.3.4.5", "::1", "::ffff:127.0.0.1"])
def test_loopback_kerberos_network_logon(address):
    record = event(4624, {"LogonType": "3", "AuthenticationPackageName": "kErBeRoS", "IpAddress": address},
                   channel="Security", provider=SECURITY)
    [match] = matches("KerberosLoopbackLogon", record)
    assert match.proposed_lane == "high" and "network logon" in match.claim.lower()


@pytest.mark.parametrize("code,kind,package,address", [
    (4624, "10", "Kerberos", "127.0.0.1"), (4625, "3", "Kerberos", "127.0.0.1"),
    (4624, "3", "NTLM", "127.0.0.1"), (4624, "3", "Kerberos", "10.0.0.1"),
])
def test_loopback_logon_requires_each_exact_field(code, kind, package, address):
    record = event(code, {"LogonType": kind, "AuthenticationPackageName": package, "IpAddress": address},
                   channel="Security", provider=SECURITY)
    assert not matches("KerberosLoopbackLogon", record)


@pytest.mark.parametrize("image", [r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                                    r"C:\Program Files\PowerShell\7\pwsh.exe", r"\??\C:\Tools\PwSh.ExE"])
def test_unexpected_powershell_server_parent_is_high(image):
    record = sysmon1(image=image, command='"' + image + '" -NoLogo -s', parent_image=r"C:\Tools\client.exe")
    [match] = matches("UnexpectedPsRemoteServer", record)
    assert match.proposed_lane == "high" and "server mode" in match.claim.lower()


@pytest.mark.parametrize("tail", ["-sta", '-Command "echo -s"', "-File script.ps1 -s",
                                  "-EncodedCommand LQBzAA==", "-NoProfile script.ps1 -s", '-ExecutionPolicy "-s"'])
def test_server_switch_is_not_an_operand_or_prefix(tail):
    assert not matches("UnexpectedPsRemoteServer", sysmon1(image="powershell.exe", command="powershell.exe " + tail,
                                                           parent_image="client.exe"))


@pytest.mark.parametrize("tail", ["-ServerMode", "-serv", "-se", "-nop -s", "-noni -s", "-nol -serv",
                                  "-noe -ServerMode", "-ex Bypass -s", "-w Hidden -s", "-inp Text -s",
                                  "-of Text -s", "-config default -s", "-wd C:\\Tools -s",
                                  "--ServerMode", "/serv", "–ServerMode"])
def test_server_mode_and_preceding_switches_use_documented_minimum_prefixes(tail):
    # ConsoleHost MatchSwitch(servermode, s), noprofile/nop, noninteractive/noni,
    # nologo/nol, and value-taking switches must keep their native token roles.
    [match] = matches("UnexpectedPsRemoteServer", sysmon1(image="pwsh.exe", command="pwsh.exe " + tail,
                                                        parent_image="client.exe"))
    assert match.proposed_lane == "high"


@pytest.mark.parametrize("tail", ["-st", "-silly", "-no -s", '-c "echo -s"', "-f script.ps1 -s",
                                  "-enc LQBzAA== -s", "-ec LQBzAA== -s", "-e LQBzAA== -s",
                                  "-cwa echo -s", "-CommandWithArgs echo -s", "-ex -s",
                                  "-w -s", "-config -s", "-Version -s", "-ea -s"])
def test_server_mode_prefixes_do_not_cross_payload_or_switch_value_boundaries(tail):
    assert not matches("UnexpectedPsRemoteServer", sysmon1(image="pwsh.exe", command="pwsh.exe " + tail,
                                                           parent_image="client.exe"))


@pytest.mark.parametrize("parent", ["wsmprovhost.exe", r"C:\Windows\System32\OpenSSH\sshd.exe"])
def test_expected_server_parents_are_not_flagged(parent):
    assert not matches("UnexpectedPsRemoteServer", sysmon1(image="pwsh.exe", command="pwsh.exe -s", parent_image=parent))


def test_missing_server_parent_is_unresolved_and_not_high():
    [match] = matches("UnexpectedPsRemoteServer", sysmon1(image="pwsh.exe", command="pwsh.exe -s"))
    assert match.proposed_lane == "lead" and "unresolved" in match.claim.lower()


@pytest.mark.parametrize("parent", ["?", "-", "(NULL)", "   ", "C:\\Tools\\bad|name.exe"])
def test_placeholder_or_malformed_server_parent_is_unresolved(parent):
    [match] = matches("UnexpectedPsRemoteServer", sysmon1(image="pwsh.exe", command="pwsh.exe -s", parent_image=parent))
    assert match.proposed_lane == "lead" and "unresolved" in match.claim.lower()


@pytest.mark.parametrize("code", [59, 60])
@pytest.mark.parametrize("url", [r"C:\Windows\cmd.exe", r"\\server\share\payload.exe", "file:///C:/Tools/payload.exe",
                                  r"\??\C:\Tools\payload.exe", r"\\?\UNC\server\share\payload.exe"])
def test_bits_local_transfer_is_high(code, url):
    record = event(code, {"Url": url, "name": "test-job"}, channel=BITS_CHANNEL, provider=BITS_PROVIDER)
    [match] = matches("BitsLocalTransfer", record)
    assert match.proposed_lane == "high" and "transfer record" in match.claim.lower()


@pytest.mark.parametrize("url", [r"C:\ stage.exe", r"\\?\Volume{01234567-0123-0123-0123-0123456789abcd}\stage.exe"])
def test_bits_native_59_local_path_spelling_is_an_observation_not_api_acceptance(url):
    record = event(59, {"url": url, "name": "test-job"}, channel=BITS_CHANNEL, provider=BITS_PROVIDER)
    [match] = matches("BitsLocalTransfer", record)
    assert match.proposed_lane == "high" and "transfer record" in match.claim.lower()
    assert "completed" not in match.claim.lower() and "executed" not in match.claim.lower()


@pytest.mark.parametrize("url", [r"Volume{01234567-0123-0123-0123-0123456789abcd}\stage.exe",
                                  r"\\?\Volume{wrong}\stage.exe", r"C: stage.exe", r"folder\stage.exe",
                                  r"\\?\relative\stage.exe", "C:\\"])
def test_bits_relative_paths_or_malformed_volume_names_do_not_become_local(url):
    record = event(59, {"url": url}, channel=BITS_CHANNEL, provider=BITS_PROVIDER)
    assert not matches("BitsLocalTransfer", record)


@pytest.mark.parametrize("url", ["https://example.test/x", "HTTP://example.test/x", "ftp://example.test/x",
                                  "gopher://example.test/x", "mystery:x", "payload.exe", "", "file:", "file://"])
def test_bits_http_unknown_schemes_or_ambiguous_paths_are_not_local(url):
    record = event(59, {"Url": url}, channel=BITS_CHANNEL, provider=BITS_PROVIDER)
    assert not matches("BitsLocalTransfer", record)


@pytest.mark.parametrize("path", [r"C:\Tools\client.exe", r"C:\Users\analyst\svchost.exe", r"\??\C:\Temp\bitsadmin.exe"])
def test_unusual_bits_creator_is_a_lead(path):
    record = event(3, {"processPath": path, "jobOwner": "EXAMPLE\\analyst", "jobTitle": "test"},
                   channel=BITS_CHANNEL, provider=BITS_PROVIDER)
    [match] = matches("BitsUnusualCreator", record)
    assert match.proposed_lane == "lead" and "creator" in match.claim.lower()
    assert "rare" not in match.claim.lower()


@pytest.mark.parametrize("name", ["svchost.exe", "bitsadmin.exe", "powershell.exe", "pwsh.exe"])
def test_typical_bits_creator_outside_writable_paths_is_negative(name):
    record = event(3, {"processPath": "C:\\Windows\\System32\\" + name}, channel=BITS_CHANNEL, provider=BITS_PROVIDER)
    assert not matches("BitsUnusualCreator", record)


def test_missing_bits_creator_is_unresolved():
    record = event(3, {"string": "job", "string2": "EXAMPLE\\analyst"}, channel=BITS_CHANNEL, provider=BITS_PROVIDER)
    [match] = matches("BitsUnusualCreator", record)
    assert match.proposed_lane == "lead" and "unresolved" in match.claim.lower()


@pytest.mark.parametrize("path", ["?", "-", "(NULL)", "   ", "C:\\Tools\\bad|name.exe"])
def test_placeholder_or_malformed_bits_creator_is_unresolved(path):
    record = event(3, {"processPath": path}, channel=BITS_CHANNEL, provider=BITS_PROVIDER)
    [match] = matches("BitsUnusualCreator", record)
    assert match.proposed_lane == "lead" and "creator image is unresolved" in match.claim.lower()


@pytest.mark.parametrize("name,path,kind,details", [
    ("RunMruDeletion", RUNMRU, "DeleteKey", None),
    ("RunMruDeletion", RUNMRU + r"\a", "DeleteValue", None),
    ("ExecutionPolicyRegistry", POLICY, "SetValue", "Unrestricted"),
    ("ExecutionPolicyRegistry", POLICY.replace("HKLM", "HKCU"), "SetValue", "Bypass"),
    ("NewServerShare", SHARE, "SetValue", "Binary Data"),
])
def test_housekeeping_registry_leads(name, path, kind, details):
    code = 12 if kind.startswith("Delete") else 13
    record = event(code, {"TargetObject": path, "EventType": kind, "Details": details})
    [match] = matches(name, record)
    assert match.proposed_lane == "lead" and match.severity == "low"


@pytest.mark.parametrize("name,path,kind,details", [
    ("RunMruDeletion", RUNMRU, "CreateKey", None),
    ("RunMruDeletion", RUNMRU + r"\child", "DeleteKey", None),
    ("RunMruDeletion", RUNMRU + "Backup", "DeleteKey", None),
    ("ExecutionPolicyRegistry", POLICY, "SetValue", "RemoteSigned"),
    ("ExecutionPolicyRegistry", POLICY, "DeleteValue", "Bypass"),
    ("ExecutionPolicyRegistry", POLICY.replace("Microsoft.PowerShell", "Other"), "SetValue", "Bypass"),
    ("ExecutionPolicyRegistry", POLICY.replace("SOFTWARE", r"Other\SOFTWARE"), "SetValue", "Bypass"),
    ("NewServerShare", SHARE, "DeleteValue", None),
    ("NewServerShare", SHARE.replace(r"\staging", r"\Security\staging"), "SetValue", "Binary Data"),
])
def test_registry_lookalikes_and_other_actions_do_not_match(name, path, kind, details):
    assert not matches(name, event(12 if kind in {"DeleteKey", "CreateKey"} else 13,
                                  {"TargetObject": path, "EventType": kind, "Details": details}))


@pytest.mark.parametrize("tail,positive", [("+h payload.exe", True), ("+H payload.exe /s", True),
    ("-h payload.exe", False), ("payload+h.exe", False), ('"file +h.txt"', False), ("+hidden file", False)])
def test_hidden_attribute_exact_argument(tail, positive):
    result = matches("HiddenFileAttribute", sysmon1(image="attrib.exe", command="attrib.exe " + tail))
    assert bool(result) is positive
    if result:
        assert result[0].proposed_lane == "lead" and result[0].severity == "low"
        assert "requested" in result[0].claim.lower()


def werfault(*, parent="svchost.exe", parent_command="svchost.exe -k LocalService -s EventLog", ppid=700,
             command="werfault.exe -u -p 700 -s 32"):
    record = sysmon1(image="werfault.exe", command=command, parent_image=parent, ppid=ppid)
    record.fields["process.parent.command_line"] = fv(parent_command, "test:ParentCommandLine")
    return record


def test_werfault_names_eventlog_parent_pid():
    [match] = matches("EventlogWerfault", werfault())
    assert match.proposed_lane == "lead" and match.severity == "low"
    assert "EventLog" in match.claim and "disabled" not in match.claim.lower()


@pytest.mark.parametrize("changes", [{"ppid": 701}, {"parent": "other.exe"},
    {"parent_command": "svchost.exe -s EventLogBackup"}, {"parent_command": 'svchost.exe -k "-s EventLog"'},
    {"command": "werfault.exe -u -p 7000 -s 32"}, {"command": 'werfault.exe -u "-p 700"'},
    {"command": "werfault.exe -p 700 -p 701"}, {"parent_command": "svchost.exe -s EventLog -s Other"}])
def test_werfault_requires_exact_service_and_pid_arguments(changes):
    assert not matches("EventlogWerfault", werfault(**changes))


def test_winrm_91_shell_start_needs_no_missing_resource_payload():
    record = event(91, {}, channel=WINRM_CHANNEL, provider=WINRM_PROVIDER)
    [match] = matches("WinrmShellStart", record)
    assert match.proposed_lane == "lead" and match.severity == "low" and "shell" in match.claim.lower()
    assert not matches("WinrmShellStart", event(6, {}, channel=WINRM_CHANNEL, provider=WINRM_PROVIDER))


def test_every_rule_declares_only_catalogued_classes_and_positive_only_coverage():
    rules = importlib.import_module("romulus.detect.windows_housekeeping").RULES
    assert len(rules) == 11 and len({rule.id for rule in rules}) == 11
    for rule in rules:
        assert rule.assures_negative is False and rule.research
        for channel, provider, code in rule.windows_event_classes:
            row = lookup_event_class(channel, provider, code)
            assert row is not None and row.family in rule.families


@pytest.mark.parametrize("shape", ["winlogbeat_7", "winlogbeat_8", "elastic_agent"])
@pytest.mark.parametrize("name,code,data,channel,provider", [
    ("HiddenSamAccount", 12, {"TargetObject": SAM, "EventType": "CreateKey"}, SYSMON_CHANNEL, SYSMON),
    ("KerberosLoopbackLogon", 4624, {"LogonType": "3", "AuthenticationPackageName": "Kerberos", "IpAddress": "::1"},
     "Security", SECURITY),
    ("UnexpectedPsRemoteServer", 1, {"Image": "pwsh.exe", "CommandLine": "pwsh.exe -s", "ParentImage": "client.exe"},
     SYSMON_CHANNEL, SYSMON),
    ("BitsLocalTransfer", 59, {"Url": r"C:\Tools\payload.exe"}, BITS_CHANNEL, BITS_PROVIDER),
    ("BitsUnusualCreator", 3, {"processPath": r"C:\Tools\client.exe"}, BITS_CHANNEL, BITS_PROVIDER),
    ("RunMruDeletion", 12, {"TargetObject": RUNMRU, "EventType": "DeleteKey"}, SYSMON_CHANNEL, SYSMON),
    ("HiddenFileAttribute", 1, {"Image": "attrib.exe", "CommandLine": "attrib.exe +h file.txt"}, SYSMON_CHANNEL, SYSMON),
    ("ExecutionPolicyRegistry", 13, {"TargetObject": POLICY, "Details": "Bypass", "EventType": "SetValue"},
     SYSMON_CHANNEL, SYSMON),
    ("NewServerShare", 13, {"TargetObject": SHARE, "Details": "Binary Data", "EventType": "SetValue"},
     SYSMON_CHANNEL, SYSMON),
    ("EventlogWerfault", 1, {"Image": "werfault.exe", "CommandLine": "werfault.exe -p 700", "ParentImage": "svchost.exe",
                           "ParentProcessId": "700", "ParentCommandLine": "svchost.exe -s EventLog"}, SYSMON_CHANNEL, SYSMON),
    ("WinrmShellStart", 91, {}, WINRM_CHANNEL, WINRM_PROVIDER),
])
def test_each_rule_works_in_all_supported_windows_shapes_and_requires_the_exact_class(shape, name, code, data, channel, provider):
    record = event(code, data, channel=channel, provider=provider, shape=shape)
    assert len(matches(name, record)) == 1
    for field, wrong in (("event.provider", "Other-Provider"), ("event.channel", "Other-Channel"), ("event.code", 99999)):
        wrong_record = record.model_copy(update={"fields": {**record.fields, field: fv(wrong, "test:class")}})
        assert not matches(name, wrong_record)


@pytest.mark.parametrize("field", ["auth.logon_type", "auth.package", "source.ip"])
def test_missing_loopback_logon_fields_leave_unresolved_coverage(field):
    record = event(4624, {"LogonType": "3", "AuthenticationPackageName": "Kerberos", "IpAddress": "::1"},
                   channel="Security", provider=SECURITY)
    record.fields.pop(field)
    instance = importlib.import_module("romulus.detect.windows_housekeeping").KerberosLoopbackLogon()
    try:
        assert not run(instance, [record])
        assert instance.missing_required == 1
    finally:
        instance.release_state()


def test_repeated_housekeeping_records_fold_with_bounded_citations():
    instance = importlib.import_module("romulus.detect.windows_housekeeping").HiddenFileAttribute()
    records = [sysmon1(image="attrib.exe", command="attrib.exe +h file.txt", offset=index) for index in range(1000)]
    try:
        result = run(instance, [records[index:index + 100] for index in range(0, 1000, 100)])
        # The shared Windows fold retains the first observation plus one fleet tally.
        assert len(result) == 2
        [match] = [item for item in result if item.group_key]
        assert match.proposed_lane == "lead" and match.severity == "low"
        assert "1000 Windows event record(s)" in match.claim
        assert len(match.events) <= 16 and len(instance.groups) <= 1
    finally:
        instance.release_state()
