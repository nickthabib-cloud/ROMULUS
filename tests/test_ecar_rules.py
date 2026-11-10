"""Synthetic CAR class discriminators; https://car.mitre.org/data_model/.

eCAR shape: https://github.com/FiveDirections/OpTC-data/blob/master/ecar.md.
Windows counterparts: https://learn.microsoft.com/sysinternals/downloads/sysmon.
"""
from base64 import b64encode

import pytest

from romulus.detect.windows_file_events import StartupFileWrite, WebRootFileWrite, WritableExecutableDeletion
from romulus.detect.windows_housekeeping import (
    ExecutionPolicyRegistry,
    HiddenFileAttribute,
    HiddenSamAccount,
    RunMruDeletion,
)
from romulus.detect.windows_image_file_rules import ClientDriveProcess, NonExecutableProcessImage
from romulus.detect.windows_memory_events import DumpLibraryLoad
from romulus.detect.windows_proxy import PowerShellEncodedOrCradle
from romulus.detect.windows_registry_events import RegistryRunKeys
from romulus.detect.windows_tunnels_w4 import LoopbackServiceConnection, PortproxyConfiguration
from romulus.evidence.ecar import normalize_ecar
from tests.test_ecar import ecar_hit


@pytest.mark.parametrize("action", ["ADD", "EDIT", "REMOVE"])
@pytest.mark.parametrize("value", [None, False, 42, [], {}])
def test_malformed_registry_value_name_does_not_imply_a_key_operation(action, value):
    event = normalize_ecar(ecar_hit("REGISTRY", action, {
        "key": r"HKLM\SAM\SAM\Domains\Account\Users\Names\hidden$", "value": value, "data": "x"}))
    assert not event.has("registry.action")
    assert not event.has("registry.event_type")
    assert any("malformed properties" in reason for reason in event.caveats)
    rule = HiddenSamAccount()
    try:
        assert not rule.judge(event)
    finally:
        rule.close_spill()


@pytest.mark.parametrize("rule,object_name,action,properties", [
    (StartupFileWrite, "FILE", "CREATE", {"file_path": r"C:\Users\person\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\start.cmd"}),
    (WebRootFileWrite, "FILE", "CREATE", {"file_path": r"C:\inetpub\wwwroot\page.aspx"}),
    (WritableExecutableDeletion, "FILE", "DELETE", {"file_path": r"C:\Users\person\AppData\Local\Temp\gone.exe"}),
    (ClientDriveProcess, "PROCESS", "CREATE", {"image_path": r"\\tsclient\c\tool.exe"}),
    (NonExecutableProcessImage, "PROCESS", "CREATE", {"image_path": r"C:\Tools\program.txt"}),
    (DumpLibraryLoad, "MODULE", "LOAD", {"module_path": r"C:\Tools\dbghelp.dll", "image_path": r"C:\Tools\client.exe"}),
    (LoopbackServiceConnection, "FLOW", "START", {"image_path": r"C:\Tools\client.exe", "dest_ip": "127.0.0.1", "dest_port": "445"}),
    (RegistryRunKeys, "REGISTRY", "ADD", {"key": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "value": "Start", "data": r"C:\Tools\start.exe", "type": "REG_SZ"}),
    (ExecutionPolicyRegistry, "REGISTRY", "EDIT", {"key": r"HKCU\Software\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell", "value": "ExecutionPolicy", "data": "Bypass"}),
    (RunMruDeletion, "REGISTRY", "REMOVE", {"key": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"}),
    (HiddenFileAttribute, "PROCESS", "CREATE", {"image_path": r"C:\Windows\System32\attrib.exe", "command_line": "attrib.exe +h C:\\Tools\\secret.txt"}),
    (PortproxyConfiguration, "REGISTRY", "EDIT", {"key": r"HKLM\SYSTEM\CurrentControlSet\Services\PortProxy\v4tov4\tcp", "value": "127.0.0.1/8443", "data": "192.0.2.20/443"}),
])
def test_semantic_gates_evaluate_ecar_without_invented_event_code(rule, object_name, action, properties):
    event = normalize_ecar(ecar_hit(object_name, action, properties))
    instance = rule()
    try:
        hits = instance.judge(event)
        assert hits
        assert not event.has("event.code")
        assert all("Sysmon recorded" not in hit.text for hit in hits)
        assert all(any(field.field == "ecar.object" for field in hit.predicate) for hit in hits)
    finally:
        instance.close_spill()


def test_create_only_rule_does_not_accept_ecar_delete():
    rule = StartupFileWrite()
    try:
        event = normalize_ecar(ecar_hit("FILE", "DELETE", {"file_path": r"C:\Users\person\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\gone.cmd"}))
        assert not rule.judge(event)
    finally:
        rule.close_spill()


def test_process_create_encoded_powershell_evaluates_native_command_line():
    payload = "Write-Output 'synthetic'"
    encoded = b64encode(payload.encode("utf-16le")).decode()
    event = normalize_ecar(ecar_hit(properties={
        "image_path": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "parent_image_path": r"C:\Windows\explorer.exe",
        "command_line": "powershell.exe -EncodedCommand " + encoded,
    }))
    rule = PowerShellEncodedOrCradle()
    try:
        hits = rule.judge(event)
        assert len(hits) == 1 and hits[0].behavior == "powershell_encoded"
        assert hits[0].lane == "lead"
        assert any(field.value == payload and field.origin.startswith("native-1:properties.command_line#parsed:")
                   for field in hits[0].predicate)
        assert not event.has("event.code")
    finally:
        rule.close_spill()
