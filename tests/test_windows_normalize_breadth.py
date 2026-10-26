"""Focused contracts for broad Windows normalizer coverage."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from romulus.evidence.normalize import normalize_hits
from romulus.evidence.windows import SCRIPT_BLOCK_MAX_PARTS, normalize_windows, registry_path_key
from romulus.evidence.windows_catalog import SECURITY, SYSMON

NOW = datetime(2026, 10, 26, 16, 0, tzinfo=UTC).isoformat()
SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"


def _hit(
    event_id: int,
    data: dict[str, object],
    *,
    channel: str = "Security",
    provider: str = SECURITY,
    record_id: int = 1,
) -> dict:
    return {
        "_index": "windows-test",
        "_id": f"{provider}-{event_id}-{record_id}",
        "_source": {
            "@timestamp": NOW,
            "agent": {"type": "winlogbeat"},
            "winlog": {
                "channel": channel,
                "provider_name": provider,
                "event_id": event_id,
                "computer_name": "WS01.example.test",
                "record_id": record_id,
                "time_created": NOW,
                "event_data": data,
            },
        },
    }


def test_existing_auth_and_process_fields_are_additive_and_codes_are_typed():
    event = normalize_windows(_hit(4624, {
        "TargetUserSid": "S-1-5-21-1-2-3-1100",
        "TargetUserName": "analyst",
        "TargetDomainName": "EXAMPLE",
        "TargetLogonId": "0x45",
        "LogonType": "10",
        "LogonProcessName": "User32",
        "AuthenticationPackageName": "Negotiate",
        "LmPackageName": "NTLM V2",
        "KeyLength": "128",
        "WorkstationName": "ADMIN01",
        "ElevatedToken": "%%1842",
        "ImpersonationLevel": "%%1833",
        "RestrictedAdminMode": "%%1843",
        "VirtualAccount": "%%1843",
        "TargetOutboundUserName": "svc-backup",
        "TargetOutboundDomainName": "EXAMPLE",
        "ProcessName": r"C:\Windows\System32\winlogon.exe",
        "ProcessId": "0x44c",
    }))

    assert event.get("auth.logon_process") == "User32"
    assert event.get("auth.package") == "Negotiate"
    assert event.get("auth.lm_package") == "NTLM V2"
    assert event.get("auth.key_length") == 128
    assert event.get("source.hostname") == "admin01"
    assert event.get("auth.elevated_token") is True
    assert event.get("auth.impersonation_level") == "impersonation"
    assert event.get("auth.restricted_admin_mode") is False
    assert event.get("auth.virtual_account") is False
    assert event.get("auth.outbound_user") == "svc-backup"
    assert event.get("auth.outbound_domain") == "example"
    assert event.get("process.pid") == 1100
    assert event.get("process.executable_key") == r"c:\windows\system32\winlogon.exe"


@pytest.mark.parametrize(("prefix", "preserved_prefix"), [
    ("\\\\?\\", "\\\\?\\"),
    ("\\??\\", "\\??\\"),
])
def test_batch_normalization_preserves_recorded_process_prefixes_and_adds_canonical_aliases(
    prefix, preserved_prefix,
):
    hit = _hit(
        1,
        {
            "ProcessId": "123",
            "ProcessGuid": "{11111111-2222-3333-4444-555555555555}",
            "Image": prefix + r"C:\Windows\System32\cmd.exe",
            "ParentImage": prefix + r"C:\Windows\explorer.exe",
        },
        channel=SYSMON_CHANNEL,
        provider=SYSMON,
    )

    events, skips, errors = normalize_hits([hit])

    assert skips == {}
    assert errors == []
    assert events[0].get("process.executable_key") == preserved_prefix + r"c:\windows\system32\cmd.exe"
    assert events[0].get("process.parent.executable_key") == preserved_prefix + r"c:\windows\explorer.exe"
    assert events[0].get("process.executable_canonical_key") == r"c:\windows\system32\cmd.exe"
    assert events[0].get("process.parent.executable_canonical_key") == r"c:\windows\explorer.exe"


def test_malformed_optional_numeric_field_drops_only_that_field_with_a_reason():
    event = normalize_windows(_hit(4625, {
        "TargetUserName": "analyst",
        "LogonType": "not-a-number",
        "Status": "0xc000006d",
        "SubStatus": "0xc000006a",
        "FailureReason": "%%2313",
        "IpAddress": "::ffff:192.0.2.25",
    }))

    assert event.family == "auth"
    assert not event.has("auth.logon_type")
    assert event.get("source.ip") == "192.0.2.25"
    assert event.get("auth.status") == 0xC000006D
    assert event.get("auth.failure_reason") == "unknown_user_name_or_bad_password"
    assert any("LogonType is malformed" in reason for reason in event.caveats)


def test_placeholders_access_codes_and_dual_process_sessions_are_typed_without_guesses():
    process = normalize_windows(_hit(4688, {
        "SubjectUserSid": "NULL SID", "SubjectUserName": "-", "SubjectDomainName": "-",
        "SubjectLogonId": "0x44", "TargetUserSid": "S-1-0-0", "TargetUserName": "svc",
        "TargetDomainName": "EXAMPLE", "TargetLogonId": "0x45", "NewProcessId": "0x100",
        "NewProcessName": r"C:\Windows\System32\cmd.exe", "ParentProcessName": "-",
    }))
    access = normalize_windows(_hit(4663, {
        "ObjectServer": "Security", "ObjectType": "File", "ObjectName": r"C:\x.txt",
        "AccessMask": "0x6", "AccessList": "%%4417 %%4418 %%9999", "ProcessName": "-",
    }, record_id=2))

    assert process.get("process.session_id") == "0x45"
    assert process.get("process.subject_session_id") == "0x44"
    assert process.get("process.target_session_id") == "0x45"
    assert not process.has("user.entity_id")
    assert not process.has("process.parent.executable")
    assert access.get("object.accesses") == [
        "write_data_or_add_file", "append_data_or_add_subdirectory_or_create_pipe_instance",
    ]
    assert access.get("object.access_codes") == ["%%4417", "%%4418"]
    assert any("%%9999" in reason for reason in access.caveats)


def test_sysmon_network_enrichment_uses_the_shared_community_id_contract():
    event = normalize_windows(_hit(3, {
        "ProcessGuid": "{11111111-1111-1111-1111-111111111111}",
        "ProcessId": "900",
        "SourceIp": "::ffff:192.0.2.10",
        "SourcePort": "50100",
        "SourceHostname": "WS01.example.test",
        "DestinationIp": "198.51.100.20",
        "DestinationPort": "443",
        "DestinationHostname": "api.example.test",
        "DestinationPortName": "https",
        "SourceIsIpv6": "false",
        "DestinationIsIpv6": "false",
        "Protocol": "tcp",
    }, channel=SYSMON_CHANNEL, provider=SYSMON))

    assert event.get("source.ip") == "192.0.2.10"
    assert event.get("source.hostname") == "ws01.example.test"
    assert event.get("destination.hostname") == "api.example.test"
    assert event.get("destination.service.name") == "https"
    assert event.get("source.address_family") == "ipv4"
    assert event.get("destination.address_family") == "ipv4"
    assert event.get("source.is_ipv6") is False
    assert event.get("destination.is_ipv6") is False
    assert str(event.get("network.community_id")).startswith("1:")


@pytest.mark.parametrize(("event_id", "family", "provider", "channel"), [
    (10, "process_access", SYSMON, SYSMON_CHANNEL),
    (7, "image_load", SYSMON, SYSMON_CHANNEL),
    (8, "remote_thread", SYSMON, SYSMON_CHANNEL),
    (25, "process_tampering", SYSMON, SYSMON_CHANNEL),
    (13, "registry_change", SYSMON, SYSMON_CHANNEL),
    (4663, "object_access", SECURITY, "Security"),
    (17, "pipe_event", SYSMON, SYSMON_CHANNEL),
    (19, "wmi_subscription", SYSMON, SYSMON_CHANNEL),
    (22, "dns_lookup", SYSMON, SYSMON_CHANNEL),
    (4104, "script_block", "Microsoft-Windows-PowerShell", "Microsoft-Windows-PowerShell/Operational"),
    (4662, "directory_access", SECURITY, "Security"),
    (5136, "directory_change", SECURITY, "Security"),
    (5145, "share_access", SECURITY, "Security"),
    (1116, "defender_event", "Microsoft-Windows-Windows Defender", "Microsoft-Windows-Windows Defender/Operational"),
    (1149, "remote_access", "Microsoft-Windows-TerminalServices-RemoteConnectionManager",
     "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"),
])
def test_each_new_family_normalizes_as_typed_evidence(event_id, family, provider, channel):
    event = normalize_windows(_hit(event_id, {}, provider=provider, channel=channel))
    assert event.family == family
    assert event.get("host.os.family") == "windows"
    assert event.normalizer == "windows-ecs@3"


def test_task_xml_is_namespace_safe_and_extracts_actions_principal_and_flags():
    xml = """<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
      <RegistrationInfo><Author>EXAMPLE\\Administrator</Author><URI>\\Example\\Daily</URI></RegistrationInfo>
      <Principals><Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
      <Settings><Hidden>true</Hidden></Settings>
      <Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers>
      <Actions Context="Author"><Exec><Command>cmd.exe</Command><Arguments>/c whoami</Arguments></Exec>
        <ComHandler><ClassId>{11111111-1111-1111-1111-111111111111}</ClassId></ComHandler></Actions>
    </Task>"""
    event = normalize_windows(_hit(4698, {"TaskName": r"\Example\Daily", "TaskContent": xml}))

    assert event.get("task.xml_parse") == "success"
    assert event.get("task.actions") == [
        {"kind": "exec", "command": "cmd.exe", "arguments": "/c whoami"},
        {"kind": "com_handler", "class_id": "11111111-1111-1111-1111-111111111111"},
    ]
    assert event.get("task.principal.user_id") == "S-1-5-18"
    assert event.get("task.hidden") is True
    assert event.get("task.author") == r"EXAMPLE\Administrator"
    assert event.get("task.uri") == r"\Example\Daily"
    assert event.get("task.triggers") == [{"kind": "logon", "enabled": True}]


def test_task_xml_scopes_trigger_identity_away_from_registration_and_principal_fields():
    xml = """<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
      <RegistrationInfo><Author>EXAMPLE\\Author</Author><URI>\\Scoped</URI></RegistrationInfo>
      <Triggers><LogonTrigger><UserId>EXAMPLE\\TriggerUser</UserId></LogonTrigger></Triggers>
      <Principals><Principal><UserId>S-1-5-18</UserId><LogonType>ServiceAccount</LogonType>
        <RunLevel>HighestAvailable</RunLevel></Principal></Principals>
      <Settings><Hidden>true</Hidden></Settings>
      <Actions><Exec><Command>cmd.exe</Command></Exec></Actions>
    </Task>"""

    event = normalize_windows(_hit(4698, {"TaskName": r"\Scoped", "TaskContent": xml}))

    assert event.get("task.author") == r"EXAMPLE\Author"
    assert event.get("task.uri") == r"\Scoped"
    assert event.get("task.principal.user_id") == "S-1-5-18"
    assert event.get("task.principal.logon_type") == "serviceaccount"
    assert event.get("task.principal.run_level") == "highestavailable"
    assert event.get("task.hidden") is True


def test_unsafe_task_xml_keeps_event_and_exposes_failure_without_actions():
    event = normalize_windows(_hit(4702, {
        "TaskName": r"\Bad",
        "TaskContent": '<!DOCTYPE task [<!ENTITY xxe SYSTEM "file:///c:/secret">]><Task>&xxe;</Task>',
    }))
    assert event.family == "scheduled_task"
    assert event.get("task.xml_parse") == "failed"
    assert not event.has("task.actions")
    assert "DOCTYPE" in event.get("task.xml_parse_reason")


def test_oversized_task_xml_keeps_the_registration_but_omits_actions():
    event = normalize_windows(_hit(4698, {
        "TaskName": r"\TooLarge",
        "TaskContent": "<Task><Actions><Exec><Command>" + "x" * 1_048_576
        + "</Command></Exec></Actions></Task>",
    }))

    assert event.get("task.xml_parse") == "failed"
    assert "exceeds" in event.get("task.xml_parse_reason")
    assert not event.has("task.actions")


def test_registry_paths_are_canonical_without_collapsing_wow6432node():
    event = normalize_windows(_hit(13, {
        "EventType": "SetValue",
        "TargetObject": r"HKLM\SOFTWARE\Wow6432Node\Example\Enabled",
        "Details": "DWORD (0x00000001)",
        "ProcessGuid": "{11111111-1111-1111-1111-111111111111}",
    }, channel=SYSMON_CHANNEL, provider=SYSMON))
    assert event.get("registry.path_key") == r"hkey_local_machine\software\wow6432node\example\enabled"
    assert event.get("registry.wow6432node") is True
    assert event.get("registry.control_set_alias") is False
    assert event.get("registry.details_truncated") is False


@pytest.mark.parametrize(("raw", "canonical"), [
    (r"HKLM\SOFTWARE\Example", r"hkey_local_machine\software\example"),
    (r"\REGISTRY\MACHINE\SOFTWARE\Example", r"hkey_local_machine\software\example"),
    (r"HKU\S-1-5-21-1\Software\Example", r"hkey_users\s-1-5-21-1\software\example"),
    (r"\REGISTRY\USER\S-1-5-21-1\Software\Example", r"hkey_users\s-1-5-21-1\software\example"),
    (r"HKCR\Example.Type", r"hkey_classes_root\example.type"),
    (r"HKCU\Software\Example", r"hkey_current_user\software\example"),
])
def test_registry_root_aliases_have_stable_comparison_keys(raw, canonical):
    assert registry_path_key(raw) == canonical


@pytest.mark.parametrize(("path", "key", "device", "short"), [
    (r"\Device\HarddiskVolume3\Windows\a.exe", r"\device\harddiskvolume3\windows\a.exe", True, False),
    (r"%SystemRoot%\System32\cmd.exe", r"%systemroot%\system32\cmd.exe", True, False),
    (r"C:\PROGRA~1\Example\x.exe", r"c:\progra~1\example\x.exe", False, True),
])
def test_non_drive_windows_path_forms_are_kept_and_annotated(path, key, device, short):
    event = normalize_windows(_hit(1, {
        "ProcessId": "1", "ProcessGuid": "{11111111-2222-3333-4444-555555555555}", "Image": path,
    }, channel=SYSMON_CHANNEL, provider=SYSMON))

    assert event.get("process.executable") == path
    assert event.get("process.executable_key") == key
    assert event.get("process.executable_key.device_path") is device
    assert event.get("process.executable_key.short_name") is short


def test_ipv4_mapped_and_loopback_addresses_are_typed_but_zero_addresses_are_absent():
    mapped = normalize_windows(_hit(4624, {"IpAddress": "::ffff:10.0.0.5", "TargetLogonId": "0x44"}))
    loopback = normalize_windows(_hit(
        4624, {"IpAddress": "::1", "TargetLogonId": "0x44"}, record_id=2,
    ))
    absent = normalize_windows(_hit(
        4624, {"IpAddress": "0.0.0.0", "TargetLogonId": "0x44"}, record_id=3,
    ))

    assert mapped.get("source.ip") == "10.0.0.5"
    assert mapped.get("source.address_family") == "ipv4"
    assert loopback.get("source.is_loopback") is True
    assert not absent.has("source.ip")


def test_failed_kerberos_machine_ticket_keeps_unsigned_encryption_code_and_dc_identity():
    event = normalize_windows(_hit(4769, {
        "TargetUserName": "MACHINE$", "ServiceName": "krbtgt/EXAMPLE.TEST",
        "TicketEncryptionType": "0xFFFFFFFF", "Status": "0x1f",
        "IpAddress": "192.0.2.10", "LogonGuid": "{11111111-2222-3333-4444-555555555555}",
    }))

    assert event.host == "ws01"
    assert event.get("account.name") == "machine$"
    assert event.get("auth.service_name") == "krbtgt/EXAMPLE.TEST"
    assert event.get("auth.encryption_type") == 0xFFFFFFFF
    assert event.outcome.value == "failure"


def test_forwarded_security_event_keeps_origin_host_instead_of_collector_identity():
    hit = _hit(4769, {
        "TargetUserName": "analyst", "ServiceName": "cifs/files.example.test",
        "TicketEncryptionType": "0x12", "Status": "0",
        "IpAddress": "192.0.2.10",
    })
    hit["_source"]["agent"]["hostname"] = "collector01.example.test"
    hit["_source"]["host"] = {"name": "collector01.example.test"}

    event = normalize_windows(hit)

    assert event.host == "ws01"
    assert event.get("source.ip") == "192.0.2.10"
    assert event.host != "collector01"


def test_auth_account_and_task_fields_cover_certificate_delegation_and_xml_principal():
    auth = normalize_windows(_hit(4768, {
        "TargetUserName": "machine$", "ServiceName": "krbtgt", "Status": "0",
        "TicketEncryptionType": "0xffffffff", "CertIssuerName": "CN=Example CA",
        "CertSerialNumber": "01AB", "CertThumbprint": "AABBCC",
    }))
    account = normalize_windows(_hit(4742, {
        "TargetUserName": "server$", "AllowedToDelegateTo": "cifs/a.example.test\r\nhttp/a.example.test",
        "UserAccountControl": "TRUSTED_FOR_DELEGATION; DONT_EXPIRE_PASSWORD",
    }, record_id=2))
    xml = """<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
      <Principals><Principal><UserId>S-1-5-18</UserId><LogonType>ServiceAccount</LogonType></Principal></Principals>
      <Actions><ShowMessage><Title>Notice</Title><Body>Hello</Body></ShowMessage></Actions>
    </Task>"""
    task = normalize_windows(_hit(4698, {"TaskName": r"\Example", "TaskContent": xml}, record_id=3))
    operational = normalize_windows(_hit(
        106, {"TaskName": r"\Example", "UserContext": "EXAMPLE\\analyst"}, record_id=4,
        channel="Microsoft-Windows-TaskScheduler/Operational", provider="Microsoft-Windows-TaskScheduler",
    ))

    assert auth.get("auth.certificate.issuer") == "CN=Example CA"
    assert auth.get("auth.certificate.serial_number") == "01AB"
    assert auth.get("auth.certificate.thumbprint") == "AABBCC"
    assert auth.get("auth.encryption_type") == 0xFFFFFFFF
    assert account.get("account.allowed_to_delegate_to") == ["cifs/a.example.test", "http/a.example.test"]
    assert account.get("account.uac_changes") == ["TRUSTED_FOR_DELEGATION", "DONT_EXPIRE_PASSWORD"]
    assert task.get("task.principal.logon_type") == "serviceaccount"
    assert task.get("task.actions") == [{"kind": "show_message"}]
    assert operational.get("task.user_context") == r"EXAMPLE\analyst"


def test_process_image_registry_object_and_wmi_fields_keep_raw_and_parsed_values():
    access = normalize_windows(_hit(10, {
        "SourceProcessGuid": "{11111111-1111-1111-1111-111111111111}", "SourceProcessId": "12",
        "SourceImage": r"C:\src.exe", "SourceUser": r"EXAMPLE\source",
        "TargetProcessGuid": "{22222222-2222-2222-2222-222222222222}", "TargetProcessId": "13",
        "TargetImage": r"C:\dst.exe", "TargetUser": r"EXAMPLE\target", "GrantedAccess": "0x17",
        "CallTrace": r"C:\Windows\System32\a.dll+1|C:\Tools\b.dll+2",
    }, channel=SYSMON_CHANNEL, provider=SYSMON))
    image = normalize_windows(_hit(7, {
        "ProcessGuid": "{11111111-1111-1111-1111-111111111111}", "ImageLoaded": r"C:\Tools\x.dll",
        "OriginalFileName": "x-original.dll", "Hashes": "SHA256=ABCD,MD5=1234",
    }, channel=SYSMON_CHANNEL, provider=SYSMON, record_id=2))
    registry = normalize_windows(_hit(4657, {
        "ObjectName": r"\REGISTRY\MACHINE\SOFTWARE\Example", "ObjectValueName": "Mode",
        "OperationType": "%%1905", "OldValue": "off", "NewValue": "on",
    }, record_id=3))
    obj = normalize_windows(_hit(4663, {
        "ObjectServer": "Security", "ObjectType": "File", "ObjectName": r"C:\secret.txt",
        "AccessMask": "0x2", "ProcessName": r"C:\Windows\System32\cmd.exe",
    }, record_id=4))
    wmi = normalize_windows(_hit(
        5861, {"Operation": "Created", "EventNamespace": r"root\subscription", "Type": "Binding",
               "Destination": "CommandLineEventConsumer.Name=Example"}, record_id=5,
        channel="Microsoft-Windows-WMI-Activity/Operational", provider="Microsoft-Windows-WMI-Activity",
    ))

    assert access.get("source.user") == r"EXAMPLE\source"
    assert access.get("target.user") == r"EXAMPLE\target"
    assert access.get("process.access.call_trace") == r"C:\Windows\System32\a.dll+1|C:\Tools\b.dll+2"
    assert access.get("process.access.call_trace_modules") == [
        r"C:\Windows\System32\a.dll", r"C:\Tools\b.dll",
    ]
    assert image.get("image.original_file_name") == "x-original.dll"
    assert image.get("image.hash.sha256") == "abcd" and image.get("image.hash.md5") == "1234"
    assert registry.get("registry.operation_type") == "existing_registry_value_modified"
    assert registry.get("registry.old_value") == "off" and registry.get("registry.value") == "on"
    assert obj.get("object.server") == "Security"
    assert wmi.get("wmi.namespace") == r"root\subscription"
    assert wmi.get("wmi.type") == "Binding"
    assert wmi.get("wmi.destination") == "CommandLineEventConsumer.Name=Example"


def test_dns_script_directory_share_defender_and_bits_fields_are_typed():
    dns = normalize_windows(_hit(22, {
        "ProcessGuid": "{11111111-1111-1111-1111-111111111111}", "QueryName": "Alias.Example.",
        "QueryStatus": "0", "QueryResults": "::ffff:192.0.2.8;CNAME.Target.Example.;2001:db8::1",
    }, channel=SYSMON_CHANNEL, provider=SYSMON))
    script = normalize_windows(_hit(
        4103, {"Payload": "Get-Process", "ContextInfo": "Host Name = ConsoleHost\r\nUser = EXAMPLE\\analyst"},
        channel="Microsoft-Windows-PowerShell/Operational", provider="Microsoft-Windows-PowerShell", record_id=2,
    ))
    legacy = normalize_windows(_hit(
        400, {"HostApplication": "powershell.exe -NoProfile", "EngineVersion": "5.1.22621.1"},
        channel="Windows PowerShell", provider="PowerShell", record_id=3,
    ))
    directory = normalize_windows(_hit(4662, {
        "ObjectServer": "DS", "ObjectType": "domainDNS", "ObjectName": "DC=example,DC=test",
        "OperationType": "Object Access", "AccessMask": "0x100",
    }, record_id=4))
    share = normalize_windows(_hit(5145, {
        "ShareName": r"\\*\ADMIN$", "RelativeTargetName": "system32", "SubjectLogonId": "0x44",
    }, record_id=5))
    defender = normalize_windows(_hit(
        5007, {
            "Threat_Name": "Example.Test", "Detection_User": r"EXAMPLE\analyst",
            "Action_Name": "Configuration changed", "Old_Value": "A", "New_Value": "B",
        }, record_id=6,
        channel="Microsoft-Windows-Windows Defender/Operational", provider="Microsoft-Windows-Windows Defender",
    ))
    bits = normalize_windows(_hit(
        59, {"JobId": "{11111111-1111-1111-1111-111111111111}", "Url": "https://example.test/a",
             "LocalName": r"C:\Temp\a.bin"}, record_id=7,
        channel="Microsoft-Windows-Bits-Client/Operational", provider="Microsoft-Windows-Bits-Client",
    ))

    assert dns.get("dns.answers.addresses") == ["192.0.2.8", "2001:db8::1"]
    assert dns.get("dns.answers.cnames") == ["cname.target.example"]
    assert script.get("script.text") == "Get-Process"
    assert script.get("script.context") == {"Host Name": "ConsoleHost", "User": r"EXAMPLE\analyst"}
    assert legacy.get("script.host_application") == "powershell.exe -NoProfile"
    assert legacy.get("script.engine_version") == "5.1.22621.1"
    assert "#parsed:" in script.fields["script.context"].origin
    assert "#parsed:" in legacy.fields["script.host_application"].origin
    assert "#parsed:" in legacy.fields["script.engine_version"].origin
    assert directory.get("directory.object.server") == "DS"
    assert directory.get("directory.object.type") == "domainDNS"
    assert directory.get("directory.access.operation_type") == "Object Access"
    assert share.get("share.session_id") == "0x44"
    assert defender.get("defender.recorded_action") == "Configuration changed"
    assert defender.get("defender.old_value") == "A" and defender.get("defender.new_value") == "B"
    assert defender.get("defender.threat.name") == "Example.Test"
    assert defender.get("defender.user") == r"EXAMPLE\analyst"
    assert bits.get("bits.local_file") == r"C:\Temp\a.bin"
    assert bits.get("bits.remote_url") == "https://example.test/a"


def test_uac_message_codes_are_typed_and_unknown_codes_are_omitted():
    event = normalize_windows(_hit(4742, {
        "TargetUserName": "server$",
        "UserAccountControl": "%%2080 %%2082 %%2084 %%9999",
    }))

    assert event.get("account.uac_changes") == [
        "account_disabled",
        "password_not_required_enabled",
        "normal_account_enabled",
    ]
    assert "#parsed:uac-flags" in event.fields["account.uac_changes"].origin
    assert any("%%9999" in caveat and "omitted" in caveat for caveat in event.caveats)


def test_script_complete_requires_valid_single_part_metadata():
    common = {
        "ScriptBlockId": "11111111-2222-3333-4444-555555555555",
        "ScriptBlockText": "Write-Output test",
    }
    missing = normalize_windows(_hit(
        4104, common,
        channel="Microsoft-Windows-PowerShell/Operational", provider="Microsoft-Windows-PowerShell",
    ))
    malformed = normalize_windows(_hit(
        4104, {**common, "MessageNumber": "not-a-number", "MessageTotal": "1"}, record_id=2,
        channel="Microsoft-Windows-PowerShell/Operational", provider="Microsoft-Windows-PowerShell",
    ))
    single = normalize_windows(_hit(
        4104, {**common, "MessageNumber": "1", "MessageTotal": "1"}, record_id=3,
        channel="Microsoft-Windows-PowerShell/Operational", provider="Microsoft-Windows-PowerShell",
    ))
    multipart = normalize_windows(_hit(
        4104, {**common, "MessageNumber": "1", "MessageTotal": "2"}, record_id=4,
        channel="Microsoft-Windows-PowerShell/Operational", provider="Microsoft-Windows-PowerShell",
    ))

    assert missing.get("script.complete") is False
    assert malformed.get("script.complete") is False
    assert single.get("script.complete") is True
    assert multipart.get("script.complete") is False
    assert any("part metadata" in caveat for caveat in missing.caveats)
    assert any("part metadata" in caveat for caveat in malformed.caveats)


def test_script_part_count_accepts_the_boundary_and_rejects_larger_metadata():
    common = {
        "ScriptBlockId": "11111111-2222-3333-4444-555555555555",
        "ScriptBlockText": "Write-Output test",
        "MessageNumber": "1",
    }
    boundary = normalize_windows(_hit(
        4104, {**common, "MessageTotal": str(SCRIPT_BLOCK_MAX_PARTS)},
        channel="Microsoft-Windows-PowerShell/Operational", provider="Microsoft-Windows-PowerShell",
    ))
    excessive = [
        normalize_windows(_hit(
            4104, {**common, "MessageTotal": str(total)}, record_id=record_id,
            channel="Microsoft-Windows-PowerShell/Operational", provider="Microsoft-Windows-PowerShell",
        ))
        for record_id, total in enumerate((SCRIPT_BLOCK_MAX_PARTS + 1, 2**31), 2)
    ]

    assert boundary.get("script.message_total") == SCRIPT_BLOCK_MAX_PARTS
    assert not any("supported maximum" in caveat for caveat in boundary.caveats)
    assert all(event.get("script.complete") is False for event in excessive)
    assert all(
        any(f"supported maximum {SCRIPT_BLOCK_MAX_PARTS}" in caveat for caveat in event.caveats)
        for event in excessive
    )


@pytest.mark.parametrize("block_id", [
    "not-a-guid",
    "00000000-0000-0000-0000-000000000000",
])
def test_invalid_script_block_ids_are_incomplete_and_not_correlation_keys(block_id):
    event = normalize_windows(_hit(
        4104,
        {
            "ScriptBlockId": block_id,
            "ScriptBlockText": "Write-Output test",
            "MessageNumber": "1",
            "MessageTotal": "1",
        },
        channel="Microsoft-Windows-PowerShell/Operational",
        provider="Microsoft-Windows-PowerShell",
    ))

    assert event.get("script.block_id") is None
    assert event.get("script.complete") is False
    assert any("cannot be correlated" in caveat for caveat in event.caveats)


def test_script_block_id_is_canonicalized_before_it_becomes_a_correlation_key():
    event = normalize_windows(_hit(
        4104,
        {
            "ScriptBlockId": "{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}",
            "ScriptBlockText": "Write-Output test",
            "MessageNumber": "1",
            "MessageTotal": "1",
        },
        channel="Microsoft-Windows-PowerShell/Operational",
        provider="Microsoft-Windows-PowerShell",
    ))

    assert event.get("script.block_id") == "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    assert event.get("script.complete") is True


def test_auth_session_fields_preserve_valid_native_spelling():
    event = normalize_windows(_hit(4624, {
        "TargetUserName": "analyst",
        "TargetLogonId": "0X00000055",
    }))

    assert event.get("auth.session_id") == "0x00000055"
    assert event.get("auth.session_key") == "ws01:0x00000055"


def test_legacy_powershell_fields_are_parsed_from_structured_data():
    event = normalize_windows(_hit(
        400,
        {"Data": (
            "NewEngineState=Available\r\n"
            "EngineVersion=5.1.22621.2506\r\n"
            "HostApplication=powershell.exe -NoProfile -File inventory.ps1"
        )},
        channel="Windows PowerShell", provider="PowerShell",
    ))

    assert event.get("script.host_application") == "powershell.exe -NoProfile -File inventory.ps1"
    assert event.get("script.engine_version") == "5.1.22621.2506"
    assert "#parsed:powershell-data" in event.fields["script.host_application"].origin
    assert "#parsed:powershell-data" in event.fields["script.engine_version"].origin


def test_legacy_powershell_structured_data_is_bounded():
    event = normalize_windows(_hit(
        400, {"Data": "HostApplication=" + ("x" * 65_537)},
        channel="Windows PowerShell", provider="PowerShell",
    ))

    assert event.get("script.host_application") is None
    assert any("Data exceeds 65536 bytes" in caveat for caveat in event.caveats)


def test_sysmon_dns_typed_answer_prefixes_are_removed():
    event = normalize_windows(_hit(22, {
        "QueryName": "alias.example.test",
        "QueryStatus": "0",
        "QueryResults": "type: 5 Target.Example.;type: 1 192.0.2.8;type: 28 2001:db8::1",
    }, channel=SYSMON_CHANNEL, provider=SYSMON))

    assert event.get("dns.answers.cnames") == ["target.example"]
    assert event.get("dns.answers.addresses") == ["192.0.2.8", "2001:db8::1"]


@pytest.mark.parametrize(("path", "preserved"), [
    (r"\\?\UNC\Server\Share\service.exe", r"\\?\unc\server\share\service.exe"),
    (r"\??\UNC\Server\Share\service.exe", r"\??\unc\server\share\service.exe"),
])
def test_extended_unc_process_paths_preserve_recorded_key_and_add_standard_canonical_alias(path, preserved):
    event = normalize_windows(_hit(1, {
        "ProcessId": "1",
        "ProcessGuid": "{11111111-2222-3333-4444-555555555555}",
        "Image": path,
    }, channel=SYSMON_CHANNEL, provider=SYSMON))

    assert event.get("process.executable") == path
    assert event.get("process.executable_key") == preserved
    assert event.get("process.executable_canonical_key") == r"\\server\share\service.exe"


def test_sysmon_stream_hash_accepts_the_native_singular_hash_field():
    event = normalize_windows(_hit(15, {
        "ProcessId": "123",
        "ProcessGuid": "{11111111-2222-3333-4444-555555555555}",
        "TargetFilename": r"C:\Temp\payload.txt:Zone.Identifier",
        "Hash": "SHA256=AABBCCDDEEFF",
        "Contents": "ZoneId=3",
    }, channel=SYSMON_CHANNEL, provider=SYSMON))

    assert event.get("file.hash.sha256") == "aabbccddeeff"


@pytest.mark.parametrize(("operation_type", "expected"), [
    ("%%14674", "value_added"),
    ("%%14675", "value_deleted"),
])
def test_directory_operation_message_codes_are_mapped(operation_type, expected):
    event = normalize_windows(_hit(5136, {
        "ObjectDN": "CN=User,DC=example,DC=test",
        "OperationType": operation_type,
    }))

    assert event.get("directory.change.operation_type") == expected


def test_unknown_directory_operation_message_code_is_omitted_with_a_caveat():
    event = normalize_windows(_hit(5136, {
        "ObjectDN": "CN=User,DC=example,DC=test",
        "OperationType": "%%99999",
    }))

    assert event.get("directory.change.operation_type") is None
    assert any("%%99999" in caveat and "omitted" in caveat for caveat in event.caveats)


def test_rcm_1149_uses_the_documented_param_fields():
    event = normalize_windows(_hit(
        1149,
        {"Param1": "analyst", "Param2": "EXAMPLE", "Param3": "203.0.113.25"},
        channel="Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
        provider="Microsoft-Windows-TerminalServices-RemoteConnectionManager",
    ))

    assert event.get("remote.user") == "analyst"
    assert event.get("remote.domain") == "EXAMPLE"
    assert event.get("source.ip") == "203.0.113.25"


@pytest.mark.parametrize("event_id", [4656, 4662, 5145])
def test_security_audit_families_honor_shipper_failure_outcome(event_id):
    hit = _hit(event_id, {
        "ObjectName": r"C:\Secret.txt",
        "ObjectDN": "CN=Secret,DC=example,DC=test",
        "ShareName": r"\\*\Secret",
        "IpAddress": "203.0.113.25",
    })
    hit["_source"]["event"] = {"outcome": "failure"}

    event = normalize_windows(hit)

    assert event.outcome.value == "failure"


def test_security_audit_families_honor_windows_audit_failure_keyword():
    hit = _hit(5145, {"ShareName": r"\\*\Secret", "IpAddress": "203.0.113.25"})
    hit["_source"]["winlog"]["keywords"] = ["Audit Failure"]

    event = normalize_windows(hit)

    assert event.outcome.value == "failure"


def test_security_audit_family_preserves_explicit_unknown_outcome():
    hit = _hit(5145, {"ShareName": r"\\*\Secret", "IpAddress": "203.0.113.25"})
    hit["_source"]["event"] = {"outcome": "unknown"}

    event = normalize_windows(hit)

    assert event.outcome.value == "unknown"


def test_sysmon_registry_details_is_value_text_not_value_type():
    details_only = normalize_windows(_hit(13, {
        "TargetObject": r"HKLM\SOFTWARE\Example\Mode",
        "Details": "DWORD (0x00000001)",
    }, channel=SYSMON_CHANNEL, provider=SYSMON))
    explicit_type = normalize_windows(_hit(13, {
        "TargetObject": r"HKLM\SOFTWARE\Example\Mode",
        "Details": "DWORD (0x00000001)",
        "NewValueType": "REG_DWORD",
    }, channel=SYSMON_CHANNEL, provider=SYSMON, record_id=2))

    assert details_only.get("registry.value") == "DWORD (0x00000001)"
    assert details_only.get("registry.value_type") is None
    assert explicit_type.get("registry.value_type") == "REG_DWORD"
