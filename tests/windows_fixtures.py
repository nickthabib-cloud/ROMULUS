"""Synthetic Windows telemetry in equivalent Winlogbeat and Elastic Agent shapes."""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from typing import Literal
from xml.sax.saxutils import escape, quoteattr

from romulus.evidence.typed import TypedEvent
from romulus.evidence.windows_catalog import SECURITY, SYSMON

Shape = Literal["winlogbeat_7", "winlogbeat_8", "elastic_agent"]
SHAPES: tuple[Shape, ...] = ("winlogbeat_7", "winlogbeat_8", "elastic_agent")

# This fixture inventory is intentionally independent of the production catalog. Security event XML:
# https://learn.microsoft.com/windows/security/threat-protection/auditing/security-auditing-overview
# Sysmon IDs 1/3/5 and channel: https://learn.microsoft.com/sysinternals/downloads/sysmon#events
# System sources: https://learn.microsoft.com/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs
# Elastic Agent Windows data-stream envelope: https://www.elastic.co/docs/reference/integrations/windows
_DOCUMENTED_EVENT_KEYS = (
    *[("Security", SECURITY, event_id) for event_id in (
        4688, 4689, 4624, 4625, 4648, 4672, 4634, 4647, 4720, 4722, 4724, 4726,
        4728, 4732, 4756, 4738, 4740, 4697, 4698, 4702,
        4768, 4769, 4770, 4771, 4776, 4778, 4779, 4964,
        4704, 4705, 4725, 4729, 4733, 4741, 4742, 4743, 4757, 4765, 4766, 4767, 4781, 4794,
        4699, 4700, 4701, 4657, 4656, 4663, 4670, 4662,
        5136, 5137, 5138, 5139, 5141, 5140, 5145,
    )],
    *[("Microsoft-Windows-Sysmon/Operational", SYSMON, event_id) for event_id in (
        1, 3, 5, 2, 11, 15, 23, 26, 10, 6, 7, 8, 25, 12, 13, 14,
        17, 18, 19, 20, 21, 22, 4, 16, 255,
    )],
    ("Security", "Microsoft-Windows-Eventlog", 1102),
    *[("Security", "Microsoft-Windows-Eventlog", event_id) for event_id in (1100, 1104, 1108)],
    ("Security", SECURITY, 4719),
    ("System", "Service Control Manager", 7045),
    ("System", "Service Control Manager", 7040),
    ("System", "Microsoft-Windows-Eventlog", 104),
    ("System", "Microsoft-Windows-Kernel-General", 12),
    ("System", "Microsoft-Windows-Kernel-General", 13),
    ("System", "EventLog", 6005),
    ("System", "EventLog", 6006),
    *[("Microsoft-Windows-TaskScheduler/Operational", "Microsoft-Windows-TaskScheduler", event_id)
      for event_id in (106, 129, 140, 141, 200, 201)],
    ("Microsoft-Windows-WMI-Activity/Operational", "Microsoft-Windows-WMI-Activity", 5861),
    *[("Microsoft-Windows-PowerShell/Operational", "Microsoft-Windows-PowerShell", event_id)
      for event_id in (4103, 4104)],
    *[("Windows PowerShell", "PowerShell", event_id) for event_id in (400, 403, 800)],
    *[("Microsoft-Windows-Windows Defender/Operational", "Microsoft-Windows-Windows Defender", event_id)
      for event_id in (1006, 1007, 1008, 1015, 1116, 1117, 1118, 1119, 5001, 5004, 5007, 5010, 5012, 5013)],
    ("Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
     "Microsoft-Windows-TerminalServices-RemoteConnectionManager", 1149),
    *[("Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
       "Microsoft-Windows-TerminalServices-LocalSessionManager", event_id)
      for event_id in (21, 22, 24, 25)],
    *[("Microsoft-Windows-WinRM/Operational", "Microsoft-Windows-WinRM", event_id)
      for event_id in (6, 91)],
    *[("Microsoft-Windows-Bits-Client/Operational", "Microsoft-Windows-Bits-Client", event_id)
      for event_id in (3, 59, 60)],
)


@dataclass(frozen=True)
class LogicalWindowsEvent:
    channel: str
    provider: str
    event_id: int
    computer: str
    record_id: int
    timestamp: str
    data: dict[str, object]


def _guid(number: int) -> str:
    return f"{{00000000-0000-0000-0000-{number:012x}}}"


def _subject() -> dict[str, object]:
    return {
        "SubjectUserSid": "S-1-5-21-111-222-333-1001",
        "SubjectDomainName": "EXAMPLE",
        "SubjectUserName": "Administrator",
        "SubjectLogonId": "0x44",
    }


def _process_data(ordinal: int) -> dict[str, object]:
    return {
        "UtcTime": "2026-01-02 03:04:05.000",
        "ProcessGuid": _guid(ordinal),
        "ProcessId": str(1000 + ordinal),
        "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "User": r"EXAMPLE\analyst",
    }


def _sysmon_data(event_id: int, ordinal: int) -> dict[str, object]:
    process = _process_data(ordinal)
    if event_id == 1:
        return {
            **process,
            "ParentProcessGuid": _guid(ordinal + 10_000),
            "ParentProcessId": "700",
            "ParentImage": r"C:\Windows\explorer.exe",
            "CommandLine": "powershell.exe -NoProfile -Command Get-Date",
            "Hashes": "SHA256=ABCDEF0123456789,MD5=0123456789ABCDEF",
        }
    if event_id == 3:
        return {
            **process,
            "SourceIp": "192.0.2.10",
            "SourcePort": "50100",
            "DestinationIp": "198.51.100.20",
            "DestinationPort": "443",
            "Protocol": "tcp",
            "Initiated": "true",
        }
    if event_id == 5:
        return {**process, "Image": r"C:\Windows\System32\whoami.exe"}
    if event_id in {2, 11, 15, 23, 26}:
        suffix = ":Zone.Identifier" if event_id == 15 else ""
        data = {
            **process,
            "TargetFilename": rf"C:\ProgramData\Example\payload.dll{suffix}",
            "CreationUtcTime": "2026-01-02 03:04:06.000",
            "PreviousCreationUtcTime": "2026-01-01 03:04:06.000",
            "Contents": "ZoneId=3",
        }
        data["Hash" if event_id == 15 else "Hashes"] = "SHA256=ABCDEF0123456789"
        return data
    if event_id == 10:
        return {
            "UtcTime": process["UtcTime"],
            "SourceProcessGuid": _guid(ordinal),
            "SourceProcessId": str(1000 + ordinal),
            "SourceImage": r"C:\Windows\System32\rundll32.exe",
            "TargetProcessGuid": _guid(ordinal + 20_000),
            "TargetProcessId": "888",
            "TargetImage": r"C:\Windows\System32\lsass.exe",
            "GrantedAccess": "0x1010",
            "CallTrace": r"C:\Windows\SYSTEM32\ntdll.dll+9d034|C:\Windows\System32\KERNELBASE.dll+2b113",
        }
    if event_id in {6, 7}:
        return {
            **process,
            "ImageLoaded": (
                r"C:\Windows\System32\drivers\example.sys"
                if event_id == 6 else r"C:\Windows\System32\example.dll"
            ),
            "Hashes": "SHA256=ABCDEF0123456789,IMPHASH=89ABCDEF01234567",
            "Signed": "true",
            "Signature": "Microsoft Windows",
            "SignatureStatus": "Valid",
            "OriginalFileName": "example.dll",
        }
    if event_id == 8:
        return {
            "UtcTime": process["UtcTime"],
            "SourceProcessGuid": _guid(ordinal),
            "SourceProcessId": str(1000 + ordinal),
            "SourceImage": r"C:\Windows\System32\rundll32.exe",
            "TargetProcessGuid": _guid(ordinal + 20_000),
            "TargetProcessId": "888",
            "TargetImage": r"C:\Windows\System32\notepad.exe",
            "NewThreadId": "4242",
            "StartAddress": "0x00007ffb12340000",
            "StartModule": "example.dll",
            "StartFunction": "ExampleEntry",
        }
    if event_id == 25:
        return {**process, "Type": "Process Hollowing"}
    if event_id in {12, 13, 14}:
        data = {
            **process,
            "EventType": {12: "CreateKey", 13: "SetValue", 14: "RenameKey"}[event_id],
            "TargetObject": r"HKLM\SOFTWARE\Example\Inventory",
            "Details": "DWORD (0x00000001)",
        }
        if event_id == 14:
            data["NewName"] = r"HKLM\SOFTWARE\Example\InventoryV2"
        return data
    if event_id in {17, 18}:
        return {**process, "PipeName": r"\example-inventory"}
    if event_id == 19:
        return {
            "Name": "Example Process Filter",
            "EventNamespace": r"root\cimv2",
            "Query": "SELECT * FROM Win32_ProcessStartTrace",
        }
    if event_id == 20:
        return {
            "Name": "Example Command Consumer",
            "Type": "Command Line Event Consumer",
            "Destination": "inventory.exe --collect",
        }
    if event_id == 21:
        return {"Consumer": "Example Command Consumer", "Filter": "Example Process Filter", "Binding": "active"}
    if event_id == 22:
        return {
            **process,
            "QueryName": "telemetry.example.test",
            "QueryResults": "type: 5 telemetry.edge.example.test;::ffff:198.51.100.20;",
            "QueryStatus": "0",
        }
    if event_id == 4:
        return {"State": "Started", "Version": "15.15"}
    if event_id == 16:
        return {"Configuration": "Configuration file validated", "ConfigurationFileHash": "ABCDEF0123456789"}
    if event_id == 255:
        return {"Description": "Failed to archive a deleted file", "Error": "5"}
    raise AssertionError(f"missing Sysmon fixture for event {event_id}")


def _security_data(event_id: int, ordinal: int) -> dict[str, object]:
    subject = _subject()
    if event_id == 4688:
        return {
            **subject,
            "NewProcessId": hex(2000 + ordinal),
            "ProcessId": "0x2bc",
            "NewProcessName": r"C:\Windows\System32\whoami.exe",
            "CommandLine": "whoami.exe /groups",
            "TargetUserSid": "S-1-5-21-111-222-333-1100",
            "TargetDomainName": "EXAMPLE",
            "TargetUserName": "analyst",
            "TargetLogonId": "0x55",
        }
    if event_id == 4689:
        return {**subject, "ProcessId": hex(2000 + ordinal), "ProcessName": r"C:\Windows\System32\whoami.exe"}
    if event_id in {4624, 4625, 4648, 4672, 4634, 4647, 4768, 4769, 4770, 4771, 4776, 4778, 4779, 4964}:
        return {
            **subject,
            "TargetUserSid": "S-1-5-21-111-222-333-1100",
            "TargetDomainName": "EXAMPLE",
            "TargetUserName": "analyst",
            "TargetLogonId": "0x55",
            "LogonGuid": _guid(ordinal),
            "LogonType": "3",
            "IpAddress": "203.0.113.25",
            "IpPort": "50200",
            "WorkstationName": "WS02",
            "ServiceName": "cifs/files01.example.test",
            "TicketOptions": "0x40810010",
            "TicketEncryptionType": "0x12",
            "Status": "0xc000006d" if event_id in {4625, 4771} else "0x0",
        }
    if event_id in {4728, 4729, 4732, 4733, 4756, 4757}:
        return {
            **subject,
            "TargetSid": "S-1-5-21-111-222-333-512",
            "TargetDomainName": "EXAMPLE",
            "TargetUserName": "Example Operators",
            "MemberSid": "S-1-5-21-111-222-333-1200",
            "MemberName": r"EXAMPLE\example-user",
        }
    if event_id in {4704, 4705}:
        return {
            **subject,
            "TargetUserSid": "S-1-5-21-111-222-333-1200",
            "TargetDomainName": "EXAMPLE",
            "TargetUserName": "example-user",
            "PrivilegeList": "SeServiceLogonRight",
        }
    if event_id in {4741, 4742, 4743}:
        return {
            **subject,
            "TargetUserSid": "S-1-5-21-111-222-333-1300",
            "TargetDomainName": "EXAMPLE",
            "TargetUserName": "WS099$",
            "SamAccountName": "WS099$",
            "DnsHostName": "ws099.example.test",
            "ServicePrincipalNames": "HOST/ws099.example.test\nRestrictedKrbHost/ws099.example.test",
        }
    if event_id in {4720, 4722, 4724, 4725, 4726, 4738, 4740, 4765, 4766, 4767, 4781, 4794}:
        return {
            **subject,
            "TargetUserSid": "S-1-5-21-111-222-333-1200",
            "TargetDomainName": "EXAMPLE",
            "TargetUserName": "example-user",
            "OldTargetUserName": "old-example-user",
            "NewTargetUserName": "example-user",
            "AllowedToDelegateTo": "cifs/files01.example.test",
            "SidHistory": "S-1-5-21-444-555-666-1200",
            "Status": "0xc0000001" if event_id == 4766 else "0x0",
        }
    if event_id == 4697:
        return {
            **subject,
            "ServiceName": "Example Inventory Service",
            "ServiceFileName": r"C:\Program Files\Example\inventory.exe --service",
            "ServiceType": "user mode service",
            "ServiceStartType": "demand start",
            "ServiceAccount": r"NT AUTHORITY\LocalService",
        }
    if event_id in {4698, 4699, 4700, 4701, 4702}:
        return {
            **subject,
            "TaskName": r"\Example\Inventory",
            "TaskContent": (
                "<Task><RegistrationInfo><Author>EXAMPLE\\analyst</Author></RegistrationInfo>"
                "<Principals><Principal><UserId>EXAMPLE\\analyst</UserId><LogonType>InteractiveToken</LogonType>"
                "</Principal></Principals><Actions><Exec><Command>inventory.exe</Command>"
                "<Arguments>--collect</Arguments></Exec></Actions></Task>"
            ),
        }
    if event_id == 4657:
        return {
            **subject,
            "ObjectName": r"\REGISTRY\MACHINE\SOFTWARE\Example\Inventory",
            "ObjectValueName": "Enabled",
            "OperationType": "%%1905",
            "OldValue": "DWORD (0x00000000)",
            "NewValue": "DWORD (0x00000001)",
        }
    if event_id in {4656, 4663, 4670}:
        return {
            **subject,
            "ObjectServer": "Security",
            "ObjectType": "File",
            "ObjectName": r"C:\ProgramData\Example\inventory.db",
            "HandleId": "0x8c",
            "AccessMask": "0x2",
            "AccessList": "%%4417",
            "ProcessId": "0x4d2",
            "ProcessName": r"C:\Program Files\Example\inventory.exe",
            "OldSd": "D:(A;;FR;;;BA)",
            "NewSd": "D:(A;;FA;;;BA)",
        }
    if event_id in {4662, 5136, 5137, 5138, 5139, 5141}:
        return {
            **subject,
            "ObjectServer": "DS",
            "ObjectType": "%{bf967aba-0de6-11d0-a285-00aa003049e2}",
            "ObjectDN": "CN=Example User,OU=People,DC=example,DC=test",
            "ObjectGUID": _guid(ordinal + 30_000),
            "ObjectClass": "user",
            "AccessMask": "0x100",
            "Properties": "{bf967aba-0de6-11d0-a285-00aa003049e2}",
            "OperationType": "%%14674",
            "AttributeLDAPDisplayName": "servicePrincipalName",
            "AttributeValue": "HTTP/app.example.test",
        }
    if event_id in {5140, 5145}:
        return {
            **subject,
            "ShareName": r"\\*\IPC$",
            "ShareLocalPath": r"\??\C:\Windows",
            "RelativeTargetName": r"System32\example.dll",
            "AccessMask": "0x1",
            "AccessList": "%%4416",
            "IpAddress": "203.0.113.25",
            "IpPort": "50200",
        }
    if event_id == 4719:
        return {**subject, "SubcategoryGuid": _guid(ordinal), "AuditPolicyChanges": "Success added"}
    raise AssertionError(f"missing Security fixture for event {event_id}")


def _data(provider: str, event_id: int, ordinal: int) -> dict[str, object]:
    if provider == SYSMON:
        return _sysmon_data(event_id, ordinal)
    if provider == SECURITY:
        return _security_data(event_id, ordinal)
    if provider == "Microsoft-Windows-Eventlog":
        return {
            **_subject(),
            "Channel": "Security",
            "BackupPath": r"C:\Windows\System32\winevt\Logs\Archive-Security.evtx",
            "Error": "The event log service reported a native condition",
        }
    if provider == "Service Control Manager":
        if event_id == 7040:
            return {
                "ServiceName": "Example Inventory Service",
                "OldStartType": "demand start",
                "StartType": "auto start",
                "AccountName": r"NT AUTHORITY\LocalService",
            }
        return {
            "ServiceName": "Example Inventory Service",
            "ImagePath": r"C:\Program Files\Example\inventory.exe --service",
            "ServiceType": "user mode service",
            "StartType": "demand start",
            "AccountName": r"NT AUTHORITY\LocalService",
        }
    if provider == "Microsoft-Windows-Kernel-General":
        return {"BootType": "0", "EventMessage": "The operating system is starting or shutting down."}
    if provider == "EventLog":
        return {"EventMessage": "The Event log service was started or stopped.", "Channel": "System"}
    if provider == "Microsoft-Windows-TaskScheduler":
        return {
            "TaskName": r"\Example\Inventory",
            "EnginePID": str(2000 + ordinal),
            "ActionName": "inventory.exe --collect",
            "UserContext": r"EXAMPLE\analyst",
            "ResultCode": "0",
        }
    if provider == "Microsoft-Windows-WMI-Activity":
        return {
            "Operation": "Created",
            "EventNamespace": r"root\subscription",
            "Name": "Example Process Filter",
            "Type": "CommandLineEventConsumer",
            "Destination": "inventory.exe --collect",
            "User": r"EXAMPLE\analyst",
        }
    if provider == "Microsoft-Windows-PowerShell":
        return {
            "ScriptBlockId": _guid(ordinal),
            "Path": r"C:\ProgramData\Example\inventory.ps1",
            "ScriptBlockText": "Get-CimInstance Win32_OperatingSystem",
            "ContextInfo": "Host Name = ConsoleHost\nHost Version = 5.1.22621.2506",
            "MessageNumber": "1",
            "MessageTotal": "1",
            "RunspaceId": _guid(ordinal + 40_000),
        }
    if provider == "PowerShell":
        return {
            "param1": "Available" if event_id in {400, 403} else "Get-CimInstance Win32_OperatingSystem",
            "param2": "None" if event_id in {400, 403} else "Pipeline execution details",
            "param3": "HostApplication=powershell.exe -NoProfile -File inventory.ps1\nEngineVersion=2.0",
        }
    if provider == "Microsoft-Windows-Windows Defender":
        return {
            "Threat Name": "Virus:Win32/Example.A",
            "Threat ID": "2147000001",
            "Severity Name": "Severe",
            "Category Name": "Virus",
            "Path": r"file:_C:\ProgramData\Example\payload.exe",
            "Process Name": r"C:\Windows\System32\svchost.exe",
            "Action Name": "Quarantine",
            "Old Value": "Disabled",
            "New Value": "Enabled",
            "Error Code": "0x0",
        }
    if provider == "Microsoft-Windows-TerminalServices-RemoteConnectionManager":
        return {"Param1": "analyst", "Param2": "EXAMPLE", "Param3": "203.0.113.25"}
    if provider == "Microsoft-Windows-TerminalServices-LocalSessionManager":
        return {
            "User": r"EXAMPLE\analyst",
            "Address": "203.0.113.25",
            "SessionID": str(ordinal + 100),
        }
    if provider == "Microsoft-Windows-WinRM":
        return {
            "ClientAddress": "203.0.113.25",
            "ClientPort": "5985",
            "ClientName": "ws02.example.test",
            "ResourceUri": "http://schemas.microsoft.com/wbem/wsman/1/wmi/root/cimv2/*",
            "UserName": r"EXAMPLE\analyst",
        }
    if provider == "Microsoft-Windows-Bits-Client":
        return {
            "JobId": _guid(ordinal + 60_000),
            "JobName": "Example inventory payload",
            "RemoteName": "https://downloads.example.test/inventory.dat",
            "LocalName": r"C:\ProgramData\Example\inventory.dat",
            "User": r"EXAMPLE\analyst",
        }
    raise AssertionError(f"missing fixture for provider {provider!r}, event {event_id}")


def all_logical_events() -> list[LogicalWindowsEvent]:
    start = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
    return [
        LogicalWindowsEvent(
            channel=channel,
            provider=provider,
            event_id=event_id,
            computer="ws01.example.test",
            record_id=10_000 + ordinal,
            timestamp=(start + timedelta(seconds=ordinal)).isoformat().replace("+00:00", "Z"),
            data=_data(provider, event_id, ordinal),
        )
        for ordinal, (channel, provider, event_id) in enumerate(_DOCUMENTED_EVENT_KEYS, 1)
    ]


def _dataset(event: LogicalWindowsEvent) -> str:
    if event.provider == SYSMON:
        return "windows.sysmon_operational"
    if event.provider == SECURITY:
        return "system.security"
    if event.channel == "System":
        return "system.system"
    if event.channel == "Microsoft-Windows-PowerShell/Operational":
        return "windows.powershell_operational"
    if event.channel == "Windows PowerShell":
        return "windows.powershell"
    if event.channel == "Microsoft-Windows-Windows Defender/Operational":
        return "windows.windows_defender"
    return "winlog.winlog"


def windows_hit(event: LogicalWindowsEvent, shape: Shape) -> dict:
    if shape not in SHAPES:
        raise ValueError(f"unknown Windows fixture shape {shape!r}")
    dataset = _dataset(event)
    native_data = dict(event.data)
    if shape == "elastic_agent" and event.provider == "Microsoft-Windows-Windows Defender":
        # The Windows integration rewrites the native spaced Defender names with underscores.
        for spaced, underscored in (
            ("Threat Name", "Threat_Name"),
            ("Threat ID", "Threat_ID"),
            ("Severity Name", "Severity_Name"),
            ("Category Name", "Category_Name"),
            ("Process Name", "Process_Name"),
            ("Action Name", "Action_Name"),
            ("Old Value", "Old_Value"),
            ("New Value", "New_Value"),
            ("Error Code", "Error_Code"),
        ):
            native_data[underscored] = native_data.pop(spaced)
    source = {
        "@timestamp": event.timestamp,
        "winlog": {
            "channel": event.channel,
            "provider_name": event.provider,
            "event_id": event.event_id,
            "computer_name": event.computer,
            "record_id": event.record_id,
            "time_created": event.timestamp,
            "event_data": native_data,
        },
    }
    if shape == "winlogbeat_7":
        # Older Winlogbeat mappings represented these native unsigned integers as keywords.
        source["winlog"]["event_id"] = str(event.event_id)
        source["winlog"]["record_id"] = str(event.record_id)
        source.update({"agent": {"type": "winlogbeat", "version": "7.17.0"}, "ecs": {"version": "1.12.0"}})
    elif shape == "winlogbeat_8":
        source.update({"agent": {"type": "winlogbeat", "version": "8.19.0"}, "ecs": {"version": "8.17.0"}})
    else:
        source.update({
            "agent": {"type": "filebeat", "version": "8.19.0"},
            "elastic_agent": {"id": "00000000-0000-0000-0000-000000000001"},
            "data_stream": {"type": "logs", "dataset": dataset, "namespace": "default"},
            "ecs": {"version": "8.17.0"},
            "event": {"dataset": dataset},
        })
    slug = re.sub(r"[^a-z0-9]+", "-", event.channel.casefold()).strip("-")
    return {
        "_index": "logs-windows-fixture",
        "_id": f"{slug}-{event.event_id}-{event.record_id}",
        "_source": source,
    }


def windows_xml_hit(event: LogicalWindowsEvent, shape: Shape = "winlogbeat_8") -> dict:
    """Render the event-data payload solely through the shipper's retained native event XML."""
    hit = windows_hit(event, shape)
    winlog = hit["_source"]["winlog"]
    data = winlog.pop("event_data")
    winlog.pop("time_created", None)
    rendered = "".join(
        (f"<Data>{escape(str(value))}</Data>" if event.provider == "PowerShell" and name.startswith("param")
         else f"<Data Name={quoteattr(str(name))}>{escape(str(value))}</Data>")
        for name, value in data.items()
    )
    hit["_source"]["event"] = {
        **hit["_source"].get("event", {}),
        "original": (
            '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
            f"<System><TimeCreated SystemTime={quoteattr(event.timestamp)}/></System>"
            f"<EventData>{rendered}</EventData></Event>"
        ),
    }
    return hit


def semantic_event(event: TypedEvent) -> dict:
    """Typed semantics without evidence identity, which reflects the native shipper representation."""
    value = event.model_dump(mode="json")
    value["id"] = "<native-shape-specific>"
    for raw in value["raw"]:
        raw["digest"] = "<shape-specific>"
    agent_defender_names = {
        "Threat_Name": "Threat Name",
        "Threat_ID": "Threat ID",
        "Severity_Name": "Severity Name",
        "Category_Name": "Category Name",
        "Process_Name": "Process Name",
        "Action_Name": "Action Name",
        "Old_Value": "Old Value",
        "New_Value": "New Value",
        "Error_Code": "Error Code",
    }
    for agent_name, spaced in agent_defender_names.items():
        compact_key = f"windows.event_data.{agent_name}"
        spaced_key = f"windows.event_data.{spaced}"
        if compact_key in value["fields"]:
            value["fields"][spaced_key] = value["fields"].pop(compact_key)
    for field in value["fields"].values():
        field["origin"] = field["origin"].replace("winlog.user_data.", "winlog.event_data.")
        for agent_name, spaced in agent_defender_names.items():
            field["origin"] = field["origin"].replace(f".{agent_name}", f".{spaced}")
    return value


def benign_admin_events() -> list[LogicalWindowsEvent]:
    by_id = {(event.provider, event.event_id): event for event in all_logical_events()}
    return [
        replace(
            by_id[(SECURITY, 4688)],
            record_id=80_001,
            data={**_subject(), "NewProcessId": "0x410", "ProcessId": "0x300",
                  "NewProcessName": r"C:\Windows\System32\mmc.exe",
                  "CommandLine": "mmc.exe compmgmt.msc"},
        ),
        replace(by_id[(SECURITY, 4722)], record_id=80_002),
        replace(by_id[(SECURITY, 4697)], record_id=80_003),
        replace(by_id[(SECURITY, 4698)], record_id=80_004),
    ]


def mission_windows_volume(count: int, *, shape: Shape, seed: int = 1):
    """Yield mission-volume records without retaining an event-count-sized fixture list."""
    if count < 0:
        raise ValueError("count must be non-negative")
    if shape not in SHAPES:
        raise ValueError(f"unknown Windows fixture shape {shape!r}")
    templates = all_logical_events()
    for ordinal in range(count):
        template = templates[(ordinal + seed) % len(templates)]
        host_number = (ordinal + seed) % 200 + 1
        address_number = (ordinal * 17 + seed) % 250 + 1
        data = {
            **template.data,
            "SourceIp": f"192.0.2.{address_number}",
            "DestinationIp": f"198.51.100.{(address_number * 7) % 250 + 1}",
        }
        logical = replace(
            template,
            computer=f"ws{host_number:03d}.example.test",
            record_id=100_000 + ordinal,
            timestamp=(datetime(2026, 1, 2, tzinfo=UTC) + timedelta(milliseconds=ordinal)).isoformat().replace(
                "+00:00", "Z"
            ),
            data=data,
        )
        yield windows_hit(logical, shape)
