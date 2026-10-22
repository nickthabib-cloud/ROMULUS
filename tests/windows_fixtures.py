"""Synthetic Windows telemetry in equivalent Winlogbeat and Elastic Agent shapes."""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from typing import Literal

from romulus.evidence.typed import TypedEvent
from romulus.evidence.windows_catalog import EVENT_CLASSES, SECURITY, SYSMON

Shape = Literal["winlogbeat_7", "winlogbeat_8", "elastic_agent"]
SHAPES: tuple[Shape, ...] = ("winlogbeat_7", "winlogbeat_8", "elastic_agent")


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


def _data(provider: str, event_id: int, ordinal: int) -> dict[str, object]:
    subject = _subject()
    if provider == SYSMON and event_id == 1:
        return {
            "UtcTime": "2026-01-02 03:04:05.000",
            "ProcessGuid": _guid(ordinal),
            "ParentProcessGuid": _guid(ordinal + 10_000),
            "ProcessId": str(1000 + ordinal),
            "ParentProcessId": "700",
            "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "ParentImage": r"C:\Windows\explorer.exe",
            "CommandLine": "powershell.exe -NoProfile -Command Get-Date",
            "User": r"EXAMPLE\analyst",
            "Hashes": "SHA256=ABCDEF0123456789,MD5=0123456789ABCDEF",
        }
    if provider == SYSMON and event_id == 3:
        return {
            "UtcTime": "2026-01-02 03:04:06.000",
            "ProcessGuid": _guid(ordinal),
            "ProcessId": str(1000 + ordinal),
            "Image": r"C:\Windows\System32\svchost.exe",
            "SourceIp": "192.0.2.10",
            "SourcePort": "50100",
            "DestinationIp": "198.51.100.20",
            "DestinationPort": "443",
            "Protocol": "tcp",
            "Initiated": "true",
        }
    if provider == SYSMON and event_id == 5:
        return {
            "UtcTime": "2026-01-02 03:04:07.000",
            "ProcessGuid": _guid(ordinal),
            "ProcessId": str(1000 + ordinal),
            "Image": r"C:\Windows\System32\whoami.exe",
        }
    if event_id == 4688:
        return {
            **subject,
            "NewProcessId": hex(2000 + ordinal),
            "ProcessId": "0x2bc",
            "NewProcessName": r"C:\Windows\System32\whoami.exe",
            "CommandLine": "whoami.exe /groups",
        }
    if event_id == 4689:
        return {**subject, "ProcessId": hex(2000 + ordinal), "ProcessName": r"C:\Windows\System32\whoami.exe"}
    if event_id in {4624, 4625, 4648, 4672, 4634, 4647}:
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
        }
    if event_id in {4720, 4722, 4724, 4726, 4738, 4740}:
        return {
            **subject,
            "TargetUserSid": "S-1-5-21-111-222-333-1200",
            "TargetDomainName": "EXAMPLE",
            "TargetUserName": "example-user",
        }
    if event_id in {4728, 4732, 4756}:
        return {
            **subject,
            "TargetSid": "S-1-5-21-111-222-333-512",
            "TargetDomainName": "EXAMPLE",
            "TargetUserName": "Example Operators",
            "MemberSid": "S-1-5-21-111-222-333-1200",
            "MemberName": r"EXAMPLE\example-user",
        }
    if event_id in {7045, 4697}:
        return {
            **subject,
            "ServiceName": "Example Inventory Service",
            "ImagePath": r"C:\Program Files\Example\inventory.exe --service",
            "ServiceFileName": r"C:\Program Files\Example\inventory.exe --service",
            "ServiceType": "user mode service",
            "StartType": "demand start",
            "AccountName": r"NT AUTHORITY\LocalService",
        }
    if event_id in {4698, 4702}:
        return {
            **subject,
            "TaskName": r"\Example\Inventory",
            "TaskContent": "<Task><Actions><Exec><Command>inventory.exe</Command></Exec></Actions></Task>",
        }
    if event_id == 4719:
        return {**subject, "SubcategoryGuid": _guid(ordinal), "AuditPolicyChanges": "Success added"}
    if event_id in {1102, 104}:
        return subject
    return {}


def all_logical_events() -> list[LogicalWindowsEvent]:
    start = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
    return [
        LogicalWindowsEvent(
            channel=event.channel,
            provider=event.provider,
            event_id=event.event_id,
            computer="ws01.example.test",
            record_id=10_000 + ordinal,
            timestamp=(start + timedelta(seconds=ordinal)).isoformat().replace("+00:00", "Z"),
            data=_data(event.provider, event.event_id, ordinal),
        )
        for ordinal, event in enumerate(EVENT_CLASSES, 1)
    ]


def _dataset(event: LogicalWindowsEvent) -> str:
    if event.provider == SYSMON:
        return "windows.sysmon_operational"
    if event.provider == SECURITY:
        return "system.security"
    return "system.system"


def windows_hit(event: LogicalWindowsEvent, shape: Shape) -> dict:
    if shape not in SHAPES:
        raise ValueError(f"unknown Windows fixture shape {shape!r}")
    dataset = _dataset(event)
    source = {
        "@timestamp": event.timestamp,
        "event": {"dataset": dataset},
        "winlog": {
            "channel": event.channel,
            "provider_name": event.provider,
            "event_id": event.event_id,
            "computer_name": event.computer,
            "record_id": event.record_id,
            "time_created": event.timestamp,
            "event_data": dict(event.data),
        },
    }
    if shape == "winlogbeat_7":
        source.update({"agent": {"type": "winlogbeat", "version": "7.17.0"}, "ecs": {"version": "1.12.0"}})
    elif shape == "winlogbeat_8":
        source.update({"agent": {"type": "winlogbeat", "version": "8.19.0"}, "ecs": {"version": "8.17.0"}})
    else:
        source.update({
            "agent": {"type": "filebeat", "version": "8.19.0"},
            "elastic_agent": {"id": "00000000-0000-0000-0000-000000000001"},
            "data_stream": {"type": "logs", "dataset": dataset, "namespace": "default"},
            "ecs": {"version": "8.17.0"},
        })
    slug = re.sub(r"[^a-z0-9]+", "-", event.channel.casefold()).strip("-")
    return {
        "_index": "logs-windows-fixture",
        "_id": f"{slug}-{event.event_id}-{event.record_id}",
        "_source": source,
    }


def semantic_event(event: TypedEvent) -> dict:
    """Full typed result except the raw-byte digest, which intentionally differs by shipper envelope."""
    value = event.model_dump(mode="json")
    for raw in value["raw"]:
        raw["digest"] = "<shape-specific>"
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
