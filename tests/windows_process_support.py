"""Helpers for the Windows process-rule tests: build typed process-creation records from the fixture factory."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from romulus.evidence.windows import normalize_windows
from romulus.evidence.windows_catalog import SECURITY, SYSMON, SYSMON_CHANNEL
from tests.windows_fixtures import LogicalWindowsEvent, windows_hit

_START = datetime(2026, 1, 2, 3, 0, 0, tzinfo=UTC)
_record_id = iter(range(500_000, 999_999))


def _guid(n: int) -> str:
    return f"{{00000000-0000-0000-0000-{n:012x}}}"


def sysmon1(*, image, command, host="ws01.example.test", parent_image=None, pid=1200, ppid=700,
            guid=1, parent_guid=2, offset=0, computer=None, shape="elastic_agent"):
    data = {
        "UtcTime": (_START + timedelta(seconds=offset)).strftime("%Y-%m-%d %H:%M:%S.000"),
        "ProcessGuid": _guid(guid), "ParentProcessGuid": _guid(parent_guid),
        "ProcessId": str(pid), "ParentProcessId": str(ppid), "Image": image, "CommandLine": command,
    }
    if parent_image is not None:
        data["ParentImage"] = parent_image
    event = LogicalWindowsEvent(SYSMON_CHANNEL, SYSMON, 1, computer or host, next(_record_id),
                                (_START + timedelta(seconds=offset)).isoformat().replace("+00:00", "Z"), data)
    return normalize_windows(windows_hit(event, shape))


def security4688(*, image, command, host="ws01.example.test", pid=0x2bc, ppid=0x300, offset=0,
                 computer=None, shape="elastic_agent"):
    data = {
        "SubjectUserSid": "S-1-5-21-1-2-3-1001", "SubjectDomainName": "EXAMPLE", "SubjectUserName": "analyst",
        "SubjectLogonId": "0x44", "NewProcessId": hex(pid), "ProcessId": hex(ppid),
        "NewProcessName": image, "CommandLine": command,
    }
    event = LogicalWindowsEvent("Security", SECURITY, 4688, computer or host, next(_record_id),
                                (_START + timedelta(seconds=offset)).isoformat().replace("+00:00", "Z"), data)
    return normalize_windows(windows_hit(event, shape))


def security4689(*, image, host="ws01.example.test", pid=0x2bc, offset=0):
    data = {"ProcessId": hex(pid), "ProcessName": image, "SubjectUserSid": "S-1-5-21-1-2-3-1001"}
    event = LogicalWindowsEvent("Security", SECURITY, 4689, host, next(_record_id),
                                (_START + timedelta(seconds=offset)).isoformat().replace("+00:00", "Z"), data)
    return normalize_windows(windows_hit(event, "elastic_agent"))


def system_boot(*, host="ws01.example.test", offset=0):
    event = LogicalWindowsEvent("System", "Microsoft-Windows-Kernel-General", 12, host, next(_record_id),
                                (_START + timedelta(seconds=offset)).isoformat().replace("+00:00", "Z"), {})
    return normalize_windows(windows_hit(event, "elastic_agent"))


def run(rule, events):
    """Consume one or more batches and finalize; return all published matches.

    Binds a loader that resolves every event the batches carried, so a finalize that cites staged records (the
    fleet rollup) can read them back exactly as the sweep's event stage would.
    """
    batches = [list(events)] if events and not isinstance(events[0], list) else [list(b) for b in events]
    by_id = {event.id: event for batch in batches for event in batch}
    rule.load = lambda ids: [by_id[i] for i in ids if i in by_id]
    matches: list = []
    for batch in batches:
        matches.extend(rule.consume(batch))
        rule.drain_staged()
        rule.drain_bounds()
    matches.extend(rule.finalize())
    # A fleet finding is emitted when it first forms (during consume) and again at finalize with final counts; both
    # carry the same group_key, and the candidate store keeps one per key. Mirror that: keep the last per non-empty
    # group_key, and every per-record finding (empty group_key) as-is.
    deduped: list = []
    latest: dict = {}
    for match in matches:
        if not match.group_key:
            deduped.append(match)
            continue
        key = (match.playbook_id, match.group_key)
        if key in latest:
            deduped[latest[key]] = match
        else:
            latest[key] = len(deduped)
            deduped.append(match)
    return deduped
