"""Typed Windows families, semantic fields, and stable identity primitives."""

from __future__ import annotations

import pytest

from romulus.evidence.normalize import normalize_hits
from romulus.evidence.windows import WINDOWS_NORMALIZER, windows_path_key
from romulus.evidence.windows_catalog import SECURITY, SYSMON, SYSMON_CHANNEL


def _hit(
    event_id: int,
    *,
    channel: str = "Security",
    provider: str = SECURITY,
    data: dict | None = None,
    computer: str = "WS01.Example.Test.",
    host_name: str = "forwarder.example.test",
    native_id: str | None = None,
):
    return {
        "_index": "logs-windows",
        "_id": native_id or f"event-{event_id}",
        "_source": {
            "@timestamp": "2026-01-02T03:04:05Z",
            "agent": {"type": "winlogbeat"},
            "event": {"dataset": "system.security"},
            "host": {"name": host_name},
            "winlog": {
                "channel": channel,
                "provider_name": provider,
                "event_id": event_id,
                "computer_name": computer,
                "record_id": event_id + 1000,
                "event_data": data or {},
            },
        },
    }


EVENT_FAMILIES = {
    4688: "process_exec",
    4689: "process_termination",
    4624: "auth",
    4625: "auth",
    4648: "auth",
    4672: "auth",
    4634: "auth",
    4647: "auth",
    4720: "account_change",
    4722: "account_change",
    4724: "account_change",
    4726: "account_change",
    4728: "account_change",
    4732: "account_change",
    4756: "account_change",
    4738: "account_change",
    4740: "account_change",
    4697: "service_change",
    4698: "scheduled_task",
    4702: "scheduled_task",
    1102: "audit_config",
    4719: "audit_config",
}


@pytest.mark.parametrize(("event_id", "family"), EVENT_FAMILIES.items())
def test_security_event_catalog_rows_normalize_to_their_typed_families(event_id, family):
    events, skips, errors = normalize_hits([_hit(event_id)])

    assert skips == {} and errors == [] and len(events) == 1
    assert events[0].family == family
    assert events[0].normalizer == WINDOWS_NORMALIZER
    assert events[0].get("host.os.family") == "windows"


@pytest.mark.parametrize(
    ("event_id", "family"),
    [(1, "process_exec"), (3, "net_socket"), (5, "process_termination")],
)
def test_sysmon_event_catalog_rows_normalize_to_their_typed_families(event_id, family):
    event = normalize_hits(
        [_hit(event_id, channel=SYSMON_CHANNEL, provider=SYSMON, data={"UtcTime": "2026-01-02 03:04:04.000"})]
    )[0][0]

    assert event.family == family and event.normalizer == WINDOWS_NORMALIZER


@pytest.mark.parametrize(
    ("event_id", "provider", "family", "system_event"),
    [
        (7045, "Service Control Manager", "service_change", None),
        (104, "Microsoft-Windows-Eventlog", "audit_config", None),
        (12, "Microsoft-Windows-Kernel-General", "system_state", "boot_start"),
        (13, "Microsoft-Windows-Kernel-General", "system_state", "boot_stop"),
        (6005, "EventLog", "system_state", "boot_start"),
        (6006, "EventLog", "system_state", "boot_stop"),
    ],
)
def test_system_event_catalog_rows_include_boot_fences(event_id, provider, family, system_event):
    event = normalize_hits([_hit(event_id, channel="System", provider=provider)])[0][0]

    assert event.family == family
    if system_event:
        assert event.get("system.event") == system_event
        assert event.get("process.fence") == "boot"


def test_host_identity_uses_computer_name_and_keeps_short_and_full_forms():
    event = normalize_hits([_hit(4624)])[0][0]

    assert event.host == "ws01"
    assert event.get("host.name") == "ws01"
    assert event.get("host.full_name") == "ws01.example.test"
    assert event.get("winlog.computer_name") == "ws01.example.test"
    assert "forwarder" not in event.model_dump_json()


def test_structured_winlog_time_created_is_the_typed_event_time():
    hit = _hit(4624)
    hit["_source"]["winlog"]["time_created"] = "2026-01-02T03:04:03.000Z"

    event = normalize_hits([hit])[0][0]

    assert event.ts.isoformat() == "2026-01-02T03:04:03+00:00"
    assert event.get("event.created") == "2026-01-02T03:04:03+00:00"
    assert event.fields["event.created"].origin.endswith("winlog.time_created")


def test_process_identity_prefers_guid_and_4688_uses_a_fenced_pid_key():
    sysmon = normalize_hits(
        [
            _hit(
                1,
                channel=SYSMON_CHANNEL,
                provider=SYSMON,
                data={
                    "ProcessGuid": "{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}",
                    "ParentProcessGuid": "{11111111-2222-3333-4444-555555555555}",
                    "ProcessId": "512",
                    "Image": r"C:\Windows\System32\CMD.EXE",
                },
            )
        ]
    )[0][0]
    fallback = normalize_hits(
        [_hit(4688, data={"NewProcessId": "0x200", "NewProcessName": r"C:\Windows\System32\cmd.exe"})]
    )[0][0]

    assert sysmon.get("process.entity_id") == "guid:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    assert sysmon.get("process.parent.entity_id") == "guid:11111111-2222-3333-4444-555555555555"
    assert fallback.get("process.pid") == 512
    assert fallback.get("process.entity_id") == "pid:ws01:512"
    assert fallback.get("process.id_kind") == "fenced_pid"


@pytest.mark.parametrize("guid", ["not-a-guid", "{00000000-0000-0000-0000-000000000000}"])
def test_unusable_process_guids_fall_back_to_the_fenced_pid(guid):
    event = normalize_hits(
        [_hit(1, channel=SYSMON_CHANNEL, provider=SYSMON, data={"ProcessGuid": guid, "ProcessId": "512"})]
    )[0][0]

    assert event.get("process.guid") is None
    assert event.get("process.entity_id") == "pid:ws01:512"
    assert event.get("process.id_kind") == "fenced_pid"


def test_termination_and_boot_events_are_explicit_pid_reuse_fences():
    termination = normalize_hits([_hit(4689, data={"ProcessId": "0x200"})])[0][0]
    boot = normalize_hits([_hit(6005, channel="System", provider="EventLog")])[0][0]

    assert termination.get("process.entity_id") == "pid:ws01:512"
    assert termination.get("process.fence") == "termination"
    assert boot.get("process.fence") == "boot"


def test_accounts_are_sid_first_then_domain_name_case_insensitively():
    sid = normalize_hits(
        [_hit(4624, data={"TargetUserSid": "S-1-5-21-1-2-3-1001", "TargetDomainName": "EXAMPLE", "TargetUserName": "Alice"})]
    )[0][0]
    name = normalize_hits(
        [_hit(4624, data={"TargetDomainName": "EXAMPLE", "TargetUserName": "Alice"})]
    )[0][0]

    assert sid.get("auth.target_account") == "sid:s-1-5-21-1-2-3-1001"
    assert name.get("auth.target_account") == r"name:example\alice"


@pytest.mark.parametrize("sid", ["not-a-sid", "s-1-0-0"])
def test_invalid_and_sentinel_sids_fall_back_to_name_with_name_lineage(sid):
    event = normalize_hits([_hit(4624, data={
        "TargetUserSid": sid,
        "TargetDomainName": "EXAMPLE",
        "TargetUserName": "Alice",
    })])[0][0]

    assert event.get("auth.target_account") == r"name:example\alice"
    assert event.fields["auth.target_account"].origin.endswith("TargetUserName")


def test_sysmon_process_user_is_a_case_insensitive_account_identity():
    event = normalize_hits(
        [
            _hit(
                1,
                channel=SYSMON_CHANNEL,
                provider=SYSMON,
                data={"ProcessId": "512", "User": r"EXAMPLE\Alice"},
            )
        ]
    )[0][0]

    assert event.get("user.entity_id") == r"name:example\alice"
    assert event.get("user.domain") == "example"
    assert event.get("user.name") == "alice"
    assert ("account", r"name:example\alice", "actor") in event.entities()


def test_sessions_are_host_scoped_and_keep_logon_guid():
    event = normalize_hits(
        [_hit(4624, data={"TargetLogonId": "0x4A", "LogonGuid": "{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}"})]
    )[0][0]

    assert event.get("auth.session_id") == "0x4a"
    assert event.get("auth.session_key") == "ws01:0x4a"
    assert event.get("auth.logon_guid") == "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


def test_process_network_service_task_and_audit_fields_are_semantic_and_typed():
    process = normalize_hits(
        [_hit(4688, data={"CommandLine": "cmd.exe /c whoami", "NewProcessName": r"C:\Windows\cmd.exe"})]
    )[0][0]
    network = normalize_hits(
        [
            _hit(
                3,
                channel=SYSMON_CHANNEL,
                provider=SYSMON,
                data={"SourceIp": "192.0.2.10", "SourcePort": "49152", "DestinationIp": "198.51.100.7", "DestinationPort": "443"},
            )
        ]
    )[0][0]
    service = normalize_hits([_hit(7045, channel="System", provider="Service Control Manager", data={"ServiceName": "ExampleSvc", "ImagePath": r"C:\Tools\svc.exe"})])[0][0]
    task = normalize_hits([_hit(4698, data={"TaskName": r"\Example\Task", "TaskContent": "<Task/>"})])[0][0]
    audit = normalize_hits([_hit(4719, data={"SubcategoryGuid": "{abc}", "AuditPolicyChanges": "Success added"})])[0][0]

    assert process.get("process.command_line") == "cmd.exe /c whoami"
    assert process.get("process.executable_key") == r"c:\windows\cmd.exe"
    assert network.get("source.ip") == "192.0.2.10" and network.get("destination.port") == 443
    assert service.get("service.name") == "ExampleSvc" and service.get("service.image_path") == r"C:\Tools\svc.exe"
    assert task.get("task.name") == r"\Example\Task" and task.get("task.xml") == "<Task/>"
    assert audit.get("audit.config.action") == "audit_policy_changed"


def test_windows_paths_compare_case_insensitively_without_changing_display_value():
    assert windows_path_key(r"C:\Windows\System32\CMD.EXE") == windows_path_key(
        r"c:\windows\system32\cmd.exe"
    )
