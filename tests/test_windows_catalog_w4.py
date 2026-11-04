"""Native Application and ETW field contracts, including malformed lookalikes."""
import pytest

from romulus.evidence.windows import normalize_windows
from romulus.evidence.windows_catalog import SECURITY, collection_requirements, lookup_event_class
from tests.windows_fixtures import LogicalWindowsEvent, windows_hit


def native(channel, provider, code, data):
    return normalize_windows(windows_hit(LogicalWindowsEvent(
        channel, provider, code, "host.example.test", 101, "2026-01-02T03:04:05Z", data),
        "winlogbeat_8_real"))


@pytest.mark.parametrize("channel,provider,code,data,key,value", [
    ("Application", "Microsoft-Windows-ProcessExitMonitor", 3001, {"param1": r"C:\Windows\System32\lsass.exe", "param3": "0"}, "monitor.exit_code", 0),
    ("Application", "MSSQL$INSTANCE", 15457, {"param1": "xp_cmdshell", "param2": "0", "param3": "1"}, "db.option.new", "1"),
    ("Security", "MSSQLSERVER$AUDIT", 33205, {"param1": "action_id:EX  \nsucceeded:true\nstatement:exec x 'https://example.test/a'\nobject_name:xp_cmdshell"}, "db.audit.succeeded", True),
    ("Security", SECURITY, 4826, {"KernelDebug": "%%1842", "TestSigning": "%%1843"}, "boot.kernel_debug", True),
    ("Application", "ESENT", 326, {"param1": "NTDS", "param2": "42", "param5": r"C:\Copy\ntds.dit"}, "ese.pid", 42),
    ("Microsoft-Windows-Winsock-WS2HELP/Operational", "Microsoft-Windows-Winsock-WS2HELP", 1, {"LSPName": "Test LSP", "Installer": "test.exe"}, "lsp.name", "Test LSP"),
    ("Application", "MsiInstaller", 1040, {"param1": "https://example.test/a.msi", "param2": "42"}, "msi.package_kind", "url"),
    ("Microsoft-Windows-Application-Experience/Program-Compatibility-Assistant", "Microsoft-Windows-Program-Compatibility-Assistant", 17, {"ExePath": r"C:\Users\test\Downloads\a.cpl", "ResolverName": "ControlPanelApplet"}, "compat.action", "resolver_fired"),
    ("Security", SECURITY, 4799, {"TargetSid": "S-1-5-32-544", "CallerProcessId": "0x2a"}, "enum.caller_pid", 42),
    ("Security", SECURITY, 4703, {"EnabledPrivilegeList": "SeDebugPrivilege\n\tSeBackupPrivilege"}, "privilege.enabled", ["SeDebugPrivilege", "SeBackupPrivilege"]),
    ("System", "Microsoft-Windows-DistributedCOM", 10016, {"param2": "Remote", "param3": "Launch"}, "dcom.scope", "Remote"),
    ("System", "Service Control Manager", 7036, {"param1": "Example", "param2": "running"}, "service.state", "running"),
])
def test_new_native_field_contract(channel, provider, code, data, key, value):
    event = native(channel, provider, code, data)
    assert event.get(key) == value
    assert event.host == "host" and event.get("host.full_name") == "host.example.test"
    assert event.get("user.name") != "SYSTEM"


def test_wfp_orientation_keeps_recorded_endpoints():
    event = native("Security", SECURITY, 5156, {"Direction": "%%14592", "SourceAddress": "192.0.2.2", "DestAddress": "127.0.0.2", "SourcePort": "52", "DestPort": "3389", "Protocol": "6", "Application": "test.exe"})
    assert event.get("network.direction") == "ingress"
    assert event.get("source.ip") == "192.0.2.2"
    assert event.get("network.local_address") == "127.0.0.2"
    assert event.get("destination.is_loopback") is True


@pytest.mark.parametrize("address,ip,port", [("192.0.2.2:42", "192.0.2.2", 42), ("[2001:db8::2]:43", "2001:db8::2", 43), ("[192.0.2.2]:44", "192.0.2.2", 44)])
def test_rdp_envelope_and_endpoint(address, ip, port):
    event = native("Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational", "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS", 131, {"ClientIP": address})
    assert event.get("source.ip") == ip and event.get("source.port") == port
    assert event.get("process.pid") == 412
    assert event.get("process.actor_sid") == "S-1-5-18"


def test_malformed_native_values_are_named_not_fabricated():
    event = native("Security", SECURITY, 5156, {"DestPort": "bad", "SourceAddress": "bad", "Direction": "%%99999"})
    assert not event.has("destination.port") and not event.has("source.ip")
    assert event.caveats
    event = native("Security", SECURITY, 4826, {"KernelDebug": "%%99999"})
    assert not event.has("boot.kernel_debug") and event.get("boot.kernel_debug.raw") == "%%99999"
    assert event.caveats


def test_provider_prefix_is_application_only_and_documented():
    assert lookup_event_class("System", "MSSQL$INSTANCE", 15457) is None
    assert lookup_event_class("Application", "MSSQLunrelated", 15457) is None
    row = lookup_event_class("Application", "MSSQL$INSTANCE", 15457)
    assert row is not None and row.provider == "MSSQL$INSTANCE"
    assert collection_requirements(row) == (("application_event_log", {}, "Windows Application event log"),)


@pytest.mark.parametrize("port", ["03389", " 3389", "0xd3d", "-1", "65536", {}, []])
def test_wfp_port_contract_matches_server_filter(port):
    event = native("Security", SECURITY, 5156, {"DestPort": port})
    assert not event.has("destination.port")
    assert event.caveats


def test_sam_access_codes_are_object_specific_and_lossless():
    event = native("Security", SECURITY, 4661, {"ObjectType": "SAM_USER", "AccessList": "%%5440 %%5448", "AccessMask": "0x2d"})
    assert event.get("object.accesses") == ["ReadGeneralInformation", "ListGroups"]
    assert event.get("object.access_codes") == ["%%5440", "%%5448"]
    event = native("Security", SECURITY, 4661, {"ObjectType": "SAM_DOMAIN", "AccessList": "%%5400"})
    assert event.get("object.accesses") == ["ListAccounts"]


def test_boot_malformed_container_does_not_crash():
    event = native("Security", SECURITY, 4826, {"KernelDebug": {"unexpected": True}})
    assert event.caveats and not event.has("boot.kernel_debug")


def test_database_audit_outcome_follows_recorded_success_flag():
    event = native("Security", "MSSQLSERVER$AUDIT", 33205, {"param1": "action_id:EX\nsucceeded:false\nobject_name:xp_cmdshell"})
    assert event.outcome.value == "failure"
    event = native("Security", "MSSQLSERVER$AUDIT", 33205, {"param1": "action_id:EX\nobject_name:xp_cmdshell"})
    assert event.outcome.value == "unknown"


def test_native_message_and_guid_fields_are_decoded():
    event = native("Security", SECURITY, 5156, {"LayerName": "%%14610"})
    assert event.get("wfp.layer") == "Receive/Accept"
    event = native("Security", SECURITY, 4826, {"ConfigAccessPolicy": "%%1846", "VsmLaunchType": "%%1848"})
    assert event.get("boot.config_access_policy") == "Default"
    assert event.get("boot.vsm_launch_type") == "Off"
    event = native("System", "Microsoft-Windows-DistributedCOM", 10016, {"param4": "{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}"})
    assert event.get("dcom.clsid") == "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


@pytest.mark.parametrize("payload", [
    "EXEC xp_cmdshell 'whoami' /*\nobject_name:other_proc\naction_id:LGIS\nsucceeded:false\n*/",
    "EXEC xp_cmdshell 'whoami'\n-- comment\nobject_name:other_proc\nstatement:replacement",
])
def test_sql_statement_cannot_overwrite_native_audit_metadata(payload):
    from romulus.detect.windows_catalog_events import MssqlXpCmdshellExec

    event = native("Application", "MSSQLSERVER", 33205, {"param1":
        "action_id:EX\nsucceeded:true\nobject_name:xp_cmdshell\nstatement:" + payload})
    assert event.get("db.audit.action_id") == "EX"
    assert event.get("db.audit.object_name") == "xp_cmdshell"
    assert event.get("db.audit.succeeded") is True
    assert event.get("db.audit.statement") == payload
    rule = MssqlXpCmdshellExec()
    try:
        assert [finding.lane for finding in rule.judge(event)] == ["high"]
    finally:
        rule.release_state()


def test_rdp_connection_identity_only_comes_from_envelope():
    channel = "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational"
    provider = "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS"
    logical = LogicalWindowsEvent(channel, provider, 148, "host.example.test", 102,
                                  "2026-01-02T03:04:05Z", {"ConnectionActivity": "borrowed-session"})
    hit = windows_hit(logical, "winlogbeat_8_real")
    assert not normalize_windows(hit).has("remote.connection_activity")
    hit["_source"]["winlog"]["activity_id"] = "authentic-session"
    event = normalize_windows(hit)
    assert event.get("remote.connection_activity") == "authentic-session"
    assert event.fields["remote.connection_activity"].origin.endswith(":winlog.activity_id")


@pytest.mark.parametrize("field,typed", [("SourceAddress", "source.ip"), ("DestAddress", "destination.ip")])
@pytest.mark.parametrize("address", [" 127.0.0.1", "\t::1", "127.0.0.1 ", "::1\n"])
def test_wfp_address_contract_rejects_surrounding_whitespace(field, typed, address):
    event = native("Security", SECURITY, 5156, {field: address})
    assert not event.has(typed)
    assert event.caveats


def test_wfp_expanded_ipv6_remains_a_supported_loopback():
    event = native("Security", SECURITY, 5156, {"DestAddress": "0:0:0:0:0:0:0:1", "DestPort": "3389"})
    assert event.get("destination.ip") == "::1"
    assert event.get("destination.is_loopback") is True


def test_payload_activity_cannot_borrow_another_connections_ip_in_sweep(tmp_path, monkeypatch):
    from tests.test_windows_catalog_state_w4 import CHANNEL, RDP, sweep_run
    from tests.test_windows_catalog_state_w4 import native as state_native

    connection = state_native(131, {"ClientIP": "192.0.2.8:44333"}, provider=RDP, channel=CHANNEL, activity="session")
    observed = state_native(148, {"ChannelName": "ms_t120", "TunnelID": "0", "ConnectionActivity": "session"}, 2,
                            provider=RDP, channel=CHANNEL, offset=1)
    findings, _rule = sweep_run(tmp_path, monkeypatch, "RdpBluekeepChannel", [[connection], [observed]])
    assert findings and all("192.0.2.8" not in finding["claim"] for finding in findings)
    assert not observed[0].has("remote.connection_activity")


@pytest.mark.parametrize("pid_alias,sid_alias", [
    ("EnvelopeProcessId", "EnvelopeActorSid"), ("envelopeprocessid", "ENVELOPEACTORSID"),
])
def test_payload_envelope_aliases_cannot_fabricate_process_context(pid_alias, sid_alias):
    logical = LogicalWindowsEvent("Application", "Microsoft-Windows-ProcessExitMonitor", 3001,
                                  "host.example.test", 102, "2026-01-02T03:04:05Z", {
                                      pid_alias: "9001", sid_alias: "S-1-5-21-1-2-3-999",
                                      "ConnectionActivity": "forged"})
    hit = windows_hit(logical, "winlogbeat_8_real")
    winlog = hit["_source"]["winlog"]
    winlog.pop("process")
    winlog.pop("user")
    event = normalize_windows(hit)
    assert not event.has("process.pid") and not event.has("process.actor_sid")
    winlog["process"] = {"pid": 42}
    winlog["user"] = {"identifier": "S-1-5-18"}
    event = normalize_windows(hit)
    assert event.get("process.pid") == 42 and event.get("process.actor_sid") == "S-1-5-18"
    assert event.fields["process.pid"].origin.endswith(":winlog.process.pid")
    assert event.fields["process.actor_sid"].origin.endswith(":winlog.user.identifier")


def test_genuine_family_process_id_survives_reserved_alias_sanitization():
    event = native("Security", SECURITY, 4703, {"ProcessId": "0x2a", "EnvelopeProcessId": "9001"})
    assert event.get("process.pid") == 42
