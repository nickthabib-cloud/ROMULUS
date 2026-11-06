"""Synthetic source records prove that Sigma mappings use real typed fields."""
from dataclasses import replace

import pytest

from romulus.evidence.normalize import normalize_hits
from romulus.evidence.windows_catalog import (
    POWERSHELL_CHANNEL,
    POWERSHELL_PROVIDER,
    SECURITY,
    SYSMON,
    SYSMON_CHANNEL,
)
from tests.test_evidence import EXECVE_HEX, SYSCALL, hit
from tests.test_network_normalizers import eve, one
from tests.windows_fixtures import LogicalWindowsEvent, windows_hit

WINDOWS_ROWS = [
    ({"category": "process_creation"}, 1, SYSMON_CHANNEL, SYSMON, "Image", "process.executable"),
    ({"category": "network_connection"}, 3, SYSMON_CHANNEL, SYSMON, "DestinationHostname", "destination.hostname"),
    ({"category": "file_event"}, 11, SYSMON_CHANNEL, SYSMON, "TargetFilename", "file.path"),
    ({"category": "registry_event"}, 13, SYSMON_CHANNEL, SYSMON, "TargetObject", "registry.path"),
    ({"category": "registry_add"}, 12, SYSMON_CHANNEL, SYSMON, "TargetObject", "registry.path"),
    ({"category": "registry_delete"}, 12, SYSMON_CHANNEL, SYSMON, "TargetObject", "registry.path"),
    ({"category": "registry_set"}, 13, SYSMON_CHANNEL, SYSMON, "Details", "registry.value"),
    ({"category": "registry_rename"}, 14, SYSMON_CHANNEL, SYSMON, "NewName", "registry.new_path"),
    ({"category": "image_load"}, 7, SYSMON_CHANNEL, SYSMON, "ImageLoaded", "image.path"),
    ({"category": "driver_load"}, 6, SYSMON_CHANNEL, SYSMON, "ImageLoaded", "image.path"),
    ({"category": "pipe_created"}, 17, SYSMON_CHANNEL, SYSMON, "PipeName", "pipe.name"),
    ({"category": "dns_query"}, 22, SYSMON_CHANNEL, SYSMON, "QueryName", "dns.question.name"),
    ({"category": "ps_script"}, 4104, POWERSHELL_CHANNEL, POWERSHELL_PROVIDER, "ScriptBlockText", "script.text"),
    ({"service": "security"}, 4697, "Security", SECURITY, "ServiceName", "service.name"),
    ({"service": "system"}, 7045, "System", "Service Control Manager", "ServiceName", "service.name"),
    ({"service": "sysmon"}, 1, SYSMON_CHANNEL, SYSMON, "Image", "process.executable"),
    ({"service": "powershell"}, 4104, POWERSHELL_CHANNEL, POWERSHELL_PROVIDER, "ScriptBlockText", "script.text"),
]


@pytest.mark.parametrize("shape", ["winlogbeat_8", "elastic_agent"])
@pytest.mark.parametrize(("source", "code", "channel", "provider", "native", "typed"), WINDOWS_ROWS)
def test_every_windows_mapping_row_has_real_positive_and_benign_typed_records(
        shape, source, code, channel, provider, native, typed):
    from romulus.content.sigma_mapping import map_rule
    source = {"product": "windows", **source}
    mapping = map_rule(source, {"selection": {native: "probe-value"}})
    assert mapping["reasons"] == []
    target = mapping["fields"][native]
    assert target == typed or isinstance(target, list) and typed in target
    assert mapping["rationale"]
    assert [channel, provider, code] in mapping["windows_event_classes"]
    base = LogicalWindowsEvent(channel, provider, code, "ws01", 1, "2026-01-02T03:04:05Z",
                               {native: "probe-value", "ProcessId": "123", "EventType": (
                                   "DeleteKey" if source.get("category") == "registry_delete" else "CreateKey")})
    events = []
    for value in ("probe-value", "benign-value"):
        event = one(windows_hit(replace(base, data={**base.data, native: value}), shape))
        assert event.family in mapping["families"]
        assert str(code) in mapping["event_codes"]
        assert event.get(typed) == value
        assert event.fields[typed].origin
        events.append(event)
    assert events[0].get(typed) == "probe-value"
    assert events[1].get(typed) != "probe-value"
    ast = _ast(source, native, "probe-value")
    from romulus.content.sigma_parser import evaluate_ast
    assert evaluate_ast(ast, events[0]) == (True, [typed])
    assert evaluate_ast(ast, events[1]) == (False, [])


@pytest.mark.parametrize("source", [{"product": "linux", "category": "process_creation"},
                                   {"product": "linux", "service": "auditd"},
                                   {"product": "linux", "category": "auditd"}])
def test_linux_rows_use_real_auditd_executable_and_reject_untyped_commandline(source):
    from romulus.content.sigma_mapping import map_rule
    mapping = map_rule(source, {"selection": {"Image": "/usr/bin/dash"}})
    assert mapping["reasons"] == []
    assert mapping["fields"]["Image"] == "process.executable"
    assert mapping["scope"] == [{"field": "audit.time", "exists": True}]
    from romulus.content.sigma_parser import evaluate_ast
    ast = _ast(source, "Image", "/usr/bin/dash")
    for executable in ("/usr/bin/dash", "/usr/bin/benign"):
        events, _, errors = normalize_hits([hit("exec", "linux.audit", EXECVE_HEX),
            hit("sys", "linux.audit", SYSCALL.replace('/usr/bin/dash', executable))])
        assert errors == []
        assert events[0].family in mapping["families"]
        assert events[0].has("audit.time") and events[0].get("process.executable") == executable
        assert evaluate_ast(ast, events[0])[0] == (executable == "/usr/bin/dash")
    rejected = map_rule(source, {"selection": {"CommandLine|contains": "dash -c"}})
    assert any("CommandLine" in reason for reason in rejected["reasons"])


@pytest.mark.parametrize(("category", "native", "record", "typed", "expected"), [
    ("dns", "query", {"event_type": "dns", "dns": {"type": "query", "rrname": "probe.example", "rrtype": "A"}},
        "dns.question.name", "probe.example"),
    ("proxy", "cs-method", {"event_type": "http", "http": {"http_method": "POST", "url": "/probe"}},
        "http.request.method", "POST"),
    ("firewall", "dst_ip", {"event_type": "flow", "dest_ip": "192.0.2.10", "flow": {"state": "closed"}},
        "destination.ip", "192.0.2.10"),
])
def test_generic_network_rows_have_positive_and_benign_native_fields(category, native, record, typed, expected):
    from romulus.content.sigma_mapping import map_rule
    mapping = map_rule({"category": category}, {"selection": {native: expected}})
    assert mapping["reasons"] == [] and mapping["fields"][native] == typed
    positive = one(eve("positive", record))
    assert positive.family in mapping["families"]
    assert positive.get(typed) == expected
    from romulus.content.sigma_parser import evaluate_ast
    ast = _ast({"category": category}, native, expected)
    assert evaluate_ast(ast, positive) == (True, [typed])
    benign = {"dns": {"type": "query", "rrname": "benign.example", "rrtype": "A"}} if category == "dns" else (
        {"http": {"http_method": "GET", "url": "/"}} if category == "proxy" else {"dest_ip": "192.0.2.11"})
    benign_event = one(eve("benign", {**record, **benign}))
    assert benign_event.get(typed) != expected
    assert evaluate_ast(ast, benign_event) == (False, [])


@pytest.mark.parametrize("shape", ["winlogbeat_8", "elastic_agent"])
@pytest.mark.parametrize(("native", "typed", "value"), [
    ("Image", "process.executable", r"C:\Tools\probe.exe"),
    ("CommandLine", "process.command_line", "probe.exe /inventory"),
    ("ParentImage", "process.parent.executable", r"C:\Windows\explorer.exe"),
    ("ParentCommandLine", "process.parent.command_line", "explorer.exe"),
    ("OriginalFileName", "process.original_file_name", "probe.exe"),
    ("User", "process.user", "EXAMPLE\\analyst"),
    ("IntegrityLevel", "process.integrity_level", "high"),
    ("ProcessId", "process.pid", 123),
])
def test_process_field_mapping_keeps_each_native_role(shape, native, typed, value):
    from romulus.content.sigma_mapping import map_rule
    mapping = map_rule({"product": "windows", "category": "process_creation"}, {"s": {native: value}})
    event = LogicalWindowsEvent(SYSMON_CHANNEL, SYSMON, 1, "ws01", 1,
        "2026-01-02T03:04:05Z", {native: str(value), "ProcessId": "123"})
    assert mapping["fields"][native] == typed
    assert one(windows_hit(event, shape)).get(typed) == value


def test_hashes_are_algorithm_typed_and_loaded_images_keep_their_role():
    from romulus.content.sigma_mapping import map_rule
    process = map_rule({"product": "windows", "category": "process_creation"}, {"s": {"Hashes": "SHA256=ab"}})
    image = map_rule({"product": "windows", "category": "image_load"}, {"s": {"Hashes": "SHA256=ab"}})
    assert process["fields"]["Hashes"]["hashes"]["SHA256"] == "file.hash.sha256"
    assert image["fields"]["Hashes"]["hashes"]["SHA256"] == "image.hash.sha256"


def test_registry_categories_preserve_native_add_delete_distinction():
    from romulus.content.sigma_mapping import map_rule
    for category, values in (("registry_add", ["CreateKey", "CreateValue"]),
                             ("registry_delete", ["DeleteKey", "DeleteValue"])):
        mapped = map_rule({"product": "windows", "category": category}, {"s": {"TargetObject": "HKLM\\Probe"}})
        assert mapped["scope"] == [{"field": "registry.event_type", "values": values}]


def test_unknown_fields_and_logsource_are_named_and_never_partially_mapped():
    from romulus.content.sigma_mapping import map_rule
    mapped = map_rule({"product": "windows", "category": "process_creation"},
                      {"s": {"Image": "probe.exe", "MysteryField|contains": "needle"}})
    assert any("MysteryField" in reason for reason in mapped["reasons"])
    assert "MysteryField" not in mapped["fields"]
    assert map_rule({"product": "other", "category": "unknown"}, {"s": {"Image": "x"}})["reasons"]


def test_eventid_in_an_arbitrary_selector_never_narrows_the_source():
    from romulus.content.sigma_mapping import map_rule
    a = map_rule({"product": "windows", "service": "security"}, {"s": {"EventID": 4624}})
    b = map_rule({"product": "windows", "service": "security"}, {"s": {"EventID": 4625}})
    assert a["event_codes"] == b["event_codes"]
    assert {"4624", "4625", "4688"} <= set(a["event_codes"])
    assert a["fields"]["EventID"] == "event.code"


def _ast(source, field, value):
    from romulus.content.sigma_parser import parse_rule
    parsed = parse_rule({"logsource": source, "detection": {"selection": {field: value}, "condition": "selection"}})
    assert parsed["reasons"] == [], parsed["reasons"]
    return parsed["ast"]


@pytest.mark.parametrize("shape", ["winlogbeat_8", "elastic_agent"])
@pytest.mark.parametrize(("category", "code", "namespace"), [
    ("process_creation", 1, "file"), ("create_stream_hash", 15, "file"), ("image_load", 7, "image")])
def test_hash_comparison_executes_against_native_hashes_by_role(shape, category, code, namespace):
    from romulus.content.sigma_parser import evaluate_ast
    ast = _ast({"product": "windows", "category": category}, "Hashes", "SHA256=" + "ab" * 32)
    for digest in ("ab" * 32, "cd" * 32):
        raw = LogicalWindowsEvent(SYSMON_CHANNEL, SYSMON, code, "ws01", 1, "2026-01-02T03:04:05Z",
            {"Hashes": "SHA256=" + digest, "ProcessId": "123"})
        event = one(windows_hit(raw, shape))
        assert event.get(f"{namespace}.hash.sha256") == digest
        assert evaluate_ast(ast, event)[0] == (digest == "ab" * 32)


@pytest.mark.parametrize("source", [{"product": "windows", "category": "ps_script"},
                                   {"product": "windows", "service": "powershell"}])
def test_powershell_source_never_claims_untyped_process_commandline(source):
    from romulus.content.sigma_mapping import map_rule
    result = map_rule(source, {"s": {"CommandLine": "probe"}})
    assert result["reasons"] == ["Unmapped Sigma field: CommandLine"]


@pytest.mark.parametrize("shape", ["winlogbeat_8", "elastic_agent"])
def test_security_service_name_keeps_kerberos_and_installed_service_roles(shape):
    from romulus.content.sigma_parser import evaluate_ast
    ast = _ast({"product": "windows", "service": "security"}, "ServiceName", "probe-service")
    for name in ("probe-service", "benign-service"):
        raw = LogicalWindowsEvent("Security", SECURITY, 4769, "ws01", 1,
            "2026-01-02T03:04:05Z", {"ServiceName": name})
        event = one(windows_hit(raw, shape))
        assert event.get("auth.service_name") == name
        matched, fields = evaluate_ast(ast, event)
        assert matched == (name == "probe-service")
        assert fields == (["auth.service_name"] if matched else [])


def test_broad_service_mappings_do_not_admit_fields_the_channel_never_types():
    from romulus.content.sigma_mapping import map_rule
    for service, field in (("security", "ScriptBlockText"), ("system", "CommandLine"),
                           ("sysmon", "ServiceName")):
        mapped = map_rule({"product": "windows", "service": service}, {"s": {field: "probe"}})
        assert mapped["reasons"] == [f"Unmapped Sigma field: {field}"]


@pytest.mark.parametrize("shape", ["winlogbeat_8", "elastic_agent"])
def test_network_connection_category_includes_typed_wfp_connection_but_not_bind(shape):
    from romulus.content.sigma_parser import evaluate_ast
    ast = _ast({"product": "windows", "category": "network_connection"}, "DestinationPort", 445)
    for code, port in ((5156, "445"), (5156, "443"), (5158, "445")):
        raw = LogicalWindowsEvent("Security", SECURITY, code, "ws01", 1, "2026-01-02T03:04:05Z",
            {"DestAddress": "192.0.2.10", "DestPort": port, "SourcePort": "49152"})
        event = one(windows_hit(raw, shape))
        assert event.get("destination.port") == int(port)
        assert evaluate_ast(ast, event)[0] == (code == 5156 and port == "445")


@pytest.mark.parametrize("shape", ["winlogbeat_8", "elastic_agent"])
def test_registry_set_includes_security_native_value_modifications(shape):
    from romulus.content.sigma_parser import evaluate_ast
    ast = _ast({"product": "windows", "category": "registry_set"}, "Details", "probe-value")
    for value in ("probe-value", "benign-value"):
        raw = LogicalWindowsEvent("Security", SECURITY, 4657, "ws01", 1, "2026-01-02T03:04:05Z",
            {"ObjectName": "HKLM\\Probe", "NewValue": value})
        event = one(windows_hit(raw, shape))
        assert event.get("registry.value") == value
        assert evaluate_ast(ast, event)[0] == (value == "probe-value")

