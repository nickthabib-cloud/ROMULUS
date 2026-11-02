"""Typed evidence boundaries and immediate publication for Windows memory event rules."""
import pytest

from romulus.catalog.attack import load_attack_bundle
from romulus.detect.windows_memory_events import (
    WINDOWS_MEMORY_PLAYBOOKS,
    DumpLibraryLoad,
    LsassProcessAccess,
    ProcessImageTampering,
    RemoteThreadCreation,
    UnexpectedClrLoad,
    UnsignedDriverLoad,
    WritableUnsignedDllLoad,
)
from romulus.evidence.windows import normalize_windows
from romulus.evidence.windows_catalog import SYSMON, SYSMON_CHANNEL
from tests.windows_event_support import event, run
from tests.windows_fixtures import SHAPES, LogicalWindowsEvent, windows_hit

LSASS = {"source.executable": r"C:\Tools\agent.exe", "target.executable": r"C:\Windows\System32\lsass.exe",
         "process.access.mask": 0x1010, "process.access.call_trace": r"C:\Windows\System32\ntdll.dll+123"}
REMOTE = {"source.executable": r"C:\Tools\agent.exe", "target.executable": r"C:\Windows\System32\svchost.exe",
          "thread.start_address": "0x123456", "thread.start_module": "", "thread.id": 11}
TAMPER = {"process.executable": r"C:\Windows\System32\svchost.exe", "process.tampering.type": "Image is replaced"}
DRIVER = {"image.kind": "driver", "image.path": r"C:\Windows\System32\drivers\custom.sys", "image.signed": False}
DLL = {"image.kind": "image", "image.path": r"C:\Users\alice\AppData\Local\plugin.dll", "image.signed": False,
       "process.executable": r"C:\Windows\System32\rundll32.exe"}
DUMP = {"image.kind": "image", "image.path": r"C:\Windows\System32\dbghelp.dll",
        "process.executable": r"C:\Tools\agent.exe"}
CLR = {"image.kind": "image", "image.path": r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll",
       "process.executable": r"C:\Windows\System32\rundll32.exe"}
CASES = (
    (LsassProcessAccess, "process_access", 10, LSASS, "high"),
    (RemoteThreadCreation, "remote_thread", 8, REMOTE, "high"),
    (ProcessImageTampering, "process_tampering", 25, TAMPER, "lead"),
    (UnsignedDriverLoad, "image_load", 6, DRIVER, "high"),
    (WritableUnsignedDllLoad, "image_load", 7, DLL, "high"),
    (DumpLibraryLoad, "image_load", 7, DUMP, "lead"),
    (UnexpectedClrLoad, "image_load", 7, CLR, "lead"),
)


@pytest.mark.parametrize("rule,family,code,fields,lane", CASES)
def test_positive_observations_are_immediate_and_cite_typed_predicates(rule, family, code, fields, lane):
    observation = event(family, code, **fields)
    matches = rule().consume([observation])
    assert len(matches) == 1
    assert matches[0].proposed_lane == lane
    assert matches[0].events == [observation]
    assert {item.field for item in matches[0].predicate} >= {"event.code", *fields}
    assert all(item.origin.startswith(observation.id) for item in matches[0].predicate)


@pytest.mark.parametrize("rule,family,code,fields,lane", CASES)
def test_each_content_shape_and_host_publishes_before_finalize(rule, family, code, fields, lane):
    instance = rule()
    assert len(instance.consume([event(family, code, **fields)])) == 1
    assert len(instance.consume([event(family, code, host="ws02", **fields)])) == 1
    changed = dict(fields)
    field = {LsassProcessAccess: "process.access.call_trace", RemoteThreadCreation: "thread.start_function",
             ProcessImageTampering: "process.tampering.type", UnsignedDriverLoad: "image.path",
             WritableUnsignedDllLoad: "image.path", DumpLibraryLoad: "process.executable",
             UnexpectedClrLoad: "process.executable"}[rule]
    # Meaningful behavior values survive clipping and key the fleet shape; addresses are instance evidence.
    if field == "image.path":
        changed[field] = str(changed[field]).replace(".dll", "-other.dll").replace(".sys", "-other.sys")
    else:
        changed[field] = "x" * 500 + "-other"
    newer = event(family, code, offset=1, **changed)
    assert len(instance.consume([newer])) == 1
    assert any(item.value == changed[field] for item in instance.judge(newer)[0].predicate if item.field == field)
    if field == "image.path":
        long_base = str(changed[field]).rsplit("\\", 1)[0] + "\\" + "x" * 500
        extension = ".sys" if code == 6 else ".dll"
    else:
        long_base, extension = "x" * 500, ""
    for offset, suffix in enumerate(("-first", "-second"), start=2):
        long_fields = {**fields, field: long_base + suffix + extension}
        assert len(instance.consume([event(family, code, offset=offset, **long_fields)])) == 1


@pytest.mark.parametrize("rule,family,code,fields,lane", CASES)
def test_wrong_os_family_and_event_class_do_not_match(rule, family, code, fields, lane):
    assert run(rule(), [event(family, code, **{**fields, "host.os.family": "linux"})]) == []
    assert run(rule(), [event("process_exec", code, **fields)]) == []
    assert run(rule(), [event(family, 999, **fields)]) == []


@pytest.mark.parametrize("mask", [0x10, 0x1010, 0x1410, 0x1FFFFF, 0x100010, 0x30, 0x18, "0x1010"])
def test_lsass_vm_read_is_a_bit_test_not_an_exact_mask_list(mask):
    matches = run(LsassProcessAccess(), [event("process_access", 10, **{**LSASS, "process.access.mask": mask})])
    assert len(matches) == 1 and matches[0].proposed_lane == "high"
    assert "PROCESS_VM_READ" in matches[0].claim
    assert "dump" not in matches[0].claim.casefold()


@pytest.mark.parametrize("mask", [0x02, 0x08, 0x20, 0x1028])
def test_lsass_related_rights_are_observed_without_claiming_reads(mask):
    matches = run(LsassProcessAccess(), [event("process_access", 10, **{**LSASS, "process.access.mask": mask})])
    assert len(matches) == 1
    assert "PROCESS_VM_READ" not in matches[0].claim


@pytest.mark.parametrize("shape", SHAPES)
def test_native_lsass_access_mask_outside_dword_is_lead_without_vm_read_claim(shape):
    native = LogicalWindowsEvent(
        SYSMON_CHANNEL, SYSMON, 10, "ws01.example.test", 431, "2026-01-02T03:00:00Z",
        {"SourceImage": LSASS["source.executable"], "TargetImage": LSASS["target.executable"],
         "GrantedAccess": "0x100000010", "CallTrace": LSASS["process.access.call_trace"]},
    )
    observation = normalize_windows(windows_hit(native, shape))
    matches = run(LsassProcessAccess(), [observation])
    assert len(matches) == 1 and matches[0].proposed_lane == "lead"
    assert "PROCESS_VM_READ" not in matches[0].claim
    assert next(item.value for item in matches[0].predicate if item.field == "process.access.mask") == 0x100000010


@pytest.mark.parametrize("mask", [0, 0x1000, 0x400, 0x1400])
def test_lsass_query_only_with_ordinary_trace_is_outside_scope(mask):
    assert run(LsassProcessAccess(), [event("process_access", 10, **{**LSASS, "process.access.mask": mask})]) == []


@pytest.mark.parametrize("trace,modules", [
    ("UNKNOWN", []), ("UNKNOWN(000001234ABC)", []),
    ("UNKNOWN(000001234ABC)+0x123", ["UNKNOWN(000001234ABC)"]),
    (r"C:\Windows\System32\dbgcore.dll+123", [r"C:\Windows\System32\dbgcore.dll"]),
    (r"C:\Windows\System32\comsvcs.dll+123", [r"C:\Windows\System32\comsvcs.dll"]),
])
def test_lsass_notable_trace_keeps_query_rights_as_a_lead(trace, modules):
    fields = {**LSASS, "process.access.mask": 0x1000, "process.access.call_trace": trace,
              "process.access.call_trace_modules": modules}
    matches = run(LsassProcessAccess(), [event("process_access", 10, **fields)])
    assert len(matches) == 1 and matches[0].proposed_lane == "lead"
    assert "dump" not in matches[0].claim.casefold()


@pytest.mark.parametrize("name", ["WerFault.exe", "Taskmgr.exe", "MsMpEng.exe", "MsSense.exe",
                                 "CSFalconService.exe", "sentinelagent.exe"])
def test_diagnostic_and_security_names_never_suppress_lsass_access(name):
    fields = {**LSASS, "source.executable": "C:\\Windows\\System32\\" + name}
    assert run(LsassProcessAccess(), [event("process_access", 10, **fields)])[0].proposed_lane == "lead"
    fields["source.executable"] = "C:\\Users\\alice\\Downloads\\" + name
    assert run(LsassProcessAccess(), [event("process_access", 10, **fields)])[0].proposed_lane == "high"


@pytest.mark.parametrize("rule,family,code,fields,missing", [
    (LsassProcessAccess, "process_access", 10, LSASS, "process.access.mask"),
    (LsassProcessAccess, "process_access", 10, LSASS, "source.executable"),
    (RemoteThreadCreation, "remote_thread", 8, REMOTE, "target.executable"),
    (ProcessImageTampering, "process_tampering", 25, TAMPER, "process.tampering.type"),
    (UnsignedDriverLoad, "image_load", 6, DRIVER, "image.signed"),
    (WritableUnsignedDllLoad, "image_load", 7, DLL, "process.executable"),
    (WritableUnsignedDllLoad, "image_load", 7, DLL, "image.signed"),
    (DumpLibraryLoad, "image_load", 7, DUMP, "process.executable"),
    (UnexpectedClrLoad, "image_load", 7, CLR, "process.executable"),
])
def test_missing_qualifiers_preserve_observation_as_lead(rule, family, code, fields, missing):
    fields = {key: value for key, value in fields.items() if key != missing}
    matches = run(rule(), [event(family, code, **fields)])
    assert len(matches) == 1 and matches[0].proposed_lane == "lead"


@pytest.mark.parametrize("status", ["Invalid", "Untrusted", "Revoked"])
def test_invalid_signature_is_not_rescued_by_signed_boolean(status):
    fields = {**DRIVER, "image.signed": True, "image.signature_status": status}
    assert run(UnsignedDriverLoad(), [event("image_load", 6, **fields)])[0].proposed_lane == "high"


def test_unavailable_driver_signature_is_lead():
    fields = {**DRIVER, "image.signed": True, "image.signature_status": "Unavailable"}
    assert run(UnsignedDriverLoad(), [event("image_load", 6, **fields)])[0].proposed_lane == "lead"


@pytest.mark.parametrize("rule,code,fields", [(UnsignedDriverLoad, 6, DRIVER), (WritableUnsignedDllLoad, 7, DLL)])
def test_known_valid_module_signature_is_outside_unsigned_scope(rule, code, fields):
    fields = {**fields, "image.signed": True, "image.signature_status": "Valid"}
    assert run(rule(), [event("image_load", code, **fields)]) == []


@pytest.mark.parametrize("path", [r"C:\Program Files\App\plugin.dll", r"C:\Windows\System32\plugin.dll"])
def test_unsigned_dll_requires_writable_dll_path(path):
    assert run(WritableUnsignedDllLoad(), [event("image_load", 7, **{**DLL, "image.path": path})]) == []


@pytest.mark.parametrize("loader", [r"C:\Tools\app.exe", r"C:\Users\alice\Windows\System32\app.exe",
                                  r"C:\Tools\Windows\System32\app.exe"])
def test_unknown_loader_signing_does_not_claim_it_is_signed(loader):
    matches = run(WritableUnsignedDllLoad(), [event("image_load", 7, **{**DLL, "process.executable": loader})])
    # A recorded system-directory-shaped path alone is not a trust assertion.
    assert matches and matches[0].proposed_lane == "lead" and "signed process" not in matches[0].claim
    assert "unavailable" in " ".join(matches[0].notes)


@pytest.mark.parametrize("loader", [r"D:\Windows\SysWOW64\app.exe", r"\Device\HarddiskVolume2\Windows\System32\app.exe",
                                  r"\\?\C:\Windows\System32\app.exe", r"%SystemRoot%\System32\app.exe"])
def test_recorded_system_directory_variants_qualify(loader):
    matches = run(WritableUnsignedDllLoad(), [event("image_load", 7, **{**DLL, "process.executable": loader})])
    assert matches[0].proposed_lane == "high"


@pytest.mark.parametrize("library", ["dbghelp.dll", "dbgcore.dll", "comsvcs.dll"])
@pytest.mark.parametrize("process", ["WerFault.exe", "Taskmgr.exe", "MsMpEng.exe", "windbg.exe"])
def test_dump_library_diagnostic_names_still_lead(library, process):
    fields = {**DUMP, "image.path": "C:\\Windows\\System32\\" + library,
              "process.executable": "C:\\Windows\\System32\\" + process}
    matches = run(DumpLibraryLoad(), [event("image_load", 7, **fields)])
    assert len(matches) == 1 and matches[0].proposed_lane == "lead"


@pytest.mark.parametrize("host", [r"C:\Program Files\dotnet\dotnet.exe",
                                r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                                r"C:\Program Files\PowerShell\7\pwsh.exe",
                                r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\msbuild.exe",
                                r"C:\Windows\Microsoft.NET\Framework\v4.0.30319\installutil.exe",
                                r"C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\devenv.exe",
                                r"C:\Program Files\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\MSBuild.exe"])
def test_known_dotnet_hosts_in_expected_paths_are_outside_clr_rule(host):
    fields = {**CLR, "process.executable": host, "image.signed": True, "image.signature_status": "Valid"}
    assert run(UnexpectedClrLoad(), [event("image_load", 7, **fields)]) == []
    fields.update({"image.path": r"C:\Users\alice\AppData\Local\clr.dll", "image.signed": False})
    assert run(UnexpectedClrLoad(), [event("image_load", 7, **fields)])[0].proposed_lane == "lead"
    assert run(WritableUnsignedDllLoad(), [event("image_load", 7, **fields)])


@pytest.mark.parametrize("host", [r"C:\Temp\powershell.exe", r"C:\Temp\dotnet.exe",
                                r"C:\Tools\powershell.exe", r"C:\Windows\System32\dotnet.exe",
                                r"C:\Tools\Windows\Microsoft.NET\Framework64\v4.0.30319\msbuild.exe"])
def test_named_dotnet_host_outside_expected_installation_path_remains_lead(host):
    matches = run(UnexpectedClrLoad(), [event("image_load", 7, **{**CLR, "process.executable": host})])
    assert len(matches) == 1 and matches[0].proposed_lane == "lead"


@pytest.mark.parametrize("qualifiers", [{"image.signed": False}, {"image.signature_status": "Invalid"},
                                     {"image.path": r"C:\Temp\clr.dll", "image.signed": True,
                                      "image.signature_status": "Valid"}])
def test_expected_dotnet_host_with_suspicious_clr_module_still_leads(qualifiers):
    fields = {**CLR, "process.executable": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
              **qualifiers}
    matches = run(UnexpectedClrLoad(), [event("image_load", 7, **fields)])
    assert len(matches) == 1 and matches[0].proposed_lane == "lead"


@pytest.mark.parametrize("qualifiers", [
    {}, {"image.signed": True}, {"image.signature_status": "Valid"},
    {"image.signed": True, "image.signature_status": "Unavailable"},
    {"image.path": r"C:\Stage\clr.dll"},
    {"image.path": r"C:\Stage\clr.dll", "image.signed": True, "image.signature_status": "Valid"},
])
def test_expected_dotnet_loader_needs_canonical_clr_path_and_recorded_valid_signature_to_exclude(qualifiers):
    fields = {**CLR, "process.executable": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
              **qualifiers}
    matches = run(UnexpectedClrLoad(), [event("image_load", 7, **fields)])
    assert len(matches) == 1 and matches[0].proposed_lane == "lead"


def test_ordinary_unlisted_application_dump_library_load_remains_lead():
    fields = {**DUMP, "process.executable": r"C:\Program Files\Browser\browser.exe"}
    matches = run(DumpLibraryLoad(), [event("image_load", 7, **fields)])
    assert len(matches) == 1 and matches[0].proposed_lane == "lead"


@pytest.mark.parametrize("rule,family,code,fields", [
    (LsassProcessAccess, "process_access", 10, {**LSASS, "target.executable": r"C:\Tools\lsass.exe.txt"}),
    (LsassProcessAccess, "process_access", 10, {**LSASS, "target.executable": r"C:\Tools\benign.exe",
                                              "process.command_line": "dump lsass.exe"}),
    (DumpLibraryLoad, "image_load", 7, {**DUMP, "image.path": r"C:\Tools\dbghelp.dll.txt"}),
    (DumpLibraryLoad, "image_load", 7, {**DUMP, "image.path": r"C:\Tools\other.dll",
                                      "process.command_line": "load dbghelp.dll"}),
    (UnexpectedClrLoad, "image_load", 7, {**CLR, "image.path": r"C:\Tools\clr.dll.old"}),
    (UnexpectedClrLoad, "image_load", 7, {**CLR, "image.path": r"C:\Tools\other.dll",
                                        "process.command_line": "clr.dll"}),
    (UnsignedDriverLoad, "image_load", 6, {**DRIVER, "image.kind": "image"}),
    (WritableUnsignedDllLoad, "image_load", 7, {**DLL, "image.kind": "driver"}),
])
def test_deceptive_names_and_payload_mentions_are_not_actions(rule, family, code, fields):
    assert run(rule(), [event(family, code, **fields)]) == []


def test_all_rule_metadata_and_attack_ids_are_active_in_vendored_bundle():
    knowledge = load_attack_bundle()
    assert len(WINDOWS_MEMORY_PLAYBOOKS) == len({rule.id for rule in WINDOWS_MEMORY_PLAYBOOKS}) == 7
    for rule in WINDOWS_MEMORY_PLAYBOOKS:
        assert rule.benign and rule.next_checks and rule.research and rule.attack
        assert rule.assures_negative is False and rule.positive_only_reason
        assert rule.card["research_basis"] and rule.windows_event_classes
        for attack_id in rule.attack:
            technique = knowledge.technique(attack_id)
            assert not technique.revoked and not technique.deprecated
