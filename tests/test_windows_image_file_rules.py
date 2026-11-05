"""Behavioral checks for typed process images and suspicious file writers."""
import importlib
from datetime import UTC, datetime

import pytest

from romulus.evidence.windows import normalize_windows
from romulus.evidence.windows_catalog import SYSMON, SYSMON_CHANNEL
from tests.windows_fixtures import LogicalWindowsEvent, windows_hit


def native(data, *, code=1, shape="winlogbeat_8"):
    record = LogicalWindowsEvent(SYSMON_CHANNEL, SYSMON, code, "host.example.test", 1,
                                 datetime(2026, 1, 2, tzinfo=UTC).isoformat(), data)
    return normalize_windows(windows_hit(record, shape))


def rule(name):
    return getattr(importlib.import_module("romulus.detect.windows_image_file_rules"), name)()


def hits(name, data, *, code=1):
    return rule(name).judge(native(data, code=code))


@pytest.mark.parametrize("shape", ["winlogbeat_7", "winlogbeat_8", "elastic_agent"])
@pytest.mark.parametrize("image", [
    r"\\tsclient\C\tools\run.exe", r"\\TSCLIENT\D\run.exe",
    r"\\?\UNC\tsclient\C\run.exe", r"\??\UNC\tsclient\C\run.exe",
])
def test_client_drive_execution_reads_the_image_in_each_shipper(shape, image):
    event = native({"Image": image, "CommandLine": "ordinary.exe"}, shape=shape)
    found = rule("ClientDriveProcess").judge(event)
    assert len(found) == 1 and found[0].lane == "high"
    assert found[0].attack == ("T1021.001",)
    assert any(field.field == "process.executable_key" for field in found[0].predicate)


@pytest.mark.parametrize("image", [
    r"C:\Tools\ordinary.exe", r"\\server\tsclient\run.exe",
    r"\\tsclient-other\C\run.exe", r"C:\tsclient\run.exe", "", None,
    r"\\tsclient\C", r"\\tsclient\C\\", r"\\tsclient\C\..",
])
def test_client_drive_requires_a_file_under_the_exact_unc_host(image):
    assert hits("ClientDriveProcess", {"Image": image,
                "CommandLine": r"cmd /c \\tsclient\C\run.exe"}) == []


@pytest.mark.parametrize("image", [
    r"C:\Temp\test.tmp", r"\\server\share\photo.JPG", r"\\?\C:\Tools\cache.DAT",
    r"\Device\HarddiskVolume4\Temp\document.txt", r"\??\C:\Temp\test.tmp",
])
def test_non_executable_image_suffix_is_a_lead(image):
    found = hits("NonExecutableProcessImage", {"Image": image,
                 "CommandLine": r"C:\Tools\ordinary.exe"})
    assert len(found) == 1 and found[0].lane == "lead"
    assert found[0].attack == ("T1036.008",)


@pytest.mark.parametrize("suffix", [
    "EXE", "com", "scr", "pif", "cpl", "msi", "dll", "sys", "ocx", "drv",
    "acm", "ax", "efi", "ime", "tsp", "xll", "wll",
])
def test_native_image_and_installer_suffixes_are_not_masquerading(suffix):
    assert hits("NonExecutableProcessImage", {"Image": "C:\\Tools\\image." + suffix,
                "CommandLine": r"C:\Temp\test.tmp"}) == []


@pytest.mark.parametrize("image", [
    "", None, {}, "unknown", "-", "System", r"C:\Temp\image", r"C:\Temp\.hidden",
    "C:\\Temp\\", "C:\\Temp\\folder.txt\\", r"%UnknownRoot%\image.tmp",
    r"relative\image.tmp", r"C:image.tmp", r"\image.tmp", r"\\server\share",
    r"\\server\share\\", r"C:\Temp\image.exe:stream", r"C:\Temp\image.",
])
def test_unresolved_or_extensionless_image_never_invents_an_extension(image):
    assert hits("NonExecutableProcessImage", {"Image": image,
                "CommandLine": r"C:\Temp\test.tmp"}) == []


@pytest.mark.parametrize("image", [
    r"C:\Windows\System32\lsass.exe", r"C:\Windows\SysWOW64\LSASS.EXE",
    r"\Device\HarddiskVolume4\Windows\Sysnative\lsass.exe",
])
def test_lsass_file_creation_is_high_for_any_recorded_file(image):
    found = hits("LsassFileWrite", {"Image": image, "TargetFilename": r"C:\Windows\System32\mimilsa.log"}, code=11)
    assert len(found) == 1 and found[0].lane == "high"
    assert found[0].attack == ("T1547.005",)


@pytest.mark.parametrize("data", [
    {"Image": r"C:\Tools\not-lsass.exe", "TargetFilename": r"C:\lsass.exe"},
    {"TargetFilename": r"C:\mimilsa.log"},
    {"Image": r"C:\Windows\System32\lsass.exe"},
])
def test_lsass_writer_requires_image_identity_and_a_recorded_file(data):
    assert hits("LsassFileWrite", data, code=11) == []


@pytest.mark.parametrize("image", ["System", "SYSTEM", "", None])
@pytest.mark.parametrize("suffix", ["exe", "DLL", "sys"])
def test_system_binary_write_requires_typed_pid_four_and_tolerates_unrecorded_image(image, suffix):
    found = hits("SystemBinaryFileWrite", {"Image": image, "ProcessId": "4",
                 "TargetFilename": "C:\\Windows\\Temp\\tool." + suffix}, code=11)
    assert len(found) == 1 and found[0].lane == "lead"
    assert found[0].attack == ("T1570",)
    assert any(field.field == "process.pid" and field.value == 4 for field in found[0].predicate)


@pytest.mark.parametrize("data", [
    {"Image": "System", "ProcessId": "44", "TargetFilename": r"C:\Temp\tool.exe"},
    {"Image": "System", "TargetFilename": r"C:\Temp\tool.exe"},
    {"Image": r"C:\Tools\System.exe", "ProcessId": "4", "TargetFilename": r"C:\Temp\tool.exe"},
    {"Image": r"C:\Tools\other.exe", "ProcessId": "4", "TargetFilename": r"C:\Temp\tool.exe"},
    {"Image": "System", "ProcessId": "4", "TargetFilename": r"C:\Temp\tool.txt"},
    {"Image": "System", "ProcessId": "4", "TargetFilename": r"C:\Temp\tool.exe:Zone.Identifier"},
    {"Image": "System", "ProcessId": "4"},
])
def test_system_writer_needs_pid_image_and_binary_file_evidence(data):
    assert hits("SystemBinaryFileWrite", data, code=11) == []


@pytest.mark.parametrize("path", [
    r"C:\Windows\System32\payload.dll", r"\\?\C:\Windows\Temp\payload.dll",
    r"\\server\share\payload.dll", r"\Device\HarddiskVolume2\Users\Public\payload.dll",
    r"C:\Windows\System32\spool\..\outside.dll", r"C:\Temp\spool",
])
def test_spooler_file_creation_outside_spool_is_high(path):
    found = hits("SpoolerFileWriteOutsideSpool", {"Image": r"C:\Windows\System32\spoolsv.exe",
                 "TargetFilename": path}, code=11)
    assert len(found) == 1 and found[0].lane == "high"
    assert found[0].attack == ("T1068",)


@pytest.mark.parametrize("path", [
    r"C:\Windows\System32\spool\PRINTERS\job.SPL",
    r"C:\Windows\SysWOW64\SPOOL\drivers\x64\3\driver.dll",
    r"\\?\C:\Windows\Sysnative\spool\drivers\driver.dll",
    r"\\server\share\spool\driver.dll", "", None, r"%Unresolved%\payload.dll",
    r"relative\payload.dll",
])
def test_spooler_known_spool_files_or_unresolved_locations_do_not_raise(path):
    assert hits("SpoolerFileWriteOutsideSpool", {"Image": r"C:\Windows\System32\spoolsv.exe",
                "TargetFilename": path}, code=11) == []


@pytest.mark.parametrize("path", [
    r"C:\program.exe", r"D:\PROGRAM.EXE", r"\\?\C:\program.exe",
    r"\??\C:\program.exe", r"\Device\HarddiskVolume3\program.exe",
    r"\\?\Volume{01234567-0123-0123-0123-0123456789abcd}\program.exe",
    r"C:\folder\..\program.exe",
])
def test_volume_root_binary_write_is_a_lead(path):
    found = hits("VolumeRootExecutableWrite", {"Image": r"C:\Tools\writer.exe",
                 "TargetFilename": path}, code=11)
    assert len(found) == 1 and found[0].lane == "lead"
    assert found[0].attack == ("T1574.009",)


@pytest.mark.parametrize("path", [
    r"C:\Tools\program.exe", r"\\server\share\program.exe", r"C:program.exe",
    r"\program.exe", r"program.exe", r"C:\program.txt", r"C:\program",
    r"C:\program.exe:stream", r"%UnknownRoot%\program.exe", None, "",
])
def test_volume_root_requires_one_local_volume_component_and_an_executable_suffix(path):
    assert hits("VolumeRootExecutableWrite", {"TargetFilename": path}, code=11) == []


@pytest.mark.parametrize("name,code,data", [
    ("ClientDriveProcess", 1, {"Image": r"\\tsclient\C\run.exe"}),
    ("NonExecutableProcessImage", 1, {"Image": r"C:\Temp\test.tmp"}),
    ("LsassFileWrite", 11, {"Image": r"C:\Windows\System32\lsass.exe", "TargetFilename": r"C:\x.log"}),
    ("SystemBinaryFileWrite", 11, {"Image": "System", "ProcessId": "4", "TargetFilename": r"C:\x.exe"}),
    ("SpoolerFileWriteOutsideSpool", 11, {"Image": r"C:\Windows\System32\spoolsv.exe", "TargetFilename": r"C:\x.dll"}),
    ("VolumeRootExecutableWrite", 11, {"TargetFilename": r"C:\program.exe"}),
])
@pytest.mark.parametrize("change", ["family", "code", "provider", "channel"])
def test_rules_reject_other_event_classes_even_when_fields_look_suspicious(name, code, data, change):
    event = native(data, code=code)
    if change == "family":
        event.family = "file_delete"
    else:
        key = "event." + change
        event.fields[key] = event.fields[key].model_copy(update={"value": 3 if change == "code" else "Other"})
    assert rule(name).judge(event) == []


def test_publication_cites_native_image_file_and_pid_without_command_line_inference():
    event = native({"Image": "System", "ProcessId": "4", "TargetFilename": r"C:\program.exe",
                    "CommandLine": "ignored"}, code=11)
    detector = rule("SystemBinaryFileWrite")
    found = detector.consume([event])
    assert len(found) == 1 and found[0].proposed_lane == "lead"
    assert found[0].events == [event]
    fields = {field.field: field for field in found[0].predicate}
    assert fields["process.pid"].value == 4
    assert fields["file.path_key"].value == r"c:\program.exe"
    assert "process.command_line" not in fields


@pytest.mark.parametrize("name,code,data,want", [
    ("NonExecutableProcessImage", 1, {"Image": r"C:\Temp\stage.tmp"}, "lead"),
    ("LsassFileWrite", 11, {"Image": r"C:\Windows\System32\lsass.exe",
                          "TargetFilename": r"C:\Temp\session.log"}, "high"),
    ("SystemBinaryFileWrite", 11, {"ProcessId": "4", "TargetFilename": r"C:\Temp\agent.sys"}, "lead"),
    ("SpoolerFileWriteOutsideSpool", 11, {"Image": r"C:\Windows\SysWOW64\spoolsv.exe",
                                        "TargetFilename": r"C:\Temp\diagnostic.dat"}, "high"),
    ("VolumeRootExecutableWrite", 11, {"TargetFilename": r"D:\agent.exe"}, "lead"),
])
def test_file_and_image_evidence_gives_equal_lanes_across_shipper_shapes(name, code, data, want):
    observed = []
    for shape in ("winlogbeat_7", "winlogbeat_8", "elastic_agent"):
        found = rule(name).judge(native(data, code=code, shape=shape))
        assert len(found) == 1
        observed.append(found[0].lane)
    assert observed == [want, want, want]


@pytest.mark.parametrize("name,code,data", [
    ("NonExecutableProcessImage", 1, {
        "Image": r"C:\Windows\SysWOW64\schtasks.exe",
        "CommandLine": r"schtasks /Create /XML C:\Temp\schedule.tmp /TN Example",
    }),
    ("NonExecutableProcessImage", 11, {
        "Image": r"C:\Windows\System32\rundll32.exe", "TargetFilename": r"C:\Temp\stage.tmp",
    }),
    ("SpoolerFileWriteOutsideSpool", 11, {
        "Image": r"C:\Windows\System32\spoolsv.exe",
        "TargetFilename": r"C:\Windows\System32\spool\drivers\x64\3\New\approved.dll",
    }),
    ("VolumeRootExecutableWrite", 11, {
        "Image": "System", "ProcessId": "4", "TargetFilename": r"C:\Windows\service.exe",
    }),
])
def test_public_corpus_behavior_shapes_remain_negative_at_the_typed_boundary(name, code, data):
    # Independently authored cases model benign-to-this-rule shapes in public
    # samples 002/175/255; no raw sample records or payloads are reproduced.
    assert hits(name, data, code=code) == []


@pytest.mark.parametrize("pid", [True, False, None, 0, 44, "4"])
def test_system_writer_pid_must_be_a_typed_integer_not_a_truthy_or_text_value(pid):
    event = native({"Image": "System", "ProcessId": "4", "TargetFilename": r"C:\Temp\agent.exe"}, code=11)
    event.fields["process.pid"] = event.fields["process.pid"].model_copy(update={"value": pid})
    assert rule("SystemBinaryFileWrite").judge(event) == []
