"""Known LSASS stores and print output stay visible with bounded behavior folds."""
import importlib

import pytest

from tests.test_windows_process_w4 import native
from tests.windows_process_support import run

LSASS = r"C:\Windows\System32\lsass.exe"
SPOOLER = r"C:\Windows\System32\spoolsv.exe"
SID = "S-1-5-21-11-22-33-1001"
GUID = "01234567-0123-0123-0123-0123456789ab"


def detector(name):
    return getattr(importlib.import_module("romulus.detect.windows_image_file_rules"), name)()


def file_event(path, *, image=LSASS, number=1, host="host.example.test", pid=400):
    return native({"Image": image, "ProcessId": str(pid), "TargetFilename": path},
                  number, code=11, host=host, offset=number)[0]


def decide(name, event):
    instance = detector(name)
    try:
        return instance.judge(event)
    finally:
        instance.release_state()


@pytest.mark.parametrize("path", [
    r"C:\Windows\NTDS\edbtmp.log", r"C:\Windows\NTDS\edb00001.log",
    r"C:\Windows\NTDS\temp.edb", r"D:\NTDS\edb00001.log", r"D:\NTDS\ntds.dit",
    r"C:\Users\alice\Documents\NTDS\edb00001.log",
    r"C:\Temp\Windows\NTDS\edbtmp.log", r"C:\Windows\NTDS-backup\edbtmp.log",
    r"D:\Windows\NTDS\edbtmp.log",
    "\\\\?\\C:\\Windows\\NTDS\\edbtmp.log", r"\??\C:\Windows\NTDS\temp.edb",
    r"%SystemRoot%\NTDS\edbtmp.log", r"\SystemRoot\NTDS\temp.edb",
    "C:\\Users\\alice\\AppData\\Roaming\\Microsoft\\Protect\\" + SID + "\\" + GUID,
    "C:\\Users\\alice\\AppData\\Roaming\\Microsoft\\Protect\\" + SID + "\\Preferred",
    "C:\\Users\\alice\\AppData\\Roaming\\Microsoft\\Protect\\" + SID + "\\{" + GUID + "}",
    "C:\\Windows\\System32\\Microsoft\\Protect\\S-1-5-18\\User\\" + GUID,
    "C:\\Windows\\System32\\Microsoft\\Protect\\S-1-5-18\\Machine\\" + GUID,
    "C:\\Windows\\ServiceProfiles\\LocalService\\AppData\\Roaming\\Microsoft\\Protect\\S-1-5-19\\" + GUID,
    "C:\\Windows\\System32\\config\\systemprofile\\AppData\\Roaming\\Microsoft\\Protect\\S-1-5-18\\" + GUID,
    r"C:\ProgramData\Microsoft\Crypto\Keys\key-0001",
    r"C:\ProgramData\Microsoft\Crypto\SystemKeys\key-0001",
    r"C:\Users\alice\AppData\Roaming\Microsoft\Crypto\Keys\key-0001",
    r"C:\Windows\debug\netlogon.log", r"C:\Windows\DEBUG\NETLOGON.BAK",
    r"C:\Windows\debug\netlogon.log.1", r"C:\Windows\debug\netlogon.old",
])
def test_lsass_standard_store_shapes_are_leads_and_never_dropped(path):
    [hit] = decide("LsassFileWrite", file_event(path))
    assert hit.lane == "lead"
    assert "file" in hit.text.lower()
    assert not any(word in hit.text.lower() for word in ("authorized", "benign", "legitimate"))


@pytest.mark.parametrize("path", [
    r"C:\Windows\System32\mimilsa.log", r"C:\Temp\mimilsa.log",
    r"C:\Windows\NTDS\mimilsa.log", r"D:\NTDS\payload.dll",
    r"C:\Windows\debug\netlogon-credentials.txt",
    r"C:\Temp\Microsoft\Crypto\Keys\key-0001",
    r"C:\Users\alice\Documents\Microsoft\Protect\user\Preferred",
    "C:\\Users\\alice\\AppData\\Roaming\\Microsoft\\Protect\\not-a-sid\\" + GUID,
    "C:\\Users\\alice\\AppData\\Roaming\\Microsoft\\Protect\\" + SID + "\\mimilsa.log",
    "C:\\Users\\alice\\AppData\\Roaming\\Microsoft\\Protect\\" + SID + "\\{" + GUID,
    "C:\\Users\\alice\\AppData\\Roaming\\Microsoft\\Protect\\" + SID + "\\" + GUID + "}",
    r"\\server\share\Windows\NTDS\edbtmp.log",
])
def test_lsass_store_lookalikes_and_memssp_remain_high(path):
    [hit] = decide("LsassFileWrite", file_event(path))
    assert hit.lane == "high"


@pytest.mark.parametrize("image", [r"C:\Users\alice\lsass.exe", r"C:\Temp\Windows\System32\lsass.exe"])
def test_masqueraded_lsass_does_not_inherit_normal_store_attention(image):
    [hit] = decide("LsassFileWrite", file_event(r"C:\Windows\NTDS\edbtmp.log", image=image))
    assert hit.lane == "high"


@pytest.mark.parametrize("path,lane", [
    (r"C:\Users\alice\Documents\report.pdf", "lead"),
    (r"C:\Users\alice\Documents\report.xps", "lead"),
    (r"C:\Temp\print-output", "lead"),
    (r"C:\Windows\Temp\stage.dll", "lead"),
    (r"\\?\C:\Windows\Temp\subdir\stage.exe", "lead"),
    (r"\??\C:\Windows\Temp\stage.sys", "lead"),
    (r"%SystemRoot%\Temp\stage.dll", "lead"),
    (r"\SystemRoot\Temp\stage.dll", "lead"),
    (r"C:\Windows\Temp\package.msi", "lead"),
    (r"C:\blah\blah\phoneinfo.dll", "high"),
    (r"C:\Windows\System32\payload.dll", "high"),
    (r"C:\Users\alice\Downloads\payload.exe", "high"),
    (r"C:\Users\alice\Documents\package.msi", "lead"),
    (r"C:\Users\alice\Documents\legacy.pif", "lead"),
    (r"C:\Temp\Windows\Temp\stage.dll", "high"),
    (r"C:\Windows\Temp-backup\stage.dll", "high"),
    (r"C:\Windows\Temp\..\System32\stage.dll", "high"),
    (r"D:\Windows\Temp\stage.dll", "high"),
    (r"\\server\share\Windows\Temp\stage.dll", "high"),
    (r"\Device\HarddiskVolume7\Windows\Temp\stage.dll", "high"),
])
def test_spooler_lanes_use_suffix_and_exact_system_root_temp(path, lane):
    [hit] = decide("SpoolerFileWriteOutsideSpool", file_event(path, image=SPOOLER))
    assert hit.lane == lane
    assert "exploitation succeeded" not in hit.text.lower()


@pytest.mark.parametrize("path", [
    r"C:\Windows\System32\spool\drivers\x64\3\approved.dll",
    r"C:\Windows\SysWOW64\spool\PRINTERS\job.spl",
    r"%UnknownRoot%\stage.dll", r"relative\stage.dll",
])
def test_spool_and_unresolved_paths_do_not_become_outside_spool_evidence(path):
    assert decide("SpoolerFileWriteOutsideSpool", file_event(path, image=SPOOLER)) == []


@pytest.mark.parametrize("path,want", [
    (r"C:\program.exe", True), (r"C:\program.com", True),
    (r"\\?\C:\PROGRAM.COM", True), (r"D:\program.exe", True),
    (r"C:\pagefile.sys", False), (r"C:\swapfile.sys", False),
    (r"C:\payload.dll", False), (r"C:\screen.scr", False), (r"C:\setup.msi", False),
    (r"\\server\share\program.exe", False), (r"C:\Temp\program.exe", False),
])
def test_root_interception_artifacts_are_only_exe_or_com(path, want):
    assert bool(decide("VolumeRootExecutableWrite", file_event(path))) is want


def folded(name, events):
    instance = detector(name)
    try:
        found = run(instance, [[event] for event in events])
        return found, len(instance.groups)
    finally:
        instance.release_state()


def test_lsass_routine_log_files_fold_by_host_and_directory_with_exact_count():
    events = [file_event("D:\\NTDS\\edb" + f"{index:05x}" + ".log", number=index + 1)
              for index in range(50)]
    [match], groups = folded("LsassFileWrite", events)
    assert match.proposed_lane == "lead" and groups == 1
    assert "50 Windows event record(s)" in match.claim
    assert len(match.events) <= 16


@pytest.mark.parametrize("name,image,suffix,directory", [
    ("SystemBinaryFileWrite", "System", "exe", r"C:\Windows\Temp"),
    ("SpoolerFileWriteOutsideSpool", SPOOLER, "pdf", r"C:\Users\alice\Documents"),
])
def test_unique_filenames_do_not_flood_system_or_print_leads(name, image, suffix, directory):
    events = [file_event(directory + "\\" + f"artifact-{index}.{suffix}", image=image,
                         pid=4 if name == "SystemBinaryFileWrite" else 400, number=index + 1)
              for index in range(50)]
    [match], groups = folded(name, events)
    assert match.proposed_lane == "lead" and groups == 1
    assert "50 Windows event record(s)" in match.claim
    assert len(match.events) <= 16


@pytest.mark.parametrize("name,image", [("SystemBinaryFileWrite", "System"),
                                      ("SpoolerFileWriteOutsideSpool", SPOOLER)])
def test_file_lead_folds_keep_distinct_hosts_directories_and_suffixes(name, image):
    suffixes = ("exe", "dll") if name == "SystemBinaryFileWrite" else ("pdf", "xps")
    events = []
    for host, directory, suffix in [
        ("host.example.test", r"C:\Temp\one", suffixes[0]),
        ("host.example.test", r"C:\Temp\two", suffixes[0]),
        ("host.example.test", r"C:\Temp\one", suffixes[1]),
        ("other.example.test", r"C:\Temp\one", suffixes[0]),
    ]:
        events.append(file_event(directory + "\\artifact." + suffix, image=image, host=host,
                                 pid=4 if name == "SystemBinaryFileWrite" else 400, number=len(events) + 1))
    found, groups = folded(name, events)
    assert len(found) == 4 and groups == 4


@pytest.mark.parametrize("kind", ["msi", "inno"])
def test_nonnative_installer_images_remain_leads_but_fold_by_directory_class(kind):
    events = []
    for index in range(50):
        image = (f"C:\\Windows\\Installer\\MSI{index:04X}.tmp" if kind == "msi" else
                 f"C:\\Users\\alice\\AppData\\Local\\Temp\\is-{index:05X}.tmp\\setup.tmp")
        events.append(native({"Image": image, "ParentImage": r"C:\Windows\System32\msiexec.exe",
                              "ParentProcessId": str(1000 + index), "CommandLine": image + f" /unique={index}"},
                             index + 1, offset=index + 1)[0])
    [match], groups = folded("NonExecutableProcessImage", events)
    assert match.proposed_lane == "lead" and groups == 1
    assert "50 Windows event record(s)" in match.claim
    assert len(match.events) <= 16


def test_nonnative_folds_keep_suffix_parent_image_and_directory_class_distinct():
    rows = [
        (r"C:\Windows\Installer\MSI001.tmp", r"C:\Windows\System32\msiexec.exe"),
        (r"C:\Windows\Installer\MSI002.dat", r"C:\Windows\System32\msiexec.exe"),
        (r"C:\Windows\Installer\MSI003.tmp", r"C:\Tools\loader.exe"),
        (r"C:\Users\alice\Downloads\image.tmp", r"C:\Windows\System32\msiexec.exe"),
    ]
    events = [native({"Image": image, "ParentImage": parent}, index + 1, offset=index + 1)[0]
              for index, (image, parent) in enumerate(rows)]
    found, groups = folded("NonExecutableProcessImage", events)
    assert len(found) == 4 and groups == 4


@pytest.mark.parametrize("path", [
    "%AppData%\\Microsoft\\Protect\\" + SID + "\\" + GUID,
    "%UserProfile%\\AppData\\Roaming\\Microsoft\\Protect\\" + SID + "\\Preferred",
    r"%AppData%\Microsoft\Crypto\Keys\key-0001",
    r"%ProgramData%\Microsoft\Crypto\SystemKeys\key-0001",
    r"C:\Documents and Settings\All Users\Application Data\Microsoft\Crypto\Keys\key-0001",
])
def test_explicit_profile_and_programdata_store_aliases_remain_recorded_leads(path):
    [hit] = decide("LsassFileWrite", file_event(path))
    assert hit.lane == "lead"
    assert any(field.field == "file.path" and field.value == path for field in hit.predicate)


@pytest.mark.parametrize("name,image,directory,pattern", [
    ("SystemBinaryFileWrite", "System", r"C:\Windows\Temp", "tool-{index}.exe"),
    ("LsassFileWrite", LSASS, r"D:\NTDS", "edb{index:05x}.log"),
])
def test_real_sweep_publication_revises_one_lead_instead_of_retaining_one_per_file(
        tmp_path, monkeypatch, name, image, directory, pattern):
    from tests.test_windows_process_w4 import sweep_run

    batch = [native({"Image": image, "ProcessId": "4" if image == "System" else "400",
                     "TargetFilename": directory + "\\" + pattern.format(index=index)},
                    index + 1, code=11, offset=index + 1) for index in range(25)]
    found, _instance = sweep_run(tmp_path, monkeypatch, detector(name), [batch])
    [saved] = found
    assert saved["lane"] == "lead"
    assert "25 Windows event record(s)" in saved["claim"]
    assert len(saved["event_ids"]) <= 16
