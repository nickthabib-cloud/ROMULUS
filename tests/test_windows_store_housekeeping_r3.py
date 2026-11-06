"""Relocated stores and exact host/path identities preserve Windows attention lanes."""
from __future__ import annotations

import itertools

import pytest

from romulus.detect.windows_housekeeping import KerberosLoopbackLogon, UnexpectedPsRemoteServer
from romulus.detect.windows_image_file_rules import LsassFileWrite
from romulus.evidence.windows import normalize_windows
from romulus.evidence.windows_catalog import SECURITY, SYSMON, SYSMON_CHANNEL
from tests.windows_fixtures import SHAPES, LogicalWindowsEvent, windows_hit
from tests.windows_process_support import run, sysmon1

IDS = itertools.count(930000)
LSASS = r"C:\Windows\System32\lsass.exe"


def record(code, data, shape, *, host="ws01.example.test"):
    logical = LogicalWindowsEvent("Security" if code == 4624 else SYSMON_CHANNEL,
                                  SECURITY if code == 4624 else SYSMON, code, host,
                                  next(IDS), "2026-01-02T03:00:00Z", data)
    return normalize_windows(windows_hit(logical, shape))


def file_record(path, shape, *, image=LSASS):
    return record(11, {"Image": image, "ProcessId": "400", "TargetFilename": path}, shape)


def hits(rule, row):
    try:
        return rule.judge(row)
    finally:
        rule.release_state()


@pytest.mark.parametrize("shape", SHAPES)
@pytest.mark.parametrize("path", [
    r"E:\Logs\edbtmp.log", r"D:\AD\NTDS\edb00001.log", r"F:\ADLogs\edb.chk",
    r"E:\Logs\EDB00000001.LOG", r"D:\Directory\ntds.dit", r"D:\Directory\temp.edb",
    r"E:\Logs\edbres00001.jrs", r"\\?\E:\Logs\edbtmp.log", r"\??\D:\AD\NTDS\edb00001.log",
    r"\Device\HarddiskVolume7\ADLogs\edb.log",
    r"\\?\Volume{01234567-0123-0123-0123-0123456789abcd}\Logs\edbtmp.log",
])
def test_canonical_lsass_ese_names_in_relocated_local_stores_are_visible_leads(shape, path):
    row = file_record(path, shape)
    [hit] = hits(LsassFileWrite(), row)
    assert hit.lane == "lead"
    assert "normal-store path shape" in hit.common
    assert "authorized" not in hit.text.lower()
    assert "dc role" not in hit.text.lower()


@pytest.mark.parametrize("shape", SHAPES)
@pytest.mark.parametrize("path", [
    r"E:\Logs\mimilsa.log", r"D:\AD\NTDS\mimilsa.log", r"E:\Logs\edbtmp.log.exe",
    r"E:\Logs\edb00001.log:stream", r"relative\edbtmp.log", r"E:Logs\edbtmp.log",
    r"\\files\share\edbtmp.log", r"\\?\UNC\files\share\edbtmp.log",
])
def test_memssp_and_nonlocal_or_inexact_ese_names_keep_high_attention(shape, path):
    [hit] = hits(LsassFileWrite(), file_record(path, shape))
    assert hit.lane == "high"


@pytest.mark.parametrize("shape", SHAPES)
@pytest.mark.parametrize("image", [r"C:\Users\Public\lsass.exe", r"D:\Windows\System32\lsass.exe",
                                   r"\\files\share\Windows\System32\lsass.exe", "lsass.exe"])
def test_ese_filename_does_not_establish_a_canonical_lsass_process_image(shape, image):
    [hit] = hits(LsassFileWrite(), file_record(r"E:\Logs\edbtmp.log", shape, image=image))
    assert hit.lane == "high"


@pytest.mark.parametrize("shape", SHAPES)
@pytest.mark.parametrize("name,sid,want", [
    ("EVIL$", "S-1-5-21-1-2-3-1001", "lead"),
    ("EVIL$", "S-1-5-21-1-2-3-500", "high"),
    ("ws010$", "S-1-5-21-1-2-3-1001", "lead"),
    ("ws01.other.test$", "S-1-5-21-1-2-3-1001", "lead"),
    ("WS01$", "S-1-5-21-1-2-3-1001", None),
    ("WS01.EXAMPLE.TEST.$", "S-1-5-21-1-2-3-1001", None),
    ("Administrator", "S-1-5-18", None),
    ("renamed-admin", "S-1-5-21-1-2-3-500", "high"),
])
def test_loopback_machine_account_quieting_requires_the_recorded_host_identity(shape, name, sid, want):
    row = record(4624, {"LogonType": "3", "AuthenticationPackageName": "Kerberos", "IpAddress": "::1",
                        "TargetUserName": name, "TargetUserSid": sid, "TargetDomainName": "EXAMPLE"}, shape)
    result = hits(KerberosLoopbackLogon(), row)
    assert [hit.lane for hit in result] == ([] if want is None else [want])


@pytest.mark.parametrize("shape", SHAPES)
@pytest.mark.parametrize("parent,want", [
    (r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "lead"),
    (r"C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell_ise.exe", "lead"),
    (r"\??\C:\Program Files\PowerShell\7\pwsh.exe", "lead"),
    (r"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe", "lead"),
    (r"C:\Users\Public\powershell.exe", "high"),
    (r"C:\Users\Public\pwsh.exe", "high"),
    (r"C:\Users\Public\powershell_ise.exe", "high"),
    (r"D:\Program Files\PowerShell\7\pwsh.exe", "high"),
    (r"\\files\share\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "high"),
    (r"C:\Windows\System32\powershell.exe", "high"),
    ("powershell.exe", "high"), ("pwsh.exe", "high"), ("powershell_ise.exe", "high"),
])
def test_start_job_attention_uses_canonical_installed_parent_paths(shape, parent, want):
    row = sysmon1(image="powershell.exe", command="powershell.exe -s", parent_image=parent, shape=shape)
    [hit] = hits(UnexpectedPsRemoteServer(), row)
    assert hit.lane == want
    assert ("Start-Job" in hit.text) == (want == "lead")


def test_relocated_ese_log_names_fold_with_exact_count_and_bounded_citations():
    rule = LsassFileWrite()
    try:
        rows = [file_record(r"E:\Logs\edb" + f"{n:05x}.log", "winlogbeat_8") for n in range(256)]
        [match] = run(rule, [rows[:128], rows[128:]])
        assert match.proposed_lane == "lead" and "256 Windows event record(s)" in match.claim
        assert len(rule.groups) == 1 and len(match.events) <= 16
        assert all(ref.native_id for event in match.events for ref in event.raw)
    finally:
        rule.release_state()
