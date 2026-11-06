"""Canonical Start-Job parents and persisted creator-handle corrections."""
from datetime import UTC, datetime, timedelta

import pytest

from romulus.detect.windows_housekeeping import UnexpectedPsRemoteServer
from romulus.detect.windows_sequence_extensions import ParentProcessSpoofing
from romulus.evidence.windows import normalize_windows
from romulus.evidence.windows_catalog import SYSMON, SYSMON_CHANNEL
from romulus.hunt.publish import publish_match
from tests.test_candidate_revision import _audits
from tests.test_sweep import _repo
from tests.windows_fixtures import LogicalWindowsEvent, windows_hit
from tests.windows_process_support import _guid, run, sysmon1

SHAPES = ("winlogbeat_7", "winlogbeat_8", "elastic_agent")


@pytest.mark.parametrize("shape", SHAPES)
@pytest.mark.parametrize("parent", [
    r"C:\Program Files\PowerShell\7-preview\pwsh.exe",
    r"\??\C:\Program Files\PowerShell\7-preview\PwSh.ExE",
    r"C:\Program Files\WindowsApps\Microsoft.PowerShell_7.5.0.0_x64__8wekyb3d8bbwe\pwsh.exe",
    r"C:\Program Files\WindowsApps\Microsoft.PowerShell_7.5.0.0_x86__8wekyb3d8bbwe\pwsh.exe",
    r"\\?\C:\Program Files\WindowsApps\Microsoft.PowerShell_7.6.0.0_arm64__8wekyb3d8bbwe\PWSH.EXE",
])
def test_installed_preview_and_msix_start_job_parents_are_leads(shape, parent):
    record = sysmon1(image="pwsh.exe", command="pwsh.exe -s -NoLogo -NoProfile",
                     parent_image=parent, shape=shape)
    rule = UnexpectedPsRemoteServer()
    try:
        [match] = run(rule, [record])
        assert match.proposed_lane == "lead"
        assert "Start-Job" in match.claim
        assert "outcome is not established" in " ".join(match.notes)
    finally:
        rule.release_state()


@pytest.mark.parametrize("shape", SHAPES)
@pytest.mark.parametrize("parent", [
    r"C:\Users\alice\.dotnet\tools\pwsh.exe",
    r"C:\Users\alice\Program Files\PowerShell\7-preview\pwsh.exe",
    r"D:\Program Files\PowerShell\7-preview\pwsh.exe",
    r"C:\Program Files\PowerShell\7-preview-evil\pwsh.exe",
    r"C:\Program Files\PowerShell\7-preview\extra\pwsh.exe",
    r"C:\Program Files\WindowsApps\Microsoft.PowerShellEvil_7.5.0.0_x64__8wekyb3d8bbwe\pwsh.exe",
    r"C:\Program Files\WindowsApps\Microsoft.PowerShell_\pwsh.exe",
    r"C:\Program Files\WindowsApps\Microsoft.PowerShell_evil\pwsh.exe",
    r"C:\Program Files\WindowsApps\Microsoft.PowerShell_7.5.0.0_x64__otherpublisher\pwsh.exe",
    r"C:\Program Files\WindowsApps\Microsoft.PowerShell_7.5.0.0_x64__8wekyb3d8bbwe\extra\pwsh.exe",
    r"C:\Users\alice\WindowsApps\Microsoft.PowerShell_7.5.0.0_x64__8wekyb3d8bbwe\pwsh.exe",
    r"D:\Program Files\WindowsApps\Microsoft.PowerShell_7.5.0.0_x64__8wekyb3d8bbwe\pwsh.exe",
    r"\\server\Program Files\WindowsApps\Microsoft.PowerShell_7.5.0.0_x64__8wekyb3d8bbwe\pwsh.exe",
])
def test_noncanonical_start_job_parent_paths_stay_high(shape, parent):
    record = sysmon1(image="pwsh.exe", command="pwsh.exe -s -NoLogo -NoProfile",
                     parent_image=parent, shape=shape)
    rule = UnexpectedPsRemoteServer()
    try:
        [match] = run(rule, [record])
        assert match.proposed_lane == "high"
        assert "Start-Job" not in match.claim
    finally:
        rule.release_state()


def test_publish_match_revises_ppid_high_to_lead_with_native_creator_proof():
    start = datetime(2026, 1, 2, 3, tzinfo=UTC)
    fixtures = [
        (10, 910001, 1, {
            "SourceProcessGUID": _guid(1), "SourceProcessId": "100",
            "SourceImage": r"C:\Tools\actor.exe", "TargetProcessGUID": _guid(2),
            "TargetProcessId": "200", "TargetImage": r"C:\Windows\explorer.exe",
            "GrantedAccess": "0x1fffff",
        }),
        (1, 910002, 2, {
            "ProcessGuid": _guid(3), "ParentProcessGuid": _guid(2),
            "ProcessId": "300", "ParentProcessId": "200",
            "Image": r"C:\Tools\child.exe", "CommandLine": "child.exe",
        }),
        (1, 910003, 0, {
            "ProcessGuid": _guid(2), "ParentProcessGuid": _guid(1),
            "ProcessId": "200", "ParentProcessId": "100",
            "Image": r"C:\Windows\explorer.exe", "CommandLine": "explorer.exe",
        }),
    ]
    records, sources = [], {}
    for code, record_id, seconds, data in fixtures:
        stamp = (start + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")
        hit = windows_hit(LogicalWindowsEvent(SYSMON_CHANNEL, SYSMON, code,
                          "ws01.example.test", record_id, stamp, {"UtcTime": stamp, **data}), "elastic_agent")
        record = normalize_windows(hit)
        records.append(record)
        sources.update({ref.key: hit["_source"] for ref in record.raw})
    access, child, creator = records
    repo, rule = _repo(), ParentProcessSpoofing()
    by_id = {record.id: record for record in records}
    rule.load = lambda ids: [by_id[identity] for identity in ids if identity in by_id]
    try:
        [initial] = list(rule.consume([access, child]))
        assert initial.proposed_lane == "high"
        assert publish_match(repo, "h1", rule, initial, None, sources)
        [before] = repo.candidates("h1")
        assert before["lane"] == "high"
        assert creator.id not in before["event_ids"]

        [corrected] = list(rule.consume([creator]))
        assert corrected.proposed_lane == "lead"
        assert publish_match(repo, "h1", rule, corrected, None, sources) is None
        [after] = repo.candidates("h1")
        assert after["id"] == before["id"]
        assert after["lane"] == "lead"
        assert {access.id, child.id, creator.id} <= set(after["event_ids"])
        assert creator.id in after["context_event_ids"]
        assert after["gate_results"]["_revision"]["count"] == 1
        [audit] = _audits(repo)
        assert audit["detail"]["candidate_id"] == before["id"]
        assert audit["detail"]["previous"]["lane"] == "high"
        assert audit["detail"]["revised"]["lane"] == "lead"
        assert "creator" in audit["detail"]["reason"].lower()
        assert creator.id in audit["detail"]["citations"]["added"]
        assert not list(rule.finalize())
    finally:
        rule.release_state()
        repo.engine.dispose()
