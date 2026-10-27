"""Adversarial typed-field and publication proofs for file/resolver signals."""
from dataclasses import replace

import pytest

from romulus.detect.windows_events import writable
from romulus.detect.windows_file_events import (
    CodeRunnerDnsLookup,
    ExecutableAlternateStream,
    ExecutableCreationTimeChange,
    LureApplicationFileWrite,
    StartupFileWrite,
    WritableExecutableDeletion,
)
from romulus.evidence.typed import fv
from tests.windows_event_support import event, run

STARTUP = r"C:\Users\analyst\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.ps1"


@pytest.mark.parametrize("path", [r"C:\Users\alice\Documents\x.dll", r"D:\Users\alice\x.dll",
                                 r"C:\Users\alice\OneDrive\x.dll", r"C:\Temp\x.dll",
                                 r"C:\Windows\Temp\x.dll", r"%USERPROFILE%\Documents\x.dll",
                                 r"\Device\HarddiskVolume3\Users\alice\x.dll",
                                 r"\\?\C:\Users\alice\x.dll"])
def test_standard_profile_and_temporary_paths_are_recognized(path):
    assert writable(path)
    [match] = run(LureApplicationFileWrite(), [event("file_change", 11, **{
        "file.path": path, "process.executable": "chrome.exe",
    })])
    assert match.proposed_lane == "lead"


@pytest.mark.parametrize("path", [r"C:\Apps\Downloads\x.dll", r"C:\Backup\Temp\x.dll",
                                 r"C:\Backup\Users\alice\x.dll", r"C:\Users\alice\..\..\Windows\x.dll",
                                 r"C:\Apps\AppData\x.dll", r"\\server\share\Users\alice\x.dll"])
def test_familiar_directory_names_do_not_establish_a_profile_or_temporary_root(path):
    assert not writable(path)


@pytest.mark.parametrize("path", [STARTUP.replace(r"Users\analyst\AppData\Roaming", "Fake"),
                                 STARTUP.replace(r"Users\analyst\AppData\Roaming", r"Backup\Users\analyst\AppData\Roaming"),
                                 STARTUP.replace(r"Startup\payload", r"Startup\subfolder\payload")])
def test_fake_prefixes_and_nested_files_do_not_claim_the_startup_folder(path):
    assert not run(StartupFileWrite(), [event("file_change", 11, **{"file.path": path})])


@pytest.mark.parametrize("path", [r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\x.exe",
                                 r"%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup\x.exe",
                                 r"\Device\HarddiskVolume2\Users\alice\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\x.exe"])
def test_startup_environment_and_native_volume_roots_are_supported(path):
    assert run(StartupFileWrite(), [event("file_change", 11, **{"file.path": path})])


@pytest.mark.parametrize("path", [STARTUP, STARTUP.lower(),
                                 r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe"])
def test_startup_file_is_immediate_even_without_a_resolved_writer(path):
    rule = StartupFileWrite()
    [match] = rule.consume([event("file_change", 11, **{"file.path": path})])
    assert "writer image is unresolved" in match.claim and match.proposed_lane == "lead"
    assert rule.assures_negative is False


@pytest.mark.parametrize("path,code", [(STARTUP + ".txt", 11), (STARTUP.replace("Startup", "StartupBackup"), 11),
                                      (STARTUP, 26), (r"C:\Downloads\readme.txt", 11)])
def test_startup_requires_whole_directory_components_extension_and_write_class(path, code):
    assert not run(StartupFileWrite(), [event("file_change", code, **{"file.path": path})])


@pytest.mark.parametrize("writer", ["winword.exe", "chrome.exe", "msedge.exe", "outlook.exe"])
def test_lure_writer_file_creation_states_only_creation(writer):
    [match] = run(LureApplicationFileWrite(), [event("file_change", 11, **{
        "file.path": r"C:\Users\analyst\Downloads\payload.exe", "process.executable": writer,
    })])
    assert "execution is not established" in match.claim


@pytest.mark.parametrize("writer,path", [("not-winword.exe", r"C:\Temp\a.exe"),
                                       ("winword.exe", r"C:\Windows\System32\a.exe"),
                                       ("winword.exe", r"C:\Temp\a.docx")])
def test_lure_writer_hard_negatives(writer, path):
    assert not run(LureApplicationFileWrite(), [event("file_change", 11, **{
        "file.path": path, "process.executable": writer,
    })])


@pytest.mark.parametrize("name,body", [("Zone.Identifier", "MZ\x00payload"),
                                      ("cache", "Invoke-Expression $payload"), ("payload.ps1", "unclassified")])
def test_executable_stream_does_not_exclude_attacker_controlled_stream_names(name, body):
    [match] = run(ExecutableAlternateStream(), [event("file_change", 15, **{
        "file.stream.name": name, "file.stream.content": body, "file.stream.base_path": r"C:\Temp\base.txt",
    })])
    assert "does not establish execution" in match.claim


def test_ordinary_zone_metadata_is_not_executable_content():
    assert not run(ExecutableAlternateStream(), [event("file_change", 15, **{
        "file.stream.name": "Zone.Identifier", "file.stream.content": "[ZoneTransfer]\nZoneId=3",
    })])


def test_changed_executable_timestamp_and_unknown_values_surface_with_accurate_claim():
    first = event("file_change", 2, **{"file.path": r"C:\Temp\payload.exe",
                                      "file.previous_creation_time": "2026-01-01", "file.creation_time": "2020-01-01"})
    [match] = run(ExecutableCreationTimeChange(), [first])
    assert "2026-01-01" in match.claim and "2020-01-01" in match.claim
    unknown = event("file_change", 2, **{"file.path": r"C:\Temp\payload.exe"})
    assert "unresolved" in run(ExecutableCreationTimeChange(), [unknown])[0].claim
    equal = first.model_copy(deep=True)
    equal.fields["file.creation_time"] = fv("2026-01-01", "native")
    assert not run(ExecutableCreationTimeChange(), [equal])


@pytest.mark.parametrize("code", [23, 26])
def test_deletion_names_observed_file_action_and_not_malicious_intent(code):
    [match] = run(WritableExecutableDeletion(), [event("file_change", code, **{"file.path": r"C:\Temp\x.exe"})])
    assert "purpose of the deletion is unresolved" in match.claim
    assert not run(WritableExecutableDeletion(), [event("file_change", code, **{"file.path": r"C:\Temp\x.txt"})])


def test_dns_identity_is_signal_even_for_benign_domain_and_failed_resolution():
    [match] = run(CodeRunnerDnsLookup(), [event("dns_lookup", 22, **{
        "process.executable": r"C:\Windows\System32\mshta.exe", "dns.question.name": "microsoft.com", "dns.status": 9003,
    })])
    assert "image identity is the signal" in match.claim and match.proposed_lane == "lead"
    assert not run(CodeRunnerDnsLookup(), [event("dns_lookup", 22, **{
        "process.executable": "not-mshta.exe", "dns.question.name": "bad.example",
    })])


def test_new_host_and_new_payload_publish_before_finalize_and_repeats_revise_in_place():
    records = [event("file_change", 11, host=host, offset=index, **{"file.path": path})
               for index, (host, path) in enumerate([
                   ("one", STARTUP), ("two", STARTUP), ("one", STARTUP.replace("payload", "other")),
                   ("one", STARTUP), ("one", STARTUP),
               ])]
    rule = StartupFileWrite()
    by_id = {item.id: item for item in records}
    rule.load = lambda ids: [by_id[identity] for identity in ids if identity in by_id]
    matches = []
    for item in records:
        matches.extend(rule.consume([item]))
        rule.drain_staged()
        rule.drain_bounds()
    own = [match for match in matches if not match.group_key]
    assert len(own) == 3 and {match.events[0].host for match in own} == {"one", "two"}
    finals = rule.finalize()
    assert len(finals) == 1 and finals[0].revision_reason
    assert "Windows event record(s)" in finals[0].claim and "process-creation" not in finals[0].claim
    running = [match for match in matches if match.group_key]
    assert running[0].group_key == finals[0].group_key
    assert replace(finals[0], revision_reason="").group_key == finals[0].group_key


@pytest.mark.parametrize("rule", [StartupFileWrite, LureApplicationFileWrite, ExecutableAlternateStream,
                                  ExecutableCreationTimeChange, WritableExecutableDeletion, CodeRunnerDnsLookup])
def test_file_rules_reject_linux_os_scope(rule):
    record = event(rule.families[0], 11, **{"file.path": STARTUP})
    record.fields["host.os.family"] = fv("linux", "native")
    assert not run(rule(), [record])
