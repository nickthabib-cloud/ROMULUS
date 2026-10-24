"""Windows record identity must survive log resets and shipper copies."""

from copy import deepcopy

from romulus.evidence.normalize import normalize_hits
from romulus.evidence.windows import RecordIdContinuity
from romulus.hunt.stage import EventStage


# Shape follows Winlogbeat's exported winlog fields and Microsoft's 4688 event schema:
# https://www.elastic.co/guide/en/beats/winlogbeat/current/exported-fields-winlog.html
# https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4688
def _winlogbeat(event_id: int, *, record_id: int = 7, created: str, image: str = "") -> dict:
    event_data = {"NewProcessId": "0x200", "NewProcessName": image} if event_id == 4688 else {
        "TargetUserSid": "S-1-5-21-1-2-3-1001",
        "TargetUserName": "alice",
        "TargetDomainName": "EXAMPLE",
        "TargetLogonId": "0xabc",
        "LogonType": "3",
        "IpAddress": "203.0.113.7",
        "IpPort": "51515",
    }
    return {
        "_index": "winlogbeat-8.17.0-2026.01.02",
        "_id": f"{event_id}-{record_id}-{created}",
        "_source": {
            "@timestamp": created,
            "agent": {"type": "winlogbeat", "version": "8.17.0"},
            "winlog": {
                "channel": "Security",
                "provider_name": "Microsoft-Windows-Security-Auditing",
                "event_id": event_id,
                "computer_name": "WS01.example.test",
                "record_id": record_id,
                "time_created": created,
                "event_data": event_data,
            },
        },
    }


def test_record_id_reset_keeps_both_records_and_reports_continuity_loss():
    benign = _winlogbeat(
        4688, created="2026-01-02T00:01:00Z", image=r"C:\Windows\System32\notepad.exe"
    )
    malicious = _winlogbeat(
        4688, created="2026-01-02T01:01:00Z", image=r"C:\Tools\mimikatz.exe"
    )

    events, skips, errors = normalize_hits([benign, malicious])
    reasons = RecordIdContinuity().observe("windows", [benign, malicious])

    assert errors == [] and len(events) == 2
    assert len({event.id for event in events}) == 2
    assert {event.get("process.executable") for event in events} == {
        r"C:\Windows\System32\notepad.exe", r"C:\Tools\mimikatz.exe",
    }
    assert skips == {"record_id reused (log cleared or reverted)": 1}
    assert "record_id reused (log cleared or reverted) on Security for ws01.example.test" in reasons


def test_snapshot_revert_with_earlier_time_is_not_treated_as_a_copy():
    before = _winlogbeat(
        4688, created="2026-01-02T03:01:00Z", image=r"C:\Windows\System32\notepad.exe"
    )
    reverted = _winlogbeat(
        4688, created="2026-01-02T02:01:00Z", image=r"C:\Windows\System32\whoami.exe"
    )

    events, skips, errors = normalize_hits([before, reverted])

    assert errors == [] and len(events) == 2 and len({event.id for event in events}) == 2
    assert skips == {"record_id reused (log cleared or reverted)": 1}


def test_same_instant_records_use_structured_payload_to_distinguish_reuse_from_copy():
    original = _winlogbeat(
        4688, created="2026-01-02T00:01:00Z", image=r"C:\Windows\System32\notepad.exe"
    )
    reused = _winlogbeat(
        4688, created="2026-01-02T00:01:00Z", image=r"C:\Windows\System32\whoami.exe"
    )
    copied = deepcopy(original)
    copied["_index"] = "winlogbeat-copy"
    copied["_id"] = "shipper-copy"

    events, skips, errors = normalize_hits([original, reused, copied])

    assert errors == [] and len(events) == 2 and len({event.id for event in events}) == 2
    assert {event.get("process.executable") for event in events} == {
        r"C:\Windows\System32\notepad.exe", r"C:\Windows\System32\whoami.exe",
    }
    assert skips == {
        "record_id reused (log cleared or reverted)": 1,
        "duplicate Windows event copy (computer/channel/record_id)": 1,
    }


def test_cross_family_record_id_reuse_keeps_each_event():
    process = _winlogbeat(
        4688, created="2026-01-02T00:01:00Z", image=r"C:\Windows\System32\notepad.exe"
    )
    logon = _winlogbeat(4624, created="2026-01-02T00:02:00Z")

    events, skips, errors = normalize_hits([process, logon])

    assert errors == [] and {event.family for event in events} == {"process_exec", "auth"}
    assert len({event.id for event in events}) == 2
    assert skips == {"record_id reused (log cleared or reverted)": 1}


def test_cross_partition_exact_copy_deduplicates_but_reused_record_id_does_not(tmp_path):
    original = _winlogbeat(
        4688, created="2026-01-02T00:01:00Z", image=r"C:\Windows\System32\notepad.exe"
    )
    copied = deepcopy(original)
    copied["_index"] = "winlogbeat-copy"
    copied["_id"] = "shipper-copy"
    reused = _winlogbeat(
        4688, created="2026-01-02T01:01:00Z", image=r"C:\Tools\mimikatz.exe"
    )
    first = normalize_hits([original])[0][0]
    duplicate = normalize_hits([copied])[0][0]
    replacement = normalize_hits([reused])[0][0]
    stage = EventStage(tmp_path)

    assert stage.unique_windows([first]) == ([first], [])
    fresh, duplicates = stage.unique_windows([duplicate])
    reused_fresh, reused_duplicates = stage.unique_windows([replacement])

    assert fresh == [] and len(duplicates) == 1
    assert reused_fresh == [replacement] and reused_duplicates == []
    assert first.id == duplicate.id and replacement.id != first.id
    stage.close()
