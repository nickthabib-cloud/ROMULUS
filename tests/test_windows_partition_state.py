"""Windows collection reasons read a partition's records once for every rule, with the same reasons as a per-rule
read: hosts, channel first/last times and collection breaks are derived once per partition, and each event class's
per-host reasons once, however many Windows rules the pack holds."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from romulus.detect.base import Playbook
from romulus.evidence.windows import windows_view
from romulus.evidence.windows_catalog import (
    COLLECTION_CHANGE_EVENTS,
    EVENT_CLASSES,
    SECURITY,
    SYSMON,
    SYSMON_CHANNEL,
    collection_requirements,
    event_classes_for_families,
    lookup_event_class,
)
from romulus.hunt import sweep as sweep_module
from romulus.hunt.sweep import NXLOG_MIXED_GATE, Sweep, WindowsPartitionState
from romulus.site import load_site_facts
from romulus.sources.models import Completeness, SearchOutcome, Window
from romulus.sources.profile import FieldContract, contract_from_types

START = datetime(2026, 1, 2, tzinfo=UTC)
POWERSHELL_CHANNEL = "Microsoft-Windows-PowerShell/Operational"
POWERSHELL = "Microsoft-Windows-PowerShell"


# ---- the per-rule derivation as it was before the partition state: the reference the shared state must equal ----

def _reference_hosts(contract, records):
    hosts = {str(host).strip().rstrip(".").casefold() for host in contract.hosts if host}
    for record in records:
        winlog = windows_view(record.get("_source") or {}).get("winlog") or {}
        computer = str(winlog.get("computer_name") or "").strip().rstrip(".").casefold()
        if computer:
            hosts.add(computer)
    return tuple(sorted(hosts))


def _reference_windows_rule_reasons(
    sweep,
    target: str,
    contract: FieldContract | None,
    playbook: Playbook,
    records: list[dict],
    gap_reasons: list[str],
    partition: Window | None = None,
    continuity_times: dict[tuple[str, str], tuple[datetime, datetime]] | None = None,
) -> list[str]:
    if contract is not None and contract.ecar and "windows" in playbook.os_families:
        reasons = ["collection not attested: eCAR sensor", *gap_reasons]
        if playbook.windows_event_classes and not getattr(playbook, "ecar_compatible", False):
            reasons.append("eCAR records have no Windows event id")
        return reasons
    if (contract is not None and contract.nxlog_mixed and contract.os_family != "windows"
            and "windows" in playbook.os_families):
        # NXLog's flat records on a Linux target: no Windows rule's search there is ever complete
        return [NXLOG_MIXED_GATE]
    if contract is None or contract.role != "host" or contract.os_family != "windows" or "windows" not in playbook.os_families:
        return []
    catalog = event_classes_for_families(set(playbook.families))
    if not catalog:
        return []
    inventory = sweep._windows_inventory.get(target, set())
    reasons = list(sweep._windows_inventory_reasons.get(target, ()))
    if playbook.windows_event_classes:
        required = []
        for channel, provider, event_id in playbook.windows_event_classes:
            event_class = lookup_event_class(channel, provider, event_id)
            if event_class is None:
                reasons.append(
                    f"event class declaration is not cataloged: {channel}|{provider}|{event_id}"
                )
            else:
                required.append(event_class)
    else:
        required = list(catalog)
    if any(event.family == "database_audit" for event in required):
        # A default-instance declaration represents this SQL event shape,
        # not a requirement that a differently named instance also exist.
        # Preserve each concrete observed provider in collection evidence.
        observed_sql = [event for event in (*EVENT_CLASSES, *sweep._windows_dynamic_classes.get(target, ()))
                        if event.family == "database_audit" and event.token in inventory]
        expanded = {}
        for event in required:
            equivalents = [observed for observed in observed_sql
                           if event.family == "database_audit"
                           and observed.channel.casefold() == event.channel.casefold()
                           and observed.event_id == event.event_id]
            for concrete in equivalents or [event]:
                expanded[concrete.token] = concrete
        required = list(expanded.values())
    for event_class in required:
        if event_class.token not in inventory:
            reasons.append(
                "event class absent from source inventory: "
                f"{event_class.channel}|{event_class.provider}|{event_class.event_id}"
            )
    reasons.extend(gap_reasons)
    hosts = set(_reference_hosts(contract, records))
    if continuity_times is not None:
        hosts.update(host for host, _channel in continuity_times)
    hosts = tuple(sorted(hosts))
    if not contract.host_inventory_complete:
        reasons.append("collection not attested: source host inventory truncated")
    if not hosts:
        reasons.append("collection not attested: source host inventory unavailable")
    if continuity_times is None:
        observed_channels = {
            (
                str((windows_view(record.get("_source") or {}).get("winlog") or {}).get("computer_name") or "")
                .strip().rstrip(".").casefold(),
                str((windows_view(record.get("_source") or {}).get("winlog") or {}).get("channel") or "").casefold(),
            )
            for record in records
        }
        observed_times: dict[tuple[str, str], tuple[datetime, datetime]] = {}
        for record in records:
            source = windows_view(record.get("_source") or {})
            winlog = source.get("winlog") or {}
            host = str(winlog.get("computer_name") or "").strip().rstrip(".").casefold()
            channel = str(winlog.get("channel") or "").casefold()
            raw_time = winlog.get("time_created") or source.get("@timestamp")
            try:
                when = datetime.fromisoformat(str(raw_time)).astimezone(UTC)
            except (TypeError, ValueError):
                continue
            key = (host, channel)
            prior = observed_times.get(key)
            observed_times[key] = (
                (when, when) if prior is None else (min(prior[0], when), max(prior[1], when))
            )
    else:
        observed_channels = set(continuity_times)
        observed_times = dict(continuity_times)
    collection_changes, cross_channel_collection_changes = _reference_collection_changes(records)

    def summarize(label: str, affected: list[str], event_class) -> str | None:
        affected = sorted(set(affected))
        if not affected:
            return None
        if len(affected) == 1:
            return f"{label} on {affected[0]}"
        sample = ", ".join(affected[:10])
        token = f"{event_class.channel}|{event_class.provider}|{event_class.event_id}"
        return f"{label} on {len(affected):,} hosts [{token}] (sample: {sample})"

    for event_class in required:
        absent_hosts: list[str] = []
        late_start_hosts: list[str] = []
        early_stop_hosts: list[str] = []
        unattested_by_label: dict[str, list[str]] = {}
        single_edge_details: dict[tuple[str, str], str] = {}
        for host in hosts:
            channel_key = (host, event_class.channel.casefold())
            reasons.extend(sorted(cross_channel_collection_changes.get(host, ())))
            reasons.extend(sorted(collection_changes.get(channel_key, ())))
            if channel_key not in observed_channels:
                absent_hosts.append(host)
            elif partition is not None and observed_times.get(channel_key):
                first, last = observed_times[channel_key]
                if first > partition.start + sweep.windows_liveness_tolerance:
                    late_start_hosts.append(host)
                    single_edge_details[("before", host)] = first.isoformat()
                if last < partition.end - sweep.windows_liveness_tolerance:
                    early_stop_hosts.append(host)
                    single_edge_details[("after", host)] = last.isoformat()
            for fact, arguments, label in collection_requirements(event_class):
                if not sweep.site_facts.attests(host, fact, **arguments):
                    unattested_by_label.setdefault(label, []).append(host)
        summarized = summarize(
            f"shipper gaps unresolved: no records on {event_class.channel} in partition",
            absent_hosts, event_class,
        )
        if summarized:
            reasons.append(summarized)
        for edge, affected in (("before", late_start_hosts), ("after", early_stop_hosts)):
            if len(set(affected)) == 1:
                host = affected[0]
                reasons.append(
                    f"no records from {host}/{event_class.channel} {edge} "
                    f"{single_edge_details[(edge, host)]}"
                )
            else:
                summarized = summarize(
                    f"no records from {event_class.channel} near partition {edge} edge",
                    affected, event_class,
                )
                if summarized:
                    reasons.append(summarized)
        for label, affected in unattested_by_label.items():
            summarized = summarize(f"collection not attested: {label}", affected, event_class)
            if summarized:
                reasons.append(summarized)
    return sorted(set(reasons))

def _reference_collection_changes(
    records: list[dict],
) -> tuple[dict[tuple[str, str], set[str]], dict[str, set[str]]]:
    """Classify collection breaks by native host and either one channel or every channel on that host."""
    collection_changes: dict[tuple[str, str], set[str]] = {}
    cross_channel_collection_changes: dict[str, set[str]] = {}
    for record in records:
        source = windows_view(record.get("_source") or {})
        winlog = source.get("winlog") or {}
        host = str(winlog.get("computer_name") or "").strip().rstrip(".").casefold()
        channel = str(winlog.get("channel") or "").casefold()
        raw_time = winlog.get("time_created") or source.get("@timestamp")
        try:
            when = datetime.fromisoformat(str(raw_time)).astimezone(UTC)
        except (TypeError, ValueError):
            continue
        try:
            event_id = int(winlog.get("event_id"))
        except (TypeError, ValueError):
            continue
        provider = str(winlog.get("provider_name") or "").strip()
        change = COLLECTION_CHANGE_EVENTS.get((channel, provider.casefold(), event_id))
        if (change and provider.casefold() == "microsoft-windows-sysmon" and event_id == 4
                and str((winlog.get("event_data") or {}).get("State") or "").casefold() == "started"):
            change = None
        if change and host:
            reason = (
                f"collection changed on {host} at {when.isoformat()}: "
                f"{winlog.get('channel')}|{provider}|{event_id} ({change})"
            )
            # Security/audit-service controls invalidate every Windows channel; provider-operational
            # controls govern only the channel that emitted them.
            if event_id in {104, 1102, 4719, 6006}:
                cross_channel_collection_changes.setdefault(host, set()).add(reason)
            else:
                collection_changes.setdefault((host, channel), set()).add(reason)
    return collection_changes, cross_channel_collection_changes


# ---- a mixed Windows partition: several hosts and channels, edges, collection breaks, malformed records ----

_DATASETS = {
    SYSMON_CHANNEL: "windows.sysmon_operational",
    "Security": "windows.security",
    "System": "windows.system",
    POWERSHELL_CHANNEL: "windows.powershell_operational",
}


def _record(number, host, channel, provider, event_id, minute, *, event_data=None, time_created=True, raw_time=None):
    when = (START + timedelta(minutes=minute)).isoformat()
    winlog = {
        "channel": channel,
        "provider_name": provider,
        "event_id": event_id,
        "computer_name": host,
        "record_id": number,
        "event_data": event_data or {},
    }
    if time_created:
        winlog["time_created"] = when
    return {
        "_index": "logs-windows",
        "_id": f"w-{number}",
        "_source": {
            "@timestamp": raw_time if raw_time is not None else when,
            "agent": {"type": "winlogbeat"},
            "host": {"id": f"machine-{host.casefold()}"},
            "event": {"dataset": _DATASETS[channel]},
            "winlog": winlog,
        },
    }


def _mixed_records():
    records = []
    number = iter(range(1000, 100_000))

    def add(*args, **kwargs):
        records.append(_record(next(number), *args, **kwargs))

    # WS01: live Sysmon and Security over the whole partition; a Sysmon configuration change (channel-scoped),
    # a Sysmon "Started" state (not a break) and an audit policy change (every channel on the host).
    for minute in (1, 12, 33, 58):
        add("WS01.example.test", SYSMON_CHANNEL, SYSMON, 1, minute,
            event_data={"Image": "C:\\Windows\\System32\\cmd.exe"})
    add("WS01.example.test", SYSMON_CHANNEL, SYSMON, 4, 10, event_data={"State": "Started"})
    add("WS01.example.test", SYSMON_CHANNEL, SYSMON, 16, 20)
    add("WS01.example.test", "Security", SECURITY, 4688, 2)
    add("WS01.example.test", "Security", SECURITY, 4688, 57, time_created=False)
    add("WS01.example.test", "Security", SECURITY, 4719, 30)
    # ws02 (trailing dot, lowercase): Sysmon starts late and stops early; PowerShell once; a Sysmon error.
    add("ws02.example.test.", SYSMON_CHANNEL, SYSMON, 1, 25)
    add("ws02.example.test.", SYSMON_CHANNEL, SYSMON, 1, 30)
    add("ws02.example.test.", SYSMON_CHANNEL, SYSMON, 255, 28)
    add("ws02.example.test.", POWERSHELL_CHANNEL, POWERSHELL, 4104, 40,
        event_data={"ScriptBlockText": "Get-Date", "ScriptBlockId": "b1", "MessageNumber": "1",
                    "MessageTotal": "1"})
    # WS03: Security only, and an event log cleared on System (every channel on the host).
    add("WS03.example.test", "Security", SECURITY, 4688, 5)
    add("WS03.example.test", "Security", SECURITY, 4688, 56)
    add("WS03.example.test", "System", "Microsoft-Windows-Eventlog", 104, 50)
    # WS04: a record whose time cannot be read and one whose event id is not a number.
    add("WS04.example.test", SYSMON_CHANNEL, SYSMON, 1, 15, time_created=False, raw_time="not-a-time")
    add("WS04.example.test", SYSMON_CHANNEL, SYSMON, "sixteen", 16)
    # a record that names no computer
    add("", SYSMON_CHANNEL, SYSMON, 1, 3)
    return records


def _adapted_records():
    """Records the reasons read through the Windows view's adapters: a native EVTX JSON record (a Security log
    cleared, every channel on its host) and an NXLog flat record (a Sysmon configuration change)."""
    from tests.test_nxlog_windows import nxlog_hit

    evtx = {"_index": "logs-windows", "_id": "evtx-1", "_source": {"Event": {
        "#attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"},
        "System": {
            "Provider": {"#attributes": {"Name": "Microsoft-Windows-Eventlog"}}, "EventID": 1102,
            "Version": 1, "Level": 4, "Task": 104, "Opcode": 0, "Keywords": "0x4020000000000000",
            "TimeCreated": {"#attributes": {"SystemTime": (START + timedelta(minutes=45)).isoformat()}},
            "EventRecordID": 77, "Execution": {"#attributes": {"ProcessID": 4, "ThreadID": 68}},
            "Channel": "Security", "Computer": "WS07.example.test", "Security": None,
        },
        "UserData": {"LogFileCleared": {"SubjectUserName": "operator"}},
    }}}
    nxlog = nxlog_hit(_record(9001, "WS08.example.test", SYSMON_CHANNEL, SYSMON, 16, 35))
    return [evtx, nxlog]


def _contract(hosts=("ws01.example.test", "ws05.example.test")):
    return contract_from_types(
        "windows-target",
        {
            "@timestamp": "date",
            "event.dataset": "keyword",
            "host.id": "keyword",
            "winlog.channel": "keyword",
            "winlog.provider_name": "keyword",
            "winlog.event_id": "long",
            "winlog.computer_name": "keyword",
            "winlog.record_id": "long",
            "winlog.event_data": "flattened",
            "winlog.time_created": "date",
        },
        role="host",
        os_family="windows",
        hosts=hosts,
    )


def _site(tmp_path):
    path = tmp_path / "site" / "collection.yaml"
    path.parent.mkdir(parents=True)
    path.write_text(
        "schema: romulus-site-collection@1\n"
        "collection:\n"
        "  - hosts: [ws01.example.test, ws02.example.test]\n"
        "    sysmon:\n"
        "      installed: true\n"
        "      event_ids: [1, 3]\n",
        encoding="utf-8",
    )
    return load_site_facts(tmp_path)


def _inventory():
    tokens = set()
    for channel, provider, event_id in ((SYSMON_CHANNEL, SYSMON, 1), ("Security", SECURITY, 4688),
                                        (POWERSHELL_CHANNEL, POWERSHELL, 4104)):
        event_class = lookup_event_class(channel, provider, event_id)
        assert event_class is not None
        tokens.add(event_class.token)
    return tokens


def _sweep(tmp_path, contract, window, repo=None, name="sweep"):
    sweep = Sweep(repo, None, "h1", window, {contract.target: contract},
                  site_facts=_site(tmp_path / name), stage_dir=tmp_path / name)
    sweep._windows_inventory[contract.target] = _inventory()
    sweep._windows_inventory_reasons[contract.target] = []
    return sweep


def _windows_views(sweep):
    from romulus.content.sigma_coverage import coverage_view
    from romulus.detect.sigma import SigmaRule

    return [coverage_view(pb) if isinstance(pb, SigmaRule) else pb
            for pb in sweep.pack if "windows" in pb.os_families]


def test_fixture_exercises_every_kind_of_windows_reason(tmp_path):
    """The mixed fixture is only a useful equivalence check if it produces each kind of reason."""
    contract = _contract()
    window = Window(start=START, end=START + timedelta(hours=1))
    sweep = _sweep(tmp_path, contract, window)
    records = [*_mixed_records(), *_adapted_records()]
    state = WindowsPartitionState(contract, records, window, None)
    reasons = set()
    for view in _windows_views(sweep):
        reasons.update(sweep._windows_rule_reasons(contract.target, contract, view, records, [], window, None, state))
    text = "\n".join(sorted(reasons))
    for expected in (
        "collection changed on ws01.example.test at 2026-01-02T00:20:00+00:00",   # channel-scoped Sysmon change
        "collection changed on ws01.example.test at 2026-01-02T00:30:00+00:00",   # audit policy, every channel
        "collection changed on ws03.example.test at 2026-01-02T00:50:00+00:00",   # log cleared, every channel
        "shipper gaps unresolved: no records on Microsoft-Windows-Sysmon/Operational in partition on",
        "no records from ws02.example.test/Microsoft-Windows-PowerShell/Operational before",
        "no records from ws02.example.test/Microsoft-Windows-PowerShell/Operational after",
        "no records from Microsoft-Windows-Sysmon/Operational near partition before edge on 3 hosts",
        "no records from Microsoft-Windows-Sysmon/Operational near partition after edge on 3 hosts",
        "collection not attested: Sysmon event id 1 on",
        "event class absent from source inventory:",
    ):
        assert expected in text, expected
    assert "2026-01-02T00:10:00" not in text  # Sysmon "Started" is not a collection break
    assert "ws05.example.test" in text        # an inventory host with no records
    assert "collection changed on ws07.example.test" in text  # read through the EVTX JSON adapter
    assert "ws08.example.test" in text        # read through the NXLog adapter


def test_shared_partition_state_gives_every_windows_rule_the_per_rule_reasons(tmp_path):
    contract = _contract()
    window = Window(start=START, end=START + timedelta(hours=1))
    sweep = _sweep(tmp_path, contract, window)
    records = [*_mixed_records(), *_adapted_records()]
    gaps = ["shipper gaps unresolved: fixture gap"]
    views = _windows_views(sweep)
    assert len(views) > 50
    state = WindowsPartitionState(contract, records, window, None)
    for view in views:
        expected = _reference_windows_rule_reasons(sweep, contract.target, contract, view, records, gaps, window)
        shared = sweep._windows_rule_reasons(contract.target, contract, view, records, gaps, window, None, state)
        assert shared == expected, view.id
        # a caller that extends the list it gets back never changes what the next rule reads
        shared.append("caller-added reason")
        assert sweep._windows_rule_reasons(contract.target, contract, view, records, gaps, window, None,
                                           state) == expected
    # no partition (a direct call) and no state: same reasons as before
    for view in views[:20]:
        assert (sweep._windows_rule_reasons(contract.target, contract, view, records, [])
                == _reference_windows_rule_reasons(sweep, contract.target, contract, view, records, []))


def test_shared_state_matches_per_rule_reasons_with_selective_continuity_times(tmp_path):
    contract = _contract()
    window = Window(start=START, end=START + timedelta(hours=1))
    sweep = _sweep(tmp_path, contract, window)
    records = [*_mixed_records(), *_adapted_records()]
    sysmon = SYSMON_CHANNEL.casefold()
    continuity_times = {
        ("ws01.example.test", sysmon): (START + timedelta(minutes=1), START + timedelta(minutes=58)),
        ("ws01.example.test", "security"): (START + timedelta(minutes=2), START + timedelta(minutes=57)),
        ("ws02.example.test", sysmon): (START + timedelta(minutes=25), START + timedelta(minutes=30)),
        ("ws06.example.test", "security"): (START, START + timedelta(minutes=59)),  # a host only the metadata saw
    }
    state = WindowsPartitionState(contract, records, window, continuity_times)
    for view in _windows_views(sweep):
        assert (sweep._windows_rule_reasons(contract.target, contract, view, records, [], window, continuity_times,
                                            state)
                == _reference_windows_rule_reasons(sweep, contract.target, contract, view, records, [], window,
                                                   continuity_times)), view.id


def test_a_state_built_for_other_inputs_is_never_reused(tmp_path):
    contract = _contract()
    window = Window(start=START, end=START + timedelta(hours=1))
    sweep = _sweep(tmp_path, contract, window)
    records = _mixed_records()
    other = WindowsPartitionState(contract, records[:3], window, None)
    view = next(view for view in _windows_views(sweep) if view.windows_event_classes)
    assert (sweep._windows_rule_reasons(contract.target, contract, view, records, [], window, None, other)
            == _reference_windows_rule_reasons(sweep, contract.target, contract, view, records, [], window))
    shifted = Window(start=START + timedelta(minutes=20), end=START + timedelta(minutes=80))
    stale = WindowsPartitionState(contract, records, window, None)
    assert (sweep._windows_rule_reasons(contract.target, contract, view, records, [], shifted, None, stale)
            == _reference_windows_rule_reasons(sweep, contract.target, contract, view, records, [], shifted))


def _serve(monkeypatch, records):
    monkeypatch.setattr(sweep_module, "execute", lambda _client, intent, _contract: SearchOutcome(
        target=intent.target,
        fingerprint="mixed-windows",
        started_at=START,
        ended_at=START,
        completeness=Completeness.complete,
        total=len(records),
        total_relation="eq",
        returned=len(records),
        records=records,
    ))


def _cells(repo):
    cells = []
    for cell in repo.rule_cells("h1"):
        detail = dict(cell["detail"] or {})
        detail.pop("timing", None)
        cells.append((cell["rule_id"], cell["rule_version"], cell["target"], cell["partition"], cell["state"],
                      cell["matched"], cell["evaluated"], repr(sorted(detail.items()))))
    return sorted(cells)


def test_coverage_cells_equal_the_per_rule_derivation_over_the_whole_pack(tmp_path, monkeypatch):
    from tests.test_sweep import _repo

    contract = _contract()
    window = Window(start=START, end=START + timedelta(hours=1))
    records = _mixed_records()
    _serve(monkeypatch, records)

    shared_repo = _repo()
    shared = _sweep(tmp_path, contract, window, shared_repo, "shared")
    shared.run_partition(contract.target, contract, [], window, est=len(records))
    shared.close_stage()

    reference_repo = _repo()
    reference = _sweep(tmp_path, contract, window, reference_repo, "reference")
    monkeypatch.setattr(reference, "_windows_rule_reasons", lambda *args: _reference_windows_rule_reasons(
        reference, *args[:7]))
    reference.run_partition(contract.target, contract, [], window, est=len(records))
    reference.close_stage()

    shared_cells = _cells(shared_repo)
    assert shared_cells == _cells(reference_repo)
    windows_cells = [cell for cell in shared_cells if "collection changed on ws01.example.test" in cell[-1]]
    assert len(windows_cells) > 50


def _count_views(monkeypatch):
    calls = {"views": 0, "derivations": 0}
    real_view = sweep_module.windows_view
    real_derive = WindowsPartitionState.derive

    def counted_view(source):
        calls["views"] += 1
        return real_view(source)

    def counted_derive(self):
        if not self.derived:
            calls["derivations"] += 1
        return real_derive(self)

    monkeypatch.setattr(sweep_module, "windows_view", counted_view)
    monkeypatch.setattr(WindowsPartitionState, "derive", counted_derive)
    return calls


def test_a_partition_reads_each_record_once_for_all_windows_rules(tmp_path, monkeypatch):
    """O(records) per partition, not O(records x rules): the count is the same for one Windows rule or the pack."""
    from tests.test_sweep import _repo

    contract = _contract()
    window = Window(start=START, end=START + timedelta(hours=1))
    records = _mixed_records()
    _serve(monkeypatch, records)
    calls = _count_views(monkeypatch)

    full = _sweep(tmp_path, contract, window, _repo(), "full")
    windows_rules = sum("windows" in pb.os_families for pb in full.pack)
    assert windows_rules > 50
    full.run_partition(contract.target, contract, [], window, est=len(records))
    full.close_stage()
    full_calls = dict(calls)

    calls.update(views=0, derivations=0)
    single = _sweep(tmp_path, contract, window, _repo(), "single")
    single.pack = [next(pb for pb in single.pack if "windows" in pb.os_families and pb.windows_event_classes)]
    single.run_partition(contract.target, contract, [], window, est=len(records))
    single.close_stage()

    assert full_calls == {"views": len(records), "derivations": 1}
    assert dict(calls) == full_calls


def test_large_partition_derives_once_and_each_event_class_once(tmp_path, monkeypatch):
    """A mission-sized partition (2,000 hosts, 12,001 records) is read once for every Windows rule in the pack, and
    each event class's per-host reasons are built once, however many rules require the class."""
    hosts = tuple(f"ws{number:04d}.example.test" for number in range(2_000))
    contract = _contract(hosts=hosts[:100])
    window = Window(start=START, end=START + timedelta(hours=1))
    sweep = _sweep(tmp_path, contract, window)
    records = []
    for index, host in enumerate(hosts):
        for minute in (1, 20, 40, 58):
            records.append(_record(len(records), host, SYSMON_CHANNEL, SYSMON, 1, minute))
        records.append(_record(len(records), host, "Security", SECURITY, 4688, index % 60))
        records.append(_record(len(records), host, POWERSHELL_CHANNEL, POWERSHELL, 4104, 30))
    records.append(_record(len(records), hosts[7], "Security", SECURITY, 4719, 31))
    calls = _count_views(monkeypatch)
    built = []
    real_class_reasons = Sweep._windows_class_reasons

    def counted_class_reasons(self, state, event_class):
        if event_class not in state.class_reasons:
            built.append(event_class)
        return real_class_reasons(self, state, event_class)

    monkeypatch.setattr(Sweep, "_windows_class_reasons", counted_class_reasons)
    state = WindowsPartitionState(contract, records, window, None)
    views = _windows_views(sweep)
    results = [sweep._windows_rule_reasons(contract.target, contract, view, records, [], window, None, state)
               for view in views]

    assert calls == {"views": len(records), "derivations": 1}
    assert len(built) == len(set(built))
    assert len(built) <= len(EVENT_CLASSES)
    # the per-host breaks and summaries stay bounded by the host count, never by rules x hosts
    assert any("collection changed on ws0007.example.test" in reason for result in results for reason in result)
    assert all(len(result) < 200 for result in results)


def test_collection_change_classification_is_unchanged_by_the_shared_helper():
    records = _mixed_records()
    assert Sweep._windows_collection_changes(records) == _reference_collection_changes(records)
    state = WindowsPartitionState(_contract(), records, None, None)
    state.derive()
    reference_changes, reference_cross = _reference_collection_changes(records)
    assert state.collection_changes == reference_changes
    assert set(state.cross_channel_reasons) == set().union(*reference_cross.values())
    assert state.hosts == _reference_hosts(_contract(), records)
