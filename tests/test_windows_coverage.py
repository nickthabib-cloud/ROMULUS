"""Windows coverage requires inventory, streaming continuity, and site collection attestations."""

from __future__ import annotations

import gc
from datetime import UTC, datetime, timedelta

from romulus.detect.base import Playbook
from romulus.detect.bounded import StateBudget, StateExhausted, live_stores
from romulus.detect.registry import ALL_PLAYBOOKS
from romulus.evidence.normalize import normalize_hits
from romulus.evidence.typed import RawRef, TypedEvent
from romulus.evidence.windows import RecordIdContinuity
from romulus.evidence.windows_catalog import (
    COLLECTION_CHANGE_EVENTS,
    EVENT_CLASSES,
    SECURITY,
    SYSMON,
    SYSMON_CHANNEL,
    collection_requirements,
    lookup_event_class,
)
from romulus.hunt.stage import EventStage
from romulus.hunt.sweep import MAX_WINDOWS_UNCATALOGUED, Sweep
from romulus.site import load_site_facts
from romulus.sources.models import Completeness, SearchOutcome, Window
from romulus.sources.profile import contract_from_types

START = datetime(2026, 1, 2, tzinfo=UTC)


def _hit(record_id: int | str, event_id: int = 1, *, native_id: str | None = None):
    return {
        "_index": "logs-windows",
        "_id": native_id or f"w-{record_id}",
        "_source": {
            "@timestamp": "2026-01-02T00:05:00Z",
            "agent": {"type": "winlogbeat"},
            "event": {"dataset": "windows.sysmon_operational"},
            "winlog": {
                "channel": SYSMON_CHANNEL,
                "provider_name": SYSMON,
                "event_id": event_id,
                "computer_name": "WS01.example.test",
                "record_id": record_id,
                "event_data": {"ProcessGuid": "{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}"},
            },
        },
    }


class WindowsProcessRule(Playbook):
    id = "test.windows.process"
    title = "test"
    families = ("process_exec",)
    os_families = ("windows",)
    windows_event_classes = ((SYSMON_CHANNEL, SYSMON, 1),)


class UndeclaredWindowsProcessRule(Playbook):
    id = "test.windows.process.undeclared"
    title = "test"
    families = ("process_exec",)
    os_families = ("windows",)


class ExhaustedWindowsProcessRule(WindowsProcessRule):
    id = "test.windows.process.exhausted"

    def consume(self, events):
        if events:
            self.evaluated += 1
        raise StateExhausted("test stage failure")


def _contract():
    return contract_from_types(
        "target-name-is-irrelevant",
        {
            "@timestamp": "date",
            "event.dataset": "keyword",
            "winlog.channel": "keyword",
            "winlog.provider_name": "keyword",
            "winlog.event_id": "long",
            "winlog.computer_name": "keyword",
            "winlog.record_id": "long",
            "winlog.event_data": "flattened",
        },
        role="host",
        hosts=("ws01.example.test",),
    )


def _site(tmp_path, *, event_ids: str = "[1]"):
    path = tmp_path / "site" / "collection.yaml"
    path.parent.mkdir(parents=True)
    path.write_text(
        "schema: romulus-site-collection@1\n"
        "collection:\n"
        "  - hosts: [ws*.example.test]\n"
        "    sysmon:\n"
        "      installed: true\n"
        f"      event_ids: {event_ids}\n",
        encoding="utf-8",
    )
    return load_site_facts(tmp_path)


def test_record_id_gap_scan_is_streaming_duplicate_safe_and_names_each_gap():
    continuity = RecordIdContinuity()

    first = continuity.observe("target", [_hit(10), _hit(10, native_id="duplicate"), _hit(13)])
    second = continuity.observe("target", [_hit(12), _hit("bad")])

    assert first == [
        f"shipper gaps: 2 records missing on {SYSMON_CHANNEL} for ws01.example.test"
    ]
    assert any("out of order" in reason for reason in second)
    assert any("non-numeric" in reason for reason in second)
    assert continuity.state_count == 1


def test_record_id_continuity_spills_5000_host_channels_without_a_count_cap():
    continuity = RecordIdContinuity()
    records = []
    for host_number in range(5_000):
        for record_id in (10, 11):
            hit = _hit(record_id, native_id=f"{host_number}-{record_id}")
            hit["_source"]["winlog"]["computer_name"] = f"ws{host_number:04d}.example.test"
            records.append(hit)

    reasons = continuity.observe("target", records)

    assert reasons == []
    assert continuity.state_count == 5_000


def test_record_id_continuity_has_its_own_floor_and_reports_refused_groups(tmp_path):
    budget = StateBudget(tmp_path, disk_total=64 * 1024, reserve=0)
    budget.plan(1)
    account = budget.account("windows_continuity")
    continuity = RecordIdContinuity(tmp_path, budget=budget, account=account)
    budget.force_full("Windows continuity floor spent (test)", lambda candidate: candidate is account)

    reasons = continuity.observe("target", [_hit(10)])

    assert continuity.state_count == 0
    assert any("continuity state refused" in reason and "floor spent" in reason for reason in reasons)
    continuity.close()


def test_record_id_continuity_summarizes_many_single_sample_groups(tmp_path):
    continuity = RecordIdContinuity(tmp_path)
    records = []
    for host_number in range(5_000):
        hit = _hit(10, native_id=f"single-{host_number}")
        hit["_source"]["winlog"]["computer_name"] = f"ws{host_number:04d}.example.test"
        records.append(hit)

    reasons = continuity.observe("target", records)

    assert len(reasons) == 1
    assert "5,000 host/channel groups" in reasons[0]
    assert sum(f"ws{number:04d}.example.test" in reasons[0] for number in range(5_000)) == 10
    continuity.close()


def test_record_time_continuity_spills_under_stage_and_names_the_largest_gap(tmp_path):
    stage = EventStage(tmp_path)
    continuity = RecordIdContinuity(stage.directory)
    records = []
    for record_id, offset in ((10, 5), (11, 10), (12, 350), (13, 355)):
        hit = _hit(record_id)
        hit["_source"]["@timestamp"] = (START + timedelta(minutes=offset)).isoformat()
        records.append(hit)

    reasons = continuity.observe("target", records, liveness_tolerance=timedelta(minutes=15))

    assert continuity.path.parent == stage.directory
    assert continuity.state_count == 1
    assert reasons == [
        ("no records from ws01.example.test/Microsoft-Windows-Sysmon/Operational "
         "between 2026-01-02T00:10:00+00:00 and 2026-01-02T05:50:00+00:00")
    ]
    continuity.close()
    stage.close()


def test_standalone_continuity_closes_its_private_database_on_collection():
    continuity = RecordIdContinuity()
    path = continuity.path

    del continuity
    gc.collect()

    assert not path.exists()


def test_windows_coverage_gate_requires_inventory_continuity_and_matching_attestation(tmp_path):
    contract = _contract()
    rule = WindowsProcessRule()
    window = Window(start=START, end=START + timedelta(hours=1))
    sweep = Sweep(None, None, "h1", window, {contract.target: contract}, site_facts=_site(tmp_path))
    event_class = lookup_event_class(SYSMON_CHANNEL, SYSMON, 1)
    assert event_class is not None
    sweep._windows_inventory[contract.target] = {event_class.token}
    sweep._windows_inventory_reasons[contract.target] = []

    assert sweep._windows_rule_reasons(contract.target, contract, rule, [_hit(10), _hit(11)], []) == []
    assert sweep._windows_rule_reasons(
        contract.target,
        contract,
        rule,
        [_hit(10)],
        ["shipper gaps: 1 records missing on channel"],
    ) == ["shipper gaps: 1 records missing on channel"]

    sweep._windows_inventory[contract.target] = set()
    missing = sweep._windows_rule_reasons(contract.target, contract, rule, [_hit(10)], [])
    assert any("absent from source inventory" in reason for reason in missing)

    unattested = Sweep(None, None, "h1", window, {contract.target: contract})
    unattested._windows_inventory[contract.target] = {event_class.token}
    unattested._windows_inventory_reasons[contract.target] = []
    missing = unattested._windows_rule_reasons(contract.target, contract, rule, [_hit(10)], [])
    assert missing == ["collection not attested: Sysmon event id 1 on ws01.example.test"]

    truncated = contract.model_copy(update={"host_inventory_complete": False})
    missing = sweep._windows_rule_reasons(
        truncated.target, truncated, rule, [_hit(10), _hit(11)], [],
    )
    assert "collection not attested: source host inventory truncated" in missing


def test_windows_partition_requires_channel_liveness_at_both_edges(tmp_path):
    contract = _contract()
    rule = WindowsProcessRule()
    window = Window(start=START, end=START + timedelta(hours=6))
    sweep = Sweep(None, None, "h1", window, {contract.target: contract}, site_facts=_site(tmp_path))
    event_class = lookup_event_class(SYSMON_CHANNEL, SYSMON, 1)
    assert event_class is not None
    sweep._windows_inventory[contract.target] = {event_class.token}
    sweep._windows_inventory_reasons[contract.target] = []
    early = _hit(10)
    early["_source"]["@timestamp"] = (START + timedelta(minutes=5)).isoformat()
    late = _hit(11)
    late["_source"]["@timestamp"] = (START + timedelta(hours=5, minutes=55)).isoformat()

    reasons = sweep._windows_rule_reasons(contract.target, contract, rule, [early], [], window)
    head_reasons = sweep._windows_rule_reasons(contract.target, contract, rule, [late], [], window)
    live_reasons = sweep._windows_rule_reasons(contract.target, contract, rule, [early, late], [], window)

    assert reasons == [
        ("no records from ws01.example.test/Microsoft-Windows-Sysmon/Operational "
         "after 2026-01-02T00:05:00+00:00")
    ]
    assert head_reasons == [
        ("no records from ws01.example.test/Microsoft-Windows-Sysmon/Operational "
         "before 2026-01-02T05:55:00+00:00")
    ]
    assert live_reasons == []


def test_mid_partition_collection_outage_cannot_be_a_complete_negative(tmp_path, monkeypatch):
    from romulus.hunt import sweep as sweep_module
    from tests.test_sweep import _repo

    records = []
    for record_id, offset in ((10, 5), (11, 10), (12, 350), (13, 355)):
        hit = _hit(record_id)
        hit["_source"]["@timestamp"] = (START + timedelta(minutes=offset)).isoformat()
        records.append(hit)

    monkeypatch.setattr(sweep_module, "execute", lambda _client, intent, _contract: SearchOutcome(
        target=intent.target,
        fingerprint="mid-outage",
        started_at=START,
        ended_at=START,
        completeness=Completeness.complete,
        total=len(records),
        total_relation="eq",
        returned=len(records),
        records=records,
    ))
    contract = _contract()
    event_class = lookup_event_class(SYSMON_CHANNEL, SYSMON, 1)
    assert event_class is not None
    window = Window(start=START, end=START + timedelta(hours=6))
    repo = _repo()
    sweep = Sweep(
        repo, None, "h1", window, {contract.target: contract},
        site_facts=_site(tmp_path), stage_dir=tmp_path,
    )
    sweep.pack = [WindowsProcessRule()]
    sweep._windows_inventory[contract.target] = {event_class.token}
    sweep._windows_inventory_reasons[contract.target] = []

    sweep.run_partition(contract.target, contract, [], window, est=len(records))

    cell = repo.rule_cells("h1")[0]
    assert cell["state"] == "evaluated_partial"
    assert cell["detail"]["reasons"] == [
        ("no records from ws01.example.test/Microsoft-Windows-Sysmon/Operational "
         "between 2026-01-02T00:10:00+00:00 and 2026-01-02T05:50:00+00:00")
    ]
    assert sweep._windows_record_ids.path.parent == sweep._event_stage().directory
    sweep.close_stage()


def test_in_window_audit_policy_changes_make_windows_cells_partial(tmp_path):
    contract = _contract()
    rule = WindowsProcessRule()
    window = Window(start=START, end=START + timedelta(minutes=30))
    sweep = Sweep(None, None, "h1", window, {contract.target: contract}, site_facts=_site(tmp_path))
    event_class = lookup_event_class(SYSMON_CHANNEL, SYSMON, 1)
    assert event_class is not None
    sweep._windows_inventory[contract.target] = {event_class.token}
    sweep._windows_inventory_reasons[contract.target] = []
    records = [_hit(10), _hit(11)]
    records[1]["_source"]["@timestamp"] = (START + timedelta(minutes=25)).isoformat()
    for record_id, offset in ((20, 10), (21, 20)):
        change = _hit(record_id, event_id=4719)
        change["_source"]["@timestamp"] = (START + timedelta(minutes=offset)).isoformat()
        change["_source"]["winlog"].update({
            "channel": "Security",
            "provider_name": SECURITY,
        })
        records.append(change)

    reasons = sweep._windows_rule_reasons(contract.target, contract, rule, records, [], window)

    assert reasons == [
        ("collection changed on ws01.example.test: Security|Microsoft-Windows-Security-Auditing|4719 "
         "(audit policy changed)")
    ]


def test_collection_change_events_are_centralized_for_future_catalog_growth():
    assert COLLECTION_CHANGE_EVENTS == {
        ("security", "microsoft-windows-security-auditing", 4719): "audit policy changed",
        ("security", "microsoft-windows-eventlog", 1102): "security log cleared",
        ("system", "microsoft-windows-eventlog", 104): "event log cleared",
        ("system", "eventlog", 6006): "event log service stopped",
    }


def test_rule_without_declared_classes_requires_every_catalog_class_for_its_family(tmp_path):
    contract = _contract()
    rule = UndeclaredWindowsProcessRule()
    window = Window(start=START, end=START + timedelta(minutes=5))
    sweep = Sweep(None, None, "h1", window, {contract.target: contract}, site_facts=_site(tmp_path))
    sysmon = lookup_event_class(SYSMON_CHANNEL, SYSMON, 1)
    security = lookup_event_class("Security", SECURITY, 4688)
    assert sysmon is not None and security is not None
    sweep._windows_inventory[contract.target] = {sysmon.token}
    sweep._windows_inventory_reasons[contract.target] = []

    reasons = sweep._windows_rule_reasons(contract.target, contract, rule, [_hit(10), _hit(11)], [])

    assert any("Security|Microsoft-Windows-Security-Auditing|4688" in reason for reason in reasons)


def test_windows_reasons_summarize_5000_hosts_per_class_with_ten_host_sample():
    hosts = tuple(f"ws{number:04d}.example.test" for number in range(5_000))
    contract = _contract().model_copy(update={"hosts": hosts})
    rule = WindowsProcessRule()
    sweep = Sweep(None, None, "h1", Window(start=START, end=START + timedelta(hours=1)), {
        contract.target: contract,
    })
    event_class = lookup_event_class(SYSMON_CHANNEL, SYSMON, 1)
    assert event_class is not None
    sweep._windows_inventory[contract.target] = {event_class.token}
    sweep._windows_inventory_reasons[contract.target] = []

    reasons = sweep._windows_rule_reasons(contract.target, contract, rule, [], [])

    assert len(reasons) == 2
    assert all("5,000 hosts" in reason for reason in reasons)
    assert all(sum(host in reason for host in hosts) == 10 for reason in reasons)


def test_skip_reason_state_is_bounded_without_losing_the_total_count():
    sweep = object.__new__(Sweep)
    sweep.stats = {"skips": {}}
    additions = {f"Windows event class unknown-{number}": number + 1 for number in range(400)}

    sweep._record_skips("windows-target", additions)

    assert len(sweep.stats["skips"]) == 257
    assert len(sweep.stats["skips_by_target"]["windows-target"]) == 257
    assert sum(sweep.stats["skips"].values()) == sum(additions.values())


def test_system_channel_collection_requires_an_explicit_event_log_attestation():
    event_class = lookup_event_class("System", "Service Control Manager", 7045)

    assert event_class is not None
    assert collection_requirements(event_class) == (
        ("system_event_log", {}, "Windows System event log"),
    )


def test_security_1102_uses_eventlog_provider_and_security_channel_attestation():
    event_class = lookup_event_class("Security", "Microsoft-Windows-Eventlog", 1102)

    assert event_class is not None
    assert lookup_event_class("Security", SECURITY, 1102) is None
    assert collection_requirements(event_class) == (
        ("security_event_log", {}, "Windows Security event log"),
    )


def test_event_class_inventory_is_a_bounded_aggregate_over_the_full_hunt_window(monkeypatch):
    from romulus.hunt import sweep as sweep_module

    seen = []

    def execute(_client, intent, _contract):
        seen.append(intent)
        return SearchOutcome(
            target=intent.target,
            fingerprint="inventory",
            started_at=START,
            ended_at=START,
            completeness=Completeness.complete,
            total=10_000,
            total_relation="eq",
            returned=1,
            buckets=[{
                "key": {
                    "event.channel": SYSMON_CHANNEL,
                    "event.provider": SYSMON,
                    "event.code": 1,
                },
                "count": 10_000,
            }],
        )

    monkeypatch.setattr(sweep_module, "execute", execute)
    contract = _contract()
    sweep = Sweep(None, object(), "h1", Window(start=START, end=START + timedelta(hours=1)), {
        contract.target: contract,
    })

    sweep._prepare_windows_inventory(contract.target, contract)

    [intent] = seen
    assert intent.kind == "aggregate" and intent.window == sweep.window
    assert intent.group_by == ["event.channel", "event.provider", "event.code"]
    event_class = lookup_event_class(SYSMON_CHANNEL, SYSMON, 1)
    assert event_class is not None
    assert sweep._windows_inventory[contract.target] == {event_class.token}


def test_catalogued_windows_class_with_no_reader_is_counted_as_not_assessed(monkeypatch):
    from romulus.hunt import sweep as sweep_module

    def execute(_client, intent, _contract):
        return SearchOutcome(
            target=intent.target, fingerprint="inventory", started_at=START, ended_at=START,
            completeness=Completeness.complete, total=9, total_relation="eq", returned=1,
            buckets=[{
                "key": {
                    "event.channel": "System",
                    "event.provider": "Service Control Manager",
                    "event.code": 7045,
                },
                "count": 9,
            }],
        )

    monkeypatch.setattr(sweep_module, "execute", execute)
    contract = _contract()
    sweep = Sweep(None, object(), "h1", Window(start=START, end=START + timedelta(hours=1)), {
        contract.target: contract,
    })
    sweep.pack = [WindowsProcessRule()]

    sweep._prepare_windows_inventory(contract.target, contract)

    assert sweep.stats["windows_unassessed"][contract.target] == [{
        "channel": "System", "provider": "Service Control Manager", "event_id": 7045,
        "family": "service_change", "records": 9,
    }]


def test_uncatalogued_winlogbeat_inventory_is_bounded_and_never_added_to_retrieval(monkeypatch):
    from romulus.hunt import sweep as sweep_module

    named = [
        ("Microsoft-Windows-PowerShell/Operational", "Microsoft-Windows-PowerShell", 4104),
        ("Microsoft-Windows-Windows Defender/Operational", "Microsoft-Windows-Windows Defender", 1116),
        ("Microsoft-Windows-TaskScheduler/Operational", "Microsoft-Windows-TaskScheduler", 106),
        ("Microsoft-Windows-WMI-Activity/Operational", "Microsoft-Windows-WMI-Activity", 5857),
    ]
    buckets = [{
        "key": {"event.channel": channel, "event.provider": provider, "event.code": event_id},
        "count": offset + 1,
    } for offset, (channel, provider, event_id) in enumerate(named)]
    buckets.extend({
        "key": {
            "event.channel": f"Uncatalogued-{number}",
            "event.provider": "Test-Provider",
            "event.code": 20_000 + number,
        },
        "count": 1,
    } for number in range(MAX_WINDOWS_UNCATALOGUED))

    monkeypatch.setattr(sweep_module, "execute", lambda _client, intent, _contract: SearchOutcome(
        target=intent.target, fingerprint="inventory", started_at=START, ended_at=START,
        completeness=Completeness.complete, total=sum(bucket["count"] for bucket in buckets),
        total_relation="eq", returned=len(buckets), buckets=buckets,
    ))
    contract = _contract()
    sweep = Sweep(None, object(), "h1", Window(start=START, end=START + timedelta(hours=1)), {
        contract.target: contract,
    })
    sweep.pack = [WindowsProcessRule()]

    sweep._prepare_windows_inventory(contract.target, contract)

    rows = sweep.stats["windows_unassessed"][contract.target]
    listed = {(row.get("channel"), row.get("provider"), row.get("event_id")) for row in rows}
    assert set(named).issubset(listed)
    assert sum(
        row.get("uncatalogued", False) and not row.get("overflow", False) for row in rows
    ) == MAX_WINDOWS_UNCATALOGUED
    assert rows[-1] == {
        "overflow": True,
        "uncatalogued": True,
        "classes": 4,
        "records": 4,
    }
    retrieval_values = {
        value
        for group in sweep._any_of_for(contract.target, contract)
        for predicate in group
        for value in predicate.value
    }
    assert all(channel not in retrieval_values for channel, _provider, _event_id in named)


def test_unknown_windows_classes_are_not_assessed_without_poisoning_every_rule():
    events, skips, errors = normalize_hits([_hit(10, event_id=9999)])

    assert events == [] and errors == [] and sum(skips.values()) == 1
    assert Sweep._unsupported_skips(skips) == {}
    assert any("Windows event class" in reason and "not normalized" in reason for reason in skips)


def test_playbook_os_families_filter_before_required_field_evaluation():
    [windows], _skips, _errors = normalize_hits([_hit(10)])
    linux = TypedEvent(
        id="linux",
        family="process_exec",
        ts=START,
        host="host1",
        fields={},
        raw=[RawRef(target="linux", native_id="1")],
        normalizer="lab-ecs@9",
    )
    rule = WindowsProcessRule()

    assert rule.applicable([linux, windows]) == [windows]
    assert rule.evaluated == 1 and rule.missing_required == 0


def test_existing_linux_rules_do_not_silently_widen_to_windows_events():
    windows_families = {event.family for event in EVENT_CLASSES}
    windows_enabled = {
        playbook.id
        for playbook in ALL_PLAYBOOKS
        if windows_families.intersection(playbook.families) and "windows" in playbook.os_families
    }

    assert windows_enabled == {"ioc.indicator_match"}


def test_wrong_os_same_family_is_not_a_complete_negative(monkeypatch):
    from romulus.hunt import sweep as sweep_module
    from tests.test_sweep import _repo

    linux = TypedEvent(
        id="linux",
        family="process_exec",
        ts=START,
        host="host1",
        fields={},
        raw=[RawRef(target="linux", native_id="1")],
        normalizer="lab-ecs@9",
    )
    monkeypatch.setattr(sweep_module, "normalize_hits", lambda *_args, **_kwargs: ([linux], {}, []))
    monkeypatch.setattr(sweep_module, "execute", lambda _client, intent, _contract: SearchOutcome(
        target=intent.target,
        fingerprint="linux",
        started_at=START,
        ended_at=START,
        completeness=Completeness.complete,
        total=1,
        total_relation="eq",
        returned=1,
        records=[{"_index": "linux", "_id": "1", "_source": {}}],
    ))
    contract = contract_from_types("linux", {"@timestamp": "date"}, role="host", os_family="linux")
    window = Window(start=START, end=START + timedelta(minutes=5))
    repo = _repo()
    sweep = Sweep(repo, None, "h1", window, {contract.target: contract})
    sweep.pack = [WindowsProcessRule()]

    sweep.run_partition(contract.target, contract, [], window, est=1)

    assert repo.rule_cells("h1")[0]["state"] == "not_applicable_no_events"


def test_mid_batch_refusal_counts_only_os_scoped_records(tmp_path, monkeypatch):
    from romulus.hunt import sweep as sweep_module
    from tests.test_sweep import _repo

    [windows_one], _skips, _errors = normalize_hits([_hit(10, native_id="windows-one")])
    [windows_two], _skips, _errors = normalize_hits([_hit(11, native_id="windows-two")])
    linux = TypedEvent(
        id="linux", family="process_exec", ts=START, host="host1", fields={},
        raw=[RawRef(target="linux", native_id="1")], normalizer="lab-ecs@9",
    )
    batch = [windows_one, linux, windows_two]
    records = [_hit(10, native_id="windows-one"), _hit(11, native_id="windows-two")]
    monkeypatch.setattr(sweep_module, "normalize_hits", lambda *_args, **_kwargs: (batch, {}, []))
    monkeypatch.setattr(sweep_module, "execute", lambda _client, intent, _contract: SearchOutcome(
        target=intent.target, fingerprint="mixed", started_at=START, ended_at=START,
        completeness=Completeness.complete, total=3, total_relation="eq", returned=3, records=records,
    ))
    contract = _contract()
    repo = _repo()
    sweep = Sweep(repo, None, "h1", Window(start=START, end=START + timedelta(minutes=5)),
                  {contract.target: contract}, stage_dir=tmp_path)
    sweep.pack = [ExhaustedWindowsProcessRule()]

    sweep.run_partition(contract.target, contract, [], sweep.window, est=3)

    cell = repo.rule_cells("h1")[0]
    assert cell["state"] == "evaluated_partial"
    assert cell["detail"]["state_capped"] == 1
    sweep.close_stage()


def test_sweep_cell_can_be_complete_only_after_all_windows_gates_pass(tmp_path, monkeypatch):
    from romulus.hunt import sweep as sweep_module
    from tests.test_sweep import _repo

    records = [_hit(10), _hit(11)]

    def execute(_client, intent, _contract):
        return SearchOutcome(
            target=intent.target,
            fingerprint="windows",
            started_at=START,
            ended_at=START,
            completeness=Completeness.complete,
            total=2,
            total_relation="eq",
            returned=2,
            records=records,
        )

    monkeypatch.setattr(sweep_module, "execute", execute)
    contract = _contract()
    event_class = lookup_event_class(SYSMON_CHANNEL, SYSMON, 1)
    assert event_class is not None
    window = Window(start=START, end=START + timedelta(minutes=5))

    def run(site_facts):
        repo = _repo()
        sweep = Sweep(repo, None, "h1", window, {contract.target: contract}, site_facts=site_facts)
        sweep.pack = [WindowsProcessRule()]
        sweep._windows_inventory[contract.target] = {event_class.token}
        sweep._windows_inventory_reasons[contract.target] = []
        sweep.run_partition(contract.target, contract, [], window, est=2)
        return repo.rule_cells("h1")[0]

    complete = run(_site(tmp_path))
    unresolved = run(None)

    assert complete["state"] == "no_match_complete"
    assert unresolved["state"] == "evaluated_partial"
    assert unresolved["detail"]["reasons"] == [
        "collection not attested: Sysmon event id 1 on ws01.example.test"
    ]


def test_5000_host_windows_sweep_refuses_bounded_state_without_crashing(tmp_path, monkeypatch):
    from romulus.hunt import sweep as sweep_module
    from tests.test_sweep import _repo

    hosts = tuple(f"ws{number:04d}.example.test" for number in range(5_000))
    records = []
    for host_number, host_name in enumerate(hosts):
        hit = _hit(10, native_id=f"host-{host_number}")
        hit["_source"]["winlog"]["computer_name"] = host_name
        records.append(hit)
    monkeypatch.setattr(sweep_module, "execute", lambda _client, intent, _contract: SearchOutcome(
        target=intent.target, fingerprint="5000-hosts", started_at=START, ended_at=START,
        completeness=Completeness.complete, total=len(records), total_relation="eq",
        returned=len(records), records=records,
    ))
    budget = StateBudget(tmp_path, disk_total=128 * 1024, reserve=0)
    monkeypatch.setattr(sweep_module, "state_budget", lambda _settings, _stage_dir: budget)
    contract = _contract().model_copy(update={"hosts": hosts})
    repo = _repo()
    sweep = Sweep(
        repo, None, "h1", Window(start=START, end=START + timedelta(minutes=10)),
        {contract.target: contract}, site_facts=_site(tmp_path), stage_dir=tmp_path,
    )
    sweep.pack = [WindowsProcessRule()]
    for rule in sweep.pack:
        rule.spill_dir, rule.budget = tmp_path, budget
    budget.plan(live_stores(sweep.pack) + 3)
    event_class = lookup_event_class(SYSMON_CHANNEL, SYSMON, 1)
    assert event_class is not None
    sweep._windows_inventory[contract.target] = {event_class.token}
    sweep._windows_inventory_reasons[contract.target] = []

    sweep.run_partition(contract.target, contract, [], sweep.window, est=len(records))

    [cell] = repo.rule_cells("h1")
    assert cell["state"] == "evaluated_partial"
    assert cell["evaluated"] == 5_000
    assert "state_capped" not in cell["detail"]
    assert any("host/channel groups" in reason for reason in cell["detail"]["reasons"])
    assert "windows_seen" in budget.full
    assert sweep._event_stage().windows_refused > 0
    assert len(cell["detail"]["reasons"]) < 10
    sweep.close_stage()
