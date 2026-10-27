"""Windows coverage requires inventory, streaming continuity, and site collection attestations."""

from __future__ import annotations

import gc
from datetime import UTC, datetime, timedelta

import pytest

from romulus.detect.base import Match, Playbook
from romulus.detect.bounded import StateBudget, StateExhausted, live_stores
from romulus.detect.registry import ALL_PLAYBOOKS
from romulus.evidence.normalize import normalize_hits
from romulus.evidence.typed import Outcome, RawRef, TypedEvent, fv
from romulus.evidence.windows import SCRIPT_BLOCK_MAX_PARTS, RecordIdContinuity
from romulus.evidence.windows_catalog import (
    COLLECTION_CHANGE_EVENTS,
    EVENT_CLASSES,
    SECURITY,
    SYSMON,
    SYSMON_CHANNEL,
    WINDOWS_HOST_DATASETS,
    collection_requirements,
    lookup_event_class,
)
from romulus.evidence.windows_reassembly import SCRIPT_FINALIZE_BATCH_SIZE
from romulus.hunt.stage import EventStage
from romulus.hunt.sweep import MAX_WINDOWS_UNCATALOGUED, PARTITION_MAX_DOCS, Sweep
from romulus.site import load_site_facts
from romulus.sources.models import Completeness, Predicate, SearchOutcome, Window
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


def _script_hit(
    record_id: int,
    minute: int,
    *,
    block: str,
    number: int,
    total: int,
    text: str,
):
    channel = "Microsoft-Windows-PowerShell/Operational"
    return {
        "_index": "logs-windows",
        "_id": f"script-{record_id}",
        "_source": {
            "@timestamp": (START + timedelta(minutes=minute)).isoformat(),
            "agent": {"type": "winlogbeat"},
            "event": {"dataset": "windows.powershell_operational"},
            "winlog": {
                "channel": channel,
                "provider_name": "Microsoft-Windows-PowerShell",
                "event_id": 4104,
                "computer_name": "WS01.example.test",
                "record_id": record_id,
                "time_created": (START + timedelta(minutes=minute)).isoformat(),
                "event_data": {
                    "ScriptBlockId": block,
                    "MessageNumber": str(number),
                    "MessageTotal": str(total),
                    "ScriptBlockText": text,
                },
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


class WindowsScriptRule(Playbook):
    id = "test.windows.script"
    title = "test"
    families = ("script_block",)
    os_families = ("windows",)
    windows_event_classes = ((
        "Microsoft-Windows-PowerShell/Operational",
        "Microsoft-Windows-PowerShell",
        4104,
    ),)


class RecordingWindowsScriptRule(WindowsScriptRule):
    id = "test.windows.script.recording"

    def __init__(self):
        super().__init__()
        self.seen_times = []

    def consume(self, events):
        applicable = self.applicable(events)
        self.seen_times.extend(event.ts for event in applicable)
        return []


class IncompleteCitationWindowsScriptRule(WindowsScriptRule):
    id = "test.windows.script.incomplete_citation"

    def match(self, event):
        return [Match(
            playbook_id=self.id,
            claim="Windows recorded a script block with invalid part metadata.",
            claim_type="script_content",
            events=[event],
            predicate=[],
            ts=event.ts,
            severity="low",
            proposed_lane="lead",
            confidence="high",
            group_key=event.id,
        )]


def _aggregate_script_match(playbook_id: str, events: list[TypedEvent]) -> Match:
    return Match(
        playbook_id=playbook_id,
        claim="Incomplete script blocks were retained for aggregate evaluation.",
        claim_type="aggregate_observation",
        events=events,
        predicate=[],
        ts=max(event.ts for event in events),
        severity="medium",
        proposed_lane="lead",
        confidence="high",
        group_key="incomplete-script-blocks",
    )


class FinalizedStagedWindowsScriptRule(WindowsScriptRule):
    id = "test.windows.script.finalized_staged"
    kind = "aggregate"
    staged = True

    def __init__(self):
        super().__init__()
        self.ids: list[str] = []
        self._pending: list[TypedEvent] = []
        self.bounds_drained = 0
        self.loaded_ids: list[str] = []

    def consume(self, events):
        applicable = self.applicable(events)
        self.ids.extend(event.id for event in applicable)
        self._pending.extend(applicable)
        return []

    def drain_staged(self):
        pending, self._pending = self._pending, []
        return pending

    def drain_bounds(self):
        self.bounds_drained += 1
        return self.ids[:1], []

    def finalize(self):
        events = self.load(self.ids)
        if len(events) != len(self.ids):
            raise LookupError("finalized incomplete script citations absent from the stage")
        self.loaded_ids = [event.id for event in events]
        return [_aggregate_script_match(self.id, events)]


class FinalizedRetainedWindowsScriptRule(WindowsScriptRule):
    id = "test.windows.script.finalized_retained"
    kind = "aggregate"

    def __init__(self):
        super().__init__()
        self.events: list[TypedEvent] = []

    def consume(self, events):
        self.events.extend(self.applicable(events))
        return []

    def retained_events(self):
        return list(self.events)

    def finalize(self):
        return [_aggregate_script_match(self.id, self.events)] if self.events else []


class FinalizedBatchRecordingWindowsScriptRule(WindowsScriptRule):
    id = "test.windows.script.finalized_batches"

    def __init__(self):
        super().__init__()
        self.batch_sizes: list[int] = []

    def consume(self, events):
        applicable = self.applicable(events)
        self.batch_sizes.append(len(applicable))
        return []


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


def _continuity_bucket(
    record_id: int,
    minute: int,
    *,
    host: str = "ws01.example.test",
    channel: str = SYSMON_CHANNEL,
) -> dict:
    when = (START + timedelta(minutes=minute)).isoformat()
    return {
        "key": {
            "@timestamp": when,
            "host.name": host,
            "event.channel": channel,
            "winlog.record_id": record_id,
        },
        "count": 1,
        "first": when,
        "last": when,
    }


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


def test_record_id_continuity_bounds_5000_host_gap_reasons_with_exact_channel_counts():
    continuity = RecordIdContinuity()
    records = []
    for host_number in range(5_000):
        host = f"ws{host_number:04d}.example.test"
        first = _hit(10, native_id=f"first-{host_number}")
        first["_source"]["winlog"]["computer_name"] = host
        second = _hit(12, native_id=f"second-{host_number}")
        second["_source"]["@timestamp"] = "2026-01-02T01:05:00Z"
        second["_source"]["winlog"]["computer_name"] = host
        records.extend((first, second))

    reasons = continuity.observe("target", records, liveness_tolerance=timedelta(minutes=15))

    assert len(reasons) == 2
    gap = next(reason for reason in reasons if reason.startswith("shipper gaps:"))
    liveness = next(reason for reason in reasons if reason.startswith("no-record time gaps"))
    assert f"5,000 records missing across 5,000 hosts on {SYSMON_CHANNEL}" in gap
    assert f"5,000 hosts on {SYSMON_CHANNEL}" in liveness
    assert sum(f"ws{number:04d}.example.test" in gap for number in range(5_000)) == 10
    assert sum(f"ws{number:04d}.example.test" in liveness for number in range(5_000)) == 10
    continuity.close()


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


def test_repeated_refused_records_count_one_host_channel_group(tmp_path):
    budget = StateBudget(tmp_path, disk_total=64 * 1024, reserve=0)
    budget.plan(1)
    account = budget.account("windows_continuity")
    continuity = RecordIdContinuity(tmp_path, budget=budget, account=account)
    budget.force_full("Windows continuity floor spent (test)", lambda candidate: candidate is account)

    reasons = continuity.observe("target", [
        _hit(record_id, native_id=f"refused-{record_id}") for record_id in range(20)
    ])

    assert len(reasons) == 1
    assert "for ws01.example.test" in reasons[0]
    assert "20 host/channel groups" not in reasons[0]
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


def test_selective_partition_uses_one_bounded_full_channel_aggregate_without_false_omitted_class_gap(
    tmp_path, monkeypatch,
):
    from romulus.hunt import sweep as sweep_module
    from tests.test_sweep import _repo

    raw_records = [_hit(10), _hit(12)]
    buckets = [
        _continuity_bucket(10, 5),
        _continuity_bucket(11, 10),       # an unrequested event class occupied this native id
        _continuity_bucket(12, 25),
    ]
    intents = []

    def execute(_client, intent, _contract):
        intents.append(intent)
        if intent.kind == "aggregate":
            return SearchOutcome(
                target=intent.target, fingerprint="continuity", started_at=START, ended_at=START,
                completeness=Completeness.complete, total=3, total_relation="eq",
                returned=len(buckets), buckets=buckets,
            )
        return SearchOutcome(
            target=intent.target, fingerprint="raw", started_at=START, ended_at=START,
            completeness=Completeness.complete, total=len(raw_records), total_relation="eq",
            returned=len(raw_records), records=raw_records,
        )

    monkeypatch.setattr(sweep_module, "execute", execute)
    contract = _contract()
    event_class = lookup_event_class(SYSMON_CHANNEL, SYSMON, 1)
    window = Window(start=START, end=START + timedelta(minutes=30))
    repo = _repo()
    sweep = Sweep(
        repo, None, "h1", window, {contract.target: contract},
        site_facts=_site(tmp_path), stage_dir=tmp_path,
    )
    sweep.pack = [WindowsProcessRule()]
    sweep._windows_inventory[contract.target] = {event_class.token}
    sweep._windows_inventory_reasons[contract.target] = []
    sweep._windows_selective.add(contract.target)

    sweep.run_partition(contract.target, contract, [], window, est=len(raw_records))

    metadata_intents = [intent for intent in intents if intent.kind == "aggregate"]
    assert len(metadata_intents) == 1
    [metadata] = metadata_intents
    assert metadata.window == window
    assert metadata.group_by == ["@timestamp", "host.name", "event.channel", "winlog.record_id"]
    assert metadata.max_records == PARTITION_MAX_DOCS
    assert metadata.any_of == []
    cell = repo.rule_cells("h1")[0]
    assert cell["state"] == "no_match_complete"
    assert not any("shipper gaps" in reason for reason in cell["detail"].get("reasons", []))
    sweep.close_stage()


def test_incomplete_selective_metadata_does_not_poison_later_continuity_state(tmp_path, monkeypatch):
    from romulus.hunt import sweep as sweep_module
    from tests.test_sweep import _repo

    outcomes = iter((
        SearchOutcome(
            target=_contract().target, fingerprint="capped", started_at=START, ended_at=START,
            completeness=Completeness.partial, reasons=["aggregate_bucket_cap:1"],
            total=3, total_relation="eq", returned=1,
            buckets=[_continuity_bucket(50, 5)],
        ),
        SearchOutcome(
            target=_contract().target, fingerprint="complete", started_at=START, ended_at=START,
            completeness=Completeness.complete, total=2, total_relation="eq", returned=2,
            buckets=[_continuity_bucket(10, 35), _continuity_bucket(11, 55)],
        ),
    ))
    monkeypatch.setattr(sweep_module, "execute", lambda *_args, **_kwargs: next(outcomes))
    contract = _contract()
    repo = _repo()
    sweep = Sweep(
        repo, None, "h1", Window(start=START, end=START + timedelta(hours=1)),
        {contract.target: contract}, stage_dir=tmp_path,
    )

    first_times, first_reasons = sweep._selective_windows_continuity(
        contract.target, contract, Window(start=START, end=START + timedelta(minutes=30)),
    )
    second_times, second_reasons = sweep._selective_windows_continuity(
        contract.target, contract,
        Window(start=START + timedelta(minutes=30), end=START + timedelta(hours=1)),
    )

    assert first_times == {}
    assert first_reasons == [
        "shipper gaps unresolved: continuity metadata incomplete: aggregate_bucket_cap:1"
    ]
    assert len(second_times) == 1
    assert not any("out of order" in reason for reason in second_reasons)
    sweep.close_stage()


def test_malformed_selective_metadata_does_not_poison_later_continuity_state(tmp_path, monkeypatch):
    from romulus.hunt import sweep as sweep_module
    from tests.test_sweep import _repo

    malformed = _continuity_bucket(51, 10)
    malformed["key"]["winlog.record_id"] = "not-numeric"
    outcomes = iter((
        SearchOutcome(
            target=_contract().target, fingerprint="malformed", started_at=START, ended_at=START,
            completeness=Completeness.complete, total=2, total_relation="eq", returned=2,
            buckets=[_continuity_bucket(50, 5), malformed],
        ),
        SearchOutcome(
            target=_contract().target, fingerprint="complete", started_at=START, ended_at=START,
            completeness=Completeness.complete, total=2, total_relation="eq", returned=2,
            buckets=[_continuity_bucket(10, 35), _continuity_bucket(11, 45)],
        ),
    ))
    monkeypatch.setattr(sweep_module, "execute", lambda *_args, **_kwargs: next(outcomes))
    contract = _contract()
    sweep = Sweep(
        _repo(), None, "h1", Window(start=START, end=START + timedelta(hours=1)),
        {contract.target: contract}, stage_dir=tmp_path,
    )

    first_times, first_reasons = sweep._selective_windows_continuity(
        contract.target, contract, Window(start=START, end=START + timedelta(minutes=30)),
    )
    _second_times, second_reasons = sweep._selective_windows_continuity(
        contract.target, contract,
        Window(start=START + timedelta(minutes=30), end=START + timedelta(hours=1)),
    )

    assert first_times == {}
    assert first_reasons == [
        "shipper gaps unresolved: 1 continuity metadata bucket(s) lack numeric record_id"
    ]
    assert not any("out of order" in reason for reason in second_reasons)
    sweep.close_stage()


def test_selective_metadata_is_sorted_by_time_before_continuity_evaluation(tmp_path, monkeypatch):
    from romulus.hunt import sweep as sweep_module
    from tests.test_sweep import _repo

    buckets = [_continuity_bucket(11, 10), _continuity_bucket(10, 5)]
    monkeypatch.setattr(sweep_module, "execute", lambda _client, intent, _contract: SearchOutcome(
        target=intent.target, fingerprint="continuity", started_at=START, ended_at=START,
        completeness=Completeness.complete, total=2, total_relation="eq",
        returned=2, buckets=buckets,
    ))
    contract = _contract()
    sweep = Sweep(
        _repo(), None, "h1", Window(start=START, end=START + timedelta(minutes=30)),
        {contract.target: contract}, stage_dir=tmp_path,
    )

    _times, reasons = sweep._selective_windows_continuity(
        contract.target, contract, sweep.window,
    )

    assert reasons == []
    sweep.close_stage()


def test_selective_metadata_preserves_record_id_reuse_at_distinct_timestamps(tmp_path, monkeypatch):
    from romulus.hunt import sweep as sweep_module
    from tests.test_sweep import _repo

    buckets = [_continuity_bucket(10, 5), _continuity_bucket(10, 10)]
    seen = []

    def execute(_client, intent, _contract):
        seen.append(intent)
        return SearchOutcome(
            target=intent.target, fingerprint="continuity", started_at=START, ended_at=START,
            completeness=Completeness.complete, total=2, total_relation="eq",
            returned=2, buckets=buckets,
        )

    monkeypatch.setattr(sweep_module, "execute", execute)
    contract = _contract()
    sweep = Sweep(
        _repo(), None, "h1", Window(start=START, end=START + timedelta(minutes=30)),
        {contract.target: contract}, stage_dir=tmp_path,
    )

    _times, reasons = sweep._selective_windows_continuity(
        contract.target, contract, sweep.window,
    )

    assert seen[0].group_by[0] == "@timestamp"
    assert any("record_id reused (log cleared or reverted)" in reason for reason in reasons)
    sweep.close_stage()


@pytest.mark.parametrize(("different_payload", "expects_reuse"), [(False, False), (True, True)])
def test_selective_metadata_resolves_collapsed_record_signatures(
    tmp_path, monkeypatch, different_payload, expects_reuse,
):
    from romulus.hunt import sweep as sweep_module
    from tests.test_sweep import _repo

    collapsed = _continuity_bucket(10, 5)
    collapsed["count"] = 2
    buckets = [collapsed, _continuity_bucket(11, 10)]
    first = _hit(10, native_id="copy-a")
    second = _hit(10, native_id="copy-b")
    if different_payload:
        second["_source"]["winlog"]["event_data"]["ProcessGuid"] = (
            "{FFFFFFFF-EEEE-DDDD-CCCC-BBBBBBBBBBBB}"
        )
    seen = []

    def execute(_client, intent, _contract):
        seen.append(intent)
        if intent.kind == "aggregate":
            return SearchOutcome(
                target=intent.target, fingerprint="continuity", started_at=START, ended_at=START,
                completeness=Completeness.complete, total=3, total_relation="eq",
                returned=2, buckets=buckets,
            )
        return SearchOutcome(
            target=intent.target, fingerprint="collision", started_at=START, ended_at=START,
            completeness=Completeness.complete, total=2, total_relation="eq",
            returned=2, records=[first, second],
        )

    monkeypatch.setattr(sweep_module, "execute", execute)
    contract = _contract()
    sweep = Sweep(
        _repo(), None, "h1", Window(start=START, end=START + timedelta(minutes=30)),
        {contract.target: contract}, stage_dir=tmp_path,
    )

    _times, reasons = sweep._selective_windows_continuity(
        contract.target, contract, sweep.window,
    )

    assert [intent.kind for intent in seen] == ["aggregate", "raw"]
    assert seen[1].purpose == "windows continuity collision signatures"
    assert seen[1].max_records < PARTITION_MAX_DOCS
    assert any("record_id reused (log cleared or reverted)" in reason for reason in reasons) is expects_reuse
    assert not any("continuity collision" in reason for reason in reasons)
    sweep.close_stage()


def test_selective_metadata_collision_followup_fails_closed_without_mutating_continuity(
    tmp_path, monkeypatch,
):
    from romulus.hunt import sweep as sweep_module
    from tests.test_sweep import _repo

    collapsed = _continuity_bucket(10, 5)
    collapsed["count"] = 2

    def execute(_client, intent, _contract):
        if intent.kind == "aggregate":
            return SearchOutcome(
                target=intent.target, fingerprint="continuity", started_at=START, ended_at=START,
                completeness=Completeness.complete, total=2, total_relation="eq",
                returned=1, buckets=[collapsed],
            )
        return SearchOutcome(
            target=intent.target, fingerprint="collision-capped", started_at=START, ended_at=START,
            completeness=Completeness.partial, reasons=["cap:2<total:3"],
            total=3, total_relation="eq", returned=2, records=[_hit(10), _hit(10)],
        )

    monkeypatch.setattr(sweep_module, "execute", execute)
    contract = _contract()
    sweep = Sweep(
        _repo(), None, "h1", Window(start=START, end=START + timedelta(minutes=30)),
        {contract.target: contract}, stage_dir=tmp_path,
    )

    times, reasons = sweep._selective_windows_continuity(
        contract.target, contract, sweep.window,
    )

    assert times == {}
    assert reasons == [
        "shipper gaps unresolved: continuity collision records incomplete: cap:2<total:3"
    ]
    assert sweep._windows_record_ids is None
    sweep.close_stage()


def test_selective_metadata_true_record_id_gap_makes_the_windows_cell_partial(tmp_path, monkeypatch):
    from romulus.hunt import sweep as sweep_module
    from tests.test_sweep import _repo

    raw_records = [_hit(10), _hit(12)]
    buckets = [_continuity_bucket(10, 5), _continuity_bucket(12, 25)]

    def execute(_client, intent, _contract):
        if intent.kind == "aggregate":
            return SearchOutcome(
                target=intent.target, fingerprint="continuity", started_at=START, ended_at=START,
                completeness=Completeness.complete, total=2, total_relation="eq",
                returned=2, buckets=buckets,
            )
        return SearchOutcome(
            target=intent.target, fingerprint="raw", started_at=START, ended_at=START,
            completeness=Completeness.complete, total=2, total_relation="eq",
            returned=2, records=raw_records,
        )

    monkeypatch.setattr(sweep_module, "execute", execute)
    contract = _contract()
    event_class = lookup_event_class(SYSMON_CHANNEL, SYSMON, 1)
    window = Window(start=START, end=START + timedelta(minutes=30))
    repo = _repo()
    sweep = Sweep(
        repo, None, "h1", window, {contract.target: contract},
        site_facts=_site(tmp_path), stage_dir=tmp_path,
    )
    sweep.pack = [WindowsProcessRule()]
    sweep._windows_inventory[contract.target] = {event_class.token}
    sweep._windows_inventory_reasons[contract.target] = []
    sweep._windows_selective.add(contract.target)

    sweep.run_partition(contract.target, contract, [], window, est=2)

    cell = repo.rule_cells("h1")[0]
    assert cell["state"] == "evaluated_partial"
    assert (
        f"shipper gaps: 1 records missing on {SYSMON_CHANNEL} for ws01.example.test"
        in cell["detail"]["reasons"]
    )
    sweep.close_stage()


def test_selective_metadata_from_one_host_cannot_attest_another_host(tmp_path, monkeypatch):
    from romulus.hunt import sweep as sweep_module
    from tests.test_sweep import _repo

    raw_records = [_hit(10), _hit(11)]
    buckets = [_continuity_bucket(10, 5), _continuity_bucket(11, 25)]

    def execute(_client, intent, _contract):
        if intent.kind == "aggregate":
            return SearchOutcome(
                target=intent.target, fingerprint="continuity", started_at=START, ended_at=START,
                completeness=Completeness.complete, total=2, total_relation="eq",
                returned=2, buckets=buckets,
            )
        return SearchOutcome(
            target=intent.target, fingerprint="raw", started_at=START, ended_at=START,
            completeness=Completeness.complete, total=2, total_relation="eq",
            returned=2, records=raw_records,
        )

    monkeypatch.setattr(sweep_module, "execute", execute)
    contract = _contract().model_copy(update={"hosts": ("ws01.example.test", "ws02.example.test")})
    event_class = lookup_event_class(SYSMON_CHANNEL, SYSMON, 1)
    window = Window(start=START, end=START + timedelta(minutes=30))
    repo = _repo()
    sweep = Sweep(
        repo, None, "h1", window, {contract.target: contract},
        site_facts=_site(tmp_path), stage_dir=tmp_path,
    )
    sweep.pack = [WindowsProcessRule()]
    sweep._windows_inventory[contract.target] = {event_class.token}
    sweep._windows_inventory_reasons[contract.target] = []
    sweep._windows_selective.add(contract.target)

    sweep.run_partition(contract.target, contract, [], window, est=2)

    cell = repo.rule_cells("h1")[0]
    assert cell["state"] == "evaluated_partial"
    assert (
        f"shipper gaps unresolved: no records on {SYSMON_CHANNEL} in partition on ws02.example.test"
        in cell["detail"]["reasons"]
    )
    sweep.close_stage()


def test_selective_metadata_from_an_earlier_partition_cannot_attest_the_next_partition(tmp_path, monkeypatch):
    from romulus.hunt import sweep as sweep_module
    from tests.test_sweep import _repo

    first = Window(start=START, end=START + timedelta(minutes=30))
    second = Window(start=first.end, end=START + timedelta(hours=1))
    first_records = [_hit(10), _hit(11)]

    def execute(_client, intent, _contract):
        in_first = intent.window == first
        if intent.kind == "aggregate":
            buckets = (
                [_continuity_bucket(10, 5), _continuity_bucket(11, 15)] if in_first else []
            )
            return SearchOutcome(
                target=intent.target, fingerprint="continuity", started_at=START, ended_at=START,
                completeness=Completeness.complete, total=len(buckets), total_relation="eq",
                returned=len(buckets), buckets=buckets,
            )
        records = first_records if in_first else []
        return SearchOutcome(
            target=intent.target, fingerprint="raw", started_at=START, ended_at=START,
            completeness=Completeness.complete, total=len(records), total_relation="eq",
            returned=len(records), records=records,
        )

    monkeypatch.setattr(sweep_module, "execute", execute)
    contract = _contract()
    event_class = lookup_event_class(SYSMON_CHANNEL, SYSMON, 1)
    repo = _repo()
    sweep = Sweep(
        repo, None, "h1", Window(start=first.start, end=second.end), {contract.target: contract},
        site_facts=_site(tmp_path), stage_dir=tmp_path,
    )
    sweep.pack = [WindowsProcessRule()]
    sweep._windows_inventory[contract.target] = {event_class.token}
    sweep._windows_inventory_reasons[contract.target] = []
    sweep._windows_selective.add(contract.target)

    sweep.run_partition(contract.target, contract, [], first, est=2)
    sweep.run_partition(contract.target, contract, [], second, est=0)

    cells = {cell["partition"]: cell for cell in repo.rule_cells("h1")}
    assert cells[first.key()]["state"] == "no_match_complete"
    assert cells[second.key()]["state"].endswith("partial")
    assert (
        f"shipper gaps unresolved: no records on {SYSMON_CHANNEL} in partition on ws01.example.test"
        in cells[second.key()]["detail"]["reasons"]
    )
    sweep.close_stage()


@pytest.mark.parametrize(
    ("completeness", "reasons", "error", "expected"),
    [
        (Completeness.partial, ["aggregate_bucket_cap:1"], None, "aggregate_bucket_cap:1"),
        (Completeness.failed, ["source_error"], "backend unavailable", "source_error"),
    ],
)
def test_selective_metadata_cap_or_failure_makes_the_windows_cell_partial(
    tmp_path, monkeypatch, completeness, reasons, error, expected,
):
    from romulus.hunt import sweep as sweep_module
    from tests.test_sweep import _repo

    raw_records = [_hit(10), _hit(11)]
    aggregate_calls = 0

    def execute(_client, intent, _contract):
        nonlocal aggregate_calls
        if intent.kind == "aggregate":
            aggregate_calls += 1
            return SearchOutcome(
                target=intent.target, fingerprint="continuity", started_at=START, ended_at=START,
                completeness=completeness, reasons=reasons, error=error,
                total=2, total_relation="eq", returned=1,
                buckets=[_continuity_bucket(10, 5)] if completeness == Completeness.partial else [],
            )
        return SearchOutcome(
            target=intent.target, fingerprint="raw", started_at=START, ended_at=START,
            completeness=Completeness.complete, total=2, total_relation="eq",
            returned=2, records=raw_records,
        )

    monkeypatch.setattr(sweep_module, "execute", execute)
    contract = _contract()
    event_class = lookup_event_class(SYSMON_CHANNEL, SYSMON, 1)
    window = Window(start=START, end=START + timedelta(minutes=30))
    repo = _repo()
    sweep = Sweep(
        repo, None, "h1", window, {contract.target: contract},
        site_facts=_site(tmp_path), stage_dir=tmp_path,
    )
    sweep.pack = [WindowsProcessRule()]
    sweep._windows_inventory[contract.target] = {event_class.token}
    sweep._windows_inventory_reasons[contract.target] = []
    sweep._windows_selective.add(contract.target)

    sweep.run_partition(contract.target, contract, [], window, est=2)

    cell = repo.rule_cells("h1")[0]
    assert aggregate_calls == 1
    assert cell["state"] == "evaluated_partial"
    assert any(
        reason.startswith("shipper gaps unresolved: continuity metadata incomplete:") and expected in reason
        for reason in cell["detail"]["reasons"]
    )
    assert sweep._windows_record_ids is None
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
        ("collection changed on ws01.example.test at 2026-01-02T00:10:00+00:00: "
         "Security|Microsoft-Windows-Security-Auditing|4719 (audit policy changed)"),
        ("collection changed on ws01.example.test at 2026-01-02T00:20:00+00:00: "
         "Security|Microsoft-Windows-Security-Auditing|4719 (audit policy changed)"),
    ]


def test_collection_change_classification_keeps_cross_channel_breaks_host_scoped():
    audit_change = _hit(20, event_id=4719)
    audit_change["_source"]["winlog"].update({
        "channel": "Security",
        "provider_name": SECURITY,
    })
    sysmon_change = _hit(21, event_id=16)
    sysmon_change["_source"]["winlog"]["computer_name"] = "WS02.example.test"

    channel_changes, cross_channel_changes = Sweep._windows_collection_changes(
        [audit_change, sysmon_change]
    )

    assert cross_channel_changes == {
        "ws01.example.test": {
            (
                "collection changed on ws01.example.test at 2026-01-02T00:05:00+00:00: "
                "Security|Microsoft-Windows-Security-Auditing|4719 (audit policy changed)"
            )
        }
    }
    assert channel_changes == {
        ("ws02.example.test", SYSMON_CHANNEL.casefold()): {
            (
                "collection changed on ws02.example.test at 2026-01-02T00:05:00+00:00: "
                f"{SYSMON_CHANNEL}|{SYSMON}|16 (Sysmon configuration changed)"
            )
        }
    }


def test_sysmon_collection_controls_are_channel_scoped_timed_and_state_aware(tmp_path):
    contract = _contract()
    rule = WindowsProcessRule()
    window = Window(start=START, end=START + timedelta(minutes=30))
    sweep = Sweep(None, None, "h1", window, {contract.target: contract}, site_facts=_site(tmp_path))
    event_class = lookup_event_class(SYSMON_CHANNEL, SYSMON, 1)
    sweep._windows_inventory[contract.target] = {event_class.token}
    sweep._windows_inventory_reasons[contract.target] = []
    records = [_hit(10), _hit(11)]
    records[1]["_source"]["@timestamp"] = (START + timedelta(minutes=25)).isoformat()
    started = _hit(20, event_id=4)
    started["_source"]["@timestamp"] = (START + timedelta(minutes=10)).isoformat()
    started["_source"]["winlog"]["event_data"] = {"State": "Started"}
    changed = _hit(21, event_id=16)
    changed["_source"]["@timestamp"] = (START + timedelta(minutes=20)).isoformat()

    reasons = sweep._windows_rule_reasons(
        contract.target, contract, rule, [*records, started, changed], [], window,
    )

    assert reasons == [
        ("collection changed on ws01.example.test at 2026-01-02T00:20:00+00:00: "
         f"{SYSMON_CHANNEL}|{SYSMON}|16 (Sysmon configuration changed)"),
    ]


def test_collection_change_events_are_centralized_for_future_catalog_growth():
    assert {
        ("security", "microsoft-windows-security-auditing", 4719): "audit policy changed",
        ("security", "microsoft-windows-eventlog", 1102): "security log cleared",
        ("system", "microsoft-windows-eventlog", 104): "event log cleared",
        ("system", "eventlog", 6006): "event log service stopped",
        (SYSMON_CHANNEL.casefold(), SYSMON.casefold(), 4): "Sysmon service state changed",
        (SYSMON_CHANNEL.casefold(), SYSMON.casefold(), 16): "Sysmon configuration changed",
        (SYSMON_CHANNEL.casefold(), SYSMON.casefold(), 255): "Sysmon error",
        ("security", "microsoft-windows-eventlog", 1100): "event log service shut down",
        ("security", "microsoft-windows-eventlog", 1104): "security log full",
        ("security", "microsoft-windows-eventlog", 1108): "event logging error",
    } == COLLECTION_CHANGE_EVENTS


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


def test_event_class_inventory_fails_closed_for_missing_identity_fields(tmp_path, monkeypatch):
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
            total=5,
            total_relation="eq",
            returned=2,
            buckets=[
                {
                    "key": {
                        "event.channel": SYSMON_CHANNEL,
                        "event.provider": SYSMON,
                        "event.code": 1,
                    },
                    "count": 2,
                },
                {
                    "key": {
                        "event.channel": None,
                        "event.provider": None,
                        "event.code": None,
                    },
                    "count": 3,
                },
            ],
        )

    monkeypatch.setattr(sweep_module, "execute", execute)
    contract = _contract()
    sweep = Sweep(
        None,
        object(),
        "h1",
        Window(start=START, end=START + timedelta(hours=1)),
        {contract.target: contract},
        site_facts=_site(tmp_path),
    )
    sweep.pack = [WindowsProcessRule()]

    sweep._prepare_windows_inventory(contract.target, contract)

    [intent] = seen
    assert intent.filters == []
    assert {group[0].field for group in intent.any_of} == {
        "event.channel",
        "event.provider",
        "event.code",
        "host.name",
        "winlog.record_id",
        "event.dataset",
    }
    dataset_group = next(group for group in intent.any_of if group[0].field == "event.dataset")
    assert dataset_group == [
        Predicate(field="event.dataset", op="in", value=list(WINDOWS_HOST_DATASETS))
    ]
    reason = (
        "event class inventory incomplete: 3 Windows record(s) have missing or invalid "
        "channel/provider/event id across 1 bucket(s)"
    )
    assert sweep._windows_inventory_reasons[contract.target] == [reason]
    assert reason in sweep._windows_rule_reasons(
        contract.target,
        contract,
        WindowsProcessRule(),
        [_hit(10), _hit(11)],
        [],
    )


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
        "classes": 1,
        "records": 1,
    }
    retrieval = {
        tuple((predicate.field, predicate.value) for predicate in group)
        for group in sweep._any_of_for(contract.target, contract)
    }
    for channel, provider, event_id in named:
        assert (
            ("event.channel", channel), ("event.provider", provider), ("event.code", event_id),
        ) not in retrieval


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
    from romulus.detect.registry import WINDOWS_PROCESS_PLAYBOOKS

    windows_families = {event.family for event in EVENT_CLASSES}
    windows_enabled = {
        playbook.id
        for playbook in ALL_PLAYBOOKS
        if windows_families.intersection(playbook.families) and "windows" in playbook.os_families
    }

    # Only the cross-platform indicator rule and the purpose-built Windows process rules read Windows families;
    # every Linux host rule stays scoped to linux.
    assert windows_enabled == {"ioc.indicator_match"} | {cls.id for cls in WINDOWS_PROCESS_PLAYBOOKS}


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


def test_incomplete_script_part_metadata_marks_only_the_relevant_windows_cell_partial(
    tmp_path, monkeypatch,
):
    from romulus.hunt import sweep as sweep_module
    from tests.test_sweep import _repo

    channel = "Microsoft-Windows-PowerShell/Operational"
    provider = "Microsoft-Windows-PowerShell"
    records = [_hit(10), _hit(11)]
    for record in records:
        record["_source"]["event"]["dataset"] = "windows.powershell_operational"
        record["_source"]["winlog"].update({
            "channel": channel,
            "provider_name": provider,
            "event_id": 4104,
            "event_data": {
                "ScriptBlockId": "11111111-2222-3333-4444-555555555555",
                "ScriptBlockText": "Write-Output partial",
                "MessageNumber": "1",
            },
        })
    event = TypedEvent(
        id="incomplete-script-metadata",
        family="script_block",
        ts=START + timedelta(minutes=1),
        host="ws01",
        outcome=Outcome.success,
        fields={
            "event.code": fv(4104, "w-10:winlog.event_id"),
            "host.os.family": fv("windows", "w-10:winlog.computer_name"),
            "script.block_id": fv(
                "11111111-2222-3333-4444-555555555555",
                "w-10:winlog.event_data.ScriptBlockId",
            ),
            "script.message_number": fv(1, "w-10:winlog.event_data.MessageNumber"),
            "script.text": fv("Write-Output partial", "w-10:winlog.event_data.ScriptBlockText"),
            "script.complete": fv(False, "w-10:computed:incomplete-metadata"),
        },
        raw=[RawRef(target="logs-windows", native_id="w-10", digest="w-10")],
        normalizer="windows-ecs@3",
    )
    monkeypatch.setattr(sweep_module, "normalize_hits", lambda *_args, **_kwargs: ([event], {}, []))
    monkeypatch.setattr(sweep_module, "execute", lambda _client, intent, _contract: SearchOutcome(
        target=intent.target,
        fingerprint="incomplete-script-metadata",
        started_at=START,
        ended_at=START,
        completeness=Completeness.complete,
        total=len(records),
        total_relation="eq",
        returned=len(records),
        records=records,
    ))
    site_path = tmp_path / "site" / "collection.yaml"
    site_path.parent.mkdir(parents=True)
    site_path.write_text(
        "schema: romulus-site-collection@1\n"
        "collection:\n"
        "  - hosts: [ws*.example.test]\n"
        "    powershell_script_block: true\n"
        f"    event_channels: [{channel}]\n",
        encoding="utf-8",
    )
    contract = _contract()
    window = Window(start=START, end=START + timedelta(minutes=5))
    repo = _repo()
    sweep = Sweep(
        repo,
        None,
        "h1",
        window,
        {contract.target: contract},
        site_facts=load_site_facts(tmp_path),
        stage_dir=tmp_path,
    )
    sweep.pack = [WindowsScriptRule(), WindowsProcessRule()]
    script_class = lookup_event_class(channel, provider, 4104)
    process_class = lookup_event_class(SYSMON_CHANNEL, SYSMON, 1)
    assert script_class is not None and process_class is not None
    sweep._windows_inventory[contract.target] = {script_class.token, process_class.token}
    sweep._windows_inventory_reasons[contract.target] = []

    sweep.run_partition(contract.target, contract, [], window, est=len(records))

    cells = {cell["rule_id"]: cell for cell in repo.rule_cells("h1")}
    script_cell = cells[WindowsScriptRule.id]
    assert script_cell["state"] == "evaluated_partial"
    assert script_cell["detail"]["reasons"] == [
        "PowerShell script-block part metadata incomplete or invalid for 1 event(s)",
    ]
    assert all(
        "script-block part metadata" not in reason
        for reason in cells[WindowsProcessRule.id]["detail"]["reasons"]
    )
    sweep.close_stage()


def test_huge_script_part_total_is_cited_partial_and_never_enters_reassembly_state(
    tmp_path, monkeypatch,
):
    from romulus.hunt import sweep as sweep_module
    from tests.test_sweep import _repo

    channel = "Microsoft-Windows-PowerShell/Operational"
    provider = "Microsoft-Windows-PowerShell"
    record = _script_hit(
        10,
        1,
        block="11111111-2222-3333-4444-555555555555",
        number=1,
        total=2**31,
        text="Write-Output hostile-metadata",
    )
    monkeypatch.setattr(sweep_module, "execute", lambda _client, intent, _contract: SearchOutcome(
        target=intent.target,
        fingerprint="huge-script-part-total",
        started_at=START,
        ended_at=START,
        completeness=Completeness.complete,
        total=1,
        total_relation="eq",
        returned=1,
        records=[record],
    ))
    site_path = tmp_path / "site" / "collection.yaml"
    site_path.parent.mkdir(parents=True)
    site_path.write_text(
        "schema: romulus-site-collection@1\n"
        "collection:\n"
        "  - hosts: [ws*.example.test]\n"
        "    sysmon:\n"
        "      installed: true\n"
        "      event_ids: [1]\n"
        "    powershell_script_block: true\n"
        f"    event_channels: [{channel}]\n",
        encoding="utf-8",
    )
    contract = _contract()
    repo = _repo()
    sweep = Sweep(
        repo,
        None,
        "h1",
        Window(start=START, end=START + timedelta(minutes=5)),
        {contract.target: contract},
        site_facts=load_site_facts(tmp_path),
        stage_dir=tmp_path,
    )
    script_rule = IncompleteCitationWindowsScriptRule()
    sweep.pack = [script_rule, WindowsProcessRule()]
    script_class = lookup_event_class(channel, provider, 4104)
    process_class = lookup_event_class(SYSMON_CHANNEL, SYSMON, 1)
    assert script_class is not None and process_class is not None
    sweep._windows_inventory[contract.target] = {script_class.token, process_class.token}
    sweep._windows_inventory_reasons[contract.target] = []

    sweep.run_partition(contract.target, contract, [], sweep.window, est=1)

    assert sweep._windows_scripts is not None
    assert sweep._windows_scripts.db.execute("SELECT count(*) FROM blocks").fetchone()[0] == 0
    [candidate] = repo.candidates("h1")
    assert candidate["rule_id"] == script_rule.id
    [stored] = repo.events_by_ids(candidate["event_ids"])
    assert stored["event"]["fields"]["script.complete"]["value"] is False
    [raw] = repo.raw_records(stored["raw_ids"])
    assert raw["native_id"] == record["_id"]
    cells = {cell["rule_id"]: cell for cell in repo.rule_cells("h1")}
    assert cells[script_rule.id]["state"] == "match_on_partial"
    assert (
        "PowerShell script-block part metadata incomplete or invalid for 1 event(s)"
        in cells[script_rule.id]["detail"]["reasons"]
    )
    assert all(
        "script-block part metadata" not in reason
        for reason in cells[WindowsProcessRule.id]["detail"]["reasons"]
    )
    assert record["_source"]["winlog"]["event_data"]["MessageTotal"] == str(2**31)
    assert 2**31 > SCRIPT_BLOCK_MAX_PARTS
    sweep.close_stage()


def test_script_reassembly_budget_refusal_marks_only_script_rules_partial(tmp_path, monkeypatch):
    from romulus.hunt import sweep as sweep_module
    from tests.test_sweep import _repo

    channel = "Microsoft-Windows-PowerShell/Operational"
    record = _script_hit(
        10,
        1,
        block="11111111-2222-3333-4444-555555555555",
        number=1,
        total=2,
        text="Write-Output partial",
    )
    monkeypatch.setattr(sweep_module, "execute", lambda _client, intent, _contract: SearchOutcome(
        target=intent.target,
        fingerprint="script-budget-refusal",
        started_at=START,
        ended_at=START,
        completeness=Completeness.complete,
        total=1,
        total_relation="eq",
        returned=1,
        records=[record],
    ))
    site_path = tmp_path / "site" / "collection.yaml"
    site_path.parent.mkdir(parents=True)
    site_path.write_text(
        "schema: romulus-site-collection@1\n"
        "collection:\n"
        "  - hosts: [ws*.example.test]\n"
        "    sysmon:\n"
        "      installed: true\n"
        "      event_ids: [1]\n"
        "    powershell_script_block: true\n"
        f"    event_channels: [{channel}]\n",
        encoding="utf-8",
    )
    contract = _contract()
    window = Window(start=START, end=START + timedelta(minutes=5))
    repo = _repo()
    sweep = Sweep(
        repo,
        None,
        "h1",
        window,
        {contract.target: contract},
        site_facts=load_site_facts(tmp_path),
        stage_dir=tmp_path,
    )
    sweep.pack = [WindowsScriptRule(), WindowsProcessRule()]
    script_class = lookup_event_class(channel, "Microsoft-Windows-PowerShell", 4104)
    process_class = lookup_event_class(SYSMON_CHANNEL, SYSMON, 1)
    assert script_class is not None and process_class is not None
    sweep._windows_inventory[contract.target] = {script_class.token, process_class.token}
    sweep._windows_inventory_reasons[contract.target] = []
    sweep._windows_script_blocks()
    sweep.budget.force_full(
        "script state test refusal",
        lambda account: account is sweep._windows_scripts_account,
    )

    sweep.run_partition(contract.target, contract, [], window, est=1)

    cells = {cell["rule_id"]: cell for cell in repo.rule_cells("h1")}
    assert cells[WindowsScriptRule.id]["state"] == "evaluated_partial"
    assert any(
        "script state test refusal" in reason
        for reason in cells[WindowsScriptRule.id]["detail"]["reasons"]
    )
    assert all(
        "script state test refusal" not in reason
        for reason in cells[WindowsProcessRule.id]["detail"]["reasons"]
    )
    sweep.close_stage()


def test_cross_partition_script_completion_uses_completion_time_and_partition(tmp_path, monkeypatch):
    from romulus.hunt import sweep as sweep_module
    from tests.test_sweep import _repo

    channel = "Microsoft-Windows-PowerShell/Operational"
    first = Window(start=START, end=START + timedelta(minutes=5))
    second = Window(start=first.end, end=START + timedelta(minutes=10))
    multi_block = "11111111-2222-3333-4444-555555555555"
    single_block = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    first_records = [
        _script_hit(10, 1, block=multi_block, number=1, total=2, text="first"),
        _script_hit(11, 4, block=single_block, number=1, total=1, text="standalone"),
    ]
    second_records = [
        _script_hit(12, 6, block=multi_block, number=2, total=2, text="second"),
    ]

    def execute(_client, intent, _contract):
        records = first_records if intent.window.start == first.start else second_records
        return SearchOutcome(
            target=intent.target,
            fingerprint=intent.window.key(),
            started_at=START,
            ended_at=START,
            completeness=Completeness.complete,
            total=len(records),
            total_relation="eq",
            returned=len(records),
            records=records,
        )

    monkeypatch.setattr(sweep_module, "execute", execute)
    site_path = tmp_path / "site" / "collection.yaml"
    site_path.parent.mkdir(parents=True)
    site_path.write_text(
        "schema: romulus-site-collection@1\n"
        "collection:\n"
        "  - hosts: [ws*.example.test]\n"
        "    powershell_script_block: true\n"
        f"    event_channels: [{channel}]\n",
        encoding="utf-8",
    )
    contract = _contract()
    repo = _repo()
    sweep = Sweep(
        repo,
        None,
        "h1",
        Window(start=first.start, end=second.end),
        {contract.target: contract},
        site_facts=load_site_facts(tmp_path),
        stage_dir=tmp_path,
    )
    rule = RecordingWindowsScriptRule()
    sweep.pack = [rule]
    script_class = lookup_event_class(channel, "Microsoft-Windows-PowerShell", 4104)
    assert script_class is not None
    sweep._windows_inventory[contract.target] = {script_class.token}
    sweep._windows_inventory_reasons[contract.target] = []

    sweep.run_partition(contract.target, contract, [], first, est=len(first_records))
    sweep.run_partition(contract.target, contract, [], second, est=len(second_records))

    assert rule.seen_times == [
        START + timedelta(minutes=1),
        START + timedelta(minutes=4),
        START + timedelta(minutes=6),
        START + timedelta(minutes=6),
    ]
    cells = {cell["partition"]: cell for cell in repo.rule_cells("h1")}
    assert cells[first.key()]["evaluated"] == 2
    assert cells[second.key()]["evaluated"] == 2
    sweep.close_stage()


def test_end_of_sweep_incomplete_scripts_use_staged_and_aggregate_bookkeeping(tmp_path):
    from tests.test_sweep import _repo

    records = [
        _script_hit(
            20,
            1,
            block="11111111-2222-3333-4444-555555555555",
            number=1,
            total=2,
            text="first incomplete block",
        ),
        _script_hit(
            21,
            2,
            block="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            number=1,
            total=2,
            text="second incomplete block",
        ),
    ]
    events, skips, errors = normalize_hits(records)
    assert not skips and not errors
    raw_sources = {f"{record['_index']}/{record['_id']}": record["_source"] for record in records}
    contract = _contract()
    repo = _repo()
    sweep = Sweep(
        repo,
        None,
        "h1",
        Window(start=START, end=START + timedelta(minutes=5)),
        {contract.target: contract},
        stage_dir=tmp_path,
    )
    staged = FinalizedStagedWindowsScriptRule()
    retained = FinalizedRetainedWindowsScriptRule()
    sweep.pack = [staged, retained]

    fragments = sweep._windows_script_blocks().consume(events, raw_sources)
    assert all(event.has("script.part_number") for event in fragments)
    sweep._finalize_windows_script_blocks()

    stage = sweep._event_stage()
    staged_events = stage.load(staged.ids)
    assert staged.bounds_drained == 1
    assert [event.id for event in staged_events] == staged.ids
    assert stage.raw_sources(staged_events) == raw_sources
    assert stage.db.execute("SELECT id, owner, n FROM hold").fetchall() == [
        (staged.ids[0], staged.id, 1),
    ]
    assert sweep._agg_raw == raw_sources

    sweep.finalize()

    candidates = {candidate["rule_id"]: candidate for candidate in repo.candidates("h1")}
    assert staged.loaded_ids == staged.ids
    assert candidates[staged.id]["event_ids"] == staged.ids
    assert candidates[retained.id]["event_ids"] == [event.id for event in retained.events]


def test_end_of_sweep_incomplete_scripts_are_consumed_in_bounded_batches(tmp_path):
    from tests.test_sweep import _repo

    count = SCRIPT_FINALIZE_BATCH_SIZE * 2 + 1
    records = [
        _script_hit(
            record_id,
            1,
            block=f"00000000-0000-0000-0000-{record_id:012x}",
            number=1,
            total=2,
            text=f"incomplete-{record_id}",
        )
        for record_id in range(1, count + 1)
    ]
    events, skips, errors = normalize_hits(records)
    assert not skips and not errors
    raw_sources = {f"{record['_index']}/{record['_id']}": record["_source"] for record in records}
    contract = _contract()
    repo = _repo()
    sweep = Sweep(
        repo,
        None,
        "h1",
        Window(start=START, end=START + timedelta(minutes=5)),
        {contract.target: contract},
        stage_dir=tmp_path,
    )
    rule = FinalizedBatchRecordingWindowsScriptRule()
    sweep.pack = [rule]

    fragments = sweep._windows_script_blocks().consume(events, raw_sources)
    assert len(fragments) == count and all(event.has("script.part_number") for event in fragments)
    sweep._finalize_windows_script_blocks()

    assert rule.batch_sizes == [SCRIPT_FINALIZE_BATCH_SIZE, SCRIPT_FINALIZE_BATCH_SIZE, 1]
    assert sweep._windows_scripts is not None and sweep._windows_scripts._emitted_sources == {}
    [cell] = repo.rule_cells("h1")
    assert cell["evaluated"] == count
    assert cell["detail"]["reasons"] == [
        f"PowerShell script-block reassembly incomplete for {count} block(s); missing parts stated",
    ]
    sweep.close_stage()


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
    refused = sweep._event_stage().windows_refused
    assert cell["state"] == "evaluated_partial"
    assert cell["evaluated"] == 5_000                        # refused dedup state never withholds a record
    assert any("counts over them may include duplicates" in reason for reason in cell["detail"]["reasons"])
    assert "state_capped" not in cell["detail"]
    assert any("host/channel groups" in reason for reason in cell["detail"]["reasons"])
    assert "windows_seen" in budget.full
    assert refused > 0
    assert len(cell["detail"]["reasons"]) < 10
    sweep.close_stage()
