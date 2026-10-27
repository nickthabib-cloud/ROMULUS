"""Bounded-memory normalization proof at ten times the documented mission fixture volume."""

from __future__ import annotations

import json
import tracemalloc
from collections import Counter
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from itertools import islice
from time import perf_counter

import pytest

from romulus.detect.base import Match, Playbook, pf
from romulus.evidence.normalize import normalize_hits
from romulus.evidence.windows_catalog import (
    POWERSHELL_CHANNEL,
    POWERSHELL_PROVIDER,
    SYSMON,
    SYSMON_CHANNEL,
)
from romulus.hunt.sweep import Sweep
from romulus.site import validate_site_content
from romulus.sources.models import Completeness, SearchOutcome, Window
from romulus.sources.profile import contract_from_types
from romulus.store.db import make_engine, migrate
from romulus.store.repo import Repo
from tests.windows_fixtures import mission_windows_volume

BASELINE_RECORDS = 20_000
TEN_X_RECORDS = BASELINE_RECORDS * 10
BATCH_SIZE = 512
MAX_PEAK_BYTES = 128 * 1024 * 1024

MISSION_TARGET = "logs-windows-mission"
MISSION_HOST = "WS001.example.test"
MISSION_START = datetime(2026, 10, 20, 12, tzinfo=UTC)
MISSION_END = MISSION_START + timedelta(minutes=10)
MISSION_HIGH_VOLUME_IDS = (7, 10, 12, 13, 22)
MISSION_HIGH_VOLUME_PER_CLASS = 4_000
MISSION_PROCESS_RECORDS = 128
MISSION_SCRIPT_BLOCKS = 32
MISSION_SOURCE_RECORDS = (
    len(MISSION_HIGH_VOLUME_IDS) * MISSION_HIGH_VOLUME_PER_CLASS
    + MISSION_PROCESS_RECORDS
    + 1  # one exact shipper duplicate
    + MISSION_SCRIPT_BLOCKS * 2
)
MISSION_MAX_PEAK_BYTES = 192 * 1024 * 1024


def _batches(records: Iterator[dict], size: int) -> Iterator[list[dict]]:
    while batch := list(islice(records, size)):
        yield batch


class _MissionProcessProof(Playbook):
    id = "test.windows.mission_process"
    title = "Windows mission-scale process proof"
    families = ("process_exec",)
    os_families = ("windows",)
    windows_event_classes = ((SYSMON_CHANNEL, SYSMON, 1),)

    def __init__(self) -> None:
        super().__init__()
        self.matched_event_ids: list[str] = []

    def match(self, event):
        if event.get("process.command_line") != "cmd.exe /c romulus-mission-proof":
            return []
        self.matched_event_ids.append(event.id)
        return [Match(
            playbook_id=self.id,
            claim="Windows recorded the mission-scale proof process.",
            claim_type="observed_action",
            events=[event],
            predicate=[pf(event, "process.command_line")],
            ts=event.ts,
            severity="low",
            proposed_lane="lead",
            confidence="high",
            group_key=event.id,
        )]


class _MissionScriptProof(Playbook):
    id = "test.windows.mission_script"
    title = "Windows mission-scale script reassembly proof"
    families = ("script_block",)
    os_families = ("windows",)
    windows_event_classes = ((POWERSHELL_CHANNEL, POWERSHELL_PROVIDER, 4104),)

    def __init__(self) -> None:
        super().__init__()
        self.completed_ids: list[str] = []

    def consume(self, events):
        applicable = self.applicable(events)
        self.completed_ids.extend(
            event.id for event in applicable if event.get("script.complete") is True
        )
        return []


class _MissionWindowsSource:
    """Compact source model: materialize only records an intent actually retrieves."""

    _sysmon_unique = (
        len(MISSION_HIGH_VOLUME_IDS) * MISSION_HIGH_VOLUME_PER_CLASS + MISSION_PROCESS_RECORDS
    )
    _duplicate_record_id = len(MISSION_HIGH_VOLUME_IDS) * MISSION_HIGH_VOLUME_PER_CLASS + 1

    def __init__(self) -> None:
        self.raw_by_purpose: Counter[str] = Counter()
        self.raw_event_ids: Counter[int] = Counter()
        self.continuity_buckets = 0
        self.continuity_records = 0
        self.inventory_buckets = 0

    @staticmethod
    def _complete(intent, *, records=None, buckets=None, total: int | None = None) -> SearchOutcome:
        records = records or []
        buckets = buckets or []
        now = datetime.now(UTC)
        return SearchOutcome(
            target=intent.target,
            fingerprint=f"mission-{intent.purpose}",
            started_at=now,
            ended_at=now,
            completeness=Completeness.complete,
            total=len(records) if total is None else total,
            total_relation="eq",
            returned=len(records),
            records=records,
            buckets=buckets,
        )

    @classmethod
    def _sysmon_event_id(cls, record_id: int) -> int:
        high_records = len(MISSION_HIGH_VOLUME_IDS) * MISSION_HIGH_VOLUME_PER_CLASS
        if record_id > high_records:
            return 1
        return MISSION_HIGH_VOLUME_IDS[(record_id - 1) // MISSION_HIGH_VOLUME_PER_CLASS]

    @classmethod
    def _sysmon_time(cls, record_id: int) -> datetime:
        span_us = int((MISSION_END - MISSION_START).total_seconds() * 1_000_000)
        return MISSION_START + timedelta(
            microseconds=(record_id - 1) * span_us // cls._sysmon_unique,
        )

    @staticmethod
    def _script_time(record_id: int) -> datetime:
        if record_id <= MISSION_SCRIPT_BLOCKS:
            return MISSION_START + timedelta(minutes=1, microseconds=record_id)
        return MISSION_START + timedelta(
            minutes=6,
            microseconds=record_id - MISSION_SCRIPT_BLOCKS,
        )

    @classmethod
    def _sysmon_hit(cls, record_id: int, *, duplicate: str = "") -> dict:
        event_id = cls._sysmon_event_id(record_id)
        when = cls._sysmon_time(record_id).isoformat()
        data = {}
        if event_id == 1:
            process_number = record_id - len(MISSION_HIGH_VOLUME_IDS) * MISSION_HIGH_VOLUME_PER_CLASS
            data = {
                "ProcessGuid": f"{{10000000-0000-0000-0000-{process_number:012x}}}",
                "ProcessId": str(10_000 + process_number),
                "ParentProcessId": "712",
                "Image": r"C:\Windows\System32\cmd.exe",
                "ParentImage": r"C:\Windows\explorer.exe",
                "CommandLine": (
                    "cmd.exe /c romulus-mission-proof"
                    if record_id == cls._duplicate_record_id
                    else f"cmd.exe /c echo mission-{process_number}"
                ),
            }
        return {
            "_index": MISSION_TARGET,
            "_id": f"sysmon-{record_id}{duplicate}",
            "_source": {
                "@timestamp": when,
                "agent": {"type": "winlogbeat"},
                "event": {"dataset": "windows.sysmon_operational"},
                "winlog": {
                    "channel": SYSMON_CHANNEL,
                    "provider_name": SYSMON,
                    "event_id": event_id,
                    "computer_name": MISSION_HOST,
                    "record_id": record_id,
                    "time_created": when,
                    "event_data": data,
                },
            },
        }

    @staticmethod
    def _script_hit(record_id: int) -> dict:
        part = 1 if record_id <= MISSION_SCRIPT_BLOCKS else 2
        block_number = record_id if part == 1 else record_id - MISSION_SCRIPT_BLOCKS
        when = _MissionWindowsSource._script_time(record_id).isoformat()
        return {
            "_index": MISSION_TARGET,
            "_id": f"powershell-{record_id}",
            "_source": {
                "@timestamp": when,
                "agent": {"type": "winlogbeat"},
                "event": {"dataset": "windows.powershell_operational"},
                "winlog": {
                    "channel": POWERSHELL_CHANNEL,
                    "provider_name": POWERSHELL_PROVIDER,
                    "event_id": 4104,
                    "computer_name": MISSION_HOST,
                    "record_id": record_id,
                    "time_created": when,
                    "event_data": {
                        "ScriptBlockId": f"20000000-0000-0000-0000-{block_number:012x}",
                        "MessageNumber": str(part),
                        "MessageTotal": "2",
                        "ScriptBlockText": f"mission-block-{block_number}-part-{part};",
                    },
                },
            },
        }

    @staticmethod
    def _bucket(when: datetime, channel: str, record_id: int, *, count: int = 1) -> dict:
        text = when.isoformat()
        return {
            "key": {
                "@timestamp": text,
                "host.name": MISSION_HOST,
                "event.channel": channel,
                "winlog.record_id": record_id,
            },
            "count": count,
            "first": text,
            "last": text,
        }

    @staticmethod
    def _selected_classes(intent) -> set[tuple[str, str, int]]:
        selected = set()
        for group in intent.any_of:
            values = {predicate.field: predicate.value for predicate in group}
            try:
                selected.add((
                    str(values["event.channel"]).casefold(),
                    str(values["event.provider"]).casefold(),
                    int(values["event.code"]),
                ))
            except (KeyError, TypeError, ValueError):
                continue
        return selected

    @staticmethod
    def _in_window(when: datetime, window: Window) -> bool:
        return window.start <= when < window.end

    def _inventory(self, intent) -> SearchOutcome:
        buckets = [
            {
                "key": {
                    "event.channel": SYSMON_CHANNEL,
                    "event.provider": SYSMON,
                    "event.code": event_id,
                },
                "count": MISSION_HIGH_VOLUME_PER_CLASS,
            }
            for event_id in MISSION_HIGH_VOLUME_IDS
        ]
        buckets.extend((
            {
                "key": {
                    "event.channel": SYSMON_CHANNEL,
                    "event.provider": SYSMON,
                    "event.code": 1,
                },
                "count": MISSION_PROCESS_RECORDS + 1,
            },
            {
                "key": {
                    "event.channel": POWERSHELL_CHANNEL,
                    "event.provider": POWERSHELL_PROVIDER,
                    "event.code": 4104,
                },
                "count": MISSION_SCRIPT_BLOCKS * 2,
            },
        ))
        self.inventory_buckets = len(buckets)
        return self._complete(intent, buckets=buckets, total=MISSION_SOURCE_RECORDS)

    def _continuity(self, intent) -> SearchOutcome:
        buckets = []
        records = 0
        for record_id in range(1, self._sysmon_unique + 1):
            when = self._sysmon_time(record_id)
            if not self._in_window(when, intent.window):
                continue
            count = 2 if record_id == self._duplicate_record_id else 1
            buckets.append(self._bucket(when, SYSMON_CHANNEL, record_id, count=count))
            records += count
        for record_id in range(1, MISSION_SCRIPT_BLOCKS * 2 + 1):
            when = self._script_time(record_id)
            if self._in_window(when, intent.window):
                buckets.append(self._bucket(when, POWERSHELL_CHANNEL, record_id))
                records += 1
        buckets.sort(key=lambda bucket: (
            bucket["first"],
            bucket["key"]["event.channel"],
            bucket["key"]["winlog.record_id"],
        ))
        self.continuity_buckets += len(buckets)
        self.continuity_records += records
        return self._complete(intent, buckets=buckets, total=records)

    def _collision(self, intent) -> SearchOutcome:
        when = self._sysmon_time(self._duplicate_record_id)
        records = []
        if self._in_window(when, intent.window):
            records = [
                self._sysmon_hit(self._duplicate_record_id, duplicate="-a"),
                self._sysmon_hit(self._duplicate_record_id, duplicate="-b"),
            ]
        self.raw_by_purpose[intent.purpose] += len(records)
        return self._complete(intent, records=records)

    def _sweep(self, intent) -> SearchOutcome:
        selected = self._selected_classes(intent)
        records = []
        for record_id in range(1, self._sysmon_unique + 1):
            event_id = self._sysmon_event_id(record_id)
            triple = (SYSMON_CHANNEL.casefold(), SYSMON.casefold(), event_id)
            when = self._sysmon_time(record_id)
            if triple not in selected or not self._in_window(when, intent.window):
                continue
            records.append(self._sysmon_hit(record_id, duplicate="-a"))
            self.raw_event_ids[event_id] += 1
            if record_id == self._duplicate_record_id:
                records.append(self._sysmon_hit(record_id, duplicate="-b"))
                self.raw_event_ids[event_id] += 1
        script_triple = (POWERSHELL_CHANNEL.casefold(), POWERSHELL_PROVIDER.casefold(), 4104)
        if script_triple in selected:
            for record_id in range(1, MISSION_SCRIPT_BLOCKS * 2 + 1):
                when = self._script_time(record_id)
                if self._in_window(when, intent.window):
                    records.append(self._script_hit(record_id))
                    self.raw_event_ids[4104] += 1
        records.sort(key=lambda record: (
            record["_source"]["@timestamp"],
            record["_source"]["winlog"]["record_id"],
            record["_id"],
        ))
        self.raw_by_purpose[intent.purpose] += len(records)
        return self._complete(intent, records=records)

    def execute(self, _client, intent, _contract) -> SearchOutcome:
        if intent.purpose == "windows event class inventory":
            return self._inventory(intent)
        if intent.purpose == "windows continuity metadata":
            return self._continuity(intent)
        if intent.purpose == "windows continuity collision signatures":
            return self._collision(intent)
        if intent.purpose == "sweep":
            return self._sweep(intent)
        raise AssertionError(f"unexpected mission-scale intent: {intent.purpose}")


def _mission_repo() -> Repo:
    engine = make_engine(":memory:")
    migrate(engine)
    repo = Repo(engine)
    repo.create_hunt("mission-hunt", {"targets": [MISSION_TARGET]}, "mission", "mission")
    return repo


@pytest.mark.slow
def test_ten_x_mission_volume_normalizes_with_bounded_streaming_memory():
    """Print machine-readable timing/memory metrics when run with pytest ``-s``."""
    records = mission_windows_volume(TEN_X_RECORDS, shape="elastic_agent", seed=17)
    normalized_count = 0
    batch_count = 0

    tracemalloc.start()
    started = perf_counter()
    try:
        for batch in _batches(records, BATCH_SIZE):
            assert len(batch) <= BATCH_SIZE
            events, skips, errors = normalize_hits(batch)
            assert skips == {} and errors == []
            normalized_count += len(events)
            batch_count += 1
        elapsed_seconds = perf_counter() - started
        _, peak_bytes = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    metrics = {
        "batch_size": BATCH_SIZE,
        "batches": batch_count,
        "elapsed_seconds": round(elapsed_seconds, 3),
        "peak_bytes": peak_bytes,
        "records": normalized_count,
        "records_per_second": round(normalized_count / elapsed_seconds, 1),
    }
    print("WINDOWS_MISSION_SCALE " + json.dumps(metrics, sort_keys=True))

    assert normalized_count == TEN_X_RECORDS
    assert batch_count == (TEN_X_RECORDS + BATCH_SIZE - 1) // BATCH_SIZE
    assert peak_bytes < MAX_PEAK_BYTES
    assert elapsed_seconds < 300


@pytest.mark.slow
def test_mission_scale_selective_sweep_is_bounded_complete_and_persistent(tmp_path, monkeypatch):
    """Exercise the selective Windows path end to end and print its exact work and resource use."""
    from romulus.hunt import sweep as sweep_module

    source = _MissionWindowsSource()
    monkeypatch.setattr(sweep_module, "execute", source.execute)
    contract = contract_from_types(
        MISSION_TARGET,
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
        os_family="windows",
        hosts=(MISSION_HOST.casefold(),),
    )
    site_facts = validate_site_content({
        "schema": "romulus-site-collection@1",
        "collection": [{
            "hosts": ["ws*.example.test"],
            "sysmon": {"installed": True, "event_ids": [1]},
            "powershell_script_block": True,
            "event_channels": [POWERSHELL_CHANNEL],
        }],
    })
    repo = _mission_repo()
    process_rule = _MissionProcessProof()
    script_rule = _MissionScriptProof()
    whole = Window(start=MISSION_START, end=MISSION_END)
    first = Window(start=MISSION_START, end=MISSION_START + timedelta(minutes=5))
    second = Window(start=first.end, end=MISSION_END)

    tracemalloc.start()
    started = perf_counter()
    sweep = None
    try:
        sweep = Sweep(
            repo,
            None,
            "mission-hunt",
            whole,
            {MISSION_TARGET: contract},
            stage_dir=tmp_path,
            site_facts=site_facts,
        )
        sweep.pack = [process_rule, script_rule]
        sweep._prepare_windows_inventory(MISSION_TARGET, contract)
        any_of = sweep._any_of_for(MISSION_TARGET, contract)
        assert MISSION_TARGET in sweep._windows_selective

        sweep.run_partition(MISSION_TARGET, contract, [], first, est=MISSION_SCRIPT_BLOCKS, any_of=any_of)
        assert sweep._windows_scripts is not None
        pending_after_first = int(sweep._windows_scripts.db.execute(
            "SELECT count(*) FROM blocks WHERE emitted = 0"
        ).fetchone()[0])

        sweep.run_partition(
            MISSION_TARGET,
            contract,
            [],
            second,
            est=MISSION_PROCESS_RECORDS + 1 + MISSION_SCRIPT_BLOCKS,
            any_of=any_of,
        )
        pending_after_second = int(sweep._windows_scripts.db.execute(
            "SELECT count(*) FROM blocks WHERE emitted = 0"
        ).fetchone()[0])
        emitted_blocks = int(sweep._windows_scripts.db.execute(
            "SELECT count(*) FROM blocks WHERE emitted = 1"
        ).fetchone()[0])

        elapsed_seconds = perf_counter() - started
        _, peak_bytes = tracemalloc.get_traced_memory()

        assert sweep._windows_record_ids is not None
        continuity_state_rows = sweep._windows_record_ids.state_count
        unassessed = sweep.stats["windows_unassessed"][MISSION_TARGET]
        unassessed_counts = {
            int(item["event_id"]): int(item["records"])
            for item in unassessed
            if "event_id" in item
        }
        candidates = repo.candidates("mission-hunt")
        assert len(candidates) == 1
        evidence = repo.events_by_ids(candidates[0]["event_ids"])
        assert len(evidence) == 1
        persisted_raw = repo.raw_records(evidence[0]["raw_ids"])

        metrics = {
            "collision_followup_records": source.raw_by_purpose[
                "windows continuity collision signatures"
            ],
            "continuity_metadata_buckets": source.continuity_buckets,
            "continuity_metadata_records": source.continuity_records,
            "continuity_state_rows": continuity_state_rows,
            "elapsed_seconds": round(elapsed_seconds, 3),
            "emitted_script_blocks": emitted_blocks,
            "high_volume_inventory_records": sum(
                unassessed_counts.get(event_id, 0) for event_id in MISSION_HIGH_VOLUME_IDS
            ),
            "high_volume_raw_records": sum(
                source.raw_event_ids[event_id] for event_id in MISSION_HIGH_VOLUME_IDS
            ),
            "inventory_buckets": source.inventory_buckets,
            "inventory_source_records": MISSION_SOURCE_RECORDS,
            "pending_blocks_after_first": pending_after_first,
            "peak_bytes": peak_bytes,
            "persisted_duplicate_raw_records": len(persisted_raw),
            "selective_raw_records": source.raw_by_purpose["sweep"],
        }
        print("WINDOWS_SWEEP_MISSION_SCALE " + json.dumps(metrics, sort_keys=True))

        assert unassessed_counts == {
            event_id: MISSION_HIGH_VOLUME_PER_CLASS for event_id in MISSION_HIGH_VOLUME_IDS
        }
        assert source.raw_event_ids == Counter({1: MISSION_PROCESS_RECORDS + 1, 4104: 64})
        assert source.raw_by_purpose["sweep"] == MISSION_PROCESS_RECORDS + 1 + 64
        assert source.raw_by_purpose["windows continuity collision signatures"] == 2
        assert source.continuity_records == MISSION_SOURCE_RECORDS
        assert source.continuity_buckets == MISSION_SOURCE_RECORDS - 1
        assert continuity_state_rows == 2
        assert pending_after_first == MISSION_SCRIPT_BLOCKS
        assert pending_after_second == 0
        assert emitted_blocks == MISSION_SCRIPT_BLOCKS
        assert len(script_rule.completed_ids) == MISSION_SCRIPT_BLOCKS
        assert len(set(script_rule.completed_ids)) == MISSION_SCRIPT_BLOCKS
        assert len(process_rule.matched_event_ids) == 1
        assert len(evidence[0]["raw_ids"]) == 2
        assert len(persisted_raw) == 2
        assert sweep.stats["skips"]["duplicate Windows event copy (computer/channel/record_id)"] == 1
        assert sweep.partial_reasons == []
        assert peak_bytes < MISSION_MAX_PEAK_BYTES
        assert elapsed_seconds < 120
    finally:
        tracemalloc.stop()
        if sweep is not None:
            sweep.close_stage()
