"""PowerShell script-block reassembly across pivot retrieval boundaries."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import ClassVar

from romulus.agent.models import EntityRef
from romulus.agent.tools import EntityTimelineArgs, EntityTimelineRequest
from romulus.evidence.typed import Outcome, RawRef, TypedEvent, fv
from romulus.evidence.windows import SCRIPT_BLOCK_MAX_PARTS
from romulus.evidence.windows_reassembly import ScriptBlockAssembler
from romulus.hunt import pivot as pivot_module
from romulus.hunt.pivot import PivotExecutor
from romulus.sources.models import Completeness, SearchIntent, SearchOutcome, Window
from romulus.sources.profile import contract_from_types
from romulus.store.db import make_engine, migrate
from romulus.store.repo import Repo, raw_id

START = datetime(2026, 10, 26, 17, 0, tzinfo=UTC)
END = START + timedelta(minutes=10)
CHANNEL = "Microsoft-Windows-PowerShell/Operational"
PROVIDER = "Microsoft-Windows-PowerShell"
BLOCK_ID = "11111111-2222-3333-4444-555555555555"


class FakeClient:
    version = "test"

    class settings:
        es_flavor = "elasticsearch"


def _repo() -> Repo:
    engine = make_engine(":memory:")
    migrate(engine)
    repo = Repo(engine)
    repo.create_hunt("h1", {"targets": []}, "digest", "test")
    return repo


def _contract(target: str):
    return contract_from_types(target, {
        "@timestamp": "date",
        "winlog.channel": "keyword",
        "winlog.provider_name": "keyword",
        "winlog.event_id": "keyword",
        "winlog.event_data": "flattened",
    }, role="host", os_family="windows")


def _part(target: str, number: int, total: int, text: str) -> dict:
    native_id = f"part-{number}"
    when = START + timedelta(seconds=number)
    return {
        "_index": target,
        "_id": native_id,
        "_source": {
            "@timestamp": when.isoformat(),
            "agent": {"type": "winlogbeat", "version": "8.19.0"},
            "winlog": {
                "channel": CHANNEL,
                "provider_name": PROVIDER,
                "event_id": 4104,
                "computer_name": "WS01.example.test",
                "record_id": number,
                "time_created": when.isoformat(),
                "event_data": {
                    "ScriptBlockId": BLOCK_ID,
                    "ScriptBlockText": text,
                    "MessageNumber": str(number),
                    "MessageTotal": str(total),
                },
            },
        },
    }


def _intent(target: str, start: datetime, end: datetime) -> SearchIntent:
    return SearchIntent(
        kind="raw",
        target=target,
        window=Window(start=start, end=end),
        max_records=10,
        purpose=f"test:script-block:{target}",
    )


def _complete_outcome(intent: SearchIntent, record: dict) -> SearchOutcome:
    return SearchOutcome(
        target=intent.target,
        fingerprint=f"fp-{intent.target}",
        started_at=START,
        ended_at=END,
        completeness=Completeness.complete,
        total=1,
        total_relation="eq",
        returned=1,
        records=[record],
    )


class TrackingAssembler(ScriptBlockAssembler):
    instances: ClassVar[list[TrackingAssembler]] = []

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.blocks_before_close: int | None = None
        self.instances.append(self)

    def close(self):
        if self.db is not None:
            self.blocks_before_close = int(self.db.execute("SELECT count(*) FROM blocks").fetchone()[0])
        super().close()


def _incomplete_metadata_event(target: str) -> TypedEvent:
    return TypedEvent(
        id="incomplete-metadata",
        family="script_block",
        ts=START,
        host="ws01",
        outcome=Outcome.success,
        fields={
            "event.code": fv(4104, "part-1:event_id"),
            "host.os.family": fv("windows", "part-1:computer"),
            "script.block_id": fv(BLOCK_ID, "part-1:ScriptBlockId"),
            "script.message_number": fv(1, "part-1:MessageNumber"),
            "script.text": fv("Write-Output 'partial'", "part-1:ScriptBlockText"),
            "script.complete": fv(False, "part-1:incomplete-metadata"),
        },
        raw=[RawRef(target=target, native_id="part-1", digest="part-1")],
        normalizer="windows-ecs@3",
    )


def test_parts_across_fetch_intents_form_one_event_with_every_raw_reference(monkeypatch):
    """One assembler spans every intent/leaf, including distinct source targets."""
    repo = _repo()
    targets = ("windows-a", "windows-b")
    records = {
        "windows-a": _part("windows-a", 2, 2, "Write-Output 'two'"),
        "windows-b": _part("windows-b", 1, 2, "$value = 'one'; "),
    }

    def fake_execute(_client, intent, _contract, *, pit=None):
        assert pit is None
        return _complete_outcome(intent, records[intent.target])

    monkeypatch.setattr(pivot_module, "execute", fake_execute)
    TrackingAssembler.instances.clear()
    monkeypatch.setattr(pivot_module, "ScriptBlockAssembler", TrackingAssembler)
    executor = PivotExecutor(
        repo,
        FakeClient(),
        "h1",
        {target: _contract(target) for target in targets},
    )
    intents = [
        _intent("windows-a", START, START + timedelta(minutes=5)),
        _intent("windows-b", START + timedelta(minutes=5), END),
    ]

    batch = executor.fetch_intents(
        "finding-1",
        "script-block",
        intents,
        lambda event: event.family == "script_block",
        persist=False,
    )

    assert batch.status == "complete"
    assert len(batch.events) == 3
    [event] = [item for item in batch.events if not item.has("script.part_number")]
    assert event.get("script.text") == "$value = 'one'; Write-Output 'two'"
    assert event.get("script.complete") is True
    assert event.get("script.part_count") == 2
    assert event.get("script.missing_parts") == []
    assert [(ref.target, ref.native_id) for ref in event.raw] == [
        ("windows-b", "part-1"),
        ("windows-a", "part-2"),
    ]
    assert set(batch.raw_sources) == {"windows-a/part-2", "windows-b/part-1"}
    assert all(cell.status == "complete" for cell in batch.coverage)

    executor.save_batch_selection(batch, batch.events)
    [stored] = repo.events_by_ids([event.id])
    assert set(stored["raw_ids"]) == {
        raw_id("windows-a", "part-2"),
        raw_id("windows-b", "part-1"),
    }
    assert {row["id"] for row in repo.raw_records(stored["raw_ids"])} == set(stored["raw_ids"])
    assert TrackingAssembler.instances[0]._emitted_sources == {}


def test_single_fetched_part_is_emitted_as_incomplete_and_marks_coverage_partial(monkeypatch):
    repo = _repo()
    target = "windows-a"
    record = _part(target, 1, 2, "$value = 'one'; ")

    monkeypatch.setattr(
        pivot_module,
        "execute",
        lambda _client, intent, _contract, *, pit=None: _complete_outcome(intent, record),
    )
    executor = PivotExecutor(repo, FakeClient(), "h1", {target: _contract(target)})

    batch = executor.fetch_intents(
        "finding-1",
        "script-block",
        [_intent(target, START, END)],
        lambda event: event.family == "script_block",
        persist=False,
    )

    assert batch.status == "partial"
    assert batch.reasons == ["PowerShell script-block reassembly incomplete for 1 block(s)"]
    assert len(batch.events) == 2
    [event] = [item for item in batch.events if not item.has("script.part_number")]
    assert event.get("script.text") == "$value = 'one'; "
    assert event.get("script.complete") is False
    assert event.get("script.part_count") == 1
    assert event.get("script.missing_parts") == [2]
    assert [(ref.target, ref.native_id) for ref in event.raw] == [(target, "part-1")]
    assert batch.raw_sources == {f"{target}/part-1": record["_source"]}
    assert batch.coverage
    assert all(cell.status == "partial" for cell in batch.coverage)
    assert all(
        batch.reasons[0] in cell.reasons and cell.unresolved_ranges
        for cell in batch.coverage
    )


def test_fetch_marks_normalizer_incomplete_part_metadata_partial(monkeypatch):
    repo = _repo()
    target = "windows-a"
    record = _part(target, 1, 1, "Write-Output 'partial'")
    event = _incomplete_metadata_event(target)
    monkeypatch.setattr(
        pivot_module,
        "execute",
        lambda _client, intent, _contract, *, pit=None: _complete_outcome(intent, record),
    )
    monkeypatch.setattr(
        pivot_module,
        "normalize_hits",
        lambda _records, **_kwargs: ([event], {}, []),
    )
    executor = PivotExecutor(repo, FakeClient(), "h1", {target: _contract(target)})

    batch = executor.fetch_intents(
        "finding-1",
        "script-block",
        [_intent(target, START, END)],
        lambda candidate: candidate.family == "script_block",
        persist=False,
    )

    assert batch.status == "partial"
    assert batch.reasons == ["PowerShell script-block part metadata incomplete or invalid for 1 event(s)"]
    assert batch.events[0].get("script.complete") is False
    assert all(cell.status == "partial" and cell.unresolved_ranges for cell in batch.coverage)


def test_fetch_cites_huge_part_total_without_entering_reassembly_state(monkeypatch):
    repo = _repo()
    target = "windows-a"
    record = _part(target, 1, 2**31, "Write-Output 'hostile metadata'")
    monkeypatch.setattr(
        pivot_module,
        "execute",
        lambda _client, intent, _contract, *, pit=None: _complete_outcome(intent, record),
    )
    TrackingAssembler.instances.clear()
    monkeypatch.setattr(pivot_module, "ScriptBlockAssembler", TrackingAssembler)
    executor = PivotExecutor(repo, FakeClient(), "h1", {target: _contract(target)})

    batch = executor.fetch_intents(
        "finding-1",
        "script-block",
        [_intent(target, START, END)],
        lambda event: event.family == "script_block",
        persist=False,
    )

    assert batch.status == "partial"
    assert batch.reasons == ["PowerShell script-block part metadata incomplete or invalid for 1 event(s)"]
    assert len(batch.events) == 1 and batch.events[0].get("script.complete") is False
    assert any(
        f"supported maximum {SCRIPT_BLOCK_MAX_PARTS}" in caveat
        for caveat in batch.events[0].caveats
    )
    assert batch.raw_sources == {f"{target}/part-1": record["_source"]}
    assert TrackingAssembler.instances[0].blocks_before_close == 0


def test_run_cites_huge_part_total_as_partial_without_reassembly_state(monkeypatch):
    repo = _repo()
    target = "windows-a"
    record = _part(target, 1, 2**31, "Write-Output 'hostile metadata'")
    monkeypatch.setattr(
        pivot_module,
        "execute",
        lambda _client, intent, _contract, *, pit=None: _complete_outcome(intent, record),
    )
    TrackingAssembler.instances.clear()
    monkeypatch.setattr(pivot_module, "ScriptBlockAssembler", TrackingAssembler)
    executor = PivotExecutor(repo, FakeClient(), "h1", {target: _contract(target)})
    intent = _intent(target, START, END)
    monkeypatch.setattr(executor, "plan", lambda _request: ([intent], []))
    request = EntityTimelineRequest(tool="entity_timeline", arguments=EntityTimelineArgs(
        entity=EntityRef(kind="host", value="ws01", role="host"),
        start=START,
        end=END,
    ))

    result = executor.run("case-1", request)

    assert result.status == "partial"
    assert result.reasons == ["PowerShell script-block part metadata incomplete or invalid for 1 event(s)"]
    assert result.matched_event_count == 1
    [stored] = repo.events_by_ids(result.event_ids)
    assert stored["event"]["fields"]["script.complete"]["value"] is False
    assert {raw["native_id"] for raw in repo.raw_records(stored["raw_ids"])} == {"part-1"}
    assert TrackingAssembler.instances[0].blocks_before_close == 0


def test_run_drains_completed_reassembly_sources_immediately(monkeypatch):
    repo = _repo()
    targets = ("windows-a", "windows-b")
    records = {
        "windows-a": _part("windows-a", 2, 2, "Write-Output 'two'"),
        "windows-b": _part("windows-b", 1, 2, "$value = 'one'; "),
    }

    monkeypatch.setattr(
        pivot_module,
        "execute",
        lambda _client, intent, _contract, *, pit=None: _complete_outcome(intent, records[intent.target]),
    )
    TrackingAssembler.instances.clear()
    monkeypatch.setattr(pivot_module, "ScriptBlockAssembler", TrackingAssembler)
    executor = PivotExecutor(
        repo,
        FakeClient(),
        "h1",
        {target: _contract(target) for target in targets},
    )
    intents = [
        _intent("windows-a", START, START + timedelta(minutes=5)),
        _intent("windows-b", START + timedelta(minutes=5), END),
    ]
    monkeypatch.setattr(executor, "plan", lambda _request: (intents, []))
    request = EntityTimelineRequest(tool="entity_timeline", arguments=EntityTimelineArgs(
        entity=EntityRef(kind="host", value="ws01", role="host"),
        start=START,
        end=END,
    ))

    result = executor.run("case-1", request)

    assert result.status == "complete"
    assert result.matched_event_count == 3
    assert TrackingAssembler.instances[0]._emitted_sources == {}
