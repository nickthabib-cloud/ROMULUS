"""Windows evidence admission and durable cross-platform host-resolution coverage."""
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

from sqlalchemy import select

from romulus.evidence.typed import RawRef, TypedEvent, fv
from romulus.hunt.expansion import ExpansionEngine
from romulus.sources.models import Window
from romulus.store import schema as t
from romulus.store.db import make_engine, migrate
from romulus.store.repo import Repo, raw_id

T0 = datetime(2026, 10, 26, 12, 0, tzinfo=UTC)
WINDOW = Window(start=T0 - timedelta(hours=1), end=T0 + timedelta(hours=1))
OUTSIDE_ADDRESS = "203.0.113.9"


def _repo(*hunts: str) -> Repo:
    repo = Repo(make_engine(":memory:"))
    migrate(repo.engine)
    for hunt_id in hunts:
        repo.create_hunt(hunt_id, {}, hunt_id, "test")
    return repo


def _event(event_id: str, ref: RawRef, account: str) -> TypedEvent:
    return TypedEvent(
        id=event_id,
        family="process_exec",
        ts=T0,
        host="ws01",
        fields={"user.name": fv(account, f"{ref.key}:user")},
        raw=[ref],
        normalizer="windows-ecs@2",
    )


def test_save_evidence_coalesces_new_duplicate_ids_before_raw_and_entity_writes():
    repo = _repo("h1")
    first_ref = RawRef(target="windows-a", native_id="copy-1", digest="first")
    later_ref = RawRef(target="windows-b", native_id="copy-2", digest="later")
    first = _event("same-event", first_ref, "alice")
    later = _event("same-event", later_ref, "mallory")

    repo.save_evidence(
        "h1",
        (event for event in (first, later)),
        {first_ref.key: {"copy": 1}, later_ref.key: {"copy": 2}},
        None,
    )

    [stored] = repo.events_by_ids([first.id])
    with repo.engine.connect() as connection:
        linked_accounts = connection.execute(
            select(t.entity.c.value)
            .join(t.event_entity, t.event_entity.c.entity_id == t.entity.c.id)
            .where(t.event_entity.c.event_id == first.id, t.entity.c.kind == "account")
        ).scalars().all()

    assert stored["event"] == first.model_dump(mode="json")
    assert stored["raw_ids"] == [raw_id(first_ref.target, first_ref.native_id)]
    assert [row["native_id"] for row in repo.raw_records([
        raw_id(first_ref.target, first_ref.native_id),
        raw_id(later_ref.target, later_ref.native_id),
    ])] == ["copy-1"]
    assert linked_accounts == ["alice"]


def test_save_evidence_still_merges_duplicate_refs_for_an_existing_cross_hunt_event():
    repo = _repo("h1", "h2")
    owner_ref = RawRef(target="windows-a", native_id="copy-1", digest="owner")
    first_ref = RawRef(target="windows-b", native_id="copy-2", digest="first")
    second_ref = RawRef(target="windows-c", native_id="copy-3", digest="second")
    owner = _event("same-event", owner_ref, "owner")
    repo.save_evidence("h1", [owner], {owner_ref.key: {"copy": 1}}, None)

    repo.save_evidence(
        "h2",
        (event for event in (
            _event(owner.id, first_ref, "alice"),
            _event(owner.id, second_ref, "bob"),
        )),
        {first_ref.key: {"copy": 2}, second_ref.key: {"copy": 3}},
        None,
    )

    [scoped] = repo.citation_events("h2", [owner.id])
    assert [raw["native_id"] for raw in scoped["event"]["raw"]] == ["copy-2", "copy-3"]
    assert scoped["raw_ids"] == [
        raw_id(first_ref.target, first_ref.native_id),
        raw_id(second_ref.target, second_ref.native_id),
    ]


def _resolution_task(repo: Repo, task_id: str, *, marker: str | None, host: str) -> None:
    intent = {"resolve_host_ip": OUTSIDE_ADDRESS, "targets": ["host-x"]}
    if marker is not None:
        intent["host_identity"] = marker
    repo.upsert_task(task_id, "h1", "expansion_link", "host-resolution", intent, task_id)
    repo.record_task_source_query(task_id)
    repo.update_task(task_id, "evaluated", outcome={"host": host, "reason": None})


def _engine(repo: Repo, os_family: str, *, datasets: set[str] | None = None) -> ExpansionEngine:
    engine = object.__new__(ExpansionEngine)
    engine.repo = repo
    engine.hunt_id = "h1"
    engine.window = WINDOW
    engine.fetcher = SimpleNamespace(executor=SimpleNamespace(
        contracts={"host-x": SimpleNamespace(os_family=os_family)},
        dataset_inventory={"host-x": datasets} if datasets is not None else {},
    ))
    engine._fallback = None
    engine._fallback_queries = 0
    return engine


def test_windows_fallback_map_reuses_only_host_resolution_tasks_with_typed_v2_input():
    repo = _repo("h1")
    _resolution_task(repo, "a-unmarked", marker=None, host="unmarked-host")
    _resolution_task(repo, "b-current", marker="typed-v2", host="ws01")

    engine = _engine(repo, "windows")

    assert engine._fallback_map() == {OUTSIDE_ADDRESS: ("ws01", None)}
    assert engine._fallback_spent() == 1


def test_linux_fallback_map_reuses_unmarked_host_resolution_tasks():
    repo = _repo("h1")
    _resolution_task(repo, "unmarked-linux", marker=None, host="linux01.example.test")

    engine = _engine(repo, "linux")

    assert engine._fallback_map() == {OUTSIDE_ADDRESS: ("linux01.example.test", None)}
    assert engine._fallback_spent() == 1


def test_mixed_target_fallback_map_requires_the_windows_typed_identity_marker():
    repo = _repo("h1")
    _resolution_task(repo, "a-unmarked", marker=None, host="unmarked-host")
    _resolution_task(repo, "b-current", marker="typed-v2", host="ws01")

    engine = _engine(repo, "linux", datasets={"linux.audit", "windows.sysmon_operational"})

    assert engine._fallback_map() == {OUTSIDE_ADDRESS: ("ws01", None)}
