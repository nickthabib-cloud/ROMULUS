from datetime import UTC, datetime

from sqlalchemy import func, select

from romulus.evidence.typed import RawRef, TypedEvent
from romulus.report.manifest import _citations
from romulus.store import schema as t
from romulus.store.db import make_engine, migrate
from romulus.store.repo import Repo, raw_id


def _citation_count(repo: Repo) -> int:
    with repo.engine.connect() as connection:
        return connection.execute(select(func.count()).select_from(t.event_citation)).scalar_one()


def test_cross_hunt_raw_merge_is_scoped_to_the_current_hunts_citations():
    repo = Repo(make_engine(":memory:"))
    migrate(repo.engine)
    repo.create_hunt("h1", {}, "d1", "test")
    repo.create_hunt("h2", {}, "d2", "test")
    first_ref = RawRef(target="windows-a", native_id="copy-1", digest="digest-1")
    second_ref = RawRef(target="windows-b", native_id="copy-2", digest="digest-2")
    first = TypedEvent(
        id="stable-event", family="process_exec", ts=datetime(2026, 1, 1, tzinfo=UTC), host="ws01",
        fields={}, raw=[first_ref], normalizer="windows-ecs@1",
    )
    second = first.model_copy(update={"raw": [first_ref, second_ref]})
    repo.save_evidence("h1", [first], {first_ref.key: {"copy": 1}}, None)
    assert _citation_count(repo) == 0
    repo.save_evidence("h2", [second], {
        first_ref.key: {"copy": 1}, second_ref.key: {"copy": 2},
    }, None)

    stored = repo.events_by_ids([first.id])[0]
    h1 = _citations(repo, {"hunt_id": "h1", "event_ids": [first.id]})
    h2 = _citations(repo, {"hunt_id": "h2", "event_ids": [first.id]})

    assert [ref["native_id"] for ref in stored["event"]["raw"]] == ["copy-1"]
    assert [citation["native_id"] for citation in h1] == ["copy-1"]
    assert [citation["native_id"] for citation in h2] == ["copy-1", "copy-2"]
    assert _citation_count(repo) == 1


def test_another_hunt_snapshots_its_citation_when_no_raw_copy_is_added():
    repo = Repo(make_engine(":memory:"))
    migrate(repo.engine)
    repo.create_hunt("h1", {}, "d1", "test")
    repo.create_hunt("h2", {}, "d2", "test")
    ref = RawRef(target="shared", native_id="copy-1", digest="digest-1")
    event = TypedEvent(
        id="stable-event", family="process_exec", ts=datetime(2026, 1, 1, tzinfo=UTC), host="ws01",
        fields={}, raw=[ref], normalizer="windows-ecs@1",
    )

    repo.save_evidence("h1", [event], {ref.key: {"copy": 1}}, None)
    repo.save_evidence("h2", [event], {ref.key: {"copy": 1}}, None)

    assert _citation_count(repo) == 1
    assert [item["native_id"] for item in _citations(
        repo, {"hunt_id": "h2", "event_ids": [event.id]},
    )] == ["copy-1"]


def test_foreign_hunt_snapshots_only_the_subset_of_owner_refs_it_retrieved():
    repo = Repo(make_engine(":memory:"))
    migrate(repo.engine)
    repo.create_hunt("h1", {}, "d1", "test")
    repo.create_hunt("h2", {}, "d2", "test")
    first_ref = RawRef(target="windows-a", native_id="copy-1", digest="digest-1")
    second_ref = RawRef(target="windows-b", native_id="copy-2", digest="digest-2")
    owner = TypedEvent(
        id="stable-event", family="process_exec", ts=datetime(2026, 1, 1, tzinfo=UTC), host="ws01",
        fields={}, raw=[first_ref, second_ref], normalizer="windows-ecs@1",
    )
    subset = owner.model_copy(update={"raw": [first_ref]})

    repo.save_evidence("h1", [owner], {
        first_ref.key: {"copy": 1}, second_ref.key: {"copy": 2},
    }, None)
    repo.save_evidence("h2", [subset], {first_ref.key: {"copy": 1}}, None)

    assert [citation["native_id"] for citation in _citations(
        repo, {"hunt_id": "h2", "event_ids": [owner.id]},
    )] == ["copy-1"]


def test_owner_later_raw_merge_does_not_rewrite_foreign_hunt_citations():
    repo = Repo(make_engine(":memory:"))
    migrate(repo.engine)
    repo.create_hunt("h1", {}, "d1", "test")
    repo.create_hunt("h2", {}, "d2", "test")
    first_ref = RawRef(target="windows-a", native_id="copy-1", digest="digest-1")
    second_ref = RawRef(target="windows-b", native_id="copy-2", digest="digest-2")
    first = TypedEvent(
        id="stable-event", family="process_exec", ts=datetime(2026, 1, 1, tzinfo=UTC), host="ws01",
        fields={}, raw=[first_ref], normalizer="windows-ecs@1",
    )

    repo.save_evidence("h1", [first], {first_ref.key: {"copy": 1}}, None)
    repo.save_evidence("h2", [first], {first_ref.key: {"copy": 1}}, None)
    repo.save_evidence(
        "h1", [first.model_copy(update={"raw": [first_ref, second_ref]})],
        {first_ref.key: {"copy": 1}, second_ref.key: {"copy": 2}}, None,
    )

    assert [citation["native_id"] for citation in _citations(
        repo, {"hunt_id": "h2", "event_ids": [first.id]},
    )] == ["copy-1"]
    assert [ref["native_id"] for ref in repo.events_by_ids([first.id])[0]["event"]["raw"]] == [
        "copy-1", "copy-2",
    ]


def test_foreign_hunt_merges_its_own_sequential_raw_observations():
    repo = Repo(make_engine(":memory:"))
    migrate(repo.engine)
    repo.create_hunt("h1", {}, "d1", "test")
    repo.create_hunt("h2", {}, "d2", "test")
    first_ref = RawRef(target="windows-a", native_id="copy-1", digest="digest-1")
    second_ref = RawRef(target="windows-b", native_id="copy-2", digest="digest-2")
    first = TypedEvent(
        id="stable-event", family="process_exec", ts=datetime(2026, 1, 1, tzinfo=UTC), host="ws01",
        fields={}, raw=[first_ref], normalizer="windows-ecs@1",
    )

    repo.save_evidence("h1", [first], {first_ref.key: {"copy": 1}}, None)
    repo.save_evidence("h2", [first], {first_ref.key: {"copy": 1}}, None)
    repo.save_evidence(
        "h2", [first.model_copy(update={"raw": [second_ref]})],
        {second_ref.key: {"copy": 2}}, None,
    )

    assert [citation["native_id"] for citation in _citations(
        repo, {"hunt_id": "h2", "event_ids": [first.id]},
    )] == ["copy-1", "copy-2"]


def test_foreign_hunt_citation_contains_only_the_raw_copy_that_hunt_retrieved():
    repo = Repo(make_engine(":memory:"))
    migrate(repo.engine)
    repo.create_hunt("h1", {}, "d1", "test")
    repo.create_hunt("h2", {}, "d2", "test")
    first_ref = RawRef(target="windows-a", native_id="copy-1", digest="digest-1")
    second_ref = RawRef(target="windows-b", native_id="copy-2", digest="digest-2")
    first = TypedEvent(
        id="stable-event", family="process_exec", ts=datetime(2026, 1, 1, tzinfo=UTC), host="ws01",
        fields={}, raw=[first_ref], normalizer="windows-ecs@1",
    )
    duplicate = first.model_copy(update={"raw": [second_ref]})

    repo.save_evidence("h1", [first], {first_ref.key: {"copy": 1}}, None)
    repo.save_evidence("h2", [duplicate], {second_ref.key: {"copy": 2}}, None)

    assert [citation["native_id"] for citation in _citations(
        repo, {"hunt_id": "h2", "event_ids": [first.id]},
    )] == ["copy-2"]
    assert [ref["native_id"] for ref in repo.events_by_ids([first.id])[0]["event"]["raw"]] == [
        "copy-1",
    ]


def test_deleting_a_hunt_removes_raw_records_referenced_only_by_its_citation_overlay():
    repo = Repo(make_engine(":memory:"))
    migrate(repo.engine)
    repo.create_hunt("h1", {}, "d1", "test")
    repo.create_hunt("h2", {}, "d2", "test")
    owner_ref = RawRef(target="windows-a", native_id="copy-1", digest="digest-1")
    overlay_ref = RawRef(target="windows-b", native_id="copy-2", digest="digest-2")
    owner = TypedEvent(
        id="stable-event", family="process_exec", ts=datetime(2026, 1, 1, tzinfo=UTC), host="ws01",
        fields={}, raw=[owner_ref], normalizer="windows-ecs@1",
    )

    repo.save_evidence("h1", [owner], {owner_ref.key: {"copy": 1}}, None)
    repo.save_evidence(
        "h2", [owner.model_copy(update={"raw": [overlay_ref]})],
        {overlay_ref.key: {"copy": 2}}, None,
    )

    repo.delete_hunt("h2", actor="test")

    assert repo.raw_records([raw_id(overlay_ref.target, overlay_ref.native_id)]) == []
    assert repo.raw_records([raw_id(owner_ref.target, owner_ref.native_id)])
    assert _citation_count(repo) == 0


def test_deleting_one_hunt_keeps_raw_records_used_by_another_hunts_overlay():
    repo = Repo(make_engine(":memory:"))
    migrate(repo.engine)
    for hunt_id in ("h1", "h2", "h3"):
        repo.create_hunt(hunt_id, {}, hunt_id, "test")
    owner_ref = RawRef(target="windows-a", native_id="copy-1", digest="digest-1")
    shared_ref = RawRef(target="windows-b", native_id="copy-2", digest="digest-2")
    owner = TypedEvent(
        id="stable-event", family="process_exec", ts=datetime(2026, 1, 1, tzinfo=UTC), host="ws01",
        fields={}, raw=[owner_ref], normalizer="windows-ecs@1",
    )
    duplicate = owner.model_copy(update={"raw": [shared_ref]})
    repo.save_evidence("h1", [owner], {owner_ref.key: {"copy": 1}}, None)
    repo.save_evidence("h2", [duplicate], {shared_ref.key: {"copy": 2}}, None)
    repo.save_evidence("h3", [duplicate], {shared_ref.key: {"copy": 2}}, None)

    repo.delete_hunt("h2", actor="test")

    shared_id = raw_id(shared_ref.target, shared_ref.native_id)
    assert repo.raw_records([shared_id])
    assert [citation["native_id"] for citation in _citations(
        repo, {"hunt_id": "h3", "event_ids": [owner.id]},
    )] == ["copy-2"]

    repo.delete_hunt("h3", actor="test")
    assert repo.raw_records([shared_id]) == []


def test_transferred_owner_merges_later_refs_into_its_snapshotted_citations():
    repo = Repo(make_engine(":memory:"))
    migrate(repo.engine)
    repo.create_hunt("h1", {}, "d1", "test")
    repo.create_hunt("h2", {}, "d2", "test")
    owner_ref = RawRef(target="windows-a", native_id="copy-1", digest="digest-1")
    transferred_ref = RawRef(target="windows-b", native_id="copy-2", digest="digest-2")
    later_ref = RawRef(target="windows-c", native_id="copy-3", digest="digest-3")
    owner = TypedEvent(
        id="stable-event", family="process_exec", ts=datetime(2026, 1, 1, tzinfo=UTC), host="ws01",
        fields={}, raw=[owner_ref], normalizer="windows-ecs@1",
    )

    repo.save_evidence("h1", [owner], {owner_ref.key: {"copy": 1}}, None)
    repo.save_evidence(
        "h2", [owner.model_copy(update={"raw": [transferred_ref]})],
        {transferred_ref.key: {"copy": 2}}, None,
    )
    repo.delete_hunt("h1", actor="test")
    repo.save_evidence(
        "h2", [owner.model_copy(update={"raw": [later_ref]})],
        {later_ref.key: {"copy": 3}}, None,
    )

    assert [citation["native_id"] for citation in _citations(
        repo, {"hunt_id": "h2", "event_ids": [owner.id]},
    )] == ["copy-2", "copy-3"]
    assert _citation_count(repo) == 0
    assert repo.raw_records([raw_id(owner_ref.target, owner_ref.native_id)]) == []
