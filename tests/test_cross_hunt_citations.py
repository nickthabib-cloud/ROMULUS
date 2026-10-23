from datetime import UTC, datetime

from romulus.evidence.typed import RawRef, TypedEvent
from romulus.report.manifest import _citations
from romulus.store.db import make_engine, migrate
from romulus.store.repo import Repo


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
    repo.save_evidence("h2", [second], {
        first_ref.key: {"copy": 1}, second_ref.key: {"copy": 2},
    }, None)

    stored = repo.events_by_ids([first.id])[0]
    h1 = _citations(repo, {"hunt_id": "h1", "event_ids": [first.id]})
    h2 = _citations(repo, {"hunt_id": "h2", "event_ids": [first.id]})

    assert [ref["native_id"] for ref in stored["event"]["raw"]] == ["copy-1"]
    assert [citation["native_id"] for citation in h1] == ["copy-1"]
    assert [citation["native_id"] for citation in h2] == ["copy-1", "copy-2"]
