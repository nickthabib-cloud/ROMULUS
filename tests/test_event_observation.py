"""A hunt observed a stored event when it owns the event's row or holds a marker for it: the owner writes no marker,
and deletion, ownership transfer and hunt-scoped citations read the two together."""
from datetime import UTC, datetime

from sqlalchemy import select

from romulus.evidence.typed import RawRef, TypedEvent
from romulus.report.manifest import _citations
from romulus.store import schema as t
from romulus.store.db import make_engine, migrate
from romulus.store.repo import Repo, raw_id


def _repo(*hunts: str) -> Repo:
    repo = Repo(make_engine(":memory:"))
    migrate(repo.engine)
    for hunt_id in hunts:
        repo.create_hunt(hunt_id, {}, hunt_id, "test")
    return repo


def _markers(repo: Repo) -> list[tuple[str, str]]:
    with repo.engine.connect() as c:
        return sorted(tuple(row) for row in c.execute(select(t.event_observation.c.hunt_id,
                                                             t.event_observation.c.event_id)))


def _event(event_id: str, ref: RawRef, host: str | None = None) -> TypedEvent:
    return TypedEvent(id=event_id, family="process_exec", ts=datetime(2026, 1, 1, tzinfo=UTC), host=host,
                      fields={}, raw=[ref], normalizer="windows-ecs@1")


REF = RawRef(target="windows-a", native_id="copy-1", digest="digest-1")
OTHER = RawRef(target="windows-b", native_id="copy-2", digest="digest-2")


def test_the_owner_writes_no_marker_and_another_hunt_writes_one_per_event():
    repo = _repo("h1", "h2")
    event = _event("e1", REF)
    repo.save_evidence("h1", [event, event], {REF.key: {"copy": 1}}, None)
    repo.save_evidence("h1", [event], {REF.key: {"copy": 1}}, None)
    assert _markers(repo) == []
    repo.save_evidence("h2", [event], {REF.key: {"copy": 1}}, None)
    repo.save_evidence("h2", [event], {REF.key: {"copy": 1}}, None)
    assert _markers(repo) == [("h2", "e1")]
    # a duplicate merged into an event another hunt owns is an observation too; one the hunt owns is not
    repo.create_hunt("h3", {}, "h3", "test")
    repo.merge_evidence_raw("h3", [event], {REF.key: {"copy": 1}})
    repo.merge_evidence_raw("h1", [event], {REF.key: {"copy": 1}})
    assert _markers(repo) == [("h2", "e1"), ("h3", "e1")]


def test_deleting_the_owner_keeps_an_event_only_observed_by_another_hunt_and_transfers_it():
    """An entity-free event with an identical observation leaves no overlay and no entity row: the marker alone keeps it
    through the owner's deletion, and the new owner's marker goes (owning it says it)."""
    repo = _repo("h1", "h2")
    event = _event("e1", REF)
    repo.save_evidence("h1", [event], {REF.key: {"copy": 1}}, None)
    repo.save_evidence("h2", [event], {REF.key: {"copy": 1}}, None)

    counts = repo.delete_hunt("h1", actor="test")

    assert counts["events_kept_for_other_hunts"] == 1
    [stored] = repo.events_by_ids(["e1"])
    assert stored["hunt_id"] == "h2"
    assert _markers(repo) == []
    assert [c["native_id"] for c in _citations(repo, {"hunt_id": "h2", "event_ids": ["e1"]})] == ["copy-1"]
    # the transferred owner's later differing copy extends the history it observed, never replaces it
    repo.save_evidence("h2", [_event("e1", OTHER)], {OTHER.key: {"copy": 2}}, None)
    assert [c["native_id"] for c in _citations(repo, {"hunt_id": "h2", "event_ids": ["e1"]})] == [
        "copy-1", "copy-2"]


def test_a_transfer_chain_keeps_every_observer_and_drops_each_new_owners_marker():
    repo = _repo("h1", "h2", "h3")
    event = _event("e1", REF)
    for hunt_id in ("h1", "h2", "h3"):
        repo.save_evidence(hunt_id, [event], {REF.key: {"copy": 1}}, None)
    assert _markers(repo) == [("h2", "e1"), ("h3", "e1")]

    repo.delete_hunt("h1", actor="test")
    owner = repo.events_by_ids(["e1"])[0]["hunt_id"]
    other = ({"h2", "h3"} - {owner}).pop()
    assert _markers(repo) == [(other, "e1")]

    repo.delete_hunt(owner, actor="test")
    assert repo.events_by_ids(["e1"])[0]["hunt_id"] == other
    assert _markers(repo) == []

    repo.delete_hunt(other, actor="test")
    assert repo.events_by_ids(["e1"]) == []
    assert repo.raw_records([raw_id(REF.target, REF.native_id)]) == []


def test_deleting_an_observer_removes_its_marker_and_leaves_the_owner_untouched():
    repo = _repo("h1", "h2")
    event = _event("e1", REF, host="ws01")
    repo.save_evidence("h1", [event], {REF.key: {"copy": 1}}, None)
    repo.save_evidence("h2", [_event("e1", OTHER, host="ws01")], {OTHER.key: {"copy": 2}}, None)

    repo.delete_hunt("h2", actor="test")

    assert _markers(repo) == []
    [stored] = repo.events_by_ids(["e1"])
    assert stored["hunt_id"] == "h1" and [r["native_id"] for r in stored["event"]["raw"]] == ["copy-1"]
    assert [c["native_id"] for c in _citations(repo, {"hunt_id": "h1", "event_ids": ["e1"]})] == ["copy-1"]


def test_an_owners_own_repeated_observation_needs_no_marker_to_extend_its_history():
    """The owner's prior observation is its row: a later differing copy it retrieves starts from the stable set."""
    repo = _repo("h1")
    repo.save_evidence("h1", [_event("e1", REF)], {REF.key: {"copy": 1}}, None)
    repo.save_evidence("h1", [_event("e1", OTHER)], {OTHER.key: {"copy": 2}}, None)
    assert _markers(repo) == []
    assert [c["native_id"] for c in _citations(repo, {"hunt_id": "h1", "event_ids": ["e1"]})] == [
        "copy-1", "copy-2"]
