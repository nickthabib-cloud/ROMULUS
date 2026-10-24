from datetime import UTC, datetime
from threading import Thread

from sqlalchemy import event as sqlalchemy_event
from sqlalchemy import func, select

from romulus.agent.toolbox import Toolbox
from romulus.evidence.typed import RawRef, TypedEvent
from romulus.report.manifest import _citations, _content_candidate_key
from romulus.store import schema as t
from romulus.store.db import digest, make_engine, migrate
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


def test_hunt_scoped_agent_and_report_consumers_read_the_citation_overlay():
    repo = Repo(make_engine(":memory:"))
    migrate(repo.engine)
    repo.create_hunt("h1", {}, "d1", "test")
    repo.create_hunt("h2", {}, "d2", "test")
    owner_ref = RawRef(target="windows-a", native_id="owner-copy", digest="digest-1")
    foreign_ref = RawRef(target="windows-b", native_id="foreign-copy", digest="digest-2")
    owner = TypedEvent(
        id="stable-event", family="process_exec", ts=datetime(2026, 1, 1, tzinfo=UTC), host="ws01",
        fields={}, raw=[owner_ref], normalizer="windows-ecs@1",
    )
    repo.save_evidence("h1", [owner], {owner_ref.key: {"copy": "owner"}}, None)
    repo.save_evidence(
        "h2", [owner.model_copy(update={"raw": [foreign_ref]})],
        {foreign_ref.key: {"copy": "foreign"}}, None,
    )
    repo.save_candidate({
        "id": "finding-h2", "hunt_id": "h2", "rule_id": "host.test", "rule_version": "1",
        "claim": "scoped evidence", "claim_type": "observed_action", "event_ids": [owner.id],
        "predicate_fields": [], "entities": [["host", "ws01", "host"]], "ts": owner.ts,
        "severity": "high", "confidence": "high", "lane": "high", "priority": 1.0,
        "priority_reasons": [], "gate_results": {}, "benign_alternatives": [], "next_checks": [],
        "source_case_id": None, "source_anchor_id": None, "source_link_id": None,
    })

    toolbox = Toolbox(repo, "h2")
    finding = toolbox.execute("get_finding", {"finding": "F1"})
    evidence = toolbox.execute("get_evidence", {
        "evidence": [finding["data"]["finding"]["evidence"][0]],
    })["data"]["evidence"][0]
    candidate = repo.candidate("finding-h2")

    assert [raw["native_id"] for raw in evidence["raw_records"]] == ["foreign-copy"]
    assert _content_candidate_key(repo, candidate) == "F-" + digest({
        "rule_id": "host.test", "evidence_identity": ["windows-b/foreign-copy"],
    })[:20]


def test_another_hunt_reuses_the_stable_citation_without_an_identical_overlay():
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

    assert _citation_count(repo) == 0
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
    assert [citation["native_id"] for citation in _citations(
        repo, {"hunt_id": "h1", "event_ids": [first.id]},
    )] == ["copy-1", "copy-2"]
    assert [ref["native_id"] for ref in repo.events_by_ids([first.id])[0]["event"]["raw"]] == [
        "copy-1",
    ]
    with repo.engine.connect() as connection:
        assert connection.execute(select(t.event_citation.c.hunt_id)).scalars().all() == ["h1"]


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


def test_entity_free_foreign_hunt_keeps_its_identical_then_differing_observations():
    repo = Repo(make_engine(":memory:"))
    migrate(repo.engine)
    repo.create_hunt("h1", {}, "d1", "test")
    repo.create_hunt("h2", {}, "d2", "test")
    first_ref = RawRef(target="windows-a", native_id="copy-1", digest="digest-1")
    second_ref = RawRef(target="windows-b", native_id="copy-2", digest="digest-2")
    first = TypedEvent(
        id="stable-event", family="process_exec", ts=datetime(2026, 1, 1, tzinfo=UTC), host=None,
        fields={}, raw=[first_ref], normalizer="windows-ecs@1",
    )

    repo.save_evidence("h1", [first], {first_ref.key: {"copy": 1}}, None)
    repo.save_evidence("h2", [first], {first_ref.key: {"copy": 1}}, None)
    assert _citation_count(repo) == 0
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


def test_foreign_duplicate_id_batch_keeps_every_retrieved_raw_ref_in_the_overlay_event():
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
    second = first.model_copy(update={"raw": [second_ref]})

    repo.save_evidence("h1", [first], {first_ref.key: {"copy": 1}}, None)
    repo.save_evidence("h2", [first, second], {
        first_ref.key: {"copy": 1}, second_ref.key: {"copy": 2},
    }, None)

    scoped = repo.citation_events("h2", [first.id])[0]
    assert [ref["native_id"] for ref in scoped["event"]["raw"]] == ["copy-1", "copy-2"]
    assert scoped["raw_ids"] == [
        raw_id(first_ref.target, first_ref.native_id),
        raw_id(second_ref.target, second_ref.native_id),
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
    assert _citation_count(repo) == 1
    assert [ref["native_id"] for ref in repo.events_by_ids([owner.id])[0]["event"]["raw"]] == ["copy-2"]
    assert repo.raw_records([raw_id(owner_ref.target, owner_ref.native_id)]) == []


def test_transfer_to_a_differing_overlay_preserves_an_identical_hunts_stable_history():
    repo = Repo(make_engine(":memory:"))
    migrate(repo.engine)
    for hunt_id in ("h1", "h2", "h3"):
        repo.create_hunt(hunt_id, {}, hunt_id, "test")
    stable_ref = RawRef(target="windows-a", native_id="copy-1", digest="digest-1")
    differing_ref = RawRef(target="windows-b", native_id="copy-2", digest="digest-2")
    event = TypedEvent(
        id="stable-event", family="process_exec", ts=datetime(2026, 1, 1, tzinfo=UTC), host="ws01",
        fields={}, raw=[stable_ref], normalizer="windows-ecs@1",
    )

    repo.save_evidence("h1", [event], {stable_ref.key: {"copy": 1}}, None)
    repo.save_evidence(
        "h2", [event.model_copy(update={"raw": [differing_ref]})],
        {differing_ref.key: {"copy": 2}}, None,
    )
    repo.save_evidence("h3", [event], {stable_ref.key: {"copy": 1}}, None)
    assert _citation_count(repo) == 1

    repo.delete_hunt("h1", actor="test")

    stored = repo.events_by_ids([event.id])[0]
    assert stored["hunt_id"] == "h2"
    assert [ref["native_id"] for ref in stored["event"]["raw"]] == ["copy-2"]
    assert [citation["native_id"] for citation in _citations(
        repo, {"hunt_id": "h3", "event_ids": [event.id]},
    )] == ["copy-1"]
    assert _citation_count(repo) == 1


def test_citation_event_read_is_one_snapshot_during_owner_transfer(tmp_path):
    repo = Repo(make_engine(tmp_path / "citation-snapshot.db"))
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
    transferred = False
    transfer_error: list[BaseException] = []

    def transfer_between_reads(_connection, _cursor, statement, _parameters, _context, _many):
        nonlocal transferred
        if transferred or not statement.lstrip().upper().startswith("SELECT") or "event_citation" not in statement:
            return
        transferred = True

        def transfer():
            try:
                repo.delete_hunt("h1", actor="test")
            except BaseException as exc:  # pragma: no cover - asserted below with the original exception
                transfer_error.append(exc)

        worker = Thread(target=transfer)
        worker.start()
        worker.join(timeout=5)
        assert not worker.is_alive()

    sqlalchemy_event.listen(repo.engine, "before_cursor_execute", transfer_between_reads)
    try:
        [scoped] = repo.citation_events("h2", [owner.id])
    finally:
        sqlalchemy_event.remove(repo.engine, "before_cursor_execute", transfer_between_reads)

    assert transfer_error == []
    assert transferred is True
    assert [ref["native_id"] for ref in scoped["event"]["raw"]] == ["copy-2"]
