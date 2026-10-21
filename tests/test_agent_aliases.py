"""Per-hunt aliases are deterministic, durable, and hunt scoped."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from romulus.agent.aliases import (
    AliasBook,
    AliasFromOtherHunt,
    AliasKindMismatch,
    UnknownAlias,
)
from romulus.evidence.typed import Outcome, TypedEvent, fv
from romulus.store.db import make_engine, migrate
from romulus.store.repo import Repo

T = datetime(2024, 11, 18, 14, 0, tzinfo=UTC)


def _repo(path=":memory:") -> Repo:
    engine = make_engine(path)
    migrate(engine)
    repo = Repo(engine)
    repo.create_hunt(
        "h1",
        {"window": {"start": T.isoformat(), "end": (T + timedelta(hours=1)).isoformat()}},
        "digest",
        "test",
    )
    return repo


def _candidate(repo: Repo, candidate_id: str, lane: str, priority: float, ts: datetime) -> None:
    event = TypedEvent(
        id=f"event-{candidate_id}", family="process_exec", ts=ts, host="web01",
        outcome=Outcome.success, fields={"process.argv": fv(["id"], "fixture")},
        raw=[], normalizer="test@1",
    )
    repo.save_evidence("h1", [event], {}, None)
    repo.save_candidate({
        "id": candidate_id, "hunt_id": "h1", "rule_id": "host.test", "rule_version": "1",
        "claim": candidate_id, "claim_type": "observed_action", "event_ids": [event.id],
        "predicate_fields": [], "entities": [["host", "web01", "host"]], "ts": ts,
        "severity": "high", "confidence": "high", "lane": lane, "priority": priority,
        "priority_reasons": [], "gate_results": {}, "benign_alternatives": [], "next_checks": [],
        "group_key": "", "source_case_id": None, "source_anchor_id": None, "source_link_id": None,
    })


def _seed(repo: Repo, reverse: bool = False) -> None:
    rows = [
        ("low-priority", "high", 10.0, T + timedelta(seconds=2)),
        ("lead", "lead", 99.0, T),
        ("high-priority", "high", 90.0, T + timedelta(seconds=1)),
        ("urgent", "urgent", 1.0, T + timedelta(seconds=3)),
    ]
    for row in reversed(rows) if reverse else rows:
        _candidate(repo, *row)


def test_alias_book_seeds_findings_in_content_order_and_is_idempotent():
    repo = _repo()
    _seed(repo, reverse=True)

    aliases = AliasBook(repo, "h1")

    assert aliases.alias_for("F", "urgent") == "F1"
    assert aliases.alias_for("F", "high-priority") == "F2"
    assert aliases.alias_for("F", "low-priority") == "F3"
    assert aliases.alias_for("F", "lead") == "F4"
    assert aliases.alias_for("F", "urgent") == "F1"
    assert aliases.resolve("F2", {"F"}) == "high-priority"


def test_alias_errors_distinguish_unknown_wrong_kind_and_other_hunt():
    repo = _repo()
    _candidate(repo, "finding", "high", 50.0, T)
    book = AliasBook(repo, "h1")
    assert book.alias_for("F", "finding") == "F1"

    with pytest.raises(AliasKindMismatch, match="expected.*N"):
        book.resolve("F1", {"N"})
    with pytest.raises(UnknownAlias, match="Z99"):
        book.resolve("Z99", {"F"})

    repo.create_hunt("h2", {"window": {}}, "digest-2", "test")
    other = AliasBook(repo, "h2")
    other.alias_for("I", "incident-only-in-h2")
    with pytest.raises(AliasFromOtherHunt, match="I1"):
        book.resolve("I1", {"I"})


def test_aliases_survive_database_reopen(tmp_path):
    path = tmp_path / "romulus.db"
    repo = _repo(path)
    _candidate(repo, "finding", "high", 50.0, T)
    assert AliasBook(repo, "h1").alias_for("F", "finding") == "F1"
    repo.engine.dispose()

    reopened = Repo(make_engine(path))
    migrate(reopened.engine)

    assert AliasBook(reopened, "h1").resolve("F1", {"F"}) == "finding"


def test_twin_databases_assign_identical_content_aliases():
    first, second = _repo(), _repo()
    _seed(first)
    _seed(second, reverse=True)

    AliasBook(first, "h1")
    AliasBook(second, "h1")

    left = [(row["alias"], row["kind"], row["target_id"]) for row in first.agent_aliases("h1")]
    right = [(row["alias"], row["kind"], row["target_id"]) for row in second.agent_aliases("h1")]
    assert left == right
