"""The per-fetch query cap is hard: sampling a capped leaf never spends past it."""
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta

import pytest

import romulus.hunt.pivot as pivot_mod
from romulus.hunt.pivot import MAX_SAMPLE_QUERIES, PivotExecutor
from romulus.sources.models import Completeness, Predicate, SearchIntent, SearchOutcome, Window
from romulus.sources.profile import contract_from_types
from romulus.store.db import make_engine, migrate
from romulus.store.repo import Repo

T0 = datetime(2024, 11, 18, 14, 0, tzinfo=UTC)


class _Client:
    @contextmanager
    def point_in_time(self, target):
        yield "pit"


def _capped(client, intent, contract, pit=None):
    now = datetime.now(UTC)
    return SearchOutcome(target=intent.target, fingerprint="f", started_at=now, ended_at=now,
                         completeness=Completeness.partial, reasons=["cap:5<total:50"], returned=0)


@pytest.mark.parametrize("query_cap", [2, 3, 4, 5, 6, 12])
def test_a_capped_dense_leaf_never_exceeds_the_fetch_cap(monkeypatch, query_cap):
    monkeypatch.setattr(pivot_mod, "execute", _capped)
    engine = make_engine(":memory:")
    migrate(engine)
    repo = Repo(engine)
    repo.create_hunt("h1", {"window": {}}, "d", "t")
    contract = contract_from_types("host-x", {"@timestamp": "date", "event.dataset": "keyword"})
    executor = PivotExecutor(repo, _Client(), "h1", {"host-x": contract}, source_query_budget=180)
    intent = SearchIntent(kind="raw", target="host-x", window=Window(start=T0, end=T0 + timedelta(seconds=8)),
                          filters=[Predicate(field="event.dataset", op="eq", value="linux.audit")],
                          max_records=10, purpose="expansion:linux.audit")
    batch = executor.fetch_intents("F", "k", [intent], lambda e: True, anchor_ts=T0 + timedelta(seconds=4),
                                   query_cap=query_cap)
    assert executor.source_queries <= query_cap
    assert repo.expansion_source_queries("h1") == executor.source_queries
    assert batch.status != "complete"
    assert all("returned" in (task["outcome"] or {}) for task in repo.tasks("h1"))
    if query_cap < 1 + MAX_SAMPLE_QUERIES:              # no room to sample: unresolved, and the reason says why
        assert executor.source_queries == 1
        assert f"expansion_link_query_cap:{query_cap}" in batch.reasons
