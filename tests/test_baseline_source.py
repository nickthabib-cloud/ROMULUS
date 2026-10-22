"""The hunt-layer adapter reuses sweep retrieval without crossing the baseline boundary."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

from romulus.hunt import baseline_source as module
from romulus.hunt.baseline_source import HuntHistorySource
from romulus.sources.models import Completeness

START = datetime(2026, 1, 1, tzinfo=UTC)


def test_adapter_reuses_partition_planner_execute_and_normalizer(monkeypatch):
    planned = []

    def plan(client, target, contract, window, filters):
        planned.append((client, target, contract, window, filters))
        return [(window, 2)]

    monkeypatch.setattr(module, "plan_partitions", plan)
    source = HuntHistorySource("client", {"host-index": "contract"})
    parts = list(source.plan("host-index", START, START + timedelta(hours=1)))
    assert len(parts) == 1 and parts[0].expected_records == 2
    assert planned[0][4][0].field == "event.dataset"

    outcome = SimpleNamespace(
        completeness=Completeness.complete, reasons=[], error=None, total=2,
        total_relation="eq", returned=2, records=[{"_id": "1"}, {"_id": "2"}],
    )
    monkeypatch.setattr(module, "execute", lambda client, intent, contract: outcome)
    monkeypatch.setattr(module, "normalize_hits", lambda records, boots: (["event"], {}, []))
    fetched = source.fetch(parts[0])
    assert fetched.completeness == "complete"
    assert fetched.events == ("event",) and fetched.record_count == 2


def test_adapter_turns_normalization_errors_and_unsupported_records_partial(monkeypatch):
    source = HuntHistorySource("client", {"network": "contract"})
    partition = module.HistoryPartition(
        "network", START, START + timedelta(hours=1), 1, "p",
    )
    outcome = SimpleNamespace(
        completeness=Completeness.complete, reasons=[], error=None, total=1,
        total_relation="eq", returned=1,
        records=[{"_id": "1", "_source": {"event": {"dataset": "unknown"}}}],
    )
    monkeypatch.setattr(module, "execute", lambda client, intent, contract: outcome)
    monkeypatch.setattr(
        module, "normalize_hits",
        lambda records, boots: ([], {"dataset:unknown is not normalized": 1}, [("1", "bad")]),
    )
    fetched = source.fetch(partition)
    assert fetched.completeness == "partial"
    assert "normalization_errors=1" in fetched.reasons
    assert "unsupported_records=1" in fetched.reasons
