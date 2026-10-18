"""Sweep partitioning: capped partitions subdivide until complete; failures stay visible."""
from datetime import UTC, datetime, timedelta

from romulus.hunt import sweep as sw
from romulus.sources.models import Completeness, SearchOutcome, Window
from romulus.store.db import make_engine, migrate
from romulus.store.repo import Repo

START = datetime(2024, 11, 18, 14, 0, tzinfo=UTC)


class FakeClient:
    version = "test"

    class settings:  # noqa: N801
        es_flavor = "elasticsearch"


def _repo():
    e = make_engine(":memory:")
    migrate(e)
    r = Repo(e)
    r.create_hunt("h1", {"targets": ["romulus-host-x"]}, "d", "t")
    return r


def test_capped_partitions_split_until_complete(monkeypatch):
    calls = []

    def fake_execute(client, intent, contract):
        span = intent.window.end - intent.window.start
        calls.append(span)
        now = datetime.now(UTC)
        if span > timedelta(minutes=5):        # dense burst: anything wider than 5 min exceeds the cap
            return SearchOutcome(target=intent.target, fingerprint="f", started_at=now, ended_at=now,
                                 completeness=Completeness.partial, reasons=["cap:1000<total:5000"], total=5000,
                                 total_relation="eq", returned=1000, records=[])
        return SearchOutcome(target=intent.target, fingerprint="f", started_at=now, ended_at=now,
                             completeness=Completeness.complete, total=0, total_relation="eq", returned=0, records=[])

    monkeypatch.setattr(sw, "execute", fake_execute)
    repo = _repo()
    s = sw.Sweep(repo, FakeClient(), "h1", Window(start=START, end=START + timedelta(minutes=40)), {"romulus-host-x": None})
    s.run_partition("romulus-host-x", None, [], Window(start=START, end=START + timedelta(minutes=40)), est=100)
    assert s.partial_reasons == []
    states = [t["state"] for t in repo.tasks("h1")]
    # 40 -> 2x20 -> 4x10 -> 8x5-minute leaves: 1 + 2 + 4 = 7 splits, 8 evaluated leaves
    assert states.count("split") == 7 and states.count("evaluated") == 8
    leaves = [c["partition"] for c in repo.rule_cells("h1")]
    assert leaves and all("partial" not in c["state"] for c in repo.rule_cells("h1"))


def test_presplit_uses_exact_histogram_count(monkeypatch):
    seen = []

    def fake_execute(client, intent, contract):
        seen.append(intent.window)
        now = datetime.now(UTC)
        return SearchOutcome(target=intent.target, fingerprint="f", started_at=now, ended_at=now,
                             completeness=Completeness.complete, total=0, total_relation="eq", returned=0, records=[])

    monkeypatch.setattr(sw, "execute", fake_execute)
    repo = _repo()
    s = sw.Sweep(repo, FakeClient(), "h1", Window(start=START, end=START + timedelta(minutes=5)), {"x": None})
    s.run_partition("x", None, [], Window(start=START, end=START + timedelta(minutes=5)),
                    est=sw.PARTITION_MAX_DOCS * 3)
    assert len(seen) == 4 and all(w.end > w.start for w in seen)       # split before any fetch


def test_failed_partition_is_recorded_not_dropped(monkeypatch):
    def fake_execute(client, intent, contract):
        now = datetime.now(UTC)
        return SearchOutcome(target=intent.target, fingerprint="f", started_at=now, ended_at=now,
                             completeness=Completeness.failed, reasons=["source_error"], error="HTTP 503")

    monkeypatch.setattr(sw, "execute", fake_execute)
    repo = _repo()
    s = sw.Sweep(repo, FakeClient(), "h1", Window(start=START, end=START + timedelta(minutes=5)), {"x": None})
    s.run_partition("x", None, [], Window(start=START, end=START + timedelta(minutes=5)), est=10)
    assert s.partial_reasons and all(c["state"] == "executed_failed" for c in repo.rule_cells("h1"))
