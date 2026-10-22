"""Streaming source I/O: hits are kept as returned (not copied), the next partition is fetched while the current one
is evaluated, a split half is counted before it is fetched, and response compression is a setting. None of these
changes what a partition holds, how it is split, or how a cap is reported."""
import threading
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from romulus.config import Settings, load_settings
from romulus.hunt import sweep as sw
from romulus.sources import execute as execute_mod
from romulus.sources.es import ElasticClient, fetch_limit
from romulus.sources.models import Completeness, SearchIntent, SearchOutcome, Window
from romulus.sources.profile import contract_from_types
from romulus.store.db import make_engine, migrate
from romulus.store.repo import Repo
from tests import throughput_fixture as tf

T0 = datetime(2024, 11, 18, 14, 0, tzinfo=UTC)
W = Window(start=T0, end=T0 + timedelta(hours=1))
C = contract_from_types("idx", {"@timestamp": "date", "event.dataset": "keyword"})


class _Client:
    """Yields the given pages as `iterate` would."""

    class settings:
        es_flavor = "elasticsearch"

    version = "8"

    def __init__(self, pages, total):
        self.pages, self.total = pages, total

    def iterate(self, q, max_records, pit=None):
        for page in self.pages:
            yield page, {"problems": [], "total": self.total, "total_relation": "eq"}


def test_raw_hits_are_kept_as_returned_with_the_sort_key_renamed():
    hits = [{"_index": "idx", "_id": str(n), "_source": {"n": n}, "sort": ["t", n]} for n in range(3)]
    odd = {"_index": "idx", "_id": "x", "_source": {"n": 9}, "sort": ["t", 9], "_score": None}
    out = execute_mod.execute(_Client([hits[:2], hits[2:] + [odd]], 4),
                              SearchIntent(kind="raw", target="idx", window=W, max_records=10), C)
    assert out.completeness == Completeness.complete and out.returned == 4
    assert all(record is hit for record, hit in zip(out.records, hits, strict=False))
    assert [r["_sort"] for r in out.records] == [["t", 0], ["t", 1], ["t", 2], ["t", 9]]
    assert all(set(r) == {"_index", "_id", "_source", "_sort"} for r in out.records)     # extra keys dropped


def test_a_hit_without_a_sort_value_records_none():
    hit = {"_index": "idx", "_id": "1", "_source": {}}
    out = execute_mod.execute(_Client([[hit]], 1), SearchIntent(kind="raw", target="idx", window=W), C)
    assert out.records == [{"_id": "1", "_index": "idx", "_source": {}, "_sort": None}]


@pytest.mark.parametrize("max_records,limit", [(1, 1), (1999, 1999), (2000, 2000), (2001, 4000),
                                               (121_000, 122_000), (145_000, 146_000)])
def test_the_fetch_limit_is_what_a_raw_retrieval_returns_at_most(max_records, limit):
    assert fetch_limit(max_records) == limit


def test_fetch_limit_matches_the_paging_of_a_real_retrieval():
    docs = {"idx": [{"_index": "idx", "_id": f"d{n}", "_source": {"@timestamp": tf._iso(T0 + timedelta(seconds=n)),
                                                                   "event": {"dataset": "x"}}}
                    for n in range(2500)]}
    es = tf.MiniES(docs, {"idx": "@timestamp"})
    client = ElasticClient(Settings(es_url="http://es.invalid"), transport=es.transport())
    for cap in (1, 700, 2001):
        out = execute_mod.execute(client, SearchIntent(kind="raw", target="idx", window=W, max_records=cap), C)
        assert out.returned == min(2500, fetch_limit(cap))
        assert any(r.startswith("cap:") for r in out.reasons) == (2500 > fetch_limit(cap))


def _repo():
    engine = make_engine(":memory:")
    migrate(engine)
    repo = Repo(engine)
    repo.create_hunt("h1", {"targets": ["romulus-host-x"]}, "d", "t")
    return repo


def _outcome(intent, total, records=()):
    now = datetime.now(UTC)
    records = list(records)
    reasons = [f"cap:{intent.max_records}<total:{total}"] if intent.kind == "raw" and len(records) < total else []
    return SearchOutcome(target=intent.target, fingerprint="f", started_at=now, ended_at=now,
                         completeness=Completeness.partial if reasons else Completeness.complete, reasons=reasons,
                         total=total, total_relation="eq", returned=len(records), records=records,
                         buckets=[{"key": intent.window.start.isoformat(), "count": total}])


def test_the_next_partition_is_fetched_while_the_current_one_is_evaluated(monkeypatch):
    parts = [(Window(start=T0 + timedelta(minutes=5 * i), end=T0 + timedelta(minutes=5 * i + 5)), 1)
             for i in range(4)]
    fetched, lock = [], threading.Lock()
    second_fetched = threading.Event()

    def execute(client, intent, contract):
        with lock:
            fetched.append(intent.window.start)
        if intent.window.start == parts[1][0].start:
            second_fetched.set()
        return _outcome(intent, 0)

    seen = []

    def normalize(hits, boots=None):
        if not seen:      # the first partition's evaluation waits until the second partition has been fetched
            assert second_fetched.wait(10), "the next partition was not fetched during this one's evaluation"
        seen.append(1)
        return [], {}, []

    monkeypatch.setattr(sw, "execute", execute)
    monkeypatch.setattr(sw, "normalize_hits", normalize)
    monkeypatch.setattr(sw, "plan_partitions", lambda *a: parts)
    repo = _repo()
    sweep = sw.Sweep(repo, None, "h1", W, {"romulus-host-x": None}, prefetch=True)
    sweep.run_target("romulus-host-x")
    assert sorted(fetched) == [w.start for w, _ in parts] and len(seen) == 4
    cells = {(c["partition"], c["state"]) for c in repo.rule_cells("h1")}
    serial = _repo()
    monkeypatch.setattr(sw, "normalize_hits", lambda hits, boots=None: ([], {}, []))
    sw.Sweep(serial, None, "h1", W, {"romulus-host-x": None}, prefetch=False).run_target("romulus-host-x")
    assert cells == {(c["partition"], c["state"]) for c in serial.rule_cells("h1")}


def test_a_failed_prefetch_fails_its_own_partition_only(monkeypatch):
    parts = [(Window(start=T0 + timedelta(minutes=5 * i), end=T0 + timedelta(minutes=5 * i + 5)), 1)
             for i in range(3)]

    def execute(client, intent, contract):
        if intent.window.start == parts[1][0].start:
            now = datetime.now(UTC)
            return SearchOutcome(target=intent.target, fingerprint="f", started_at=now, ended_at=now,
                                 completeness=Completeness.failed, reasons=["source_error"], error="HTTP 503")
        return _outcome(intent, 0)

    monkeypatch.setattr(sw, "execute", execute)
    monkeypatch.setattr(sw, "plan_partitions", lambda *a: parts)
    repo = _repo()
    sweep = sw.Sweep(repo, None, "h1", W, {"romulus-host-x": None}, prefetch=True)
    sweep.run_target("romulus-host-x")
    states = {c["partition"]: c["state"] for c in repo.rule_cells("h1")}
    assert states[parts[1][0].key()] == "executed_failed"
    assert states[parts[0][0].key()] != "executed_failed" and states[parts[2][0].key()] != "executed_failed"
    assert sweep.partial_reasons == [f"romulus-host-x {parts[1][0].key()}: HTTP 503"]


def _dense(monkeypatch, counting: bool):
    """A burst whose records all sit in the first quarter of a bucket: the halves' estimates are wrong."""
    stamps = [T0 + timedelta(milliseconds=n * 10) for n in range(3000)]      # 30 s of a 5-minute window
    raw_fetches = []

    def execute(client, intent, contract):
        inside = [s for s in stamps if intent.window.start <= s < intent.window.end]
        if intent.kind == "histogram":
            if not counting:
                now = datetime.now(UTC)
                return SearchOutcome(target=intent.target, fingerprint="f", started_at=now, ended_at=now,
                                     completeness=Completeness.failed, reasons=["source_error"], error="no count")
            return _outcome(intent, len(inside))
        limit = fetch_limit(intent.max_records)
        raw_fetches.append((intent.window.key(), len(inside), limit))
        records = [{"_index": "romulus-network-x", "_id": f"{s.timestamp()}", "_source": {}, "_sort": None}
                   for s in inside[:limit]]
        return _outcome(intent, len(inside), records)

    monkeypatch.setattr(sw, "execute", execute)
    monkeypatch.setattr(sw, "normalize_hits", lambda hits, boots=None: ([], {}, []))
    monkeypatch.setattr(sw, "PARTITION_MAX_DOCS", 100)
    repo = _repo()
    sweep = sw.Sweep(repo, None, "h1", Window(start=T0, end=T0 + timedelta(minutes=5)), {"romulus-network-x": None},
                     prefetch=False)
    sweep.run_partition("romulus-network-x", None, [], Window(start=T0, end=T0 + timedelta(minutes=5)), est=900)
    leaves = sorted((c["partition"], c["state"]) for c in repo.rule_cells("h1") if c["rule_id"] == sweep.pack[0].id)
    tasks = sorted((t["id"], t["state"]) for t in repo.tasks("h1"))
    return leaves, tasks, raw_fetches, sweep.stats["records"], repo


def test_a_split_half_is_counted_and_never_fetched_only_to_be_discarded(monkeypatch):
    counted_leaves, counted_tasks, counted_fetches, counted_records, repo = _dense(monkeypatch, counting=True)
    fetched_leaves, fetched_tasks, fetched_fetches, fetched_records, _ = _dense(monkeypatch, counting=False)
    # the same partitions, states and tasks as when every half is fetched first
    assert counted_leaves == fetched_leaves and counted_tasks == fetched_tasks
    assert counted_records == fetched_records == 3000
    # without counts some halves were fetched whole and thrown away; with counts none is
    assert any(n > limit for _key, n, limit in fetched_fetches)
    assert all(n <= limit for _key, n, limit in counted_fetches)
    split = [t for t in repo.tasks("h1") if t["state"] == "split"]
    assert split and all(t["outcome"]["counted"] and t["outcome"]["returned"] == 0
                         and t["outcome"]["reasons"][0].startswith("cap:") for t in split)


def test_compression_is_a_setting_and_stays_on_by_default():
    seen = []

    def handler(request):
        seen.append(request.headers.get("accept-encoding"))
        return httpx.Response(200, json={"version": {"number": "8"}})

    for settings in (Settings(es_url="http://es"), Settings(es_url="http://es", es_compression=False)):
        ElasticClient(settings, transport=httpx.MockTransport(handler)).info()
    assert "gzip" in seen[0] and seen[1] == "identity"
    assert load_settings(environ={"ES_COMPRESSION": "false"}).es_compression is False
    assert load_settings(environ={"ROMULUS_SWEEP_PREFETCH": "true"}).sweep_prefetch is True
    assert Settings().es_compression is True and Settings().sweep_prefetch is False
