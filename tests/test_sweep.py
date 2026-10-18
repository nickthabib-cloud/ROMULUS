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


def test_partition_heartbeats_before_and_after_source_execution(monkeypatch):
    calls = []

    def fake_execute(client, intent, contract):
        calls.append("execute")
        return _complete(intent, [])

    monkeypatch.setattr(sw, "execute", fake_execute)
    repo = _repo()
    sweep = sw.Sweep(
        repo, FakeClient(), "h1", Window(start=START, end=START + timedelta(minutes=5)),
        {"x": None}, heartbeat=lambda: calls.append("heartbeat"),
    )

    sweep.run_partition(
        "x", None, [], Window(start=START, end=START + timedelta(minutes=5)), est=0,
    )

    assert calls == ["heartbeat", "execute", "heartbeat"]


# ---------------------------------------------------------------- M1 gate regressions (B2, B3, B5)
def _complete(intent, records):
    now = datetime.now(UTC)
    return SearchOutcome(target=intent.target, fingerprint="f", started_at=now, ended_at=now,
                         completeness=Completeness.complete, total=len(records), total_relation="eq",
                         returned=len(records), records=records)


def test_aggregate_rules_with_zero_evaluated_are_not_complete_negatives(monkeypatch):
    monkeypatch.setattr(sw, "execute", lambda client, intent, contract: _complete(intent, []))
    repo = _repo()
    s = sw.Sweep(repo, FakeClient(), "h1", Window(start=START, end=START + timedelta(minutes=5)), {"x": None})
    s.run_partition("x", None, [], Window(start=START, end=START + timedelta(minutes=5)), est=0)
    s.finalize()
    window_cells = {c["rule_id"]: c["state"] for c in repo.rule_cells("h1") if c["target"] == "*"}
    assert window_cells and "no_match_complete" not in window_cells.values()
    assert set(window_cells.values()) == {"not_applicable_no_events"}


def test_report_coverage_never_complete_with_unexecuted_or_missing_work():
    from romulus.report.manifest import _coverage
    done = {"rule_id": "r", "target": "a", "partition": "p1", "state": "no_match_complete", "evaluated": 10}
    planned = {"rule_id": "r", "target": "a", "partition": "p2", "state": "planned", "evaluated": 0}
    split = {"rule_id": "r", "target": "a", "partition": "p0", "state": "split", "evaluated": 0}
    claim = lambda cells, **kw: _coverage(cells, **kw)["rules"][0]["negative_claim"]  # noqa: E731
    assert claim([done, split], targets=["a"]) == "complete"
    assert claim([done, planned], targets=["a"]).startswith("unresolved")
    assert "target(s) ['b']" in claim([done], targets=["a", "b"])
    assert "sweep did not finish" in claim([done], targets=["a"], sweep_finished=False)
    never = _coverage([done], targets=["a"], rule_ids=["r", "other"])["rules"]
    assert [r["negative_claim"] for r in never if r["rule_id"] == "other"][0].startswith("unresolved")


def test_target_planning_failure_is_recorded_and_other_targets_continue(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("histogram shard failure")
    monkeypatch.setattr(sw, "plan_partitions", boom)
    repo = _repo()
    s = sw.Sweep(repo, FakeClient(), "h1", Window(start=START, end=START + timedelta(minutes=5)), {"x": None})
    s.run_target("x")                      # must not raise
    assert s.partial_reasons and all(c["state"] == "executed_failed" for c in repo.rule_cells("h1"))


def test_firewall_drop_citations_resolve_on_a_fresh_database(monkeypatch):
    from romulus.report.manifest import build_manifest
    execve = 'type=EXECVE msg=audit(1731940424.829:9001): argc=7 a0="iptables" a1="-A" a2="INPUT" ' \
             'a3="-s" a4="192.0.2.65" a5="-j" a6="DROP"'
    syscall = 'type=SYSCALL msg=audit(1731940424.829:9001): arch=c000003e syscall=59 success=yes exit=0 ' \
              'ppid=10 pid=11 auid=0 uid=0 euid=0 comm="iptables" exe="/usr/sbin/iptables" key=(null)'
    recs = [{"_id": f"r{i}", "_index": "romulus-host-x", "_source": {
        "@timestamp": "2024-11-18T14:33:44.829Z", "message": raw, "host": {"name": "video"},
        "event": {"dataset": "linux.audit", "original": raw}}} for i, raw in enumerate((execve, syscall))]
    monkeypatch.setattr(sw, "execute", lambda client, intent, contract: _complete(intent, recs))
    repo = _repo()
    repo.set_hunt_state("h1", "running")
    w = Window(start=START, end=START + timedelta(minutes=40))
    s = sw.Sweep(repo, FakeClient(), "h1", w, {"romulus-host-x": None})
    s.run_partition("romulus-host-x", None, [], w, est=2)
    s.finalize()
    fw = [c for c in repo.candidates("h1") if c["rule_id"] == "host.firewall_rule_change_command"
          and c["lane"] == "high"]
    assert len(fw) == 1
    from romulus.report import manifest as rm
    cites = rm._citations(repo, fw[0])
    assert cites and all(c["status"] == "retained" for c in cites), cites
    assert build_manifest is not None


def test_audit_errors_make_only_process_rules_partial(monkeypatch):
    bad = {"_id": "bad", "_index": "romulus-host-x", "_source": {
        "@timestamp": "2024-11-18T14:00:01Z", "message": "type=EXECVE garbage", "host": {"name": "video"},
        "event": {"dataset": "linux.audit", "original": "type=EXECVE garbage"}}}
    monkeypatch.setattr(sw, "execute", lambda client, intent, contract: _complete(intent, [bad]))
    repo = _repo()
    s = sw.Sweep(repo, FakeClient(), "h1", Window(start=START, end=START + timedelta(minutes=5)), {"x": None})
    s.run_partition("romulus-host-x", None, [], Window(start=START, end=START + timedelta(minutes=5)), est=1)
    cells = {c["rule_id"]: c["state"] for c in repo.rule_cells("h1")}
    assert cells["host.credential_store_read"] == "evaluated_partial"        # process_exec rule
    assert cells["net.suricata_alert_stack"] == "not_applicable_no_events"   # unaffected family
    assert s.partial_reasons                                                  # hunt still records it
