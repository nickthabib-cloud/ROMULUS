"""Hunt-level investigator integration and agent-only resume (scenario 16)."""
from datetime import UTC, datetime, timedelta
from typing import ClassVar

import pytest

from romulus import cli
from romulus.config import Settings
from romulus.hunt import run as hunt_run

START = datetime(2024, 11, 18, 14, 0, tzinfo=UTC)


def _manifest(*, targets=None):
    return {
        "window": {"start": START.isoformat(), "end": (START + timedelta(hours=1)).isoformat()},
        "targets": targets or [], "source_profiles": {},
        "budgets": {"agent_steps_total": 2, "agent_steps_per_case": 2, "max_cases": 2,
                    "wall_clock_minutes": 10},
    }


def _new_hunt(settings: Settings, hunt_id="h1"):
    repo = hunt_run.open_repo(settings)
    repo.create_hunt(hunt_id, _manifest(), "digest", "test")
    return repo


class FakeSweep:
    constructed = 0

    def __init__(self, *_args, **_kwargs):
        type(self).constructed += 1
        self.partial_reasons = []
        self.stats = {"partitions": 0, "records": 0, "events": 0, "candidates": 0, "skips": {}, "errors": 0}

    def run_target(self, _target):
        raise AssertionError("test manifest has no targets")

    def finalize(self):
        return None


class FakeInvestigator:
    result: ClassVar = {
        "status": "completed", "partial": False, "stop_reason": "all selected cases concluded",
        "unworked_count": 0,
    }

    def __init__(self, *_args, **_kwargs):
        pass

    def run(self):
        return dict(type(self).result)


def test_outage_then_resume_continues_agent_without_rerunning_sweep(tmp_path, monkeypatch):
    settings = Settings(agent_mode="model", home=tmp_path)
    _new_hunt(settings)
    FakeSweep.constructed = 0
    monkeypatch.setattr(hunt_run, "Sweep", FakeSweep)
    monkeypatch.setattr(hunt_run, "Investigator", FakeInvestigator)
    FakeInvestigator.result = {
        "status": "unavailable", "partial": True, "stop_reason": "model unavailable: connection refused",
        "unworked_count": 1,
    }

    first = hunt_run.run_hunt(settings, "h1")
    assert first["agent"]["status"] == "unavailable"
    assert hunt_run.open_repo(settings).get_hunt("h1")["execution_state"] == "partial"
    assert FakeSweep.constructed == 1

    FakeInvestigator.result = {
        "status": "completed", "partial": False, "stop_reason": "all selected cases concluded",
        "unworked_count": 0,
    }
    resumed = hunt_run.resume_hunt(settings, "h1")

    assert resumed["agent"]["status"] == "completed"
    assert FakeSweep.constructed == 1
    assert hunt_run.open_repo(settings).get_hunt("h1")["execution_state"] == "completed_within_scope"


def test_source_preflight_failure_does_not_leave_a_live_running_lease(tmp_path, monkeypatch):
    settings = Settings(agent_mode="model", home=tmp_path)
    _new_hunt(settings)
    monkeypatch.setattr(hunt_run, "_contracts", lambda *_args: (_ for _ in ()).throw(RuntimeError("mapping down")))

    with pytest.raises(RuntimeError, match="mapping down"):
        hunt_run.run_hunt(settings, "h1")

    repo = hunt_run.open_repo(settings)
    assert repo.get_hunt("h1")["execution_state"] == "failed"
    assert repo.get_hunt("h1")["lease_until"] is None
    assert repo.latest_audit("h1", "hunt.sweep_summary")["detail"]["finished"] is False


def test_resume_preflight_failure_does_not_leave_a_live_running_lease(tmp_path, monkeypatch):
    settings = Settings(agent_mode="model", home=tmp_path)
    repo = _new_hunt(settings)
    repo.claim_hunt("h1", 1, now=START)
    repo.audit("system", "hunt.sweep_summary", "h1", {"finished": True, "complete": True})
    repo.set_hunt_state("h1", "partial", stop_reason="model unavailable")
    monkeypatch.setattr(
        hunt_run, "_contracts", lambda *_args: (_ for _ in ()).throw(RuntimeError("mapping down")),
    )

    with pytest.raises(RuntimeError, match="mapping down"):
        hunt_run.resume_hunt(settings, "h1")

    stored = hunt_run.open_repo(settings)
    hunt = stored.get_hunt("h1")
    assert hunt["execution_state"] == "failed"
    assert hunt["lease_until"] is None
    assert "source preflight error: mapping down" in hunt["stop_reason"]
    assert stored.latest_audit("h1", "hunt.sweep_summary")["detail"]["finished"] is True
    agent = stored.latest_audit("h1", "hunt.agent_summary")["detail"]
    assert agent["status"] == "failed"
    assert agent["stop_reason"] == "source preflight error: mapping down"


def test_resume_refuses_an_active_lease(tmp_path):
    settings = Settings(agent_mode="model", home=tmp_path)
    repo = _new_hunt(settings)
    repo.claim_hunt("h1", lease_seconds=600)
    repo.audit("system", "hunt.sweep_summary", "h1", {"finished": True, "complete": True})

    with pytest.raises(RuntimeError, match="active lease"):
        hunt_run.resume_hunt(settings, "h1")


def test_resume_refuses_running_hunt_without_finished_sweep_summary(tmp_path):
    settings = Settings(agent_mode="model", home=tmp_path)
    repo = _new_hunt(settings)
    repo.claim_hunt("h1", lease_seconds=1, now=START)

    with pytest.raises(RuntimeError, match="sweep did not finish"):
        hunt_run.resume_hunt(settings, "h1")


def test_resume_reclaims_expired_running_lease(tmp_path, monkeypatch):
    settings = Settings(agent_mode="model", home=tmp_path)
    repo = _new_hunt(settings)
    repo.claim_hunt("h1", lease_seconds=1, now=START)
    repo.audit("system", "hunt.sweep_summary", "h1", {"finished": True, "complete": True})
    monkeypatch.setattr(hunt_run, "Investigator", FakeInvestigator)
    FakeInvestigator.result = {"status": "completed", "partial": False, "stop_reason": "done", "unworked_count": 0}

    hunt_run.resume_hunt(settings, "h1")

    assert hunt_run.open_repo(settings).latest_audit("h1", "hunt.resume_stale") is not None


def test_failed_hunt_resume_requires_proof_that_sweep_finished(tmp_path, monkeypatch):
    settings = Settings(agent_mode="model", home=tmp_path)
    repo = _new_hunt(settings, "eligible")
    repo.claim_hunt("eligible", 1, now=START)
    repo.audit("system", "hunt.sweep_summary", "eligible", {"finished": True, "complete": True})
    repo.set_hunt_state("eligible", "failed", stop_reason="agent crashed")
    monkeypatch.setattr(hunt_run, "Investigator", FakeInvestigator)
    FakeInvestigator.result = {"status": "completed", "partial": False, "stop_reason": "done", "unworked_count": 0}

    assert hunt_run.resume_hunt(settings, "eligible")["agent"]["status"] == "completed"

    repo = _new_hunt(settings, "unfinished")
    repo.claim_hunt("unfinished", 1, now=START)
    repo.audit("system", "hunt.sweep_summary", "unfinished", {"finished": False, "complete": False})
    repo.set_hunt_state("unfinished", "failed", stop_reason="sweep crashed")
    with pytest.raises(RuntimeError, match="sweep did not finish"):
        hunt_run.resume_hunt(settings, "unfinished")


def test_old_partial_without_sweep_summary_remains_conservatively_partial(tmp_path, monkeypatch):
    settings = Settings(agent_mode="model", home=tmp_path)
    repo = _new_hunt(settings)
    repo.claim_hunt("h1", 1, now=START)
    repo.set_hunt_state("h1", "partial", stop_reason="legacy interruption")
    monkeypatch.setattr(hunt_run, "Investigator", FakeInvestigator)
    FakeInvestigator.result = {"status": "completed", "partial": False, "stop_reason": "done", "unworked_count": 0}

    result = hunt_run.resume_hunt(settings, "h1")

    assert result["execution_state"] == "partial"
    assert "sweep summary missing" in hunt_run.open_repo(settings).get_hunt("h1")["stop_reason"]


def test_agent_budget_exhaustion_does_not_make_complete_sweep_partial(tmp_path, monkeypatch):
    settings = Settings(agent_mode="model", home=tmp_path)
    repo = _new_hunt(settings)
    repo.claim_hunt("h1", 1, now=START)
    repo.audit("system", "hunt.sweep_summary", "h1", {"finished": True, "complete": True})
    repo.set_hunt_state("h1", "partial", stop_reason="model interrupted")
    monkeypatch.setattr(hunt_run, "Investigator", FakeInvestigator)
    FakeInvestigator.result = {
        "status": "budget_exhausted", "partial": True, "partial_pivots": 1,
        "stop_reason": "agent total-step budget exhausted", "unworked_count": 2,
    }

    result = hunt_run.resume_hunt(settings, "h1")

    assert result["execution_state"] == "completed_within_scope"
    assert result["detection_result"] == "no_qualifying_observation_in_assessed_scope"
    stored = hunt_run.open_repo(settings)
    assert stored.get_hunt("h1")["execution_state"] == "completed_within_scope"
    assert stored.latest_audit("h1", "hunt.agent_summary")["detail"]["partial"] is True


def test_unexpected_agent_failure_marks_hunt_failed_instead_of_partial(tmp_path, monkeypatch):
    settings = Settings(agent_mode="model", home=tmp_path)
    repo = _new_hunt(settings)
    repo.claim_hunt("h1", 1, now=START)
    repo.audit("system", "hunt.sweep_summary", "h1", {"finished": True, "complete": True})
    repo.set_hunt_state("h1", "partial", stop_reason="agent interrupted")
    monkeypatch.setattr(hunt_run, "Investigator", FakeInvestigator)
    FakeInvestigator.result = {
        "status": "failed", "partial": True, "stop_reason": "investigator invariant failed",
        "unworked_count": 2,
    }

    result = hunt_run.resume_hunt(settings, "h1")

    assert result["execution_state"] == "failed"
    assert hunt_run.open_repo(settings).get_hunt("h1")["execution_state"] == "failed"


def test_expansion_exception_is_audited_and_finishes_hunt_partial(tmp_path, monkeypatch):
    settings = Settings(agent_mode="off", home=tmp_path)
    repo = _new_hunt(settings)
    repo.save_candidate({
        "id": "F-anchor", "hunt_id": "h1", "rule_id": "host.test", "rule_version": "1",
        "claim": "test anchor", "claim_type": "observed_action", "event_ids": [],
        "predicate_fields": [], "entities": [["host", "web1", "host"]], "ts": START,
        "severity": "high", "confidence": "high", "lane": "high", "priority": 1.0,
        "priority_reasons": [], "gate_results": {}, "benign_alternatives": [], "next_checks": [],
        "source_case_id": None, "source_anchor_id": None, "source_link_id": None,
    })
    repo.save_expansion_anchor({
        "id": "F-anchor", "hunt_id": "h1", "candidate_id": "F-anchor", "depth": 0,
        "parent_anchor_id": None, "host": "web1", "lane": "high", "severity": "high",
        "ts": START, "status": "pending", "reasons": [],
    })
    monkeypatch.setattr(hunt_run, "Sweep", FakeSweep)
    monkeypatch.setattr(
        hunt_run, "_run_expansion",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("expansion exploded")),
    )

    result = hunt_run.run_hunt(settings, "h1")

    stored = hunt_run.open_repo(settings)
    assert result["execution_state"] == "partial"
    assert result["expansion"]["status"] == "failed"
    assert stored.expansion_anchors("h1")[0]["status"] == "unexpanded"
    assert stored.expansion_anchors("h1")[0]["reasons"] == ["expansion error"]
    audit = stored.latest_audit("h1", "hunt.expansion_summary")["detail"]
    assert audit["status"] == "failed"
    assert audit["error"] == "expansion exploded"


def test_no_expand_preserves_the_nonempty_sweep_only_finding_set(tmp_path, monkeypatch):
    settings = Settings(agent_mode="off", home=tmp_path)
    repo = hunt_run.open_repo(settings)
    manifest = _manifest()
    manifest.update({"agent_mode": "off", "expansion": {"enabled": False}})
    repo.create_hunt("h-no-expand", manifest, "digest", "test")
    repo.save_candidate({
        "id": "sweep-only", "hunt_id": "h-no-expand", "rule_id": "host.test", "rule_version": "1",
        "claim": "sweep finding", "claim_type": "observed_action", "event_ids": [],
        "predicate_fields": [], "entities": [["host", "web1", "host"]], "ts": START,
        "severity": "high", "confidence": "high", "lane": "high", "priority": 1.0,
        "priority_reasons": [], "gate_results": {}, "benign_alternatives": [], "next_checks": [],
        "source_case_id": None, "source_anchor_id": None, "source_link_id": None,
    })
    sweep_only = [{key: row[key] for key in ("rule_id", "claim", "event_ids", "lane")}
                  for row in repo.candidates("h-no-expand")]
    monkeypatch.setattr(hunt_run, "Sweep", FakeSweep)

    result = hunt_run.run_hunt(settings, "h-no-expand", expand=False)

    after = hunt_run.open_repo(settings)
    findings = [{key: row[key] for key in ("rule_id", "claim", "event_ids", "lane")}
                for row in after.candidates("h-no-expand")]
    assert findings == sweep_only
    assert result["expansion"]["status"] == "disabled"
    assert after.expansion_anchors("h-no-expand") == []


def test_cli_status_shows_completed_hunt_and_agent_partial_pivots(monkeypatch, capsys, tmp_path):
    settings = Settings(agent_mode="model", home=tmp_path)
    repo = _new_hunt(settings)
    repo.claim_hunt("h1", 60)
    repo.audit("system", "hunt.agent_summary", "h1", {
        "status": "completed", "mode": "model", "partial": True, "partial_pivots": 1, "unworked_count": 1,
        "deterministic_fallbacks": 1,
        "analyst_flags": [{"case_id": "case-1", "reason": "analyst review required"}],
    })
    repo.set_hunt_state("h1", "completed_within_scope",
                        detection_result="no_qualifying_observation_in_assessed_scope")
    monkeypatch.setattr(cli, "load_settings", lambda _path: settings)

    code = cli.main(["hunt", "status", "h1"])

    output = capsys.readouterr().out
    assert code == 0
    assert "completed_within_scope" in output
    assert "agent=completed" in output
    assert "unworked=1" in output
    assert "partial_pivots=1" in output
    assert "mode=model" in output
    assert "fallbacks=1" in output
    assert "analyst_flags=1" in output


def test_cli_exposes_hunt_resume_and_prints_result(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(cli, "load_settings", lambda _path: Settings(agent_mode="model", home=tmp_path))
    monkeypatch.setattr(hunt_run, "resume_hunt", lambda _settings, hunt_id: {
        "hunt_id": hunt_id, "execution_state": "completed_within_scope",
        "agent": {"status": "completed", "unworked_count": 0},
    })

    code = cli.main(["--json", "hunt", "resume", "h1"])

    assert code == 0
    assert '"hunt_id": "h1"' in capsys.readouterr().out


@pytest.mark.parametrize(
    ("flags", "expected"),
    [(["--agent-mode", "deterministic"], "deterministic"), (["--no-agent"], "off")],
)
def test_cli_maps_agent_mode_and_no_agent_alias(monkeypatch, capsys, tmp_path, flags, expected):
    settings = Settings(agent_mode="model", home=tmp_path, es_index_patterns=["logs-*"])
    seen = {}
    monkeypatch.setattr(cli, "load_settings", lambda _path: settings)
    monkeypatch.setattr(hunt_run, "create_hunt", lambda *_args, **_kwargs: "h1")

    def fake_run(_settings, _hunt_id, **kwargs):
        seen.update(kwargs)
        return {
            "execution_state": "completed_within_scope", "detection_result": "leads_only",
            "lanes": {}, "stats": {}, "agent": {"status": "completed"},
        }

    monkeypatch.setattr(hunt_run, "run_hunt", fake_run)

    code = cli.main(["hunt", "start", "--start", START.isoformat(), "--end",
                     (START + timedelta(hours=1)).isoformat(), *flags])

    assert code == 0
    assert seen["agent_mode"] == expected
    capsys.readouterr()


def test_cli_status_shows_expansion_and_packet_accounting_when_the_agent_is_off(monkeypatch, capsys, tmp_path):
    settings = Settings(agent_mode="off", home=tmp_path)
    repo = _new_hunt(settings)
    repo.claim_hunt("h1", 60)
    repo.audit("system", "hunt.agent_summary", "h1", {"status": "disabled", "unworked_count": 9})
    repo.audit("system", "hunt.packet_summary", "h1", {"status": "partial", "responses": 12, "matched": 2})
    repo.audit("system", "hunt.expansion_summary", "h1", {
        "status": "completed", "anchors": 3, "expanded_complete": 1, "expanded_partial": 2, "unexpanded": [],
        "source_queries": 40})
    repo.set_hunt_state("h1", "partial", detection_result="reportable_findings")
    monkeypatch.setattr(cli, "load_settings", lambda _path: settings)

    assert cli.main(["hunt", "status", "h1"]) == 0
    output = capsys.readouterr().out
    assert "expansion=completed anchors=3 (complete 1, partial 2, unexpanded 0) queries=40" in output
    assert "packets=partial responses=12 matched=2" in output
    assert "agent=off" in output and "unworked=" not in output


def test_default_and_no_expand_hunts_have_identical_sweep_findings(tmp_path, monkeypatch):
    """Expansion adds findings; it never changes, adds to or removes what the sweep found (review minor)."""
    from romulus.evidence.typed import RawRef, TypedEvent, fv
    from romulus.hunt.pivot import PivotEventBatch, PivotExecutor
    from romulus.sources.profile import contract_from_types

    def exec_event(event_id, ts, argv):
        return TypedEvent(id=event_id, family="process_exec", ts=ts, host="web1",
                          fields={"process.executable": fv(argv[0], f"{event_id}:exe"),
                                  "process.argv": fv(argv, f"{event_id}:argv"), "process.pid": fv(10, f"{event_id}:pid")},
                          raw=[RawRef(target="host-x", native_id=event_id, digest="d")], normalizer="test@1")

    shell = exec_event("shell", START + timedelta(minutes=10), ["/bin/sh", "-c", "id"])
    cred = exec_event("cred", START + timedelta(minutes=11), ["/usr/bin/cat", "/etc/shadow"])

    class PublishingSweep(FakeSweep):
        def __init__(self, repo, client, hunt_id, *args, **kwargs):
            super().__init__()
            self.repo, self.hunt_id = repo, hunt_id

        def finalize(self):
            self.repo.save_evidence(self.hunt_id, [shell], {}, None)
            self.repo.save_candidate({
                "id": f"{self.hunt_id}-sweep", "hunt_id": self.hunt_id, "rule_id": "host.web_shell",
                "rule_version": "1", "claim": "web service spawned a shell", "claim_type": "observed_action",
                "event_ids": [shell.id], "predicate_fields": [], "entities": [["host", "web1", "host"]],
                "ts": shell.ts, "severity": "critical", "confidence": "high", "lane": "urgent", "priority": 100.0,
                "priority_reasons": [], "gate_results": {}, "benign_alternatives": [], "next_checks": [],
                "group_key": "web1|shell", "source_case_id": None, "source_anchor_id": None,
                "source_link_id": None,
            })

    class HostSource:
        def __init__(self, repo, client, hunt_id, contracts, *args, owner_token=None, source_query_budget=None,
                     **kwargs):
            self.repo, self.hunt_id, self.owner_token = repo, hunt_id, owner_token
            self.contracts = {"host-x": contract_from_types("host-x", {
                "@timestamp": "date", "event.dataset": "keyword", "host.name": "keyword"})}
            self.dataset_inventory, self.source_queries, self.source_query_budget = {}, 0, source_query_budget

        def _intents(self, request):
            return PivotExecutor._intents(self, request)

        def fetch_intents(self, owner, fetch_key, intents, retain, **kwargs):
            self.source_queries += len(intents)
            hits = [e for e in (cred,) if retain(e)]
            self.repo.save_evidence(self.hunt_id, hits, {}, None, owner_token=self.owner_token)
            return PivotEventBatch(status="complete", task_ids=[], events=hits, raw_sources={}, coverage=[],
                                   reasons=[], duration_ms=1)

    monkeypatch.setattr(hunt_run, "Sweep", PublishingSweep)
    monkeypatch.setattr(hunt_run, "PivotExecutor", HostSource)
    settings = Settings(agent_mode="off", home=tmp_path)
    repo = hunt_run.open_repo(settings)
    for hunt_id, expand in (("h-default", True), ("h-sweep-only", False)):
        manifest = _manifest()
        manifest.update({"agent_mode": "off", "expansion": {"enabled": expand, "max_source_queries": 40}})
        repo.create_hunt(hunt_id, manifest, "digest", "test")
        hunt_run.run_hunt(settings, hunt_id, expand=expand)

    def sweep_findings(hunt_id):
        out = set()
        for row in repo.candidates(hunt_id):
            if row["source_anchor_id"] is None:
                raws = sorted(ref["native_id"] for ev in repo.events_by_ids(row["event_ids"])
                              for ref in ev["event"]["raw"])
                out.add((row["rule_id"], row["group_key"], tuple(raws), row["lane"], row["claim"]))
        return out

    assert sweep_findings("h-default") == sweep_findings("h-sweep-only") != set()
    added = [row for row in repo.candidates("h-default") if row["source_anchor_id"]]
    # Expansion re-detects the linked `cat /etc/shadow` with the direct pack (host.credential_store_read) and
    # judges it in the anchored-session context (context.credential_access, an M3 context rule).
    assert {row["rule_id"] for row in added} == {"host.credential_store_read", "context.credential_access"}
    assert not [row for row in repo.candidates("h-sweep-only") if row["source_anchor_id"]]


def test_resume_refuses_a_hunt_normalized_by_another_evidence_version(tmp_path):
    settings = Settings(agent_mode="off", home=tmp_path)
    repo = hunt_run.open_repo(settings)
    manifest = _manifest()
    manifest["normalizer"] = "lab-ecs@1"
    repo.create_hunt("h-old", manifest, "digest", "test")
    with pytest.raises(RuntimeError, match="Start a new hunt"):
        hunt_run.resume_hunt(settings, "h-old")
