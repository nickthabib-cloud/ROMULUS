"""Agent leases preserve completed detection, including failure and resume boundaries."""
from datetime import UTC, datetime, timedelta
from threading import Event
from types import SimpleNamespace

import pytest

from romulus.config import Settings
from romulus.hunt import run as hunt_run
from romulus.hunt.expansion import ExpansionEngine
from romulus.sources.models import Window
from tests.test_report import _repo_with_finding


def _hunt(tmp_path, *, requested=True):
    settings = Settings(home=tmp_path)
    repo = hunt_run.open_repo(settings)
    now = datetime.now(UTC)
    repo.create_hunt("h1", {"window": {"start": now.isoformat(), "end": (now + timedelta(hours=1)).isoformat()},
                            "targets": [], "ai_agent": {"requested": requested}}, "d", "test")
    token = repo.claim_hunt("h1", 600)["lease_owner"]
    repo.audit("system", "hunt.sweep_summary", "h1", {"finished": True, "complete": True},
               owner_token=token)
    return settings, repo, token


def test_finish_prepares_recoverable_agent_work_without_leaving_detection_running(tmp_path):
    _settings, repo, token = _hunt(tmp_path)
    result = hunt_run._finish(repo, "h1", {"status": "pending"}, {"finished": True, "complete": True},
                             owner_token=token, pending_agent_owner_token="agent-owner",
                             pending_agent_lease_seconds=600)
    assert result["execution_state"] == "completed_within_scope"
    assert repo.get_hunt("h1")["lease_owner"] is None
    pending = repo.agent_run("h1")
    assert pending["state"] == "pending" and pending["lease_owner"] == "agent-owner"
    assert repo.hunts_with_live_lease() == ["h1"]
    with pytest.raises(RuntimeError, match="lease"):
        repo.claim_agent_lease("h1", 600)


def test_template_failure_cannot_undo_completed_detection(tmp_path, monkeypatch):
    settings, repo, token = _hunt(tmp_path, requested=False)
    fixture, cid = _repo_with_finding()
    lead = {**fixture.candidate(cid), "id": "deterministic-lead", "lane": "lead",
            "event_ids": [], "context_event_ids": []}
    lead.pop("created_at", None)
    repo.save_candidate(lead, owner_token=token)
    fixture.engine.dispose()
    repo.set_hunt_state("h1", "completed_within_scope", owner_token=token,
                        detection_result="leads_only", stop_reason="frontier complete")
    monkeypatch.setattr(hunt_run, "skip_agent_phase", lambda *_a, **_kw: (_ for _ in ()).throw(OSError("template disk")))
    result = hunt_run._ai_agent_phase(settings, repo, "h1", repo.get_hunt("h1")["manifest"], None, None, {})
    assert result["status"] == "failed" and "OSError" in result["reason"]
    stored = repo.get_hunt("h1")
    assert (stored["execution_state"], stored["detection_result"], stored["stop_reason"]) == (
        "completed_within_scope", "leads_only", "frontier complete")
    assert repo.agent_run("h1")["state"] == "failed"
    assert repo.agent_run("h1")["lease_owner"] is None


def test_agent_resume_preflight_keeps_detection_and_prior_agent_state(tmp_path, monkeypatch):
    settings, repo, token = _hunt(tmp_path)
    repo.set_hunt_state("h1", "completed_within_scope", owner_token=token,
                        detection_result="leads_only", stop_reason="frontier complete")
    repo.save_agent_run({"hunt_id": "h1", "state": "partial", "reason": "provider_unavailable",
                         "prompt_digests": {}, "provider": {}, "started_at": None, "ended_at": None})
    seen = []
    def preflight(*_args, **_kwargs):
        seen.append(repo.get_hunt("h1")["execution_state"])
        raise OSError("source offline")
    monkeypatch.setattr(hunt_run, "ensure_site_unchanged", lambda *_a, **_kw: None)
    monkeypatch.setattr(hunt_run, "install_for_hunt", lambda *_a, **_kw: None)
    monkeypatch.setattr(hunt_run, "ElasticClient", lambda *_a, **_kw: object())
    monkeypatch.setattr(hunt_run, "_contracts", preflight)
    result = hunt_run.resume_hunt(settings, "h1")
    assert seen == ["completed_within_scope"]
    assert result["execution_state"] == "completed_within_scope"
    assert repo.agent_run("h1")["state"] == "partial"
    assert repo.agent_run("h1")["reason"] == "provider_unavailable"
    assert repo.agent_run("h1")["lease_owner"] is None


def test_background_heartbeat_keeps_one_blocking_call_owned(tmp_path, monkeypatch):
    from romulus.store import repo as repo_module
    _settings, repo, token = _hunt(tmp_path)
    now = datetime.now(UTC)
    clock = {"now": now}
    monkeypatch.setattr(repo_module, "utcnow", lambda: clock["now"])
    repo.set_hunt_state("h1", "completed_within_scope", owner_token=token)
    owner = repo.claim_agent_lease("h1", 1, now=now)["lease_owner"]
    renewed = Event()
    original = repo.heartbeat_agent_lease
    ticks = []
    def heartbeat(*args, **kwargs):
        clock["now"] += timedelta(seconds=0.4)
        row = original(*args, **kwargs)
        ticks.append(clock["now"])
        if len(ticks) >= 3:
            renewed.set()
        return row
    monkeypatch.setattr(repo, "heartbeat_agent_lease", heartbeat)
    with hunt_run._agent_heartbeat(repo, "h1", owner, 1):
        assert renewed.wait(5), "heartbeat must continue while the caller is blocked"
        assert clock["now"] > now + timedelta(seconds=1)
        assert repo.hunts_with_live_lease(now=clock["now"]) == ["h1"]
        with pytest.raises(RuntimeError, match="lease"):
            repo.claim_agent_lease("h1", 1, now=clock["now"])
    assert repo.get_hunt("h1")["execution_state"] == "completed_within_scope"


def test_resumed_expansion_does_not_seed_agent_provenance_findings():
    repo, cid = _repo_with_finding()
    finding = repo.candidate(cid)
    agent = {**finding, "id": "agent-extra", "provenance": "agent", "source_case_id": None,
             "rule_id": "agent.finding"}
    agent.pop("created_at", None)
    repo.save_candidate(agent)
    stamp = finding["ts"].replace(tzinfo=UTC)
    window = Window(start=stamp - timedelta(hours=1), end=stamp + timedelta(hours=1))
    engine = ExpansionEngine(repo, "h1", window, SimpleNamespace())
    engine._seed_candidates([finding], [])
    before = repo.expansion_anchors("h1")
    engine._seed_candidates([finding, agent], before)
    assert repo.expansion_anchors("h1") == before


def test_retention_maintenance_keeps_material_under_a_live_agent_lease():
    from romulus.hunt.baseline_writer import run_hunt_segment_writer
    from tests.test_baseline_writer_hours import SPEC, _repo, _retained_hunt
    repo = _repo()
    _retained_hunt(repo, "busy", 5)
    repo.set_hunt_state("busy", "completed_within_scope")
    repo.claim_agent_lease("busy", 600)
    _retained_hunt(repo, "other", 5)
    run_hunt_segment_writer(repo, "other", hunt_partial=True, retain_budget_bytes=1)
    assert repo.baseline_window_material_pairs("busy") == [(SPEC.id, "host-index")]


def test_reassessment_refuses_a_hunt_with_a_live_detection_lease(tmp_path, monkeypatch, capsys):
    from romulus import cli
    from romulus.agent import provider as provider_port
    from romulus.report import manifest as report_manifest
    settings, _repo, _token = _hunt(tmp_path)
    monkeypatch.setattr(cli, "load_settings", lambda *_args: settings)
    monkeypatch.setattr(provider_port, "agent_readiness", lambda *_args:
                        SimpleNamespace(ready=False, message=lambda: "offline"))
    monkeypatch.setattr(report_manifest, "publish_revision", lambda *_a, **_kw: {"revision": {"number": 1}})
    assert cli.main(["agent", "reassess", "h1"]) == cli.EXIT_FAIL
    assert "lease" in capsys.readouterr().err


def test_partial_detection_resume_keeps_prior_agent_progress_when_provider_is_not_ready(tmp_path, monkeypatch):
    settings, repo, token = _hunt(tmp_path)
    repo.set_hunt_state("h1", "partial", owner_token=token, detection_result="leads_only")
    repo.save_agent_run({"hunt_id": "h1", "state": "partial", "reason": "provider_unavailable",
                         "prompt_digests": {}, "provider": {}, "started_at": None, "ended_at": None})
    monkeypatch.setattr(hunt_run, "ensure_site_unchanged", lambda *_a, **_kw: None)
    monkeypatch.setattr(hunt_run, "install_for_hunt", lambda *_a, **_kw: None)
    monkeypatch.setattr(hunt_run, "ElasticClient", lambda *_a, **_kw: object())
    monkeypatch.setattr(hunt_run, "_contracts", lambda *_a, **_kw: {})
    for name in ("_packet_stage", "_baseline_stage", "_run_expansion_safely"):
        monkeypatch.setattr(hunt_run, name, lambda *_a, **_kw: {"finished": True, "status": "complete"})
    monkeypatch.setattr(hunt_run, "agent_readiness", lambda *_a:
                        SimpleNamespace(ready=False, message=lambda: "offline", provenance=lambda _s: {}))
    result = hunt_run.resume_hunt(settings, "h1")
    assert result["execution_state"] == "completed_within_scope"
    assert repo.agent_run("h1")["state"] == "partial"
    assert repo.agent_run("h1")["reason"] == "provider_unavailable"
    assert repo.agent_run("h1")["lease_owner"] is None


def test_failed_agent_claim_never_uses_an_unfenced_failure_write(tmp_path):
    settings, repo, token = _hunt(tmp_path, requested=False)
    repo.set_hunt_state("h1", "completed_within_scope", owner_token=token)
    repo.claim_agent_lease("h1", 600, owner_token="other-worker")
    before = repo.agent_run("h1")
    hunt_run._ai_agent_phase(settings, repo, "h1", repo.get_hunt("h1")["manifest"], None, None, {})
    assert repo.agent_run("h1") == before


def test_hunt_resume_recovers_pending_handoff_only_after_lease_expiry(tmp_path, monkeypatch):
    from romulus.agent.provider.base import ToolCall
    from romulus.store import repo as repo_module
    from tests.agent_scripted import ScriptedProvider, response
    settings, repo, token = _hunt(tmp_path)
    hunt_run._finish(repo, "h1", {"status": "pending"}, {"finished": True, "complete": True},
                     owner_token=token, pending_agent_owner_token="killed-worker",
                     pending_agent_lease_seconds=600)
    monkeypatch.setattr(hunt_run, "ensure_site_unchanged", lambda *_a, **_kw: None)
    monkeypatch.setattr(hunt_run, "install_for_hunt", lambda *_a, **_kw: None)
    monkeypatch.setattr(hunt_run, "ElasticClient", lambda *_a, **_kw: object())
    monkeypatch.setattr(hunt_run, "_contracts", lambda *_a, **_kw: {})
    monkeypatch.setattr(hunt_run, "agent_readiness", lambda *_a: SimpleNamespace(ready=True))
    body = {"overall": [], "key_steps": [], "confidence": {"overall": "low", "reasons": []},
            "alternatives": [], "gaps": [], "next_checks": []}
    provider = ScriptedProvider([
        response(tool_calls=[ToolCall("finish", "finish_session", {"summary": "Review finished."}, "{}")]),
        response(parsed=body),
    ])
    monkeypatch.setattr(hunt_run, "build_provider", lambda *_a, **_kw: provider)
    with pytest.raises(RuntimeError, match="active lease"):
        hunt_run.resume_hunt(settings, "h1")
    expired = repo.agent_run("h1")["lease_until"].replace(tzinfo=UTC) + timedelta(seconds=1)
    monkeypatch.setattr(repo_module, "utcnow", lambda: expired)
    result = hunt_run.resume_hunt(settings, "h1")
    assert result["execution_state"] == "completed_within_scope"
    assert result["detection_result"] == "no_qualifying_observation_in_assessed_scope"
    assert repo.agent_run("h1")["state"] == "completed"
    assert repo.agent_run("h1")["lease_owner"] is None
    assert len(provider.requests) == 2


def test_duplicate_iterator_releases_the_previous_batch_before_materializing_next(monkeypatch):
    from weakref import WeakValueDictionary

    from romulus.store import repo as repo_module
    from romulus.store import schema
    repo, cid = _repo_with_finding()
    template = repo.candidate(cid)
    with repo.engine.begin() as connection:
        connection.execute(schema.candidate.insert(), [
            {**template, "id": f"overlap-{index:04d}", "event_ids": ["shared"]} for index in range(1001)
        ])
    live = WeakValueDictionary()
    peak = [0]
    class TrackedRow(dict):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            live[id(self)] = self
            peak[0] = max(peak[0], len(live))
    monkeypatch.setattr(repo_module, "dict", TrackedRow, raising=False)
    batches = repo.candidate_duplicate_batches("h1", ["shared"], ["high"])
    seen = 0
    while True:
        try:
            batch = next(batches)
        except StopIteration:
            break
        seen += len(batch)
        del batch
    assert seen == 1001
    assert peak[0] <= 500


def test_finalization_cannot_change_canonical_deterministic_projection():
    from romulus.report.manifest import canonical_manifest
    repo, _cid = _repo_with_finding()
    owner = repo.claim_agent_lease("h1", 600)["lease_owner"]
    repo.finalize_agent_run("h1", {"state": "skipped", "reason": "not_requested"}, owner_token=owner)
    before = canonical_manifest(repo, "h1")
    owner = repo.claim_agent_lease("h1", 600)["lease_owner"]
    repo.finalize_agent_run("h1", {"state": "completed", "reason": None}, owner_token=owner)
    after = canonical_manifest(repo, "h1")
    assert {key: value for key, value in before.items() if key != "ai"} == {
        key: value for key, value in after.items() if key != "ai"}


def test_stored_finalization_recovers_without_source_or_provider_access(tmp_path, monkeypatch):
    from romulus.store import repo as repo_module
    settings, repo, token = _hunt(tmp_path)
    repo.set_hunt_state("h1", "completed_within_scope", owner_token=token,
                        detection_result="leads_only", stop_reason="frontier complete")
    owner = repo.claim_agent_lease("h1", 600)["lease_owner"]
    repo.save_agent_run({"hunt_id": "h1", "state": "running", "reason": None}, owner_token=owner)
    now = datetime.now(UTC)
    repo.save_agent_session({"id": "finished-assess", "hunt_id": "h1", "hypothesis_id": None,
                             "purpose": "assess", "state": "finished", "tool_calls": 0,
                             "summary": "Assessment stored.", "started_at": now - timedelta(seconds=2),
                             "ended_at": now}, owner_token=owner)
    repo.save_agent_assessment({"id": "stored-assessment", "hunt_id": "h1", "revision": 1,
                                "source": "agent", "model": {}, "body": {}, "checker": {},
                                "created_at": now - timedelta(seconds=1)}, owner_token=owner)
    fixture, cid = _repo_with_finding()
    high = {**fixture.candidate(cid), "id": "pivot-deterministic-high", "event_ids": [], "context_event_ids": []}
    high.pop("created_at", None)
    repo.save_candidate(high, owner_token=owner)
    fixture.engine.dispose()
    expired = repo.agent_run("h1")["lease_until"].replace(tzinfo=UTC) + timedelta(seconds=1)
    monkeypatch.setattr(repo_module, "utcnow", lambda: expired)
    monkeypatch.setattr(hunt_run, "ensure_site_unchanged", lambda *_a, **_kw: None)
    monkeypatch.setattr(hunt_run, "install_for_hunt", lambda *_a, **_kw: None)
    def unavailable(*_args, **_kwargs):
        raise AssertionError("local finalization must not access an external dependency")
    monkeypatch.setattr(hunt_run, "_contracts", unavailable)
    monkeypatch.setattr(hunt_run, "agent_readiness", unavailable)
    monkeypatch.setattr(hunt_run, "ElasticClient", unavailable)
    result = hunt_run.resume_hunt(settings, "h1")
    assert result["execution_state"] == "completed_within_scope"
    assert result["detection_result"] == "reportable_findings"
    assert repo.agent_run("h1")["state"] == "partial"
    assert repo.agent_run("h1")["reason"] == "recovered_finished_sessions"


@pytest.mark.parametrize("state", ["planned", "running", "failed"])
def test_reassessment_never_publishes_a_result_for_unfinished_detection(tmp_path, monkeypatch, capsys, state):
    from romulus import cli
    from romulus.agent import provider as provider_port
    from romulus.report import manifest as report_manifest
    from romulus.store import repo as repo_module
    settings, repo, token = _hunt(tmp_path)
    if state == "planned":
        repo.create_hunt("h2", {"window": repo.get_hunt("h1")["manifest"]["window"], "targets": [],
                                "ai_agent": {"requested": True}}, "d", "test")
        hunt_id = "h2"
    else:
        hunt_id = "h1"
        if state == "failed":
            repo.set_hunt_state("h1", "failed", owner_token=token, stop_reason="sweep error: source offline")
        else:
            # A crashed sweep: the detection lease lapsed with the hunt still running.
            later = datetime.now(UTC) + timedelta(seconds=601)
            monkeypatch.setattr(repo_module, "utcnow", lambda: later)
    monkeypatch.setattr(cli, "load_settings", lambda *_args: settings)
    monkeypatch.setattr(provider_port, "agent_readiness", lambda *_args:
                        SimpleNamespace(ready=False, message=lambda: "offline"))
    published = []
    monkeypatch.setattr(report_manifest, "publish_revision",
                        lambda _repo, hid, *_a, **_kw: published.append(hid) or {"revision": {"number": 1}})
    assert cli.main(["agent", "reassess", hunt_id]) == cli.EXIT_FAIL
    assert "detection finishes" in capsys.readouterr().err
    hunt = repo.get_hunt(hunt_id)
    assert hunt["execution_state"] == state and hunt["detection_result"] is None
    assert published == [] and repo.agent_run(hunt_id) is None


def test_finalization_refuses_to_write_a_result_over_unfinished_detection(tmp_path):
    _settings, repo, token = _hunt(tmp_path)
    repo.set_hunt_state("h1", "completed_within_scope", owner_token=token, detection_result="leads_only")
    owner = repo.claim_agent_lease("h1", 600)["lease_owner"]
    # Detection is resumed underneath the agent's (lapsed) claim; the stale worker must not finalize.
    with repo.engine.begin() as connection:
        from romulus.store import schema as t
        connection.execute(t.hunt.update().where(t.hunt.c.id == "h1").values(execution_state="running",
                                                                               detection_result=None))
    with pytest.raises(RuntimeError, match="no detection result"):
        repo.finalize_agent_run("h1", {"state": "partial", "reason": "provider_not_ready"}, owner_token=owner)
    assert repo.get_hunt("h1")["detection_result"] is None


def test_heartbeat_rides_out_a_busy_database_but_not_a_lost_fence(tmp_path, monkeypatch):
    from sqlalchemy.exc import OperationalError
    _settings, repo, token = _hunt(tmp_path)
    repo.set_hunt_state("h1", "completed_within_scope", owner_token=token)
    owner = repo.claim_agent_lease("h1", 600)["lease_owner"]
    original = repo.heartbeat_agent_lease
    outcomes = ["busy", "ok", "lost"]
    def heartbeat(*args, **kwargs):
        outcome = outcomes.pop(0)
        if outcome == "busy":
            raise OperationalError("UPDATE agent_run", {}, Exception("database is locked"))
        if outcome == "lost":
            raise RuntimeError("hunt h1 agent lease ownership lost")
        return original(*args, **kwargs)
    monkeypatch.setattr(repo, "heartbeat_agent_lease", heartbeat)
    with hunt_run._agent_heartbeat(repo, "h1", owner, 600) as guard:
        guard()  # busy with most of the lease left: deferred, still owned
        guard()  # renewed
        with pytest.raises(RuntimeError, match="ownership lost"):
            guard()
        with pytest.raises(RuntimeError, match="ownership lost"):
            guard()  # a lost fence stays lost


def test_heartbeat_treats_a_busy_database_without_margin_as_lost(tmp_path, monkeypatch):
    from sqlalchemy.exc import OperationalError
    _settings, repo, token = _hunt(tmp_path)
    repo.set_hunt_state("h1", "completed_within_scope", owner_token=token)
    owner = repo.claim_agent_lease("h1", 600)["lease_owner"]
    clock = {"now": 1000.0}
    monkeypatch.setattr(hunt_run, "monotonic", lambda: clock["now"])
    def busy(*_args, **_kwargs):
        raise OperationalError("UPDATE agent_run", {}, Exception("database is locked"))
    monkeypatch.setattr(repo, "heartbeat_agent_lease", busy)
    with hunt_run._agent_heartbeat(repo, "h1", owner, 600) as guard:
        clock["now"] += 401  # less than a third of the lease is left
        with pytest.raises(OperationalError):
            guard()
        with pytest.raises(RuntimeError, match="ownership lost"):
            guard()
