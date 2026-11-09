"""Hunt-level guarantees for the independent persisted agent phase."""
from datetime import UTC, datetime

from romulus.config import Settings
from romulus.hunt import run as hunt_run


def _repo(tmp_path):
    settings = Settings(home=tmp_path)
    repo = hunt_run.open_repo(settings)
    repo.create_hunt("h1", {"window": {"start": datetime.now(UTC).isoformat(), "end": datetime.now(UTC).isoformat()},
                              "targets": [], "ai_agent": {"requested": True}}, "d", "test")
    return settings, repo


def test_agent_failure_does_not_change_completed_deterministic_hunt(tmp_path):
    _settings, repo = _repo(tmp_path)
    token = repo.claim_hunt("h1", 600)["lease_owner"]
    repo.audit("system", "hunt.sweep_summary", "h1", {"finished": True, "complete": True}, owner_token=token)

    result = hunt_run._finish(repo, "h1", {"status": "failed", "reason": "provider_unavailable"},
                             {"finished": True, "complete": True},
                             ai_agent_summary={"status": "failed", "reason": "provider_unavailable"},
                             owner_token=token)

    stored = repo.get_hunt("h1")
    assert result["execution_state"] == "completed_within_scope"
    assert stored["execution_state"] == "completed_within_scope"
    assert stored["detection_result"] == "no_qualifying_observation_in_assessed_scope"
    assert "provider_unavailable" not in stored["stop_reason"]


def test_completed_hunt_resume_runs_only_a_resumable_agent_phase(tmp_path, monkeypatch):
    settings, repo = _repo(tmp_path)
    token = repo.claim_hunt("h1", 600)["lease_owner"]
    repo.audit("system", "hunt.sweep_summary", "h1", {"finished": True, "complete": True, "stats": {}},
               owner_token=token)
    repo.set_hunt_state("h1", "completed_within_scope", owner_token=token,
                        detection_result="no_qualifying_observation_in_assessed_scope", stop_reason="frontier complete")
    repo.save_agent_run({"hunt_id": "h1", "state": "partial", "reason": "provider_unavailable",
                         "prompt_digests": {}, "provider": {}, "started_at": datetime.now(UTC),
                         "ended_at": datetime.now(UTC)})
    stages = []
    monkeypatch.setattr(hunt_run, "ensure_site_unchanged", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(hunt_run, "install_for_hunt", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(hunt_run, "ElasticClient", lambda _settings: object())
    monkeypatch.setattr(hunt_run, "_contracts", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(hunt_run, "_ai_agent_phase", lambda *_args, **_kwargs:
                        stages.append("agent") or {"status": "completed", "unworked": []})
    monkeypatch.setattr(hunt_run, "_run_expansion_safely", lambda *_args, **_kwargs:
                        stages.append("expansion") or {})
    monkeypatch.setattr(hunt_run, "_baseline_stage", lambda *_args, **_kwargs:
                        stages.append("baseline") or {})
    monkeypatch.setattr(hunt_run, "_packet_stage", lambda *_args, **_kwargs:
                        stages.append("packets") or {})
    monkeypatch.setattr(hunt_run, "Sweep", lambda *_args, **_kwargs: (_ for _ in ()).throw(
        AssertionError("agent-only resume must not rerun the sweep")))

    result = hunt_run.resume_hunt(settings, "h1")

    assert stages == ["agent"]
    assert result["execution_state"] == "completed_within_scope"
    stored = hunt_run.open_repo(settings).get_hunt("h1")
    assert stored["detection_result"] == "no_qualifying_observation_in_assessed_scope"
    assert stored["stop_reason"] == "frontier complete"
