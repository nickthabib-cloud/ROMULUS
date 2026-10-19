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
    settings = Settings(home=tmp_path)
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
    settings = Settings(home=tmp_path)
    _new_hunt(settings)
    monkeypatch.setattr(hunt_run, "_contracts", lambda *_args: (_ for _ in ()).throw(RuntimeError("mapping down")))

    with pytest.raises(RuntimeError, match="mapping down"):
        hunt_run.run_hunt(settings, "h1")

    repo = hunt_run.open_repo(settings)
    assert repo.get_hunt("h1")["execution_state"] == "failed"
    assert repo.get_hunt("h1")["lease_until"] is None
    assert repo.latest_audit("h1", "hunt.sweep_summary")["detail"]["finished"] is False


def test_resume_preflight_failure_does_not_leave_a_live_running_lease(tmp_path, monkeypatch):
    settings = Settings(home=tmp_path)
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
    settings = Settings(home=tmp_path)
    repo = _new_hunt(settings)
    repo.claim_hunt("h1", lease_seconds=600)
    repo.audit("system", "hunt.sweep_summary", "h1", {"finished": True, "complete": True})

    with pytest.raises(RuntimeError, match="active lease"):
        hunt_run.resume_hunt(settings, "h1")


def test_resume_refuses_running_hunt_without_finished_sweep_summary(tmp_path):
    settings = Settings(home=tmp_path)
    repo = _new_hunt(settings)
    repo.claim_hunt("h1", lease_seconds=1, now=START)

    with pytest.raises(RuntimeError, match="sweep did not finish"):
        hunt_run.resume_hunt(settings, "h1")


def test_resume_reclaims_expired_running_lease(tmp_path, monkeypatch):
    settings = Settings(home=tmp_path)
    repo = _new_hunt(settings)
    repo.claim_hunt("h1", lease_seconds=1, now=START)
    repo.audit("system", "hunt.sweep_summary", "h1", {"finished": True, "complete": True})
    monkeypatch.setattr(hunt_run, "Investigator", FakeInvestigator)
    FakeInvestigator.result = {"status": "completed", "partial": False, "stop_reason": "done", "unworked_count": 0}

    hunt_run.resume_hunt(settings, "h1")

    assert hunt_run.open_repo(settings).latest_audit("h1", "hunt.resume_stale") is not None


def test_failed_hunt_resume_requires_proof_that_sweep_finished(tmp_path, monkeypatch):
    settings = Settings(home=tmp_path)
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
    settings = Settings(home=tmp_path)
    repo = _new_hunt(settings)
    repo.claim_hunt("h1", 1, now=START)
    repo.set_hunt_state("h1", "partial", stop_reason="legacy interruption")
    monkeypatch.setattr(hunt_run, "Investigator", FakeInvestigator)
    FakeInvestigator.result = {"status": "completed", "partial": False, "stop_reason": "done", "unworked_count": 0}

    result = hunt_run.resume_hunt(settings, "h1")

    assert result["execution_state"] == "partial"
    assert "sweep summary missing" in hunt_run.open_repo(settings).get_hunt("h1")["stop_reason"]


def test_agent_budget_exhaustion_does_not_make_complete_sweep_partial(tmp_path, monkeypatch):
    settings = Settings(home=tmp_path)
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
    settings = Settings(home=tmp_path)
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


def test_cli_status_shows_completed_hunt_and_agent_partial_pivots(monkeypatch, capsys, tmp_path):
    settings = Settings(home=tmp_path)
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
    monkeypatch.setattr(cli, "load_settings", lambda _path: Settings(home=tmp_path))
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
    settings = Settings(home=tmp_path, es_index_patterns=["logs-*"])
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
