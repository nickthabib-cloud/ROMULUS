"""--agent-model replaces AGENT_MODEL for one run, is recorded where the configured model is, and a resume keeps the
model the hunt's agent recorded unless --force-model."""
from datetime import UTC, datetime, timedelta

import pytest

from romulus import cli
from romulus.config import Settings, with_agent_model
from romulus.hunt import run as hunt_run

ENV = "AGENT_PROVIDER=openai_compatible\nAGENT_BASE_URL=http://10.0.0.5:8000/v1\nAGENT_MODEL=configured-model\n"


def test_a_model_id_is_validated_and_replaces_the_configured_one_without_touching_the_env(tmp_path):
    env = tmp_path / ".env"
    env.write_text(ENV, encoding="utf-8")
    base = cli.load_settings(env)
    for good in ("claude-opus-5-5", "org/model:7b-q4_K_M", "a.b_c-d", "m" * 128):
        assert with_agent_model(base, good).agent_model == good
    for bad in ("", " model", "model id", "model;rm", "m" * 129, "mödel", "model\n", "$(id)"):
        with pytest.raises(ValueError, match="--agent-model"):
            with_agent_model(base, bad)
    assert with_agent_model(base, None) is base and base.agent_model == "configured-model"
    assert env.read_text(encoding="utf-8") == ENV


def test_the_hunt_records_the_overriding_model(tmp_path, monkeypatch):
    seen = {}

    def create(s, *_a, **kw):
        seen["create"] = s.agent_model
        seen["entry"] = hunt_run.ai_agent_entry(s, kw.get("ai_agent"))
        raise ValueError("stop after recording")

    monkeypatch.setattr(hunt_run, "create_hunt", create)
    env = tmp_path / ".env"
    env.write_text(ENV + f"ROMULUS_HOME={tmp_path}\n", encoding="utf-8")
    code = cli.main(["--env-file", str(env), "hunt", "start", "--start", "2024-11-18T10:00:00Z",
                     "--end", "2024-11-18T11:00:00Z", "--agent", "--agent-model", "override-model"])
    assert code == cli.EXIT_FAIL                     # the injected stop, after the model was recorded
    assert seen["create"] == "override-model"
    assert seen["entry"]["requested"] is True and seen["entry"]["model"] == "override-model"
    assert "override-model" not in env.read_text(encoding="utf-8")


def test_a_malformed_model_id_is_a_usage_error(tmp_path, capsys):
    env = tmp_path / ".env"
    env.write_text(ENV, encoding="utf-8")
    assert cli.main(["--env-file", str(env), "doctor", "--agent-model", "bad model"]) == cli.EXIT_USAGE
    assert cli.main(["--env-file", str(env), "hunt", "status", "--agent-model", "x;y"]) == cli.EXIT_USAGE
    assert cli.main(["--env-file", str(env), "hunt", "status", "--force-model"]) == cli.EXIT_USAGE
    assert "--agent-model" in capsys.readouterr().err


def test_doctor_checks_the_overriding_model(tmp_path, monkeypatch):
    seen = []
    monkeypatch.setattr("romulus.doctor.run_all", lambda s, _env, **_kw: seen.append(s.agent_model) or [])
    env = tmp_path / ".env"
    env.write_text(ENV, encoding="utf-8")
    assert cli.main(["--env-file", str(env), "doctor", "--agent-model", "override-model"]) == cli.EXIT_OK
    assert cli.main(["--env-file", str(env), "doctor"]) == cli.EXIT_OK
    assert seen == ["override-model", "configured-model"]


def test_the_provider_is_built_for_the_overriding_model():
    from romulus.agent.provider import build_provider
    s = with_agent_model(Settings(agent_provider="openai_compatible", agent_base_url="http://10.0.0.5:8000/v1",
                                  agent_model="configured-model"), "override-model")
    provider = build_provider(s, resolver=lambda _host: ["10.0.0.5"])
    assert provider.model == "override-model" and provider.describe()["model"] == "override-model"


def _hunt(tmp_path, *, requested=True, recorded="recorded-model", run_model=None):
    settings = Settings(home=tmp_path, agent_model="configured-model")
    repo = hunt_run.open_repo(settings)
    now = datetime.now(UTC)
    repo.create_hunt("h1", {"window": {"start": now.isoformat(), "end": (now + timedelta(hours=1)).isoformat()},
                            "targets": [], "ai_agent": {"requested": requested, "model": recorded}}, "d", "test")
    token = repo.claim_hunt("h1", 600)["lease_owner"]
    repo.audit("system", "hunt.sweep_summary", "h1", {"finished": True, "complete": True}, owner_token=token)
    repo.set_hunt_state("h1", "completed_within_scope", owner_token=token, detection_result="leads_only")
    repo.save_agent_run({"hunt_id": "h1", "state": "partial", "reason": "provider_unavailable", "prompt_digests": {},
                         "provider": {"model": run_model} if run_model else {}, "started_at": None,
                         "ended_at": None})
    return settings, repo


def _resumable(monkeypatch):
    """Resume up to its source preflight, which fails: enough to show whether the model check let it through."""
    reached = []

    def preflight(*_a, **_kw):
        reached.append(True)
        raise OSError("source offline")
    monkeypatch.setattr(hunt_run, "ensure_site_unchanged", lambda *_a, **_kw: None)
    monkeypatch.setattr(hunt_run, "install_for_hunt", lambda *_a, **_kw: None)
    monkeypatch.setattr(hunt_run, "ElasticClient", lambda *_a, **_kw: object())
    monkeypatch.setattr(hunt_run, "_contracts", preflight)
    return reached


def test_resume_refuses_another_model_than_the_hunt_recorded(tmp_path, monkeypatch):
    settings, repo = _hunt(tmp_path, run_model="ran-model")
    reached = _resumable(monkeypatch)
    assert hunt_run.recorded_agent_model(repo, repo.get_hunt("h1")) == "ran-model"   # what ran, over what was planned
    with pytest.raises(hunt_run.AgentModelMismatch, match="--agent-model ran-model"):
        hunt_run.resume_hunt(settings, "h1")
    with pytest.raises(hunt_run.AgentModelMismatch):
        hunt_run.resume_hunt(with_agent_model(settings, "other-model"), "h1")
    assert reached == [] and repo.agent_run("h1")["lease_owner"] is None
    hunt_run.resume_hunt(with_agent_model(settings, "ran-model"), "h1")
    hunt_run.resume_hunt(with_agent_model(settings, "other-model"), "h1", force_model=True)
    assert reached == [True, True]


def test_resume_compares_with_the_manifest_model_when_the_agent_never_ran_and_ignores_unrequested_agents(
        tmp_path, monkeypatch):
    settings, _repo = _hunt(tmp_path)
    _resumable(monkeypatch)
    with pytest.raises(hunt_run.AgentModelMismatch, match="recorded-model"):
        hunt_run.resume_hunt(settings, "h1")
    other = tmp_path / "off"
    other.mkdir()
    settings, _repo = _hunt(other, requested=False)
    reached = _resumable(monkeypatch)
    hunt_run.resume_hunt(settings, "h1")         # not refused for its model: the agent was never requested
    assert reached == [True]


def test_the_cli_reports_a_model_mismatch_and_accepts_force(tmp_path, monkeypatch, capsys):
    settings, _repo = _hunt(tmp_path, run_model="ran-model")
    reached = _resumable(monkeypatch)
    monkeypatch.setattr(cli, "load_settings", lambda _env: settings)
    assert cli.main(["hunt", "resume", "h1"]) == cli.EXIT_FAIL
    assert "used model ran-model" in capsys.readouterr().err and reached == []
    assert cli.main(["hunt", "resume", "h1", "--agent-model", "ran-model"]) == cli.EXIT_OK
    assert cli.main(["hunt", "resume", "h1", "--agent-model", "new-model", "--force-model"]) == cli.EXIT_OK
    assert reached == [True, True]
