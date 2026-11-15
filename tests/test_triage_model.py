"""The triage pass's own model (--agent-model, else AGENT_TRIAGE_MODEL, else AGENT_MODEL), recorded apart from the
agent's, and a forced resume's model switch recorded in the audit trail and the manifest."""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from romulus import cli, doctor
from romulus.agent import provider as provider_port
from romulus.config import Settings, load_settings, triage_model, triage_settings, with_agent_model
from romulus.hunt import run as hunt_run
from romulus.hunt.triage import run_triage
from romulus.report.manifest import _ai_agent, build_manifest
from tests.test_ai_triage import (
    FakeTriage,
    _hunt,
    _stage,  # noqa: F401 - stages under each test's own directory
    by_rule,
    settings,
)
from tests.test_cli_agent_model import _hunt as _agent_hunt
from tests.test_cli_agent_model import _resumable


def test_the_triage_model_is_the_flag_then_the_setting_then_the_agent_model(tmp_path):
    base = Settings(agent_model="agent-model")
    assert triage_model(base) == ("agent-model", "AGENT_MODEL")
    assert triage_settings(base) is base
    configured = Settings(agent_model="agent-model", agent_triage_model="triage-model")
    assert triage_model(configured) == ("triage-model", "AGENT_TRIAGE_MODEL")
    assert triage_settings(configured).agent_model == "triage-model"
    assert triage_model(configured, "flag-model") == ("flag-model", "--agent-model")
    assert configured.agent_model == "agent-model"                     # the agent's model is never touched
    with pytest.raises(ValueError, match="--agent-model"):
        triage_model(configured, "bad model")
    with pytest.raises(ValidationError, match="AGENT_TRIAGE_MODEL"):
        Settings(agent_triage_model="model;rm")
    env = tmp_path / ".env"
    env.write_text("AGENT_MODEL=agent-model\nAGENT_TRIAGE_MODEL=triage-model\n", encoding="utf-8")
    loaded = load_settings(env, environ={})
    assert (loaded.agent_model, loaded.agent_triage_model) == ("agent-model", "triage-model")


class NamedTriage(FakeTriage):
    def __init__(self, model: str):
        super().__init__(by_rule({"r.attack"}))
        self.model = model


def _ready(monkeypatch) -> tuple[list, list]:
    checked, built = [], []
    monkeypatch.setattr(provider_port, "agent_readiness",
                        lambda s, *_a: checked.append(s.agent_model) or SimpleNamespace(ready=True,
                                                                                       model=s.agent_model))
    monkeypatch.setattr(provider_port, "build_provider",
                        lambda s, **_kw: built.append(NamedTriage(s.agent_model)) or built[-1])
    return checked, built


def test_the_pass_runs_on_its_model_and_records_it_apart_from_the_agents(monkeypatch):
    repo = _hunt(filler=10)
    agent_before = repo.agent_run("h1")
    checked, built = _ready(monkeypatch)
    s = settings(agent_model="agent-model", agent_triage_model="triage-model")
    first = run_triage(s, repo, "h1")
    assert checked == ["triage-model"] and [p.model for p in built] == ["triage-model"]
    assert first["status"] == "complete" and first["model"] == "triage-model"
    assert first["model_source"] == "AGENT_TRIAGE_MODEL" and first["provider"]["model"] == "triage-model"
    # a readiness checked for the agent's model is checked again for the triage model
    second = run_triage(s, repo, "h1", model="flag-model", readiness=SimpleNamespace(ready=True, model="agent-model"))
    assert checked == ["triage-model", "flag-model"] and built[-1].model == "flag-model"
    assert (second["model"], second["model_source"]) == ("flag-model", "--agent-model")
    assert second["prompt_digest"] != first["prompt_digest"]          # the model is part of the prompt digest
    view = build_manifest(repo, "h1", "test")["ai_triage"]
    assert (view["model"], view["model_source"]) == ("flag-model", "--agent-model")
    assert repo.agent_run("h1")["provider"] == agent_before["provider"]


def test_the_cli_flag_overrides_the_triage_model_for_one_run(tmp_path, monkeypatch, capsys):
    from romulus.hunt.run import open_repo
    for name in ("ROMULUS_HOME", "ROMULUS_STAGE_DIR", "AGENT_MODEL", "AGENT_TRIAGE_MODEL"):
        monkeypatch.delenv(name, raising=False)
    home = tmp_path / "home"
    env = tmp_path / "test.env"
    text = f"ROMULUS_HOME={home}\nAGENT_MODEL=agent-model\nAGENT_TRIAGE_MODEL=triage-model\n"
    env.write_text(text, encoding="utf-8")
    _hunt(filler=10, repo=open_repo(Settings(home=home)))
    assert cli.main(["--env-file", str(env), "triage", "h1", "--agent-model", "bad model"]) == cli.EXIT_USAGE
    assert "--agent-model" in capsys.readouterr().err
    _checked, built = _ready(monkeypatch)
    assert cli.main(["--env-file", str(env), "--json", "triage", "h1", "--agent-model", "flag-model"]) == cli.EXIT_OK
    summary = json.loads(capsys.readouterr().out)
    assert [p.model for p in built] == ["flag-model"] and summary["model"] == "flag-model"
    assert cli.main(["--env-file", str(env), "triage", "h1"]) == cli.EXIT_OK
    assert [p.model for p in built] == ["flag-model", "triage-model"]
    assert env.read_text(encoding="utf-8") == text


def test_doctor_checks_the_triage_model_only_when_it_differs(monkeypatch):
    seen = []
    monkeypatch.setattr(doctor, "check_agent", lambda s, *_a: seen.append(s.agent_model) or [
        doctor.Check("agent.provider", "ok", f"model {s.agent_model}"), doctor.Check("agent.model", "fail", "no")])
    assert doctor.check_triage_model(Settings(agent_model="agent-model")) == []
    assert doctor.check_triage_model(Settings(agent_model="m", agent_triage_model="m")) == []
    checks = doctor.check_triage_model(Settings(agent_model="agent-model", agent_triage_model="triage-model"))
    assert seen == ["triage-model"]
    assert [(c.name, c.status) for c in checks] == [("triage.provider", "ok"), ("triage.model", "fail")]
    assert all(c.detail.startswith("AGENT_TRIAGE_MODEL=triage-model: ") for c in checks)


def test_a_forced_resume_records_the_switch_and_the_manifest_lists_it(tmp_path, monkeypatch):
    s, repo = _agent_hunt(tmp_path, run_model="ran-model")
    reached = _resumable(monkeypatch)
    with pytest.raises(hunt_run.AgentModelMismatch):                    # refused: nothing switched, nothing recorded
        hunt_run.resume_hunt(with_agent_model(s, "other-model"), "h1")
    hunt_run.resume_hunt(with_agent_model(s, "ran-model"), "h1")       # the same model: no switch
    assert repo.latest_audit("h1", "hunt.agent_model_forced") is None
    hunt_run.resume_hunt(with_agent_model(s, "other-model"), "h1", force_model=True)
    assert reached == [True, True]
    audit = repo.latest_audit("h1", "hunt.agent_model_forced")
    assert audit["detail"] == {"from": "ran-model", "to": "other-model"}
    hunt = repo.get_hunt("h1")
    forced = _ai_agent(repo, "h1", hunt["manifest"])["model_forced"]
    assert forced["total"] == 1 and forced["switches"][0]["from"] == "ran-model"
    assert forced["switches"][0]["to"] == "other-model"


def test_the_automatic_pass_after_the_agent_runs_on_the_triage_model(monkeypatch):
    repo = _hunt(filler=10)
    checked, built = _ready(monkeypatch)
    monkeypatch.setattr(hunt_run, "agent_readiness", lambda s, *_a: SimpleNamespace(ready=True, model=s.agent_model))
    monkeypatch.setattr(hunt_run, "build_provider", lambda s, **_kw: built.append(NamedTriage(s.agent_model))
                        or built[-1])
    s = settings(agent_model="agent-model", agent_triage_model="triage-model")
    result = hunt_run._with_agent_result({"hunt_id": "h1"}, repo, {"status": "completed"}, settings=s,
                                         manifest={"ai_agent": {"requested": True}})
    assert checked == ["triage-model"] and [p.model for p in built] == ["triage-model"]
    assert result["ai_triage"]["model"] == "triage-model"
    assert result["ai_triage"]["model_source"] == "AGENT_TRIAGE_MODEL"


def test_dropped_triage_items_are_recorded_by_field_and_reason_without_their_values():
    sentinel = "SENTINELq7triage"
    repo = _hunt(filler=10)

    def policy(cards):
        items = [{"group_id": f"G-{sentinel}", "assessment": "likely_attack", "incident_label": None,
                  "rationale": "r", "cites": []}]
        for n, card in enumerate(cards):
            item = {"group_id": card["group"], "assessment": "likely_benign", "incident_label": None,
                    "rationale": "Evidence on the card.", "cites": []}
            if n == 0:
                item["incident_label"] = f"Bad {sentinel}"
            elif n == 1:
                item["rationale"] = sentinel * 40
            elif n == 2:
                item["cites"] = [sentinel]
            items.append(item)
        return {"groups": items}
    summary = run_triage(settings(), repo, "h1", provider=FakeTriage(policy))
    assert summary["dropped"]["bad_incident_label"] and summary["dropped"]["unknown_group"]
    rows = [row for row in repo.model_calls(hunt_id="h1") if row["purpose"] == "triage"]
    reasons = rows[0]["validation"]["reasons"]
    assert {"groups[].incident_label: pattern_mismatch", "groups[].rationale: too_long",
            "groups[].cites[]: foreign_citation", "groups[].group_id: unknown_group"} <= set(reasons)
    assert sentinel not in json.dumps([row["validation"] for row in rows])
