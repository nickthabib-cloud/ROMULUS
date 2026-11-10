"""Fenced recovery and local-only template completion after detection finishes."""
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy import event

from romulus import cli
from romulus.agent import provider as provider_port
from romulus.config import Settings
from romulus.hunt import run as hunt_run
from romulus.report import manifest as report_manifest
from romulus.store import schema as t
from tests.agent_scripted import ScriptedProvider, response
from tests.test_report import _repo_with_finding


def _crashed(repo, *, sessions=1):
    now = datetime.now(UTC)
    repo.save_agent_run({"hunt_id": "h1", "state": "running", "lease_owner": "crashed",
        "lease_until": now - timedelta(seconds=1), "started_at": now - timedelta(minutes=5)})
    for index in range(sessions):
        repo.save_agent_session({"id": f"old-{index:03}", "hunt_id": "h1", "purpose": "investigate",
            "state": "running", "tool_calls": 0, "summary": "", "started_at": now - timedelta(minutes=1)})


def test_reassess_closes_crashed_sessions_and_preserves_partial_investigation(tmp_path, monkeypatch):
    repo, _ = _repo_with_finding()
    _crashed(repo)
    monkeypatch.setattr(hunt_run, "open_repo", lambda _s: repo)
    monkeypatch.setattr(cli, "load_settings", lambda _path: Settings(home=tmp_path))
    monkeypatch.setattr(provider_port, "agent_readiness", lambda _s: SimpleNamespace(ready=True))
    body = {"overall": [], "key_steps": [], "confidence": {"overall": "low", "reasons": []},
            "alternatives": [], "gaps": [], "next_checks": []}
    monkeypatch.setattr(provider_port, "build_provider", lambda *_a, **_kw: ScriptedProvider([response(parsed=body)]))
    monkeypatch.setattr(report_manifest, "publish_revision", lambda *_a, **_kw: {"revision": {"number": 1}})
    assert cli.main(["agent", "reassess", "h1"]) == 0
    old = next(s for s in repo.agent_sessions("h1") if s["id"] == "old-000")
    assert old["state"] == "interrupted" and old["ended_at"] is not None
    assert repo.agent_run("h1")["state"] == "partial"
    assert repo.agent_run("h1")["reason"] == "interrupted_by_reassessment"
    assert not report_manifest._ai_assessment(repo, "h1").get("stale")
    assert repo.latest_audit("h1", "agent.recovered_for_reassessment")["detail"]["session_ids"] == ["old-000"]
    assert repo.get_hunt("h1")["execution_state"] == "partial"


def test_recovery_is_fenced_atomic_bounded_and_hunt_scoped():
    from romulus.store.agent_recovery import recover_for_reassessment
    repo, _ = _repo_with_finding()
    _crashed(repo, sessions=105)
    repo.create_hunt("other", {}, "d", "test")
    repo.save_agent_session({"id": "other-session", "hunt_id": "other", "purpose": "orient", "state": "running",
        "tool_calls": 0, "summary": "", "started_at": datetime.now(UTC)})
    owner = repo.claim_agent_lease("h1", 600)["lease_owner"]
    with pytest.raises(RuntimeError, match="ownership lost"):
        recover_for_reassessment(repo, "h1", "loser")
    def crash(_c, _cursor, statement, _parameters, _context, _many):
        if statement.startswith("INSERT INTO audit_event"):
            raise OSError("crash inside recovery")
    event.listen(repo.engine, "before_cursor_execute", crash)
    with pytest.raises(OSError, match="crash inside"):
        recover_for_reassessment(repo, "h1", owner)
    event.remove(repo.engine, "before_cursor_execute", crash)
    assert {s["state"] for s in repo.agent_sessions("h1")} == {"running"}
    assert repo.agent_run("h1")["state"] == "running"
    assert repo.latest_audit("h1", "agent.recovered_for_reassessment") is None
    assert recover_for_reassessment(repo, "h1", owner) is True
    assert {s["state"] for s in repo.agent_sessions("h1")} == {"interrupted"}
    assert repo.agent_sessions("other")[0]["state"] == "running"
    detail = repo.latest_audit("h1", "agent.recovered_for_reassessment")["detail"]
    assert detail["session_count"] == 105
    assert len(detail["session_ids"]) == 100
    assert recover_for_reassessment(repo, "h1", owner) is False
    with pytest.raises(RuntimeError, match="active lease"):
        repo.claim_agent_lease("h1", 600)


@pytest.mark.parametrize("requested,broken_config", [(False, False), (True, False), (True, True)])
def test_pending_template_resume_needs_no_sources_and_keeps_deterministic_digest(tmp_path, monkeypatch, requested, broken_config):
    repo, _ = _repo_with_finding()
    hunt = repo.get_hunt("h1")
    manifest = {**hunt["manifest"], "ai_agent": {"requested": requested}}
    # Capture the durable handoff a killed worker leaves after _finish.
    with repo.engine.begin() as connection:
        connection.execute(t.hunt.update().where(t.hunt.c.id == "h1").values(manifest=manifest))
    repo.audit("system", "hunt.sweep_summary", "h1", {"finished": True, "complete": True})
    token = repo.claim_hunt("h1", 600, resume=True)["lease_owner"]
    hunt_run._finish(repo, "h1", {"status": "disabled", "mode": "off"}, {"finished": True, "complete": True},
                     owner_token=token, pending_agent_owner_token="crashed", pending_agent_lease_seconds=600)
    monkeypatch.setattr(hunt_run, "open_repo", lambda _s: repo)
    monkeypatch.setattr(hunt_run, "ensure_site_unchanged", lambda *_a: None)
    monkeypatch.setattr(hunt_run, "install_for_hunt", lambda *_a: None)
    monkeypatch.setattr(hunt_run, "NORMALIZER_VERSION", "n")
    readiness = SimpleNamespace(ready=False, message=lambda: "offline", provenance=lambda _s: {})
    def resolve(_s):
        if broken_config:
            raise ValueError("unusable provider configuration")
        return readiness
    monkeypatch.setattr(hunt_run, "agent_readiness", resolve)
    def offline(*_a, **_kw):
        raise AssertionError("source must not be contacted")
    monkeypatch.setattr(hunt_run, "ElasticClient", offline)
    monkeypatch.setattr(hunt_run, "_contracts", offline)
    before = report_manifest.canonical_manifest(repo, "h1")
    before.pop("ai", None)
    settings = Settings(home=tmp_path)
    with pytest.raises(RuntimeError, match="active lease"):
        hunt_run.resume_hunt(settings, "h1")
    with repo.engine.begin() as connection:
        connection.execute(t.agent_run.update().where(t.agent_run.c.hunt_id == "h1").values(
            lease_until=datetime.now(UTC) - timedelta(seconds=1)))
    result = hunt_run.resume_hunt(settings, "h1")
    assert result["execution_state"] == "completed_within_scope"
    assert repo.agent_run("h1")["state"] == "skipped"
    assert repo.agent_assessments("h1")[-1]["source"] == "template"
    after = report_manifest.canonical_manifest(repo, "h1")
    after.pop("ai", None)
    assert after == before


def test_pending_ready_agent_still_performs_source_preflight(tmp_path, monkeypatch):
    from tests.test_agent_lifecycle_r2 import _hunt
    settings, repo, token = _hunt(tmp_path)
    hunt_run._finish(repo, "h1", {}, {"finished": True, "complete": True}, owner_token=token)
    repo.save_agent_run({"hunt_id": "h1", "state": "pending"})
    monkeypatch.setattr(hunt_run, "ensure_site_unchanged", lambda *_a: None)
    monkeypatch.setattr(hunt_run, "install_for_hunt", lambda *_a: None)
    monkeypatch.setattr(hunt_run, "agent_readiness", lambda _s: SimpleNamespace(ready=True))
    monkeypatch.setattr(hunt_run, "ElasticClient", lambda _s: object())
    calls = []
    def preflight(*_a, **_kw):
        calls.append(1)
        raise OSError("source down")
    monkeypatch.setattr(hunt_run, "_contracts", preflight)
    result = hunt_run.resume_hunt(settings, "h1")
    assert calls == [1]
    assert "source preflight failed" in result["ai_agent"]["reason"]
    assert repo.agent_run("h1")["state"] == "pending"
