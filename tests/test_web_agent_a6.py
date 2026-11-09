"""Authenticated, bounded AI views and mutation-aware live activity."""
import asyncio
import json
import re
import secrets
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import select

from romulus.agent.provider import AgentReadiness
from romulus.config import Settings
from romulus.store import schema as t
from romulus.store.db import utcnow
from romulus.web import app as web
from romulus.web.auth import create_user
from tests.test_report import _repo_with_finding


@pytest.fixture
def setup(tmp_path, monkeypatch):
    settings = Settings(home=tmp_path, secret_key=secrets.token_urlsafe(32))
    repo = web.open_repo(settings)
    source, cid = _repo_with_finding()
    with source.engine.connect() as read, repo.engine.begin() as write:
        for table in (t.hunt, t.raw_record, t.typed_event, t.candidate):
            rows = [dict(row) for row in read.execute(select(table)).mappings()]
            if rows:
                write.execute(table.insert(), rows)
    source.engine.dispose()
    monkeypatch.setattr(web, "open_repo", lambda _: repo)
    app = web.create_app(settings, tmp_path / "settings.env")
    password = secrets.token_urlsafe(20)
    create_user(repo.engine, "lead", password, "lead")
    create_user(repo.engine, "analyst", password, "analyst")
    client = TestClient(app)
    client.post("/login", data={"username": "lead", "password": password})
    yield client, repo, cid, settings, app, password
    repo.engine.dispose()


def csrf(client):
    return re.search(r'name="csrf" value="([^"]+)"', client.get("/hunts/new").text).group(1)


def run_row(repo, state="completed", **changes):
    row = {"hunt_id": "h1", "state": state, "reason": None, "prompt_digests": {},
           "provider": {"provider": "scripted", "model": "requested-model"}, "started_at": utcnow(),
           "ended_at": None, "updated_at": utcnow(), **changes}
    repo.save_agent_run(row)


def hypothesis(repo, hid="hyp1", hunt="h1", **changes):
    now = utcnow()
    repo.create_agent_hypothesis({"id": hid, "hunt_id": hunt, "statement": "Review <script>alert(1)</script>",
        "techniques": ["T1059"], "entity_ids": [], "status": "open", "confidence": "low",
        "questions": ["What is <img onerror=x> ?"], "sessions_run": 0,
        "created_at": now, "updated_at": now, **changes},
        {"id": "he-" + hid, "hunt_id": hunt, "hypothesis_id": hid, "kind": "opened", "session_id": None,
         "payload": {"statement": "<script>hostile</script>"}, "created_at": now})


@pytest.mark.parametrize("state,default,checked", [("ready", "on", True), ("ready", "off", False),
    ("not_configured", "on", False), ("blocked", "on", False)])
def test_new_form_readiness_defaults(setup, monkeypatch, state, default, checked):
    client, _, _, settings, _, _ = setup
    settings.agent_default = default
    monkeypatch.setattr(web, "agent_readiness", lambda _: AgentReadiness(state, "reason-for-readiness", "scripted", "new-model"))
    body = client.get("/hunts/new").text
    box = re.search(r'<input[^>]+name="agent"[^>]*>', body).group()
    assert ("checked" in box) is checked
    assert ("disabled" in box) is (state != "ready")
    assert "scripted/new-model" in body
    if state != "ready":
        assert "reason-for-readiness" in body


def test_new_form_remote_banner_and_unready_post_still_preserves_request(setup, monkeypatch):
    client, _, _, settings, _, _ = setup
    from romulus.agent import provider

    settings.agent_base_url = "https://203.0.113.10/v1"
    settings.agent_model = "remote-model"
    settings.agent_api_key = SecretStr("key-for-test")
    settings.model_egress = "lab-public-data"
    monkeypatch.setattr(provider, "build_provider", lambda *a, **kw: pytest.fail("page must not construct a provider"))
    body = client.get("/hunts/new").text
    assert "remote endpoint 203.0.113.10" in body and "remote-model" in body
    assert body.index("Model egress:") < body.index('type="submit">Start hunt')
    settings.agent_model = ""
    launched = []
    monkeypatch.setattr(web.subprocess, "Popen", lambda cmd, **kw: launched.append(cmd))
    token = csrf(client)
    response = client.post("/hunts", data={"start": "2024-01-01", "end": "2024-01-02", "agent": "model", "csrf": token},
                           follow_redirects=False)
    assert response.status_code == 303 and "--agent" in launched[0]


def test_hypotheses_are_scoped_paginated_and_escaped(setup):
    client, repo, _, _, _, _ = setup
    for index in range(51):
        hypothesis(repo, f"hyp{index:03}")
    page = client.get("/hunts/h1/hypotheses")
    assert page.status_code == 200
    assert "AI-generated hypotheses" in page.text
    assert "1 more" in page.text and "hyp049" in page.text and "hyp050" not in page.text
    assert "<script>" not in page.text and "&lt;script&gt;" in page.text
    assert "hyp050" in client.get("/hunts/h1/hypotheses?after=hyp049").text
    repo.create_hunt("other", repo.get_hunt("h1")["manifest"], "d", "test")
    assert client.get("/hunts/other/hypotheses/hyp000").status_code == 404
    assert client.get("/hunts/missing/hypotheses").status_code == 404


def test_reassess_role_csrf_guard_and_spawn(setup, monkeypatch):
    client, repo, _, settings, _, password = setup
    calls = []
    monkeypatch.setattr(web.subprocess, "Popen", lambda cmd, **kw: calls.append((cmd, kw)))
    run_row(repo)
    token = csrf(client)
    assert client.post("/hunts/h1/agent/reassess").status_code == 403
    response = client.post("/hunts/h1/agent/reassess", data={"csrf": token}, follow_redirects=False)
    assert response.status_code == 303
    cmd, kwargs = calls.pop()
    assert cmd[-3:] == ["agent", "reassess", "h1"]
    assert str(settings.home / "settings.env") in cmd
    assert kwargs["env"]["USER"] == "web:lead" and kwargs["start_new_session"]
    assert repo.latest_audit("h1", "web.agent_reassess")
    repo.set_hunt_state("h1", "running")
    response = client.post("/hunts/h1/agent/reassess", data={"csrf": token})
    assert response.status_code == 200 and repo.agent_reassessment_refusal("h1") in response.text
    assert calls == []
    client.post("/login", data={"username": "analyst", "password": password})
    assert client.post("/hunts/h1/agent/reassess", data={"csrf": csrf(client)}).status_code == 403


def test_hypothesis_detail_tool_paging_and_byte_bounded_hostile_arguments(setup):
    client, repo, cid, _, _, _ = setup
    from romulus.web.agent_views import json_text

    hypothesis(repo)
    now = utcnow()
    repo.save_agent_session({"id": "session", "hunt_id": "h1", "hypothesis_id": "hyp1",
        "purpose": "investigate", "state": "finished", "tool_calls": 101, "summary": "<img onerror=x>",
        "started_at": now, "ended_at": now})
    for index in range(101):
        repo.save_agent_tool_call({"id": f"tool{index:03}", "hunt_id": "h1", "session_id": "session", "seq": index,
            "name": "get_finding", "arguments": {"text": '<script>"雪' + "x" * (1024 * 1024 if index == 0 else 1)},
            "status": "ok", "result_digest": "d", "created_at": now})
    repo.save_agent_output("agent_note", {"id": "note", "hunt_id": "h1", "session_id": "session",
        "target_kind": "finding", "target_id": cid, "text": '<script>"雪' + "z" * 1024 * 1024,
        "cites": [{"kind": "F", "id": cid}], "suspicious_content": True, "created_at": now})
    body = client.get("/hunts/h1/hypotheses/hyp1").text
    assert "1 more" in body and "tools_after=tool099" in body
    assert "&lt;script&gt;" in body and "<script>" not in body and "[truncated]" in body
    assert len(body) < 70000
    assert "101" not in client.get("/hunts/h1/hypotheses/hyp1?session=missing").text
    assert client.get("/hunts/h1/hypotheses/hyp1?session=missing").status_code == 404
    page2 = client.get("/hunts/h1/hypotheses/hyp1?session=session&tools_after=tool099")
    assert page2.status_code == 200 and "<td>100</td>" in page2.text
    preview = json_text({"text": "雪" * 2000})
    assert len(preview.split(" … [truncated]")[0].encode()) <= 2048
    note_page = client.get(f"/findings/{cid}").text
    assert "AI-generated notes" in note_page and "suspicious content" in note_page
    assert "<script>" not in note_page and len(note_page) < 20000


def test_assessment_panel_validates_cites_and_crashed_run(setup):
    client, repo, cid, _, _, _ = setup
    run_row(repo, "running", lease_owner="expired", lease_until=utcnow() - timedelta(minutes=1),
            reason="cap:notes")
    hypothesis(repo, status="abandoned")
    now = utcnow()
    repo.save_agent_assessment({"id": "assessment", "hunt_id": "h1", "revision": 1, "source": "agent",
        "model": {"provider": "scripted", "model_requested": "requested-model"},
        "body": {"overall": [{"text": "<script>hostile</script>", "kind": "hypothesis", "cites": [
            {"kind": "F", "id": cid}, {"kind": "E", "id": "ev1"}, {"kind": "F", "id": "javascript:bad"}]}]},
        "checker": {"removed": [{"reason": "no cites"}]}, "created_at": now})
    body = client.get("/hunts/h1").text
    assert "interrupted (lease expired)" in body and "cap:notes" in body
    assert "Re-run assessment" in body and "AI-generated hypothesis" in body
    assert f'/findings/{cid}' in body and '#evidence-ev1' in body and "unresolved cite" in body
    assert "javascript:bad" not in body and "<script>" not in body
    assert "sentences removed" in body and "no cites" in body
    assert client.get(f"/findings/{cid}?event=ev1").status_code == 200
    assert client.get(f"/findings/{cid}?event=not-cited").status_code == 404
    with repo.engine.begin() as connection:
        connection.execute(t.candidate.update().where(t.candidate.c.id == cid).values(
            provenance="agent", agent_hypothesis_id="hyp1"))
    finding = client.get(f"/findings/{cid}").text
    assert "AI agent · unconfirmed" in finding and "Hypothesis (abandoned)" in finding
    assert "AI agent · unconfirmed" in client.get("/hunts/h1").text
    assert "running" in client.get("/").text


def test_reassess_live_lease_refused_and_no_longer_lead_is_refused(setup, monkeypatch):
    client, repo, _, _, _, _ = setup
    run_row(repo, "running", lease_owner="worker", lease_until=utcnow() + timedelta(minutes=10))
    monkeypatch.setattr(web.subprocess, "Popen", lambda *a, **kw: pytest.fail("must not spawn"))
    token = csrf(client)
    response = client.post("/hunts/h1/agent/reassess", data={"csrf": token})
    assert response.status_code == 200 and "lease" in response.text.lower()
    with repo.engine.begin() as connection:
        connection.execute(t.user.update().where(t.user.c.username == "lead").values(role="analyst"))
    assert client.post("/hunts/h1/agent/reassess", data={"csrf": token}).status_code == 403


class Connected:
    async def is_disconnected(self):
        return False


def unpack(message):
    lines = message.splitlines()
    return lines[0][7:], json.loads(lines[1][6:])


def test_stream_resends_mutations_and_never_materializes_candidates(setup, monkeypatch):
    _, repo, cid, _, _, _ = setup
    from romulus.web.agent_views import live_events
    run_row(repo, "pending")
    hypothesis(repo)
    now = utcnow()
    repo.save_agent_session({"id": "session", "hunt_id": "h1", "hypothesis_id": "hyp1",
        "purpose": "investigate", "state": "running", "tool_calls": 0, "summary": "",
        "started_at": now, "ended_at": None})
    monkeypatch.setattr(repo, "candidates", lambda *a, **kw: pytest.fail("unbounded candidate read"))
    sleeps = []
    async def sleep(seconds):
        sleeps.append(seconds)
        with repo.engine.begin() as connection:
            connection.execute(t.candidate.update().where(t.candidate.c.id == cid).values(claim="changed claim"))
            connection.execute(t.agent_hypothesis.update().where(t.agent_hypothesis.c.id == "hyp1").values(
                status="supported", confidence="high"))
            connection.execute(t.agent_session.update().where(t.agent_session.c.id == "session").values(
                state="finished", tool_calls=1, ended_at=utcnow()))
            connection.execute(t.agent_run.update().where(t.agent_run.c.hunt_id == "h1").values(state="completed"))
        repo.save_agent_tool_call({"id": "call", "hunt_id": "h1", "session_id": "session", "seq": 1,
            "name": "get_finding", "arguments": {"secret": "never streamed"}, "status": "ok",
            "result_digest": "d", "created_at": now})
    async def collect():
        return [unpack(value) async for value in live_events(repo, Connected(), "h1", sleep)]
    events = asyncio.run(collect())
    assert sleeps == [2]
    assert any(name == "finding" and value["claim"] == "changed claim" and value["revised"] for name, value in events)
    assert any(name == "hypothesis" and value["status"] == "supported" and value["confidence"] == "high" for name, value in events)
    assert any(name == "session" and value["state"] == "finished" and value["tool_calls"] == 1 for name, value in events)
    assert any(name == "agent_run" and value["state"] == "completed" for name, value in events)
    assert any(name == "tool_call" for name, _ in events)
    assert "never streamed" not in str(events)
    assert events[-1][0] == "end"


@pytest.mark.parametrize("finish_during_backlog", [False, True])
def test_stream_drains_over_200_changes_before_terminal_close(setup, monkeypatch, finish_during_backlog):
    _, repo, cid, _, _, _ = setup
    from romulus.web.agent_views import live_events
    run_row(repo, "pending" if finish_during_backlog else "completed")
    original = repo.candidate(cid)
    original.pop("created_at")
    for index in range(251):
        repo.save_candidate({**original, "id": f"many{index:03}"})
    page = repo.agent_change_page
    sizes = []
    def instrumented(*args, **kwargs):
        rows = page(*args, **kwargs)
        sizes.append(len(rows))
        if finish_during_backlog and len(sizes) == 1:
            run_row(repo, "completed")
        return rows
    monkeypatch.setattr(repo, "agent_change_page", instrumented)
    async def no_sleep(_):
        pytest.fail("full pages and terminal backlog must not sleep")
    async def collect():
        return [unpack(value) async for value in live_events(repo, Connected(), "h1", no_sleep)]
    events = asyncio.run(collect())
    findings = [value["id"] for name, value in events if name == "finding"]
    assert len(findings) == len(set(findings)) == 252
    assert max(sizes) == 200 and len(sizes) >= 2
    assert events[-2][0] == "state" and events[-1][0] == "end"


def test_deleted_hunt_ends_live_stream_cleanly(setup):
    _, repo, _, _, _, _ = setup
    from romulus.web.agent_views import live_events
    async def no_sleep(_):
        pytest.fail("deleted stream must close")
    async def collect():
        stream = live_events(repo, Connected(), "h1", no_sleep)
        first = await anext(stream)
        assert "event: finding" in first
        repo.delete_hunt("h1", actor="test")
        return [unpack(value) async for value in stream]
    assert asyncio.run(collect()) == [("end", {})]


def test_stream_does_not_repeat_unchanged_run_for_heartbeat(setup):
    _, repo, _, _, _, _ = setup
    from romulus.web.agent_views import live_events
    run_row(repo, "pending")
    sleeps = []
    async def sleep(_):
        sleeps.append(1)
        if len(sleeps) == 1:
            run_row(repo, "pending", lease_until=utcnow() + timedelta(minutes=10))
        else:
            run_row(repo, "completed")
    async def collect():
        return [unpack(value) async for value in live_events(repo, Connected(), "h1", sleep)]
    states = [value["state"] for name, value in asyncio.run(collect()) if name == "agent_run"]
    assert states == ["pending", "completed"]


def test_hunt_list_and_agent_findings_pages_are_keyset_bounded(setup, monkeypatch):
    client, repo, cid, _, _, _ = setup
    for index in range(51):
        repo.create_hunt(f"hunt{index:03}", repo.get_hunt("h1")["manifest"], "d", "test")
    listing = client.get("/").text
    assert "2 more" in listing and "after=hunt001" in listing and "hunt000" not in listing
    assert "hunt000" in client.get("/?after=hunt001").text
    run_row(repo)
    original = repo.candidate(cid)
    original.pop("created_at")
    for index in range(51):
        repo.save_candidate({**original, "id": f"agent{index:03}", "provenance": "agent"})
    page = client.get("/hunts/h1/agent/findings").text
    assert "1 more" in page and "agent049" in page and "agent050" not in page
    # Existing expansion accounting still reads legacy discovery rows; the new finding list must not
    # add a second full candidate read. Its own table is an independent bounded keyset projection.
    old_candidates, calls = repo.candidates, []
    def candidates(*args, **kwargs):
        calls.append(args)
        return old_candidates(*args, **kwargs)
    monkeypatch.setattr(repo, "candidates", candidates)
    detail = client.get("/hunts/h1").text
    assert "2 more" in detail and "Next findings" in detail
    assert len(calls) == 1
