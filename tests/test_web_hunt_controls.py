"""The web controls on a hunt: the start form's agent budget, extending it, stopping a hunt or its agent, force
stop. Every POST checks the CSRF token and the account's role as the database has it."""
import re
from datetime import timedelta

from romulus.agent import hunt_budget
from romulus.store import schema as t
from romulus.store.db import utcnow
from tests import test_web_agent_a6
from tests.test_web_hunt_tabs import _login_analyst

setup = test_web_agent_a6.setup
csrf = test_web_agent_a6.csrf


def _running(repo, created_by="cli:web:analyst", agent=True):
    with repo.engine.begin() as connection:
        manifest = dict(connection.execute(t.hunt.select().where(t.hunt.c.id == "h1")).mappings().one()["manifest"])
        manifest["ai_agent"] = {**(manifest.get("ai_agent") or {}), "requested": agent}
        connection.execute(t.hunt.update().where(t.hunt.c.id == "h1").values(
            manifest=manifest, created_by=created_by, execution_state="running", lease_owner="worker",
            lease_until=utcnow() + timedelta(minutes=10)))


def test_every_control_post_needs_the_csrf_token(setup):
    client, repo, *_ = setup
    _running(repo)
    for path, data in (("/hunts/h1/stop", {"scope": "hunt"}), ("/hunts/h1/force-stop", {"confirm": "h1"}),
                       ("/hunts/h1/extend", {"calls": "5"})):
        assert client.post(path, data=data, follow_redirects=False).status_code == 403
        assert client.post(path, data={**data, "csrf": "wrong"}, follow_redirects=False).status_code == 403
    assert repo.latest_stop("h1") is None and repo.agent_budget_extensions("h1") == []


def test_a_lead_stops_any_hunt_and_an_analyst_only_their_own(setup):
    client, repo, _cid, _settings, _app, password = setup
    _running(repo, created_by="cli:web:someone-else")
    _login_analyst(client, password)
    token = csrf(client)
    refused = client.post("/hunts/h1/stop", data={"csrf": token, "scope": "hunt"}, follow_redirects=False)
    assert refused.status_code == 403 and repo.latest_stop("h1") is None
    _running(repo, created_by="cli:web:analyst")
    done = client.post("/hunts/h1/stop", data={"csrf": token, "scope": "agent"}, follow_redirects=False)
    assert done.status_code == 303 and done.headers["location"].startswith("/hunts/h1/run?control=")
    row = repo.latest_stop("h1")
    assert row["scope"] == "agent" and row["requested_by"] == "web:analyst"
    assert repo.latest_audit("h1", "hunt.stop_requested")["actor"] == "web:analyst"
    page = client.get("/hunts/h1/run").text
    assert 'id="stop-banner"' in page and "Stop of the AI agent requested by web:analyst" in page
    # force stop is a lead's: refused for the analyst whatever the hunt
    forced = client.post("/hunts/h1/force-stop", data={"csrf": token, "confirm": "h1"}, follow_redirects=False)
    assert forced.status_code == 403


def test_a_demoted_lead_loses_the_controls_at_once(setup):
    client, repo, *_ = setup
    _running(repo, created_by="cli:web:someone-else")
    with repo.engine.begin() as connection:
        connection.execute(t.user.update().where(t.user.c.username == "lead").values(role="analyst"))
    response = client.post("/hunts/h1/stop", data={"csrf": csrf(client), "scope": "hunt"}, follow_redirects=False)
    assert response.status_code == 403


def test_force_stop_waits_for_the_grace_period(setup):
    client, repo, *_ = setup
    _running(repo)
    token = csrf(client)
    assert client.post("/hunts/h1/stop", data={"csrf": token, "scope": "hunt"}, follow_redirects=False).status_code == 303
    early = client.post("/hunts/h1/force-stop", data={"csrf": token, "confirm": "h1"}, follow_redirects=False)
    assert early.status_code == 409 and "force stop is possible after" in early.text
    assert client.post("/hunts/h1/force-stop", data={"csrf": token, "confirm": "nope"},
                       follow_redirects=False).status_code == 400


def test_extend_is_held_to_the_ceiling_by_role_and_shows_on_the_run_page(setup, monkeypatch):
    client, repo, _cid, settings, _app, password = setup
    _running(repo, created_by="cli:web:analyst")
    spawned = []
    monkeypatch.setattr(test_web_agent_a6.web.subprocess, "Popen", lambda *a, **k: spawned.append(a))
    _login_analyst(client, password)
    token = csrf(client)
    too_much = settings.agent_max_calls * int(settings.agent_budget_ceiling_multiplier) + 1
    refused = client.post("/hunts/h1/extend", data={"csrf": token, "calls": str(too_much)}, follow_redirects=False)
    assert refused.status_code == 403 and "only a lead" in refused.text
    assert client.post("/hunts/h1/extend", data={"csrf": token, "calls": "-1"},
                       follow_redirects=False).status_code == 400
    done = client.post("/hunts/h1/extend", data={"csrf": token, "calls": "25", "minutes": "30"},
                       follow_redirects=False)
    assert done.status_code == 303 and "extended_running" in done.headers["location"]
    assert spawned == []                                     # the running agent picks it up; nothing is started
    row = repo.agent_budget_extensions("h1")[-1]
    assert row["amounts"] == {"max_calls": 25, "max_wall_seconds": 1800} and row["added_by"] == "web:analyst"
    page = client.get("/hunts/h1/run").text
    assert 'id="controls"' in page and "Budget extensions (1)" in page and "max_calls +25" in page


def test_the_start_form_offers_profiles_and_hands_the_checked_budget_to_the_hunt_process(setup, monkeypatch):
    client, repo, _cid, settings, _app, password = setup
    form = client.get("/hunts/new").text
    assert 'name="effort"' in form and "Advanced limits" in form
    spawned = []
    monkeypatch.setattr(test_web_agent_a6.web.subprocess, "Popen", lambda cmd, **k: spawned.append(cmd))
    data = {"start": "2024-11-18T10:00:00Z", "end": "2024-11-18T11:00:00Z", "effort": "deep",
            "max_calls": str(settings.agent_max_calls * 20), "csrf": csrf(client)}
    assert client.post("/hunts", data=data, follow_redirects=False).status_code == 303     # a lead may go above
    command = spawned[-1]
    grant = command[command.index("--budget-grant") + 1]
    stored = repo.consume_budget_grant(grant, max_age_seconds=600)
    assert stored["role"] == "lead" and stored["choice"]["profile"] == "deep"
    assert stored["choice"]["overrides"] == {"max_calls": settings.agent_max_calls * 20}
    assert repo.consume_budget_grant(grant, max_age_seconds=600) is None                  # read once
    _login_analyst(client, password)
    refused = client.post("/hunts", data={**data, "csrf": csrf(client)}, follow_redirects=False)
    assert refused.status_code == 400 and "only a lead" in refused.text
    assert len(spawned) == 1
    assert client.post("/hunts", data={**data, "csrf": csrf(client), "effort": "huge", "max_calls": ""},
                       follow_redirects=False).status_code == 400


def test_the_run_page_shows_the_pinned_budget_and_a_legacy_hunts_source(setup):
    client, repo, *_ = setup
    page = client.get("/hunts/h1/run").text
    assert re.search(r"Controls and agent budget", page)
    assert "created before agent budgets were pinned" in page
    with repo.engine.begin() as connection:
        manifest = dict(connection.execute(t.hunt.select().where(t.hunt.c.id == "h1")).mappings().one()["manifest"])
        from romulus.config import Settings
        manifest["ai_agent"] = {"requested": True, "budgets": hunt_budget.pinned_block(
            hunt_budget.choose(Settings(), "quick", role="analyst", chosen_by="web:lead"))}
        connection.execute(t.hunt.update().where(t.hunt.c.id == "h1").values(manifest=manifest))
    page = client.get("/hunts/h1/run").text
    assert "profile quick" in page and "created before agent budgets were pinned" not in page
