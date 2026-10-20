"""Web UI: authentication, CSRF, security headers and output encoding of telemetry."""
import re
import secrets

import pytest
from fastapi.testclient import TestClient

from romulus.config import Settings
from romulus.web.app import create_app
from romulus.web.auth import create_user
from tests.test_report import T, _add_investigation, _repo_with_finding


@pytest.fixture()
def client(tmp_path, monkeypatch):
    s = Settings(home=tmp_path, secret_key=secrets.token_urlsafe(32))
    app = create_app(s)
    # seed the app's DB with a finding containing hostile text, plus a generated test account
    from romulus.hunt import run as hr
    repo = hr.open_repo(s)
    pw = secrets.token_urlsafe(18)
    create_user(repo.engine, "analyst1", pw, "analyst")
    src_repo, cid = _repo_with_finding(claim_suffix=' <script>alert(1)</script><img src=x onerror=alert(2)>')
    _add_investigation(src_repo, cid)
    src_repo.set_hunt_state("h1", "running")
    src_repo.set_hunt_state("h1", "completed_within_scope", detection_result="reportable_findings")
    # copy the seeded hunt into the app DB
    from romulus.store import schema as t
    with src_repo.engine.connect() as a, repo.engine.begin() as b:
        for table in (t.hunt, t.raw_record, t.typed_event, t.candidate, t.disposition_event,
                      t.case, t.case_step, t.model_call):
            rows = [dict(r) for r in a.execute(table.select()).mappings()]
            if rows:
                b.execute(table.insert(), rows)
    repo.audit("system", "hunt.agent_summary", "h1", {
        "status": "budget_exhausted", "mode": "model", "partial": True, "partial_pivots": 1,
        "unworked_count": 3, "model_calls": 4, "pivots": 2,
        "deterministic_fallbacks": 1,
        "analyst_flags": [{"case_id": "case-1", "reason": "Analyst review required"}],
    })
    return TestClient(app), pw, cid


def _login(c, pw):
    return c.post("/login", data={"username": "analyst1", "password": pw}, follow_redirects=False)


def _csrf(html):
    return re.search(r'name="csrf" value="([^"]+)"', html).group(1)


def test_requires_login(client):
    c, _, _ = client
    r = c.get("/", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"


def test_bad_password_rejected_and_rate_limited(client):
    c, pw, _ = client
    for _ in range(6):
        r = c.post("/login", data={"username": "analyst1", "password": "wrong-password-x"}, follow_redirects=False)
        assert "error" in r.headers["location"]
    # even the right password is refused while rate limited
    assert "error" in _login(c, pw).headers["location"]


def test_login_headers_and_escaping(client):
    c, pw, cid = client
    assert _login(c, pw).headers["location"] == "/"
    r = c.get(f"/findings/{cid}")
    assert r.status_code == 200
    assert "script-src 'self'" in r.headers["content-security-policy"]
    assert r.headers["x-frame-options"] == "DENY"
    assert "<script>alert(1)" not in r.text and "<img src=x" not in r.text
    assert "&lt;script&gt;" in r.text


def test_state_changes_need_csrf(client):
    c, pw, cid = client
    _login(c, pw)
    r = c.post(f"/findings/{cid}/disposition", data={"status": "benign", "csrf": "forged"})
    assert r.status_code == 403
    token = _csrf(c.get(f"/findings/{cid}").text)
    r = c.post(f"/findings/{cid}/disposition", data={"status": "benign", "note": "checked", "csrf": token},
               follow_redirects=False)
    assert r.status_code == 303
    assert "benign" in c.get(f"/findings/{cid}").text


def test_report_path_traversal_refused(client):
    c, pw, _ = client
    _login(c, pw)
    assert c.get("/reports/h1/..%2F..%2Fetc%2Fpasswd.md").status_code == 404
    assert c.get("/reports/h1/h1-r1.txt").status_code == 404


def test_hunt_page_shows_latest_agent_status_and_unworked_count(client):
    c, pw, _ = client
    _login(c, pw)

    page = c.get("/hunts/h1")

    assert page.status_code == 200
    assert "completed_within_scope" in page.text
    assert "budget_exhausted" in page.text
    assert "3 unworked" in page.text
    assert "1 partial pivot" in page.text
    assert "Mode model" in page.text
    assert "process_tree for host web01 pid 10" in page.text
    assert "model output failed twice; selected top-ranked pivot" in page.text
    assert "5 hidden option" in page.text
    assert "Analyst review required" in page.text


def test_hunt_page_shows_expansion_accounting_instead_of_seed_wording(tmp_path):
    from romulus.hunt import run as hr
    from romulus.store import schema as tables

    settings = Settings(home=tmp_path, secret_key=secrets.token_urlsafe(32))
    app = create_app(settings)
    repo = hr.open_repo(settings)
    password = secrets.token_urlsafe(18)
    create_user(repo.engine, "analyst1", password, "analyst")
    source, finding_id = _repo_with_finding()
    source.save_expansion_anchor({
        "id": finding_id, "hunt_id": "h1", "candidate_id": finding_id, "depth": 0,
        "parent_anchor_id": None, "host": "web01", "lane": "high", "severity": "high",
        "ts": T,
        "status": "expanded_partial", "reasons": ["source query budget exhausted"],
    })
    with source.engine.connect() as read, repo.engine.begin() as write:
        for table in (
            tables.hunt, tables.raw_record, tables.typed_event, tables.candidate,
            tables.disposition_event, tables.expansion_anchor,
        ):
            rows = [dict(row) for row in read.execute(table.select()).mappings()]
            if rows:
                write.execute(table.insert(), rows)
    repo.audit("system", "hunt.expansion_summary", "h1", {
        "status": "completed", "mode": "deterministic_expansion", "anchors": 1,
        "expanded_complete": 0, "expanded_partial": 1, "unexpanded": [],
        "source_queries": 12,
    })
    client = TestClient(app)
    _login(client, password)

    page = client.get("/hunts/h1")

    assert page.status_code == 200
    assert "Expansion accounting" in page.text
    assert "incident graph" in page.text and "technical report" in page.text
    assert "1 anchor(s)" in page.text
    assert "1 expanded partial" in page.text
    assert "unworked seed" not in page.text


@pytest.mark.parametrize("form, mode", [({}, "off"), ({"agent": "model"}, "model")])
def test_new_hunt_is_deterministic_unless_the_agentic_box_is_checked(client, monkeypatch, form, mode):
    from romulus.web import app as web
    launched = []

    class FakePopen:
        def __init__(self, cmd, **_kw):
            launched.append(cmd)

    monkeypatch.setattr(web.subprocess, "Popen", FakePopen)
    c, pw, _ = client
    _login(c, pw)
    page = c.get("/hunts/new").text
    assert 'name="agent" value="model"' in page and "checked" not in page.split('name="agent"')[1][:40]
    r = c.post("/hunts", data={"start": "2024-11-18T10:00:00Z", "end": "2024-11-18T17:30:00Z",
                               "csrf": _csrf(page), **form}, follow_redirects=False)
    assert r.status_code == 303
    cmd = launched[0]
    assert cmd[cmd.index("--agent-mode") + 1] == mode


def test_unknown_agent_option_is_refused(client):
    c, pw, _ = client
    _login(c, pw)
    page = c.get("/hunts/new").text
    r = c.post("/hunts", data={"start": "2024-11-18T10:00:00Z", "end": "2024-11-18T17:30:00Z",
                               "csrf": _csrf(page), "agent": "deterministic; rm -rf /"})
    assert r.status_code == 400
