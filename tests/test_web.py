"""Web UI: authentication, CSRF, security headers and output encoding of telemetry."""
import re
import secrets

import pytest
from fastapi.testclient import TestClient

from romulus.config import Settings
from romulus.web.app import create_app
from romulus.web.auth import create_user
from tests.test_report import _repo_with_finding


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
    # copy the seeded hunt into the app DB
    from romulus.store import schema as t
    with src_repo.engine.connect() as a, repo.engine.begin() as b:
        for table in (t.hunt, t.raw_record, t.typed_event, t.candidate, t.disposition_event):
            rows = [dict(r) for r in a.execute(table.select()).mappings()]
            if rows:
                b.execute(table.insert(), rows)
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
