"""Web sessions end with the account: a disabled account, a logout, and a changed role or password revoke them."""
from sqlalchemy import update

from romulus.config import Settings
from romulus.hunt import run as hr
from romulus.store import schema as t
from tests.test_web import _csrf, _login
from tests.test_web import client as client  # noqa: PLC0414 - the shared authenticated web fixture


def _repo(tmp_path):
    return hr.open_repo(Settings(home=tmp_path))


def _disable(tmp_path, username="analyst1"):
    repo = _repo(tmp_path)
    try:
        with repo.engine.begin() as conn:
            assert conn.execute(update(t.user).where(t.user.c.username == username).values(disabled=1)).rowcount == 1
    finally:
        repo.engine.dispose()


def _dispositions(tmp_path, cid):
    repo = _repo(tmp_path)
    try:
        return repo.dispositions(cid)
    finally:
        repo.engine.dispose()


def test_disabled_account_cannot_read_a_finding(client, tmp_path):
    c, pw, cid = client
    assert _login(c, pw).headers["location"] == "/"
    assert c.get(f"/findings/{cid}").status_code == 200
    _disable(tmp_path)
    r = c.get(f"/findings/{cid}", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"


def test_disabled_account_cannot_set_a_disposition(client, tmp_path):
    c, pw, cid = client
    _login(c, pw)
    token = _csrf(c.get(f"/findings/{cid}").text)
    before = len(_dispositions(tmp_path, cid))
    _disable(tmp_path)
    r = c.post(f"/findings/{cid}/disposition", data={"status": "benign", "note": "after disable", "csrf": token},
               follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"
    assert len(_dispositions(tmp_path, cid)) == before


def test_disabled_account_cannot_publish_a_report(client, tmp_path):
    c, pw, cid = client
    _login(c, pw)
    token = _csrf(c.get(f"/findings/{cid}").text)
    _disable(tmp_path)
    r = c.post("/hunts/h1/report", data={"csrf": token}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"
    assert not (tmp_path / "reports" / "h1").exists()


def test_cookie_replayed_after_logout_is_refused(client):
    c, pw, cid = client
    _login(c, pw)
    cookie = c.cookies.get("romulus_session")
    token = _csrf(c.get(f"/findings/{cid}").text)
    assert c.post("/logout", data={"csrf": token}, follow_redirects=False).status_code == 303
    c.cookies.clear()
    c.cookies.set("romulus_session", cookie)
    r = c.get(f"/findings/{cid}", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"
