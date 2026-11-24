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


def _running_hunt_stream(tmp_path, monkeypatch, change):
    """Open the live stream of a running hunt as a logged-in analyst; `change(engine)` runs during the first poll
    delay. Returns the event names the stream sent and how many poll delays it took."""
    import asyncio
    import secrets

    from starlette.requests import Request

    from romulus.web import app as web
    from romulus.web import auth
    from tests.test_report import _repo_with_finding

    settings = Settings(home=tmp_path, secret_key=secrets.token_urlsafe(32))
    repo = hr.open_repo(settings)
    source, _cid = _repo_with_finding()
    try:
        with source.engine.connect() as read, repo.engine.begin() as write:
            for table in (t.hunt, t.candidate):
                write.execute(table.insert(), [dict(row) for row in read.execute(table.select()).mappings()])
    finally:
        source.engine.dispose()
    repo.set_hunt_state("h1", "running")
    auth.create_user(repo.engine, "viewer", secrets.token_urlsafe(18), "analyst")
    monkeypatch.setattr(web, "open_repo", lambda _: repo)
    app = web.create_app(settings)
    endpoint = next(route.endpoint for route in app.routes if getattr(route, "path", None) == "/hunts/{hunt_id}/stream")
    cookie = auth.Sessions(settings.secret_key.get_secret_value()).issue(
        {"username": "viewer", "role": "analyst", "generation": 0})
    sleeps = []

    async def poll_sleep(delay):
        sleeps.append(delay)
        if len(sleeps) == 1:
            change(repo.engine)
        assert len(sleeps) < 5, "the stream kept running"

    monkeypatch.setattr(web.asyncio, "sleep", poll_sleep)

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def run():
        request = Request({"type": "http", "headers": [(b"cookie", f"{web.COOKIE}={cookie}".encode())]}, receive)
        response = await endpoint(request, "h1")
        return [chunk.split("\n", 1)[0].removeprefix("event: ") async for chunk in response.body_iterator]

    try:
        return asyncio.run(run()), len(sleeps)
    finally:
        repo.engine.dispose()


def test_open_stream_ends_when_the_account_is_disabled(tmp_path, monkeypatch):
    from romulus.web import auth
    events, polls = _running_hunt_stream(tmp_path, monkeypatch,
                                         lambda engine: auth.set_disabled(engine, "viewer", True))
    assert events[-1] == "end" and polls == 1


def test_open_stream_ends_when_the_sessions_are_ended(tmp_path, monkeypatch):
    from romulus.web import auth
    events, polls = _running_hunt_stream(tmp_path, monkeypatch, lambda engine: auth.end_sessions(engine, "viewer"))
    assert events[-1] == "end" and polls == 1


def test_open_stream_keeps_running_while_the_session_is_valid(tmp_path, monkeypatch):
    import pytest
    with pytest.raises(AssertionError, match="kept running"):
        _running_hunt_stream(tmp_path, monkeypatch, lambda engine: None)
