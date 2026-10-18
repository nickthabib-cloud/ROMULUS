"""Hunt deletion: lead-only, confirmed, CSRF-protected, refuses live hunts, keeps evidence other hunts cite."""
import re
import secrets
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from romulus.config import Settings
from romulus.store import schema as t
from romulus.store.db import utcnow
from romulus.web.app import create_app
from romulus.web.auth import create_user
from tests.test_report import _repo_with_finding


def _seed(repo):
    """h1 with one finding; h2 whose finding cites the same stored event (shared evidence)."""
    src, cid = _repo_with_finding()
    src.set_hunt_state("h1", "running")
    src.set_hunt_state("h1", "completed_within_scope", detection_result="reportable_findings")
    with src.engine.connect() as a, repo.engine.begin() as b:
        for table in (t.hunt, t.raw_record, t.typed_event, t.candidate, t.disposition_event):
            rows = [dict(r) for r in a.execute(table.select()).mappings()]
            if rows:
                b.execute(table.insert(), rows)
        h1 = dict(a.execute(t.hunt.select()).mappings().one())
        cand = dict(a.execute(t.candidate.select()).mappings().one())
    with repo.engine.begin() as b:
        b.execute(t.hunt.insert(), {**h1, "id": "h2"})
        b.execute(t.candidate.insert(), {**cand, "id": "cand-h2", "hunt_id": "h2"})
    return cid


def _count(repo, table, **where):
    q = select(func.count()).select_from(table)
    for k, v in where.items():
        q = q.where(getattr(table.c, k) == v)
    with repo.engine.connect() as c:
        return c.execute(q).scalar_one()


@pytest.fixture()
def env(tmp_path):
    s = Settings(home=tmp_path, secret_key=secrets.token_urlsafe(32))
    app = create_app(s)
    from romulus.hunt import run as hr
    repo = hr.open_repo(s)
    pw = secrets.token_urlsafe(18)
    create_user(repo.engine, "lead1", pw, "lead")
    create_user(repo.engine, "analyst1", pw, "analyst")
    _seed(repo)
    (s.reports_dir / "h1").mkdir(parents=True)
    (s.reports_dir / "h1" / "h1-r1.md").write_text("report", encoding="utf-8")
    return TestClient(app), repo, s, pw


def _login(c, user, pw):
    assert c.post("/login", data={"username": user, "password": pw}, follow_redirects=False).status_code == 303


def _csrf(html):
    return re.search(r'name="csrf" value="([^"]+)"', html).group(1)


def test_lead_sees_warning_then_deletes(env):
    c, repo, s, pw = env
    _login(c, "lead1", pw)
    assert "/hunts/h1/delete" in c.get("/hunts/h1").text
    warn = c.get("/hunts/h1/delete")
    assert warn.status_code == 200 and "cannot be undone" in warn.text
    r = c.post("/hunts/h1/delete", data={"csrf": _csrf(warn.text), "confirm": "h1"}, follow_redirects=False)
    assert r.status_code == 303 and "deleted=h1" in r.headers["location"]
    assert repo.get_hunt("h1") is None
    assert _count(repo, t.candidate, hunt_id="h1") == 0
    assert not (s.reports_dir / "h1").exists()
    # the deletion itself stays auditable
    assert repo.latest_audit("h1", "hunt.delete") is not None


def test_evidence_cited_by_another_hunt_survives(env):
    c, repo, s, pw = env
    from romulus.report import manifest as rm
    repo.delete_hunt("h1", actor="test")
    other = repo.candidate("cand-h2")
    cites = rm._citations(repo, other)
    assert cites and all(x["status"] == "retained" for x in cites), cites
    with repo.engine.connect() as conn:
        assert conn.execute(select(t.typed_event.c.hunt_id)).scalars().all() == ["h2"]
        assert conn.exec_driver_sql("PRAGMA foreign_key_check").fetchall() == []


def test_unshared_evidence_is_removed(env):
    c, repo, s, pw = env
    repo.delete_hunt("h2", actor="test")            # h2 owns nothing exclusively
    repo.delete_hunt("h1", actor="test")
    assert _count(repo, t.typed_event) == 0 and _count(repo, t.raw_record) == 0


def test_analyst_cannot_delete(env):
    c, repo, s, pw = env
    _login(c, "analyst1", pw)
    assert "/hunts/h1/delete" not in c.get("/hunts/h1").text
    assert c.get("/hunts/h1/delete").status_code == 403
    assert repo.get_hunt("h1") is not None


def test_delete_requires_csrf_and_confirmation(env):
    c, repo, s, pw = env
    _login(c, "lead1", pw)
    token = _csrf(c.get("/hunts/h1/delete").text)
    assert c.post("/hunts/h1/delete", data={"csrf": "forged", "confirm": "h1"}).status_code == 403
    assert c.post("/hunts/h1/delete", data={"csrf": token, "confirm": "h2"}).status_code == 400
    assert repo.get_hunt("h1") is not None


def test_live_hunt_cannot_be_deleted_but_stale_one_can(env):
    c, repo, s, pw = env
    with repo.engine.begin() as conn:
        conn.execute(t.hunt.update().where(t.hunt.c.id == "h1").values(
            execution_state="running", lease_until=utcnow() + timedelta(minutes=5)))
    with pytest.raises(ValueError, match="live worker lease"):
        repo.delete_hunt("h1", actor="test")
    with repo.engine.begin() as conn:
        conn.execute(t.hunt.update().where(t.hunt.c.id == "h1").values(lease_until=utcnow() - timedelta(minutes=5)))
    repo.delete_hunt("h1", actor="test")
    assert repo.get_hunt("h1") is None
