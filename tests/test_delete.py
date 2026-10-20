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


# ---------------------------------------------------------------- gate re-review regressions (B4, I1, minors)
def _event_id(repo):
    with repo.engine.connect() as c:
        return c.execute(select(t.typed_event.c.id)).scalar_one()


def _strip_h2_candidate(repo):
    with repo.engine.begin() as c:
        c.execute(t.candidate.delete().where(t.candidate.c.id == "cand-h2"))


def test_evidence_cited_only_by_another_hunts_pivot_step_survives(env):
    c, repo, s, pw = env
    _strip_h2_candidate(repo)                          # no finding cites it: only an investigation step
    eid = _event_id(repo)
    repo.create_case({"id": "case-h2", "hunt_id": "h2", "title": "pivot", "priority": 1.0, "entities": [],
                      "step_budget": 4})
    repo.append_case_step("case-h2", 1, {"tool": "entity_timeline", "evidence_ids": [eid]}, True,
                          result_digest={"status": "complete", "event_ids": [eid]})
    repo.delete_hunt("h1", actor="test")
    with repo.engine.connect() as conn:
        assert conn.execute(select(t.typed_event.c.hunt_id).where(t.typed_event.c.id == eid)).scalar() == "h2"
        assert conn.exec_driver_sql("PRAGMA foreign_key_check").fetchall() == []
    from romulus.report.manifest import _broken_investigation_citations
    assert _broken_investigation_citations(repo, {"cases": [{"pivot_steps": [{"evidence_ids": [eid]}]}]}) == []


def test_evidence_linked_only_through_another_hunts_entities_survives(env):
    c, repo, s, pw = env
    _strip_h2_candidate(repo)
    eid = _event_id(repo)
    with repo.engine.begin() as conn:
        conn.execute(t.entity.insert().values(id="h2:host:web01", hunt_id="h2", kind="host", value="web01",
                                              event_count=1))
        conn.execute(t.event_entity.insert().values(event_id=eid, entity_id="h2:host:web01", role="host"))
    repo.delete_hunt("h1", actor="test")
    with repo.engine.connect() as conn:
        assert conn.execute(select(t.typed_event.c.hunt_id).where(t.typed_event.c.id == eid)).scalar() == "h2"
        assert conn.execute(select(func.count()).select_from(t.event_entity)
                            .where(t.event_entity.c.entity_id == "h2:host:web01")).scalar_one() == 1


def test_missing_investigation_evidence_makes_report_not_finalizable(env):
    c, repo, s, pw = env
    from romulus.report.manifest import _broken_investigation_citations
    assert _broken_investigation_citations(repo, {"cases": [{"steps": [{"event_ids": ["gone"]}]}]}) == ["gone"]


def test_demoted_lead_loses_delete_rights_immediately(env):
    c, repo, s, pw = env
    _login(c, "lead1", pw)
    token = _csrf(c.get("/hunts/h1/delete").text)
    with repo.engine.begin() as conn:
        conn.execute(t.user.update().where(t.user.c.username == "lead1").values(role="analyst"))
    assert c.post("/hunts/h1/delete", data={"csrf": token, "confirm": "h1"}).status_code == 403
    assert repo.get_hunt("h1") is not None


def test_spoofed_deleted_banner_is_not_shown(env):
    c, repo, s, pw = env
    _login(c, "lead1", pw)
    assert "permanently deleted" not in c.get("/?deleted=h1").text   # h1 exists, never deleted


def test_delete_keeps_events_another_hunts_expansion_links_cite():
    """An event with no entities, reached only by another hunt's expansion link, must survive deletion."""
    from romulus.evidence.typed import RawRef, TypedEvent, fv
    from romulus.store.db import make_engine, migrate
    from romulus.store.repo import Repo
    engine = make_engine(":memory:")
    migrate(engine)
    repo = Repo(engine)
    for hunt_id in ("hA", "hB"):
        repo.create_hunt(hunt_id, {}, "d", "t")
        repo.set_hunt_state(hunt_id, "running")
        repo.set_hunt_state(hunt_id, "completed_within_scope", detection_result="leads_only")
    ts = utcnow()
    shared = TypedEvent(id="ev-shared", family="process_exec", ts=ts, host=None,
                        fields={"process.executable": fv("/bin/true", "x")},
                        raw=[RawRef(target="idx", native_id="doc-1", digest="d")], normalizer="test@1")
    repo.save_evidence("hA", [shared], {"idx/doc-1": {"k": 1}}, None)
    anchor_event = TypedEvent(id="ev-anchor", family="process_exec", ts=ts, host="web1",
                              fields={"process.executable": fv("/bin/sh", "x")},
                              raw=[RawRef(target="idx", native_id="doc-2", digest="d")], normalizer="test@1")
    repo.save_evidence("hB", [anchor_event], {"idx/doc-2": {"k": 2}}, None)
    repo.save_candidate({
        "id": "F-B", "hunt_id": "hB", "rule_id": "host.web_shell", "rule_version": "1", "claim": "c",
        "claim_type": "observed_action", "event_ids": ["ev-anchor"], "predicate_fields": [], "entities": [],
        "ts": ts, "severity": "high", "confidence": "high", "lane": "high", "priority": 1.0, "priority_reasons": [],
        "gate_results": {}, "benign_alternatives": [], "next_checks": [], "source_case_id": None,
        "source_anchor_id": None, "source_link_id": None})
    repo.save_expansion_anchor({"id": "F-B", "hunt_id": "hB", "candidate_id": "F-B", "depth": 0,
                                "parent_anchor_id": None, "host": "web1", "lane": "high", "severity": "high",
                                "ts": ts, "status": "expanded_complete", "reasons": []})
    repo.save_expansion_link({
        "id": "L-B", "hunt_id": "hB", "anchor_id": "F-B", "link_type": "host_after_anchor",
        "window_label": "anchor ±5 min", "window_start": ts, "window_end": ts, "strength": "inferred",
        "key": {}, "status": "complete", "event_ids": ["ev-shared"], "evidence_ids": ["ev-anchor", "ev-shared"],
        "task_ids": [], "coverage": [], "reasons": [], "duration_ms": 1, "query_spend": 1, "evaluated": 1})

    repo.delete_hunt("hA", "lead")

    kept = repo.events_by_ids(["ev-shared"])
    assert len(kept) == 1 and kept[0]["hunt_id"] == "hB"
    assert repo.raw_records([kept[0]["raw_ids"][0]])
