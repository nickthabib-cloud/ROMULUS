"""A computed positive without a recoverable timestamp remains visible and honest."""
from xml.etree import ElementTree
from zipfile import ZipFile

import pytest
from alembic import command
from sqlalchemy import event, inspect

from romulus.detect.bounded import CitationUnavailable
from romulus.detect.citing import citation_group
from romulus.hunt.expansion import ExpansionEngine
from romulus.hunt.publish import publish_match
from romulus.report import executive, markdown
from romulus.report.manifest import canonical_manifest, publish_revision
from romulus.report.timeline import build_timeline
from romulus.store import schema as t
from romulus.store.db import make_engine, migrate
from tests.test_baseline_store import _alembic_config
from tests.test_bounded_starvation import _Listed
from tests.test_expansion_engine import WINDOW, ScriptedFetcher
from tests.test_report import _repo_with_finding
from tests.test_web import _login, client  # noqa: F401


def publish_untimed(repo):
    owner, matches = _Listed(), []
    with citation_group(owner, matches, ("C2-DOM", "domain", "host", "missing.c2.test"),
                        (1, {"ids": ["missing"]})):
        raise CitationUnavailable("native witness unavailable")
    assert len(matches) == 1 and matches[0].ts is None
    assert "citation_time" in owner.limits
    candidate = publish_match(repo, "h1", owner, matches[0], None, {})
    assert candidate["ts"] is None and candidate["lane"] == "high"
    return candidate


def test_missing_time_survives_publication_reports_and_timeline(tmp_path):
    repo, dated_id = _repo_with_finding()
    candidate = publish_untimed(repo)
    manifest = publish_revision(repo, "h1", "round7")
    finding = next(f for f in manifest["findings"] if f["id"] == candidate["id"])
    assert finding["observed_at"] is None
    assert {dated_id, candidate["id"]} <= {f["id"] for f in manifest["findings"]}
    assert "not recorded" in markdown.render(manifest).lower()
    assert any(f["observed_at"] is None for f in canonical_manifest(repo, "h1", "round7")["findings"])
    path = tmp_path / "executive.docx"
    executive.write(manifest, path, "technical.md")
    with ZipFile(path) as archive:
        ElementTree.fromstring(archive.read("word/document.xml"))
    layout = build_timeline(manifest["findings"], [], [], WINDOW.start, WINDOW.end)
    assert [f["id"] for f in layout["undated"]] == [candidate["id"]]
    assert all(f["id"] != candidate["id"] for row in layout["rows"] for f in row["items"])
    narrative = " ".join(s["text"] for i in manifest["incident_graph"]["incidents"] for s in i["narrative"])
    assert "time not recorded" in narrative.lower()


def test_missing_time_cannot_spend_expansion_queries():
    repo, _ = _repo_with_finding()
    candidate = publish_untimed(repo)
    fetcher = ScriptedFetcher(repo)
    engine = ExpansionEngine(repo, "h1", WINDOW, fetcher, per_anchor_source_queries=4)
    engine.run()
    anchor = next(a for a in repo.expansion_anchors("h1") if a["id"] == candidate["id"])
    assert anchor["ts"] is None and anchor["status"] == "unexpanded"
    assert anchor["reasons"] == ["observation time unavailable"]
    assert all(call[0] != candidate["id"] for call in fetcher.calls)
    canonical_manifest(repo, "h1", "round7")


def test_nullable_time_migration_preserves_candidate_dependents(tmp_path):
    source, candidate_id = _repo_with_finding()
    source.save_expansion_anchor({"id": candidate_id, "hunt_id": "h1", "candidate_id": candidate_id,
        "depth": 0, "parent_anchor_id": None, "host": "web01", "lane": "high", "severity": "high",
        "ts": source.candidate(candidate_id)["ts"], "status": "pending", "reasons": []})
    with source.engine.begin() as conn:
        conn.execute(t.candidate_host.insert().values(candidate_id=candidate_id, host="web01", first_event_id="ev1"))
    engine = make_engine(tmp_path / "existing.db")
    with engine.begin() as conn:
        command.upgrade(_alembic_config(conn), "0028")
    with source.engine.connect() as src, engine.begin() as dst:
        for table in (t.hunt, t.raw_record, t.typed_event, t.candidate, t.candidate_host, t.expansion_anchor):
            rows = [dict(row) for row in src.execute(table.select()).mappings()]
            if rows:
                dst.execute(table.insert(), rows)
    migrate(engine)
    with engine.connect() as conn:
        assert conn.exec_driver_sql("PRAGMA foreign_keys").scalar_one() == 1
        assert conn.exec_driver_sql("PRAGMA foreign_key_check").all() == []
        assert conn.execute(t.candidate_host.select()).mappings().one()["host"] == "web01"
        assert conn.execute(t.expansion_anchor.select()).mappings().one()["candidate_id"] == candidate_id
    for table in ("candidate", "expansion_anchor"):
        assert next(c for c in inspect(engine).get_columns(table) if c["name"] == "ts")["nullable"]
    # Direct Alembic callers also keep children during a populated round-trip with foreign keys enabled.
    with engine.begin() as conn:
        command.downgrade(_alembic_config(conn), "0028")
    with engine.connect() as conn:
        assert conn.execute(t.candidate_host.select()).mappings().one()["host"] == "web01"
        assert conn.execute(t.expansion_anchor.select()).mappings().one()["candidate_id"] == candidate_id
        assert conn.exec_driver_sql("PRAGMA foreign_key_check").all() == []
    with engine.begin() as conn:
        command.upgrade(_alembic_config(conn), "head")
    with engine.connect() as conn:
        assert conn.execute(t.candidate_host.select()).mappings().one()["host"] == "web01"
        assert conn.exec_driver_sql("PRAGMA foreign_keys").scalar_one() == 1


@pytest.mark.parametrize("route", ["/hunts/h1", "/hunts/h1/timeline", "/findings/{id}"])
def test_missing_time_is_visible_in_authenticated_web(client, tmp_path, route):  # noqa: F811
    from romulus.config import Settings
    from romulus.hunt.run import open_repo

    browser, password, _ = client
    candidate = publish_untimed(open_repo(Settings(home=tmp_path)))
    _login(browser, password)
    response = browser.get(route.format(id=candidate["id"]))
    assert response.status_code == 200
    assert "not recorded" in response.text.lower()
    assert candidate["id"] in response.text


def test_missing_time_pivot_is_named_refusal_without_executor_call():
    from romulus.agent.toolbox import Toolbox
    from tests.test_agent_pivot_tools_v2 import FakeToolExecutor, _args, _repo, _result

    repo = _repo()
    with repo.engine.begin() as conn:
        conn.execute(t.candidate.update().values(ts=None))
    executor = FakeToolExecutor(_result("complete"))
    result = Toolbox(repo, "h1", executor=executor, session_id="session-1").execute("entity_timeline", _args(repo))
    assert result["status"] == "refused"
    assert result["data"]["error"]["code"] == "observation_time_unavailable"
    assert executor.calls == []


@pytest.mark.parametrize("active_transaction", [False, True])
def test_nullable_time_downgrade_refuses_to_drop_untimed_positive(tmp_path, active_transaction):
    from romulus.store.repo import Repo

    engine = make_engine(tmp_path / "untimed.db")
    migrate(engine)
    source, _ = _repo_with_finding()
    with source.engine.connect() as src, engine.begin() as dst:
        dst.execute(t.hunt.insert(), [dict(row) for row in src.execute(t.hunt.select()).mappings()])
    repo = Repo(engine)
    candidate = publish_untimed(repo)
    visibility = {"sensor": "sensor-1", "family": "net_flow", "partial": True,
                  "reasons": ["capture loss 2.3%"], "start": "2026-01-01T00:00:00Z"}
    snapshot = repo.save_zeek_visibility("h1", [visibility])
    with pytest.raises(RuntimeError, match="untimed positives"), engine.begin() as conn:
        if active_transaction:
            conn.execute(t.hunt.update().where(t.hunt.c.id == "h1").values(created_by="rollback-test"))
        command.downgrade(_alembic_config(conn), "0028")
    engine.dispose()
    engine = make_engine(tmp_path / "untimed.db")
    assert "report_zeek_visibility" in inspect(engine).get_table_names()
    assert list(Repo(engine).zeek_visibility_rows("h1", snapshot["sha256"])) == [visibility]
    assert Repo(engine).candidate(candidate["id"])["ts"] is None
    with engine.connect() as conn:
        assert conn.exec_driver_sql("PRAGMA foreign_keys").scalar_one() == 1
        assert conn.exec_driver_sql("SELECT version_num FROM alembic_version").scalar_one() == "0030"
        assert conn.exec_driver_sql("PRAGMA foreign_key_check").all() == []


def test_failed_migration_rolls_back_and_restores_foreign_keys(tmp_path, monkeypatch):
    engine = make_engine(tmp_path / "rollback.db")
    with engine.begin() as conn:
        command.upgrade(_alembic_config(conn), "0028")

    def broken_upgrade(config, _revision):
        config.attributes["connection"].exec_driver_sql(
            "INSERT INTO candidate_host VALUES ('missing-candidate', 'host', 'missing-event')")

    monkeypatch.setattr(command, "upgrade", broken_upgrade)
    with pytest.raises(RuntimeError, match="invalid foreign-key references"):
        migrate(engine)
    with engine.connect() as conn:
        assert conn.exec_driver_sql("PRAGMA foreign_keys").scalar_one() == 1
        assert conn.exec_driver_sql("PRAGMA foreign_key_check").all() == []
        assert conn.execute(t.candidate_host.select()).all() == []
        assert conn.exec_driver_sql("SELECT version_num FROM alembic_version").scalar_one() == "0028"


def test_current_schema_can_open_while_another_connection_is_writing(tmp_path):
    engine = make_engine(tmp_path / "current.db")
    migrate(engine)

    @event.listens_for(engine, "connect")
    def no_lock_wait(connection, _record):
        connection.execute("PRAGMA busy_timeout=0")

    with engine.connect() as writer:
        writer.exec_driver_sql("BEGIN IMMEDIATE")
        try:
            migrate(engine)
        finally:
            writer.rollback()


def test_visibility_migration_successful_downgrade_and_upgrade(tmp_path):
    engine = make_engine(tmp_path / "visibility-roundtrip.db")
    migrate(engine)
    assert "report_zeek_visibility" in inspect(engine).get_table_names()
    with engine.begin() as conn:
        command.downgrade(_alembic_config(conn), "0029")
    engine.dispose()
    engine = make_engine(tmp_path / "visibility-roundtrip.db")
    assert "report_zeek_visibility" not in inspect(engine).get_table_names()
    with engine.connect() as conn:
        assert conn.exec_driver_sql("SELECT version_num FROM alembic_version").scalar_one() == "0029"
        assert conn.exec_driver_sql("PRAGMA foreign_keys").scalar_one() == 1
    migrate(engine)
    assert "report_zeek_visibility" in inspect(engine).get_table_names()
    with engine.connect() as conn:
        assert conn.exec_driver_sql("SELECT version_num FROM alembic_version").scalar_one() == "0030"
        assert conn.exec_driver_sql("PRAGMA foreign_key_check").all() == []
