"""All fleet names survive report snapshots and bounded-memory rendering."""
import hashlib
import json
import tracemalloc
from xml.etree import ElementTree
from zipfile import ZipFile

import pytest

from romulus.report import markdown
from romulus.report.manifest import publish_revision
from tests.test_report import _repo_with_finding


def test_ten_thousand_host_report_snapshot_and_markdown_stream_keep_every_host(tmp_path):
    repo, candidate = _repo_with_finding()
    repo.save_candidate_hosts(candidate, "h1", ((f"host-{n:05}", f"event-{n}") for n in range(10000)),
                              expected_count=10000)
    tracemalloc.start()
    try:
        manifest = publish_revision(repo, "h1", "test")
        [finding] = manifest["findings"]
        assert "fleet_hosts" in finding
        appendix = finding["fleet_hosts"]
        assert appendix["count"] == 10000 and appendix["complete"]
        assert len(json.dumps(manifest)) < 100_000
        path = tmp_path/"technical.md"
        with path.open("w", encoding="utf-8") as stream:
            for chunk in markdown.iter_render(manifest, host_rows=lambda ref: repo.report_hosts("h1", ref["sha256"])):
                stream.write(chunk)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 8*2**20
    text = path.read_text(encoding="utf-8")
    assert all(f"host-{n:05}" in text for n in range(10000))
    assert "Fleet host appendix" in text
    before = list(repo.report_hosts("h1", appendix["sha256"]))
    repo.save_candidate_hosts(candidate, "h1", [("replacement", "new")], replace=True, expected_count=1)
    assert list(repo.report_hosts("h1", appendix["sha256"])) == before
    second = publish_revision(repo, "h1", "test")
    assert second["findings"][0]["fleet_hosts"]["count"] == 1
    assert not second["revision"]["unchanged_from_previous"]


def test_report_bundle_contains_referenced_host_stream_and_executive_docx(tmp_path):
    repo, candidate = _repo_with_finding()
    repo.save_candidate_hosts(candidate, "h1", [("<host>|\nname", "first"), ("host-last", "last")], expected_count=2)
    manifest = publish_revision(repo, "h1", "test")
    assert "fleet_hosts" in manifest["findings"][0]
    from romulus.report.bundle import write_reports
    paths = write_reports(repo, manifest, tmp_path)
    descriptor = manifest["findings"][0]["fleet_hosts"]
    blob = (tmp_path/descriptor["filename"]).read_bytes()
    assert hashlib.sha256(blob).hexdigest() == descriptor["sha256"]
    assert [json.loads(line)["host"] for line in blob.splitlines()] == ["<host>|\nname", "host-last"]
    with ZipFile(paths["docx"]) as archive:
        root = ElementTree.fromstring(archive.read("word/document.xml"))
    document = " ".join(root.itertext())
    assert "2 reporting hosts" in document
    assert paths["md"].name in document and "Fleet host appendix" in document
    assert "host-last" in paths["md"].read_text(encoding="utf-8")
    assert "\\<host\\>\\| name" in paths["md"].read_text(encoding="utf-8")


def test_incomplete_host_snapshot_is_named_in_every_report(tmp_path):
    repo, candidate = _repo_with_finding()
    repo.save_candidate_hosts(candidate, "h1", [("known", "first")], expected_count=2)
    manifest = publish_revision(repo, "h1", "test")
    assert "fleet_hosts" in manifest["findings"][0]
    from romulus.report.bundle import write_reports
    paths = write_reports(repo, manifest, tmp_path)
    descriptor = manifest["findings"][0]["fleet_hosts"]
    assert descriptor["count"] == 1 and descriptor["expected_count"] == 2 and not descriptor["complete"]
    assert not manifest["integrity"]["finalizable"]
    assert "1 of 2" in paths["md"].read_text(encoding="utf-8")


def test_failed_appendix_export_preserves_every_previous_report_file(tmp_path, monkeypatch):
    from romulus.report.bundle import write_reports
    repo, candidate = _repo_with_finding()
    repo.save_candidate_hosts(candidate, "h1", [("first", "e1"), ("second", "e2")], expected_count=2)
    manifest = publish_revision(repo, "h1", "test")
    write_reports(repo, manifest, tmp_path)
    before = {path.name: path.read_bytes() for path in tmp_path.iterdir()}

    def interrupted(*args):
        yield {"host": "first", "first_event_id": "e1"}
        raise RuntimeError("injected interrupted appendix read")

    monkeypatch.setattr(repo, "report_hosts", interrupted)
    with pytest.raises(RuntimeError, match="interrupted"):
        write_reports(repo, manifest, tmp_path)
    assert {path.name: path.read_bytes() for path in tmp_path.iterdir()} == before


def test_report_refuses_a_candidate_changed_before_membership_snapshot(monkeypatch):
    repo, candidate = _repo_with_finding()
    repo.save_candidate_hosts(candidate, "h1", [("first", "e1")], expected_count=1, claim="first host decision")
    original = repo.snapshot_candidate_hosts

    def raced(*args, **kwargs):
        repo.save_candidate_hosts(candidate, "h1", [("second", "e2")], replace=True,
                                  expected_count=1, claim="second host decision")
        return original(*args, **kwargs)

    monkeypatch.setattr(repo, "snapshot_candidate_hosts", raced)
    with pytest.raises(RuntimeError, match="changed while.*report"):
        publish_revision(repo, "h1", "test")


def test_failed_render_retry_preserves_existing_report_bundle(tmp_path, monkeypatch):
    from romulus.report.bundle import write_reports
    repo, _ = _repo_with_finding()
    manifest = publish_revision(repo, "h1", "test")
    write_reports(repo, manifest, tmp_path)
    before = {path.name: path.read_bytes() for path in tmp_path.iterdir()}

    def interrupted(*args, **kwargs):
        yield "partial report"
        raise RuntimeError("injected renderer failure")

    monkeypatch.setattr(markdown, "iter_render", interrupted)
    with pytest.raises(RuntimeError, match="renderer failure"):
        write_reports(repo, manifest, tmp_path)
    assert {path.name: path.read_bytes() for path in tmp_path.iterdir()} == before


def test_cli_report_exports_all_formats_and_deleting_hunt_removes_snapshots(tmp_path, monkeypatch, capsys):
    from argparse import Namespace

    from sqlalchemy import func, select

    from romulus import cli
    from romulus.config import Settings
    from romulus.hunt import run
    from romulus.store import schema

    repo, candidate = _repo_with_finding()
    repo.save_candidate_hosts(candidate, "h1", [("fleet-first", "ev1"), ("fleet-last", "ev1")], expected_count=2)
    settings = Settings(home=tmp_path)
    monkeypatch.setattr(cli, "load_settings", lambda _: settings)
    monkeypatch.setattr(run, "open_repo", lambda _: repo)
    cli.cmd_report(Namespace(env_file="unused", hunt_id="h1"))
    output = capsys.readouterr().out
    for suffix in ("json", "md", "docx"):
        assert f"h1-r1.{suffix}" in output
        assert (settings.reports_dir / "h1" / f"h1-r1.{suffix}").is_file()
    with repo.engine.connect() as connection:
        assert connection.scalar(select(func.count()).select_from(schema.report_host)) == 2
    repo.delete_hunt("h1", actor="test")
    with repo.engine.connect() as connection:
        assert connection.scalar(select(func.count()).select_from(schema.report_host)) == 0


def test_web_report_exports_authenticated_docx_and_exact_appendix(tmp_path):
    import io
    import secrets

    from fastapi.testclient import TestClient

    from romulus.config import Settings
    from romulus.hunt.run import open_repo
    from romulus.store import schema
    from romulus.web.app import create_app
    from romulus.web.auth import create_user
    from tests.test_web import _csrf, _login

    settings = Settings(home=tmp_path, secret_key=secrets.token_urlsafe(32))
    app = create_app(settings)
    repo = open_repo(settings)
    password = secrets.token_urlsafe(18)
    create_user(repo.engine, "analyst1", password, "analyst")
    source, candidate = _repo_with_finding()
    with source.engine.connect() as read, repo.engine.begin() as write:
        for table in (schema.hunt, schema.raw_record, schema.typed_event, schema.candidate):
            write.execute(table.insert(), [dict(row) for row in read.execute(table.select()).mappings()])
    repo.save_candidate_hosts(candidate, "h1", [("fleet-first", "ev1"), ("fleet-last", "ev1")], expected_count=2)
    client = TestClient(app)
    assert client.get("/reports/h1/h1-r1.docx", follow_redirects=False).status_code == 303
    _login(client, password)
    assert client.post("/hunts/h1/report", data={"csrf": "forged"}).status_code == 403
    token = _csrf(client.get("/hunts/h1").text)
    response = client.post("/hunts/h1/report", data={"csrf": token}, follow_redirects=False)
    assert response.status_code == 303
    manifest = client.get("/reports/h1/h1-r1.json").json()
    descriptor = manifest["findings"][0]["fleet_hosts"]
    appendix = client.get(f"/reports/h1/{descriptor['filename']}")
    assert appendix.status_code == 200
    assert hashlib.sha256(appendix.content).hexdigest() == descriptor["sha256"]
    assert [json.loads(line)["host"] for line in appendix.content.splitlines()] == ["fleet-first", "fleet-last"]
    docx = client.get("/reports/h1/h1-r1.docx")
    assert docx.status_code == 200
    assert docx.headers["content-type"].startswith("application/vnd.openxmlformats")
    with ZipFile(io.BytesIO(docx.content)) as archive:
        text = " ".join(ElementTree.fromstring(archive.read("word/document.xml")).itertext())
    assert "2 reporting hosts" in text and "h1-r1.md" in text
    assert "fleet-last" in client.get("/reports/h1/h1-r1.md").text
    assert "h1-r1.docx" in client.get("/hunts/h1").text
    for path in ("h1-r1.jsonl", "fleet-hosts-invalid.jsonl", "h1-r1.exe", "..%2Foutside.docx"):
        assert client.get(f"/reports/h1/{path}").status_code == 404


def test_membership_snapshot_fences_an_independent_writer_after_candidate_read(tmp_path):
    import sqlite3

    from sqlalchemy import event

    from romulus.store import schema
    from romulus.store.db import make_engine, migrate
    from romulus.store.repo import Repo

    database = tmp_path / "snapshot.db"
    engine = make_engine(database)
    migrate(engine)
    repo = Repo(engine)
    source, candidate = _repo_with_finding()
    with source.engine.connect() as read, engine.begin() as write:
        for table in (schema.hunt, schema.raw_record, schema.typed_event, schema.candidate):
            write.execute(table.insert(), [dict(row) for row in read.execute(table.select()).mappings()])
    repo.save_candidate_hosts(candidate, "h1", [("original", "ev1")], expected_count=1)
    attempted = []

    def competing_write(connection, cursor, statement, parameters, context, executemany):
        if attempted or not statement.startswith("SELECT candidate_host.host"):
            return
        # A separate raw connection models another process, bypassing the in-process writer lock.
        with sqlite3.connect(database, timeout=0) as other:
            try:
                other.execute("UPDATE candidate_host SET host='replacement'")
                other.commit()
                attempted.append("committed")
            except sqlite3.OperationalError as error:
                assert "locked" in str(error)
                attempted.append("blocked")

    event.listen(engine, "before_cursor_execute", competing_write)
    try:
        manifest = publish_revision(repo, "h1", "test")
    finally:
        event.remove(engine, "before_cursor_execute", competing_write)
    assert attempted == ["blocked"]
    descriptor = manifest["findings"][0]["fleet_hosts"]
    assert [row["host"] for row in repo.report_hosts("h1", descriptor["sha256"])] == ["original"]
    with sqlite3.connect(database, timeout=0) as other:
        other.execute("UPDATE candidate_host SET host='replacement'")
    assert repo.candidate_hosts(candidate)[0][0]["host"] == "replacement"


def test_report_host_migration_round_trip_preserves_existing_hunt(tmp_path):
    from alembic import command
    from sqlalchemy import inspect

    from romulus.store.db import make_engine
    from tests.test_baseline_store import _alembic_config

    engine = make_engine(tmp_path / "migration.db")
    with engine.begin() as connection:
        config = _alembic_config(connection)
        command.upgrade(config, "0027")
        connection.exec_driver_sql(
            "INSERT INTO hunt (id, created_at, created_by, manifest, manifest_digest, execution_state) "
            "VALUES ('h1', '2026-01-01', 'test', '{}', 'd', 'planned')")
        command.upgrade(config, "0028")
        connection.exec_driver_sql("INSERT INTO report_host VALUES ('h1', 'digest', 'host', 'event')")
        command.downgrade(config, "0027")
        assert "report_host" not in inspect(connection).get_table_names()
        assert connection.exec_driver_sql("SELECT id FROM hunt").scalar_one() == "h1"
        command.upgrade(config, "0028")
        assert connection.exec_driver_sql("SELECT count(*) FROM report_host").scalar_one() == 0
