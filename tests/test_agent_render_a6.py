"""Agent report text, stored assessment reads, and status counts."""
import hashlib
import json
from datetime import UTC, datetime, timedelta
from xml.etree import ElementTree
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

from sqlalchemy import select

from romulus import cli
from romulus.report import executive
from romulus.report.manifest import _ai_assessment, build_manifest
from romulus.store import schema as t
from tests.test_report import _repo_with_finding


def _docx(tmp_path, monkeypatch, manifest):
    manifest["revision"] = {"number": 1}
    class FixedZip(ZipFile):
        def writestr(self, name, data, *args, **kwargs):
            info = ZipInfo(name, date_time=(2024, 1, 1, 0, 0, 0))
            info.compress_type = ZIP_DEFLATED
            return super().writestr(info, data, *args, **kwargs)
    monkeypatch.setattr(executive, "ZipFile", FixedZip)
    path = tmp_path / "report.docx"
    executive.write(manifest, path, "technical.md")
    return path


def test_old_hunt_docx_bytes_are_unchanged(tmp_path, monkeypatch):
    repo, _ = _repo_with_finding()
    manifest = build_manifest(repo, "h1", "test")
    path = _docx(tmp_path, monkeypatch, manifest)
    assert hashlib.sha256(path.read_bytes()).hexdigest() == "0a153da5054826714df626d05f915a5af35442e45e8abd675a8855acb1705721"


def test_old_hunt_json_and_markdown_are_unchanged(monkeypatch):
    from romulus.report import manifest, markdown
    from romulus.store import db
    from romulus.store import repo as store
    from tests.test_report import T
    for module in (db, store, manifest):
        monkeypatch.setattr(module, "utcnow", lambda: T)
    repo, _ = _repo_with_finding()
    result = build_manifest(repo, "h1", "test")
    result["revision"] = {"number": 1, "id": "h1-r1", "supersedes": None}
    assert hashlib.sha256(json.dumps(result, indent=2, sort_keys=True).encode()).hexdigest() == (
        "385fcc8611505ba2c10fb36935040fc7711561e5a1834d18c3e90449e0c54d6e")
    assert hashlib.sha256(markdown.render(result).encode()).hexdigest() == (
        "8e8fbc3e031a0dce83494cd40f31af8fc2324f1675eccf52d3954477a1a28902")


def test_docx_assessment_uses_plain_text_and_all_sentence_groups(tmp_path, monkeypatch):
    repo, _ = _repo_with_finding()
    manifest = build_manifest(repo, "h1", "test")
    hostile = '<script>javascript:alert(1)</script> <w:fldSimple instr="DDE"/>'
    sentence = {"text": hostile, "kind": "hypothesis", "cites": ["F-real", "E-real"]}
    manifest["ai_assessment"] = {"source": "agent", "header": "Prior AI assessment: not current.",
        "body": {"overall": [sentence], "key_steps": [{"time": "now", "tactic": "TA0001", "sentence": sentence}],
                 "confidence": {"overall": "low", "reasons": [sentence]}, "alternatives": [sentence],
                 "gaps": [sentence], "next_checks": [sentence]}, "checker": {"removed": [{"reason": "uncited"}]}}
    path = _docx(tmp_path, monkeypatch, manifest)
    with ZipFile(path) as archive:
        document = ElementTree.fromstring(archive.read("word/document.xml"))
        assert "word/_rels/document.xml.rels" not in archive.namelist()
    values = [node.text or "" for node in document.iter(f"{{{executive._WORD}}}t")]
    assert "AI assessment" in values
    assert "Prior AI assessment: not current." in values
    assert sum(hostile in value for value in values) == 6
    assert sum("[F-real, E-real]" in value and "hypothesis" in value for value in values) == 6
    assert any("uncited" in value for value in values)
    assert values.index("AI assessment") > next(i for i, v in enumerate(values) if v.startswith("Recommended check:"))
    assert all(node.tag not in {f"{{{executive._WORD}}}fldSimple", f"{{{executive._WORD}}}hyperlink"}
               for node in document.iter())


def test_assessment_latest_and_stale_check_do_not_materialize_history(monkeypatch):
    repo, _ = _repo_with_finding()
    now = datetime.now(UTC)
    repo.save_agent_run({"hunt_id": "h1", "state": "partial"})
    for index in range(3):
        repo.save_agent_assessment({"id": f"a-{index}", "hunt_id": "h1", "revision": index + 1,
            "source": "agent", "model": {}, "body": {}, "checker": {}, "created_at": now})
    repo.save_agent_session({"id": "s1", "hunt_id": "h1", "purpose": "investigate", "state": "finished",
        "tool_calls": 0, "summary": "", "started_at": now, "ended_at": now + timedelta(seconds=1)})
    def unbounded(*_args, **_kwargs):
        raise AssertionError("must not materialize history")
    for name in ("agent_assessments", "agent_sessions", "agent_hypotheses"):
        monkeypatch.setattr(repo, name, unbounded)
    assessment = _ai_assessment(repo, "h1", stored_only=True)
    assert assessment["revision"] == 3
    assert assessment["stale"] is True
    with repo.engine.begin() as connection:
        connection.execute(t.agent_assessment.delete())
    monkeypatch.setattr(repo, "candidates", unbounded)
    assert _ai_assessment(repo, "h1", stored_only=True) is None


def test_cli_status_counts_hypotheses_by_status_without_loading_rows(monkeypatch):
    repo, _ = _repo_with_finding()
    repo.save_agent_run({"hunt_id": "h1", "state": "partial"})
    now = datetime.now(UTC)
    with repo.engine.begin() as connection:
        for index, status in enumerate(("open", "open", "supported")):
            connection.execute(t.agent_hypothesis.insert().values(id=f"h-{index}", hunt_id="h1", statement="Investigate",
                techniques=[], entity_ids=[], status=status, confidence="low", questions=[],
                created_at=now, updated_at=now))
        row = dict(connection.execute(select(t.candidate)).mappings().one())
        connection.execute(t.candidate.insert().values(**{**row, "id": "ai-finding", "provenance": "agent"}))
    monkeypatch.setattr(repo, "agent_hypotheses", lambda *_a: (_ for _ in ()).throw(AssertionError("unbounded")))
    text = cli._stage_status(repo, "h1", {"status": "partial"})
    assert "hypotheses=open:2,supported:1" in text
    assert "agent_findings=1" in text
