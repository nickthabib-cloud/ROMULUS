"""A hunt stored without evidence ranks renders exactly as it did before ranking existed."""
import hashlib
import tempfile
import zipfile
from datetime import timedelta
from pathlib import Path

from romulus.report import executive
from romulus.report.manifest import build_manifest
from romulus.report.markdown import render
from tests.test_report import T, _repo_with_finding

# The digest of this hunt's Markdown report as rendered before evidence ranking existed (captured by rendering this
# same hunt with the code before ranking), and of its executive document body in the current executive layout,
# without the recommendations and indicator export sections: a manifest without them renders exactly as before.
MARKDOWN_SHA256 = "916270762b901bf993ba001d5ee0f3ae6c6609fe69c7e3c5454e61f0a0b3ffd0"
DOCX_SHA256 = "3bbb10c7fd1b6bf289e3d008e296c3748c5d3a67ba1d7f2f0450e258fcdbf25b"
# The same hunt with those two sections: the Markdown gains its Recommendations and Indicators sections before
# Coverage, the executive document its recommendations by priority and an indicator export paragraph; nothing else.
MARKDOWN_WITH_PARTNER_SECTIONS_SHA256 = "84950f3845fd1f9a62b6db8240abc4c98d3e3011aac9b7a48e214e1cda294f31"
DOCX_WITH_PARTNER_SECTIONS_SHA256 = "16189eb83f0df2afb46ce1ddd5b7ee0307dec09a19ee5ac5eaa5912726b5d523"
PARTNER_SECTIONS = ("recommendations", "indicators")


def render_unranked(*, partner_sections: bool = False) -> tuple[str, bytes]:
    repo, finding_id = _repo_with_finding()
    stored = {key: value for key, value in repo.candidate(finding_id).items() if key != "created_at"}
    for suffix, lane, priority in (("-lead", "lead", 30.0), ("-urgent", "urgent", 90.0), ("-high", "high", 60.0)):
        repo.save_candidate({**stored, "id": finding_id + suffix, "lane": lane, "priority": priority,
                             "ts": T + timedelta(minutes=len(suffix)), "claim": stored["claim"] + suffix})
    manifest = build_manifest(repo, "h1", "test")
    if not partner_sections:
        for key in PARTNER_SECTIONS:
            manifest.pop(key)
    manifest["revision"] = {"number": 1, "id": "h1-r1", "supersedes": None}
    for key in ("started_at", "ended_at"):
        manifest["hunt"][key] = "fixed"
    markdown = render(manifest)
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "executive.docx"
        executive.write(manifest, path, "technical.md")
        with zipfile.ZipFile(path) as archive:
            document = archive.read("word/document.xml")
    return markdown, document


def test_a_hunt_without_ranks_renders_exactly_as_before():
    markdown, document = render_unranked()
    assert "rule estimate" not in markdown and "Reported entities" not in markdown
    assert hashlib.sha256(markdown.encode()).hexdigest() == MARKDOWN_SHA256
    assert hashlib.sha256(document).hexdigest() == DOCX_SHA256


def test_the_partner_sections_are_the_only_addition():
    markdown, document = render_unranked(partner_sections=True)
    assert hashlib.sha256(markdown.encode()).hexdigest() == MARKDOWN_WITH_PARTNER_SECTIONS_SHA256
    assert hashlib.sha256(document).hexdigest() == DOCX_WITH_PARTNER_SECTIONS_SHA256
    before, _ = render_unranked()
    start, end = markdown.index("## Recommendations"), markdown.index("## Coverage")
    assert markdown[:start] + markdown[end:] == before


def test_a_hunt_with_a_pack_digest_names_it_in_the_report_versions(monkeypatch):
    repo, _finding_id = _repo_with_finding()
    stored = repo.get_hunt
    def with_digest(hunt_id):
        hunt = stored(hunt_id)
        hunt["manifest"]["pack"] = {**hunt["manifest"]["pack"], "digest": "a" * 64}
        return hunt
    monkeypatch.setattr(repo, "get_hunt", with_digest)
    versions = build_manifest(repo, "h1", "test")["versions"]
    assert versions["pack_digest"] == "a" * 64
    assert '"pack_digest": "' + "a" * 64 + '"' in render({**build_manifest(repo, "h1", "test"),
                                                         "revision": {"number": 1, "id": "h1-r1", "supersedes": None}})
