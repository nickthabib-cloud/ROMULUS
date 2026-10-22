"""The hunt records which internal-network definition it used, installs it, refuses to resume under another,
and shows it in the report manifest, the Markdown report and the web hunt page. Documentation ranges only."""
import secrets
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from romulus.config import Settings
from romulus.detect import netdef
from romulus.detect.netdef import SiteNetworks
from romulus.hunt import run as hunt_run
from romulus.hunt.manifest import build_manifest
from romulus.hunt.site_networks import install_for_hunt
from romulus.report import markdown
from romulus.report.manifest import build_manifest as build_report
from romulus.sources.models import Window
from romulus.web.app import create_app
from romulus.web.auth import create_user

SITE_LISTS = {"internal_networks": ["198.51.100.0/24", "10.0.0.0/8"], "external_networks": ["10.50.0.0/16"]}
SITE = SiteNetworks.from_lists(SITE_LISTS["internal_networks"], SITE_LISTS["external_networks"])
WINDOW = Window(start=datetime(2024, 11, 18, 10, tzinfo=UTC), end=datetime(2024, 11, 18, 11, tzinfo=UTC))
DEFAULT_LINE = "Internal networks: default (RFC 1918 and reserved ranges); not configured for this site"
SITE_LINE = "Internal networks: configured (2 ranges, 1 carve-out)"


def _manifest(settings: Settings) -> dict:
    return build_manifest(settings, WINDOW, {}, "broad", ["idx"], {})


def _hunt(settings: Settings, manifest: dict, hunt_id: str = "h1"):
    repo = hunt_run.open_repo(settings)
    repo.create_hunt(hunt_id, manifest, "digest", "test")
    return repo


# ---- item 3: provenance ----------------------------------------------------------------------------------

def test_the_hunt_manifest_records_the_definition_and_its_digest(tmp_path):
    configured = _manifest(Settings(home=tmp_path, **SITE_LISTS))
    record = configured["internal_networks"]
    assert record["source"] == "configured" and record["digest"] == SITE.digest
    assert record["internal"] == ["10.0.0.0/8", "198.51.100.0/24"] and record["external"] == ["10.50.0.0/16"]
    assert record["summary"] == SITE_LINE
    default = _manifest(Settings(home=tmp_path))
    assert default["internal_networks"]["source"] == "default"
    assert default["internal_networks"]["digest"] == SiteNetworks.default().digest
    # the setting is part of the config provenance as well
    assert configured["config_digest"] != default["config_digest"]


def test_install_for_hunt_installs_the_recorded_definition(tmp_path):
    settings = Settings(home=tmp_path, **SITE_LISTS)
    installed = install_for_hunt(settings, "h1", _manifest(settings))
    assert installed == SITE and netdef.current() == SITE


@pytest.mark.parametrize(("created_with", "now"), [
    ({}, SITE_LISTS),                                                       # default, then configured
    (SITE_LISTS, {}),                                                       # configured, then unset
    (SITE_LISTS, {**SITE_LISTS, "external_networks": ["10.51.0.0/16"]}),    # another carve-out
])
def test_resume_refuses_a_changed_definition(tmp_path, created_with, now):
    repo = _hunt(Settings(home=tmp_path), _manifest(Settings(home=tmp_path, **created_with)))
    repo.set_hunt_state("h1", "running")
    repo.set_hunt_state("h1", "partial", stop_reason="test")
    with pytest.raises(RuntimeError, match="internal networks"):
        hunt_run.resume_hunt(Settings(home=tmp_path, **now), "h1")
    assert repo.get_hunt("h1")["lease_owner"] is None                      # refused before claiming the hunt
    assert netdef.current() == SiteNetworks.default()                     # nothing was installed


def test_resume_of_a_hunt_recorded_before_the_setting_refuses_a_configured_site(tmp_path):
    manifest = _manifest(Settings(home=tmp_path))
    del manifest["internal_networks"]
    _hunt(Settings(home=tmp_path), manifest)
    with pytest.raises(RuntimeError, match="internal networks"):
        hunt_run.resume_hunt(Settings(home=tmp_path, **SITE_LISTS), "h1")
    assert install_for_hunt(Settings(home=tmp_path), "h1", manifest) == SiteNetworks.default()


def test_running_a_hunt_refuses_a_definition_changed_since_creation(tmp_path):
    _hunt(Settings(home=tmp_path), _manifest(Settings(home=tmp_path)))
    with pytest.raises(RuntimeError, match="internal networks"):
        hunt_run.run_hunt(Settings(home=tmp_path, **SITE_LISTS), "h1")


def _reported(tmp_path, record: dict | None):
    from tests.test_report import _repo_with_finding
    repo, _cid = _repo_with_finding()
    if record is not None:
        with repo.engine.begin() as c:
            from romulus.store import schema as t
            hunt = c.execute(t.hunt.select()).mappings().one()
            c.execute(t.hunt.update().values(manifest={**hunt["manifest"], "internal_networks": record}))
    return build_report(repo, "h1", "test")


def test_the_report_manifest_and_markdown_show_one_line(tmp_path):
    configured = _reported(tmp_path, SITE.record())
    assert configured["internal_networks"]["summary"] == SITE_LINE
    assert configured["internal_networks"]["digest"] == SITE.digest
    assert f"| Internal networks | {SITE_LINE.removeprefix('Internal networks: ')} |" in _render(configured)
    default = _reported(tmp_path, None)                                     # recorded before the setting existed
    assert default["internal_networks"]["summary"] == DEFAULT_LINE
    assert "| Internal networks | default (RFC 1918 and reserved ranges); not configured for this site |" \
        in _render(default)


def _render(manifest: dict) -> str:
    return markdown.render({**manifest, "revision": {"number": 1, "id": "r1", "supersedes": None}})


def test_the_web_hunt_page_shows_one_line(tmp_path):
    settings = Settings(home=tmp_path, secret_key=secrets.token_urlsafe(32))
    app = create_app(settings)
    repo = _hunt(settings, {**_manifest(Settings(home=tmp_path, **SITE_LISTS)), "targets": ["idx"]})
    repo.set_hunt_state("h1", "running")
    password = secrets.token_urlsafe(18)
    create_user(repo.engine, "analyst1", password, "analyst")
    client = TestClient(app)
    client.post("/login", data={"username": "analyst1", "password": password})
    page = client.get("/hunts/h1")
    assert page.status_code == 200
    assert '<span class="label">Internal networks</span> configured (2 ranges, 1 carve-out)' in page.text
