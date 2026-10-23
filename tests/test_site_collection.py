"""Strict site-local Windows collection attestation and hunt provenance."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

import romulus.hunt.run as hunt_run
from romulus.config import Settings
from romulus.doctor import check_site
from romulus.hunt.manifest import build_manifest
from romulus.site import (
    SiteChangedError,
    SiteValidationError,
    _SiteDocument,
    ensure_site_unchanged,
    load_site_facts,
)
from romulus.sources.models import Window

VALID = """\
schema: romulus-site-collection@1
collection:
  - hosts: [WS-*.example.test, dc01]
    sysmon:
      installed: true
      event_ids: [1, 3, 5]
    security_4688_command_line: true
    security_event_log: true
    powershell_script_block: false
    audit_policy:
      Process Creation: success
      Logon: both
    defender_operational: true
    task_scheduler_operational: false
    system_event_log: true
domain_controllers: [DC01.EXAMPLE.TEST]
directory_sync_accounts: [S-1-5-21-111-222-333-444, EXAMPLE\\SyncSvc]
"""


def _write(home, text: str = VALID):
    path = home / "site" / "collection.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="")
    return path


def test_absent_site_file_attests_nothing_and_needs_no_manifest_member(tmp_path):
    facts = load_site_facts(tmp_path)

    assert facts.present is False
    assert facts.groups == ()
    assert facts.attests("ws01", "sysmon", event_id=1) is False
    assert facts.manifest_entry() is None


def test_valid_site_file_is_canonical_strict_and_host_scoped(tmp_path):
    _write(tmp_path)

    facts = load_site_facts(tmp_path)

    assert facts.present is True
    assert facts.digest
    assert facts.content["schema"] == "romulus-site-collection@1"
    assert facts.domain_controllers == ("dc01.example.test",)
    assert facts.directory_sync_accounts == (
        "sid:s-1-5-21-111-222-333-444",
        "name:example\\syncsvc",
    )
    assert facts.attests("WS-22.EXAMPLE.TEST", "sysmon", event_id=3) is True
    assert facts.attests("ws-22", "sysmon", event_id=7) is False
    assert facts.attests("ws-22.example.test", "audit_policy", subcategory="Logon", outcome="failure") is True
    assert facts.attests("unmatched", "security_4688_command_line") is False
    assert facts.attests("ws-22.example.test", "security_event_log") is True
    assert "schema_name" in _SiteDocument.model_fields and "schema" not in _SiteDocument.model_fields


@pytest.mark.parametrize(
    ("body", "message"),
    [
        (VALID.replace("schema:", "unexpected: true\nschema:"), "unknown key"),
        (VALID.replace("    sysmon:", "    mystery: true\n    sysmon:"), "unknown key"),
        (VALID.replace("WS-*.example.test", "../hosts/*"), "host glob"),
        (VALID.replace("S-1-5-21-111-222-333-444", "S-1-bad"), "directory_sync_accounts"),
        (VALID.replace("collection:\n", "collection:\n  - hosts: [dc01]\n    sysmon: {installed: true, event_ids: [1]}\n"), "duplicate host group"),
        (VALID.replace("schema: romulus-site-collection@1", "schema: romulus-site-collection@1\nschema: old"), "duplicate key"),
        (VALID.replace("installed: true", "installed: 1"), "boolean"),
        (VALID.replace("security_4688_command_line: true", "security_4688_command_line: 'true'"), "boolean"),
        (VALID.replace("event_ids: [1, 3, 5]", "event_ids: ['1', 3, 5]"), "integer"),
        (VALID.replace("hosts: [WS-*.example.test, dc01]", "hosts: ['*']\n  - hosts: all"), "catch-all|duplicate"),
    ],
)
def test_invalid_site_files_fail_with_a_clear_validation_error(tmp_path, body, message):
    _write(tmp_path, body)

    with pytest.raises(SiteValidationError, match=message):
        load_site_facts(tmp_path)


def test_doctor_reports_absent_valid_and_invalid_site_file(tmp_path):
    settings = Settings(home=tmp_path)
    absent = check_site(settings)
    assert absent.name == "site.collection" and absent.status == "warn"
    assert "absent" in absent.detail and "nothing is attested" in absent.detail

    _write(tmp_path)
    valid = check_site(settings)
    assert valid.status == "ok" and valid.data["digest"]

    _write(tmp_path, VALID.replace("event_ids: [1, 3, 5]", "event_ids: [0]"))
    invalid = check_site(settings)
    assert invalid.status == "fail" and "event_ids" in invalid.detail


def test_manifest_records_present_site_content_and_absence_stays_byte_compatible(tmp_path):
    window = Window(
        start=datetime(2025, 1, 1, tzinfo=UTC),
        end=datetime(2025, 1, 1, 1, tzinfo=UTC),
    )
    settings = Settings(home=tmp_path)
    kwargs = {
        "s": settings,
        "window": window,
        "original_input": {"start": "x", "end": "y"},
        "style": "broad",
        "targets": [],
        "profiles": {},
    }

    absent = build_manifest(**kwargs)
    assert "site" not in absent

    _write(tmp_path)
    facts = load_site_facts(tmp_path)
    present = build_manifest(**kwargs, site_facts=facts)
    assert present["site"] == facts.manifest_entry()
    assert present["site"]["content"]["collection"][0]["hosts"] == ["ws-*.example.test", "dc01"]


def test_resume_provenance_refuses_added_removed_or_changed_site_file(tmp_path):
    assert ensure_site_unchanged(tmp_path, None).present is False

    _write(tmp_path)
    first = load_site_facts(tmp_path)
    with pytest.raises(SiteChangedError, match="changed since the hunt was created"):
        ensure_site_unchanged(tmp_path, None)
    assert ensure_site_unchanged(tmp_path, first.manifest_entry()).digest == first.digest

    _write(tmp_path, VALID.replace("event_ids: [1, 3, 5]", "event_ids: [1, 3]"))
    with pytest.raises(SiteChangedError, match="changed since the hunt was created"):
        ensure_site_unchanged(tmp_path, first.manifest_entry())

    (tmp_path / "site" / "collection.yaml").unlink()
    with pytest.raises(SiteChangedError, match="changed since the hunt was created"):
        ensure_site_unchanged(tmp_path, first.manifest_entry())


def test_resume_hunt_checks_site_provenance_before_claiming_work(tmp_path, monkeypatch):
    _write(tmp_path)
    recorded = load_site_facts(tmp_path).manifest_entry()

    class Repo:
        def get_hunt(self, hunt_id):
            assert hunt_id == "h1"
            return {"manifest": {"site": recorded}, "execution_state": "partial"}

        def claim_hunt(self, *_args, **_kwargs):  # pragma: no cover - must never be reached
            raise AssertionError("resume claimed work before validating site provenance")

    monkeypatch.setattr(hunt_run, "open_repo", lambda _settings: Repo())
    _write(tmp_path, VALID.replace("event_ids: [1, 3, 5]", "event_ids: [1, 3]"))

    with pytest.raises(SiteChangedError, match="changed since the hunt was created"):
        hunt_run.resume_hunt(Settings(home=tmp_path), "h1")


def test_web_service_startup_rejects_an_invalid_present_site_file(tmp_path, monkeypatch):
    from romulus.web import app as web_app

    _write(tmp_path, VALID.replace("installed: true", "installed: 1"))
    monkeypatch.setattr(web_app, "open_repo", lambda _settings: pytest.fail("opened store before site validation"))

    with pytest.raises(SiteValidationError, match="boolean"):
        web_app.create_app(Settings(home=tmp_path, secret_key="test-secret"))
