"""A hunt whose last finish held its baseline history back says so where an analyst looks: the hunt page notice and
the report's coverage limitations. Once a resumed finish writes the history, the line is gone."""
from __future__ import annotations

import secrets

from fastapi.testclient import TestClient

from romulus.config import Settings
from romulus.hunt import run as hunt_run
from romulus.report import markdown
from romulus.report.manifest import build_manifest as build_report
from romulus.report.manifest import held_history_line
from romulus.web.app import create_app
from romulus.web.auth import create_user
from tests.test_site_networks_hunt import SITE_LISTS, _manifest

STAGES = ["baseline stage", "network-host join", "expansion"]
LINE = held_history_line(STAGES)


def _writer(repo, hunt_id: str, status: str) -> None:
    writer = ({"status": "held", "written": 0, "held": {"stages": STAGES, "reason": "held"}} if status == "held"
              else {"status": "complete", "written": 2})
    repo.audit("system", "hunt.baseline_summary", hunt_id, {"segment_writer": writer})
    if status == "held":
        # a held finish keeps the window material for the resume, charged to the disk budget
        from romulus.store.db import utcnow
        repo.retain_baseline_window_material(hunt_id, bytes_=1, retained_at=utcnow(), reason="kept for the resume")
    else:
        repo.drop_baseline_window_retention(hunt_id)


def test_the_line_names_the_unfinished_stages_and_the_resume():
    assert LINE == ("This hunt's hours add no baseline history until it is resumed: baseline stage, network-host "
                    "join, expansion did not run to its end, so the records its findings would cite are not all "
                    "known.")


def test_the_report_names_held_history_in_its_coverage_limitations_until_a_resumed_finish_writes_it():
    from tests.test_report import _repo_with_finding
    repo, _cid = _repo_with_finding()
    _writer(repo, "h1", "held")

    report = build_report(repo, "h1", "test")
    assert report["coverage"]["baseline"]["history_held"] == LINE
    text = markdown.render({**report, "revision": {"number": 1, "id": "r1", "supersedes": None}})
    assert f"**Baseline history held back:** {LINE}" in text

    _writer(repo, "h1", "complete")
    report = build_report(repo, "h1", "test")
    assert "history_held" not in report["coverage"]["baseline"]
    assert "Baseline history held back" not in markdown.render(
        {**report, "revision": {"number": 2, "id": "r2", "supersedes": "r1"}})


def test_the_executive_document_carries_the_line(tmp_path):
    from romulus.report import executive
    from tests.test_report import _repo_with_finding
    repo, _cid = _repo_with_finding()
    _writer(repo, "h1", "held")
    report = {**build_report(repo, "h1", "test"), "revision": {"number": 1, "id": "r1", "supersedes": None}}

    import io
    stream = io.BytesIO()
    body = executive._Body(stream)
    executive._coverage(body, report, "technical.md")
    body.flush()

    xml = stream.getvalue().decode("utf-8")
    # the paragraph text is escaped for XML; compare on a fragment without an apostrophe
    assert "hours add no baseline history until it is resumed: baseline stage, network-host join" in xml
    assert xml.index("hours add no baseline history") < xml.index("Rules by search result")


def test_the_hunt_page_shows_a_notice_while_history_is_held(tmp_path):
    settings = Settings(home=tmp_path, secret_key=secrets.token_urlsafe(32))
    app = create_app(settings)
    repo = hunt_run.open_repo(settings)
    repo.create_hunt("h1", {**_manifest(Settings(home=tmp_path, **SITE_LISTS)), "targets": ["idx"]}, "digest", "test")
    repo.set_hunt_state("h1", "running")
    repo.set_hunt_state("h1", "partial", stop_reason="stopped by analyst")
    _writer(repo, "h1", "held")
    password = secrets.token_urlsafe(18)
    create_user(repo.engine, "analyst1", password, "analyst")
    client = TestClient(app)
    client.post("/login", data={"username": "analyst1", "password": password})

    page = client.get("/hunts/h1")
    assert page.status_code == 200
    assert "<b>Baseline history:</b> This hunt&#39;s hours add no baseline history until it is resumed" in page.text

    _writer(repo, "h1", "complete")
    assert "Baseline history:" not in client.get("/hunts/h1").text


def test_a_finish_stopped_after_the_sweep_and_its_resumed_finish_set_and_clear_the_line():
    from romulus.report.manifest import held_history
    from tests.test_baseline_held_history import _finish_run, _later_stage_finding, _stop_after_sweep, _window
    from tests.test_baseline_hunt_writer import _repo
    repo = _repo()
    _window(repo)
    _stop_after_sweep(repo)
    assert held_history(repo, "hunt-a") == LINE

    repo.claim_hunt("hunt-a", 600, resume=True)
    _later_stage_finding(repo)
    _finish_run(repo)
    assert held_history(repo, "hunt-a") is None


def test_held_history_whose_material_the_disk_budget_released_promises_no_resume():
    from romulus.report.manifest import held_history
    from tests.test_baseline_held_history import NOT_RUN, PACKETS, STOP_AT_BASELINE, _finish_run, _window
    from tests.test_baseline_hunt_writer import _repo
    repo = _repo()
    _window(repo)
    # a budget smaller than this hunt's material: the held finish cannot keep it
    _finish_run(repo, stopped=STOP_AT_BASELINE, packet=PACKETS, baseline={}, expansion=NOT_RUN, budget=1)

    writer = repo.latest_audit("hunt-a", "hunt.baseline_summary")["detail"]["segment_writer"]
    assert writer["status"] == "held" and writer["material"]["kept"] is False
    assert "resuming the hunt will not write" in writer["held"]["reason"]
    assert "resumed hunt's finish writes" not in writer["held"]["reason"]
    line = held_history(repo, "hunt-a")
    assert line == held_history_line(STAGES, resumable=False) and "until it is resumed" not in line


def test_held_history_kept_at_the_finish_but_released_later_stops_promising_a_resume():
    from romulus.report.manifest import held_history
    from tests.test_baseline_held_history import _stop_after_sweep, _window
    from tests.test_baseline_hunt_writer import _repo
    repo = _repo()
    _window(repo)
    _stop_after_sweep(repo)
    assert held_history(repo, "hunt-a") == LINE
    # another hunt's finish later releases it under the budget
    for spec_id, target in repo.baseline_window_material_pairs("hunt-a"):
        repo.release_baseline_window_material("hunt-a", spec_id, target, "released by the disk budget")
    repo.drop_baseline_window_retention("hunt-a")
    assert held_history(repo, "hunt-a") == held_history_line(STAGES, resumable=False)
