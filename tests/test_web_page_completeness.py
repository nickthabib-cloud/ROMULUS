"""The web pages show everything the report does: the Coverage tab's blind-spot lists with exact counts, a
finding's every cited event and raw record a page at a time, a failed report renderer with its reason, a revision
whose files were not written marked as such, and request bodies bounded before anything parses them."""
import re

from sqlalchemy import select

from romulus.report import bundle
from romulus.store import schema as t
from tests import test_web_agent_a6

setup = test_web_agent_a6.setup
csrf = test_web_agent_a6.csrf


# ------------------------------------------------------------------------------------------------------ coverage tab
def _sweep(repo, stats):
    repo.audit("system", "hunt.sweep_summary", "h1", {"finished": True, "stats": stats})


def test_coverage_tab_shows_gaps_unassessed_data_notes_and_baseline(setup):
    client, repo, *_ = setup
    reason = "Windows record seen under more than one collection source"
    _sweep(repo, {
        "dataset_reconciliation": {"idx": [{"dataset": "secure-log", "records": 987654,
                                            "count_scope": "hunt window", "reason": "no recognized format"}]},
        "skips_by_target": {"idx": {reason: 7}}, "skips": {reason: 7}})
    repo.set_rule_cell("h1", "rule.full", "1", "idx", "window", "no_match_complete", 0, 5, {})
    repo.set_rule_cell("h1", "rule.part", "1", "idx", "shard-3", "partial", 0, 5,
                       {"reasons": ["shard 3 timed out after 30 s"]})
    with repo.engine.begin() as connection:
        manifest = connection.execute(select(t.hunt.c.manifest).where(t.hunt.c.id == "h1")).scalar_one()
        manifest = {**manifest, "baseline": {"specs": [{"id": "spec.logon-rarity", "version": "1"}]}}
        connection.execute(t.hunt.update().where(t.hunt.c.id == "h1").values(manifest=manifest))
    html = client.get("/hunts/h1/coverage").text
    gaps = html.split('id="coverage-gaps"', 1)[1].split("</section>", 1)[0]
    assert "shard-3" in gaps and "shard 3 timed out after 30 s" in gaps and "rule.part" in gaps
    unassessed = html.split('id="not-assessed"', 1)[1].split("</section>", 1)[0]
    assert "secure-log" in unassessed and "987654" in unassessed and "no recognized format" in unassessed
    notes = html.split('id="coverage-notes"', 1)[1].split("</section>", 1)[0]
    assert "7 Windows records were seen under more than one collection source" in notes
    baseline = html.split('id="baseline-coverage"', 1)[1].split("</section>", 1)[0]
    assert "spec.logon-rarity" in baseline and "unresolved" in baseline and "not_frozen" in baseline


def test_coverage_tab_pages_every_gap_and_unassessed_row_with_exact_counts(setup):
    client, repo, *_ = setup
    _sweep(repo, {"dataset_reconciliation": {"idx": [
        {"dataset": f"ds-{i:03}", "records": i, "count_scope": "hunt window", "reason": "not read"}
        for i in range(120)]}})
    repo.set_rule_cells("h1", [{"rule_id": "rule.a", "version": "1", "target": "idx", "partition": f"p-{i:03}",
                                "state": "failed", "matched": 0, "evaluated": 0, "detail": {"reasons": [f"why {i}"]}}
                               for i in range(120)])
    first = client.get("/hunts/h1/coverage").text
    assert "120 coverage gaps" in first and "120 rows of data not assessed" in first

    def walk(param, section, pattern):
        seen, number = [], 1
        while True:
            html = client.get("/hunts/h1/coverage", params={param: number}).text
            part = html.split(f'id="{section}"', 1)[1].split("</section>", 1)[0]
            seen += re.findall(pattern, part)
            if "Next →" not in part:
                return seen
            number += 1
    gaps = walk("gaps_page", "coverage-gaps", r">(p-\d{3})<")
    assert sorted(gaps) == [f"p-{i:03}" for i in range(120)]
    rows = walk("unassessed_page", "not-assessed", r">(ds-\d{3})<")
    assert sorted(rows) == [f"ds-{i:03}" for i in range(120)]


# ------------------------------------------------------------------------------------------------------ finding page
def _many_events(repo, cid, events=30, raws_per_event=3):
    with repo.engine.begin() as connection:
        event = dict(connection.execute(select(t.typed_event)).mappings().first())
        raw = dict(connection.execute(select(t.raw_record)).mappings().first())
        ids = []
        for i in range(events):
            raw_ids = []
            for j in range(raws_per_event):
                rid = f"raw-{i:03}-{j}"
                connection.execute(t.raw_record.insert().values({**raw, "id": rid, "native_id": rid}))
                raw_ids.append(rid)
            eid = f"evx-{i:03}"
            connection.execute(t.typed_event.insert().values({**event, "id": eid, "raw_ids": raw_ids}))
            ids.append(eid)
        connection.execute(t.candidate.update().where(t.candidate.c.id == cid).values(event_ids=ids))
    return ids


def test_finding_page_states_every_cited_event_and_pages_through_them(setup):
    client, repo, cid, *_ = setup
    ids = _many_events(repo, cid)
    html = client.get(f"/findings/{cid}").text
    assert "Cited evidence (30 event(s))" in html
    seen = re.findall(r"event (evx-\d{3})</summary>", html)
    assert len(seen) == 20 and "10 more cited event(s)" in html
    nxt = re.search(r'href="([^"]*events_at=20[^"]*)"', html).group(1).replace("&amp;", "&")
    page2 = client.get(nxt).text
    seen += re.findall(r"event (evx-\d{3})</summary>", page2)
    assert sorted(seen) == ids
    assert "Cited evidence (30 event(s))" in page2


def test_finding_page_pages_retained_raw_records_with_exact_counts(setup):
    client, repo, cid, *_ = setup
    _many_events(repo, cid, events=20, raws_per_event=3)
    html = client.get(f"/findings/{cid}").text
    assert "Retained raw records (60" in html
    shown = re.findall(r"/ (raw-\d{3}-\d) ·", html)
    assert len(shown) == 40 and "20 more retained raw record(s)" in html
    nxt = re.search(r'href="([^"]*raw_at=40[^"]*)"', html).group(1).replace("&amp;", "&")
    shown += re.findall(r"/ (raw-\d{3}-\d) ·", client.get(nxt).text)
    assert sorted(shown) == sorted(f"raw-{i:03}-{j}" for i in range(20) for j in range(3))


# ------------------------------------------------------------------------------------------------------ report files
def test_failed_docx_is_shown_with_its_reason_and_never_linked(setup, monkeypatch):
    client, *_ = setup

    def broken(*_args, **_kwargs):
        raise RuntimeError("renderer <b>exploded</b>")
    monkeypatch.setattr(bundle.executive, "write", broken)
    response = client.post("/hunts/h1/report", data={"csrf": csrf(client)}, follow_redirects=False)
    assert response.status_code == 303
    overview = client.get("/hunts/h1").text
    assert 'href="/reports/h1/h1-r1.docx"' not in overview
    assert 'href="/reports/h1/h1-r1.md"' in overview
    assert "renderer &lt;b&gt;exploded&lt;/b&gt;" in overview
    assert 'href="/reports/h1/h1-r1.docx-error.txt"' in overview
    note = client.get("/reports/h1/h1-r1.docx-error.txt")
    assert note.status_code == 200 and "exploded" in note.text and note.headers["content-type"].startswith("text/plain")
    header = client.get("/hunts/h1/coverage").text
    assert 'href="/reports/h1/h1-r1.docx"' not in header and 'href="/reports/h1/h1-r1.md"' in header
    assert client.get("/reports/h1/h1-r1.other-error.txt").status_code == 404
    assert client.get("/reports/h1/h2-r1.docx-error.txt").status_code == 404


def test_failed_report_write_marks_the_revision_and_keeps_the_last_good_one_linked(setup, monkeypatch):
    client, repo, *_ = setup
    assert client.post("/hunts/h1/report", data={"csrf": csrf(client)}, follow_redirects=False).status_code == 303

    def broken(*_args, **_kwargs):
        raise ValueError("Host appendix differs from its report manifest")
    from romulus.web import app as web
    monkeypatch.setattr(web, "write_reports", broken)
    response = client.post("/hunts/h1/report", data={"csrf": csrf(client)}, follow_redirects=False)
    assert response.status_code == 303
    assert repo.latest_audit("h1", "report.write_failed")["detail"]["revision"] == "h1-r2"
    overview = client.get("/hunts/h1").text
    assert 'href="/reports/h1/h1-r2.md"' not in overview and 'href="/reports/h1/h1-r2.json"' not in overview
    assert "Host appendix differs from its report manifest" in overview
    note = client.get("/reports/h1/h1-r2.write-error.txt")
    assert note.status_code == 200 and "Host appendix differs" in note.text
    header = client.get("/hunts/h1/coverage").text
    assert 'href="/reports/h1/h1-r1.md"' in header and 'href="/reports/h1/h1-r2.md"' not in header


# ------------------------------------------------------------------------------------------------------ body limits
def test_unauthenticated_oversized_bodies_are_refused_before_parsing(setup):
    client, *_ = setup
    client.cookies.clear()
    big = b"x" * (2 * 1024 * 1024)
    for path in ("/login", "/hunts", "/logout", "/hunts/h1/report", "/findings/x/disposition"):
        response = client.post(path, files={"blob": ("a.bin", big)}, follow_redirects=False)
        assert response.status_code == 413, path
        response = client.post(path, data={"username": "a", "password": "b", "pad": "y" * (2 * 1024 * 1024)},
                               follow_redirects=False)
        assert response.status_code == 413, path


def test_body_without_content_length_is_counted(setup):
    client, *_ = setup
    client.cookies.clear()

    def chunks():
        for _ in range(64):
            yield b"username=a&pad=" + b"y" * 65536 + b"&"
    response = client.post("/login", content=chunks(), headers={"content-type": "application/x-www-form-urlencoded"},
                           follow_redirects=False)
    assert response.status_code == 413


def test_legitimate_forms_still_fit(setup):
    client, *_ = setup
    response = client.post("/findings/missing/disposition",
                           data={"csrf": csrf(client), "status": "benign", "note": "é" * 2000},
                           follow_redirects=False)
    assert response.status_code == 400  # refused by the route (no such finding), not by the size limit
    from romulus.web.body_limit import limit_for
    from romulus.web.indicator_routes import HTTP_MAX_BYTES
    assert limit_for("/indicators") == HTTP_MAX_BYTES and limit_for("/site") >= 3 * 1024 * 1024
