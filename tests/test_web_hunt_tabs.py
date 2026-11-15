"""The hunt workspace: one URL per tab, bounded pages that always state what is left, the header's actions,
operator detail on Run details, the catalog without applicability, and escaping of model text on every tab."""
import re
from datetime import timedelta

import pytest
from sqlalchemy import event

from romulus.store import schema as t
from romulus.store.db import utcnow
from romulus.store.repo import FINAL_RANK_PASS
from romulus.web import hunt_views
from romulus.web.finding_order import finding_page, ranked_finding_page, segment_sizes
from tests import test_web_agent_a6
from tests.test_agent_store_r2 import NOW, _candidate, _repo

setup = test_web_agent_a6.setup
TABS = ("", "/findings", "/assessment", "/triage", "/timeline", "/coverage", "/run")
HOSTILE = "<script>alert('x')</script><img src=x onerror=alert(2)>"


def _seed(repo, rows):
    with repo.engine.begin() as connection:
        connection.execute(t.candidate.insert(), [dict(row, created_at=NOW) for row in rows])


def _ids(html):
    return re.findall(r'data-finding-id="([^"]+)"', html)


def _login_analyst(client, password):
    client.post("/logout", data={"csrf": test_web_agent_a6.csrf(client)})
    client.post("/login", data={"username": "analyst", "password": password})


def _assessment(repo, cid, text=HOSTILE):
    repo.save_agent_assessment({"id": "assessment", "hunt_id": "h1", "revision": 1, "source": "agent",
        "model": {"provider": "scripted", "model_requested": "requested-model"},
        "body": {"overall": [{"text": text, "kind": "hypothesis", "cites": [{"kind": "F", "id": cid}]}],
                 "key_steps": [{"text": "Step " + text, "kind": "observed", "cites": []}]},
        "checker": {}, "created_at": utcnow()})


# ------------------------------------------------------------------------------------------------------- routing
@pytest.mark.parametrize("suffix", TABS)
def test_every_tab_is_its_own_url_and_marks_itself_current(setup, suffix):
    client, *_ = setup
    response = client.get("/hunts/h1" + suffix)
    assert response.status_code == 200
    current = re.findall(r'<a href="([^"]+)" aria-current="page">', response.text)
    assert current[-1] == "/hunts/h1" + suffix
    for other in TABS:
        assert f'href="/hunts/h1{other}"' in response.text
    # the header is the same on every tab: state, window and the live-stream cursor
    assert 'id="live-state"' in response.text and "data-stream-cursor=" in response.text
    assert client.get("/hunts/missing" + suffix).status_code == 404


def test_findings_query_on_the_hunt_url_redirects_to_the_findings_tab(setup):
    client, *_ = setup
    response = client.get("/hunts/h1?lane=urgent", follow_redirects=False)
    assert response.status_code == 303 and response.headers["location"] == "/hunts/h1/findings?lane=urgent"
    assert client.get("/hunts/h1", params={"after": "!!"}).status_code == 400


def test_agent_pages_and_reassess_return_to_the_assessment_tab(setup, monkeypatch):
    client, repo, *_ = setup
    test_web_agent_a6.run_row(repo)
    for path in ("/hunts/h1/hypotheses", "/hunts/h1/agent/notes"):
        page = client.get(path).text
        assert 'href="/hunts/h1/assessment" aria-current="page"' in page
    monkeypatch.setattr(test_web_agent_a6.web.subprocess, "Popen", lambda *a, **kw: None)
    response = client.post("/hunts/h1/agent/reassess", data={"csrf": test_web_agent_a6.csrf(client)},
                           follow_redirects=False)
    assert response.headers["location"] == "/hunts/h1/assessment"
    report = client.post("/hunts/h1/report", data={"csrf": test_web_agent_a6.csrf(client)}, follow_redirects=False)
    assert report.headers["location"] == "/hunts/h1#reports"
    assert 'id="reports"' in client.get("/hunts/h1").text


# ---------------------------------------------------------------------------------------------------- pagination
def test_findings_tab_pages_state_what_is_left_and_reach_every_row(setup):
    client, repo, cid, *_ = setup
    _seed(repo, [_candidate(f"lead-{i:03}") for i in range(119)])
    seen, url, pages = [], "/hunts/h1/findings", 0
    while url:
        html = client.get(url).text
        rows = _ids(html)
        assert len(rows) <= 50
        seen += rows
        pages += 1
        left = 120 - len(seen)
        if left:
            assert f"{left} more" in html
            url = re.search(r'href="([^"]+)">Next findings', html).group(1).replace("&amp;", "&")
        else:
            assert "no more findings after this page" in html and "Next findings" not in html
            url = None
    assert pages == 3 and len(seen) == len(set(seen)) == 120 and cid in seen


def test_findings_tab_filters_by_lane_and_rule(setup):
    client, repo, cid, *_ = setup
    _seed(repo, [_candidate(f"lead-{i:03}") for i in range(5)] + [_candidate("urgent-1", lane="urgent")])
    rule = repo.candidate(cid)["rule_id"]
    assert _ids(client.get("/hunts/h1/findings", params={"rule": "test.rule"}).text) == [
        "urgent-1", *[f"lead-{i:03}" for i in range(5)]]
    assert _ids(client.get("/hunts/h1/findings", params={"rule": "test.rule", "lane": "urgent"}).text) == ["urgent-1"]
    assert _ids(client.get("/hunts/h1/findings", params={"rule": rule}).text) == [cid]
    empty = client.get("/hunts/h1/findings", params={"rule": "no.such.rule"}).text
    assert _ids(empty) == [] and "No findings match these filters." in empty
    assert client.get("/hunts/h1/findings", params={"rule": "r" * 300}).status_code == 400


def test_rule_filter_seeks_the_rule_order_index():
    repo = _repo()
    _seed(repo, [_candidate(f"f{i:04}") for i in range(120)])
    statements = []
    event.listen(repo.engine, "before_cursor_execute", lambda _c, _x, sql, params, *_: statements.append((sql, params)))
    rows, remaining, cursor = finding_page(repo, "h1", predicates=(t.candidate.c.rule_id == "test.rule",))
    assert len(rows) == 50 and remaining == 70
    finding_page(repo, "h1", after=cursor, predicates=(t.candidate.c.rule_id == "test.rule",))
    with repo.engine.connect() as connection:
        plans = [" ".join(str(row) for row in connection.exec_driver_sql("EXPLAIN QUERY PLAN " + sql, params))
                 for sql, params in list(statements)]
    # the rule's own range of ix_candidate_rule_order, in importance order, with no temporary sort
    assert plans and all("ix_candidate_rule_order (hunt_id=? AND rule_id=?" in plan for plan in plans)
    assert all("TEMP B-TREE" not in plan for plan in plans)


def test_overview_shows_the_top_findings_and_how_many_more(setup):
    client, repo, *_ = setup
    _seed(repo, [_candidate(f"lead-{i:03}") for i in range(30)])
    html = client.get("/hunts/h1").text
    assert len(_ids(html)) == hunt_views.TOP_FINDINGS
    assert "21 more" in html and 'href="/hunts/h1/findings">All findings' in html
    assert "Timeline preview" in html


def test_ranked_overview_lists_only_the_reported_set_in_report_order(setup):
    from tests.test_rank_views import _copy_into, _ranked_repo
    client, repo, *_ = setup
    ranked = _ranked_repo(filler=40)
    _copy_into(repo, ranked)
    sizes = segment_sizes(repo, "h1", pass_no=FINAL_RANK_PASS)
    reported = sum(sizes[index] for index in hunt_views.REPORTED_SEGMENTS)
    first, _, _ = ranked_finding_page(repo, "h1", pass_no=FINAL_RANK_PASS, limit=hunt_views.TOP_FINDINGS)
    expected = [row["id"] for row in first if row["segment"] in hunt_views.REPORTED_SEGMENTS]
    html = client.get("/hunts/h1").text
    top = html.split("Top Reported findings", 1)[1].split("Timeline preview", 1)[0]
    assert _ids(top) == expected and expected[0] == "c-urgent" and "p-single" not in expected
    left = reported - len(expected)
    assert (f"{left} more ·" in top) if left else ("more ·" not in top)
    tile = html.split('<div class="t-label">Reported</div>', 1)[1].split("</a>", 1)[0]
    assert f'<div class="t-value">{reported}</div>' in tile
    assert f"{sizes[0] + sizes[1]} confirmed" in tile and f"{sizes[3]} ranked, not reported" in tile


def test_coverage_tab_lists_unresolved_first_and_pages_every_rule(setup):
    client, repo, *_ = setup
    repo.audit("system", "hunt.sweep_summary", "h1", {"finished": True})
    for i in range(120):
        state = "partial" if i % 40 == 0 else "no_match_complete"
        repo.set_rule_cell("h1", f"rule.{i:03}", "1", "idx", "window", state, 0, 5, {})
    first = client.get("/hunts/h1/coverage").text
    rows = re.findall(r'<tr class="cov-(\w+)"><td class="mono">([^<]+)</td>', first)
    assert len(rows) == 50 and [cls for cls, _ in rows[:3]] == ["attention"] * 3
    assert rows[3][0] != "attention"
    seen = [rule for _, rule in rows]
    page = 2
    while True:
        html = client.get("/hunts/h1/coverage", params={"page": page}).text
        found = [rule for _, rule in re.findall(r'<tr class="cov-(\w+)"><td class="mono">([^<]+)</td>', html)]
        seen += found
        if "Next rules" not in html:
            assert "no more rules after this page" in html
            break
        page += 1
    rules = {f"rule.{i:03}" for i in range(120)}
    assert rules <= set(seen) and len(seen) == len(set(seen))
    attention = client.get("/hunts/h1/coverage", params={"show": "attention"}).text
    assert len(re.findall(r'<tr class="cov-attention">', attention)) == 3


def test_coverage_page_bounds():
    rows = [{"rule_id": f"r{i:03}", "states": {"no_match_complete": 1}, "search_result": "searched in full: 1"}
            for i in range(101)]
    view = hunt_views.coverage_page(rows, page=99)
    assert view["page"] == 3 and len(view["rows"]) == 1 and view["more"] == 0
    assert hunt_views.coverage_page(rows, page=-4)["page"] == 1
    assert hunt_views.coverage_page([], page=2)["rows"] == []


def test_timeline_chronology_pages_every_finding_in_time_order(setup):
    client, repo, *_ = setup
    rows = []
    for i in range(70):
        row = _candidate(f"lead-{i:03}")
        row["ts"] = NOW + timedelta(minutes=70 - i)
        rows.append(row)
    _seed(repo, rows)
    html = client.get("/hunts/h1/timeline").text
    chronology = html.split('id="chronology"', 1)[1]
    listed = re.findall(r'<div class="meta">lead · test\.rule · (lead-\d+)</div>', chronology)
    assert listed[:2] == ["lead-069", "lead-068"] and "21 more" in chronology
    later = re.search(r'href="([^"]+)">Later', chronology).group(1).replace("&amp;", "&")
    rest = client.get(later).text.split('id="chronology"', 1)[1]
    assert "lead-000" in rest and "no more findings after this page" in rest
    # the analyst-link form is bounded to the page: no select of every finding
    assert "<select name=\"from_finding\"" not in html and 'list="finding-ids"' in html


# ----------------------------------------------------------------------------------------------- header actions
def test_lead_header_has_a_delete_dialog_naming_the_hunt_and_a_fallback_page(setup):
    client, repo, *_ = setup
    html = client.get("/hunts/h1/findings").text
    assert 'href="/hunts/h1/delete" data-dialog="delete-dialog"' in html
    dialog = html.split('<dialog id="delete-dialog"', 1)[1].split("</dialog>", 1)[0]
    assert 'data-expected="h1"' in dialog and 'name="confirm"' in dialog and 'name="csrf"' in dialog
    assert 'action="/hunts/h1/delete"' in dialog and "cannot be undone" in dialog
    # the server check is unchanged: the typed confirmation must equal the hunt ID
    token = test_web_agent_a6.csrf(client)
    assert client.post("/hunts/h1/delete", data={"csrf": token, "confirm": "H1"}).status_code == 400
    assert client.post("/hunts/h1/delete", data={"csrf": token, "confirm": ""}).status_code == 400
    assert repo.get_hunt("h1") is not None
    response = client.post("/hunts/h1/delete", data={"csrf": token, "confirm": "h1"}, follow_redirects=False)
    assert response.status_code == 303 and repo.get_hunt("h1") is None


def test_analyst_header_has_no_delete_or_reassess(setup):
    client, repo, _, _, _, password = setup
    test_web_agent_a6.run_row(repo)
    _login_analyst(client, password)
    html = client.get("/hunts/h1").text
    assert "Publish new report revision" in html
    assert "delete-dialog" not in html and "/hunts/h1/delete" not in html and "Re-run assessment" not in html
    assert client.get("/hunts/h1/delete").status_code == 403


def test_counts_say_which_findings_they_cover(setup):
    client, repo, cid, *_ = setup
    lane = repo.candidate(cid)["lane"]
    _seed(repo, [_candidate("agent-1", lane=lane, provenance="agent")])
    html = client.get("/hunts/h1/findings").text
    # header lane chips count deterministic findings, as the live stream does; agent findings are named beside them
    assert 'title="Deterministic findings by lane">Deterministic' in html
    assert f'<b data-lane-count="{lane}">1</b>' in html and "+ 1 AI agent · unconfirmed" in html
    # the Findings tab and its lane filters count what the list shows, agent findings included
    assert re.search(r'Findings <span class="count" title="Reportable findings, including 1 from the AI agent">2</span>',
                     html)
    assert len(_ids(html)) == 2 and "incl. 1 AI" in html
    dialog = html.split('<dialog id="delete-dialog"', 1)[1].split("</dialog>", 1)[0]
    assert "(including 1 from the AI agent)" in dialog and f"2 {lane}" in dialog


def test_header_links_the_latest_report(setup):
    client, *_ = setup
    client.post("/hunts/h1/report", data={"csrf": test_web_agent_a6.csrf(client)})
    html = client.get("/hunts/h1/coverage").text
    assert 'href="/reports/h1/h1-r1.md"' in html and 'href="/reports/h1/h1-r1.docx"' in html


# --------------------------------------------------------------------------------------------------- run details
def test_run_details_shows_long_blobs_as_a_line_that_opens_to_the_full_text(setup):
    client, repo, *_ = setup
    long_reason = "Partial search: " + "; ".join(f"partition {i} timed out after 30 s" for i in range(80)) + HOSTILE
    with repo.engine.begin() as connection:
        connection.execute(t.hunt.update().where(t.hunt.c.id == "h1").values(stop_reason=long_reason))
    html = client.get("/hunts/h1/run").text
    row = html.split('id="stop-reason"', 1)[1].split("</tr>", 1)[0]
    summary = re.search(r"<summary><span>([^<]*)</span>", row).group(1)
    assert len(summary) < 200 and '<details class="blob">' in row
    assert "partition 79 timed out" in row
    assert "<script>" not in html and "&lt;script&gt;" in row
    overview = client.get("/hunts/h1").text
    assert "partition 79" not in overview and 'href="/hunts/h1/run#stop-reason"' in overview


def test_one_line_summary():
    assert hunt_views.one_line("short") == {"summary": "short", "more": False}
    assert hunt_views.one_line("a\n  b") == {"summary": "a b", "more": True}
    long = hunt_views.one_line("First sentence is here. " + "x " * 200)
    assert long == {"summary": "First sentence is here.", "more": True}
    words = hunt_views.one_line("word " * 100, limit=40)
    assert words["more"] and words["summary"].endswith(" …") and len(words["summary"]) <= 42


def test_detail_rows_bound_nested_values():
    rows = hunt_views.detail_rows({"a": "x", "b": list(range(5000)), "c": {"k": "v" * 50000}, "d": None})
    by_key = {row["key"]: row for row in rows}
    assert by_key["a"]["summary"] == "x" and by_key["a"]["json"] is None
    assert by_key["b"]["json"].endswith("[truncated]") and len(by_key["b"]["json"].encode()) < 17000
    assert by_key["c"]["summary"] == "1 field" and by_key["d"]["summary"] == ""


def test_run_details_escape_egress_and_manifest_values(setup):
    client, repo, *_ = setup
    repo.save_model_call({"id": "mc-1", "hunt_id": "h1", "purpose": "agent.test", "model": "<b>model</b>",
                          "options": {}, "prompt_digest": "d", "status": "ok", "provider": "anthropic",
                          "endpoint_host": "<script>host</script>", "egress": "remote", "model_reported": "<i>m</i>"})
    with repo.engine.begin() as connection:
        manifest = repo.get_hunt("h1")["manifest"]
        connection.execute(t.hunt.update().where(t.hunt.c.id == "h1").values(
            manifest={**manifest, "hypothesis": HOSTILE}))
    html = client.get("/hunts/h1/run").text
    assert "Model egress:" in html and "&lt;script&gt;host&lt;/script&gt;" in html
    assert "<script>" not in html and "<b>model</b>" not in html and "<img src=x" not in html
    assert 'id="manifest"' in html and "hypothesis" in html
    assert "<img src=x" not in client.get("/hunts/h1").text


# ------------------------------------------------------------------------------------------------------ escaping
def test_model_text_is_escaped_on_every_tab(setup):
    client, repo, cid, *_ = setup
    test_web_agent_a6.run_row(repo, reason="cap:" + HOSTILE)
    _assessment(repo, cid)
    repo.publish_triage("h1", 1, [{"group_id": "G1", "section": 0, "position": 1, "best_position": 1,
        "rule_id": "r.x", "entity_kind": "host", "entity": HOSTILE, "provenance": "deterministic", "finding_count": 1,
        "finding_ids": [cid], "status": "promoted", "reason": None, "assessment": "likely_attack",
        "incident_label": HOSTILE, "rationale": HOSTILE, "cites": [cid], "prompt_digest": "d", "model": "m"}],
        {"label": "AI triage order (model-proposed; the deterministic order is authoritative)",
         "status": "complete", "mode": "ranked", "pass": 1, "groups": {"total": 1, "triaged": 1}})
    with repo.engine.begin() as connection:
        connection.execute(t.candidate.update().where(t.candidate.c.id == cid).values(claim="Claim " + HOSTILE))
    for suffix in TABS:
        html = client.get("/hunts/h1" + suffix).text
        assert "<script>alert" not in html and "<img src=x" not in html, suffix
    assert "&lt;script&gt;" in client.get("/hunts/h1/assessment").text
    assert "&lt;script&gt;" in client.get("/hunts/h1/triage").text
    overview = client.get("/hunts/h1").text
    assert "AI-generated · unconfirmed" in overview and "&lt;script&gt;alert" in overview


def test_a_template_narrative_is_not_labelled_as_ai_generated(setup):
    client, repo, cid, *_ = setup
    test_web_agent_a6.run_row(repo)
    repo.save_agent_assessment({"id": "template", "hunt_id": "h1", "revision": 1, "source": "template",
        "model": {}, "body": {"overall": [{"text": "Template sentence", "kind": "observed", "cites": [cid]}]},
        "checker": {}, "created_at": utcnow()})
    for suffix in ("", "/assessment"):
        html = client.get("/hunts/h1" + suffix).text
        assert "Template sentence" in html and "template narrative" in html
        assert "AI-generated · unconfirmed</span>" not in html


def test_overview_points_to_egress_from_any_remote_model_call(setup):
    client, repo, *_ = setup
    assert "Model egress:" not in client.get("/hunts/h1").text
    repo.save_model_call({"id": "triage-1", "hunt_id": "h1", "purpose": "triage", "model": "m", "options": {},
                          "prompt_digest": "d", "status": "ok", "provider": "anthropic",
                          "endpoint_host": "api.provider.example", "egress": "remote", "model_reported": "m"})
    html = client.get("/hunts/h1").text
    assert "telemetry excerpts were sent to a remote model endpoint" in html
    assert 'href="/hunts/h1/run#model-egress"' in html


def test_overview_without_an_agent_says_so(setup):
    client, *_ = setup
    html = client.get("/hunts/h1").text
    assert "No AI assessment: this hunt ran without the AI agent." in html
    assert "No AI assessment." in client.get("/hunts/h1/assessment").text


# ------------------------------------------------------------------------------------------------------- catalog
def test_catalog_list_has_no_applicability_column_or_filter_but_the_parameter_still_filters(setup):
    client, *_ = setup
    html = client.get("/catalog").text
    assert "Applicability" not in html and 'name="applicability"' not in html
    assert client.get("/catalog", params={"applicability": "runs"}).status_code == 200


# ---------------------------------------------------------------------------------------------------- live stream
def test_live_hunt_header_streams_and_the_feed_exists_on_every_tab(setup):
    client, repo, *_ = setup
    repo.set_hunt_state("h1", "running")
    for suffix in TABS:
        html = client.get("/hunts/h1" + suffix).text
        assert 'id="live"' in html and 'id="feed"' in html, suffix
    repo.set_hunt_state("h1", "completed_within_scope", detection_result="leads_only")
    test_web_agent_a6.run_row(repo, "running", lease_until=utcnow() - timedelta(minutes=1))
    assert 'id="live"' not in client.get("/hunts/h1").text
