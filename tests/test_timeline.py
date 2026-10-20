"""Attack-path timeline: rows by host, account and IP; link styles keep provenance; filters say what they
hide; analyst links are stored, audited and always labelled as assertions."""
from datetime import UTC, datetime, timedelta

import pytest

from romulus.report.timeline import build_timeline
from tests.test_report import _copy_candidate
from tests.test_web import _csrf, _login, client  # noqa: F401  (pytest fixture)

T0 = datetime(2024, 11, 18, 14, 0, tzinfo=UTC)


def finding(fid, minutes, lane="high", entities=(("host", "web01", "host"),), rule="host.web_shell"):
    return {"id": fid, "lane": lane, "rule_id": rule, "claim": f"claim {fid}",
            "observed_at": str(T0 + timedelta(minutes=minutes)), "entities": [list(e) for e in entities]}


def test_rows_marks_and_link_styles():
    findings = [finding("A", 10), finding("B", 20, entities=(("host", "web01", "host"), ("account", "root", "actor"))),
                finding("C", 30, lane="lead", entities=(("host", "sensor", "observer"), ("ip", "203.0.113.8", "src"))),
                finding("X", 40, lane="context")]
    edges = [{"from": "A", "to": "B", "style": "observed", "link_type": "process_lineage"},
             {"from": "B", "to": "C", "style": "inferred", "link_type": "flow_host_side"}]
    analyst = [{"from_finding": "A", "to_finding": "C", "relation": "same operator"}]
    tl = build_timeline(findings, edges, analyst, T0, T0 + timedelta(hours=1))
    rows = [(r["kind"], r["value"]) for r in tl["rows"]]
    assert rows == [("host", "web01"), ("account", "root"), ("ip", "203.0.113.8")]   # no row for the sensor
    xs = [i["x"] for i in tl["rows"][0]["items"]]
    assert xs == sorted(xs) and len(xs) == 2                                            # time order, context excluded
    styles = {(li["from"], li["to"]): li["style"] for li in tl["links"]}
    assert styles == {("A", "B"): "observed", ("B", "C"): "inferred", ("A", "C"): "analyst"}
    analyst_link = next(li for li in tl["links"] if li["style"] == "analyst")
    assert "analyst assertion, not proven" in analyst_link["label"]


def test_filters_report_what_they_hide():
    findings = [finding("A", 10), finding("B", 20, lane="lead", entities=(("ip", "203.0.113.8", "src"),))]
    edges = [{"from": "A", "to": "B", "style": "inferred", "link_type": "source_ip"}]
    tl = build_timeline(findings, edges, [], T0, T0 + timedelta(hours=1), lanes=["high"], kinds=["host"],
                        styles=["observed"])
    assert tl["hidden"]["findings_by_lane"] == 1 and tl["hidden"]["links_by_style"] == {"inferred": 1}
    tl = build_timeline(findings, edges, [], T0, T0 + timedelta(hours=1), kinds=["host"])
    assert tl["hidden"]["rows_by_kind"] == 1 and tl["hidden"]["links_without_both_ends"] == 1
    tl = build_timeline(findings, edges, [], T0, T0 + timedelta(hours=1), kinds=["account"])
    assert tl["shown_findings"] == 0 and tl["hidden"]["findings_on_hidden_rows"] == 2     # counted, not "shown"


def test_timeline_page_renders_escapes_and_accepts_analyst_links_only_with_csrf(client, tmp_path):  # noqa: F811
    from romulus.config import Settings
    from romulus.hunt import run as hr
    c, pw, cid = client
    repo = hr.open_repo(Settings(home=tmp_path))          # the same database the app under test uses
    second = f"{cid}-b"
    _copy_candidate(repo, cid, second)
    _login(c, pw)
    page = c.get("/hunts/h1/timeline")
    assert page.status_code == 200 and "<svg" in page.text and "<script>alert" not in page.text
    assert page.headers["content-security-policy"].startswith("default-src 'self'")
    form = {"from_finding": cid, "to_finding": second, "relation": "same operator", "note": "my judgement"}
    assert c.post("/hunts/h1/links", data=form, follow_redirects=False).status_code == 403
    bad = c.post("/hunts/h1/links", data={**form, "to_finding": cid, "csrf": _csrf(page.text)}, follow_redirects=False)
    assert bad.status_code == 400
    ok = c.post("/hunts/h1/links", data={**form, "csrf": _csrf(page.text)}, follow_redirects=False)
    assert ok.status_code == 303
    after = c.get("/hunts/h1/timeline").text
    assert "assertion, not proven" in after and "same operator" in after


def test_analyst_links_are_validated_audited_and_reach_the_manifest_as_assertions():
    from romulus.report.manifest import publish_revision
    from romulus.report.markdown import render
    from tests.test_report import _repo_with_finding
    repo, cid = _repo_with_finding()
    _copy_candidate(repo, cid, f"{cid}-b")
    with pytest.raises(ValueError):
        repo.add_analyst_link("h1", cid, cid, "self", None, "web:a")
    with pytest.raises(ValueError):
        repo.add_analyst_link("h1", cid, "not-in-this-hunt", "x", None, "web:a")
    _copy_candidate(repo, cid, f"{cid}-ctx")
    from sqlalchemy import update

    from romulus.store import schema
    with repo.engine.begin() as c:
        c.execute(update(schema.candidate).where(schema.candidate.c.id == f"{cid}-ctx").values(lane="context"))
    with pytest.raises(ValueError):                       # only reportable findings can be joined
        repo.add_analyst_link("h1", cid, f"{cid}-ctx", "x", None, "web:a")
    link = repo.add_analyst_link("h1", cid, f"{cid}-b", "  same   operator ", "line one\n| injected | row |",
                                 "web:analyst1")
    assert link["relation"] == "same operator"
    assert repo.latest_audit("h1", "analyst_link.add")["detail"]["id"] == link["id"]
    manifest = publish_revision(repo, "h1", "test")
    assert manifest["analyst_links"][0]["status"] == "analyst assertion, not proven"
    text = render(manifest)
    assert "Analyst-asserted links (not proven)" in text
    row = next(line for line in text.splitlines() if "same operator" in line)
    assert "line one" in row and "injected" in row                     # the note stays inside its table row
    assert all(edge["style"] != "analyst" for edge in manifest["incident_graph"]["edges"])
