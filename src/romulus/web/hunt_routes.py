"""The hunt workspace: one URL per tab, all sharing the sticky hunt header."""
from __future__ import annotations

from fastapi import Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from romulus.agent.provider import egress_banners
from romulus.report.manifest import coverage_for_hunt, internal_networks_view, investigations_for_hunt
from romulus.web import agent_views, hunt_views
from romulus.web.auth import csrf_ok

TIMELINE_PAGE = 50


def make_hunt_page(repo, page):
    """Render a hunt tab: the template gets the hunt, the shared header and the tab's own context. A tab that lists
    findings builds its header first and passes it as `head`: the live-stream cursor must be read before the rows,
    so a finding stored while the page renders reaches the browser through the stream."""
    def hunt_page(request: Request, name: str, user: dict, h: dict, tab: str, head: dict | None = None, **ctx):
        message = agent_views.REASSESS_MESSAGES.get(request.query_params.get("agent_message"), "")
        return page(request, name, user, h=h, head=head or hunt_views.header(repo, h, user, tab),
                    agent_message=message, **ctx)
    return hunt_page


def register_hunt_routes(app, repo, s, need, hunt_page):
    def hunt(hunt_id: str) -> dict:
        h = repo.get_hunt(hunt_id)
        if h is None:
            raise HTTPException(404)
        return h

    def cursor(value: str) -> str:
        if len(value) > 512:
            raise HTTPException(400, "Invalid page cursor")
        return value

    @app.get("/hunts/{hunt_id}", response_class=HTMLResponse)
    def hunt_overview(request: Request, hunt_id: str):
        u = need(request)
        params = request.query_params
        if "lane" in params or "after" in params:
            # a findings query (lane or page cursor) on the hunt URL lists findings
            return RedirectResponse(hunt_views.hunt_url(hunt_id, "/findings", lane=params.get("lane", ""),
                                                        after=params.get("after", "")), status_code=303)
        h = hunt(hunt_id)
        head = hunt_views.header(repo, h, u, "overview")
        return hunt_page(request, "hunt_overview.html", u, h, "overview", head, ov=hunt_views.overview(repo, h),
                         internal_networks=internal_networks_view(repo, hunt_id, h["manifest"]),
                         reports=hunt_views.reports(repo, hunt_id))

    @app.get("/hunts/{hunt_id}/findings", response_class=HTMLResponse)
    def hunt_findings(request: Request, hunt_id: str, lane: str = "", rule: str = "", after: str = ""):
        u = need(request)
        h = hunt(hunt_id)
        if len(rule) > 256:
            raise HTTPException(400, "Rule filter is too long")
        head = hunt_views.header(repo, h, u, "findings")
        try:
            view = hunt_views.findings(repo, hunt_id, lane=lane, rule=rule, after=cursor(after))
        except ValueError as error:
            raise HTTPException(400, "Invalid page cursor") from error
        agent_views.validate_hypothesis_links(repo, hunt_id, view["rows"])
        return hunt_page(request, "hunt_findings.html", u, h, "findings", head, fv=view)

    @app.get("/hunts/{hunt_id}/assessment", response_class=HTMLResponse)
    def hunt_assessment(request: Request, hunt_id: str):
        u = need(request)
        h = hunt(hunt_id)
        usage = repo.agent_usage(hunt_id, group_limit=50)
        return hunt_page(request, "hunt_assessment.html", u, h, "assessment",
                         ai_panel=agent_views.panel(repo, h, usage))

    @app.get("/hunts/{hunt_id}/triage", response_class=HTMLResponse)
    def triage(request: Request, hunt_id: str):
        """The AI triage order, from the same builder the report manifest uses; templates escape every field. The page
        checks staleness by finding count and final ranking; the report and the export verify the whole order."""
        from romulus.report.triage import triage_view
        u = need(request)
        h = hunt(hunt_id)
        return hunt_page(request, "triage.html", u, h, "triage", view=triage_view(repo, hunt_id))

    def _timeline_findings(hunt_id: str) -> list[dict]:
        return [{"id": c["id"], "lane": c["lane"], "rule_id": c["rule_id"], "claim": c["claim"],
                 "observed_at": str(c["ts"]) if c["ts"] is not None else None,
                 "entities": c["entities"], "event_ids": c["event_ids"],
                 "source_link_id": c.get("source_link_id"), "provenance": c.get("provenance", "deterministic")}
                for c in repo.candidates(hunt_id, ["urgent", "high", "lead"])]

    @app.get("/hunts/{hunt_id}/timeline", response_class=HTMLResponse)
    def timeline(request: Request, hunt_id: str, at: int = 0):
        from romulus.detect.metadata import hunt_rule_metadata
        from romulus.report.incidents import build_incident_graph
        from romulus.report.timeline import LANES, LINK_STYLES, ROW_KINDS, build_timeline
        u = need(request)
        h = hunt(hunt_id)
        params = request.query_params
        explicit = "lane" in params or "kind" in params or "style" in params
        lanes = [v for v in params.getlist("lane") if v in LANES] if explicit else list(LANES)
        kinds = [v for v in params.getlist("kind") if v in ROW_KINDS] if explicit else list(ROW_KINDS)
        styles = [v for v in params.getlist("style") if v in LINK_STYLES] if explicit else list(LINK_STYLES)
        head = hunt_views.header(repo, h, u, "timeline")
        findings = _timeline_findings(hunt_id)
        graph = build_incident_graph(repo, hunt_id, findings)
        titles = {rule_id: rule.title for rule_id, rule in
                  hunt_rule_metadata(repo, manifest=h['manifest']).items()}
        analyst = repo.analyst_links(hunt_id)
        window = h["manifest"].get("window") or {}
        tl = build_timeline(findings, graph["edges"], analyst, window.get("start"), window.get("end"),
                            titles=titles, lanes=lanes, kinds=kinds, styles=styles)
        # The chronological list follows the lane filter and is paged, so every finding stays reachable.
        chronological = sorted(({**f, "title": titles.get(f["rule_id"], f["rule_id"])} for f in findings
                                if f["lane"] in tl["filters"]["lanes"]),
                               key=lambda f: (f["observed_at"] is None, f["observed_at"] or "", f["id"]))
        at = max(0, min(at, max(0, len(chronological) - 1)))
        shown = chronological[at:at + TIMELINE_PAGE]
        keep = [(key, value) for key, value in params.multi_items() if key in ("lane", "kind", "style")]

        def at_url(offset):
            from urllib.parse import urlencode
            return hunt_views.hunt_url(hunt_id, "/timeline") + "?" + urlencode([*keep, ("at", offset)]) + "#chronology"
        return hunt_page(request, "timeline.html", u, h, "timeline", head, tl=tl, analyst_links=analyst,
                         has_agent_marks=any(f.get("provenance") == "agent" for f in findings),
                         chronology=shown, chronology_total=len(chronological), chronology_first=at + 1 if shown else 0,
                         chronology_more=max(0, len(chronological) - at - len(shown)),
                         chronology_next=at_url(at + TIMELINE_PAGE) if at + TIMELINE_PAGE < len(chronological) else None,
                         chronology_prev=at_url(max(0, at - TIMELINE_PAGE)) if at else None,
                         all_lanes=LANES, all_kinds=ROW_KINDS, all_styles=LINK_STYLES)

    @app.post("/hunts/{hunt_id}/links")
    def add_link(request: Request, hunt_id: str, from_finding: str = Form(...), to_finding: str = Form(...),
                 relation: str = Form(...), note: str = Form(""), csrf: str = Form("")):
        u = need(request)
        if not csrf_ok(u, csrf):
            raise HTTPException(403, "bad CSRF token")
        try:
            repo.add_analyst_link(hunt_id, from_finding.strip(), to_finding.strip(), relation, note, f"web:{u['u']}")
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        return RedirectResponse(hunt_views.hunt_url(hunt_id, "/timeline"), status_code=303)

    @app.get("/hunts/{hunt_id}/coverage", response_class=HTMLResponse)
    def hunt_coverage(request: Request, hunt_id: str, show: str = "", page: int = 1):
        u = need(request)
        h = hunt(hunt_id)
        cov = coverage_for_hunt(repo, hunt_id)
        zeek_visibility = cov.get("zeek_visibility")
        zeek_visibility_bundled = False
        if zeek_visibility:
            snapshot = zeek_visibility["snapshot"]
            digest = snapshot.get("sha256", "")
            if (isinstance(digest, str) and len(digest) == 64
                    and all(char in "0123456789abcdef" for char in digest)):
                filename = f"zeek-visibility-{digest}.jsonl"
                appendix = (s.reports_dir / hunt_id / filename).resolve()
                zeek_visibility_bundled = (snapshot.get("filename") == filename
                    and s.reports_dir.resolve() in appendix.parents and appendix.is_file())
        view = hunt_views.coverage_page(cov["rules"], show=show, page=page)

        def page_url(number, show_class=view["show"]):
            return hunt_views.hunt_url(hunt_id, "/coverage", show=show_class, page=number if number > 1 else "")
        return hunt_page(request, "hunt_coverage.html", u, h, "coverage", cv=view, page_url=page_url,
                         zeek_visibility=zeek_visibility, zeek_visibility_bundled=zeek_visibility_bundled)

    @app.get("/hunts/{hunt_id}/run", response_class=HTMLResponse)
    def hunt_run(request: Request, hunt_id: str, tasks_after: str = ""):
        u = need(request)
        h = hunt(hunt_id)
        agent_audit = repo.latest_audit(hunt_id, "hunt.agent_summary")
        ai_audit = repo.latest_audit(hunt_id, "hunt.ai_agent_summary")
        agent_usage = repo.agent_usage(hunt_id, group_limit=50)
        banners = [agent_views.clip(banner, 1000) for banner in
                   egress_banners(h["manifest"].get("ai_agent"), agent_usage)]
        # calls a model other than the configured one answered (a provider's refusal fallback)
        answered_by = [{**r, "model": agent_views.clip(r["model"], 300),
                        "model_reported": agent_views.clip(r["model_reported"], 300)}
                       for r in agent_usage["models_reported"] if r["model_reported"] != r["model"]]
        networks = internal_networks_view(repo, hunt_id, h["manifest"])
        return hunt_page(request, "hunt_run.html", u, h, "run",
                         agent=agent_audit["detail"] if agent_audit else None,
                         ai_agent=ai_audit["detail"] if ai_audit else None,
                         investigations=investigations_for_hunt(repo, hunt_id),
                         egress_banners=[{**hunt_views.one_line(text), "full": text} for text in banners],
                         answered_by=answered_by,
                         ai_panel=agent_views.panel(repo, h, agent_usage, with_assessment=False),
                         internal_networks=networks,
                         network_rows=hunt_views.detail_rows({key: value for key, value in networks.items()
                                                              if key not in ("line", "summary", "warning")}),
                         stop_reason={**hunt_views.one_line(h["stop_reason"]), "full": h["stop_reason"] or ""},
                         manifest_rows=hunt_views.detail_rows(h["manifest"]),
                         tasks=hunt_views.tasks_page(repo, hunt_id, after=cursor(tasks_after)))
