"""FastAPI application. Thin: reads the store, calls services, renders escaped templates."""
from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from romulus.agent.provider import egress_banners
from romulus.config import Settings
from romulus.decide.policy import LANE_ORDER
from romulus.hunt.run import open_repo
from romulus.report.manifest import internal_networks_view, investigations_for_hunt, publish_revision
from romulus.report.markdown import render as render_md
from romulus.site import SiteChangedError, SiteValidationError, load_site_facts, save_site_facts
from romulus.web import site_form
from romulus.web.auth import RateLimiter, Sessions, csrf_ok, verify

HERE = Path(__file__).resolve().parent
COOKIE = "romulus_session"
STATUSES = ("under_review", "confirmed_malicious", "benign", "expected_activity", "unresolved", "escalated")
SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
                               "frame-ancestors 'none'; form-action 'self'; base-uri 'none'",
    "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", "X-Frame-Options": "DENY",
    "Cache-Control": "no-store",
}


def create_app(s: Settings, env_file: Path | None = None) -> FastAPI:
    load_site_facts(s.home)
    repo = open_repo(s)
    sessions = Sessions(s.secret_key.get_secret_value())
    limiter = RateLimiter()
    app = FastAPI(title="ROMULUS", docs_url=None, redoc_url=None, openapi_url=None)
    app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")
    tpl = Jinja2Templates(directory=HERE / "templates")
    tpl.env.autoescape = True

    @app.middleware("http")
    async def headers(request: Request, call_next):
        resp = await call_next(request)
        for k, v in SECURITY_HEADERS.items():
            resp.headers.setdefault(k, v)
        return resp

    def user_of(request: Request) -> dict | None:
        return sessions.read(request.cookies.get(COOKIE))

    def need(request: Request) -> dict:
        u = user_of(request)
        if u is None:
            raise HTTPException(status_code=303, headers={"Location": "/login"})
        return u

    def page(request, name, user, **ctx):
        return tpl.TemplateResponse(request, name, {"user": user, "csrf": user["csrf"] if user else "",
                                                     "banner": "UNCLASSIFIED // FOR TRAINING USE", **ctx})

    # ------------------------------------------------------------------ auth
    @app.get("/login", response_class=HTMLResponse)
    def login_form(request: Request, error: str = ""):
        return tpl.TemplateResponse(request, "login.html", {"error": error, "user": None,
                                                            "banner": "UNCLASSIFIED // FOR TRAINING USE"})

    @app.post("/login")
    def login(request: Request, username: str = Form(...), password: str = Form(...)):
        client = request.client.host if request.client else "unknown"
        u = verify(repo.engine, username, password, client, limiter)
        if u is None:
            repo.audit(username[:64], "web.login_failed", detail={"client": client})
            return RedirectResponse("/login?error=1", status_code=303)
        repo.audit(u["username"], "web.login", detail={"client": client})
        resp = RedirectResponse("/", status_code=303)
        resp.set_cookie(COOKIE, sessions.issue(u), httponly=True, samesite="strict",
                        secure=bool(os.environ.get("ROMULUS_COOKIE_SECURE", "1") == "1" and s.web_tls_enabled))
        return resp

    @app.post("/logout")
    def logout(request: Request, csrf: str = Form("")):
        u = need(request)
        if not csrf_ok(u, csrf):
            raise HTTPException(403, "bad CSRF token")
        resp = RedirectResponse("/login", status_code=303)
        resp.delete_cookie(COOKIE)
        return resp

    # ------------------------------------------------------------------ hunts
    @app.get("/", response_class=HTMLResponse)
    def hunts(request: Request):
        u = need(request)
        rows = [{**h, "lanes": repo.lane_counts(h["id"])} for h in repo.list_hunts()]
        deleted = request.query_params.get("deleted", "")
        # only confirm a deletion that the audit log actually records (the query string is spoofable)
        confirmed = deleted if deleted and repo.latest_audit(deleted, "hunt.delete") else ""
        return page(request, "hunts.html", u, hunts=rows, deleted=confirmed)

    @app.get("/hunts/new", response_class=HTMLResponse)
    def new_hunt_form(request: Request):
        u = need(request)
        return page(request, "new_hunt.html", u, tz=s.mission_timezone, sources=s.es_index_patterns,
                    model=s.ollama_model_triage)

    @app.post("/hunts")
    def start_hunt(request: Request, start: str = Form(...), end: str = Form(...), style: str = Form("broad"),
                   hypothesis: str = Form(""), agent: str = Form(""), csrf: str = Form("")):
        u = need(request)
        if not csrf_ok(u, csrf):
            raise HTTPException(403, "bad CSRF token")
        try:
            for v in (start, end):
                datetime.fromisoformat(v)
        except ValueError:
            raise HTTPException(400, "start/end must be ISO 8601 times") from None
        if style not in ("broad", "directed"):
            raise HTTPException(400, "bad style")
        if agent not in ("", "model"):
            raise HTTPException(400, "bad agent option")
        mode = "model" if agent == "model" else "off"     # unchecked: deterministic search only
        cmd = [sys.executable, "-m", "romulus.cli"] + (["--env-file", str(env_file)] if env_file else []) + \
              ["hunt", "start", "--start", start, "--end", end, "--style", style, "--agent-mode", mode]
        if hypothesis.strip():
            cmd += ["--hypothesis", hypothesis.strip()[:500]]
        s.logs_dir.mkdir(parents=True, exist_ok=True)
        env = {**os.environ, "USER": f"web:{u['u']}"}
        with open(s.logs_dir / f"hunt-{datetime.now():%Y%m%d-%H%M%S}.log", "ab") as log:
            subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT, env=env, start_new_session=True)
        repo.audit(f"web:{u['u']}", "web.hunt_start", detail={"start": start, "end": end, "style": style,
                                                                "agent_mode": mode})
        return RedirectResponse("/?started=1", status_code=303)

    @app.get("/hunts/{hunt_id}", response_class=HTMLResponse)
    def hunt_detail(request: Request, hunt_id: str, lane: str = ""):
        u = need(request)
        h = repo.get_hunt(hunt_id)
        if h is None:
            raise HTTPException(404)
        cands = repo.candidates(hunt_id, [lane] if lane in LANE_ORDER else None)
        cands.sort(key=lambda c: (LANE_ORDER.get(c["lane"], 9), -c["priority"], str(c["ts"])))
        if not lane:
            cands = [c for c in cands if c["lane"] != "context"]
        from romulus.report.manifest import coverage_for_hunt
        cov = coverage_for_hunt(repo, hunt_id)
        with repo.engine.connect() as c:
            from sqlalchemy import select

            from romulus.store import schema as t
            reports = c.execute(select(t.report_manifest.c.id, t.report_manifest.c.revision,
                                       t.report_manifest.c.created_at).where(t.report_manifest.c.hunt_id == hunt_id)
                                .order_by(t.report_manifest.c.revision.desc())).mappings().all()
        agent_audit = repo.latest_audit(hunt_id, "hunt.agent_summary")
        agent_summary = agent_audit["detail"] if agent_audit else None
        investigations = investigations_for_hunt(repo, hunt_id)
        ai_audit = repo.latest_audit(hunt_id, "hunt.ai_agent_summary")
        banners = egress_banners(h["manifest"].get("ai_agent"), repo.agent_usage(hunt_id))
        return page(request, "hunt.html", u, h=h, cands=cands, lanes=repo.lane_counts(hunt_id), lane=lane,
                    coverage=cov["rules"], tasks=repo.tasks(hunt_id), reports=reports, agent=agent_summary,
                    investigations=investigations, ai_agent=ai_audit["detail"] if ai_audit else None,
                    egress_banners=banners,
                    internal_networks=internal_networks_view(repo, hunt_id, h["manifest"]))

    def _timeline_findings(hunt_id: str) -> list[dict]:
        return [{"id": c["id"], "lane": c["lane"], "rule_id": c["rule_id"], "claim": c["claim"],
                 "observed_at": str(c["ts"]), "entities": c["entities"], "event_ids": c["event_ids"],
                 "source_link_id": c.get("source_link_id")}
                for c in repo.candidates(hunt_id, ["urgent", "high", "lead"])]

    @app.get("/hunts/{hunt_id}/timeline", response_class=HTMLResponse)
    def timeline(request: Request, hunt_id: str):
        from romulus.detect.registry import ALL_PLAYBOOKS
        from romulus.report.incidents import build_incident_graph
        from romulus.report.timeline import LANES, LINK_STYLES, ROW_KINDS, build_timeline
        u = need(request)
        h = repo.get_hunt(hunt_id)
        if h is None:
            raise HTTPException(404)
        params = request.query_params
        explicit = "lane" in params or "kind" in params or "style" in params
        lanes = [v for v in params.getlist("lane") if v in LANES] if explicit else list(LANES)
        kinds = [v for v in params.getlist("kind") if v in ROW_KINDS] if explicit else list(ROW_KINDS)
        styles = [v for v in params.getlist("style") if v in LINK_STYLES] if explicit else list(LINK_STYLES)
        findings = _timeline_findings(hunt_id)
        graph = build_incident_graph(repo, hunt_id, findings)
        titles = {p.id: p.title for p in ALL_PLAYBOOKS}
        analyst = repo.analyst_links(hunt_id)
        window = h["manifest"].get("window") or {}
        tl = build_timeline(findings, graph["edges"], analyst, window.get("start"), window.get("end"),
                            titles=titles, lanes=lanes, kinds=kinds, styles=styles)
        pick = sorted(({**f, "title": titles.get(f["rule_id"], f["rule_id"])} for f in findings),
                      key=lambda f: (f["observed_at"], f["id"]))
        return page(request, "timeline.html", u, h=h, tl=tl, analyst_links=analyst, pick=pick,
                    all_lanes=LANES, all_kinds=ROW_KINDS, all_styles=LINK_STYLES)

    @app.post("/hunts/{hunt_id}/links")
    def add_link(request: Request, hunt_id: str, from_finding: str = Form(...), to_finding: str = Form(...),
                 relation: str = Form(...), note: str = Form(""), csrf: str = Form("")):
        u = need(request)
        if not csrf_ok(u, csrf):
            raise HTTPException(403, "bad CSRF token")
        try:
            repo.add_analyst_link(hunt_id, from_finding, to_finding, relation, note, f"web:{u['u']}")
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        return RedirectResponse(f"/hunts/{hunt_id}/timeline", status_code=303)

    @app.get("/hunts/{hunt_id}/stream")
    async def stream(request: Request, hunt_id: str):
        need(request)
        if repo.get_hunt(hunt_id) is None:
            raise HTTPException(404)

        async def gen():
            seen: set[str] = set()
            while not await request.is_disconnected():
                h = repo.get_hunt(hunt_id)
                fresh = [c for c in repo.candidates(hunt_id, ["urgent", "high", "lead"]) if c["id"] not in seen]
                for c in sorted(fresh, key=lambda c: str(c["ts"])):
                    seen.add(c["id"])
                    yield "event: finding\ndata: " + json.dumps({"id": c["id"], "lane": c["lane"],
                                                                 "rule": c["rule_id"], "claim": c["claim"][:300],
                                                                 "ts": str(c["ts"])}) + "\n\n"
                yield "event: state\ndata: " + json.dumps({"state": h["execution_state"],
                                                           "lanes": repo.lane_counts(hunt_id)}) + "\n\n"
                if h["execution_state"] not in ("planned", "running"):
                    break
                await asyncio.sleep(2)
        return StreamingResponse(gen(), media_type="text/event-stream")

    # ------------------------------------------------------------------ findings
    @app.get("/findings/{cid}", response_class=HTMLResponse)
    def finding(request: Request, cid: str):
        u = need(request)
        c = repo.candidate(cid)
        if c is None:
            raise HTTPException(404)
        events = repo.citation_events(c["hunt_id"], c["event_ids"][:20])
        raw_ids = [rid for e in events for rid in e["raw_ids"]]
        raws = repo.raw_records(raw_ids[:40])
        gates = dict(c["gate_results"])
        notes = gates.pop("_notes", [])
        pred_fields = {p["field"] for p in c["predicate_fields"]}
        return page(request, "finding.html", u, c=c, gates=gates, notes=notes, events=events, raws=raws,
                    pred_fields=pred_fields, dispositions=repo.dispositions(cid), statuses=STATUSES,
                    pretty=lambda v: json.dumps(v, indent=2, ensure_ascii=False, sort_keys=True, default=str))

    @app.post("/findings/{cid}/disposition")
    def disposition(request: Request, cid: str, status: str = Form(...), note: str = Form(""),
                    csrf: str = Form("")):
        u = need(request)
        if not csrf_ok(u, csrf):
            raise HTTPException(403, "bad CSRF token")
        if status not in STATUSES or repo.candidate(cid) is None:
            raise HTTPException(400)
        repo.add_disposition(cid, f"web:{u['u']}", status, note.strip()[:2000] or None)
        return RedirectResponse(f"/findings/{cid}", status_code=303)

    # ------------------------------------------------------------------ deletion
    def need_lead(request: Request) -> dict:
        """Lead check against the database, not just the cookie: a demoted or disabled account
        must lose delete rights immediately, not when its 8-hour session expires."""
        u = need(request)
        from sqlalchemy import select as _select

        from romulus.store import schema as _t
        with repo.engine.connect() as c:
            row = c.execute(_select(_t.user.c.role, _t.user.c.disabled)
                            .where(_t.user.c.username == u.get("u"))).first()
        if u.get("r") != "lead" or row is None or row.disabled or row.role != "lead":
            raise HTTPException(403, "only an active lead account can do this")
        return u

    @app.get("/hunts/{hunt_id}/delete", response_class=HTMLResponse)
    def delete_confirm(request: Request, hunt_id: str):
        u = need_lead(request)
        h = repo.get_hunt(hunt_id)
        if h is None:
            raise HTTPException(404)
        return page(request, "delete_hunt.html", u, h=h, preview=repo.deletion_preview(hunt_id),
                    lanes=repo.lane_counts(hunt_id))

    @app.post("/hunts/{hunt_id}/delete")
    def delete_hunt(request: Request, hunt_id: str, csrf: str = Form(""), confirm: str = Form("")):
        u = need_lead(request)
        if not csrf_ok(u, csrf):
            raise HTTPException(403, "bad CSRF token")
        if confirm != hunt_id:
            raise HTTPException(400, "deletion not confirmed")
        try:
            counts = repo.delete_hunt(hunt_id, actor=f"web:{u['u']}")
        except KeyError:
            raise HTTPException(404) from None
        except ValueError as e:
            raise HTTPException(409, str(e)) from None
        # generated report files for this hunt, path-checked to stay inside the reports directory
        rdir = (s.reports_dir / hunt_id).resolve()
        if s.reports_dir.resolve() in rdir.parents and rdir.is_dir():
            import shutil
            shutil.rmtree(rdir, ignore_errors=True)
        # Return freed pages to the filesystem, but never while a hunt may be writing: VACUUM blocks
        # writers and could push a running sweep past its busy timeout. Compaction then simply waits
        # for the next deletion made while nothing is running.
        if not repo.hunts_with_live_lease():
            try:
                with repo.engine.connect() as c:
                    c.exec_driver_sql("VACUUM")
            except Exception:  # noqa: BLE001, S110 - best-effort; the deletion already committed
                pass
        return RedirectResponse(f"/?deleted={hunt_id}&removed={counts.get('candidates', 0)}", status_code=303)

    # ------------------------------------------------------------------ site setup
    def site_page(request: Request, u: dict, content: dict, digest: str, present: bool, error: str = "",
                  status_code: int = 200):
        from romulus.detect.netdef import SiteNetworks
        try:
            networks = SiteNetworks.from_settings(s).summary()
        except ValueError as exc:
            networks = f"not usable: {exc}"
        response = page(request, "site.html", u, form=site_form.view(content), digest=digest, present=present,
                        error=error, saved=request.query_params.get("saved") == "1", networks=networks,
                        env_networks=bool(s.internal_networks or s.external_networks),
                        running=repo.hunts_with_live_lease())
        response.status_code = status_code
        return response

    @app.get("/site", response_class=HTMLResponse)
    def site_setup(request: Request):
        u = need_lead(request)
        try:
            facts = load_site_facts(s.home)
        except SiteValidationError as exc:
            raise HTTPException(409, f"{exc}. Fix or remove the file on the server; the page edits only a valid "
                                     "file.") from None
        return site_page(request, u, facts.content, facts.digest, facts.present)

    @app.post("/site")
    async def save_site(request: Request):
        u = need_lead(request)
        form = await request.form(max_fields=site_form.max_fields())
        if not csrf_ok(u, str(form.get("csrf", ""))):
            raise HTTPException(403, "bad CSRF token")
        digest = str(form.get("digest", ""))
        try:
            content = site_form.parse_form(form)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from None
        if (content.get("internal_networks") or content.get("external_networks")) and (
                s.internal_networks or s.external_networks):
            # Saving would leave the networks set in two places, which every new hunt then refuses.
            return site_page(request, u, content, digest, bool(digest), status_code=400, error=(
                "internal networks are already set on this server in ROMULUS_INTERNAL_NETWORKS or "
                "ROMULUS_EXTERNAL_NETWORKS: leave the network boxes empty, or remove those settings first"))

        def record(before, after) -> None:
            changed = site_form.describe_change(before.content, after.content)
            detail = {"before_digest": before.digest or None, "after_digest": after.digest, "changed": changed}
            # Both versions fit in the record (the file is bounded); the audit log is then the file's history.
            detail |= {"before": before.content if before.present else None, "after": after.content}
            repo.audit(f"web:{u['u']}", "site.update", detail=detail)

        try:
            save_site_facts(s.home, content, digest, record=record)
        except SiteValidationError as exc:
            return site_page(request, u, content, digest, bool(digest), error=str(exc), status_code=400)
        except SiteChangedError as exc:
            raise HTTPException(409, str(exc)) from None
        return RedirectResponse("/site?saved=1", status_code=303)

    # ------------------------------------------------------------------ reports
    @app.post("/hunts/{hunt_id}/report")
    def make_report(request: Request, hunt_id: str, csrf: str = Form("")):
        u = need(request)
        if not csrf_ok(u, csrf):
            raise HTTPException(403, "bad CSRF token")
        m = publish_revision(repo, hunt_id, f"web:{u['u']}")
        out = s.reports_dir / hunt_id
        out.mkdir(parents=True, exist_ok=True)
        (out / f"{m['revision']['id']}.json").write_text(json.dumps(m, indent=2, sort_keys=True), encoding="utf-8")
        (out / f"{m['revision']['id']}.md").write_text(render_md(m), encoding="utf-8")
        return RedirectResponse(f"/hunts/{hunt_id}#reports", status_code=303)

    @app.get("/reports/{hunt_id}/{rev_id}.{ext}")
    def get_report(request: Request, hunt_id: str, rev_id: str, ext: str):
        need(request)
        if ext not in ("md", "json") or not rev_id.startswith(hunt_id + "-r") or "/" in rev_id or ".." in rev_id:
            raise HTTPException(404)
        p = (s.reports_dir / hunt_id / f"{rev_id}.{ext}").resolve()
        if s.reports_dir.resolve() not in p.parents or not p.exists():
            raise HTTPException(404)
        media = "text/markdown; charset=utf-8" if ext == "md" else "application/json"
        return PlainTextResponse(p.read_text(encoding="utf-8"), media_type=media,
                                 headers={"Content-Disposition": f'attachment; filename="{rev_id}.{ext}"'})

    @app.exception_handler(HTTPException)
    async def http_exc(request: Request, exc: HTTPException):
        if exc.status_code == 303:
            return RedirectResponse(exc.headers["Location"], status_code=303)
        return PlainTextResponse(str(exc.detail), status_code=exc.status_code)

    return app
