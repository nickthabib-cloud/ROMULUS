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
from fastapi.responses import (
    FileResponse,
    HTMLResponse,
    PlainTextResponse,
    RedirectResponse,
    StreamingResponse,
)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.concurrency import run_in_threadpool

from romulus.agent.provider import agent_readiness, egress_banners
from romulus.config import Settings
from romulus.evidence.raw_citation import RAW_GATE, RAW_LABEL_PLURAL, raw_record_view
from romulus.hunt.run import open_repo
from romulus.report.bundle import write_reports
from romulus.report.manifest import publish_revision
from romulus.site import SiteChangedError, SiteValidationError, load_site_facts, save_site_facts
from romulus.store.db import compact, maintenance_lease
from romulus.web import agent_views, site_form
from romulus.web.agent_routes import register_agent_routes
from romulus.web.auth import RateLimiter, Sessions, authenticate, csrf_ok, end_sessions, session_user
from romulus.web.catalog_routes import register_catalog_routes
from romulus.web.control_routes import new_hunt_context, register_control_routes, start_grant
from romulus.web.hunt_routes import make_hunt_page, register_hunt_routes
from romulus.web.indicator_routes import IndicatorBodyLimit, register_indicator_routes
from romulus.web.request_routes import DetectionRequestBodyLimit, register_request_routes
from romulus.web_exposure import cookie_secure

HERE = Path(__file__).resolve().parent
COOKIE = "romulus_session"
# recorded in place of a submitted username that names no account: it may be a password typed in the wrong field
UNKNOWN_ACCOUNT = "(unknown account)"
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
    app.add_middleware(IndicatorBodyLimit)
    app.add_middleware(DetectionRequestBodyLimit)
    app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")
    tpl = Jinja2Templates(directory=HERE / "templates")
    tpl.env.autoescape = True

    @app.middleware("http")
    async def headers(request: Request, call_next):
        resp = await call_next(request)
        for k, v in SECURITY_HEADERS.items():
            resp.headers.setdefault(k, v)
        return resp

    def need(request: Request) -> dict:
        """The signed session, checked against the account on every request: a missing or disabled account, or a
        session from before a logout, disable, role or password change, is sent to the login page. The role is the
        account's current one, never the one the cookie was issued with."""
        u = sessions.read(request.cookies.get(COOKIE))
        if u is not None:
            u = session_user(repo.engine, u)
        if u is None:
            raise HTTPException(status_code=303, headers={"Location": "/login"})
        return u

    def page(request, name, user, **ctx):
        return tpl.TemplateResponse(request, name, {"user": user, "csrf": user["csrf"] if user else "",
                                                     "banner": "UNCLASSIFIED // FOR TRAINING USE", **ctx})

    # ------------------------------------------------------------------ auth
    register_indicator_routes(app, repo, need, page)
    register_catalog_routes(app, repo, need, page)
    register_request_routes(app, repo, need, page)
    hunt_page = make_hunt_page(repo, page)
    register_agent_routes(app, repo, need, page, hunt_page)

    @app.get("/login", response_class=HTMLResponse)
    def login_form(request: Request, error: str = ""):
        return tpl.TemplateResponse(request, "login.html", {"error": error, "user": None,
                                                            "banner": "UNCLASSIFIED // FOR TRAINING USE"})

    @app.post("/login")
    async def login(request: Request, username: str = Form(...), password: str = Form(...)):
        # the connection's address, or the forwarded one when the connection comes from a trusted proxy
        client = request.client.host if request.client else "unknown"
        delay = limiter.admit(client)
        if delay:
            # an address with many recent failures waits its turn (parallel attempts queue); no thread is held
            await asyncio.sleep(delay)
        u, known = await run_in_threadpool(authenticate, repo.engine, username, password, client, limiter)
        if u is None:
            await run_in_threadpool(repo.audit, username[:64] if known else UNKNOWN_ACCOUNT, "web.login_failed",
                                    detail={"client": client})
            return RedirectResponse("/login?error=1", status_code=303)
        await run_in_threadpool(repo.audit, u["username"], "web.login", detail={"client": client})
        resp = RedirectResponse("/", status_code=303)
        resp.set_cookie(COOKIE, sessions.issue(u), httponly=True, samesite="strict",
                        secure=cookie_secure(s, request.url.scheme))
        return resp

    @app.post("/logout")
    def logout(request: Request, csrf: str = Form("")):
        u = need(request)
        if not csrf_ok(u, csrf):
            raise HTTPException(403, "bad CSRF token")
        # every session of the account ends, not only this browser's copy of the cookie
        end_sessions(repo.engine, u["u"])
        repo.audit(u["u"], "web.logout", detail={"client": request.client.host if request.client else "unknown"})
        resp = RedirectResponse("/login", status_code=303)
        resp.delete_cookie(COOKIE, httponly=True, samesite="strict", secure=cookie_secure(s, request.url.scheme))
        return resp

    # ------------------------------------------------------------------ hunts
    @app.get("/", response_class=HTMLResponse)
    def hunts(request: Request, after: str = ""):
        from urllib.parse import urlencode

        from sqlalchemy import and_, func, not_, select

        from romulus.store import schema as tables
        from romulus.store.repo import triage_placeholder_clause
        u = need(request)
        if len(after) > 512:
            raise HTTPException(400, "Invalid page cursor")
        with repo.engine.connect() as connection:
            where = (tables.hunt.c.id < after,) if after else ()
            rows = [dict(row) for row in connection.execute(select(tables.hunt,
                tables.agent_run.c.state.label("ai_state")).select_from(tables.hunt.outerjoin(
                tables.agent_run, and_(tables.agent_run.c.hunt_id == tables.hunt.c.id,
                                       not_(triage_placeholder_clause())))).where(*where)
                .order_by(tables.hunt.c.id.desc()).limit(50)).mappings()]
            more = int(connection.execute(select(func.count()).select_from(tables.hunt).where(
                tables.hunt.c.id < rows[-1]["id"])).scalar_one()) if rows else 0
        for row in rows:
            row["lanes"] = repo.lane_counts(row["id"])
        next_url = "?" + urlencode({"after": rows[-1]["id"]}) if more else None
        deleted = request.query_params.get("deleted", "")
        # only confirm a deletion that the audit log actually records (the query string is spoofable)
        confirmed = deleted if deleted and repo.latest_audit(deleted, "hunt.delete") else ""
        return page(request, "hunts.html", u, hunts=rows, deleted=confirmed, more=more, next_url=next_url,
                    compaction_failed=bool(confirmed and repo.latest_audit(confirmed, "hunt.compaction_failed")))

    @app.get("/hunts/new", response_class=HTMLResponse)
    def new_hunt_form(request: Request):
        u = need(request)
        readiness = agent_readiness(s)
        provenance = {**readiness.provenance(s), "requested": True}
        return page(request, "new_hunt.html", u, tz=s.mission_timezone, sources=s.es_index_patterns,
                    readiness=readiness, agent_checked=s.agent_default == "on" and readiness.ready,
                    egress_banners=egress_banners(provenance, {}), budget=new_hunt_context(s, repo, u))

    @app.post("/hunts")
    def start_hunt(request: Request, start: str = Form(...), end: str = Form(...), style: str = Form("broad"),
                   hypothesis: str = Form(""), agent: str = Form(""), csrf: str = Form(""),
                   effort: str = Form("standard"), max_calls: str = Form(""), max_tokens: str = Form(""),
                   minutes: str = Form(""), max_cost_usd: str = Form(""), max_source_queries: str = Form(""),
                   max_initial_hypotheses: str = Form(""), max_hypotheses: str = Form(""),
                   max_sessions_per_hypothesis: str = Form(""), max_tool_calls_per_session: str = Form("")):
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
        requested = agent == "model"
        # the agent budget, checked against the account's role now and handed to the hunt process as a grant
        grant, budget = start_grant(s, repo, u, {
            "effort": effort, "max_calls": max_calls, "max_tokens": max_tokens, "minutes": minutes,
            "max_cost_usd": max_cost_usd, "max_source_queries": max_source_queries,
            "max_initial_hypotheses": max_initial_hypotheses, "max_hypotheses": max_hypotheses,
            "max_sessions_per_hypothesis": max_sessions_per_hypothesis,
            "max_tool_calls_per_session": max_tool_calls_per_session})
        cmd = [sys.executable, "-m", "romulus.cli"] + (["--env-file", str(env_file)] if env_file else []) + \
              ["hunt", "start", "--start", start, "--end", end, "--style", style,
               "--agent" if requested else "--no-agent", "--budget-grant", grant]
        if hypothesis.strip():
            # one argument, so text that starts with "-" is never read as an option
            cmd += [f"--hypothesis={hypothesis.strip()[:500]}"]
        s.logs_dir.mkdir(parents=True, exist_ok=True)
        env = {**os.environ, "USER": f"web:{u['u']}"}
        with open(s.logs_dir / f"hunt-{datetime.now():%Y%m%d-%H%M%S}.log", "ab") as log:
            subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT, env=env, start_new_session=True)
        repo.audit(f"web:{u['u']}", "web.hunt_start", detail={
            "start": start, "end": end, "style": style, "agent_requested": requested,
            "agent_budget": {key: budget[key] for key in ("profile", "overrides", "role", "above_ceiling")}})
        return RedirectResponse("/?started=1", status_code=303)

    register_hunt_routes(app, repo, s, need, hunt_page)
    register_control_routes(app, repo, s, env_file, need)

    @app.get("/hunts/{hunt_id}/stream")
    async def stream(request: Request, hunt_id: str, after_seq: str = "0"):
        u = await run_in_threadpool(need, request)
        if (not after_seq.isascii() or not after_seq.isdigit() or len(after_seq) > 19
                or int(after_seq) > 9223372036854775807):
            raise HTTPException(400, "Invalid stream cursor")
        if await run_in_threadpool(repo.get_hunt, hunt_id) is None:
            raise HTTPException(404)

        # the session is checked again on every poll, so a logout, disable, role or password change ends the stream
        return StreamingResponse(agent_views.live_events(
            repo, request, hunt_id, asyncio.sleep, after_seq=int(after_seq),
            authorised=lambda: session_user(repo.engine, u) is not None), media_type="text/event-stream")

    # ------------------------------------------------------------------ findings
    @app.get("/findings/{cid}", response_class=HTMLResponse)
    def finding(request: Request, cid: str, host_after: str = "", event: str = "", notes_after: str = ""):
        u = need(request)
        c = repo.candidate(cid)
        if c is None:
            raise HTTPException(404)
        event_ids = c["event_ids"][:20]
        if event:
            from sqlalchemy import select

            from romulus.store import schema as tables
            with repo.engine.connect() as connection:
                exists = connection.execute(select(tables.candidate_event.c.event_id).where(
                    tables.candidate_event.c.candidate_id == cid, tables.candidate_event.c.hunt_id == c["hunt_id"],
                    tables.candidate_event.c.event_id == event)).scalar_one_or_none()
            if exists is None:
                raise HTTPException(404)
            event_ids = [event]
        events = repo.citation_events(c["hunt_id"], event_ids)
        raw_ids = [rid for e in events for rid in e["raw_ids"]]
        raws = repo.raw_records(raw_ids[:40])
        gates = dict(c["gate_results"])
        notes = gates.pop("_notes", [])
        # records no normalizer read that an AI finding cites as text: shown apart, labelled, never as typed events
        raw_cited = list(gates.pop(RAW_GATE, None) or [])
        raw_records = [raw_record_view(row) for row in repo.agent_raw_records(c["hunt_id"], raw_cited[:20])]
        pred_fields = {p["field"] for p in c["predicate_fields"]}
        fleet_hosts, fleet_next = repo.candidate_hosts(cid, after=host_after)
        from romulus.store import schema as tables
        agent_notes, notes_more, notes_cursor = agent_views.page_rows(repo, tables.agent_note, c["hunt_id"],
            after=notes_after, predicates=(tables.agent_note.c.target_kind == "finding", tables.agent_note.c.target_id == cid))
        for note in agent_notes:
            note["shown_text"] = agent_views.clip(note["text"], 2000)
            note["shown_cites"] = agent_views.cites_view(repo, c["hunt_id"], note["cites"])
            note["cites_more"] = max(0, len(note["cites"]) - 20)
        linked_hypothesis = repo.agent_hypothesis(c["hunt_id"], c["agent_hypothesis_id"]) if c.get("agent_hypothesis_id") else None
        if linked_hypothesis and linked_hypothesis["hunt_id"] != c["hunt_id"]:
            linked_hypothesis = None
        return page(request, "finding.html", u, c=c, gates=gates, notes=notes, events=events, raws=raws,
                    fleet_hosts=fleet_hosts, fleet_next=fleet_next, fleet_after=host_after,
                    pred_fields=pred_fields, dispositions=repo.dispositions(cid), statuses=STATUSES,
                    agent_notes=agent_notes, agent_notes_more=notes_more, agent_notes_cursor=notes_cursor,
                    linked_hypothesis=linked_hypothesis, raw_records=raw_records,
                    raw_missing=max(0, len(raw_cited[:20]) - len(raw_records)), raw_more=max(0, len(raw_cited) - 20),
                    raw_label=RAW_LABEL_PLURAL,
                    pretty=lambda v: json.dumps(v, indent=2, ensure_ascii=False, sort_keys=True, default=str))

    @app.get("/hunts/{hunt_id}/raw-records/{rid}", response_class=HTMLResponse)
    def raw_record(request: Request, hunt_id: str, rid: str):
        u = need(request)
        rows = repo.agent_raw_records(hunt_id, [rid]) if len(rid) <= 64 else []
        if not rows:
            raise HTTPException(404)
        view = raw_record_view(rows[0])
        return page(request, "raw_record.html", u, hunt_id=hunt_id, raw=view, raw_label=view["label"])

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
        """need() reads the role from the account, so a demoted or disabled account loses lead rights at once."""
        u = need(request)
        if u.get("r") != "lead":
            raise HTTPException(403, "only an active lead account can do this")
        return u

    @app.post("/hunts/{hunt_id}/agent/reassess")
    def reassess(request: Request, hunt_id: str, csrf: str = Form("")):
        from urllib.parse import urlencode
        u = need_lead(request)
        if not csrf_ok(u, csrf):
            raise HTTPException(403, "bad CSRF token")
        if repo.get_hunt(hunt_id) is None:
            raise HTTPException(404)
        refusal = repo.agent_reassessment_refusal(hunt_id)
        if refusal:
            return RedirectResponse(agent_views.href(hunt_id, "/assessment") + "?" + urlencode({"agent_message": agent_views.reassess_code(refusal)}),
                                    status_code=303)
        cmd = [sys.executable, "-m", "romulus.cli"] + (["--env-file", str(env_file)] if env_file else []) + [
            "agent", "reassess", hunt_id]
        s.logs_dir.mkdir(parents=True, exist_ok=True)
        env = {**os.environ, "USER": f"web:{u['u']}"}
        with open(s.logs_dir / f"agent-reassess-{datetime.now():%Y%m%d-%H%M%S}.log", "ab") as log:
            subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT, env=env, start_new_session=True)
        repo.audit(f"web:{u['u']}", "web.agent_reassess", hunt_id=hunt_id)
        return RedirectResponse(agent_views.href(hunt_id, "/assessment"), status_code=303)

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
        # the network-to-host join's rows kept for its pass after the packet and baseline stages
        from romulus.hunt.net_join_pass import discard_rows
        discard_rows(s.stage_path, hunt_id)
        # generated report files for this hunt, path-checked to stay inside the reports directory
        rdir = (s.reports_dir / hunt_id).resolve()
        if s.reports_dir.resolve() in rdir.parents and rdir.is_dir():
            import shutil
            shutil.rmtree(rdir, ignore_errors=True)
        # The same cross-process lease guards hunt claims through the final
        # checkpoint, closing the check-then-VACUUM race with a new hunt.
        try:
            with maintenance_lease(repo.engine):
                if not repo.hunts_with_live_lease():
                    compact(repo.engine)
        except Exception as error:  # deletion has already committed
            import logging
            logging.getLogger(__name__).exception("Hunt deletion compaction failed for %s", hunt_id)
            repo.audit(f"web:{u['u']}", "hunt.compaction_failed", hunt_id=hunt_id,
                       detail={"error": str(error)[:500]})
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
        try:
            current = load_site_facts(s.home)
        except SiteValidationError:
            current = None  # the save below reports the invalid file
        if current is not None and current.present and current.digest == digest:
            # The page edits only some of the file; keep the rest. A file changed since the page was loaded is
            # refused by the save's digest check, so nothing newer is merged here.
            content = site_form.with_unedited(current.content, content)
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
        m = publish_revision(repo, hunt_id, f"web:{u['u']}", settings=s)
        out = s.reports_dir / hunt_id
        out.mkdir(parents=True, exist_ok=True)
        write_reports(repo, m, out, settings=s)
        return RedirectResponse(agent_views.href(hunt_id) + "#reports", status_code=303)

    @app.get("/reports/{hunt_id}/{rev_id}.{ext}")
    def get_report(request: Request, hunt_id: str, rev_id: str, ext: str):
        need(request)
        appendix = (ext == "jsonl" and rev_id.startswith("fleet-hosts-") and len(rev_id) == 76
                    and all(char in "0123456789abcdef" for char in rev_id[12:]))
        appendix |= (ext == "jsonl" and rev_id.startswith("zeek-visibility-") and len(rev_id) == 80
                     and all(char in "0123456789abcdef" for char in rev_id[16:]))
        if (not appendix and (ext not in ("md", "json", "docx", "csv") or not rev_id.startswith(hunt_id + "-r"))
                or "/" in rev_id or ".." in rev_id):
            raise HTTPException(404)
        p = (s.reports_dir / hunt_id / f"{rev_id}.{ext}").resolve()
        if s.reports_dir.resolve() not in p.parents or not p.exists():
            raise HTTPException(404)
        media = {"md": "text/markdown; charset=utf-8", "json": "application/json", "jsonl": "application/x-ndjson",
                 "csv": "text/csv; charset=utf-8",
                 "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document"}[ext]
        return FileResponse(p, media_type=media, filename=f"{rev_id}.{ext}")

    @app.exception_handler(HTTPException)
    async def http_exc(request: Request, exc: HTTPException):
        if exc.status_code == 303:
            return RedirectResponse(exc.headers["Location"], status_code=303)
        return PlainTextResponse(str(exc.detail), status_code=exc.status_code)

    return app
