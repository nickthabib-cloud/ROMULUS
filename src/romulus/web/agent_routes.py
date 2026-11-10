"""Read-only AI investigation pages with guarded assessment requests."""
from __future__ import annotations

from urllib.parse import quote, urlencode

from fastapi import HTTPException, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import select

from romulus.catalog.browser import CatalogBrowser
from romulus.store import schema as t
from romulus.web import agent_views as view
from romulus.web.finding_order import finding_page


def register_agent_routes(app, repo, need, page):
    def hunt(hunt_id):
        row = repo.get_hunt(hunt_id)
        if row is None:
            raise HTTPException(404)
        return row

    def cursors(request):
        if any(len(value) > 2048 for value in request.query_params.values()):
            raise HTTPException(400, "Invalid page cursor")
        return request.query_params

    def next_url(request, key, value):
        return request.url.path + "?" + urlencode({**request.query_params, key: value})

    @app.get("/hunts/{hunt_id}/hypotheses", response_class=HTMLResponse)
    def hypotheses(request: Request, hunt_id: str, after: str = ""):
        user = need(request)
        h = hunt(hunt_id)
        cursors(request)
        rows, more, cursor = view.hypotheses_page(repo, hunt_id, after)
        catalog = CatalogBrowser(repo)
        techniques = {row.technique.id for domain in ("enterprise", "ics")
                      for row in catalog.catalog(domain).coverage_by_technique}
        return page(request, "hypotheses.html", user, h=h, rows=rows, more=more, techniques=techniques,
                    next_url=next_url(request, "after", cursor) if cursor else None)

    @app.get("/hunts/{hunt_id}/hypotheses/{hid}", response_class=HTMLResponse)
    def hypothesis(request: Request, hunt_id: str, hid: str):
        user = need(request)
        h = hunt(hunt_id)
        params = cursors(request)
        row = repo.agent_hypothesis(hunt_id, hid)
        if row is None or row["hunt_id"] != hunt_id:
            raise HTTPException(404)
        events, events_more, events_after = view.page_rows(repo, t.agent_hypothesis_event, hunt_id,
            predicates=(t.agent_hypothesis_event.c.hypothesis_id == hid,), after=params.get("history_after", ""))
        for event in events:
            event["shown_payload"] = view.json_text(event["payload"])
        sessions, sessions_more, sessions_after = view.page_rows(repo, t.agent_session, hunt_id,
            predicates=(t.agent_session.c.hypothesis_id == hid,), limit=25, after=params.get("sessions_after", ""))
        chosen = None
        if params.get("session"):
            with repo.engine.connect() as connection:
                chosen = connection.execute(select(t.agent_session).where(
                    t.agent_session.c.hunt_id == hunt_id, t.agent_session.c.hypothesis_id == hid,
                    t.agent_session.c.id == params["session"])).mappings().first()
            if chosen is None:
                raise HTTPException(404)
        elif sessions:
            chosen = sessions[0]
        calls, calls_more, calls_after = ([], 0, None)
        if chosen:
            calls, calls_more, calls_after = view.page_rows(repo, t.agent_tool_call, hunt_id,
                predicates=(t.agent_tool_call.c.session_id == chosen["id"],), limit=100,
                after=params.get("tools_after", ""))
            for call in calls:
                call["shown_arguments"] = view.json_text(call["arguments"])
        try:
            cites, cites_more, cites_after = view.hypothesis_cites(repo, hunt_id, hid, params.get("cites_after", ""))
        except ValueError as error:
            raise HTTPException(400, str(error)) from error
        return page(request, "hypothesis.html", user, h=h, hypothesis=row,
            questions=[view.clip(question, 1000) for question in row["questions"][:50]],
            questions_more=max(0, len(row["questions"]) - 50),
            history=events, history_more=events_more,
            history_next=next_url(request, "history_after", events_after) if events_after else None,
            cites=cites, cites_more=cites_more,
            cites_next=next_url(request, "cites_after", cites_after) if cites_more else None,
            sessions=sessions, sessions_more=sessions_more,
            sessions_next=next_url(request, "sessions_after", sessions_after) if sessions_after else None,
            chosen=chosen, calls=calls, calls_more=calls_more,
            calls_next=request.url.path + "?" + urlencode({"session": chosen["id"], "tools_after": calls_after})
                if calls_after else None, clip=view.clip)

    @app.get("/hunts/{hunt_id}/agent/{kind}", response_class=HTMLResponse)
    def outputs(request: Request, hunt_id: str, kind: str, after: str = ""):
        user = need(request)
        h = hunt(hunt_id)
        cursors(request)
        tables = {"notes": t.agent_note, "links": t.agent_link, "requests": t.agent_rule_request,
                  "findings": t.candidate}
        if kind not in tables:
            raise HTTPException(404)
        table = tables[kind]
        columns = (table.c.id, table.c.claim, table.c.lane, table.c.agent_hypothesis_id) if kind == "findings" else None
        if kind == "findings":
            try:
                rows, more, cursor = finding_page(repo, hunt_id, after=after, columns=columns,
                    predicates=(table.c.provenance == "agent",))
            except ValueError as error:
                raise HTTPException(400, "Invalid page cursor") from error
        else:
            rows, more, cursor = view.page_rows(repo, table, hunt_id, after=after, columns=columns)
        if kind == "findings":
            view.validate_hypothesis_links(repo, hunt_id, rows)
        for row in rows:
            row["shown_text"] = view.clip(row.get("text") or row.get("rationale") or
                                          row.get("pattern_description") or row.get("claim"), 2000)
            row["shown_cites"] = view.cites_view(repo, hunt_id, row.get("cites"))
            row["cites_more"] = max(0, len(row.get("cites") or []) - 20)
            if kind == "links":
                row["endpoints"] = [view.resolved_cite(repo, hunt_id, {"kind": row[key + "_kind"],
                    "id": row[key + "_id"]}) for key in ("from", "to")]
        return page(request, "agent_outputs.html", user, h=h, kind=kind, rows=rows, more=more,
                    next_url=next_url(request, "after", cursor) if cursor else None,
                    finding_url=lambda cid: "/findings/" + quote(cid, safe=""))
