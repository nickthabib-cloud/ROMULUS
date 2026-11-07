"""Small authenticated forms for shared detection intake."""
from __future__ import annotations

import re
from urllib.parse import urlencode

from fastapi import HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from starlette.concurrency import run_in_threadpool

from romulus.catalog.browser import known_families
from romulus.catalog.requests import BEHAVIOR_MAX, STATUSES, DetectionRequests
from romulus.web.auth import csrf_ok
from romulus.web.catalog_routes import catalog_user

BODY_LIMIT = 32 * 1024


class DetectionRequestBodyLimit:
    """Bound actual incoming form bytes even without a Content-Length header."""
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if (scope['type'] != 'http' or scope.get('method') != 'POST'
                or not (scope['path'] == '/catalog/requests' or scope['path'].startswith('/catalog/requests/'))):
            return await self.app(scope, receive, send)
        total = 0
        async def bounded_receive():
            nonlocal total
            message = await receive()
            total += len(message.get('body', b''))
            if total > BODY_LIMIT:
                raise HTTPException(413, 'Detection request form exceeds the size limit')
            return message
        await self.app(scope, bounded_receive, send)


def register_request_routes(app, repo, need, page):
    store = DetectionRequests(repo)

    def user_of(request, *, lead=False):
        return catalog_user(repo, need, request, lead=lead)

    def error(exc):
        if isinstance(exc, PermissionError):
            raise HTTPException(403, str(exc)) from exc
        if isinstance(exc, KeyError):
            raise HTTPException(404, 'Detection request not found') from exc
        raise HTTPException(400, str(exc)) from exc

    def filter_of(request):
        status = request.query_params.get('status', '')
        requester = request.query_params.get('requester', '')
        if status and status not in STATUSES or len(requester) > 256:
            raise HTTPException(400, 'Invalid request filter')
        return {'status': status, 'requester': requester}

    def get(request_id):
        if len(request_id) > 256:
            raise HTTPException(404)
        try:
            return store.get(request_id)
        except KeyError as exc:
            error(exc)

    async def form_of(request, user):
        length = request.headers.get('content-length', '')
        if length and (not length.isascii() or not length.isdigit() or len(length) > 10):
            raise HTTPException(400, 'Invalid request length')
        if length and int(length) > BODY_LIMIT:
            raise HTTPException(413, 'Detection request form exceeds the size limit')
        form = await request.form(max_files=0, max_fields=12, max_part_size=BODY_LIMIT)
        if not csrf_ok(user, field(form, 'csrf', 256)):
            raise HTTPException(403, 'bad CSRF token')
        return form

    def field(form, key, maximum, default=''):
        value = form.get(key, default)
        if not isinstance(value, str) or len(value) > maximum or len(form.getlist(key)) > 1:
            raise HTTPException(400, 'Invalid or repeated form field')
        return value

    @app.get('/catalog/requests', response_class=HTMLResponse)
    def requests(request: Request, after: str = ''):
        user = user_of(request)
        filters = filter_of(request)
        try:
            rows, cursor = store.list(**filters, after=after)
        except ValueError as exc:
            error(exc)
        return page(request, 'detection_requests.html', user, rows=rows, statuses=STATUSES, filters=filters,
                    next_url='/catalog/requests?' + urlencode({**filters, 'after': cursor}) if cursor else None,
                    export_query=urlencode(filters))

    @app.get('/catalog/requests/new', response_class=HTMLResponse)
    def new(request: Request, candidate: str = '', event: str = ''):
        user = user_of(request)
        draft = {'behavior': '', 'family': 'unknown', 'attack_ids': [], 'candidate_id': '',
                 'event_id': '', 'event_choices': []}
        if candidate or event:
            try:
                draft = store.prefill(candidate, event)
            except (ValueError, KeyError) as exc:
                error(exc)
        return page(request, 'detection_request_form.html', user, draft=draft, families=known_families())

    @app.get('/catalog/requests/export')
    def export(request: Request):
        user_of(request)
        format = request.query_params.get('format', 'yaml')
        if format not in {'csv', 'yaml'}:
            raise HTTPException(400, 'Unsupported request export format')
        return StreamingResponse(store.export(format, filter_of(request)),
            media_type='text/csv' if format == 'csv' else 'application/yaml',
            headers={'Content-Disposition': f'attachment; filename="detection-requests.{format}"'})

    @app.post('/catalog/requests')
    async def create(request: Request):
        user = user_of(request)
        form = await form_of(request, user)
        try:
            attack_ids = [value for value in re.split(r'[\s,]+', field(form, 'attack_ids', 2048)) if value]
            row = await run_in_threadpool(store.create, actor=user['u'],
                behavior=field(form, 'behavior', BEHAVIOR_MAX),
                family=field(form, 'telemetry_family', 128, 'unknown'), attack_ids=attack_ids,
                candidate_id=field(form, 'example_candidate_id', 256), event_id=field(form, 'example_event_id', 256))
        except (ValueError, PermissionError, KeyError) as exc:
            error(exc)
        return RedirectResponse('/catalog/requests/' + row['id'], status_code=303)

    @app.get('/catalog/requests/{request_id}', response_class=HTMLResponse)
    def detail(request: Request, request_id: str, history_after: int = 0):
        user = user_of(request)
        row = get(request_id)
        try:
            events, cursor = store.history(request_id, after=history_after)
        except ValueError as exc:
            error(exc)
        example = repo.candidate(row['example_candidate_id']) if row['example_candidate_id'] else None
        return page(request, 'detection_request.html', user, item=row, events=events, statuses=STATUSES,
                    example_available=example is not None,
                    next_url=f'/catalog/requests/{request_id}?history_after={cursor}' if cursor else None)

    @app.post('/catalog/requests/{request_id}/edit')
    async def edit(request: Request, request_id: str):
        user = user_of(request)
        form = await form_of(request, user)
        try:
            await run_in_threadpool(store.edit, request_id, actor=user['u'],
                                    behavior=field(form, 'behavior', BEHAVIOR_MAX))
        except (ValueError, PermissionError, KeyError) as exc:
            error(exc)
        return RedirectResponse('/catalog/requests/' + request_id, status_code=303)

    @app.post('/catalog/requests/{request_id}/status')
    async def status(request: Request, request_id: str):
        # Authenticate and validate CSRF before enforcing the stronger live lead role.
        user = user_of(request)
        form = await form_of(request, user)
        user_of(request, lead=True)
        try:
            await run_in_threadpool(store.change_status, request_id, actor=user['u'],
                status=field(form, 'status', 32), rule_id=field(form, 'rule_id', 256),
                reason=field(form, 'reason', BEHAVIOR_MAX))
        except (ValueError, PermissionError, KeyError) as exc:
            error(exc)
        return RedirectResponse('/catalog/requests/' + request_id, status_code=303)
