"""Authenticated offline indicator uploads and bounded version views."""
from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory

from fastapi import HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from sqlalchemy import select
from starlette.concurrency import run_in_threadpool
from starlette.datastructures import UploadFile

from romulus.content.indicator_import import CSV_MAX_BYTES, JSON_MAX_BYTES, parse_indicator_file
from romulus.content.indicator_lists import IndicatorLists
from romulus.store import schema as t
from romulus.web.auth import csrf_ok

HTTP_MAX_BYTES = CSV_MAX_BYTES + 256 * 1024
FIELD_MAX_BYTES = 128 * 1024


class IndicatorBodyLimit:
    """Count actual ASGI bytes, including requests without Content-Length."""
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http' or scope.get('method') != 'POST' or not (
                scope['path'] == '/indicators' or scope['path'].startswith('/indicators/')):
            return await self.app(scope, receive, send)
        total = 0
        async def bounded_receive():
            nonlocal total
            message = await receive()
            total += len(message.get('body', b''))
            if total > HTTP_MAX_BYTES:
                raise HTTPException(413, 'Indicator upload exceeds the request size limit')
            return message
        await self.app(scope, bounded_receive, send)


def register_indicator_routes(app, repo, need, page):
    store = IndicatorLists(repo)

    def authorized(request, *, lead=False):
        user = need(request)
        with repo.engine.connect() as c:
            account = c.execute(select(t.user.c.role, t.user.c.disabled).where(
                t.user.c.username == user.get('u'))).first()
        if (account is None or account.disabled or account.role not in ('analyst', 'lead')
                or (lead and (account.role != 'lead' or user.get('r') != 'lead'))):
            raise HTTPException(403, 'An active lead account is required' if lead else 'An active analyst account is required')
        return {**user, 'r': account.role}

    def version_of(request):
        value = request.query_params.get('version')
        if value is None:
            return None
        if not value.isascii() or not value.isdigit() or len(value) > 10 or int(value) < 1:
            raise HTTPException(400, 'Version must be a positive integer')
        return int(value)

    def get_list(list_id, version=None):
        if len(list_id) > 128:
            raise HTTPException(404)
        row = store.get(list_id, version)
        if row is None:
            raise HTTPException(404, 'Indicator list version not found')
        if row['status'] == 'active' and datetime.fromisoformat(row['expires_at']) <= datetime.now(UTC):
            row = {**row, 'status': 'expired'}
        return row

    async def form_of(request):
        length = request.headers.get('content-length')
        if length is not None:
            if not length.isascii() or not length.isdigit() or len(length) > 12:
                raise HTTPException(400, 'Invalid request length')
            if int(length) > HTTP_MAX_BYTES:
                raise HTTPException(413, 'Indicator upload exceeds the request size limit')
        # URL-encoded forms are small textarea submissions; stream them with a smaller cap.
        if request.headers.get('content-type', '').split(';')[0] != 'multipart/form-data':
            total = 0
            pieces = []
            async for piece in request.stream():
                total += len(piece)
                if total > FIELD_MAX_BYTES:
                    raise HTTPException(413, 'Indicator form fields exceed the size limit')
                pieces.append(piece)
            request._body = b''.join(pieces)
        return await request.form(max_files=1, max_fields=16, max_part_size=FIELD_MAX_BYTES)

    def field(form, key, limit, default=''):
        value = form.get(key, default)
        if not isinstance(value, str) or len(value) > limit or len(form.getlist(key)) > 1:
            raise ValueError('invalid form field')
        return value

    @app.get('/indicators', response_class=HTMLResponse)
    def lists(request: Request):
        user = authorized(request)
        offset_text = request.query_params.get('offset', '0')
        if not offset_text.isascii() or not offset_text.isdigit() or len(offset_text) > 9:
            raise HTTPException(400, 'Invalid list page')
        offset = int(offset_text)
        rows = store.lists(limit=100, offset=offset)
        for row in rows:
            if row['status'] == 'active' and datetime.fromisoformat(row['expires_at']) <= datetime.now(UTC):
                row['status'] = 'expired'
        return page(request, 'indicators.html', user, lists=rows, offset=offset)

    @app.post('/indicators')
    async def upload(request: Request):
        user = authorized(request)  # Authenticate before parsing multipart input.
        form = None
        try:
            form = await form_of(request)
            if not csrf_ok(user, field(form, 'csrf', 128)):
                raise HTTPException(403, 'bad CSRF token')
            name, source = field(form, 'name', 256), field(form, 'source', 2048)
            notes = field(form, 'notes', 16384)
            lane = field(form, 'lane', 16, 'lead')
            severity = field(form, 'severity', 16, 'medium')
            reason = field(form, 'reason', 2048)
            list_id = field(form, 'list_id', 128) or None
            expires = field(form, 'expires', 64)
            expires_at = datetime.fromisoformat(expires) if expires else None
            if expires_at is not None and expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=UTC)
            include = field(form, 'include_non_ids', 1)
            if include not in ('', '1'):
                raise ValueError('invalid non-IDS flag')
            if list_id is not None:
                get_list(list_id)
            uploaded = form.get('file')
            text = field(form, 'csv_text', 65536)
            has_file = isinstance(uploaded, UploadFile) and bool(uploaded.filename)
            if bool(text.strip()) == has_file:
                raise ValueError('provide one CSV or JSON upload, or CSV text')
            suffix = Path(uploaded.filename).suffix.lower() if has_file else '.csv'
            if suffix not in ('.csv', '.json'):
                raise ValueError('only CSV and JSON files are accepted')
            limit = CSV_MAX_BYTES if suffix == '.csv' else JSON_MAX_BYTES
            with TemporaryDirectory(prefix='romulus-indicators-') as directory:
                path = Path(directory) / ('upload' + suffix)
                with path.open('wb') as destination:
                    if has_file:
                        total = 0
                        while chunk := await uploaded.read(65536):
                            total += len(chunk)
                            if total > limit:
                                raise HTTPException(413, 'Indicator file exceeds its format size limit')
                            destination.write(chunk)
                    else:
                        destination.write(text.encode('utf-8'))
                def import_list():
                    result = parse_indicator_file(path, include_non_ids=include == '1')
                    return store.create_version(result.rows, name=name, source=source, author=user['u'],
                        notes=notes, list_id=list_id, expires_at=expires_at, report=result.summary,
                        role=user['r'], lane=lane, severity=severity, reason=reason)
                row = await run_in_threadpool(import_list)
            return RedirectResponse(f"/indicators/{row['id']}?version={row['version']}", status_code=303)
        except HTTPException as exc:
            if exc.status_code in (400, 413):
                repo.audit(user['u'], 'indicator_list.import_rejected', detail={
                    'reason': 'request_size_limit' if exc.status_code == 413 else 'invalid_form'})
            raise
        except (ValueError, OSError, UnicodeError, OverflowError, PermissionError) as exc:
            if not getattr(exc, 'audit_recorded', False):
                repo.audit(user['u'], 'indicator_list.import_rejected', detail={'reason': 'invalid_file_or_metadata'})
            raise HTTPException(400, 'Import rejected: invalid CSV/JSON file or metadata; no version was saved') from None
        finally:
            if form is not None:
                await form.close()

    @app.get('/indicators/{list_id}', response_class=HTMLResponse)
    def detail(request: Request, list_id: str):
        user = authorized(request)
        row = get_list(list_id, version_of(request))
        return page(request, 'indicator_list.html', user, item=row, latest=get_list(list_id),
                    values=list(store.values(list_id, row['version'], limit=100)))

    @app.post('/indicators/{list_id}/retire')
    async def retire(request: Request, list_id: str):
        user = authorized(request, lead=True)
        form = await form_of(request)
        try:
            if not csrf_ok(user, field(form, 'csrf', 128)):
                raise HTTPException(403, 'bad CSRF token')
            get_list(list_id)
            store.retire(list_id, actor=user['u'], role=user['r'])
        finally:
            await form.close()
        return RedirectResponse('/indicators/' + list_id, status_code=303)

    @app.get('/indicators/{list_id}/export')
    def export(request: Request, list_id: str):
        authorized(request)
        row = get_list(list_id, version_of(request))
        fmt = request.query_params.get('format', 'yaml')
        if fmt not in ('yaml', 'csv'):
            raise HTTPException(400, 'Export format must be yaml or csv')
        from romulus.content.indicator_export import export_indicators
        return StreamingResponse(export_indicators(store, list_id, row['version'], format=fmt),
            media_type='text/csv' if fmt == 'csv' else 'application/yaml',
            headers={'Content-Disposition': f'attachment; filename="indicators-v{row["version"]}.{fmt}"'})
