"""A byte limit on every request body, enforced before anything parses it.

Form parameters are read before a route checks the session, so without a limit an unauthenticated client could make
the web process spool any number of bytes to the temporary directory or hold them in memory. Bytes are counted as
they arrive, so a body sent without Content-Length (or with a false one) is bounded the same way. Each limit fits the
largest form the pages themselves submit; a larger body is answered 413 Payload Too Large.
"""
from __future__ import annotations

from fastapi import HTTPException
from starlette.responses import PlainTextResponse

from romulus.site import MAX_SITE_BYTES
from romulus.web import site_form
from romulus.web.indicator_routes import HTTP_MAX_BYTES as INDICATOR_MAX_BYTES

# Every form but two holds a few short fields and notes of at most a few thousand characters: even fully
# percent-encoded (up to 12 bytes per character), they stay well inside this.
DEFAULT_MAX_BYTES = 64 * 1024
# The site setup form carries the site file's lists (at most MAX_SITE_BYTES, each byte at most three once
# percent-encoded) and one field per checkbox of every host group (a field name and value fit in 128 bytes).
SITE_MAX_BYTES = 3 * MAX_SITE_BYTES + 128 * site_form.max_fields()


def limit_for(path: str) -> int:
    if path == "/indicators" or path.startswith("/indicators/"):
        return INDICATOR_MAX_BYTES   # an indicator file upload; its own middleware applies its tighter field limits
    if path == "/site":
        return SITE_MAX_BYTES
    return DEFAULT_MAX_BYTES


def _too_large() -> HTTPException:
    return HTTPException(413, "Request body exceeds the size limit")


class BodyLimit:
    """Refuse a body larger than its path's limit: at once when Content-Length says so, else as the bytes arrive."""
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        limit = limit_for(scope["path"])
        for name, value in scope.get("headers") or ():
            if name == b"content-length":
                if value.isdigit() and int(value) > limit:
                    response = PlainTextResponse("Request body exceeds the size limit", status_code=413,
                                                 headers={"Connection": "close"})
                    return await response(scope, receive, send)
        total = 0

        async def bounded_receive():
            nonlocal total
            message = await receive()
            total += len(message.get("body", b""))
            if total > limit:
                raise _too_large()
            return message
        await self.app(scope, bounded_receive, send)
