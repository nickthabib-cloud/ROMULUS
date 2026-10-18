"""Local accounts (argon2), signed session cookies, CSRF tokens and login rate limiting."""
from __future__ import annotations

import hmac
import secrets
import time
from collections import defaultdict

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from itsdangerous import BadSignature, URLSafeTimedSerializer
from sqlalchemy import select

from romulus.store import schema as t
from romulus.store.db import utcnow, write_txn

ROLES = ("lead", "analyst")
SESSION_MAX_AGE = 8 * 3600
_ph = PasswordHasher()
MAX_ATTEMPTS, WINDOW = 5, 300


class RateLimiter:
    """Per-application login throttle keyed by client address."""

    def __init__(self):
        self.attempts: dict[str, list[float]] = defaultdict(list)

    def blocked(self, client: str) -> bool:
        now = time.time()
        self.attempts[client] = [a for a in self.attempts[client] if now - a < WINDOW]
        return len(self.attempts[client]) >= MAX_ATTEMPTS

    def fail(self, client: str):
        self.attempts[client].append(time.time())

    def clear(self, client: str):
        self.attempts.pop(client, None)


def create_user(engine, username: str, password: str, role: str):
    if role not in ROLES:
        raise ValueError(f"role must be one of {ROLES}")
    if len(password) < 12:
        raise ValueError("password must be at least 12 characters")
    with write_txn(engine) as c:
        c.execute(t.user.insert().values(username=username, password_hash=_ph.hash(password), role=role,
                                         created_at=utcnow(), disabled=0))


def verify(engine, username: str, password: str, client: str, limiter: RateLimiter) -> dict | None:
    if limiter.blocked(client):
        return None
    with engine.connect() as c:
        row = c.execute(select(t.user).where(t.user.c.username == username)).mappings().first()
    ok = False
    if row and not row["disabled"]:
        try:
            ok = _ph.verify(row["password_hash"], password)
        except (VerificationError, InvalidHashError):
            ok = False
    else:
        _ph.hash("timing-equalizer")          # similar cost whether or not the user exists
    if not ok:
        limiter.fail(client)
        return None
    limiter.clear(client)
    return {"username": row["username"], "role": row["role"]}


class Sessions:
    def __init__(self, secret: str):
        if len(secret) < 16:
            raise ValueError("ROMULUS_SECRET_KEY must be set (16+ chars) to serve the web UI")
        self.s = URLSafeTimedSerializer(secret, salt="romulus-session")

    def issue(self, user: dict) -> str:
        return self.s.dumps({"u": user["username"], "r": user["role"], "csrf": secrets.token_urlsafe(24)})

    def read(self, cookie: str | None) -> dict | None:
        if not cookie:
            return None
        try:
            return self.s.loads(cookie, max_age=SESSION_MAX_AGE)
        except BadSignature:
            return None


def csrf_ok(session: dict, token: str | None) -> bool:
    return bool(token) and hmac.compare_digest(session.get("csrf", ""), token)
