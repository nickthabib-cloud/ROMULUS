"""Local accounts (argon2), signed session cookies tied to the account's session generation, CSRF tokens and the
login throttle."""
from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time
from collections import OrderedDict, deque
from collections.abc import Callable

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from itsdangerous import BadSignature, URLSafeTimedSerializer
from sqlalchemy import select

from romulus.config import session_secret_problem
from romulus.store import schema as t
from romulus.store.db import utcnow, write_txn

ROLES = ("lead", "analyst")
SESSION_MAX_AGE = 8 * 3600
MIN_PASSWORD = 12
_ph = PasswordHasher()

# Login throttle.
# - Per username: MAX_ATTEMPTS failures within WINDOW seconds lock that username until the oldest one ages out. Other
#   accounts are not affected. A password check reserves a slot before it runs, and failures plus checks still running
#   may not exceed MAX_ATTEMPTS, so a burst of parallel attempts gets no more checks than one attempt after another.
# - Per client address: failures beyond ADDRESS_FREE_ATTEMPTS within WINDOW delay further attempts from that address
#   (BACKOFF_BASE doubling up to BACKOFF_MAX seconds per attempt). Each attempt is given its own start time after the
#   previous one's, so parallel connections queue rather than share one delay; no attempt waits longer than
#   BACKOFF_WAIT_MAX. The password is still checked after the wait, so a correct password is never refused because of
#   its address alone; the delay only slows guessing across many usernames.
# - Each map keeps at most THROTTLE_KEYS keys and drops the least recently used one beyond that, and each key keeps a
#   bounded number of failure times, so the state stays fixed-size whatever is sent; a reservation exists only while
#   its check runs. Usernames are kept as short digests, so neither a long value nor a password typed into the username
#   field is held in memory, and only names of existing accounts are kept (a locked, an unknown and a wrong-password
#   attempt answer alike).
MAX_ATTEMPTS, WINDOW = 5, 300
ADDRESS_FREE_ATTEMPTS = 20
BACKOFF_BASE, BACKOFF_MAX, BACKOFF_WAIT_MAX = 0.5, 4.0, 30.0
THROTTLE_KEYS = 4096
_ADDRESS_DEPTH = ADDRESS_FREE_ATTEMPTS + 8


class _Failures:
    """Recent failure times per key: a fixed-size map with least-recently-used eviction."""

    def __init__(self, keys: int, depth: int):
        self.keys, self.depth = keys, depth
        self.times: OrderedDict[str, deque[float]] = OrderedDict()

    def count(self, key: str, now: float) -> int:
        times = self.times.get(key)
        if times is None:
            return 0
        while times and now - times[0] >= WINDOW:
            times.popleft()
        if not times:
            del self.times[key]
            return 0
        return len(times)

    def add(self, key: str, now: float) -> None:
        times = self.times.get(key)
        if times is None:
            times = self.times[key] = deque(maxlen=self.depth)
        times.append(now)
        self.times.move_to_end(key)
        while len(self.times) > self.keys:
            self.times.popitem(last=False)

    def clear(self, key: str) -> None:
        self.times.pop(key, None)


def _user_key(username: str) -> str:
    return hashlib.sha256(username.encode("utf-8", "replace")).hexdigest()[:32]


class RateLimiter:
    """Login throttle per username and per client address (see the constants above). Thread-safe."""

    def __init__(self, clock: Callable[[], float] = time.monotonic, keys: int = THROTTLE_KEYS):
        self.clock = clock
        self.keys = keys
        self._lock = threading.Lock()
        self.users = _Failures(keys, MAX_ATTEMPTS)
        self.addresses = _Failures(keys, _ADDRESS_DEPTH)
        self.pending: dict[str, int] = {}                          # password checks running, per username key
        self.next_start: OrderedDict[str, float] = OrderedDict()   # per address in backoff: the next start time

    def locked(self, username: str) -> bool:
        with self._lock:
            key = _user_key(username)
            return self.users.count(key, self.clock()) + self.pending.get(key, 0) >= MAX_ATTEMPTS

    def admit(self, client: str) -> float:
        """Seconds this attempt from `client` waits before its password is checked. Each attempt from an address in
        backoff takes the next start time, one backoff step after the previous attempt's, at most BACKOFF_WAIT_MAX
        from now."""
        with self._lock:
            now = self.clock()
            excess = self.addresses.count(client, now) - ADDRESS_FREE_ATTEMPTS
            if excess < 0:
                return 0.0
            step = min(BACKOFF_BASE * 2 ** min(excess, 16), BACKOFF_MAX)
            start = min(max(now, self.next_start.get(client, now)) + step, now + BACKOFF_WAIT_MAX)
            self.next_start[client] = start
            self.next_start.move_to_end(client)
            while len(self.next_start) > self.keys:
                self.next_start.popitem(last=False)
            return start - now

    def reserve(self, username: str) -> bool:
        """Reserve a password check for an existing account; False while it is locked (recent failures plus checks
        still running reach MAX_ATTEMPTS). Every True is followed by exactly one settle(username, ...)."""
        with self._lock:
            key = _user_key(username)
            if self.users.count(key, self.clock()) + self.pending.get(key, 0) >= MAX_ATTEMPTS:
                return False
            self.pending[key] = self.pending.get(key, 0) + 1
            return True

    def settle(self, username: str | None, client: str, ok: bool) -> None:
        """End a check: release the account's reservation (when `username` is given) and record the outcome. A
        success clears only the account's failures: one good password must not reset its address's backoff."""
        with self._lock:
            now = self.clock()
            if username is not None:
                key = _user_key(username)
                left = self.pending.get(key, 0) - 1
                if left > 0:
                    self.pending[key] = left
                else:
                    self.pending.pop(key, None)
                if ok:
                    self.users.clear(key)
                else:
                    self.users.add(key, now)
            if not ok:
                self.addresses.add(client, now)

    def fail(self, username: str | None, client: str) -> None:
        """Record a failed attempt that reserved nothing."""
        with self._lock:
            now = self.clock()
            self.addresses.add(client, now)
            if username is not None:
                self.users.add(_user_key(username), now)


def create_user(engine, username: str, password: str, role: str):
    if role not in ROLES:
        raise ValueError(f"role must be one of {ROLES}")
    _check_password(password)
    with write_txn(engine) as c:
        c.execute(t.user.insert().values(username=username, password_hash=_ph.hash(password), role=role,
                                         created_at=utcnow(), disabled=0, session_generation=0))


def _check_password(password: str) -> None:
    if len(password) < MIN_PASSWORD:
        raise ValueError(f"password must be at least {MIN_PASSWORD} characters")


def authenticate(engine, username: str, password: str, client: str,
                 limiter: RateLimiter) -> tuple[dict | None, bool]:
    """(account, known): the account when the password is right and the account active, else None; `known` says
    whether `username` names an account, so a caller never records an unknown value (possibly a mistyped password)."""
    with engine.connect() as c:
        row = c.execute(select(t.user).where(t.user.c.username == username)).mappings().first()
    known = row is not None
    # Only a real account is reserved and locked, so made-up names cannot evict a lock from the fixed-size map; an
    # unknown name still counts against its address.
    if known and not limiter.reserve(username):
        _ph.hash("timing-equalizer")          # a locked username answers in the same time as a wrong password
        limiter.fail(None, client)
        return None, known
    ok = False
    try:
        if row and not row["disabled"]:
            try:
                ok = _ph.verify(row["password_hash"], password)
            except (VerificationError, InvalidHashError):
                ok = False
        else:
            _ph.hash("timing-equalizer")      # similar cost whether or not the user exists
    finally:
        limiter.settle(username if known else None, client, ok)
    if not ok:
        return None, known
    return {"username": row["username"], "role": row["role"], "generation": row["session_generation"]}, known


def verify(engine, username: str, password: str, client: str, limiter: RateLimiter) -> dict | None:
    return authenticate(engine, username, password, client, limiter)[0]


def session_user(engine, session: dict) -> dict | None:
    """The session with the account's current role, or None when the account is gone or disabled, or the session was
    issued under an older session generation (logout, disable, role or password change since). One primary-key read."""
    username, generation = session.get("u"), session.get("g")
    if not isinstance(username, str) or not isinstance(generation, int) or isinstance(generation, bool):
        return None
    with engine.connect() as c:
        row = c.execute(select(t.user.c.role, t.user.c.disabled, t.user.c.session_generation)
                        .where(t.user.c.username == username)).first()
    if row is None or row.disabled or row.session_generation != generation:
        return None
    return {**session, "r": row.role}


def _update(engine, username: str, **values) -> bool:
    """Apply `values` to the account and raise its session generation in the same statement; False when no such
    account exists."""
    with write_txn(engine) as c:
        result = c.execute(t.user.update().where(t.user.c.username == username).values(
            session_generation=t.user.c.session_generation + 1, **values))
    return result.rowcount == 1


def end_sessions(engine, username: str) -> bool:
    """Refuse every session cookie issued to the account so far."""
    return _update(engine, username)


def set_disabled(engine, username: str, disabled: bool) -> bool:
    return _update(engine, username, disabled=1 if disabled else 0)


def set_role(engine, username: str, role: str) -> bool:
    if role not in ROLES:
        raise ValueError(f"role must be one of {ROLES}")
    return _update(engine, username, role=role)


def set_password(engine, username: str, password: str) -> bool:
    _check_password(password)
    return _update(engine, username, password_hash=_ph.hash(password))


class Sessions:
    def __init__(self, secret: str):
        problem = session_secret_problem(secret)
        if problem:
            raise ValueError(problem)
        self.s = URLSafeTimedSerializer(secret, salt="romulus-session")

    def issue(self, user: dict) -> str:
        return self.s.dumps({"u": user["username"], "r": user["role"], "g": int(user["generation"]),
                             "csrf": secrets.token_urlsafe(24)})

    def read(self, cookie: str | None) -> dict | None:
        if not cookie:
            return None
        try:
            session = self.s.loads(cookie, max_age=SESSION_MAX_AGE)
        except BadSignature:
            return None
        return session if isinstance(session, dict) else None


def csrf_ok(session: dict, token: str | None) -> bool:
    return bool(token) and hmac.compare_digest(session.get("csrf", ""), token)
