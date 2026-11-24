"""Web authentication hardening: session revocation by role and password change, the login throttle per username and
per address, trusted proxies, the plain-HTTP bind rule and its doctor check, and the failed-login audit."""
import os
import secrets
import stat

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

from romulus import cli, doctor
from romulus import web_exposure as serve
from romulus.config import Settings
from romulus.hunt.run import open_repo
from romulus.store import schema as t
from romulus.web import app as web
from romulus.web import auth
from tests.test_web import _csrf, _login
from tests.test_web import client as client  # noqa: PLC0414 - the shared authenticated web fixture


def _settings(tmp_path, **kw):
    return Settings(home=tmp_path, secret_key=secrets.token_urlsafe(32), **kw)


@pytest.fixture()
def accounts(tmp_path):
    """An app with a lead and an analyst account (generated passwords) and no seeded hunt."""
    s = _settings(tmp_path)
    repo = open_repo(s)
    pws = {name: secrets.token_urlsafe(18) for name in ("lead1", "analyst1")}
    auth.create_user(repo.engine, "lead1", pws["lead1"], "lead")
    auth.create_user(repo.engine, "analyst1", pws["analyst1"], "analyst")
    yield s, repo, pws
    repo.engine.dispose()


def _login_as(c, name, pw):
    return c.post("/login", data={"username": name, "password": pw}, follow_redirects=False)


def _audit(repo, action):
    with repo.engine.connect() as conn:
        return [dict(r) for r in conn.execute(select(t.audit_event).where(t.audit_event.c.action == action)
                                              .order_by(t.audit_event.c.id)).mappings()]


# ---------------------------------------------------------------- sessions

def test_demoted_lead_loses_lead_pages_at_once(accounts):
    s, repo, pws = accounts
    c = TestClient(web.create_app(s))
    assert _login_as(c, "lead1", pws["lead1"]).headers["location"] == "/"
    assert c.get("/site").status_code == 200
    assert auth.set_role(repo.engine, "lead1", "analyst")
    # the old cookie is refused outright, and a new session carries the account's current role
    assert c.get("/site", follow_redirects=False).headers["location"] == "/login"
    assert _login_as(c, "lead1", pws["lead1"]).headers["location"] == "/"
    assert c.get("/site").status_code == 403


def test_password_change_ends_open_sessions(accounts):
    s, repo, pws = accounts
    c = TestClient(web.create_app(s))
    _login_as(c, "analyst1", pws["analyst1"])
    assert c.get("/").status_code == 200
    new = secrets.token_urlsafe(18)
    assert auth.set_password(repo.engine, "analyst1", new)
    assert c.get("/", follow_redirects=False).headers["location"] == "/login"
    assert "error" in _login_as(c, "analyst1", pws["analyst1"]).headers["location"]
    assert _login_as(c, "analyst1", new).headers["location"] == "/"


def test_role_in_cookie_is_never_trusted(accounts):
    s, _repo, _ = accounts
    c = TestClient(web.create_app(s))
    # a validly signed cookie that claims lead for an analyst account (e.g. issued before a demotion)
    c.cookies.set(web.COOKIE, auth.Sessions(s.secret_key.get_secret_value()).issue(
        {"username": "analyst1", "role": "lead"}))
    assert c.get("/").status_code == 200
    assert c.get("/site").status_code == 403


def test_cookie_without_a_generation_or_for_a_missing_account_is_refused(accounts):
    s, _repo, _ = accounts
    signer = auth.Sessions(s.secret_key.get_secret_value())
    c = TestClient(web.create_app(s))
    c.cookies.set(web.COOKIE, signer.s.dumps({"u": "analyst1", "r": "analyst", "csrf": "x"}))
    assert c.get("/", follow_redirects=False).headers["location"] == "/login"
    c.cookies.set(web.COOKIE, signer.issue({"username": "nobody", "role": "lead"}))
    assert c.get("/", follow_redirects=False).headers["location"] == "/login"


def test_logout_ends_the_accounts_sessions_everywhere(accounts):
    s, repo, pws = accounts
    app = web.create_app(s)
    first, second = TestClient(app), TestClient(app)
    _login_as(first, "analyst1", pws["analyst1"])
    _login_as(second, "analyst1", pws["analyst1"])
    token = _csrf(first.get("/hunts/new").text)
    assert first.post("/logout", data={"csrf": token}, follow_redirects=False).status_code == 303
    assert second.get("/", follow_redirects=False).headers["location"] == "/login"
    assert _audit(repo, "web.logout")[-1]["actor"] == "analyst1"


@pytest.mark.parametrize("action", ["disable", "role", "passwd", "logout"])
def test_user_cli_changes_end_web_sessions(accounts, monkeypatch, tmp_path, action):
    s, repo, pws = accounts
    c = TestClient(web.create_app(s))
    _login_as(c, "lead1", pws["lead1"])
    assert c.get("/").status_code == 200
    env = tmp_path / "cli.env"
    env.write_text(f"ROMULUS_HOME={tmp_path}\n", encoding="utf-8")
    new = secrets.token_urlsafe(18)
    monkeypatch.setattr("getpass.getpass", lambda _prompt="": new)
    argv = ["--env-file", str(env), "user", action, "lead1"] + (["--role", "analyst"] if action == "role" else [])
    assert cli.main(argv) == cli.EXIT_OK
    assert c.get("/", follow_redirects=False).headers["location"] == "/login"
    assert _audit(repo, f"user.{action}")[-1]["detail"]["username"] == "lead1"


def test_user_cli_refuses_an_unknown_account_and_a_role_change_without_a_role(accounts, tmp_path):
    env = tmp_path / "cli.env"
    env.write_text(f"ROMULUS_HOME={tmp_path}\n", encoding="utf-8")
    assert cli.main(["--env-file", str(env), "user", "disable", "nobody"]) == cli.EXIT_FAIL
    assert cli.main(["--env-file", str(env), "user", "role", "lead1"]) == cli.EXIT_USAGE


def test_enable_after_disable_needs_a_new_login(accounts):
    s, repo, pws = accounts
    c = TestClient(web.create_app(s))
    _login_as(c, "analyst1", pws["analyst1"])
    assert auth.set_disabled(repo.engine, "analyst1", True)
    assert "error" in _login_as(c, "analyst1", pws["analyst1"]).headers["location"]
    assert auth.set_disabled(repo.engine, "analyst1", False)
    assert c.get("/", follow_redirects=False).headers["location"] == "/login"
    assert _login_as(c, "analyst1", pws["analyst1"]).headers["location"] == "/"


# ---------------------------------------------------------------- throttle

class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def test_one_locked_username_does_not_lock_another():
    clock = Clock()
    limiter = auth.RateLimiter(clock=clock)
    for _ in range(auth.MAX_ATTEMPTS):
        limiter.fail("alice", "10.0.0.5")
    assert limiter.locked("alice") and not limiter.locked("bob")
    assert limiter.delay("10.0.0.5") == 0
    clock.now += auth.WINDOW
    assert not limiter.locked("alice")


def test_address_backoff_is_short_bounded_and_survives_a_good_login():
    clock = Clock()
    limiter = auth.RateLimiter(clock=clock)
    for n in range(auth.ADDRESS_FREE_ATTEMPTS):
        limiter.fail(f"user{n}", "10.0.0.9")
    assert limiter.delay("10.0.0.9") == auth.BACKOFF_BASE
    for n in range(40):
        limiter.fail(f"more{n}", "10.0.0.9")
    assert limiter.delay("10.0.0.9") == auth.BACKOFF_MAX
    limiter.succeed("someone")
    assert limiter.delay("10.0.0.9") == auth.BACKOFF_MAX
    assert limiter.delay("10.0.0.10") == 0
    clock.now += auth.WINDOW
    assert limiter.delay("10.0.0.9") == 0


def test_throttle_state_is_fixed_size():
    limiter = auth.RateLimiter(clock=Clock(), keys=8)
    for n in range(1000):
        limiter.fail("x" * 10_000 + str(n), f"10.1.{n // 256}.{n % 256}")
    assert len(limiter.users.times) == 8 and len(limiter.addresses.times) == 8
    assert all(len(key) == 32 for key in limiter.users.times)
    assert max(len(v) for v in limiter.addresses.times.values()) <= auth._ADDRESS_DEPTH


def test_correct_password_passes_under_address_backoff(accounts, monkeypatch):
    s, _repo, pws = accounts
    waits = []

    async def no_wait(seconds):
        waits.append(seconds)

    monkeypatch.setattr(web.asyncio, "sleep", no_wait)
    c = TestClient(web.create_app(s))
    # a spray of wrong passwords over many names from one address
    for n in range(auth.ADDRESS_FREE_ATTEMPTS + 3):
        assert "error" in _login_as(c, f"spray{n}", "wrong-password-x").headers["location"]
    assert waits and max(waits) <= auth.BACKOFF_MAX
    waits.clear()
    assert _login_as(c, "analyst1", pws["analyst1"]).headers["location"] == "/"
    assert waits, "the address is still in backoff, and the right password still passed"


def test_failed_login_never_audits_an_unknown_username(accounts):
    s, repo, _pws = accounts
    c = TestClient(web.create_app(s))
    typed = "a-password-typed-in-the-username-box-" + secrets.token_hex(4)
    _login_as(c, typed, "x")
    _login_as(c, "analyst1", "wrong-password-x")
    actors = [row["actor"] for row in _audit(repo, "web.login_failed")]
    assert actors == [web.UNKNOWN_ACCOUNT, "analyst1"]
    with repo.engine.connect() as conn:
        rows = conn.execute(select(t.audit_event)).mappings().all()
    assert not any(typed in str(dict(row)) for row in rows)


# ---------------------------------------------------------------- proxies and cookies

def _proxied(s, peer, trusted):
    return TestClient(ProxyHeadersMiddleware(web.create_app(s), trusted_hosts=trusted), client=(peer, 40000))


def test_forwarded_headers_are_used_only_from_a_trusted_proxy(accounts):
    s, repo, pws = accounts
    headers = {"x-forwarded-for": "198.51.100.7", "x-forwarded-proto": "https"}
    trusted = _proxied(s, "10.9.9.9", ["10.9.9.9"])
    r = trusted.post("/login", data={"username": "analyst1", "password": pws["analyst1"]}, headers=headers,
                     follow_redirects=False)
    assert r.headers["location"] == "/"
    assert "secure" in r.headers["set-cookie"].lower()
    assert _audit(repo, "web.login")[-1]["detail"]["client"] == "198.51.100.7"

    untrusted = _proxied(s, "203.0.113.4", ["10.9.9.9"])
    r = untrusted.post("/login", data={"username": "analyst1", "password": pws["analyst1"]}, headers=headers,
                       follow_redirects=False)
    assert r.headers["location"] == "/"
    assert "secure" not in r.headers["set-cookie"].lower()
    assert _audit(repo, "web.login")[-1]["detail"]["client"] == "203.0.113.4"


def test_failures_behind_a_proxy_are_counted_per_forwarded_address(accounts, monkeypatch):
    s, repo, pws = accounts

    async def no_wait(_seconds):
        return None

    monkeypatch.setattr(web.asyncio, "sleep", no_wait)
    c = _proxied(s, "10.9.9.9", ["10.9.9.9"])
    for n in range(auth.MAX_ATTEMPTS + 1):
        c.post("/login", data={"username": "analyst1", "password": "wrong-password-x"},
               headers={"x-forwarded-for": "198.51.100.66"}, follow_redirects=False)
    assert {row["detail"]["client"] for row in _audit(repo, "web.login_failed")} == {"198.51.100.66"}
    # another person behind the same proxy, another account: not locked out
    r = c.post("/login", data={"username": "lead1", "password": pws["lead1"]},
               headers={"x-forwarded-for": "198.51.100.67"}, follow_redirects=False)
    assert r.headers["location"] == "/"


@pytest.mark.parametrize("tls, flag, scheme, secure", [
    (False, False, "http", False), (False, True, "http", True), (True, False, "http", True),
    (False, False, "https", True)])
def test_cookie_secure_rule(tmp_path, tls, flag, scheme, secure):
    files = {"web_tls_cert": "c.pem", "web_tls_key": "k.pem"} if tls else {}
    assert serve.cookie_secure(_settings(tmp_path, web_cookie_secure=flag, **files), scheme) is secure


def test_cookie_secure_setting_is_read_from_the_env_file(tmp_path):
    from romulus.config import load_settings
    env = tmp_path / "x.env"
    env.write_text("ROMULUS_COOKIE_SECURE=1\nROMULUS_WEB_ALLOW_PLAINTEXT=1\nROMULUS_WEB_TRUSTED_PROXIES=10.0.0.1\n",
                   encoding="utf-8")
    s = load_settings(env, environ={})
    assert s.web_cookie_secure and s.web_allow_plaintext and s.web_trusted_proxies == "10.0.0.1"


def test_uvicorn_trusts_forwarded_headers_only_from_configured_proxies(tmp_path):
    plain = serve.uvicorn_options(_settings(tmp_path, web_bind="127.0.0.1:8443"))
    assert plain["proxy_headers"] is False and "forwarded_allow_ips" not in plain
    assert plain["host"] == "127.0.0.1" and plain["port"] == 8443
    proxied = serve.uvicorn_options(_settings(tmp_path, web_trusted_proxies="10.0.0.1, 10.0.1.0/24"))
    assert proxied["proxy_headers"] is True and proxied["forwarded_allow_ips"] == ["10.0.0.1", "10.0.1.0/24"]
    for bad in ("*", "0.0.0.0/0", "::/0", "proxy.example"):
        with pytest.raises(ValueError):
            serve.uvicorn_options(_settings(tmp_path, web_trusted_proxies=bad))


# ---------------------------------------------------------------- plain HTTP bind rule

@pytest.mark.parametrize("bind, loopback", [("127.0.0.1:8443", True), ("localhost:8443", True),
                                            ("[::1]:8443", True), ("127.0.0.2:8443", True),
                                            ("0.0.0.0:8443", False), (":8443", False), ("[::]:8443", False),
                                            ("192.168.1.10:8443", False)])
def test_loopback_detection(tmp_path, bind, loopback):
    assert serve.is_loopback(serve.bind_address(_settings(tmp_path, web_bind=bind))[0]) is loopback


def _run_web(tmp_path, monkeypatch, lines):
    env = tmp_path / "web.env"
    env.write_text("\n".join([f"ROMULUS_HOME={tmp_path}", f"ROMULUS_SECRET_KEY={secrets.token_urlsafe(32)}",
                              *lines]) + "\n", encoding="utf-8")
    for name in ("ROMULUS_WEB_BIND", "ROMULUS_WEB_TLS_CERT", "ROMULUS_WEB_TLS_KEY", "ROMULUS_WEB_ALLOW_PLAINTEXT",
                 "ROMULUS_WEB_TRUSTED_PROXIES", "ROMULUS_COOKIE_SECURE"):
        monkeypatch.delenv(name, raising=False)
    import uvicorn
    started = []
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: started.append(kw))
    monkeypatch.setattr(web, "create_app", lambda s, env=None: object())
    return cli.main(["--env-file", str(env), "web"]), started


def test_web_refuses_plain_http_off_loopback(tmp_path, monkeypatch, capsys):
    code, started = _run_web(tmp_path, monkeypatch, ["ROMULUS_WEB_BIND=0.0.0.0:8443"])
    err = capsys.readouterr().err
    assert code == cli.EXIT_FAIL and not started
    assert "ROMULUS_WEB_TLS_CERT" in err and "ROMULUS_WEB_ALLOW_PLAINTEXT=1" in err


def test_web_serves_plain_http_off_loopback_only_with_the_override(tmp_path, monkeypatch, capsys):
    code, started = _run_web(tmp_path, monkeypatch, ["ROMULUS_WEB_BIND=0.0.0.0:8443",
                                                     "ROMULUS_WEB_ALLOW_PLAINTEXT=1"])
    assert code == cli.EXIT_OK and started[0]["host"] == "0.0.0.0" and started[0]["proxy_headers"] is False
    assert "WARNING" in capsys.readouterr().err


def test_web_serves_loopback_and_tls_without_the_override(tmp_path, monkeypatch):
    code, started = _run_web(tmp_path, monkeypatch, ["ROMULUS_WEB_BIND=127.0.0.1:8443"])
    assert code == cli.EXIT_OK and started[0]["ssl_certfile"] is None
    code, started = _run_web(tmp_path, monkeypatch, ["ROMULUS_WEB_BIND=0.0.0.0:8443",
                                                     "ROMULUS_WEB_TLS_CERT=/x/cert.pem",
                                                     "ROMULUS_WEB_TLS_KEY=/x/key.pem",
                                                     "ROMULUS_WEB_TRUSTED_PROXIES=10.0.0.1"])
    assert code == cli.EXIT_OK and started[0]["ssl_keyfile"] == "/x/key.pem"
    assert started[0]["forwarded_allow_ips"] == ["10.0.0.1"]


def test_web_refuses_half_configured_tls_and_a_wildcard_proxy(tmp_path, monkeypatch):
    code, started = _run_web(tmp_path, monkeypatch, ["ROMULUS_WEB_TLS_CERT=/x/cert.pem"])
    assert code == cli.EXIT_FAIL and not started
    code, started = _run_web(tmp_path, monkeypatch, ["ROMULUS_WEB_TRUSTED_PROXIES=*"])
    assert code == cli.EXIT_FAIL and not started


# ---------------------------------------------------------------- doctor

def _tls_files(tmp_path):
    cert, key = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert.write_text("test certificate placeholder\n", encoding="utf-8")
    key.write_text("test key placeholder\n", encoding="utf-8")
    return cert, key


def test_doctor_web_tls_states(tmp_path):
    check = doctor.check_web_tls
    assert check(_settings(tmp_path, web_bind="0.0.0.0:8443")).status == "fail"
    assert check(_settings(tmp_path, web_bind="0.0.0.0:8443", web_allow_plaintext=True)).status == "warn"
    assert check(_settings(tmp_path, web_bind="127.0.0.1:8443")).status == "ok"
    assert check(_settings(tmp_path, web_tls_cert=str(tmp_path / "c.pem"))).status == "fail"
    assert check(_settings(tmp_path, web_trusted_proxies="*")).status == "fail"
    cert, key = _tls_files(tmp_path)
    tls = _settings(tmp_path, web_bind="0.0.0.0:8443", web_tls_cert=str(cert), web_tls_key=str(key))
    assert check(tls, posix=False).status == "ok"
    missing = _settings(tmp_path, web_bind="0.0.0.0:8443", web_tls_cert=str(cert),
                        web_tls_key=str(tmp_path / "absent.pem"))
    result = check(missing, posix=False)
    assert result.status == "fail" and "ROMULUS_WEB_TLS_KEY" in result.detail


def test_doctor_fails_a_world_readable_tls_key(tmp_path):
    cert, key = _tls_files(tmp_path)
    os.chmod(key, 0o644)          # on Windows the mode reads back as 0o666, still readable by others
    tls = _settings(tmp_path, web_bind="0.0.0.0:8443", web_tls_cert=str(cert), web_tls_key=str(key))
    result = doctor.check_web_tls(tls, posix=True)
    assert result.status == "fail" and "every local user" in result.detail
    assert doctor.key_file_problem(0o600) is None and doctor.key_file_problem(0o640) is None
    assert doctor.key_file_problem(0o604)


def test_doctor_home_mode_rule(tmp_path):
    assert doctor.open_mode(0o700) is None
    assert doctor.open_mode(0o750) == "group"
    assert doctor.open_mode(0o705) == "others"
    assert doctor.open_mode(0o777) == "group and others"
    assert doctor.check_home_modes(_settings(tmp_path), posix=False).status == "ok"


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits")
def test_doctor_warns_on_an_open_home(tmp_path):
    s = _settings(tmp_path)
    for path in (s.home, s.reports_dir, s.logs_dir):
        path.mkdir(parents=True, exist_ok=True)
        os.chmod(path, 0o700)
    assert doctor.check_home_modes(s).status == "ok"
    os.chmod(s.logs_dir, 0o755)
    result = doctor.check_home_modes(s)
    assert result.status == "warn" and str(s.logs_dir) in result.detail
    assert stat.S_IMODE(s.logs_dir.stat().st_mode) == 0o755


def test_doctor_runs_the_web_tls_check(tmp_path):
    assert "web.tls" in {step.name for step in doctor.doctor_steps(_settings(tmp_path))}


# ---------------------------------------------------------------- hunt start arguments

def test_hypothesis_is_passed_as_one_argument(client, monkeypatch):
    launched = []

    class FakePopen:
        def __init__(self, cmd, **_kw):
            launched.append(cmd)

    monkeypatch.setattr(web.subprocess, "Popen", FakePopen)
    c, pw, _ = client
    _login(c, pw)
    page = c.get("/hunts/new").text
    r = c.post("/hunts", data={"start": "2024-11-18T10:00:00Z", "end": "2024-11-18T17:30:00Z",
                               "csrf": _csrf(page), "hypothesis": "--no-agent lateral movement"},
               follow_redirects=False)
    assert r.status_code == 303
    cmd = launched[0]
    assert "--hypothesis=--no-agent lateral movement" in cmd
    assert "--hypothesis" not in cmd and cmd.count("--no-agent") == 1
