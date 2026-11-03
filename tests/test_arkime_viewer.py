"""The Arkime viewer behind a proxy: a configurable base path and digest or basic authentication, with the same
read-only endpoint allowlist.

Malcolm's layout (cisagov/Malcolm, Apache-2.0, commit c6160d8e3101c017a45df9d40504ece3da047f43): nginx/nginx.conf
serves the viewer at `location /arkime` (proxy_pass to arkime:8005, the original URI kept), arkime/etc/config.ini
sets `webBasePath=/arkime/` and `authMode=header`, and nginx authenticates the user first with `auth_basic`
(nginx/nginx_auth_basic.conf) or `auth_ldap` (nginx/nginx_auth_ldap.conf)."""
import base64
import hashlib

import httpx
import pytest

from romulus.config import Settings, load_settings
from romulus.doctor import check_arkime, check_arkime_auth
from romulus.sources import packets as pk

PCAP = b"\xd4\xc3\xb2\xa1" + b"\x00" * 20
IDS = ["241118-AAAAAAAAAAAA"]


def settings(tmp_path, **kw) -> Settings:
    base = {"home": tmp_path, "arkime_url": "https://malcolm.test/", "arkime_username": "analyst",
            "arkime_password": "s3cret-pass"}
    return Settings(**{**base, **kw})


def test_basic_auth_under_a_base_path(tmp_path):
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200, content=PCAP)

    s = settings(tmp_path, arkime_base_path="/arkime", arkime_auth="basic")
    out = pk.ArkimePackets(s, transport=httpx.MockTransport(handler)).fetch(IDS, tmp_path / "a.pcap")
    assert out.error is None and len(seen) == 1
    request = seen[0]
    assert request.method == "GET" and request.url.path == "/arkime/api/sessions/pcap"
    assert request.url.params["ids"] == IDS[0]
    assert request.headers["authorization"] == "Basic " + base64.b64encode(b"analyst:s3cret-pass").decode()


def test_digest_auth_under_a_base_path_answers_the_challenge(tmp_path):
    seen = []

    def handler(request):
        seen.append(request)
        if "authorization" not in request.headers:
            return httpx.Response(401, headers={"WWW-Authenticate": 'Digest realm="Arkime", nonce="abc123", qop="auth"'})
        return httpx.Response(200, content=PCAP)

    s = settings(tmp_path, arkime_base_path="/arkime/")          # a trailing slash is the same path
    out = pk.ArkimePackets(s, transport=httpx.MockTransport(handler)).fetch(IDS, tmp_path / "a.pcap")
    assert out.error is None and [r.url.path for r in seen] == ["/arkime/api/sessions/pcap"] * 2
    header = seen[1].headers["authorization"]
    assert header.startswith("Digest ") and 'username="analyst"' in header and 'realm="Arkime"' in header
    assert f'uri="/arkime/api/sessions/pcap?ids={IDS[0]}"' in header
    ha1 = hashlib.md5(b"analyst:Arkime:s3cret-pass").hexdigest()
    assert ha1 not in header and "s3cret-pass" not in header


def test_digest_stays_the_default_and_no_base_path_is_the_root(tmp_path):
    seen = []
    s = settings(tmp_path)
    assert s.arkime_auth == "digest" and s.arkime_base_path == ""
    pk.ArkimePackets(s, transport=httpx.MockTransport(
        lambda r: seen.append(r) or httpx.Response(200, content=PCAP))).fetch(IDS, tmp_path / "a.pcap")
    assert seen[0].url.path == "/api/sessions/pcap" and "authorization" not in seen[0].headers


@pytest.mark.parametrize("method,path", [
    ("POST", "/api/sessions/pcap"), ("GET", "/api/sessions/pcap/x"), ("GET", "/api/delete"),
    ("POST", "/api/sessions/addtags"), ("POST", "/api/sessions/removetags"), ("GET", "/api/user"),
    ("DELETE", "/api/sessions"), ("GET", "/api/sessions.csv"), ("POST", "/api/sessions/scrub"),
    ("GET", "/arkime/api/sessions/pcap"),
])
def test_only_the_two_read_endpoints_are_allowed(method, path):
    with pytest.raises(pk.PacketError):
        pk.check_arkime_endpoint(method, path)


def test_allowlist_is_exactly_two_gets():
    assert pk.ARKIME_ENDPOINTS == {("GET", "/api/sessions/pcap"), ("GET", "/api/sessions")}


@pytest.mark.parametrize("auth,expect", [("basic", "Basic "), ("digest", None)])
def test_doctor_reads_the_session_list_through_the_same_client(tmp_path, auth, expect):
    seen = []

    def handler(request):
        seen.append(request)
        if expect is None and "authorization" not in request.headers:
            return httpx.Response(401, headers={"WWW-Authenticate": 'Digest realm="Arkime", nonce="n1", qop="auth"'})
        return httpx.Response(200, json={"data": []})

    s = settings(tmp_path, arkime_base_path="/arkime", arkime_auth=auth)
    check = check_arkime(s, transport=httpx.MockTransport(handler))
    assert check.status == "ok" and f"{auth} authentication" in check.detail and "/arkime" in check.detail
    assert {r.url.path for r in seen} == {"/arkime/api/sessions"} and all(r.method == "GET" for r in seen)
    assert seen[-1].headers["authorization"].startswith(expect or "Digest ")


def test_doctor_reports_a_refused_viewer(tmp_path):
    s = settings(tmp_path, arkime_auth="basic", arkime_base_path="/arkime")
    check = check_arkime(s, transport=httpx.MockTransport(lambda r: httpx.Response(401)))
    assert check.status == "fail" and "HTTP 401" in check.detail


def test_basic_over_plain_http_is_a_warning(tmp_path):
    assert check_arkime_auth(settings(tmp_path, arkime_auth="basic")) is None
    assert check_arkime_auth(settings(tmp_path, arkime_url="http://malcolm.test", arkime_auth="digest")) is None
    warn = check_arkime_auth(settings(tmp_path, arkime_url="http://malcolm.test", arkime_auth="basic"))
    assert warn.status == "warn" and "in clear" in warn.detail


# ---- settings ---------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("value,expect", [("", ""), ("/arkime", "/arkime"), ("/arkime/", "/arkime"),
                                          ("/a/b-c_d.e~f", "/a/b-c_d.e~f")])
def test_base_path_accepts_plain_paths(value, expect):
    assert Settings(arkime_base_path=value).arkime_base_path == expect


@pytest.mark.parametrize("value", ["arkime", "/arkime?x=1", "/ark ime", "/../admin", "/a/./b", "/a%2fb", "/a#b",
                                   "//host", "/a//b", "http://x/arkime"])
def test_base_path_refuses_anything_else(value):
    with pytest.raises(ValueError, match="ARKIME_BASE_PATH"):
        Settings(arkime_base_path=value)


def test_auth_mode_is_validated_and_loaded():
    with pytest.raises(ValueError, match="ARKIME_AUTH"):
        Settings(arkime_auth="ntlm")
    loaded = load_settings(environ={"ARKIME_AUTH": "basic", "ARKIME_BASE_PATH": "/arkime"})
    assert loaded.arkime_auth == "basic" and loaded.arkime_base_path == "/arkime"


def test_read_only_roles_setting():
    assert Settings().es_read_only_roles == []
    assert load_settings(environ={"ES_READ_ONLY_ROLES": "readall, site_reader"}).es_read_only_roles == [
        "readall", "site_reader"]
    with pytest.raises(ValueError, match="all_access"):
        Settings(es_read_only_roles=["readall", "all_access"])
    with pytest.raises(ValueError, match="ES_READ_ONLY_ROLES"):
        Settings(es_read_only_roles=["read all"])
