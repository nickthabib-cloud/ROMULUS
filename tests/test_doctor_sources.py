"""`romulus doctor` source checks: `os.flavor_version` and `os.read_only` on both flavors, against the recorded
responses in tests/data/opensearch_responses.json (sources cited in tests/test_sources_opensearch.py).

Read-only is reported only when it is shown: on Elasticsearch by `_has_privileges`; on OpenSearch by the security
plugin's role list matching the site's configured read-only roles. Anything else is a warning that names the request
allowlist as the write guard, or a failure when the account is shown to be able to write."""
import json

import httpx
import pytest

from romulus.config import Settings
from romulus.doctor import READ_ONLY_UNPROVEN, check_es
from tests.test_sources_opensearch import RESPONSES, FakeOpenSearch, recorded


def by_name(checks):
    return {c.name: c for c in checks}


def os_settings(**kw) -> Settings:
    return Settings(es_url="https://os.invalid", es_flavor="opensearch", es_index_patterns=["arkime_sessions3-*"], **kw)


def opensearch_doctor(root="root_opensearch_2.11.1", authinfo="authinfo_read_only_roles", **kw):
    fake = FakeOpenSearch(root=root, authinfo=authinfo)
    return by_name(check_es(os_settings(**kw), transport=httpx.MockTransport(fake))), fake


# ---- os.flavor_version ---------------------------------------------------------------------------------------

@pytest.mark.parametrize("root,status,text", [
    ("root_opensearch_2.3.0", "fail", "no point-in-time search (OpenSearch 2.4 or later)"),
    ("root_opensearch_compatibility_mode", "fail", "turn off compatibility.override_main_response_version"),
    ("root_elasticsearch_8.15.0", "fail", "ES_FLAVOR=opensearch, but the cluster reports elasticsearch 8.15.0"),
    ("root_opensearch_2.11.1", "ok", "no _shard_doc tiebreaker"),
    ("root_opensearch_3.3.0", "ok", "point-in-time search available"),
])
def test_opensearch_flavor_and_version(root, status, text):
    checks, fake = opensearch_doctor(root=root)
    assert checks["os.flavor_version"].status == status and text in checks["os.flavor_version"].detail
    if status == "fail":
        # the client refuses to run: nothing past GET / is asked, and nothing past the failure is reported
        assert fake.sent() == ["GET /"] and set(checks) == {"es.reachable", "os.flavor_version"}


def test_opensearch_3_3_carries_no_tie_group_note():
    checks, _fake = opensearch_doctor(root="root_opensearch_3.3.0")
    assert "_shard_doc" not in checks["os.flavor_version"].detail


def _es_handler(root, privileges=None, indices=("logs-a",), resolve_status=200, privileges_status=200, seen=None):
    def handler(request):
        path = request.url.path
        if seen is not None:
            seen.append(request)
        if path == "/":
            return recorded(root)
        if path == "/_security/_authenticate":
            return httpx.Response(200, json={"username": "hunt_reader", "roles": ["reader"]})
        if path.startswith("/_resolve/index/"):
            return httpx.Response(resolve_status, json={"indices": [{"name": i} for i in indices], "aliases": [],
                                                        "data_streams": []})
        if path == "/_security/user/_has_privileges":
            if privileges_status != 200:
                return httpx.Response(privileges_status, json={"error": "security_exception"})
            return httpx.Response(200, json=privileges or {
                "cluster": {"all": False, "manage": False, "monitor": True, "manage_security": False},
                "index": {"logs-a": {"read": True, "write": False, "index": False, "delete": False,
                                     "manage": False, "create": False, "delete_index": False}}})
        raise AssertionError(f"unexpected request {request.method} {path}")
    return httpx.MockTransport(handler)


@pytest.mark.parametrize("root,status,text", [
    ("root_elasticsearch_8.15.0", "ok", "elasticsearch 8.15.0 matches ES_FLAVOR=elasticsearch"),
    ("root_elasticsearch_7.17.0", "fail", "Elasticsearch 8 or later is required"),
    ("root_opensearch_2.11.1", "fail", "ES_FLAVOR=elasticsearch, but the cluster reports opensearch 2.11.1"),
])
def test_elasticsearch_flavor_and_version(root, status, text):
    s = Settings(es_url="https://es.invalid", es_index_patterns=["logs-*"])
    checks = by_name(check_es(s, transport=_es_handler(root)))
    assert checks["os.flavor_version"].status == status and text in checks["os.flavor_version"].detail


# ---- os.read_only: Elasticsearch -----------------------------------------------------------------------------

def test_elasticsearch_read_only_is_the_has_privileges_check():
    s = Settings(es_url="https://es.invalid", es_index_patterns=["logs-*"])
    checks = by_name(check_es(s, transport=_es_handler("root_elasticsearch_8.15.0")))
    assert checks["os.read_only"].status == checks["es.least_privilege"].status == "ok"


def test_elasticsearch_write_privilege_fails_read_only():
    s = Settings(es_url="https://es.invalid", es_index_patterns=["logs-*"])
    privileges = {"cluster": {"all": False, "manage": False, "manage_security": False},
                  "index": {"logs-a": {"read": True, "write": True}}}
    checks = by_name(check_es(s, transport=_es_handler("root_elasticsearch_8.15.0", privileges)))
    assert checks["os.read_only"].status == checks["es.least_privilege"].status == "fail"
    assert "logs-a:write" in checks["os.read_only"].detail


@pytest.mark.parametrize("index_privilege", ["create_doc", "create_index", "auto_configure", "maintenance"])
def test_elasticsearch_index_write_privileges_beyond_write_fail_read_only(index_privilege):
    s = Settings(es_url="https://es.invalid", es_index_patterns=["logs-*"])
    privileges = {"cluster": {}, "index": {"logs-a": {"read": True, index_privilege: True}}}
    checks = by_name(check_es(s, transport=_es_handler("root_elasticsearch_8.15.0", privileges)))
    assert checks["os.read_only"].status == "fail" and f"logs-a:{index_privilege}" in checks["os.read_only"].detail


@pytest.mark.parametrize("cluster_privilege", ["manage_pipeline", "manage_ingest_pipelines", "manage_watcher",
                                               "manage_index_templates", "manage_transform", "create_snapshot"])
def test_elasticsearch_cluster_write_privileges_fail_read_only(cluster_privilege):
    s = Settings(es_url="https://es.invalid", es_index_patterns=["logs-*"])
    privileges = {"cluster": {cluster_privilege: True, "monitor": True},
                  "index": {"logs-a": {"read": True, "write": False}}}
    checks = by_name(check_es(s, transport=_es_handler("root_elasticsearch_8.15.0", privileges)))
    assert checks["os.read_only"].status == "fail" and cluster_privilege in checks["os.read_only"].detail


def test_elasticsearch_asks_for_every_write_privilege_the_docs_list():
    seen = []
    s = Settings(es_url="https://es.invalid", es_index_patterns=["logs-*"])
    check_es(s, transport=_es_handler("root_elasticsearch_8.15.0", seen=seen))
    body = json.loads(next(r for r in seen if r.url.path == "/_security/user/_has_privileges").content)
    asked = set(body["index"][0]["privileges"])
    assert {"create_doc", "create_index", "write", "index", "delete", "delete_index", "manage", "all"} <= asked
    assert {"manage_pipeline", "manage_ingest_pipelines", "manage_watcher", "manage_security", "all",
            "manage"} <= set(body["cluster"])


@pytest.mark.parametrize("handler_args,text", [
    ({"privileges_status": 403}, "_has_privileges could not be read"),
    ({"indices": ()}, "no configured index pattern resolves"),
    ({"resolve_status": 500}, "index patterns could not be resolved"),
])
def test_elasticsearch_read_only_is_a_warning_when_it_could_not_be_asked(handler_args, text):
    s = Settings(es_url="https://es.invalid", es_index_patterns=["logs-*"])
    checks = by_name(check_es(s, transport=_es_handler("root_elasticsearch_8.15.0", **handler_args)))
    assert checks["os.read_only"].status == "warn" and text in checks["os.read_only"].detail
    assert checks["os.read_only"].detail.endswith(READ_ONLY_UNPROVEN)
    assert "es.least_privilege" not in checks


# ---- os.read_only: OpenSearch --------------------------------------------------------------------------------

def test_roles_all_configured_read_only_is_ok():
    checks, _fake = opensearch_doctor(es_read_only_roles=["readall", "site_reader"])
    assert checks["os.read_only"].status == "ok"
    assert checks["es.account"].status == "ok" and "user=hunt_reader" in checks["es.account"].detail


def test_a_role_outside_the_configured_set_is_a_warning():
    checks, _fake = opensearch_doctor(authinfo="authinfo_unlisted_role", es_read_only_roles=["readall"])
    assert checks["os.read_only"].status == "warn"
    assert "['own_index']" in checks["os.read_only"].detail and READ_ONLY_UNPROVEN in checks["os.read_only"].detail


def test_no_configured_read_only_roles_is_a_warning():
    checks, _fake = opensearch_doctor()
    assert checks["os.read_only"].status == "warn" and "ES_READ_ONLY_ROLES" in checks["os.read_only"].detail


def test_no_roles_listed_is_a_warning():
    checks, _fake = opensearch_doctor(authinfo="authinfo_no_roles", es_read_only_roles=["readall"])
    assert checks["os.read_only"].status == "warn" and READ_ONLY_UNPROVEN in checks["os.read_only"].detail


def test_the_superuser_role_fails():
    checks, _fake = opensearch_doctor(authinfo="authinfo_all_access", es_read_only_roles=["readall"])
    assert checks["os.read_only"].status == "fail" and checks["es.account"].status == "fail"
    allowed, _fake = opensearch_doctor(authinfo="authinfo_all_access", allow_privileged_source_account=True)
    assert allowed["os.read_only"].status == "warn" and allowed["es.account"].status == "ok"


@pytest.mark.parametrize("authinfo,status", [
    ("security_absent_no_handler", 400), ("security_absent_proxy_not_found", 404), ("security_unauthorized", 401),
])
def test_security_plugin_absent_or_refusing_is_a_warning_never_ok(authinfo, status):
    checks, _fake = opensearch_doctor(authinfo=authinfo, es_read_only_roles=["readall"])
    read_only = checks["os.read_only"]
    assert read_only.status == "warn" and f"HTTP {status}" in read_only.detail
    assert read_only.detail.endswith(READ_ONLY_UNPROVEN)
    assert checks["es.account"].status == "warn"
    assert checks["es.index[arkime_sessions3-*]"].status == "ok"


def test_read_only_is_never_ok_without_proof():
    for authinfo in ("authinfo_unlisted_role", "authinfo_no_roles", "authinfo_all_access",
                     "security_absent_no_handler", "security_absent_proxy_not_found", "security_unauthorized"):
        for roles in ([], ["readall"]):
            checks, _fake = opensearch_doctor(authinfo=authinfo, es_read_only_roles=roles)
            assert checks["os.read_only"].status != "ok", (authinfo, roles)


def test_opensearch_doctor_never_asks_elasticsearch_security_apis():
    _checks, fake = opensearch_doctor(es_read_only_roles=["readall"])
    assert not [r for r in fake.sent() if "_security/_authenticate" in r or "_has_privileges" in r]


def test_recorded_authinfo_roles_are_the_mapped_security_roles():
    assert RESPONSES["authinfo_read_only_roles"]["body"]["roles"] == ["readall", "site_reader"]
