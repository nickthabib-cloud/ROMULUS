"""net.tool_user_agent_http over web-server and proxy access logs (`http_access`), beside sensor transactions."""
from datetime import UTC, datetime, timedelta

from romulus.detect import network
from romulus.evidence.typed import RawRef, TypedEvent, fv
from tests.test_claim_citations import batches, clean, staged

T0 = datetime(2024, 11, 18, 14, 0, tzinfo=UTC)
_n = 0


def ev(family, ts=T0, host="web01", **fields):
    global _n
    _n += 1
    f = {k.replace("__", "."): fv(v, f"ua{_n}:{k}") for k, v in fields.items() if v is not None}
    return TypedEvent(id=f"ua{_n:06d}", family=family, ts=ts, host=host, outcome="success", fields=f,
                      raw=[RawRef(target="fx", native_id=f"ua{_n}")], normalizer="fixture")


def access(ua, ts=T0, url="/index.php", src="198.51.100.7", host="web01", **extra):
    return ev("http_access", ts, host=host, source__ip=src, user_agent__original=ua, url__original=url,
              http__request__method="GET", http__response__status_code=200, **extra)


def run(events):
    rule = network.ToolUserAgentHttp()
    return rule, rule.consume(events) + rule.finalize()


def test_a_web_server_access_log_line_with_a_tool_agent_is_a_lead_naming_the_logging_host():
    rule, [m] = run([access("curl/8.4.0", url="/uploads/x.php")])
    assert m.proposed_lane == "lead" and m.severity == "low"
    assert "from 198.51.100.7 recorded in the access log of web01" in m.claim
    assert "'curl/8.4.0'" in m.claim and "curl tool signature" in m.claim and "self-reported" in m.claim
    assert m.group_key == "access|web01|198.51.100.7|curl/8.4.0"
    assert {p.field for p in m.predicate} >= {"user_agent.original", "source.ip", "url.original"}
    assert rule.missing_required == 0


def test_access_log_requests_group_per_client_server_and_tool_across_batches(tmp_path):
    requests = [access("python-requests/2.31", ts=T0 + timedelta(seconds=i), url=f"/p{i}") for i in range(30)]
    [m] = staged(network.ToolUserAgentHttp(), batches(requests, 7), tmp_path)
    clean([m])
    assert m.claim.startswith("30 HTTP request(s) from 198.51.100.7 recorded in the access log of web01")


def test_a_proxy_line_names_the_fetched_site_and_the_proxy_host():
    _rule, [m] = run([access("Wget/1.21.3", url="http://downloads.example.test/a.sh", host="proxy01",
                            src="10.0.0.23", proxy__result="TCP_MISS")])
    assert "from 10.0.0.23 to downloads.example.test recorded in the proxy access log on proxy01" in m.claim
    _rule, [m] = run([access("curl/8.0", url="tunnel.example.test:443", host="proxy01", src="10.0.0.23")])
    assert "to tunnel.example.test recorded in the proxy access log" in m.claim


def test_sensor_transactions_keep_their_identity():
    _rule, [m] = run([ev("http_tx", source__ip="198.51.100.7", destination__ip="192.0.2.99",
                        http__hostname="192.0.2.99", user_agent__original="curl/7.81.0", url__original="/")])
    assert m.group_key == "198.51.100.7|192.0.2.99|curl/7.81.0"
    assert "to 192.0.2.99 (Host: 192.0.2.99)" in m.claim


def test_hard_benign_lookalikes_are_not_tools():
    rule, matches = run([
        access("Mozilla/5.0 (X11; Linux x86_64) curl-compatible-browser"),          # name inside a browser agent
        access("Mozilla/5.0 (Windows NT 10.0) Firefox/128.0", url="/downloads/curl-8.4.0.tar.gz"),  # name in path
        access("Mozilla/5.0", url="/search?q=wget+https%3A%2F%2Fexample.test"),     # name in a search
        access("Mozilla/5.0 (compatible; Googlebot/2.1)", url="/docs/sqlmap-usage.html"),
        access("-"),
    ])
    assert matches == [] and rule.missing_required == 0


def test_missing_fields_are_counted_never_a_clean_no_match():
    rule, matches = run([
        ev("http_access", source__host="client.example.test", user_agent__original="curl/8.0", url__original="/"),
        ev("http_access", source__ip="198.51.100.7", url__original="/"),             # no user agent logged
        ev("http_tx", source__ip="198.51.100.7", user_agent__original="curl/8.0"),   # sensor record, no server
        ev("http_access", host=None, source__ip="198.51.100.7", user_agent__original="curl/8.0", url__original="/"),
    ])
    assert matches == [] and rule.missing_required == 4 and rule.evaluated == 0


def test_the_span_runs_from_the_first_to_the_last_request_at_the_boundary():
    first, last = access("curl/8.0", ts=T0), access("curl/8.0", ts=T0 + timedelta(hours=7, minutes=29, seconds=59))
    _rule, [m] = run([last, first])
    assert T0.isoformat() in m.claim and last.ts.isoformat() in m.claim
