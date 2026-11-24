"""web.scan_burst: each burst of one source's error-heavy requests is its own finding and cites its own records."""
from collections import Counter
from datetime import UTC, datetime, timedelta

from romulus.detect import network
from romulus.evidence.typed import RawRef, TypedEvent, fv
from tests.test_claim_citations import batches, clean, staged

T0 = datetime(2024, 11, 18, 10, 0, tzinfo=UTC)
SCANNER = "198.51.100.4"
_n = 0


def req(ts, status=404, src=SCANNER, url="", host="web01", ua="Mozilla/5.0 (compatible; Nmap Scripting Engine)"):
    global _n
    _n += 1
    fields = {"source.ip": src, "http.response.status_code": status, "url.original": f"/p{_n}" if url == "" else url,
              "user_agent.original": ua, "http.request.method": "GET"}
    return TypedEvent(id=f"sb{_n:07d}", family="http_access", ts=ts, host=host, outcome="success",
                      fields={k: fv(v, f"sb{_n}:{k}") for k, v in fields.items() if v is not None},
                      raw=[RawRef(target="fx", native_id=f"sb{_n}")], normalizer="fixture")


def scan(start, n=250, step=2, status=404, **kw):
    return [req(start + timedelta(seconds=i * step), status=status, **kw) for i in range(n)]


def run(events):
    rule = network.WebScanBurst()
    return rule, rule.consume(events) + rule.finalize()


def within(match, start, end):
    return all(start <= e.ts <= end for e in match.events)


def test_two_scans_by_one_source_are_two_findings_each_citing_its_own_records(tmp_path):
    first, second = scan(T0), scan(T0 + timedelta(hours=3))
    out = staged(network.WebScanBurst(), batches(first + second, 60), tmp_path)
    clean(out)
    assert [m.group_key for m in out] == [f"web01|{SCANNER}|{T0.isoformat()}",
                                          f"web01|{SCANNER}|{(T0 + timedelta(hours=3)).isoformat()}"]
    assert within(out[0], first[0].ts, first[-1].ts) and within(out[1], second[0].ts, second[-1].ts)
    assert all("250 HTTP requests to web01 from 198.51.100.4 in one burst" in m.claim for m in out)
    assert all(m.proposed_lane == "lead" and m.severity == "medium" for m in out)
    assert "over the hunt window this source sent 500 requests" in out[0].notes[0]


def test_a_scan_after_benign_browsing_by_the_same_source_cites_only_the_scan(tmp_path):
    browsing = [req(T0 + timedelta(minutes=i), status=200, url="/index.php", ua="Mozilla/5.0 Firefox/128.0")
                for i in range(20)]
    attack = scan(T0 + timedelta(hours=2))
    [m] = staged(network.WebScanBurst(), batches(browsing + attack, 50), tmp_path)
    clean([m])
    assert within(m, attack[0].ts, attack[-1].ts) and all(e.get("http.response.status_code") == 404 for e in m.events)
    assert m.ts == attack[0].ts


def test_a_scan_adjoining_benign_browsing_is_one_burst_from_the_browsing_on():
    browsing = [req(T0 + timedelta(minutes=i), status=200, url="/") for i in range(30)]
    attack = scan(T0 + timedelta(minutes=40))           # ten minutes after the last page view: one session
    _rule, [m] = run(browsing + attack)
    assert m.claim.startswith("280 HTTP requests") and m.ts == browsing[0].ts


def test_the_gap_boundary_is_inclusive_at_thirty_minutes():
    head = scan(T0, n=120)
    last = head[-1].ts
    joined = scan(last + timedelta(minutes=30), n=120)
    _rule, out = run(head + joined)
    assert len(out) == 1 and out[0].claim.startswith("240 HTTP requests")
    head = scan(T0, n=120)
    split = scan(head[-1].ts + timedelta(minutes=30, seconds=1), n=120)
    _rule, out = run(head + split)
    # neither half alone is a burst; the window still reaches the thresholds, so it is reported once, never lost
    assert [m.group_key for m in out] == [f"web01|{SCANNER}"]
    assert "none of its bursts qualifies on its own" in out[0].claim


def test_a_slow_scan_with_long_pauses_is_reported_for_the_window(tmp_path):
    slow = [req(T0 + timedelta(minutes=40 * i), status=404 if i % 4 else 200) for i in range(260)]
    [m] = staged(network.WebScanBurst(), batches(slow, 25), tmp_path)
    clean([m])
    assert m.group_key == f"web01|{SCANNER}"
    assert all(e.get("http.response.status_code") == 404 for e in m.events if e.id not in m.context_ids)


def test_normal_traffic_and_a_mostly_successful_burst_are_not_scans():
    normal = [req(T0 + timedelta(seconds=i), status=200, url="/zm/index.php") for i in range(600)]
    crawler = [req(T0 + timedelta(seconds=i), status=404 if i % 10 < 4 else 200, src="192.0.2.80")
               for i in range(400)]
    rule, out = run(normal + crawler)
    assert out == [] and rule.missing_required == 0


def test_missing_and_malformed_status_are_counted_not_a_clean_no_match():
    events = [req(T0, status=None), req(T0, status="-"), req(T0, src=None), req(T0, url=None)]
    rule, out = run(events)
    assert out == [] and rule.missing_required == 4 and rule.evaluated == 0


def test_records_out_of_order_within_the_gap_join_their_burst():
    attack = scan(T0, n=240)
    rule = network.WebScanBurst()
    rule.consume(attack[120:])
    rule.consume(attack[:120])                          # an earlier page delivered later, ending within the gap
    [m] = rule.finalize()
    assert m.claim.startswith("240 HTTP requests") and m.ts == attack[0].ts
    assert rule.limit_reasons() == []


def test_a_record_from_before_an_open_burst_is_counted_and_named_never_dropped():
    attack = scan(T0 + timedelta(hours=5))
    early = req(T0)
    rule = network.WebScanBurst()
    rule.consume(attack)
    rule.consume([early])
    [m] = rule.finalize()
    assert m.claim.startswith("250 HTTP requests")
    assert "over the hunt window this source sent 251 requests" in m.notes[0]
    assert any("not placed in a burst (1 record(s) not evaluated)" in r for r in rule.limit_reasons())


def test_each_source_target_is_read_in_its_own_time_order():
    attack = scan(T0, n=240)
    rule = network.WebScanBurst()
    rule.bind_raw({}, "target-b")
    rule.consume(attack[120:])
    rule.bind_raw({}, "target-a")
    rule.consume(attack[:120])
    out = rule.finalize()
    # each target's half is its own run, too short alone; the window holds both and is reported once
    assert [m.group_key for m in out] == [f"web01|{SCANNER}"] and rule.limit_reasons() == []


def test_mission_scale_clients_keep_holds_only_for_bursts():
    """Many clients over days, one hourly session each: every run that ends without qualifying releases its held
    records, so the holds left at the end are those of the one scan, not one per client session."""
    rule = network.WebScanBurst()
    rule.HOT = 64
    stage, holds = {}, Counter()
    days, clients = 3, 400
    for day in range(days):
        for hour in range(24):
            ts = T0 + timedelta(days=day, hours=hour)
            batch = [req(ts + timedelta(seconds=c), status=200 if c % 7 else 404, src=f"10.9.{c // 250}.{c % 250}",
                         url="/") for c in range(clients)]
            if (day, hour) == (1, 3):
                batch += scan(ts, n=300, step=1)
            rule.consume(batch)
            stage.update({e.id: e for e in rule.drain_staged()})
            held, released = rule.drain_bounds()
            holds.update(held)
            holds.subtract(released)
    rule.bind_loader(lambda ids: [stage[i] for i in ids if i in stage])
    out = rule.finalize()
    assert [m.group_key.split("|")[1] for m in out] == [SCANNER]
    outstanding = sum(n for n in (+holds).values())
    # open runs: one per client (its last hour) plus the scan's burst; a run holds at most its 20 examples, two bounds
    # and five user agents
    assert outstanding <= (clients + 1) * 27
    rule.release_state()
