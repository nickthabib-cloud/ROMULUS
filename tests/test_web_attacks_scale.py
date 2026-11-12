"""Actual streamed synthetic HTTP inspection, fold and login-window measurements."""
from __future__ import annotations

import json
import time
from datetime import timedelta

import pytest

from romulus.detect.bounded import StateBudget
from romulus.detect.web_attacks import WebAttacks, WebLoginBurst
from romulus.evidence.typed import RawRef, fv
from tests.test_smb_impact_scale import _rss
from tests.test_web_attacks import event

_PLANTS = (
    "/item?id=1+union+select+1", "/?x=<script>alert(1)</script>", "/../../private/data",
    "/?include=http://files.example/payload.php", "/?x=host;whoami", "/?x={{7*7}}", "/ordinary",
)


def run_scale(tmp_path, rows):
    attack, login = WebAttacks(), WebLoginBurst()
    budget = StateBudget(tmp_path, disk_total=256 * 2**20, reserve=0, memory_total=2**20)
    attack.budget = login.budget = budget
    attack.spill_dir = login.spill_dir = tmp_path
    base = event()
    baseline_rss = peak_rss = _rss()
    began = time.perf_counter()
    batches = planted = 0
    # A synthetic oracle of one scalar per planted login group; the detector
    # publishes threshold matches during consume and may have no final revision.
    observed_login = {}
    try:
        for start in range(0, rows, 256):
            batch = []
            for number in range(start, min(start + 256, rows)):
                group, offset = divmod(number, 1000)
                source = f"10.7.{group // 256}.{group % 256}"
                fields = dict(base.fields)
                fields["source.ip"] = fv(source, "native.source.ip")
                uri, method, status, agent = f"/products?tracking=id-{number}", "GET", 200, "Mozilla/5.0"
                if offset < 20:
                    uri, method, status = f"/login?user=account{offset % 4}", "POST", 401
                elif 25 <= offset <= 31:
                    uri = _PLANTS[offset - 25]
                    if offset == 31:
                        agent = "Nikto/2.5"
                    planted += 1
                for key, value in (("url.original", uri), ("http.request.method", method),
                                   ("http.response.status_code", status), ("user_agent.original", agent)):
                    fields[key] = fv(value, "native." + key)
                batch.append(base.model_copy(update={"id": f"request-{number}", "fields": fields,
                    "ts": base.ts + timedelta(seconds=number),
                    "raw": [RawRef(target="synthetic-scale-http", native_id=str(number))]}))
            sum(1 for _ in attack.consume(batch))
            for match in login.consume(batch):
                assert match.proposed_lane == "lead"
                observed_login[match.group_key] = match.aggregate_summary["total_refs"]
            batches += 1
            if batches % 16 == 0:
                peak_rss = max(peak_rss, _rss())
        attack_groups = attack_rows = 0
        for match in attack.finalize():
            assert match.proposed_lane == "lead" and len(match.events) <= 2
            assert match.aggregate_summary["count_complete"] == 1
            attack_groups += 1
            attack_rows += match.aggregate_summary["record_count"]
        for match in login.finalize():
            assert match.proposed_lane == "lead" and match.aggregate_summary["total_refs"] == 20
            observed_login[match.group_key] = match.aggregate_summary["total_refs"]
        login_groups = len(observed_login)
        login_rows = sum(observed_login.values())
        seconds = time.perf_counter() - began
        peak_rss = max(peak_rss, _rss())
        assert attack.evaluated == login.evaluated == rows
        assert attack.capped == login.capped == 0
        assert planted == attack_rows == attack_groups == rows // 1000 * 7
        assert login_groups == rows // 1000 and login_rows == rows // 1000 * 20
        return {"rows": rows, "seconds": seconds, "rows_per_second": rows / seconds,
                "baseline_rss_bytes": baseline_rss, "sampled_peak_rss_bytes": peak_rss,
                "sampled_rss_growth_bytes": peak_rss - baseline_rss,
                "attack_groups": attack_groups, "attack_records": attack_rows,
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
