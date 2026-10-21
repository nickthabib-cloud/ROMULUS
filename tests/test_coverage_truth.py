"""Coverage truth: one fault-injection suite proving that no lost work ever reads as a complete negative.

Each fault is injected at the lowest layer that produces it (an Elasticsearch HTTP response, a raw record, a
TShark run or an Arkime download), then followed through the stage that consumes it and into the report. For
every fault the suite checks that no coverage cell is `no_match_complete`, no link is `complete`, the hunt is
partial, neither the JSON manifest nor the Markdown report renders a complete negative for the affected rule,
and the gap is listed with its reason. A no-fault control runs the same path and must reach a complete
negative, so the assertions cannot pass vacuously.
"""
from __future__ import annotations

import json
import subprocess
from datetime import UTC, datetime, timedelta
from urllib.parse import urlparse

import httpx
import pytest

from romulus.agent.models import EntityRef
from romulus.agent.tools import EntityTimelineArgs, EntityTimelineRequest
from romulus.config import Settings
from romulus.hunt import packets as hp
from romulus.hunt import run as hunt_run
from romulus.hunt.expansion import ExpansionEngine
from romulus.hunt.links import LinkAnchor, LinkFetcher, LinkWindow
from romulus.hunt.pivot import PivotExecutor
from romulus.hunt.sweep import Sweep
from romulus.report import markdown
from romulus.report.manifest import _coverage, publish_revision
from romulus.sources import packets as pk
from romulus.sources.es import ElasticClient
from romulus.sources.models import Completeness, SearchOutcome, Window
from romulus.sources.profile import contract_from_types
from romulus.store.db import make_engine, migrate
from romulus.store.repo import Repo
from tests import test_packets as packet_fixtures

T0 = datetime(2024, 11, 18, 14, 0, tzinfo=UTC)
WINDOW = Window(start=T0, end=T0 + timedelta(minutes=5))
HOST_TARGET = "romulus-host-x"
HOST_TYPES = {"@timestamp": "date", "event.dataset": "keyword", "host.name": "keyword", "source.ip": "ip",
              "url.original": "keyword", "http.response.status_code": "long", "user.name": "keyword"}
# web.scan_burst consumes http_access and can assure a negative: the control proves it reaches `complete`.
NEGATIVE_RULE = "web.scan_burst"

ES_FAULTS = ("cap", "timed_out", "terminated_early", "shard_failures", "total_gte", "partial_pit")
RECORD_FAULTS = ("normalization_error", "missing_field")
PACKET_FAULTS = ("truncated_pcap", "tshark_byte_cap", "tshark_timeout")
# What the report must say about each fault: the gap is listed with this reason.
FAULT_REASON = {
    "cap": "cap:", "timed_out": "timed_out", "terminated_early": "terminated_early",
    "shard_failures": "shard_failures", "total_gte": "total_relation:gte", "partial_pit": "HTTP 500",
    "normalization_error": "normalization_errors", "missing_field": "missing_required",
    "truncated_pcap": "capture cut short", "tshark_byte_cap": "download byte cap",
    "tshark_timeout": "TShark exceeded",
}


# ---- a fault-injecting Elasticsearch -------------------------------------------------------------------

def _iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat()


def _range_start(body: dict) -> datetime:
    for clause in body.get("query", {}).get("bool", {}).get("filter", []):
        bounds = clause.get("range", {})
        for spec in bounds.values():
            if "gte" in spec:
                return datetime.fromisoformat(str(spec["gte"]))
    return WINDOW.start


def _access_doc(n: int, ts: datetime, *, status=200, url: str | None = "/index.html") -> dict:
    source = {"@timestamp": _iso(ts), "event": {"dataset": "apache.access"}, "host": {"name": "web1"},
              "source": {"ip": "198.51.100.7"}, "http": {"request": {"method": "GET"},
                                                         "response": {"status_code": status}}}
    if url is not None:
        source["url"] = {"original": url}
    return {"_index": HOST_TARGET, "_id": f"doc-{n}", "_source": source,
            "sort": [int(ts.timestamp() * 1000), n]}


class FaultyES:
    """Answers the read-only calls the sweep and pivots make, with one fault on every raw retrieval page."""

    def __init__(self, fault: str):
        self.fault = fault
        self.searches = 0

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path = urlparse(str(request.url)).path
        body = json.loads(request.content) if request.content else {}
        if request.method == "GET" and path == "/":
            return httpx.Response(200, json={"version": {"number": "8.15.0"}})
        if path.endswith("/_pit") and request.method == "POST":
            return httpx.Response(200, json={"id": "pit-1"})
        if path == "/_pit" and request.method == "DELETE":
            return httpx.Response(200, json={"succeeded": True})
        if "h" in body.get("aggs", {}):                       # partition planning histogram: always clean
            start = _range_start(body)
            return httpx.Response(200, json={
                "timed_out": False, "_shards": {"failed": 0},
                "hits": {"total": {"value": 3, "relation": "eq"}, "hits": []},
                "aggregations": {"h": {"buckets": [{"key_as_string": _iso(start), "doc_count": 3}]}}})
        if path == "/_search":
            return self._page(body)
        return httpx.Response(404, json={"error": f"unexpected {request.method} {path}"})

    def _page(self, body: dict) -> httpx.Response:
        self.searches += 1
        start = _range_start(body) + timedelta(seconds=1)
        size = int(body.get("size", 10))
        if self.fault == "partial_pit":
            if "search_after" in body:                       # the second page of a PIT walk fails
                return httpx.Response(500, json={"error": "search_context_missing_exception"})
            hits = [_access_doc(n, start) for n in range(size)]
            return httpx.Response(200, json=self._response(hits, total=size * 2))
        hits = [_access_doc(n, start) for n in range(3)]
        if self.fault == "normalization_error":
            hits.append(_access_doc(3, start, status="not-a-status"))
        elif self.fault == "missing_field":
            hits.append(_access_doc(3, start, url=None))
        total = {"cap": 1_000_000}.get(self.fault, len(hits))
        return httpx.Response(200, json=self._response(hits, total=total))

    def _response(self, hits: list[dict], *, total: int) -> dict:
        d = {"pit_id": "pit-1", "timed_out": self.fault == "timed_out",
             "_shards": {"total": 2, "successful": 2 - (self.fault == "shard_failures"),
                         "failed": int(self.fault == "shard_failures")},
             "hits": {"total": {"value": total, "relation": "gte" if self.fault == "total_gte" else "eq"},
                      "hits": hits}}
        if self.fault == "terminated_early":
            d["terminated_early"] = True
        return d


def _client(fault: str) -> ElasticClient:
    return ElasticClient(Settings(es_url="http://es.invalid"), transport=httpx.MockTransport(FaultyES(fault)))


def _contracts() -> dict:
    return {HOST_TARGET: contract_from_types(HOST_TARGET, HOST_TYPES)}


# ---- a hunt to report on -------------------------------------------------------------------------------

def _repo(*, targets=(HOST_TARGET,), profiles=None) -> Repo:
    engine = make_engine(":memory:")
    migrate(engine)
    repo = Repo(engine)
    repo.create_hunt("h1", {
        "window": {"start": WINDOW.start.isoformat(), "end": WINDOW.end.isoformat()},
        "style": "broad", "hypothesis": "", "original_input": {}, "targets": list(targets),
        "pack": {"version": "test", "playbooks": []}, "normalizer": "test", "policy": "test",
        "model": {}, "romulus_version": "test", "agent_mode": "off", "source_profiles": profiles or {},
        "budgets": {"wall_clock_minutes": 120},
    }, "digest", "test")
    repo.set_hunt_state("h1", "running")
    return repo


def _finish(repo: Repo, *, sweep: Sweep | None = None, packet_summary=None, expansion_summary=None) -> dict:
    summary = {"finished": True, "complete": not (sweep.partial_reasons if sweep else []),
               "partial_reasons": list(sweep.partial_reasons) if sweep else [],
               "stats": sweep.stats if sweep else {}}
    repo.audit("system", "hunt.sweep_summary", "h1", summary)
    return hunt_run._finish(repo, "h1", {"status": "disabled", "stop_reason": ""}, summary,
                            partial_reasons=summary["partial_reasons"], packet_summary=packet_summary,
                            expansion_summary=expansion_summary)


def _report(repo: Repo) -> tuple[dict, str]:
    manifest = publish_revision(repo, "h1", "test")
    return manifest, markdown.render(manifest)


def _coverage_row(manifest: dict, rule_id: str) -> dict:
    return next(row for row in manifest["coverage"]["rules"] if row["rule_id"] == rule_id)


def _markdown_rows(text: str, rule_id: str) -> list[str]:
    return [line for line in text.splitlines() if line.startswith(f"| {markdown.esc(rule_id)} |")]


def _assert_gap_listed(manifest: dict, text: str, fault: str, target: str) -> None:
    reason = FAULT_REASON[fault]
    gaps = [gap for gap in manifest["coverage"]["gaps"] if gap["target"] == target]
    assert gaps and all(gap["reasons"] for gap in gaps), manifest["coverage"]["gaps"]
    assert any(reason in r for gap in gaps for r in gap["reasons"]), gaps
    assert markdown.esc(reason) in text.split("## Coverage", 1)[1]


def _assert_no_complete_negative(repo: Repo, manifest: dict, text: str, rule_id: str) -> None:
    states = [cell["state"] for cell in repo.rule_cells("h1")]
    assert "no_match_complete" not in states
    row = _coverage_row(manifest, rule_id)
    assert row["negative_claim"] != "complete" and not row["negative_claim"].startswith("not applicable")
    for line in _markdown_rows(text, rule_id):
        assert "| complete |" not in line, line


# ---- the sweep -----------------------------------------------------------------------------------------

def _sweep(fault: str) -> tuple[Repo, Sweep]:
    repo = _repo()
    sweep = Sweep(repo, _client(fault), "h1", WINDOW, _contracts())
    sweep.run_target(HOST_TARGET)
    sweep.finalize()
    return repo, sweep


def test_control_sweep_reaches_a_complete_negative():
    repo, sweep = _sweep("none")
    result = _finish(repo, sweep=sweep)
    manifest, text = _report(repo)
    assert sweep.partial_reasons == [] and result["execution_state"] == "completed_within_scope"
    assert _coverage_row(manifest, NEGATIVE_RULE)["negative_claim"] == "complete"
    assert manifest["coverage"]["gaps"] == []
    assert any("| complete |" in line for line in _markdown_rows(text, NEGATIVE_RULE))


@pytest.mark.parametrize("fault", ES_FAULTS + RECORD_FAULTS)
def test_sweep_fault_never_yields_a_complete_negative(fault):
    repo, sweep = _sweep(fault)
    result = _finish(repo, sweep=sweep)
    manifest, text = _report(repo)
    if fault == "missing_field":
        # By design a record that lacks a rule's field leaves that rule's cells partial, not the hunt: retrieval
        # and normalization ran to completion. The rule's own claim and the gap list carry it.
        assert result["execution_state"] == "completed_within_scope"
    else:
        assert sweep.partial_reasons
        assert result["execution_state"] == "partial" and manifest["execution_state"] == "partial"
    _assert_no_complete_negative(repo, manifest, text, NEGATIVE_RULE)
    assert _coverage_row(manifest, NEGATIVE_RULE)["negative_claim"].startswith("unresolved")
    _assert_gap_listed(manifest, text, fault, HOST_TARGET)


def test_every_capped_leaf_is_listed_not_only_the_first_ten():
    """A cap that survives splitting leaves many partial leaves; the report lists every one of them."""
    repo, sweep = _sweep("cap")
    _finish(repo, sweep=sweep)
    manifest, text = _report(repo)
    leaves = {c["partition"] for c in repo.rule_cells("h1")
              if c["target"] == HOST_TARGET and c["state"] not in ("split", "planned")}
    assert len(leaves) > 10
    listed = {gap["partition"] for gap in manifest["coverage"]["gaps"] if gap["target"] == HOST_TARGET}
    assert leaves <= listed
    for partition in leaves:
        assert markdown.esc(partition) in text


# ---- pivots and expansion link fetches -----------------------------------------------------------------

def _timeline() -> EntityTimelineRequest:
    return EntityTimelineRequest(tool="entity_timeline", arguments=EntityTimelineArgs(
        entity=EntityRef(kind="host", value="web1"), start=WINDOW.start, end=WINDOW.end))


def test_control_pivot_and_link_are_complete():
    repo = _repo()
    executor = PivotExecutor(repo, _client("none"), "h1", _contracts())
    assert executor.run("case-1", _timeline()).status == "complete"
    link = _link_fetch(repo, "none")
    assert link.status == "complete"


@pytest.mark.parametrize("fault", ES_FAULTS + ("normalization_error",))
def test_pivot_fault_is_partial_with_unresolved_ranges(fault):
    repo = _repo()
    result = PivotExecutor(repo, _client(fault), "h1", _contracts()).run("case-1", _timeline())
    assert result.status in ("partial", "failed")
    assert result.coverage and all(cell.status != "complete" for cell in result.coverage)
    assert all(cell.unresolved_ranges for cell in result.coverage)
    assert any(FAULT_REASON[fault] in r or (fault == "partial_pit" and "source_error" in r)
               for r in result.reasons + [cell.unresolved_ranges[0].reason for cell in result.coverage])


def _anchor_event():
    from romulus.evidence.typed import Outcome, RawRef, TypedEvent, fv
    return TypedEvent(id="anchor-event", family="process_exec", ts=T0 + timedelta(minutes=2), host="web1",
                      outcome=Outcome.success,
                      fields={"process.executable": fv("/bin/sh", "anchor:exe"),
                              "process.argv": fv(["/bin/sh"], "anchor:argv")},
                      raw=[RawRef(target=HOST_TARGET, native_id="anchor-event", digest="d")], normalizer="test@1")


def _link_fetch(repo: Repo, fault: str):
    anchor_event = _anchor_event()
    anchor = LinkAnchor(finding_id="F-anchor", ts=anchor_event.ts, host="web1", event_ids=[anchor_event.id],
                        events=[anchor_event])
    executor = PivotExecutor(repo, _client(fault), "h1", _contracts())
    return LinkFetcher(executor, WINDOW.start, WINDOW.end).fetch(
        anchor, "host_after_anchor", LinkWindow(label="anchor ±5 min", start=WINDOW.start, end=WINDOW.end))


@pytest.mark.parametrize("fault", ES_FAULTS + ("normalization_error",))
def test_link_fetch_fault_is_never_a_complete_link(fault):
    link = _link_fetch(_repo(), fault)
    assert link.status in ("partial", "failed")
    assert all(cell.status != "complete" for cell in link.coverage)


def _expansion_repo() -> Repo:
    repo = _repo()
    anchor = _anchor_event()
    repo.save_evidence("h1", [anchor], {}, None)
    repo.save_candidate({
        "id": "F-anchor", "hunt_id": "h1", "rule_id": "host.web_shell", "rule_version": "1",
        "claim": "web service spawned a shell", "claim_type": "observed_action", "event_ids": [anchor.id],
        "predicate_fields": [], "entities": [["host", "web1", "host"]], "ts": anchor.ts,
        "severity": "critical", "confidence": "high", "lane": "urgent", "priority": 100.0,
        "priority_reasons": [], "gate_results": {}, "benign_alternatives": [], "next_checks": [],
        "source_case_id": None, "source_anchor_id": None, "source_link_id": None,
    })
    return repo


def _expand(fault: str) -> tuple[Repo, dict]:
    repo = _expansion_repo()
    executor = PivotExecutor(repo, _client(fault), "h1", _contracts(), source_query_budget=400)
    summary = ExpansionEngine(repo, "h1", WINDOW, LinkFetcher(executor, WINDOW.start, WINDOW.end),
                              max_depth=1, max_source_queries=400).run()
    repo.audit("system", "hunt.expansion_summary", "h1", summary)
    return repo, summary


def test_control_expansion_has_complete_host_links():
    repo = _expand("none")[0]
    links = [row for row in repo.expansion_links("h1") if row["link_type"] == "host_after_anchor"]
    assert links and all(row["status"] == "complete" for row in links)


@pytest.mark.parametrize("fault", ES_FAULTS + ("normalization_error",))
def test_expansion_fault_reports_partial_links_and_anchors(fault):
    repo, summary = _expand(fault)
    fetched = [row for row in repo.expansion_links("h1") if row["status"] != "unsupported"]
    assert fetched and all(row["status"] in ("partial", "failed") for row in fetched)
    anchors = repo.expansion_anchors("h1")
    assert anchors and all(row["status"] == "expanded_partial" and row["reasons"] for row in anchors)
    assert summary["expanded_complete"] == 0 and summary["expanded_partial"] == len(anchors)
    result = _finish(repo, expansion_summary=summary)
    manifest, text = _report(repo)
    # By design a link that failed outright stops expansion as a source failure and makes the hunt partial; a
    # partial link leaves the engine `completed` and is carried by the anchor and link accounting instead.
    if any(row["status"] == "failed" for row in fetched):
        assert summary["status"] == "partial" and result["execution_state"] == "partial"
    assert manifest["investigations"]["anchor_accounting"]["expanded_complete"] == []
    assert "Expanded complete: none" in text
    accounting = {row["id"]: row for row in manifest["investigations"]["link_accounting"]}
    assert all(accounting[row["id"]]["status"] != "complete" for row in fetched)
    assert all(row["reasons"] for row in fetched)
    link_rows = text.split("**Expansion links**", 1)[1].split("## Investigations", 1)[0]
    for row in fetched:
        line = next(line for line in link_rows.splitlines() if line.startswith(f"| {markdown.esc(row['id'])} |"))
        assert "| complete |" not in line
    assert "no_match_complete" not in {cell["state"] for cell in repo.rule_cells("h1")}


# ---- the packet stage ----------------------------------------------------------------------------------

def _tshark(fault: str, rows):
    def run(cmd, **_kw):
        if fault == "tshark_timeout":
            raise subprocess.TimeoutExpired(cmd, 180)
        stdout = json.dumps([{"_source": {"layers": row}} for row in rows]).encode()
        if fault == "truncated_pcap":
            return subprocess.CompletedProcess(
                cmd, 2, stdout=stdout, stderr=b"The file appears to have been cut short in the middle of a packet.")
        return subprocess.CompletedProcess(cmd, 0, stdout=stdout, stderr=b"")
    return run


def _packet_stage(tmp_path, monkeypatch, fault: str):
    """The real packet stage and the real TShark runner; only the subprocess, Arkime and ES calls are faked."""
    f = packet_fixtures
    sessions = [f._session(f"241118-SESS{i:08d}", 50000 + i) for i in range(3)]
    rows = [f._row(50000 + i, f.T0.timestamp() + 900 * i) for i in range(3)]

    def execute(client, intent, contract):
        if intent.kind == "histogram":
            return SearchOutcome(target=intent.target, fingerprint="h", started_at=f.T0, ended_at=f.T0,
                                 completeness=Completeness.complete, total=0, total_relation="eq")
        return SearchOutcome(target=intent.target, fingerprint="f", started_at=f.T0, ended_at=f.T0,
                             completeness=Completeness.complete, total=len(sessions), total_relation="eq",
                             returned=len(sessions), records=sessions)

    monkeypatch.setattr(hp, "execute", execute)
    monkeypatch.setattr(hp, "merge_captures", f._merge())
    monkeypatch.setattr(pk.subprocess, "run", _tshark(fault, rows))
    repo = _repo(targets=(f.TARGET,))
    window = Window(start=f.T0 - timedelta(hours=1), end=f.T0 + timedelta(hours=2))
    packets = f._Packets(capped=fault == "tshark_byte_cap")
    summary = hp.run_packet_stage(Settings(home=tmp_path), repo, None, "h1", window, {f.TARGET: f._contract()},
                                  packets=packets)
    return repo, summary


def test_control_packet_stage_is_complete(tmp_path, monkeypatch):
    repo, summary = _packet_stage(tmp_path, monkeypatch, "none")
    assert summary["status"] == "complete" and summary["partial_reasons"] == []
    result = _finish(repo, packet_summary=summary)
    assert result["execution_state"] == "completed_within_scope"


@pytest.mark.parametrize("fault", PACKET_FAULTS)
def test_packet_fault_is_partial_everywhere_it_is_reported(tmp_path, monkeypatch, fault):
    repo, summary = _packet_stage(tmp_path, monkeypatch, fault)
    assert summary["status"] == "partial" and summary["finished"]
    assert any(FAULT_REASON[fault] in r for r in summary["partial_reasons"]), summary["partial_reasons"]
    cells = [c for c in repo.rule_cells("h1") if c["rule_id"] == packet_fixtures.RULE]
    assert cells and all(c["state"] in ("positive_only_partial", "match_on_partial") for c in cells)
    result = _finish(repo, packet_summary=summary)
    manifest, text = _report(repo)
    assert result["execution_state"] == "partial"
    _assert_no_complete_negative(repo, manifest, text, packet_fixtures.RULE)
    assert "coverage incomplete" in _coverage_row(manifest, packet_fixtures.RULE)["negative_claim"]
    _assert_gap_listed(manifest, text, fault, f"{hp.PCAP_TARGET}:{packet_fixtures.TARGET}")


# ---- the report renderers on their own ----------------------------------------------------------------

@pytest.mark.parametrize("state", ["planned", "executed_failed", "evaluated_partial", "match_on_partial",
                                   "positive_only_partial"])
def test_every_unresolved_cell_is_a_listed_gap_and_never_complete(state):
    done = {"rule_id": "r", "target": "a", "partition": "p1", "state": "no_match_complete", "evaluated": 5,
            "detail": {}}
    gap = {"rule_id": "r", "target": "a", "partition": "p2", "state": state, "evaluated": 0,
           "detail": {"reasons": ["timed_out"]} if state != "planned" else {}}
    coverage = _coverage([done, gap], targets=["a"])
    assert coverage["rules"][0]["negative_claim"] != "complete"
    assert [(g["target"], g["partition"]) for g in coverage["gaps"]] == [("a", "p2")]
    assert coverage["gaps"][0]["reasons"]


# ---- data the sweep does not evaluate -----------------------------------------------------------------

def _journal_doc(n: int, identifier: str) -> dict:
    original = json.dumps({"SYSLOG_IDENTIFIER": identifier, "MESSAGE": "job started", "_HOSTNAME": "web1"})
    return {"_index": HOST_TARGET, "_id": f"journal-{n}", "_source": {
        "@timestamp": _iso(T0 + timedelta(seconds=n)), "host": {"name": "web1"},
        "event": {"dataset": "systemd.journal", "original": original}}}


def _sweep_records(monkeypatch, records, *, profiles=None, normalized=None):
    from romulus.hunt import sweep as sweep_mod

    def execute(client, intent, contract):
        now = datetime.now(UTC)
        if intent.kind == "histogram":
            return SearchOutcome(target=intent.target, fingerprint="h", started_at=now, ended_at=now,
                                 completeness=Completeness.complete, total=len(records), total_relation="eq",
                                 buckets=[{"key": _iso(WINDOW.start), "count": len(records)}])
        return SearchOutcome(target=intent.target, fingerprint="f", started_at=now, ended_at=now,
                             completeness=Completeness.complete, total=len(records), total_relation="eq",
                             returned=len(records), records=records)

    monkeypatch.setattr(sweep_mod, "execute", execute)
    if normalized is not None:
        monkeypatch.setattr(sweep_mod, "normalize_hits", lambda hits: normalized)
    repo = _repo(profiles=profiles)
    sweep = Sweep(repo, None, "h1", WINDOW, _contracts())
    sweep.run_target(HOST_TARGET)
    sweep.finalize()
    _finish(repo, sweep=sweep)
    return repo, sweep


def test_unswept_datasets_and_unnormalized_records_are_listed_as_not_assessed(monkeypatch):
    profiles = {HOST_TARGET: {"id": "p", "backend_version": "8", "doc_count": 1543,
                              "datasets": {"linux.audit": 1000, "zoneminder": 500, "ghosts": 40,
                                           "systemd.journal": 3}}}
    records = [_access_doc(n, T0 + timedelta(seconds=n)) for n in range(3)] + [_journal_doc(1, "cron"),
                                                                                  _journal_doc(2, "cron")]
    repo = _sweep_records(monkeypatch, records, profiles=profiles)[0]
    manifest, text = _report(repo)
    listed = {(item["target"], item["dataset"]): item for item in manifest["coverage"]["not_assessed"]}
    assert listed[(HOST_TARGET, "zoneminder")]["records"] == 500
    assert listed[(HOST_TARGET, "ghosts")]["records"] == 40
    assert (HOST_TARGET, "linux.audit") not in listed and (HOST_TARGET, "systemd.journal") not in listed
    skipped = [item for item in manifest["coverage"]["not_assessed"] if "'cron'" in item["reason"]]
    assert len(skipped) == 1 and skipped[0]["records"] == 2
    section = text.split("### Data not assessed", 1)[1]
    assert "zoneminder" in section and "ghosts" in section and "cron" in section
    # an unswept dataset is not counted as evaluated: the http rule evaluated only the three access records
    assert _coverage_row(manifest, NEGATIVE_RULE)["records_evaluated"] == 3


def test_a_target_without_a_dataset_inventory_still_says_what_was_not_retrieved(monkeypatch):
    repo = _sweep_records(monkeypatch, [_access_doc(0, T0)])[0]
    manifest, text = _report(repo)
    item = next(i for i in manifest["coverage"]["not_assessed"] if i["target"] == HOST_TARGET)
    assert item["records"] is None and "other than" in item["dataset"]
    assert "unknown" in text.split("### Data not assessed", 1)[1]


def test_an_error_from_an_unmapped_dataset_marks_every_rule_partial_and_says_why(monkeypatch):
    from romulus.evidence.normalize import normalize_hits
    events, _skips, _errors = normalize_hits([_access_doc(0, T0)])
    error = ("bad", "suricata.eve.smb: suricata event.original is not JSON")
    repo, sweep = _sweep_records(monkeypatch, [_access_doc(0, T0)], normalized=(events, {}, [error]))
    cells = [c for c in repo.rule_cells("h1") if c["target"] == HOST_TARGET]
    assert cells and all(c["state"] not in ("no_match_complete", "evaluated_complete", "not_applicable_no_events",
                                            "positive_only", "matched") for c in cells)
    manifest, _text = _report(repo)
    gap = next(g for g in manifest["coverage"]["gaps"] if g["target"] == HOST_TARGET)
    assert gap["every_rule_there"]
    assert any("suricata.eve.smb feeds no known event family, so every rule is partial" in r for r in gap["reasons"])
    assert sweep.partial_reasons


def test_an_audit_login_group_error_leaves_network_rules_assessable(monkeypatch):
    from romulus.evidence.normalize import normalize_hits
    events, _skips, _errors = normalize_hits([_access_doc(0, T0)])
    error = ("bad", "linux.audit.auth: malformed login record")
    repo = _sweep_records(monkeypatch, [_access_doc(0, T0)], normalized=(events, {}, [error]))[0]
    cells = {c["rule_id"]: c for c in repo.rule_cells("h1") if c["target"] == HOST_TARGET}
    assert cells["host.ssh_login_external_source"]["state"] == "evaluated_partial"     # auth: may be hidden
    assert cells["host.credential_store_read"]["state"] == "evaluated_partial"          # exec: same event
    assert cells["net.port_scan"]["state"] == "not_applicable_no_events"               # no flow can hide here
    assert cells[NEGATIVE_RULE]["state"] == "evaluated_complete"
    assert any("normalization_errors=1 in linux.audit.auth" in r
               for r in cells["host.ssh_login_external_source"]["detail"]["reasons"])
