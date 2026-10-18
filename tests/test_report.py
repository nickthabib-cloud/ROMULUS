"""Report manifest integrity, revisions, renderer agreement and output safety."""
import json
import re
from datetime import UTC, datetime

from romulus.decide.policy import decide
from romulus.detect import host
from romulus.evidence.typed import Outcome, RawRef, TypedEvent, fv
from romulus.report.manifest import publish_revision
from romulus.report.markdown import fence, outcome_sentence, render
from romulus.store.db import make_engine, migrate
from romulus.store.repo import Repo

T = datetime(2024, 11, 18, 15, 19, tzinfo=UTC)


def _repo_with_finding(claim_suffix=""):
    e = make_engine(":memory:")
    migrate(e)
    repo = Repo(e)
    manifest = {"style": "broad", "window": {"start": "2024-11-18T10:00:00+00:00", "end": "2024-11-18T17:30:00+00:00"},
                "original_input": {}, "targets": ["idx"], "pack": {"version": "p"}, "normalizer": "n",
                "policy": "d", "model": {}, "romulus_version": "0"}
    repo.create_hunt("h1", manifest, "dig", "test")
    repo.set_hunt_state("h1", "running")
    argv = ["cat", "/etc/shadow" + claim_suffix] if not claim_suffix else ["cat", "/etc/shadow"]
    ev = TypedEvent(id="ev1", family="process_exec", ts=T, host="web01", outcome=Outcome.success,
                    fields={"process.argv": fv(argv, "raw1:event.original")},
                    raw=[RawRef(target="idx", native_id="raw1", digest="abc")], normalizer="t")
    m = host.CredentialStoreRead().consume([ev])[0]
    if claim_suffix:
        m.claim += claim_suffix
    d = decide(m, "h1")
    repo.save_evidence("h1", [ev], {"idx/raw1": {"message": "x"}}, None)
    # make the retained digest match the reference
    with e.begin() as c:
        c.exec_driver_sql("update raw_record set digest='abc'")
    repo.save_candidate({"id": d.candidate_id, "hunt_id": "h1", "rule_id": m.playbook_id, "rule_version": "1",
                         "claim": m.claim, "claim_type": m.claim_type, "event_ids": ["ev1"],
                         "predicate_fields": [{"field": p.field, "value": p.value, "origin": p.origin}
                                              for p in m.predicate],
                         "entities": [list(x) for x in m.entities], "ts": T, "severity": d.severity,
                         "confidence": d.confidence, "lane": d.lane, "priority": d.priority,
                         "priority_reasons": d.priority_reasons, "gate_results": {**d.gates, "_notes": d.notes},
                         "benign_alternatives": ["backup"], "next_checks": ["auth_activity"], "source_case_id": None})
    repo.set_hunt_state("h1", "partial", detection_result="reportable_findings", stop_reason="test")
    return repo, d.candidate_id


def test_manifest_citations_resolve_and_renderers_agree():
    repo, cid = _repo_with_finding()
    m = publish_revision(repo, "h1", "test")
    assert m["integrity"]["broken_citations"] == 0 and m["findings"][0]["id"] == cid
    md = render(m)
    assert cid in md and m["revision"]["id"] in md
    j = json.loads(json.dumps(m))
    assert [f["id"] for f in j["findings"]] == re.findall(r'<a id="f-([0-9a-f]+)"></a>', md)
    # partial hunt with findings states both facts and never claims cleanliness
    s = outcome_sentence(m)
    assert "finding" in s and "partial" in s and "clean" not in s.replace("not a statement that the environment is clean", "")


def test_revisions_are_append_only():
    repo, cid = _repo_with_finding()
    r1 = publish_revision(repo, "h1", "test")
    repo.add_disposition(cid, "analyst1", "confirmed_malicious", "verified on host")
    r2 = publish_revision(repo, "h1", "test")
    assert r2["revision"]["number"] == 2 and r2["revision"]["supersedes"] == r1["revision"]["id"]
    assert r2["findings"][0]["analyst_status"] == "confirmed_malicious"
    assert r1["findings"][0]["analyst_status"] == "new"


def test_broken_citation_degrades_report():
    repo, _ = _repo_with_finding()
    with repo.engine.begin() as c:
        c.exec_driver_sql("update raw_record set digest='tampered'")
    m = publish_revision(repo, "h1", "test")
    assert m["integrity"]["broken_citations"] == 1 and not m["integrity"]["finalizable"]
    assert "Degraded report" in render(m)


def test_telemetry_cannot_break_markdown_or_inject_html():
    repo, _ = _repo_with_finding(claim_suffix=" <script>alert(1)</script> | ``` [x](javascript:1) \x1b[31m")
    md = render(publish_revision(repo, "h1", "test"))
    assert "<script>" not in md
    assert "\x1b" not in md
    assert re.search(r"(?<!\\)\]\(javascript", md) is None      # only the escaped, inert form may appear
    assert fence("a ```` b").startswith("`````")
