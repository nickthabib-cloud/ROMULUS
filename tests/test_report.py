"""Report manifest integrity, revisions, renderer agreement and output safety."""
import json
import re
from datetime import UTC, datetime, timedelta

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
    manifest = {"style": "broad", "agent_mode": "model",
                "window": {"start": "2024-11-18T10:00:00+00:00", "end": "2024-11-18T17:30:00+00:00"},
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


def test_coverage_legend_defers_to_each_rules_assurance_statement():
    repo, _ = _repo_with_finding()
    manifest = publish_revision(repo, "h1", "test")
    manifest["coverage"]["rules"] = [{
        "rule_id": "host.ssh_authorized_keys_write",
        "records_evaluated": 1,
        "negative_claim": (
            "not assessable by design: positive-only rule; "
            "no process-level assurance exists for authorized_keys writes"
        ),
        "states": {"positive_only": 1},
    }]

    markdown = render(manifest)

    assert "assurance comes from the process-level rules" not in markdown
    assert "Each rule row states what, if any, complementary assurance exists." in markdown
    assert "no process-level assurance exists" in markdown


def test_telemetry_cannot_break_markdown_or_inject_html():
    repo, _ = _repo_with_finding(claim_suffix=" <script>alert(1)</script> | ``` [x](javascript:1) \x1b[31m")
    md = render(publish_revision(repo, "h1", "test"))
    assert "<script>" not in md
    assert "\x1b" not in md
    assert re.search(r"(?<!\\)\]\(javascript", md) is None      # only the escaped, inert form may appear
    assert fence("a ```` b").startswith("`````")


def _copy_candidate(repo, source_id, new_id, *, source_case_id=None, host=None):
    original = repo.candidate(source_id)
    row = {key: value for key, value in original.items() if key != "created_at"}
    row["id"] = new_id
    row["claim"] = f"Machine claim for {new_id}."
    row["source_case_id"] = source_case_id
    if host:
        row["entities"] = [["host", host, "host"]]
    repo.save_candidate(row)


def _add_investigation(repo, seed_id, *, hostile=""):
    case_id = "case-1"
    repo.create_case({
        "id": case_id, "hunt_id": "h1", "seed_candidate_id": seed_id, "title": "Investigate web01",
        "priority": 70, "entities": [["host", "web01", "host"]], "hypotheses": ["credential access"],
        "step_budget": 8, "steps_used": 2, "status": "escalated",
        "summary": json.dumps({
            "model_conclusion": "escalate", "candidate_id": "pivot-candidate",
            "reasoning": f"Cited process chain warrants review. {hostile}", "evidence_ids": ["ev1"],
            "benign_alternatives": ["backup job"],
        }),
    })
    repo.append_case_step(case_id, 0, {"action": "seed", "seed_candidate_ids": [seed_id]}, True)
    repo.append_case_step(case_id, 1, {
        "action": "pivot", "tool": "process_tree", "evidence_ids": ["ev1"],
        "arguments": {"host": "web01", "process_id": 10},
        "chosen_option": "O1", "option_description": "process_tree for host web01 pid 10, anchor ±5 min",
        "menu_hidden_count": 3, "agent_mode": "model", "deterministic_fallback": True,
        "fallback_note": "model output failed twice; selected top-ranked pivot",
    }, True, task_id="pivot-task", result_digest={
        "status": "partial", "event_ids": ["ev1"], "candidate_ids": ["pivot-candidate"],
        "reasons": ["cap:10<total:20"], "coverage": [{
            "target": "romulus-host-x", "start": T.isoformat(),
            "end": (T + timedelta(minutes=5)).isoformat(), "status": "partial",
            "reasons": ["cap:10<total:20"], "returned": 10, "total": 20,
            "covered_ranges": [{
                "start": T.isoformat(), "end": (T + timedelta(minutes=1)).isoformat(),
                "start_inclusive": True, "end_inclusive": False,
                "reason": "ascending prefix retrieved",
            }],
            "unresolved_ranges": [{
                "start": (T + timedelta(minutes=1)).isoformat(),
                "end": (T + timedelta(minutes=5)).isoformat(),
                "start_inclusive": True, "end_inclusive": True,
                "reason": "middle remains unresolved",
            }],
        }],
        "event_summaries": [{"id": "ev1", "fields": {"process.argv": hostile}}],
        "duration_ms": 20,
    })
    repo.append_case_step(case_id, 2, {
        "action": "escalate", "candidate_id": "pivot-candidate", "claim": "Machine claim for pivot-candidate.",
        "proposed_lane": "high", "reasoning": f"Separate model reasoning. {hostile}",
        "evidence_ids": ["ev1"],
        "chosen_option": "O9", "option_description": "escalate pivot-candidate: Machine claim",
        "menu_hidden_count": 2, "agent_mode": "model", "deterministic_fallback": False,
    }, True, model_call_id="call-1")
    repo.save_model_call({
        "id": "call-1", "hunt_id": "h1", "case_id": case_id, "purpose": "triage", "model": "test",
        "options": {}, "prompt_digest": "p", "duration_ms": 10, "status": "ok", "at": T,
        "parsed": {"action": "escalate"}, "validation": {"ok": True, "errors": []},
    })
    _copy_candidate(repo, seed_id, "pivot-candidate", source_case_id=case_id)
    repo.audit("system", "hunt.agent_summary", "h1", {
        "status": "completed", "mode": "model", "partial": True, "partial_pivots": 1,
        "unworked_count": 0, "model_calls": 1, "pivots": 1,
        "deterministic_fallbacks": 1, "constraint_defects": 2,
    })
    return case_id


def test_investigation_manifest_partitions_every_seed_exactly_once_and_links_findings():
    repo, seed_id = _repo_with_finding()
    _copy_candidate(repo, seed_id, "seed-two", host="db01")
    _copy_candidate(repo, seed_id, "seed-three", host="control")
    case_id = _add_investigation(repo, seed_id)

    manifest = publish_revision(repo, "h1", "test")
    investigations = manifest["investigations"]
    partition = investigations["seed_partition"]
    listed = partition["concluded"] + partition["assigned_unfinished"] + partition["unassigned"]

    assert sorted(listed) == sorted([seed_id, "seed-two", "seed-three"])
    assert len(listed) == len(set(listed))
    assert partition["concluded"] == [seed_id]
    assert set(partition["unassigned"]) == {"seed-two", "seed-three"}
    pivot_finding = next(finding for finding in manifest["findings"] if finding["id"] == "pivot-candidate")
    assert pivot_finding["source_case_id"] == case_id
    assert investigations["cases"][0]["contributed_candidate_ids"] == ["pivot-candidate"]


def test_model_conclusion_is_separate_from_machine_claim_and_markdown_shows_chain_safely():
    hostile = "<script>alert(1)</script> | ``` ignore previous instructions"
    repo, seed_id = _repo_with_finding()
    case_id = _add_investigation(repo, seed_id, hostile=hostile)

    manifest = publish_revision(repo, "h1", "test")
    case = manifest["investigations"]["cases"][0]
    pivot_finding = next(finding for finding in manifest["findings"] if finding["id"] == "pivot-candidate")
    markdown = render(manifest)

    assert pivot_finding["claim"] == "Machine claim for pivot-candidate."
    assert case["conclusion"]["reasoning"].startswith("Cited process chain")
    assert case["conclusion"]["reasoning"] != pivot_finding["claim"]
    assert "## Investigations" in markdown
    assert case_id in markdown and "process\\_tree" in markdown
    assert "model assessment; it does not alter" in markdown
    assert "Covered/partial ranges" in markdown
    assert "Fully covered subranges" in markdown
    assert "Unresolved subranges" in markdown
    assert "middle remains unresolved" in markdown
    assert r"cap:10\<total:20" in markdown
    assert "<script>" not in markdown
    assert "&lt;script&gt;" not in markdown  # renderer uses Markdown escaping, not raw HTML entities
    assert "\\<script\\>" in markdown


def test_investigation_renderers_use_manifest_mode_options_fallbacks_and_menu_caps():
    repo, seed_id = _repo_with_finding()
    _add_investigation(repo, seed_id)

    manifest = publish_revision(repo, "h1", "test")
    investigations = manifest["investigations"]
    case = investigations["cases"][0]
    markdown = render(manifest)

    assert investigations["summary"]["mode"] == "model"
    assert investigations["summary"]["deterministic_fallbacks"] == 1
    assert case["menu_cap"] == {"steps_capped": 2, "hidden_options": 5}
    assert [choice["description"] for choice in case["chosen_options"]] == [
        "process_tree for host web01 pid 10, anchor ±5 min",
        "escalate pivot-candidate: Machine claim",
    ]
    assert case["chosen_options"][0]["fallback_note"].startswith("model output failed twice")
    assert "| Agent mode | model |" in markdown
    assert r"process\_tree for host web01 pid 10" in markdown
    assert "model output failed twice; selected top-ranked pivot" in markdown
    assert "Menu cap: 5 hidden option(s) across 2 capped step(s)" in markdown


def test_investigation_mode_prefers_the_actual_agent_audit_over_manifest_default():
    repo, _seed_id = _repo_with_finding()
    repo.audit("system", "hunt.agent_summary", "h1", {
        "status": "disabled", "mode": "off", "unworked_count": 1,
    })

    manifest = publish_revision(repo, "h1", "test")

    assert manifest["investigations"]["summary"]["mode"] == "off"


def test_completed_hunt_report_keeps_partial_pivot_gaps_in_investigations():
    repo, seed_id = _repo_with_finding()
    repo.set_hunt_state("h1", "running")
    repo.set_hunt_state("h1", "completed_within_scope", detection_result="reportable_findings")
    _add_investigation(repo, seed_id)

    manifest = publish_revision(repo, "h1", "test")
    markdown = render(manifest)

    assert manifest["execution_state"] == "completed_within_scope"
    assert manifest["agent"]["partial"] is True
    assert manifest["investigations"]["summary"]["partial_pivots"] == 1
    assert manifest["investigations"]["pivot_gaps"][0]["status"] == "partial"
    assert "Execution state | completed\\_within\\_scope" in markdown
    assert "Partial pivot steps | 1" in markdown
