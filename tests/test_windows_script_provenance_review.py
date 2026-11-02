"""Real publication preserves script discovery ownership and preferred evidence views."""
from contextlib import closing
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path

import pytest
from jinja2 import Environment, FileSystemLoader, select_autoescape

from romulus.detect.windows_scripts import ScriptReflectiveLoad
from romulus.evidence.windows import normalize_windows
from romulus.evidence.windows_catalog import POWERSHELL_CHANNEL, POWERSHELL_PROVIDER
from romulus.evidence.windows_reassembly import ScriptBlockAssembler
from romulus.hunt.publish import publish_match
from romulus.report.manifest import build_manifest, investigations_for_hunt, publish_revision
from romulus.report.markdown import render
from romulus.store import schema as tables
from tests.test_report import _add_investigation, _repo_with_finding
from tests.windows_fixtures import LogicalWindowsEvent, windows_hit

CODE = "[System.Reflection.Assembly]::Load($bytes); "
BLOCK = "11111111-2222-3333-4444-555555555555"


def _part(number, text):
    envelope = windows_hit(LogicalWindowsEvent(POWERSHELL_CHANNEL, POWERSHELL_PROVIDER, 4104,
                                              "ws01.example.test", number, datetime(2026, 1, 2, tzinfo=UTC).isoformat(), {
                                                  "ScriptBlockText": text, "ScriptBlockId": BLOCK,
                                                  "MessageNumber": str(number), "MessageTotal": "2",
                                              }), "winlogbeat_8")
    event = normalize_windows(envelope)
    return event, {event.raw[0].key: envelope["_source"]}


def _views(tmp_path, *, cap=None):
    parts = [_part(1, CODE), _part(2, "Get-Date")]
    raws = {key: value for _, raw in parts for key, value in raw.items()}
    with closing(ScriptBlockAssembler(tmp_path, **({"text_cap": cap} if cap else {}))) as assembler:
        fragment = parts[0][0]
        views = assembler.consume([event for event, _ in parts], raws)
        joined = next(event for event in views if event.get("script.view") == "joined")
        raws.update(assembler.sources_for(views))
    return fragment, joined, raws


def _reach(number):
    return {"anchor_id": f"anchor-{number}", "link_id": f"link-{number}",
            "link_type": "script_block", "strength": "agent_hypothesis"}


def _publish(repo, event, raw, *, case="case-1", number=1, legacy=False):
    rule = ScriptReflectiveLoad()
    [match] = rule.consume([event])
    if legacy:
        match.predicate = [item for item in match.predicate if item.field != "script.view_quality"]
    return publish_match(repo, "h1", rule, match, None, raw, source_case_id=case,
                         source_anchor_id=f"anchor-{number}", source_link_id=f"link-{number}",
                         context_reach=_reach(number))


def _script_candidate(repo):
    return next(row for row in repo.candidates("h1") if row["rule_id"] == ScriptReflectiveLoad.id)


def test_agent_first_join_revision_keeps_case_origin_reaches_disposition_and_report(tmp_path):
    repo, seed = _repo_with_finding()
    _add_investigation(repo, seed)
    fragment, joined, raw = _views(tmp_path)
    first = _publish(repo, fragment, raw)
    assert first is not None and first["source_case_id"] == "case-1"
    repo.add_disposition(first["id"], "analyst", "under_review", "retained across the revision")
    assert _publish(repo, joined, raw, case=None, number=2) is None
    assert _publish(repo, fragment, raw, case="other-case", number=3) is None
    candidate = _script_candidate(repo)
    assert candidate["id"] == first["id"] and candidate["group_key"] == first["group_key"]
    assert (candidate["source_case_id"], candidate["source_anchor_id"], candidate["source_link_id"]) == (
        "case-1", "anchor-1", "link-1")
    assert candidate["gate_results"]["_context_reaches"] == [_reach(i) for i in (1, 2, 3)]
    assert candidate["gate_results"]["_revision"]["count"] == 1
    assert repo.dispositions(candidate["id"])[-1]["status"] == "under_review"
    assert any(item["field"] == "script.view_quality" and item["value"] == 15 for item in candidate["predicate_fields"])
    assert fragment.id in candidate["context_event_ids"]
    manifest = build_manifest(repo, "h1", "test")
    finding = next(row for row in manifest["findings"] if row["id"] == candidate["id"])
    assert finding["source_case_id"] == "case-1" and finding["source_anchor_id"] == "anchor-1"
    assert candidate["id"] in manifest["investigations"]["cases"][0]["contributed_candidate_ids"]
    assert candidate["id"] in investigations_for_hunt(repo, "h1")["model_contribution"]["candidate_ids"]
    assert "Investigator chain: [case `case-1`]" in render(publish_revision(repo, "h1", "test"))
    assert all(citation["status"] == "retained" for citation in finding["citations"])


def test_complete_join_supersedes_partial_join_at_equal_view_rank(tmp_path):
    repo, _ = _repo_with_finding()
    _, partial, raw = _views(tmp_path / "partial", cap=len(CODE))
    _, complete, full_raw = _views(tmp_path / "complete")
    assert partial.get("script.view") == complete.get("script.view") == "joined"
    first = _publish(repo, partial, raw)
    assert _publish(repo, complete, full_raw, number=2) is None
    candidate = _script_candidate(repo)
    assert candidate["id"] == first["id"]
    assert "partial script view" not in candidate["claim"]
    assert candidate["gate_results"]["_revision"]["count"] == 1
    assert any(item["field"] == "script.view_quality" and item["value"] == 15 for item in candidate["predicate_fields"])


def test_legacy_predicate_view_ranking_still_revises_fragments(tmp_path):
    repo, _ = _repo_with_finding()
    fragment, joined, raw = _views(tmp_path)
    _publish(repo, fragment, raw, legacy=True)
    _publish(repo, joined, raw, number=2, legacy=True)
    candidate = _script_candidate(repo)
    assert "partial script view" not in candidate["claim"]
    assert candidate["source_case_id"] == "case-1"


def test_report_and_live_projection_recover_legacy_origin_columns(tmp_path):
    repo, seed = _repo_with_finding()
    _add_investigation(repo, seed)
    fragment, _, raw = _views(tmp_path)
    first = _publish(repo, fragment, raw)
    with repo.engine.begin() as connection:
        connection.execute(tables.candidate.update().where(tables.candidate.c.id == first["id"]).values(
            source_case_id=None, source_anchor_id=None, source_link_id=None))
    manifest = build_manifest(repo, "h1", "test")
    finding = next(row for row in manifest["findings"] if row["id"] == first["id"])
    assert (finding["source_case_id"], finding["source_anchor_id"], finding["source_link_id"]) == (
        "case-1", "anchor-1", "link-1")
    assert first["id"] in investigations_for_hunt(repo, "h1")["model_contribution"]["candidate_ids"]


@pytest.mark.parametrize("change", ["claim_type", "group_key", "rule_id", "hunt_id", "predicate_fields"])
def test_evidence_view_revision_opt_in_is_narrowly_guarded(tmp_path, change):
    repo, _ = _repo_with_finding()
    fragment, _, raw = _views(tmp_path)
    first = _publish(repo, fragment, raw)
    row = deepcopy(repo.candidate(first["id"]))
    with pytest.raises(ValueError, match="only direct"):
        repo.revise_candidate(row, "ordinary revisions cannot modify an agent-owned finding")
    row[change] = {"claim_type": "observed_action", "group_key": "another-group", "rule_id": "other-rule",
                   "hunt_id": "another-hunt", "predicate_fields": []}[change]
    with pytest.raises(ValueError, match="evidence view"):
        repo.revise_candidate(row, "invalid evidence view revision", evidence_view=True)
    assert repo.candidate(first["id"])["source_case_id"] == "case-1"


def test_finding_template_shows_origin_from_stored_columns_or_legacy_fallback(tmp_path):
    repo, _ = _repo_with_finding()
    fragment, _, raw = _views(tmp_path)
    first = _publish(repo, fragment, raw)
    candidate = repo.candidate(first["id"])
    env = Environment(loader=FileSystemLoader(Path(__file__).resolve().parents[1] / "src/romulus/web/templates"),
                      autoescape=select_autoescape())
    for legacy in (False, True):
        row = deepcopy(candidate)
        if legacy:
            row.update(source_case_id=None, source_anchor_id=None, source_link_id=None)
        html = env.get_template("finding.html").render(c=row, gates=row["gate_results"], notes=[], events=[], raws=[],
                                                       dispositions=[], statuses=[], csrf="test", pretty=str)
        assert "Discovery origin" in html and "case-1" in html and "anchor-1" in html and "link-1" in html


def test_sweep_first_script_is_not_reassigned_to_a_later_investigator(tmp_path):
    repo, _ = _repo_with_finding()
    fragment, joined, raw = _views(tmp_path)
    rule = ScriptReflectiveLoad()
    [match] = rule.consume([fragment])
    first = publish_match(repo, "h1", rule, match, None, raw)
    _publish(repo, joined, raw, number=2)
    candidate = repo.candidate(first["id"])
    assert candidate["source_case_id"] is None and candidate["source_anchor_id"] is None
    assert candidate["gate_results"]["_evidence_view_origin"] == {
        "source_case_id": None, "source_anchor_id": None, "source_link_id": None}
    finding = next(row for row in build_manifest(repo, "h1", "test")["findings"] if row["id"] == first["id"])
    assert finding["source_case_id"] is None


def test_stale_revision_row_cannot_downgrade_a_newer_script_view(tmp_path):
    repo, _ = _repo_with_finding()
    fragment, joined, raw = _views(tmp_path)
    _publish(repo, fragment, raw)
    stale = deepcopy(_script_candidate(repo))
    stale["gate_results"]["_context_reaches"] = [_reach(3)]
    _publish(repo, joined, raw, number=2)
    repo.revise_candidate(stale, "late rediscovery of the earlier fragment", evidence_view=True)
    candidate = _script_candidate(repo)
    assert "partial script view" not in candidate["claim"]
    assert candidate["gate_results"]["_revision"]["count"] == 1
    assert candidate["gate_results"]["_context_reaches"] == [_reach(i) for i in (1, 2, 3)]
