"""Retained positives with unavailable anchors leave named downstream coverage gaps."""
from datetime import UTC, datetime

from romulus.detect.base import Match, Playbook
from romulus.hunt.context import finalize_context
from romulus.hunt.publish import publish_match
from tests.test_sweep import _repo


def test_uncited_positive_names_each_unassessed_context_rule_and_resume_clears_restored_gap():
    class Rule(Playbook):
        id = "host.web_service_spawns_interpreter"
        title = "recorded service child"
        families = ("process_exec",)
    repo = _repo()
    match = Match(Rule.id, "Recorded service child on web1; no citation could be retained.", "observed_action",
                  [], [], datetime(2026, 1, 2, tzinfo=UTC), "high", "high", "medium",
                  group_key="web1|service", citation_unavailable=True)
    candidate = publish_match(repo, "h1", Rule(), match, None, {})
    assert candidate["lane"] == "high"
    finalize_context(repo, "h1")
    cells = [cell for cell in repo.rule_cells("h1") if cell["target"] == "context:uncited_anchor"]
    assert {"context.credential_access", "context.lateral_movement", "context.staging_and_transfer"} <= {
        cell["rule_id"] for cell in cells}
    assert all(cell["state"] == "evaluated_partial" and candidate["id"] in str(cell["detail"]) for cell in cells)
    assert all("no citation could be retained" in str(cell["detail"]) for cell in cells)
    # A later source-backed correction removes only these synthetic gap cells on recomputation.
    row = repo.candidate(candidate["id"])
    row["gate_results"] = {key: value for key, value in row["gate_results"].items() if key != "_citation_unavailable"}
    repo.revise_candidate(row, "native citations restored")
    finalize_context(repo, "h1")
    assert not [cell for cell in repo.rule_cells("h1") if cell["target"] == "context:uncited_anchor"]
