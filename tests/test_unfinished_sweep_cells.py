"""A hunt that ends before its sweep finished keeps no whole-window cell that claims a complete answer.

Finalize writes window cells rule by rule; a sweep that stops part-way leaves some of them looking complete. Such a
hunt cannot resume its sweep, so the end transition narrows those cells in its own transaction.
"""
from datetime import UTC, datetime, timedelta

import pytest

from romulus.store.db import make_engine, migrate
from romulus.store.repo import Repo

T = datetime(2024, 11, 18, 10, tzinfo=UTC)
COMPLETE = {"r.none": "no_match_complete", "r.match": "matched", "r.empty": "not_applicable_no_events",
            "r.po": "positive_only", "r.eval": "evaluated_complete"}
NARROWED = {"r.none": "evaluated_partial", "r.match": "match_on_partial", "r.empty": "evaluated_partial",
            "r.po": "positive_only_partial", "r.eval": "evaluated_partial"}


def _repo(tmp_path):
    engine = make_engine(tmp_path / "db.sqlite")
    migrate(engine)
    repo = Repo(engine)
    repo.create_hunt("h1", {"window": {"start": T.isoformat(), "end": (T + timedelta(hours=1)).isoformat()},
                            "targets": ["t"]}, "digest", "test")
    owner = repo.claim_hunt("h1", 600)["lease_owner"]
    for rule, state in COMPLETE.items():
        repo.set_rule_cell("h1", rule, "1", "*", "window", state, 1 if "match" in state else 0, 3,
                           {"reasons": ["kept"]}, owner_token=owner)
        repo.set_rule_cell("h1", rule, "1", "t", "p0", state, 0, 3, {}, owner_token=owner)
    repo.set_rule_cell("h1", "r.failed", "1", "*", "window", "executed_failed", 0, 0, {"error": "x"},
                       owner_token=owner)
    return repo, owner


def _states(repo):
    return {(c["rule_id"], c["target"]): (c["state"], (c["detail"] or {}).get("reasons"))
            for c in repo.rule_cells("h1")}


@pytest.mark.parametrize("state", ["failed", "partial", "canceled"])
@pytest.mark.parametrize("summary", [None, {"finished": False, "complete": False}])
def test_ending_without_a_finished_sweep_narrows_window_cells(tmp_path, state, summary):
    repo, owner = _repo(tmp_path)
    if summary is not None:
        repo.audit("system", "hunt.sweep_summary", "h1", summary, owner_token=owner)
    if state == "partial":
        repo.set_hunt_state("h1", "paused", owner_token=owner)
        owner = None
    repo.set_hunt_state("h1", state, owner_token=owner, stop_reason="sweep error: boom")
    cells = _states(repo)
    for rule, narrowed in NARROWED.items():
        window_state, reasons = cells[(rule, "*")]
        assert window_state == narrowed
        assert reasons[0] == "kept"
        assert reasons[-1].startswith(f"the hunt ended {state} before its sweep finished")
        # a partition's own answer is about that partition and is kept
        assert cells[(rule, "t")][0] == COMPLETE[rule]
    assert cells[("r.failed", "*")][0] == "executed_failed"


def test_a_finished_sweep_keeps_its_window_cells(tmp_path):
    repo, owner = _repo(tmp_path)
    repo.audit("system", "hunt.sweep_summary", "h1", {"finished": True, "complete": True}, owner_token=owner)
    repo.set_hunt_state("h1", "failed", owner_token=owner, stop_reason="expansion error: boom")
    assert {rule: _states(repo)[(rule, "*")][0] for rule in COMPLETE} == COMPLETE


def test_pausing_is_not_an_end(tmp_path):
    repo, owner = _repo(tmp_path)
    repo.set_hunt_state("h1", "paused", owner_token=owner)
    assert {rule: _states(repo)[(rule, "*")][0] for rule in COMPLETE} == COMPLETE


def test_the_latest_summary_decides(tmp_path):
    repo, owner = _repo(tmp_path)
    repo.audit("system", "hunt.sweep_summary", "h1", {"finished": True}, owner_token=owner)
    repo.audit("system", "hunt.sweep_summary", "h1", {"finished": False, "error": "resume failed"},
               owner_token=owner)
    repo.set_hunt_state("h1", "failed", owner_token=owner)
    assert _states(repo)[("r.none", "*")][0] == "evaluated_partial"


def test_narrowing_is_bounded_per_statement(tmp_path):
    repo, owner = _repo(tmp_path)
    repo.set_rule_cells("h1", [{"rule_id": f"bulk.{i}", "version": "1", "target": "*", "partition": "window",
                                "state": "no_match_complete", "matched": 0, "evaluated": 1, "detail": {}}
                               for i in range(1_234)], owner_token=owner)
    repo.set_hunt_state("h1", "failed", owner_token=owner)
    states = {c["state"] for c in repo.rule_cells("h1") if c["rule_id"].startswith("bulk.")}
    assert states == {"evaluated_partial"}
