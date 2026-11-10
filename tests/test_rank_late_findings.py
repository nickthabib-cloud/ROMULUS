"""Findings stored after the final ranking pass (an AI agent's proposals and its pivots' rule matches) are placed into
it when the agent's run ends, scored from the pass's stored entity scores, without recomputing the pass."""
from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import select

from romulus.agent import investigate
from romulus.agent.dossier import build_dossier
from romulus.agent.toolbox import Toolbox
from romulus.hunt import rank as rank_module
from romulus.hunt.rank import PASS_FINAL, PLACE_FAILED_ACTION, compute_rank_pass, place_late_findings
from romulus.store import schema as t
from romulus.store.repo import FINAL_RANK_SUMMARY
from tests import test_evidence_rank as evidence
from tests.test_evidence_rank import START, _event, _flow, _insert, _ranks, _row
from tests.test_rank_views import _ranked_repo, _repo, _report_order, _walk, dossier_alias_target


def _late_repo(filler=30):
    """A ranked hunt, then an AI agent's proposal (from `_ranked_repo`), a confirmed rule match one of its pivots found,
    and an agent proposal in the context lane, all stored after the final pass."""
    repo = _ranked_repo(filler=filler)
    pivot = _row("zz-pivot-urgent", "r.dump", lane="urgent", host="h-t", ts=START + timedelta(hours=6))
    pivot["source_case_id"] = "session-1"
    _insert(repo, [pivot, _row("z-context", "agent.ctx", lane="context", host="h-t", provenance="agent")])
    return repo


def _audits(repo, action, hunt_id="h1"):
    with repo.engine.connect() as connection:
        return connection.execute(select(t.audit_event.c.detail).where(
            t.audit_event.c.hunt_id == hunt_id, t.audit_event.c.action == action)
            .order_by(t.audit_event.c.id)).scalars().all()


def _done(repo, hunt_id="h1"):
    with repo.engine.begin() as connection:
        connection.execute(t.hunt.update().where(t.hunt.c.id == hunt_id).values(
            execution_state="completed_within_scope"))


def _kept(before, after):
    """Every earlier row keeps its score, reported flag, section, entity and reasons, and their relative order."""
    fields = ("score", "reported", "section", "entity_kind", "entity", "reasons")
    assert {cid: tuple(after[cid][key] for key in fields) for cid in before} == {
        cid: tuple(row[key] for key in fields) for cid, row in before.items()}
    assert sorted(before, key=lambda cid: before[cid]["position"]) == sorted(
        before, key=lambda cid: after[cid]["position"])
    assert sorted(row["position"] for row in after.values()) == list(range(1, len(after) + 1))


def test_late_findings_are_placed_and_every_earlier_rank_and_entity_is_unchanged():
    repo = _late_repo()
    before, entities_before = _ranks(repo)
    summary_before = _audits(repo, FINAL_RANK_SUMMARY)
    assert repo.unranked_findings("h1") == 2      # the proposal and the pivot's rule match; context is not ranked
    summary = place_late_findings(repo, "h1")
    after, entities_after = _ranks(repo)
    assert repo.unranked_findings("h1") == 0
    assert set(after) == set(before) | {"z-agent", "zz-pivot-urgent"}
    _kept(before, after)
    assert entities_after == entities_before
    assert after["zz-pivot-urgent"]["section"] == 0
    assert after["z-agent"]["section"] in {1, 2}
    assert all("after the last ranking pass" in after[cid]["reasons"] for cid in ("z-agent", "zz-pivot-urgent"))
    assert summary["late_findings_placed"] == 2
    assert summary["ranked_findings"] == len(after)
    assert summary["reported_findings"] == sum(bool(row["reported"]) for row in after.values())
    assert _audits(repo, FINAL_RANK_SUMMARY) == [*summary_before, summary]


def test_evidence_an_agent_pivot_stored_never_changes_earlier_ranks_or_the_hunts_result():
    """An agent pivot stores another host's telemetry carrying an address a ranked host owns (address reuse).
    Recomputing the pass would rebuild the address map from it and move the earlier findings; placing does not."""
    repo = evidence._repo()
    _event(repo, "e1", "web01", "process_exec", ["10.0.0.5"])
    flow = _flow("n1", ["10.0.0.5", "203.0.113.9"], rule="net.c2", ts=START + timedelta(minutes=10))
    flow["gate_results"]["_attack"] = ["T1071"]
    _insert(repo, [_row("h1", "host.exec", host="web01", attack=["T1059"]), flow])
    compute_rank_pass(repo, "h1", PASS_FINAL)
    before, entities_before = _ranks(repo)
    assert before["h1"]["reported"] and before["n1"]["reported"]
    result = repo.detection_result("h1")
    assert result[1] == "reportable_findings"
    # what the agent's pivot and proposal store
    _event(repo, "e2", "laptop7", "auth", ["10.0.0.5"], ts=START + timedelta(hours=3))
    _insert(repo, [_row("agent-x", "agent.finding", host="laptop7", provenance="agent"),
                   _row("agent-y", "agent.finding", entities=[["ip", "10.0.0.5", "src"]], provenance="agent")])
    place_late_findings(repo, "h1")
    after, entities_after = _ranks(repo)
    _kept(before, after)
    assert entities_after == entities_before
    assert repo.detection_result("h1") == result
    # an agent proposal on a ranked entity is placed by that entity's stored score, but never counts toward it
    assert after["agent-y"]["entity"] in {None, "10.0.0.5", "web01"}


def test_after_placement_every_view_lists_the_report_order_with_no_unranked_finding():
    repo = _late_repo()
    place_late_findings(repo, "h1")
    report = _report_order(repo)
    seen = _walk(repo, 3)[0]
    assert [row["id"] for row in seen] == report
    assert all(row["segment"] in {0, 2, 3} for row in seen)       # ranked segments only
    findings = [item for page in build_dossier(repo, "h1", token_budget=200_000).pages
                for item in page.get("findings", [])]
    assert [dossier_alias_target(repo, item["alias"]) for item in findings] == report
    assert "not_ranked" not in {item.get("rank") for item in findings}
    listed = Toolbox(repo, "h1").execute("list_findings", {"page": 1})["data"]["findings"]
    assert [dossier_alias_target(repo, item["alias"]) for item in listed] == report[:len(listed)]


def test_nothing_is_written_without_a_final_pass_or_without_late_findings():
    unranked = _repo()
    _insert(unranked, [_row("a", "r.a", host="x"), _row("b", "r.b", lane="urgent", host="y", provenance="agent")])
    assert place_late_findings(unranked, "h1") is None
    assert not unranked.has_rank_pass("h1", PASS_FINAL) and not _audits(unranked, FINAL_RANK_SUMMARY)
    ranked = _ranked_repo(agent=False)
    state = ranked.rank_state("h1")
    assert place_late_findings(ranked, "h1") is None
    assert ranked.rank_state("h1") == state


def test_placement_runs_in_batches_and_a_failure_keeps_the_placed_ones(monkeypatch):
    repo = _ranked_repo(filler=30, agent=False)
    _insert(repo, [_row(f"z-agent-{index}", "agent.proposal", host="h-t", provenance="agent") for index in range(5)])
    real, calls = rank_module.rank_unranked, []

    def flaky(*args, **kwargs):
        calls.append(1)
        if len(calls) == 3:
            raise ValueError("store unavailable")
        return real(*args, **kwargs)

    monkeypatch.setattr(rank_module, "rank_unranked", flaky)
    detail = place_late_findings(repo, "h1", batch_size=2)
    assert detail["status"] == "failed" and detail["placed"] == 4 and "store unavailable" in detail["reason"]
    assert _audits(repo, PLACE_FAILED_ACTION)[-1] == detail
    assert repo.unranked_findings("h1") == 1
    assert _audits(repo, FINAL_RANK_SUMMARY)[-1]["late_findings_placed"] == 4
    # the one left is listed after every ranked finding, then placed by the next call
    assert [row["id"] for row in _walk(repo, 50)[0]][-1] == "z-agent-4"
    monkeypatch.setattr(rank_module, "rank_unranked", real)
    assert place_late_findings(repo, "h1")["late_findings_placed"] == 5
    assert repo.unranked_findings("h1") == 0


def test_placement_is_fenced_by_the_agent_lease():
    repo = _late_repo()
    _done(repo)
    owner = repo.claim_agent_lease("h1", 60)["lease_owner"]
    before = _ranks(repo)[0]
    with pytest.raises(RuntimeError, match="lease ownership lost"):
        place_late_findings(repo, "h1", owner_token="someone-else")
    assert _ranks(repo)[0] == before and not _audits(repo, PLACE_FAILED_ACTION)
    assert place_late_findings(repo, "h1", owner_token=owner)["late_findings_placed"] == 2


def test_the_agent_run_places_late_findings_before_it_is_final():
    repo = _late_repo()
    _done(repo)
    owner = repo.claim_agent_lease("h1", 60)["lease_owner"]
    investigate._finalize(repo, "h1", investigate.AgentPhaseResult("completed", None, {}, {}), owner_token=owner)
    assert repo.unranked_findings("h1") == 0 and repo.agent_run("h1")["state"] == "completed"
    with repo.engine.connect() as connection:
        order = connection.execute(select(t.audit_event.c.action).where(
            t.audit_event.c.hunt_id == "h1", t.audit_event.c.action.in_(
                (FINAL_RANK_SUMMARY, "hunt.ai_agent_summary"))).order_by(t.audit_event.c.id)).scalars().all()
    assert order[-2:] == [FINAL_RANK_SUMMARY, "hunt.ai_agent_summary"]
    # the pivot's confirmed rule match counts toward the hunt's result once placed
    assert repo.get_hunt("h1")["detection_result"] == "reportable_findings"


def test_a_ranking_error_never_fails_the_agent_run_but_a_lost_lease_stops_it(monkeypatch):
    def store_error(*args, **kwargs):
        raise ValueError("database is busy")

    def lost(*args, **kwargs):
        raise RuntimeError("hunt h1 agent lease ownership lost")

    for failure, state in ((store_error, "completed"), (lost, "pending")):
        repo = _late_repo()
        _done(repo)
        owner = repo.claim_agent_lease("h1", 60)["lease_owner"]
        monkeypatch.setattr(investigate, "place_late_findings", failure)
        result = investigate.AgentPhaseResult("completed", None, {}, {})
        if state == "pending":
            with pytest.raises(RuntimeError, match="lease ownership lost"):
                investigate._finalize(repo, "h1", result, owner_token=owner)
        else:
            investigate._finalize(repo, "h1", result, owner_token=owner)
        assert repo.agent_run("h1")["state"] == state and repo.unranked_findings("h1") == 2


def test_ties_and_missing_times_keep_the_pass_order():
    repo = _repo()
    rows = [_row(f"t-{index:02}", "r.same", host="same", ts=None if index % 3 == 0 else
                 START + timedelta(seconds=index % 4, microseconds=7 * index)) for index in range(24)]
    _insert(repo, rows)
    compute_rank_pass(repo, "h1", PASS_FINAL)
    before = _ranks(repo)[0]
    _insert(repo, [_row("z-tie", "agent.proposal", host="same", provenance="agent", ts=START + timedelta(seconds=1)),
                   _row("z-none", "agent.proposal", host="same", provenance="agent", ts=None)])
    place_late_findings(repo, "h1")
    after = _ranks(repo)[0]
    _kept(before, after)


def test_a_large_hunt_places_many_late_findings_in_batches():
    repo = _ranked_repo(filler=3000, agent=False)
    _insert(repo, [_row(f"z-agent-{index:04}", "agent.proposal", host=f"fill-{index % 9}", provenance="agent",
                        ts=START + timedelta(minutes=index)) for index in range(1500)])
    before, entities_before = _ranks(repo)
    assert place_late_findings(repo, "h1", batch_size=400)["late_findings_placed"] == 1500
    after, entities_after = _ranks(repo)
    assert len(after) == len(before) + 1500 and repo.unranked_findings("h1") == 0
    _kept(before, after)
    assert entities_after == entities_before
    ids = [row["id"] for row in _walk(repo, 200)[0]]
    assert len(ids) == len(set(ids)) == len(after)
