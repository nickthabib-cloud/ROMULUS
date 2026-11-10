"""The final ranking pass runs again when the AI agent's run ends, so findings stored after it get stored ranks."""
from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import select

from romulus.agent import investigate
from romulus.agent.dossier import build_dossier
from romulus.agent.toolbox import Toolbox
from romulus.hunt import rank as rank_module
from romulus.hunt.rank import PASS_FINAL, REFRESH_FAILED_ACTION, compute_rank_pass, refresh_final_pass
from romulus.store import schema as t
from romulus.store.repo import FINAL_RANK_SUMMARY
from tests.test_evidence_rank import START, _insert, _ranks, _row
from tests.test_rank_views import _ranked_repo, _repo, _report_order, _walk, dossier_alias_target


def _late_repo(filler=30):
    """A ranked hunt, then an AI agent's proposal and a confirmed pivot match stored after the final pass."""
    repo = _ranked_repo(filler=filler)
    _insert(repo, [_row("zz-late-urgent", "r.dump", lane="urgent", host="second", ts=START + timedelta(hours=6)),
                   _row("z-context", "agent.ctx", lane="context", host="h-t", provenance="agent")])
    return repo


def _audits(repo, action):
    with repo.engine.connect() as connection:
        return connection.execute(select(t.audit_event.c.detail).where(
            t.audit_event.c.hunt_id == "h1", t.audit_event.c.action == action)).scalars().all()


def _done(repo):
    with repo.engine.begin() as connection:
        connection.execute(t.hunt.update().where(t.hunt.c.id == "h1").values(execution_state="completed_within_scope"))


def test_findings_stored_after_the_pass_are_ranked_and_earlier_ranks_keep_their_scores_and_order():
    repo = _late_repo()
    before, entities_before = _ranks(repo)
    assert repo.unranked_findings("h1") == 2      # the agent's proposal and the late confirmed match; context is not
    summary = refresh_final_pass(repo, "h1")
    assert summary["status"] == "complete" and summary["late_findings"] == 2
    after, entities_after = _ranks(repo)
    assert repo.unranked_findings("h1") == 0
    assert set(after) == set(before) | {"z-agent", "zz-late-urgent"}
    # an agent's finding never counts toward an entity's evidence: every earlier finding and entity keeps its score
    assert {cid: row["score"] for cid, row in after.items() if cid in before} == {
        cid: row["score"] for cid, row in before.items()}
    assert {key: row["score"] for key, row in entities_after.items() if key in entities_before} == {
        key: row["score"] for key, row in entities_before.items()}
    assert sorted(before, key=lambda cid: before[cid]["position"]) == sorted(
        before, key=lambda cid: after[cid]["position"])
    assert sorted(row["position"] for row in after.values()) == list(range(1, len(after) + 1))
    assert after["zz-late-urgent"]["section"] == 0
    assert after["z-agent"]["section"] in {1, 2}
    assert _audits(repo, FINAL_RANK_SUMMARY)[-1]["late_findings"] == 2


def test_after_the_refresh_every_view_lists_the_report_order_with_no_unranked_finding():
    repo = _late_repo()
    refresh_final_pass(repo, "h1")
    report = _report_order(repo)
    assert report[:2] == ["c-urgent", "zz-late-urgent"]
    seen = _walk(repo, 3)[0]
    assert [row["id"] for row in seen] == report
    assert all(row["segment"] in {0, 2, 3} for row in seen)       # ranked segments only
    findings = [item for page in build_dossier(repo, "h1", token_budget=200_000).pages
                for item in page.get("findings", [])]
    assert [dossier_alias_target(repo, item["alias"]) for item in findings] == report
    assert "not_ranked" not in {item.get("rank") for item in findings}
    listed = Toolbox(repo, "h1").execute("list_findings", {"page": 1})["data"]["findings"]
    assert [dossier_alias_target(repo, item["alias"]) for item in listed] == report[:len(listed)]


def test_nothing_runs_without_a_final_pass_or_without_late_findings(monkeypatch):
    calls = []
    real = rank_module.compute_rank_pass
    monkeypatch.setattr(rank_module, "compute_rank_pass", lambda *a, **k: calls.append(a) or real(*a, **k))
    unranked = _repo()
    _insert(unranked, [_row("a", "r.a", host="x"), _row("b", "r.b", lane="urgent", host="y", provenance="agent")])
    assert refresh_final_pass(unranked, "h1") is None
    assert not unranked.has_rank_pass("h1", PASS_FINAL) and not _audits(unranked, FINAL_RANK_SUMMARY)
    ranked = _ranked_repo(agent=False)
    state = ranked.rank_state("h1")
    assert refresh_final_pass(ranked, "h1") is None
    assert ranked.rank_state("h1") == state and not calls


def test_a_failed_refresh_keeps_the_published_pass_and_records_why(monkeypatch):
    repo = _late_repo()
    before, _ = _ranks(repo)
    summaries = len(_audits(repo, FINAL_RANK_SUMMARY))

    def broken(*args, **kwargs):
        raise ValueError("staging failed")

    monkeypatch.setattr(rank_module, "compute_rank_pass", broken)
    detail = refresh_final_pass(repo, "h1")
    assert detail["status"] == "failed" and "staging failed" in detail["reason"] and detail["late_findings"] == 2
    assert _ranks(repo)[0] == before
    assert len(_audits(repo, FINAL_RANK_SUMMARY)) == summaries
    assert _audits(repo, REFRESH_FAILED_ACTION)[-1]["reason"] == detail["reason"]
    # the late findings stay labelled as stored after the pass, after every ranked finding
    ids = [row["id"] for row in _walk(repo, 50)[0]]
    assert ids[:2] == ["c-urgent", "zz-late-urgent"] and ids[-1] == "z-agent"


def test_the_refresh_publishes_under_the_agent_lease_and_never_without_it():
    repo = _late_repo()
    _done(repo)
    owner = repo.claim_agent_lease("h1", 60)["lease_owner"]
    before, _ = _ranks(repo)
    with pytest.raises(RuntimeError, match="lease ownership lost"):
        refresh_final_pass(repo, "h1", owner_token="someone-else")
    assert _ranks(repo)[0] == before and not _audits(repo, REFRESH_FAILED_ACTION)
    assert refresh_final_pass(repo, "h1", owner_token=owner)["status"] == "complete"
    assert repo.unranked_findings("h1") == 0


def test_the_agent_run_ranks_late_findings_before_it_is_final():
    repo = _late_repo()
    _done(repo)
    owner = repo.claim_agent_lease("h1", 60)["lease_owner"]
    result = investigate.AgentPhaseResult("completed", None, {}, {})
    investigate._finalize(repo, "h1", result, owner_token=owner)
    assert repo.unranked_findings("h1") == 0
    assert repo.agent_run("h1")["state"] == "completed"
    with repo.engine.connect() as connection:
        order = connection.execute(select(t.audit_event.c.action).where(
            t.audit_event.c.hunt_id == "h1", t.audit_event.c.action.in_(
                (FINAL_RANK_SUMMARY, "hunt.ai_agent_summary"))).order_by(t.audit_event.c.id)).scalars().all()
    assert order[-2:] == [FINAL_RANK_SUMMARY, "hunt.ai_agent_summary"]


def test_a_ranking_error_never_fails_the_agent_run_but_a_lost_lease_stops_it(monkeypatch):
    repo = _late_repo()
    _done(repo)
    owner = repo.claim_agent_lease("h1", 60)["lease_owner"]

    def store_error(*args, **kwargs):
        raise ValueError("database is busy")

    monkeypatch.setattr(investigate, "refresh_final_pass", store_error)
    investigate._finalize(repo, "h1", investigate.AgentPhaseResult("completed", None, {}, {}), owner_token=owner)
    assert repo.agent_run("h1")["state"] == "completed" and repo.unranked_findings("h1") == 2

    repo = _late_repo()
    _done(repo)
    owner = repo.claim_agent_lease("h1", 60)["lease_owner"]

    def lost(*args, **kwargs):
        raise RuntimeError("hunt h1 agent lease ownership lost")

    monkeypatch.setattr(investigate, "refresh_final_pass", lost)
    with pytest.raises(RuntimeError, match="lease ownership lost"):
        investigate._finalize(repo, "h1", investigate.AgentPhaseResult("completed", None, {}, {}),
                              owner_token=owner)
    assert repo.agent_run("h1")["state"] == "pending"


def test_a_large_hunt_refreshes_completely():
    repo = _ranked_repo(filler=3000, agent=False)
    _insert(repo, [_row(f"z-agent-{index:04}", "agent.proposal", host=f"fill-{index % 9}", provenance="agent",
                        ts=START + timedelta(minutes=index)) for index in range(500)])
    before, _ = _ranks(repo)
    assert refresh_final_pass(repo, "h1")["late_findings"] == 500
    after, _ = _ranks(repo)
    assert len(after) == len(before) + 500 and repo.unranked_findings("h1") == 0
    assert {cid: row["score"] for cid, row in after.items() if cid in before} == {
        cid: row["score"] for cid, row in before.items()}
    ids = [row["id"] for row in _walk(repo, 200)[0]]
    assert len(ids) == len(set(ids)) == len(after)
    # the pass is deterministic: running it again over the same stored findings changes nothing
    compute_rank_pass(repo, "h1", PASS_FINAL)
    assert _ranks(repo)[0] == after
